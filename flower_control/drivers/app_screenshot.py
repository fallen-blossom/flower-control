"""One-frame, exact-window App screenshot return.

This adapter reuses Computer's bounded WGC/PrintWindow capture primitive but
keeps App target selection, task grants, and MCP ownership as the authority.
Pixels stay in memory and are returned only as one MCP image block.
"""
from __future__ import annotations

from dataclasses import asdict
from typing import Callable

from flower_control.control.arbitration import wait_for_turn_sync
from flower_control.control.native import (process_creation_filetime,
                                           physical_window_resource)
from flower_control.control.state import ControlError
from flower_control.control.worker_call import command_hash
from flower_control.drivers.app_control import AppAuthorization, AppBoundaryError, AppRuntime
from flower_control.drivers.computer_capture import CaptureError, capture_window
from flower_control.drivers.computer_native import (NativeInputError, WindowIdentity,
                                                    assert_window, bind_window, window_geometry, Rect, WindowGeometry)
from flower_control.drivers.computer_png import bmp_to_png
from flower_control.window_registry import WindowSelectionError


def masked_frame_png(capture, geometry: WindowGeometry | None = None):
    """Transform only an already privacy-masked capture; grants stay with callers."""
    png = bmp_to_png(capture.bmp)
    bounds, width, height = capture.source_bounds, capture.width, capture.height
    if geometry is not None:
        x, y = geometry.client_origin
        width, height = geometry.client_size
        if not (bounds.left <= x < x + width <= bounds.right
                and bounds.top <= y < y + height <= bounds.bottom):
            raise CaptureError("client_area_outside_capture")
        from .computer_image_view import image_view
        png, _ = image_view(png, crop=[x - bounds.left, y - bounds.top,
            x + width - bounds.left, y + height - bounds.top])
        bounds = Rect(x, y, x + width, y + height)
    return png, bounds, width, height


def capture_app_screenshot(runtime: AppRuntime, target: dict, action_id: str,
                           resolve_identity: Callable[[], WindowIdentity], *,
                           trusted_task: str, client_area: bool = False) -> dict:
    """Capture one selected window frame under its live task/content grant."""
    if type(client_area) is not bool:
        raise AppBoundaryError("invalid_app_frame_options")
    if type(action_id) is not str or not 1 <= len(action_id) <= 128:
        raise AppBoundaryError("invalid_action_id")
    payload = {"target": target, "content": True, "action_id": action_id,
               "view": "frame"}
    grant = runtime._authorized("flower_app_observe", payload, target,
                                trusted_task=trusted_task)
    if not grant.content_scope:
        raise AppBoundaryError("content_scope_not_approved")

    identity = resolve_identity()
    _check_identity(grant, identity)
    owner, resource = runtime._owner_resource(grant)
    key = runtime._action_key(grant.task_id, action_id)
    arguments = {"target": {"pid": grant.pid, "hwnd": grant.hwnd,
                             "process_start_filetime": grant.process_start_filetime},
                 "action_id": action_id, "frame_count": 1,
                 "capture_scope": "selected_window_frame"}
    if client_area:
        arguments["client_area"] = True
    fingerprint = command_hash("screenshot", arguments)
    resources = (resource,) + ((grant.shared_resource,) if grant.shared_resource else ())
    queued = runtime.store.enqueue(owner, action_id=key, fingerprint=fingerprint,
                                   resources=resources, scope=grant.content_scope,
                                   read_only=True)
    if queued["state"] != "queued":
        return {"state": "rejected", "dispatched": False,
                "reason": "action_id_replayed"}
    # This read-only capture stays local; arbitration does not invoke Jev.
    decision = wait_for_turn_sync(runtime.store, owner, key, resources)
    if decision.action_id != key:
        return {"state": "queued", "dispatched": False,
                "action_id": action_id,
                "receipt": runtime.store.queue_status(owner, key)}

    geometry = None

    def preflight() -> None:
        runtime.store.check_dispatch(owner, key)
        current = runtime._authorized("flower_app_observe", payload, target,
                                      trusted_task=trusted_task)
        if (current.content_scope != grant.content_scope or
                current.target_scope != grant.target_scope or
                current.shared_resource != grant.shared_resource):
            raise AppBoundaryError("capture_permission_changed")
        if current.content_scope is None:
            raise AppBoundaryError("content_scope_not_approved")
        with runtime.store.transaction() as db:
            task = runtime.store._task(db, current.task_id)
            if task["paused"]:
                raise ControlError("user_paused")
            runtime.store._require_scope(db, current.task_id, current.target_scope)
            runtime.store._require_scope(db, current.task_id, current.content_scope)
            if current.shared_resource is not None:
                row = db.execute("SELECT paused,quarantined FROM resources WHERE id=?",
                                 (current.shared_resource,)).fetchone()
                if row is None or row["paused"]:
                    raise ControlError("resource_paused_or_quarantined")
        selected = resolve_identity()
        if selected != identity:
            raise WindowSelectionError("selected_window_changed")
        _check_identity(current, selected)
        assert_window(selected)
        if geometry is not None and window_geometry(selected) != geometry:
            raise AppBoundaryError("client_geometry_changed")

    try:
        with runtime.store.dispatch(owner, key, decision.decision_id):
            try:
                preflight()
                if client_area:
                    geometry = window_geometry(identity)
                def stopped():
                    try:
                        runtime.store.check_dispatch(owner, key)
                        return False
                    except ControlError:
                        return True
                from flower_control.privacy import capture_private
                from flower_control.permissions import PermissionError
                try:
                    capture = capture_private(identity, lambda: capture_window(identity,
                        preflight=preflight, stopped=stopped, timeout=3.0, backend="auto"),
                        preflight=preflight, stopped=stopped, task=grant.task_id)
                except PermissionError as error:
                    raise AppBoundaryError(error.code) from None
                if geometry is not None:
                    preflight()
                png, bounds, width, height = masked_frame_png(capture, geometry)
                # Recheck the task, exact HWND/PID lifetime and content grant
                # after encoding and immediately before the caller can publish.
                preflight()
                runtime.store.check_dispatch(owner, key)
                runtime.store.finish(owner, key, "verified",
                                     result_code="app_screenshot_captured")
            except (AppBoundaryError, CaptureError, ControlError, NativeInputError,
                    ValueError, WindowSelectionError) as error:
                runtime.store.finish(owner, key, "not_verified",
                                     result_code="app_screenshot_not_returned")
                return {"state": "rejected", "dispatched": False,
                        "reason": getattr(error, "code", "capture_failed")}
    except ControlError as error:
        return {"state": "rejected", "dispatched": False,
                "reason": error.code}

    return {"state": "observed", "dispatched": False,
            "action_id": action_id,
            "target": {"pid": grant.pid, "hwnd": grant.hwnd,
                       "process_start_filetime": grant.process_start_filetime},
            "capture": {
                "scope": "selected_window_client_frame" if client_area else "selected_window_frame",
                "source_bounds": asdict(bounds),
                "source_bounds_space": "physical_screen_pixels",
                "width": width, "height": height,
                "occlusion": {"status": "not_measured",
                              "detail": "window capture does not include the desktop occlusion composite"},
                "source": capture.source,
                "fallback_reason": capture.fallback_reason,
                "content_verified": capture.content_verified,
                "elapsed_ms": capture.elapsed_ms,
                "format": "png", "encoded_bytes": len(png),
                "image_content_index": 1},
            "_image": png,
            "_return_context": {
                "identity": identity,
                "geometry": geometry,
                "privacy_revision": capture.privacy_revision,
                "content_scope": grant.content_scope,
                "target_scope": grant.target_scope,
                "shared_resource": grant.shared_resource}}


def authorize_app_screenshot_return(runtime: AppRuntime, target: dict,
                                    action_id: str,
                                    resolve_identity: Callable[[], WindowIdentity], *,
                                    trusted_task: str,
                                    expected_identity: WindowIdentity,
                                    expected_content_scope: str,
                                    expected_target_scope: str | None,
                                    expected_shared_resource: str | None = None,
                                    expected_privacy_revision: str | None = None,
                                    expected_geometry: WindowGeometry | None = None) -> None:
    """Recheck authority immediately before publishing already-captured pixels."""
    from flower_control.permissions import revision, PermissionError
    try:
        if (expected_privacy_revision or "absent") != revision():
            raise AppBoundaryError("user_policy_requires_new_observation")
    except PermissionError as error:
        raise AppBoundaryError(error.code) from None
    payload = {"target": target, "content": True, "action_id": action_id,
               "view": "frame"}
    current = runtime._authorized("flower_app_observe", payload, target,
                                  trusted_task=trusted_task)
    if (current.content_scope != expected_content_scope or
            current.target_scope != expected_target_scope or
            current.shared_resource != expected_shared_resource):
        raise AppBoundaryError("capture_permission_changed")
    if current.content_scope is None:
        raise AppBoundaryError("content_scope_not_approved")
    with runtime.store.transaction() as db:
        task = runtime.store._task(db, current.task_id)
        if task["paused"]:
            raise ControlError("user_paused")
        runtime.store._require_scope(db, current.task_id, current.target_scope)
        runtime.store._require_scope(db, current.task_id, current.content_scope)
        if current.shared_resource is not None:
            row = db.execute("SELECT paused,quarantined FROM resources WHERE id=?",
                             (current.shared_resource,)).fetchone()
            if row is None or row["paused"]:
                raise ControlError("resource_paused_or_quarantined")
    selected = resolve_identity()
    if selected != expected_identity:
        raise WindowSelectionError("selected_window_changed")
    _check_identity(current, selected)
    assert_window(selected)
    if expected_geometry is not None and window_geometry(selected) != expected_geometry:
        raise AppBoundaryError("client_geometry_changed")


def _check_identity(grant: AppAuthorization, identity: WindowIdentity) -> None:
    if not isinstance(identity, WindowIdentity):
        raise AppBoundaryError("window_identity_unavailable")
    if (identity.pid != grant.pid or identity.hwnd != grant.hwnd or
            process_creation_filetime(identity.pid,
                                      expected_iso=identity.process_created) !=
            grant.process_start_filetime):
        raise AppBoundaryError("target_not_approved")
    assert_window(identity)
