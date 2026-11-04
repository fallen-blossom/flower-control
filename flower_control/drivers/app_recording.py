"""Short, exact-window WGC frame sequence saved as a local ZIP artifact."""

from __future__ import annotations

import hashlib
import json
import tempfile
import time
import zipfile
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from .recording_storage import zip_storage_usage, include_capture_storage, recording_write_errors, recording_workspace
from typing import Callable

from flower_control.drivers.computer_capture import CaptureError, capture_window
from flower_control.drivers.computer_native import WindowIdentity, assert_window, window_geometry
from flower_control.drivers.computer_png import bmp_to_png
from flower_control.drivers.web_artifacts import artifact_path, persist_file, check_recording_storage


class AppRecordingError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def app_record_options(limits):
    """Closed public record options, without filesystem or encoder side effects."""
    options = {} if limits is None else limits
    if (type(options) is not dict or set(options) - {"duration_seconds", "fps", "output_path", "format", "client_area"}):
        raise AppRecordingError("invalid_record_request")
    duration, fps, format_ = options.get("duration_seconds", 3), options.get("fps", 2), options.get("format", "zip")
    client = options.get("client_area", False)
    output = options.get("output_path")
    if (type(duration) not in (int, float) or not 0 < duration <= 120 or type(fps) is not int or not 1 <= fps <= 30
            or type(format_) is not str or format_ not in {"zip", "mp4"} or type(client) is not bool
            or output is not None and (type(output) is not str or not output or "\0" in output)):
        raise AppRecordingError("invalid_record_request")
    return duration, fps, format_, client, output


def recording_scope_statement(identity, *, client_area=False):
    """Describe the selected-window route; this is not a capture capability probe."""
    if not isinstance(identity, WindowIdentity) or type(client_area) is not bool:
        raise AppRecordingError("invalid_record_request")
    return {"state": "record_preflight", "dispatched": False, "read_only": True,
        "target": asdict(identity), "capture_scope": "selected_window_client_area" if client_area else "one_selected_window",
        "can_prove": ["captured pixels from the exact selected window after privacy masking"],
        "cannot_prove": ["task success", "independent overlay pixels", "WDA-protected pixels", "requested FPS achieved"],
        "audio_status": "not_captured", "backend_started": False, "artifact_reservations": 0,
        "capture_tested": False, "activation_dispatched": False, "input_dispatched": False}


class _RecordingGuard:
    """One live target/privacy snapshot for capture and any later local encode."""
    def __init__(self, identity, resolve_identity, preflight):
        from flower_control.permissions import revision, PermissionError
        try:
            self.policy_revision = revision()
        except PermissionError as error:
            raise AppRecordingError(error.code) from None
        self.identity, self.resolve_identity, self.preflight = identity, resolve_identity, preflight
        self.geometry = None

    def check(self):
        from flower_control.permissions import revision, PermissionError
        try:
            if revision() != self.policy_revision:
                raise AppRecordingError("user_policy_requires_new_observation")
        except PermissionError as error:
            raise AppRecordingError(error.code) from None
        self.preflight()
        if self.resolve_identity() != self.identity:
            raise AppRecordingError("selected_window_changed")
        assert_window(self.identity)
        if self.geometry is not None and window_geometry(self.identity) != self.geometry:
            raise AppRecordingError("client_geometry_changed")


def _record_window_zip(identity: WindowIdentity, *,
                  resolve_identity: Callable[[], WindowIdentity],
                  preflight: Callable[[], None], stopped: Callable[[], bool],
                  duration_seconds: float, fps: int,
                  output_path: str | None = None, task: str | None = None, client_area: bool = False,
                  _guard: _RecordingGuard | None = None, _frame_capture=None,
                  _capture_scope='one_selected_window') -> dict:
    """Capture at most 3600 slots; no foreground activation or input resource."""
    if (not isinstance(identity, WindowIdentity) or not callable(resolve_identity)
            or not callable(preflight) or not callable(stopped)
            or type(duration_seconds) not in (int, float)
            or not 0 < duration_seconds <= 120 or type(fps) is not int
            or not 1 <= fps <= 30 or type(client_area) is not bool):
        raise AppRecordingError("invalid_record_request")
    artifact_path(output_path, suffix=".zip", suggested="app-recording", recording_budget=True)
    check_recording_storage(output_path)
    from flower_control.permissions import PermissionError
    from flower_control.privacy import capture_private
    guard = _guard or _RecordingGuard(identity, resolve_identity, preflight)
    recheck = guard.check
    recheck()
    if stopped():
        raise AppRecordingError("record_cancelled_before_start")
    if client_area and guard.geometry is None:
        guard.geometry = window_geometry(identity)
    geometry = guard.geometry
    started_utc = datetime.now(timezone.utc).isoformat()
    started = time.monotonic()
    slot_count = min(3600, int(duration_seconds * fps) + (1 if duration_seconds * fps % 1 else 0))
    frames: list[dict] = []
    dropped: list[int] = []
    reason: str | None = None
    can_publish = True
    total_png_bytes = 0
    with recording_workspace(prefix="flower-app-record-") as directory:
        staged = Path(directory) / "recording.zip"
        with recording_write_errors(), zipfile.ZipFile(staged, "w", zipfile.ZIP_DEFLATED) as archive:
            for slot in range(slot_count):
                due = started + slot / fps
                while True:
                    if stopped():
                        reason = "cancelled"
                        break
                    try:
                        recheck()
                    except Exception:
                        reason = "target_or_permission_changed"
                        can_publish = False
                        break
                    remaining = due - time.monotonic()
                    if remaining <= 0:
                        break
                    time.sleep(min(0.05, remaining))
                if reason is not None:
                    break
                if time.monotonic() > due + 1 / fps:
                    dropped.append(slot)
                    continue
                try:
                    try:
                        capture = _frame_capture(recheck,stopped) if _frame_capture is not None else capture_private(identity, lambda: capture_window(identity,
                            preflight=recheck, stopped=stopped, timeout=3.0, backend="WGC"),
                            preflight=recheck, stopped=stopped, task=task)
                        captured_elapsed = time.monotonic() - started
                        captured_utc = datetime.now(timezone.utc).isoformat()
                    except PermissionError as error:
                        raise AppRecordingError(error.code) from None
                    recheck()
                    if geometry is None:
                        png = bmp_to_png(capture.bmp)
                        bounds, width, height = capture.source_bounds, capture.width, capture.height
                    else:
                        from .app_screenshot import masked_frame_png
                        png, bounds, width, height = masked_frame_png(capture, geometry)
                    recheck()
                except (CaptureError, AppRecordingError, ValueError, OSError) as error:
                    reason = getattr(error, "code", "capture_failed")
                    if reason in {"selected_window_changed", "window_changed", "client_geometry_changed", "client_area_outside_capture",'region_capture_cleanup_pending'}:
                        can_publish = False
                    break
                if stopped():
                    reason = "cancelled"
                    break
                if total_png_bytes + len(png) > 45_000_000:
                    reason = "artifact_size_limit"
                    break
                total_png_bytes += len(png)
                name = f"frames/{slot:03d}.png"
                archive.writestr(name, png)
                frames.append({"slot": slot, "captured_utc": captured_utc,
                               "captured_elapsed_seconds": captured_elapsed,
                               "scheduled_offset_ms": round(slot * 1000 / fps, 1),
                               "name": name, "bytes": len(png),
                               "sha256": hashlib.sha256(png).hexdigest(),
                               "width": width, "height": height,
                               "source_bounds": asdict(bounds),
                               "source": capture.source,
                               "content_verified": capture.content_verified,
                               "capture_elapsed_ms": capture.elapsed_ms})
            # Hold the last sample for the requested final sampling interval.
            # Waiting remains interruptible and never activates the window.
            while reason is None and time.monotonic() < started + duration_seconds:
                if stopped():
                    reason = "cancelled"
                    break
                try:
                    recheck()
                except Exception:
                    reason = "target_or_permission_changed"
                    can_publish = False
                    break
                time.sleep(min(.05, max(0, started + duration_seconds - time.monotonic())))
            capture_elapsed = time.monotonic() - started
            manifest = {"format": "flower-app-wgc-frames-v1" if _capture_scope=='one_selected_window' else 'flower-app-isolated-region-frames-v1',
                        "scope": _capture_scope, "target": asdict(identity),
                        "started_utc": started_utc,
                        "finished_utc": datetime.now(timezone.utc).isoformat(),
                        "finished_elapsed_seconds": capture_elapsed,
                        "requested_duration_seconds": duration_seconds,
                        "requested_fps": fps, "scheduled_slots": slot_count,
                        "frames": frames, "dropped_slots": dropped,
                        "partial": bool(reason or dropped),
                        "stop_reason": reason,
                        "frame_format": "png"}
            if client_area:
                manifest["client_area"] = True
            archive.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))
        if not can_publish:
            return {"state": "rejected", "frames": len(frames), "partial": True,
                    "stop_reason": reason, "artifact": None,
                    "target": asdict(identity)}
        recheck()  # no captured content leaves a revoked or replaced target
        with recording_write_errors():
            artifact = persist_file(staged, output_path, suffix=".zip",
                                    suggested="app-recording", recording_budget=True, preflight=recheck)
        storage_usage = zip_storage_usage(staged, artifact)
    return {"state": "recorded" if frames else "not_verified",
            "format": manifest['format'], "artifact": artifact, "storage_usage": storage_usage,
            "frames": len(frames), "scheduled_slots": slot_count,
            "requested_duration_seconds": duration_seconds, "requested_fps": fps,
            "actual_duration_seconds": capture_elapsed,
            "actual_average_fps": len(frames) / capture_elapsed if capture_elapsed else 0,
            "dropped_slots": dropped, "partial": manifest["partial"],
            "stop_reason": reason, "target": asdict(identity),
            **({"client_area": True} if client_area else {})}


def record_window(identity, *, resolve_identity, preflight, stopped, duration_seconds,
                  fps, output_path=None, task=None, output_format="zip", encoder=None, client_area=False):
    """ZIP stays the default; MP4 exports the same guarded/redacted frames."""
    if type(client_area) is not bool:
        raise AppRecordingError("invalid_record_request")
    if type(output_format) is not str or output_format not in {"zip", "mp4"}:
        raise AppRecordingError("invalid_record_format")
    app_record_options({"duration_seconds": duration_seconds, "fps": fps, "format": output_format,
        "client_area": client_area, "output_path": output_path})
    if output_format == "zip":
        return _record_window_zip(identity, resolve_identity=resolve_identity, preflight=preflight,
            stopped=stopped, duration_seconds=duration_seconds, fps=fps, output_path=output_path, task=task, client_area=client_area)
    from .local_video import approved_encoder, export_recording
    encoder = encoder or approved_encoder()
    encoder.verify()
    artifact_path(output_path, suffix=".mp4", suggested="app-recording", recording_budget=True)
    check_recording_storage(output_path)
    guard = _RecordingGuard(identity, resolve_identity, preflight)
    with recording_workspace(prefix="flower-mp4-record-") as directory:
        intermediate = Path(directory) / "frames.zip"
        captured = _record_window_zip(identity, resolve_identity=resolve_identity, preflight=preflight,
            stopped=stopped, duration_seconds=duration_seconds, fps=fps, output_path=str(intermediate), task=task, client_area=client_area, _guard=guard)
        if captured["state"] != "recorded":
            return {**captured, "artifact": None, "format": "mp4"}
        encoded = export_recording(intermediate, output_path=output_path, preflight=guard.check,
                                   stopped=stopped, encoder=encoder)
        include_capture_storage(encoded, captured)
        guard.check()
        return {**encoded, "target": asdict(identity), "capture_partial": captured["partial"],
                "actual_duration_seconds": captured["actual_duration_seconds"],
                "actual_average_fps": captured["actual_average_fps"],
                "dropped_slots": captured["dropped_slots"], "stop_reason": captured["stop_reason"],
                **({"client_area": True} if client_area else {})}
