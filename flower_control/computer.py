"""Computer MCP process with task-bound ordinary window selection."""

import asyncio
import base64
import binascii
import ctypes
import hashlib
import threading
import uuid
import sqlite3
from contextlib import asynccontextmanager
from dataclasses import asdict
from typing import Literal

from mcp.server.fastmcp import Context, FastMCP, Image
from pydantic import StrictInt

from flower_control._status import loaded_source, status_details
from flower_control.authorization.hook_bridge import (live_ledger,
                                                      state_directory)
from flower_control.mcp_origin import consume_origin_async, ledger_error_code
from flower_control.authorization.origin import OriginError
from flower_control.control.state import ControlError, StateStore, HumanHandoffKind, human_handoff_kind
from flower_control.permissions import PermissionError as PolicyPermissionError
from flower_control.control.jev_runtime import client_factory as jev_client_factory, enabled as jev_enabled
from flower_control.control.jev_diagnostics import public_tool_call_async
from flower_control.drivers.computer_capture import CaptureError
from flower_control.drivers.desktop_capture import DesktopCaptureError
from flower_control.drivers.computer_capture_session import ComputerCaptureSession
from flower_control.drivers.computer_mcp import (ComputerAuthorization,
                                                 ComputerBoundaryError,
                                                 ComputerRuntime,
                                                 diagnose_value_error)
from flower_control.drivers.computer_native import NativeInputError
from flower_control.drivers.computer_takeover import ComputerTakeover
from flower_control.drivers.computer_native import WindowIdentity
from flower_control.drivers.computer_host_lifetime import ComputerHostLifetime
from flower_control.drivers.computer_wait import call_lifetime
from flower_control.drivers.high_helper import HighHelperClient, ActiveHelperClient, HighHelperError
from flower_control.drivers.computer_png import bmp_to_png
from flower_control.local_target import FixtureTarget, LocalTargetError
from flower_control.target_wire import (computer_result_to_wire as _target_result_to_wire,
                                        computer_target_from_wire,
                                        computer_target_to_wire)
from flower_control.window_registry import WindowRegistry, WindowSelectionError
from flower_control.browser_window_policy import BrowserWindowPolicy


def computer_result_to_wire(value):
    """Keep lossless identities and explain known Computer failure receipts."""
    def public(value):
        if isinstance(value, dict):
            return {key: public(item) for key, item in value.items()
                    if key not in {"_bmp", "base64"}}
        if isinstance(value, list):
            return [public(item) for item in value]
        return value
    return _target_result_to_wire(public(value))


def _has_visual_bmp(visual):
    return (isinstance(visual, dict) and
            (type(visual.get("_bmp")) is bytes or type(visual.get("base64")) is str))


def _visual_bmp(visual):
    raw = visual.get("_bmp") if isinstance(visual, dict) else None
    if type(raw) is bytes:
        return raw
    encoded = visual.get("base64") if isinstance(visual, dict) else None
    if type(encoded) is str:
        return base64.b64decode(encoded, validate=True)
    raise ValueError("observation_image_unavailable")


def _public_visual(visual):
    return {key: value for key, value in visual.items()
            if key not in {"base64", "_bmp"}}


def _suppress_visual_return(outcome: dict, reason: str) -> dict:
    """A denied result read cannot change an already recorded write outcome."""
    def without_pixels(value):
        if isinstance(value, dict):
            return {key: without_pixels(item) for key, item in value.items()
                    if key not in {"base64", "_bmp", "image", "visual_recheck", "retained_artifact",
                                   "artifact_id", "image_content_index"}}
        if isinstance(value, list):
            return [without_pixels(item) for item in value]
        return value
    safe = without_pixels(outcome)
    safe.update(visual_return_suppressed=True, visual_return_reason=reason)
    safe.setdefault("reason", reason)
    if isinstance(safe.get("result"), dict):
        safe["result"].update(visual_return_suppressed=True, visual_return_reason=reason,
                              requires_new_observation=True)
    return computer_result_to_wire(safe)


def _publish_visual_return(active, task, metadata, images, presentations):
    """Last synchronous publication point, after all visual authorization gates."""
    binder = getattr(active, 'bind_returned_images', None)
    if callable(binder):
        bound = binder([(identity, view) for identity, view, _field in presentations], trusted_task=task)
    else:
        single = getattr(active, 'bind_returned_image', None)
        bound = [single(identity, trusted_task=task, view_metadata=view)
                 if callable(single) and identity is not None else False
                 for identity, view, _field in presentations]
    for (_identity, _view, field), accepted in zip(presentations, bound):
        field['returned_image_coordinate_spaces'] = (
            ['returned_image', 'normalized_1000_image'] if accepted is True else [])
    return [computer_result_to_wire(metadata), *images]


def _task_control_cycle_status(task, window_runtime, desktop_runtime):
    # Snapshot existing adapters only; this query never creates a runtime or
    # task cycle. One runtime can appear through both routes.
    with desktop_runtime._gate:
        adapter = desktop_runtime._input_adapters.get(task)
        desktop = adapter.runtime if adapter is not None else None
    selected = []
    for active in (window_runtime, desktop):
        if active is not None and all(active is not old for old in selected):
            selected.append(active)
    if not selected:
        return {"runtime_present": False, "cycle_present": False, "stopped": None,
                "stop_pending": None, "pending_layers": None}
    snapshots = [active.control_cycle_status(task) for active in selected]
    return {"runtime_present": True,
            "cycle_present": any(row["cycle_present"] for row in snapshots),
            "stopped": any(row["stopped"] for row in snapshots),
            "stop_pending": any(row["stop_pending"] for row in snapshots),
            "pending_layers": sum(row["pending_layers"] for row in snapshots)}


def create_computer_server(runtime: ComputerRuntime | None = None,
                           *, fixture_target: FixtureTarget | None = None,
                           high_client_factory=ActiveHelperClient) -> FastMCP:
    lifetime = ComputerHostLifetime()
    @asynccontextmanager
    async def host_lifespan(_server):
        phase_consumer.start()
        try:
            yield lifetime
        finally:
            from .drivers.host_cleanup import close_host_resources
            def steps():
                yield "idle_phase_release", phase_consumer.close
                yield "plans", lambda: asyncio.to_thread(plan_manager.close)
                yield "executions", lifetime.close
                yield "desktop", lambda: asyncio.to_thread(desktop_runtime.close)
                for active in ([runtime] if runtime is not None else tuple(runtimes.values())):
                    yield "capture_sessions", lambda active=active: asyncio.to_thread(active.close_capture_sessions)
            await close_host_resources("computer", steps())
    from flower_control.tool_guidance import task_method_instructions
    server = FastMCP("flower-computer", lifespan=host_lifespan,
                     instructions=task_method_instructions("flower-computer"))
    source = loaded_source(__file__)
    if runtime is not None and fixture_target is not None:
        raise ValueError("choose one trusted adapter")
    if fixture_target is not None and fixture_target.kind != "computer_tk":
        raise ValueError("wrong fixture kind")
    runtimes: dict[str, ComputerRuntime] = {}
    runtime_gate = threading.RLock()
    from .control.host_phase import PhaseConsumer
    def phase_runtimes():
        with runtime_gate:
            selected = [runtime] if runtime is not None else list(runtimes.values())
        with desktop_runtime._gate:
            selected.extend(adapter.runtime for adapter in desktop_runtime._input_adapters.values())
        return tuple(selected)
    phase_consumer = PhaseConsumer(phase_runtimes,
        busy=lambda task: lifetime.busy(task) or plan_manager.busy(task))
    from flower_control.drivers.desktop_cursor import DesktopCursorReader
    cursor_reader = DesktopCursorReader()
    from flower_control.drivers.desktop_runtime import DesktopRuntime,DesktopObservationOwnership
    desktop_runtime=DesktopRuntime(high_client_factory=high_client_factory)
    from flower_control.drivers.computer_plan import ComputerPlans
    plan_manager=ComputerPlans()
    windows = (WindowRegistry(BrowserWindowPolicy(state_directory()),
                             window_binder=lambda request, current: require_runtime(
                                 request.task, "flower_computer_action_status", {}).bind_selected_window(request, current))
               if runtime is None and fixture_target is None else None)

    def require_runtime(task: str, tool: str, arguments: dict) -> ComputerRuntime:
        if runtime is not None:
            return runtime
        if tool in ("flower_computer_action_status", "flower_computer_cancel", "flower_computer_plan") or (
                tool == "flower_computer_pause" and arguments.get("mode") in {"finish", "release_phase"}):
            pass  # Receipts are task-bound; a closed target need not be rebound.
        elif fixture_target is None:
            assert windows is not None
            windows.resolve(task, arguments.get("target"))
        else:
            fixture_target.verify(arguments.get("target"))
        with runtime_gate:
            active = runtimes.get(task)
            if active is None:
                directory = state_directory()
                store = StateStore(directory, jev_enabled=lambda: jev_enabled(directory))

                def resolve_call(_tool: str, payload: dict) -> ComputerAuthorization:
                    if fixture_target is None:
                        assert windows is not None
                        identity = windows.resolve(task, payload.get("target"))
                        access = windows.access(task, payload.get("target"))
                    else:
                        fixture_target.verify(payload.get("target"))
                        identity = WindowIdentity(fixture_target.hwnd, fixture_target.pid,
                                                  fixture_target.process_created,
                                                  fixture_target.window_nonce)
                        access = None
                    return ComputerAuthorization(task, identity, store.clock() + call_lifetime(_tool, payload),
                                                 capture_allowed=True, input_allowed=True,
                                                 target_scope=(access.target_scope if access else None),
                                                 shared_resource=(access.shared_resource if access else None),
                                                 execution_guard=(windows.execution_guard(task, identity, access)
                                                                  if windows and access else None))

                active = ComputerRuntime(store, resolve_call,
                                         takeover_policy=ComputerTakeover() if fixture_target is None else None,
                                         jev_client_factory=jev_client_factory(directory),
                                         capture_session_factory=ComputerCaptureSession,
                                         high_client_factory=high_client_factory if fixture_target is None else None,
                                         owned_window_binder=(lambda task, parent, hwnd:
                                             windows.bind_owned_window(task, parent, hwnd)) if windows else None)
                runtimes[task] = active
            return active

    async def linked_task(tool: str, arguments: dict, origin: object):
        if (runtime is None and fixture_target is None and origin is None and
                tool not in ("flower_computer_list_windows",
                             "flower_computer_select_window")):
            raise ComputerBoundaryError("trusted_origin_unavailable")
        expected = (f"mcp__flower_computer__{tool}", f"mcp__flower-computer__{tool}")
        if not isinstance(origin, dict) or origin.get("tool_name") not in expected:
            raise OriginError("origin_missing_or_invalid")
        # A consumed ticket links this call to a chat; it creates no target or profile grant.
        linked = await consume_origin_async(live_ledger, tool_name=origin["tool_name"],
                                            arguments=arguments, origin=origin)
        if tool in {"flower_computer_select_window", "flower_computer_activate", "flower_computer_observe",
                    "flower_computer_input", "flower_computer_execute_sequence", "flower_computer_window_layout"}:
            task, ledger = linked
            await asyncio.to_thread(ledger.store.record_event, "computer_control_attempted", task=task, details={})
        from .control.business_calls import retry_pending
        await asyncio.to_thread(retry_pending)
        return linked

    async def prepare(method, *args, **kwargs):
        try:
            return await lifetime.call(method, *args, **kwargs)
        except sqlite3.Error as error:
            raise ControlError(ledger_error_code(error, prefix="control_ledger")) from None


    async def linked_call(tool: str, arguments: dict, origin: object,
                          method: str, *args, visual_key: str | None = None,
                          **kwargs):
        try:
            task, ledger = await linked_task(tool, arguments, origin)
            async with public_tool_call_async(ledger.store, task=task, channel="computer", tool=tool):
                from .control.business_calls import public_call, public_action_key
                action = arguments.get('action_id')
                key = public_action_key(task, 'computer', action) if type(action) is str and method not in {'action_status', 'cancel'} else None
                async with public_call(ledger.store, task, key):
                    return await prepared_call(task, tool, arguments, method, *args,
                                               visual_key=visual_key, **kwargs)
        except (ComputerBoundaryError, OriginError, ControlError) as error:
            return computer_result_to_wire({"state": "rejected", "dispatched": False, "reason": error.code})

    async def prepared_call(task, tool, arguments, method, *args, visual_key=None, **kwargs):
        try:
            native = ({**arguments, "target": computer_target_from_wire(arguments["target"])}
                      if "target" in arguments else arguments)
            active = await prepare(require_runtime, task, tool, native)
            if "target" in native:
                args = (native["target"], *args[1:])
        except (ComputerBoundaryError, OriginError, ControlError, LocalTargetError,
                WindowSelectionError, ValueError) as error:
            return computer_result_to_wire({"state": "rejected", "dispatched": False,
                    "reason": getattr(error, "code", "invalid_target_encoding")})
        outcome = await call(getattr(active, method), *args,
                             trusted_task=task, **kwargs)
        def publish(metadata, images, presentations):
            try:
                return _publish_visual_return(active, task, metadata, images, presentations)
            except (ComputerBoundaryError, ControlError) as error:
                return _suppress_visual_return(outcome, error.code)
            except Exception:
                return _suppress_visual_return(outcome, 'returned_image_binding_failed')
        if (tool == "flower_computer_input" and
                arguments.get("command") == "sequence" and
                isinstance(outcome.get("result"), dict) and
                type(outcome["result"].get("step_observations")) is list):
            observations = outcome["result"]["step_observations"]
            safe_result = {**outcome["result"], "step_observations": []}
            safe_outcome = {**outcome, "result": safe_result}
            images = []
            presentations = []
            sequence_return_checks = []
            try:
                if len(observations) > 8:
                    raise ValueError("too many sequence images")
                sample_indices = (set(range(len(observations))) if len(observations) <= 3 else
                    {0, (len(observations)-1)//3, 2*(len(observations)-1)//3, len(observations)-1})
                for entry in observations:
                    visual = entry["image"]
                    from flower_control.permissions import revision
                    if (visual.get("privacy_revision") or "absent") != revision():
                        raise ComputerBoundaryError("user_policy_requires_new_observation")
                    await asyncio.to_thread(active.authorize_visual_return, tool,
                        native, task, policy_revision=visual.get("privacy_revision"))
                    encoded = bmp_to_png(_visual_bmp(visual))
                    retained = None
                    if len(observations) > 3:
                        from flower_control.control.local_artifacts import LocalArtifactStore
                        try:
                            retained = await asyncio.to_thread(LocalArtifactStore(active.store.directory).put, task, encoded,
                                kind="image", metadata={"channel": "computer", "scope": "one_selected_window",
                                    "target": native["target"], "source_bounds": visual.get("source_bounds"),
                                    "width": visual["width"], "height": visual["height"],
                                    "privacy_revision": visual.get("privacy_revision"), "capture_id": entry.get("observation_id")})
                        except ControlError as error:
                            retained = {"state": "unavailable", "reason": error.code}
                    inline = entry["index"] in sample_indices
                    mapping = {}
                    if inline:
                        if len(observations) > 3:
                            from flower_control.drivers.computer_image_view import image_view
                            encoded, mapping = image_view(encoded, max_size=[1024, 1024])
                        images.append(Image(data=encoded, format="png"))
                    safe_entry = {
                        "index": entry["index"],
                        **({"observation_id": entry["observation_id"]} if entry.get("observation_id") else {}),
                        "image": {**_public_visual(visual),
                                  **mapping, "format": "png", "encoded_bytes": len(encoded),
                                  "image_content_index": len(images) if inline else None,
                                  "retained_artifact": retained}}
                    safe_result["step_observations"].append(safe_entry)
                    if inline:
                        presentations.append((entry.get("observation_id"), mapping, safe_entry['image']))
                followups = safe_result.get("followup_targets")
                if (safe_result.get("reason") == "new_window_detected" and
                        type(followups) is list and len(followups) == 1 and
                        type(followups[0]) is dict):
                    followup_target = followups[0]
                    followup_action = "followup-" + uuid.uuid4().hex
                    try:
                        observed = await call(active.observe, followup_target,
                                              followup_action, trusted_task=task)
                        detail = observed.get("result")
                        screenshot = detail.get("image") if isinstance(detail, dict) else None
                        if not _has_visual_bmp(screenshot):
                            raise ComputerBoundaryError(
                                observed.get("reason", "followup_capture_unavailable"))
                        followup_bytes = bmp_to_png(_visual_bmp(screenshot))
                        await asyncio.to_thread(
                            active.authorize_visual_return, "flower_computer_observe",
                            {"target": followup_target, "action_id": followup_action}, task,
                            policy_revision=screenshot.get("privacy_revision"))
                        images.append(Image(data=followup_bytes, format="png"))
                        safe_result["followup_observation"] = {
                            "target": computer_target_to_wire(followup_target),
                            "observation_id": detail.get("observation_id"),
                            "image": {**_public_visual(screenshot), "format": "png",
                                      "encoded_bytes": len(followup_bytes),
                                      "image_content_index": len(images)}}
                        sequence_return_checks.append(("flower_computer_observe",
                            {"target": followup_target, "action_id": followup_action},
                            screenshot.get("privacy_revision")))
                        presentations.append((detail.get('observation_id'), {},
                            safe_result['followup_observation']['image']))
                    except Exception as error:
                        safe_result["followup_capture"] = (
                            "unavailable:" + getattr(error, "code", type(error).__name__))
                for entry in observations:
                    await asyncio.to_thread(active.authorize_visual_return, tool,
                        native, task, policy_revision=entry["image"].get("privacy_revision"))
                for return_tool, return_payload, return_revision in sequence_return_checks:
                    await asyncio.to_thread(active.authorize_visual_return, return_tool,
                        return_payload, task, policy_revision=return_revision)
            except (ValueError, KeyError, TypeError, binascii.Error,
                    ComputerBoundaryError, ControlError, NativeInputError) as error:
                reason = getattr(error, "code", "sequence_visual_return_unavailable")
            except Exception:
                reason = "sequence_visual_return_unavailable"
            else:
                return (publish(safe_outcome, images, presentations) if images
                        else computer_result_to_wire(safe_outcome))
            return _suppress_visual_return(outcome, reason)
        if visual_key is None or not isinstance(outcome.get("result"), dict) or (
                isinstance(outcome.get("result"), dict) and
                visual_key not in outcome["result"]):
            # An actively foregrounded owned dialog ends the old suffix. Its
            # new image is a separate read, under the original trusted task.
            input_detail = outcome.get("result") if isinstance(outcome.get("result"), dict) else outcome
            followups = input_detail.get("followup_targets")
            dialog_found = (outcome.get("reason") == "new_window_detected" or
                            input_detail.get("visual_scope") == "followup_window_detected")
            if (tool == "flower_computer_input" and dialog_found and
                    outcome.get("receipt", {}).get("state") != "outcome_uncertain" and
                    input_detail.get("input_release", "released") == "released" and
                    type(followups) is list and len(followups) == 1 and type(followups[0]) is dict):
                action = "followup-" + uuid.uuid4().hex
                try:
                    observed = await call(active.observe, followups[0], action, trusted_task=task)
                    detail = observed.get("result")
                    screenshot = detail.get("image") if isinstance(detail, dict) else None
                    if not _has_visual_bmp(screenshot):
                        raise ComputerBoundaryError(observed.get("reason", "followup_capture_unavailable"))
                    image_bytes = bmp_to_png(_visual_bmp(screenshot))
                    await asyncio.to_thread(active.authorize_visual_return, "flower_computer_observe",
                                            {"target": followups[0], "action_id": action}, task,
                                            policy_revision=screenshot.get("privacy_revision"))
                except Exception as error:
                    outcome["followup_capture"] = "unavailable:" + getattr(error, "code", type(error).__name__)
                else:
                    outcome["followup_observation"] = {
                        "target": computer_target_to_wire(followups[0]),
                        "observation_id": detail.get("observation_id"),
                        "image": {**_public_visual(screenshot),
                                  "format": "png", "encoded_bytes": len(image_bytes), "image_content_index": 1}}
                    return publish(outcome, [Image(data=image_bytes, format="png")],
                        [(detail.get('observation_id'), {}, outcome['followup_observation']['image'])])
            outcome_result = outcome.get("result")
            closed_after_input = (
                isinstance(outcome_result, dict) and
                outcome_result.get("state") in {"target_closed_after_input", "closed_to_owner"})
            if (tool == "flower_computer_input" and windows is not None and
                    (closed_after_input or
                     outcome.get("dispatched") and
                     outcome.get("reason") == "target_not_captureable")):
                # Confirmation dialogs commonly destroy themselves on click.
                # Keep the original receipt and show the selected parent's
                # independently captured state in this same reply.
                try:
                    root = asdict(await prepare(windows.selected_root, task))
                    if root != native["target"]:
                        recovery_action = "recovery-" + uuid.uuid4().hex
                        recovered = await call(active.observe, root, recovery_action,
                                               trusted_task=task)
                        detail = recovered.get("result")
                        screenshot = detail.get("image") if isinstance(detail, dict) else None
                        if _has_visual_bmp(screenshot):
                            recovered_bytes = bmp_to_png(_visual_bmp(screenshot))
                            await asyncio.to_thread(
                                active.authorize_visual_return, "flower_computer_observe",
                                {"target": root, "action_id": recovery_action}, task,
                                policy_revision=screenshot.get("privacy_revision"))
                            recovery = {
                                "target": computer_target_to_wire(root),
                                "observation_id": detail.get("observation_id"),
                                "image": {**_public_visual(screenshot), "format": "png",
                                          "encoded_bytes": len(recovered_bytes),
                                          "image_content_index": 1}}
                            if closed_after_input:
                                outcome_result["recovery_observation"] = recovery
                            else:
                                outcome["recovery_observation"] = recovery
                            return publish(outcome, [Image(data=recovered_bytes, format="png")],
                                [(detail.get('observation_id'), {}, recovery['image'])])
                except Exception as error:
                    recovery_status = (
                        "unavailable:" + getattr(error, "code", type(error).__name__))
                    if closed_after_input:
                        outcome_result["recovery_capture"] = recovery_status
                    else:
                        outcome["recovery_capture"] = recovery_status
            return computer_result_to_wire(outcome)
        visual = outcome["result"].get(visual_key)
        if not _has_visual_bmp(visual):
            return computer_result_to_wire(outcome)
        try:
            image_bytes = bmp_to_png(_visual_bmp(visual))
            view_metadata = {}
            if tool == "flower_computer_observe" and ("crop" in arguments or "max_size" in arguments):
                from flower_control.drivers.computer_image_view import image_view
                image_bytes, view_metadata = image_view(image_bytes,
                    crop=arguments.get("crop"), max_size=arguments.get("max_size"),
                    **({"crop_format": arguments["crop_format"]} if "crop_format" in arguments else {}))
        except (ValueError, binascii.Error) as error:
            return _suppress_visual_return(outcome,
                "image_crop_outside_capture" if str(error) == "image_crop_outside_capture"
                else "capture_encoding_invalid")
        except Exception:
            return _suppress_visual_return(outcome, "capture_encoding_invalid")
        # Conversion can take time. Recheck task, target and visual scope at the
        # last point before handing any pixels to the MCP client.
        try:
            await asyncio.to_thread(active.authorize_visual_return, tool,
                                    native, task, policy_revision=visual.get("privacy_revision"))
        except (ComputerBoundaryError, ControlError, NativeInputError) as error:
            return _suppress_visual_return(outcome, error.code)
        except Exception:
            return _suppress_visual_return(outcome, "visual_return_check_failed")
        metadata = {**outcome, "result": {**outcome["result"],
                                          visual_key: {**_public_visual(visual),
                                                       "format": "png",
                                                       **view_metadata,
                                                       "encoded_bytes": len(image_bytes),
                                                       "image_content_index": 1}}}
        images = [Image(data=image_bytes, format="png")]
        presentations = [(outcome['result'].get('result_observation_id') or outcome['result'].get('observation_id'), view_metadata,
                          metadata['result'][visual_key])]
        return_checks = [(tool, native, visual.get("privacy_revision"))]
        # A click may reveal a confirmation dialog. Observe one exact owned
        # follow-up inside this same MCP call so the host can decide from the
        # new image without another round trip or guessed dialog script.
        followups = outcome["result"].get("followup_targets")
        if (tool == "flower_computer_input" and outcome["result"].get("dispatched")
                and type(followups) is list and len(followups) == 1
                and type(followups[0]) is dict):
            followup_target = followups[0]
            followup_action = "followup-" + uuid.uuid4().hex
            try:
                observed = await call(active.observe, followup_target, followup_action,
                                      trusted_task=task)
            except Exception:
                observed = {}
            next_result = observed.get("result")
            next_image = next_result.get("image") if isinstance(next_result, dict) else None
            if _has_visual_bmp(next_image):
                try:
                    followup_bytes = bmp_to_png(_visual_bmp(next_image))
                    await asyncio.to_thread(
                        active.authorize_visual_return, "flower_computer_observe",
                        {"target": followup_target, "action_id": followup_action}, task,
                        policy_revision=next_image.get("privacy_revision"))
                except (ValueError, binascii.Error, ComputerBoundaryError,
                        ControlError, NativeInputError):
                    metadata["result"]["followup_capture"] = "unavailable"
                except Exception:
                    # The original input receipt and image remain useful even
                    # when the optional second capture fails unexpectedly.
                    metadata["result"]["followup_capture"] = "unavailable"
                else:
                    metadata["result"]["followup_observation"] = {
                        "target": computer_target_to_wire(followup_target),
                        "observation_id": next_result.get("observation_id"),
                        "image": {**_public_visual(next_image),
                                  "format": "png", "encoded_bytes": len(followup_bytes),
                                  "image_content_index": 2}}
                    images.append(Image(data=followup_bytes, format="png"))
                    presentations.append((next_result.get('observation_id'), {},
                        metadata['result']['followup_observation']['image']))
                    return_checks.append(("flower_computer_observe",
                        {"target": followup_target, "action_id": followup_action}, next_image.get("privacy_revision")))
            else:
                metadata["result"]["followup_capture"] = "unavailable"
        try:
            for return_tool, return_payload, return_revision in return_checks:
                await asyncio.to_thread(active.authorize_visual_return, return_tool,
                    return_payload, task, policy_revision=return_revision)
        except Exception as error:
            return _suppress_visual_return(outcome,
                getattr(error, "code", "visual_return_check_failed"))
        # Finish all async gates and construct the return value before publishing
        # an image-coordinate binding. No await or optional capture follows it.
        return publish(metadata, images, presentations)

    async def call(method, *args, **kwargs) -> dict:
        try:
            return await lifetime.call(method, *args, **kwargs)
        except (ComputerBoundaryError, ControlError, CaptureError, HighHelperError,
                NativeInputError, WindowSelectionError, ValueError) as error:
            if isinstance(error, ValueError):
                diagnose_value_error(error, "adapter")
            return {"state": "rejected", "dispatched": False,
                    "reason": getattr(error, "code", "invalid_computer_request")}
        except Exception:
            return computer_result_to_wire({"state": "outcome_uncertain", "dispatched": None,
                    "reason": "computer_adapter_failed"})

    def build_status() -> dict:
        return {"channel": "flower-computer", "ready": runtime is not None,
                "phase": ("trusted_computer_context_injected" if runtime is not None
                          else "fixture_only" if fixture_target is not None
                          else "ordinary_window_selection"),
                "fixture_target_registered": fixture_target is not None,
                "ordinary_targets_available": windows is not None,
                "available_actions": (["list_windows", "select_window", "observe",
                                       "activate", "input", "action_status",
                                       "cancel", "pause"] if windows is not None else
                                      ["observe", "activate", "input", "action_status",
                                       "cancel", "pause"] if runtime is not None or
                                      fixture_target is not None else []),
                **status_details(
                    "flower-computer", source,
                    registered_tools=[tool.name for tool in server._tool_manager.list_tools()],
                    channel_usable=windows is not None or runtime is not None or fixture_target is not None)}

    @server.tool(name='flower_computer_plan',description='Start a finite window-bound legacy plan: 1..8 steps, total hard 120 seconds, up to four PNG samples. Requires the selected target and fresh original observation. Step types: dwell {duration:0.1..30}; sample {max_size?:256..1024}; act {actions:1..16 legacy type/action dictionaries accepted by batch}; scroll {x,y,dx,dy}; wait_visual {roi:[left,top,right,bottom],state:changed|stable,timeout?:0.1..30,threshold?:0..255}; repeat_visual {actions,roi,roi_anchor?:returned_image|window|client,roi_units?:pixels|normalized_1000,state?:stable|changed,threshold?,settle?:{state:stable,threshold?,timeout?},stop?:{state:unchanged|changed,threshold?},max_iterations?:1..100,max_duration?:1..120,keyframes?:start_change_failure_end}. Actions use current explicit coordinate spaces and balanced input; no cross-call hold. Coordinates/ROI stay bound to the original window geometry. Internally uses current executor/High with fresh per-action observations, shared locks, exact receipts, privacy and Stop; never retries uncertain input or suffixes. First takeover must already be completed via activate. Returns plan_id immediately; query plan_status and cancel that exact plan. Omitted sample pixels stay local until explicitly included. Completed means plan conditions only, not business success. Same action_id only reads the original plan. Optional task_purpose (1-80 characters) and next_step (1-48) carry separate non-secret HUD purpose and step text; they never select targets or grant permission.')
    async def flower_computer_plan(target:dict,observation_id:str,steps:list[dict],action_id:str,
                                   flower_origin:dict|None=None,task_purpose:str|None=None,
                                   next_step:str|None=None)->dict:
        payload=dict(target=target,observation_id=observation_id,steps=steps,action_id=action_id)
        if task_purpose is not None:payload['task_purpose']=task_purpose
        if next_step is not None:payload['next_step']=next_step
        stopped=threading.Event();ownership={}
        try:
            task,ledger=await linked_task('flower_computer_plan',payload,flower_origin)
            native_target=computer_target_from_wire(target)
            active=await prepare(require_runtime,task,'flower_computer_plan',dict(payload,target=native_target))
            def on_stop():
                stopped.set()
                if ownership.get('plan_id') is not None:
                    plan_manager.status(ledger.store,task,ownership['plan_id'],cancel=True)
            async with public_tool_call_async(ledger.store,task=task,channel='computer',tool='flower_computer_plan'):
                return await lifetime.call(plan_manager.start,active,native_target,observation_id,steps,action_id,
                    task=task,raw_arguments=payload,stopped=stopped.is_set,ownership=ownership,_on_host_stop=on_stop)
        except (OriginError,ControlError,ComputerBoundaryError,NativeInputError,WindowSelectionError,PolicyPermissionError,ValueError) as error:
            return dict(state='rejected',reason=getattr(error,'code','invalid_plan_request'),dispatched=False)
        except sqlite3.Error as error:
            return dict(state='rejected',reason=ledger_error_code(error,prefix='control_ledger'),dispatched=False)

    @server.tool(name='flower_computer_plan_status',structured_output=False,description='Read only this chat exact plan_id, optionally wait_seconds:0..30 (default 0) for its terminal state. Cancelling this status wait does not cancel the plan. include_samples:true returns at most four stored PNGs only after fresh same-task target/permission/privacy/Stop checks. Does not repeat input, continue stopped suffixes, revive a previous host plan or grant access. Inspect original child dispatch_receipts if outcome is uncertain; completed does not prove business success.')
    async def flower_computer_plan_status(plan_id:str,wait_seconds:StrictInt=0,include_samples:bool=False,
                                          flower_origin:dict|None=None):
        payload=dict(plan_id=plan_id,wait_seconds=wait_seconds,include_samples=include_samples)
        try:
            task,ledger=await linked_task('flower_computer_plan_status',payload,flower_origin)
            stop=threading.Event()
            async with public_tool_call_async(ledger.store,task=task,channel='computer',tool='flower_computer_plan_status'):
                result=await lifetime.call(plan_manager.status,ledger.store,task,plan_id,wait_seconds=wait_seconds,
                    stopped=stop.is_set,_on_host_stop=stop.set)
                if not include_samples:return result
                samples=await lifetime.call(plan_manager.samples,ledger.store,task,plan_id)
                images=[Image(data=row['png'],format='png') for row in samples]
                result['samples']=[{k:v for k,v in row.items() if k!='png'} for row in samples]
                await lifetime.call(plan_manager.samples,ledger.store,task,plan_id)
                return [result,*images]
        except (OriginError,ControlError,ComputerBoundaryError,NativeInputError,WindowSelectionError,PolicyPermissionError) as error:
            return dict(state='rejected',reason=error.code,dispatched=False)
        except sqlite3.Error as error:
            return dict(state='rejected',reason=ledger_error_code(error,prefix='control_ledger'),dispatched=False)

    @server.tool(name='flower_computer_plan_cancel',description='Stop this chat exact finite plan and its active original child action. Reads the retained terminal/ongoing state without activation, capture, replay or closing the app. An in-progress result may still need plan_status and exact original receipt recovery; unknown input is never marked released.')
    async def flower_computer_plan_cancel(plan_id:str,flower_origin:dict|None=None)->dict:
        try:
            task,ledger=await linked_task('flower_computer_plan_cancel',dict(plan_id=plan_id),flower_origin)
            return await lifetime.call(plan_manager.status,ledger.store,task,plan_id,cancel=True)
        except (OriginError,ControlError,ComputerBoundaryError,NativeInputError) as error:
            return dict(state='rejected',reason=error.code,dispatched=False)
        except sqlite3.Error as error:
            return dict(state='rejected',reason=ledger_error_code(error,prefix='control_ledger'),dispatched=False)

    @server.tool(name="flower_status", description="Report Computer channel readiness and its authorization boundary.")
    async def flower_status() -> dict:
        return await asyncio.to_thread(build_status)

    @server.tool(name="flower_computer_list_windows", description="List visible ordinary app windows for this chat, including untitled ordinary roots. Returns short-lived candidate IDs, title_empty facts, process names, bounds and same-enumeration omission/truncation diagnostics; no window content or foreground change.")
    async def flower_computer_list_windows(flower_origin: dict | None = None) -> dict:
        try:
            task, ledger = await linked_task("flower_computer_list_windows", {}, flower_origin)
            async with public_tool_call_async(ledger.store, task=task, channel="computer", tool="flower_computer_list_windows"):
                if windows is None:
                    raise WindowSelectionError("ordinary_window_selection_unavailable")
                listing_stop = threading.Event()
                listing = await lifetime.call(windows.list_windows, task,
                    include_diagnostics=True, include_untitled=True,
                    stopped=listing_stop.is_set, _on_host_stop=listing_stop.set)
                return {"state": "observed", "candidates": listing["windows"],
                        **{key: value for key, value in listing.items() if key != "windows"}}
        except (OriginError, ControlError, WindowSelectionError, ComputerBoundaryError) as error:
            return computer_result_to_wire({"state": "rejected", "reason": error.code,
                                            "dispatched": False})

    @server.tool(name="flower_computer_select_window", description="Select one just-listed ordinary app window for this chat, returning its exact Computer target. Does not activate or input.")
    async def flower_computer_select_window(candidate_id: str,
                                       flower_origin: dict | None = None) -> dict:
        try:
            task, ledger = await linked_task("flower_computer_select_window",
                               {"candidate_id": candidate_id}, flower_origin)
            async with public_tool_call_async(ledger.store, task=task, channel="computer", tool="flower_computer_select_window"):
                if windows is None:
                    raise WindowSelectionError("ordinary_window_selection_unavailable")
                selection_stop = threading.Event()
                if candidate_id.startswith("app-handoff:"):
                    identity = WindowIdentity(**await prepare(ledger.store.consume_window_handoff, task, candidate_id))
                    identity = await lifetime.call(windows.adopt_handoff, task, identity,
                        stopped=selection_stop.is_set, _on_host_stop=selection_stop.set)
                else:
                    identity = await lifetime.call(windows.select, task, candidate_id,
                        stopped=selection_stop.is_set, _on_host_stop=selection_stop.set)
                return {"state": "selected", "target": computer_target_to_wire(asdict(identity))}
        except (OriginError, ControlError, WindowSelectionError, ComputerBoundaryError) as error:
            return computer_result_to_wire({"state": "rejected", "reason": error.code,
                                            "dispatched": False})


    @server.tool(name="flower_computer_handoff_window", description="Issue one short-lived App handoff candidate for this chat's currently selected Computer window. Rechecks the exact process/window generation and refuses when nothing is selected or the window is gone. It does not activate, capture or input. The App channel must consume the candidate with flower_app_select_window and observe again; the token is single-use and expires in about 30 seconds.")
    async def flower_computer_handoff_window(flower_origin: dict | None = None) -> dict:
        try:
            task, ledger = await linked_task("flower_computer_handoff_window", {}, flower_origin)
            async with public_tool_call_async(ledger.store, task=task, channel="computer", tool="flower_computer_handoff_window"):
                if windows is None:
                    raise WindowSelectionError("ordinary_window_selection_unavailable")
                handoff_stop = threading.Event()
                identity = await lifetime.call(windows.selected_root, task,
                    stopped=handoff_stop.is_set, _on_host_stop=handoff_stop.set)
                token = await prepare(ledger.store.create_window_handoff, task, asdict(identity))
                return {"state": "handoff_ready", "app_candidate_id": token,
                        "target": computer_target_to_wire(asdict(identity))}
        except (OriginError, ControlError, WindowSelectionError, ComputerBoundaryError) as error:
            return computer_result_to_wire({"state": "rejected", "reason": error.code,
                                            "dispatched": False})


    @server.tool(name='flower_computer_desktop_observe',structured_output=False,description='Observe an isolated-window desktop composite without list/select_window. Each admitted window is captured/redacted independently; raw screen pixels are never read. Rasters are painted opaque: transparency, transient/unavailable windows and black areas may differ from the real screen; complete=false. A later input must freshly hit-test/focus-bind the actual desktop. Returns a fresh task-bound observation_id and PNG; coordinates use this returned image, including scaling and negative desktop origins. Window-locked observe remains independent. Protected/unknown surfaces and explicit manual regions are locally masked before PNG; masked areas cannot be operated. Pixels do not automatically discover password fields; structured Web/App and input password checks remain separate. Incomplete scene/secure desktop/Stop reject the frame. Conservative masks may also cover occluded protected windows. Requires the actual chat Origin and ordinary task policy; it creates no private-profile or administrator grant. Reusing action_id only re-reads the original still-current image; use a new action_id for a new screenshot.')
    async def flower_computer_desktop_observe(action_id:str,max_size:list[StrictInt]|None=None,
                                               flower_origin:dict|None=None):
        from flower_control.permissions import PermissionError
        import pywintypes
        arguments=dict(action_id=action_id)
        if max_size is not None:arguments['max_size']=max_size
        reference=None;replayed=False;published=False;task=None;ledger=None
        ownership=DesktopObservationOwnership()
        try:
            task,ledger=await linked_task('flower_computer_desktop_observe',arguments,flower_origin)
            async with public_tool_call_async(ledger.store,task=task,channel='computer',tool='flower_computer_desktop_observe'):
                stop=threading.Event()
                reference,frame,replayed=await lifetime.call(desktop_runtime.observe,ledger.store,
                    task=task,action_id=action_id,max_size=[1920,1080] if max_size is None else max_size,
                    raw_arguments=arguments,
                    ownership=ownership,
                    stopped=stop.is_set,_on_host_stop=stop.set)
                bounds=frame.image_space.source
                value=dict(state='observed',mode='desktop',observation_id=reference,replayed=replayed,
                    rendering='isolated_window_composite',complete=False,
                    visual_limitations='Window rasters are painted opaque; transient/unavailable windows may be absent or black. This is not a pixel-identical screen capture. Fresh live hit/focus checks are required for input.',
                    coordinate_space='returned_image',width=frame.image_space.image_size[0],
                    height=frame.image_space.image_size[1],
                    source_bounds=[bounds.left,bounds.top,bounds.right,bounds.bottom],
                    topology_revision=frame.state.topology.fingerprint,
                    masked_regions=len(frame.state.protected_rects),image_content_index=1,
                    ttl_seconds=60,dispatched=False)
                image=Image(data=frame.png,format='png')
                await lifetime.call(desktop_runtime.publish,ledger.store,task=task,
                    reference=reference,stopped=stop.is_set,_on_host_stop=stop.set)
                response=[value,image]
                published=True
                return response
        except (OriginError,ControlError,ComputerBoundaryError,NativeInputError,PermissionError) as error:
            return computer_result_to_wire(dict(state='rejected',reason=error.code,dispatched=False))
        except DesktopCaptureError as error:
            return dict(state='rejected',reason=str(error),dispatched=False)
        except (OSError,pywintypes.error):
            return dict(state='rejected',reason='desktop_capture_unavailable',dispatched=False)
        finally:
            if ownership.created and ownership.reference is not None and not published:
                # Local image ownership must disappear even when metadata I/O
                # fails. discard removes the exact row before its DB update.
                try:desktop_runtime.discard(ledger.store,task=task,reference=ownership.reference)
                except Exception:pass

    @server.tool(name='flower_computer_desktop_input',description='Use a fresh desktop observation without a preselected window: click/double_click/move/hover/scroll use returned_image x,y (or explicit physical_screen/normalized_1000_image); text/type and key/keypress bind the observed foreground/focus. activate uses an observed x,y only to choose the real surface for the normal first-takeover countdown; re-observe before business input. Protected/black points, changed surface/focus/topology, expired images and Stop reject. Internally binds the actual hit window and uses the existing Computer/High executor and shared physical locks. Does not widen private/admin permission. No cross-window drag/batch in this basic legacy route. New window-locked abilities stay available. Each action_id dispatches at most once; results keep receipts/unknown outcomes and request a new desktop observation, without returning internal window screenshots. Optional task_purpose (1-80 characters) and next_step (1-48) carry separate non-secret HUD purpose and step text; they never select targets or grant permission.')
    async def flower_computer_desktop_input(observation_id:str,command:str,arguments:dict,
                                           action_id:str,flower_origin:dict|None=None,
                                           task_purpose:str|None=None,next_step:str|None=None)->dict:
        from flower_control.window_registry import WindowSelectionError
        from flower_control.permissions import PermissionError
        from flower_control.drivers.high_helper import HighHelperError
        payload=dict(observation_id=observation_id,command=command,arguments=arguments,action_id=action_id)
        display={key:value for key,value in {'task_purpose':task_purpose,'next_step':next_step}.items()
                 if value is not None}
        payload.update(display)
        try:
            task,ledger=await linked_task('flower_computer_desktop_input',payload,flower_origin)
            async with public_tool_call_async(ledger.store,task=task,channel='computer',tool='flower_computer_desktop_input'):
                stop=threading.Event()
                def on_stop():
                    stop.set();desktop_runtime.stop_action(task,action_id)
                result=await lifetime.call(desktop_runtime.input,ledger.store,task=task,
                    observation_id=observation_id,command=command,arguments=arguments,action_id=action_id,
                    stopped=stop.is_set,_on_host_stop=on_stop,**display)
                return computer_result_to_wire(result)
        except (OriginError,ControlError,ComputerBoundaryError,NativeInputError,WindowSelectionError,
                PermissionError,HighHelperError) as error:
            return dict(state='rejected',reason=error.code,dispatched=False)
        except DesktopCaptureError as error:
            return dict(state='rejected',reason=str(error),dispatched=False)

    @server.tool(name='flower_computer_desktop_action_status',description='Read the original task-bound desktop input receipt without reselecting a window or dispatching. wait_seconds:0..30 optionally waits for a change; cancelling this metadata wait does not cancel the original action. Unknown outcomes stay unknown, including after window exit.')
    async def flower_computer_desktop_action_status(action_id:str,wait_seconds:StrictInt|None=None,
                                                    flower_origin:dict|None=None)->dict:
        payload=dict(action_id=action_id)
        if wait_seconds is not None:payload['wait_seconds']=wait_seconds
        try:
            task,ledger=await linked_task('flower_computer_desktop_action_status',payload,flower_origin)
            stop=threading.Event()
            return computer_result_to_wire(await lifetime.call(desktop_runtime.action_status,ledger.store,
                task=task,action_id=action_id,wait_seconds=wait_seconds,stopped=stop.is_set,_on_host_stop=stop.set))
        except (OriginError,ControlError,ComputerBoundaryError,NativeInputError) as error:
            return dict(state='rejected',reason=error.code,dispatched=False)

    @server.tool(name='flower_computer_desktop_cancel',description='Cancel only this chat exact desktop action_id and read its recorded state. Does not resume, replay, clear unknown release debt, close apps or affect window-mode actions with another ID.')
    async def flower_computer_desktop_cancel(action_id:str,flower_origin:dict|None=None)->dict:
        payload=dict(action_id=action_id)
        try:
            task,ledger=await linked_task('flower_computer_desktop_cancel',payload,flower_origin)
            return computer_result_to_wire(await lifetime.call(desktop_runtime.action_status,ledger.store,
                task=task,action_id=action_id,cancel=True))
        except (OriginError,ControlError,ComputerBoundaryError,NativeInputError) as error:
            return dict(state='rejected',reason=error.code,dispatched=False)

    @server.tool(name="flower_computer_cursor_position", description="Read the current global mouse position in physical_screen pixels without selecting a window. Returns virtual desktop bounds, monitor count and a topology revision. This is cursor/geometry metadata only: no image, window identity, title, observation_id, activation or input grant. Requires a trusted chat ticket, enabled channel, live task/Stop checks and the active ordinary Default desktop. Coordinates are a past snapshot, never authority to input; use the appropriate fresh window or desktop observation before control.")
    async def flower_computer_cursor_position(flower_origin: dict | None = None) -> dict:
        from flower_control.drivers.desktop_capture import DesktopCaptureError
        from flower_control.permissions import PermissionError
        import pywintypes
        try:
            task, ledger = await linked_task('flower_computer_cursor_position',{},flower_origin)
            async with public_tool_call_async(ledger.store,task=task,channel='computer',
                                             tool='flower_computer_cursor_position'):
                stop = threading.Event()
                return await lifetime.call(cursor_reader.read,ledger.store,trusted_task=task,
                    stopped=stop.is_set,_on_host_stop=stop.set)
        except (OriginError,ControlError,ComputerBoundaryError,NativeInputError,PermissionError) as error:
            return computer_result_to_wire(dict(state='rejected',reason=error.code,dispatched=False))
        except DesktopCaptureError as error:
            return computer_result_to_wire(dict(state='rejected',reason=str(error),dispatched=False))
        except (OSError,pywintypes.error):
            return computer_result_to_wire(dict(state='rejected',reason='desktop_cursor_unavailable',dispatched=False))

    @server.tool(name="flower_computer_origin_probe", description="Check this Computer MCP call's genuine host chat ticket without capturing or controlling the desktop.")
    async def flower_computer_origin_probe(flower_origin: dict | None = None) -> dict:
        expected = ("mcp__flower_computer__flower_computer_origin_probe",
                    "mcp__flower-computer__flower_computer_origin_probe")
        if not isinstance(flower_origin, dict) or flower_origin.get("tool_name") not in expected:
            return {"linked": False, "reason": "origin_missing_or_invalid"}
        try:
            task, ledger = await linked_task("flower_computer_origin_probe", {}, flower_origin)
            async with public_tool_call_async(ledger.store, task=task, channel="computer", tool="flower_computer_origin_probe"):
                return {"linked": True, "chat_ref": hashlib.sha256(task.encode()).hexdigest()[:16],
                        "private_grant": False}
        except (OriginError, ControlError) as error:
            return {"linked": False, "reason": error.code}

    @server.tool(name="flower_computer_artifact", structured_output=False, description="Retain one current observation by observation_id, or retrieve this chat's generated image by artifact_id with hash, current target/content permission and policy checks. Exactly one ID is required. Encrypted local storage is bounded; an artifact never grants input authority or makes an old observation fresh.")
    async def flower_computer_artifact(artifact_id: str | None = None, observation_id: str | None = None,
                                      flower_origin: dict | None = None):
        arguments = {}
        if artifact_id is not None:
            arguments["artifact_id"] = artifact_id
        if observation_id is not None:
            arguments["observation_id"] = observation_id
        try:
            if (artifact_id is None) == (observation_id is None):
                raise ComputerBoundaryError("invalid_artifact_request")
            task, ledger = await linked_task("flower_computer_artifact", arguments, flower_origin)
            from .control.local_artifacts import LocalArtifactStore
            artifacts = LocalArtifactStore(ledger.store.directory)
            def authorize(metadata):
                if metadata.get("channel") != "computer" or metadata.get("scope") != "one_selected_window":
                    return False
                payload = {"target": metadata["target"], "action_id": "artifact-read-" + uuid.uuid4().hex}
                active = require_runtime(task, "flower_computer_observe", payload)
                active.authorize_visual_return("flower_computer_observe", payload, task,
                    policy_revision=metadata.get("privacy_revision"))
                return True
            async with public_tool_call_async(ledger.store, task=task, channel="computer", tool="flower_computer_artifact"):
                if artifact_id is None:
                    with runtime_gate:
                        active = runtime if runtime is not None else runtimes.get(task)
                    if active is None:
                        raise ComputerBoundaryError("observation_unavailable")
                    with active._gate:
                        observed = active._observations.get(observation_id)
                        if not observed or observed["task"] != task or observed["expires"] <= active.store.clock():
                            raise ComputerBoundaryError("observation_unavailable")
                        descriptor = observed["capture_descriptor"]
                        import zlib
                        encoded = bmp_to_png(zlib.decompress(observed["capture_compressed"]))
                        metadata = {"channel": "computer", "scope": "one_selected_window", "target": asdict(observed["identity"]),
                            "source_bounds": asdict(observed["source_bounds"]), "width": observed["image_width"],
                            "height": observed["image_height"], "privacy_revision": descriptor.privacy_revision,
                            "capture_id": observation_id}
                    await asyncio.to_thread(authorize, metadata)
                    result = await asyncio.to_thread(artifacts.put, task, encoded, kind="image", metadata=metadata)
                    await asyncio.to_thread(authorize, metadata)
                    return result
                metadata, encoded = await asyncio.to_thread(artifacts.read, task, artifact_id, authorize=authorize)
                return [computer_result_to_wire({"state": "resolved", "input_authority_granted": False, **metadata}),
                        Image(data=encoded, format="png")]
        except (OriginError, ControlError, ComputerBoundaryError, NativeInputError, ValueError) as error:
            return {"state": "rejected", "dispatched": False, "reason": getattr(error, "code", "invalid_artifact_request")}

    @server.tool(name="flower_computer_chain", description=(
        "Local business-chain ledger for one cross-channel task. begin creates a run_id from a short goal; "
        "step appends channel/state/summary (web, app or computer) with optional parent_step_id; status reads "
        "the run and its ordered steps; finish records completed, partial, cancelled, failed or "
        "outcome_uncertain. Reusing the same step_id with identical facts is idempotent; a different payload "
        "or a step after finish is rejected. run_id/step_id only associate evidence: they grant no permission, "
        "do not prove business success and do not replace the original channel receipt. Unknown writes must "
        "remain outcome_uncertain and are never replayed by this tool. plan installs one immutable "
        "manifest of 1..64 steps {step_id,channel,action_id,depends_on?:[step_id],session_id?:string,dependency_requirement?:'verified'|'finished'}; "
        "Web requires session_id. Use normal public channel action IDs; matching queued/future calls "
        "wait until all parent actions have verified receipts by default. dependency_requirement:'finished' "
        "explicitly permits a completed, known and released parent without claiming business success. "
        "Planning never submits a channel call and must precede those calls. "
        "stop permanently stops only this plan and its derived actions, preserving in-flight/unknown "
        "receipts; use a new run for new work. attach links a task-owned generated artifact_id to an "
        "existing recorded step_id using local integrity facts, without returning content. export "
        "returns a bounded privacy-filtered chain summary as JSON, writing no file. Detailed export "
        "uses section:'steps'|'artifacts'|'plan'|'members', limit:1..32 and after from next_after; "
        "members also requires the planned step_id. Pages are live views, not frozen snapshots. "
        "Counts cover all records; truncated and next_after identify remaining details."))
    async def flower_computer_chain(command: str, run_id: str | None = None,
                                    step_id: str | None = None,
                                    parent_step_id: str | None = None,
                                    goal: str | None = None,
                                    channel: str | None = None,
                                    state: str | None = None,
                                    summary: str | None = None,
                                    steps: list[dict] | None = None,
                                    artifact_id: str | None = None,
                                    section: str | None = None,
                                    after: str | None = None,
                                    limit: int | None = None,
                                    flower_origin: dict | None = None) -> dict:
        if command not in {"begin", "step", "status", "finish", "plan", "stop", "attach", "export"}:
            return {"state": "rejected", "dispatched": False,
                    "reason": "business_chain_command_invalid",
                    "grants_authorization": False}
        payload = {"command": command}
        for field, value in (("run_id", run_id), ("step_id", step_id),
                             ("parent_step_id", parent_step_id), ("goal", goal),
                             ("channel", channel), ("state", state), ("summary", summary),
                             ("steps", steps), ("artifact_id", artifact_id),
                             ("section", section), ("after", after), ("limit", limit)):
            if value is not None:
                payload[field] = value
        try:
            task, ledger = await linked_task("flower_computer_chain", payload, flower_origin)
            from flower_control.privacy import redact_sensitive_values
            async with public_tool_call_async(ledger.store, task=task,
                                              channel="computer", tool="flower_computer_chain"):
                fields = {
                    "begin": {"goal"},
                    "step": {"run_id", "step_id", "parent_step_id", "channel", "state", "summary"},
                    "finish": {"run_id", "state", "summary"},
                    "status": {"run_id"}, "export": {"run_id", "section", "after", "limit", "step_id"},
                    "plan": {"run_id", "steps"}, "stop": {"run_id"},
                    "attach": {"run_id", "step_id", "artifact_id"}}
                if set(payload) - {"command"} - fields[command]:
                    raise ComputerBoundaryError("business_chain_" + command + "_fields_invalid")
                if command == "plan":
                    return redact_sensitive_values(await asyncio.to_thread(ledger.store.plan_business_run, task, run_id, steps))
                if command == "stop":
                    return redact_sensitive_values(await asyncio.to_thread(ledger.store.stop_business_run, task, run_id))
                if command == "attach":
                    return redact_sensitive_values(await asyncio.to_thread(ledger.store.attach_business_artifact, task, run_id, step_id, artifact_id))
                if command == "export" and section is not None:
                    result = await asyncio.to_thread(ledger.store.business_run_page, task, run_id, section,
                        after=after, limit=32 if limit is None else limit, step_id=step_id)
                    return redact_sensitive_values({"format": "flower-business-chain-v1", **result})
                if command == "export" and any(value is not None for value in (after, limit, step_id)):
                    raise ComputerBoundaryError("business_export_section_required")
                if command == "begin":
                    if run_id is not None or step_id is not None or summary is not None:
                        raise ComputerBoundaryError("business_chain_begin_fields_invalid")
                    goal = redact_sensitive_values({"goal": goal or ""})["goal"]
                    return redact_sensitive_values(await asyncio.to_thread(
                        ledger.store.create_business_run, task, goal))
                if command == "step":
                    if run_id is None or channel is None or state is None or summary is None or goal is not None:
                        raise ComputerBoundaryError("business_chain_step_fields_invalid")
                    summary = redact_sensitive_values({"summary": summary})["summary"]
                    return redact_sensitive_values(await asyncio.to_thread(
                        ledger.store.append_business_step, task, run_id,
                        channel, state, summary,
                        parent_step_id=parent_step_id, step_id=step_id))
                if command == "finish":
                    if run_id is None or state is None or summary is None or goal is not None or channel is not None:
                        raise ComputerBoundaryError("business_chain_finish_fields_invalid")
                    summary = redact_sensitive_values({"summary": summary})["summary"]
                    return redact_sensitive_values(await asyncio.to_thread(
                        ledger.store.finish_business_run, task, run_id, state, summary))
                if run_id is None or any(value is not None for value in
                                         (goal, channel, state, summary, step_id, parent_step_id)):
                    raise ComputerBoundaryError("business_chain_status_fields_invalid")
                result = redact_sensitive_values(await asyncio.to_thread(
                    ledger.store.business_run_status, task, run_id))
                return {"format": "flower-business-chain-v1", **result} if command == "export" else result
        except (OriginError, ControlError, ComputerBoundaryError, ValueError) as error:
            return {"state": "rejected", "dispatched": False,
                    "reason": getattr(error, "code", "business_chain_unavailable"),
                    "grants_authorization": False}

    @server.tool(name="flower_computer_tasks", description="Read this chat's finite control actions, pause/release/unknown state and result receipts without capture, dispatch or replay. Continue with a new observation and new action_id; cancel/resume use their explicit tools.")
    async def flower_computer_tasks(flower_origin: dict | None = None) -> dict:
        try:
            task, ledger = await linked_task("flower_computer_tasks", {}, flower_origin)
            async with public_tool_call_async(ledger.store, task=task, channel="computer", tool="flower_computer_tasks"):
                from flower_control.privacy import redact_sensitive_values
                result = await asyncio.to_thread(ledger.store.task_control_status, task)
                with runtime_gate:
                    active = runtime if runtime is not None else runtimes.get(task)
                result["control_cycle"] = _task_control_cycle_status(task, active, desktop_runtime)
                return redact_sensitive_values(result)
        except (OriginError, ControlError, ComputerBoundaryError) as error:
            return {"state": "rejected", "dispatched": False, "reason": error.code}

    @server.tool(name="flower_computer_jev_policy", description="Read or disable/enable configured decision API use (Perplexity/Jev; legacy tool name) for this chat. enabled=false prevents new and late service decisions; true is only an opt-out reset and cannot enable a new provider or bypass the machine setting. Returns retained metadata usage, never candidate content. No window capture or activation.")
    async def flower_computer_jev_policy(enabled: bool | None = None, flower_origin: dict | None = None) -> dict:
        arguments = {} if enabled is None else {"enabled": enabled}
        try:
            task, ledger = await linked_task("flower_computer_jev_policy", arguments, flower_origin)
            async with public_tool_call_async(ledger.store, task=task, channel="computer", tool="flower_computer_jev_policy"):
                result = await asyncio.to_thread(ledger.store.task_jev_policy, task, enabled=enabled)
                from flower_control.control.task_service_report import chat_jev_summary
                result["usage"] = await asyncio.to_thread(chat_jev_summary, ledger.store, task)
                return result
        except (ComputerBoundaryError, OriginError, ControlError) as error:
            return {"state": "rejected", "dispatched": False, "reason": error.code}

    @server.tool(name="flower_computer_observe", structured_output=False, description="Capture one approved exact window and return an actual MCP image plus observation metadata. Optional crop:[left,top,right,bottom] crops original image pixels by default. Explicit crop_format:xywh accepts legacy [x,y,width,height]; crop_format:ltrb makes the current format explicit. A format requires crop; bounds are checked without clamping; original_image_box always uses left/top/right/bottom. Crop does not change default input coordinates. This returned observation also supports explicit coordinate_space:'returned_image' for actual returned PNG pixels or 'normalized_1000_image' for integer 0..999 coordinates on that image, including crop and resizing; use only with its own observation_id, and never rebind a different crop to it; max_size:[width,height] shrinks without upscaling; legacy integer max_size:256..4096 limits the longest side with the same mapping. The image includes original_image_box and original_pixels_per_display_pixel: map displayed coordinates back before input. Default input uses original physical client/window pixels; click_region and choose_region require original image boxes. Crop is presentation, not automatic privacy masking. Optional goal_hint adds same-window UIA click candidates and Jev/local selection; canvas targets may require host visual regions. Optional next_step (1-48 characters, no controls or secrets) is the separate current-step display text; task_purpose independently supplies the non-secret business purpose (1-80 characters) without target selection or Jev. Computer observations can create/update the persistent task HUD; confirmed finish/release_phase closes its display. Display text grants nothing. Requires trusted host context; no desktop-wide capture.")
    async def flower_computer_observe(target: dict, action_id: str,
                                      goal_hint: str | None = None,
                                      next_step: str | None = None,
                                      flower_origin: dict | None = None,
                                      crop: list[int] | None = None,
                                      max_size: StrictInt | list[int] | None = None,
                                      crop_format: Literal["ltrb", "xywh"] | None = None,
                                      task_purpose: str | None = None):
        payload = {"target": target, "action_id": action_id}
        view_options = {}
        if crop is not None:
            view_options["crop"] = payload["crop"] = crop
        if crop_format is not None:
            view_options["crop_format"] = payload["crop_format"] = crop_format
        if max_size is not None:
            view_options["max_size"] = payload["max_size"] = max_size
        if goal_hint is not None:
            payload["goal_hint"] = goal_hint
        if next_step is not None:
            payload["next_step"] = next_step
        if task_purpose is not None:
            payload['task_purpose'] = task_purpose
        return await linked_call("flower_computer_observe",
                                 payload,
                                 flower_origin, "observe", target, action_id,
                                 visual_key="image",
                                 **view_options,
                                 **({"goal_hint": goal_hint} if goal_hint is not None else {}),
                                 **({"next_step": next_step} if next_step is not None else {}),
                                 **({"task_purpose": task_purpose} if task_purpose is not None else {}))

    @server.tool(name="flower_computer_activate", structured_output=False, description="Once per foreground phase, request bounded restoration and activation of the approved exact window. Ordinary windows may receive one balanced Alt tap to assist activation; the exact Shell desktop uses one Show Desktop request. Activation reports auxiliary input events and release state separately from business input. On success, return a fresh MCP image and observation_id ready for input, so no separate observe call is needed. Windows may still refuse activation; foreground takeover stops the attempt without reclaiming focus. Fill task_purpose with the non-secret business purpose (1-80 characters, display only, no Jev), and next_step with the specific current step rather than click/wait (1-48 characters, no control characters) is display text for the task HUD and grants nothing.")
    async def flower_computer_activate(target: dict, restore_minimized: bool,
                                       action_id: str,
                                       next_step: str | None = None,
                                       flower_origin: dict | None = None, task_purpose: str | None = None):
        payload = {"target": target, "restore_minimized": restore_minimized,
                   "action_id": action_id}
        if next_step is not None:
            payload["next_step"] = next_step
        if task_purpose is not None:
            payload['task_purpose'] = task_purpose
        return await linked_call("flower_computer_activate", payload, flower_origin,
                                 "activate", target, restore_minimized, action_id,
                                 visual_key="image",
                                 **({"next_step": next_step} if next_step is not None else {}),
                                 **({"task_purpose": task_purpose} if task_purpose is not None else {}))

    @server.tool(name="flower_computer_input", structured_output=False, description="Drag duration_ms omitted uses bounded automatic motion; explicit 0 stays immediate, positive integers keep the requested total time. Point drag defaults to axis-preserving direct motion for sliders; path_mode=free opts into a free curve. Optional avoid_rects [l,t,r,b] use the same coordinate_space and restrict the existing authorized action with normal clearance; drag_footprint [l,t,r,b] relative to the grab hotspot and uncertainty_px are always physical pixels. Explicit path keeps ordered waypoints. Automatic drag is supported inside short sequence with timed playback; other existing held/timed sequence limits remain. Explicit coordinate_space:'returned_image' or 'normalized_1000_image' maps point actions through the exact returned observe PNG and crop/resize binding; normalized values are integers 0..999. Legacy coordinate_space:'returned_image_pixels' uses the same bound PNG and additionally accepts finite fractional pixel coordinates from 0 through width-1 / height-1, floored locally to source pixels. The newer image and normalized spellings remain integer-only. These require a successfully returned image for that observation, never a model-supplied mapping; default physical client/window coordinates stay unchanged. Click, double_click, drag and mouse_hold default to button:left when omitted; button:right or button:middle remain explicit. Send one observed text, click, click_region, double_click, drag, key chord, bounded key_mouse, raw move_relative or bounded scroll action to the foreground target. click_candidate uses {candidate_id} from the same observed frame, with target-region freshness rechecked before input. choose_region uses arguments {goal_hint:string,regions:[{box:[left,top,right,bottom],label:string},...]}, with 2-8 visible candidate boxes localized by the host from this observation's original MCP PNG. Jev receives short candidate labels, selects one, and Flower directly clicks it within this same input request after the normal freshness and Stop checks. Use deterministic batch for already decided mechanical steps. Batch also accepts arguments {actions:[{type:'click'|'move'|'scroll'|'text'|'key'|'drag'|'hold',...},...]} with 1-16 flat legacy action dictionaries, as an alternative to steps, never mixed. Each item may instead use the old local-cu action discriminator (never both type and action). Added names: double_click, right_click, middle_click, type (literal text). key may use key:'ctrl+shift+s' instead of keys, never both. action:'scroll' may use clicks:-10..10 (nonzero, positive up, 120 units per notch; default 1 if no axis fields), never mixed with dx/dy. No legacy motion duration or wait is implied. These use current original physical client/window coordinates unless an explicit coordinate_space is supplied, not old session image coordinates. Hold and drag use duration seconds 0.01..3 (default 0.5, whole milliseconds); all existing total hold, event, coordinate and scroll bounds still apply. No wait/repeat/nested batch in this adapter; re-observe when selection cannot proceed. wait uses {condition:'image_changed'|'image_unchanged'|'image_stable'|'window_closed'|'new_window'|'elapsed',timeout_ms:1..30000} to inspect a later state without replaying input or holding global keyboard/mouse. elapsed restores a bounded dwell: wait for that duration, then capture once; no intermediate sampling, input or business-success assertion. Closed/replaced targets, Stop, revocation and call expiry cannot complete the dwell. Admission still requires an existing fresh observation (current Computer TTL 60s); a running read-only wait consumes that snapshot without extending its expiry or writable refs. Only this valid wait gets enough call lifetime for its condition deadline plus final fresh capture; target/permission/cancellation checks remain live. Visual waits optionally accept roi:[left,top,right,bottom] in original captured pixels, roi_units:'pixels'|'normalized_1000' (normalized_1000 requires roi; lower edges floor and upper edges ceil), and threshold:0..255 for mean absolute grayscale difference. Omitted threshold preserves exact digest matching; image_changed means delta>threshold, image_unchanged means delta<=threshold, and image_stable needs consecutive fresh adjacent samples within threshold for stable_ms (default 300). These visual predicates never prove task success. All regions stay inside the original selected-window capture; backend or ROI geometry changes reject. For the first mouse/keyboard action in a task, call flower_computer_activate first: it shows a cancelable two-second countdown, pauses while the user is active, and requests the exact target in foreground after the user is idle and returns a fresh image in that same call. Input before first activation returns first_takeover_requires_activation with next_action; it does not run a countdown or send business input. Ordinary switching interrupts the current input suffix and releases held input. After a fresh observation, the next actual input request may restore the exact approved target once; window events never reactivate it. Explicit Stop stays paused until an explicit resume, and unknown writes are never replayed. Single-action click_region uses arguments {box:[left,top,right,bottom],button:'left'}; the half-open box is in the original MCP PNG pixel size for this observation, not pixels after UI display scaling. Flower checks the entire box against that captured image and client area, calculates its center locally, and then follows the normal click safety and visual recheck path. A sequence uses arguments {steps:[{command,arguments,expect}]} with 2-8 short steps; expect is capture_available, image_changed or image_unchanged. Every step gets a new capture and safety check; new windows, focus loss, cancellation, target change or uncertain dispatch stop the suffix. Image conditions only compare pixels and never prove business success. Text up to 8192 UTF-16 units is split into short balanced batches for a single action; CRLF/CR/LF send actual ENTER and Tab sends the TAB key, so editors may apply indentation and form fields may move focus. move/hover use {x,y,coordinate_space?}. Drag also accepts {path:[[x,y],...],button,keys?,duration_ms?} with 2-64 waypoints. click accepts count:1..3 and middle button. batch uses {steps:[{command,arguments},...]} with 1-32 explicit mechanical steps, at most 8192 finite plans / 16384 events / 3000ms total held duration with the shared bounded work admission; it checks the target and Stop between native segments and returns one final observation without per-step screenshots or Jev requests. batch excludes nested batch/sequence, waits and window layout; use new observation on a focus/window change. WIN/LWIN/RWIN, NUM0-9 and F1-24 are accepted key names; each sequence text step may use multiple safe navigation segments with at most 128 native events in total. Click/double_click/scroll x/y and drag from_x/from_y/to_x/to_y default to physical client pixels. For click, double_click, scroll, drag, mouse_hold or key_mouse with button and x/y, optional arguments.coordinate_space:'window' uses physical pixels from the selected window top-left, including titlebar and frame; window_origin/window_size are returned by observe. Explicit coordinate_space:'normalized_1000_client' or 'normalized_1000_window' uses integer points 0..999 relative to the observed full client or outer window, respectively, with floor(value*physical_size/1000); this is independent of displayed image crop/resize and applies no extra DPI scaling. Unanchored 'normalized_1000' is rejected. Relative deltas and image-region boxes do not use these units. Coordinates remain inside that selected window; arbitrary screen coordinates are rejected. A titlebar drag that moves the window can interrupt on geometry_changed; take a new observation before continuing. window_move uses {dx,dy} from the observed physical window outer bounds; window_resize uses {width,height} and keeps the observed top-left. These fixed layout actions require a normal, non-minimized, non-maximized window and the installed broker, including for Medium targets; resize also requires a resizable frame. The requested outer rectangle must fit the observed monitor work-area union, including another monitor or continuous areas across monitors. Each layout action calls SetWindowPos at most once without activation or z-order changes. layout_result separately returns requested_rect, observed_rect, dispatch_attempted, call_returned, api_succeeded, dispatched and requested_reached; API true alone never proves an exact rectangle or business success. The synchronous call runs in one owned worker; semantic_executor and semantic_executor_exited report that actual worker and its confirmed exit. A returned call with requested_reached:false reports application-adjusted geometry; a returned API false reports the failed call. Both can continue with a fresh observation. Missing call completion or unconfirmed worker exit remains uncertain and isolated. No keyboard/mouse events are sent by layout. An attempted or uncertain layout invalidates old observations; a returned new image and observation must be used for the next action. Layout actions are excluded from short sequences and are never replayed after an uncertain result. Click accepts optional count:1..3 (default 1); double_click always uses two clicks. Click, double_click and drag accept left, right or middle button; click_region supports left or right. Use text for literal content. Letter key chords send physical keyboard input and can open Chinese IME candidates; observe input_state for the selected target; on the current IME, English and CapsLock type directly while Chinese may compose candidates. CTRL+SPACE toggles this IME between direct and candidate mode; re-observe to confirm a deliberate switch. Physical letter dispatch alone does not prove committed text. Text value readback excludes uncommitted IME text. Key arguments use up to five distinct key names, case-insensitively, such as ['CTRL','S'], ['ENTER'] or ['F5']; legacy CONTROL/RETURN/ESCAPE/SUPER/PAGE_UP/PAGE_DOWN/DEL/BACK_SPACE/PRIOR/NEXT/PRINT_SCREEN/CAPS_LOCK/NUM_LOCK/CMD aliases and MENU are accepted, and aliases cannot repeat the same physical key. Key accepts optional duration_ms:0..3000 (0 is the original balanced tap). A positive duration keeps the chord down within this one call and always attempts its exact recorded ups on interruption. key_mouse uses {keys,duration_ms:1..3000,dx,dy} and sends the raw relative move while the keys are down. Optional button:'left'|'right'|'middle' requires client x/y, holds that button at the same time, and permits keys:[]. mouse_hold uses {x,y,button:'left'|'right'|'middle',duration_ms:1..3000,keys?} without movement; optional keys uses the same chord limits. move_relative uses {dx,dy}; each raw delta is an integer in -2048..2048, not both zero. Windows pointer speed and acceleration can change the physical distance; no game-specific raw-input compatibility is promised. Drag accepts optional keys and duration_ms:0..3000 for simultaneous keys and timed movement. Explicitly timed plans remain single actions; a short sequence may include an automatic drag within its existing total held-time bound. No cross-call holds. Before keyboard input, Flower can interrupt a confirmed active composition in the same target focus with one balanced Escape, counted as ime_preparation; it never reads composition text or changes layout/open status. Unknown IME state remains unknown. Persistent physical holds wait at most 300ms without releasing user keys; a continuing conflict ends this phase. Scroll delta is signed wheel units, up to 1200; optional axis:'horizontal'|'vertical' keeps vertical as the default. Alternatively scroll accepts {x,y,dx,dy}: dx/dy are signed Win32 wheel units in -1200..1200, at least one nonzero; do not mix them with delta/axis. The single bounded plan moves once, then emits vertical dy followed by horizontal dx (zero axes omitted), not simultaneous hardware input. Positive dy scrolls up; positive dx scrolls right. A sequence returns up to four ordered MCP image samples; additional original images can be retained as same-chat encrypted artifacts, an explicit sent prefix, undispatched suffix and input release state; never retry an uncertain action. Fill task_purpose with the non-secret business purpose (1-80 characters, display only, no Jev), and next_step with the specific current step rather than click/wait (1-48 characters, no control characters, keep it free of secrets) is display text for the task HUD and grants nothing.")
    async def flower_computer_input(target: dict, observation_id: str, command: str,
                                    arguments: dict, action_id: str,
                                    next_step: str | None = None,
                                    flower_origin: dict | None = None, task_purpose: str | None = None):
        payload = {"target": target, "observation_id": observation_id,
                   "command": command, "arguments": arguments, "action_id": action_id}
        if next_step is not None:
            payload["next_step"] = next_step
        if task_purpose is not None:
            payload['task_purpose'] = task_purpose
        return await linked_call("flower_computer_input", payload, flower_origin,
                                 "input", target, observation_id, command, arguments,
                                 action_id, visual_key="image" if command == "wait" else "visual_recheck",
                                 **({"next_step": next_step} if next_step is not None else {}),
                                 **({"task_purpose": task_purpose} if task_purpose is not None else {}))

    @server.tool(name="flower_computer_action_status", description="Read an existing Computer action receipt without dispatching again. Optional wait_seconds:0..30 waits for a ledger status change or terminal state; omitted/0 keeps the original immediate read. Host cancellation stops only this wait; task Stop/cancellation returns its last authorized receipt, which may be stale. The initial native release status/recovery check occurs once, never per poll; polling reads the ledger and does not replay input or clear unknown effects. Positive waits cannot combine with result_report. Optional result_report:{result_observation_id,outcome} records the host's visual judgement of a fresh observe image taken after that action. outcome is completed, not_completed or uncertain. Return host_visual_result separately; it does not verify the business goal, alter the original receipt or clear unknown effects/release. Time and image digest come only from this chat's stored observation; do not supply them. An input visual_recheck without an observation_id cannot be reported.")
    async def flower_computer_action_status(action_id: str,
                                            flower_origin: dict | None = None,
                                            result_report: dict | None = None,
                                            ctx: Context = None, wait_seconds: StrictInt | None = None) -> dict:
        payload = {"action_id": action_id}
        report_present = result_report is not None
        wait_present = wait_seconds is not None
        if ctx is not None and (not report_present or not wait_present):
            try:
                request = ctx.request_context.request
            except ValueError:
                request = None
            if request is not None:
                # Preserve an explicit JSON null in the signed call payload.
                report_present = report_present or "result_report" in (request.params.arguments or {})
                wait_present = wait_present or "wait_seconds" in (request.params.arguments or {})
        if report_present:
            payload["result_report"] = result_report
        if wait_present:
            payload['wait_seconds'] = wait_seconds
        if wait_seconds:
            stop = threading.Event()
            return await linked_call("flower_computer_action_status", payload, flower_origin,
                "action_status", action_id, result_report=result_report, wait_seconds=wait_seconds,
                stopped=stop.is_set, _on_host_stop=stop.set)
        options = {'wait_seconds':wait_seconds} if wait_present else {}
        return await linked_call("flower_computer_action_status", payload, flower_origin,
                                 "action_status", action_id, result_report=result_report, **options)

    @server.tool(name="flower_computer_cancel", description="Request cancellation of this task's Computer action; in-flight input may be partial or uncertain.")
    async def flower_computer_cancel(action_id: str,
                                     flower_origin: dict | None = None) -> dict:
        return await linked_call("flower_computer_cancel", {"action_id": action_id},
                                 flower_origin, "cancel", action_id)

    @server.tool(name="flower_computer_pause", description="Pause Computer input on the selected window while independent work continues. mode='release_phase' yields an idle UI stage before backend work, closes HUD and releases safe target claims while preserving task, authorization and first-takeover state; it never clears Stop or reclaims focus. Fresh observation is required on continuation. mode='handoff' accepts optional kind (12 fixed blocker classes, default unknown_blocker; classification never authorizes sensitive actions) and optional message (1-240 characters, no controls/secrets), pauses all Flower channels in this chat for human/login steps, including capture and Jev. Confirm input_release:'released' before asking via the host popup; pending requires release/status checks. Wait for the user's explicit answer. After explicit continue call mode='resume' then freshly observe; resume sends no activation/input. On task completion mode='finish' drains calls, checks release, closes this task's indicator and clears temporary observations/capture sessions, preserving apps, other tasks, historical receipts and uncertain outcomes. Confirm task_finished; pending requires cleanup/retry. Metadata modes handoff_status/handoff_complete/handoff_cancel/handoff_extend require the exact request_id and never resume capture or input. handoff_status optionally accepts wait_seconds:0..30; omitted/null/0 returns immediately, positive waits for state or extension changes. Host cancellation stops only this metadata wait; timeout never completes or extends the request. A revoked task returns its last authorized metadata when already waiting. Only explicit resume after the human answer can continue control.")
    async def flower_computer_pause(mode: str | None = None,
                                    flower_origin: dict | None = None,
                                      message: str | None = None, request_id: str | None = None,
                                      timeout_seconds: int | None = None,
                                      wait_seconds: StrictInt | None = None, ctx: Context = None,
                                      kind: HumanHandoffKind | None = None) -> dict:
        if kind is not None:
            try:
                if mode != "handoff":
                    raise ControlError("invalid_handoff_kind")
                human_handoff_kind(kind)
            except ControlError as error:
                return {"state": "rejected", "dispatched": False, "reason": error.code}
        payload = {} if mode is None else {"mode": mode}
        if kind is not None:
            payload["kind"] = kind
        if message is not None:
            payload["message"] = message
        if request_id is not None:
            payload["request_id"] = request_id
        if timeout_seconds is not None:
            payload["timeout_seconds"] = timeout_seconds
        wait_present = wait_seconds is not None
        if not wait_present and ctx is not None:
            try:request=ctx.request_context.request
            except ValueError:request=None
            if request is not None:wait_present='wait_seconds' in (request.params.arguments or {})
        if wait_present:
            payload['wait_seconds']=wait_seconds
            if mode!='handoff_status' or (wait_seconds is not None and not 0<=wait_seconds<=30):
                return {'state':'rejected','dispatched':False,'reason':'invalid_handoff_wait'}
        if mode in {"handoff_status", "handoff_complete", "handoff_cancel", "handoff_extend"}:
            try:
                task, ledger = await linked_task("flower_computer_pause", payload, flower_origin)
                from .drivers.human_handoff import handoff_metadata_request, wait_handoff_status
                async with public_tool_call_async(ledger.store, task=task, channel="computer", tool="flower_computer_pause"):
                    if mode=='handoff_status' and wait_seconds:
                        return await wait_handoff_status(ledger.store,task,request_id,wait_seconds,timeout_seconds)
                    return await asyncio.to_thread(handoff_metadata_request, ledger.store, task, mode, request_id, timeout_seconds)
            except (OriginError, ControlError, ValueError) as error:
                return {"state": "rejected", "dispatched": False, "reason": getattr(error, "code", "invalid_handoff_request")}
        if request_id is not None:
            return {"state": "rejected", "dispatched": False, "reason": "invalid_handoff_request"}
        if mode in {'finish','release_phase'}:
            try:
                task,ledger=await linked_task('flower_computer_pause',payload,flower_origin)
                # Match Runtime.pause's validation before any global cleanup.
                if message is not None:raise ComputerBoundaryError('invalid_handoff_message')
                if timeout_seconds is not None:raise ComputerBoundaryError('invalid_handoff_timeout')
                async with public_tool_call_async(ledger.store,task=task,channel='computer',tool='flower_computer_pause'):
                    plan_drain=await lifetime.call(plan_manager.stop_task,ledger.store,task)
                    if not plan_drain['drained']:
                        return dict(state='plan_cleanup_pending',dispatched=False)
                    drained=await lifetime.call(desktop_runtime.drain_task,task,mode)
                    if drained['state']!='desktop_calls_drained':return drained
                    outcome=await prepared_call(task,'flower_computer_pause',payload,'pause',mode,
                        **({'message':message} if message is not None else {}),
                        **({'timeout_seconds':timeout_seconds} if timeout_seconds is not None else {}))
                    if outcome.get('state') in {'task_finished','phase_released'}:
                        desktop_runtime.end_drain(task,drained['epoch'])
                        plan_manager.end_drain(ledger.store,task,plan_drain['epoch'])
                    if outcome.get('state') == 'task_finished':
                        await asyncio.to_thread(ledger.store.record_event, "computer_channel_finished", task=task, details={})
                    return outcome
            except (OriginError,ControlError,ComputerBoundaryError) as error:
                return dict(state='rejected',reason=error.code,dispatched=False)
        return await linked_call("flower_computer_pause", payload,
                                 flower_origin, "pause", mode,
                                   **({"message": message} if message is not None else {}),
                                   **({"timeout_seconds": timeout_seconds} if timeout_seconds is not None else {}),
                                   **({"kind": kind} if kind is not None else {}))



    from .mcp_argument_adapter import preserve_literal_string_arguments
    preserve_literal_string_arguments(server)
    from .antigravity_adapter import install_antigravity_adapter
    install_antigravity_adapter(server, "flower-computer")
    return server


server = create_computer_server()


if __name__ == "__main__":
    # Native input checks this again per batch.  A failed process setting only
    # leaves input unavailable; status and read-only refusal remain usable.
    awareness = ctypes.windll.user32.SetProcessDpiAwarenessContext
    awareness.argtypes = [ctypes.c_void_p]
    awareness.restype = ctypes.c_bool
    awareness(ctypes.c_void_p(-4))
    create_computer_server(fixture_target=FixtureTarget.from_environment("computer_tk")).run(
        transport="stdio")
