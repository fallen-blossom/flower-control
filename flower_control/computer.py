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

from mcp.server.fastmcp import Context, FastMCP, Image

from flower_control._status import loaded_source, status_details
from flower_control.authorization.hook_bridge import (live_ledger,
                                                      state_directory)
from flower_control.mcp_origin import consume_origin_async, ledger_error_code
from flower_control.authorization.origin import OriginError
from flower_control.control.state import ControlError, StateStore
from flower_control.control.jev_runtime import client_factory as jev_client_factory, enabled as jev_enabled
from flower_control.control.jev_diagnostics import public_tool_call_async
from flower_control.drivers.computer_capture import CaptureError
from flower_control.drivers.computer_capture_session import ComputerCaptureSession
from flower_control.drivers.computer_mcp import (ComputerAuthorization,
                                                 ComputerBoundaryError,
                                                 ComputerRuntime,
                                                 diagnose_value_error)
from flower_control.drivers.computer_native import NativeInputError
from flower_control.drivers.computer_native import WindowIdentity
from flower_control.drivers.computer_host_lifetime import ComputerHostLifetime
from flower_control.drivers.high_helper import HighHelperClient, HighHelperError
from flower_control.drivers.computer_png import bmp_to_png
from flower_control.local_target import FixtureTarget, LocalTargetError
from flower_control.target_wire import (computer_result_to_wire as _target_result_to_wire,
                                        computer_target_from_wire,
                                        computer_target_to_wire)
from flower_control.window_registry import WindowRegistry, WindowSelectionError
from flower_control.browser_window_policy import BrowserWindowPolicy


def computer_result_to_wire(value):
    """Keep lossless identities and explain known Computer failure receipts."""
    return _target_result_to_wire(value)


def create_computer_server(runtime: ComputerRuntime | None = None,
                           *, fixture_target: FixtureTarget | None = None,
                           high_client_factory=HighHelperClient) -> FastMCP:
    lifetime = ComputerHostLifetime()
    @asynccontextmanager
    async def host_lifespan(_server):
        try:
            yield lifetime
        finally:
            try:
                await lifetime.close()
            finally:
                for active in ([runtime] if runtime is not None else tuple(runtimes.values())):
                    await asyncio.to_thread(active.close_capture_sessions)
    server = FastMCP("flower-computer", lifespan=host_lifespan)
    source = loaded_source(__file__)
    if runtime is not None and fixture_target is not None:
        raise ValueError("choose one trusted adapter")
    if fixture_target is not None and fixture_target.kind != "computer_tk":
        raise ValueError("wrong fixture kind")
    runtimes: dict[str, ComputerRuntime] = {}
    runtime_gate = threading.RLock()
    windows = (WindowRegistry(BrowserWindowPolicy(state_directory()),
                             window_binder=lambda request, current: require_runtime(
                                 request.task, "flower_computer_action_status", {}).bind_selected_window(request, current))
               if runtime is None and fixture_target is None else None)

    def require_runtime(task: str, tool: str, arguments: dict) -> ComputerRuntime:
        if runtime is not None:
            return runtime
        if tool in ("flower_computer_action_status", "flower_computer_cancel"):
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
                    return ComputerAuthorization(task, identity, store.clock() + 30,
                                                 capture_allowed=True, input_allowed=True,
                                                 target_scope=(access.target_scope if access else None),
                                                 shared_resource=(access.shared_resource if access else None))

                active = ComputerRuntime(store, resolve_call,
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
        return await consume_origin_async(live_ledger, tool_name=origin["tool_name"],
                                          arguments=arguments, origin=origin)

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
        if (tool == "flower_computer_input" and
                arguments.get("command") == "sequence" and
                isinstance(outcome.get("result"), dict) and
                type(outcome["result"].get("step_observations")) is list):
            observations = outcome["result"]["step_observations"]
            safe_result = {**outcome["result"], "step_observations": []}
            safe_outcome = {**outcome, "result": safe_result}
            images = []
            try:
                if len(observations) > 3:
                    raise ValueError("too many sequence images")
                for entry in observations:
                    visual = entry["image"]
                    encoded = bmp_to_png(base64.b64decode(visual["base64"],
                                                          validate=True))
                    images.append(Image(data=encoded, format="png"))
                    safe_result["step_observations"].append({
                        "index": entry["index"],
                        "image": {**{key: value for key, value in visual.items()
                                     if key != "base64"},
                                  "format": "png", "encoded_bytes": len(encoded),
                                  "image_content_index": len(images)}})
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
                        if (not isinstance(screenshot, dict) or
                                type(screenshot.get("base64")) is not str):
                            raise ComputerBoundaryError(
                                observed.get("reason", "followup_capture_unavailable"))
                        followup_bytes = bmp_to_png(base64.b64decode(
                            screenshot["base64"], validate=True))
                        await asyncio.to_thread(
                            active.authorize_visual_return, "flower_computer_observe",
                            {"target": followup_target, "action_id": followup_action}, task)
                        images.append(Image(data=followup_bytes, format="png"))
                        safe_result["followup_observation"] = {
                            "target": computer_target_to_wire(followup_target),
                            "observation_id": detail.get("observation_id"),
                            "image": {**{key: value for key, value in screenshot.items()
                                         if key != "base64"}, "format": "png",
                                      "encoded_bytes": len(followup_bytes),
                                      "image_content_index": len(images)}}
                    except Exception as error:
                        safe_result["followup_capture"] = (
                            "unavailable:" + getattr(error, "code", type(error).__name__))
                await asyncio.to_thread(active.authorize_visual_return, tool,
                                        native, task)
            except (ValueError, KeyError, TypeError, binascii.Error,
                    ComputerBoundaryError, ControlError, NativeInputError) as error:
                reason = getattr(error, "code", "sequence_visual_return_unavailable")
            except Exception:
                reason = "sequence_visual_return_unavailable"
            else:
                return ([computer_result_to_wire(safe_outcome), *images] if images
                        else computer_result_to_wire(safe_outcome))
            dispatched = bool(safe_result.get("dispatched"))
            return {"state": "outcome_uncertain" if dispatched else "rejected",
                    "dispatched": dispatched,
                    "reason": reason, "visual_return_suppressed": True,
                    "sent_prefix": safe_result.get("sent_prefix", []),
                    "undispatched_suffix": safe_result.get("undispatched_suffix", []),
                    "input_release": safe_result.get("input_release"),
                    "unbound_followup_windows": safe_result.get(
                        "unbound_followup_windows", []),
                    "followup_capture": safe_result.get("followup_capture")}
        if visual_key is None or not isinstance(outcome.get("result"), dict) or (
                isinstance(outcome.get("result"), dict) and
                visual_key not in outcome["result"]):
            # An actively foregrounded owned dialog ends the old suffix. Its
            # new image is a separate read, under the original trusted task.
            followups = outcome.get("followup_targets")
            if (tool == "flower_computer_input" and outcome.get("reason") == "new_window_detected" and
                    outcome.get("receipt", {}).get("state") != "outcome_uncertain" and
                    type(followups) is list and len(followups) == 1):
                action = "followup-" + uuid.uuid4().hex
                observed = await call(active.observe, followups[0], action, trusted_task=task)
                detail = observed.get("result")
                screenshot = detail.get("image") if isinstance(detail, dict) else None
                try:
                    if not isinstance(screenshot, dict):
                        raise ComputerBoundaryError(observed.get("reason", "followup_capture_unavailable"))
                    image_bytes = bmp_to_png(base64.b64decode(screenshot["base64"], validate=True))
                    await asyncio.to_thread(active.authorize_visual_return, "flower_computer_observe",
                                            {"target": followups[0], "action_id": action}, task)
                except Exception as error:
                    outcome["followup_capture"] = "unavailable:" + getattr(error, "code", type(error).__name__)
                else:
                    outcome["followup_observation"] = {
                        "target": computer_target_to_wire(followups[0]),
                        "observation_id": detail.get("observation_id"),
                        "image": {**{k: v for k, v in screenshot.items() if k != "base64"},
                                  "format": "png", "encoded_bytes": len(image_bytes), "image_content_index": 1}}
                    return [computer_result_to_wire(outcome), Image(data=image_bytes, format="png")]
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
                        if (isinstance(screenshot, dict) and
                                type(screenshot.get("base64")) is str):
                            recovered_bytes = bmp_to_png(base64.b64decode(
                                screenshot["base64"], validate=True))
                            await asyncio.to_thread(
                                active.authorize_visual_return, "flower_computer_observe",
                                {"target": root, "action_id": recovery_action}, task)
                            recovery = {
                                "target": computer_target_to_wire(root),
                                "observation_id": detail.get("observation_id"),
                                "image": {**{key: value for key, value in screenshot.items()
                                             if key != "base64"}, "format": "png",
                                          "encoded_bytes": len(recovered_bytes),
                                          "image_content_index": 1}}
                            if closed_after_input:
                                outcome_result["recovery_observation"] = recovery
                            else:
                                outcome["recovery_observation"] = recovery
                            return [computer_result_to_wire(outcome),
                                    Image(data=recovered_bytes, format="png")]
                except Exception as error:
                    recovery_status = (
                        "unavailable:" + getattr(error, "code", type(error).__name__))
                    if closed_after_input:
                        outcome_result["recovery_capture"] = recovery_status
                    else:
                        outcome["recovery_capture"] = recovery_status
            return computer_result_to_wire(outcome)
        visual = outcome["result"].get(visual_key)
        if not isinstance(visual, dict) or type(visual.get("base64")) is not str:
            return computer_result_to_wire(outcome)
        try:
            image_bytes = bmp_to_png(base64.b64decode(visual["base64"], validate=True))
        except (ValueError, binascii.Error):
            dispatched = bool(outcome["result"].get("dispatched"))
            return {"state": "outcome_uncertain" if dispatched else "rejected",
                    "dispatched": dispatched,
                    "reason": "capture_encoding_invalid"}
        # Conversion can take time. Recheck task, target and visual scope at the
        # last point before handing any pixels to the MCP client.
        try:
            await asyncio.to_thread(active.authorize_visual_return, tool,
                                    native, task)
        except (ComputerBoundaryError, ControlError, NativeInputError) as error:
            dispatched = bool(outcome["result"].get("dispatched"))
            return {"state": "outcome_uncertain" if dispatched else "rejected",
                    "dispatched": dispatched, "reason": error.code,
                    "visual_return_suppressed": True}
        except Exception:
            dispatched = bool(outcome["result"].get("dispatched"))
            return {"state": "outcome_uncertain" if dispatched else "rejected",
                    "dispatched": dispatched, "reason": "visual_return_check_failed",
                    "visual_return_suppressed": True}
        metadata = {**outcome, "result": {**outcome["result"],
                                          visual_key: {**{key: value for key, value
                                                           in visual.items() if key != "base64"},
                                                       "format": "png",
                                                       "encoded_bytes": len(image_bytes),
                                                       "image_content_index": 1}}}
        images = [Image(data=image_bytes, format="png")]
        # A click may reveal a confirmation dialog. Observe one exact owned
        # follow-up inside this same MCP call so the host can decide from the
        # new image without another round trip or guessed dialog script.
        followups = outcome["result"].get("followup_targets")
        if (tool == "flower_computer_input" and outcome["result"].get("dispatched")
                and type(followups) is list and len(followups) == 1
                and type(followups[0]) is dict):
            followup_target = followups[0]
            followup_action = "followup-" + uuid.uuid4().hex
            observed = await call(active.observe, followup_target, followup_action,
                                  trusted_task=task)
            next_result = observed.get("result")
            next_image = next_result.get("image") if isinstance(next_result, dict) else None
            if (isinstance(next_image, dict) and
                    type(next_image.get("base64")) is str):
                try:
                    followup_bytes = bmp_to_png(base64.b64decode(
                        next_image["base64"], validate=True))
                    await asyncio.to_thread(
                        active.authorize_visual_return, "flower_computer_observe",
                        {"target": followup_target, "action_id": followup_action}, task)
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
                        "image": {**{key: value for key, value in next_image.items()
                                     if key != "base64"},
                                  "format": "png", "encoded_bytes": len(followup_bytes),
                                  "image_content_index": 2}}
                    images.append(Image(data=followup_bytes, format="png"))
            else:
                metadata["result"]["followup_capture"] = "unavailable"
        return [computer_result_to_wire(metadata), *images]

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

    @server.tool(name="flower_computer_observe", structured_output=False, description="Capture one approved exact window and return a visible MCP image plus observation metadata. Optional goal_hint also generates same-window UIA click candidates and lets Jev/local selection choose a candidate_id. Canvas/image-only targets may require host visual regions. Optional next_step (1-48 characters, no control characters, keep it free of secrets) is shown on the task HUD as \"下一步：\" so the user can read what this caller intends to do next; it is display text only and never grants authority or proves a step happened. Requires trusted host context; no desktop-wide capture.")
    async def flower_computer_observe(target: dict, action_id: str,
                                      goal_hint: str | None = None,
                                      next_step: str | None = None,
                                      flower_origin: dict | None = None):
        payload = {"target": target, "action_id": action_id}
        if goal_hint is not None:
            payload["goal_hint"] = goal_hint
        if next_step is not None:
            payload["next_step"] = next_step
        return await linked_call("flower_computer_observe",
                                 payload,
                                 flower_origin, "observe", target, action_id,
                                 visual_key="image",
                                 **({"goal_hint": goal_hint} if goal_hint is not None else {}),
                                 **({"next_step": next_step} if next_step is not None else {}))

    @server.tool(name="flower_computer_activate", structured_output=False, description="Once per foreground phase, request bounded restoration and activation of the approved exact window. Ordinary windows may receive one balanced Alt tap to assist activation; the exact Shell desktop uses one Show Desktop request. Activation reports auxiliary input events and release state separately from business input. On success, return a fresh MCP image and observation_id ready for input, so no separate observe call is needed. Windows may still refuse activation; foreground takeover stops the attempt without reclaiming focus. Optional next_step (1-48 characters, no control characters) is display text for the task HUD and grants nothing.")
    async def flower_computer_activate(target: dict, restore_minimized: bool,
                                       action_id: str,
                                       next_step: str | None = None,
                                       flower_origin: dict | None = None):
        payload = {"target": target, "restore_minimized": restore_minimized,
                   "action_id": action_id}
        if next_step is not None:
            payload["next_step"] = next_step
        return await linked_call("flower_computer_activate", payload, flower_origin,
                                 "activate", target, restore_minimized, action_id,
                                 visual_key="image",
                                 **({"next_step": next_step} if next_step is not None else {}))

    @server.tool(name="flower_computer_input", structured_output=False, description="Send one observed text, click, click_region, double_click, drag, key chord, bounded key_mouse, raw move_relative or vertical scroll action to the foreground target. click_candidate uses {candidate_id} from the same observed frame, with target-region freshness rechecked before input. choose_region uses arguments {goal_hint:string,regions:[{box:[left,top,right,bottom],label:string},...]}, with 2-8 visible candidate boxes localized by the host from this observation's original MCP PNG. Jev receives short candidate labels, selects one, and Flower directly clicks it within this same input request after the normal freshness and Stop checks. Use deterministic batch for already decided mechanical steps; re-observe when selection cannot proceed. wait uses {condition:'image_changed'|'image_unchanged'|'window_closed'|'new_window',timeout_ms:1..5000} to inspect a later state without replaying input or holding global keyboard/mouse. Computer input activates its selected target once if necessary, then respects user takeover. Single-action click_region uses arguments {box:[left,top,right,bottom],button:'left'}; the half-open box is in the original MCP PNG pixel size for this observation, not pixels after UI display scaling. Flower checks the entire box against that captured image and client area, calculates its center locally, and then follows the normal click safety and visual recheck path. A sequence uses arguments {steps:[{command,arguments,expect}]} with 2-3 short steps; expect is capture_available, image_changed or image_unchanged. Every step gets a new capture and safety check; new windows, focus loss, cancellation, target change or uncertain dispatch stop the suffix. Image conditions only compare pixels and never prove business success. Text up to 8192 UTF-16 units is split into short balanced batches for a single action; CRLF/CR/LF send actual ENTER and Tab sends the TAB key, so editors may apply indentation and form fields may move focus. move/hover use {x,y,coordinate_space?}. Drag also accepts {path:[[x,y],...],button,keys?,duration_ms?} with 2-16 waypoints. click accepts count:1..3 and middle button. batch uses {steps:[{command,arguments},...]} with 1-32 explicit mechanical steps, at most 131 finite plans / 16384 events / 2000ms total held duration; it checks the target and Stop between native segments and returns one final observation without per-step screenshots or Jev requests. batch excludes nested batch/sequence, waits and window layout; use new observation on a focus/window change. WIN/LWIN/RWIN, NUM0-9 and F1-24 are accepted key names; each sequence text step is at most one 64-unit batch. Click/double_click/scroll x/y and drag from_x/from_y/to_x/to_y default to physical client pixels. For click, double_click, scroll, drag, mouse_hold or key_mouse with button and x/y, optional arguments.coordinate_space:'window' uses physical pixels from the selected window top-left, including titlebar and frame; window_origin/window_size are returned by observe. Coordinates remain inside that selected window; arbitrary screen coordinates are rejected. A titlebar drag that moves the window can interrupt on geometry_changed; take a new observation before continuing. window_move uses {dx,dy} from the observed physical window outer bounds; window_resize uses {width,height} and keeps the observed top-left. These fixed layout actions require a normal, non-minimized, non-maximized window and the installed broker, including for Medium targets; resize also requires a resizable frame. The requested outer rectangle must fit the observed monitor work-area union, including another monitor or continuous areas across monitors. Each layout action calls SetWindowPos at most once without activation or z-order changes. layout_result separately returns requested_rect, observed_rect, dispatch_attempted, call_returned, api_succeeded, dispatched and requested_reached; API true alone never proves an exact rectangle or business success. The synchronous call runs in one owned worker; semantic_executor and semantic_executor_exited report that actual worker and its confirmed exit. A returned call with requested_reached:false reports application-adjusted geometry; a returned API false reports the failed call. Both can continue with a fresh observation. Missing call completion or unconfirmed worker exit remains uncertain and isolated. No keyboard/mouse events are sent by layout. An attempted or uncertain layout invalidates old observations; a returned new image and observation must be used for the next action. Layout actions are excluded from short sequences and are never replayed after an uncertain result. Double_click, drag and click_region support left or right button. Use text for literal content. Letter key chords send physical keyboard input and can open Chinese IME candidates; observe input_state for the selected target; on the current IME, English and CapsLock type directly while Chinese may compose candidates. CTRL+SPACE toggles this IME between direct and candidate mode; re-observe to confirm a deliberate switch. Physical letter dispatch alone does not prove committed text. Text value readback excludes uncommitted IME text. Key arguments use up to four uppercase names, such as ['CTRL','S'], ['ENTER'] or ['F5']. Key accepts optional duration_ms:0..2000 (0 is the original balanced tap). A positive duration keeps the chord down within this one call and always attempts its exact recorded ups on interruption. key_mouse uses {keys,duration_ms:1..2000,dx,dy} and sends the raw relative move while the keys are down. Optional button:'left'|'right'|'middle' requires client x/y, holds that button at the same time, and permits keys:[]. mouse_hold uses {x,y,button:'left'|'right'|'middle',duration_ms:1..2000,keys?} without movement; optional keys uses the same chord limits. move_relative uses {dx,dy}; each raw delta is an integer in -2048..2048, not both zero. Windows pointer speed and acceleration can change the physical distance; no game-specific raw-input compatibility is promised. Drag accepts optional keys and duration_ms:0..2000 for simultaneous keys and timed movement. Timed plans are single actions, excluded from short sequences; no cross-call holds. Before keyboard input, Flower can interrupt a confirmed active composition in the same target focus with one balanced Escape, counted as ime_preparation; it never reads composition text or changes layout/open status. Unknown IME state remains unknown. Persistent physical holds wait at most 300ms without releasing user keys; a continuing conflict ends this phase. Scroll delta is signed wheel units, up to 1200; optional axis:'horizontal'|'vertical' keeps vertical as the default. A sequence returns up to three ordered MCP images, an explicit sent prefix, undispatched suffix and input release state; never retry an uncertain action. Optional next_step (1-48 characters, no control characters, keep it free of secrets) is display text for the task HUD and grants nothing.")
    async def flower_computer_input(target: dict, observation_id: str, command: str,
                                    arguments: dict, action_id: str,
                                    next_step: str | None = None,
                                    flower_origin: dict | None = None):
        payload = {"target": target, "observation_id": observation_id,
                   "command": command, "arguments": arguments, "action_id": action_id}
        if next_step is not None:
            payload["next_step"] = next_step
        return await linked_call("flower_computer_input", payload, flower_origin,
                                 "input", target, observation_id, command, arguments,
                                 action_id, visual_key="visual_recheck",
                                 **({"next_step": next_step} if next_step is not None else {}))

    @server.tool(name="flower_computer_action_status", description="Read an existing Computer action receipt without dispatching again. Optional result_report:{result_observation_id,outcome} records the host's visual judgement of a fresh observe image taken after that action. outcome is completed, not_completed or uncertain. Return host_visual_result separately; it does not verify the business goal, alter the original receipt or clear unknown effects/release. Time and image digest come only from this chat's stored observation; do not supply them. An input visual_recheck without an observation_id cannot be reported.")
    async def flower_computer_action_status(action_id: str,
                                            flower_origin: dict | None = None,
                                            result_report: dict | None = None,
                                            ctx: Context = None) -> dict:
        payload = {"action_id": action_id}
        report_present = result_report is not None
        if not report_present and ctx is not None:
            try:
                request = ctx.request_context.request
            except ValueError:
                request = None
            if request is not None:
                # Preserve an explicit JSON null in the signed call payload.
                report_present = "result_report" in (request.params.arguments or {})
        if report_present:
            payload["result_report"] = result_report
        return await linked_call("flower_computer_action_status",
                                 payload, flower_origin, "action_status", action_id,
                                 result_report=result_report)

    @server.tool(name="flower_computer_cancel", description="Request cancellation of this task's Computer action; in-flight input may be partial or uncertain.")
    async def flower_computer_cancel(action_id: str,
                                     flower_origin: dict | None = None) -> dict:
        return await linked_call("flower_computer_cancel", {"action_id": action_id},
                                 flower_origin, "cancel", action_id)

    @server.tool(name="flower_computer_pause", description="Pause Computer input on the selected window, cancelling its queued actions while independent work continues. After an explicit chat request to continue that same selected window, call with mode='resume', then obtain a fresh observation. mode='finish' closes this task's persistent indicator when work is complete without closing the target or sending input. Resume sends no activation or input and does not clear uncertain outcomes, quarantine or unconfirmed release.")
    async def flower_computer_pause(mode: str | None = None,
                                    flower_origin: dict | None = None) -> dict:
        payload = {} if mode is None else {"mode": mode}
        return await linked_call("flower_computer_pause", payload,
                                 flower_origin, "pause", mode)

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
