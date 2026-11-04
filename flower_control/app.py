"""App MCP entrypoint with task-bound ordinary window selection."""
from __future__ import annotations

import asyncio
import ctypes
import hashlib
import inspect
import math
import threading
import uuid
from contextlib import asynccontextmanager, AsyncExitStack
from contextvars import ContextVar
from functools import wraps
import sqlite3
import sys
from pathlib import Path
from dataclasses import asdict

from mcp.server.fastmcp import FastMCP, Image

from flower_control._status import loaded_source, status_details
from flower_control.authorization.hook_bridge import (live_ledger,
                                                      state_directory)
from flower_control.mcp_origin import consume_origin_async, ledger_error_code
from flower_control.authorization.origin import OriginError
from flower_control.control.state import ControlError, StateStore, HumanHandoffKind, human_handoff_kind
from flower_control.control.jev_runtime import client_factory as jev_client_factory, enabled as jev_enabled
from flower_control.control.jev_diagnostics import public_tool_call_async, JevUsage, jev_context, _public_tool_event
from flower_control.control.native import process_creation_filetime
from flower_control.drivers.app_control import (AppAuthorization, AppBoundaryError,
                                                AppRuntime)
from flower_control.drivers.app_host_lifetime import AppHostLifetime, AppLaunchCall
from flower_control.drivers.computer_capture import CaptureError
from flower_control.drivers.computer_mcp import (ComputerAuthorization,
                                                 ComputerBoundaryError,
                                                 ComputerRuntime, valid_next_step, valid_task_purpose)
from flower_control.drivers.computer_native import NativeInputError
from flower_control.drivers.computer_native import WindowIdentity, bind_window
from flower_control.drivers.high_helper import ActiveHelperClient, HighHelperError
from flower_control.drivers.app_screenshot import (authorize_app_screenshot_return,
                                                   capture_app_screenshot)
from flower_control.drivers.app_lifecycle import (AppLifecycleError, launch_application,
                                                request_normal_close, safe_launch_diagnostic)
from flower_control.drivers.app_recording import record_window, app_record_options, recording_scope_statement, AppRecordingError
from flower_control.drivers.app_sequence import capture_sequence, sequence_options,FrameGroupOwnership
from flower_control.drivers.app_region_recording import RegionRecorder,region_options


from flower_control.control.arbitration import wait_for_turn_sync
from flower_control.control.worker_call import command_hash
from flower_control.control.native import FOREGROUND_INPUT_RESOURCE
from flower_control.browser_window_policy import BrowserWindowPolicy
from flower_control.local_target import FixtureTarget, LocalTargetError, _process_image_and_liveness
from flower_control.target_wire import (app_result_to_wire as _app_result_to_wire, app_target_from_wire,
                                        app_target_to_wire)
from flower_control.drivers.app_contracts import AppPostcondition, operation_receipt
from flower_control.drivers.app_errors import explain_app_error as explain_error
from flower_control.window_registry import WindowRegistry, WindowSelectionError
from flower_control.security_prompt_continuation import LaunchContinuationRegistry
from flower_control.drivers.app_contracts import POSTCONDITION_SCHEMA
from typing import Annotated
from pydantic import WithJsonSchema

_continuation_schema = {**POSTCONDITION_SCHEMA, "oneOf": [*POSTCONDITION_SCHEMA["oneOf"], {
    "type": "object", "properties": {
        "semantic_action": {"const": "security_prompt_allow"},
        "launch_action_id": {"type": "string", "minLength": 1, "maxLength": 128}},
    "required": ["semantic_action", "launch_action_id"], "additionalProperties": False}]}
AppContinuationPostcondition = Annotated[dict, WithJsonSchema(_continuation_schema)]

def _local_call_lifetime(tool, payload):
    """Only an explicit valid recording gets its bounded capture/export time."""
    if tool=='flower_app_observe' and payload.get('view')=='record_region' and payload.get('content') is True:
        try:_,duration,_,_,_=region_options(payload.get('limits'))
        except AppRecordingError:return 30
        return max(30,duration+45)
    if tool == "flower_app_observe" and payload.get("view") == "record" and payload.get("content") is True:
        try:
            duration, _, _, _, _ = app_record_options(payload.get("limits"))
        except AppRecordingError:
            return 30
        return max(30, duration + 25)
    if tool == "flower_app_observe" and payload.get("view") == "frames" and payload.get("content") is True:
        try:
            count, duration_ms, _, _ = sequence_options(payload.get("limits"))
        except AppRecordingError:
            return 30
        return max(30, duration_ms / 1000 + count * 5 + 10)
    return 30

def _explain_app_result(value: object) -> object:
    """Enrich only known reason codes, preserving all original result fields."""
    if type(value) is dict:
        result = {key: _explain_app_result(item) for key, item in value.items()}
        error_record = ("state" in result or result.get("linked") is False)
        if error_record and "reason" in result and "explanation" not in result:
            explanation = explain_error(result.get("reason"), state=result.get("state"),
                                        dispatched=result.get("dispatched"))
            if explanation is not None:
                result["explanation"] = explanation
        return result
    if type(value) is list:
        return [_explain_app_result(item) for item in value]
    return value


def app_result_to_wire(value: object) -> object:
    """Serialize App target IDs and attach static known-error explanations."""
    return _app_result_to_wire(_explain_app_result(value))


class AppActivationRuntime(ComputerRuntime):
    """Keep delegated activation receipts in the public App action namespace."""

    ACTION_CHANNEL = "app"
    PERSISTENT_INDICATOR = False
    COMPUTER_INPUT_RUN = False

    def stop_for_task(self, task: str) -> None:
        with self._host_gate:
            for key, event in self._stops.items():
                if key.startswith(task + ":app:"):
                    event.set()


def create_app_server(runtime: AppRuntime | None = None,
                      *, fixture_target: FixtureTarget | None = None,
                      admin_client_factory=None) -> FastMCP:
    high_bridges = {}
    lifetime = AppHostLifetime()
    security_continuations = LaunchContinuationRegistry()
    region_recorder=RegionRecorder()
    if admin_client_factory is None:
        admin_client_factory = lambda: ActiveHelperClient(channel="flower-app")
    @asynccontextmanager
    async def lifespan(_server):
        phase_consumer.start()
        try:
            yield {}
        finally:
            from .drivers.host_cleanup import close_host_resources
            from .drivers.human_handoff import close_handoffs
            def steps():
                yield "security_prompt_continuations", lambda: asyncio.to_thread(security_continuations.close)
                yield "idle_phase_release", phase_consumer.close
                yield "executions", lifetime.close
                yield "region_recorder", lambda: asyncio.to_thread(region_recorder.close)
                # Snapshot each collection after in-flight preparation drains;
                # workers can finish registering resources during that wait.
                for active in ([runtime] if runtime is not None else tuple(runtimes.values())):
                    yield "handoffs", lambda active=active: asyncio.to_thread(close_handoffs, active.store)
                for bridge in tuple(high_bridges.values()):
                    yield "high_bridge", lambda bridge=bridge: asyncio.to_thread(bridge.close)
                for activator in tuple(activators.values()):
                    yield "capture_sessions", lambda activator=activator: asyncio.to_thread(activator.close_capture_sessions)
            await close_host_resources("app", steps())
    from flower_control.tool_guidance import task_method_instructions
    server = FastMCP("flower-app", lifespan=lifespan,
                     instructions=task_method_instructions("flower-app"))
    source = loaded_source(__file__)
    if runtime is not None and fixture_target is not None:
        raise ValueError("choose one trusted adapter")
    if fixture_target is not None and fixture_target.kind != "app_wpf":
        raise ValueError("wrong fixture kind")
    runtimes: dict[str, AppRuntime] = {}
    trace_starts: dict[str, dict] = {}
    activators: dict[str, ComputerRuntime] = {}
    runtime_gate = threading.RLock()
    from .control.host_phase import PhaseConsumer
    def phase_runtimes():
        with runtime_gate:
            return ([runtime] if runtime is not None else list(runtimes.values())) + list(activators.values())
    phase_consumer = PhaseConsumer(phase_runtimes, busy=lifetime.busy)
    launch_owners: dict[str, str] = {}
    selection_owners: dict[str, set[str]] = {}
    parent_contexts: dict[str, dict] = {}
    public_stack = ContextVar("flower_app_public_stack", default=None)
    public_ledger = ContextVar("flower_app_public_ledger", default=None)

    def public_handler(handler):
        """Keep the consumed-origin measurement open through wire preparation.

        Each public handler owns its stack; linked_task opens the measurement
        only after successful consumption. Internal continuations never count.
        wraps preserves the public signature used by FastMCP.
        """
        @wraps(handler)
        async def measured(*args, **kwargs):
            async with AsyncExitStack() as stack:
                token = public_stack.set(stack)
                ledger_token = public_ledger.set(None)
                from flower_control.drivers.app_stage import display_next_step, display_task_purpose, execution_mode
                display_token = display_next_step.set(None)
                purpose_token = display_task_purpose.set(None)
                mode_token = execution_mode.set("foreground")
                try:
                    bound_arguments = inspect.signature(handler).bind(*args, **kwargs).arguments
                    mode = bound_arguments.get('execution_mode')
                    if mode not in (None, "foreground", "must_background"):
                        return {"state": "rejected", "dispatched": False, "reason": "invalid_execution_mode"}
                    execution_mode.set(mode or "foreground")
                    note = valid_next_step(bound_arguments.get('next_step'))
                    display_next_step.set(note)
                    display_task_purpose.set(valid_task_purpose(bound_arguments.get('task_purpose')))
                    return await handler(*args, **kwargs)
                finally:
                    display_next_step.reset(display_token)
                    display_task_purpose.reset(purpose_token)
                    execution_mode.reset(mode_token)
                    public_stack.reset(token)
                    public_ledger.reset(ledger_token)
        return measured

    async def begin_public_call(task, tool, ledger, arguments):
        stack = public_stack.get()
        if stack is None:
            raise RuntimeError("app_public_boundary_missing")
        await stack.enter_async_context(lifetime.task_call(task,
            finish=tool == "flower_app_pause" and arguments.get("mode") in {"finish", "release_phase"},
            priority=tool == "flower_app_pause" and arguments.get("mode") in {
                None, "pause", "handoff", "handoff_status", "handoff_complete", "handoff_cancel", "handoff_extend"},
            diagnostic=tool in {"flower_app_action_status", "flower_app_cancel"}))
        await stack.enter_async_context(public_tool_call_async(ledger.store,
                            task=task, channel="app", tool=tool))
        from .control.business_calls import public_call, public_action_key
        action = arguments.get('action_id')
        if tool in {'flower_app_action_status', 'flower_app_cancel'}:
            action = None
        if action is None and type(arguments.get('launch')) is dict:
            action = arguments['launch'].get('action_id')
        key = public_action_key(task, 'app', action) if type(action) is str else None
        await stack.enter_async_context(public_call(ledger.store, task, key))
        public_ledger.set(ledger)
        # A new control attempt starts a fresh App phase on the same chat task.
        # Metadata/status calls and pause/finish do not reopen it.
        if (tool in {"flower_app_select_window", "flower_app_activate", "flower_app_observe",
                     "flower_app_set_value", "flower_app_invoke", "flower_app_set_toggle",
                     "flower_app_select_item"}
                or tool == "flower_app_list_windows" and arguments.get("launch") is not None):
            await asyncio.to_thread(ledger.store.record_event, "app_control_attempted", task=task,
                                    details={"tool": tool})

    def linked_store():
        ledger = public_ledger.get()
        if ledger is None:
            raise RuntimeError("app_public_boundary_missing")
        return ledger.store

    async def prepare(method, *args, **kwargs):
        try:
            return await lifetime.call(method, *args, **kwargs)
        except sqlite3.Error as error:
            raise ControlError(ledger_error_code(error, prefix="control_ledger")) from None

    def high_bridge(task):
        from flower_control.drivers.app_high import AppHighBridge
        with runtime_gate:
            bridge = high_bridges.get(task)
            if bridge is None:
                directory = state_directory()
                bridge = AppHighBridge(StateStore(directory, jev_enabled=lambda: jev_enabled(directory)), task)
                high_bridges[task] = bridge
            return bridge

    def window_binder(request, current):
        from flower_control.drivers.high_helper import HighTarget, HighHelperError
        physical = HighTarget.inspect(request.hwnd, request.pid)
        if physical.facts["Created"] != request.created or not current():
            raise WindowSelectionError("candidate_changed")
        if physical.facts["Integrity"] <= 8192:
            return bind_window(request.hwnd)
        bridge = high_bridge(request.task)
        try:
            with bridge.route({"pid": request.pid, "hwnd": request.hwnd,
                               "process_start_filetime": request.created}, "bind") as route:
                if route is None:
                    return bind_window(request.hwnd)
                owner = bridge.store.register_owner(request.task)
                with runtime_gate:
                    selection_owners.setdefault(request.task, set()).add(owner)
                _, identity = bridge.bind(route, owner, scope=request.access.target_scope,
                    shared_resource=request.access.shared_resource, current=current,
                    authorized_until=request.expires_at)
                return identity
        except (HighHelperError, ControlError) as error:
            raise WindowSelectionError(error.code) from error

    windows = (WindowRegistry(BrowserWindowPolicy(state_directory()), window_binder=window_binder)
               if runtime is None and fixture_target is None else None)

    def resolve_app_identity(task: str, target: dict | None = None, *, stopped=None) -> WindowIdentity:
        assert windows is not None
        if target is None:
            return windows.resolve(task, stopped=stopped)
        root = windows.resolve(task, stopped=stopped)
        selected = (root if target["hwnd"] == root.hwnd
                    else windows.bind_owned_window(task, root, target["hwnd"], stopped=stopped))
        created = process_creation_filetime(selected.pid, expected_iso=selected.process_created)
        if stopped is not None and stopped():
            raise WindowSelectionError("window_selection_cancelled")
        if target != {"pid": selected.pid, "hwnd": selected.hwnd,
                      "process_start_filetime": created}:
            raise AppBoundaryError("target_changed")
        return selected

    async def window_call(method, *args):
        stopped = threading.Event()
        return await prepare(method, *args, stopped=stopped.is_set,
                                   _on_host_stop=stopped.set)

    def app_identity_target(identity: WindowIdentity) -> dict:
        return {"pid": identity.pid, "hwnd": identity.hwnd,
                "process_start_filetime": process_creation_filetime(identity.pid,
                    expected_iso=identity.process_created)}

    def parent_context(task: str, root: WindowIdentity, child: dict, active: AppRuntime) -> dict:
        with runtime_gate:
            now = active.store.clock()
            for stale in [key for key, item in parent_contexts.items() if item["expires"] <= now]:
                parent_contexts.pop(stale)
            if len(parent_contexts) >= 128:
                parent_contexts.pop(next(iter(parent_contexts)))
            token = "appparent:" + uuid.uuid4().hex
            parent_contexts[token] = {"task": task, "root": root, "child": child, "expires": now + 300}
        return {"context_id": token, "target": app_identity_target(root), "expires_in_seconds": 300}

    def is_fresh_observation(value: dict) -> bool:
        result = value.get("result")
        return (type(result) is dict and result.get("state") == "observed"
                and type(value.get("observation_id")) is str)

    async def fresh_window_context(task: str, active: AppRuntime, root: WindowIdentity,
                                   original_target: dict, outcome: dict) -> dict:
        """Preserve the action prefix and offer freshly approved window state."""
        if (windows is None or outcome.get("replayed") or original_target["hwnd"] == root.hwnd
                and outcome.get("result", {}).get("state") == "closed"):
            return outcome
        result = outcome.get("result")
        diagnostic_only = (outcome.get("receipt", {}).get("state") == "outcome_uncertain"
                           or type(result) is dict and result.get("state") == "outcome_uncertain")
        try:
            if await prepare(windows.selected_root, task) != root:
                raise AppBoundaryError("selected_parent_changed")
            root_target = await prepare(app_identity_target, root)
            if original_target["hwnd"] != root.hwnd:
                outcome["parent_context"] = await prepare(parent_context, task, root, original_target, active)
                hidden_completed = (outcome.get("result", {}).get("target_lifecycle") == "transient_target_hidden"
                    and not __import__("win32gui").IsWindowVisible(original_target["hwnd"]))
                if not __import__("win32gui").IsWindow(original_target["hwnd"]) or hidden_completed:
                    observation = await call(active.observe, root_target, content=True,
                        action_id="parent-after-dialog-" + uuid.uuid4().hex, trusted_task=task)
                    outcome["continuation"] = {"state": "parent_ready" if is_fresh_observation(observation)
                                               else "needs_observation", "target": root_target,
                                               "observation": observation, "diagnostic_only": diagnostic_only}
                    return outcome
            owned = await window_call(windows.list_owned_windows, task, asdict(root))
            candidates = []
            for item in owned:
                child_target = await prepare(app_identity_target, WindowIdentity(**item["target"]))
                candidates.append({**item, "target": child_target,
                    "parent_context": await prepare(parent_context, task, root, child_target, active)})
            if candidates:
                outcome["owned_windows"] = candidates
                if len(candidates) == 1:
                    child_target = candidates[0]["target"]
                    observation = await call(active.observe, child_target, content=True,
                        action_id="owned-after-action-" + uuid.uuid4().hex, trusted_task=task)
                    outcome["continuation"] = {"state": "owned_window_ready" if is_fresh_observation(observation)
                                               else "needs_observation", "target": child_target,
                        "parent_context": candidates[0]["parent_context"], "observation": observation,
                        "purpose_unverified": True, "diagnostic_only": diagnostic_only}
                else:
                    outcome["continuation"] = {"state": "choose_owned_window", "candidates": candidates}
        except Exception as error:
            outcome["continuation"] = {"state": "needs_observation", "dispatched": False,
                "reason": getattr(error, "code", "window_context_unavailable")}
        return outcome

    def require_runtime(task: str, tool: str, arguments: dict) -> AppRuntime:
        if runtime is not None:
            return runtime
        if fixture_target is None:
            assert windows is not None
            windows.resolve(task)
        else:
            fixture_target.verify(arguments.get("target"))
        with runtime_gate:
            active = runtimes.get(task)
            if active is None:
                directory = state_directory()
                store = StateStore(directory, jev_enabled=lambda: jev_enabled(directory))

                def resolve_call(_tool: str, payload: dict) -> AppAuthorization:
                    if fixture_target is None:
                        assert windows is not None
                        stopped = active._host_stop_callback()
                        identity = resolve_app_identity(task, payload.get("target"), stopped=stopped)
                        created = process_creation_filetime(identity.pid,
                                                            expected_iso=identity.process_created)
                        access = windows.access(task, asdict(identity), stopped=stopped)
                        scope = access.target_scope
                        if scope is None:
                            scope = f"app-content:ordinary:{identity.pid}:{created}:{identity.hwnd}"
                            store.record_confirmed_grant(task, scope,
                                                         "ordinary-bound-target:" + uuid.uuid4().hex,
                                                         lifetime=3600)
                        return AppAuthorization(task, identity.pid, identity.hwnd,
                                                created, scope, store.clock() + _local_call_lifetime(_tool, payload),
                                                access.target_scope, access.shared_resource,
                                                window_nonce=identity.window_nonce)
                    fixture_target.verify(payload.get("target"))
                    return AppAuthorization(task, fixture_target.pid,
                                            fixture_target.hwnd,
                                            fixture_target.process_start_filetime,
                                            "app-content:synthetic-fixture",
                                            store.clock() + _local_call_lifetime(_tool, payload))

                def validate_target(current_task, target, target_scope, shared_resource):
                    if current_task != task:
                        raise ControlError("ticket_task_mismatch")
                    if fixture_target is not None:
                        fixture_target.verify(target)
                        return
                    try:
                        stopped = active._host_stop_callback()
                        current = resolve_app_identity(task, target, stopped=stopped)
                        access = windows.access(task, asdict(current), stopped=stopped)
                    except (WindowSelectionError, AppBoundaryError) as error:
                        raise ControlError(error.code) from error
                    if access.target_scope != target_scope or access.shared_resource != shared_resource:
                        raise ControlError("observation_unavailable")
                active = AppRuntime(store, resolve_call,
                                    jev_client_factory=jev_client_factory(directory), validate_target=validate_target,
                                    high_bridge=high_bridge(task) if fixture_target is None else None)
                runtimes[task] = active
            return active

    async def linked_runtime(tool: str, arguments: dict, origin: object) -> tuple[AppRuntime, str, dict]:
        task = await linked_task(tool, arguments, origin)
        native = ({**arguments, "target": app_target_from_wire(arguments["target"])}
                  if "target" in arguments else arguments)
        return await prepare(require_runtime, task, tool, native), task, native

    async def linked_task(tool: str, arguments: dict, origin: object) -> str:
        if (runtime is None and fixture_target is None and origin is None and
                tool not in ("flower_app_list_windows", "flower_app_select_window")):
            raise AppBoundaryError("trusted_origin_unavailable")
        expected = (f"mcp__flower_app__{tool}", f"mcp__flower-app__{tool}")
        if not isinstance(origin, dict) or origin.get("tool_name") not in expected:
            raise OriginError("origin_missing_or_invalid")
        # A consumed ticket links this call to a chat; it creates no target or profile grant.
        task, ledger = await consume_origin_async(live_ledger, tool_name=origin["tool_name"],
                                                arguments=arguments, origin=origin)
        await begin_public_call(task, tool, ledger, arguments)
        return task

    async def linked_call(tool: str, arguments: dict, origin: object,
                          method: str, *args, **kwargs) -> dict:
        try:
            if method in {"action_status", "cancel"}:
                task = await linked_task(tool, arguments, origin)
                def cached_runtimes():
                    with runtime_gate:
                        return (runtime if runtime is not None else runtimes.get(task),
                                activators.get(task))
                active, activator = await prepare(cached_runtimes)
                if active is None:
                    if method == "action_status":
                        # Diagnostics remain available after reconnect even
                        # without a selected/live target or a cached runtime.
                        def diagnostic_runtime():
                            return AppRuntime(linked_store(), lambda *_: None,
                                high_bridge=high_bridge(task) if fixture_target is None else None)
                        diagnostic = await prepare(diagnostic_runtime)
                        return app_result_to_wire(await asyncio.to_thread(
                            diagnostic.action_status, args[0], trusted_task=task, **kwargs))
                    key = AppRuntime._action_key(task, args[0])
                    receipt = await asyncio.to_thread(
                        linked_store().diagnostic_action_for_task, task, key,
                        cancel=method == "cancel")
                    if method == "cancel":
                        receipt = {"action_id": args[0], **receipt}
                    return app_result_to_wire(receipt)
                if method == "cancel" and activator is not None:
                    # Both runtimes share the task's App key; signal the actual
                    # activation worker as well as any UIA worker.
                    await asyncio.to_thread(activator.cancel, args[0], trusted_task=task)
                native = arguments
            else:
                active, task, native = await linked_runtime(tool, arguments, origin)
            root_before = (await prepare(windows.selected_root, task) if windows is not None
                           and "target" in native and method in {"observe", "invoke", "set_value", "set_toggle", "select_item"}
                           else None)
            if "target" in native:
                args = (native["target"], *args[1:])
        except (AppBoundaryError, ComputerBoundaryError, OriginError, ControlError, LocalTargetError,
                WindowSelectionError, ValueError) as error:
            return {"state": "rejected", "dispatched": False,
                    "reason": getattr(error, "code", "invalid_target_encoding")}
        from flower_control.permissions import revision, PermissionError
        try:
            return_policy = revision() if "target" in native and method not in {"cancel", "action_status", "pause"} else None
        except PermissionError as error:
            return {"state": "rejected", "dispatched": False, "reason": error.code}
        outcome = await call(getattr(active, method), *args, trusted_task=task, **kwargs)
        if root_before is not None:
            if method == "observe" and native["target"]["hwnd"] != root_before.hwnd:
                try:
                    outcome["parent_context"] = await prepare(parent_context, task, root_before, native["target"], active)
                except Exception as error:
                    outcome["parent_context_error"] = getattr(error, "code", "window_context_unavailable")
            elif method != "observe":
                outcome = await fresh_window_context(task, active, root_before, native["target"], outcome)
        if method == "pause" and outcome.get("state") == "paused":
            def stop_activator():
                with runtime_gate:
                    activator = activators.get(task)
                if activator is not None:
                    activator.stop_for_task(task)
            await prepare(stop_activator)
        if return_policy is not None:
            try:
                return_target = native["target"]
                continuation = outcome.get("continuation")
                if (root_before is not None and native["target"]["hwnd"] != root_before.hwnd
                        and type(continuation) is dict and continuation.get("state") == "parent_ready"
                        and (not __import__("win32gui").IsWindow(native["target"]["hwnd"])
                            or outcome.get("result", {}).get("target_lifecycle") == "transient_target_hidden"
                            and not __import__("win32gui").IsWindowVisible(native["target"]["hwnd"]))):
                    # Only the selected, freshly observed parent can replace a
                    # disposed child at the final content gate. Rebind its full
                    # identity immediately before returning the observation.
                    root_now = await window_call(windows.resolve, task)
                    parent_target = await prepare(app_identity_target, root_now)
                    if root_now != root_before or continuation.get("target") != parent_target:
                        raise AppBoundaryError("selected_parent_changed")
                    return_target = parent_target
                await prepare(active._check_text_return, return_target["hwnd"], return_policy)
                if return_target is not native["target"]:
                    # The dead child's provider text cannot be authorized by
                    # the parent's policy. Keep its execution facts and
                    # receipt, but expose only the newly authorized parent.
                    from flower_control.drivers.app_flow import suppress_app_content
                    safe = suppress_app_content(outcome, "closed_child_content_suppressed")
                    receipt = safe.pop('receipt', None)
                    steps = safe.pop('steps', None)
                    outcome = {"result": safe, "continuation": continuation,
                               "parent_context": outcome.get("parent_context")}
                    if receipt is not None:
                        outcome['receipt'] = receipt
                    if steps is not None:
                        outcome['steps'] = steps
            except (AppBoundaryError, ControlError, PermissionError, WindowSelectionError) as error:
                from flower_control.drivers.app_flow import suppress_app_content
                return app_result_to_wire(suppress_app_content(outcome, error.code))
        return app_result_to_wire(outcome)

    async def call(method, *args, **kwargs) -> dict:
        try:
            return await lifetime.call(method, *args, **kwargs)
        except (AppBoundaryError, ControlError, ValueError) as error:
            return {"state": "rejected", "dispatched": False,
                    "reason": getattr(error, "code", "invalid_app_request"),
                    **getattr(error, "details", {})}
        except Exception:
            return {"state": "outcome_uncertain", "dispatched": None,
                    "reason": "app_adapter_failed"}

    def build_status() -> dict:
        return {"channel": "flower-app", "ready": runtime is not None,
                "phase": ("trusted_app_context_injected" if runtime is not None
                          else "fixture_only" if fixture_target is not None
                          else "ordinary_window_selection"),
                "fixture_target_registered": fixture_target is not None,
                "ordinary_targets_available": windows is not None,
                "available_actions": (["list_windows", "select_window", "activate", "observe",
                                       "screenshot", "set_value", "invoke", "set_toggle", "select_item",
                                       "action_status", "cancel", "pause"]
                                      if windows is not None else
                                      ["observe", "screenshot", "set_value", "invoke", "set_toggle",
                                       "select_item", "action_status", "cancel", "pause"]
                                      if runtime is not None or fixture_target is not None else []),
                **status_details(
                    "flower-app", source,
                    registered_tools=[tool.name for tool in server._tool_manager.list_tools()],
                    channel_usable=windows is not None or runtime is not None or fixture_target is not None)}

    @server.tool(name="flower_status", description="Report App channel readiness and its authorization boundary.")
    async def flower_status() -> dict:
        return await asyncio.to_thread(build_status)

    @server.tool(name="flower_app_list_windows", description="List visible ordinary app windows for this chat. Returns short-lived candidates; no UIA content or foreground change unless launch is requested. Optional launch={executable:absolute_exe,args:[],mode:'normal'|'background',action_id:stable_id,purpose?:'temporary'|'result'|'preserve'}, or launch={aumid:'registered-package-family!AppId',mode:'normal',action_id:stable_id} with no arguments, activates once. Purpose defaults to preserve and is metadata only: no automatic close or cleanup authority. Windows package registration and returned process identity are checked. Activation can reuse an instance; a PID is not a completion claim. An EXE background launch taking longer than a short initial budget returns launch_pending with the original action_id; query that action instead of relaunching. The original worker remains cancellable/tracked and no timeout proves success. Choose a fresh window candidate next. This ordinary launcher does not accept arbitrary shell/URI or administrator execution; use the separate flower_app_launch_admin route for an explicitly approved High privilege inheritance launch.")
    @public_handler
    async def flower_app_list_windows(flower_origin: dict | None = None,
                                     launch: dict | None = None) -> dict:
        try:
            payload = {} if launch is None else {"launch": launch}
            task = await linked_task("flower_app_list_windows", payload, flower_origin)
            if windows is None:
                raise WindowSelectionError("ordinary_window_selection_unavailable")
            if launch is not None:
                if (type(launch) is not dict or set(launch) - {"executable", "aumid", "args", "mode", "action_id", "purpose"}
                        or len({"executable", "aumid"} & launch.keys()) != 1):
                    raise AppBoundaryError("invalid_launch_request")
                store = linked_store()
                from .drivers.app_resource_manifest import AppResourceManifest, PURPOSES
                if type(launch.get("purpose", "preserve")) is not str or launch.get("purpose", "preserve") not in PURPOSES:
                    raise AppBoundaryError("invalid_app_resource_purpose")
                if type(launch.get("action_id")) is not str or not 1 <= len(launch["action_id"]) <= 128:
                    raise AppBoundaryError("invalid_action_id")
                source_expires = (await prepare(security_continuations.source_expiry, public_ledger.get(),
                    tool_name=flower_origin["tool_name"], tool_input=payload, token=flower_origin["token"])
                    if "executable" in launch and launch.get("mode", "normal") == "background" else None)
                key = AppRuntime._action_key(task, launch["action_id"])
                resource = (FOREGROUND_INPUT_RESOURCE if launch.get("mode", "normal") == "normal"
                            else "app-launch:" + task)
                preparation_stop = threading.Event()
                def prepare_launch():
                    def check_stop():
                        if preparation_stop.is_set():
                            raise AppBoundaryError("app_host_stopping")
                    check_stop()
                    with runtime_gate:
                        owner = store.renew_or_replace_owner(task, launch_owners.get(task)) if task in launch_owners else store.register_owner(task)
                        launch_owners[task] = owner
                    check_stop()
                    queued = store.enqueue(owner, action_id=key, fingerprint=command_hash("launch", launch),
                        resources=(resource,), context={"channel": "app", "operation": "launch",
                            "foreground_needed": resource == FOREGROUND_INPUT_RESOURCE})
                    if preparation_stop.is_set():
                        if queued["state"] == "queued":
                            store.cancel(owner, key)
                        check_stop()
                    return owner, queued
                owner, queued = await prepare(prepare_launch, _on_host_stop=preparation_stop.set)
                if queued["state"] != "queued":
                    return {"receipt": await prepare(store.status, owner, key), "replayed": True}
                import copy
                # Keep the actual executor's copy, never a later model hint.
                launch = copy.deepcopy(launch)
                original_payload = copy.deepcopy(payload)
                original_origin = dict(flower_origin)
                original_ledger = public_ledger.get()
                launch_started = asyncio.Event()
                launch_primitive_ended = threading.Event()
                launch_loop = asyncio.get_running_loop()
                def run_launch(check_stop, stopped):
                    launch_loop.call_soon_threadsafe(launch_started.set)
                    original_record = None
                    remember_armed = False
                    try:
                        check_stop()
                        decision = wait_for_turn_sync(store, owner, key, (resource,),
                            client_factory=jev_client_factory(store.directory))
                        check_stop()
                    except ControlError as error:
                        return {"receipt": store.status(owner, key),
                                "result": {"state": "rejected", "dispatched": False,
                                           "reason": error.code}, "observation_stopped": stopped()}
                    if decision.action_id != key:
                        return {"receipt": store.queue_status(owner, key)}
                    with store.dispatch(owner, key, decision.decision_id):
                        try:
                            def preflight():
                                nonlocal original_record
                                check_stop()
                                store.check_dispatch(owner, key)
                                if remember_armed and original_record is None:
                                    # The actual lifecycle primitive invokes this
                                    # only after validating path/args/exclusions,
                                    # and before its one Popen call.
                                    original_record = security_continuations.remember(original_ledger,
                                        tool_name=original_origin["tool_name"], tool_input=original_payload,
                                        token=original_origin["token"], owner=owner, action=key,
                                        native_arguments=launch, executable=executable,
                                        executor_image=str(Path(sys.executable).resolve()), check_request=original_current)
                            preflight()
                            existing = None
                            try:
                                selected = windows.selected_root(task)
                                if _process_image_and_liveness(selected.pid).resolve() == Path(launch["executable"]).resolve():
                                    existing = selected
                            except Exception:
                                pass
                            if "aumid" in launch:
                                from .drivers.app_packaged import launch_packaged_application
                                try:
                                    result = launch_packaged_application(launch["aumid"],
                                        mode=launch.get("mode", "normal"), args=launch.get("args", []), preflight=preflight)
                                finally:
                                    launch_primitive_ended.set()
                            else:
                                executable = launch["executable"]
                                original_path = Path(executable)
                                canonical_exe = (str(original_path.resolve(strict=True))
                                    if original_path.is_absolute() and original_path.is_file()
                                    and original_path.suffix.lower() == ".exe" else None)
                                if canonical_exe is not None:
                                    executable = canonical_exe
                                def original_current():
                                    check_stop()
                                    if lifetime.closing or store.task_write_stopped(task):
                                        raise ControlError("security_prompt_original_request_not_current")
                                    status = store.status(owner, key)
                                    if status.get("cancel_requested") or status.get("state") == "cancelled":
                                        raise ControlError("action_cancelled")
                                remember_armed = launch.get("mode", "normal") == "background" and canonical_exe is not None
                                try:
                                    result = launch_application(executable, launch.get("args", []),
                                        mode=launch.get("mode", "normal"), preflight=preflight,
                                        existing_identity=existing,
                                        resolve_existing=(lambda: windows.resolve(task, asdict(existing))) if existing is not None else None)
                                finally:
                                    launch_primitive_ended.set()
                                security_continuations.complete(original_record, result)
                        except (AppLifecycleError, ControlError, ValueError, OSError) as error:
                            launch_primitive_ended.set()
                            store.finish(owner, key, "not_verified", result_code="app_launch_rejected")
                            result = {"state": "rejected", "dispatched": False,
                                      "reason": getattr(error, "code", "launch_rejected")}
                        except Exception:
                            launch_primitive_ended.set()
                            store.finish(owner, key, "outcome_uncertain",
                                         result_code="app_launch_outcome_uncertain")
                            result = {"state": "outcome_uncertain", "dispatched": None,
                                      "reason": "launch_outcome_uncertain"}
                        else:
                            if type(result.get("dispatched")) is bool:
                                store.record_action_effects(owner, key,
                                    business_dispatched=result["dispatched"])
                            store.finish(owner, key,
                                "outcome_uncertain" if result.get("state") == "outcome_uncertain"
                                else "not_verified", result_code="app_" + result.get("state", "started"))
                        finally:
                            if original_record is not None:
                                security_continuations.complete(original_record, locals().get("result", {
                                    "state": "outcome_uncertain", "dispatched": None}))
                    try:
                        store.record_event("app_launch", action=key, details=safe_launch_diagnostic(result))
                    except sqlite3.Error:
                        print("Flower App launch diagnostic log write failed", file=sys.stderr)
                    receipt = store.status(owner, key)
                    try:
                        resource_record = AppResourceManifest(store).record_launch(task, key, result,
                            purpose=launch.get("purpose", "preserve"),
                            launch_kind="aumid" if "aumid" in launch else "exe")
                    except (ControlError, sqlite3.Error) as error:
                        # A metadata failure must retain the actual launch receipt.
                        resource_record = {"state": "unverified", "reason": getattr(error, "code", "app_resource_record_failed"),
                                           "preserve_process": True, "physical_cleanup_authority": False}
                    return {"receipt": receipt, "result": result, "resource_record": resource_record,
                            "observation_stopped": stopped() or bool(receipt.get("cancel_requested"))}
                launch_call = AppLaunchCall(store, task, owner, run_launch)
                if "executable" in launch and launch.get("mode", "normal") == "background":
                    pending_call = asyncio.create_task(lifetime.call(launch_call.run,
                        launch["action_id"], trusted_task=task))
                    security_continuations.retain_call(pending_call)
                    def expire_original():
                        # The outer public call may already have returned its
                        # pending receipt. Keep the original source budget in
                        # force while queued as well as inside CreateProcess.
                        try:
                            if store.status(owner, key).get("state") in {"queued", "running"}:
                                store.cancel(owner, key)
                        except (ControlError, sqlite3.Error):
                            print("Flower App source deadline cancellation remains unconfirmed", file=sys.stderr)
                        finally:
                            launch_call.request_host_stop(key)
                    source_timer = threading.Timer(max(0, min(30, source_expires - store.clock())), expire_original)
                    source_timer.daemon = True
                    pending_call.add_done_callback(lambda _: source_timer.cancel())
                    source_timer.start()
                    try:
                        done, _ = await asyncio.wait({pending_call}, timeout=.25)
                        if not done and not launch_started.is_set():
                            started_wait = asyncio.create_task(launch_started.wait())
                            try:
                                await asyncio.wait({pending_call, started_wait}, return_when=asyncio.FIRST_COMPLETED)
                            finally:
                                started_wait.cancel()
                        if not pending_call.done() and not launch_primitive_ended.is_set():
                            # Already completed execution keeps its original
                            # return/reconciliation path, even if final cleanup
                            # or an adapter continuation is still draining.
                            receipt = await asyncio.to_thread(store.status, owner, key)
                            if receipt.get("state") in {"queued", "running"} and not launch_primitive_ended.is_set():
                                return app_result_to_wire({"state": "launch_pending", "action_id": launch["action_id"],
                                    "receipt": receipt, "input_replay": False, "business_result_verified": False,
                                    "next_action": "Query flower_app_action_status with this original action_id; do not launch again.",
                                    "security_prompt_continuation": {"supported_original_operation": "background_exe_create",
                                        "profile": "huorong-process-create-exact-v1", "profile_runtime_verified": False}})
                        launched = await pending_call
                    except asyncio.CancelledError as cancellation:
                        # Cancelling a task before lifetime.call enters its
                        # worker cannot itself cancel the already queued row.
                        # Seal the exact private signal immediately and retain
                        # its ledger cleanup before propagating host cancel.
                        stop_cleanup = launch_call.signal_host_stop(key)
                        def cancel_original():
                            store.cancel(owner, key)
                            if callable(stop_cleanup):
                                stop_cleanup()
                        cleanup_key = (pending_call, "pending_launch_cancel")
                        lifetime.cleanup.remember(cleanup_key, task, "pending_launch_cancel",
                            cancel_original, cancellation, threaded=True)
                        pending_call.cancel()
                        try:
                            await lifetime.cleanup.retry_threaded(task, timeout=lifetime.CLEANUP_WAIT_SECONDS)
                            await asyncio.wait({pending_call}, timeout=lifetime.CLEANUP_WAIT_SECONDS)
                        except asyncio.CancelledError:
                            pass  # Exact pending cleanup remains retained for the next boundary.
                        raise
                else:
                    launched = await lifetime.call(launch_call.run, launch["action_id"], trusted_task=task)
                def observation_stopped():
                    launched["receipt"] = store.status(owner, key)
                    return (lifetime.closing or launched.get("observation_stopped")
                            or launched["receipt"].get("cancel_requested"))
                async def reconcile_launch_stop():
                    # Reconcile an already completed launch; this does not admit
                    # new host work or read window candidates after shutdown.
                    try:
                        return await asyncio.to_thread(observation_stopped)
                    except sqlite3.Error as error:
                        raise ControlError(ledger_error_code(error, prefix="control_ledger")) from None
                def suppress_observation():
                    launched["observation_stopped"] = True
                    launched.pop("candidates", None)
                    launched.pop("window_listing", None)
                    if type(launched.get("result")) is dict:
                        result = {**launched["result"], "windows": [], "window_selection_required": False}
                        result.pop("existing_instance", None)
                        if result.get("dispatched") is True:
                            result.update(state="outcome_uncertain", reason="launch_authority_changed")
                        launched["result"] = result
                if await reconcile_launch_stop():
                    suppress_observation()
                    return app_result_to_wire(launched)
                try:
                    listing_stop = threading.Event()
                    listing = await lifetime.call(windows.list_windows, task,
                        include_diagnostics=True, include_untitled=True,
                        stopped=lambda: listing_stop.is_set() or observation_stopped(),
                        _on_host_stop=listing_stop.set)
                    launched["candidates"] = listing["windows"]
                    launched["window_listing"] = {name: value for name, value in listing.items() if name != "windows"}
                except (ControlError, WindowSelectionError) as error:
                    launched["candidate_error"] = error.code
                except AppBoundaryError as error:
                    if error.code != "app_host_stopping":
                        raise
                    suppress_observation()
                    return app_result_to_wire(launched)
                if await reconcile_launch_stop():
                    suppress_observation()
                return app_result_to_wire(launched)
            listing_stop = threading.Event()
            listing = await lifetime.call(windows.list_windows, task,
                include_diagnostics=True, include_untitled=True,
                stopped=listing_stop.is_set, _on_host_stop=listing_stop.set)
            return {"state": "observed", "candidates": listing["windows"],
                    "window_listing": {name: value for name, value in listing.items() if name != "windows"}}
        except (OriginError, ControlError, WindowSelectionError, AppBoundaryError, ValueError, KeyError) as error:
            return app_result_to_wire({"state": "rejected", "dispatched": False,
                    "reason": getattr(error, "code", "invalid_launch_request")})

    @server.tool(name="flower_app_select_window", description="Select one just-listed ordinary app window for this chat, returning its exact App target. Does not activate or input. replacement=true binds a newly listed HWND from the same selected process instance.")
    @public_handler
    async def flower_app_select_window(candidate_id: str, replacement: bool = False,
                                  flower_origin: dict | None = None) -> dict:
        try:
            task = await linked_task("flower_app_select_window",
                               {"candidate_id": candidate_id, **({"replacement": True} if replacement else {})}, flower_origin)
            if windows is None:
                raise WindowSelectionError("ordinary_window_selection_unavailable")
            # High binding waits for the shared queue via asyncio.run. Run the
            # synchronous registry outside FastMCP's own event loop.
            selection_stop = threading.Event()
            if candidate_id.startswith("app-handoff:"):
                from flower_control.drivers.computer_native import WindowIdentity
                identity = WindowIdentity(**await prepare(linked_store().consume_window_handoff,
                                                          task, candidate_id))
                identity = await lifetime.call(windows.adopt_handoff, task, identity,
                    stopped=selection_stop.is_set, _on_host_stop=selection_stop.set)
            else:
                select = windows.select_replacement if replacement else windows.select
                identity = await lifetime.call(select, task, candidate_id,
                    stopped=selection_stop.is_set, _on_host_stop=selection_stop.set)
            def finish_selection():
                if selection_stop.is_set():
                    raise WindowSelectionError("window_selection_cancelled")
                created = process_creation_filetime(identity.pid,
                                                    expected_iso=identity.process_created)
                access = windows.access(task, asdict(identity), stopped=selection_stop.is_set)
                if selection_stop.is_set():
                    raise WindowSelectionError("window_selection_cancelled")
                if access.target_scope is None:
                    scope = f"app-content:ordinary:{identity.pid}:{created}:{identity.hwnd}"
                    linked_store().record_confirmed_grant(
                        task, scope, "ordinary-selection:" + uuid.uuid4().hex, lifetime=3600)
                return {"state": "selected", "target": app_target_to_wire({
                    "pid": identity.pid, "hwnd": identity.hwnd,
                    "process_start_filetime": created})}
            return await prepare(finish_selection, _on_host_stop=selection_stop.set)
        except (OriginError, ControlError, WindowSelectionError, AppBoundaryError) as error:
            return app_result_to_wire({"state": "rejected", "dispatched": False,
                                       "reason": error.code})

    @server.tool(name="flower_app_activate", description="Bring the selected ordinary app window to the foreground with bounded activation, then return a fresh UIA observation. Uses Computer activation, which may send one balanced auxiliary Alt tap and reports those input events separately from business actions; user takeover stops the attempt without reclaiming focus. Fill task_purpose with the non-secret business purpose (1-80 characters) and next_step with the specific current step (1-48); these separate HUD fields never select targets or grant permission.")
    @public_handler
    async def flower_app_activate(target: dict, restore_minimized: bool,
                                  action_id: str,
                                  flower_origin: dict | None = None, next_step: str | None = None,
                                  task_purpose: str | None = None) -> dict:
        arguments = {"target": target, "restore_minimized": restore_minimized,
                     "action_id": action_id}
        if next_step is not None:
            arguments['next_step'] = next_step
        if task_purpose is not None:
            arguments['task_purpose'] = task_purpose
        try:
            task = await linked_task("flower_app_activate", arguments, flower_origin)
            if windows is None:
                raise AppBoundaryError("ordinary_window_selection_unavailable")
            identity = await window_call(resolve_app_identity, task, app_target_from_wire(target))
            created = await prepare(process_creation_filetime, identity.pid,
                                                expected_iso=identity.process_created)
            expected_target = {"pid": identity.pid, "hwnd": identity.hwnd,
                               "process_start_filetime": created}
            if app_target_from_wire(target) != expected_target:
                raise AppBoundaryError("target_not_approved")
            active = await prepare(require_runtime, task, "flower_app_activate", arguments)
            layout_memory = active._hud_layouts.lease(task)
            def prepare_activator():
                with runtime_gate:
                    activator = activators.get(task)
                    if activator is not None:
                        return activator
                    def resolve_activation(_tool: str, payload: dict) -> ComputerAuthorization:
                        current = windows.resolve(task, payload.get("target"))
                        access = windows.access(task, asdict(current))
                        return ComputerAuthorization(task, current,
                                                     active.store.clock() + 30,
                                                     capture_allowed=True,
                                                     input_allowed=True,
                                                     target_scope=access.target_scope,
                                                     capture_scope=access.target_scope,
                                                     input_scope=access.target_scope,
                                                     shared_resource=access.shared_resource,
                                                     execution_guard=windows.execution_guard(task, current, access))
                    activator = AppActivationRuntime(
                        active.store, resolve_activation,
                        jev_client_factory=jev_client_factory(active.store.directory),
                        high_client_factory=lambda: ActiveHelperClient(channel="flower-app"),
                        owned_window_binder=lambda current_task, parent, hwnd:
                            windows.bind_owned_window(current_task, parent, hwnd))
                    activators[task] = activator
                    return activator
            activator = await prepare(prepare_activator)
            activation = await lifetime.call(
                activator.activate, asdict(identity), restore_minimized, action_id,
                trusted_task=task, **({"next_step": next_step} if next_step is not None else {}),
                **({"task_purpose": task_purpose} if task_purpose is not None else {}))
            result = activation.get("result")
            if isinstance(result, dict):
                activation = {**activation, "result": {key: value for key, value in
                              result.items() if key != "image"}}
            if not isinstance(result, dict) or not result.get("foreground"):
                return app_result_to_wire({"activation": activation, "observation": None})
            # Activation already captured this exact approved window. Reuse
            # its small privacy-masked map if the current App grant still
            # admits content, without retaining or capturing another image.
            try:
                def reuse_activation_map():
                    with activator._gate:
                        row = activator._observations.get(result.get("observation_id"))
                    if not row or row.get("task") != task or row.get("identity") != identity:
                        return
                    content = row.get("content_map")
                    if content is None:
                        return
                    grant = active._authorized("flower_app_observe", {"target": expected_target},
                                               expected_target, trusted_task=task)
                    active.remember_hud_map(task, identity, content,
                        row["capture_descriptor"].privacy_revision, grant.content_scope, grant.target_scope,
                        layout_memory=layout_memory)
                await lifetime.call(reuse_activation_map)
            except Exception:
                pass  # A layout hint cannot invalidate successful activation.
            try:
                observation = await lifetime.call(
                    active.observe, expected_target, content=True,
                    action_id="after-activate-" + uuid.uuid4().hex,
                    trusted_task=task)
            except Exception as error:
                observation = {"state": "rejected", "dispatched": False,
                    "reason": getattr(error, "code", "app_observation_failed"),
                    "requires_new_observation": True}
            return app_result_to_wire({"activation": activation,
                                       "observation": observation})
        except (OriginError, ControlError, WindowSelectionError, AppBoundaryError,
                ComputerBoundaryError, CaptureError, NativeInputError,
                LocalTargetError, ValueError) as error:
            return app_result_to_wire({"state": "rejected", "dispatched": False,
                    "reason": getattr(error, "code", "invalid_app_request")})

    @server.tool(name="flower_app_origin_probe", description="Check this App MCP call's genuine host chat ticket without reading a window or granting control.")
    @public_handler
    async def flower_app_origin_probe(flower_origin: dict | None = None) -> dict:
        expected = ("mcp__flower_app__flower_app_origin_probe",
                    "mcp__flower-app__flower_app_origin_probe")
        if not isinstance(flower_origin, dict) or flower_origin.get("tool_name") not in expected:
            return app_result_to_wire({"linked": False, "reason": "origin_missing_or_invalid"})
        try:
            task = await linked_task("flower_app_origin_probe", {}, flower_origin)
        except (OriginError, ControlError) as error:
            return app_result_to_wire({"linked": False, "reason": error.code})
        return app_result_to_wire({"linked": True, "chat_ref": hashlib.sha256(task.encode()).hexdigest()[:16],
                "private_grant": False})

    @server.tool(name="flower_app_work_authority", description=(
        "Prepare one work-scoped administrator authority for this authenticated chat through Flower's fixed High helper. "
        "This authority decides whether approved work may use High capabilities; it does not itself launch a process. "
        "The separate flower_app_launch_admin route performs a High privilege inheritance launch inside the already "
        "running High helper. "
        "This route belongs to the App channel and does not require a selected App/Computer window, Computer input, or the "
        "Computer-only pause. A protected local semantic-mode delegation to Codex and a matching native user-message binding "
        "activate work without a per-work desktop confirmation; old semantic preferences alone cannot migrate into delegation. "
        "Missing local selection or native message binding rejects without opening a confirmation window. Other modes retain "
        "their protected local confirmation. There is no MCP approval command. source_status reads bounded current host-message "
        "and delegation diagnostics without a work_id or message registration; it creates no authority and never reviews a "
        "message. status reads the same work_id; recover completes only an authenticated exact interrupted commit; amend re-evaluates "
        "scope under the same current delegation. revoke/close persist denial without terminating created programs. When the "
        "approved work ends or is canceled, call close and verify its closed status before reporting authority withdrawn. "
        "Global protected Stop, real denial, blacklists and unknown effects remain shared and cannot be bypassed by changing "
        "Flower channels. This is not a sandbox or proof of arbitrary code safety."))
    @public_handler
    async def flower_app_work_authority(command: str = "status", work_id: str | None = None,
                                        goal: str = "", constraints: str = "", expected_revision: int = 0,
                                        flower_origin: dict | None = None) -> dict:
        import re
        if command not in {"prepare", "status", "amend", "revoke", "close", "recover", "source_status"}:
            return {"state": "rejected", "reason": "work_authority_request_invalid"}
        payload = {"command": command, "goal": goal, "constraints": constraints, "expected_revision": expected_revision}
        if work_id is not None: payload["work_id"] = work_id
        if command == "source_status" and (work_id is not None or goal != "" or constraints != "" or expected_revision != 0):
            return {"state": "rejected", "reason": "work_authority_request_invalid"}
        if command != "source_status" and (type(work_id) is not str or re.fullmatch("[a-f0-9]{32}", work_id) is None):
            return {"state": "rejected", "reason": "work_authority_id_required",
                    "next_action": "Generate and retain one random 32-character lowercase hexadecimal work_id before prepare. Reuse it after cancellation or reply loss; the user does not need to enter or repeat it."}
        cancelled = threading.Event()
        try:
            task = await linked_task("flower_app_work_authority", payload, flower_origin)
            ledger = public_ledger.get()
            if ledger is None: raise RuntimeError("app_public_boundary_missing")
            audit_thread = await asyncio.to_thread(ledger.audit_thread, task)
            def stopped():
                return cancelled.is_set() or (command in {"prepare", "amend"} and ledger.store.task_write_stopped(task))
            def request():
                with admin_client_factory().open_session(task) as session:
                    return session.work_authority(command, work_id=work_id, goal=goal, constraints=constraints,
                        expected_revision=expected_revision, audit_thread=audit_thread, stopped=stopped)
            result = await asyncio.to_thread(request)
            return {**app_result_to_wire(result), "work_id": work_id}
        except asyncio.CancelledError:
            cancelled.set(); raise
        except (ComputerBoundaryError, OriginError, ControlError, HighHelperError, ValueError,
                OSError, RuntimeError, sqlite3.Error) as error:
            if command == "source_status":
                return {"state": "unavailable", "read_only": True, "authority_created": False,
                        "reason": getattr(error, "code", "work_authority_unavailable"),
                        "next_action": "Read source_status again after the source or connection is available; this read created no authority."}
            return {"state": "unconfirmed", "work_id": work_id,
                    "reason": getattr(error, "code", "work_authority_unavailable"),
                    "next_action": "Query this exact work_id before a new attempt; no authority is inferred from a timeout."}

    @server.tool(name="flower_app_launch_admin", description=(
        "High privilege inheritance launch (High launch): request one exact-bound child process inside Flower's already "
        "running High helper from the App channel. It inherits the existing High helper's administrator context; this is not "
        "a new elevation request, does not use ordinary-process RunAs, and normally shows no UAC. It is neither work-authority "
        "approval nor first-time High installation or repair. This does not select or "
        "activate a window and is not blocked by Computer-only pause or by closing the Computer input session. Tier, blacklists, "
        "work revision, global Stop, current input-release debt and the exact execution binding are still rechecked. Semantic mode "
        "requires an active work_id and execution:{argv:string[],working_directory:absolute_path,"
        "executable_sha256:64_lowercase_hex,payloads:[{path:absolute_path,sha256:64_lowercase_hex}],purpose:string}. "
        "Hash the current executable and entry files locally. Common bound forms include native/embedded-CLR EXE; Python file/-c; "
        "Node file/eval; PowerShell explicit File/Command/EncodedCommand; dotnet DLL/exec DLL; WSH file; cmd /d /s /c with one exact "
        "command string or a bound batch plus literal arguments; and file-based MSI operations. ProgramRef, one-shot request IDs, "
        "unknown-result recovery, continuation and independently approved new-run proof retain their existing contracts. A "
        "tracked full-tree exit and a weaker root-exit-after-helper-restart recovery are distinct: the latter keeps tree and "
        "business state unknown and requires an explicit current new-run request after its exact review. Created "
        "and ExitCode are not business success; inspect ProcessState and WindowReady separately. Use flower_status or the returned "
        "High fields for connection identity; a launch receipt does not grant another channel's authority."))
    @public_handler
    async def flower_app_launch_admin(command: str = "list", program_ref: str | None = None,
                                      request_id: str | None = None, program_path: str | None = None,
                                      arguments: str | None = None,
                                      work_id: str | None = None,
                                      execution: dict | None = None,
                                      new_run: dict | None = None,
                                      flower_origin: dict | None = None) -> dict:
        import re
        # Bind the actual host input before deriving any execution identity.
        payload = {"command": command}
        for field, value in (("program_ref", program_ref), ("request_id", request_id),
                             ("program_path", program_path), ("arguments", arguments), ("work_id", work_id),
                             ("execution", execution), ("new_run", new_run)):
            if value is not None: payload[field] = value
        bound_execution = None
        if execution is not None:
            from .drivers.semantic_execution import bind_execution
            try:
                if command not in {"launch", "status", "cancel"} or arguments not in (None, ""):
                    raise ValueError("program_launch_execution_binding_invalid")
                computed, bound_execution = bind_execution(program_path, execution)
                if program_ref is not None and program_ref != computed:
                    raise ValueError("program_launch_execution_reference_changed")
                program_ref, arguments = computed, ""
            except (ValueError, TypeError, UnicodeError):
                return {"state": "rejected", "dispatched": False, "reason": "program_launch_execution_binding_invalid"}
        elif program_path is not None:
            import hashlib, ntpath
            if (command != "launch" or not ntpath.isabs(program_path)
                    or arguments is not None and type(arguments) is not str):
                return {"state": "rejected", "dispatched": False, "reason": "program_launch_binding_rejected"}
            arguments = arguments or ""
            program_ref = hashlib.sha256(("flower-semantic-launch-v1\n" + program_path.lower()
                                          + "\n" + arguments).encode()).hexdigest()
        if (command not in {"list", "launch", "status", "cancel"}
                or (command == "list" and (program_ref is not None or request_id is not None))
                or (command != "list" and (type(program_ref) is not str
                    or re.fullmatch("[a-f0-9]{64}", program_ref) is None
                    or type(request_id) is not str
                    or re.fullmatch("[a-zA-Z0-9_-]{1,128}", request_id) is None))):
            return {"state": "rejected", "dispatched": False, "reason": "program_launch_binding_rejected"}
        cancelled, request_started = threading.Event(), threading.Event()
        try:
            # Origin consumption binds the chat only. Administrator process
            # creation is independent of selected windows and Computer input.
            task = await linked_task("flower_app_launch_admin", payload, flower_origin)
            ledger = public_ledger.get()
            if ledger is None: raise RuntimeError("app_public_boundary_missing")
            audit_thread = await asyncio.to_thread(ledger.audit_thread, task)
            def preflight():
                if cancelled.is_set() or ledger.store.task_write_stopped(task):
                    raise ControlError("global_write_stopped")
                with ledger.store.read_transaction() as db:
                    # Process creation does not use the foreground input
                    # resource. Keep real release debt and task/global Stop,
                    # without inheriting another target's effect quarantine.
                    ledger.store._require_input_release_confirmed(db)
            def stopped():
                try: preflight()
                except (ControlError, sqlite3.Error, OSError): return True
                return False
            if command == "launch": await asyncio.to_thread(preflight)
            def request():
                with admin_client_factory().open_session(task) as session:
                    request_started.set()
                    return session.program_launch(command, program_ref=program_ref, request_id=request_id,
                        program_path=program_path, arguments=arguments, execution=bound_execution, new_run=new_run,
                        preflight=preflight if command == "launch" else None,
                        stopped=stopped if command == "launch" else None, audit_thread=audit_thread, work_id=work_id)
            value = await asyncio.to_thread(request)
            return app_result_to_wire(value)
        except (ComputerBoundaryError, OriginError, ControlError, HighHelperError, ValueError,
                OSError, RuntimeError, sqlite3.Error) as error:
            uncertain = command in {"launch", "cancel"} and request_started.is_set()
            return {"state": "outcome_uncertain" if uncertain else "unavailable" if command == "status" else "rejected",
                    "dispatched": None if uncertain or command == "status" else False,
                    "reason": ledger_error_code(error, prefix="program_launch_ledger") if isinstance(error, sqlite3.Error)
                              else getattr(error, "code", "program_launch_component_unavailable"),
                    "program_ref": program_ref, "request_id": request_id, "input_replay": False,
                    "next_action": "Query status with the original program_ref and request_id; do not create a new launch ID."}
        finally:
            cancelled.set()

    @server.tool(name="flower_app_observe", description="Observe this chat's exact App window. UIA tree pages accept limits={cursor:next_cursor}, or {observation_id,root_ref,max_nodes?,max_depth?} for an exact subtree; Tree pages and writable refs have at most 15s lifetime and return remaining seconds; identity/version/authority changes invalidate them. After cursor failure, observe the current selected window again and use only its new refs/pages; never replay an input or combine old/new pages. Truncated without next_cursor means no continuation. view='properties', content=true accepts limits={observation_id,ref,properties:['help_text']} for one fresh non-password control (disabled controls allowed); HelpText is limited to 512 Unicode scalars with per-property available/unsupported/read_error/not_read_due_to_budget states; password or unknown privacy rejects the diagnostic read, without refreshing writable refs or reading referenced resources. view='wait', content=true accepts limits={observation_id,ref,field,equals,timeout_seconds?:0..10,stable_observations?:1..3} and polls only that bound control. Default view='uia' preserves full entries with limits default max_nodes=96,max_depth=6,max_bytes=80000,max_ms=1800,max_provider_calls=5000. Explicit limits support max_nodes:1..500,max_depth:0..12,max_bytes:1..1000000,max_ms:1..2000,max_provider_calls:1..5000, filter:{automation_id?,control_type?,name?} exact AND, and projection:'full'|'compact'|'actionable'. Name filtering requires content=true. Projection reduces returned fields and keeps exact internal reference records; actionable adds supported action fields rather than filtering nodes. Node/provider/time budgets include unmatched traversal; byte budget counts full native retained entries in UTF-8 before projection. Cursor continuation preserves all original settings; changed filters/budgets/projection require a new observation. view='text', content=true reads TextPattern正文: first limits={observation_id,ref,max_chars?:1..4096}, then limits={cursor:next_cursor,max_chars?}; returns Unicode-scalar pages, text_version, truncated and document_complete, independent of tree truncation. Text cursors have 300s idle and 900s total lifetime; every page rechecks authorization/identity/version. Document cap is 1048576 UTF-16 units; no full-text claim on limit/provider failure. view='item', content=true, limits={observation_id,ref,max_nodes?:1..500,max_depth?:0..12} refreshes the Realize result's bound item subtree using recheck.observation_id and realized_item_ref; new refs still target the selected window and never select the item automatically. view='parent' with the previous child target and limits={context_id:parent_context.context_id} returns fresh refs in the bound selected parent after a dialog closes, without replay or activation. view='frame', content=true returns a window image and capture metadata; optional limits={client_area:true} crops the already privacy-masked image to this exact window's current physical client area. Default remains the full window; geometry changes or unavailable bounds reject, with no activation. owned_windows lists exact dialogs; computer returns a 30s same-chat handoff; view='record_preflight', content=true, limits={client_area?:bool} only describes the exact window recording scope, without starting capture, reserving an artifact, checking achieved FPS, or activating. view='record_region', content=true requires limits={region:[physical_x,physical_y,width,height],duration_seconds?,fps?,format?,output_path?}. This independent ordinary-policy desktop route records admitted window rasters within one monitor, at most3840x2160; protected/unknown areas are black. It includes independently admitted overlays, is explicitly incomplete and not pixel-identical screen capture, and never widens the selected-window grant. It does not activate or capture audio. view='frames', content=true uses limits={frame_count?:2..12,duration_milliseconds?:100..5000,client_area?:bool,output_path?,retain_frames?:bool}; defaults are 5 frames across 1000ms including both endpoints. Returns one local ZIP containing individually indexed PNGs and a manifest with actual/scheduled offsets and sample-hash classification, not task success. Slow captures may extend elapsed time; no dropped/replayed slots, and any capture/geometry/permission/cancellation failure publishes no partial group. Each capture is bounded to 5s, whole call remains bounded, and no foreground/input is used. Explicit retain_frames:true adds independent opaque per-frame artifact IDs backed by one local encrypted group; use flower_app_artifact to read, accept a baseline or compare. Omitted/false keeps the original ZIP-only path. record with content=true uses limits={duration_seconds:(0,120],fps:1..30,output_path?,format?:'zip'|'mp4',client_area?:bool} to save local guarded WGC frames; Defaults stay 3 seconds/2 fps/ZIP; fps is a requested sampling rate, late or size-limited samples return partial/dropped slots. Default outputs are registered temporary results, retained seven days and reclaimed only on a later recording; specify output_path for permanent export. ZIP stays the default and MP4 uses only the fixed admitted local encoder. Content modes require live App content authority. Requires trusted host context.")
    @public_handler
    async def flower_app_observe(target: dict, content: bool, action_id: str,
                                 limits: dict | None = None,
                                 view: str | None = None,
                                 flower_origin: dict | None = None, retain_artifact: bool | None = None) -> object:
        arguments = {"target": target, "content": content, "action_id": action_id}
        if limits is not None:
            arguments["limits"] = limits
        if view is not None:
            arguments["view"] = view
        if retain_artifact is not None:
            if type(retain_artifact) is not bool or view != "frame":
                return {"state": "rejected", "dispatched": False, "reason": "invalid_artifact_request"}
            arguments["retain_artifact"] = retain_artifact
        if view == "wait":
            if not content:
                return {"state": "rejected", "dispatched": False, "reason": "content_scope_not_approved"}
            return await linked_call("flower_app_observe", arguments, flower_origin,
                                     "wait_condition", target, options=limits, action_id=action_id)
        if view in (None, "uia"):
            return await linked_call("flower_app_observe", arguments, flower_origin,
                                     "observe", target, content=content, action_id=action_id,
                                     limits=limits)
        if view == "parent" and windows is not None:
            try:
                task = await linked_task("flower_app_observe", arguments, flower_origin)
                native_target = app_target_from_wire(target)
                if type(limits) is not dict or set(limits) != {"context_id"} or type(limits["context_id"]) is not str:
                    raise AppBoundaryError("invalid_parent_context")
                def cached_parent():
                    with runtime_gate:
                        return parent_contexts.get(limits["context_id"]), runtimes.get(task)
                context, active = await prepare(cached_parent)
                if (context is None or active is None or context["task"] != task
                        or context["child"] != native_target or context["expires"] <= active.store.clock()
                        or await prepare(windows.selected_root, task) != context["root"]):
                    raise AppBoundaryError("parent_context_unavailable")
                root_target = await prepare(app_identity_target, context["root"])
                await window_call(resolve_app_identity, task, root_target)
                observation = await call(active.observe, root_target, content=content,
                                         action_id=action_id, trusted_task=task)
                return app_result_to_wire({"state": "parent_observed" if is_fresh_observation(observation)
                                          else "needs_observation", "target": root_target,
                    "observation": observation, "previous_action_replayed": False})
            except (OriginError, ControlError, WindowSelectionError, AppBoundaryError, ValueError) as error:
                return app_result_to_wire({"state": "rejected", "dispatched": False,
                    "reason": getattr(error, "code", "invalid_parent_context")})
        if view == "item":
            if content is not True:
                return app_result_to_wire({"state": "rejected", "dispatched": False,
                                          "reason": "content_scope_not_approved"})
            return await linked_call("flower_app_observe", arguments, flower_origin,
                "observe_item", target, options=limits, action_id=action_id)
        if view == "properties":
            if content is not True:
                return app_result_to_wire({"state": "rejected", "dispatched": False,
                                          "reason": "content_scope_not_approved"})
            return await linked_call("flower_app_observe", arguments, flower_origin,
                "read_properties", target, options=limits, action_id=action_id)
        if view == "text":
            if content is not True:
                return app_result_to_wire({"state": "rejected", "dispatched": False,
                                          "reason": "content_scope_not_approved"})
            return await linked_call("flower_app_observe", arguments, flower_origin,
                "read_text", target, options=limits, action_id=action_id)
        if view in ("owned_windows", "computer") and windows is not None:
            try:
                task = await linked_task("flower_app_observe", arguments, flower_origin)
                native_target = app_target_from_wire(target)
                identity = await window_call(resolve_app_identity, task, native_target)
                if view == "computer":
                    token = await prepare(linked_store().create_window_handoff, task, asdict(identity))
                    return {"state": "handoff_ready", "computer_candidate_id": token,
                            "next_tool": "flower_computer_select_window",
                            "previous_action_replayed": False, "expires_in_seconds": 30}
                owned = await window_call(windows.list_owned_windows, task, asdict(identity))
                def prepare_owned_targets():
                    for item in owned:
                        item["target"] = app_target_to_wire(app_identity_target(WindowIdentity(**item["target"])))
                    return owned
                owned = await prepare(prepare_owned_targets)
                return {"state": "observed", "windows": owned,
                        "root_enabled": bool(__import__("win32gui").IsWindowEnabled(identity.hwnd))}
            except (OriginError, ControlError, WindowSelectionError, AppBoundaryError, ValueError) as error:
                return app_result_to_wire({"state": "rejected", "dispatched": False,
                    "reason": getattr(error, "code", "invalid_target_encoding")})
        if view == "record_preflight" and content is True and windows is not None:
            if (limits is not None and (type(limits) is not dict or set(limits) - {"client_area"}
                    or type(limits.get("client_area", False)) is not bool)):
                return app_result_to_wire({"state": "rejected", "dispatched": False, "reason": "invalid_record_request"})
            try:
                active, task, native = await linked_runtime("flower_app_observe", arguments, flower_origin)
                identity = await window_call(resolve_app_identity, task, native["target"])
                def describe_recording(preflight, stopped):
                    preflight()
                    if resolve_app_identity(task, native["target"], stopped=stopped) != identity:
                        raise AppBoundaryError("selected_window_changed")
                    result = recording_scope_statement(identity, client_area=(limits or {}).get("client_area", False))
                    preflight()
                    if resolve_app_identity(task, native["target"], stopped=stopped) != identity:
                        raise AppBoundaryError("selected_window_changed")
                    return result
                return app_result_to_wire(await call(active.local_operation, "flower_app_observe", native["target"],
                    native, action_id, describe_recording, read_only=True, trusted_task=task))
            except (OriginError, ControlError, WindowSelectionError, AppBoundaryError, AppRecordingError, ValueError) as error:
                return app_result_to_wire({"state": "rejected", "dispatched": False,
                    "reason": getattr(error, "code", "invalid_record_request")})
        if view == "frames" and content is True and windows is not None:
            try:
                active, task, native = await linked_runtime("flower_app_observe", arguments, flower_origin)
                identity = await window_call(resolve_app_identity, task, native["target"])
                count, duration_ms, client, output = sequence_options(limits)
                from .control.local_artifacts import LocalArtifactStore
                artifacts=LocalArtifactStore(linked_store().directory) if (limits or {}).get('retain_frames',False) else None
                ownership=FrameGroupOwnership(artifacts,task) if artifacts is not None else None
                try:
                    outcome=await call(active.local_operation,
                    "flower_app_observe", native["target"], native, action_id,
                    lambda preflight, stopped: capture_sequence(identity,
                        resolve_identity=lambda: resolve_app_identity(task, native["target"], stopped=active._host_stop_callback()),
                        preflight=preflight, stopped=stopped, frame_count=count,
                        duration_milliseconds=duration_ms, client_area=client, output_path=output, task=task,
                        retain_frames=(limits or {}).get('retain_frames',False),artifact_store=artifacts,
                        retained_target=native['target'],ownership=ownership),
                    read_only=True, trusted_task=task)
                    wire=app_result_to_wire(outcome)
                    if ownership is not None:ownership.publish(outcome)
                    return wire
                finally:
                    if ownership is not None:ownership.close()
            except (OriginError, ControlError, WindowSelectionError, AppBoundaryError, AppRecordingError, ValueError) as error:
                return app_result_to_wire({"state": "rejected", "dispatched": False,
                    "reason": getattr(error, "code", "invalid_sequence_request")})
        if view == 'record_region' and content is True and windows is not None:
            try:
                region_options(limits)
                active,task,native=await linked_runtime('flower_app_observe',arguments,flower_origin)
                identity=await window_call(resolve_app_identity,task,native['target'])
                return app_result_to_wire(await call(active.local_operation,'flower_app_observe',native['target'],
                    native,action_id,lambda preflight,stopped:region_recorder.record(active.store,
                        task=task,identity=identity,resolve_identity=lambda:resolve_app_identity(task,native['target'],
                            stopped=active._host_stop_callback()),preflight=preflight,stopped=stopped,
                        arguments=native,limits=limits),read_only=True,trusted_task=task))
            except (OriginError,ControlError,WindowSelectionError,AppBoundaryError,AppRecordingError,ValueError) as error:
                return app_result_to_wire(dict(state='rejected',dispatched=False,
                    reason=getattr(error,'code','region_recording_unavailable')))
        if view == "record" and content is True and windows is not None:
            try:
                active, task, native = await linked_runtime("flower_app_observe", arguments, flower_origin)
                identity = await window_call(resolve_app_identity, task, native["target"])
                duration, fps, format_, client, output = app_record_options(limits)
                return app_result_to_wire(await call(active.local_operation,
                    "flower_app_observe", native["target"], native, action_id,
                    lambda preflight, stopped: record_window(identity,
                        resolve_identity=lambda: resolve_app_identity(task, native["target"],
                            stopped=active._host_stop_callback()),
                        preflight=preflight, stopped=stopped,
                        duration_seconds=duration, fps=fps,
                        output_path=output, task=task,
                        output_format=format_, client_area=client), read_only=True, trusted_task=task))
            except (OriginError, ControlError, WindowSelectionError, AppBoundaryError, AppRecordingError, ValueError) as error:
                return app_result_to_wire({"state": "rejected", "dispatched": False,
                    "reason": getattr(error, "code", "invalid_record_request")})
        if (view != "frame" or content is not True or limits is not None and
                (type(limits) is not dict or set(limits) - {"client_area"} or type(limits.get("client_area", False)) is not bool)):
            return app_result_to_wire({"state": "rejected", "dispatched": False,
                    "reason": "invalid_app_observation_view"})
        try:
            active, task, native = await linked_runtime("flower_app_observe", arguments,
                                                  flower_origin)
            layout_memory = active._hud_layouts.lease(task)

            def resolve_identity() -> WindowIdentity:
                if windows is not None:
                    return resolve_app_identity(task, native["target"],
                                                stopped=active._host_stop_callback())
                if fixture_target is not None:
                    fixture_target.verify(native.get("target"))
                    return WindowIdentity(fixture_target.hwnd, fixture_target.pid,
                                          fixture_target.process_created,
                                          fixture_target.window_nonce)
                return bind_window(native["target"]["hwnd"])

            outcome = await lifetime.call(
                capture_app_screenshot, active, native["target"], action_id,
                resolve_identity, trusted_task=task, client_area=(limits or {}).get("client_area", False))
        except (OriginError, ControlError, WindowSelectionError, AppBoundaryError,
                CaptureError, NativeInputError, LocalTargetError, ValueError) as error:
            return app_result_to_wire({"state": "rejected", "dispatched": False,
                    "reason": getattr(error, "code", "invalid_app_observation_request")})
        if outcome.get("state") != "observed" or type(outcome.get("_image")) is not bytes:
            return app_result_to_wire(outcome)
        return_context = outcome.pop("_return_context", {})
        try:
            await lifetime.call(
                authorize_app_screenshot_return, active, native["target"],
                action_id, resolve_identity, trusted_task=task,
                expected_identity=return_context["identity"],
                expected_privacy_revision=return_context.get("privacy_revision"),
                expected_content_scope=return_context["content_scope"],
                expected_target_scope=return_context["target_scope"],
                expected_shared_resource=return_context["shared_resource"],
                expected_geometry=return_context.get("geometry"))
        except Exception as error:
            outcome.pop("_image", None)
            return app_result_to_wire({"state": "rejected", "dispatched": False,
                    "reason": getattr(error, "code", "visual_return_not_authorized"),
                    "visual_return_suppressed": True})
        pixels = outcome.pop("_image")
        outcome.pop("_return_context", None)
        if retain_artifact:
            from .control.local_artifacts import LocalArtifactStore
            try:
                capture = outcome["capture"]
                outcome["retained_artifact"] = await asyncio.to_thread(LocalArtifactStore(linked_store().directory).put,
                    task, pixels, kind="image", metadata={"channel": "app", "scope": "one_selected_window",
                        "target": {**native["target"], "window_nonce": return_context["identity"].window_nonce,
                            "process_created": return_context["identity"].process_created},
                        "source_bounds": capture["source_bounds"], "width": capture["width"], "height": capture["height"],
                        "privacy_revision": return_context.get("privacy_revision"), "capture_id": action_id})
            except ControlError as error:
                outcome["retained_artifact"] = {"state": "unavailable", "reason": error.code}
            try:
                await lifetime.call(authorize_app_screenshot_return, active, native["target"], action_id, resolve_identity,
                    trusted_task=task, expected_identity=return_context["identity"],
                    expected_privacy_revision=return_context.get("privacy_revision"), expected_content_scope=return_context["content_scope"],
                    expected_target_scope=return_context["target_scope"], expected_shared_resource=return_context["shared_resource"],
                    expected_geometry=return_context.get("geometry"))
            except Exception as error:
                return {"state": "rejected", "dispatched": False, "reason": getattr(error, "code", "visual_return_not_authorized"),
                        "visual_return_suppressed": True}
        # Reuse only this already-authorized, privacy-masked frame for the
        # same task and window; never take an additional capture for the HUD.
        try:
            bounds = outcome["capture"]["source_bounds"]
            frame_bounds = tuple(bounds[k] for k in ("left", "top", "right", "bottom"))
            geometry = return_context.get("geometry")
            window = geometry.window if geometry is not None else None
            window_bounds = ((window.left, window.top, window.right, window.bottom)
                             if window is not None else frame_bounds)
            active.remember_hud_frame(task, return_context["identity"], pixels, frame_bounds,
                window_bounds, return_context.get("privacy_revision"),
                return_context["content_scope"], return_context["target_scope"], layout_memory=layout_memory)
        except (AttributeError, KeyError, OSError, TypeError, ValueError):
            pass
        return [app_result_to_wire(outcome), Image(data=pixels, format="png")]

    @server.tool(name="flower_app_artifact", structured_output=False, description="Read this chat's retained generated frame by artifact_id, accept it as a baseline, or compare to baseline_id. Current exact target/content authorization and privacy revision are checked twice. operation is read (default), accept_baseline, or compare; comparison requires identical capture scope/bounds/dimensions and reports pixels, not task success. compare accepts masks:[[left,top,right,bottom],...] in PNG pixels, at most128 rectangles. No arbitrary paths or input authority.")
    @public_handler
    async def flower_app_artifact(artifact_id: str, operation: str | None = None, baseline_id: str | None = None,
                                 channel_tolerance: int | None = None, max_changed_ratio: float | None = None,
                                 masks: list | None = None,
                                 flower_origin: dict | None = None):
        arguments = {"artifact_id": artifact_id}
        for name, value in (("operation", operation), ("baseline_id", baseline_id),
                            ("channel_tolerance", channel_tolerance), ("max_changed_ratio", max_changed_ratio), ("masks",masks)):
            if value is not None:
                arguments[name] = value
        try:
            mode = operation or "read"
            if mode not in {"read", "accept_baseline", "compare"} or (mode == "compare") != (baseline_id is not None):
                raise AppBoundaryError("invalid_artifact_request")
            if masks is not None and mode!='compare':raise AppBoundaryError('invalid_artifact_request')
            task = await linked_task("flower_app_artifact", arguments, flower_origin)
            from .control.local_artifacts import LocalArtifactStore, compare_png
            from .drivers.computer_native import _read_window_identity
            artifacts = LocalArtifactStore(linked_store().directory)
            def authorize(metadata):
                if metadata.get("channel") == "app" and metadata.get("scope") == "chat_metadata" and mode == "read":
                    return True
                if metadata.get("channel") != "app" or metadata.get("scope") != "one_selected_window":
                    return False
                saved = metadata["target"]
                target = {name: saved[name] for name in ("pid", "hwnd", "process_start_filetime")}
                payload = {"target": target, "content": True, "view": "frame", "action_id": "artifact-read-" + uuid.uuid4().hex}
                active = require_runtime(task, "flower_app_observe", payload)
                grant = active._authorized("flower_app_observe", payload, target, trusted_task=task)
                identity = _read_window_identity(target["hwnd"])
                if identity.window_nonce != saved.get("window_nonce") or identity.process_created != saved.get("process_created"):
                    return False
                authorize_app_screenshot_return(active, target, payload["action_id"], lambda: _read_window_identity(target["hwnd"]),
                    trusted_task=task, expected_identity=identity, expected_content_scope=grant.content_scope,
                    expected_target_scope=grant.target_scope, expected_shared_resource=grant.shared_resource,
                    expected_privacy_revision=metadata.get("privacy_revision"))
                return True
            metadata, pixels = await asyncio.to_thread(artifacts.read, task, artifact_id, authorize=authorize)
            if metadata["kind"] == "trace" and mode == "read":
                import json
                return {"state": "resolved", "metadata": metadata, "trace": json.loads(pixels), "input_authority_granted": False}
            if metadata["kind"] not in {"image", "baseline"}:
                raise AppBoundaryError("invalid_artifact_request")
            if mode == "accept_baseline":
                content_metadata = {key: value for key, value in metadata.items() if key not in {"kind", "sha256", "artifact_id"}}
                return await asyncio.to_thread(artifacts.put, task, pixels, kind="baseline", metadata=content_metadata)
            if mode == "compare":
                baseline_metadata, baseline = await asyncio.to_thread(artifacts.read, task, baseline_id, authorize=authorize)
                if baseline_metadata["kind"] != "baseline" or any(metadata.get(key) != baseline_metadata.get(key) for key in
                    ("channel", "scope", "target", "source_bounds", "width", "height", "privacy_revision")):
                    raise AppBoundaryError("baseline_scope_mismatch")
                result = await asyncio.to_thread(compare_png, baseline, pixels,
                    channel_tolerance=0 if channel_tolerance is None else channel_tolerance,
                    max_changed_ratio=0 if max_changed_ratio is None else max_changed_ratio,
                    masks=() if masks is None else masks)
                if (await asyncio.to_thread(authorize, metadata) is not True
                        or await asyncio.to_thread(authorize, baseline_metadata) is not True):
                    raise AppBoundaryError("artifact_content_not_authorized")
                return {**result, "state": "compared", "task_success_verified": False}
            return [app_result_to_wire({"state": "resolved", "input_authority_granted": False, **metadata}), Image(data=pixels, format="png")]
        except (OriginError, ControlError, AppBoundaryError, NativeInputError, ValueError) as error:
            return {"state": "rejected", "dispatched": False, "reason": getattr(error, "code", "invalid_artifact_request")}

    @server.tool(name="flower_app_trace", description="Start or stop a finite same-chat trace of control metadata. Exports local encrypted receipts, release/unknown and timing facts without screenshots, text, titles, URLs or secret input. No capture, activation, authority grant or replay.")
    @public_handler
    async def flower_app_trace(mode: str, flower_origin: dict | None = None):
        try:
            if mode not in {"start", "stop"}:
                raise AppBoundaryError("invalid_trace_request")
            task = await linked_task("flower_app_trace", {"mode": mode}, flower_origin)
            from .control.local_artifacts import LocalArtifactStore
            store = linked_store()
            snapshot = await asyncio.to_thread(store.task_control_status, task)
            if mode == "start":
                if task in trace_starts:raise AppBoundaryError('trace_already_started')
                def marker():
                    with store.read_transaction() as db:return db.execute('SELECT COALESCE(MAX(seq),0) FROM control_events').fetchone()[0]
                after=await asyncio.to_thread(marker)
                if task in trace_starts:raise AppBoundaryError('trace_already_started')
                trace_starts[task] = dict(snapshot=snapshot,after_seq=after)
                return {"state": "tracing", "scope": "chat_metadata", "content_recorded": False}
            start = trace_starts.get(task)
            if start is None:
                raise AppBoundaryError("trace_not_started")
            import json
            def trace_rows():
                prefix=task+':app:'
                with store.read_transaction() as db:
                    rows=db.execute('SELECT e.seq,e.monotonic,e.event,e.action FROM control_events e '
                        'JOIN actions a ON a.id=e.action WHERE a.task=? AND substr(a.id,1,?)=? AND e.seq>? '
                        "AND e.event IN ('action_queued','action_dispatched','action_finished','mcp_call_cancelled') "
                        'ORDER BY e.seq LIMIT 2001',(task,len(prefix),prefix,start['after_seq'])).fetchall()
                    events=[dict(row) for row in rows[:2000]]
                    ids=list(dict.fromkeys(row['action'] for row in rows[:2000]))[:256]
                    actions=[]
                    for identifier in ids:
                        row=db.execute('SELECT a.id,a.state,a.cancel_requested,a.created,a.updated,'
                            'e.business_dispatched,e.activation_dispatched,e.input_release FROM actions a '
                            'LEFT JOIN action_effects e ON e.action=a.id WHERE a.id=? AND a.task=?',(identifier,task)).fetchone()
                        actions.append(dict(row))
                return dict(events=events,actions=actions,truncated=len(rows)>2000 or len({row['action'] for row in rows})>256,
                    content_recorded=False,scope='this_chat_app_actions',is_protected_audit_chain=False)
            recorded=await asyncio.to_thread(trace_rows)
            artifact = await asyncio.to_thread(LocalArtifactStore(store.directory).put, task,
                json.dumps({"start": start['snapshot'], "end": snapshot,**recorded}, separators=(",", ":")).encode(), kind="trace",
                metadata={"channel": "app", "scope": "chat_metadata"})
            if trace_starts.get(task) is start:trace_starts.pop(task)
            return {"state": "trace_stopped", "content_recorded": False, "artifact": artifact}
        except (OriginError, ControlError, AppBoundaryError) as error:
            return {"state": "rejected", "dispatched": False, "reason": error.code}

    @server.tool(name="flower_app_tasks", description="Read this chat's finite control actions, pause/release/unknown state and result receipts without window content, dispatch or replay. Optional resources={operation:'list',after?:next_after,limit?:1..32} pages this chat's registered launch purposes; resources={operation:'classify',action_id:original_launch_id,purpose:'temporary'|'result'|'preserve'} changes metadata only. Labels grant no process ownership or cleanup authority; old unregistered history cannot be adopted. Continue with a new observation and new action_id; cancel/resume use their explicit tools.")
    @public_handler
    async def flower_app_tasks(flower_origin: dict | None = None, resources: dict | None = None) -> dict:
        try:
            task = await linked_task("flower_app_tasks", {} if resources is None else {"resources": resources}, flower_origin)
            if resources is not None:
                from .drivers.app_resource_manifest import AppResourceManifest
                if type(resources) is not dict:
                    raise ControlError("invalid_app_resource_request")
                operation = resources.get("operation", "list")
                def resource_request():
                    manifest = AppResourceManifest(linked_store())
                    if operation == "classify" and set(resources) == {"operation", "action_id", "purpose"}:
                        key = AppRuntime._action_key(task, resources["action_id"])
                        return {"resource_record": manifest.classify(task, key, resources["purpose"]), "dispatched": False}
                    if operation == "list" and not set(resources) - {"operation", "after", "limit"}:
                        return {"resource_manifest": manifest.task_manifest(task,
                            after=resources.get("after"), limit=resources.get("limit", 32)), "dispatched": False}
                    raise ControlError("invalid_app_resource_request")
                return await prepare(resource_request)
            return await asyncio.to_thread(linked_store().task_control_status, task)
        except (OriginError, ControlError, AppBoundaryError) as error:
            return {"state": "rejected", "dispatched": False, "reason": error.code}

    @server.tool(name="flower_app_jev_policy", description="Read or disable/enable configured decision API use (Perplexity/Jev; legacy tool name) for this chat without selecting a window. enabled=false prevents new and late service decisions; true cannot enable a new provider or bypass the machine setting. Returns retained metadata usage without content.")
    @public_handler
    async def flower_app_jev_policy(enabled: bool | None = None, flower_origin: dict | None = None) -> dict:
        arguments = {} if enabled is None else {"enabled": enabled}
        try:
            task = await linked_task("flower_app_jev_policy", arguments, flower_origin)
            store = linked_store()
            result = await asyncio.to_thread(store.task_jev_policy, task, enabled=enabled)
            from flower_control.control.task_service_report import chat_jev_summary
            result["usage"] = await asyncio.to_thread(chat_jev_summary, store, task)
            return result
        except (AppBoundaryError, OriginError, ControlError) as error:
            return {"state": "rejected", "dispatched": False, "reason": error.code}

    @server.tool(name="flower_app_set_value", description="Set one observed non-password Value control once, then observe fresh state. automation_id accepts the current observation entry's appref: reference for duplicate or empty AutomationIds. Requires trusted host context. Fill task_purpose with the non-secret business purpose (1-80 characters) and next_step with the specific current step (1-48); these separate HUD fields never select targets or grant permission. execution_mode='foreground' is the default. Explicit 'must_background' currently admits only an exact standard Win32 Edit, with a bounded native text message, fresh Value version and readback; it never activates or falls back to foreground. Other providers reject before dispatch. Same-window/profile exclusion remains enforced.")
    @public_handler
    async def flower_app_set_value(target: dict, observation_id: str,
                                   automation_id: str, value: str, action_id: str,
                                   flower_origin: dict | None = None, next_step: str | None = None,
                                   execution_mode: str | None = None, task_purpose: str | None = None) -> dict:
        arguments = {"target": target, "observation_id": observation_id,
                     "automation_id": automation_id, "value": value, "action_id": action_id}
        if next_step is not None:
            arguments['next_step'] = next_step
        if task_purpose is not None:
            arguments['task_purpose'] = task_purpose
        if execution_mode is not None:
            arguments['execution_mode'] = execution_mode
        return await linked_call("flower_app_set_value", arguments, flower_origin,
                                 "set_value", target, observation_id, automation_id,
                                 value, action_id)

    @server.tool(name="flower_app_invoke", description="Perform one observed UIA Invoke and check {automation_id,field,equals}; legal fields are name/value/toggle_state/expand_collapse_state with string equals, or selected/focused with boolean equals. enabled/offscreen are read-only wait fields, not write postconditions. Examples: {automation_id:'Save',field:'name',equals:'Saved'} or {automation_id:'Choice',field:'selected',equals:true}. Empty objects are invalid. Receipts separate dispatch/executor end, whether UI recheck ran, why it did not match, and final artifacts that need an independent task check; automation_id accepts a current observation appref. Semantic alternatives also include {semantic_action:'focus'}, {semantic_action:'guarded_input',value,replace?:false,check?:{automation_id,field,equals}} through the High input ledger, and {semantic_action:'flow',steps:[{operation:'set_value',ref,value}|{operation:'select_item',ref,desired}|{operation:'invoke',ref,postcondition}]}, where invoke may carry goal_hint for existing Jev selection. Flows advance fresh local refs and stop the suffix after unknown/replayed/failed results. A bounded Huorong continuation uses {semantic_action:'security_prompt_allow',launch_action_id:original_background_exe_launch_id}. Only a real retained background EXE create in the same host turn is eligible; the exact source profile requires all original full fields, verified vendor/window and remember unchecked. Unknown UI profiles return unsupported. It invokes once through normal window authorization and queries only the original launch process/window result; it does not authorize protection rules or prove deeper business success. For a current purpose=temporary resource, {semantic_action:'close_temporary',launch_action_id} requests one normal close of its exact original exclusive process/window, preserving unknown ownership and save prompts. Semantic alternatives: {semantic_action:'expand'|'collapse'}, {semantic_action:'scroll',direction:'up'|'down'|'left'|'right',amount:'small'|'large'}, {semantic_action:'realize_item',item_name:exact_name}, {semantic_action:'menu'} for one exact-ref menu step using ExpandCollapse/Invoke/SelectionItem, or {semantic_action:'close'} for one normal WM_CLOSE preserving save dialogs. goal_hint applies to ordinary Invoke/expand/collapse/scroll/realize; menu requires an exact current reference. Returns fresh refs after each step and approved owned-window/parent continuation when available; dialog purpose and final save result need independent verification. Never auto-confirms a dialog or replays an unknown write. Requires trusted host context. Fill task_purpose with the non-secret business purpose (1-80 characters) and next_step with the specific current step (1-48); these separate HUD fields never select targets or grant permission. A fixed recipe can use {semantic_action:'recipe',name:'two_field_submit'|'select_and_invoke'|'menu_item',parameters:{...}} and expands into the same validated flow/exact-menu steps. execution_mode defaults to 'foreground'; 'must_background' rejects Invoke, focus, guarded input, flow, recipe and close before any prefix; only the separate exact standard Win32 Edit set_value lane is currently admitted.")
    @public_handler
    async def flower_app_invoke(target: dict, observation_id: str,
                                automation_id: str, postcondition: AppContinuationPostcondition,
                                action_id: str,
                                flower_origin: dict | None = None, next_step: str | None = None,
                                execution_mode: str | None = None, task_purpose: str | None = None) -> dict:
        arguments = {"target": target, "observation_id": observation_id,
                     "automation_id": automation_id, "postcondition": postcondition,
                     "action_id": action_id}
        if next_step is not None:
            arguments['next_step'] = next_step
        if task_purpose is not None:
            arguments['task_purpose'] = task_purpose
        if execution_mode is not None:
            arguments['execution_mode'] = execution_mode
        if type(postcondition) is dict and postcondition.get("semantic_action") == "security_prompt_allow":
            if (set(postcondition) != {"semantic_action", "launch_action_id"}
                    or type(postcondition["launch_action_id"]) is not str):
                return {"state": "rejected", "dispatched": False, "reason": "invalid_security_prompt_continuation"}
            if execution_mode == "must_background":
                return {"state": "rejected", "dispatched": False, "reason": "background_pattern_requires_foreground"}
            try:
                active, task, native = await linked_runtime("flower_app_invoke", arguments, flower_origin)
                call_stop = threading.Event()
                return app_result_to_wire(await lifetime.call(security_continuations.execute, active,
                    ledger=public_ledger.get(), task=task, tool_name=flower_origin["tool_name"],
                    tool_input=arguments, token=flower_origin["token"],
                    original_action_id=postcondition["launch_action_id"], target=native["target"],
                    observation_id=observation_id, automation_id=automation_id,
                    current_stopped=lambda: call_stop.is_set() or lifetime.closing,
                    _on_host_stop=call_stop.set))
            except (OriginError, ControlError, WindowSelectionError, AppBoundaryError, ValueError) as error:
                return {"state": "rejected", "dispatched": False, "reason": getattr(error, "code", "security_prompt_continuation_unavailable")}
        if execution_mode == "must_background" and type(postcondition) is dict and postcondition.get("semantic_action") in {"close", "close_temporary"}:
            return {"state": "rejected", "dispatched": False,
                    "reason": "background_pattern_requires_foreground", "foreground_requested": False}
        if (type(postcondition) is dict
                and (postcondition.get("semantic_action") == "close" and set(postcondition) <= {"semantic_action", "goal_hint"}
                     or postcondition.get("semantic_action") == "close_temporary" and set(postcondition) == {"semantic_action", "launch_action_id"})
                and windows is not None):
            try:
                if "goal_hint" in postcondition and (type(postcondition["goal_hint"]) is not str
                        or not postcondition["goal_hint"].strip()):
                    raise AppBoundaryError("invalid_target_goal")
                active, task, native = await linked_runtime("flower_app_invoke", arguments, flower_origin)
                cleanup_guard, cleanup_record = None, None
                if postcondition["semantic_action"] == "close_temporary":
                    from .drivers.app_resource_manifest import AppResourceManifest
                    launch_key = active._action_key(task, postcondition["launch_action_id"])
                    manifest = AppResourceManifest(active.store)
                    def cleanup_guard():
                        return manifest.require_temporary_close(task, launch_key, native["target"])
                    cleanup_record = await prepare(cleanup_guard)
                    # One cleanup attempt per original launch, even if a model
                    # changes its public action_id after an uncertain close.
                    action_id = "temporary-close-" + hashlib.sha256(launch_key.encode()).hexdigest()[:40]
                    native = {**native, "action_id": action_id}
                identity = await window_call(resolve_app_identity, task, native["target"])
                root_before = await prepare(windows.selected_root, task)
                operation_key = active._action_key(task, action_id)
                usage = JevUsage()
                usage.observe("target_selection", {"reason": "selection_not_required",
                    "skip_reason": "selection_not_required", "opportunity": False, "client_invoked": False})
                with jev_context(task=task, channel="app", action=operation_key,
                                 observation_id=observation_id, usage=usage):
                    outcome = await call(active.close_window, native["target"], native, action_id,
                        identity=identity, resolve_identity=lambda: resolve_app_identity(task, native["target"],
                            stopped=active._host_stop_callback()),
                        trusted_task=task, **({"source_guard": cleanup_guard} if cleanup_guard else {})) if active.high_bridge is not None else await call(active.local_operation,
                        "flower_app_invoke", native["target"], native, action_id,
                        lambda preflight, stopped: request_normal_close(identity,
                            resolve_identity=lambda: resolve_app_identity(task, native["target"],
                                stopped=active._host_stop_callback()),
                            preflight=preflight), foreground=True, trusted_task=task,
                        **({"source_guard": cleanup_guard} if cleanup_guard else {}))
                    outcome = await fresh_window_context(task, active, root_before, native["target"], outcome)
                outcome["operation_receipt"] = operation_receipt(outcome, requested=False)
                if cleanup_record is not None:
                    outcome["temporary_cleanup"] = {**cleanup_record, "action_id": action_id,
                        "state": (outcome.get("result") or {}).get("state", "unverified"),
                        "force_terminated": False, "automatic_finish_cleanup": False}
                outcome["jev_participation"] = (active._jev_participation(usage) if not outcome.get("replayed")
                    else {"state": "unknown", "reason": "replayed_action_requires_history"})
                if not outcome.get("replayed"):
                    _public_tool_event(active.store, "app_operation_receipt", task=task, action=operation_key,
                        details={"action_id": operation_key, "receipt": outcome["operation_receipt"],
                                 "jev_participation": outcome["jev_participation"]})
                return app_result_to_wire(outcome)
            except (OriginError, ControlError, WindowSelectionError, AppBoundaryError, ValueError) as error:
                return app_result_to_wire({"state": "rejected", "dispatched": False,
                    "reason": getattr(error, "code", "invalid_close_request")})
        return await linked_call("flower_app_invoke", arguments, flower_origin,
                                 "invoke", target, observation_id, automation_id,
                                 postcondition, action_id)

    @server.tool(name="flower_app_set_toggle", description="Set an observed UIA Toggle control to exact on or off with at most one Toggle call, then check fresh state; Indeterminate is neither on nor off and a single provider transition may not reach the desired state. automation_id also accepts the current observation entry's appref: reference. Fill task_purpose with the non-secret business purpose (1-80 characters) and next_step with the specific current step (1-48); these separate HUD fields never select targets or grant permission. execution_mode defaults to 'foreground'. Explicit 'must_background' currently rejects this unverified provider before dispatch, with no foreground fallback.")
    @public_handler
    async def flower_app_set_toggle(target: dict, observation_id: str,
                                    automation_id: str, desired: bool, action_id: str,
                                    flower_origin: dict | None = None, next_step: str | None = None,
                                    execution_mode: str | None = None, task_purpose: str | None = None) -> dict:
        arguments = {"target": target, "observation_id": observation_id,
                     "automation_id": automation_id, "desired": desired,
                     "action_id": action_id}
        if next_step is not None:
            arguments['next_step'] = next_step
        if task_purpose is not None:
            arguments['task_purpose'] = task_purpose
        if execution_mode is not None:
            arguments['execution_mode'] = execution_mode
        return await linked_call("flower_app_set_toggle", arguments, flower_origin,
                                 "set_toggle", target, observation_id, automation_id,
                                 desired, action_id)

    @server.tool(name="flower_app_select_item", description="Set an observed UIA SelectionItem to desired=true (default) or false (RemoveFromSelection), at most once; already satisfied means zero writes. Return fresh refs and selected readback. automation_id accepts the observation's appref. Fill task_purpose with the non-secret business purpose (1-80 characters) and next_step with the specific current step (1-48); these separate HUD fields never select targets or grant permission. execution_mode defaults to 'foreground'. Explicit 'must_background' currently rejects this unverified provider before dispatch, with no foreground fallback.")
    @public_handler
    async def flower_app_select_item(target: dict, observation_id: str,
                                     automation_id: str, action_id: str,
                                     flower_origin: dict | None = None, desired: bool | None = None, next_step: str | None = None,
                                    execution_mode: str | None = None, task_purpose: str | None = None) -> dict:
        arguments = {"target": target, "observation_id": observation_id,
                     "automation_id": automation_id, "action_id": action_id}
        if next_step is not None:
            arguments['next_step'] = next_step
        if task_purpose is not None:
            arguments['task_purpose'] = task_purpose
        if execution_mode is not None:
            arguments['execution_mode'] = execution_mode
        if desired is not None:
            arguments["desired"] = desired
        return await linked_call("flower_app_select_item", arguments, flower_origin,
                                 "select_item", target, observation_id,
                                 automation_id, action_id, desired=True if desired is None else desired)

    @server.tool(name="flower_app_action_status", description="Read this chat's App action state and anonymous waiting reasons without dispatching again. Default reads history only. refresh_launch=true checks only original recorded PID/creation instances and visible root-window counts, with no titles, process discovery, selection or relaunch. Stop/cancel suppress fresh results. New window control still requires list_windows and selection.")
    @public_handler
    async def flower_app_action_status(action_id: str,
                                       flower_origin: dict | None = None,
                                       refresh_launch: bool | None = None) -> dict:
        """Opt in to bounded identity-only launch refresh; default is history."""
        arguments = {"action_id": action_id}
        if refresh_launch is not None:
            arguments["refresh_launch"] = refresh_launch
        return await linked_call("flower_app_action_status", arguments,
                                 flower_origin, "action_status", action_id,
                                 refresh_launch=refresh_launch)

    @server.tool(name="flower_app_cancel", description="Request stop for an action belonging to the trusted current task.")
    @public_handler
    async def flower_app_cancel(action_id: str,
                                flower_origin: dict | None = None) -> dict:
        return await linked_call("flower_app_cancel", {"action_id": action_id},
                                 flower_origin, "cancel", action_id)

    @server.tool(name="flower_app_pause", description="Pause this chat's selected App window and stop in-flight actions. mode='release_phase' yields an idle UI stage before backend work, releases safe claims and closes HUD without ending the task or clearing Stop; next control requires a fresh observation. App writes can activate foreground; read-only App frame/record need no Computer switch. mode='finish' ends this connection's App work, closes delegated activation HUDs and releases its target claims, preserving other channels and unknown history; usable after the target closes. mode='resume' uses the explicit request in this chat and checks the same approved window/task snapshot, then requires new observation; no activation or local continue card. Unknown input release, quarantine and unresolved execution remain blocked. Human handoff has explicit handoff_status, handoff_complete, handoff_cancel and handoff_extend modes bound to request_id. Completion/cancellation/expiry keep this chat paused; only explicit resume allows fresh observation and new actions. Optional kind is metadata only: UAC, login_secret, MFA, captcha, license_or_key, payment_or_private_data, external_auth_or_redirect, system_permission, physical_action, inaccessible_modal, legal_or_account_decision or unknown_blocker (default). It grants no sensitive-input permission. A fixed native popup supplies Complete, Cancel, Extend and immediate Stop; expiry never means completion. No handoff response grants new authorization or replays an old action.")
    @public_handler
    async def flower_app_pause(flower_origin: dict | None = None, mode: str | None = None,
                               message: str | None = None, request_id: str | None = None,
                               timeout_seconds: int | None = None, kind: HumanHandoffKind | None = None) -> dict:
        if kind is not None:
            try:
                if mode != "handoff":
                    raise ControlError("invalid_handoff_kind")
                human_handoff_kind(kind)
            except ControlError as error:
                return {"state": "rejected", "dispatched": False, "reason": error.code}
        if message is not None and mode != "handoff":
            return {"state": "rejected", "dispatched": False, "reason": "invalid_handoff_message"}
        if mode in {"handoff_status", "handoff_complete", "handoff_cancel", "handoff_extend"}:
            arguments = {"mode": mode}
            if request_id is not None:
                arguments["request_id"] = request_id
            if timeout_seconds is not None:
                arguments["timeout_seconds"] = timeout_seconds
            try:
                task = await linked_task("flower_app_pause", arguments, flower_origin)
                from .drivers.human_handoff import handoff_metadata_request
                return await asyncio.to_thread(handoff_metadata_request, linked_store(), task, mode, request_id, timeout_seconds)
            except (OriginError, ControlError, ValueError) as error:
                return {"state": "rejected", "dispatched": False, "reason": getattr(error, "code", "invalid_handoff_request")}
        if request_id is not None:
            return {"state": "rejected", "dispatched": False, "reason": "invalid_handoff_request"}
        if mode == "release_phase":
            try:
                task = await linked_task("flower_app_pause", {"mode": mode}, flower_origin)
                if lifetime.task_calls.get(task) or any(current == task and not worker.done() for worker, current in lifetime.execution_tasks.items()):
                    return {"state": "phase_release_pending", "reason": "app_calls_in_flight", "input_dispatched": False}
                def release_cached():
                    store = linked_store()
                    if store.task_write_stopped(task):
                        return {"state": "phase_release_pending", "reason": "task_write_stopped", "input_dispatched": False}
                    with runtime_gate:
                        active = runtime if runtime is not None else runtimes.get(task)
                        activator = activators.get(task)
                        owners = set(selection_owners.get(task, ()))
                        if task in launch_owners:
                            owners.add(launch_owners[task])
                    results = []
                    if activator is not None:
                        results.append(activator.pause("release_phase", trusted_task=task))
                    if active is not None:
                        results.append(active.release_phase(task))
                    pending = next((item for item in results if item.get("state") != "phase_released"), None)
                    if pending is not None:
                        return pending
                    store = linked_store()
                    with store.transaction() as db:
                        store._require_input_release_confirmed(db, task=task, action_prefix=task + ":app:")
                    ownership = [store.finish_owned_resources(owner, phase_release=True) for owner in owners]
                    with runtime_gate:
                        for key in [key for key, value in parent_contexts.items() if value["task"] == task]:
                            parent_contexts.pop(key, None)
                    return {"state": "phase_released", "task_finished": False, "input_release": "released",
                            "indicator_closed": True, "requires_new_observation": True, "input_dispatched": False,
                            "foreground_activated": False, "connections": results, "extra_target_ownership": ownership,
                            "stop_and_authority_preserved": True}
                return app_result_to_wire(await prepare(release_cached))
            except (OriginError, ControlError, AppBoundaryError, ComputerBoundaryError) as error:
                return app_result_to_wire({"state": "phase_release_pending", "reason": error.code, "input_dispatched": False})
        if mode == "finish":
            try:
                task = await linked_task("flower_app_pause", {"mode": mode}, flower_origin)
                if not await lifetime.drain_task(task):
                    return {"state": "task_finish_pending", "reason": "app_calls_in_flight",
                            "input_dispatched": False, "requires_finish_retry": True}
                if not await asyncio.to_thread(region_recorder.drain_task,task):
                    return dict(state='task_finish_pending',reason='region_capture_cleanup_pending',
                        input_dispatched=False,requires_finish_retry=True)
                def finish_cached():
                    from .drivers.app_resource_manifest import AppResourceManifest
                    with runtime_gate:
                        active = runtime if runtime is not None else runtimes.get(task)
                        activator = activators.get(task)
                        extra_owners = set(selection_owners.get(task, ()))
                        if task in launch_owners:
                            extra_owners.add(launch_owners[task])
                        bridge = high_bridges.get(task)
                    results = []
                    if activator is not None:
                        results.append(activator.pause("finish", trusted_task=task))
                    if active is not None:
                        results.append(active.finish(task))
                    if any(item.get("state") != "task_finished" for item in results):
                        return next(item for item in results if item.get("state") != "task_finished")
                    security_continuations.close(task)
                    store = linked_store()
                    retained = set()
                    released = 0
                    with store.transaction() as db:
                        store._require_input_release_confirmed(db, task=task, action_prefix=task + ":app:")
                    for owner in extra_owners:
                        result = store.finish_owned_resources(owner)
                        store.retire_owner(owner)
                        released += result["released"]
                        if result["retained_for_peer_or_unresolved"]:
                            retained.add(owner)
                    if bridge is not None:
                        bridge.close()
                    with runtime_gate:
                        selection_owners[task] = retained
                        if task in launch_owners and launch_owners[task] not in retained:
                            launch_owners.pop(task)
                        for key in [key for key, value in parent_contexts.items() if value["task"] == task]:
                            parent_contexts.pop(key, None)
                    try:
                        resource_manifest = AppResourceManifest(store).finish_manifest(task)
                    except (ControlError, sqlite3.Error) as error:
                        resource_manifest = {"state": "unverified",
                            "reason": getattr(error, "code", "app_resource_manifest_unavailable"),
                            "physical_cleanup_performed": False, "physical_cleanup_authority": False,
                            "process_liveness_verified": False}
                    # Commit only after all App finish checks and cleanup have succeeded.
                    store.record_event("app_channel_finished", task=task, details={})
                    return {"state": "task_finished", "finished_channel": "app",
                            "input_release": "released", "indicator_closed": True,
                            "input_dispatched": False, "historical_receipts_preserved": True,
                            "connections": results, "extra_targets_released": released,
                            "extra_owners_retained_for_cleanup": len(retained),
                            "resource_manifest": resource_manifest}
                return app_result_to_wire(await prepare(finish_cached))
            except (OriginError, ControlError, AppBoundaryError, ComputerBoundaryError) as error:
                return app_result_to_wire({"state": "task_finish_pending", "reason": error.code,
                                          "input_dispatched": False, "requires_finish_retry": True})
        arguments = {} if mode is None else {"mode": mode}
        if message is not None:
            arguments["message"] = message
        if timeout_seconds is not None:
            arguments["timeout_seconds"] = timeout_seconds
        if kind is not None:
            arguments["kind"] = kind
        return await linked_call("flower_app_pause", arguments, flower_origin, "pause", **arguments)

    from .mcp_argument_adapter import preserve_literal_string_arguments
    preserve_literal_string_arguments(server)
    from .antigravity_adapter import install_antigravity_adapter
    install_antigravity_adapter(server, "flower-app")
    return server


server = create_app_server()


if __name__ == "__main__":
    awareness = ctypes.windll.user32.SetProcessDpiAwarenessContext
    awareness.argtypes = [ctypes.c_void_p]
    awareness.restype = ctypes.c_bool
    awareness(ctypes.c_void_p(-4))
    create_app_server(fixture_target=FixtureTarget.from_environment("app_wpf")).run(
        transport="stdio")
