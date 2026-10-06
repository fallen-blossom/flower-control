"""App MCP entrypoint with task-bound ordinary window selection."""
from __future__ import annotations

import asyncio
import ctypes
import hashlib
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
from flower_control.control.state import ControlError, StateStore
from flower_control.control.jev_runtime import client_factory as jev_client_factory, enabled as jev_enabled
from flower_control.control.jev_diagnostics import public_tool_call_async
from flower_control.control.native import process_creation_filetime
from flower_control.drivers.app_control import (AppAuthorization, AppBoundaryError,
                                                AppRuntime)
from flower_control.drivers.app_host_lifetime import AppHostLifetime, AppLaunchCall
from flower_control.drivers.computer_capture import CaptureError
from flower_control.drivers.computer_mcp import (ComputerAuthorization,
                                                 ComputerBoundaryError,
                                                 ComputerRuntime)
from flower_control.drivers.computer_native import NativeInputError
from flower_control.drivers.computer_native import WindowIdentity, bind_window
from flower_control.drivers.high_helper import HighHelperClient
from flower_control.drivers.app_screenshot import (authorize_app_screenshot_return,
                                                   capture_app_screenshot)
from flower_control.drivers.app_lifecycle import (AppLifecycleError, launch_application,
                                                request_normal_close, safe_launch_diagnostic)
from flower_control.drivers.app_recording import record_window
from flower_control.control.arbitration import wait_for_turn_sync
from flower_control.control.worker_call import command_hash
from flower_control.control.native import FOREGROUND_INPUT_RESOURCE
from flower_control.browser_window_policy import BrowserWindowPolicy
from flower_control.local_target import FixtureTarget, LocalTargetError, _process_image_and_liveness
from flower_control.target_wire import (app_result_to_wire as _app_result_to_wire, app_target_from_wire,
                                        app_target_to_wire)
from flower_control.drivers.app_errors import explain_app_error as explain_error
from flower_control.window_registry import WindowRegistry, WindowSelectionError


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

    @staticmethod
    def _key(task: str, action_id: str) -> str:
        return AppRuntime._action_key(task, action_id)

    def stop_for_task(self, task: str) -> None:
        with self._host_gate:
            for key, event in self._stops.items():
                if key.startswith(task + ":app:"):
                    event.set()


def create_app_server(runtime: AppRuntime | None = None,
                      *, fixture_target: FixtureTarget | None = None) -> FastMCP:
    high_bridges = {}
    lifetime = AppHostLifetime()
    @asynccontextmanager
    async def lifespan(_server):
        try:
            yield {}
        finally:
            await lifetime.close()
            for bridge in tuple(high_bridges.values()):
                await asyncio.to_thread(bridge.close)
            for activator in tuple(activators.values()):
                await asyncio.to_thread(activator.close_capture_sessions)
    server = FastMCP("flower-app", lifespan=lifespan)
    source = loaded_source(__file__)
    if runtime is not None and fixture_target is not None:
        raise ValueError("choose one trusted adapter")
    if fixture_target is not None and fixture_target.kind != "app_wpf":
        raise ValueError("wrong fixture kind")
    runtimes: dict[str, AppRuntime] = {}
    activators: dict[str, ComputerRuntime] = {}
    runtime_gate = threading.RLock()
    launch_owners: dict[str, str] = {}
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
                try:
                    return await handler(*args, **kwargs)
                finally:
                    public_stack.reset(token)
                    public_ledger.reset(ledger_token)
        return measured

    async def begin_public_call(task, tool, ledger):
        stack = public_stack.get()
        if stack is None:
            raise RuntimeError("app_public_boundary_missing")
        await stack.enter_async_context(public_tool_call_async(ledger.store,
                            task=task, channel="app", tool=tool))
        public_ledger.set(ledger)

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
                if not __import__("win32gui").IsWindow(original_target["hwnd"]):
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
                                                created, scope, store.clock() + 30,
                                                access.target_scope, access.shared_resource,
                                                window_nonce=identity.window_nonce)
                    fixture_target.verify(payload.get("target"))
                    return AppAuthorization(task, fixture_target.pid,
                                            fixture_target.hwnd,
                                            fixture_target.process_start_filetime,
                                            "app-content:synthetic-fixture",
                                            store.clock() + 30)

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
        await begin_public_call(task, tool, ledger)
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
                            diagnostic.action_status, args[0], trusted_task=task))
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
        return app_result_to_wire(outcome)

    async def call(method, *args, **kwargs) -> dict:
        try:
            return await lifetime.call(method, *args, **kwargs)
        except (AppBoundaryError, ControlError, ValueError) as error:
            return {"state": "rejected", "dispatched": False,
                    "reason": getattr(error, "code", "invalid_app_request")}
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

    @server.tool(name="flower_app_list_windows", description="List visible ordinary app windows for this chat. Returns short-lived candidate IDs and titles; no UIA content or foreground change. Optional launch={executable:absolute_exe,args:[],mode:'normal'|'background',action_id:stable_id} launches once and returns process/windows; choose a fresh candidate next.")
    @public_handler
    async def flower_app_list_windows(flower_origin: dict | None = None,
                                     launch: dict | None = None) -> dict:
        try:
            payload = {} if launch is None else {"launch": launch}
            task = await linked_task("flower_app_list_windows", payload, flower_origin)
            if windows is None:
                raise WindowSelectionError("ordinary_window_selection_unavailable")
            if launch is not None:
                if type(launch) is not dict or set(launch) - {"executable", "args", "mode", "action_id"}:
                    raise AppBoundaryError("invalid_launch_request")
                store = linked_store()
                if type(launch.get("action_id")) is not str or not 1 <= len(launch["action_id"]) <= 128:
                    raise AppBoundaryError("invalid_action_id")
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
                def run_launch(check_stop, stopped):
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
                                check_stop()
                                store.check_dispatch(owner, key)
                            preflight()
                            existing = None
                            try:
                                selected = windows.selected_root(task)
                                if _process_image_and_liveness(selected.pid).resolve() == Path(launch["executable"]).resolve():
                                    existing = selected
                            except Exception:
                                pass
                            result = launch_application(launch["executable"], launch.get("args", []),
                                mode=launch.get("mode", "normal"), preflight=preflight,
                                existing_identity=existing,
                                resolve_existing=(lambda: windows.resolve(task, asdict(existing))) if existing is not None else None)
                        except (AppLifecycleError, ControlError, ValueError, OSError) as error:
                            store.finish(owner, key, "not_verified", result_code="app_launch_rejected")
                            result = {"state": "rejected", "dispatched": False,
                                      "reason": getattr(error, "code", "launch_rejected")}
                        except Exception:
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
                    try:
                        store.record_event("app_launch", action=key, details=safe_launch_diagnostic(result))
                    except sqlite3.Error:
                        print("Flower App launch diagnostic log write failed", file=sys.stderr)
                    receipt = store.status(owner, key)
                    return {"receipt": receipt, "result": result,
                            "observation_stopped": stopped() or bool(receipt.get("cancel_requested"))}
                launch_call = AppLaunchCall(store, task, owner, run_launch)
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
            select = windows.select_replacement if replacement else windows.select
            selection_stop = threading.Event()
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

    @server.tool(name="flower_app_activate", description="Bring the selected ordinary app window to the foreground with bounded activation, then return a fresh UIA observation. Uses Computer activation, which may send one balanced auxiliary Alt tap and reports those input events separately from business actions; user takeover stops the attempt without reclaiming focus.")
    @public_handler
    async def flower_app_activate(target: dict, restore_minimized: bool,
                                  action_id: str,
                                  flower_origin: dict | None = None) -> dict:
        arguments = {"target": target, "restore_minimized": restore_minimized,
                     "action_id": action_id}
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
                                                     shared_resource=access.shared_resource)
                    activator = AppActivationRuntime(
                        active.store, resolve_activation,
                        jev_client_factory=jev_client_factory(active.store.directory),
                        high_client_factory=lambda: HighHelperClient(channel="flower-app"),
                        owned_window_binder=lambda current_task, parent, hwnd:
                            windows.bind_owned_window(current_task, parent, hwnd))
                    activators[task] = activator
                    return activator
            activator = await prepare(prepare_activator)
            activation = await lifetime.call(
                activator.activate, asdict(identity), restore_minimized, action_id,
                trusted_task=task)
            result = activation.get("result")
            if isinstance(result, dict):
                activation = {**activation, "result": {key: value for key, value in
                              result.items() if key != "image"}}
            if not isinstance(result, dict) or not result.get("foreground"):
                return app_result_to_wire({"activation": activation, "observation": None})
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

    @server.tool(name="flower_app_observe", description="Observe this chat's exact App window. UIA tree pages accept limits={cursor:next_cursor}, or {observation_id,root_ref,max_nodes?,max_depth?} for an exact subtree; cursors expire on changed identity/version. view='wait', content=true accepts limits={observation_id,ref,field,equals,timeout_seconds?:0..10,stable_observations?:1..3} and polls only that bound control. Default view='uia' returns bounded tree entries with appref (limits={max_nodes:1..192,max_depth:0..8}). view='text', content=true reads TextPattern正文: first limits={observation_id,ref,max_chars?:1..4096}, then limits={cursor:next_cursor,max_chars?}; returns Unicode-scalar pages, text_version, truncated and document_complete, independent of tree truncation. Text cursors have 300s idle and 900s total lifetime; every page rechecks authorization/identity/version. Document cap is 1048576 UTF-16 units; no full-text claim on limit/provider failure. view='item', content=true, limits={observation_id,ref,max_nodes?:1..192,max_depth?:0..8} refreshes the Realize result's bound item subtree using recheck.observation_id and realized_item_ref; new refs still target the selected window and never select the item automatically. view='parent' with the previous child target and limits={context_id:parent_context.context_id} returns fresh refs in the bound selected parent after a dialog closes, without replay or activation. view='frame', content=true returns a window image and capture metadata. owned_windows lists exact dialogs; computer returns a 30s same-chat handoff; record with content=true uses limits={duration_seconds:(0,10],fps:1..4,output_path?} to save local WGC PNG+manifest ZIP. Content modes require live App content authority. Requires trusted host context.")
    @public_handler
    async def flower_app_observe(target: dict, content: bool, action_id: str,
                                 limits: dict | None = None,
                                 view: str | None = None,
                                 flower_origin: dict | None = None) -> object:
        arguments = {"target": target, "content": content, "action_id": action_id}
        if limits is not None:
            arguments["limits"] = limits
        if view is not None:
            arguments["view"] = view
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
        if view == "record" and content is True and windows is not None:
            try:
                active, task, native = await linked_runtime("flower_app_observe", arguments, flower_origin)
                identity = await window_call(resolve_app_identity, task, native["target"])
                options = limits or {}
                return app_result_to_wire(await call(active.local_operation,
                    "flower_app_observe", native["target"], native, action_id,
                    lambda preflight, stopped: record_window(identity,
                        resolve_identity=lambda: resolve_app_identity(task, native["target"],
                            stopped=active._host_stop_callback()),
                        preflight=preflight, stopped=stopped,
                        duration_seconds=options.get("duration_seconds", 3), fps=options.get("fps", 2),
                        output_path=options.get("output_path")), read_only=True, trusted_task=task))
            except (OriginError, ControlError, WindowSelectionError, AppBoundaryError, ValueError) as error:
                return app_result_to_wire({"state": "rejected", "dispatched": False,
                    "reason": getattr(error, "code", "invalid_record_request")})
        if view != "frame" or content is not True or limits is not None:
            return app_result_to_wire({"state": "rejected", "dispatched": False,
                    "reason": "invalid_app_observation_view"})
        try:
            active, task, native = await linked_runtime("flower_app_observe", arguments,
                                                  flower_origin)

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
                resolve_identity, trusted_task=task)
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
                expected_content_scope=return_context["content_scope"],
                expected_target_scope=return_context["target_scope"],
                expected_shared_resource=return_context["shared_resource"])
        except Exception as error:
            outcome.pop("_image", None)
            return app_result_to_wire({"state": "rejected", "dispatched": False,
                    "reason": getattr(error, "code", "visual_return_not_authorized"),
                    "visual_return_suppressed": True})
        pixels = outcome.pop("_image")
        outcome.pop("_return_context", None)
        return [app_result_to_wire(outcome), Image(data=pixels, format="png")]

    @server.tool(name="flower_app_set_value", description="Set one observed non-password Value control once, then observe fresh state. automation_id accepts the current observation entry's appref: reference for duplicate or empty AutomationIds. Requires trusted host context.")
    @public_handler
    async def flower_app_set_value(target: dict, observation_id: str,
                                   automation_id: str, value: str, action_id: str,
                                   flower_origin: dict | None = None) -> dict:
        arguments = {"target": target, "observation_id": observation_id,
                     "automation_id": automation_id, "value": value, "action_id": action_id}
        return await linked_call("flower_app_set_value", arguments, flower_origin,
                                 "set_value", target, observation_id, automation_id,
                                 value, action_id)

    @server.tool(name="flower_app_invoke", description="Perform one observed UIA Invoke and check {automation_id,field,equals}; automation_id accepts a current observation appref. Semantic alternatives also include {semantic_action:'focus'}, {semantic_action:'guarded_input',value,replace?:false,check?:{automation_id,field,equals}} through the High input ledger, and {semantic_action:'flow',steps:[{operation:'set_value',ref,value}|{operation:'select_item',ref,desired}|{operation:'invoke',ref,postcondition}]}, where invoke may carry goal_hint for existing Jev selection. Flows advance fresh local refs and stop the suffix after unknown/replayed/failed results. Semantic alternatives: {semantic_action:'expand'|'collapse'}, {semantic_action:'scroll',direction:'up'|'down'|'left'|'right',amount:'small'|'large'}, {semantic_action:'realize_item',item_name:exact_name}, {semantic_action:'menu'} for one exact-ref menu step using ExpandCollapse/Invoke/SelectionItem, or {semantic_action:'close'} for one normal WM_CLOSE preserving save dialogs. goal_hint applies to ordinary Invoke/expand/collapse/scroll/realize; menu requires an exact current reference. Returns fresh refs after each step and approved owned-window/parent continuation when available; dialog purpose and final save result need independent verification. Never auto-confirms a dialog or replays an unknown write. Requires trusted host context.")
    @public_handler
    async def flower_app_invoke(target: dict, observation_id: str,
                                automation_id: str, postcondition: dict,
                                action_id: str,
                                flower_origin: dict | None = None) -> dict:
        arguments = {"target": target, "observation_id": observation_id,
                     "automation_id": automation_id, "postcondition": postcondition,
                     "action_id": action_id}
        if (type(postcondition) is dict and postcondition.get("semantic_action") == "close"
                and set(postcondition) <= {"semantic_action", "goal_hint"}
                and windows is not None):
            try:
                if "goal_hint" in postcondition and (type(postcondition["goal_hint"]) is not str
                        or not postcondition["goal_hint"].strip()):
                    raise AppBoundaryError("invalid_target_goal")
                active, task, native = await linked_runtime("flower_app_invoke", arguments, flower_origin)
                identity = await window_call(resolve_app_identity, task, native["target"])
                root_before = await prepare(windows.selected_root, task)
                outcome = await call(active.close_window, native["target"], native, action_id,
                    identity=identity, resolve_identity=lambda: resolve_app_identity(task, native["target"],
                        stopped=active._host_stop_callback()),
                    trusted_task=task) if active.high_bridge is not None else await call(active.local_operation,
                    "flower_app_invoke", native["target"], native, action_id,
                    lambda preflight, stopped: request_normal_close(identity,
                        resolve_identity=lambda: resolve_app_identity(task, native["target"],
                            stopped=active._host_stop_callback()),
                        preflight=preflight), foreground=True, trusted_task=task)
                return app_result_to_wire(await fresh_window_context(task, active, root_before,
                                                                     native["target"], outcome))
            except (OriginError, ControlError, WindowSelectionError, AppBoundaryError, ValueError) as error:
                return app_result_to_wire({"state": "rejected", "dispatched": False,
                    "reason": getattr(error, "code", "invalid_close_request")})
        return await linked_call("flower_app_invoke", arguments, flower_origin,
                                 "invoke", target, observation_id, automation_id,
                                 postcondition, action_id)

    @server.tool(name="flower_app_set_toggle", description="Set an observed UIA Toggle control to exact on or off with at most one Toggle call, then check fresh state; Indeterminate is neither on nor off and a single provider transition may not reach the desired state. automation_id also accepts the current observation entry's appref: reference.")
    @public_handler
    async def flower_app_set_toggle(target: dict, observation_id: str,
                                    automation_id: str, desired: bool, action_id: str,
                                    flower_origin: dict | None = None) -> dict:
        arguments = {"target": target, "observation_id": observation_id,
                     "automation_id": automation_id, "desired": desired,
                     "action_id": action_id}
        return await linked_call("flower_app_set_toggle", arguments, flower_origin,
                                 "set_toggle", target, observation_id, automation_id,
                                 desired, action_id)

    @server.tool(name="flower_app_select_item", description="Set an observed UIA SelectionItem to desired=true (default) or false (RemoveFromSelection), at most once; already satisfied means zero writes. Return fresh refs and selected readback. automation_id accepts the observation's appref.")
    @public_handler
    async def flower_app_select_item(target: dict, observation_id: str,
                                     automation_id: str, action_id: str,
                                     flower_origin: dict | None = None, desired: bool | None = None) -> dict:
        arguments = {"target": target, "observation_id": observation_id,
                     "automation_id": automation_id, "action_id": action_id}
        if desired is not None:
            arguments["desired"] = desired
        return await linked_call("flower_app_select_item", arguments, flower_origin,
                                 "select_item", target, observation_id,
                                 automation_id, action_id, desired=True if desired is None else desired)

    @server.tool(name="flower_app_action_status", description="Read this chat's App action state and anonymous waiting reasons without dispatching again.")
    @public_handler
    async def flower_app_action_status(action_id: str,
                                       flower_origin: dict | None = None) -> dict:
        return await linked_call("flower_app_action_status", {"action_id": action_id},
                                 flower_origin, "action_status", action_id)

    @server.tool(name="flower_app_cancel", description="Request stop for an action belonging to the trusted current task.")
    @public_handler
    async def flower_app_cancel(action_id: str,
                                flower_origin: dict | None = None) -> dict:
        return await linked_call("flower_app_cancel", {"action_id": action_id},
                                 flower_origin, "cancel", action_id)

    @server.tool(name="flower_app_pause", description="Pause this chat's selected App window and stop in-flight actions. mode='resume' uses the explicit request in this chat and checks the same approved window/task snapshot, then requires new observation; no activation or local continue card. Unknown input release, quarantine and unresolved execution remain blocked. Unrelated background resources remain usable.")
    @public_handler
    async def flower_app_pause(flower_origin: dict | None = None, mode: str | None = None) -> dict:
        return await linked_call("flower_app_pause", {} if mode is None else {"mode": mode},
                                 flower_origin, "pause", **({"mode": mode} if mode is not None else {}))

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
