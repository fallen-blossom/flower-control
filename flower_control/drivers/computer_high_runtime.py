"""Computer consumers of the fixed broker; no installation or elevation here."""
from contextlib import contextmanager, nullcontext
from dataclasses import asdict, replace
import hashlib
import time
import uuid

from flower_control._executor_metadata import executor_metadata
from flower_control.control.arbitration import wait_for_turn_sync
from flower_control.control.foreground_stage import begin_foreground_stage
from flower_control.control.native import physical_window_resource
from flower_control.control.state import ControlError
from flower_control.window_registry import WindowSelectionError
from . import computer_native as native
from .computer_capture import CaptureError
from .computer_high import assert_target_geometry, input_plan
from .computer_targets import CandidateError, checked_click_arguments, _region_digest
from .foreground_indicator import ForegroundIndicator, IndicatorError
from .high_helper import HighHelperError, HighTarget
import win32con
import win32gui


def require_local_capability(hwnd, pid):
    """An absent broker permits only a known same-session, sufficient-IL actor."""
    target = HighTarget.inspect(hwnd, pid)
    actor = executor_metadata()
    if (actor.get("metadata_available") is not True or actor.get("session_id") != target.facts["Session"]
            or type(actor.get("integrity_rid")) is not int
            or target.facts["Integrity"] not in {8192, 12288}
            or actor["integrity_rid"] < target.facts["Integrity"]):
        raise HighHelperError("broker_unavailable_for_target")
    return actor


def bind_selected_window(runtime, request, current):
    # The registry supplies this exact immutable candidate and verifies again
    # after return. Neither a probe nor a broker handshake creates its grant.
    def check():
        if time.monotonic() >= request.expires_at or not current():
            raise WindowSelectionError("candidate_changed")

    check()
    status = runtime._high.status(request.task) if runtime._high is not None else None
    if status is None:
        if runtime._high is not None:
            require_local_capability(request.hwnd, request.pid)
        check()
        identity = native.bind_window(request.hwnd)
        check()
        return identity
    # Binding is metadata only. The helper's read-only checks still enforce
    # source, desktop, process identity and shutdown while Stop remains set.
    target = HighTarget.inspect(request.hwnd, request.pid, broker_revision=status.desktop_revision)
    if target.facts["Created"] != request.created:
        raise WindowSelectionError("candidate_changed")
    owner = runtime._task_owner(request.task)
    resource = physical_window_resource(request.pid, request.created, request.hwnd)
    runtime.store.register_resource(resource, required_scope=request.access.target_scope)
    runtime.store.bind_owned_resource(owner, resource)
    resources = (resource,)
    if request.access.shared_resource is not None:
        runtime.store.register_resource(request.access.shared_resource, required_scope=request.access.target_scope)
        resources += (request.access.shared_resource,)
    key = runtime._key(request.task, "bind-" + uuid.uuid4().hex)
    runtime.store.enqueue(owner, action_id=key,
        fingerprint=hashlib.sha256(repr((request.hwnd, request.pid, request.created)).encode()).hexdigest(),
        resources=resources, scope=request.access.target_scope, read_only=True,
        context={"channel": "computer", "operation": "bind"})
    # Queue failures are also pre-dispatch failures: never leave an abandoned
    # eligible bind request ahead of later real actions.
    try:
        decision = wait_for_turn_sync(runtime.store, owner, key, resources,
            client_factory=runtime.jev_client_factory, timeout=max(0, min(5, request.expires_at - time.monotonic())))
    except BaseException:
        if runtime.store.status(owner, key)["state"] == "queued":
            runtime.store.cancel(owner, key)
        raise
    if decision.action_id != key:
        runtime.store.cancel(owner, key)
        raise WindowSelectionError("window_binding_busy")

    @contextmanager
    def before_go(lease):
        with runtime.store.dispatch_external(owner, key, decision.decision_id, lease):
            check()
            runtime.store.check_dispatch(owner, key)
            yield
            check()
            runtime.store.check_dispatch(owner, key)
            receipt = lease.result
            bound = (receipt is not None and receipt["State"] == "bound"
                     and receipt["MutexReleased"] and receipt["InputRelease"] == "released")
            runtime.store.finish(owner, key, "verified" if bound else "not_verified",
                                 result_code="window_bound" if bound else "window_binding_failed")

    try:
        outcome = runtime._high.session(request.task).execute(request.task, target, {"Kind": "bind"},
            before_go=before_go, stopped=lambda: not current() or
                runtime.store.external_dispatch_stopped(owner, key), resources=resources)
        if outcome["receipt"]["State"] != "bound":
            raise WindowSelectionError(outcome["receipt"].get("Reason") or "window_binding_failed")
        identity = outcome["target"]
        check()
        native.assert_window(identity)
        return identity
    except BaseException:
        if runtime.store.status(owner, key)["state"] == "queued":
            runtime.store.cancel(owner, key)
        raise


def recover_release_for_status(runtime, task, key):
    # Ordinary queries remain useful for a closed window and absent helper.
    # Only persisted external unconfirmed ledgers warrant a recovery query.
    with runtime.store.transaction() as db:
        row = db.execute("SELECT b.confirmed,b.executor_process,o.process FROM input_release_bindings b "
            "JOIN actions a ON a.id=b.action JOIN owners o ON o.id=a.owner WHERE a.id=? AND a.task=?",
            (key, task)).fetchone()
    if not row or row["confirmed"] is not None or row["executor_process"] == row["process"]:
        return None
    try:
        owner = runtime._task_owner(task)
        runtime.store.external_release_pending(owner, key)
        runtime._high.session(task)  # Lazy client construction; no business request.
        runtime._high.client.recover_release(runtime.store, owner, key)
        return {"state": "confirmed", "business_outcome_verified": False}
    except (ControlError, HighHelperError) as error:
        return {"state": "pending", "reason": error.code, "business_outcome_verified": False}


def _released(receipt):
    return (receipt["NativeCountKnown"] and receipt["InputRelease"] == "released"
            and receipt["MutexReleased"] and receipt["SemanticExecutorExited"] is not False)


def _complete(receipt):
    return (_released(receipt) and receipt["State"] == "dispatched_unverified"
            and receipt["InputResult"] is not None and receipt["InputResult"]["BusinessComplete"]
            and not receipt["RequiresNewObservation"])


def _layout_completed(receipt):
    layout = receipt.get("LayoutResult")
    return (layout is not None and layout["CallReturned"] is True
            and receipt["SemanticExecutor"] is not None and receipt["SemanticExecutorExited"] is True)


def _layout_state(receipt):
    layout = receipt["LayoutResult"]
    if not layout["DispatchAttempted"]:
        return "rejected"
    if not _layout_completed(receipt):
        return "outcome_uncertain"
    if layout["ApiSucceeded"] is False:
        return "window_layout_api_failed"
    if layout["RequestedReached"] is False:
        return "window_layout_adjusted"
    return "window_layout_dispatched"


_INTERRUPTION_FACTS = {"input_stopped": "explicit_stop", "broker_paused": "explicit_stop",
    "global_write_stopped": "explicit_stop",
    "foreground_changed": "foreground_changed",
    "geometry_changed": "geometry_changed", "client_geometry_changed": "geometry_changed",
    "target_minimized": "target_minimized", "input_context_changed": "ime_changed",
    "external_input_held": "external_keyboard", "deadline_expired": "deadline_exceeded",
    "desktop_topology_changed": "geometry_changed", "mouse_receiver_changed": "external_mouse"}


def _detail(receipt):
    value = receipt["InputResult"]
    detail = {"execution_route": "high_broker", "native_receipt": receipt,
        "dispatched": True if receipt["ActivationRequested"] or receipt["BusinessEvents"] or receipt["ImeEvents"] else
            False if receipt["NativeCountKnown"] else None,
        "input_dispatched": True if receipt["BusinessEvents"] else
            False if receipt["NativeCountKnown"] else None,
        "sent_events": receipt["BusinessEvents"] + receipt["ImeEvents"],
        "business_events": receipt["BusinessEvents"], "ime_events": receipt["ImeEvents"],
        "activation_events": receipt["ActivationEvents"], "native_count_known": receipt["NativeCountKnown"],
        "sent_batches": value["CompletedPlans"] if value else 0,
        "input_release": receipt["InputRelease"], "foreground": receipt["Foreground"],
        "business_outcome_verified": False, "requires_new_observation": receipt["RequiresNewObservation"],
        "ime_preparation": receipt["ImePreparation"],
        "activation": {"foreground": receipt["Foreground"],
            "activation_input_events": receipt["ActivationEvents"],
            "activation_request_sent": receipt["ActivationRequested"],
            "activation_diagnostics": receipt["ActivationDiagnostics"]},
        **({"input_result": value, "sent_segments": value["CompletedSegments"],
             "timed_plan_completed": value["BusinessComplete"]} if value else {})}
    if receipt.get("LayoutResult") is not None:
        layout = receipt["LayoutResult"]
        detail.update(dispatched=layout["Dispatched"], layout_result={
            "command": layout["Command"], "requested_rect": layout["RequestedRect"],
            "observed_rect": layout["ObservedRect"], "dispatch_attempted": layout["DispatchAttempted"],
            "call_returned": layout["CallReturned"],
            "api_succeeded": layout["ApiSucceeded"], "dispatched": layout["Dispatched"],
            "requested_reached": layout["RequestedReached"]},
            semantic_executor=receipt["SemanticExecutor"],
            semantic_executor_exited=receipt["SemanticExecutorExited"])
    return detail


def execute_high(runtime, owner, resource, grant, key, command, payload, decision_id,
                 resources, stop, status, *, observation=None, generation=None, batches=None,
                 geometry=None, restore_minimized=False, sequence=None, shared_revision=None,
                 semantic_candidate=None, region_version=None, layout_plan=None):
    from .computer_mcp import ComputerBoundaryError, _indicator_paths, _plan_input
    store = runtime.store
    stage = indicator = lease_seen = None
    native_receipts, step_observations, checks, sent_prefix = [], [], [], []
    expected_shared = shared_revision
    partial_step = None
    result, reason, error_details = None, None, None
    before_windows = frozenset()
    return_parent = None
    sequence_started = False
    final_sequence = "sequence_stopped"
    terminal = "not_verified"
    original_revision = status.desktop_revision
    restore_pending = False
    tool = "flower_computer_activate" if command == "activate" else "flower_computer_input"

    def stopped():
        return (stop.is_set() or grant.expires_at <= store.clock()
                or store.external_dispatch_stopped(owner, key))

    def check(*, running=True, expected_geometry=None, foreground=False):
        if stop.is_set():
            raise ComputerBoundaryError("input_stopped")
        runtime._authorized(tool, payload, payload.get("target"), "input", trusted_task=grant.task_id)
        if grant.expires_at <= store.clock():
            raise ComputerBoundaryError("trusted_call_expired")
        if running:
            store.check_dispatch(owner, key)
            if grant.shared_resource is not None and expected_shared is not None:
                with store.transaction() as db:
                    row = db.execute("SELECT revision FROM resources WHERE id=?", (grant.shared_resource,)).fetchone()
                if row is None or row[0] != expected_shared + 1:
                    raise ComputerBoundaryError("observation_unavailable")
        native.assert_window(grant.identity)
        # The helper restores a minimized target and checks these original
        # observed pixels before business input. Never plan against its iconic
        # bounds, and never replace the observation with restore-time geometry.
        if (expected_geometry is not None
                and not (restore_pending and win32gui.IsIconic(grant.identity.hwnd))):
            native.assert_geometry(expected_geometry)
        if foreground:
            native.assert_foreground(grant.identity)

    def finish(receipt):
        nonlocal terminal
        terminal = "not_verified" if _released(receipt) else "outcome_uncertain"
        if (layout_plan is not None and receipt["LayoutResult"]["DispatchAttempted"]
                and not _layout_completed(receipt)):
            terminal = "outcome_uncertain"
        if (command == "input" and receipt["BusinessEvents"] and not _complete(receipt)
                and receipt["InputResult"] is not None and not receipt["InputResult"]["BusinessComplete"]
                and receipt["Reason"] not in _INTERRUPTION_FACTS):
            terminal = "outcome_uncertain"
        if command == "activate" and _released(receipt) and receipt["State"] == "activated" and receipt["Foreground"]:
            terminal = "verified"  # Only this activation fact; business remains unverified.
        if layout_plan is not None:
            result_code = reason or receipt["Reason"] or (
                "computer_window_layout_dispatched" if receipt["LayoutResult"]["Dispatched"] is True
                else "computer_window_layout_not_completed")
        else:
            result_code = reason or ("computer_activated" if command == "activate" and terminal == "verified"
                else "computer_input_dispatched" if _complete(receipt) else
                receipt["Reason"] or "computer_high_not_completed")
        store.finish(owner, key, terminal,
            result_code=result_code,
            sequence_final_state=final_sequence if sequence_started else None)

    try:
        check(running=False)
        if command == "input":
            with runtime._gate:
                observed = runtime._observations.get(observation)
            if (observed is None or observed["task"] != grant.task_id or observed["identity"] != grant.identity
                    or observed.get("broker_revision") != original_revision):
                raise ComputerBoundaryError("desktop_revision_requires_new_observation")
        # Activation has no pixel coordinates. A minimized window commonly has
        # a zero-size client; the helper restores it before any later capture.
        # Input/layout still require the exact original observed geometry.
        if geometry is None and command != "activate":
            geometry = native.window_geometry(grant.identity)
        target = HighTarget.inspect(grant.identity.hwnd, grant.identity.pid, nonce=grant.identity.window_nonce,
                                    broker_revision=original_revision)
        if layout_plan is not None:
            try:
                normal = (not win32gui.IsIconic(grant.identity.hwnd)
                          and win32gui.GetWindowPlacement(grant.identity.hwnd)[1] != win32con.SW_SHOWMAXIMIZED)
            except win32gui.error as error:
                raise native.NativeInputError("window_missing") from error
            if not normal:
                raise ComputerBoundaryError("window_layout_requires_normal_window")
        restore_pending = layout_plan is None and command == "input" and bool(win32gui.IsIconic(grant.identity.hwnd))
        if restore_pending:
            target = replace(target,
                bounds=(geometry.window.left, geometry.window.top, geometry.window.right, geometry.window.bottom),
                client_rect=(0, 0, *geometry.client_size), client_origin=geometry.client_origin, window_dpi=geometry.dpi)
        if geometry is not None:
            assert_target_geometry(target, geometry)
        before_windows = observed["visible_windows"] if command == "input" else native.visible_process_top_levels(grant.identity)
        parent_hwnd = win32gui.GetWindow(grant.identity.hwnd, win32con.GW_OWNER)
        if parent_hwnd:
            try:
                parent = native._read_window_identity(parent_hwnd)
                if (parent.pid == grant.identity.pid and parent.process_created == grant.identity.process_created
                        and native.is_owned_popup(parent, grant.identity.hwnd)):
                    return_parent = parent
            except native.NativeInputError:
                pass
        if command == "input":
            new = native.new_visible_followups(grant.identity, before_windows, bind_allowed=False)
            if new["visual_scope"] != "target_window_only":
                raise ComputerBoundaryError("new_window_detected")
        total = len(sequence) if sequence else 1
        chain_context = store.external_sequence(owner, key, decision_id, total_steps=total) if sequence else nullcontext(None)
        with chain_context as chain:
            try:
                for index in range(total):
                    # Exactly one native request now. Never send the suffix before
                    # the preceding real capture/expect and fresh Store.observe.
                    step_command, step_batches = (sequence[index][0], (sequence[index][1],)) if sequence else (
                        payload.get("command", command), batches)
                    if index:
                        check(expected_geometry=geometry, foreground=True)
                    if step_command in {"click_candidate", "click_region", "choose_region"}:
                        step_command = "click"
                    if layout_plan is not None:
                        plan, operation = layout_plan, layout_plan.operation()
                    elif command == "activate":
                        plan, operation = None, {"Kind": "activate", "RestoreMinimized": restore_minimized}
                    else:
                        plan = input_plan(step_command, step_batches,
                            task=grant.task_id, action=key, observation=observation, generation=generation,
                            sequence_step=index if sequence else None)
                        operation = plan.operation(restore_minimized=True)

                    @contextmanager
                    def before_go(lease):
                        nonlocal stage, indicator, lease_seen, sequence_started, partial_step, result
                        lease_seen = lease
                        dispatch = chain.before_go(lease) if chain else store.dispatch_external(owner, key, decision_id, lease)
                        with dispatch:
                            if stage is None:
                                stage = begin_foreground_stage(store, owner, key, target_resource=resource,
                                    channel="computer", operation=payload.get("command", command))
                            stage.bind_input_release(lease.ledger_identity, executor_process=lease.executor_process)
                            check(expected_geometry=geometry)
                            if command == "input":
                                new = native.new_visible_followups(grant.identity, before_windows, bind_allowed=False)
                                if new["visual_scope"] != "target_window_only":
                                    raise ComputerBoundaryError("new_window_detected")
                            if command == "activate":
                                with store.transaction() as db:
                                    store._require_scope(db, grant.task_id, grant.capture_scope)
                            if indicator is None:
                                def on_stop():
                                    stop.set()
                                    store.pause_computer_target(grant.task_id, resource)
                                indicator = runtime._acquire_indicator(grant,
                                    payload.get("goal_hint") or payload.get("command") or "窗口操作", on_stop, prepare=True, factory=ForegroundIndicator,
                                    paths=_indicator_paths(
                                        tuple(item[1] for item in sequence) if sequence else step_batches or (), geometry))
                            indicator.set_stage("prepare", checkpoint=f"准备步骤 {index + 1}/{total}" if sequence else
                                "重查目标与窗口外框" if layout_plan is not None else "重查目标与输入位置")
                            if region_version is not None or semantic_candidate is not None:
                                if restore_pending and win32gui.IsIconic(grant.identity.hwnd):
                                    raise ComputerBoundaryError("candidate_requires_new_observation")
                                snapshot = runtime._capture(grant, preflight=lambda: check(expected_geometry=geometry), stopped=stop.is_set)
                                if region_version is not None and _region_digest(snapshot, region_version[0]) != region_version[1]:
                                    raise ComputerBoundaryError("candidate_requires_new_observation")
                                if semantic_candidate is not None:
                                    checked = checked_click_arguments(semantic_candidate, identity=grant.identity,
                                        geometry=geometry, capture=snapshot, computer_observation_id=observation)
                                    expected_batches = _plan_input("click", checked, geometry)
                                    # The immutable plan was already sent at prepare;
                                    # compare it, never replace after ready.
                                    if input_plan("click", expected_batches, task=grant.task_id, action=key,
                                        observation=observation, generation=generation).wire() != plan.wire():
                                        raise ComputerBoundaryError("candidate_requires_new_observation")
                            if sequence:
                                if not sequence_started:
                                    store.start_computer_sequence(owner, key, total)
                                    sequence_started = True
                                store.begin_computer_sequence_step(owner, key, index)
                                partial_step = index
                            check(expected_geometry=geometry)
                            indicator.set_stage("input", checkpoint=f"步骤 {index + 1}/{total}" if sequence else
                                "执行已绑定窗口调整" if layout_plan is not None else "执行已绑定输入")
                            yield
                            actual = lease.result
                            native_receipts.append(actual)
                            result = {**_detail(actual), "executor_process": lease.executor_process,
                                      "peer_evidence": dict(lease.peer_evidence)}
                            interruption = _INTERRUPTION_FACTS.get(actual["Reason"])
                            if interruption == "explicit_stop":
                                # HUD/explicit pause already records the exact
                                # selected-window Stop through pause_computer_target.
                                # The stage's explicit_stop method instead pauses
                                # the whole chat. Host cancellation/expiry must
                                # never acquire that wider persistent effect.
                                interruption = None
                            if interruption is not None and lease.go_sent:
                                stage.interrupt_after_external(lease, interruption)
                            if sequence:
                                complete = (_released(actual) and actual["InputResult"] is not None
                                            and actual["InputResult"]["BusinessComplete"])
                                store.finish_computer_sequence_step(owner, key, index, complete=complete,
                                    input_release="released" if _released(actual) else "release_pending")
                                partial_step = None if complete else index
                                if complete:
                                    sent_prefix.append(index)
                            else:
                                finish(lease.result)

                    session = runtime._high.session(grant.task_id)
                    if layout_plan is not None:
                        outcome = session.execute_window_layout(grant.task_id, target, plan,
                            before_go=before_go, stopped=stopped, resources=resources, deadline_ms=3000)
                    else:
                        outcome = session.execute(grant.task_id, target, operation,
                            before_go=before_go, stopped=stopped, resources=resources, deadline_ms=5000)
                    receipt = outcome["receipt"]
                    result = {**_detail(receipt), **{name: outcome[name] for name in
                        ("executor_process", "helper_session_retained", "helper_exited", "helper_exit_reason", "new_connection",
                         "new_helper_process", "peer_evidence", "broker_version", "connection_id", "parent_timings_ms")}}
                    if receipt["Reason"]:
                        reason = receipt["Reason"]
                    if not sequence:
                        result["state"] = _layout_state(receipt) if layout_plan is not None else (
                            "activated" if terminal == "verified" else "input_dispatched" if _complete(receipt)
                            else "not_verified" if _released(receipt) else "outcome_uncertain")
                        break
                    complete = (_released(receipt) and receipt["InputResult"] is not None
                                and receipt["InputResult"]["BusinessComplete"])
                    if not complete or not _complete(receipt) or stopped():
                        break
                    indicator.set_stage("verify", checkpoint=f"复查步骤 {index + 1}")
                    new = native.new_visible_followups(grant.identity, before_windows, bind_allowed=False)
                    if new["visual_scope"] != "target_window_only":
                        reason = "new_window_detected"
                        result.update(new)
                        break
                    fresh = runtime._capture_observation(grant, owner, resource,
                        lambda: check(expected_geometry=geometry, foreground=True), stop.is_set)
                    with runtime._gate:
                        fresh_meta = runtime._observations[fresh["observation_id"]]
                        old_meta = runtime._observations[observation]
                    if fresh_meta["broker_revision"] != original_revision:
                        raise ComputerBoundaryError("desktop_revision_changed")
                    expectation = sequence[index][2]
                    digest = fresh_meta["image_digest"]
                    matched = (expectation == "capture_available" or
                        expectation == "image_changed" and digest != old_meta["image_digest"] or
                        expectation == "image_unchanged" and digest == old_meta["image_digest"])
                    step_observations.append({"index": index, "command": step_command, "expect": expectation,
                        "observation_id": fresh["observation_id"], "generation": fresh_meta["generation"], "image": fresh["image"]})
                    checks.append({"index": index, "expect": expectation, "matched": matched})
                    # A popup may appear while the screenshot is captured.
                    check(expected_geometry=geometry, foreground=True)
                    new = native.new_visible_followups(grant.identity, before_windows, bind_allowed=False)
                    if new["visual_scope"] != "target_window_only":
                        reason = "new_window_detected"
                        result.update(new)
                        break
                    if not matched:
                        reason = "step_condition_unmet"
                        break
                    observation, generation = fresh["observation_id"], fresh_meta["generation"]
                    expected_shared = fresh_meta.get("shared_revision")
                    # Continuation consumes one additional shared revision. The
                    # capture check above used the preceding dispatch's revision.
                    if index == total - 1:
                        final_sequence = "sequence_completed"
                if sequence and sequence_started:
                    finish(native_receipts[-1])
            except BaseException:
                # Finalize inside the existing action context, before its ledger
                # cleanup. Never re-enter dispatch on a running action.
                if sequence_started and store.status(owner, key)["state"] == "running":
                    known = lease_seen is not None and lease_seen.result is not None and _released(lease_seen.result)
                    store.finish(owner, key, "not_verified" if known and partial_step is None else "outcome_uncertain",
                        result_code="computer_sequence_interrupted",
                        sequence_final_state="sequence_stopped" if known and partial_step is None else "outcome_uncertain")
                raise
    except (ControlError, HighHelperError, native.NativeInputError, ComputerBoundaryError,
            CaptureError, IndicatorError, CandidateError, ValueError) as error:
        reason = getattr(error, "code", "invalid_computer_request")
        error_details = dict(error.details) if isinstance(error, HighHelperError) else None
        current = store.status(owner, key)
        if current["state"] == "queued":
            store.cancel(owner, key)
        if lease_seen is not None and lease_seen.result is not None and result is None:
            result = _detail(lease_seen.result)
        if result is None:
            result = {"execution_route": "high_broker", "business_outcome_verified": False}
        result["reason"] = reason
        if error_details:
            result["helper_diagnostics"] = error_details
    finally:
        if indicator is not None:
            released = lease_seen is not None and lease_seen.result is not None and _released(lease_seen.result)
            if stop.is_set():
                indicator.set_stage("stopped" if released else "release_unconfirmed",
                    checkpoint="本次输入已停止" if released else "输入释放尚未确认",
                    input_release="released" if released else "unknown")
            runtime._finish_indicator(indicator, stopped=stop.is_set(), released=released)
        with runtime._gate:
            if key not in runtime._host_calls:
                runtime._stops.pop(key, None)

    receipt = store.status(owner, key)
    uncertain = receipt["state"] == "outcome_uncertain"
    latest = lease_seen.result if lease_seen is not None else None
    # The Store includes the latest ledger, including a dispatched step whose
    # done never arrived. An older accepted step cannot confirm that release.
    if receipt.get("input_release") is not None:
        result["input_release"] = receipt["input_release"]
    if lease_seen is not None:
        result["native_receipt"] = latest
        if latest is None:
            for name in ("input_result", "timed_plan_completed", "sent_segments", "foreground", "activation",
                         "ime_preparation", "helper_session_retained", "helper_exited", "helper_exit_reason",
                         "new_connection", "new_helper_process", "parent_timings_ms"):
                result.pop(name, None)
            result.update(native_count_known=False, requires_new_observation=True,
                           executor_process=lease_seen.executor_process, peer_evidence=dict(lease_seen.peer_evidence))
    if layout_plan is not None and "layout_result" not in result:
        unknown = lease_seen is not None and lease_seen.go_sent and latest is None
        wire = layout_plan.wire()
        result["layout_result"] = {"command": wire["command"], "requested_rect": wire["requested_rect"],
            "observed_rect": None, "dispatch_attempted": None if unknown else False,
            "call_returned": None if unknown else False,
            "api_succeeded": None, "dispatched": None if unknown else False,
            "requested_reached": None if unknown else False}
        result.update(semantic_executor=None, semantic_executor_exited=None)
    if layout_plan is not None and lease_seen is not None and (
            latest is not None and latest["RequiresNewObservation"] or latest is None and lease_seen.go_sent):
        # Missing done cannot certify that the old pixels survived. Invalidate
        # every prior image of this target, including sibling observations.
        with runtime._gate:
            handles = [handle for handle, row in runtime._observations.items()
                       if row["task"] == grant.task_id and row["identity"] == grant.identity]
            for handle in handles:
                runtime._observations[handle]["expires"] = 0
        with store.transaction() as db:
            for handle in handles:
                db.execute("UPDATE observations SET expires=0 WHERE id=? AND task=? AND resource=?",
                           (handle, grant.task_id, resource))
        result["requires_new_observation"] = True
    if sequence:
        suffix_start = len(sent_prefix)
        if (partial_step is not None and lease_seen is not None and lease_seen.go_sent
                and (latest is None or latest["BusinessEvents"] or not latest["NativeCountKnown"])):
            suffix_start = max(suffix_start, partial_step + 1)
        result.update(state="outcome_uncertain" if uncertain else final_sequence,
            sent_prefix=sent_prefix, undispatched_suffix=list(range(suffix_start, len(sequence))),
            partial_step=partial_step, step_checks=checks, step_observations=step_observations,
            native_steps=native_receipts,
            sent_events=sum(item["BusinessEvents"] + item["ImeEvents"] for item in native_receipts),
            business_events=sum(item["BusinessEvents"] for item in native_receipts),
            ime_events=sum(item["ImeEvents"] for item in native_receipts),
            activation_events=sum(item["ActivationEvents"] for item in native_receipts),
            counts_complete=(latest is not None and all(item["NativeCountKnown"] for item in native_receipts)),
            sent_batches=sum((item["InputResult"] or {}).get("CompletedPlans", 0) for item in native_receipts))
        result["dispatched"] = (True if any(item["ActivationRequested"] or item["BusinessEvents"] or item["ImeEvents"]
            for item in native_receipts) else None if uncertain else False)
        result["input_dispatched"] = (True if any(item["BusinessEvents"] for item in native_receipts)
            else None if uncertain else False)
    elif uncertain:
        result["state"] = "outcome_uncertain"
    elif "state" not in result:
        accepted = native_receipts[-1] if native_receipts else None
        result["state"] = (_layout_state(accepted) if layout_plan is not None and accepted is not None else
            "activated" if command == "activate" and receipt["state"] == "verified" else
            "input_dispatched" if accepted is not None and _complete(accepted) else
            "not_verified" if accepted is not None else "rejected")
    if "dispatched" not in result:
        result["dispatched"] = None if uncertain else False
    if reason:
        result["reason"] = reason

    # The original dispatch and facade lock are now closed. Followup binding
    # and an actual new observation can use the normal registry/queue safely.
    last = latest
    if (last is not None and receipt.get("input_release") == "released" and _released(last)
            and (layout_plan is None or _layout_completed(last))
            and not stop.is_set()):
        def bind_child(hwnd):
            if runtime._owned_window_binder is not None:
                return runtime._owned_window_binder(grant.task_id, grant.identity, hwnd)
            raise WindowSelectionError("owned_window_binding_unavailable")
        try:
            if return_parent is not None and not win32gui.IsWindow(grant.identity.hwnd):
                native.assert_window(return_parent)
                result.update(state="closed_to_owner", owned_return_hwnd=return_parent.hwnd,
                              owned_return_target=asdict(return_parent), requires_new_observation=True)
            found = native.new_visible_followups(grant.identity, before_windows,
                bind_allowed=True, window_binder=bind_child)
            result.update(found)
        except (native.NativeInputError, WindowSelectionError, HighHelperError):
            result["followup_observation_required"] = True
        if not sequence and (command == "activate" and last["Foreground"] or _complete(last)
                or layout_plan is not None and _layout_completed(last) and last["RequiresNewObservation"]):
            try:
                fresh_action = "post-high-" + uuid.uuid4().hex
                with runtime._gate:
                    runtime._stops[runtime._key(grant.task_id, fresh_action)] = stop
                post_grant = replace(grant, capture_scope=grant.input_scope) if command == "input" else grant
                fresh = runtime._execute(owner, resource, post_grant, fresh_action, "observe",
                    {"target": payload["target"], "action_id": fresh_action})
                detail = fresh.get("result")
                if isinstance(detail, dict) and "image" in detail:
                    result.update({name: value for name, value in detail.items()
                                   if name not in {"image", "state", "dispatched"}})
                    result["image" if command == "activate" else "visual_recheck"] = detail["image"]
                else:
                    result.update(requires_new_observation=True, capture_reason=fresh.get("reason"))
            except (ControlError, ComputerBoundaryError, native.NativeInputError, CaptureError, HighHelperError):
                result.update(requires_new_observation=True, capture_reason="post_input_capture_unavailable")
    return {"receipt": store.status(owner, key), "result": result}
