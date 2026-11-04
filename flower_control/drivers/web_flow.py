"""A public short Web flow using the shared Jev stage loop and existing ledger."""
from dataclasses import replace
import asyncio
import json
import time

from flower_control.control.state import ControlError
from flower_control.control.targets import TargetRequest, candidate_from_dom
from flower_control.control.target_selection import selection_permitted_async
from flower_control.control.jev_workflow import TargetFlowStep, TargetFlowReadback, run_target_flow
from flower_control.control.jev_workflow import _uncertain
from flower_control.control.jev_diagnostics import FlowMeasurements, current_context
from flower_control.control.worker_call import command_hash
from .web_batch import validate_batch, validate_condition
from .web_business import digest


def validate_flow(arguments):
    if type(arguments) is not dict or set(arguments) != {"page_id", "stages"}:
        raise ControlError("invalid_web_flow")
    stages = arguments["stages"]
    if type(stages) is not list or not 1 <= len(stages) <= 16:
        raise ControlError("invalid_web_flow")
    for stage in stages:
        if type(stage) is not dict or set(stage) != {"task_stage", "goal_hint", "choices", "condition"}:
            raise ControlError("invalid_web_flow")
        if any(type(stage[key]) is not str or not 1 <= len(stage[key]) <= 160 for key in ("task_stage", "goal_hint")):
            raise ControlError("invalid_web_flow")
        validate_condition(stage["condition"])
        choices = stage["choices"]
        if type(choices) is not list or not 1 <= len(choices) <= 8:
            raise ControlError("invalid_web_flow")
        for choice in choices:
            if type(choice) is not dict or set(choice) != {"command", "selector", "arguments"}:
                raise ControlError("invalid_web_flow")
            if type(choice["command"]) is not str or choice["command"] not in {"fill", "type", "select_option", "set_checked", "click", "press"}:
                raise ControlError("invalid_web_flow")
            if type(choice["selector"]) is not str or not 1 <= len(choice["selector"]) <= 2000 or type(choice["arguments"]) is not dict or "reference" in choice["arguments"]:
                raise ControlError("invalid_web_flow")
            validate_batch({"page_id": arguments["page_id"], "steps": [{"command": choice["command"],
                "arguments": {"reference": "prevalidated", **choice["arguments"]}}]})
    return stages


async def execute_flow(control, arguments, action_id):
    stages = validate_flow(arguments)
    fingerprint = command_hash("flow", arguments)
    with control.store.transaction() as db:
        if db.execute("SELECT 1 FROM actions WHERE id=?", (action_id,)).fetchone():
            raise ControlError("action_id_conflict")
        prior = db.execute("SELECT fingerprint,result FROM web_batch_intents WHERE task=? AND action=?", (control.task, action_id)).fetchone()
        if prior and prior["fingerprint"] != fingerprint:
            raise ControlError("action_id_conflict")
        if prior and prior["result"]:
            return {**json.loads(prior["result"]), "replayed": False}
        if not prior:
            db.execute("INSERT INTO web_batch_intents(task,action,fingerprint) VALUES(?,?,?)", (control.task, action_id, fingerprint))
    position = 0
    progress = []
    measurements = FlowMeasurements()

    async def driver_call(command, values, **options):
        measurements.driver_call(command)
        return await control._execute_direct(command, values, **options)

    async def permitted():
        if control.store.write_stopped() or control._batch_cancelled(action_id):
            return False
        return await selection_permitted_async(control.store, control.task, (control.resource,), (control.scope,) if control.scope else ())

    async def require_permitted():
        if not await permitted():
            raise ControlError("flow_not_permitted")

    async def next_step(previous):
        if position == len(stages):
            return TargetFlowReadback("complete", previous.progress_key)
        stage = stages[position]
        recovery_generation = None
        for attempt in range(2):
            await require_permitted()
            candidates, generation, observed, complete = [], None, None, True
            unavailable = []
            for index, choice in enumerate(stage["choices"]):
                observation_action = f"{action_id}:flow:{position}:observe:{index}" + (":refresh" if attempt else "")
                observed = await driver_call("observe", {"page_id": arguments["page_id"],
                    "selector": choice["selector"], "limit": 32, "ttl": 15},
                    action_id=observation_action)
                data = observed.get("result")
                if not isinstance(data, dict):
                    raise ControlError("flow_observation_unavailable")
                if recovery_generation is not None and recovery_generation != data["generation"]:
                    raise ControlError("flow_page_changed")
                if generation is not None and generation != data["generation"]:
                    raise ControlError("flow_page_changed")
                generation = data["generation"]
                complete = complete and data["complete"]
                entries = data["entries"]
                if not entries or any(row.get("disabled") is True or row.get("visible") is False
                                      or row.get("connected") is False for row in entries):
                    unavailable.append((choice, entries))
                for row in data["entries"]:
                    candidate = candidate_from_dom(row, action=choice["command"])
                    if candidate is not None:
                        candidates.append(replace(candidate, target_id=f"{index}:{candidate.target_id}",
                            target={"ref": row["ref"], "choice_index": index}))
                if len(candidates) > 32:
                    raise ControlError("flow_candidate_limit")
            # A temporarily missing/disabled target has not received a write.
            # Wait once on the first unavailable declared choice, then rescan
            # the original set. Another declared alternative may become ready
            # while that wait times out; neither path invents a selector.
            if candidates or attempt or not complete or not unavailable:
                break
            choice, entries = unavailable[0]
            alternatives = len(stage["choices"]) > 1
            if alternatives:
                # Rebuilding alternatives is safe only within the original
                # document. An unrelated page can expose identical controls.
                recovery_generation = generation
            await require_permitted()
            measurements.recovery_attempts += 1
            condition = "attached" if not entries else "visible" if any(
                row.get("visible") is False for row in entries) else "enabled"
            recovery = await driver_call("wait_condition", {"page_id": arguments["page_id"],
                "condition": {"selector": choice["selector"], "condition": condition,
                              "timeout_ms": min(1000, stage["condition"]["timeout_ms"])}},
                action_id=f"{action_id}:flow:{position}:availability")
            await require_permitted()
            result = recovery.get("result", {})
            if (result.get("state") != "verified" and not (alternatives
                    and result.get("state") == "not_verified"
                    and result.get("wait", {}).get("reason") == "condition_timeout")):
                break
        request = TargetRequest(stage["goal_hint"], observed["observation_id"], generation,
            tuple(candidates), time.monotonic() + 12, complete=complete,
            fallback_id=candidates[0].target_id if len(candidates) == 1 and complete else None,
            candidate_scope="bounded", task_stage=stage["task_stage"],
            assessment_questions=())
        async def fresh():
            return control.session.guarded and request.expires_at > time.monotonic()
        return TargetFlowStep(f"{action_id}:flow:{position}:write", request,
            previous.progress_key if previous else "initial_observed_state", permitted, fresh,
            selection_action_id=observation_action)

    async def execute(step, candidate):
        target = candidate.local_target()
        choice = stages[position]["choices"][target["choice_index"]]
        values = {"page_id": arguments["page_id"], "reference": target["ref"], **choice["arguments"]}
        if candidate.action in {"click", "press"}:
            values["read_page_state"] = False
        outcome = await driver_call(candidate.action, values, action_id=step.action_id,
            task_hint=stages[position]["task_stage"])
        if "dialog_response" in values:
            outcome = await control._continue_expected_dialog(outcome, values, step.action_id, action_id)
        return outcome

    async def readback(step, candidate, outcome):
        nonlocal position
        result = outcome.get("result", {})
        if (_uncertain(outcome) or
                outcome.get("receipt", {}).get("state") in {"cancelled", "outcome_uncertain", "running"}):
            return TargetFlowReadback("outcome_unknown", "write_uncertain")
        if isinstance(result, dict) and result.get("verification") in {"dialog_pending", "chooser_pending"}:
            return TargetFlowReadback("needs_host", "pending_confirmation", result)
        # A document change can end the existing wait before its budget runs
        # out. Rebind one read to the current document using only the remainder;
        # ordinary delayed results already use the driver's complete budget.
        # Neither case can dispatch the original input again.
        condition = stages[position]["condition"]
        deadline = time.monotonic() + condition["timeout_ms"] / 1000
        response = await driver_call("wait_condition", {"page_id": arguments["page_id"],
            "condition": condition},
            action_id=step.action_id + ":readback")
        result = response.get("result", {})
        if (isinstance(result, dict) and result.get("state") == "not_verified"
                and result.get("wait", {}).get("reason") == "page_changed_during_wait"):
            remaining_ms = min(condition["timeout_ms"], int((deadline - time.monotonic()) * 1000))
            if remaining_ms > 0:
                await require_permitted()
                measurements.recovery_attempts += 1
                response = await driver_call("wait_condition", {"page_id": arguments["page_id"],
                    "condition": {**condition, "timeout_ms": remaining_ms}},
                    action_id=step.action_id + ":readback:recovery")
                result = response.get("result", {})
        if not isinstance(result, dict) or result.get("state") != "verified":
            return TargetFlowReadback("needs_host", "condition_not_observed", result)
        key = digest({"condition": stages[position]["condition"], "wait": result.get("wait")})
        progress.append({"task_stage": stages[position]["task_stage"], "action": candidate.action,
            "action_id": step.action_id, "state": "condition_observed"})
        position += 1
        return TargetFlowReadback("progress", key)

    try:
        result = await run_target_flow(control.store, control.task, next_step, execute, readback,
            client_factory=control.jev_client_factory)
        response = {"state": result.state, "reason": result.reason, "elapsed_ms": result.elapsed_ms,
            "completed_steps": len(progress), "next_step": position if position < len(stages) else None,
            "progress": progress, "decision_ids": list(result.decision_ids), "business_result_verified": False}
    except asyncio.CancelledError:
        control._batch_finish(action_id, {"state": "cancelled", "reason": "host_cancelled",
            "completed_steps": len(progress), "next_step": position, "progress": progress,
            "measurements": measurements.snapshot(usage=current_context().get("usage")),
            "replay_old_action": False, "business_result_verified": False})
        raise
    except (ControlError, RuntimeError, ValueError) as error:
        response = {"state": "stopped", "reason": getattr(error, "code", "flow_failed"),
            "completed_steps": len(progress), "next_step": position, "progress": progress,
            "business_result_verified": False}
    response["measurements"] = measurements.snapshot(usage=current_context().get("usage"))
    return control._batch_finish(action_id, response)
