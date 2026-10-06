"""A public short Web flow using the shared Jev stage loop and existing ledger."""
from dataclasses import replace
import json
import time

from flower_control.control.state import ControlError
from flower_control.control.targets import TargetRequest, candidate_from_dom
from flower_control.control.target_selection import selection_permitted_async
from flower_control.control.jev_workflow import TargetFlowStep, TargetFlowReadback, run_target_flow
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
            if type(choice["command"]) is not str or choice["command"] not in {"fill", "select_option", "set_checked", "click", "press"}:
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

    async def permitted():
        if control.store.write_stopped() or control._batch_cancelled(action_id):
            return False
        return await selection_permitted_async(control.store, control.task, (control.resource,), (control.scope,) if control.scope else ())

    async def next_step(previous):
        if position == len(stages):
            return TargetFlowReadback("complete", previous.progress_key)
        stage = stages[position]
        candidates, generation, observed, complete = [], None, None, True
        for index, choice in enumerate(stage["choices"]):
            observed = await control._execute_direct("observe", {"page_id": arguments["page_id"],
                "selector": choice["selector"], "limit": 32, "ttl": 15},
                action_id=f"{action_id}:flow:{position}:observe:{index}")
            data = observed.get("result")
            if not isinstance(data, dict):
                raise ControlError("flow_observation_unavailable")
            if generation is not None and generation != data["generation"]:
                raise ControlError("flow_page_changed")
            generation = data["generation"]
            complete = complete and data["complete"]
            for row in data["entries"]:
                candidate = candidate_from_dom(row, action=choice["command"])
                if candidate is not None:
                    candidates.append(replace(candidate, target_id=f"{index}:{candidate.target_id}",
                        target={"ref": row["ref"], "choice_index": index}))
            if len(candidates) > 32:
                raise ControlError("flow_candidate_limit")
        request = TargetRequest(stage["goal_hint"], observed["observation_id"], generation,
            tuple(candidates), time.monotonic() + 12, complete=complete,
            fallback_id=candidates[0].target_id if len(candidates) == 1 and complete else None,
            candidate_scope="bounded", task_stage=stage["task_stage"])
        async def fresh():
            return control.session.guarded and request.expires_at > time.monotonic()
        return TargetFlowStep(f"{action_id}:flow:{position}:write", request,
            previous.progress_key if previous else "initial_observed_state", permitted, fresh,
            selection_action_id=f"{action_id}:flow:{position}:observe:{len(stage['choices']) - 1}")

    async def execute(step, candidate):
        target = candidate.local_target()
        choice = stages[position]["choices"][target["choice_index"]]
        values = {"page_id": arguments["page_id"], "reference": target["ref"], **choice["arguments"]}
        if candidate.action in {"click", "press"}:
            values["read_page_state"] = False
        outcome = await control._execute_direct(candidate.action, values, action_id=step.action_id,
            task_hint=stages[position]["task_stage"])
        if "dialog_response" in values:
            outcome = await control._continue_expected_dialog(outcome, values, step.action_id, action_id)
        return outcome

    async def readback(step, candidate, outcome):
        nonlocal position
        result = outcome.get("result", {})
        if outcome.get("receipt", {}).get("state") in {"cancelled", "outcome_uncertain", "running"}:
            return TargetFlowReadback("outcome_unknown", "write_uncertain")
        if isinstance(result, dict) and result.get("verification") in {"dialog_pending", "chooser_pending"}:
            return TargetFlowReadback("needs_host", "pending_confirmation", result)
        response = await control._execute_direct("wait_condition", {"page_id": arguments["page_id"],
            "condition": stages[position]["condition"]}, action_id=step.action_id + ":readback")
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
    except (ControlError, RuntimeError, ValueError) as error:
        response = {"state": "stopped", "reason": getattr(error, "code", "flow_failed"),
            "completed_steps": len(progress), "next_step": position, "progress": progress,
            "business_result_verified": False}
    return control._batch_finish(action_id, response)
