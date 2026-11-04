"""Small deterministic App suffixes; no model, input emitter or task state machine."""


def validate_transition(value):
    if (type(value) is not dict or set(value) != {"semantic_action", "precondition", "postcondition"}
            or value["semantic_action"] != "transition"):
        raise ValueError("invalid_app_transition")
    for condition in (value["precondition"], value["postcondition"]):
        if (type(condition) is not dict or set(condition) != {"automation_id", "field", "equals"}
                or type(condition["automation_id"]) is not str or not condition["automation_id"]
                or type(condition["field"]) is not str
                or condition["field"] not in {"name", "value", "toggle_state", "expand_collapse_state", "selected", "focused"}
                or (type(condition["equals"]) is not bool if condition["field"] in {"selected", "focused"}
                    else type(condition["equals"]) is not str or len(condition["equals"]) > 8192)):
            raise ValueError("invalid_app_transition")


def bind_transition(value, entries):
    """Bind both predicates to the exact authorized observation, never a later name lookup."""
    validate_transition(value)
    bound = {}
    for label in ("precondition", "postcondition"):
        condition = value[label]
        ref, field = condition["automation_id"], condition["field"]
        rows = [row for row in entries if (row.get("ref") == ref if ref.startswith("appref:")
                                           else row.get("automation_id") == ref)]
        if len(rows) != 1 or not rows[0].get("runtime_id"):
            raise ValueError("transition_control_ambiguous_or_missing")
        row = rows[0]
        if row.get("password") or field not in row or row[field] is None or type(row[field]) is not type(condition["equals"]) or row.get(field + "_truncated") or row.get(field + "_read_error"):
            raise ValueError("transition_property_unavailable")
        bound[label] = {"reference": {"runtime_id": row["runtime_id"], "automation_id": row["automation_id"]},
                        "field": field, "equals": condition["equals"]}
    return bound


def suppress_app_content(outcome, reason):
    """Keep local effect receipts when revocation removes all UIA content."""
    receipt = outcome.get("receipt")
    detail = outcome.get("result") or {}
    steps = [suppress_app_content(step, reason) for step in outcome.get("steps", ())]
    effects = [step["dispatched"] for step in steps]
    for source in (outcome, detail, receipt or {}):
        if "dispatched" in source:
            value = source["dispatched"]
            # Old read-only receipts use integer 1 for entering dispatch.
            # Only actual three-valued input effects are authoritative here.
            if value is None or type(value) is bool:
                effects.append(value)
    uncertain = any(source.get("state") == "outcome_uncertain" for source in (outcome, detail, receipt or {})) or any(step["state"] == "outcome_uncertain" for step in steps)
    dispatched = True if True in effects else None if None in effects or uncertain else False
    result = {"state": "outcome_uncertain" if uncertain else "not_verified",
        "dispatched": dispatched, "reason": reason, "content_suppressed": True}
    # Revocation suppresses provider content, not the already accepted native
    # execution facts. Never publish AppResult, input text or private seals.
    high = outcome.get("native_receipt")
    high = high if type(high) is dict else {}
    operation = outcome.get("operation_receipt")
    operation = operation if type(operation) is dict else {}
    execution = operation.get("execution")
    execution = execution if type(execution) is dict else {}
    if "SemanticExecutorExited" in high:
        ended = high["SemanticExecutorExited"]
    elif "native_executor_exited" in detail:
        ended = detail["native_executor_exited"]
    elif "native_executor_exited" in outcome:
        ended = outcome["native_executor_exited"]
    else:
        ended = execution.get("executor_ended")
    ended = ended if type(ended) is bool else None
    result["native_executor_exited"] = ended
    if high:
        safe_fields = ("State", "Reason", "Winerror", "SemanticBusinessDispatched",
            "SemanticExecutorExited", "NativeCountKnown", "InputRelease", "MutexReleased",
            "ActivationRequested", "ActivationEvents", "BusinessEvents", "ReleaseEvents")
        result["execution_facts"] = {name: high[name] for name in safe_fields if name in high}
        peer = high.get("SemanticExecutor")
        if type(peer) is dict:
            result["execution_facts"]["SemanticExecutor"] = {name: peer[name] for name in
                ("Pid", "Created", "Session", "Integrity", "ImageDigest") if name in peer}
    elif "native_executor_exited" in detail:
        result["execution_facts"] = {"SemanticExecutorExited": ended,
            "SemanticBusinessDispatched": detail.get("dispatched"),
            "Reason": detail.get("reason"), "InputRelease": (receipt or {}).get("input_release")}
    if receipt is not None:
        result["receipt"] = receipt
    if steps:
        result["steps"] = steps
    return result


def validate_steps(steps):
    if type(steps) is not list or not 1 <= len(steps) <= 32:
        raise ValueError("invalid_app_flow")
    for step in steps:
        if type(step) is not dict or type(step.get("ref")) is not str or not step["ref"]:
            raise ValueError("invalid_app_flow")
        operation = step.get("operation")
        if type(operation) is not str:
            raise ValueError("invalid_app_flow")
        shape = {"set_value": {"value"}, "select_item": {"desired"}, "invoke": {"postcondition"}}.get(operation)
        if shape is None or set(step) != {"operation", "ref"} | shape:
            raise ValueError("invalid_app_flow")
        if operation == "set_value" and (type(step["value"]) is not str or len(step["value"]) > 8192):
            raise ValueError("invalid_app_flow")
        if operation == "select_item" and type(step["desired"]) is not bool:
            raise ValueError("invalid_app_flow")
        if operation == "invoke":
            check = step["postcondition"]
            if type(check) is not dict or check.get("semantic_action") == "flow":
                raise ValueError("invalid_app_flow")
            if "goal_hint" in check:
                if type(check["goal_hint"]) is not str or not check["goal_hint"].strip() or len(check["goal_hint"]) > 160:
                    raise ValueError("invalid_app_flow")
                check = {key: value for key, value in check.items() if key != "goal_hint"}
            semantic = check.get("semantic_action")
            if semantic is not None and type(semantic) is not str:
                raise ValueError("invalid_app_flow")
            if semantic == "transition":
                validate_transition(step["postcondition"])
                valid = True
            elif semantic in {"focus", "menu", "expand", "collapse"}:
                valid = set(check) == {"semantic_action"}
            elif semantic == "guarded_input":
                valid = (not set(check) - {"semantic_action", "value", "replace", "check"}
                    and type(check.get("value")) is str and 1 <= len(check["value"]) <= 8192
                    and type(check.get("replace", False)) is bool)
                if valid and "check" in check:
                    if type(check["check"]) is not dict or set(check["check"]) != {"automation_id", "field", "equals"}:
                        raise ValueError("invalid_app_flow")
                    validate_steps([{"operation": "invoke", "ref": step["ref"], "postcondition": check["check"]}])
            elif semantic == "scroll":
                valid = (set(check) == {"semantic_action", "direction", "amount"}
                    and check["direction"] in {"up", "down", "left", "right"} and check["amount"] in {"small", "large"})
            else:
                valid = (set(check) == {"automation_id", "field", "equals"}
                    and type(check["automation_id"]) is str and check["field"] in {"value", "name", "selected", "focused", "toggle_state", "expand_collapse_state"}
                    and (type(check["equals"]) is bool if check["field"] in {"selected", "focused"}
                         else type(check["equals"]) is str and len(check["equals"]) <= 8192))
            if not valid:
                raise ValueError("invalid_app_flow")


def common_scope(steps, entries):
    paths = []
    for step in steps:
        if step["operation"] == "invoke" and "goal_hint" in step["postcondition"]:
            return None  # Candidate discovery retains the caller's observed scope.
        refs = [step["ref"]]
        if step["operation"] == "invoke" and "automation_id" in step["postcondition"]:
            refs.append(step["postcondition"]["automation_id"])
        if step["operation"] == "invoke" and "check" in step["postcondition"]:
            refs.append(step["postcondition"]["check"]["automation_id"])
        if step["operation"] == "invoke" and step["postcondition"].get("semantic_action") == "transition":
            refs.extend(step["postcondition"][label]["automation_id"] for label in ("precondition", "postcondition"))
        for ref in refs:
            rows = [row for row in entries if (row.get("ref") == ref if ref.startswith("appref:") else row.get("automation_id") == ref)]
            if len(rows) != 1 or not rows[0].get("tree_path"):
                return None
            paths.append(rows[0]["tree_path"])
    scope = []
    for ancestors in zip(*paths):
        if any(ancestor != ancestors[0] for ancestor in ancestors):
            break
        scope.append(ancestors[0])
    return scope or None


def advance_reference(ref, baseline, fresh, *, exact=False):
    from flower_control.drivers.app_control import AppBoundaryError
    if ref.startswith("appref:") or exact:
        originals = [row for row in baseline if (row.get("ref") == ref if ref.startswith("appref:")
                                                else row.get("automation_id") == ref)]
        if len(originals) != 1:
            raise AppBoundaryError("control_ambiguous_or_missing")
        hits = [row for row in fresh if row.get("runtime_id") == originals[0].get("runtime_id")
                and row.get("automation_id") == originals[0].get("automation_id")]
    else:
        hits = [row for row in fresh if row.get("automation_id") == ref]
    if len(hits) != 1 or not hits[0].get("ref"):
        raise AppBoundaryError("control_ambiguous_or_missing")
    return hits[0]["ref"]


def step_complete(result):
    return (not result.get("replayed") and not result.get("error")
            and not result.get("receipt", {}).get("cancel_requested")
            and result.get("postcondition") == "verified"
            and result.get("result", {}).get("state") != "outcome_uncertain")
