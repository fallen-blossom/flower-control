"""Fixed public schemas and derived App facts; no authorization or dispatch."""
from typing import Annotated
from pydantic import WithJsonSchema

CURSOR_CAUSES = frozenset({"record_missing", "task_mismatch", "target_changed", "expired",
    "content_mode_changed", "authority_changed", "shared_binding_changed", "shared_revision_changed",
    "no_continuation", "clock_invalid", "cursor_expired", "root_changed", "branch_unavailable", "lookup_limit"})

def _object(properties, required):
    return {"type": "object", "properties": properties, "required": required, "additionalProperties": False}

_goal = {"type": "string", "minLength": 1, "maxLength": 160}
_ref = {"type": "string"}
_string_check = _object({"automation_id": _ref,
    "field": {"enum": ["name", "value", "toggle_state", "expand_collapse_state"]},
    "equals": {"type": "string", "maxLength": 8192}, "goal_hint": _goal}, ["automation_id", "field", "equals"])
_bool_check = _object({"automation_id": _ref, "field": {"enum": ["selected", "focused"]},
    "equals": {"type": "boolean"}, "goal_hint": _goal}, ["automation_id", "field", "equals"])
_checks = [_string_check, _bool_check]

def _semantic(names, properties=None, required=None, goal=False):
    fields = {"semantic_action": {"enum": names}, **(properties or {})}
    if goal:
        fields["goal_hint"] = _goal
    return _object(fields, ["semantic_action", *(required or [])])

_focus_menu = _semantic(["focus", "menu"])
_expand = _semantic(["expand", "collapse"], goal=True)
_scroll = _semantic(["scroll"], {"direction": {"enum": ["up", "down", "left", "right"]},
    "amount": {"enum": ["small", "large"]}}, ["direction", "amount"], goal=True)
_plain_checks = [{**row, "properties": {k: v for k, v in row["properties"].items() if k != "goal_hint"}} for row in _checks]
_guarded = _semantic(["guarded_input"], {"value": {"type": "string", "minLength": 1, "maxLength": 8192},
    "replace": {"type": "boolean", "default": False}, "check": {"oneOf": _plain_checks}}, ["value"])
_transition = _semantic(["transition"], {"precondition": {"oneOf": _plain_checks},
    "postcondition": {"oneOf": _plain_checks}}, ["precondition", "postcondition"])
_flow_checks = [*_checks, _focus_menu, _expand, _scroll, _guarded, _transition]
_flow_ref = {"type": "string", "minLength": 1}
_steps = {"oneOf": [
    _object({"operation": {"const": "set_value"}, "ref": _flow_ref, "value": {"type": "string", "maxLength": 8192}}, ["operation", "ref", "value"]),
    _object({"operation": {"const": "select_item"}, "ref": _flow_ref, "desired": {"type": "boolean"}}, ["operation", "ref", "desired"]),
    _object({"operation": {"const": "invoke"}, "ref": _flow_ref, "postcondition": {"oneOf": _flow_checks}}, ["operation", "ref", "postcondition"])]}
POSTCONDITION_SCHEMA = {"type": "object", "oneOf": [*_checks, _focus_menu, _expand, _scroll,
    _guarded, _transition, _semantic(["realize_item"], {"item_name": {"type": "string", "minLength": 1, "maxLength": 256}}, ["item_name"], goal=True),
    _semantic(["close"], goal=True),
    _semantic(["close_temporary"], {"launch_action_id": {"type": "string", "minLength": 1, "maxLength": 128}},
        ["launch_action_id"]),
    _semantic(["recipe"], {"name": {"enum": ["two_field_submit", "select_and_invoke", "menu_item"]},
        "parameters": {"type": "object"}}, ["name", "parameters"]),
    _semantic(["flow"], {"steps": {"type": "array", "minItems": 1, "maxItems": 32, "items": _steps}}, ["steps"])]}
AppPostcondition = Annotated[dict, WithJsonSchema(POSTCONDITION_SCHEMA)]

def reference_lifetime(record, *, now, wall_time):
    native_remaining = 15 - (wall_time * 1000 - record["result"]["observed_at_ms"]) / 1000
    remaining = max(0.0, min(record["expires"] - now, native_remaining, 15.0))
    result = {"reference_lifetime_seconds": 15, "reference_seconds_remaining": round(remaining, 3)}
    if record.get("tree_next") is not None:
        result["tree_cursor_seconds_remaining"] = result["reference_seconds_remaining"]
    return result

def operation_receipt(outcome, *, requested):
    native = outcome.get("result") or {}
    high = outcome.get("native_receipt") or {}
    action = outcome.get("receipt") or {}
    effect = action.get("effects") or {}
    dispatched = native.get("dispatched", outcome.get("dispatched", effect.get("business_dispatched")))
    if type(dispatched) is not bool:
        dispatched = None
    executor_ended = high.get("SemanticExecutorExited", native.get("native_executor_exited", outcome.get("native_executor_exited")))
    if type(executor_ended) is not bool:
        executor_ended = None
    recheck = outcome.get("recheck") or {}
    checked = recheck.get("result") or {}
    observed = outcome.get("ui_recheck_succeeded", checked.get("state") == "observed") is True
    attempted = outcome.get("ui_recheck_attempted", bool(recheck)) is True
    predicate = outcome.get("postcondition")
    if outcome.get("queued"):
        check_state, reason = "not_run", "action_queued"
    elif outcome.get("replayed"):
        check_state, reason = "not_run", "replayed_action_requires_history"
    elif not requested:
        check_state, reason = "not_requested", None
    elif predicate == "not_run":
        check_state, reason = "not_run", outcome.get("recheck_error") or "execution_not_verified"
    elif outcome.get("recheck_error"):
        check_state, reason = "read_failed", outcome["recheck_error"]
    elif recheck and not observed:
        check_state, reason = "read_failed", checked.get("reason", "recheck_unavailable")
    elif predicate == "verified" and observed:
        check_state, reason = "matched", None
    elif predicate == "not_verified" and observed:
        detail = outcome.get("postcondition_detail", "value_mismatch")
        check_state, reason = (("read_failed", detail) if detail == "property_not_observed"
                               else ("not_matched", detail))
    else:
        check_state, reason = "not_run", native.get("reason") or outcome.get("error") or "execution_not_verified"
    # Only codes generated by this implementation enter the metadata receipt.
    if reason is not None and (type(reason) is not str or not reason.replace('_', '').isalnum() or len(reason) > 96):
        reason = "check_unavailable"
    release = effect.get("input_release", action.get("input_release", high.get("InputRelease", (outcome.get("activation") or {}).get("input_release", "not_reported"))))
    if release not in {"released", "release_pending", "not_acquired", "unknown", "not_reported"}:
        release = "unknown"
    detail = outcome.get("postcondition_detail")
    if detail is not None and (type(detail) is not str or not detail.replace('_', '').isalnum()
                               or len(detail) > 96):
        detail = "check_unavailable"
    value_read = outcome.get("postcondition_value_read")
    if value_read is None and detail == "property_not_observed":
        # The control was observed, but the compact projection omitted this
        # property. No value was read, so this is not a value mismatch.
        value_read = False
    if type(value_read) is not bool:
        value_read = None
    return {"execution": {"dispatched": dispatched, "executor_ended": executor_ended,
                "input_release": release},
            "ui_check": {"requested": requested, "observation_ran": attempted, "observation_succeeded": observed,
                         "state": check_state, "detail": detail, "value_read": value_read},
            "ui_check_reason": reason,
            "postcondition_detail": detail,
            "postcondition_value_read": value_read,
            "business_verification": {"uia_readback": "verified" if check_state == "matched" else "unverified",
                "artifact_verification": "not_performed", "requires_independent_task_check": True}}
