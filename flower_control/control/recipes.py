"""Fixed mechanical recipes compiled to existing, independently guarded commands.

No execution, persistence, target discovery, model calls, or retry policy here.
Parameters are task-local content and must not be logged by callers.
"""
from copy import deepcopy

from flower_control.control.state import ControlError


WEB_RECIPES = ("two_field_submit", "select_and_apply", "standard_editor_replace")
APP_RECIPES = ("two_field_submit", "select_and_invoke", "menu_item")


def _shape(parameters, keys):
    if type(parameters) is not dict or set(parameters) != set(keys):
        raise ControlError("invalid_recipe_parameters")


def _text(value, *, limit=2000, empty=False):
    if type(value) is not str or len(value) > limit or (not empty and not value) or "\x00" in value:
        raise ControlError("invalid_recipe_parameters")
    return value


def _stage(command, selector, arguments, condition, purpose):
    return {"task_stage": purpose, "goal_hint": purpose,
            "choices": [{"command": command, "selector": selector, "arguments": arguments}],
            "condition": condition}


def _field(selector, value):
    return _stage("fill", selector, {"text": value}, {"selector": selector,
        "condition": "value", "expected_value": value, "timeout_ms": 1000}, "填写指定字段")


def build_web_recipe(name, parameters):
    """Return {command, arguments}; pass unchanged to WebMcpRuntime.run.

    Every stage uses one selector choice. Nonunique current candidates still
    follow the executor's normal ambiguity policy; no uniqueness is invented.
    Jev can be disabled per task when zero external decisions are required.
    """
    from flower_control.drivers.web_flow import validate_flow
    from flower_control.drivers.web_batch import validate_condition
    p = deepcopy(parameters)
    if name == "two_field_submit":
        _shape(p, ("page_id", "first_selector", "first_text", "second_selector", "second_text", "submit_selector", "submitted_condition"))
        _text(p["first_text"], limit=8192, empty=True)
        _text(p["second_text"], limit=8192, empty=True)
        stages = [_field(p["first_selector"], p["first_text"]), _field(p["second_selector"], p["second_text"]),
            _stage("click", p["submit_selector"], {}, p["submitted_condition"], "提交已填写表单")]
    elif name == "select_and_apply":
        _shape(p, ("page_id", "select_selector", "value", "apply_selector", "applied_condition"))
        _text(p["value"], limit=256, empty=True)
        stages = [_stage("select_option", p["select_selector"], {"value": p["value"]},
            {"selector": p["select_selector"], "condition": "value", "expected_value": p["value"], "timeout_ms": 1000}, "选择指定列表值"),
            _stage("click", p["apply_selector"], {}, p["applied_condition"], "应用指定选择")]
    elif name == "standard_editor_replace":
        _shape(p, ("page_id", "reference", "text", "expected_uri", "expected_version"))
        _text(p["page_id"], limit=64)
        _text(p["reference"], limit=100)
        _text(p["text"], limit=1_000_000, empty=True)
        _text(p["expected_uri"], limit=2048)
        if type(p["expected_version"]) is not int or p["expected_version"] < 1:
            raise ControlError("invalid_recipe_parameters")
        # This is an existing exact editor command; it does not save or run.
        return {"command": "editor_replace", "arguments": p}
    else:
        raise ControlError("unknown_web_recipe")
    for key in (key for key in p if key.endswith("selector")):
        _text(p[key])
    condition = p.get("submitted_condition", p.get("applied_condition"))
    validate_condition(condition)
    result = {"page_id": p["page_id"], "stages": stages}
    validate_flow(result)  # Includes the complete generated suffix before return.
    return {"command": "flow", "arguments": result}


def build_app_recipe(name, parameters):
    """Return the existing flower_app_invoke postcondition for a current observation.

    Target, observation_id and action_id remain with the original App caller.
    References cannot be persisted or substituted by names in this builder.
    """
    from flower_control.drivers.app_flow import validate_steps
    p = deepcopy(parameters)
    if name == "two_field_submit":
        _shape(p, ("first_ref", "first_value", "second_ref", "second_value", "submit_ref", "postcondition"))
        steps = [{"operation": "set_value", "ref": p["first_ref"], "value": p["first_value"]},
                 {"operation": "set_value", "ref": p["second_ref"], "value": p["second_value"]},
                 {"operation": "invoke", "ref": p["submit_ref"], "postcondition": p["postcondition"]}]
    elif name == "select_and_invoke":
        _shape(p, ("item_ref", "invoke_ref", "postcondition"))
        steps = [{"operation": "select_item", "ref": p["item_ref"], "desired": True},
                 {"operation": "invoke", "ref": p["invoke_ref"], "postcondition": p["postcondition"]}]
    elif name == "menu_item":
        _shape(p, ("item_ref",))
        steps = [{"operation": "invoke", "ref": p["item_ref"], "postcondition": {"semantic_action": "menu"}}]
    else:
        raise ControlError("unknown_app_recipe")
    for step in steps:
        _text(step["ref"], limit=100)
        if "value" in step:
            _text(step["value"], limit=8192, empty=True)
    try:
        validate_steps(steps)
    except ValueError:
        raise ControlError("invalid_recipe_parameters") from None
    return {"semantic_action": "flow", "steps": steps}
