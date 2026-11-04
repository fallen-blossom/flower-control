"""Mechanical Web batches: validate the entire suffix before any write."""
import re
from flower_control.control.state import ControlError


FIELDS = {
    "fill": {"reference", "text"},
    "type": {"reference", "text", "replace", "input_mode"},
    "select_option": {"reference", "value"},
    "set_checked": {"reference", "checked"},
    "click": {"reference", "goal_hint", "task_stage", "selector", "frame_index", "wait_for", "dialog_response"},
    "press": {"reference", "key", "goal_hint", "task_stage", "selector", "frame_index", "wait_for", "dialog_response"},
    "wait_condition": {"condition"},
}


def validate_condition(spec):
    if (type(spec) is not dict or not {"selector", "timeout_ms"} <= spec.keys()
            or not spec.keys() <= {"selector", "timeout_ms", "condition", "frame_index", "expected_text", "expected_value", "attribute", "baseline"}
            or type(spec["selector"]) is not str or not 1 <= len(spec["selector"]) <= 2000
            or type(spec["timeout_ms"]) is not int or not 1 <= spec["timeout_ms"] <= 10000
            or type(spec.get("frame_index", 0)) is not int or spec.get("frame_index", 0) < 0):
        raise ControlError("invalid_wait_condition")
    kind = spec.get("condition", "text_changed")
    if type(kind) is not str or kind not in {"text_changed", "attached", "detached", "visible", "hidden", "enabled", "disabled", "checked", "unchecked", "value", "attribute", "attribute_contains", "class", "url", "url_contains", "media_playing", "media_paused", "message_appended"}:
        raise ControlError("invalid_wait_condition")
    if "expected_text" in spec and (kind not in {"text_changed", "attached", "message_appended"} or type(spec["expected_text"]) is not str or not 1 <= len(spec["expected_text"]) <= 1000):
        raise ControlError("invalid_wait_condition")
    if kind in {"value", "attribute", "attribute_contains", "class", "url", "url_contains"}:
        expected = spec.get("expected_value")
        if type(expected) is not str or len(expected) > 8192 or (kind in {"class", "url", "url_contains", "attribute_contains"} and not expected):
            raise ControlError("invalid_wait_condition")
    elif "expected_value" in spec or "attribute" in spec:
        raise ControlError("invalid_wait_condition")
    if kind in {"attribute", "attribute_contains"}:
        name = spec.get("attribute")
        if type(name) is not str or not 1 <= len(name) <= 120 or any(ch.isspace() for ch in name):
            raise ControlError("invalid_wait_condition")
    elif "attribute" in spec:
        raise ControlError("invalid_wait_condition")
    if kind == "message_appended":
        baseline = spec.get("baseline")
        if type(baseline) is dict and "container_identity" in baseline:
            if (type(baseline["container_identity"]) is not str
                    or re.fullmatch(r"mbase:[a-f0-9]{32}", baseline["container_identity"]) is None):
                raise ControlError("message_container_binding_unavailable")
            if "last_message_hash" not in baseline:
                raise ControlError("invalid_wait_condition")
        if ("expected_text" not in spec or type(baseline) is not dict
                or not {"count"} <= baseline.keys()
                or not baseline.keys() <= {"count", "last_message_hash", "container_identity"}
                or type(baseline["count"]) is not int or not 0 <= baseline["count"] <= 100000
                or ("last_message_hash" in baseline and baseline["last_message_hash"] is not None
                    and (type(baseline["last_message_hash"]) is not str or re.fullmatch(r"[a-f0-9]{64}", baseline["last_message_hash"]) is None))
                or ("container_identity" in baseline and (type(baseline["container_identity"]) is not str
                    or len(baseline["container_identity"]) > 256))):
            raise ControlError("invalid_wait_condition")
    elif "baseline" in spec:
        raise ControlError("invalid_wait_condition")


def validate_batch(arguments):
    if type(arguments) is not dict or set(arguments) != {"page_id", "steps"}:
        raise ControlError("invalid_web_batch")
    page = arguments["page_id"]
    steps = arguments["steps"]
    if type(page) is not str or not 1 <= len(page) <= 64 or type(steps) is not list or not 1 <= len(steps) <= 32:
        raise ControlError("invalid_web_batch")
    for step in steps:
        if type(step) is not dict or set(step) != {"command", "arguments"}:
            raise ControlError("invalid_web_batch")
        command, values = step["command"], step["arguments"]
        if type(command) is not str or command not in FIELDS or type(values) is not dict or not set(values) <= FIELDS[command]:
            raise ControlError("invalid_web_batch")
        required = FIELDS[command] - {"replace", "input_mode"}
        if command in {"click", "press"}:
            required = {"key"} if command == "press" else set()
            if "reference" not in values:
                required.add("goal_hint")
        if not required <= values.keys():
            raise ControlError("invalid_web_batch")
        for key, value in values.items():
            if key in {"condition", "wait_for"}:
                validate_condition(value)
            elif key == "dialog_response":
                if (type(value) is not dict or not {"type", "message", "accept"} <= value.keys()
                        or not value.keys() <= {"type", "message", "accept", "prompt_text"}
                        or type(value["type"]) is not str or value["type"] not in {"alert", "confirm", "prompt"}
                        or type(value["message"]) is not str or len(value["message"]) > 1000
                        or type(value["accept"]) is not bool
                        or "prompt_text" in value and (value["type"] != "prompt" or not value["accept"]
                            or type(value["prompt_text"]) is not str or len(value["prompt_text"]) > 64000 or "\x00" in value["prompt_text"])):
                    raise ControlError("invalid_web_batch")
            elif key == "frame_index":
                if type(value) is not int or value < 0:
                    raise ControlError("invalid_web_batch")
            elif key in {"replace", "checked"}:
                if type(value) is not bool:
                    raise ControlError("invalid_web_batch")
            elif key == "input_mode":
                if type(value) is not str or value not in {"insert_text", "paste_event"}:
                    raise ControlError("invalid_text_input_mode")
            else:
                bound = {"reference": 100, "text": 1_000_000, "key": 80, "value": 256,
                    "goal_hint": 160, "task_stage": 160, "selector": 2000}[key]
                if type(value) is not str or len(value) > bound or "\x00" in value or (key in {"reference", "key", "goal_hint", "task_stage", "selector"} and not value):
                    raise ControlError("invalid_web_batch")
        if command == "press" and any(ch in values["key"] for ch in "\r\n\t"):
            raise ControlError("invalid_web_batch")
    return steps
