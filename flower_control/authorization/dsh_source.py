"""Immutable per-call source expectation; a fence, never an authority grant."""
from contextvars import ContextVar
import re

SOURCE_FIELD = "flower_dsh_source"
current_source: ContextVar[tuple[str, int] | None] = ContextVar("flower_dsh_call_source", default=None)


def requires_source(name, arguments):
    if name == "flower_app_work_authority":
        return arguments.get("command", "status") not in {"status", "source_status", "revoke", "close"}
    if name == "flower_app_launch_admin":
        return arguments.get("command", "list") not in {"list", "status", "cancel"}
    return False


def take_source(name, arguments, *, dsh):
    present = SOURCE_FIELD in arguments
    value = arguments.pop(SOURCE_FIELD, None)
    required = dsh and requires_source(name, arguments)
    if not required:
        if present:
            raise ValueError("dsh_call_source_unexpected")
        return None
    if (type(value) is not dict or set(value) != {"instance_id", "revision"}
            or type(value["instance_id"]) is not str or re.fullmatch("[a-f0-9]{32}", value["instance_id"]) is None
            or type(value["revision"]) is not int or not 0 <= value["revision"] <= 9007199254740991):
        raise ValueError("dsh_call_source_required")
    return value["instance_id"], value["revision"]


def native_source_fields():
    value = current_source.get()
    return {} if value is None else {"DshSource": {"InstanceId": value[0], "Revision": value[1]}}
