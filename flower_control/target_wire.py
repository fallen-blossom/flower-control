"""Lossless public target identities across JSON and JavaScript tool calls."""

from __future__ import annotations

import re
from typing import Any

from flower_control.control.errors import explain_error


_SAFE_JSON_INTEGER = (1 << 53) - 1
_MAX_IDENTITY_INTEGER = (1 << 64) - 1


def _integer(value: Any) -> int:
    if type(value) is str and re.fullmatch(r"[1-9][0-9]{0,19}", value):
        number = int(value)
    elif type(value) is int and 0 < value <= _SAFE_JSON_INTEGER:
        number = value  # Compatibility with already safe synthetic callers.
    else:
        raise ValueError("invalid_target_encoding")
    if number > _MAX_IDENTITY_INTEGER:
        raise ValueError("invalid_target_encoding")
    return number


def app_target_from_wire(target: object) -> dict[str, int]:
    if type(target) is not dict or set(target) != {"pid", "hwnd", "process_start_filetime"}:
        raise ValueError("invalid_target_encoding")
    return {name: _integer(target[name]) for name in
            ("pid", "hwnd", "process_start_filetime")}


def app_target_to_wire(target: dict[str, int]) -> dict[str, str]:
    return {name: str(target[name]) for name in
            ("pid", "hwnd", "process_start_filetime")}


def app_result_to_wire(value: Any) -> Any:
    if type(value) is dict:
        if set(value) == {"pid", "hwnd", "process_start_filetime"}:
            return app_target_to_wire(value)
        return {key: app_result_to_wire(item) for key, item in value.items()}
    if type(value) is list:
        return [app_result_to_wire(item) for item in value]
    return value


def computer_target_from_wire(target: object) -> dict[str, int | str]:
    if type(target) is not dict or set(target) != {"pid", "hwnd", "process_created", "window_nonce"}:
        raise ValueError("invalid_target_encoding")
    created = target["process_created"]
    if type(created) is not str or not created or len(created) > 128:
        raise ValueError("invalid_target_encoding")
    return {"pid": _integer(target["pid"]), "hwnd": _integer(target["hwnd"]),
            "process_created": created, "window_nonce": _integer(target["window_nonce"])}


def computer_target_to_wire(value: dict[str, int | str]) -> dict[str, str]:
    return {"pid": str(value["pid"]), "hwnd": str(value["hwnd"]),
            "process_created": str(value["process_created"]),
            "window_nonce": str(value["window_nonce"])}


def computer_result_to_wire(value: Any) -> Any:
    """Normalize exact identities, then explain supplied Computer failure facts."""
    if type(value) is dict:
        if set(value) == {"pid", "hwnd", "process_created", "window_nonce"}:
            return computer_target_to_wire(value)
        result = {key: computer_result_to_wire(item) for key, item in value.items()}
        explanation = explain_error(result.get("reason"), state=result.get("state"),
                                    dispatched=result.get("dispatched"), stage=result.get("stage"),
                                    source="computer", effects=result)
        if explanation is not None:
            result["explanation"] = explanation
        return result
    if type(value) is list:
        return [computer_result_to_wire(item) for item in value]
    return value
