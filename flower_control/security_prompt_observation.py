"""Bounded hints from an already authorized, exact-window UIA observation.

This module does no I/O and grants no authority. A title, accessible label or
process basename can be spoofed: even a matching Huorong-looking dialog stays
an unverified candidate. Its displayed decision is not the original program's
business result, nor evidence relating another process or request to it.
"""
from __future__ import annotations

import re

_TARGET_KEYS = ("pid", "hwnd", "process_start_filetime")
_ALLOW = frozenset({"允许", "允许一次", "本次允许", "放行"})
_DENY = frozenset({"阻止", "阻止一次", "本次阻止", "拒绝"})
_REMEMBER = frozenset({"记住", "记住选择", "记住我的选择", "记住本次选择", "记住此次选择", "记住此操作", "记住此次操作"})
_FIELD_LABELS = {
    "命令行": "command_line", "进程命令行": "command_line",
    "父进程命令行": "parent_command_line", "父命令行": "parent_command_line",
    "程序路径": "program_path", "操作类型": "operation_type",
    "发起程序": "initiating_program", "防护项目": "protection_item",
    "操作目标": "operation_target", "父进程": "parent_process",
}
_MAX_ENTRIES = 500
_MAX_TEXT = 512
_COUNTDOWN_SUFFIX = re.compile(r"\s*(?:\([0-9]{1,4}\)|（[0-9]{1,4}）)$")


def _button_label(value: str) -> str:
    # Only a final numeric countdown is removed. Do not normalize arbitrary
    # parenthetical claims, words, interior digits or recommended actions.
    return _COUNTDOWN_SUFFIX.sub("", value.replace("&", "").strip()).strip()


def security_prompt_observation(uia: object, *, expected_target: dict,
                                content_allowed: bool,
                                window_title: str | None = None,
                                process_basename: str | None = None) -> dict | None:
    """Classify only supplied visible fields; absence never means no blocker.

    Optional title/process hints must come from the caller's same exact window
    snapshot. Production App/Computer callers currently supply only the UIA
    result and their independently checked target. No signature verification,
    process enumeration, extra UIA read, input, persistent content or request
    association is performed here.
    """
    if (content_allowed is not True or type(uia) is not dict
            or uia.get("state") != "observed" or type(expected_target) is not dict
            or any(type(expected_target.get(key)) is not int or expected_target[key] <= 0
                   or type(uia.get(key)) is not int or uia[key] != expected_target[key] for key in _TARGET_KEYS)
            or type(uia.get("root_runtime_id")) is not list or not uia["root_runtime_id"]
            or len(uia["root_runtime_id"]) > 64 or any(type(item) is not int for item in uia["root_runtime_id"])
            or type(uia.get("observed_at_ms")) is not int or uia["observed_at_ms"] <= 0
            or type(uia.get("entries")) is not list):
        return None

    rows = []
    for entry in uia["entries"][:_MAX_ENTRIES]:
        if (type(entry) is not dict or entry.get("offscreen") is not False
                or entry.get("password") is not False or entry.get("password_read_error") is True):
            continue
        name = entry.get("name") if entry.get("name_read_error") is not True else None
        value = entry.get("value") if entry.get("value_read_error") is not True else None
        name = name.strip()[:_MAX_TEXT] if type(name) is str else ""
        value = value.strip()[:_MAX_TEXT] if type(value) is str else ""
        if name or value:
            rows.append((entry, name, value))
    if not rows:
        return None

    # The brand signal is only a hint, never a trusted publisher identity.
    text = "\n".join(name + "\n" + value for _, name, value in rows)
    title = window_title[:_MAX_TEXT] if type(window_title) is str else ""
    process = process_basename[:128].casefold() if type(process_basename) is str else ""
    brand_text = text + "\n" + title
    brand = "火绒" in brand_text or "huorong" in brand_text.casefold() or process == "hipstray.exe"
    buttons = {_button_label(name) for entry, name, _ in rows
               if entry.get("control_type") == "Button"}
    choices_visible = bool(buttons & _ALLOW) and bool(buttons & _DENY)
    enabled_buttons = {_button_label(name) for entry, name, _ in rows
                       if entry.get("control_type") == "Button" and entry.get("enabled") is True}
    pending = bool(enabled_buttons & _ALLOW) and bool(enabled_buttons & _DENY)
    reported_block = any(token in name or token in value
                         for entry, name, value in rows if entry.get("control_type") != "Button"
                         for token in ("已阻止", "已拦截", "已阻断"))
    # Older system-hardening questions can omit the vendor name. Require the
    # combined question template and all three visible labels, never just a
    # generic title. This is a possible-vendor hint, not product authentication.
    security_template = (("系统加固" in text or "发现程序试图操作" in text)
                         and all(label in text for label in ("发起程序", "防护项目", "操作目标")))
    if not (brand and (choices_visible or reported_block)
            or security_template and choices_visible):
        return None

    fields = {}
    for entry, name, value in rows:
        for label, key in _FIELD_LABELS.items():
            observed = None
            label_seen = name.rstrip("：: ") == label
            if label_seen and value:
                observed = value
            else:
                for supplied in (name, value):
                    for separator in ("：", ":"):
                        prefix = label + separator
                        if supplied.startswith(prefix):
                            label_seen = True
                            observed = supplied[len(prefix):].strip() or None
            if not label_seen:
                continue
            truncated = (entry.get("name_truncated") is True or entry.get("value_truncated") is True
                         or any(type(entry.get(part)) is str and len(entry[part]) > _MAX_TEXT for part in ("name", "value")))
            field = {"state": "label_only" if observed is None else "partial" if truncated else "observed"}
            if observed is not None:
                field["text"] = observed
            # Duplicate labels are ambiguous; do not pick one command as the
            # complete original request or infer a value from the next node.
            if key in fields:
                fields[key] = {"state": "ambiguous"}
            else:
                fields[key] = field
    command_keys = {"command_line", "parent_command_line"} & fields.keys()
    command_information = ("not_observed" if not command_keys else
        "both_visible_fields_observed" if len(command_keys) == 2
        and all(fields[key]["state"] == "observed" for key in command_keys)
        and uia.get("truncated") is False and len(uia["entries"]) <= _MAX_ENTRIES else "partial")
    remember = [entry for entry, name, _ in rows
                if entry.get("control_type") == "CheckBox" and name.replace("&", "").strip() in _REMEMBER]
    remember_state = "not_observed"
    if len(remember) > 1:
        remember_state = "ambiguous"
    elif remember:
        entry = remember[0]
        if (uia.get("truncated") is not False or len(uia["entries"]) > _MAX_ENTRIES
                or entry.get("name_truncated") is True or entry.get("name_read_error") is True):
            remember_state = "unknown"
        else:
            toggle = entry.get("toggle_state")
            remember_state = {"Off": "unchecked", "On": "checked"}.get(toggle, "unknown") if type(toggle) is str else "unknown"
    return {
        "kind": "security_prompt_candidate", "vendor_hint": "huorong" if brand else "huorong_possible",
        "identity": "unverified", "window_identity": {key: expected_target[key] for key in _TARGET_KEYS},
        "observed_at_ms": uia["observed_at_ms"], "source": "visible_uia",
        "not_authorization": True, "business_result_unknown": True,
        "automatic_action": False, "original_request_relation": "not_established",
        "reported_decision": "blocked" if reported_block else "pending" if pending else "unknown",
        "uia_truncated": uia.get("truncated") is not False or len(uia["entries"]) > _MAX_ENTRIES,
        "information_scope": "observed_visible_fields_only",
        "command_line_information": command_information,
        "remember_choice": {"state": remember_state, "source": "visible_uia", "not_authorization": True},
        **({"fields": fields} if fields else {}),
    }
