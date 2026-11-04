"""Finite non-content failure facts accepted across the worker boundary."""
import re
_ENUMS = {
    "phase": {"preflight", "dispatch", "postflight", "actionability", "input", "observe", "wait", "read", "write", "lookup", "other"},
    "exception_type": {"TimeoutError", "Error", "RuntimeError", "ValueError", "TypeError", "ControlError", "CancelledError", "ConnectionError", "OSError", "OtherError"},
    "target_tag": {"A", "BUTTON", "DIV", "SPAN", "INPUT", "TEXTAREA", "SELECT", "OPTION", "LABEL", "FORM", "CANVAS", "IFRAME", "IMG", "P", "UL", "OL", "LI", "SVG", "BODY", "HTML", "OTHER"},
    "blocking_tag": {"A", "BUTTON", "DIV", "SPAN", "INPUT", "TEXTAREA", "SELECT", "OPTION", "LABEL", "FORM", "CANVAS", "IFRAME", "IMG", "P", "UL", "OL", "LI", "SVG", "BODY", "HTML", "OTHER"},
    "blocking_role": {"button", "link", "dialog", "alert", "textbox", "checkbox", "radio", "menu", "menuitem", "listbox", "option", "combobox", "tab", "tabpanel", "tree", "treeitem", "region", "grid", "row", "cell", "table", "document", "img", "presentation", "none", "progressbar", "slider", "scrollbar", "tooltip", "heading", "status", "other"},
}


def safe_failure_facts(value):
    if type(value) is not dict:
        return {}
    output = {}
    for key in ("connected", "visible", "enabled", "covered", "receives_pointer"):
        if type(value.get(key)) is bool:
            output[key] = value[key]
    for key in ("elapsed_ms",):
        if type(value.get(key)) is int and 0 <= value[key] <= 120000:
            output[key] = value[key]
    for key in ("phase", "exception_type", "target_tag", "blocking_tag", "blocking_role"):
        item = value.get(key)
        if type(item) is str and re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,47}", item):
            normalized = item.upper() if key.endswith("_tag") else item
            output[key] = normalized if normalized in _ENUMS[key] else "OtherError" if key == "exception_type" else "OTHER" if key.endswith("_tag") else "other"
    return output


def exception_facts(error, phase, elapsed_ms=0):
    name = type(error).__name__
    return safe_failure_facts({"phase": phase, "exception_type": name if name in {
        "TimeoutError", "Error", "RuntimeError", "ValueError", "TypeError", "ControlError",
        "CancelledError", "ConnectionError", "OSError"} else "OtherError", "elapsed_ms": elapsed_ms})
