"""Only behavior-equivalent legacy names; no lifecycle or permission changes."""
from flower_control.control.state import ControlError


def normalize_window_mode(value, *, allow_none=True):
    if value is None and allow_none:
        return None
    if type(value) is not str:
        raise ControlError("invalid_window_mode")
    modes = {"visible": "visible", "hidden": "hidden",
        "headed-maximized": "visible", "headless": "hidden",
        "headed-minimized":"minimized","minimized":"minimized","foreground":"visible"}
    if value not in modes:
        raise ControlError("invalid_window_mode")
    return modes[value]


def browser_window_mode(browser):
    return 'hidden' if browser.headless else 'minimized' if getattr(browser,'start_minimized',False) is True else 'visible'
