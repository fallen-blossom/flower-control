"""Closed read-only wait shape shared by call lifetime and actual admission."""
import math

VISUAL = {"image_changed", "image_unchanged", "image_stable"}


def wait_timeout_ms(arguments):
    if (type(arguments) is not dict or not {"condition", "timeout_ms"} <= set(arguments)
            or set(arguments) - {"condition", "timeout_ms", "roi", "stable_ms", "roi_units", "threshold"}
            or type(arguments["condition"]) is not str
            or arguments["condition"] not in VISUAL | {"window_closed", "new_window", "elapsed"}
            or type(arguments["timeout_ms"]) is not int or not 1 <= arguments["timeout_ms"] <= 30000):
        raise ValueError("invalid_wait_request")
    condition = arguments["condition"]
    if "threshold" in arguments:
        threshold = arguments["threshold"]
        if type(threshold) not in (int, float) or not 0 <= threshold <= 255 or not math.isfinite(threshold):
            raise ValueError("invalid_visual_threshold")
    if (any(key in arguments for key in ("roi", "roi_units", "threshold")) and condition not in VISUAL
            or "stable_ms" in arguments and condition != "image_stable"
            or condition == "image_stable" and (type(arguments.get("stable_ms", 300)) is not int
                or not 100 <= arguments.get("stable_ms", 300) <= arguments["timeout_ms"])):
        raise ValueError("invalid_wait_request")
    if condition in VISUAL:
        units, roi = arguments.get("roi_units", "pixels"), arguments.get("roi")
        if type(units) is not str or units not in {"pixels", "normalized_1000"} or roi is None and units != "pixels":
            raise ValueError("invalid_visual_roi_units")
        if roi is not None and (type(roi) is not list or len(roi) != 4
                or any(type(value) is not int for value in roi)
                or not 0 <= roi[0] < roi[2] or not 0 <= roi[1] < roi[3]
                or units == "normalized_1000" and (roi[2] > 1000 or roi[3] > 1000)):
            raise ValueError("invalid_visual_roi")
    return arguments["timeout_ms"]


def call_lifetime(tool, payload):
    if tool == 'flower_computer_action_status':
        seconds = payload.get('wait_seconds')
        if type(seconds) is int and 0 <= seconds <= 30 and payload.get('result_report') is None:
            return max(30,seconds+10)
    if tool == "flower_computer_input" and payload.get("command") == "wait":
        try:
            timeout = wait_timeout_ms(payload.get("arguments"))
        except ValueError:
            return 30
        # Final fresh capture is outside the condition deadline. This changes
        # only this read-only call, never a writable observation or scope grant.
        return max(30, timeout / 1000 + 10)
    return 30
