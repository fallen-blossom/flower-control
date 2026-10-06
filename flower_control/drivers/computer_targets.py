"""Bounded local Computer candidates from an authorized FlaUI observation.

This module does not read arbitrary desktop windows. The caller supplies the
App worker's UIA result for the same selected HWND and a Computer capture.
Candidates are advisory until the Computer input path independently checks its
permission, foreground, geometry and target-region freshness before SendInput.
"""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import hmac
import json
import secrets
import struct
import time

from flower_control.control.native import process_creation_filetime
from flower_control.drivers.computer_capture import CaptureResult
from flower_control.drivers.computer_native import (WindowGeometry, WindowIdentity,
                                                    assert_geometry, assert_window)


_CLICKABLE_ROLES = frozenset({"Button", "MenuItem", "ListItem", "CheckBox",
                              "RadioButton", "TabItem", "Hyperlink"})
_MAX_CANDIDATES = 48
_MAX_UIA_GAP_MS = 1500
_CANDIDATE_TTL_MS = 15_000
_SEAL_KEY = secrets.token_bytes(32)


class CandidateError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _generation(geometry: WindowGeometry) -> str:
    return json.dumps(asdict(geometry), sort_keys=True, separators=(",", ":"))


def _seal(candidate: dict) -> str:
    try:
        body = json.dumps({key: value for key, value in candidate.items()
                           if key != "_seal"}, sort_keys=True,
                          separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError):
        return ""
    return hmac.new(_SEAL_KEY, body, hashlib.sha256).hexdigest()


def _inside(rect: tuple[int, int, int, int], x: int, y: int) -> bool:
    left, top, right, bottom = rect
    return left <= x < right and top <= y < bottom


def _rect(value: object) -> tuple[int, int, int, int] | None:
    if (type(value) is not list or len(value) != 4 or
            any(type(item) is not int for item in value)):
        return None
    left, top, right, bottom = value
    return (left, top, right, bottom) if left < right and top < bottom else None


def _region_digest(capture: CaptureResult,
                   screen_rect: tuple[int, int, int, int]) -> str:
    """Hash only the target's pixels in the capture's validated BGRA BMP."""
    bmp = capture.bmp
    if type(bmp) is not bytes or len(bmp) < 54 or bmp[:2] != b"BM":
        raise CandidateError("capture_bitmap_invalid")
    file_size, offset = struct.unpack_from("<IxxxxI", bmp, 2)
    dib_size, width, negative_height, planes, bits, compression = (
        struct.unpack_from("<IiiHHI", bmp, 14))
    if (file_size != len(bmp) or offset != 54 or dib_size != 40 or
            width != capture.width or -negative_height != capture.height or
            planes != 1 or bits != 32 or compression != 0 or
            len(bmp) != 54 + width * capture.height * 4 or
            capture.source_bounds.width != width or
            capture.source_bounds.height != capture.height):
        raise CandidateError("capture_bitmap_invalid")
    left = screen_rect[0] - capture.source_bounds.left
    top = screen_rect[1] - capture.source_bounds.top
    right = screen_rect[2] - capture.source_bounds.left
    bottom = screen_rect[3] - capture.source_bounds.top
    if not (0 <= left < right <= width and
            0 <= top < bottom <= capture.height):
        raise CandidateError("candidate_region_outside_capture")
    hashed = hashlib.sha256()
    stride = width * 4
    for y in range(top, bottom):
        start = 54 + y * stride + left * 4
        hashed.update(bmp[start:start + (right - left) * 4])
    return hashed.hexdigest()


def build_uia_candidates(*, identity: WindowIdentity, geometry: WindowGeometry,
                         capture: CaptureResult, computer_observation_id: str,
                         uia: dict, captured_at_ms: int,
                         goal_coverage_confirmed: bool = False) -> dict:
    """Convert named UIA clickable points to client pixels, preserving gaps.

    `goal_coverage_confirmed` is an advisory host judgment that all plausible
    targets for the current goal are represented. A full UIA tree alone cannot
    establish that a canvas, icon without an accessible name, or native menu
    was covered; the host may use the screenshot when coverage is uncertain.
    """
    if (not isinstance(identity, WindowIdentity) or
            not isinstance(geometry, WindowGeometry) or
            geometry.identity != identity or
            not isinstance(capture, CaptureResult) or
            type(computer_observation_id) is not str or
            not computer_observation_id or
            type(captured_at_ms) is not int or captured_at_ms <= 0 or
            type(goal_coverage_confirmed) is not bool or
            type(uia) is not dict):
        raise CandidateError("candidate_input_invalid")
    assert_window(identity)
    assert_geometry(geometry)
    start = process_creation_filetime(identity.pid, expected_iso=identity.process_created)
    if (uia.get("state") != "observed" or uia.get("pid") != identity.pid or
            uia.get("hwnd") != identity.hwnd or
            uia.get("process_start_filetime") != start or
            type(uia.get("root_runtime_id")) is not list or
            not uia["root_runtime_id"]):
        raise CandidateError("uia_target_mismatch")
    observed_at = uia.get("observed_at_ms")
    if (type(observed_at) is not int or
            abs(captured_at_ms - observed_at) > _MAX_UIA_GAP_MS or
            abs(int(time.time() * 1000) - captured_at_ms) > 15_000):
        raise CandidateError("uia_capture_not_coherent")
    if (type(uia.get("entries")) is not list or
            type(uia.get("truncated")) is not bool or
            capture.width <= 0 or capture.height <= 0 or not capture.bmp):
        raise CandidateError("candidate_input_invalid")

    client_left, client_top = geometry.client_origin
    client_width, client_height = geometry.client_size
    client_rect = (client_left, client_top,
                   client_left + client_width, client_top + client_height)
    source = capture.source_bounds
    source_rect = (source.left, source.top, source.right, source.bottom)
    if not (_inside(source_rect, client_left, client_top) and
            _inside(source_rect, client_rect[2] - 1, client_rect[3] - 1)):
        raise CandidateError("capture_client_mismatch")

    digest = hashlib.sha256(capture.bmp).hexdigest()
    generation = _generation(geometry)
    candidates: list[dict] = []
    seen: set[tuple] = set()
    gaps: set[str] = set()
    if uia.get("window_enabled") is not True:
        return {"channel": "computer", "source": "uia",
                "computer_observation_id": computer_observation_id,
                "target_identity": asdict(identity), "generation": generation,
                "image_digest": digest, "candidates": [], "complete": False,
                "incomplete_reasons": ["host_vision_required", "window_disabled"],
                "host_vision_required": True}
    for entry in uia["entries"]:
        if type(entry) is not dict or entry.get("control_type") not in _CLICKABLE_ROLES:
            continue
        if (entry.get("password") or entry.get("offscreen") is not False or
                entry.get("enabled") is not True):
            continue
        if not (entry.get("invoke_supported") or entry.get("selection_item_supported")
                or entry.get("toggle_supported")):
            gaps.add("uia_action_unavailable")
            continue
        label = entry.get("name")
        label_source = "name"
        if type(label) is not str or not label.strip():
            label = entry.get("automation_id")
            label_source = "automation_id"
        if type(label) is not str or not label.strip():
            gaps.add("uia_label_unavailable")
            continue
        bounds = _rect(entry.get("bounding_rect_screen"))
        point = entry.get("clickable_point_screen")
        # The candidate contract covers the physical client. Caption buttons
        # are deliberately outside that domain, rather than missing targets.
        if bounds is not None and (bounds[2] <= client_rect[0] or bounds[0] >= client_rect[2]
                                   or bounds[3] <= client_rect[1] or bounds[1] >= client_rect[3]):
            continue
        if (bounds is None or type(point) is not list or len(point) != 2 or
                any(type(item) is not int for item in point) or
                not _inside(bounds, point[0], point[1]) or
                not _inside(client_rect, point[0], point[1]) or
                not _inside(source_rect, point[0], point[1]) or
                not (_inside(client_rect, bounds[0], bounds[1]) and
                     _inside(client_rect, bounds[2] - 1, bounds[3] - 1))):
            gaps.add("uia_clickable_point_unavailable")
            continue
        rect_client = [bounds[0] - client_left, bounds[1] - client_top,
                       bounds[2] - client_left, bounds[3] - client_top]
        point_client = [point[0] - client_left, point[1] - client_top]
        role = entry["control_type"]
        key = (role, label, *rect_client, *point_client)
        if key in seen:
            continue
        seen.add(key)
        if len(candidates) >= _MAX_CANDIDATES:
            gaps.add("candidate_limit")
            break
        candidate = {
            "candidate_id": secrets.token_urlsafe(12),
            "channel": "computer", "source": "uia", "action": "click",
            "role": role, "label": label[:96], "label_source": label_source,
            "visible": True,
            "enabled": True, "password": False,
            "rect_client": rect_client, "point_client": point_client,
            "coordinate_space": "physical_client_pixels",
            "target_identity": asdict(identity),
            "generation": generation, "image_digest": digest,
            "capture_bounds_screen": list(source_rect),
            "capture_width": capture.width, "capture_height": capture.height,
            "capture_backend": capture.source,
            "region_digest": _region_digest(capture, bounds),
            "uia_observed_at_ms": observed_at,
            "uia_bounds_screen": list(bounds),
            "uia_automation_id": entry.get("automation_id"),
            "uia_name": entry.get("name"),
            "computer_observation_id": computer_observation_id,
            "uia_root_runtime_id": uia["root_runtime_id"],
            "uia_runtime_id": entry.get("runtime_id"),
            "expires_at_ms": captured_at_ms + _CANDIDATE_TTL_MS,
        }
        candidate["_seal"] = _seal(candidate)
        candidates.append(candidate)
    if uia["truncated"]:
        gaps.add("uia_truncated")
    if not candidates:
        gaps.add("host_vision_required")
    complete = bool(candidates and (goal_coverage_confirmed or not gaps))
    if not complete:
        gaps.add("host_vision_required")
    return {"channel": "computer", "source": "uia", "coverage_domain": "client_controls",
            "computer_observation_id": computer_observation_id,
            "target_identity": asdict(identity), "generation": generation,
            "image_digest": digest, "candidates": candidates,
            "complete": complete,
            "incomplete_reasons": sorted(gaps) if not complete else [],
            "coverage_notes": sorted(gaps),
            "host_vision_required": not complete}


def checked_click_arguments(candidate: dict, *, identity: WindowIdentity,
                            geometry: WindowGeometry, capture: CaptureResult,
                            computer_observation_id: str,
                            current_uia: dict | None = None,
                            current_captured_at_ms: int | None = None) -> dict:
    """Check target pixels or a fresh exact UIA ref before the input gate.

    Whole-frame changes elsewhere are harmless. A hover or cursor change over
    the target can be accepted only with a new UIA observation that still binds
    the same control, bounds and clickable point.
    """
    if (type(candidate) is not dict or type(candidate.get("_seal")) is not str or
            len(candidate["_seal"]) != 64 or
            not hmac.compare_digest(candidate["_seal"], _seal(candidate)) or
            type(candidate.get("expires_at_ms")) is not int or
            candidate["expires_at_ms"] <= int(time.time() * 1000) or
            candidate.get("source") != "uia" or
            candidate.get("channel") != "computer" or
            candidate.get("computer_observation_id") != computer_observation_id or
            candidate.get("target_identity") != asdict(identity) or
            candidate.get("generation") != _generation(geometry) or
            candidate.get("capture_bounds_screen") != list(
                (capture.source_bounds.left, capture.source_bounds.top,
                 capture.source_bounds.right, capture.source_bounds.bottom)) or
            candidate.get("capture_width") != capture.width or
            candidate.get("capture_height") != capture.height):
        raise CandidateError("candidate_version_changed")
    assert_window(identity)
    assert_geometry(geometry)
    bounds = _rect(candidate.get("uia_bounds_screen"))
    if bounds is None:
        raise CandidateError("candidate_region_invalid")
    same_region = _region_digest(capture, bounds) == candidate.get("region_digest")
    if not same_region:
        if (type(current_uia) is not dict or
                type(current_captured_at_ms) is not int or
                current_uia.get("state") != "observed" or
                current_uia.get("pid") != identity.pid or
                current_uia.get("hwnd") != identity.hwnd or
                current_uia.get("process_start_filetime") !=
                process_creation_filetime(identity.pid,
                                          expected_iso=identity.process_created) or
                current_uia.get("root_runtime_id") != candidate.get("uia_root_runtime_id") or
                current_uia.get("window_enabled") is not True or
                type(current_uia.get("observed_at_ms")) is not int or
                current_uia["observed_at_ms"] <= candidate.get("uia_observed_at_ms", 0) or
                abs(current_captured_at_ms - current_uia["observed_at_ms"]) > _MAX_UIA_GAP_MS or
                type(current_uia.get("entries")) is not list):
            raise CandidateError("candidate_requires_new_observation")
        hits = [entry for entry in current_uia["entries"]
                if type(entry) is dict and
                entry.get("runtime_id") == candidate.get("uia_runtime_id") and
                entry.get("automation_id") == candidate.get("uia_automation_id") and
                entry.get("control_type") == candidate.get("role") and
                entry.get("name") == candidate.get("uia_name") and
                entry.get("bounding_rect_screen") == list(bounds) and
                entry.get("clickable_point_screen") == [
                    geometry.client_origin[0] + candidate["point_client"][0],
                    geometry.client_origin[1] + candidate["point_client"][1]] and
                entry.get("offscreen") is False and
                entry.get("enabled") is True and not entry.get("password")]
        if len(hits) != 1:
            raise CandidateError("candidate_requires_new_observation")
    point = candidate.get("point_client")
    if (type(point) is not list or len(point) != 2 or
            any(type(value) is not int for value in point) or
            not (0 <= point[0] < geometry.client_size[0] and
                 0 <= point[1] < geometry.client_size[1])):
        raise CandidateError("candidate_point_invalid")
    return {"x": point[0], "y": point[1], "button": "left"}
