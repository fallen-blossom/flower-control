"""Deterministic on-device redaction, before image caches and MCP encoding."""
from __future__ import annotations

from dataclasses import replace
import os
import re
import struct
import time
import uuid
from functools import lru_cache
from pathlib import Path

from flower_control.permissions import (PermissionError, active_policy, canonical_path,
                                        process_facts, require_window, revision)

# Applications whose whole client surface is private by default. Match the
# executable basename, never a user-editable window title.
SENSITIVE_EXECUTABLES = frozenset({"bitwarden.exe"})


def sensitive_application(image):
    import ntpath
    return ntpath.basename(str(image)).casefold() in SENSITIVE_EXECUTABLES


def intersects(a, b):
    return a[0] < b[2] and b[0] < a[2] and a[1] < b[3] and b[1] < a[3]


def application_masks(image, policy=None):
    value = policy or active_policy.read()
    return [row for row in value["Masks"] if row["Enabled"]
            and canonical_path(row["Path"]) == canonical_path(str(image))]


def window_masks(identity, geometry=None):
    value = require_window(identity.hwnd)
    try:
        image, _ = process_facts(identity.pid)
    except Exception:
        image = None
    if image is not None and sensitive_application(image):
        from flower_control.drivers.computer_native import window_geometry
        geometry = geometry or window_geometry(identity)
        left, top = geometry.client_origin
        width, height = geometry.client_size
        return value["Revision"], ((left, top, left + width, top + height),)
    if not any(row["Enabled"] for row in value["Masks"]):
        return value["Revision"], ()
    if image is None:
        raise PermissionError("privacy_application_identity_unavailable")
    masks = application_masks(image, value)
    if not masks:
        return value["Revision"], ()
    from flower_control.drivers.computer_native import window_geometry
    geometry = geometry or window_geometry(identity)
    rects = []
    for row in masks:
        if tuple(row["ClientSize"]) != tuple(geometry.client_size):
            raise PermissionError("privacy_region_geometry_changed")
        rects.append(tuple(n + geometry.client_origin[i % 2] for i, n in enumerate(row["Rect"])))
    return value["Revision"], tuple(rects)


def redact_capture(capture, identity, *, geometry=None, password_rects=(), _mask_snapshot=None):
    version, manual = window_masks(identity, geometry) if _mask_snapshot is None else _mask_snapshot
    rects = tuple(manual) + tuple(password_rects)
    if not rects:
        if revision() != version:
            raise PermissionError("user_policy_requires_new_observation")
        return replace(capture, privacy_revision=version)
    data = capture.bmp
    if (type(data) is not bytes or len(data) < 54 or data[:2] != b"BM"
            or struct.unpack_from("<I", data, 10)[0] != 54
            or struct.unpack_from("<IiiHHI", data, 14) != (40, capture.width, -capture.height, 1, 32, 0)
            or len(data) != 54 + capture.width * capture.height * 4):
        raise PermissionError("privacy_bitmap_invalid")
    pixels = bytearray(data)
    bounds = capture.source_bounds
    for rect in rects:
        left, top = max(0, rect[0] - bounds.left), max(0, rect[1] - bounds.top)
        right, bottom = min(capture.width, rect[2] - bounds.left), min(capture.height, rect[3] - bounds.top)
        if left >= right or top >= bottom:
            continue
        black = b"\0\0\0\xff" * (right - left)
        for y in range(top, bottom):
            offset = 54 + (y * capture.width + left) * 4
            pixels[offset:offset + len(black)] = black
    if revision() != version:
        raise PermissionError("user_policy_requires_new_observation")
    # Preserve the worker's exact 32-bit top-down BMP protocol.
    return replace(capture, bmp=bytes(pixels), privacy_revision=version, privacy_rects=rects)


def capture_private(identity, capture, *, preflight, stopped, task=None):
    """Capture with cheap explicit masks; no whole-window UIA discovery.

    Daily-use policy (2026-11-01): password controls remain protected by the
    structured App/Web and input paths. Pixels have no automatic password-field
    discovery guarantee. Do not start a provider scan just to return a frame.
    """
    from .drivers.high_helper import capture_target_image_snapshot
    with capture_target_image_snapshot():
        return _capture_private(identity, capture, preflight=preflight, stopped=stopped, task=task)


def _capture_private(identity, capture, *, preflight, stopped, task=None):
    from dataclasses import replace
    from time import perf_counter
    began = perf_counter()
    preflight()
    if stopped():
        raise PermissionError("privacy_scan_cancelled")
    masks = window_masks(identity)
    mapping = None
    if masks[1]:
        mapping = _capture_mapping(identity)
        masks = window_masks(identity, mapping[0])
    before_end = perf_counter()
    capture_began = perf_counter()
    frame = capture()
    capture_end = perf_counter()
    if stopped():
        raise PermissionError("privacy_scan_cancelled")
    if masks != window_masks(identity):
        raise PermissionError("privacy_image_mapping_changed")
    if mapping is not None:
        geometry, visible = mapping
        expected = geometry.window if frame.source == "PrintWindow" else visible if frame.source == "WGC" else None
        if expected is None or frame.source_bounds != expected or _capture_mapping(identity) != mapping:
            raise PermissionError("privacy_image_mapping_changed")
    preflight()
    frame = redact_capture(frame, identity, _mask_snapshot=masks)
    after_end = perf_counter()
    # Local numeric stage times only. The existing backend elapsed_ms retains
    # its original meaning; it must not be mistaken for the entire observation.
    if hasattr(frame, "capture_stage_timings_ms"):
        frame = replace(frame, capture_stage_timings_ms={
            "metadata_before": round((before_end - began) * 1000, 3),
            "capture": round((capture_end - capture_began) * 1000, 3),
            "metadata_after": round((after_end - capture_end) * 1000, 3),
            "total": round((perf_counter() - began) * 1000, 3)})
    return frame


def _capture_mapping(identity):
    from flower_control.drivers.computer_native import Rect, window_geometry
    from flower_control.drivers.computer_capture_worker import _visible_bounds, WgcUnavailable
    geometry = window_geometry(identity)
    try:
        visible = Rect(*_visible_bounds(identity.hwnd))
    except WgcUnavailable:
        visible = None
    if window_geometry(identity) != geometry:
        raise PermissionError("privacy_image_mapping_changed")
    return geometry, visible


def require_unmasked_point(identity, screen_point, *, geometry=None):
    _, rects = window_masks(identity, geometry)
    x, y = screen_point
    if any(r[0] <= x < r[2] and r[1] <= y < r[3] for r in rects):
        raise PermissionError("privacy_region_input_disabled")


def require_unmasked_steps(identity, steps, geometry, *, password_info=None, sweep_motion=False, owned_tokens=(), check_keyboard=True):
    """Cannot infer a relative/keyboard focus path through a manual mask."""
    _, rects = window_masks(identity, geometry)
    rects += tuple(password_info["rectangles"]) if password_info is not None else ()
    if check_keyboard and password_info is not None and password_info.get("focus_password") is True and any(s.raw.type == 1 for s in steps):
        raise PermissionError("privacy_keyboard_focus_unverified")
    if not rects:
        return
    from flower_control.drivers.computer_native import virtual_desktop
    import win32gui
    desktop = virtual_desktop()
    previous = win32gui.GetCursorPos()
    dragging = any(kind == "mouse" for kind, _ in owned_tokens)
    for step in steps:
        raw = step.raw
        if raw.type == 1:
            if check_keyboard:
                focus = password_info.get("focus_rectangle") if password_info else None
                if focus is None or password_info.get("focus_password") is True or any(intersects(focus, r) for r in rects):
                    raise PermissionError("privacy_keyboard_focus_unverified")
            continue
        if raw.type != 0:
            continue
        flags = raw.data.mi.dwFlags
        if flags & 1 and not flags & 0x8000:
            raise PermissionError("privacy_relative_input_disabled")
        point = previous
        if flags & 0x8000:
            point = (desktop.left + raw.data.mi.dx * desktop.width // 65536,
                     desktop.top + raw.data.mi.dy * desktop.height // 65536)
        # Conservative bounding-box rejection also covers a drag through a mask.
        swept = ((min(previous[0], point[0]), min(previous[1], point[1]),
                  max(previous[0], point[0]) + 1, max(previous[1], point[1]) + 1)
                 if dragging or sweep_motion else (point[0], point[1], point[0] + 1, point[1] + 1))
        if any(intersects(swept, rect) for rect in rects):
            raise PermissionError("privacy_region_input_disabled")
        previous = point
        if flags & 0x2a: dragging = True
        if flags & 0x54: dragging = False


def require_text_unmasked(hwnd):
    """Manual pixel regions cannot safely redact arbitrary container TextPattern."""
    value = require_window(hwnd)
    import win32process
    try:
        image, _ = process_facts(win32process.GetWindowThreadProcessId(hwnd)[1])
    except Exception:
        # Unavailable process identity is not evidence for or against the
        # default sensitive list; retain the existing password/mask checks.
        image = None
    if image is not None and sensitive_application(image):
        raise PermissionError("privacy_sensitive_application")
    if not any(row["Enabled"] for row in value["Masks"]):
        return
    if image is None:
        raise PermissionError("privacy_application_identity_unavailable")
    if application_masks(image, value):
        raise PermissionError("privacy_text_mapping_unavailable")


_PII = re.compile(r"(?i)(?:[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+"
                  r"|\b(?:sk-|pplx-|ghp_|github_pat_)[a-z0-9_-]{12,}\b"
                  r"|\b\d{17}[0-9X]\b|\b1[3-9]\d{9}\b)")


def redact_candidate_text(value):
    """One local text pass, preserving same/different identity within a packet.

    No model is called. Known patterns and the user's literal word list are
    limited protection, not a promise to identify every private string. Alias
    mappings are transient and never returned, logged or reused across calls.
    """
    pattern = _candidate_pattern(tuple(sensitive_words()))
    prefix = "private_" + uuid.uuid4().hex[:12] + "_"
    aliases = {}
    def alias(match):
        key = match[0].casefold()
        if key not in aliases:
            aliases[key] = "[" + prefix + str(len(aliases) + 1) + "]"
        return aliases[key]
    def walk(item, key=None):
        if isinstance(item, str):
            # These are opaque local identifiers or typed protocol tags, not
            # UI content. Redacting them breaks the exact local choice map.
            if key == "candidate_id" and re.fullmatch(r"[0-9a-f]{32}", item):
                return item
            if key == "type" and item in {"choice", "score", "noul"}:
                return item
            return pattern.sub(alias, item)
        if isinstance(item, list):
            return [walk(part) for part in item]
        if isinstance(item, dict):
            return {name: walk(part, name) for name, part in item.items()}
        return item
    return walk(value)


@lru_cache(maxsize=2)
def _candidate_pattern(words):
    # Compile once per bounded word-list snapshot, rather than once per label.
    # Factor shared prefixes so a 2,000-word list does not scan 2,000 complete
    # alternatives at every character. Greedy optional tails keep longest-match
    # behavior, including literal matches inside ordinary words.
    root = {}
    for word in words:
        node = root
        for character in word:
            node = node.setdefault(character, {})
        node[None] = True
    def branch(node):
        parts = [re.escape(character) + branch(child)
                 for character, child in node.items() if character is not None]
        joined = "|".join(parts)
        result = ("(?:" + joined + ")") if len(parts) > 1 else joined
        return "(?:" + result + ")?" if None in node and result else result
    suffix = "|" + branch(root) if words else ""
    return re.compile(_PII.pattern + suffix, re.IGNORECASE)


_WORD_CACHE = {"stamp": None, "words": ()}
_WORD_LIMIT = 2000
_WORD_MAX_LENGTH = 200


def sensitive_word_paths():
    """Local, optional word lists; missing files mean no extra blocking."""
    paths = []
    try:
        from flower_control.permissions import production_path
        paths.append(production_path().parent.parent / "privacy" / "sensitive-words.txt")
    except Exception:
        pass
    local = os.environ.get("LOCALAPPDATA")
    if local:
        paths.append(Path(local) / "FlowerControl" / "privacy" / "sensitive-words.txt")
    return tuple(paths)


def _word_stamp(paths):
    stamp = []
    for path in paths:
        try:
            stat = path.stat()
            stamp.append((str(path), stat.st_mtime_ns, stat.st_size))
        except OSError:
            stamp.append((str(path), None, None))
    return tuple(stamp)


def sensitive_words(paths=None):
    """Read one word per line, UTF-8; bounded and cached by file metadata."""
    paths = tuple(paths or sensitive_word_paths())
    stamp = _word_stamp(paths)
    if _WORD_CACHE["stamp"] == stamp:
        return _WORD_CACHE["words"]
    words = []
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeError):
            continue
        for line in text.splitlines():
            word = line.strip()
            if (word and not word.startswith("#") and len(word) <= _WORD_MAX_LENGTH
                    and word not in words):
                words.append(word)
                if len(words) >= _WORD_LIMIT:
                    break
        if len(words) >= _WORD_LIMIT:
            break
    result = tuple(sorted(words, key=len, reverse=True))
    _WORD_CACHE.update(stamp=stamp, words=result)
    return result


_CONTENT_KEYS = frozenset({"text", "name", "value", "help_text", "title", "label", "message",
                           "content", "description", "url", "selected_text", "page_text",
                           "goal", "summary", "goal_hint", "next_step", "task_stage", "purpose",
                           "prompt_text", "expected_text", "attribute_value"})
_STRUCTURAL_KEYS = frozenset({"ref", "runtime_id", "automation_id", "observation_id", "action_id",
                              "token", "path", "file", "output_path", "reason", "next_cursor", "cursor",
                              "id", "page_id", "session_id", "chat_ref", "request_id", "program_ref",
                              "work_id", "handle", "hwnd", "pid", "process_created", "window_nonce",
                              "sha256", "hash", "fingerprint", "revision", "generation"})


def redact_sensitive_text(text, words=None):
    """Replace only locally configured words; no model-supplied patterns."""
    if type(text) is not str:
        return text
    words = sensitive_words() if words is None else words
    if not words:
        return text
    pattern = re.compile("|".join(re.escape(word) for word in words), re.IGNORECASE)
    if pattern.search(text) is None:
        return text
    return pattern.sub("[REDACTED]", text)


def redact_sensitive_values(value, words=None, *, key=None, depth=0):
    """Walk JSON-like results and redact content fields only.

    Structural identity and continuation fields stay byte-exact so the model
    can keep using an observation or action. Sensitive words never enter the
    returned content in the first place; this is the last local gate.
    """
    if depth > 32:
        return value
    if type(value) is dict:
        result = None
        for name, item in value.items():
            if name in _STRUCTURAL_KEYS:
                redacted = item
            elif name in _CONTENT_KEYS:
                redacted = redact_sensitive_values(item, words, key=name, depth=depth + 1)
            else:
                redacted = redact_sensitive_values(item, words, key=name, depth=depth + 1)
            if redacted is not item:
                if result is None:
                    result = dict(value)
                result[name] = redacted
        return value if result is None else result
    if type(value) is list:
        result = None
        for index, item in enumerate(value):
            redacted = redact_sensitive_values(item, words, key=key, depth=depth + 1)
            if redacted is not item:
                if result is None:
                    result = list(value)
                result[index] = redacted
        return value if result is None else result
    if type(value) is str and key in _CONTENT_KEYS:
        return redact_sensitive_text(value, words)
    return value
