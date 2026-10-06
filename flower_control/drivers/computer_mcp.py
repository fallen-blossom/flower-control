"""Computer MCP runtime for a trusted, exact task and window call context.

The resolver is installed in-process by a trusted host adapter. MCP arguments
cannot create a grant. The default stdio server deliberately has no resolver.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import sys
import threading
import time
import traceback
from typing import Callable

import win32con
import win32gui

from flower_control.control.arbitration import wait_for_turn_sync
from flower_control.control.jev import JevClient
from flower_control.control.jev_diagnostics import (BusinessResultProducer, JevUsage,
                                                   current_context, jev_context,
                                                   report_host_visual_result)
from flower_control.control.state import ControlError, StateStore
from flower_control.control.foreground_recovery import recover_shared_foreground_for_new_target
from flower_control.control.foreground_stage import (measured_stage_cost, StageCost, yielded_foreground_wait,
                                                    begin_foreground_stage)
from flower_control.control.takeover import TakeoverBarrier
from flower_control.window_registry import WindowSelectionError
from flower_control.control.native import (FOREGROUND_INPUT_RESOURCE,
                                           physical_window_resource,
                                           process_creation_filetime)
from .computer_capture import CaptureError, capture_window
from .computer_native import (HeldInputLedger, NativeInputError, PartialInput, TimedInputPlan,
                              WindowIdentity, activate_window, assert_foreground,
                              assert_geometry, assert_window, client_to_screen,
                              bind_window, mouse_button, mouse_move, mouse_move_relative, mouse_wheel,
                              new_visible_followups, plan_batch, plan_timed, plan_unicode_batches,
                              is_owned_popup,
                              send_batch, send_timed_plan, virtual_desktop, virtual_key,
                              visible_process_top_levels, window_geometry)
from .foreground_watch import ForegroundWatch
from .foreground_indicator import ForegroundIndicator, IndicatorError, mouse_path_rects
from .computer_phase import ComputerForegroundPhase
from .computer_input_state import read_input_context, read_input_mode, prepare_ime
from .computer_capture_cache import ComputerCaptureCache
from .computer_high import (ComputerHighConnection, input_plan, assert_target_geometry,
                            layout_environment, window_layout_plan)
from .high_helper import HighHelperError, HighTarget
from .computer_targets import build_uia_candidates, checked_click_arguments, CandidateError
from flower_control.control.targets import TargetCandidate, TargetRequest
from flower_control.control.target_selection import select_target
from flower_control.control.scheduling import Phase
import asyncio
import uuid
import zlib
from dataclasses import replace
from .computer_targets import _region_digest
from flower_control.control.target_selection import selection_permitted


class ComputerBoundaryError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def diagnose_value_error(error: ValueError, phase: str) -> None:
    """Leave a local stack location without logging arguments or window content."""
    frames = traceback.extract_tb(error.__traceback__)[-5:]
    location = [[Path(frame.filename).name, frame.name, frame.lineno]
                for frame in frames]
    print(json.dumps({"event": "computer_value_error", "phase": phase,
                      "location": location}, separators=(",", ":")),
          file=sys.stderr, flush=True)


@dataclass(frozen=True)
class ComputerAuthorization:
    """One exact call decision supplied by a trusted in-process adapter."""

    task_id: str
    identity: WindowIdentity
    expires_at: float  # StateStore.clock domain
    capture_allowed: bool
    input_allowed: bool
    target_scope: str | None = None  # Required for every access to a private window.
    capture_scope: str | None = None
    input_scope: str | None = None  # Includes the post-input visual recheck.
    shared_resource: str | None = None  # Managed Brave's Web conflict domain.


Resolver = Callable[[str, dict], ComputerAuthorization]

_NAMED_KEYS = {
    "CTRL": 0x11, "SHIFT": 0x10, "ALT": 0x12,
    "ENTER": 0x0D, "ESC": 0x1B, "TAB": 0x09,
    "BACKSPACE": 0x08, "DELETE": 0x2E, "INSERT": 0x2D,
    "HOME": 0x24, "END": 0x23, "PAGEUP": 0x21, "PAGEDOWN": 0x22,
    "LEFT": 0x25, "UP": 0x26, "RIGHT": 0x27, "DOWN": 0x28,
    "SPACE": 0x20,
    "WIN": 0x5B, "LWIN": 0x5B, "RWIN": 0x5C,
    "CAPSLOCK": 0x14, "NUMLOCK": 0x90, "SCROLLLOCK": 0x91,
    "PRINTSCREEN": 0x2C, "PAUSE": 0x13,
    "ADD": 0x6B, "SUBTRACT": 0x6D, "MULTIPLY": 0x6A, "DIVIDE": 0x6F, "DECIMAL": 0x6E,
    **{f"NUM{number}": 0x60 + number for number in range(10)},
    **{f"F{number}": 0x6F + number for number in range(1, 25)},
}


def _key_batch(keys: object):
    if (type(keys) is not list or not 1 <= len(keys) <= 4
            or any(type(key) is not str for key in keys)):
        raise ValueError("invalid_key_list")
    codes = []
    for key in keys:
        code = (_NAMED_KEYS.get(key) if key in _NAMED_KEYS else
                ord(key) if len(key) == 1 and key in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                else None)
        if code is None or code in codes:
            raise ValueError("invalid_key_list")
        codes.append(code)
    return plan_batch(tuple(virtual_key(code, down=True) for code in codes)
                      + tuple(virtual_key(code, down=False) for code in reversed(codes)))


def _point_to_screen(geometry, x, y, coordinate_space):
    if coordinate_space == "client":
        return client_to_screen(geometry, x, y)
    if (geometry is None or type(x) is not int or type(y) is not int
            or not 0 <= x < geometry.window.width or not 0 <= y < geometry.window.height):
        raise ComputerBoundaryError("input_point_outside_window")
    return geometry.window.left + x, geometry.window.top + y


def _plan_input(command: str, arguments: dict, geometry):
    if type(arguments) is not dict or command not in (
            "text", "click", "double_click", "key", "key_mouse", "mouse_hold", "move_relative", "scroll", "drag", "move", "hover", "batch"):
        raise ComputerBoundaryError("invalid_input_command")
    if command == "batch":
        if (set(arguments) != {"steps"} or type(arguments["steps"]) is not list or
                not 1 <= len(arguments["steps"]) <= 32):
            raise ComputerBoundaryError("invalid_input_batch")
        result = []
        for step in arguments["steps"]:
            if (type(step) is not dict or set(step) != {"command", "arguments"} or
                    step["command"] in {"batch", "sequence", "wait", "window_move", "window_resize"}):
                raise ComputerBoundaryError("invalid_input_batch")
            result.extend(_plan_input(step["command"], step["arguments"], geometry))
        if (len(result) > 131 or sum(len(batch.steps) for batch in result) > 16384 or
                sum(batch.duration_ms for batch in result if isinstance(batch, TimedInputPlan)) > 2000):
            raise ComputerBoundaryError("input_batch_too_long")
        return tuple(result)
    coordinate_space = arguments.get("coordinate_space", "client")
    if "coordinate_space" in arguments:
        if (type(coordinate_space) is not str or coordinate_space not in {"client", "window"} or command not in {
                "click", "double_click", "scroll", "drag", "mouse_hold", "key_mouse", "move", "hover"}
                or command == "key_mouse" and not {"button", "x", "y"} <= set(arguments)):
            raise ComputerBoundaryError("invalid_coordinate_space")
        arguments = {key: value for key, value in arguments.items() if key != "coordinate_space"}
    if command in {"move", "hover"}:
        if set(arguments) != {"x", "y"} or any(type(n) is not int for n in arguments.values()):
            raise ComputerBoundaryError("invalid_input_arguments")
        try:
            return (plan_batch((mouse_move(*_point_to_screen(geometry, arguments["x"], arguments["y"], coordinate_space), virtual_desktop()),)),)
        except ValueError as error:
            raise ComputerBoundaryError("input_point_outside_client") from error
    if command == "drag" and "path" in arguments:
        path = arguments["path"]
        if (type(path) is not list or not 2 <= len(path) <= 16 or
                set(arguments) - {"path", "button", "keys", "duration_ms"} or "button" not in arguments or
                any(type(p) not in (tuple, list) or len(p) != 2 or any(type(n) is not int for n in p) for p in path)):
            raise ComputerBoundaryError("invalid_input_arguments")
        try:
            points = [_point_to_screen(geometry, *point, coordinate_space) for point in path]
            if any(a == b for a, b in zip(points, points[1:])):
                raise ValueError("duplicate drag point")
            duration = arguments.get("duration_ms", 0)
            if type(duration) is not int or not 0 <= duration <= 2000 or duration and duration < len(points) - 1:
                raise ValueError("invalid drag duration")
            keys = _key_batch(arguments["keys"]).steps if arguments.get("keys") else ()
            size = len(keys) // 2
            releases = (mouse_button(arguments["button"], down=False), *keys[size:])
            desktop = virtual_desktop()
            start = (mouse_move(*points[0], desktop), *keys[:size], mouse_button(arguments["button"], down=True))
            if duration:
                segments = [(0, start)]
                for index, point in enumerate(points[1:], 1):
                    segments.append((round(duration * index / (len(points) - 1)),
                        (mouse_move(*point, desktop), *(releases if index == len(points) - 1 else ()))))
                return (plan_timed(segments, duration),)
            return (plan_batch((*start, *(mouse_move(*p, desktop) for p in points[1:]), *releases)),)
        except ValueError as error:
            raise ComputerBoundaryError("invalid_input_arguments") from error
    if command == "text":
        if set(arguments) != {"text"} or type(arguments["text"]) is not str:
            raise ComputerBoundaryError("invalid_input_arguments")
        try:
            return plan_unicode_batches(arguments["text"])
        except (ValueError, UnicodeError) as error:
            raise ComputerBoundaryError("invalid_input_arguments") from error
    if command == "key":
        if set(arguments) not in ({"keys"}, {"keys", "duration_ms"}):
            raise ComputerBoundaryError("invalid_input_arguments")
        try:
            batch = _key_batch(arguments["keys"])
            duration = arguments.get("duration_ms", 0)
            if type(duration) is not int or not 0 <= duration <= 2000:
                raise ValueError("invalid hold duration")
            if not duration:
                return (batch,)
            size = len(batch.steps) // 2
            return (plan_timed(((0, batch.steps[:size]), (duration, batch.steps[size:])), duration),)
        except ValueError as error:
            raise ComputerBoundaryError("invalid_input_arguments") from error
    if command in ("move_relative", "key_mouse"):
        expected = {"dx", "dy"} if command == "move_relative" else {"dx", "dy", "keys", "duration_ms"}
        optional = {"button", "x", "y"} if command == "key_mouse" else set()
        if not expected <= set(arguments) or set(arguments) - expected - optional:
            raise ComputerBoundaryError("invalid_input_arguments")
        try:
            move = mouse_move_relative(arguments["dx"], arguments["dy"])
            if command == "move_relative":
                return (plan_batch((move,)),)
            key_steps = () if arguments["keys"] == [] else _key_batch(arguments["keys"]).steps
            duration = arguments["duration_ms"]
            size = len(key_steps) // 2
            initial = key_steps[:size]
            releases = key_steps[size:]
            if "button" in arguments:
                if not {"x", "y"} <= set(arguments) or arguments["button"] not in ("left", "right", "middle"):
                    raise ValueError("invalid mouse hold")
                initial = (mouse_move(*_point_to_screen(geometry, arguments["x"], arguments["y"], coordinate_space), virtual_desktop()),
                           *initial, mouse_button(arguments["button"], down=True))
                releases = (mouse_button(arguments["button"], down=False), *releases)
            elif {"x", "y"} & set(arguments) or not key_steps:
                raise ValueError("mouse coordinates require button")
            return (plan_timed(((0, (*initial, move)), (duration, releases)), duration),)
        except ValueError as error:
            raise ComputerBoundaryError("invalid_input_arguments") from error
    if command == "mouse_hold":
        if (not {"x", "y", "button", "duration_ms"} <= set(arguments)
                or set(arguments) - {"x", "y", "button", "duration_ms", "keys"}
                or arguments["button"] not in ("left", "right", "middle")):
            raise ComputerBoundaryError("invalid_input_arguments")
        try:
            keys = _key_batch(arguments["keys"]).steps if "keys" in arguments else ()
            size = len(keys) // 2
            initial = (mouse_move(*_point_to_screen(geometry, arguments["x"], arguments["y"], coordinate_space), virtual_desktop()),
                       *keys[:size], mouse_button(arguments["button"], down=True))
            releases = (mouse_button(arguments["button"], down=False), *keys[size:])
            return (plan_timed(((0, initial), (arguments["duration_ms"], releases)), arguments["duration_ms"]),)
        except ValueError as error:
            raise ComputerBoundaryError("invalid_input_arguments") from error
    expected = ({"x", "y", "button"} if command in ("click", "double_click") else
                {"x", "y", "delta"} if command == "scroll" else
                {"from_x", "from_y", "to_x", "to_y", "button"})
    optional = {"keys", "duration_ms"} if command == "drag" else {"axis"} if command == "scroll" else {"count"} if command == "click" else set()
    if (not expected <= set(arguments) or set(arguments) - expected - optional or
            any(type(arguments[name]) is not int for name in
                (("x", "y") if command != "drag" else
                 ("from_x", "from_y", "to_x", "to_y")))):
        raise ComputerBoundaryError("invalid_input_arguments")
    if command == "scroll" and arguments.get("axis", "vertical") not in ("vertical", "horizontal"):
        raise ComputerBoundaryError("invalid_input_arguments")
    if ((command in ("click", "double_click", "drag") and
            arguments["button"] not in ("left", "right", "middle")) or
            (command == "scroll" and (type(arguments["delta"]) is not int or
                                      not arguments["delta"] or
                                      abs(arguments["delta"]) > 1200))):
        raise ComputerBoundaryError("invalid_input_arguments")
    try:
        desktop = virtual_desktop()
        if command == "drag":
            duration = arguments.get("duration_ms", 0)
            if type(duration) is not int or not 0 <= duration <= 2000:
                raise ComputerBoundaryError("invalid_input_arguments")
            key_steps = _key_batch(arguments["keys"]).steps if "keys" in arguments else ()
            size = len(key_steps) // 2
            start = _point_to_screen(geometry, arguments["from_x"], arguments["from_y"], coordinate_space)
            end = _point_to_screen(geometry, arguments["to_x"], arguments["to_y"], coordinate_space)
            if start == end:
                raise ValueError("drag endpoints are equal")
            segments = min(12, max(2, max(abs(end[0] - start[0]),
                                           abs(end[1] - start[1])) // 24))
            if duration:
                segments = min(segments, duration)
            points = [(round(start[0] + (end[0] - start[0]) * i / segments),
                       round(start[1] + (end[1] - start[1]) * i / segments))
                      for i in range(1, segments + 1)]
            releases = (mouse_button(arguments["button"], down=False), *key_steps[size:])
            initial = (mouse_move(*start, desktop), *key_steps[:size],
                       mouse_button(arguments["button"], down=True))
            if duration:
                timed = [(0, initial)]
                for index, (x, y) in enumerate(points, 1):
                    timed.append((round(duration * index / segments),
                                  (mouse_move(x, y, desktop), *(releases if index == segments else ()))))
                return (plan_timed(timed, duration),)
            steps = (mouse_move(*start, desktop), *key_steps[:size],
                     mouse_button(arguments["button"], down=True),
                     *(mouse_move(x, y, desktop) for x, y in points),
                     *releases)
        else:
            x, y = _point_to_screen(geometry, arguments["x"], arguments["y"], coordinate_space)
            move = mouse_move(x, y, desktop)
            if command in ("click", "double_click"):
                press = mouse_button(arguments["button"], down=True)
                release = mouse_button(arguments["button"], down=False)
                steps = ((move, press, release) if command == "click" else
                         (move, press, release,
                          mouse_button(arguments["button"], down=True),
                          mouse_button(arguments["button"], down=False)))
                if command == "click" and "count" in arguments:
                    count = arguments["count"]
                    if type(count) is not int or not 1 <= count <= 3:
                        raise ComputerBoundaryError("invalid_input_arguments")
                    steps = (move, *(event for _ in range(count) for event in (press, release)))
            else:
                steps = (move, mouse_wheel(arguments["delta"], horizontal=arguments.get("axis") == "horizontal"))
        return (plan_batch(steps),)
    except ValueError as error:
        raise ComputerBoundaryError("input_point_outside_client") from error


def _indicator_paths(batches, geometry):
    # The HUD's existing decoder deliberately accepts absolute paths only.
    # Raw deltas cannot predict a physical endpoint; reserve the target client
    # instead, so its Stop surface is never put in the controlled client.
    absolute_batches = []
    relative = False
    for batch in batches:
        steps = tuple(step for step in batch.steps if not (
            step.raw.type == 0 and step.raw.data.mi.dwFlags == 1))
        relative = relative or len(steps) != len(batch.steps)
        if steps:
            absolute_batches.append(plan_batch(steps))
    paths = mouse_path_rects(absolute_batches)
    if relative:
        x, y = geometry.client_origin
        paths += ((x, y, x + geometry.client_size[0], y + geometry.client_size[1]),)
    return paths


def _click_point_from_region(arguments: dict, observed: dict) -> tuple[int, int]:
    """Map a box in the original MCP image to physical client pixels."""
    if (type(arguments) is not dict or set(arguments) != {"box", "button"} or
            arguments["button"] not in ("left", "right") or
            type(arguments["box"]) is not list or len(arguments["box"]) != 4 or
            any(type(value) is not int for value in arguments["box"])):
        raise ComputerBoundaryError("invalid_input_region")
    left, top, right, bottom = arguments["box"]
    bounds = observed.get("source_bounds")
    width = observed.get("image_width")
    height = observed.get("image_height")
    geometry = observed["geometry"]
    if (bounds is None or type(width) is not int or type(height) is not int or
            bounds.width != width or bounds.height != height):
        raise ComputerBoundaryError("observation_image_unavailable")
    if not (0 <= left < right <= width and 0 <= top < bottom <= height):
        raise ComputerBoundaryError("input_region_outside_capture")
    screen_left, screen_top = bounds.left + left, bounds.top + top
    screen_right, screen_bottom = bounds.left + right, bounds.top + bottom
    origin_x, origin_y = geometry.client_origin
    client_width, client_height = geometry.client_size
    if not (origin_x <= screen_left < screen_right <= origin_x + client_width and
            origin_y <= screen_top < screen_bottom <= origin_y + client_height):
        raise ComputerBoundaryError("input_region_outside_client")
    # Half-open bounds: the chosen pixel is always inside the proposed region.
    return ((screen_left + screen_right - 1) // 2 - origin_x,
            (screen_top + screen_bottom - 1) // 2 - origin_y)


class ComputerRuntime:
    OBSERVATION_TTL_SECONDS = 60
    MAX_BMP_BYTES = 54 + 3840 * 2160 * 4
    MAX_WINDOW_PIXELS = 3840 * 2160
    MAX_SEQUENCE_PIXELS = 1920 * 1080

    def __init__(self, store: StateStore, resolve_call: Resolver,
                 *, jev_client_factory: Callable[[], JevClient] | None = None,
                 capture_session_factory=None, high_client_factory=None, owned_window_binder=None):
        if not callable(resolve_call):
            raise TypeError("trusted resolver required")
        self.store = store
        self.resolve_call = resolve_call
        self.jev_client_factory = jev_client_factory
        self._owners: dict[str, str] = {}
        self._observations: dict[str, dict] = {}
        self._stops: dict[str, threading.Event] = {}
        self._host_calls: dict[str, int] = {}
        self._host_gate = threading.RLock()  # Host Stop cannot share ledger waits.
        self._action_targets: dict[str, WindowIdentity] = {}
        self._gate = threading.RLock()
        self._capture_cache = ComputerCaptureCache(capture_session_factory) if capture_session_factory else None
        self._high = ComputerHighConnection(high_client_factory) if high_client_factory is not None else None
        self._owned_window_binder = owned_window_binder
        self._indicators = {}
        self._task_hints = {}

    def _acquire_indicator(self, grant, hint, on_stop, *, paths=(), prepare=False, factory=None):
        hint = self._task_hints.get(grant.task_id, hint)
        key = (grant.task_id, grant.identity)
        with self._gate:
            for old_key in list(self._indicators):
                if old_key[0] == grant.task_id and old_key != key:
                    self._indicators.pop(old_key).close()
            indicator = self._indicators.get(key)
            if indicator is not None and (indicator._closed.is_set() or indicator.stop_requested.is_set() or indicator.error):
                indicator.close()
                self._indicators.pop(key)
                indicator = None
            if indicator is None:
                def task_stop():
                    with self._host_gate:
                        for action, event in tuple(self._stops.items()):
                            if action.startswith(grant.task_id + ":computer:") and self._action_targets.get(action) == grant.identity:
                                event.set()
                    active_stop = getattr(indicator, "_active_stop", None)
                    if active_stop is not None:
                        active_stop()
                        return
                    _, resource = self._owner(grant)
                    self.store.pause_computer_target(grant.task_id, resource)
                    self._stop_idle_indicators(grant.task_id, grant.identity)
                indicator = (factory or ForegroundIndicator)(grant.identity, hint[:80], task_stop,
                    avoid_screen_rects=paths, prepare=prepare, stop_probe=self.store.write_stopped,
                    persistent=True)
                indicator.start()
                self._indicators[key] = indicator
            # Only an active stage owns this callback. Idle Stop persists the
            # task pause through the callback created above, without old leases.
            indicator._active_stop = on_stop
            indicator.keep_alive(hint)
            indicator.reserve_mouse_paths(paths)
            return indicator

    def _finish_indicator(self, indicator, *, stopped=False, released=True):
        if indicator is None:
            return
        indicator._active_stop = None
        indicator._input_released = bool(released)
        if not released or stopped or indicator.stop_requested.is_set() or self.store.write_stopped():
            indicator.set_stage("stopped" if released else "release_unconfirmed",
                checkpoint="写入已停止" if released else "输入释放尚未确认",
                input_release="released" if released else "unknown")
            indicator.linger()
        else:
            indicator.set_stage("wait", checkpoint="等待下一步；键鼠已释放" if released else "等待确认输入释放")

    def _stop_idle_indicators(self, task, identity=None):
        with self._gate:
            indicators = [indicator for (owner, target), indicator in self._indicators.items()
                          if owner == task and (identity is None or target == identity)
                          and getattr(indicator, "_active_stop", None) is None]
        for indicator in indicators:
            self._finish_indicator(indicator, stopped=True,
                released=getattr(indicator, "_input_released", False))

    def _close_indicators(self, task=None):
        with self._gate:
            keys = [key for key in self._indicators if task is None or key[0] == task]
            indicators = [self._indicators.pop(key) for key in keys]
        for indicator in indicators:
            indicator.close()

    def _capture(self, grant, *, preflight, stopped):
        if self._capture_cache is None:
            return capture_window(grant.identity, preflight=preflight, stopped=stopped)
        return self._capture_cache.capture(grant, preflight=preflight, stopped=stopped, fallback=capture_window)

    def close_capture_sessions(self):
        self._close_indicators()
        if self._capture_cache is not None:
            self._capture_cache.close()
        if self._high is not None:
            self._high.close()

    def bind_selected_window(self, request, current):
        from .computer_high_runtime import bind_selected_window
        try:
            return bind_selected_window(self, request, current)
        except HighHelperError as error:
            raise WindowSelectionError(error.code) from error

    def _task_owner(self, task):
        with self._gate:
            owner = self._owners.get(task)
            owner = (self.store.register_owner(task) if owner is None else
                     self.store.renew_or_replace_owner(task, owner))
            self._owners[task] = owner
            return owner

    def _authorized(self, tool: str, payload: dict, target: dict | None = None,
                    capability: str | None = None, *,
                    trusted_task: str | None = None) -> ComputerAuthorization:
        try:
            grant = self.resolve_call(tool, payload)
        except (ComputerBoundaryError, ControlError, NativeInputError, WindowSelectionError):
            raise
        except Exception as error:
            raise ComputerBoundaryError("trusted_origin_unavailable") from error
        if (not isinstance(grant, ComputerAuthorization) or
                type(grant.task_id) is not str or not grant.task_id or
                not isinstance(grant.identity, WindowIdentity) or
                type(grant.capture_allowed) is not bool or
                type(grant.input_allowed) is not bool):
            raise ComputerBoundaryError("trusted_origin_unavailable")
        if trusted_task is not None and grant.task_id != trusted_task:
            raise ComputerBoundaryError("ticket_task_mismatch")
        if any(scope is not None and (type(scope) is not str or not 1 <= len(scope) <= 256)
               for scope in (grant.target_scope, grant.capture_scope, grant.input_scope)):
            raise ComputerBoundaryError("invalid_authorization_scope")
        if (grant.shared_resource is not None and
                (type(grant.shared_resource) is not str or
                 not (grant.shared_resource.startswith("web-profile:") or
                      grant.shared_resource.startswith("web-session:")))):
            raise ComputerBoundaryError("invalid_shared_resource")
        if grant.expires_at <= self.store.clock():
            raise ComputerBoundaryError("trusted_call_expired")
        if target is not None and (type(target) is not dict or
                                   target != asdict(grant.identity)):
            raise ComputerBoundaryError("target_not_approved")
        if capability == "capture" and not grant.capture_allowed:
            raise ComputerBoundaryError("capture_not_approved")
        if capability == "input" and not grant.input_allowed:
            raise ComputerBoundaryError("input_not_approved")
        return grant

    @staticmethod
    def _resource(identity: WindowIdentity) -> str:
        created = process_creation_filetime(identity.pid,
                                            expected_iso=identity.process_created)
        return physical_window_resource(identity.pid, created, identity.hwnd)

    @staticmethod
    def _key(task: str, action_id: str) -> str:
        if type(action_id) is not str or not 1 <= len(action_id) <= 128:
            raise ComputerBoundaryError("invalid_action_id")
        return task + ":computer:" + action_id

    def _owner(self, grant: ComputerAuthorization) -> tuple[str, str]:
        resource = self._resource(grant.identity)
        with self._gate:
            owner = self._task_owner(grant.task_id)
            self.store.register_resource(resource, required_scope=grant.target_scope)
            self.store.bind_owned_resource(owner, resource)
            if grant.shared_resource is not None:
                self.store.register_resource(grant.shared_resource,
                                             required_scope=grant.target_scope)
        return owner, resource

    def _recover_shared_front_for_new_target(self, grant: ComputerAuthorization,
                                             resource: str) -> None:
        """Free only an abandoned shared input lane, preserving old target state."""
        recover_shared_foreground_for_new_target(
            self.store, resource, lambda: assert_window(grant.identity))

    @staticmethod
    def _generation(geometry) -> str:
        return json.dumps(asdict(geometry), sort_keys=True, separators=(",", ":"))

    @staticmethod
    def _image(result) -> dict:
        return {"format": "bmp", "base64": base64.b64encode(result.bmp).decode("ascii"),
                "width": result.width, "height": result.height,
                "source_bounds": asdict(result.source_bounds), "backend": result.source,
                "source_bounds_space": "physical_screen_pixels",
                "fallback_reason": result.fallback_reason,
                "content_verified": False, "elapsed_ms": result.elapsed_ms}

    def authorize_visual_return(self, tool: str, payload: dict,
                                trusted_task: str) -> None:
        """Last local gate before captured pixels become an MCP ImageContent."""
        if tool not in ("flower_computer_observe", "flower_computer_activate",
                        "flower_computer_input"):
            raise ComputerBoundaryError("invalid_visual_return")
        grant = self._authorized(tool, payload, payload.get("target"),
                                 "capture" if tool == "flower_computer_observe"
                                 else "input", trusted_task=trusted_task)
        if not grant.capture_allowed:
            raise ComputerBoundaryError("capture_not_approved")
        assert_window(grant.identity)
        resource = self._resource(grant.identity)
        read_only = (tool == "flower_computer_observe" or
                     tool == "flower_computer_input" and payload.get("command") == "wait")
        if read_only:
            visual_scopes = (grant.capture_scope,)
        elif tool == "flower_computer_activate":
            visual_scopes = (grant.input_scope, grant.capture_scope)
        else:
            visual_scopes = (grant.input_scope,)
        with self.store.read_transaction() as db:
            task = self.store._task(db, trusted_task)
            if task["paused"]:
                raise ControlError("user_paused")
            for scope in (grant.target_scope, *visual_scopes):
                self.store._require_scope(db, trusted_task, scope)
            # A completed click may close its dialog and release foreground.
            # Keep fresh read-only observation available on the selected parent;
            # the foreground input resource still blocks further input.
            checked_resources = ((resource,) if read_only
                                 else (resource, FOREGROUND_INPUT_RESOURCE))
            if grant.shared_resource is not None:
                checked_resources += (grant.shared_resource,)
            for item in checked_resources:
                row = db.execute("SELECT paused,quarantined FROM resources WHERE id=?",
                                 (item,)).fetchone()
                if row and (row["paused"] or row["quarantined"] and not read_only):
                    raise ControlError("resource_paused_or_quarantined")

    def observe(self, target: dict, action_id: str, goal_hint: str | None = None,
                *, trusted_task: str | None = None) -> dict:
        payload = {"target": target, "action_id": action_id}
        if goal_hint is not None:
            payload["goal_hint"] = goal_hint
        grant = self._authorized("flower_computer_observe", payload, target, "capture",
                                 trusted_task=trusted_task)
        if goal_hint:
            self._task_hints[grant.task_id] = goal_hint[:80]
        return self._measure_call(grant, action_id, None,
                                  lambda: self._observe_impl(grant, action_id, payload, goal_hint))

    def _observe_impl(self, grant, action_id, payload, goal_hint):
        owner, resource = self._owner(grant)
        uia = None
        visual_reason = None
        if goal_hint is not None:
            from .app_control import AppBoundaryError
            # UIA is an optional semantic hint for an independently approved
            # screenshot. Authority/identity/Stop failures must still propagate.
            try:
                with self._gate:
                    host_stop = self._stops.get(self._key(grant.task_id, action_id))
                uia = (self._uia_observe(grant) if host_stop is None else
                       self._uia_observe(grant, host_stop=host_stop))
            except AppBoundaryError as error:
                if error.code not in {"native_preflight_timeout", "native_preflight_failed",
                        "uia_timeout", "uia_initialization_failed", "uia_read_failed",
                        "uia_provider_identity_unavailable",
                        "uia_access_denied", "uia_element_unavailable", "native_call_timeout",
                        "native_worker_failed", "native_exit_timeout", "app_native_worker_missing",
                        "native_response_invalid", "native_protocol_invalid", "app_worker_failed",
                        "worker_response_unavailable", "worker_result_invalid",
                        "worker_call_failed_or_timed_out", "per_monitor_dpi_awareness_required"}:
                    raise
                visual_reason = error.code
        outcome = self._execute(owner, resource, grant, action_id, "observe", payload,
                                candidate_uia=uia,
                                shared_revision=(uia.get("_shared_revision") if uia else None))
        result = outcome.get("result")
        if visual_reason is not None and isinstance(result, dict) and "image" in result:
            result["target_route"] = {"source": "visual", "reason": visual_reason,
                                      "uia_available": False}
        if goal_hint is not None and isinstance(result, dict) and result.get("candidates"):
            rows = result["candidates"]
            candidates = tuple(TargetCandidate(row["candidate_id"], "computer", "uia", "click",
                                row["role"], row["label"], {"candidate_id": row["candidate_id"]})
                               for row in rows[:32])
            exact = [c.target_id for c in candidates if c.label.strip() == goal_hint.strip()]
            request = TargetRequest(goal_hint, result["observation_id"], result["candidate_generation"],
                                    candidates, self.store.clock() + 10,
                                    complete=(len(rows) <= 32 and
                                        result.get("candidate_coverage", {}).get("complete", False)),
                                    candidate_scope="bounded",
                                    task_stage="当前窗口观察完成；选择随后点击的 UIA 控件",
                                    fallback_id=exact[0] if len(exact) == 1 else None)
            key = self._key(grant.task_id, action_id)
            def selection_stopped():
                with self._gate:
                    event = self._stops.get(key)
                return event is not None and event.is_set()
            def permitted_sync():
                if (selection_stopped() or
                        self.store.task_write_stopped(grant.task_id, observation=result["observation_id"])):
                    return False
                resources = (resource,) + ((grant.shared_resource,) if grant.shared_resource else ())
                allowed = grant.expires_at > self.store.clock() and selection_permitted(
                    self.store, grant.task_id, resources, (grant.target_scope, grant.capture_scope),
                    result["observation_id"])
                return allowed and not selection_stopped()
            def fresh_sync():
                if selection_stopped():
                    return False
                with self._gate:
                    snapshot = self._observations.get(result["observation_id"])
                return bool(snapshot and win32gui.IsWindow(grant.identity.hwnd)
                            and self._shared_observation_current(grant, snapshot) and not selection_stopped())
            async def permitted():
                if self.store.write_stopped():
                    return False
                return await asyncio.to_thread(permitted_sync)
            async def fresh():
                return await asyncio.to_thread(fresh_sync)
            with yielded_foreground_wait(self.store, owner, reason="model", channel="computer",
                                         action_id=self._key(grant.task_id, action_id)):
                selected = asyncio.run(select_target(self.store, grant.task_id, request,
                    client_factory=self.jev_client_factory, permitted=permitted, fresh=fresh,
                    action_id=self._key(grant.task_id, action_id)))
            if selection_stopped():
                handle = result["observation_id"]
                with self._gate:
                    snapshot = self._observations.get(handle)
                    if snapshot is not None:
                        snapshot["expires"] = 0
                        snapshot["candidates"] = []
                with self.store.transaction() as db:
                    db.execute("UPDATE observations SET expires=0 WHERE id=? AND task=? AND resource=?",
                               (handle, grant.task_id, resource))
                result.update(state="cancelled", candidates=[], requires_new_observation=True,
                              selection={"reason": "input_stopped", "elapsed_ms": selected.elapsed_ms,
                                         "candidate_id": None})
                result.pop("candidate_generation", None)
            else:
                result["selection"] = {"reason": selected.reason, "elapsed_ms": selected.elapsed_ms,
                                       "candidate_id": selected.target_id}
        return outcome

    def _shared_observation_current(self, grant, observed):
        if grant.shared_resource is None:
            return True
        with self.store.read_transaction() as db:
            row = db.execute("SELECT revision FROM resources WHERE id=?",
                             (grant.shared_resource,)).fetchone()
        return bool(row and row[0] == observed.get("shared_revision"))

    def _uia_observe(self, grant, *, host_stop=None):
        from .app_control import AppRuntime, AppAuthorization, AppBoundaryError
        scope = grant.capture_scope or grant.target_scope
        if scope is None:
            scope = "computer-uia:" + self._resource(grant.identity)
            self.store.record_confirmed_grant(grant.task_id, scope, "computer-capture:" + uuid.uuid4().hex,
                                              lifetime=30)
        created = process_creation_filetime(grant.identity.pid, expected_iso=grant.identity.process_created)
        app_grant = AppAuthorization(grant.task_id, grant.identity.pid, grant.identity.hwnd,
                                     created, scope, grant.expires_at, grant.target_scope,
                                     grant.shared_resource)
        bridge = None
        if self._high is not None:
            from .app_high import AppHighBridge
            bridge = AppHighBridge(self.store, grant.task_id, client=self._high.factory())
            bridge.adopt_identity(grant.identity.hwnd, grant.identity.pid, created, grant.identity.window_nonce)
        class BoundUIARuntime(AppRuntime):
            def _host_stopped(self, key):
                # This one UIA read belongs to the original Computer observe.
                # App's native preflight/High stop callback consumes this same
                # exact Event; no cancellation of sibling chat actions.
                return (host_stop is not None and host_stop.is_set()) or super()._host_stopped(key)

        runtime = BoundUIARuntime(self.store, lambda tool, payload: app_grant, high_bridge=bridge)
        try:
            outcome = runtime._observe(app_grant, content=True, action_id="candidates-" + uuid.uuid4().hex,
                                       limits={"max_nodes": 192, "max_depth": 8})
        finally:
            if bridge is not None:
                bridge.close()
        result = outcome.get("result")
        if isinstance(result, dict) and result.get("state") != "observed":
            raise AppBoundaryError(result.get("reason") or "uia_observation_unavailable")
        if not isinstance(result, dict):
            raise AppBoundaryError(outcome.get("error") or "uia_observation_unavailable")
        if isinstance(result, dict) and grant.shared_resource is not None:
            snapshot = runtime._observations.get(outcome.get("observation_id"))
            if not snapshot or snapshot.get("shared_revision") is None:
                return None
            result = {**result, "_shared_revision": snapshot["shared_revision"]}
        return result

    def activate(self, target: dict, restore_minimized: bool, action_id: str,
                 *, trusted_task: str | None = None) -> dict:
        payload = {"target": target, "restore_minimized": restore_minimized,
                   "action_id": action_id}
        grant = self._authorized("flower_computer_activate", payload, target, "input",
                                 trusted_task=trusted_task)
        if not grant.capture_allowed:
            raise ComputerBoundaryError("capture_not_approved")
        if type(restore_minimized) is not bool:
            raise ComputerBoundaryError("invalid_activation_request")
        owner, resource = self._owner(grant)
        self._recover_shared_front_for_new_target(grant, resource)
        return self._measure_call(grant, action_id, None, lambda:
            self._execute(owner, resource, grant, action_id, "activate", payload,
                          restore_minimized=restore_minimized))

    def input(self, target: dict, observation_id: str, command: str,
              arguments: dict, action_id: str,
              *, trusted_task: str | None = None) -> dict:
        payload = {"target": target, "observation_id": observation_id,
                   "command": command, "arguments": arguments, "action_id": action_id}
        grant = self._authorized("flower_computer_input", payload, target, "input",
                                 trusted_task=trusted_task)
        return self._measure_call(grant, action_id, observation_id, lambda:
            self._input_impl(grant, target, observation_id, command, arguments, action_id,
                             payload, trusted_task))

    def _input_impl(self, grant, target, observation_id, command, arguments, action_id,
                    payload, trusted_task):
        if not grant.capture_allowed:
            raise ComputerBoundaryError("capture_not_approved")
        if type(arguments) is not dict or command not in (
                "text", "click", "click_region", "double_click", "key", "scroll",
                "drag", "move_relative", "key_mouse", "mouse_hold", "move", "hover", "batch",
                "sequence", "click_candidate", "wait", "choose_region",
                "window_move", "window_resize"):
            raise ComputerBoundaryError("invalid_input_command")
        # Preserve input validation before looking up an observation. Text and
        # key steps have no geometry dependency.
        early_batches = (_plan_input(command, arguments, None)
                         if command in ("text", "key") else None)
        with self._gate:
            observed = self._observations.get(observation_id)
        if (observed is None or observed["task"] != grant.task_id or
                observed["identity"] != grant.identity or
                observed["expires"] <= self.store.clock()):
            raise ComputerBoundaryError("observation_unavailable")
        if observed.get("shared_resource") != grant.shared_resource:
            raise ComputerBoundaryError("observation_unavailable")
        geometry = observed["geometry"]
        if command in {"window_move", "window_resize"}:
            try:
                plan = window_layout_plan(command, arguments, geometry, observed.get("layout_environment"),
                    task=grant.task_id, action=self._key(grant.task_id, action_id),
                    observation=observation_id, generation=observed["generation"])
            except ValueError as error:
                raise ComputerBoundaryError(str(error)) from error
            owner, resource = self._owner(grant)
            self._recover_shared_front_for_new_target(grant, resource)
            return self._execute(owner, resource, grant, action_id, "input", payload,
                observation=observation_id, generation=observed["generation"], geometry=geometry,
                shared_revision=observed.get("shared_revision"), layout_plan=plan)
        region_selection = None
        region_version = None
        if command == "choose_region":
            if (set(arguments) != {"goal_hint", "regions"} or type(arguments["goal_hint"]) is not str
                    or type(arguments["regions"]) is not list or not 2 <= len(arguments["regions"]) <= 8):
                raise ComputerBoundaryError("invalid_region_candidates")
            candidates = []
            for index, row in enumerate(arguments["regions"]):
                if type(row) is not dict or set(row) != {"box", "label"} or type(row["label"]) is not str:
                    raise ComputerBoundaryError("invalid_region_candidates")
                _click_point_from_region({"box": row["box"], "button": "left"}, observed)
                candidates.append(TargetCandidate(str(index), "computer", "host_region", "click",
                                                  "region", row["label"], {"box": row["box"], "button": "left"}))
            request = TargetRequest(arguments["goal_hint"], observation_id, observed["generation"],
                                    tuple(candidates), observed["expires"], candidate_scope="bounded",
                                    task_stage="当前图像已绑定；选择一个区域并执行点击")
            def permitted_sync():
                try:
                    if self.store.task_write_stopped(grant.task_id, observation=observation_id):
                        return False
                    with self._gate:
                        pending_stop = self._stops.get(self._key(grant.task_id, action_id))
                    if pending_stop is not None and pending_stop.is_set():
                        return False
                    self._authorized("flower_computer_input", payload, target, "input", trusted_task=trusted_task)
                    resources = (self._resource(grant.identity),) + (
                        (grant.shared_resource,) if grant.shared_resource else ())
                    return selection_permitted(self.store, grant.task_id, resources,
                        (grant.target_scope, grant.input_scope), observation_id)
                except (ComputerBoundaryError, ControlError):
                    return False
            def fresh_sync():
                return (observed["expires"] > self.store.clock()
                        and window_geometry(grant.identity) == geometry
                        and self._shared_observation_current(grant, observed))
            async def permitted():
                return await asyncio.to_thread(permitted_sync)
            async def fresh():
                return await asyncio.to_thread(fresh_sync)
            # Selection is bound to the requested action before an external
            # Choice; no foreground/input lock is acquired while choosing.
            if not asyncio.run(permitted()):
                return {"state": "needs_observation", "dispatched": False,
                        "selection": {"reason": "not_permitted", "source": "host_region"}}
            if not asyncio.run(fresh()):
                return {"state": "needs_observation", "dispatched": False,
                        "selection": {"reason": "stale", "source": "host_region"}}
            owner, resource = self._owner(grant)
            key = self._key(grant.task_id, action_id)
            queued, _ = self._queue_action(owner, resource, grant, action_id, "input", payload,
                                            observation_id, observed["generation"])
            if queued["state"] != "queued":
                return {"receipt": self.store.status(owner, key), "replayed": True}
            try:
                with yielded_foreground_wait(self.store, owner, reason="model", channel="computer", action_id=key):
                    choice = asyncio.run(select_target(self.store, grant.task_id, request,
                        client_factory=self.jev_client_factory, permitted=permitted, fresh=fresh,
                        action_id=key))
            except BaseException:
                self.store.cancel(owner, key)
                raise
            region_selection = {"reason": choice.reason, "elapsed_ms": choice.elapsed_ms,
                                "candidate_id": choice.target_id, "source": "host_region"}
            if choice.candidate is None:
                self.store.cancel(owner, key)
                return {"state": "needs_observation", "dispatched": False, "selection": region_selection,
                        "receipt": self.store.status(owner, key)}
            command = "click_region"
            arguments = choice.candidate.local_target()
            bounds = observed["source_bounds"]
            screen_box = tuple(value + (bounds.left if index % 2 == 0 else bounds.top)
                               for index, value in enumerate(arguments["box"]))
            baseline = replace(observed["capture_descriptor"],
                               bmp=zlib.decompress(observed["capture_compressed"]))
            region_version = (screen_box, _region_digest(baseline, screen_box))
        if command == "wait":
            if (set(arguments) != {"condition", "timeout_ms"} or
                    arguments["condition"] not in {"image_changed", "image_unchanged", "window_closed", "new_window"} or
                    type(arguments["timeout_ms"]) is not int or not 1 <= arguments["timeout_ms"] <= 5000):
                raise ComputerBoundaryError("invalid_wait_request")
            owner, resource = self._owner(grant)
            return self._execute(owner, resource, grant, action_id, "wait", payload,
                                 observation=observation_id, generation=observed["generation"],
                                 wait_observation=observed)
        sequence = None
        resolved_click = None
        semantic_candidate = None
        if command == "sequence":
            if (type(arguments) is not dict or set(arguments) != {"steps"} or
                    type(arguments["steps"]) is not list or
                    not 2 <= len(arguments["steps"]) <= 3):
                raise ComputerBoundaryError("invalid_input_sequence")
            if geometry.window.width * geometry.window.height > self.MAX_SEQUENCE_PIXELS:
                raise ComputerBoundaryError("sequence_window_too_large")
            planned = []
            for index, step in enumerate(arguments["steps"]):
                if (type(step) is not dict or
                        set(step) != {"command", "arguments", "expect"} or
                        type(step["command"]) is not str or
                        step["expect"] not in ("capture_available", "image_changed",
                                               "image_unchanged")):
                    raise ComputerBoundaryError("invalid_input_sequence")
                batches = _plan_input(step["command"], step["arguments"], geometry)
                if len(batches) != 1 or isinstance(batches[0], TimedInputPlan):
                    raise ComputerBoundaryError("sequence_step_too_long")
                planned.append((step["command"], batches[0], step["expect"]))
            sequence = tuple(planned)
            batches = None
        else:
            if command == "click_candidate":
                if set(arguments) != {"candidate_id"}:
                    raise ComputerBoundaryError("invalid_candidate_click")
                semantic_candidate = next((row for row in observed.get("candidates", [])
                                           if row["candidate_id"] == arguments["candidate_id"]), None)
                if semantic_candidate is None:
                    raise ComputerBoundaryError("candidate_unavailable")
                point = semantic_candidate["point_client"]
                batches = _plan_input("click", {"x": point[0], "y": point[1], "button": "left"}, geometry)
            elif command == "click_region":
                resolved_click = _click_point_from_region(arguments, observed)
                click_arguments = {"x": resolved_click[0], "y": resolved_click[1],
                                   "button": arguments["button"]}
                batches = _plan_input("click", click_arguments, geometry)
            else:
                batches = (early_batches if early_batches is not None else
                           _plan_input(command, arguments, geometry))
        owner, resource = self._owner(grant)
        self._recover_shared_front_for_new_target(grant, resource)
        outcome = self._execute(owner, resource, grant, action_id, "input", payload,
                                observation=observation_id,
                                generation=observed["generation"],
                                batches=batches, geometry=geometry, sequence=sequence,
                                shared_revision=observed.get("shared_revision"),
                                semantic_candidate=semantic_candidate, region_version=region_version)
        if resolved_click is not None:
            outcome["resolved_click_region"] = {
                "observation_id": observation_id,
                "box_in_original_image": arguments["box"],
                "point_in_client": list(resolved_click),
                "coordinate_space": "physical_client_pixels"}
        if region_selection is not None:
            outcome["selection"] = region_selection
        return outcome

    def _measure_call(self, grant, action_id, observation_id, operation):
        """Measure this Computer call; no capture/receipt verifies its business goal."""
        started = time.monotonic()
        key = self._key(grant.task_id, action_id)
        usage = JevUsage(parent=current_context().get("usage"))
        outcome, error = None, None
        try:
            with jev_context(task=grant.task_id, action=key, channel="computer",
                             observation_id=observation_id, usage=usage):
                outcome = operation()
            if isinstance(outcome, dict) and "receipt" in outcome:
                # Early sequence/activation returns were assembled while the
                # mutex was held. Refresh only after dispatch and seal exit.
                with self._gate:
                    owner = self._owners.get(grant.task_id)
                if owner is not None:
                    outcome["receipt"] = self.store.status(owner, key)
            return outcome
        except BaseException as caught:
            error = caught
            raise
        finally:
            # Metrics are best effort. They must never replay input or replace
            # the existing control result if a logging/binding check fails.
            try:
                if not isinstance(outcome, dict) or not (outcome.get("replayed") or outcome.get("queued")):
                    with self.store.read_transaction() as db:
                        action = db.execute("SELECT state FROM actions WHERE id=? AND task=?",
                                            (key, grant.task_id)).fetchone()
                        decisions = db.execute("SELECT id FROM decisions WHERE chosen=? LIMIT 64", (key,)).fetchall()
                        selections = db.execute("SELECT details FROM control_events WHERE task=? AND action=? "
                                                "AND event='target_selection' ORDER BY seq DESC LIMIT 64",
                                                (grant.task_id, key)).fetchall()
                    if action is not None and action["state"] not in {"queued", "running"}:
                        selected_observation = observation_id
                        if selected_observation is None and selections:
                            selected_observation = json.loads(selections[0][0]).get("observation_id")
                        producer = BusinessResultProducer(self.store, task=grant.task_id,
                            action=key, channel="computer", observation_id=selected_observation,
                            started_at=started)
                        producer.usage = usage
                        for row in decisions:
                            producer.bind_decision(row[0])
                        for row in selections:
                            producer.bind_decision(json.loads(row[0])["decision_id"])
                        response = outcome if isinstance(outcome, dict) else {}
                        code = getattr(error, "code", None) or response.get("reason")
                        cancelled = (isinstance(error, asyncio.CancelledError) or code in {
                            "input_stopped", "capture_cancelled", "user_paused", "user_revoked"})
                        failure = ("cancelled" if cancelled else "outcome_unknown" if action["state"] == "outcome_uncertain"
                                   else "timeout" if code in {"capture_timeout", "trusted_call_expired"}
                                   else "stale" if code in {"observation_unavailable", "candidate_requires_new_observation",
                                                            "geometry_changed", "desktop_topology_changed"}
                                   else "other" if error is not None or code else "outcome_unknown")
                        result_kind = ("cancelled" if cancelled else "unverified" if action["state"] == "outcome_uncertain"
                                       else "failed" if error is not None or code else "unverified")
                        result_snapshot = response.get("result")
                        result_handle = (result_snapshot.get("observation_id")
                                         if isinstance(result_snapshot, dict) else None)
                        with self._gate:
                            result_observed = (self._observations.get(result_handle)
                                               if type(result_handle) is str else None)
                        if (result_observed is None or result_observed["task"] != grant.task_id or
                                result_observed["identity"] != grant.identity):
                            result_handle, result_observed = None, None
                        # Bind an actual stored fresh capture when present. It
                        # is evidence provenance, never a business verifier.
                        measured = producer.finish(outcome=result_kind, failure_class=failure,
                            result_observation_id=result_handle,
                            result_observed_at=(result_observed.get("observed_at")
                                                if result_observed is not None else None))
                        if isinstance(outcome, dict):
                            outcome["business_result"] = measured
            except Exception:
                print("computer_business_metrics_unavailable", file=sys.stderr, flush=True)
            finally:
                with self._host_gate:
                    if key not in self._host_calls:
                        self._stops.pop(key, None)

    def _queue_action(self, owner, resource, grant, action_id, command, payload,
                      observation, generation):
        key = self._key(grant.task_id, action_id)
        with self._gate:
            with self._host_gate:
                stop = self._stops.setdefault(key, threading.Event())
                if stop.is_set():
                    raise ComputerBoundaryError("input_stopped")
            previous = self._action_targets.get(key)
            if previous is not None and previous != grant.identity:
                raise ComputerBoundaryError("action_id_conflict")
            self._action_targets[key] = grant.identity
        fingerprint = hashlib.sha256(json.dumps([command, payload], sort_keys=True,
                                                ensure_ascii=False,
                                                separators=(",", ":")).encode()).hexdigest()
        resources = ((resource,) if command in {"observe", "wait"}
                     else (resource, FOREGROUND_INPUT_RESOURCE))
        if grant.shared_resource is not None:
            resources += (grant.shared_resource,)
        operation = payload.get("command", command)
        hints = {"text": "向授权窗口输入文本", "key": "向授权窗口发送组合键",
                 "activate": "切换到授权窗口", "observe": "观察授权窗口", "wait": "等待授权窗口状态",
                 "window_move": "移动授权窗口", "window_resize": "调整授权窗口大小",
                 "sequence": "执行授权窗口的有限输入步骤"}
        with self.store.read_transaction() as db:
            previous = db.execute("SELECT h.estimated_ms,c.details FROM actions a "
                "JOIN action_hints h ON h.action=a.id JOIN action_context c ON c.action=a.id "
                "WHERE a.id=? AND a.task=?", (key, grant.task_id)).fetchone()
        if previous is not None:
            # Replay must retain its original immutable scheduling contract;
            # later measurements belong to a new action, never this ID.
            options = {"estimated_ms": previous[0], "context": json.loads(previous[1])}
        else:
            cost = (measured_stage_cost(self.store, owner, channel="computer", operation=operation)
                    if command not in {"observe", "wait"} else StageCost())
            options = cost.enqueue_options({"channel": "computer", "operation": operation,
                "task_hint": hints.get(operation, "操作授权窗口的指定位置"),
                "foreground_needed": command not in {"observe", "wait"}
                    and operation not in {"window_move", "window_resize"}})
        queued = self.store.enqueue(owner, action_id=key, fingerprint=fingerprint,
            resources=resources, observation=observation, generation=generation,
            scope=grant.capture_scope if command in {"observe", "wait"} else grant.input_scope,
            phase=Phase.START if command == "activate" else Phase.CONTINUE,
            read_only=command in {"observe", "wait"},
            **options)
        return queued, resources

    def action_status(self, action_id: str, *, trusted_task: str | None = None,
                      result_report: dict | None = None) -> dict:
        if trusted_task is not None:
            task = trusted_task
            key = self._key(task, action_id)
            if self._high is not None:
                from .computer_high_runtime import recover_release_for_status
                recovery = recover_release_for_status(self, task, key)
            else:
                recovery = None
            receipt = self.store.diagnostic_action_for_task(task, key)
            with self._gate:
                owner = self._owners.get(task)
            if owner is not None:
                receipt = self.store.queue_status(owner, key)
            if recovery is not None:
                receipt = {**receipt, "release_recovery": recovery}
        else:
            payload = {"action_id": action_id}
            if result_report is not None:
                payload["result_report"] = result_report
            grant = self._authorized("flower_computer_action_status", payload)
            task = grant.task_id
            key = self._key(task, action_id)
            with self._gate:
                owner = self._owners.get(task)
                target = self._action_targets.get(key)
            receipt = (self.store.computer_sequence_status_for_task(
                task, key, self._resource(grant.identity))
                if owner is None or target != grant.identity else self.store.queue_status(owner, key))
        if result_report is None:
            return receipt
        try:
            report = {"state": "recorded", **self._report_host_result(task, key, result_report)}
        except ComputerBoundaryError as error:
            report = {"state": "rejected", "reason": error.code}
        except ValueError as error:
            known = {"host_visual_invalid_binding", "host_visual_invalid_outcome",
                     "host_visual_invalid_digest", "host_visual_action_not_completed",
                     "host_visual_observation_binding_mismatch", "host_visual_observation_time_mismatch",
                     "host_visual_observation_stale"}
            report = {"state": "rejected", "reason": str(error) if str(error) in known
                      else "host_visual_report_unavailable"}
        except Exception:
            print("computer_host_visual_report_unavailable", file=sys.stderr, flush=True)
            report = {"state": "rejected", "reason": "host_visual_report_unavailable"}
        return {**receipt, "host_visual_result": report}

    def _report_host_result(self, task: str, key: str, report: dict) -> dict:
        if type(report) is not dict or set(report) != {"result_observation_id", "outcome"}:
            raise ComputerBoundaryError("host_visual_invalid_report")
        handle, outcome = report["result_observation_id"], report["outcome"]
        if type(handle) is not str or not 1 <= len(handle) <= 256:
            raise ComputerBoundaryError("host_visual_invalid_binding")
        if type(outcome) is not str or outcome not in {"completed", "not_completed", "uncertain"}:
            raise ComputerBoundaryError("host_visual_invalid_outcome")
        with self._gate:
            cached = self._observations.get(handle)
            observed = dict(cached) if cached is not None else None
            target = self._action_targets.get(key)
        if observed is None or any(field not in observed for field in
                ("task", "identity", "generation", "expires", "observed_at", "image_digest")):
            raise ComputerBoundaryError("host_visual_observation_unavailable")
        if observed["task"] != task:
            raise ComputerBoundaryError("host_visual_observation_binding_mismatch")
        if observed["expires"] <= self.store.clock():
            raise ComputerBoundaryError("host_visual_observation_stale")
        with self.store.read_transaction() as db:
            original = db.execute("SELECT state,generation FROM actions WHERE id=? AND task=?",
                                  (key, task)).fetchone()
            if original is None or original["state"] not in {
                    "verified", "not_verified", "outcome_uncertain", "cancelled"}:
                raise ComputerBoundaryError("host_visual_action_not_completed")
            if original["generation"]:
                try:
                    identity = json.loads(original["generation"])["identity"]
                    if (type(identity) is not dict or set(identity) != {
                            "hwnd", "pid", "process_created", "window_nonce"}
                            or any(type(identity[field]) is not int or identity[field] <= 0
                                   for field in ("hwnd", "pid", "window_nonce"))
                            or type(identity["process_created"]) is not str or not identity["process_created"]):
                        raise ValueError("invalid persisted Computer identity")
                    target = WindowIdentity(**identity)
                except (TypeError, ValueError, KeyError):
                    raise ComputerBoundaryError("host_visual_original_identity_unavailable") from None
            if target is None:
                raise ComputerBoundaryError("host_visual_original_identity_unavailable")
            if observed["identity"] != target:
                raise ComputerBoundaryError("host_visual_observation_binding_mismatch")
            row = db.execute("SELECT task,generation FROM observations WHERE id=?", (handle,)).fetchone()
            if row is None or row["task"] != task or row["generation"] != observed["generation"]:
                raise ComputerBoundaryError("host_visual_observation_binding_mismatch")
            if observed.get("shared_resource") is not None:
                shared = db.execute("SELECT revision FROM resources WHERE id=?",
                                    (observed["shared_resource"],)).fetchone()
                if shared is None or shared[0] != observed.get("shared_revision"):
                    raise ComputerBoundaryError("host_visual_observation_stale")
        return report_host_visual_result(self.store, task=task, action=key,
            result_observation_id=handle, result_observed_at=observed["observed_at"],
            outcome=outcome, evidence_digest=observed["image_digest"])

    def cancel(self, action_id: str, *, trusted_task: str | None = None) -> dict:
        if trusted_task is not None:
            key = self._key(trusted_task, action_id)
            receipt = self.store.diagnostic_action_for_task(trusted_task, key, cancel=True)
            with self._gate:
                event = self._stops.get(key)
            if event is not None:
                event.set()
            self._stop_idle_indicators(trusted_task)
            return {"action_id": action_id, **receipt}
        grant = self._authorized("flower_computer_cancel", {"action_id": action_id},
                                 trusted_task=trusted_task)
        key = self._key(grant.task_id, action_id)
        with self._gate:
            owner = self._owners.get(grant.task_id)
            event = self._stops.get(key)
            target = self._action_targets.get(key)
        if owner is None or target != grant.identity:
            raise ComputerBoundaryError("action_not_found")
        receipt = self.store.cancel(owner, key)
        if event is not None:
            event.set()
        self._stop_idle_indicators(grant.task_id, grant.identity)
        return {"action_id": action_id, **receipt}

    def begin_host_call(self, task: str, action_id: str) -> str:
        """Register before starting a thread, closing the cancellation race."""
        key = self._key(task, action_id)
        with self._host_gate:
            self._stops.setdefault(key, threading.Event())
            self._host_calls[key] = self._host_calls.get(key, 0) + 1
        return key

    def end_host_call(self, key: str) -> None:
        with self._host_gate:
            count = self._host_calls.get(key, 0)
            if count <= 1:
                self._host_calls.pop(key, None)
                self._stops.pop(key, None)
            else:
                self._host_calls[key] = count - 1

    def request_host_stop(self, key: str) -> None:
        # This event is bound by the trusted adapter, never by model input.
        with self._host_gate:
            event = self._stops.get(key)
            if event is not None:
                event.set()

    def request_host_shutdown(self) -> None:
        with self._host_gate:
            events = list(self._stops.values())
        for event in events:
            event.set()
        self._close_indicators()

    def pause(self, mode: str | None = None,
              *, trusted_task: str | None = None) -> dict:
        payload = {} if mode is None else {"mode": mode}
        grant = self._authorized("flower_computer_pause", payload,
                                 trusted_task=trusted_task)
        if mode == "finish":
            self._close_indicators(grant.task_id)
            return {"state": "indicator_finished", "input_dispatched": False}
        if mode == "resume":
            assert_window(grant.identity)
            _, resource = self._owner(grant)
            snapshot = self.store.computer_resume_snapshot(grant.task_id, resource)
            if snapshot is None:
                return {"state": "already_active", "requires_new_observation": True}
            self._authorized("flower_computer_pause", payload, asdict(grant.identity),
                             trusted_task=grant.task_id)
            assert_window(grant.identity)
            with self.store.read_transaction() as db:
                self.store._require_scope(db, grant.task_id, grant.target_scope)
            self.store.resume_computer_from_chat_request(grant.task_id, resource, snapshot)
            return {"state": "resumed", "requires_new_observation": True,
                    "resume_source": "trusted_chat_request", "foreground_activated": False}
        if mode not in (None, "pause"):
            raise ComputerBoundaryError("invalid_pause_mode")
        _, resource = self._owner(grant)
        self.store.pause_computer_target(grant.task_id, resource)
        with self._host_gate:
            events = [event for key, event in self._stops.items()
                      if (key.startswith(grant.task_id + ":computer:") and
                          self._action_targets.get(key) == grant.identity)]
        for event in events:
            event.set()
        self._stop_idle_indicators(grant.task_id, grant.identity)
        return {"state": "paused", "stop_received": True,
                "in_flight_actions": len(events),
                "resume_requires_trusted_chat_request": True}

    def _capture_observation(self, grant: ComputerAuthorization, owner: str,
                             resource: str, preflight: Callable[[], None],
                             stopped: Callable[[], bool], candidate_uia=None) -> dict:
        preflight()
        broker_status = self._high.status(grant.task_id) if self._high is not None else None
        current = window_geometry(grant.identity)
        environment = layout_environment()
        if current.window.width * current.window.height > self.MAX_WINDOW_PIXELS:
            raise ComputerBoundaryError("window_capture_too_large")
        capture = self._capture(grant, preflight=preflight,
                                 stopped=stopped)
        if len(capture.bmp) > self.MAX_BMP_BYTES:
            raise ComputerBoundaryError("window_capture_too_large")
        input_state = read_input_mode(grant.identity)
        preflight()
        if window_geometry(grant.identity) != current:
            raise ComputerBoundaryError("capture_target_changed")
        if layout_environment() != environment:
            raise ComputerBoundaryError("desktop_topology_changed")
        if broker_status is not None:
            final_status = self._high.status(grant.task_id)
            if final_status is None or final_status.desktop_revision != broker_status.desktop_revision:
                raise ComputerBoundaryError("desktop_revision_changed")
        generation = self._generation(current)
        handle = self.store.observe(owner, resource, generation,
                                    ttl=self.OBSERVATION_TTL_SECONDS)
        shared_revision = None
        candidate_set = None
        if candidate_uia is not None:
            try:
                candidate_set = build_uia_candidates(identity=grant.identity, geometry=current,
                    capture=capture, computer_observation_id=handle, uia=candidate_uia,
                    captured_at_ms=int(time.time() * 1000), goal_coverage_confirmed=False)
            except CandidateError as error:
                candidate_set = {"candidates": [], "complete": False,
                                 "host_vision_required": True, "reason": error.code}
        if grant.shared_resource is not None:
            with self.store.read_transaction() as db:
                row = db.execute("SELECT revision FROM resources WHERE id=?",
                                 (grant.shared_resource,)).fetchone()
                if row is None:
                    raise ComputerBoundaryError("browser_resource_unavailable")
                shared_revision = row[0]
        with self._gate:
            self._observations[handle] = {"task": grant.task_id,
                                          "identity": grant.identity,
                                          "observed_at": self.store.clock(),
                                          "broker_revision": broker_status.desktop_revision if broker_status is not None else None,
                                          "geometry": current,
                                          "layout_environment": environment,
                                          "generation": generation,
                                          "shared_resource": grant.shared_resource,
                                          "shared_revision": shared_revision,
                                          "source_bounds": capture.source_bounds,
                                          "image_width": capture.width,
                                          "image_height": capture.height,
                                          "image_digest": hashlib.sha256(capture.bmp).hexdigest(),
                                          "capture_descriptor": replace(capture, bmp=b""),
                                          "capture_compressed": zlib.compress(capture.bmp, 1),
                                          "visible_windows": visible_process_top_levels(grant.identity),
                                          "candidates": candidate_set["candidates"] if candidate_set else [],
                                          "expires": self.store.clock() + self.OBSERVATION_TTL_SECONDS}
            if len(self._observations) > 128:
                self._observations.pop(next(iter(self._observations)))
            while len(self._observations) > 1 and sum(len(row.get("capture_compressed", b"")) for row in self._observations.values()) > 32_000_000:
                self._observations.pop(next(iter(self._observations)))
        return {"observation_id": handle, "image": self._image(capture),
                "input_state": input_state,
                "client_origin": list(current.client_origin),
                "client_size": list(current.client_size),
                "client_coordinate_space": "physical_client_pixels",
                "window_origin": [current.window.left, current.window.top],
                "window_size": [current.window.right - current.window.left, current.window.bottom - current.window.top],
                "window_coordinate_space": "physical_window_pixels",
                "desktop": environment[0], "work_areas": [list(area) for area in environment[1]],
                **({"candidates": [{key: row[key] for key in ("candidate_id", "role", "label", "rect_client")}
                                    for row in candidate_set["candidates"]],
                    "candidate_generation": generation,
                    "candidate_coverage": {k: v for k, v in candidate_set.items() if k not in
                                           {"candidates", "target_identity"}}} if candidate_set else {})}

    def _run_sequence(self, owner: str, key: str,
                      grant: ComputerAuthorization, geometry, sequence,
                      before_windows: frozenset[int],
                      preflight: Callable[[], None], stopped: Callable[[], bool],
                      progress: dict, indicator=None, followup_check=None, phase=None) -> dict:
        """One bounded foreground phase; every next step needs a fresh check."""
        preflight()
        if stopped():
            raise ComputerBoundaryError("input_stopped")
        assert_foreground(grant.identity)
        assert_geometry(geometry)
        baseline = self._capture(grant, preflight=preflight,
                                  stopped=stopped)
        if len(baseline.bmp) > self.MAX_BMP_BYTES:
            raise ComputerBoundaryError("window_capture_too_large")
        preflight()
        if stopped():
            raise ComputerBoundaryError("input_stopped")
        assert_foreground(grant.identity)
        assert_geometry(geometry)
        before_action = new_visible_followups(grant.identity, before_windows,
                                              bind_allowed=False)
        if before_action["visual_scope"] != "target_window_only":
            return {"state": "sequence_stopped", "reason": "new_window_detected",
                    "business_outcome_verified": False, **before_action}
        previous_digest = hashlib.sha256(baseline.bmp).hexdigest()
        for index, (step_command, batch, expectation) in enumerate(sequence):
            progress["current_step"] = index
            preflight()
            if stopped():
                raise ComputerBoundaryError("input_stopped")
            assert_foreground(grant.identity)
            assert_geometry(geometry)
            if indicator is not None:
                indicator.reserve_mouse_paths(mouse_path_rects((batch,)))
            ledger = HeldInputLedger()
            if phase is not None:
                phase.track(ledger)
            if indicator is not None:
                indicator.set_stage("input", checkpoint=f"步骤 {index + 1}/{len(sequence)}")
            self.store.begin_computer_sequence_step(owner, key, index)
            progress["partial_step"] = index
            progress["input_release"] = "unknown"
            sent_success = False
            try:
                baseline = None
                if step_command in {"text", "key"}:
                    def accepted_ime(count):
                        progress["sent_events"] += count
                    baseline, ime_report = prepare_ime(grant.identity, geometry, ledger,
                        preflight=lambda: preflight() or True, stopped=stopped, accepted=accepted_ime)
                    progress.setdefault("ime_preparations", []).append({"step": index, **ime_report})
                def step_preflight():
                    preflight()
                    if baseline is not None and baseline.changed(read_input_context(grant.identity)):
                        raise NativeInputError("input_context_changed")
                    return True
                sent = send_batch(batch, ledger, expected=grant.identity,
                                  geometry=geometry,
                                  preflight=step_preflight,
                                  stopped=stopped)
                sent_success = True
                progress["sent_events"] += sent
                progress["sent_batches"] += 1
            except PartialInput as error:
                progress["sent_events"] += error.sent
                raise
            finally:
                try:
                    if ledger.held:
                        from .computer_native import release_held
                        progress["input_release"] = "release_pending"
                        release_held(ledger, cleanup_owned=lambda: True, stopped=stopped)
                finally:
                    progress["input_release"] = (
                        "released" if ledger.release_confirmed else "release_pending")
                    self.store.finish_computer_sequence_step(
                        owner, key, index, complete=sent_success,
                        input_release=progress["input_release"])
                    if sent_success:
                        progress["sent_prefix"].append(index)
                        progress["partial_step"] = None
            if indicator is not None:
                indicator.set_stage("verify", checkpoint=f"复查步骤 {index + 1}")
            followup = (followup_check() if followup_check is not None else
                        new_visible_followups(grant.identity, before_windows,
                                              bind_allowed=not stopped()))
            if followup["visual_scope"] != "target_window_only":
                return {"state": "sequence_stopped", "reason": "new_window_detected",
                        "business_outcome_verified": False, **followup}
            preflight()
            if stopped():
                raise ComputerBoundaryError("input_stopped")
            assert_foreground(grant.identity)
            assert_geometry(geometry)
            current = window_geometry(grant.identity)
            if current.window.width * current.window.height > self.MAX_WINDOW_PIXELS:
                raise ComputerBoundaryError("window_capture_too_large")
            capture = self._capture(grant, preflight=preflight,
                                     stopped=stopped)
            if len(capture.bmp) > self.MAX_BMP_BYTES:
                raise ComputerBoundaryError("window_capture_too_large")
            preflight()
            if stopped():
                raise ComputerBoundaryError("input_stopped")
            assert_foreground(grant.identity)
            assert_geometry(geometry)
            followup = (followup_check() if followup_check is not None else
                        new_visible_followups(grant.identity, before_windows,
                                              bind_allowed=not stopped()))
            if followup["visual_scope"] != "target_window_only":
                return {"state": "sequence_stopped", "reason": "new_window_detected",
                        "business_outcome_verified": False, **followup}
            digest = hashlib.sha256(capture.bmp).hexdigest()
            matched = (expectation == "capture_available" or
                       expectation == "image_changed" and digest != previous_digest or
                       expectation == "image_unchanged" and digest == previous_digest)
            progress["checks"].append({"index": index, "command": step_command,
                                       "expect": expectation, "matched": matched,
                                       "capture_backend": capture.source})
            progress["step_observations"].append({"index": index,
                                                   "image": self._image(capture)})
            if not matched:
                return {"state": "sequence_stopped", "reason": "step_condition_unmet",
                        "business_outcome_verified": False}
            previous_digest = digest
        return {"state": "sequence_completed", "business_outcome_verified": False}

    def _execute(self, owner: str, resource: str, grant: ComputerAuthorization,
                 action_id: str, command: str, payload: dict, *,
                 observation: str | None = None, generation: str | None = None,
                 batches=None, geometry=None, restore_minimized: bool = False,
                 sequence=None, shared_revision: int | None = None,
                 candidate_uia=None, semantic_candidate=None, wait_observation=None,
                 region_version=None, layout_plan=None) -> dict:
        key = self._key(grant.task_id, action_id)
        with self._gate:
            with self._host_gate:
                stop = self._stops.setdefault(key, threading.Event())
                if stop.is_set():
                    raise ComputerBoundaryError("input_stopped")
            previous_target = self._action_targets.get(key)
            if previous_target is not None and previous_target != grant.identity:
                raise ComputerBoundaryError("action_id_conflict")
            self._action_targets[key] = grant.identity
        queued, resources = self._queue_action(owner, resource, grant, action_id, command,
                                              payload, observation, generation)
        if queued["state"] != "queued":
            return {"receipt": self.store.status(owner, key), "replayed": True}
        decision = wait_for_turn_sync(self.store, owner, key, resources,
                                      client_factory=self.jev_client_factory,
                                      timeout=max(0, min(5, grant.expires_at - self.store.clock())))
        if decision.action_id != key:
            return {"receipt": self.store.queue_status(owner, key), "queued": True}
        if grant.expires_at <= self.store.clock():
            self.store.cancel(owner, key)
            raise ComputerBoundaryError("trusted_call_expired")
        if stop.is_set():
            self.store.cancel(owner, key)
            raise ComputerBoundaryError("input_stopped")
        if self._high is not None and command not in {"observe", "wait"}:
            from .computer_high_runtime import execute_high, require_local_capability
            try:
                high_status = self._high.status(grant.task_id)
                if high_status is not None:
                    self._high.require_input(high_status)
                    return execute_high(self, owner, resource, grant, key, command, payload,
                        decision.decision_id, resources, stop, high_status,
                        observation=observation, generation=generation, batches=batches,
                        geometry=geometry, restore_minimized=restore_minimized,
                        sequence=sequence, shared_revision=shared_revision,
                        semantic_candidate=semantic_candidate, region_version=region_version,
                        layout_plan=layout_plan)
                if layout_plan is not None:
                    raise ComputerBoundaryError("window_layout_executor_unavailable")
                require_local_capability(grant.identity.hwnd, grant.identity.pid)
            except (HighHelperError, ComputerBoundaryError, NativeInputError, ControlError) as error:
                # This is before local dispatch. Never replay a failed High call.
                current = self.store.status(owner, key)
                if current["state"] == "queued":
                    self.store.cancel(owner, key)
                    current = self.store.status(owner, key)
                return {"receipt": current, "state": "outcome_uncertain" if current["state"] == "outcome_uncertain" else "rejected",
                        "dispatched": None if current["state"] == "outcome_uncertain" else False,
                        "reason": error.code}
        if layout_plan is not None:
            self.store.cancel(owner, key)
            return {"receipt": self.store.status(owner, key), "state": "rejected", "dispatched": False,
                    "reason": "window_layout_executor_unavailable"}
        dispatched = False
        input_batch_started = False
        sent_events = 0
        sent_batches = 0
        timed_progress = None
        ime_baseline = None
        expected_focus_transition = 0
        ime_preparation = None
        result = None
        activation_result = None
        activation_progress = {"activation_input_events": 0, "activation_input_release": "not_used"}
        followup = None
        barrier = None
        return_hwnd = None
        before_windows = frozenset()
        sequence_progress = ({"sent_prefix": [], "sent_events": 0,
                              "sent_batches": 0, "checks": [],
                              "step_observations": [], "partial_step": None,
                              "input_release": "released"}
                             if sequence is not None else None)
        sequence_started = False
        ledger = None
        input_release = "not_used"
        activated_capture_failed = False
        activation_started = False
        activation_known_zero = False
        business_known_zero = False
        phase = None
        def effective_release():
            raw = (sequence_progress["input_release"] if sequence_started else
                   input_release if input_release != "not_used" else "released")
            if activation_progress["activation_input_release"] not in {"not_used", "released"}:
                raw = "unknown"
            if phase is not None and phase.release_state not in {"not_used", "released"}:
                raw = phase.release_state
            return raw
        def record_effects():
            business_events = sent_events + (sequence_progress["sent_events"] if sequence_progress else 0)
            business_started = input_batch_started or sequence_started
            activation_sent = bool(activation_progress["activation_input_events"] or
                                   activation_progress.get("activation_shell_dispatched") or
                                   activation_progress.get("activation_request_sent"))
            release = effective_release()
            activation_unresolved = activation_sent and activation_result is None
            self.store.record_action_effects(
                owner, key,
                activation_dispatched=True if activation_sent else False if not activation_started or activation_known_zero else None,
                # Until activation itself has returned, do not publish a
                # completed zero-business phase: shared failure inference
                # would otherwise discard the unresolved activation effect.
                business_dispatched=None if activation_unresolved else
                    True if business_events else False if not business_started or business_known_zero else None,
                input_release=release)
            return activation_unresolved
        def finish(*args, **kwargs):
            record_effects()
            if isinstance(result, dict) and command not in {"observe", "wait"}:
                result["input_release"] = effective_release()
                if timed_progress is not None:
                    result.update(sent_segments=timed_progress["sent_segments"],
                                  timed_plan_completed=sent_batches > 0)
                if ime_preparation is not None:
                    result["ime_preparation"] = ime_preparation
            return self.store.finish(*args, **kwargs)
        try:
            with (self.store.dispatch(owner, key, decision.decision_id),
                  self._record_effects_on_failure(owner, key, record_effects),
                  self._finish_read_failure(owner, key, command)):
                if command not in {"observe", "wait"}:
                    phase = ComputerForegroundPhase(self.store, owner, key, resource,
                                                     payload.get("command", command))
                watch = None
                watch_started = False
                def preflight() -> None:
                    if command not in {"observe", "wait"} and self.store.write_stopped():
                        raise ControlError("global_write_stopped")
                    if stop.is_set():
                        raise ComputerBoundaryError("input_stopped")
                    if phase is not None:
                        phase.stage.check()
                    else:
                        self.store.check_dispatch(owner, key)
                    if shared_revision is not None:
                        with self.store.read_transaction() as db:
                            row = db.execute("SELECT revision FROM resources WHERE id=?",
                                             (grant.shared_resource,)).fetchone()
                            if row is None or row[0] != shared_revision + 1:
                                raise ComputerBoundaryError("observation_unavailable")
                    if grant.expires_at <= self.store.clock():
                        raise ComputerBoundaryError("trusted_call_expired")
                    if watch is not None and watch_started:
                        try:
                            watch.check()
                        except ControlError as error:
                            if phase is not None and error.code in {"foreground_phase_interrupted", "user_takeover_paused"}:
                                reason = {"foreground_left_target": "foreground_changed",
                                          "target_minimized": "target_minimized", "user_stop": "explicit_stop",
                                          "target_destroyed": "target_closed"}.get(barrier.reason)
                                if reason is not None:
                                    phase.interrupted(reason)
                            raise
                    assert_window(grant.identity)

                def input_preflight() -> bool:
                    nonlocal ime_baseline, expected_focus_transition
                    preflight()
                    if ime_baseline is not None:
                        current = read_input_context(grant.identity)
                        if ime_baseline.changed(current):
                            if (current.focus is not None and time.monotonic() <= expected_focus_transition
                                    and not replace(ime_baseline, focus=current.focus).changed(current)):
                                ime_baseline = replace(ime_baseline, focus=current.focus)
                                expected_focus_transition = 0
                            else:
                                phase.interrupted("ime_changed")
                                raise ControlError("foreground_phase_interrupted")
                    return True

                if command == "observe":
                    result = {"state": "observed", "dispatched": False,
                              **self._capture_observation(grant, owner, resource,
                                                          preflight, stop.is_set, candidate_uia)}
                    finish(owner, key, "verified", result_code="computer_observed")
                elif command == "wait":
                    condition = payload["arguments"]["condition"]
                    wait_started = time.monotonic()
                    deadline = wait_started + payload["arguments"]["timeout_ms"] / 1000
                    matched = False
                    details = {}
                    while time.monotonic() < deadline and not stop.is_set():
                        self.store.check_dispatch(owner, key)
                        target_closed = not win32gui.IsWindow(grant.identity.hwnd)
                        if target_closed:
                            matched = condition == "window_closed"
                            details = {"target_closed": True}
                        elif condition == "new_window":
                            details = new_visible_followups(grant.identity,
                                wait_observation["visible_windows"], bind_allowed=self._high is None)
                            matched = details["visual_scope"] != "target_window_only"
                        elif condition in {"image_changed", "image_unchanged"}:
                            capture = self._capture(grant, preflight=preflight, stopped=stop.is_set)
                            changed = hashlib.sha256(capture.bmp).hexdigest() != wait_observation["image_digest"]
                            matched = changed if condition == "image_changed" else not changed
                        # Sampling may itself outlast the condition deadline.
                        # A late result is never accepted as an in-time match.
                        if time.monotonic() >= deadline:
                            matched = False
                            break
                        if matched or target_closed:
                            break
                        time.sleep(min(0.1, max(0, deadline - time.monotonic())))
                    if stop.is_set():
                        raise ComputerBoundaryError("input_stopped")
                    result = {"state": "wait_completed" if matched else "wait_timeout",
                              "matched": matched, "condition": condition, "dispatched": False,
                              "business_outcome_verified": False,
                              "condition_wait_elapsed_ms": round((time.monotonic() - wait_started) * 1000, 3),
                              **details}
                    # The fresh observation remains a separate part of the
                    # response and may add time after the condition deadline.
                    post_wait_started = time.monotonic()
                    if win32gui.IsWindow(grant.identity.hwnd):
                        result.update(self._capture_observation(grant, owner, resource, preflight, stop.is_set))
                    result["post_wait_observation_elapsed_ms"] = round((time.monotonic() - post_wait_started) * 1000, 3)
                    finish(owner, key, "verified" if matched else "not_verified",
                                      result_code="computer_" + result["state"])
                elif command == "activate":
                    preflight()
                    try:
                        with self.store.read_transaction() as db:
                            self.store._require_scope(db, grant.task_id, grant.capture_scope)
                    except ControlError as error:
                        finish(owner, key, "not_verified", result_code=error.code)
                        raise
                    try:
                        activation_started = True
                        activation_result = activate_window(
                            grant.identity, preflight=input_preflight,
                            stopped=stop.is_set, restore_minimized=restore_minimized,
                            progress=activation_progress, on_input_ledger=phase.track)
                    except NativeInputError as error:
                        if (not activation_progress.get("activation_request_sent") and
                                not activation_progress["activation_input_events"] and
                                not activation_progress.get("activation_shell_dispatched")):
                            activation_known_zero = True
                            finish(owner, key, "not_verified", result_code=error.code)
                        raise
                    activation_input_dispatched = bool(activation_result.get("activation_input_events", 0))
                    dispatched = bool(activation_input_dispatched or
                                      activation_progress.get("activation_shell_dispatched"))
                    preflight()
                    result = {**activation_progress, **activation_result, "dispatched": dispatched,
                              "input_dispatched": activation_input_dispatched,
                              "target": asdict(grant.identity)}
                    if activation_result["foreground"]:
                        try:
                            result.update(self._capture_observation(
                                grant, owner, resource, preflight, stop.is_set))
                        except CaptureError:
                            activated_capture_failed = True
                            finish(owner, key, "not_verified",
                                              result_code="activated_visual_unavailable")
                            raise
                    finish(owner, key,
                                      "outcome_uncertain" if result["state"] == "outcome_uncertain" else
                                      "verified" if result["foreground"] else "not_verified",
                                      result_code=("computer_activated" if result["foreground"]
                                                   else result.get("reason", "user_activation_required")))
                else:
                    # Owned confirmation dialogs usually close back to their
                    # parent after a click. This transition is part of the
                    # same app flow, not a user takeover of another app.
                    return_hwnd = None
                    try:
                        parent_hwnd = win32gui.GetWindow(grant.identity.hwnd,
                                                         win32con.GW_OWNER)
                        if parent_hwnd:
                            parent = bind_window(parent_hwnd)
                            if (parent.pid == grant.identity.pid and
                                    parent.process_created == grant.identity.process_created):
                                return_hwnd = parent_hwnd
                    except (NativeInputError, OSError, ValueError, win32gui.error):
                        pass
                    barrier = TakeoverBarrier(
                        grant.identity.hwnd,
                        lambda: self.store.pause_computer_target(grant.task_id, resource),
                        return_hwnd=return_hwnd)
                    watch = ForegroundWatch(barrier)
                    indicator = None
                    try:
                        try:
                            assert_foreground(grant.identity)
                            needs_activation = False
                        except NativeInputError as error:
                            if error.code not in {"foreground_changed", "foreground_target_not_interactive"}:
                                raise
                            needs_activation = True
                        if needs_activation:
                            activation_started = True
                            activation_result = activate_window(
                                grant.identity, preflight=input_preflight,
                                stopped=stop.is_set, restore_minimized=True,
                                progress=activation_progress, on_input_ledger=phase.track)
                            if not activation_result["foreground"]:
                                dispatched = bool(activation_result.get("activation_input_events", 0) or
                                                  activation_progress.get("activation_shell_dispatched"))
                                uncertain = activation_result.get("state") == "outcome_uncertain"
                                finish(owner, key, "outcome_uncertain" if uncertain else "not_verified",
                                                  result_code=activation_result.get("reason", "user_activation_required"))
                                return {"receipt": self.store.status(owner, key),
                                        "result": {"state": "outcome_uncertain" if uncertain else "not_verified",
                                                   "dispatched": dispatched,
                                                   "reason": activation_result.get("reason", "user_activation_required"),
                                                   "input_release": effective_release(),
                                                   "activation": activation_result}}
                        watch.start()
                        watch_started = True
                        preflight()
                        assert_foreground(grant.identity)
                        assert_geometry(geometry)
                        if win32gui.IsWindow(grant.identity.hwnd):
                            indicator = self._acquire_indicator(grant,
                                payload.get("goal_hint") or payload.get("command") or "窗口操作", barrier.stop_clicked,
                                paths=_indicator_paths(
                                    tuple(step[1] for step in sequence) if sequence is not None else batches,
                                    geometry))
                            indicator.set_stage("prepare", checkpoint="重查目标与输入位置")
                        if region_version is not None:
                            snapshot = self._capture(grant, preflight=preflight,
                                                      stopped=stop.is_set)
                            try:
                                unchanged = _region_digest(snapshot, region_version[0]) == region_version[1]
                            except CandidateError as error:
                                raise ComputerBoundaryError(error.code) from error
                            if not unchanged:
                                raise ComputerBoundaryError("candidate_requires_new_observation")
                        if semantic_candidate is not None:
                            snapshot = self._capture(grant, preflight=preflight,
                                                      stopped=stop.is_set)
                            try:
                                checked = checked_click_arguments(semantic_candidate,
                                    identity=grant.identity, geometry=geometry, capture=snapshot,
                                    computer_observation_id=payload["observation_id"])
                            except CandidateError as error:
                                raise ComputerBoundaryError(error.code) from error
                            batches = _plan_input("click", checked, geometry)
                        before_windows = visible_process_top_levels(grant.identity)
                        def followup_check():
                            allowed = not stop.is_set() and not barrier.stopped.is_set()
                            foreground = win32gui.GetForegroundWindow()
                            owned_transition = (
                                not stop.is_set() and barrier.reason == "foreground_left_target" and
                                foreground not in before_windows and
                                is_owned_popup(grant.identity, foreground))
                            found = new_visible_followups(grant.identity, before_windows,
                                                          bind_allowed=allowed or owned_transition)
                            if owned_transition:
                                targets = found.get("followup_targets", [])
                                if len(targets) != 1 or targets[0]["hwnd"] != foreground:
                                    return new_visible_followups(grant.identity, before_windows, bind_allowed=False)
                            return found
                        if sequence is not None:
                            assert sequence_progress is not None
                            self.store.start_computer_sequence(owner, key, len(sequence))
                            sequence_started = True
                            sequence_result = self._run_sequence(
                                owner, key, grant, geometry, sequence,
                                before_windows, preflight,
                                lambda: stop.is_set() or barrier.stopped.is_set(),
                                sequence_progress, indicator, followup_check, phase=phase)
                            # All sequence ledgers were registered before down.
                            completed = len(sequence_progress["sent_prefix"])
                            result = {**sequence_result, "dispatched": completed > 0,
                                      "sent_prefix": sequence_progress["sent_prefix"],
                                      "undispatched_suffix": list(range(completed, len(sequence))),
                                      "step_checks": sequence_progress["checks"],
                                      "step_observations": sequence_progress[
                                          "step_observations"],
                                      "sent_events": sequence_progress["sent_events"],
                                      "sent_batches": sequence_progress["sent_batches"],
                                      "partial_step": sequence_progress["partial_step"],
                                      "ime_preparations": sequence_progress.get("ime_preparations", []),
                                      "input_release": sequence_progress["input_release"]}
                            finish(owner, key, "not_verified",
                                              result_code=("computer_sequence_completed"
                                                           if result["state"] == "sequence_completed"
                                                           else result["reason"]),
                                              sequence_final_state=result["state"])
                            return {"receipt": self.store.status(owner, key),
                                    "result": result}
                        ledger = HeldInputLedger()
                        phase.track(ledger)
                        input_release = "released"
                        try:
                            for batch_index, batch in enumerate(batches):
                                if indicator is not None:
                                    indicator.reserve_mouse_paths(_indicator_paths((batch,), geometry))
                                    indicator.set_stage("input", checkpoint=f"输入批次 {batch_index + 1}/{len(batches)}")
                                input_batch_started = True
                                if payload["command"] in {"text", "key", "key_mouse", "batch"} or (
                                        payload["command"] in {"drag", "mouse_hold"} and "keys" in payload["arguments"]):
                                    if batch_index == 0:
                                        def ime_accepted(count):
                                            nonlocal sent_events, dispatched
                                            sent_events += count
                                            dispatched = dispatched or count > 0
                                        try:
                                            ime_baseline, ime_preparation = prepare_ime(
                                                grant.identity, geometry, ledger,
                                                preflight=lambda: preflight() or True,
                                                stopped=lambda: stop.is_set() or barrier.stopped.is_set(),
                                                accepted=ime_accepted)
                                        except NativeInputError as ime_error:
                                            if ime_error.code == "input_context_changed":
                                                phase.interrupted("ime_changed")
                                                raise ControlError("foreground_phase_interrupted") from None
                                            raise
                                if isinstance(batch, TimedInputPlan):
                                    timed_progress = {"sent_events": 0, "sent_segments": 0}
                                    try:
                                        send_timed_plan(batch, ledger, expected=grant.identity,
                                            geometry=geometry, preflight=input_preflight,
                                            stopped=lambda: stop.is_set() or barrier.stopped.is_set(),
                                            progress=timed_progress)
                                    finally:
                                        sent_events += timed_progress["sent_events"]
                                        dispatched = dispatched or timed_progress["sent_events"] > 0
                                else:
                                    sent = send_batch(batch, ledger, expected=grant.identity,
                                                  geometry=geometry, preflight=input_preflight,
                                                  stopped=lambda: (stop.is_set() or
                                                                   barrier.stopped.is_set()))
                                    sent_events += sent
                                sent_batches += 1
                                dispatched = True
                                if any(step.pressed and (step.token == ("vk", 9) or
                                        step.token is not None and step.token[0] == "mouse") for step in batch.steps):
                                    expected_focus_transition = time.monotonic() + .150
                        except PartialInput as error:
                            if timed_progress is None:
                                sent_events += error.sent
                            dispatched = dispatched or error.sent > 0
                            raise
                        finally:
                            # A partial batch may leave a down event. The dispatch
                            # lock remains held until this exact ledger is released.
                            try:
                                if ledger.held:
                                    input_release = "release_pending"
                                    from .computer_native import release_held
                                    release_held(ledger, cleanup_owned=lambda: True,
                                                 stopped=lambda: stop.is_set() or barrier.stopped.is_set())
                            finally:
                                input_release = "released" if ledger.release_confirmed else "release_pending"
                        if indicator is not None:
                            indicator.set_stage("verify", checkpoint="输入已结束，读取新状态")
                        followup = new_visible_followups(
                            grant.identity, before_windows,
                            bind_allowed=not stop.is_set() and not barrier.stopped.is_set())
                        def closed_to_owner() -> bool:
                            return bool(
                                return_hwnd and
                                win32gui.GetForegroundWindow() == return_hwnd and
                                not stop.is_set() and not barrier.stopped.is_set())

                        target_closed_to_owner = bool(
                            closed_to_owner() and
                            not win32gui.IsWindow(grant.identity.hwnd))
                        if target_closed_to_owner:
                            result = {"state": "target_closed_after_input",
                                      "dispatched": True, "sent_events": sent_events,
                                      "sent_batches": sent_batches, "held_input": [],
                                      "business_outcome_verified": False,
                                      **followup}
                            finish(owner, key, "not_verified",
                                              result_code="computer_target_closed_to_owner")
                        else:
                            try:
                                preflight()
                                if stop.is_set():
                                    raise ComputerBoundaryError("input_stopped")
                                current = window_geometry(grant.identity)
                                if current.window.width * current.window.height > self.MAX_WINDOW_PIXELS:
                                    raise ComputerBoundaryError("window_capture_too_large")
                                capture = self._capture(
                                    grant, preflight=preflight,
                                    stopped=lambda: stop.is_set() or barrier.stopped.is_set())
                                if len(capture.bmp) > self.MAX_BMP_BYTES:
                                    raise ComputerBoundaryError("window_capture_too_large")
                                preflight()
                            except (NativeInputError, CaptureError) as error:
                                if getattr(error, "code", None) != "target_not_captureable":
                                    raise
                                deadline = time.monotonic() + 0.15
                                while not closed_to_owner() and time.monotonic() < deadline:
                                    time.sleep(0.01)
                                if not closed_to_owner():
                                    raise
                                result = {"state": "target_closed_after_input",
                                          "dispatched": True, "sent_events": sent_events,
                                          "sent_batches": sent_batches, "held_input": [],
                                          "business_outcome_verified": False,
                                          **followup}
                                finish(owner, key, "not_verified",
                                                  result_code="computer_target_closed_to_owner")
                            else:
                                latest_followup = new_visible_followups(
                                    grant.identity, before_windows,
                                    bind_allowed=not stop.is_set() and not barrier.stopped.is_set())
                                if (latest_followup["visual_scope"] != "target_window_only" or
                                        followup is None):
                                    followup = latest_followup
                                result = {"state": "outcome_unverified", "dispatched": True,
                                          "sent_events": sent_events,
                                          "sent_batches": sent_batches, "held_input": [],
                                          "visual_recheck": self._image(capture),
                                          "input_state": read_input_mode(grant.identity),
                                          **followup}
                                preflight()
                                finish(owner, key, "not_verified",
                                                  result_code="computer_visual_recheck_only")
                    except (ControlError, ComputerBoundaryError, NativeInputError,
                            CaptureError, IndicatorError, ValueError) as error:
                        if phase is not None and getattr(error, "code", None) in {
                                "mouse_receiver_changed", "external_input_held", "input_context_changed"}:
                            phase.interrupted("external_mouse" if error.code == "mouse_receiver_changed" else
                                              "ime_changed" if error.code == "input_context_changed" else "external_keyboard")
                            error = ControlError("foreground_phase_interrupted")
                        if phase is not None:
                            interruption = {"foreground_phase_interrupted": {
                                "foreground_left_target": "foreground_changed",
                                "target_minimized": "target_minimized"}.get(barrier.reason),
                                "geometry_changed": "geometry_changed",
                                "desktop_topology_changed": "geometry_changed"}.get(getattr(error, "code", None))
                            if interruption is not None:
                                phase.interrupted(interruption)
                        # A switch can land between preflight and a native
                        # stopped/foreground check. Reconcile that signal with
                        # the watch instead of misclassifying the known prefix.
                        if watch_started and getattr(error, "code", None) in {
                                "input_stopped", "foreground_changed", "foreground_target_not_interactive",
                                "capture_cancelled", "target_not_captureable", "capture_target_changed"}:
                            try:
                                watch.check()
                            except ControlError as watched_error:
                                if (watched_error.code == "foreground_phase_interrupted" and
                                        not stop.is_set()):
                                    error = watched_error
                        # Ordinary switching ends this phase without pausing
                        # the target or quarantining a known balanced prefix.
                        # Partial sends and failed release remain uncertain.
                        phase_interrupted = getattr(error, "code", None) == "foreground_phase_interrupted"
                        pre_send_refusal = getattr(error, "code", None) in {
                            "user_takeover_paused", "foreground_phase_interrupted", "external_input_held",
                            "foreground_changed", "foreground_target_not_interactive",
                            "window_changed", "geometry_changed", "input_stopped",
                            "desktop_topology_changed", "mouse_desktop_required",
                            "mouse_receiver_unavailable", "mouse_geometry_required",
                            "user_paused_or_cancelled", "trusted_call_expired",
                            "resource_paused_or_quarantined"} or isinstance(error, PartialInput) and error.sent == 0
                        step_started = (input_batch_started if sequence_progress is None else
                                        sequence_progress["partial_step"] is not None)
                        no_input_sent = (not activation_progress.get("activation_shell_dispatched") and
                                         not activation_progress["activation_input_events"] and sent_events == 0 and
                                         (not step_started or pre_send_refusal) and
                                         (sequence_progress is None or
                                          sequence_progress["input_release"] == "released" and
                                          not sequence_progress["sent_prefix"]))
                        business_known_zero = (sent_events == 0 and
                            (not step_started or pre_send_refusal) and
                            (sequence_progress is None or not sequence_progress["sent_events"]))
                        known_interrupted_prefix = (
                            phase_interrupted and
                            effective_release() == "released" and
                            activation_progress["activation_input_release"] in {"not_used", "released"} and
                            (ledger is None or ledger.release_confirmed) and
                            (sequence_progress is None or
                             sequence_progress["input_release"] == "released"))
                        known_activation_read_failure = (
                            isinstance(error, CaptureError) and error.code != "capture_cancelled" and
                            activation_result is not None and activation_result.get("foreground") and
                            activation_progress["activation_input_release"] in {"not_used", "released"} and
                            not input_batch_started and not sequence_started)
                        if no_input_sent or known_interrupted_prefix or known_activation_read_failure:
                            finish(
                                owner, key, "not_verified",
                                result_code=getattr(error, "code", "computer_input_not_sent"),
                                sequence_final_state=("sequence_stopped"
                                                      if sequence_started
                                                      else None))
                            if sequence_progress is not None:
                                sequence_progress["partial_step"] = None
                        raise error
                    finally:
                        if indicator is not None and stop.is_set():
                            release = effective_release()
                            indicator.set_stage("stopped" if release == "released" else "release_unconfirmed",
                                checkpoint="本次输入已停止" if release == "released" else "输入释放尚未确认",
                                input_release=release)
                        try:
                            if barrier is not None:
                                barrier.require_persisted_before_release()
                        finally:
                            watch.close()
                            if indicator is not None:
                                self._finish_indicator(indicator, stopped=stop.is_set() or barrier.stopped.is_set(),
                                                       released=effective_release() == "released")
        except (ControlError, ComputerBoundaryError, NativeInputError, CaptureError, IndicatorError,
                ValueError) as error:
            if isinstance(error, ValueError):
                diagnose_value_error(error, "execute")
            code = getattr(error, "code", "invalid_computer_request")
            dispatched = dispatched or bool(activation_progress["activation_input_events"] or
                                             activation_progress.get("activation_shell_dispatched"))
            if sequence_progress is not None:
                dispatched = bool(activation_progress["activation_input_events"] or
                                  activation_progress.get("activation_shell_dispatched") or sequence_progress["sent_prefix"] or
                                  sequence_progress["sent_events"] > 0 or
                                  (sequence_progress["partial_step"] is not None and
                                   sequence_progress["input_release"] != "released"))
            receipt = self.store.status(owner, key)
            uncertain = receipt["state"] == "outcome_uncertain"
            response = {"receipt": receipt,
                    "state": "outcome_uncertain" if uncertain else "not_verified" if dispatched else "rejected",
                    "dispatched": (None if uncertain and not dispatched else dispatched),
                    "reason": code}
            if sequence_progress is None:
                response.update({"input_release": effective_release(),
                                 "held_input": [list(token) for token in ledger.held] if ledger is not None else [],
                                 "input_dispatched": True if sent_events else
                                     None if uncertain and input_batch_started else False})
                if ime_preparation is not None:
                    response["ime_preparation"] = ime_preparation
                if timed_progress is not None:
                    response["sent_segments"] = timed_progress["sent_segments"]
                    response["timed_plan_completed"] = sent_batches > 0
            if sequence_progress is not None:
                completed = len(sequence_progress["sent_prefix"])
                response.update({"sent_prefix": sequence_progress["sent_prefix"],
                                 "undispatched_suffix": list(range(completed, len(sequence))),
                                 "partial_step": sequence_progress["partial_step"],
                                 "ime_preparations": sequence_progress.get("ime_preparations", []),
                                 "step_checks": sequence_progress["checks"],
                                 "sent_events": sequence_progress["sent_events"],
                                 "sent_batches": sequence_progress["sent_batches"],
                                 "input_release": effective_release()})
            if code == "foreground_phase_interrupted":
                response.update({"requires_new_observation": True,
                                 "business_outcome_verified": False,
                                 "foreground_watch_reason": barrier.reason if barrier is not None else None})
                if not uncertain:
                    response["state"] = "not_verified"
            elif (activation_result is not None and activation_result["foreground"] and
                  not uncertain and
                  (activated_capture_failed or
                   isinstance(error, CaptureError) and code != "capture_cancelled" and
                   not input_batch_started and not sequence_started)):
                response.update({"state": "activated_visual_unavailable",
                                 "foreground": True,
                                 "requires_new_observation": True})
            if dispatched:
                if sequence_progress is None:
                    response["sent_events"] = sent_events
                    response["sent_batches"] = sent_batches
                response["foreground_watch_reason"] = (
                    barrier.reason if barrier is not None else None)
                response["owned_return_hwnd"] = return_hwnd
                if followup is None:
                    followup = new_visible_followups(grant.identity, before_windows,
                                                     bind_allowed=False)
                if (code == "foreground_phase_interrupted" and not uncertain and
                        not stop.is_set() and barrier is not None and
                        barrier.reason == "foreground_left_target"):
                    foreground = win32gui.GetForegroundWindow()
                    if is_owned_popup(grant.identity, foreground) and foreground not in before_windows:
                        candidate_followup = new_visible_followups(
                            grant.identity, before_windows, bind_allowed=True)
                        targets = candidate_followup.get("followup_targets", [])
                        if len(targets) == 1 and targets[0]["hwnd"] == foreground:
                            followup = candidate_followup
                            response.update({"reason": "new_window_detected", "state": "not_verified"})
                response.update(followup)
            if activation_result is not None or activation_progress["activation_input_events"] or activation_progress.get("activation_shell_dispatched"):
                response["activation"] = {**activation_progress, **(activation_result or {})}
            if (phase is not None and code == "foreground_phase_interrupted" and not uncertain
                    and not stop.is_set() and response.get("reason") != "new_window_detected"):
                summary = phase.stage.snapshot()["foreground_stage"]
                if summary["reobserve_without_user_resume"]:
                    fresh_action = "continuation-" + uuid.uuid4().hex
                    fresh_key = self._key(grant.task_id, fresh_action)
                    with self._host_gate:
                        self._stops[fresh_key] = stop
                    try:
                        fresh = self._execute(owner, resource, grant, fresh_action, "observe",
                                              {"target": payload["target"], "action_id": fresh_action})
                        detail = fresh.get("result")
                        if isinstance(detail, dict) and "image" in detail:
                            phase.stage.validate_reentry(detail["observation_id"])
                            response["continuation"] = {"new_action_required": True,
                                "replay_old_action": False, "observation_id": detail["observation_id"]}
                            response["result"] = {**{name: value for name, value in response.items()
                                if name not in {"receipt", "result"}},
                                **{name: value for name, value in detail.items() if name != "image"},
                                "visual_recheck": detail["image"]}
                        else:
                            response["continuation"] = {"new_action_required": True,
                                "replay_old_action": False, "capture_state": fresh.get("state"),
                                "capture_reason": fresh.get("reason")}
                    except Exception as error:
                        # Optional recovery cannot erase the original input
                        # prefix/uncertainty or expose provider exception text.
                        response["continuation"] = {"new_action_required": True,
                            "replay_old_action": False, "capture_state": "unavailable",
                            "capture_reason": error.code if isinstance(error, (
                                ControlError, ComputerBoundaryError, NativeInputError, CaptureError))
                                else "continuation_unavailable"}
            return response
        finally:
            if phase is not None:
                try:
                    phase.seal()
                except ControlError as error:
                    if error.code != "release_execution_not_quiescent":
                        raise
                    # A peer may already own the mutex. Keep the exact native
                    # release fact and original receipt; never re-send cleanup.
                    print("computer_release_confirmation_deferred", file=sys.stderr)
            with self._host_gate:
                if key not in self._host_calls:
                    self._stops.pop(key, None)
        if command == "input" and activation_result is not None and result is not None:
            result["activation"] = activation_result
        if (command == "wait" and result is not None and result.get("matched")
                and payload["arguments"]["condition"] == "new_window" and self._high is not None
                and self._owned_window_binder is not None and not stop.is_set()):
            result.update(new_visible_followups(grant.identity, wait_observation["visible_windows"],
                bind_allowed=True, window_binder=lambda hwnd:
                    self._owned_window_binder(grant.task_id, grant.identity, hwnd)))
        return {"receipt": self.store.status(owner, key), "result": result}

    @contextmanager
    def _record_effects_on_failure(self, owner: str, key: str, record):
        try:
            yield
        except BaseException:
            if self.store.status(owner, key)["state"] == "running":
                if record():
                    self.store.finish(owner, key, "outcome_uncertain", result_code="activation_effect_unresolved")
            raise

    @contextmanager
    def _finish_read_failure(self, owner: str, key: str, command: str):
        """Close zero-write failures before dispatch's unknown-write fallback."""
        try:
            yield
        except BaseException as error:
            if command in {"observe", "wait"}:
                self.store.finish(owner, key, "not_verified",
                                  result_code=getattr(error, "code", "computer_read_failed"))
            raise
