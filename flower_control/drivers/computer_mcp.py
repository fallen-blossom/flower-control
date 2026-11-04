"""Computer MCP runtime for a trusted, exact task and window call context.

The resolver is installed in-process by a trusted host adapter. MCP arguments
cannot create a grant. The default stdio server deliberately has no resolver.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
import hashlib
import json
import math
from pathlib import Path
import sqlite3
import sys
import threading
from flower_control.control.business_plan import planned_app_call
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
from flower_control.mcp_origin import ledger_error_code
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
                              WindowIdentity, VirtualDesktop, activate_window, assert_foreground,
                              assert_geometry, assert_window, client_to_screen,
                              bind_window, mouse_button, mouse_move, mouse_move_relative, mouse_wheel,
                              new_visible_followups, plan_batch, plan_timed, plan_unicode_batches,
                              is_owned_popup,
                              send_batch, send_timed_plan, virtual_desktop, virtual_key,
                              visible_process_top_levels, window_geometry)
from .computer_native import end_keyboard_input, pre_dispatch_recovery
from .foreground_watch import ForegroundWatch
from .foreground_indicator import ForegroundIndicator, IndicatorError, mouse_path_rects
from .computer_phase import ComputerForegroundPhase
from .focus_borrow import FocusBorrow
from .computer_input_state import read_input_context, read_input_mode, prepare_ime
from .computer_capture_cache import ComputerCaptureCache
from .auxiliary_owner_cleanup import AuxiliaryOwnerCleanup
from .computer_high import (ComputerHighConnection, input_plan, assert_target_geometry, sequence_batches,
                            layout_environment, window_layout_plan)
from .high_helper import HighHelperError, HighTarget
from .computer_targets import build_uia_candidates, checked_click_arguments, CandidateError
from flower_control.security_prompt_observation import security_prompt_observation
from flower_control.security_prompt_identity import security_prompt_identity
from flower_control.control.targets import TargetCandidate, TargetRequest
from flower_control.control.target_selection import select_target
from flower_control.control.scheduling import Phase
import asyncio
import uuid
import zlib


NEXT_STEP_LIMIT = 48
TASK_PURPOSE_LIMIT = 80


def valid_next_step(value):
    """Optional host-authored HUD text: bounded, display-only, no authority.

    It never grants a target, never changes a stage and never replaces a
    receipt; it only tells the user (and a later read-only inspection) what the
    caller intends to do next.
    """
    if value is None:
        return None
    # The signed call payload must stay byte-identical to the Hook-visible
    # arguments, so this validates instead of normalizing the host text. The
    # indicator trims surrounding whitespace for display, and this accepts the
    # same range, so both sides share one rule instead of two.
    if (type(value) is not str or not 1 <= len(value.strip()) <= NEXT_STEP_LIMIT
            or any(ord(character) < 32 for character in value)):
        raise ComputerBoundaryError("invalid_next_step")
    return value


def valid_task_purpose(value):
    """Optional bound display text; independent of target selection and Jev."""
    if value is None:
        return None
    if (type(value) is not str or not value.strip() or len(value) > TASK_PURPOSE_LIMIT
            or any(ord(character) < 32 for character in value)):
        raise ComputerBoundaryError('invalid_task_purpose')
    return value
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
    execution_guard: Callable[[], None] | None = None  # Trusted desktop adapter only.
    request_fingerprint: str | None = None
    suppress_pointer_approach: bool = False
    pointer_constraints: object | None = None


Resolver = Callable[[str, dict], ComputerAuthorization]

_NAMED_KEYS = {
    "CTRL": 0x11, "SHIFT": 0x10, "ALT": 0x12,
    "ENTER": 0x0D, "ESC": 0x1B, "TAB": 0x09,
    "BACKSPACE": 0x08, "DELETE": 0x2E, "INSERT": 0x2D,
    "HOME": 0x24, "END": 0x23, "PAGEUP": 0x21, "PAGEDOWN": 0x22,
    "LEFT": 0x25, "UP": 0x26, "RIGHT": 0x27, "DOWN": 0x28,
    "SPACE": 0x20,
    "WIN": 0x5B, "LWIN": 0x5B, "RWIN": 0x5C,
    "MENU": 0x5D,
    "CAPSLOCK": 0x14, "NUMLOCK": 0x90, "SCROLLLOCK": 0x91,
    "PRINTSCREEN": 0x2C, "PAUSE": 0x13,
    "ADD": 0x6B, "SUBTRACT": 0x6D, "MULTIPLY": 0x6A, "DIVIDE": 0x6F, "DECIMAL": 0x6E,
    **{f"NUM{number}": 0x60 + number for number in range(10)},
    **{f"F{number}": 0x6F + number for number in range(1, 25)},
}


_KEY_ALIASES = {
    "CONTROL": "CTRL", "RETURN": "ENTER", "ESCAPE": "ESC", "SUPER": "WIN",
    "PAGE_UP": "PAGEUP", "PAGE_DOWN": "PAGEDOWN", "DEL": "DELETE",
    "BACK_SPACE": "BACKSPACE", "PRIOR": "PAGEUP", "NEXT": "PAGEDOWN",
    "PRINT_SCREEN": "PRINTSCREEN", "CAPS_LOCK": "CAPSLOCK", "NUM_LOCK": "NUMLOCK", "CMD": "WIN",
}


def _key_batch(keys: object):
    from .computer_keys import key_batch
    return key_batch(keys)


def _point_to_screen(geometry, x, y, coordinate_space):
    if coordinate_space in {"normalized_1000_client", "normalized_1000_window"}:
        if (geometry is None or type(x) is not int or type(y) is not int
                or not 0 <= x < 1000 or not 0 <= y < 1000):
            raise ComputerBoundaryError("invalid_normalized_input_point")
        coordinate_space = "client" if coordinate_space.endswith("_client") else "window"
        width, height = (geometry.client_size if coordinate_space == "client"
                         else (geometry.window.width, geometry.window.height))
        if width <= 0 or height <= 0:
            raise ComputerBoundaryError("invalid_normalized_input_point")
        # The observation binds physical geometry. Never apply DPI again or
        # interpret the displayed crop/resize as an input coordinate frame.
        x, y = x * width // 1000, y * height // 1000
    if coordinate_space == "client":
        return client_to_screen(geometry, x, y)
    if (geometry is None or type(x) is not int or type(y) is not int
            or not 0 <= x < geometry.window.width or not 0 <= y < geometry.window.height):
        raise ComputerBoundaryError("input_point_outside_window")
    return geometry.window.left + x, geometry.window.top + y


def _pointer_constraints(raw, geometry, coordinate_space, default=None):
    from .pointer_geometry import MotionConstraints
    if default is not None and type(default) is not MotionConstraints:
        raise ComputerBoundaryError("invalid_pointer_constraints")
    if not raw and default is None:
        return None
    if "path_mode" in raw and (type(raw["path_mode"]) is not str or raw["path_mode"] not in {"free", "direct"}):
        raise ComputerBoundaryError("invalid_pointer_path_mode")
    if "uncertainty_px" in raw and (type(raw["uncertainty_px"]) is not int or not 0<=raw["uncertainty_px"]<=256):
        raise ComputerBoundaryError("invalid_pointer_uncertainty")
    obstacles=[];quantization=4
    if "avoid_rects" in raw:
        rects=raw["avoid_rects"]
        if type(rects) is not list or len(rects)>16:
            raise ComputerBoundaryError("pointer_obstacle_limit")
        if geometry is None:
            raise ComputerBoundaryError("mouse_geometry_required")
        client=coordinate_space.endswith("client")
        width,height=geometry.client_size if client else (geometry.window.width,geometry.window.height)
        origin=geometry.client_origin if client else (geometry.window.left,geometry.window.top)
        normalized=coordinate_space.startswith("normalized_1000_")
        if normalized:
            quantization=max(4,math.ceil(max(width,height)/1000))
        for rect in rects:
            if (type(rect) not in (tuple,list) or len(rect)!=4
                    or any(type(n) is not int for n in rect)):
                raise ComputerBoundaryError("invalid_pointer_obstacle")
            l,t,r,b=rect
            w,h=(1000,1000) if normalized else (width,height)
            if not 0<=l<r<=w or not 0<=t<b<=h:
                raise ComputerBoundaryError("pointer_obstacle_outside_observation")
            if normalized:
                l,t=l*width//1000,t*height//1000
                r,b=(r*width+999)//1000,(b*height+999)//1000
            obstacles.append((origin[0]+l,origin[1]+t,origin[0]+r,origin[1]+b))
    if default is not None:
        obstacles.extend(default.obstacles)
    try:
        return MotionConstraints(obstacles=tuple(dict.fromkeys(obstacles)),
            footprint=raw.get("drag_footprint",(0,0,0,0)),
            uncertainty_px=max(raw.get("uncertainty_px",4),default.uncertainty_px if default else 4,quantization))
    except (ValueError,TypeError) as error:
        raise ComputerBoundaryError(str(error)) from error


def _pointer_drag_plan(points, initial, releases, desktop, *, mover, duration, path_mode,
                       constraints, explicit_path=False, checkpoint=None):
    from .pointer_path import plan_pointer_motion
    bounds=(desktop.left,desktop.top,desktop.left+desktop.width,desktop.top+desktop.height)
    try:
        motion=plan_pointer_motion(points[0],points[-1],bounds,
            constraints=constraints,duration_ms=duration,path_mode=path_mode,
            waypoints=points if explicit_path else None,force_motion=True,checkpoint=checkpoint)
    except ValueError as error:
        raise ComputerBoundaryError(str(error)) from error
    if not motion.duration_ms:
        return (plan_batch((*initial,*(mover(*s.point,desktop) for s in motion.samples),*releases),
            pointer_constraints=constraints,pointer_motion=motion),)
    segments=[(0,initial)]
    for index,sample in enumerate(motion.samples):
        segments.append((sample.offset_ms,(mover(*sample.point,desktop),
            *(releases if index==len(motion.samples)-1 else ()))))
    return (plan_timed(segments,motion.duration_ms,pointer_constraints=constraints,pointer_motion=motion),)


def _plan_input(command: str, arguments: dict, geometry, *, observed_desktop: VirtualDesktop | None = None,
                point_guard=None, default_pointer_constraints=None, planning_checkpoint=None):
    # Internal pure-planning seam for desktop images; never an MCP request field.
    if observed_desktop is not None and type(observed_desktop) is not VirtualDesktop:
        raise ComputerBoundaryError("invalid_observed_desktop")
    def _desktop():
        return virtual_desktop() if observed_desktop is None else observed_desktop
    if point_guard is not None and not callable(point_guard):
        raise ComputerBoundaryError("invalid_input_point_guard")
    def _move(x, y, desktop):
        if point_guard is not None and point_guard(x, y) is not True:
            raise ComputerBoundaryError("input_point_guard_rejected")
        return mouse_move(x, y, desktop)
    if type(arguments) is not dict or command not in (
            "text", "click", "double_click", "key", "key_mouse", "mouse_hold", "move_relative", "scroll", "drag", "move", "hover", "batch"):
        raise ComputerBoundaryError("invalid_input_command")
    pointer_fields={"path_mode","avoid_rects","drag_footprint","uncertainty_px"}
    raw_pointer={k:v for k,v in arguments.items() if k in pointer_fields}
    if raw_pointer:
        if (command not in {"move","hover","click","double_click","scroll","drag"}
                or command!="drag" and {"path_mode","drag_footprint"}&set(raw_pointer)
                or "path" in arguments and "path_mode" in raw_pointer):
            raise ComputerBoundaryError("invalid_pointer_arguments")
        arguments={k:v for k,v in arguments.items() if k not in pointer_fields}
    if command in {"click", "double_click", "drag", "mouse_hold"} and "button" not in arguments:
        # The old ordinary click/drag contract used the left button by default.
        # Normalize a copy; the original task/action request remains unchanged.
        arguments = {**arguments, "button": "left"}
    if command == "batch":
        from .computer_legacy_actions import canonical_batch
        try:
            arguments = canonical_batch(arguments)
        except ValueError as error:
            raise ComputerBoundaryError(str(error)) from error
        if (set(arguments) != {"steps"} or type(arguments["steps"]) is not list or
                not 1 <= len(arguments["steps"]) <= 32):
            raise ComputerBoundaryError("invalid_input_batch")
        result = []
        for step in arguments["steps"]:
            if (type(step) is not dict or set(step) != {"command", "arguments"} or
                    step["command"] in {"batch", "sequence", "wait", "window_move", "window_resize"}):
                raise ComputerBoundaryError("invalid_input_batch")
            result.extend(_plan_input(step["command"], step["arguments"], geometry,
                observed_desktop=observed_desktop, point_guard=point_guard,
                default_pointer_constraints=default_pointer_constraints, planning_checkpoint=planning_checkpoint))
        if (len(result) > 8192 or sum(len(batch.steps) for batch in result) > 16384 or
                sum(batch.duration_ms for batch in result if isinstance(batch, TimedInputPlan)) > 3000):
            raise ComputerBoundaryError("input_batch_too_long")
        return tuple(result)
    coordinate_space = arguments.get("coordinate_space", "client")
    if "coordinate_space" in arguments:
        if (type(coordinate_space) is not str or coordinate_space not in {
                "client", "window", "normalized_1000_client", "normalized_1000_window"} or command not in {
                "click", "double_click", "scroll", "drag", "mouse_hold", "key_mouse", "move", "hover"}
                or command == "key_mouse" and not {"button", "x", "y"} <= set(arguments)):
            raise ComputerBoundaryError("invalid_coordinate_space")
        arguments = {key: value for key, value in arguments.items() if key != "coordinate_space"}
    constraints=_pointer_constraints(raw_pointer,geometry,coordinate_space,default_pointer_constraints)
    if command == "scroll" and ({"dx", "dy"} & set(arguments)):
        if (set(arguments) != {"x", "y", "dx", "dy"}
                or any(type(arguments[key]) is not int for key in arguments)
                or any(abs(arguments[key]) > 1200 for key in ("dx", "dy"))
                or not (arguments["dx"] or arguments["dy"])):
            raise ComputerBoundaryError("invalid_input_arguments")
        try:
            x, y = _point_to_screen(geometry, arguments["x"], arguments["y"], coordinate_space)
            # Two wheel records form one bounded plan. Win32 represents the
            # axes separately; this does not claim simultaneous hardware input.
            steps = (_move(x, y, _desktop()),)
            if arguments["dy"]:
                steps += (mouse_wheel(arguments["dy"]),)
            if arguments["dx"]:
                steps += (mouse_wheel(arguments["dx"], horizontal=True),)
            return (plan_batch(steps,pointer_constraints=constraints),)
        except ValueError as error:
            raise ComputerBoundaryError("input_point_outside_client") from error
    if command in {"move", "hover"}:
        if set(arguments) != {"x", "y"} or any(type(n) is not int for n in arguments.values()):
            raise ComputerBoundaryError("invalid_input_arguments")
        try:
            return (plan_batch((_move(*_point_to_screen(geometry, arguments["x"], arguments["y"], coordinate_space), _desktop()),),
                pointer_constraints=constraints),)
        except ValueError as error:
            raise ComputerBoundaryError("input_point_outside_client") from error
    if command == "drag" and "path" in arguments:
        path = arguments["path"]
        if (type(path) is not list or not 2 <= len(path) <= 64 or
                set(arguments) - {"path", "button", "keys", "duration_ms"} or "button" not in arguments or
                any(type(p) not in (tuple, list) or len(p) != 2 or any(type(n) is not int for n in p) for p in path)):
            raise ComputerBoundaryError("invalid_input_arguments")
        try:
            points = [_point_to_screen(geometry, *point, coordinate_space) for point in path]
            if any(a == b for a, b in zip(points, points[1:])):
                raise ValueError("duplicate drag point")
            duration = arguments.get("duration_ms")
            if "duration_ms" in arguments and (type(duration) is not int or not 0 <= duration <= 3000
                    or duration and duration < len(points)-1):
                raise ValueError("invalid drag duration")
            keys = _key_batch(arguments["keys"]).steps if arguments.get("keys") else ()
            size = len(keys) // 2
            releases = (mouse_button(arguments["button"], down=False), *keys[size:])
            desktop = _desktop()
            start = (_move(*points[0], desktop), *keys[:size], mouse_button(arguments["button"], down=True))
            return _pointer_drag_plan(points,start,releases,desktop,mover=_move,duration=duration,
                path_mode="preserve",constraints=constraints,explicit_path=True,checkpoint=planning_checkpoint)
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
            if type(duration) is not int or not 0 <= duration <= 3000:
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
                initial = (_move(*_point_to_screen(geometry, arguments["x"], arguments["y"], coordinate_space), _desktop()),
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
            initial = (_move(*_point_to_screen(geometry, arguments["x"], arguments["y"], coordinate_space), _desktop()),
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
        desktop = _desktop()
        if command == "drag":
            duration = arguments.get("duration_ms")
            if "duration_ms" in arguments and (type(duration) is not int or not 0 <= duration <= 3000):
                raise ComputerBoundaryError("invalid_input_arguments")
            key_steps = _key_batch(arguments["keys"]).steps if "keys" in arguments else ()
            size = len(key_steps) // 2
            start = _point_to_screen(geometry, arguments["from_x"], arguments["from_y"], coordinate_space)
            end = _point_to_screen(geometry, arguments["to_x"], arguments["to_y"], coordinate_space)
            if start == end:
                raise ValueError("drag endpoints are equal")
            releases = (mouse_button(arguments["button"], down=False), *key_steps[size:])
            initial = (_move(*start, desktop), *key_steps[:size],
                       mouse_button(arguments["button"], down=True))
            return _pointer_drag_plan((start,end),initial,releases,desktop,mover=_move,duration=duration,
                path_mode=raw_pointer.get("path_mode","direct"),constraints=constraints,checkpoint=planning_checkpoint)
        else:
            x, y = _point_to_screen(geometry, arguments["x"], arguments["y"], coordinate_space)
            move = _move(x, y, desktop)
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
        return (plan_batch(steps,pointer_constraints=constraints),)
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
    ACTION_CHANNEL = "computer"
    PERSISTENT_INDICATOR = True
    COMPUTER_INPUT_RUN = True
    RELEASE_WARNING_SECONDS = 3.0

    @classmethod
    def _action_prefix(cls, task: str) -> str:
        return task + ":" + cls.ACTION_CHANNEL + ":"

    OBSERVATION_TTL_SECONDS = 60
    MAX_BMP_BYTES = 54 + 3840 * 2160 * 4
    MAX_WINDOW_PIXELS = 3840 * 2160
    MAX_SEQUENCE_PIXELS = MAX_WINDOW_PIXELS

    def __init__(self, store: StateStore, resolve_call: Resolver,
                 *, jev_client_factory: Callable[[], JevClient] | None = None,
                 capture_session_factory=None, high_client_factory=None, owned_window_binder=None,
                 takeover_policy=None):
        if not callable(resolve_call):
            raise TypeError("trusted resolver required")
        self.store = store
        self.resolve_call = resolve_call
        self.jev_client_factory = jev_client_factory
        self._owners: dict[str, str] = {}
        self._auxiliary_cleanup = AuxiliaryOwnerCleanup(store)
        self._observations: dict[str, dict] = {}
        self._stops: dict[str, threading.Event] = {}
        self._host_calls: dict[str, int] = {}
        self._host_tasks: dict[str, str] = {}
        self._host_gate = threading.RLock()  # Host Stop cannot share ledger waits.
        self._host_condition = threading.Condition(self._host_gate)
        self._finishing_tasks: set[str] = set()
        self._action_targets: dict[str, WindowIdentity] = {}
        self._gate = threading.RLock()
        self._capture_cache = ComputerCaptureCache(capture_session_factory) if capture_session_factory else None
        self._high = ComputerHighConnection(high_client_factory) if high_client_factory is not None else None
        self._owned_window_binder = owned_window_binder
        self._indicators = {}
        self._indicator_reads = {}
        self._indicator_cycles = {}
        self._indicator_shutdown = False
        self._task_hints = {}
        self._next_steps: dict[str, str | None] = {}
        self._text_targets = {}
        self._takeover_policy = takeover_policy

    def control_cycle_status(self, task):
        """Read this runtime's task-local HUD stop state without creating a cycle."""
        with self._gate:
            cycle = self._indicator_cycles.get(task)
            layers = [layer for (owner, _), layer in self._indicators.items() if owner == task]
            pending = sum(bool(getattr(layer, "_stop_pending", False)) for layer in layers)
            return {"runtime_present": True, "cycle_present": cycle is not None,
                    "stopped": bool(cycle and cycle.get("stop") and cycle["stop"].is_set()),
                    "stop_pending": pending > 0, "pending_layers": pending}

    def _ensure_indicator_cycle(self, task, *, display_read=False):
        cycle = self._indicator_cycles.get(task)
        if cycle is None or cycle["ended"]:
            if display_read and cycle is not None:
                return None
            for old_key, old in tuple(self._indicators.items()):
                if old_key[0] != task:
                    continue
                if not getattr(old, "_input_released", True):
                    raise IndicatorError("indicator_release_pending")
                old.close()
                if not old._closed.is_set():
                    raise IndicatorError("indicator_close_unconfirmed")
                self._indicators.pop(old_key)
            cycle = self._indicator_cycles[task] = {
                "started": time.monotonic(), "token": object(), "ended": False,
                "stop": threading.Event()}
        return cycle

    def _native_control_stop(self, task, expected_cycle=None):
        with self._gate:
            cycle = self._indicator_cycles.get(task)
            if cycle is not None and (expected_cycle is None or cycle is expected_cycle):
                cycle["native_stopped"] = True
                cycle["stop"].set()
                layers = [layer for (owner, _), layer in self._indicators.items() if owner == task
                          and getattr(layer, "_display_cycle", None) is cycle["token"]]
            else:
                layers = []
            for layer in layers:
                if hasattr(layer, "latch_external_stop"):
                    layer.latch_external_stop()
                else:
                    layer.stop_requested.set()
        for layer in layers:
            if getattr(layer, "_input_released", False):
                self._finish_indicator(layer, stopped=True, released=True)

    def _start_control_run_watch(self, task, cycle):
        if not self.COMPUTER_INPUT_RUN or self._high is None or cycle.get("watch_started"):
            return
        cycle["watch_started"] = True
        def watch():
            session = None
            try:
                while not cycle["stop"].wait(.1):
                    with self._gate:
                        if self._indicator_shutdown or cycle["ended"] or self._indicator_cycles.get(task) is not cycle:
                            return
                    if session is None:
                        session = self._high.open_monitor(task)
                    if session.computer_run_status() != cycle["broker_stop"]:
                        self._native_control_stop(task, cycle)
                        return
            except Exception as error:
                self._native_control_stop(task, cycle)
                self._indicator_display_warning("stop_monitor", error)
            finally:
                if session is not None:
                    session.close()
        cycle["watch"] = threading.Thread(target=watch, name="flower-computer-stop-status", daemon=True)
        try:
            cycle["watch"].start()
        except Exception:
            cycle["watch_started"] = False
            self._native_control_stop(task, cycle)
            raise ComputerBoundaryError("computer_stop_monitor_unavailable") from None

    def _pin_control_run(self, grant, status=None, *, display_read=False, expected_cycle=None):
        if status is None and self._high is not None and self.COMPUTER_INPUT_RUN:
            status = self._high.status(grant.task_id)
        snapshot = status.computer_run if status is not None and self.COMPUTER_INPUT_RUN else None
        with self._gate:
            old = self._indicator_cycles.get(grant.task_id)
            if expected_cycle is not None and (old is not expected_cycle or old["ended"] or old["stop"].is_set()):
                raise ComputerBoundaryError("computer_stopped")
            if expected_cycle is None and old is not None and old.get("native_stopped") and not display_read:
                if any(not getattr(layer, "_input_released", True) or getattr(layer, "_active_stop", None) is not None
                       for (task, _), layer in self._indicators.items() if task == grant.task_id):
                    raise ComputerBoundaryError("indicator_release_pending")
                if self._close_indicators(grant.task_id):
                    raise ComputerBoundaryError("indicator_stop_pending")
            cycle = self._ensure_indicator_cycle(grant.task_id, display_read=display_read)
            if cycle is None:
                return None
            if cycle["stop"].is_set():
                raise ComputerBoundaryError("input_stopped")
            if snapshot is not None:
                previous = cycle.setdefault("broker_stop", snapshot)
                if previous != snapshot:
                    self._native_control_stop(grant.task_id)
                    raise ComputerBoundaryError("computer_stopped")
                self._start_control_run_watch(grant.task_id, cycle)
            return cycle

    def _acquire_indicator(self, grant, hint, on_stop, *, paths=(), prepare=False, factory=None,
                           next_step=None, display_read=False, stop_signal=None):
        key = (grant.task_id, grant.identity)
        if self._high is not None and self.COMPUTER_INPUT_RUN:
            with self._gate:
                existing = self._indicator_cycles.get(grant.task_id)
                pinned = existing is not None and not existing["ended"] and "broker_stop" in existing
            if not pinned:
                self._pin_control_run(grant, display_read=display_read)
        with self._gate:
            if self._indicator_shutdown:
                if display_read:
                    return None
                raise IndicatorError("indicator_shutdown")
            cycle = self._ensure_indicator_cycle(grant.task_id, display_read=display_read)
            if cycle is None:
                return None
            if cycle["stop"].is_set():
                if display_read:
                    return None
                raise ComputerBoundaryError("input_stopped")
            for old_key in list(self._indicators):
                if old_key[0] == grant.task_id and old_key != key:
                    old = self._indicators[old_key]
                    if (getattr(old, "_active_stop", None) is not None or
                            not getattr(old, "_input_released", True)):
                        if display_read:
                            return old
                        raise IndicatorError("indicator_release_pending")
                    old.close()
                    if not old._closed.is_set():
                        raise IndicatorError("indicator_close_unconfirmed")
                    self._indicators.pop(old_key)
            indicator = self._indicators.get(key)
            if indicator is not None and (indicator._closed.is_set() or indicator.stop_requested.is_set() or indicator.error):
                if not getattr(indicator, "_input_released", True):
                    if display_read:
                        return indicator
                    raise IndicatorError("indicator_release_pending")
                indicator.close()
                if not indicator._closed.is_set():
                    raise IndicatorError("indicator_close_unconfirmed")
                self._indicators.pop(key)
                indicator = None
            if indicator is None:
                indicator = (factory or ForegroundIndicator)(grant.identity, hint[:80], lambda: None,
                    avoid_screen_rects=paths, prepare=prepare, stop_probe=self.store.write_stopped,
                    persistent=self.PERSISTENT_INDICATOR, channel=self.ACTION_CHANNEL)
                indicator._display_grant = grant
                indicator._display_cycle = cycle["token"]
                indicator._input_released = True
                indicator._active_stop = None
                self._bind_indicator_stop(indicator, grant, cycle, on_stop, stop_signal)
                if self.PERSISTENT_INDICATOR and hasattr(indicator, "set_task_started"):
                    indicator.set_task_started(cycle["started"])
                try:
                    indicator.start()
                except Exception:
                    # Preserve any unconfirmed close for later cleanup instead
                    # of losing the sole handle to a partly-created UI thread.
                    self._indicators[key] = indicator
                    indicator.close()
                    raise
                self._indicators[key] = indicator
            indicator._display_grant = grant
            indicator._display_cycle = cycle["token"]
            if hasattr(indicator, "set_presented"):
                indicator.set_presented(True)
            if display_read and (getattr(indicator, "_active_stop", None) is not None or
                                 not getattr(indicator, "_input_released", True)):
                return indicator
            if not display_read:
                indicator._active_stop = on_stop
                indicator._input_released = False
                indicator._input_owner = stop_signal if stop_signal is not None else on_stop
            self._bind_indicator_stop(indicator, grant, cycle,
                getattr(indicator, "_active_stop", None), stop_signal)
            recent = next((row for row in reversed(tuple(self._observations.values()))
                if row["task"] == grant.task_id and row.get("identity") == grant.identity
                and row.get("content_map") is not None and row["content_map"].fresh()), None)
            if recent is not None and hasattr(indicator, "set_content_map"):
                indicator.set_content_map(recent["content_map"])
            hint = self._task_hints.get(grant.task_id) or hint
            indicator.keep_alive(hint)
            set_next_step = getattr(indicator, "set_next_step", None)
            if set_next_step is not None:
                set_next_step(next_step if next_step is not None else self._next_steps.get(grant.task_id))
            indicator.reserve_mouse_paths(paths)
            return indicator

    def _release_phase_presentation(self, task, owner, *, terminal, validate):
        """Called only under idle cleanup's exact-task admission guard."""
        with self._gate:
            if self._owners.get(task) != owner:
                raise ControlError("host_phase_wrong_owner")
            cycle = self._indicator_cycles.get(task)
            layers = [(key, layer) for key, layer in self._indicators.items() if key[0] == task]
            if any(not getattr(layer, "_input_released", True) or
                   getattr(layer, "_active_stop", None) is not None or
                   getattr(layer, "_stop_pending", False) for _key, layer in layers):
                raise ControlError("phase_cleanup_calls_in_flight")
        # Commit this final watermark check before changing RAM or windows. No
        # runtime gate is acquired while the SQLite write transaction is held.
        with self.store.transaction(timeout=.02) as db:
            validate(db)
        with self._gate:
            if self._owners.get(task) != owner or self._indicator_cycles.get(task) is not cycle:
                raise ControlError("host_phase_superseded")
            if any(getattr(layer, "_stop_pending", False) for _key, layer in layers):
                raise ControlError("indicator_stop_pending")
            if terminal and cycle is not None:
                cycle["ended"] = True
                self._task_hints.pop(task, None)
                self._next_steps.pop(task, None)
                self._text_targets.pop(task, None)
        for key, layer in layers:
            if not terminal:
                if hasattr(layer, "set_presented"):
                    layer.set_presented(False)
                continue
            layer.close()
            if not layer._closed.is_set():
                raise ControlError("indicator_close_unconfirmed")
            with self._gate:
                if self._indicators.get(key) is layer:
                    self._indicators.pop(key)

    def _bind_indicator_stop(self, indicator, grant, cycle, on_stop, stop_signal=None):
        """Freeze the exact action callback; a late click cannot stop a new run."""
        if indicator.stop_requested.is_set():
            return
        binding = object()
        signals = (cycle.setdefault("stop", threading.Event()),)
        if stop_signal is not None:
            signals += (stop_signal,)

        def persist_stop():
            # Mouse-down has already set both Events without taking either
            # runtime lock. Only durable cleanup uses this admission guard.
            while True:
                with self._host_condition:
                    with self._gate:
                        current = self._indicator_cycles.get(grant.task_id)
                        if (current is not cycle or current["ended"] or
                                indicator._stop_owner_binding is not binding or
                                self._indicators.get((grant.task_id, grant.identity)) is not indicator):
                            return False
                    if grant.task_id not in self._finishing_tasks:
                        self._finishing_tasks.add(grant.task_id)
                        break
                    self._host_condition.wait(.02)
            try:
                # Phase cleanup can release this task's claim while the
                # persistent HUD or its frozen action callback still exists.
                # Rebind the exact grant under the finish admission; another
                # task's ownership is still rejected.
                _, resource = self._owner(grant)
                if on_stop is not None:
                    on_stop()
                else:
                    self.store.pause_computer_target(grant.task_id, resource)
                    self._stop_idle_indicators(grant.task_id, grant.identity)
                return True
            finally:
                with self._host_condition:
                    self._finishing_tasks.discard(grant.task_id)
                    self._host_condition.notify_all()

        bind = getattr(indicator, "bind_stop", None)
        if bind is not None:
            bind(persist_stop, *signals, owner_token=binding)
        else:
            # Older presentation test doubles keep the original callback field.
            indicator.on_stop = indicator.callback = persist_stop
            indicator._stop_owner_binding = binding

    def _finish_indicator(self, indicator, *, stopped=False, released=True, action_owner=None):
        if indicator is None:
            return
        try:
            terminal_stop = stopped or indicator.stop_requested.is_set() or self.store.write_stopped()
            with self._gate:
                # The same layer can already belong to a later action by the
                # time an earlier action reaches its finally block. Its exact
                # stop Event is also the action's presentation owner.
                if action_owner is not None and getattr(indicator, "_input_owner", None) is not action_owner:
                    return
                grant = getattr(indicator, "_display_grant", None)
                cycle = self._indicator_cycles.get(grant.task_id) if grant is not None else None
                if grant is not None and (cycle is None or cycle["ended"] or
                        getattr(indicator, "_display_cycle", None) is not cycle["token"] or
                        self._indicators.get((grant.task_id, grant.identity)) is not indicator):
                    return
                indicator._active_stop = None
                indicator._input_released = bool(released)
                if released and not indicator.stop_requested.is_set() and cycle is not None:
                    self._bind_indicator_stop(indicator, grant, cycle, None)
                if terminal_stop:
                    indicator.set_stage("stopped" if released else "release_unconfirmed",
                        checkpoint="写入已停止" if released else "输入释放尚未确认",
                        input_release="released" if released else "unknown")
                    indicator.close()
                    # A pending callback still needs its exact RAM binding.
                    if not getattr(indicator, "_stop_pending", False):
                        self._forget_indicator(indicator)
                elif not self.PERSISTENT_INDICATOR:
                    indicator.set_stage("idle" if released else "release_unconfirmed",
                        checkpoint="本次输入已结束，键鼠已释放" if released else "输入释放尚未确认",
                        input_release="released" if released else "unknown")
                    indicator.close()
                    self._forget_indicator(indicator)
                elif not released:
                    indicator.set_stage("release_unconfirmed", checkpoint="输入释放尚未确认",
                                        input_release="unknown")
                    if hasattr(indicator, "linger"):
                        indicator.linger(self.RELEASE_WARNING_SECONDS)
                    else:
                        indicator.close()
                        self._forget_indicator(indicator)
                else:
                    # Reader/input acquisition cannot interleave with release
                    # ownership checks and presentation changes.
                    if not self._restore_read_indicator(indicator):
                        indicator.set_stage("idle", checkpoint="本次输入已结束，键鼠已释放",
                                            input_release="released")
                        # Input is released independently of presentation.
                        # Keep this GUI phase visible through model latency;
                        # trusted backend/terminal events hide or close it.
                        indicator.keep_alive()
        except Exception as error:
            # A presentation failure after dispatch never replaces the business
            # receipt or tells the caller to repeat the action.
            self._indicator_display_warning("finish", error)

    def _forget_indicator(self, indicator):
        with self._gate:
            for (task, _target), current in tuple(self._indicators.items()):
                if current is indicator:
                    self._next_steps.pop(task, None)
                    self._indicators.pop((task, _target), None)

    @staticmethod
    def _indicator_display_warning(stage, error):
        from .host_cleanup import cleanup_event
        cleanup_event({"event": "computer_indicator_display_unavailable", "stage": stage,
                       "failure_type": type(error).__name__})

    def _indicator_stopped(self, grant):
        if self.store.task_write_stopped(grant.task_id):
            return True
        with self.store.read_transaction() as db:
            row = db.execute("SELECT paused FROM resources WHERE id=?", (self._resource(grant.identity),)).fetchone()
            return bool(row and row[0])

    def _stop_idle_indicators(self, task, identity=None):
        with self._gate:
            indicators = [(indicator, getattr(indicator, "_input_owner", None))
                          for (owner, target), indicator in self._indicators.items()
                          if owner == task and (identity is None or target == identity)
                          and getattr(indicator, "_active_stop", None) is None]
        for indicator, action_owner in indicators:
            self._finish_indicator(indicator, stopped=True,
                released=getattr(indicator, "_input_released", False), action_owner=action_owner)

    def _close_indicators(self, task=None):
        # Older runtime fixtures and recovery paths can carry only the
        # indicator table. Missing cycle bookkeeping must not turn a best-effort
        # presentation cleanup into an AttributeError that leaves every HUD
        # window behind.
        cycles = getattr(self, "_indicator_cycles", None)
        if cycles is None:
            cycles = self._indicator_cycles = {}
        with self._gate:
            if task is not None:
                pending = sum(bool(getattr(layer, "_stop_pending", False))
                    for (owner, _target), layer in self._indicators.items() if owner == task)
                if pending:
                    return pending
            if task is None:
                self._indicator_shutdown = True
            elif task not in cycles:
                cycles[task] = {"started": time.monotonic(), "token": object(), "ended": True}
            for owner, cycle in cycles.items():
                if task is None or owner == task:
                    cycle["ended"] = True
            keys = [key for key in self._indicators if task is None or key[0] == task]
            indicators = [(key, self._indicators[key]) for key in keys]
        pending = 0
        for key, indicator in indicators:
            try:
                indicator.close()
            except Exception as error:
                self._indicator_display_warning("close", error)
                pending += 1
                continue
            if not indicator._closed.is_set():
                pending += 1
                continue
            with self._gate:
                if self._indicators.get(key) is indicator:
                    self._indicators.pop(key)
        return pending

    @contextmanager
    def _resume_indicator_admission(self, task):
        with self._gate:
            layers = [layer for (owner, _), layer in self._indicators.items() if owner == task]
        for layer in layers:
            if getattr(layer, "_stop_pending", False) and hasattr(layer, "retry_pending_stop"):
                layer.retry_pending_stop(timeout=.2)
        with self._host_condition:
            if task in self._finishing_tasks or task in self._host_tasks.values():
                raise ControlError("phase_cleanup_in_progress")
            with self._gate:
                if any(getattr(layer, "_stop_pending", False)
                       for (owner, _), layer in self._indicators.items() if owner == task):
                    raise ControlError("indicator_stop_pending")
                if any(not getattr(layer, "_input_released", True)
                       for (owner, _), layer in self._indicators.items() if owner == task):
                    raise ControlError("input_release_unconfirmed")
            self._finishing_tasks.add(task)
        try:
            yield
        finally:
            with self._host_condition:
                self._finishing_tasks.discard(task)
                self._host_condition.notify_all()

    def _retire_resumed_cycle(self, task):
        # Only an explicit, successfully verified resume reaches this helper.
        with self._host_gate:
            if task in self._host_tasks.values():
                raise ControlError("phase_cleanup_in_progress")
            with self._gate:
                cycle = self._indicator_cycles.get(task)
                if cycle is None or cycle.get("stop") is None or not cycle["stop"].is_set():
                    return
                layers = [layer for (owner, _), layer in self._indicators.items() if owner == task]
                if any(not getattr(layer, "_input_released", True) or getattr(layer, "_stop_pending", False) for layer in layers):
                    raise ControlError("indicator_stop_pending")
            with self.store.read_transaction() as db:
                self.store._require_input_release_confirmed(db, task=task, action_prefix=self._action_prefix(task))
            if self._close_indicators(task):
                raise ControlError("indicator_close_unconfirmed")

    def _refresh_indicator_text(self, task, identity):
        # Observation updates display only; it cannot acquire a HUD, a window
        # or the foreground input lane.
        with self._gate:
            for (owner, target), indicator in self._indicators.items():
                if owner == task and target == identity and not indicator._closed.is_set():
                    indicator.set_task_hint(self._task_hints.get(task))
                    indicator.set_next_step(self._next_steps.get(task))

    def _set_indicator_text(self, grant, next_step, goal_hint=None, *, task_purpose=None,
                            preserve_if_omitted=False):
        with self._gate:
            if self.PERSISTENT_INDICATOR and preserve_if_omitted:
                cycle = self._indicator_cycles.get(grant.task_id)
                if cycle is not None and cycle["ended"]:
                    return
                if any(task == grant.task_id and getattr(layer, "_active_stop", None) is not None
                       for (task, _), layer in self._indicators.items()):
                    return
            if not self.PERSISTENT_INDICATOR and self._text_targets.get(grant.task_id) != grant.identity:
                self._task_hints.pop(grant.task_id, None)
                self._next_steps.pop(grant.task_id, None)
            self._text_targets[grant.task_id] = grant.identity
            purpose = task_purpose if task_purpose is not None else goal_hint
            if purpose:
                self._task_hints[grant.task_id] = purpose[:TASK_PURPOSE_LIMIT]
            if next_step is None and not preserve_if_omitted:
                self._next_steps.pop(grant.task_id, None)
            elif next_step is not None:
                self._next_steps[grant.task_id] = next_step

    @contextmanager
    def _observation_indicator(self, grant, *, waiting=False):
        token = object()
        indicator = None
        if self.PERSISTENT_INDICATOR:
            try:
                with self._gate:
                    cycle = self._indicator_cycles.get(grant.task_id)
                    if (grant.task_id not in self._finishing_tasks and
                            (not cycle or not cycle["ended"]) and not self._indicator_stopped(grant)):
                        indicator = self._acquire_indicator(grant,
                            self._task_hints.get(grant.task_id) or "读取目标窗口", None, display_read=True,
                            next_step=self._next_steps.get(grant.task_id))
                        cycle = self._indicator_cycles.get(grant.task_id)
                        if indicator is not None and cycle is not None and not cycle["ended"]:
                            self._indicator_reads[token] = (grant, bool(waiting), cycle["token"])
                            self._restore_read_indicator(indicator)
            except Exception as error:
                self._indicator_display_warning("observe", error)
        try:
            yield
        finally:
            try:
                with self._gate:
                    self._indicator_reads.pop(token, None)
                    if indicator is not None:
                        current = next((layer for (task, _), layer in self._indicators.items()
                            if task == grant.task_id), None)
                        if current is not None and not self._restore_read_indicator(current):
                            cycle = self._indicator_cycles.get(grant.task_id)
                            if (cycle is not None and not cycle["ended"] and
                                    not current._closed.is_set() and not current.stop_requested.is_set() and
                                    getattr(current, "_active_stop", None) is None and
                                    getattr(current, "_input_released", True) and
                                    not self._indicator_stopped(grant)):
                                current.set_stage("idle", checkpoint="观察已完成，当前未发送输入", input_release="released")
                                # The same GUI phase can wait for a later model
                                # response without inventing a hide deadline.
            except Exception as error:
                self._indicator_display_warning("read_restore", error)

    def _restore_read_indicator(self, indicator):
        with self._gate:
            owner = next((task for (task, _target), layer in self._indicators.items()
                if layer is indicator), None)
            cycle = self._indicator_cycles.get(owner)
            if (cycle is None or cycle["ended"] or indicator._closed.is_set() or
                    indicator.stop_requested.is_set() or not getattr(indicator, "_input_released", True) or
                    getattr(indicator, "_active_stop", None) is not None or
                    self._indicator_stopped(indicator._display_grant)):
                return False
            readers = [row for row in self._indicator_reads.values()
                if row[0].task_id == owner and row[2] is cycle["token"]]
            if not readers:
                return False
            grant, waiting, _ = next((row for row in reversed(readers) if row[1]), readers[-1])
            if grant.identity != indicator.identity:
                indicator = self._acquire_indicator(grant,
                    self._task_hints.get(owner) or "读取目标窗口", None, display_read=True,
                    next_step=self._next_steps.get(owner))
                if indicator is None:
                    return False
            indicator.set_stage("wait" if waiting else "observe",
                checkpoint="等待目标条件满足" if waiting else "读取目标窗口")
            return True

    def _capture(self, grant, *, preflight, stopped):
        from flower_control.privacy import capture_private
        from flower_control.permissions import PermissionError
        def capture():
            if self._capture_cache is None:
                return capture_window(grant.identity, preflight=preflight, stopped=stopped)
            return self._capture_cache.capture(grant, preflight=preflight, stopped=stopped, fallback=capture_window)
        try:
            result = capture_private(grant.identity, capture, preflight=preflight, stopped=stopped, task=grant.task_id)
        except PermissionError as error:
            failure = ComputerBoundaryError(error.code)
            if getattr(error, "privacy_diagnostics", None) is not None:
                failure.privacy_diagnostics = error.privacy_diagnostics
            raise failure from None
        preflight()
        return result

    def close_capture_sessions(self):
        from .host_cleanup import cleanup_warning
        from .human_handoff import close_handoffs
        def indicators():
            if self._close_indicators():
                raise ComputerBoundaryError("indicator_cleanup_pending")
        steps = [("indicators", indicators), ("handoffs", lambda: close_handoffs(self.store))]
        if self._capture_cache is not None:
            steps.append(("capture_cache", self._capture_cache.close))
        if self._high is not None:
            steps.append(("high_bridge", self._high.close))
        first_error = None
        for phase, operation in steps:
            try:
                operation()
            except Exception as error:
                cleanup_warning("computer", phase, error)
                if first_error is None:
                    first_error = error
        if first_error is not None:
            raise first_error

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
                      grant.shared_resource.startswith("web-session:") or
                      grant.shared_resource.startswith("web-borrower:")))):
            raise ComputerBoundaryError("invalid_shared_resource")
        if grant.expires_at <= self.store.clock():
            raise ComputerBoundaryError("trusted_call_expired")
        from .computer_plan import compound_guard
        outer_guard=compound_guard.get()
        if outer_guard is not None:
            original_guard=grant.execution_guard
            def guarded_compound_call():
                outer_guard()
                if original_guard is not None:original_guard()
            grant=replace(grant,execution_guard=guarded_compound_call)
        from .pointer_geometry import MotionConstraints
        if (grant.pointer_constraints is not None and type(grant.pointer_constraints) is not MotionConstraints
                or grant.execution_guard is not None and not callable(grant.execution_guard)
                or type(grant.suppress_pointer_approach) is not bool
                or grant.request_fingerprint is not None and (type(grant.request_fingerprint) is not str
                    or len(grant.request_fingerprint)!=64
                    or any(c not in '0123456789abcdef' for c in grant.request_fingerprint))):
            raise ComputerBoundaryError('invalid_authorization_scope')
        if grant.execution_guard is not None:grant.execution_guard()
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

    @classmethod
    def _key(cls, task: str, action_id: str) -> str:
        if type(action_id) is not str or not 1 <= len(action_id) <= 128:
            raise ComputerBoundaryError("invalid_action_id")
        return cls._action_prefix(task) + action_id

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
        return {"format": "bmp", "_bmp": result.bmp,
                "width": result.width, "height": result.height,
                "source_bounds": asdict(result.source_bounds), "backend": result.source,
                "source_bounds_space": "physical_screen_pixels",
                "fallback_reason": result.fallback_reason,
                "privacy_revision": result.privacy_revision,
                "masked_regions": len(result.privacy_rects),
                "content_verified": False, "elapsed_ms": result.elapsed_ms,
                **({"capture_stage_timings_ms": result.capture_stage_timings_ms}
                   if result.capture_stage_timings_ms is not None else {})}

    def authorize_visual_return(self, tool: str, payload: dict,
                                trusted_task: str, *, policy_revision=None) -> None:
        """Last local gate before captured pixels become an MCP ImageContent."""
        if tool not in ("flower_computer_observe", "flower_computer_activate",
                        "flower_computer_input"):
            raise ComputerBoundaryError("invalid_visual_return")
        from flower_control.permissions import revision, PermissionError
        try:
            if (policy_revision or "absent") != revision():
                raise ComputerBoundaryError("user_policy_requires_new_observation")
        except PermissionError as error:
            raise ComputerBoundaryError(error.code) from None
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
                if row and (row["paused"] or not read_only and self.store._effective_quarantine(db, item, row)):
                    raise ControlError("resource_paused_or_quarantined")

    def bind_returned_image(self, observation_id, *, trusted_task, view_metadata):
        """Internal PNG return path only; binding creates no new observation."""
        return self.bind_returned_images([(observation_id, view_metadata)], trusted_task=trusted_task)[0]

    def bind_returned_images(self, presentations, *, trusted_task):
        """Validate a complete reply before publishing any of its image views."""
        from .computer_returned_points import ReturnedImageView
        pending, results = [], []
        with self._gate:
            for observation_id, metadata in presentations:
                observed = self._observations.get(observation_id)
                if observed is None or observed['expires'] <= self.store.clock():
                    results.append(False)
                    continue
                if observed['task'] != trusted_task:
                    raise ComputerBoundaryError('ticket_task_mismatch')
                original = (observed['image_width'], observed['image_height'])
                try:
                    if tuple(metadata.get('original_size', original)) != original:
                        raise ValueError('returned_image_view_changed')
                    view = ReturnedImageView(original,
                        tuple(metadata.get('original_image_box', (0, 0, *original))),
                        (metadata.get('width', original[0]), metadata.get('height', original[1])))
                except (TypeError, ValueError) as error:
                    raise ComputerBoundaryError(str(error)) from error
                previous = observed.get('returned_image_view')
                if previous is not None and previous != view:
                    raise ComputerBoundaryError('returned_image_view_changed')
                if any(item is observed and prior != view for item, prior in pending):
                    raise ComputerBoundaryError('returned_image_view_changed')
                pending.append((observed, view))
                results.append(True)
            for observed, view in pending:
                observed['returned_image_view'] = view
        return results

    @planned_app_call
    def observe(self, target: dict, action_id: str, goal_hint: str | None = None,
                *, next_step: str | None = None, task_purpose: str | None = None, crop=None, max_size=None,
                crop_format=None,
                trusted_task: str | None = None) -> dict:
        payload = {"target": target, "action_id": action_id}
        from .computer_image_view import validate_view
        try:
            validate_view(crop, max_size, crop_format=crop_format)
        except ValueError as error:
            raise ComputerBoundaryError(str(error)) from error
        if crop is not None:
            payload["crop"] = crop
        if crop_format is not None:
            payload["crop_format"] = crop_format
        if max_size is not None:
            payload["max_size"] = max_size
        if goal_hint is not None:
            payload["goal_hint"] = goal_hint
        next_step = valid_next_step(next_step)
        task_purpose = valid_task_purpose(task_purpose)
        if task_purpose is not None:
            payload['task_purpose'] = task_purpose
        if next_step is not None:
            payload["next_step"] = next_step
        grant = self._authorized("flower_computer_observe", payload, target, "capture",
                                 trusted_task=trusted_task)
        self._set_indicator_text(grant, next_step, goal_hint, task_purpose=task_purpose,
                                 preserve_if_omitted=True)
        with self._observation_indicator(grant):
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
                        "deadline_expired",
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
                                    assessment_questions=(),
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
                    action_id=self._key(grant.task_id, action_id), prefer_batch=True))
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
            result = outcome.get("result")
            if isinstance(result, dict) and result.get("state") != "observed":
                raise AppBoundaryError(result.get("reason") or "uia_observation_unavailable")
            if not isinstance(result, dict):
                raise AppBoundaryError(outcome.get("error") or "uia_observation_unavailable")
        finally:
            try:
                # The helper read is temporary, not another live App session.
                # Keep its historical receipt/claim as an inactive tombstone;
                # the parent Computer owner still protects this target.
                self._auxiliary_cleanup.retire(grant.task_id, tuple(runtime._owners.values()),
                                               primary_error=sys.exc_info()[1])
            finally:
                if bridge is not None:
                    bridge.close()
        if isinstance(result, dict) and grant.shared_resource is not None:
            snapshot = runtime._observations.get(outcome.get("observation_id"))
            if not snapshot or snapshot.get("shared_revision") is None:
                return None
            result = {**result, "_shared_revision": snapshot["shared_revision"]}
        return result

    @planned_app_call
    def activate(self, target: dict, restore_minimized: bool, action_id: str,
                 *, next_step: str | None = None, task_purpose: str | None = None,
                 trusted_task: str | None = None) -> dict:
        payload = {"target": target, "restore_minimized": restore_minimized,
                   "action_id": action_id}
        next_step = valid_next_step(next_step)
        task_purpose = valid_task_purpose(task_purpose)
        if task_purpose is not None:
            payload['task_purpose'] = task_purpose
        if next_step is not None:
            payload["next_step"] = next_step
        grant = self._authorized("flower_computer_activate", payload, target, "input",
                                 trusted_task=trusted_task)
        self._set_indicator_text(grant, next_step, task_purpose=task_purpose)
        if not grant.capture_allowed:
            raise ComputerBoundaryError("capture_not_approved")
        if type(restore_minimized) is not bool:
            raise ComputerBoundaryError("invalid_activation_request")
        owner, resource = self._owner(grant)
        self._recover_shared_front_for_new_target(grant, resource)
        return self._measure_call(grant, action_id, None, lambda:
            self._execute(owner, resource, grant, action_id, "activate", payload,
                          restore_minimized=restore_minimized))

    @planned_app_call
    def input(self, target: dict, observation_id: str, command: str,
              arguments: dict, action_id: str,
              *, next_step: str | None = None, task_purpose: str | None = None,
              trusted_task: str | None = None) -> dict:
        payload = {"target": target, "observation_id": observation_id,
                   "command": command, "arguments": arguments, "action_id": action_id}
        next_step = valid_next_step(next_step)
        task_purpose = valid_task_purpose(task_purpose)
        if task_purpose is not None:
            payload['task_purpose'] = task_purpose
        if next_step is not None:
            payload["next_step"] = next_step
        grant = self._authorized("flower_computer_input", payload, target, "input",
                                 trusted_task=trusted_task)
        self._set_indicator_text(grant, next_step, task_purpose=task_purpose)
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
        last_planning_check = [None]
        def planning_checkpoint():
            now = time.monotonic()
            if last_planning_check[0] is not None and now - last_planning_check[0] < .02:
                return
            last_planning_check[0] = now
            if self.store.task_write_stopped(grant.task_id, observation=observation_id):
                raise ComputerBoundaryError("input_stopped")
            with self._gate:
                pending_stop = self._stops.get(self._key(grant.task_id, action_id))
            if pending_stop is not None and pending_stop.is_set():
                raise ComputerBoundaryError("input_stopped")
        geometry = observed["geometry"]
        from .computer_returned_points import map_returned_points
        try:
            arguments = map_returned_points(command, arguments, observed)
        except ValueError as error:
            raise ComputerBoundaryError(str(error)) from error
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
                                    assessment_questions=(),
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
                        action_id=key, prefer_batch=True))
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
            from .computer_wait import wait_timeout_ms
            try:
                wait_timeout_ms(arguments)
            except ValueError as error:
                raise ComputerBoundaryError(str(error)) from None
            if arguments["condition"] in {"image_changed", "image_unchanged", "image_stable"}:
                from .visual_conditions import VisualCondition
                baseline = replace(observed["capture_descriptor"], bmp=zlib.decompress(observed["capture_compressed"]))
                try:
                    VisualCondition(arguments["condition"], baseline, roi=arguments.get("roi"), stable_ms=arguments.get("stable_ms", 300),
                                    roi_units=arguments.get("roi_units", "pixels"), threshold=arguments.get("threshold"))
                except ValueError as error:
                    raise ComputerBoundaryError(str(error)) from None
            owner, resource = self._owner(grant)
            with self._observation_indicator(grant, waiting=True):
                return self._execute(owner, resource, grant, action_id, "wait", payload,
                                     observation=observation_id, generation=observed["generation"],
                                     wait_observation=observed)
        sequence = None
        resolved_click = None
        semantic_candidate = None
        if command == "sequence":
            if (type(arguments) is not dict or set(arguments) != {"steps"} or
                    type(arguments["steps"]) is not list or
                    not 2 <= len(arguments["steps"]) <= 8):
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
                batches = _plan_input(step["command"], step["arguments"], geometry,
                    default_pointer_constraints=grant.pointer_constraints, planning_checkpoint=planning_checkpoint)
                if (any(isinstance(batch, TimedInputPlan) and not (
                        step["command"] == "drag" and batch.pointer_motion and batch.pointer_motion.automatic)
                        for batch in batches) or sum(len(batch.steps) for batch in batches) > 128):
                    raise ComputerBoundaryError("sequence_step_too_long")
                planned.append((step["command"], batches[0] if len(batches) == 1 else tuple(batches), step["expect"]))
            if sum(batch.duration_ms for _, item, _ in planned for batch in sequence_batches(item)
                    if isinstance(batch, TimedInputPlan)) > 3000:
                raise ComputerBoundaryError("sequence_step_too_long")
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
                batches = _plan_input("click", {"x": point[0], "y": point[1], "button": "left"}, geometry,
                    default_pointer_constraints=grant.pointer_constraints)
            elif command == "click_region":
                resolved_click = _click_point_from_region(arguments, observed)
                click_arguments = {"x": resolved_click[0], "y": resolved_click[1],
                                   "button": arguments["button"]}
                batches = _plan_input("click", click_arguments, geometry,
                    default_pointer_constraints=grant.pointer_constraints)
            else:
                batches = (early_batches if early_batches is not None else
                           _plan_input(command, arguments, geometry,
                               default_pointer_constraints=grant.pointer_constraints, planning_checkpoint=planning_checkpoint))
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
        fingerprint = grant.request_fingerprint or hashlib.sha256(json.dumps([command, payload], sort_keys=True,
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
                      result_report: dict | None = None, wait_seconds: int | None = None,
                      stopped=None) -> dict:
        if wait_seconds is not None and (type(wait_seconds) is not int or not 0 <= wait_seconds <= 30):
            raise ComputerBoundaryError('invalid_status_wait')
        if wait_seconds and result_report is not None:
            raise ComputerBoundaryError('status_wait_report_requires_immediate_read')
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
            if wait_seconds is not None:
                payload['wait_seconds'] = wait_seconds
            grant = self._authorized("flower_computer_action_status", payload)
            task = grant.task_id
            key = self._key(task, action_id)
            with self._gate:
                owner = self._owners.get(task)
                target = self._action_targets.get(key)
            receipt = (self.store.computer_sequence_status_for_task(
                task, key, self._resource(grant.identity))
                if owner is None or target != grant.identity else self.store.queue_status(owner, key))
        if wait_seconds:
            from .computer_status_wait import wait_action_receipt
            recovery = receipt.get('release_recovery')
            def snapshot():
                value = (self.store.diagnostic_action_for_task(task,key) if owner is None
                         else self.store.queue_status(owner,key))
                return {**value,'release_recovery':recovery} if recovery is not None else value
            receipt = wait_action_receipt(receipt,snapshot,seconds=wait_seconds,
                stopped=stopped or (lambda:False),task_stopped=lambda:self.store.task_write_stopped(task))
            if recovery is not None:
                receipt['status_wait']['native_release_check'] = 'initial_only'
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
            with self._host_gate:
                event = self._stops.get(key)
            if event is not None:
                event.set()
            receipt = self.store.diagnostic_action_for_task(trusted_task, key, cancel=True)
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
        if event is not None:
            event.set()
        receipt = self.store.cancel(owner, key)
        return {"action_id": action_id, **receipt}

    def begin_host_call(self, task: str, action_id: str) -> str:
        """Register before starting a thread, closing the cancellation race."""
        key = self._key(task, action_id)
        with self._host_gate:
            if task in self._finishing_tasks:
                raise ComputerBoundaryError("computer_task_finishing")
            self._stops.setdefault(key, threading.Event())
            self._host_calls[key] = self._host_calls.get(key, 0) + 1
            self._host_tasks[key] = task
        return key

    def end_host_call(self, key: str, *, on_pending_cleanup=None) -> dict | None:
        with self._host_gate:
            task = self._host_tasks.get(key)
            count = self._host_calls.get(key, 0)
            if count <= 1:
                self._host_calls.pop(key, None)
                self._stops.pop(key, None)
                self._host_tasks.pop(key, None)
            else:
                self._host_calls[key] = count - 1
            self._host_condition.notify_all()
            idle = task is not None and task not in self._host_tasks.values()
        if not idle:
            return None
        with self._gate:
            owner = self._owners.get(task)
        prefix = self._action_prefix(task)
        try:
            with self.store.read_transaction() as db:
                self.store._require_input_release_confirmed(db, task=task,
                    action_prefix=prefix)
            ownership = (self.store.finish_owned_resources(owner, phase_release=True,
                preserve_observations=True) if owner else {"released": 0, "retained_for_peer_or_unresolved": 0})
            return {"state": "released", "input_release": "released", "target_ownership": ownership,
                "task_finished": False, "selection_preserved": True, "old_actions_replayed": False}
        except (ControlError, sqlite3.Error) as error:
            if on_pending_cleanup is not None:
                from .idle_phase_cleanup import idle_release_callback
                on_pending_cleanup(idle_release_callback(self, task, owner, prefix))
            return {"state": "release_pending", "reason": getattr(error, "code", "control_ledger_unavailable"),
                "task_finished": False, "old_actions_replayed": False}

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
        from .human_handoff import close_handoffs
        close_handoffs(self.store)

    def pause(self, mode: str | None = None,
              *, trusted_task: str | None = None, message: str | None = None, timeout_seconds: int | None = None,
              kind: str | None = None) -> dict:
        payload = {} if mode is None else {"mode": mode}
        if kind is not None:
            from flower_control.control.state import human_handoff_kind
            if mode != "handoff":
                raise ComputerBoundaryError("invalid_handoff_kind")
            try:
                human_handoff_kind(kind)
            except ControlError as error:
                raise ComputerBoundaryError(error.code) from None
            payload["kind"] = kind
        if message is not None:
            if (mode != "handoff" or type(message) is not str or not 1 <= len(message.strip()) <= 240
                    or any(ord(char) < 32 for char in message)):
                raise ComputerBoundaryError("invalid_handoff_message")
            payload["message"] = message
        if timeout_seconds is not None:
            if mode != "handoff" or type(timeout_seconds) is not int or not 10 <= timeout_seconds <= 3600:
                raise ComputerBoundaryError("invalid_handoff_timeout")
            payload["timeout_seconds"] = timeout_seconds
        if mode in {"finish", "release_phase"}:
            # Trusted origin binds this cleanup to a chat. Finishing reads no
            # window content and must remain usable after the target closes.
            task = trusted_task if trusted_task is not None else self._authorized(
                "flower_computer_pause", payload).task_id
            return self._release_phase(task) if mode == "release_phase" else self._finish_task(task)
        if trusted_task is not None and mode in {None, "pause", "handoff"}:
            with self._host_gate:
                for key, event in self._stops.items():
                    if self._host_tasks.get(key) == trusted_task:
                        event.set()
            with self._gate:
                cycle = self._indicator_cycles.get(trusted_task)
                if cycle is not None and cycle.get("stop") is not None:
                    cycle["stop"].set()
        grant = self._authorized("flower_computer_pause", payload,
                                 trusted_task=trusted_task)
        if mode == "resume":
            with self._resume_indicator_admission(grant.task_id):
                assert_window(grant.identity)
                _, resource = self._owner(grant)
                snapshot = self.store.computer_resume_snapshot(grant.task_id, resource)
                if snapshot is None:
                    if self._takeover_policy is not None:
                        self._takeover_policy.resume(grant.task_id)
                    self._retire_resumed_cycle(grant.task_id)
                    return {"state": "already_active", "requires_new_observation": True}
                self._authorized("flower_computer_pause", payload, asdict(grant.identity),
                                 trusted_task=grant.task_id)
                assert_window(grant.identity)
                with self.store.read_transaction() as db:
                    self.store._require_scope(db, grant.task_id, grant.target_scope)
                self.store.resume_computer_from_chat_request(grant.task_id, resource, snapshot)
                from .human_handoff import explicit_resume_handoffs
                explicit_resume_handoffs(self.store, grant.task_id)
                if self._takeover_policy is not None:
                    self._takeover_policy.resume(grant.task_id)
                self._retire_resumed_cycle(grant.task_id)
                return {"state": "resumed", "requires_new_observation": True,
                        "resume_source": "trusted_chat_request", "foreground_activated": False}
        if mode not in (None, "pause", "handoff"):
            raise ComputerBoundaryError("invalid_pause_mode")
        with self._host_gate:
            events = [event for key, event in self._stops.items()
                      if (key.startswith(self._action_prefix(grant.task_id)) and
                          self._action_targets.get(key) == grant.identity)]
        for event in events:
            event.set()
        with self._gate:
            cycle = self._indicator_cycles.get(grant.task_id)
            if cycle is not None and cycle.get("stop") is not None:
                cycle["stop"].set()
        _, resource = self._owner(grant)
        self.store.pause_computer_target(grant.task_id, resource,
            reason="human_handoff" if mode == "handoff" else "user_pause")
        if mode == "handoff":
            # Human secret entry must not be observed through a sibling channel
            # in this chat. This pauses existing authority; it grants nothing.
            self.store.pause_task(grant.task_id, reason="human_handoff")
        self._stop_idle_indicators(grant.task_id, grant.identity)
        if mode == "handoff":
            deadline = time.monotonic() + 2
            with self._host_condition:
                self._host_condition.wait_for(lambda: not any(
                    key.startswith(self._action_prefix(grant.task_id)) for key in self._host_calls),
                    timeout=max(0, deadline-time.monotonic()))
            with self.store.read_transaction() as db:
                running = db.execute("SELECT 1 FROM actions WHERE task=? AND state='running' LIMIT 1",
                                     (grant.task_id,)).fetchone() is not None
                unresolved = db.execute("SELECT 1 FROM input_release_bindings b JOIN actions a ON a.id=b.action "
                    "WHERE a.task=? AND b.confirmed IS NULL LIMIT 1", (grant.task_id,)).fetchone() is not None
                try:
                    self.store._require_input_release_confirmed(db, task=grant.task_id)
                except ControlError as error:
                    if error.code != "input_release_unconfirmed":
                        raise
                    unresolved = True
            handoff = self.store.begin_human_handoff(grant.task_id,
                timeout_seconds=300 if timeout_seconds is None else timeout_seconds, kind=kind)
            popup = {"state": "waiting_for_input_release"}
            if not running and not unresolved:
                from .human_handoff import show_handoff
                popup = show_handoff(self.store, grant.task_id, handoff["request_id"], message or "请完成这一步后明确继续")
            return {"state": "human_action_required", "message": message or "请完成这一步后明确继续",
                    "input_release": "pending" if running or unresolved else "released",
                    "handoff": handoff, "popup": popup,
                    "all_chat_channels_paused": True, "captures_and_jev_paused": True,
                    "ask_user_via_host_popup": True, "resume_requires_trusted_chat_request": True,
                    "foreground_activated": False}
        return {"state": "paused", "stop_received": False, "pause_received": True,
                "in_flight_actions": len(events),
                "resume_requires_trusted_chat_request": True}

    def _release_phase(self, task):
        """Yield idle control resources without pausing or ending this task."""
        prefix = self._action_prefix(task)
        with self._host_condition:
            if task in self._finishing_tasks:
                return {"state": "phase_release_pending", "reason": "cleanup_in_progress", "input_dispatched": False}
            self._finishing_tasks.add(task)
            pending = any(key.startswith(prefix) for key in self._host_calls)
        try:
            if pending:
                return {"state": "phase_release_pending", "reason": "computer_actions_in_flight", "input_dispatched": False}
            with self.store.transaction() as db:
                self.store._task(db, task)
                if db.execute("SELECT 1 FROM actions WHERE task=? AND id LIKE ? AND state IN ('queued','running') LIMIT 1", (task, prefix + '%')).fetchone():
                    return {"state": "phase_release_pending", "reason": "computer_actions_in_flight", "input_dispatched": False}
                self.store._require_input_release_confirmed(db, task=task, action_prefix=prefix)
            if self.store.task_write_stopped(task):
                return {"state": "phase_release_pending", "reason": "task_paused_or_stopped",
                        "input_dispatched": False, "stop_and_authority_preserved": True}
            if self._close_indicators(task):
                return {"state": "phase_release_pending", "reason": "indicator_close_unconfirmed", "input_dispatched": False}
            if self._capture_cache is not None:
                self._capture_cache.close(task=task)
            from .human_handoff import close_handoffs
            close_handoffs(self.store, task)
            with self._gate:
                owner = self._owners.get(task)
                handles = [key for key, row in self._observations.items() if row['task'] == task]
                with self.store.transaction() as db:
                    for handle in handles:
                        db.execute("UPDATE observations SET expires=0 WHERE id=? AND task=?", (handle, task))
                for handle in handles:
                    self._observations.pop(handle, None)
                self._next_steps.pop(task, None)
                self._task_hints.pop(task, None)
            ownership = self.store.finish_owned_resources(owner, phase_release=True) if owner else {"released": 0, "retained_for_peer_or_unresolved": 0}
            return {"state": "phase_released", "input_release": "released", "indicator_closed": True,
                    "target_ownership": ownership, "task_finished": False, "requires_new_observation": True,
                    "foreground_activated": False, "input_dispatched": False, "stop_and_authority_preserved": True}
        except ControlError as error:
            return {"state": "phase_release_pending", "reason": error.code, "input_dispatched": False}
        finally:
            with self._host_condition:
                self._finishing_tasks.discard(task)
                self._host_condition.notify_all()

    def _finish_task(self, task):
        prefix = self._action_prefix(task)
        with self._host_condition:
            if task in self._finishing_tasks:
                return {"state": "task_finish_pending", "reason": "finish_already_in_progress",
                        "input_dispatched": False, "requires_finish_retry": True}
            self._finishing_tasks.add(task)
            for key, event in self._stops.items():
                if key.startswith(prefix):
                    event.set()
            drained = self._host_condition.wait_for(
                lambda: not any(key.startswith(prefix) for key in self._host_calls), timeout=2)
        try:
            with self._gate:
                connection_owner = self._owners.get(task)
            with self.store.transaction() as db:
                if not db.execute("SELECT id FROM tasks WHERE id=?", (task,)).fetchone():
                    raise ControlError("task_revoked_or_missing")
                rows = db.execute("SELECT id,state FROM actions WHERE task=? AND owner=?",
                                  (task, connection_owner)).fetchall()
                pending = [row for row in rows if row["id"].startswith(prefix)
                           and row["state"] in {"queued", "running"}]
                for row in pending:
                    db.execute("UPDATE actions SET cancel_requested=1,state=?,updated=? WHERE id=?",
                        ("cancelled" if row["state"] == "queued" else row["state"],
                         self.store.clock(), row["id"]))
                    self.store._mark_stage_stop(db, row["id"])
                if not drained or any(row["state"] == "running" for row in pending):
                    return {"state": "task_finish_pending", "reason": "computer_actions_in_flight",
                            "input_dispatched": False, "requires_finish_retry": True}
                self.store._require_input_release_confirmed(db, task=task, action_prefix=prefix)
            if self._close_indicators(task):
                return {"state": "task_finish_pending", "reason": "indicator_close_unconfirmed",
                        "input_dispatched": False, "input_release": "released",
                        "requires_finish_retry": True}
            if self._capture_cache is not None:
                self._capture_cache.close(task=task)
            if self._high is not None:
                self._high.discard(task)
            from .human_handoff import close_handoffs
            close_handoffs(self.store, task)
            with self._gate:
                owner = self._owners.get(task)
            self._auxiliary_cleanup.retire(task)
            ownership = (self.store.finish_owned_resources(owner) if owner is not None else
                         {"released": 0, "retained_for_peer_or_unresolved": 0})
            if owner is not None:
                # A finished owner is no longer a live peer. Retained claims
                # remain exact cleanup tombstones for a later retry; unknown
                # effects and other live connections still protect the target.
                self.store.retire_owner(owner)
            if owner is not None and not ownership["retained_for_peer_or_unresolved"]:
                with self._gate:
                    if self._owners.get(task) == owner:
                        self._owners.pop(task)
            with self._gate:
                handles = [key for key, value in self._observations.items() if value["task"] == task]
                with self.store.transaction() as db:
                    for handle in handles:
                        db.execute("UPDATE observations SET expires=0 WHERE id=? AND task=?", (handle, task))
                for handle in handles:
                    self._observations.pop(handle, None)
                self._task_hints.pop(task, None)
                self._next_steps.pop(task, None)
                self._text_targets.pop(task, None)
                if self._takeover_policy is not None:
                    self._takeover_policy.finish(task)
                for key in list(self._action_targets):
                    if key.startswith(prefix):
                        self._action_targets.pop(key, None)
            with self._host_gate:
                for key in list(self._stops):
                    if key.startswith(prefix):
                        self._stops.pop(key, None)
            return {"state": "task_finished", "input_release": "released",
                    "finished_channel": self.ACTION_CHANNEL,
                    "indicator_closed": True, "input_dispatched": False,
                    "historical_receipts_preserved": True, "target_ownership": ownership}
        except ControlError as error:
            if error.code == "auxiliary_owner_cleanup_pending":
                return {"state": "task_finish_pending", "reason": error.code,
                        "input_dispatched": False, "requires_finish_retry": True}
            if error.code != "input_release_unconfirmed":
                raise
            return {"state": "task_finish_pending", "reason": error.code,
                    "input_release": "unknown", "input_dispatched": False,
                    "requires_finish_retry": True}
        finally:
            # A retry remains possible; old observations never bypass the
            # ledger's cancellation or input-release protection.
            with self._host_gate:
                self._finishing_tasks.discard(task)

    def _capture_observation(self, grant: ComputerAuthorization, owner: str,
                             resource: str, preflight: Callable[[], None],
                             stopped: Callable[[], bool], candidate_uia=None) -> dict:
        preflight()
        if win32gui.IsIconic(grant.identity.hwnd):
            raise ComputerBoundaryError("target_not_captureable")
        broker_status = self._high.status(grant.task_id) if self._high is not None else None
        current = window_geometry(grant.identity)
        environment = layout_environment()
        if current.window.width * current.window.height > self.MAX_WINDOW_PIXELS:
            raise ComputerBoundaryError("window_capture_too_large")
        with self._gate:
            indicator = self._indicators.get((grant.task_id, grant.identity))
        if indicator is not None and getattr(indicator, "_active_stop", None) is not None:
            indicator.set_stage("verify", checkpoint="读取操作后的窗口")
        capture = self._capture(grant, preflight=preflight, stopped=stopped)
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
        security_hint = None
        if candidate_uia is not None:
            try:
                candidate_set = build_uia_candidates(identity=grant.identity, geometry=current,
                    capture=capture, computer_observation_id=handle, uia=candidate_uia,
                    captured_at_ms=int(time.time() * 1000), goal_coverage_confirmed=False)
                from flower_control.privacy import intersects
                candidate_count = len(candidate_set["candidates"])
                candidate_set["candidates"] = [row for row in candidate_set["candidates"]
                    if not any(intersects(tuple(row["rect_client"][i] + current.client_origin[i % 2] for i in range(4)), mask)
                               for mask in capture.privacy_rects)]
                if len(candidate_set["candidates"]) != candidate_count:
                    candidate_set.update(complete=False, privacy_filtered=True,
                        hidden_candidates=candidate_count - len(candidate_set["candidates"]))
                # build_uia_candidates independently reads creation FILETIME
                # against identity.process_created and compares it with UIA's
                # supplied time, besides HWND/PID and capture coherence. This
                # is not trust in candidate_uia's self-reported identity.
                # Do not transfer a hint
                # across a failed match, or expose text under a privacy mask.
                if not capture.privacy_rects:
                    security_hint = security_prompt_observation(candidate_uia,
                        expected_target={"pid": grant.identity.pid, "hwnd": grant.identity.hwnd,
                            "process_start_filetime": candidate_uia.get("process_start_filetime")},
                        content_allowed=True)
                    if security_hint is not None:
                        security_hint["source_identity"] = security_prompt_identity(security_hint["window_identity"])
                        preflight()
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
        try:
            from .indicator_content import ContentMap
            protected = [tuple(row["rect_client"][i] + current.client_origin[i % 2]
                               for i in range(4)) for row in (candidate_set or {}).get("candidates", ())]
            content = ContentMap.from_capture(capture, protected)
            content.window_bounds = (current.window.left, current.window.top,
                                     current.window.right, current.window.bottom)
            with self._gate:
                self._observations[handle]["content_map"] = content
                indicator = self._indicators.get((grant.task_id, grant.identity))
            if indicator is not None and hasattr(indicator, "set_content_map"):
                indicator.set_content_map(content)
        except (ValueError, KeyError):
            pass  # Optional layout hint must not turn a valid observation into failure.
        return {"observation_id": handle, "image": self._image(capture),
                "input_state": input_state,
                "client_origin": list(current.client_origin),
                "client_size": list(current.client_size),
                "client_coordinate_space": "physical_client_pixels",
                "window_origin": [current.window.left, current.window.top],
                "window_size": [current.window.right - current.window.left, current.window.bottom - current.window.top],
                "window_coordinate_space": "physical_window_pixels",
                "desktop": environment[0], "work_areas": [list(area) for area in environment[1]],
                **({"security_prompt": security_hint} if security_hint is not None else {}),
                **({"candidates": [{key: row[key] for key in ("candidate_id", "role", "label", "rect_client")}
                                    for row in candidate_set["candidates"]],
                    "candidate_generation": generation,
                    "candidate_coverage": {k: v for k, v in candidate_set.items() if k not in
                                           {"candidates", "target_identity"}}} if candidate_set else {})}

    def _run_sequence(self, owner: str, key: str,
                      grant: ComputerAuthorization, geometry, sequence,
                      before_windows: frozenset[int],
                      preflight: Callable[[], None], stopped: Callable[[], bool],
                      progress: dict, indicator=None, followup_check=None, phase=None,
                      before_final_readback=None) -> dict:
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
        previous_backend = baseline.source
        context = None
        needs_keyboard = any(step.raw.type == 1 for row in sequence
                             for batch in sequence_batches(row[1]) for step in batch.steps)
        for index, (step_command, planned, expectation) in enumerate(sequence):
            step_batches = sequence_batches(planned)
            progress["current_step"] = index
            preflight()
            if stopped():
                raise ComputerBoundaryError("input_stopped")
            assert_foreground(grant.identity)
            assert_geometry(geometry)
            if indicator is not None:
                indicator.reserve_mouse_paths(mouse_path_rects(step_batches))
            ledger = HeldInputLedger()
            if phase is not None:
                phase.track(ledger)
            if indicator is not None:
                from .indicator_visual import computer_action_label
                indicator.set_stage("input", checkpoint=f"{computer_action_label(step_command)} · {index + 1}/{len(sequence)}")
            self.store.begin_computer_sequence_step(owner, key, index)
            progress["partial_step"] = index
            progress["input_release"] = "unknown"
            sent_success = False
            timed_progress = None
            try:
                baseline = None
                if context is None and needs_keyboard:
                    def accepted_ime(count):
                        progress["sent_events"] += count
                    baseline, ime_report = prepare_ime(grant.identity, geometry, ledger,
                        preflight=lambda: preflight() or True, stopped=stopped, accepted=accepted_ime)
                    progress.setdefault("ime_preparations", []).append({"step": index, **ime_report})
                from .computer_context_guard import InputContextGuard
                if baseline is not None:
                    context = InputContextGuard(baseline)
                receiver = None
                def step_preflight():
                    preflight()
                    if context is not None:
                        context.recheck(read_input_context(grant.identity), time.monotonic())
                    return True
                def before_step_segment(steps):
                    if context is not None:
                        context.settle_pending(lambda: read_input_context(grant.identity),
                            time.monotonic, preflight, time.sleep)
                def final_step_preflight(steps):
                    nonlocal receiver
                    step_preflight()
                    from .computer_native import expected_mouse_focus
                    receiver = expected_mouse_focus(steps, grant.identity, geometry) if context is not None else None
                    return True
                def after_step_segment(steps):
                    if context is not None:
                        if any(step.pressed and step.token == ("vk", 9) for step in steps):
                            context.traversal_dispatched(time.monotonic())
                        elif any(step.pressed and step.token is not None and step.token[0] == "mouse" for step in steps):
                            context.mouse_dispatched(receiver, time.monotonic())
                for batch in step_batches:
                    before_step_segment(batch.steps)
                    if isinstance(batch, TimedInputPlan):
                        timed_progress = {"sent_events": 0, "sent_segments": 0}
                        try:
                            send_timed_plan(batch, ledger, expected=grant.identity, geometry=geometry,
                                preflight=step_preflight, stopped=stopped, progress=timed_progress,
                                before_segment=before_step_segment, final_preflight=final_step_preflight,
                                after_segment=after_step_segment)
                        finally:
                            progress["sent_events"] += timed_progress["sent_events"]
                    else:
                        timed_progress = None
                        sent = send_batch(batch, ledger, expected=grant.identity, geometry=geometry,
                            preflight=step_preflight, stopped=stopped,
                            final_preflight=lambda: final_step_preflight(batch.steps))
                        progress["sent_events"] += sent
                        after_step_segment(batch.steps)
                    progress["sent_batches"] += 1
                if context is not None and context.has_pending and index < len(sequence) - 1:
                    context.settle_pending(lambda: read_input_context(grant.identity),
                        time.monotonic, preflight, time.sleep)
                sent_success = True
            except PartialInput as error:
                if timed_progress is None:
                    progress["sent_events"] += error.sent
                raise
            finally:
                try:
                    if ledger.held:
                        from .computer_native import release_held
                        progress["input_release"] = "release_pending"
                        release_held(ledger, cleanup_owned=lambda: True, stopped=stopped)
                finally:
                    progress["input_release"] = ledger.release_state
                    progress["pointer_events"] = progress.get("pointer_events", 0) + ledger.pointer_events
                    progress["native_prefix_known"] = ledger.release_confirmed and not ledger.blocked
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
            final_readback = index == len(sequence) - 1 and before_final_readback is not None
            if final_readback:
                before_final_readback()
                preflight()
                if stopped():
                    raise ComputerBoundaryError("input_stopped")
            else:
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
            if not final_readback:
                assert_foreground(grant.identity)
            assert_geometry(geometry)
            followup = (followup_check() if followup_check is not None else
                        new_visible_followups(grant.identity, before_windows,
                                              bind_allowed=not stopped()))
            if followup["visual_scope"] != "target_window_only":
                return {"state": "sequence_stopped", "reason": "new_window_detected",
                        "business_outcome_verified": False, **followup}
            digest = hashlib.sha256(capture.bmp).hexdigest()
            if expectation != "capture_available" and capture.source != previous_backend:
                raise CaptureError("capture_backend_changed")
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
            previous_backend = capture.source
        return {"state": "sequence_completed", "business_outcome_verified": False}

    def _execute(self, owner: str, resource: str, grant: ComputerAuthorization,
                 action_id: str, command: str, payload: dict, *,
                 observation: str | None = None, generation: str | None = None,
                 batches=None, geometry=None, restore_minimized: bool = False,
                 sequence=None, shared_revision: int | None = None,
                 candidate_uia=None, semantic_candidate=None, wait_observation=None,
                 region_version=None, layout_plan=None) -> dict:
        control_cycle = None
        if command not in {"observe", "wait"}:
            from .computer_plan import expected_control_cycle
            control_cycle = self._pin_control_run(grant, expected_cycle=expected_control_cycle.get())
        if command == "input":
            from .computer_native import input_execution_budget
            try:
                if batches:
                    input_execution_budget(batches)
                if sequence:
                    input_execution_budget(tuple(batch for row in sequence for batch in sequence_batches(row[1])))
            except ValueError as error:
                raise ComputerBoundaryError(str(error)) from None
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
        first = False
        if self._takeover_policy is not None and command not in {"observe", "wait"}:
            indicator = None
            try:
                def initial_check():
                    nonlocal grant
                    if stop.is_set() or self.store.task_write_stopped(grant.task_id):
                        raise ComputerBoundaryError("input_stopped")
                    # The same already-admitted activation may wait for a
                    # person to finish. Re-resolve the exact selected target
                    # through its normal trusted adapter before its short call
                    # lease expires; no new source ticket or broader scope is
                    # created, and changed bindings require a fresh action.
                    if command == "activate" and grant.expires_at - self.store.clock() <= 3:
                        refreshed = self._authorized("flower_computer_activate", payload, payload.get("target"),
                                                     "input", trusted_task=grant.task_id)
                        fields = ("task_id", "identity", "target_scope", "capture_scope", "input_scope",
                                  "shared_resource", "request_fingerprint", "suppress_pointer_approach",
                                  "pointer_constraints", "capture_allowed", "input_allowed")
                        if any(getattr(refreshed, field) != getattr(grant, field) for field in fields):
                            raise ComputerBoundaryError("target_changed")
                        grant = refreshed
                    if grant.expires_at <= self.store.clock():
                        raise ComputerBoundaryError("trusted_call_expired")
                    assert_window(grant.identity)
                def progress(text):
                    nonlocal indicator
                    if indicator is None:
                        def on_stop():
                            stop.set()
                            self.store.pause_computer_target(grant.task_id, resource)
                        indicator = self._acquire_indicator(grant, "首次 Computer 接管", on_stop, prepare=True, next_step=payload.get("next_step"), stop_signal=stop)
                        indicator._input_released = True  # No input has been submitted.
                    indicator.set_stage("takeover", checkpoint=text)
                    return indicator.stage_visible("takeover", text) if hasattr(indicator, "stage_visible") else None
                first = self._takeover_policy.prepare(grant.task_id, grant.identity,
                    stop=stop, check=initial_check, progress=progress,
                    allow_first=command == "activate")
                if first:
                    with self._gate:
                        handles = [handle for handle, row in self._observations.items()
                                   if row["task"] == grant.task_id and row["identity"] == grant.identity]
                        for handle in handles:
                            self._observations[handle]["expires"] = 0
                    with self.store.transaction() as db:
                        for handle in handles:
                            db.execute("UPDATE observations SET expires=0 WHERE id=? AND task=?",
                                       (handle, grant.task_id))
                # Initial input coordinates were observed before the user went
                # idle; they must be refreshed instead of replayed after waiting.
                if first and command == "input":
                    raise ComputerBoundaryError("first_takeover_requires_new_observation")
            except (NativeInputError, ComputerBoundaryError, IndicatorError, ControlError, WindowSelectionError) as error:
                self.store.cancel(owner, key)
                return {"receipt": self.store.status(owner, key), "state": "waiting",
                        "reason": error.code, "dispatched": False, "input_release": "released",
                        "requires_new_observation": True, "foreground_activated": False,
                        **({"next_action": "flower_computer_activate",
                            "message": "首次操作请先接管目标：activate 会在空闲倒计时结束后立即切到目标前台，并返回新截图。"}
                           if error.code == "first_takeover_requires_activation" else {})}
            finally:
                # Countdown owns no input. Clear its callback and text on every
                # exit, including a later activation refusal or queue wait.
                if indicator is not None:
                    self._finish_indicator(indicator, stopped=stop.is_set(), released=True, action_owner=stop)
        decision = wait_for_turn_sync(self.store, owner, key, resources,
                                      client_factory=self.jev_client_factory,
                                      timeout=max(0, min(5, grant.expires_at - self.store.clock())))
        if decision.action_id != key:
            return {"receipt": self.store.queue_status(owner, key), "queued": True}
        if first and command == "activate":
            # The user can start interacting again while the call waits for
            # its queue turn. This is still the original unsent activation:
            # re-arm the same countdown before opening a High input lease.
            indicator = None
            try:
                self._takeover_policy.prepare(grant.task_id, grant.identity,
                    stop=stop, check=initial_check, progress=progress,
                    allow_first=True, recheck_activity=True)
            except (NativeInputError, ComputerBoundaryError, IndicatorError, ControlError, WindowSelectionError) as error:
                self.store.cancel(owner, key)
                return {"receipt": self.store.status(owner, key), "state": "waiting",
                        "reason": error.code, "dispatched": False, "input_release": "released",
                        "requires_new_observation": True, "foreground_activated": False}
            finally:
                if indicator is not None:
                    self._finish_indicator(indicator, stopped=stop.is_set(), released=True, action_owner=stop)
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
                    self._pin_control_run(grant, high_status, expected_cycle=control_cycle)
                    self._high.require_input(high_status)
                    return execute_high(self, owner, resource, grant, key, command, payload,
                        decision.decision_id, resources, stop, high_status,
                        observation=observation, generation=generation, batches=batches,
                        geometry=geometry, restore_minimized=restore_minimized,
                        sequence=sequence, shared_revision=shared_revision,
                        semantic_candidate=semantic_candidate, region_version=region_version,
                        layout_plan=layout_plan, control_cycle=control_cycle)
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
        deferred_input_capture = False
        ime_baseline = None
        input_context = None
        focus_receiver = None
        ime_preparation = None
        result = None
        activation_result = None
        activation_indicator = None
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
        sequence_readback_started = False
        ledger = None
        input_release = "not_used"
        activated_capture_failed = False
        activation_started = False
        activation_known_zero = False
        business_known_zero = False
        phase = None
        focus_borrow = None
        focus_return_report = None
        recovery_token = None
        foreground_recoveries = []
        recovering_foreground = False
        business_complete = False
        def keyboard_release_count():
            return sum(item.keyboard_release_events for item in phase.ledgers) if phase is not None else 0
        def return_borrowed_focus():
            nonlocal watch_started, focus_return_report
            if focus_borrow is None or focus_return_report is not None:
                return
            try:
                preflight()
                # Stop observing our intentional return as user interference.
                # The independent activity watch stays active through dispatch.
                if watch_started:
                    watch.close()
                    watch_started = False
                focus_return_report = focus_borrow.restore(phase.stage,
                    released=phase.release_state == "released" and effective_release() == "released",
                    check=preflight)
            except Exception:
                focus_return_report = {"state": "skipped", "reason": "conditions_changed", "attempted": False}
        def pointer_count():
            return (ledger.pointer_events if ledger is not None else 0) + (sequence_progress.get("pointer_events", 0) if sequence_progress else 0)
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
                activation_dispatched=True if activation_sent or keyboard_release_count() else False if not activation_started or activation_known_zero else None,
                # Until activation itself has returned, do not publish a
                # completed zero-business phase: shared failure inference
                # would otherwise discard the unresolved activation effect.
                business_dispatched=None if activation_unresolved else
                    True if business_events else False if not business_started or business_known_zero else None,
                input_release=release, pointer_events=pointer_count())
            return activation_unresolved
        def finish(*args, **kwargs):
            record_effects()
            if not sequence_readback_started:
                return_borrowed_focus()
            if isinstance(result, dict) and command not in {"observe", "wait"}:
                if focus_return_report is not None:
                    result["focus_return"] = focus_return_report
                result["input_release"] = effective_release()
                result["pointer_events"] = pointer_count()
                result["keyboard_release_events"] = keyboard_release_count()
                result["foreground_recoveries"] = list(foreground_recoveries)
                result["physical_input_dispatched"] = (True if keyboard_release_count() or pointer_count() or sent_events or activation_progress["activation_input_events"] or (sequence_progress and sequence_progress["sent_events"])
                    else None if effective_release() == "unknown" else False)
                if keyboard_release_count() or pointer_count():
                    result["dispatched"] = True
                if timed_progress is not None:
                    result.update(sent_segments=timed_progress["sent_segments"],
                                  timed_plan_completed=sent_batches > 0)
                if ime_preparation is not None:
                    result["ime_preparation"] = ime_preparation
            return self.store.finish(*args, **kwargs)
        try:
            from .computer_native import input_privacy_session
            with (self.store.dispatch(owner, key, decision.decision_id),
                  self._record_effects_on_failure(owner, key, record_effects),
                  self._finish_read_failure(owner, key, command), input_privacy_session()):
                if command not in {"observe", "wait"}:
                    phase = ComputerForegroundPhase(self.store, owner, key, resource,
                                                     payload.get("command", command))
                watch = None
                watch_started = False
                def preflight(*, authority_only=False) -> None:
                    if grant.execution_guard is not None:grant.execution_guard()
                    if focus_borrow is not None and not sequence_readback_started:
                        focus_borrow.check_activity()
                    if command not in {"observe", "wait"} and self.store.write_stopped():
                        raise ControlError("global_write_stopped")
                    if stop.is_set():
                        raise ComputerBoundaryError("input_stopped")
                    if command == "input" and barrier is not None and not business_complete:
                        foreground = win32gui.GetForegroundWindow()
                        if barrier.owned_followup is not None and barrier.owned_followup(foreground):
                            barrier.foreground_changed(foreground)
                        if barrier.reason == "new_window_detected":
                            barrier.check()
                    if phase is not None and not sequence_readback_started:
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
                    if watch is not None and watch_started and not authority_only and not recovering_foreground:
                        try:
                            watch.check()
                        except ControlError as error:
                            if (business_complete and error.code == "foreground_phase_interrupted"
                                    and not barrier.persistent_stop_requested):
                                assert_window(grant.identity)
                                return
                            if recover_foreground(error.code):
                                return preflight()
                            if phase is not None and error.code in {"external_keyboard_activity", "external_mouse_activity"}:
                                phase.interrupted("external_mouse" if error.code == "external_mouse_activity" else "external_keyboard")
                                raise ControlError("foreground_phase_interrupted") from None
                            if phase is not None and error.code in {"foreground_phase_interrupted", "user_takeover_paused"}:
                                reason = {"foreground_left_target": "foreground_changed",
                                          "target_minimized": "target_minimized", "user_stop": "explicit_stop",
                                          "target_destroyed": "target_closed"}.get(barrier.reason)
                                if reason is not None:
                                    phase.interrupted(reason)
                            raise
                    assert_window(grant.identity)

                def phase_stopped():
                    # Ordinary focus events are handled at preflight, before
                    # an unsent step. They never become cancellation tokens.
                    return stop.is_set() or bool(barrier and barrier.persistent_stop_requested)

                def recover_foreground(reason):
                    nonlocal recovering_foreground, watch, watch_started, activation_started
                    nonlocal activation_result, ime_baseline, ime_preparation, input_context
                    allowed = {"foreground_phase_interrupted", "foreground_changed",
                               "foreground_target_not_interactive", "waiting_for_target_foreground",
                               "target_minimized", "external_input_held", "input_context_changed"}
                    if (reason not in allowed or command != "input" or recovering_foreground
                            or business_complete or foreground_recoveries or phase is None
                            or phase.release_state not in {"not_used", "released"}
                            or any(item.blocked for item in phase.ledgers)
                            or barrier is None or barrier.persistent_stop_requested
                            or barrier.reason == "new_window_detected"):
                        return False
                    foreground = win32gui.GetForegroundWindow()
                    if (foreground and foreground != grant.identity.hwnd and foreground not in before_windows
                            and is_owned_popup(grant.identity, foreground)):
                        # A newly opened application dialog is the action's
                        # follow-up, not a user switching to another task.
                        # Let the existing fresh follow-up path bind it.
                        return False
                    # Consume the one recovery budget before any activation.
                    # A second switch cannot start a foreground tug-of-war.
                    foreground_recoveries.append(reason)
                    recovering_foreground = True
                    try:
                        preflight(authority_only=True)
                        if watch_started:
                            watch.close()
                            watch_started = False
                        local_progress = {}
                        activation_started = True
                        try:
                            restored = activate_window(grant.identity,
                                preflight=lambda: preflight(authority_only=True) or True,
                                stopped=phase_stopped, restore_minimized=True,
                                progress=local_progress, on_input_ledger=phase.track)
                        finally:
                            # An activation may acknowledge keys, then fail its
                            # final target check. Preserve that native prefix too.
                            activation_progress["activation_input_events"] += local_progress.get("activation_input_events", 0)
                            if local_progress.get("activation_request_sent"):
                                activation_progress["activation_request_sent"] = True
                            if local_progress.get("activation_shell_dispatched"):
                                activation_progress["activation_shell_dispatched"] = True
                            if "activation_input_release" in local_progress:
                                activation_progress["activation_input_release"] = local_progress["activation_input_release"]
                        activation_result = restored
                        if not restored.get("foreground"):
                            raise NativeInputError(restored.get("reason", "user_activation_required"))
                        if self._takeover_policy is not None:
                            self._takeover_policy.confirm_activation(grant.task_id, grant.identity)
                        preflight(authority_only=True)
                        assert_foreground(grant.identity)
                        assert_geometry(geometry)
                        fresh = self._capture(grant,
                            preflight=lambda: preflight(authority_only=True), stopped=phase_stopped)
                        if region_version is not None and _region_digest(fresh, region_version[0]) != region_version[1]:
                            raise ComputerBoundaryError("candidate_requires_new_observation")
                        if semantic_candidate is not None:
                            checked_click_arguments(semantic_candidate, identity=grant.identity,
                                geometry=geometry, capture=fresh,
                                computer_observation_id=payload["observation_id"])
                        if ime_baseline is not None:
                            current = read_input_context(grant.identity)
                            reference = input_context.baseline if input_context is not None else ime_baseline
                            if (current.focus != reference.focus or current.layout != reference.layout):
                                raise NativeInputError("input_context_changed")
                            preparation_ledger = HeldInputLedger()
                            phase.track(preparation_ledger)
                            def accepted(count):
                                nonlocal sent_events
                                sent_events += count
                            ime_baseline, ime_preparation = prepare_ime(grant.identity, geometry,
                                preparation_ledger, preflight=lambda: preflight(authority_only=True) or True,
                                stopped=phase_stopped, accepted=accepted)
                            from .computer_context_guard import InputContextGuard
                            input_context = InputContextGuard(ime_baseline)
                        barrier.restart_transient()
                        watch = ForegroundWatch(barrier)
                        watch_started = True
                        watch.start()
                        watch.check()
                        preflight(authority_only=True)
                        return True
                    finally:
                        recovering_foreground = False

                recovery_token = pre_dispatch_recovery.set(recover_foreground)

                def input_environment() -> bool:
                    preflight()
                    if self._takeover_policy is not None:
                        self._takeover_policy.check_dispatch(grant.task_id, grant.identity,
                            allow_activation=command == "activate" or command == "input" and not watch_started)
                    return True

                def input_preflight() -> bool:
                    input_environment()
                    if input_context is not None:
                        try:
                            input_context.recheck(read_input_context(grant.identity), time.monotonic())
                        except NativeInputError:
                            phase.interrupted("ime_changed")
                            raise ControlError("foreground_phase_interrupted") from None
                    return True

                def before_segment(steps):
                    if input_context is not None:
                        input_context.settle_pending(lambda: read_input_context(grant.identity),
                            time.monotonic, input_environment, time.sleep)

                def final_input_preflight(steps):
                    nonlocal focus_receiver
                    input_preflight()
                    from .computer_native import expected_mouse_focus
                    focus_receiver = expected_mouse_focus(steps, grant.identity, geometry) if input_context is not None else None
                    return True

                def after_segment(steps):
                    if input_context is None:
                        return
                    if any(step.pressed and step.token == ("vk", 9) for step in steps):
                        input_context.traversal_dispatched(time.monotonic())
                    elif any(step.pressed and step.token is not None and step.token[0] == "mouse" for step in steps):
                        input_context.mouse_dispatched(focus_receiver, time.monotonic())

                if command == "observe":
                    result = {"state": "observed", "dispatched": False,
                              **self._capture_observation(grant, owner, resource,
                                                          preflight, stop.is_set, candidate_uia)}
                    finish(owner, key, "verified", result_code="computer_observed")
                elif command == "wait":
                    condition = payload["arguments"]["condition"]
                    wait_started = time.monotonic()
                    visual_condition = None
                    if condition in {"image_changed", "image_unchanged", "image_stable"}:
                        from .visual_conditions import VisualCondition
                        baseline = replace(wait_observation["capture_descriptor"], bmp=zlib.decompress(wait_observation["capture_compressed"]))
                        visual_condition = VisualCondition(condition, baseline, roi=payload["arguments"].get("roi"),
                            stable_ms=payload["arguments"].get("stable_ms", 300),
                            roi_units=payload["arguments"].get("roi_units", "pixels"),
                            threshold=payload["arguments"].get("threshold"))
                    deadline = wait_started + payload["arguments"]["timeout_ms"] / 1000
                    matched = False
                    details = {}
                    while time.monotonic() < deadline and not stop.is_set():
                        self.store.check_dispatch(owner, key)
                        if grant.expires_at <= self.store.clock():
                            raise ComputerBoundaryError("trusted_call_expired")
                        target_closed = not win32gui.IsWindow(grant.identity.hwnd)
                        if target_closed:
                            matched = condition == "window_closed"
                            details = {"target_closed": True}
                        elif condition == "elapsed":
                            # A bounded dwell needs no intermediate screenshots.
                            # Keep exact target, task, policy and call gates live.
                            preflight()
                        elif condition == "new_window":
                            preflight()
                            details = new_visible_followups(grant.identity,
                                wait_observation["visible_windows"], bind_allowed=self._high is None)
                            matched = details["visual_scope"] != "target_window_only"
                        elif condition in {"image_changed", "image_unchanged", "image_stable"}:
                            capture = self._capture(grant, preflight=preflight, stopped=stop.is_set)
                            descriptor = wait_observation.get("capture_descriptor")
                            if descriptor is not None and capture.source != descriptor.source:
                                raise CaptureError("capture_backend_changed")
                            matched = visual_condition.sample(capture, (time.monotonic()-wait_started)*1000)
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
                    if condition == "elapsed" and not details.get("target_closed"):
                        preflight()
                        matched = time.monotonic() >= deadline
                    result = {"state": "wait_completed" if matched else "wait_timeout",
                              "matched": matched, "condition": condition, "dispatched": False,
                              "business_outcome_verified": False,
                              "condition_wait_elapsed_ms": round((time.monotonic() - wait_started) * 1000, 3),
                              **details}
                    if visual_condition is not None and visual_condition.threshold is not None:
                        result["visual_comparison"] = {"method": "mean_absolute_grayscale_delta",
                            "threshold": visual_condition.threshold, "last_delta": visual_condition.last_delta,
                            "roi_pixels": visual_condition.roi}
                    # The fresh observation remains a separate part of the
                    # response and may add time after the condition deadline.
                    post_wait_started = time.monotonic()
                    if (condition == "elapsed" and matched) or win32gui.IsWindow(grant.identity.hwnd):
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
                    activation_indicator = self._acquire_indicator(grant, payload.get("goal_hint") or "接管目标窗口",
                        lambda: (stop.set(), self.store.pause_computer_target(grant.task_id, resource)),
                        prepare=True, next_step=payload.get("next_step"), stop_signal=stop)
                    activation_indicator.set_stage("prepare", checkpoint="激活目标并取得新截图")
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
                        if self._takeover_policy is not None:
                            self._takeover_policy.confirm_activation(grant.task_id, grant.identity)
                        if (phase is not None and phase.release_state in {"released", "not_used"}
                                and effective_release() == "released" and not stop.is_set()):
                            deferred_input_capture = True
                        else:
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
                    def persist_takeover():
                        reason="target_closed" if barrier.reason=="target_destroyed" else "explicit_stop"
                        self.store.pause_computer_target(grant.task_id,resource,reason=reason)
                        # A physical Stop click may reach its HUD just after
                        # the mouse-activity event has ended this same phase.
                        # Preserve that exact Stop in the original stage too.
                        if reason=="explicit_stop":
                            with self.store.transaction() as db:
                                self.store._mark_stage_stop(db,key)
                                db.execute("UPDATE actions SET cancel_requested=1 WHERE id=? AND task=?",(key,grant.task_id))
                    barrier = TakeoverBarrier(
                        grant.identity.hwnd,
                        persist_takeover,
                        return_hwnd=return_hwnd,
                        owned_followup=(lambda hwnd: bool(hwnd and hwnd not in before_windows
                            and is_owned_popup(grant.identity, hwnd))) if command == "input" else None)
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
                        preflight()
                        if needs_activation:
                            focus_borrow = FocusBorrow(grant.identity)
                            focus_borrow.start()
                            activation_started = True
                            activation_result = activate_window(
                                grant.identity, preflight=input_preflight,
                                stopped=stop.is_set, restore_minimized=True,
                                progress=activation_progress, on_input_ledger=phase.track)
                            if not activation_result["foreground"]:
                                dispatched = bool(keyboard_release_count() or activation_result.get("activation_input_events", 0) or
                                                  activation_progress.get("activation_shell_dispatched"))
                                uncertain = activation_result.get("state") == "outcome_uncertain"
                                result = {"state": "outcome_uncertain" if uncertain else "not_verified",
                                          "dispatched": dispatched,
                                          "reason": activation_result.get("reason", "user_activation_required"),
                                          "input_release": effective_release(),
                                          "activation": activation_result}
                                finish(owner, key, "outcome_uncertain" if uncertain else "not_verified",
                                                  result_code=activation_result.get("reason", "user_activation_required"))
                                return {"receipt": self.store.status(owner, key),
                                        "result": result}
                        else:
                            end_keyboard_input(grant.identity,
                                preflight=lambda: preflight(authority_only=True) or True,
                                stopped=phase_stopped, on_input_ledger=phase.track)
                        watch_started = True
                        try:
                            watch.start()
                        except ControlError as error:
                            if not recover_foreground(error.code):
                                raise
                        preflight()
                        assert_foreground(grant.identity)
                        assert_geometry(geometry)
                        if win32gui.IsWindow(grant.identity.hwnd):
                            indicator = self._acquire_indicator(grant,
                                payload.get("goal_hint") or "执行窗口操作", barrier.stop_clicked,
                                paths=_indicator_paths(
                                    tuple(batch for step in sequence for batch in sequence_batches(step[1])) if sequence is not None else batches,
                                    geometry), next_step=payload.get("next_step"), stop_signal=stop)
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
                            batches = _plan_input("click", checked, geometry,
                                default_pointer_constraints=grant.pointer_constraints)
                        before_windows = visible_process_top_levels(grant.identity)
                        def followup_check():
                            allowed = not stop.is_set() and not barrier.stopped.is_set()
                            foreground = (barrier.followup_hwnd if barrier.reason == "new_window_detected"
                                          else win32gui.GetForegroundWindow())
                            owned_transition = (
                                not stop.is_set() and barrier.reason in {"foreground_left_target", "new_window_detected"} and
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
                            def begin_final_readback():
                                nonlocal sequence_readback_started, watch_started, business_complete
                                business_complete = True
                                preflight()
                                return_borrowed_focus()
                                if watch_started:
                                    watch.close()
                                    watch_started = False
                                record_effects()
                                self.store.begin_sequence_final_readback(owner, key,
                                    binding=phase.binding,
                                    verify=lambda binding: binding == phase.binding
                                        and phase.release_state == "released")
                                sequence_readback_started = True
                                self._finish_indicator(indicator, released=True, action_owner=stop)
                            sequence_result = self._run_sequence(
                                owner, key, grant, geometry, sequence,
                                before_windows, preflight,
                                phase_stopped,
                                sequence_progress, indicator, followup_check, phase=phase,
                                before_final_readback=begin_final_readback)
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
                                    from .indicator_visual import computer_action_label
                                    indicator.set_stage("input", checkpoint=f"{computer_action_label(payload.get('command'))} · {batch_index + 1}/{len(batches)}")
                                input_batch_started = True
                                if any(step.raw.type == 1 for planned in batches for step in planned.steps):
                                    if batch_index == 0:
                                        def ime_accepted(count):
                                            nonlocal sent_events, dispatched
                                            sent_events += count
                                            dispatched = dispatched or count > 0
                                        try:
                                            ime_baseline, ime_preparation = prepare_ime(
                                                grant.identity, geometry, ledger,
                                                preflight=lambda: preflight() or True,
                                                stopped=phase_stopped,
                                                accepted=ime_accepted)
                                            from .computer_context_guard import InputContextGuard
                                            input_context = InputContextGuard(ime_baseline)
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
                                            stopped=phase_stopped, progress=timed_progress,
                                            before_segment=before_segment, final_preflight=final_input_preflight,
                                            after_segment=after_segment)
                                    finally:
                                        sent_events += timed_progress["sent_events"]
                                        dispatched = dispatched or timed_progress["sent_events"] > 0
                                else:
                                    before_segment(batch.steps)
                                    sent = send_batch(batch, ledger, expected=grant.identity,
                                                  geometry=geometry, preflight=input_preflight,
                                                  stopped=phase_stopped,
                                                  final_preflight=lambda: final_input_preflight(batch.steps))
                                    sent_events += sent
                                    after_segment(batch.steps)
                                sent_batches += 1
                                dispatched = True
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
                                                 stopped=phase_stopped)
                            finally:
                                input_release = ledger.release_state
                        business_complete = True
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
                        elif (phase is not None and phase.release_state == "released"
                                and effective_release() == "released" and not stop.is_set()
                                and not barrier.persistent_stop_requested):
                            # Native input has completed and every exact ledger
                            # acknowledged its ups. Result pixels need no input
                            # mutex/HUD. End this write before a separate fresh
                            # read; an unresolved/partial executor never enters.
                            result = {"state": "outcome_unverified", "dispatched": True,
                                      "sent_events": sent_events, "sent_batches": sent_batches,
                                      "held_input": [], **followup}
                            deferred_input_capture = True
                            finish(owner, key, "not_verified", result_code="computer_visual_recheck_only")
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
                                    stopped=phase_stopped)
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
                        if phase is not None and not sequence_readback_started and getattr(error, "code", None) == "waiting_for_target_foreground":
                            # This refusal can race the foreground watch between
                            # checks. It still means a normal focus switch, not
                            # an unknown native send or a durable user Stop.
                            phase.interrupted("foreground_changed")
                            error = ControlError("foreground_phase_interrupted")
                        if phase is not None and not sequence_readback_started and getattr(error, "code", None) in {
                                "mouse_receiver_changed", "external_input_held", "input_context_changed",
                                "external_mouse_activity", "external_keyboard_activity"}:
                            phase.interrupted("external_mouse" if error.code in {"mouse_receiver_changed", "external_mouse_activity"} else
                                              "ime_changed" if error.code == "input_context_changed" else "external_keyboard")
                            error = ControlError("foreground_phase_interrupted")
                        if phase is not None and not sequence_readback_started:
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
                        focus_unconfirmed = getattr(error, "code", None) == "input_focus_transition_unconfirmed"
                        if focus_unconfirmed and phase is not None:
                            phase.interrupted("ime_changed")
                        phase_interrupted = (getattr(error, "code", None) == "foreground_phase_interrupted"
                                             or focus_unconfirmed)
                        known_native_refusal = (isinstance(error, NativeInputError) and not isinstance(error, PartialInput)
                            and error.code.startswith("privacy_")
                            and (ledger is not None and ledger.release_confirmed and not ledger.blocked
                                 or sequence_progress is not None and sequence_progress.get("native_prefix_known") is True))
                        pre_send_refusal = getattr(error, "code", None) in {
                            "user_takeover_paused", "foreground_phase_interrupted", "input_focus_transition_unconfirmed", "external_input_held",
                            "foreground_changed", "foreground_target_not_interactive",
                            "window_changed", "geometry_changed", "input_stopped",
                            "desktop_topology_changed", "mouse_desktop_required",
                            "mouse_receiver_unavailable", "mouse_geometry_required",
                            "user_paused_or_cancelled", "trusted_call_expired",
                            "resource_paused_or_quarantined"} or known_native_refusal or isinstance(error, PartialInput) and error.sent == 0
                        step_started = (input_batch_started if sequence_progress is None else
                                        sequence_progress["partial_step"] is not None)
                        no_input_sent = (not pointer_count() and not activation_progress.get("activation_shell_dispatched") and
                                         not activation_progress["activation_input_events"] and sent_events == 0 and
                                         (not step_started or pre_send_refusal) and
                                         (sequence_progress is None or
                                          sequence_progress["input_release"] == "released" and
                                          not sequence_progress["sent_prefix"] and
                                          not sequence_progress["sent_events"]))
                        business_known_zero = (sent_events == 0 and
                            (not step_started or pre_send_refusal) and
                            (sequence_progress is None or not sequence_progress["sent_events"]))
                        known_interrupted_prefix = (
                            (phase_interrupted or known_native_refusal or getattr(error,"code",None) in {
                                "user_paused_or_cancelled", "input_stopped", "resource_paused_or_quarantined"}
                                and phase is not None and phase.stage.snapshot()["foreground_stage"]["interruption"]
                                    in {"explicit_stop","user_pause","human_handoff"}) and
                            (barrier is None or barrier.reason != "target_destroyed") and
                            effective_release() == "released" and
                            activation_progress["activation_input_release"] in {"not_used", "released"} and
                            (ledger is None or ledger.release_confirmed and not ledger.blocked) and
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
                        try:
                            if barrier is not None:
                                barrier.require_persisted_before_release()
                        finally:
                            watch.close()
                            if indicator is not None:
                                self._finish_indicator(indicator, stopped=stop.is_set() or barrier.reason=="user_stop",
                                                       released=effective_release() == "released", action_owner=stop)
        except (ControlError, ComputerBoundaryError, NativeInputError, CaptureError, IndicatorError,
                ValueError) as error:
            if isinstance(error, ValueError):
                diagnose_value_error(error, "execute")
            code = getattr(error, "code", "invalid_computer_request")
            dispatched = dispatched or bool(keyboard_release_count() or pointer_count() or activation_progress["activation_input_events"] or
                                             activation_progress.get("activation_shell_dispatched"))
            if sequence_progress is not None:
                dispatched = bool(keyboard_release_count() or pointer_count() or activation_progress["activation_input_events"] or
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
            if getattr(error, "privacy_diagnostics", None) is not None:
                response["privacy_diagnostics"] = error.privacy_diagnostics
            if getattr(error, "privacy_cleanup_reason", None) == "privacy_scan_exit_unconfirmed":
                response["privacy_cleanup_reason"] = "privacy_scan_exit_unconfirmed"
            response.update(pointer_events=pointer_count(),
                            keyboard_release_events=keyboard_release_count(),
                            foreground_recoveries=list(foreground_recoveries),
                            physical_input_dispatched=(True if keyboard_release_count() or pointer_count() or sent_events or activation_progress["activation_input_events"] or (sequence_progress and sequence_progress["sent_events"])
                                else None if uncertain else False))
            if isinstance(error, CaptureError):
                response.update(requires_new_observation=True)
                if error.diagnostics:
                    response["capture_diagnostics"] = error.diagnostics
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
                if sequence_readback_started:
                    response["requires_new_observation"] = True
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
                        barrier.reason in {"foreground_left_target", "new_window_detected"}):
                    foreground = (barrier.followup_hwnd if barrier.reason == "new_window_detected"
                                  else win32gui.GetForegroundWindow())
                    if barrier.reason == "new_window_detected":
                        response.update({"reason": "new_window_detected", "state": "not_verified"})
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
                            if fresh.get("privacy_diagnostics") is not None:
                                response["continuation"]["privacy_diagnostics"] = fresh["privacy_diagnostics"]
                    except Exception as error:
                        # Optional recovery cannot erase the original input
                        # prefix/uncertainty or expose provider exception text.
                        response["continuation"] = {"new_action_required": True,
                            "replay_old_action": False, "capture_state": "unavailable",
                            "capture_reason": error.code if isinstance(error, (
                                ControlError, ComputerBoundaryError, NativeInputError, CaptureError))
                                else "continuation_unavailable"}
                        if getattr(error, "privacy_diagnostics", None) is not None:
                            response["continuation"]["privacy_diagnostics"] = error.privacy_diagnostics
            return response
        finally:
            if recovery_token is not None:
                pre_dispatch_recovery.reset(recovery_token)
            if focus_borrow is not None:
                focus_borrow.close()
            if activation_indicator is not None:
                self._finish_indicator(activation_indicator, stopped=stop.is_set(),
                    released=effective_release() == "released", action_owner=stop)
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
        if deferred_input_capture:
            # We have left dispatch, closed its event watcher/HUD, and sealed
            # the exact binding above. Releasing claims must preserve peer and
            # unknown actions and must not invalidate still-fresh references.
            claims_released = False
            try:
                sealed_receipt = self.store.status(owner, key)
                sealed_stage = sealed_receipt["foreground_stage"]
                if (phase is None or not phase.sealed or sealed_stage["lease_state"] != "released"
                        or phase.binding is not None and sealed_stage["input_release_confirmed_at"] is None):
                    raise ControlError("input_release_unconfirmed")
                self.store.finish_owned_resources(owner, preserve_observations=True)
                claims_released = True
                if stop.is_set() or self.store.task_write_stopped(grant.task_id):
                    raise ComputerBoundaryError("input_stopped")
                fresh_action = "post-input-" + uuid.uuid4().hex
                with self._host_gate:
                    self._stops[self._key(grant.task_id, fresh_action)] = stop
                post_grant = (replace(grant, capture_scope=grant.input_scope)
                              if command == "input" else grant)
                fresh = self._execute(owner, resource, post_grant, fresh_action, "observe",
                    {"target": payload["target"], "action_id": fresh_action})
                detail = fresh.get("result", {})
                if "image" in detail:
                    if command == "activate":
                        result.update({name: value for name, value in detail.items()
                            if name not in {"state", "dispatched", "input_release", "input_dispatched",
                                            "activation", "business_result"}})
                    else:
                        result.update(visual_recheck=detail["image"], input_state=detail.get("input_state"),
                            result_observation_id=detail.get("observation_id"))
                    result["foreground_released_before_readback"] = True
                    result.update({name: detail[name] for name in
                        ("visual_scope", "visual_scope_incomplete", "followup_targets") if name in detail})
                else:
                    result.update(requires_new_observation=True,
                        capture_reason=fresh.get("reason") or "post_input_capture_unavailable")
                    if fresh.get("privacy_diagnostics") is not None:
                        result["privacy_diagnostics"] = fresh["privacy_diagnostics"]
            except (ControlError, ComputerBoundaryError, NativeInputError, CaptureError, ValueError,
                    sqlite3.Error) as error:
                if not claims_released:
                    result.update(phase_cleanup_pending=True,
                        phase_cleanup_reason=(ledger_error_code(error, prefix="control_ledger")
                            if isinstance(error, sqlite3.Error)
                            else getattr(error, "code", "phase_cleanup_unavailable")))
                result.update(requires_new_observation=True,
                    capture_reason=(ledger_error_code(error, prefix="control_ledger")
                        if isinstance(error, sqlite3.Error)
                        else getattr(error, "code", "post_input_capture_unavailable")))
                if getattr(error, "privacy_diagnostics", None) is not None:
                    result["privacy_diagnostics"] = error.privacy_diagnostics
            finally:
                # The dialog can appear while either successful or failed
                # readback is in progress. Its discovery never replays input.
                if command == "input" and claims_released and not stop.is_set():
                    try:
                        result.update(new_visible_followups(grant.identity, before_windows,
                            bind_allowed=not self.store.task_write_stopped(grant.task_id)))
                    except (NativeInputError, ControlError):
                        result.update(visual_scope_incomplete=True)
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
