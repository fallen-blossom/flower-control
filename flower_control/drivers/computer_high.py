"""Computer's closed input conversion and task-owned global broker connections."""
from __future__ import annotations

import ctypes
from dataclasses import asdict
import threading
import win32api

from . import computer_native as native
from .high_broker_types import ComputerInputPlan, InputBinding, WindowLayoutPlan
from .high_helper import HighHelperError, HighTarget


def _event(step):
    # Validate the native DTO again; never pass arbitrary INPUT bytes or flags.
    step.__post_init__()
    if step.raw.type == 1:
        if step.token[0] == "unicode":
            return {"kind": "unicode_key", "unit": step.token[1], "down": step.pressed}
        return {"kind": "virtual_key", "code": step.token[1], "down": step.pressed}
    mouse = step.raw.data.mi
    if step.token is not None:
        button = tuple(native._BUTTON_FLAGS)[step.token[1]]
        if button not in {"left", "right", "middle"}:
            raise ValueError("input button is outside the Computer contract")
        return {"kind": "mouse_button", "button": button, "down": step.pressed}
    if mouse.dwFlags == native.MOUSEEVENTF_MOVE:
        return {"kind": "mouse_relative", "dx": mouse.dx, "dy": mouse.dy}
    if mouse.dwFlags in (native.MOUSEEVENTF_WHEEL, 0x1000):
        return {"kind": "mouse_wheel", "axis": "horizontal" if mouse.dwFlags == 0x1000 else "vertical",
                "delta": ctypes.c_int32(mouse.mouseData).value}
    if step.desktop is None:
        raise ValueError("absolute input is missing its observed desktop")
    return {"kind": "mouse_absolute", "nx": mouse.dx, "ny": mouse.dy}


def input_plan(command, batches, *, task, action, observation, generation, sequence_step=None):
    binding = InputBinding(task, action, observation, generation, sequence_step)
    desktop, plans = None, []
    for batch in batches:
        batch.__post_init__()
        for step in batch.steps:
            if step.desktop is not None:
                shape = asdict(step.desktop)
                if desktop is not None and shape != desktop:
                    raise ValueError("input desktop changed inside a plan")
                desktop = shape
        timed = isinstance(batch, native.TimedInputPlan)
        segments = batch.segments if timed else ((0, batch.steps),)
        plans.append({"duration_ms": batch.duration_ms if timed else 0,
                      "segments": [{"offset_ms": offset, "events": [_event(step) for step in steps]}
                                   for offset, steps in segments]})
    return ComputerInputPlan.from_wire({"kind": "computer_input_plan", "schema_version": 1,
        "command": command, "binding": binding.wire(), "desktop": desktop, "plans": plans})


def layout_environment():
    """Read physical desktop and all monitor work areas for one observation."""
    desktop = asdict(native.virtual_desktop())
    try:
        areas = tuple(sorted(tuple(win32api.GetMonitorInfo(handle)["Work"])
                             for handle, _dc, _rect in win32api.EnumDisplayMonitors()))
    except win32api.error as error:
        raise native.NativeInputError("desktop_topology_unavailable") from error
    return desktop, areas


def window_layout_plan(command, arguments, geometry, environment, *, task, action,
                       observation, generation):
    keys = {"dx", "dy"} if command == "window_move" else {"width", "height"}
    if (command not in {"window_move", "window_resize"} or type(arguments) is not dict
            or set(arguments) != keys or any(type(n) is not int for n in arguments.values())):
        raise ValueError("window_layout_rejected")
    if environment is None:
        raise ValueError("window_layout_requires_new_observation")
    rect = geometry.window
    if command == "window_move":
        dx, dy = arguments["dx"], arguments["dy"]
        requested = (rect.left + dx, rect.top + dy, rect.right + dx, rect.bottom + dy)
    else:
        requested = (rect.left, rect.top, rect.left + arguments["width"], rect.top + arguments["height"])
    desktop, areas = environment
    return WindowLayoutPlan.create(command, requested,
        InputBinding(task, action, observation, generation), desktop=desktop, work_areas=areas)


def assert_target_geometry(target: HighTarget, geometry):
    if (target.hwnd != geometry.identity.hwnd or target.facts["Pid"] != geometry.identity.pid
            or target.process_created != geometry.identity.process_created or target.nonce != geometry.identity.window_nonce
            or target.bounds != (geometry.window.left, geometry.window.top, geometry.window.right, geometry.window.bottom)
            or target.client_rect is None
            or (target.client_rect[2] - target.client_rect[0], target.client_rect[3] - target.client_rect[1]) != geometry.client_size
            or target.client_origin != geometry.client_origin or target.window_dpi != geometry.dpi):
        raise native.NativeInputError("geometry_changed")


class ComputerHighConnection:
    """No elevation/install/idle shutdown; close only this task's connection."""
    UNAVAILABLE = frozenset({"broker_not_installed", "broker_unavailable"})

    def __init__(self, factory):
        self.factory = factory
        self.client = None
        self.sessions = {}
        self.gate = threading.RLock()

    def session(self, task):
        with self.gate:
            if self.client is None:
                self.client = self.factory()
            if task in self.sessions and self.sessions[task].lifecycle.get("connection_closed") is True:
                self.sessions.pop(task)
            if task not in self.sessions:
                self.sessions[task] = self.client.open_session(task)
            return self.sessions[task]

    def discard(self, task):
        with self.gate:
            session = self.sessions.pop(task, None)
        if session is not None:
            session.close()

    def status(self, task):
        try:
            return self.session(task).status()
        except HighHelperError as error:
            if error.code in self.UNAVAILABLE:
                self.discard(task)
                return None
            raise

    @staticmethod
    def require_input(status):
        for field, reason in (("paused", "broker_paused"), ("desktop_locked", "desktop_locked"),
                              ("stopping", "broker_stopping"), ("release_fault", "broker_release_fault")):
            if status.facts.get(field) is True:
                raise HighHelperError(reason)

    def close(self):
        with self.gate:
            tasks = tuple(self.sessions)
        for task in tasks:
            self.discard(task)
