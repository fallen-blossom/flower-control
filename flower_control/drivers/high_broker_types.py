"""Closed broker payloads. These carry existing scope; they never grant it."""
from __future__ import annotations

from dataclasses import dataclass
import json


def _text(value, maximum):
    if type(value) is not str or not 1 <= len(value) <= maximum or any(ord(c) < 32 for c in value):
        raise ValueError("input_binding_rejected")
    return value


@dataclass(frozen=True)
class InputBinding:
    task_id: str
    action_id: str
    observation_id: str | None
    generation: str | None
    sequence_step: int | None = None

    def __post_init__(self):
        for name, maximum in (("task_id", 128), ("action_id", 512)):
            _text(getattr(self, name), maximum)
        if (self.observation_id is None) != (self.generation is None):
            raise ValueError("input_binding_rejected")
        if self.observation_id is not None:
            _text(self.observation_id, 256)
            _text(self.generation, 4096)
        if self.sequence_step is not None and (type(self.sequence_step) is not int or not 0 <= self.sequence_step <= 2):
            raise ValueError("input_binding_rejected")
        if self.observation_id is None and self.sequence_step is not None:
            raise ValueError("input_binding_rejected")

    def require_observation(self):
        if self.observation_id is None:
            raise ValueError("input_observation_required")

    def wire(self):
        return dict(task_id=self.task_id, action_id=self.action_id, observation_id=self.observation_id,
                    generation=self.generation, sequence_step=self.sequence_step)

    def result_wire(self):
        return dict(TaskId=self.task_id, ActionId=self.action_id, ObservationId=self.observation_id,
                    Generation=self.generation, SequenceStep=self.sequence_step)


@dataclass(frozen=True)
class ComputerInputPlan:
    """Immutable wire snapshot; the native executor validates every finite event."""
    encoded: bytes
    binding: InputBinding

    @classmethod
    def from_wire(cls, value):
        if type(value) is not dict or set(value) != {"kind", "schema_version", "command", "binding", "desktop", "plans"}:
            raise ValueError("input_plan_rejected")
        if value["kind"] != "computer_input_plan" or type(value["schema_version"]) is not int or value["schema_version"] != 1:
            raise ValueError("input_plan_rejected")
        if value["command"] not in {"text", "key", "click", "double_click", "scroll", "drag", "move_relative", "key_mouse", "mouse_hold", "move", "hover", "batch"}:
            raise ValueError("input_plan_rejected")
        binding = value["binding"]
        if type(binding) is not dict or set(binding) != {"task_id", "action_id", "observation_id", "generation", "sequence_step"}:
            raise ValueError("input_binding_rejected")
        bound = InputBinding(**binding)
        bound.require_observation()
        if type(value["plans"]) is not list or not 1 <= len(value["plans"]) <= 131:
            raise ValueError("input_plan_rejected")
        encoded = json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("ascii")
        if len(encoded) > 2 * 1024 * 1024 - 8192:
            raise ValueError("input_plan_rejected")
        return cls(encoded, bound)

    def wire(self):
        return json.loads(self.encoded)

    def operation(self, *, restore_minimized=False):
        if type(restore_minimized) is not bool:
            raise ValueError("operation_rejected")
        return {"Kind": "computer_input_plan", "Plan": self.wire(), "RestoreMinimized": restore_minimized}


def _layout_rect(value):
    if (type(value) not in (list, tuple) or len(value) != 4
            or any(type(n) is not int or not -(1 << 31) <= n < 1 << 31 for n in value)
            or value[0] >= value[2] or value[1] >= value[3]):
        raise ValueError("window_layout_rejected")
    return tuple(value)


def _covered_by_work_areas(rect, areas):
    left, top, right, bottom = rect
    edges = sorted({left, right, *(max(left, min(right, a[i])) for a in areas for i in (0, 2))})
    for x1, x2 in zip(edges, edges[1:]):
        cursor = top
        intervals = sorted((max(top, a[1]), min(bottom, a[3])) for a in areas
                           if a[0] <= x1 and a[2] >= x2 and a[1] < bottom and a[3] > top)
        for y1, y2 in intervals:
            if y1 > cursor:
                return False
            cursor = max(cursor, y2)
        if cursor < bottom:
            return False
    return True


@dataclass(frozen=True)
class WindowLayoutPlan:
    """One fixed, observed window layout operation; no caller-selected flags."""
    encoded: bytes
    binding: InputBinding

    @classmethod
    def create(cls, command, requested_rect, binding, *, desktop, work_areas):
        if type(binding) is not InputBinding:
            raise ValueError("input_binding_rejected")
        return cls.from_wire(dict(kind="window_layout", schema_version=1, command=command,
                                  binding=binding.wire(), requested_rect=list(requested_rect),
                                  desktop=desktop, work_areas=[list(a) for a in work_areas]))

    @classmethod
    def from_wire(cls, value):
        if (type(value) is not dict or set(value) != {"kind", "schema_version", "command", "binding", "requested_rect", "desktop", "work_areas"}
                or value["kind"] != "window_layout" or type(value["schema_version"]) is not int or value["schema_version"] != 1
                or value["command"] not in {"window_move", "window_resize"}):
            raise ValueError("window_layout_rejected")
        raw_binding = value["binding"]
        if type(raw_binding) is not dict or set(raw_binding) != {"task_id", "action_id", "observation_id", "generation", "sequence_step"}:
            raise ValueError("input_binding_rejected")
        binding = InputBinding(**raw_binding)
        binding.require_observation()
        rect = _layout_rect(value["requested_rect"])
        width, height = rect[2] - rect[0], rect[3] - rect[1]
        if width > 16384 or height > 16384 or width * height > 16777216:
            raise ValueError("window_layout_budget_exceeded")
        desktop = value["desktop"]
        if (type(desktop) is not dict or set(desktop) != {"left", "top", "width", "height"}
                or any(type(n) is not int for n in desktop.values())
                or not 1 <= desktop["width"] <= 100000 or not 1 <= desktop["height"] <= 100000):
            raise ValueError("window_layout_rejected")
        extent = _layout_rect([desktop["left"], desktop["top"], desktop["left"] + desktop["width"], desktop["top"] + desktop["height"]])
        raw_areas = value["work_areas"]
        if type(raw_areas) is not list or not 1 <= len(raw_areas) <= 32:
            raise ValueError("window_layout_rejected")
        areas = sorted(_layout_rect(a) for a in raw_areas)
        if len(set(areas)) != len(areas) or any(a[0] < extent[0] or a[1] < extent[1] or a[2] > extent[2] or a[3] > extent[3] for a in areas):
            raise ValueError("window_layout_rejected")
        if not _covered_by_work_areas(rect, areas):
            raise ValueError("window_layout_outside_work_area")
        snapshot = {**value, "binding": binding.wire(), "requested_rect": list(rect),
                    "desktop": dict(desktop), "work_areas": [list(a) for a in areas]}
        return cls(json.dumps(snapshot, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("ascii"), binding)

    def wire(self):
        return json.loads(self.encoded)

    def operation(self):
        return {"Kind": "window_layout", "Plan": self.wire()}


@dataclass(frozen=True)
class AppRequest:
    """Fixed UIA worker request; never an executable or free-form command."""
    command: str
    encoded_arguments: bytes
    binding: InputBinding

    @classmethod
    def create(cls, command, arguments, binding: InputBinding):
        from .app_worker import validate_request, MAX_MESSAGE
        if type(binding) is not InputBinding:
            raise ValueError("input_binding_rejected")
        if command not in {"observe", "close_window"}:
            binding.require_observation()
        if command == "close_window":
            if type(arguments) is not dict or set(arguments) != {"target"} or type(arguments["target"]) is not dict:
                raise ValueError("app_request_rejected")
            target = arguments["target"]
            if set(target) != {"pid", "hwnd", "process_start_filetime", "root_runtime_id"} or any(type(target[k]) is not int or target[k] <= 0 for k in ("pid", "hwnd", "process_start_filetime")):
                raise ValueError("app_request_rejected")
        else:
            validate_request(command, arguments)
        encoded = json.dumps(arguments, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("ascii")
        if len(encoded) >= MAX_MESSAGE:
            raise ValueError("app_request_rejected")
        return cls(command, encoded, binding)

    def operation(self, *, activate=False, restore_minimized=False):
        if (type(activate) is not bool or type(restore_minimized) is not bool
                or activate and self.command not in {"invoke", "focus", "guarded_input"}
                or restore_minimized and not activate or self.command == "guarded_input" and not activate):
            raise ValueError("app_activation_rejected")
        return {"Kind": "app_request", "Plan": {"schema_version": 1, "command": self.command,
                "arguments": json.loads(self.encoded_arguments), "binding": self.binding.wire()},
                "Activate": activate, "RestoreMinimized": restore_minimized}
