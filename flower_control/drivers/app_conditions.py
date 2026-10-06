"""Fresh state matching and bounded wait, adapted from legacy ConditionService."""
from dataclasses import dataclass
import time


@dataclass(frozen=True)
class Condition:
    kind: str
    expected: object


class ConditionService:
    def __init__(self, read, *, stopped=lambda: False, sleep=time.sleep):
        self.read, self.stopped, self.sleep = read, stopped, sleep

    @staticmethod
    def validate(condition):
        fields = {"enabled", "focused", "selected", "offscreen", "name", "value", "toggle_state", "expand_collapse_state"}
        if (type(condition.kind) is not str or condition.kind not in fields
                or condition.kind in {"enabled", "focused", "selected", "offscreen"} and type(condition.expected) is not bool
                or condition.kind in {"name", "value", "toggle_state", "expand_collapse_state"}
                and (type(condition.expected) is not str or len(condition.expected) > 8192)):
            raise ValueError("invalid_app_condition")

    @staticmethod
    def matches(observed, condition):
        # A short Value/name preview is not an exact full-value Oracle.
        return (not observed.get("password", True)
                and condition.kind in observed
                and not observed.get(condition.kind + "_truncated", False)
                and not observed.get(condition.kind + "_read_error", False)
                and observed[condition.kind] == condition.expected)

    def wait(self, condition, *, deadline, stable_observations=1):
        from flower_control.control.state import ControlError
        self.validate(condition)
        consecutive = 0
        while True:
            if self.stopped():
                raise ControlError("action_cancelled")
            observed = self.read()
            if self.stopped():
                raise ControlError("action_cancelled")
            consecutive = consecutive + 1 if self.matches(observed, condition) else 0
            if consecutive >= stable_observations:
                return observed
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            self.sleep(min(remaining, .05))
