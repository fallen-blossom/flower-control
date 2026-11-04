"""Pure fixed lifecycle Hook rendering; no package, settings or process I/O."""
from copy import deepcopy

BACKEND_MATCHER = "*"  # Native HookMatcher wildcard, without Rust regex lookaround.
PHASE_EVENTS = ("PreToolUse", "PostToolUse", "Stop", "Interrupt", "SessionEnd")

def add_phase_hooks(hooks, command):
    result = deepcopy(hooks)
    for event in PHASE_EVENTS:
        row = {"hooks": [{"type": "command", "command": command, "timeout": 1}]}
        if event in {"PreToolUse", "PostToolUse"}:
            row["matcher"] = BACKEND_MATCHER
        result["hooks"].setdefault(event, []).append(row)
    return result
