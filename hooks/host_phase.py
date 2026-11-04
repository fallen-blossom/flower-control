"""Advisory metadata-only lifecycle Hook. It never approves or denies tools."""
from __future__ import annotations

import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

def _metadata(event):
    """Pure native metadata guard before state resolution or runtime imports."""
    if type(event) is not dict:
        return None
    kind = event.get("hook_event_name")
    if type(kind) is not str or kind not in {"PreToolUse", "PostToolUse", "Stop", "Interrupt", "SessionEnd"}:
        return None
    def identifier(value):
        return (type(value) is str and 1 <= len(value) <= 256 and value == value.strip()
                and all(ord(char) >= 32 and ord(char) != 127 for char in value))
    session, turn = event.get("session_id"), event.get("turn_id")
    if not identifier(session) or (kind != "SessionEnd" and not identifier(turn)):
        return None
    result = {"hook_event_name": kind, "session_id": session}
    if kind != "SessionEnd":
        result["turn_id"] = turn
    if kind in {"PreToolUse", "PostToolUse"}:
        tool, use = event.get("tool_name"), event.get("tool_use_id")
        if (type(tool) is not str or re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", tool) is None
                or not identifier(use) or re.match(r"mcp__(?:plugin_flower-control_)?flower[-_](?:web|app|computer)__", tool)):
            return None
        result.update(tool_name=tool, tool_use_id=use)
    return result

def main():
    try:
        raw = sys.stdin.buffer.read(8 * 1024 * 1024 + 1)
        if len(raw) > 8 * 1024 * 1024:
            raise ValueError("event_too_large")
        event = _metadata(json.loads(raw))
        if event is not None:
            from flower_control.authorization.hook_bridge import state_directory
            directory = state_directory()
            if (directory / "control.sqlite3").is_file():
                from flower_control.control.host_phase import PhasePublisher, publish_event
                publish_event(PhasePublisher(directory), event)
    except Exception:
        # Never include event fields, payloads, paths or exception text.
        sys.stderr.write("flower_host_phase_unavailable\n")
    sys.stdout.buffer.write(b"{}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
