"""Fixed authenticated DSH lifecycle adapter; metadata only, never authority."""
from __future__ import annotations

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main():
    receipt = None
    failed = False
    try:
        raw = sys.stdin.buffer.read(4097)
        if len(raw) > 4096:
            raise ValueError("event_too_large")
        event = json.loads(raw)
        from flower_control.authorization.hook_bridge import state_directory
        directory = state_directory()
        if (directory / "control.sqlite3").is_file():
            from flower_control.control.host_phase import PhasePublisher, publish_dsh_event
            receipt = publish_dsh_event(PhasePublisher(directory), event)
    except Exception:
        failed = True
        sys.stderr.write("flower_dsh_phase_unavailable\n")
    print(json.dumps({"phase": "dsh_phase", "state": "unavailable" if failed else "published" if receipt is not None else "ignored"}))
    return 2 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
