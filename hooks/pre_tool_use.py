"""Plugin-bundled synchronous Hook for an exact Flower MCP probe."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from flower_control.authorization.hook_bridge import issue_for_hook, live_ledger  # noqa: E402
from flower_control.authorization.origin import OriginError  # noqa: E402
from flower_control.control.state import ControlError  # noqa: E402


def main(*, host: str = "codex") -> int:
    try:
        body = sys.stdin.buffer.read(8 * 1024 * 1024 + 1)
        if len(body) > 8 * 1024 * 1024:
            raise ValueError("hook_event_too_large")
        result = issue_for_hook(json.loads(body), live_ledger(), host=host)
    except Exception as error:
        # Report only a fixed internal code, never the event or exception text:
        # tool arguments can contain passwords and private page content.
        code = (error.code if isinstance(error, (OriginError, ControlError))
                and re.fullmatch(r"[a-z][a-z0-9_]{0,79}", error.code)
                else "hook_internal_error")
        sys.stderr.write(f"flower_hook_denied:{code}\n")
        result = {"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "deny",
            "permissionDecisionReason": f"Flower 调用来源未获验证（{code}）。",
        }}
    # Hook stdout can use a legacy Windows code page.  Escaping JSON to ASCII
    # preserves Chinese/emoji tool arguments without relying on that encoding.
    sys.stdout.buffer.write(json.dumps(result, ensure_ascii=True,
                                       separators=(",", ":")).encode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
