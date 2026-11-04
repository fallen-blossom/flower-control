"""Bounded local display metadata; never used for admission or authority."""
import json
import os
from pathlib import Path
import tempfile


def read_display() -> dict:
    try:
        path = Path(os.environ.get("FLOWER_DSH_DISPLAY", ""))
        if (path.name != "display.json" or not path.parent.name.startswith("flower-dsh-display-")
                or path.parent.parent.resolve() != Path(tempfile.gettempdir()).resolve()
                or any(p.is_symlink() or p.is_junction() for p in (path, *path.parents))):
            return {}
        with path.open("rb") as handle:
            data = handle.read(4097)
        if len(data) > 4096:
            return {}
        row = json.loads(data)
        if (not isinstance(row, dict) or row.get("session_id") != os.environ.get("FLOWER_DSH_CHAT_ID")
                or row.get("source") != "dsh-session-request-header"):
            return {}
        values = {k: row.get(k) for k in ("model", "provider", "title")}
        if any(v is not None and (not isinstance(v, str) or len(v) > 256 or any(ord(c) < 32 or ord(c) == 127 for c in v))
               for v in values.values()):
            return {}
        return values
    except (OSError, ValueError, TypeError):
        return {}
