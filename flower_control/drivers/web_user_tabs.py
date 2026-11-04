"""Identify manually opened tabs in the exact shared browser instance."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from flower_control.control.state import ControlError
from flower_control.profile_registry import direct_path
from .web_page_registry import page_registry


def other_borrower_targets(download_directory, browser_process, task):
    """Read only non-content ownership metadata, never another page's data."""
    if not download_directory:
        raise ControlError("shared_browser_identity_unverified")
    instance = direct_path(Path(download_directory).parent)
    if not re.fullmatch(r"[0-9a-f]{32}", instance.name):
        raise ControlError("shared_browser_identity_unverified")
    own = hashlib.sha256(task.encode()).hexdigest()
    files = list(instance.glob("*.json"))
    if len(files) > 256:
        raise ControlError("shared_browser_borrower_recovery_required")
    result = set()
    for path in files:
        path = direct_path(path)
        if path.stem == own:
            continue
        try:
            if not re.fullmatch(r"[0-9a-f]{64}", path.stem) or path.stat().st_size > 200000:
                raise ValueError()
            row = json.loads(path.read_bytes())
            if type(row) is not dict:
                raise ValueError()
            pages = row["pages"]
            if (row.get("schema") != 1 or row.get("browser_id") != instance.name
                    or row.get("browser_process") != browser_process or row.get("task_key") != path.stem
                    or type(pages) is not dict or page_registry(pages) != pages):
                raise ValueError()
            result.update(pages)
        except (OSError, ValueError, TypeError, KeyError):
            raise ControlError("shared_browser_borrower_recovery_required") from None
    return result
