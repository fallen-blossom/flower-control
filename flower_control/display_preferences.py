"""Ordinary local presentation preference; never a permission or Stop source."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import uuid

from .control.state import ControlError
from .profile_registry import direct_path

FILE_NAME = "display-preferences.json"
LANGUAGES = frozenset({"zh-CN", "en"})
DEFAULT_LANGUAGE = "zh-CN"


def read_preferences(root):
    path = direct_path(Path(root) / FILE_NAME)
    try:
        with path.open("rb") as stream:
            raw = stream.read(4097)
    except FileNotFoundError:
        return {"schema": 1, "language": DEFAULT_LANGUAGE}, None
    except OSError as error:
        raise ControlError("display_preferences_unverified") from error
    try:
        if len(raw) > 4096:
            raise ValueError("size")
        def unique(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError("duplicate")
                value[key] = item
            return value
        value = json.loads(raw, object_pairs_hook=unique)
        if (type(value) is not dict or set(value) != {"schema", "language"}
                or type(value["schema"]) is not int or value["schema"] != 1
                or type(value["language"]) is not str or value["language"] not in LANGUAGES):
            raise ValueError("shape")
        return value, hashlib.sha256(raw).hexdigest()
    except (ValueError, TypeError, UnicodeError) as error:
        raise ControlError("display_preferences_unverified") from error


def _require_medium_writer():
    import win32api
    import win32con
    import win32security
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    try:
        label = win32security.GetTokenInformation(token, win32security.TokenIntegrityLevel)
        sid = label[0] if isinstance(label, tuple) else label
        integrity = int(win32security.ConvertSidToStringSid(sid).rsplit("-", 1)[1])
        if integrity != 8192 or win32security.GetTokenInformation(token, win32security.TokenElevation):
            raise ControlError("display_preferences_medium_required")
    finally:
        token.Close()


def save_preferences(root, language, expected_revision):
    if type(language) is not str or language not in LANGUAGES:
        raise ControlError("invalid_display_language")
    if expected_revision is not None and (type(expected_revision) is not str or len(expected_revision) != 64
            or any(c not in "0123456789abcdef" for c in expected_revision)):
        raise ControlError("display_preferences_revision_required")
    _require_medium_writer()
    root = direct_path(Path(root)); path = direct_path(root / FILE_NAME)
    import win32api
    import win32event
    name = "Local\\FlowerControl.DisplayPreferences." + hashlib.sha256(str(path).replace("/", "\\").lower().encode()).hexdigest()
    mutex = win32event.CreateMutex(None, False, name)
    acquired = False
    temporary = direct_path(path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp"))
    try:
        acquired = win32event.WaitForSingleObject(mutex, 3000) in (0, 0x80)
        if not acquired:
            raise ControlError("display_preferences_busy")
        _, current = read_preferences(root)
        if current != expected_revision:
            raise ControlError("display_preferences_conflict")
        root.mkdir(parents=True, exist_ok=True); direct_path(root)
        raw = (json.dumps({"schema": 1, "language": language}, separators=(",", ":")) + "\n").encode()
        with temporary.open("xb") as output:
            output.write(raw); output.flush(); os.fsync(output.fileno())
        direct_path(path)
        if read_preferences(root)[1] != expected_revision:
            raise ControlError("display_preferences_conflict")
        os.replace(temporary, path)
        value, revision = read_preferences(root)
        if revision != hashlib.sha256(raw).hexdigest():
            raise ControlError("display_preferences_save_unconfirmed")
        return {"state": "saved", "language": value["language"], "revision": revision,
                "permissions_changed": False, "stop_changed": False, "services_changed": False}
    finally:
        if temporary.exists():
            temporary.unlink()  # Only this call's exact unpublished metadata.
        if acquired:
            win32event.ReleaseMutex(mutex)
        win32api.CloseHandle(mutex)
