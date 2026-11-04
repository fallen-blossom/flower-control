"""Local browser choice and installation metadata; never reads account data."""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
from pathlib import Path
import uuid

from .browsers import (browser_family, browser_install_candidates, _trusted_install_candidate,
                       resolve_browser_executable, BROWSER_ALIASES)
from .control.state import ControlError
from .profile_registry import direct_path, profile_paths

FILE_NAME = "browser-preferences.json"
BROWSER_NAMES = {"brave": "Brave", "edge": "Microsoft Edge", "chrome": "Google Chrome"}


def canonical_browser(value):
    if not isinstance(value, str):
        raise ControlError("unsupported_browser_executable")
    name = BROWSER_ALIASES.get(value.lower(), value.lower())
    if name == "chrome-x86":
        name = "chrome"
    if name not in BROWSER_NAMES:
        raise ControlError("unsupported_browser_executable")
    return name


def installed_browsers():
    result = []
    for name, label in BROWSER_NAMES.items():
        path = next((p for p in browser_install_candidates(name) if _trusted_install_candidate(p)), None)
        if path is not None:
            result.append({"browser": name, "name": label, "executable": str(path)})
    return result


def windows_default_browser():
    if os.name != "nt":
        return {"browser": None, "name": "未知", "executable": None}
    try:
        from ctypes import wintypes
        api = ctypes.WinDLL("shlwapi").AssocQueryStringW
        api.argtypes = [wintypes.DWORD, ctypes.c_int, wintypes.LPCWSTR, wintypes.LPCWSTR,
                        wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        api.restype = ctypes.c_long
        size = wintypes.DWORD(32768)
        buffer = ctypes.create_unicode_buffer(size.value)
        if api(0, 2, "https", None, buffer, ctypes.byref(size)) != 0:
            raise ValueError("association_unavailable")
        executable = Path(buffer.value)
        try:
            name = browser_family(executable)
            return {"browser": name, "name": BROWSER_NAMES[name], "executable": str(executable)}
        except ValueError:
            label = "Mozilla Firefox" if executable.name.lower() == "firefox.exe" else "不支持的浏览器"
            return {"browser": None, "name": label, "executable": None}
    except (OSError, ValueError):
        return {"browser": None, "name": "未知", "executable": None}


def read_preferences(root):
    path = direct_path(Path(root) / FILE_NAME)
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return {"schema": 1, "default_browser": "system"}, None
    except OSError as error:
        raise ControlError("browser_preferences_unverified") from error
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
        if (type(value) is not dict or set(value) != {"schema", "default_browser"}
                or type(value["schema"]) is not int or value["schema"] != 1
                or value["default_browser"] not in {"system", *BROWSER_NAMES}):
            raise ValueError("shape")
        return value, hashlib.sha256(raw).hexdigest()
    except (ValueError, TypeError) as error:
        raise ControlError("browser_preferences_unverified") from error


def selected_browser(root):
    value, revision = read_preferences(root)
    installed = installed_browsers()
    available = {row["browser"]: row for row in installed}
    choice = value["default_browser"]
    if choice == "system":
        legacy = os.environ.get("FLOWER_WEB_BROWSER") if revision is None else None
        if legacy:
            try:
                path = resolve_browser_executable(legacy)
                name = browser_family(path)
            except ValueError:
                # Preserve the prior invalid-environment fallback. An explicit
                # valid selection that was uninstalled still requires repair.
                path = None
            if path is not None:
                if not path.is_file():
                    raise ControlError("selected_browser_not_installed")
                return name, path
        system = windows_default_browser()["browser"]
        choice = system if system in available else "brave" if "brave" in available else next(iter(available), None)
    if choice not in available:
        raise ControlError("selected_browser_not_installed")
    return choice, Path(available[choice]["executable"])


def browser_profiles(root, browser):
    name = canonical_browser(browser)
    if name == "brave":
        return profile_paths(root)
    base = direct_path(Path(root) / "profiles")
    result = {kind: direct_path(base / f"{kind}-{name}-v1") for kind in ("ai", "luohua")}
    legacy = profile_paths(root)
    if any(path in legacy.values() for path in result.values()):
        raise ControlError("browser_profile_storage_collision")
    return result


def inventory(root):
    rows = installed_browsers()
    value, revision = read_preferences(root)
    try:
        family, path = selected_browser(root)
        selection = {"browser": family, "name": BROWSER_NAMES[family], "executable": str(path)}
        reason = None
    except ControlError as error:
        selection, reason = None, error.code
    return {"schema": 1, "installed": rows, "windows_default": windows_default_browser(),
            "preference": value["default_browser"], "revision": revision, "selected": selection,
            "reason": reason, "account_data_read": False, "authorization_issued": False}


def save_preferences(root, choice, expected_revision):
    """One local UI save, CAS-bound; never changes a grant or Windows default."""
    if type(choice) is not str or choice not in {"system", *BROWSER_NAMES}:
        raise ControlError("unsupported_browser_executable")
    if expected_revision is not None and (type(expected_revision) is not str or len(expected_revision) != 64
            or any(c not in "0123456789abcdef" for c in expected_revision)):
        raise ControlError("browser_preferences_revision_required")
    root = direct_path(Path(root)); path = direct_path(root / FILE_NAME)
    if choice != "system" and choice not in {row["browser"] for row in installed_browsers()}:
        raise ControlError("selected_browser_not_installed")
    import win32api
    import win32event
    name = "Local\\FlowerControl.BrowserPreferences." + hashlib.sha256(str(path).replace('/', '\\').lower().encode()).hexdigest()
    mutex = win32event.CreateMutex(None, False, name)
    acquired = False
    temporary = direct_path(path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp"))
    try:
        acquired = win32event.WaitForSingleObject(mutex, 3000) in (0, 0x80)
        if not acquired:
            raise ControlError("browser_preferences_busy")
        _, current = read_preferences(root)
        if current != expected_revision:
            raise ControlError("browser_preferences_conflict")
        root.mkdir(parents=True, exist_ok=True); direct_path(root)
        raw = (json.dumps({"schema": 1, "default_browser": choice}, separators=(",", ":")) + "\n").encode()
        with temporary.open("xb") as output:
            output.write(raw); output.flush(); os.fsync(output.fileno())
        direct_path(path)
        if read_preferences(root)[1] != expected_revision:
            raise ControlError("browser_preferences_conflict")
        os.replace(temporary, path)
        value, revision = read_preferences(root)
        if revision != hashlib.sha256(raw).hexdigest():
            raise ControlError("browser_preferences_save_unconfirmed")
        return {"state": "saved", "default_browser": value["default_browser"], "revision": revision,
                "windows_default_changed": False, "authorization_issued": False}
    finally:
        if temporary.exists():
            temporary.unlink()  # Exact unpublished metadata created by this call.
        if acquired:
            win32event.ReleaseMutex(mutex)
        win32api.CloseHandle(mutex)
