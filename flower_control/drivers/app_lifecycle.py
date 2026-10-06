"""Bounded launch and normal-close primitives for an authorized ordinary app.

The public App entrypoint supplies task authority and a selected window resolver.
This module neither adopts arbitrary existing processes nor terminates an app.
"""

from __future__ import annotations

import os
import subprocess
import time
from dataclasses import asdict
from pathlib import Path
from typing import Callable

import win32con
import win32gui
import win32process

from flower_control.control.native import process_creation_filetime
from flower_control.local_target import _process_image_and_liveness
from flower_control.drivers.computer_native import (WindowIdentity, assert_window,
                                                    bind_window, is_owned_popup)
from flower_control.drivers.app_process_chain import LaunchChain, handle_times


class AppLifecycleError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def safe_launch_diagnostic(result):
    """Persist identity/status only, never executable arguments or titles."""
    diagnostic = {}
    for name in ("pid", "process_start_filetime"):
        if type(result.get(name)) is int and result[name] > 0:
            diagnostic[name] = result[name]
    for name, choices in {
            "state": {"window_candidates", "window_pending", "process_exited", "outcome_uncertain", "rejected"},
            "handoff_status": {"descendant_window_observed", "direct_window_observed", "unresolved"},
            "launch_chain_reason": {"launch_chain_unavailable", "launch_chain_partial", "launch_chain_observation_failed"},
            "reason": {"process_identity_unavailable", "launch_authority_changed", "launch_observation_failed"}}.items():
        if result.get(name) in choices:
            diagnostic[name] = result[name]
    for name in ("process_running", "window_selection_required"):
        if type(result.get(name)) is bool:
            diagnostic[name] = result[name]
    related = []
    for identity in result.get("related_processes", [])[:16]:
        if (type(identity) is dict and type(identity.get("pid")) is int and identity["pid"] > 0
                and type(identity.get("process_start_filetime")) is int and identity["process_start_filetime"] > 0):
            related.append({name: identity[name] for name in
                ("pid", "process_start_filetime", "parent_pid", "depth", "process_running") if name in identity})
    diagnostic["related_processes"] = related
    existing = result.get("existing_instance")
    if type(existing) is dict and type(existing.get("target")) is dict:
        target = existing["target"]
        if all(type(target.get(name)) is int and target[name] > 0
               for name in ("pid", "hwnd", "process_start_filetime")):
            diagnostic["existing_instance"] = {"target": {name: target[name] for name in
                ("pid", "hwnd", "process_start_filetime")}, "diagnostic_only": True,
                "command_delivery_verified": False, "launcher_handoff_proven": False}
    diagnostic["automatic_window_selection"] = False
    diagnostic["next_step"] = "list_windows_and_match_exact_process_identity_then_select"
    return diagnostic


def _ordinary_environment() -> dict[str, str]:
    """Pass normal Windows app paths, excluding inherited provider credentials."""
    allowed = {"SystemRoot", "SystemDrive", "WINDIR", "COMSPEC", "PATH", "PATHEXT",
               "TEMP", "TMP", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
               "PROGRAMDATA", "PROGRAMFILES", "PROGRAMFILES(X86)",
               "COMMONPROGRAMFILES", "COMMONPROGRAMFILES(X86)",
               "HOMEDRIVE", "HOMEPATH", "PUBLIC", "LANG", "LC_ALL"}
    names = {name.upper() for name in allowed}
    result = {key: value for key, value in os.environ.items()
              if key.upper() in names}
    if not any(key.upper() in {"SYSTEMROOT", "WINDIR"} for key in result):
        raise AppLifecycleError("windows_system_root_missing")
    return result


def _visible_windows(pid: int, created: int) -> list[dict]:
    found: list[dict] = []

    def collect(hwnd: int, _unused: object) -> None:
        if len(found) >= 16 or not win32gui.IsWindow(hwnd) or not win32gui.IsWindowVisible(hwnd):
            return
        if win32gui.GetAncestor(hwnd, win32con.GA_ROOT) != hwnd:
            return
        try:
            if (win32process.GetWindowThreadProcessId(hwnd)[1] != pid or
                    process_creation_filetime(pid) != created):
                return
            identity = bind_window(hwnd)
            assert_window(identity)
            found.append({"target": asdict(identity),
                          "title": win32gui.GetWindowText(hwnd)[:160],
                          "minimized": bool(win32gui.IsIconic(hwnd))})
        except Exception:
            return

    win32gui.EnumWindows(collect, None)
    return found


def launch_application(executable: str, args: list[str], *, mode: str,
                       preflight: Callable[[], None],
                       window_wait_seconds: float = 3.0,
                       existing_identity: WindowIdentity | None = None,
                       resolve_existing: Callable[[], WindowIdentity] | None = None) -> dict:
    """Start an exact executable once; return its process and candidate windows."""
    if (type(executable) is not str or not executable or "\x00" in executable
            or type(args) is not list or len(args) > 32
            or any(type(arg) is not str or "\x00" in arg or len(arg) > 2048 for arg in args)
            or sum(len(arg) for arg in args) > 8192 or mode not in {"normal", "background"}
            or type(window_wait_seconds) not in (int, float)
            or not 0 <= window_wait_seconds <= 5 or not callable(preflight)):
        raise AppLifecycleError("invalid_launch_request")
    path = Path(executable)
    if not path.is_absolute() or not path.is_file() or path.suffix.lower() != ".exe":
        raise AppLifecycleError("executable_not_found")
    path = path.resolve(strict=True)
    if path.suffix.lower() != ".exe" or not path.is_file():
        raise AppLifecycleError("executable_not_found")
    if path.name.lower() in {"brave.exe", "credentialuibroker.exe", "consent.exe", "logonui.exe"}:
        raise AppLifecycleError("app_launch_target_excluded")
    if (existing_identity is None) != (resolve_existing is None):
        raise AppLifecycleError("invalid_existing_instance")

    def existing_candidate() -> dict | None:
        if existing_identity is None:
            return None
        try:
            if resolve_existing() != existing_identity:
                return None
            assert_window(existing_identity)
            if _process_image_and_liveness(existing_identity.pid).resolve() != path:
                return None
            existing_created = process_creation_filetime(existing_identity.pid,
                                                        expected_iso=existing_identity.process_created)
            return {"target": {"pid": existing_identity.pid, "hwnd": existing_identity.hwnd,
                              "process_start_filetime": existing_created},
                    "identity_basis": "previously_selected_exact_process_and_executable",
                    "command_delivery_verified": False, "launcher_handoff_proven": False}
        except Exception:
            return None

    # Snapshot only a preapproved exact instance; never adopt a same-title window.
    prior_instance = existing_candidate()
    preflight()
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = (win32con.SW_SHOWNORMAL if mode == "normal"
                           else win32con.SW_SHOWNOACTIVATE)
    environment = _ordinary_environment()
    preflight()
    process = subprocess.Popen([str(path), *args], executable=str(path),
                               cwd=str(path.parent), shell=False, close_fds=True,
                               startupinfo=startup, env=environment)
    # PID is insufficient: bind the creation time before any window candidate.
    try:
        created = (handle_times(process._handle)[0] if hasattr(process, "_handle")
                   else process_creation_filetime(process.pid))
    except Exception:
        result = {"state": "outcome_uncertain", "dispatched": True,
                  "pid": process.pid, "reason": "process_identity_unavailable"}
        if prior_instance is not None and (existing := existing_candidate()) is not None:
            result["existing_instance"] = existing
            result["existing_instance_diagnostic_only"] = True
        return result
    try:
        preflight()
    except Exception:
        return {"state": "outcome_uncertain", "dispatched": True,
                "pid": process.pid, "process_start_filetime": created,
                "reason": "launch_authority_changed"}
    deadline = time.monotonic() + window_wait_seconds
    candidates: list[dict] = []
    chain = None
    chain_error = None
    identities = [{"pid": process.pid, "process_start_filetime": created,
                   "parent_pid": None, "depth": 0, "process_running": process.poll() is None}]
    try:
        try:
            chain = LaunchChain(process, created)
        except Exception:
            chain_error = "launch_chain_unavailable"
        while True:
            try:
                preflight()
            except Exception:
                return {"state": "outcome_uncertain", "dispatched": True,
                        "pid": process.pid, "process_start_filetime": created,
                        "related_processes": identities, "windows": candidates,
                        "reason": "launch_authority_changed"}
            try:
                if chain is not None:
                    try:
                        chain.sample()
                        identities = chain.identities()
                        if chain.incomplete:
                            chain_error = "launch_chain_partial"
                    except Exception:
                        chain_error = "launch_chain_observation_failed"
                candidates = []
                for identity in identities:
                    if identity["process_running"]:
                        for window in _visible_windows(identity["pid"], identity["process_start_filetime"]):
                            candidates.append({**window,
                                "identity_basis": "launched_process" if identity["depth"] == 0 else "verified_launch_descendant",
                                "process_start_filetime": identity["process_start_filetime"]})
                            if len(candidates) >= 16:
                                break
                    if len(candidates) >= 16:
                        break
            except Exception:
                return {"state": "outcome_uncertain", "dispatched": True,
                        "pid": process.pid, "process_start_filetime": created,
                        "related_processes": identities, "reason": "launch_observation_failed"}
            try:
                preflight()
            except Exception:
                return {"state": "outcome_uncertain", "dispatched": True,
                        "pid": process.pid, "process_start_filetime": created,
                        "related_processes": identities, "reason": "launch_authority_changed"}
            # A launcher exiting is not the end of its child's window startup.
            if candidates or time.monotonic() >= deadline:
                break
            time.sleep(min(0.05, max(0, deadline - time.monotonic())))
    finally:
        if chain is not None:
            chain.close()
    result = {"state": "window_candidates" if candidates else
            "window_pending" if any(item["process_running"] for item in identities) else "process_exited",
            "dispatched": True, "pid": process.pid,
            "process_start_filetime": created, "executable": str(path),
            "windows": candidates,
            "process_running": process.poll() is None,
            "requested_mode": mode,
            "window_selection_required": bool(candidates),
            "related_processes": identities,
            "launch_chain_reason": chain_error,
            "handoff_status": "descendant_window_observed" if any(
                item["identity_basis"] == "verified_launch_descendant" for item in candidates)
                else "direct_window_observed" if candidates else "unresolved",
            "next_step": "list_windows_and_match_exact_process_identity_then_select",
            "automatic_window_selection": False}
    if not candidates and prior_instance is not None and (existing := existing_candidate()) is not None:
        result["existing_instance"] = existing
        result["next_step"] = "observe_known_selected_instance_without_relaunch"
    return result


def request_normal_close(identity: WindowIdentity, *,
                         resolve_identity: Callable[[], WindowIdentity],
                         preflight: Callable[[], None],
                         wait_seconds: float = 5.0) -> dict:
    """Send exactly one WM_CLOSE and observe this window or a new owned dialog."""
    if (not isinstance(identity, WindowIdentity) or not callable(resolve_identity)
            or not callable(preflight) or type(wait_seconds) not in (int, float)
            or not 0 <= wait_seconds <= 10):
        raise AppLifecycleError("invalid_close_request")

    def recheck() -> None:
        preflight()
        if resolve_identity() != identity:
            raise AppLifecycleError("selected_window_changed")
        assert_window(identity)

    recheck()
    before = set()

    def collect_before(hwnd: int, _unused: object) -> None:
        try:
            if is_owned_popup(identity, hwnd):
                before.add(hwnd)
        except Exception:
            pass

    win32gui.EnumWindows(collect_before, None)
    recheck()
    try:
        sent = win32gui.PostMessage(identity.hwnd, win32con.WM_CLOSE, 0, 0)
        if sent is False:
            raise AppLifecycleError("close_dispatch_failed")
    except Exception as error:
        raise AppLifecycleError("close_dispatch_failed") from error
    deadline = time.monotonic() + wait_seconds
    while True:
        try:
            preflight()
        except Exception:
            return {"state": "outcome_uncertain", "dispatched": True,
                    "reason": "close_authority_changed"}
        if not win32gui.IsWindow(identity.hwnd):
            return {"state": "closed", "dispatched": True,
                    "window_closed": True, "process_running": _process_running(identity)}
        try:
            assert_window(identity)
        except Exception:
            return {"state": "window_replaced", "dispatched": True,
                    "window_closed": False, "process_running": _process_running(identity)}
        dialogs = []

        def collect_after(hwnd: int, _unused: object) -> None:
            if hwnd in before:
                return
            try:
                if is_owned_popup(identity, hwnd):
                    bound = bind_window(hwnd)
                    assert_window(bound)
                    dialogs.append({"target": asdict(bound),
                                    "title": win32gui.GetWindowText(hwnd)[:160]})
            except Exception:
                pass

        win32gui.EnumWindows(collect_after, None)
        if dialogs:
            return {"state": "new_dialog", "dispatched": True,
                    "window_closed": False, "dialogs": dialogs[:8]}
        if time.monotonic() >= deadline:
            return {"state": "close_requested", "dispatched": True,
                    "window_closed": False, "process_running": _process_running(identity)}
        time.sleep(min(0.05, max(0, deadline - time.monotonic())))


def _process_running(identity: WindowIdentity) -> bool | None:
    try:
        from flower_control.control.native import process_is_alive
        return process_is_alive(f"{identity.pid}:{identity.process_created}")
    except Exception:
        return None


def observe_requested_close(identity: WindowIdentity, *, preflight, wait_seconds=2.0) -> dict:
    """Read back an already dispatched close. This function sends no messages."""
    deadline = time.monotonic() + wait_seconds
    while True:
        try:
            preflight()
            if not win32gui.IsWindow(identity.hwnd):
                return {"state": "closed", "dispatched": True, "window_closed": True,
                        "process_running": _process_running(identity)}
            assert_window(identity)
            owned = []
            def collect(hwnd, _):
                if is_owned_popup(identity, hwnd):
                    owned.append(hwnd)
            win32gui.EnumWindows(collect, None)
            if owned or time.monotonic() >= deadline:
                return {"state": "close_pending", "dispatched": True,
                        "window_closed": False, "owned_window_hwnds": owned[:16],
                        "dialog_purpose_unverified": bool(owned),
                        "process_running": _process_running(identity)}
        except Exception as error:
            return {"state": "outcome_uncertain", "dispatched": True,
                    "reason": getattr(error, "code", "close_readback_unavailable")}
        time.sleep(min(.05, max(0, deadline - time.monotonic())))
