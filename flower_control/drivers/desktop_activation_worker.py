"""Private one-shot Shell desktop helper; only a fresh parent go can mutate UI.

COM may block, so the parent owns and can terminate this exact interpreter.
No Shell process, window, browser, or descendant process is ever terminated.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time

import win32api
import win32con
import win32event
import win32gui

from flower_control.control.native import process_identity
from flower_control.drivers import computer_native as native


def _write(stream, response: dict) -> None:
    stream.write(json.dumps(response, separators=(",", ":")).encode("ascii") + b"\n")
    stream.flush()


def _identity(request: dict) -> native.WindowIdentity:
    if (type(request) is not dict or set(request) != {
            "identity", "previous_foreground", "deadline", "owner_identity"}
            or type(request["identity"]) is not dict
            or set(request["identity"]) != {"hwnd", "pid", "process_created", "window_nonce"}
            or type(request["previous_foreground"]) is not int or request["previous_foreground"] < 0
            or type(request["deadline"]) not in (int, float)
            or not time.monotonic() < request["deadline"] <= time.monotonic() + 2.1
            or type(request["owner_identity"]) is not str):
        raise ValueError("invalid_desktop_request")
    return native.WindowIdentity(**request["identity"])


def _check(identity: native.WindowIdentity, request: dict) -> bool:
    if time.monotonic() >= request["deadline"]:
        raise RuntimeError("desktop_request_expired")
    native.assert_window(identity)
    if not native._is_shell_desktop(identity):
        raise RuntimeError("desktop_target_changed")
    current = win32gui.GetForegroundWindow()
    if current and win32gui.GetAncestor(current, win32con.GA_ROOT) == identity.hwnd:
        return False
    if current != request["previous_foreground"]:
        raise RuntimeError("desktop_foreground_changed")
    if any(native._user32.GetAsyncKeyState(key) < 0 for key in native._EXTERNAL_HOLD_KEYS):
        raise RuntimeError("desktop_external_input_held")
    native._assert_activation_foreground_allowed(current)
    return True


def run_request(request: dict, input_stream, output_stream) -> int:
    """Protocol seam for isolated tests; errors expose fixed phases only."""
    requested = False
    initialized = False
    shell = None
    try:
        identity = _identity(request)
        _check(identity, request)
        import pythoncom
        from win32com.client import Dispatch

        pythoncom.CoInitialize()
        initialized = True
        shell = Dispatch("Shell.Application")
        _check(identity, request)
        _write(output_stream, {"phase": "ready"})
        if input_stream.readline(4) != b"go\n":
            raise RuntimeError("desktop_go_missing")
        if not _check(identity, request):
            _write(output_stream, {"phase": "rejected", "dispatched": False})
            return 0
        # The only mutation. A COM error or parent timeout after this point
        # cannot prove that all windows stayed unchanged; there is no retry.
        requested = True
        shell.MinimizeAll()
        _write(output_stream, {"phase": "complete", "dispatched": True})
        return 0
    except Exception:
        _write(output_stream, {"phase": "failed" if requested else "rejected",
                               "dispatched": requested})
        return 1
    finally:
        shell = None
        if initialized:
            pythoncom.CoUninitialize()


def main() -> int:
    try:
        line = sys.stdin.buffer.readline(2049)
        if not line or len(line) > 2048 or not line.endswith(b"\n"):
            return 1
        request = json.loads(line)
        _identity(request)
        owner = request["owner_identity"]
        owner_pid = int(owner.partition(":")[0])
        parent = win32api.OpenProcess(
            win32con.SYNCHRONIZE | win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, owner_pid)
        if process_identity(owner_pid) != owner:
            parent.Close()
            return 1

        def parent_died() -> None:
            win32event.WaitForSingleObject(parent, win32event.INFINITE)
            os._exit(3)  # Only this helper, including when COM is blocked.

        threading.Thread(target=parent_died, name="flower-desktop-parent-watch", daemon=True).start()
        return run_request(request, sys.stdin.buffer, sys.stdout.buffer)
    except Exception:
        # Never print a COM exception, command, environment, or window content.
        return 1


if __name__ == "__main__":
    code = main()
    sys.stdout.flush()
    os._exit(code)
