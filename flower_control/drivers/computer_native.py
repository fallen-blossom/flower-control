"""Narrow Windows geometry and input primitives; no observation or MCP surface.

Callers must hold the control-layer execution lock and supply a fresh permission /
target check. A SendInput return is a dispatch count, never business verification.
"""

from __future__ import annotations

import ctypes
import secrets
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Callable, Iterable

import win32api
import win32con
import win32gui
import win32process


class NativeInputError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class PartialInput(NativeInputError):
    def __init__(self, sent: int, requested: int, winerror: int):
        super().__init__("input_partial_or_blocked")
        self.sent, self.requested, self.winerror = sent, requested, winerror


@dataclass(frozen=True)
class WindowIdentity:
    hwnd: int
    pid: int
    process_created: str
    window_nonce: int

    def __post_init__(self):
        if (type(self.hwnd) is not int or type(self.pid) is not int
                or type(self.window_nonce) is not int or self.hwnd <= 0
                or self.pid <= 0 or not self.process_created
                or not 0 < self.window_nonce < 1 << (ctypes.sizeof(ctypes.c_void_p) * 8)):
            raise ValueError("window identity requires HWND, process lifetime and window nonce")


@dataclass(frozen=True)
class Rect:
    left: int
    top: int
    right: int
    bottom: int

    def __post_init__(self):
        if (any(type(value) is not int for value in
                (self.left, self.top, self.right, self.bottom))
                or self.right <= self.left or self.bottom <= self.top):
            raise ValueError("rectangle must have positive width and height")

    @property
    def width(self) -> int:
        return self.right - self.left

    @property
    def height(self) -> int:
        return self.bottom - self.top


@dataclass(frozen=True)
class WindowGeometry:
    identity: WindowIdentity
    window: Rect
    client_origin: tuple[int, int]  # physical screen pixels
    client_size: tuple[int, int]
    dpi: int = 96

    def __post_init__(self):
        if (len(self.client_origin) != 2 or len(self.client_size) != 2
                or any(type(value) is not int for value in
                       (*self.client_origin, *self.client_size))
                or any(size <= 0 for size in self.client_size)
                or type(self.dpi) is not int or self.dpi <= 0):
            raise ValueError("client area must have positive dimensions")


@dataclass(frozen=True)
class VirtualDesktop:
    left: int
    top: int
    width: int
    height: int

    def __post_init__(self):
        if (any(type(value) is not int for value in
                (self.left, self.top, self.width, self.height))
                or self.width <= 0 or self.height <= 0):
            raise ValueError("virtual desktop must have positive dimensions")


_user32 = ctypes.WinDLL("user32", use_last_error=True)
_user32.GetThreadDpiAwarenessContext.restype = ctypes.c_void_p
_user32.GetAwarenessFromDpiAwarenessContext.argtypes = [ctypes.c_void_p]
_user32.GetAwarenessFromDpiAwarenessContext.restype = ctypes.c_int
_user32.GetSystemMetrics.argtypes = [ctypes.c_int]
_user32.GetSystemMetrics.restype = ctypes.c_int
_user32.GetDpiForWindow.argtypes = [ctypes.c_void_p]
_user32.GetDpiForWindow.restype = ctypes.c_uint
_WINDOW_PROP = "FlowerControl.WindowNonce.v1"
_PROTECTED_WINDOW_PROPS = ("FlowerControlResumePrompt", "FlowerControlTaskIndicator")
_user32.GetPropW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
_user32.GetPropW.restype = ctypes.c_void_p
_user32.SetPropW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_void_p]
_user32.SetPropW.restype = ctypes.c_int
_user32.GetShellWindow.restype = ctypes.c_void_p
_user32.BringWindowToTop.argtypes = [ctypes.c_void_p]
_user32.BringWindowToTop.restype = ctypes.c_int
_user32.SetForegroundWindow.argtypes = [ctypes.c_void_p]
_user32.SetForegroundWindow.restype = ctypes.c_int
_user32.ShowWindowAsync.argtypes = [ctypes.c_void_p, ctypes.c_int]
_user32.ShowWindowAsync.restype = ctypes.c_int


def _require_physical_coordinates() -> None:
    context = _user32.GetThreadDpiAwarenessContext()
    if _user32.GetAwarenessFromDpiAwarenessContext(context) != 2:
        raise NativeInputError("per_monitor_dpi_awareness_required")


def _process_identity(hwnd: int) -> tuple[int, str]:
    if not hwnd or not win32gui.IsWindow(hwnd):
        raise NativeInputError("window_missing")
    _, pid = win32process.GetWindowThreadProcessId(hwnd)
    if not pid:
        raise NativeInputError("window_missing")
    process = win32api.OpenProcess(win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    try:
        created = win32process.GetProcessTimes(process)["CreationTime"].isoformat()
    finally:
        process.Close()
    if not win32gui.IsWindow(hwnd) or win32process.GetWindowThreadProcessId(hwnd)[1] != pid:
        raise NativeInputError("window_changed")
    return pid, created


def _read_window_identity(hwnd: int) -> WindowIdentity:
    pid, created = _process_identity(hwnd)
    nonce = _user32.GetPropW(hwnd, _WINDOW_PROP)
    if not nonce:
        raise NativeInputError("window_identity_property_missing")
    if not win32gui.IsWindow(hwnd) or win32process.GetWindowThreadProcessId(hwnd)[1] != pid:
        raise NativeInputError("window_changed")
    if _user32.GetPropW(hwnd, _WINDOW_PROP) != nonce:
        raise NativeInputError("window_identity_property_changed")
    return WindowIdentity(hwnd, pid, created, nonce)


def bind_window(hwnd: int) -> WindowIdentity:
    """Bind once using a Flower property; inaccessible properties fail closed.

    The nonce distinguishes later reuse of an HWND within the same process.
    This writes only a window property, not target content or foreground state.
    """

    pid, created = _process_identity(hwnd)
    nonce = _user32.GetPropW(hwnd, _WINDOW_PROP)
    if not nonce:
        nonce = secrets.randbits(ctypes.sizeof(ctypes.c_void_p) * 8 - 1) or 1
        if not _user32.SetPropW(hwnd, _WINDOW_PROP, ctypes.c_void_p(nonce)):
            if ctypes.get_last_error() == 5:
                raise NativeInputError("window_identity_access_denied")
            raise NativeInputError("window_identity_property_unavailable")
    identity = _read_window_identity(hwnd)
    if ((identity.pid, identity.process_created) != (pid, created)
            or identity.window_nonce != nonce):
        raise NativeInputError("window_changed")
    return identity


def assert_window(identity: WindowIdentity) -> None:
    if _read_window_identity(identity.hwnd) != identity:
        raise NativeInputError("window_changed")


def visible_process_top_levels(identity: WindowIdentity) -> frozenset[int]:
    """Bounded identity-only snapshot; includes owned top-level popups."""
    assert_window(identity)
    found: set[int] = set()

    def collect(hwnd: int, _) -> None:
        if (hwnd != identity.hwnd and win32gui.IsWindow(hwnd) and
                win32gui.IsWindowVisible(hwnd) and
                win32process.GetWindowThreadProcessId(hwnd)[1] == identity.pid):
            found.add(hwnd)

    win32gui.EnumWindows(collect, None)
    return frozenset(found)


def is_owned_popup(parent: WindowIdentity, hwnd: int) -> bool:
    """Read-only same-process owner relation for one visible new top-level."""
    try:
        return (win32gui.IsWindow(hwnd) and win32gui.IsWindowVisible(hwnd)
                and win32process.GetWindowThreadProcessId(hwnd)[1] == parent.pid
                and win32gui.GetWindow(hwnd, win32con.GW_OWNER) == parent.hwnd)
    except win32gui.error:
        return False


def new_visible_followups(identity: WindowIdentity, before: frozenset[int],
                          *, bind_allowed: bool, window_binder=None) -> dict:
    """Report new same-process top-levels without reading their content."""
    try:
        new = sorted(visible_process_top_levels(identity) - before)
        from .computer_input_state import is_target_candidate_window
        new = [hwnd for hwnd in new if not is_target_candidate_window(identity, hwnd)]
    except Exception:
        return {"visual_scope": "visual_scope_incomplete",
                "visual_scope_incomplete": True, "followup_targets": []}
    if not new:
        return {"visual_scope": "target_window_only",
                "visual_scope_incomplete": False, "followup_targets": []}
    targets = []
    unbound = []
    for hwnd in new[:8]:
        try:
            root = win32gui.GetAncestor(hwnd, win32con.GA_ROOT)
            if any(_user32.GetPropW(root, marker)
                   for marker in _PROTECTED_WINDOW_PROPS):
                unbound.append({"pid": identity.pid, "hwnd": hwnd,
                                "reason": "authorization_window_protected"})
                continue
            if not is_owned_popup(identity, hwnd):
                unbound.append({"pid": identity.pid, "hwnd": hwnd,
                                "reason": "followup_owner_unrelated"})
                continue
            if not bind_allowed:
                unbound.append({"pid": identity.pid, "hwnd": hwnd,
                                "reason": "trusted_rebind_required"})
                continue
            candidate = (bind_window(hwnd) if window_binder is None else window_binder(hwnd))
            if (not isinstance(candidate, WindowIdentity) or candidate.hwnd != hwnd or
                    candidate.pid != identity.pid or candidate.process_created != identity.process_created):
                raise NativeInputError("followup_process_changed")
            if not is_owned_popup(identity, hwnd):
                raise NativeInputError("followup_owner_changed")
            if window_binder is not None:
                assert_window(identity)
                assert_window(candidate)
            targets.append(asdict(candidate))
        except Exception:
            unbound.append({"pid": identity.pid, "hwnd": hwnd,
                            "reason": "followup_binding_unavailable"})
    return {"visual_scope": "followup_window_detected",
            "visual_scope_incomplete": True,
            "followup_targets": targets,
            "unbound_followup_windows": unbound,
            "followup_windows_truncated": len(new) > 8}


def assert_foreground(identity: WindowIdentity) -> None:
    hwnd = win32gui.GetForegroundWindow()
    if not hwnd or win32gui.GetAncestor(hwnd, win32con.GA_ROOT) != identity.hwnd:
        raise NativeInputError("foreground_changed")
    assert_window(identity)
    if not win32gui.IsWindowVisible(identity.hwnd) or win32gui.IsIconic(identity.hwnd):
        raise NativeInputError("foreground_target_not_interactive")


def _is_shell_desktop(identity: WindowIdentity) -> bool:
    shell = int(_user32.GetShellWindow() or 0)
    if not shell:
        return False
    if identity.hwnd == shell:
        return True
    return (win32gui.GetClassName(identity.hwnd) == "WorkerW" and
            win32process.GetWindowThreadProcessId(shell)[1] == identity.pid and
            bool(win32gui.FindWindowEx(identity.hwnd, 0, "SHELLDLL_DefView", None)))


def _show_shell_desktop(identity: WindowIdentity, preflight: Callable[[], bool],
                        stopped: Callable[[], bool], previous_foreground: int,
                        progress: dict | None = None, *, timeout: float = 2.0) -> None:
    """One Shell request in an exact disposable process; never replay on failure.

    COM preparation happens before ready. Only a fresh parent check can send
    go; after go, losing the helper cannot prove that MinimizeAll had no effect.
    Termination uses this Popen's process handle, never a PID search or a Job
    containing the user's Shell. No prior window state is restored.
    """
    import json
    import os
    from pathlib import Path
    import queue
    import subprocess
    import sys

    from flower_control.control.native import process_identity

    if not 0 < timeout <= 2.0:
        raise ValueError("desktop activation timeout must be in (0, 2]")
    tracked = progress if progress is not None else {}
    prior_request = bool(tracked.get("activation_request_sent", False))
    tracked.update(activation_shell_dispatched=False, activation_shell_complete=False,
                   activation_shell_effect="not_requested", activation_shell_replay_allowed=False)
    deadline = time.monotonic() + timeout
    process = None
    reader = None
    messages = queue.Queue(maxsize=4)

    def check() -> None:
        if stopped() or not preflight():
            raise NativeInputError("activation_interrupted")
        if time.monotonic() >= deadline:
            raise NativeInputError("shell_desktop_timeout")

    def next_message() -> dict:
        while True:
            check()
            try:
                line = messages.get(timeout=min(0.020, max(0, deadline - time.monotonic())))
            except queue.Empty:
                continue
            if not line or len(line) > 512 or not line.endswith(b"\n"):
                raise NativeInputError("shell_desktop_worker_failed")
            try:
                result = json.loads(line)
            except (ValueError, UnicodeError):
                raise NativeInputError("shell_desktop_worker_failed") from None
            if type(result) is not dict:
                raise NativeInputError("shell_desktop_worker_failed")
            return result

    def read_messages() -> None:
        try:
            while True:
                line = process.stdout.readline(513)
                messages.put_nowait(line)
                if not line or len(line) > 512 or not line.endswith(b"\n"):
                    return
        except (OSError, ValueError, queue.Full):
            return

    try:
        check()
        assert_window(identity)
        if not _is_shell_desktop(identity):
            raise NativeInputError("shell_desktop_target_changed")
        root = Path(__file__).resolve().parents[2]
        # A venv python.exe may be a redirector with a second interpreter PID.
        # Use the direct base interpreter and only this venv's known packages,
        # so killing Popen's owned handle also ends the blocked COM caller.
        bootstrap = ("import sys,site,runpy;site.addsitedir(sys.argv[1]);"
                     "sys.path.insert(0,sys.argv[2]);sys.argv=[sys.argv[2]];"
                     "runpy.run_module('flower_control.drivers.desktop_activation_worker',run_name='__main__')")
        environment = {name: os.environ[name] for name in
                       ("SystemRoot", "WINDIR", "TEMP", "TMP", "ComSpec") if name in os.environ}
        startup = subprocess.STARTUPINFO()
        startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startup.wShowWindow = win32con.SW_HIDE
        process = subprocess.Popen(
            [sys._base_executable, "-I", "-S", "-B", "-c", bootstrap,
             str(Path(sys.prefix) / "Lib" / "site-packages"), str(root)],
            cwd=str(root), env=environment, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, bufsize=0, startupinfo=startup,
            creationflags=subprocess.CREATE_NO_WINDOW)
        reader = threading.Thread(target=read_messages, name="flower-desktop-helper-reader", daemon=True)
        reader.start()
        request = {"identity": asdict(identity), "previous_foreground": previous_foreground,
                   "deadline": deadline, "owner_identity": process_identity()}
        process.stdin.write(json.dumps(request, separators=(",", ":")).encode("ascii") + b"\n")
        if next_message() != {"phase": "ready"}:
            raise NativeInputError("shell_desktop_worker_failed")
        # Ready does not grant permission. Recheck immediately before the only
        # go message, after potentially blocked COM preparation has completed.
        check()
        assert_window(identity)
        if not _is_shell_desktop(identity):
            raise NativeInputError("shell_desktop_target_changed")
        current = win32gui.GetForegroundWindow()
        if current and win32gui.GetAncestor(current, win32con.GA_ROOT) == identity.hwnd:
            return
        if current != previous_foreground:
            raise NativeInputError("foreground_changed")
        if any(_user32.GetAsyncKeyState(key) < 0 for key in _EXTERNAL_HOLD_KEYS):
            raise NativeInputError("external_input_held")
        _assert_activation_foreground_allowed(current)
        tracked.update(activation_request_sent=True, activation_shell_dispatched=True,
                       activation_shell_effect="uncertain")
        process.stdin.write(b"go\n")
        response = next_message()
        if response == {"phase": "rejected", "dispatched": False}:
            tracked.update(activation_request_sent=prior_request, activation_shell_dispatched=False,
                           activation_shell_effect="not_requested")
            raise NativeInputError("shell_desktop_preflight_failed")
        if response != {"phase": "complete", "dispatched": True}:
            raise NativeInputError("shell_desktop_worker_failed")
        while process.poll() is None:
            check()
            time.sleep(min(0.020, max(0, deadline - time.monotonic())))
        if process.returncode != 0:
            raise NativeInputError("shell_desktop_worker_failed")
        check()
        tracked.update(activation_shell_complete=True, activation_shell_effect="unverified")
    except BaseException as error:
        tracked["activation_shell_reason"] = (
            error.code if isinstance(error, NativeInputError) else "shell_desktop_request_failed")
        raise
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()  # TerminateProcess on this exact owned handle only.
            try:
                process.wait(timeout=0.3)
            except subprocess.TimeoutExpired:
                tracked["activation_shell_reason"] = "shell_desktop_cleanup_unconfirmed"
                raise NativeInputError("shell_desktop_cleanup_unconfirmed") from None
            for stream in (process.stdin, process.stdout):
                stream.close()
        if reader is not None:
            reader.join(timeout=0.1)


def _assert_activation_foreground_allowed(hwnd: int) -> None:
    # This marker belongs to explicit Stop recovery, not retired permission UI.
    if hwnd and _user32.GetPropW(hwnd, "FlowerControlResumePrompt"):
        raise NativeInputError("activation_foreground_protected")


def _activation_alt(previous: int, identity: WindowIdentity, preflight, stopped,
                    progress: dict | None = None, on_input_ledger=None) -> dict:
    """One balanced Alt tap while the scheduled foreground is unchanged."""
    assert_window(identity)
    if stopped() or not preflight():
        raise NativeInputError("activation_interrupted")
    current = win32gui.GetForegroundWindow()
    if current and win32gui.GetAncestor(current, win32con.GA_ROOT) == identity.hwnd:
        return {"activation_input_events": 0, "activation_input_release": "not_used",
                "activation_input_complete": True}
    if current != previous:
        raise NativeInputError("foreground_changed")
    if any(_user32.GetAsyncKeyState(key) < 0 for key in _EXTERNAL_HOLD_KEYS):
        raise NativeInputError("external_input_held")
    _assert_activation_foreground_allowed(previous)
    steps = (virtual_key(0x12, down=True), virtual_key(0x12, down=False))
    array = (INPUT * 2)(*(step.raw for step in steps))
    ledger = HeldInputLedger()
    if on_input_ledger is not None:
        on_input_ledger(ledger)
    if stopped() or not preflight():
        raise NativeInputError("activation_interrupted")
    # Ledger binding may write SQLite. Recheck the activation's exact prior
    # foreground after that callback, immediately before the balanced tap.
    current = win32gui.GetForegroundWindow()
    if current and win32gui.GetAncestor(current, win32con.GA_ROOT) == identity.hwnd:
        return {"activation_input_events": 0, "activation_input_release": "not_used",
                "activation_input_complete": True}
    if current != previous:
        raise NativeInputError("foreground_changed")
    if any(_user32.GetAsyncKeyState(key) < 0 for key in _EXTERNAL_HOLD_KEYS):
        raise NativeInputError("external_input_held")
    _assert_activation_foreground_allowed(current)
    ledger._begin_send()
    try:
        sent = int(_user32.SendInput(2, array, ctypes.sizeof(INPUT)))
    except Exception:
        raise NativeInputError("input_release_unconfirmed") from None
    if progress is not None:
        progress.update(activation_input_events=sent,
                        activation_input_release="unconfirmed" if sent == 1 else "released")
    ledger._record(steps[:sent])
    release = "released"
    if ledger.held:
        try:
            # The caller still owns the foreground execution lock. Cancellation
            # does not suppress releasing the single modifier we injected.
            release_held(ledger, cleanup_owned=lambda: True, stopped=stopped)
        except NativeInputError:
            release = "unconfirmed"
    result = {"activation_input_events": sent, "activation_input_release": release,
              "activation_input_complete": sent == 2}
    if progress is not None:
        progress.update(result)
    return result


def activate_window(identity: WindowIdentity, *, preflight: Callable[[], bool],
                    stopped: Callable[[], bool], restore_minimized: bool = False,
                    progress: dict | None = None, on_input_ledger=None) -> dict:
    """One explicitly scheduled activation, never a focus-maintenance loop.

    The caller holds the foreground execution right. Windows may refuse the
    focus request. Desktop uses Shell's Show Desktop operation; normal windows
    get one bounded Alt-assisted retry if the foreground remains unchanged.
    No input-queue attachment, focus maintenance or previous-focus restoration.
    """
    if type(restore_minimized) is not bool:
        raise ValueError("restore_minimized must be a boolean")
    if progress is not None:
        progress.setdefault("activation_request_sent", False)
    if not preflight() or stopped():
        raise NativeInputError("activation_not_authorized")
    assert_window(identity)
    if not win32gui.IsWindowVisible(identity.hwnd):
        raise NativeInputError("target_not_visible")
    if any(_user32.GetAsyncKeyState(key) < 0 for key in _EXTERNAL_HOLD_KEYS):
        raise NativeInputError("external_input_held")
    was_minimized = bool(win32gui.IsIconic(identity.hwnd))
    previous_foreground = win32gui.GetForegroundWindow()
    _assert_activation_foreground_allowed(previous_foreground)
    if was_minimized:
        if not restore_minimized:
            raise NativeInputError("target_minimized")
        if progress is not None:
            progress["activation_request_sent"] = True
        _user32.ShowWindowAsync(identity.hwnd, win32con.SW_RESTORE)
    if stopped() or not preflight():
        raise NativeInputError("activation_interrupted")
    assert_window(identity)
    method = "already_foreground"
    from .computer_input_state import activation_probe
    diagnostics = {"probe": activation_probe(identity), "attempts": [],
                   "verification": "exact_target_foreground", "last_error_authoritative": False}
    activation_input = {"activation_input_events": 0, "activation_input_release": "not_used",
                        "activation_diagnostics": diagnostics}
    if progress is not None:
        progress.update(activation_input)
    if (not previous_foreground or
            win32gui.GetAncestor(previous_foreground, win32con.GA_ROOT) != identity.hwnd):
        if any(_user32.GetAsyncKeyState(key) < 0 for key in _EXTERNAL_HOLD_KEYS):
            raise NativeInputError("external_input_held")
        if _is_shell_desktop(identity):
            method = "shell_show_desktop"
            if stopped() or not preflight():
                raise NativeInputError("activation_interrupted")
            assert_window(identity)
            current = win32gui.GetForegroundWindow()
            if (current != previous_foreground and
                    (not current or win32gui.GetAncestor(current, win32con.GA_ROOT) != identity.hwnd)):
                raise NativeInputError("foreground_changed")
            if not current or win32gui.GetAncestor(current, win32con.GA_ROOT) != identity.hwnd:
                try:
                    _show_shell_desktop(identity, preflight, stopped, previous_foreground, progress)
                except NativeInputError:
                    raise
                except Exception as error:
                    raise NativeInputError("shell_desktop_request_failed") from error
        else:
            method = "bring_then_set_foreground"
        try:
            # Flush the target queue without attaching to it. A hung target
            # must not hang the MCP worker or consume the shared input lane.
            win32gui.SendMessageTimeout(identity.hwnd, win32con.WM_NULL, 0, 0,
                                        win32con.SMTO_ABORTIFHUNG | win32con.SMTO_BLOCK, 200)
        except win32gui.error as error:
            return {"foreground": False, "state": "user_activation_required",
                    "reason": "activation_access_denied" if error.winerror == 5 else "target_unresponsive",
                    "activation_method": method, **activation_input,
                    "restored_from_minimized": was_minimized}
        if stopped() or not preflight():
            raise NativeInputError("activation_interrupted")
        current = win32gui.GetForegroundWindow()
        if (current not in (0, previous_foreground) and
                win32gui.GetAncestor(current, win32con.GA_ROOT) != identity.hwnd):
            return {"foreground": False, "state": "user_activation_required",
                    "reason": "foreground_changed", "activation_method": method,
                    **activation_input, "restored_from_minimized": was_minimized}
        diagnostics["attempts"].append(_request_foreground(identity, previous_foreground,
            preflight, stopped, progress))
        after_request = win32gui.GetForegroundWindow()
        if (after_request not in (0, previous_foreground) and
                win32gui.GetAncestor(after_request, win32con.GA_ROOT) != identity.hwnd):
            return {"foreground": False, "state": "user_activation_required",
                    "reason": "foreground_changed", "activation_method": method,
                    **activation_input,
                    "restored_from_minimized": was_minimized}
        if (after_request == previous_foreground and not stopped() and preflight()):
            activation_input = _activation_alt(previous_foreground, identity, preflight, stopped,
                                                progress=progress, on_input_ledger=on_input_ledger)
            activation_input["activation_diagnostics"] = diagnostics
            if activation_input["activation_input_events"]:
                method += "_alt"
            if not activation_input["activation_input_complete"]:
                return {"foreground": False,
                        "state": "outcome_uncertain" if activation_input["activation_input_release"] == "unconfirmed"
                                 else "user_activation_required",
                        "reason": "activation_input_incomplete", "activation_method": method,
                        **activation_input, "restored_from_minimized": was_minimized}
            if stopped() or not preflight():
                raise NativeInputError("activation_interrupted")
            current = win32gui.GetForegroundWindow()
            if current == previous_foreground:
                diagnostics["attempts"].append(_request_foreground(identity, previous_foreground,
                    preflight, stopped, progress))
            elif (not current or
                  win32gui.GetAncestor(current, win32con.GA_ROOT) != identity.hwnd):
                raise NativeInputError("foreground_changed")
    # The foreground transition can complete after SetForegroundWindow returns.
    # Observe that single request briefly; never retry it or accept a later
    # recovery after a different window has taken the foreground.
    deadline = time.monotonic() + 0.500
    foreground = False
    while True:
        if stopped() or not preflight():
            raise NativeInputError("activation_interrupted")
        assert_window(identity)
        current_foreground = win32gui.GetForegroundWindow()
        if (current_foreground and
                win32gui.GetAncestor(current_foreground, win32con.GA_ROOT) == identity.hwnd):
            foreground = (win32gui.IsWindowVisible(identity.hwnd)
                          and not win32gui.IsIconic(identity.hwnd))
            break
        if current_foreground not in (0, previous_foreground):
            break
        if time.monotonic() >= deadline:
            break
        time.sleep(0.015)
    return {"foreground": foreground,
            "state": "activated" if foreground else "user_activation_required",
            "activation_method": method, **activation_input,
            "restored_from_minimized": was_minimized}


def _request_foreground(identity, previous, preflight, stopped, progress):
    """One finite Win32 attempt, never a request after an unrelated switch."""
    if stopped() or not preflight():
        raise NativeInputError("activation_interrupted")
    assert_window(identity)
    current = win32gui.GetForegroundWindow()
    if current and win32gui.GetAncestor(current, win32con.GA_ROOT) == identity.hwnd:
        return {"bring_return": None, "set_foreground_return": None, "state": "already_target"}
    if current != previous:
        raise NativeInputError("foreground_changed")
    _assert_activation_foreground_allowed(current)
    if progress is not None:
        progress["activation_request_sent"] = True
    ctypes.set_last_error(0)
    brought = bool(_user32.BringWindowToTop(identity.hwnd))
    bring_error = ctypes.get_last_error() if not brought else 0
    current = win32gui.GetForegroundWindow()
    if current and win32gui.GetAncestor(current, win32con.GA_ROOT) == identity.hwnd:
        return {"bring_return": brought, "bring_winerror": bring_error,
                "set_foreground_return": None, "state": "target_after_bring"}
    if current != previous:
        return {"bring_return": brought, "bring_winerror": bring_error,
                "set_foreground_return": None, "state": "unrelated_foreground_after_bring"}
    if stopped() or not preflight():
        raise NativeInputError("activation_interrupted")
    assert_window(identity)
    current = win32gui.GetForegroundWindow()
    if current != previous:
        raise NativeInputError("foreground_changed")
    _assert_activation_foreground_allowed(current)
    ctypes.set_last_error(0)
    requested = bool(_user32.SetForegroundWindow(identity.hwnd))
    return {"bring_return": brought, "bring_winerror": bring_error,
            "set_foreground_return": requested,
            "set_foreground_winerror": ctypes.get_last_error() if not requested else 0,
            "state": "requested"}


def window_geometry(identity: WindowIdentity) -> WindowGeometry:
    _require_physical_coordinates()
    assert_window(identity)
    def sample():
        window = Rect(*win32gui.GetWindowRect(identity.hwnd))
        client = win32gui.GetClientRect(identity.hwnd)
        origin = win32gui.ClientToScreen(identity.hwnd, (0, 0))
        dpi = int(_user32.GetDpiForWindow(identity.hwnd))
        if not dpi:
            raise NativeInputError("window_changed")
        return WindowGeometry(identity, window, origin,
                              (client[2] - client[0], client[3] - client[1]), dpi)
    geometry = sample()
    if sample() != geometry:
        raise NativeInputError("geometry_changed")
    assert_window(identity)
    return geometry


def assert_geometry(geometry: WindowGeometry) -> None:
    if window_geometry(geometry.identity) != geometry:
        raise NativeInputError("geometry_changed")


def client_to_screen(geometry: WindowGeometry, x: int, y: int) -> tuple[int, int]:
    if (type(x) is not int or type(y) is not int
            or not (0 <= x < geometry.client_size[0] and 0 <= y < geometry.client_size[1])):
        raise ValueError("client point is outside the client area")
    return geometry.client_origin[0] + x, geometry.client_origin[1] + y


def screen_to_client(geometry: WindowGeometry, x: int, y: int) -> tuple[int, int]:
    if type(x) is not int or type(y) is not int:
        raise ValueError("screen point must use integer physical pixels")
    return x - geometry.client_origin[0], y - geometry.client_origin[1]


def virtual_desktop() -> VirtualDesktop:
    _require_physical_coordinates()
    return VirtualDesktop(*(_user32.GetSystemMetrics(code) for code in (76, 77, 78, 79)))


def normalize_absolute(x: int, y: int, desktop: VirtualDesktop) -> tuple[int, int]:
    if (type(x) is not int or type(y) is not int
            or not (desktop.left <= x < desktop.left + desktop.width
                    and desktop.top <= y < desktop.top + desktop.height)):
        raise ValueError("screen point is outside the virtual desktop")
    return (round((x - desktop.left) * 65535 / max(1, desktop.width - 1)),
            round((y - desktop.top) * 65535 / max(1, desktop.height - 1)))


ULONG_PTR = ctypes.c_size_t


class MOUSEINPUT(ctypes.Structure):
    _fields_ = [("dx", ctypes.c_long), ("dy", ctypes.c_long),
                ("mouseData", ctypes.c_ulong), ("dwFlags", ctypes.c_ulong),
                ("time", ctypes.c_ulong), ("dwExtraInfo", ULONG_PTR)]


class KEYBDINPUT(ctypes.Structure):
    _fields_ = [("wVk", ctypes.c_ushort), ("wScan", ctypes.c_ushort),
                ("dwFlags", ctypes.c_ulong), ("time", ctypes.c_ulong),
                ("dwExtraInfo", ULONG_PTR)]


class HARDWAREINPUT(ctypes.Structure):
    _fields_ = [("uMsg", ctypes.c_ulong), ("wParamL", ctypes.c_ushort),
                ("wParamH", ctypes.c_ushort)]


class INPUT_UNION(ctypes.Union):
    _fields_ = [("mi", MOUSEINPUT), ("ki", KEYBDINPUT), ("hi", HARDWAREINPUT)]


class INPUT(ctypes.Structure):
    _fields_ = [("type", ctypes.c_ulong), ("data", INPUT_UNION)]


_user32.SendInput.argtypes = [ctypes.c_uint, ctypes.POINTER(INPUT), ctypes.c_int]
_user32.SendInput.restype = ctypes.c_uint
_user32.GetAsyncKeyState.argtypes = [ctypes.c_int]
_user32.GetAsyncKeyState.restype = ctypes.c_short

KEYEVENTF_KEYUP = 0x0002
KEYEVENTF_UNICODE = 0x0004
MOUSEEVENTF_MOVE = 0x0001
MOUSEEVENTF_ABSOLUTE = 0x8000
MOUSEEVENTF_VIRTUALDESK = 0x4000
MOUSEEVENTF_WHEEL = 0x0800
_BUTTON_FLAGS = {
    "left": (0x0002, 0x0004, 0),
    "right": (0x0008, 0x0010, 0),
    "middle": (0x0020, 0x0040, 0),
    "x1": (0x0080, 0x0100, 1),
    "x2": (0x0080, 0x0100, 2),
}
_EXTERNAL_HOLD_KEYS = (
    0x01, 0x02, 0x04, 0x05, 0x06,  # physical mouse buttons
    0x10, 0x11, 0x12,              # Shift, Control, Alt
    0x5B, 0x5C,                    # Windows keys
)


HeldToken = tuple[str, int]


@dataclass(frozen=True)
class InputStep:
    raw: INPUT
    token: HeldToken | None = None
    pressed: bool | None = None
    desktop: VirtualDesktop | None = None

    def __post_init__(self):
        if not isinstance(self.raw, INPUT):
            raise ValueError("input step requires an INPUT structure")
        if self.raw.type == 1:
            key = self.raw.data.ki
            if key.time or key.dwExtraInfo:
                raise ValueError("keyboard event has unsupported metadata")
            if key.dwFlags in (KEYEVENTF_UNICODE,
                               KEYEVENTF_UNICODE | KEYEVENTF_KEYUP):
                expected = ("unicode", key.wScan)
                if key.wVk:
                    raise ValueError("Unicode event must have a zero virtual key")
            elif key.dwFlags in (0, KEYEVENTF_KEYUP, 1, 1 | KEYEVENTF_KEYUP):
                expected = ("vk", key.wVk)
                if not 1 <= key.wVk <= 254 or key.wScan:
                    raise ValueError("invalid virtual-key event")
            else:
                raise ValueError("unsupported keyboard flags")
            if self.token != expected or self.pressed != (
                not bool(key.dwFlags & KEYEVENTF_KEYUP)
            ):
                raise ValueError("keyboard event is missing its release accounting")
            return
        if self.raw.type != 0:
            raise ValueError("unsupported input type")
        mouse = self.raw.data.mi
        if mouse.time or mouse.dwExtraInfo:
            raise ValueError("mouse event has unsupported metadata")
        if mouse.dwFlags == (MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE |
                             MOUSEEVENTF_VIRTUALDESK):
            if mouse.mouseData or not 0 <= mouse.dx <= 65535 or not 0 <= mouse.dy <= 65535:
                raise ValueError("invalid absolute move")
            expected, down = None, None
        elif mouse.dwFlags == MOUSEEVENTF_MOVE:
            if mouse.mouseData or (not mouse.dx and not mouse.dy) or max(abs(mouse.dx), abs(mouse.dy)) > 2048:
                raise ValueError("invalid relative move")
            expected, down = None, None
        elif mouse.dwFlags in (MOUSEEVENTF_WHEEL, 0x1000):
            signed = ctypes.c_int32(mouse.mouseData).value
            if mouse.dx or mouse.dy or not signed or abs(signed) > 1200:
                raise ValueError("invalid wheel event")
            expected, down = None, None
        else:
            matched = None
            for index, (_, (down_flag, up_flag, data)) in enumerate(_BUTTON_FLAGS.items()):
                if mouse.dwFlags == down_flag and mouse.mouseData == data:
                    matched = (("mouse", index), True)
                    break
                if mouse.dwFlags == up_flag and mouse.mouseData == data:
                    matched = (("mouse", index), False)
                    break
            if matched is None or mouse.dx or mouse.dy:
                raise ValueError("unsupported mouse event")
            expected, down = matched
        if self.token != expected or self.pressed != down:
            raise ValueError("mouse event is missing its release accounting")


def _keyboard(vk: int, scan: int, flags: int, token: HeldToken, down: bool) -> InputStep:
    raw = INPUT()
    raw.type = 1
    raw.data.ki = KEYBDINPUT(vk, scan, flags, 0, 0)
    return InputStep(raw, token, down)


def virtual_key(vk: int, *, down: bool) -> InputStep:
    if isinstance(vk, bool) or not isinstance(vk, int) or not 1 <= vk <= 254:
        raise ValueError("virtual key must be in 1..254")
    extended = 1 if vk in {0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
                          0x2C, 0x2D, 0x2E, 0x5B, 0x5C, 0x6F, 0x90, 0xA3, 0xA5} else 0
    return _keyboard(vk, 0, extended | (0 if down else KEYEVENTF_KEYUP), ("vk", vk), down)


def unicode_text(text: str) -> tuple[InputStep, ...]:
    if not text:
        raise ValueError("text must not be empty")
    units = text.encode("utf-16-le", errors="strict")
    if len(units) // 2 > 64:
        raise ValueError("Unicode batch exceeds 64 UTF-16 code units")
    result = []
    for offset in range(0, len(units), 2):
        unit = int.from_bytes(units[offset:offset + 2], "little")
        token = ("unicode", unit)
        result.append(_keyboard(0, unit, KEYEVENTF_UNICODE, token, True))
        result.append(_keyboard(0, unit, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP,
                                token, False))
    return tuple(result)


def _mouse(flags: int, *, dx: int = 0, dy: int = 0, data: int = 0,
           token: HeldToken | None = None, down: bool | None = None) -> InputStep:
    raw = INPUT()
    raw.type = 0
    raw.data.mi = MOUSEINPUT(dx, dy, data & 0xFFFFFFFF, flags, 0, 0)
    return InputStep(raw, token, down)


def mouse_button(button: str, *, down: bool) -> InputStep:
    if button not in _BUTTON_FLAGS:
        raise ValueError("unknown mouse button")
    down_flag, up_flag, data = _BUTTON_FLAGS[button]
    return _mouse(down_flag if down else up_flag, data=data,
                  token=("mouse", tuple(_BUTTON_FLAGS).index(button)), down=down)


def mouse_move(x: int, y: int, desktop: VirtualDesktop) -> InputStep:
    nx, ny = normalize_absolute(x, y, desktop)
    raw = _mouse(MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
                 dx=nx, dy=ny)
    return InputStep(raw.raw, desktop=desktop)


def mouse_move_relative(dx: int, dy: int) -> InputStep:
    """Raw Windows relative units; pointer speed/acceleration can change distance."""
    if (type(dx) is not int or type(dy) is not int or not (dx or dy)
            or max(abs(dx), abs(dy)) > 2048):
        raise ValueError("invalid relative move")
    return _mouse(MOUSEEVENTF_MOVE, dx=dx, dy=dy)


def mouse_wheel(delta: int, *, horizontal: bool = False) -> InputStep:
    if isinstance(delta, bool) or not isinstance(delta, int) or not delta or abs(delta) > 1200:
        raise ValueError("wheel delta must be nonzero and at most ten detents")
    if type(horizontal) is not bool:
        raise ValueError("invalid wheel axis")
    return _mouse(0x1000 if horizontal else MOUSEEVENTF_WHEEL, data=delta)


@dataclass(frozen=True)
class InputBatch:
    steps: tuple[InputStep, ...]

    def __post_init__(self):
        if not 1 <= len(self.steps) <= 128:
            raise ValueError("batch must contain 1..128 input events")
        held: set[HeldToken] = set()
        for step in self.steps:
            if not isinstance(step, InputStep) or not isinstance(step.raw, INPUT):
                raise ValueError("batch contains an invalid input event")
            if step.token is None:
                continue
            if step.pressed:
                if step.token in held:
                    raise ValueError("duplicate key or button press")
                held.add(step.token)
            elif step.token not in held:
                raise ValueError("release without matching press")
            else:
                held.remove(step.token)
        if held:
            raise ValueError("batch must release every pressed key and button")


def plan_batch(steps: Iterable[InputStep]) -> InputBatch:
    return InputBatch(tuple(steps))


@dataclass(frozen=True)
class TimedInputPlan(InputBatch):
    """One balanced call, with finite offsets, never a cross-call hold handle."""
    segments: tuple[tuple[int, tuple[InputStep, ...]], ...]
    duration_ms: int

    def __post_init__(self):
        super().__post_init__()
        if type(self.duration_ms) is not int or not 1 <= self.duration_ms <= 2000:
            raise ValueError("invalid hold duration")
        if not 2 <= len(self.segments) <= 16:
            raise ValueError("invalid timed segments")
        offsets = tuple(offset for offset, _ in self.segments)
        if (offsets[0] != 0 or offsets[-1] != self.duration_ms
                or any(type(offset) is not int for offset in offsets)
                or any(a >= b for a, b in zip(offsets, offsets[1:]))):
            raise ValueError("invalid timed offsets")
        flat = tuple(step for _, segment in self.segments for step in segment)
        if (any(not segment for _, segment in self.segments) or len(flat) != len(self.steps)
                or any(a.token != b.token or a.pressed != b.pressed or a.desktop != b.desktop
                       or bytes(a.raw) != bytes(b.raw) for a, b in zip(flat, self.steps))):
            raise ValueError("timed segments do not match input envelope")
        final = self.segments[-1][1]
        if any(step.pressed is True for step in final) or final[-1].pressed is not False:
            raise ValueError("timed plan must end with owned releases")


def plan_timed(segments: Iterable[tuple[int, Iterable[InputStep]]], duration_ms: int) -> TimedInputPlan:
    segments = tuple((offset, tuple(steps)) for offset, steps in segments)
    return TimedInputPlan(tuple(step for _, steps in segments for step in steps), segments, duration_ms)


def plan_unicode_batches(text: str) -> tuple[InputBatch, ...]:
    """Validate a bounded whole text before dispatch and keep surrogate pairs intact.

    Each returned batch is independently balanced. Callers must still check
    authorization, foreground state and business postconditions for the whole
    sequence; building this plan never asserts that text reached an editor.
    """
    if not isinstance(text, str) or not text:
        raise ValueError("text must be a nonempty string")
    try:
        units = len(text.encode("utf-16-le", errors="strict")) // 2
    except UnicodeEncodeError as error:
        raise ValueError("text contains an unpaired surrogate") from error
    if units > 8192:
        raise ValueError("text plan exceeds 8192 UTF-16 code units")
    batches: list[InputBatch] = []
    current: list[InputStep] = []
    current_units = 0
    # Narrow port of legacy core.py:text_inputs. ENTER/TAB are actual keys;
    # CRLF is one ENTER and every batch retains its own exact balanced ups.
    for character in text.replace("\r\n", "\n").replace("\r", "\n"):
        character_units = 2 if ord(character) > 0xFFFF else 1
        if current_units + character_units > 64:
            batches.append(plan_batch(current))
            current.clear()
            current_units = 0
        if character in ("\n", "\t"):
            code = 0x0D if character == "\n" else 0x09
            current.extend((virtual_key(code, down=True), virtual_key(code, down=False)))
        else:
            current.extend(unicode_text(character))
        current_units += character_units
    if current:
        batches.append(plan_batch(current))
    return tuple(batches)


def _stop_epoch():
    from ..control.write_gate import session_write_gate
    return session_write_gate().snapshot().epoch


@dataclass
class HeldInputLedger:
    """Tracks only this dispatch's sent down events; never releases all OS keys."""

    _held: list[HeldToken] = field(default_factory=list, init=False, repr=False)
    blocked: bool = False
    _dispatch_count_confirmed: bool = field(default=True, init=False, repr=False)
    thread_id: int = field(default_factory=threading.get_ident, init=False)
    stop_epoch: int = field(default_factory=_stop_epoch, init=False, repr=False)

    @property
    def held(self) -> tuple[HeldToken, ...]:
        return tuple(self._held)

    @property
    def release_confirmed(self) -> bool:
        # Empty tokens alone do not prove release if the native call never
        # returned its count. This fact concerns this exact ledger only.
        return self._dispatch_count_confirmed and not self._held

    @property
    def release_state(self) -> str:
        if not self._dispatch_count_confirmed:
            return "unknown"
        return "release_pending" if self._held else "released"

    def _begin_send(self) -> None:
        if threading.get_ident() != self.thread_id:
            raise NativeInputError("input_ledger_wrong_thread")
        self._dispatch_count_confirmed = False

    def _record(self, steps: Iterable[InputStep]) -> None:
        if threading.get_ident() != self.thread_id:
            raise NativeInputError("input_ledger_wrong_thread")
        for step in steps:
            if step.token is None:
                continue
            if step.pressed:
                self._held.append(step.token)
            else:
                self._held.remove(step.token)
        self._dispatch_count_confirmed = True


def _release_step(token: HeldToken) -> InputStep:
    kind, value = token
    if kind == "vk":
        return virtual_key(value, down=False)
    if kind == "unicode":
        return _keyboard(0, value, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP, token, False)
    button = tuple(_BUTTON_FLAGS)[value]
    return mouse_button(button, down=False)


def assert_mouse_receiver(steps, expected, geometry):
    from .computer_input_state import check_mouse_receiver
    check_mouse_receiver(steps, expected, geometry)


def _send_checked(steps: tuple[InputStep, ...], *, expected: WindowIdentity | None,
               geometry: WindowGeometry | None, preflight: Callable[[], bool],
               stopped: Callable[[], bool], cleanup: bool, before_send=None,
               owned_tokens: tuple[HeldToken, ...] = (), stop_epoch=None, final_preflight=None) -> int:
    from ..control.write_gate import session_write_gate, WriteGateError
    write_gate = session_write_gate() if not cleanup else None
    if stop_epoch is None and write_gate is not None:
        stop_epoch = write_gate.snapshot().epoch
    if not callable(preflight) or not callable(stopped):
        raise TypeError("preflight and stopped callbacks are required")
    if cleanup:
        if any(step.token is None or step.pressed is not False for step in steps):
            raise NativeInputError("cleanup_must_release_held_input_only")
        if not preflight():
            raise NativeInputError("cleanup_ownership_missing")
        stopped()  # stopping never suppresses already-owned input release
    else:
        if not preflight():
            raise NativeInputError("execution_preflight_failed")
        if stopped():
            raise NativeInputError("input_stopped")
        if expected is None:
            raise NativeInputError("target_identity_required")
        assert_foreground(expected)
        if geometry is not None:
            assert_geometry(geometry)
        absolute = [step for step in steps if step.raw.type == 0 and
                    step.raw.data.mi.dwFlags & MOUSEEVENTF_ABSOLUTE]
        if absolute:
            current_desktop = virtual_desktop()
            if any(step.desktop is None for step in absolute):
                raise NativeInputError("mouse_desktop_required")
            if any(step.desktop != current_desktop for step in absolute):
                raise NativeInputError("desktop_topology_changed")
        # Only this exact ledger's recorded downs are exempt during a timed
        # call. Never release a physical user-held key to acquire task priority.
        # GetAsyncKeyState's zero result is ambiguous on inaccessible desktops:
        # this is an extra refusal check, not proof that the desktop is idle.
        planned_keys = {step.token[1] for step in steps if step.token is not None and step.token[0] == "vk"}
        owned_keys = {value for kind, value in owned_tokens if kind == "vk"}
        owned_keys.update((0x01, 0x02, 0x04, 0x05, 0x06)[value]
                          for kind, value in owned_tokens if kind == "mouse")
        checked_keys = (set(_EXTERNAL_HOLD_KEYS) | planned_keys) - owned_keys
        deadline = time.monotonic() + (0 if owned_tokens else 0.300)
        while any(_user32.GetAsyncKeyState(key) < 0 for key in checked_keys):
            if stopped():
                raise NativeInputError("input_stopped")
            if not preflight():
                raise NativeInputError("execution_preflight_failed")
            assert_foreground(expected)
            if time.monotonic() >= deadline:
                raise NativeInputError("external_input_held")
            time.sleep(0.010)
        # Waiting and callbacks may have changed the receiver or geometry.
        if stopped() or not preflight():
            raise NativeInputError("input_stopped")
        assert_foreground(expected)
        if geometry is not None:
            assert_geometry(geometry)
        if absolute and any(step.desktop != virtual_desktop() for step in absolute):
            raise NativeInputError("desktop_topology_changed")
        if any(step.raw.type == 0 for step in steps):
            assert_mouse_receiver(steps, expected, geometry)
    array = (INPUT * len(steps))(*(step.raw for step in steps))
    if write_gate is not None:
        try:
            write_gate.admit(stop_epoch)
        except WriteGateError as error:
            raise NativeInputError(error.code) from error
    if final_preflight is not None and (stopped() or not final_preflight()):
        raise NativeInputError("input_stopped")
    if before_send is not None:
        before_send()
    try:
        sent = _user32.SendInput(len(steps), array, ctypes.sizeof(INPUT))
    except Exception:
        raise NativeInputError("input_release_unconfirmed") from None
    if sent != len(steps):
        raise PartialInput(sent, len(steps), ctypes.get_last_error())
    return sent


def send_batch(batch: InputBatch, ledger: HeldInputLedger, *, expected: WindowIdentity,
               geometry: WindowGeometry | None, preflight: Callable[[], bool],
               stopped: Callable[[], bool], final_preflight=None) -> int:
    """Dispatch one balanced short batch; never retries a partial SendInput."""

    if ledger.blocked or ledger.held or not ledger.release_confirmed or threading.get_ident() != ledger.thread_id:
        raise NativeInputError("input_release_unconfirmed")
    # Snapshot mutable ctypes structs before caller callbacks or native dispatch.
    steps = tuple(InputStep(INPUT.from_buffer_copy(bytes(step.raw)), step.token,
                            step.pressed, step.desktop) for step in batch.steps)
    InputBatch(steps)
    if geometry is not None and geometry.identity != expected:
        raise NativeInputError("geometry_target_mismatch")
    if any(step.raw.type == 0 for step in steps) and geometry is None:
        raise NativeInputError("mouse_geometry_required")
    try:
        sent = _send_checked(steps, expected=expected, geometry=geometry,
                               preflight=preflight, stopped=stopped, cleanup=False,
                               before_send=ledger._begin_send, stop_epoch=ledger.stop_epoch,
                               final_preflight=final_preflight)
    except PartialInput as error:
        ledger._record(steps[:error.sent])
        ledger.blocked = True
        raise
    ledger._record(steps)
    return sent


def send_timed_plan(plan: TimedInputPlan, ledger: HeldInputLedger, *, expected: WindowIdentity,
                    geometry: WindowGeometry | None, preflight: Callable[[], bool],
                    stopped: Callable[[], bool], progress: dict) -> int:
    """Send finite segments once; caller keeps the mutex and cleans this ledger.

    Progress is the exact accepted planned prefix, excluding emergency release.
    Even a zero-length or unknown native return never retries a segment.
    """
    if (ledger.blocked or ledger.held or not ledger.release_confirmed
            or threading.get_ident() != ledger.thread_id):
        raise NativeInputError("input_release_unconfirmed")
    segments = tuple((offset, tuple(InputStep(INPUT.from_buffer_copy(bytes(step.raw)),
                     step.token, step.pressed, step.desktop) for step in segment))
                     for offset, segment in plan.segments)
    snapshot = plan_timed(segments, plan.duration_ms)
    if geometry is not None and geometry.identity != expected:
        raise NativeInputError("geometry_target_mismatch")
    if geometry is None and any(step.raw.type == 0 for step in snapshot.steps):
        raise NativeInputError("mouse_geometry_required")
    if set(progress) != {"sent_events", "sent_segments"} or any(progress[name] != 0 for name in progress):
        raise ValueError("timed progress must start empty")
    started = None
    for offset, steps in snapshot.segments:
        if started is not None:
            deadline = started + offset / 1000
            while True:
                if stopped():
                    raise NativeInputError("input_stopped")
                if not preflight():
                    raise NativeInputError("execution_preflight_failed")
                assert_foreground(expected)
                if geometry is not None:
                    assert_geometry(geometry)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(0.020, remaining))
        # Validation of the whole envelope proves balance; this per-segment
        # check binds every up and every exemption to the exact active ledger.
        held = set(ledger.held)
        for step in steps:
            if step.token is None:
                continue
            if step.pressed:
                if step.token in held:
                    raise NativeInputError("input_release_unconfirmed")
                held.add(step.token)
            elif step.token not in held:
                raise NativeInputError("input_release_unconfirmed")
            else:
                held.remove(step.token)
        try:
            sent = _send_checked(steps, expected=expected, geometry=geometry,
                                 preflight=preflight, stopped=stopped, cleanup=False,
                                 owned_tokens=ledger.held, before_send=ledger._begin_send, stop_epoch=ledger.stop_epoch)
        except PartialInput as error:
            ledger._record(steps[:error.sent])
            progress["sent_events"] += error.sent
            ledger.blocked = True
            raise
        ledger._record(steps)
        progress["sent_events"] += sent
        progress["sent_segments"] += 1
        if started is None:
            started = time.monotonic()
    return progress["sent_events"]


def release_held(ledger: HeldInputLedger, *, cleanup_owned: Callable[[], bool],
                 stopped: Callable[[], bool]) -> int:
    """Release only recorded downs; cleanup ownership is separate from grants.

    Key/button ups are global input events. The caller must hold the cleanup
    execution right and check user input state; target focus may already be gone.
    A successful SendInput count does not verify OS or application key state.
    """

    if threading.get_ident() != ledger.thread_id:
        raise NativeInputError("input_ledger_wrong_thread")
    if not callable(cleanup_owned) or not callable(stopped):
        raise TypeError("cleanup ownership and stopped callbacks are required")
    steps = tuple(_release_step(token) for token in reversed(ledger.held))
    if not steps:
        return 0
    count_was_known = ledger._dispatch_count_confirmed
    try:
        sent = _send_checked(steps, expected=None, geometry=None,
                               preflight=cleanup_owned, stopped=stopped, cleanup=True,
                               before_send=ledger._begin_send)
    except PartialInput as error:
        ledger._record(steps[:error.sent])
        if not count_was_known:
            ledger._dispatch_count_confirmed = False
        ledger.blocked = True
        raise
    except BaseException:
        ledger.blocked = True
        raise
    ledger._record(steps)
    if not count_was_known:
        # Known emergency ups do not recover a previous unknown native count.
        ledger._dispatch_count_confirmed = False
    return sent
