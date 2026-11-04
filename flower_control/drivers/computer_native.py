"""Narrow Windows geometry and input primitives; no observation or MCP surface.

Callers must hold the control-layer execution lock and supply a fresh permission /
target check. A SendInput return is a dispatch count, never business verification.
"""

from __future__ import annotations

import ctypes
import secrets
import threading
import time
from contextvars import ContextVar
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from typing import Callable, Iterable

import win32api
import win32con
import win32gui
import win32process

# Internal per-call rendering scope, never a policy writer or MCP argument.
suppress_pointer_approach = ContextVar('flower_desktop_no_extra_pointer_path',default=False)
pre_dispatch_recovery = ContextVar('flower_input_pre_dispatch_recovery', default=None)


class NativeInputError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _permission_input_error(error) -> NativeInputError:
    from .privacy_diagnostics import scan_diagnostics
    converted = NativeInputError(error.code)
    diagnostic = scan_diagnostics(getattr(error, "privacy_diagnostics", None))
    if diagnostic is not None:
        converted.privacy_diagnostics = diagnostic
    if getattr(error, 'privacy_cleanup_reason', None) == 'privacy_scan_exit_unconfirmed':
        converted.privacy_cleanup_reason = 'privacy_scan_exit_unconfirmed'
    return converted


@contextmanager
def input_privacy_session():
    from flower_control.permissions import PermissionError
    from .password_pixels import action_privacy_session
    try:
        with action_privacy_session():
            yield
    except PermissionError as error:
        raise _permission_input_error(error) from None


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
    from flower_control.permissions import require_window, PermissionError
    try:
        require_window(identity.hwnd)
    except PermissionError as error:
        raise _permission_input_error(error) from None
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


def same_process_window(parent: WindowIdentity, hwnd: int) -> bool:
    """Read-only same-application visible top-level relation, without GW_OWNER.

    Application dialogs, tool palettes and panels are frequently created
    without an explicit owner, yet they still belong to the running task
    context. This narrows nothing about authority: input keeps its own exact
    foreground, target and Stop checks; the relation only keeps a HUD frame
    from disappearing while the same application owns the foreground.

    The relation is deliberately process-wide: an unrelated top-level of the
    same process also keeps the frame, because dropping it in that case looked
    like the original defect. Tightening this needs a real owner or thread
    signal, not a guess, so the tradeoff stays documented here.
    """
    try:
        return (bool(hwnd) and win32gui.IsWindow(hwnd) and win32gui.IsWindowVisible(hwnd)
                and win32gui.GetAncestor(hwnd, win32con.GA_ROOT) == hwnd
                and win32process.GetWindowThreadProcessId(hwnd)[1] == parent.pid)
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
    from .input_activity import INPUT_TAG
    for event in array:
        event.data.ki.dwExtraInfo = INPUT_TAG
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
    keyboard = end_keyboard_input(identity, preflight=preflight, stopped=stopped,
                                 on_input_ledger=on_input_ledger, wait_for_user=True)
    if progress is not None:
        progress["keyboard_release_events"] = progress.get("keyboard_release_events", 0) + keyboard
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
    def coordinate(value, origin, size):
        # Choose the centre of this pixel's representable integer interval.
        # The OS divides the 65536 normalized units into physical pixels.
        low = ((value-origin)*65536 + size-1)//size
        high = ((value-origin+1)*65536 + size-1)//size-1
        if low>high or not 0<=low<=high<=65535:
            raise ValueError("pointer_pixel_unrepresentable")
        return (low+high)//2
    return coordinate(x,desktop.left,desktop.width),coordinate(y,desktop.top,desktop.height)


def absolute_point(step):
    if step.desktop is None:
        raise NativeInputError("mouse_desktop_required")
    desktop=step.desktop
    return (desktop.left + step.raw.data.mi.dx*desktop.width//65536,
            desktop.top + step.raw.data.mi.dy*desktop.height//65536)


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
POINTER_MOTION_GROUP_MS = 16
POINTER_MOTION_CHECK_MS = 80
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
    pointer_constraints: object | None = field(default=None, kw_only=True)
    pointer_motion: object | None = field(default=None, kw_only=True)

    def __post_init__(self):
        from .pointer_geometry import MotionConstraints, PointerMotion
        if self.pointer_constraints is not None and type(self.pointer_constraints) is not MotionConstraints:
            raise ValueError("invalid_pointer_constraints")
        if self.pointer_motion is not None and type(self.pointer_motion) is not PointerMotion:
            raise ValueError("invalid_pointer_motion")
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


def plan_batch(steps: Iterable[InputStep], **pointer_options) -> InputBatch:
    return InputBatch(tuple(steps), **pointer_options)


@dataclass(frozen=True)
class TimedInputPlan(InputBatch):
    """One balanced call, with finite offsets, never a cross-call hold handle."""
    segments: tuple[tuple[int, tuple[InputStep, ...]], ...]
    duration_ms: int

    def __post_init__(self):
        super().__post_init__()
        if type(self.duration_ms) is not int or not 1 <= self.duration_ms <= 3000:
            raise ValueError("invalid hold duration")
        if not 2 <= len(self.segments) <= 128:
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


def plan_timed(segments: Iterable[tuple[int, Iterable[InputStep]]], duration_ms: int, **pointer_options) -> TimedInputPlan:
    segments = tuple((offset, tuple(steps)) for offset, steps in segments)
    return TimedInputPlan(tuple(step for _, steps in segments for step in steps), segments, duration_ms, **pointer_options)


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
    def flush():
        nonlocal current_units
        if current:
            batches.append(plan_batch(current))
            current.clear()
            current_units = 0
    # Narrow port of legacy core.py:text_inputs. ENTER/TAB are actual keys;
    # CRLF is one ENTER and every batch retains its own exact balanced ups.
    for character in text.replace("\r\n", "\n").replace("\r", "\n"):
        character_units = 2 if ord(character) > 0xFFFF else 1
        navigation = character in ("\n", "\t")
        if current_units + character_units > 64 or navigation:
            flush()
        if character in ("\n", "\t"):
            code = 0x0D if character == "\n" else 0x09
            current.extend((virtual_key(code, down=True), virtual_key(code, down=False)))
        else:
            current.extend(unicode_text(character))
        current_units += character_units
        # Navigation/submission is its own balanced segment. The next segment
        # must re-observe focus, privacy, modal state and authority before send.
        if navigation:
            flush()
    flush()
    return tuple(batches)


def input_execution_budget(batches: Iterable[InputBatch | TimedInputPlan]) -> int:
    """Bound High execution work before go; this is not a measured latency SLA.

    Every actual fresh segment is charged; bounded factory motion samples use
    the lighter non-button weight. Owned release-only segments retain their
    bypass, and hold time starts at the accepted down. These weights must
    match ComputerPlans.ExecutionBudget; they grant no input or extra TTL.
    """
    batches = tuple(batches)
    if not 1 <= len(batches) <= 8192:
        raise ValueError("input_plan_rejected")
    budget = 2000
    physical_allowance = 0
    for batch in batches:
        batch.__post_init__()
        timed = isinstance(batch, TimedInputPlan)
        segments = batch.segments if timed else ((0, batch.steps),)
        budget += batch.duration_ms if timed else 0
        first = segments[0][1][0]
        if first.token is None and first.raw.type == 0 and first.raw.data.mi.dwFlags == 0xc001:
            budget += 120
        held = set()
        for _offset, steps in segments:
            owned_ups = all(step.token is not None and step.pressed is False and step.token in held
                            for step in steps)
            if not owned_ups:
                motion_sample = (timed and batch.pointer_motion is not None and all(
                    step.token is None and step.raw.type == 0 and step.raw.data.mi.dwFlags == 0xc001
                    for step in steps))
                physical_key = any(step.raw.type == 1 and step.token is not None
                                   and step.token[0] == "vk" and step.token[1] != 9 for step in steps)
                # B40 measured 0.34-0.37s per physical key plan. A 50ms
                # estimate truncated an admitted 32-key sequence at step 17.
                # Keep Unicode chunk/navigation capacity and charge 500ms for
                # physical-key provider/check work, never shorten key holds.
                weight = 500 if not motion_sample and any(step.raw.type == 0 for step in steps) else 50
                budget += weight
                if physical_key and weight == 50:
                    physical_allowance += 450
            if any(step.pressed and (step.token == ("vk", 9) or
                                    step.token is not None and step.token[0] == "mouse") for step in steps):
                budget += 150
            for step in steps:
                if step.token is not None:
                    if step.pressed:
                        held.add(step.token)
                    else:
                        held.remove(step.token)
    if budget > 30000:
        raise ValueError("input_plan_budget_exceeded")
    # Calibration increases the execution deadline, never shrinks the original
    # admitted plan capacity. The native transport contract caps one lease.
    return min(30000, max(5000, budget + physical_allowance))


def _stop_epoch():
    from ..control.write_gate import session_write_gate
    return session_write_gate().snapshot().epoch


@dataclass
class HeldInputLedger:
    """Tracks exact own downs and counted keyboard preparation, without replay."""

    _held: list[HeldToken] = field(default_factory=list, init=False, repr=False)
    blocked: bool = False
    pointer_events: int = 0
    _last_dispatch_check: float = field(default=0.0, init=False, repr=False)
    _mouse_capture: int | None = field(default=None, init=False, repr=False)
    _gesture_privacy: object = field(default=None, init=False, repr=False)
    _pending_gesture_privacy: object = field(default=None, init=False, repr=False)
    keyboard_release_events: int = 0
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
        self._last_dispatch_check = time.monotonic()

    def _check_mouse_capture(self, capture):
        if not any(kind=="mouse" for kind,_ in self.held):
            self._mouse_capture=None
            return
        if self._mouse_capture is not None and capture!=self._mouse_capture:
            raise NativeInputError("pointer_drag_capture_changed")
        if type(capture) is int and capture:
            self._mouse_capture=capture

    def _record(self, steps: Iterable[InputStep]) -> None:
        if threading.get_ident() != self.thread_id:
            raise NativeInputError("input_ledger_wrong_thread")
        steps = tuple(steps)
        reviewed_gesture = self._pending_gesture_privacy
        if any(step.raw.type == 1 for step in steps):
            self._clear_gesture_privacy()
        for step in steps:
            if step.token is None:
                continue
            if step.pressed:
                self._held.append(step.token)
            else:
                self._held.remove(step.token)
        if any(step.pressed and step.token is not None and step.token[0] == "mouse" for step in steps):
            self._gesture_privacy = reviewed_gesture
        self._pending_gesture_privacy = None
        if not any(kind == "mouse" for kind, _ in self.held):
            self._clear_gesture_privacy()
        self._dispatch_count_confirmed = True

    def _clear_gesture_privacy(self):
        self._gesture_privacy = self._pending_gesture_privacy = None

    def _record_keyboard_ups(self, steps: Iterable[InputStep]) -> None:
        if threading.get_ident() != self.thread_id or self._held:
            raise NativeInputError("input_ledger_wrong_thread")
        if any(step.raw.type != 1 or step.pressed is not False for step in steps):
            raise NativeInputError("keyboard_preparation_requires_ups")
        self._dispatch_count_confirmed = True


def end_keyboard_input(identity, *, preflight, stopped, on_input_ledger=None, wait_for_user=False):
    """End one current logical keyboard chord for an admitted AI input phase.

    Only key-up events are possible. No mouse release, key-down, event capture,
    replay or ongoing suppression is performed. The caller still owns the
    exact foreground execution resource. Unknown native counts remain unknown.
    """
    if stopped() or not preflight():
        raise NativeInputError("input_stopped")
    assert_window(identity)
    previous = win32gui.GetForegroundWindow()
    _assert_activation_foreground_allowed(previous)
    if wait_for_user:
        # Activation waits for the person's own keys and mouse buttons; it
        # never sends synthetic ups to make a foreground takeover possible.
        while any(_user32.GetAsyncKeyState(key) < 0 for key in range(1, 255)):
            if stopped() or not preflight():
                raise NativeInputError("input_stopped")
            assert_window(identity)
            time.sleep(.02)
        return 0
    held = {key for key in range(8, 255) if _user32.GetAsyncKeyState(key) < 0}
    for generic, left, right in ((16, 160, 161), (17, 162, 163), (18, 164, 165)):
        if held.intersection((left, right)):
            held.discard(generic)
    if not held:
        return 0
    def check_desktop():
        # Reuse the existing read-only ordinary-desktop identity probe. A
        # window grant does not permit global key-ups on a secure desktop.
        from .desktop_capture_native import _open_ordinary_desktop, _close_desktop
        from .desktop_capture import DesktopCaptureError
        try:
            handle, _ = _open_ordinary_desktop()
            if not _close_desktop(handle):
                raise NativeInputError("desktop_handle_close_failed")
        except DesktopCaptureError:
            raise NativeInputError("desktop_input_unavailable") from None
    check_desktop()
    ledger = HeldInputLedger()
    if on_input_ledger is not None:
        on_input_ledger(ledger)
    # Re-sample the bounded set at dispatch; a released key needs no synthetic
    # up. New keys are handled by the next safe phase, never a release loop.
    if stopped() or not preflight():
        raise NativeInputError("input_stopped")
    assert_window(identity)
    if win32gui.GetForegroundWindow() != previous:
        raise NativeInputError("foreground_changed")
    _assert_activation_foreground_allowed(previous)
    steps = tuple(virtual_key(key, down=False) for key in sorted(held)
                  if _user32.GetAsyncKeyState(key) < 0)
    if not steps:
        return 0
    from ..control.write_gate import session_write_gate, WriteGateError
    try:
        session_write_gate().admit(ledger.stop_epoch)
    except WriteGateError as error:
        raise NativeInputError(error.code) from error
    if stopped() or not preflight():
        raise NativeInputError("input_stopped")
    assert_window(identity)
    if win32gui.GetForegroundWindow() != previous:
        raise NativeInputError("foreground_changed")
    _assert_activation_foreground_allowed(previous)
    check_desktop()
    from .input_activity import INPUT_TAG
    array = (INPUT * len(steps))(*(step.raw for step in steps))
    for event in array:
        event.data.ki.dwExtraInfo = INPUT_TAG
    ledger._begin_send()
    try:
        count = int(_user32.SendInput(len(steps), array, ctypes.sizeof(INPUT)))
    except Exception:
        raise NativeInputError("input_release_unconfirmed") from None
    if not 0 <= count <= len(steps):
        raise NativeInputError("input_release_unconfirmed")
    ledger._record_keyboard_ups(steps[:count])
    ledger.keyboard_release_events += count
    if count != len(steps):
        ledger.blocked = True
        raise NativeInputError("keyboard_preparation_incomplete")
    return count


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
    return check_mouse_receiver(steps, expected, geometry)


def expected_mouse_focus(steps, expected, geometry) -> int | None:
    """Bind one own mouse-down to its exact child; never guess relative focus."""
    steps = tuple(steps)
    mouse_down = lambda step: step.raw.type == 0 and bool(step.raw.data.mi.dwFlags & 0x2a)
    if not any(mouse_down(step) for step in steps):
        return None
    from . import computer_input_state as state
    state.check_mouse_receiver(steps, expected, geometry)
    thread, pid = state.win32process.GetWindowThreadProcessId(expected.hwnd)
    gui = state.GUIThreadInfo()
    gui.cbSize = ctypes.sizeof(gui)
    if pid != expected.pid or not state._user32.GetGUIThreadInfo(thread, ctypes.byref(gui)):
        raise NativeInputError("mouse_receiver_unavailable")
    if gui.hwndCapture:
        if win32gui.GetAncestor(int(gui.hwndCapture), 2) != expected.hwnd:
            raise NativeInputError("mouse_receiver_changed")
        return None  # Capture proves the root, not the next focused child.
    point = None
    clicked = None
    saw_absolute = any(step.raw.type == 0 and step.raw.data.mi.dwFlags & 0x8000 for step in steps)
    if not saw_absolute:
        point = win32gui.GetCursorPos()
    for step in steps:
        if step.raw.type != 0:
            continue
        mouse = step.raw.data.mi
        if mouse.dwFlags & 0x8000:
            desktop = step.desktop
            if desktop is None or desktop != virtual_desktop():
                raise NativeInputError("desktop_topology_changed")
            point = absolute_point(step)
        elif mouse.dwFlags & 1:
            point = None
        if mouse_down(step):
            clicked = point
    if clicked is None:
        return None
    receiver = win32gui.WindowFromPoint(clicked)
    if not receiver or win32gui.GetAncestor(receiver, 2) != expected.hwnd:
        raise NativeInputError("mouse_receiver_changed")
    return int(receiver)


def _send_checked(steps: tuple[InputStep, ...], **kwargs) -> int:
    """Recover only a proven pre-send refusal; a native attempt is never retried."""
    began = False
    original_begin = kwargs.get("before_send")
    def before_send():
        nonlocal began
        began = True
        if original_begin is not None:
            original_begin()
    kwargs["before_send"] = before_send
    for attempt in range(2):
        try:
            return _send_checked_once(steps, **kwargs)
        except NativeInputError as error:
            if kwargs.get("privacy_ledger") is not None:
                kwargs["privacy_ledger"]._clear_gesture_privacy()
            recover = pre_dispatch_recovery.get()
            if (attempt or began or kwargs.get("cleanup") or recover is None
                    or not recover(error.code)):
                raise
            if kwargs.get("privacy_ledger") is not None:
                kwargs["privacy_ledger"]._clear_gesture_privacy()
    raise NativeInputError("input_stopped")


def _send_checked_once(steps: tuple[InputStep, ...], *, expected: WindowIdentity | None,
               geometry: WindowGeometry | None, preflight: Callable[[], bool],
               stopped: Callable[[], bool], cleanup: bool, before_send=None,
               owned_tokens: tuple[HeldToken, ...] = (), stop_epoch=None, final_preflight=None,
               pointer_approach=False, capture_guard=None, privacy_ledger=None) -> int:
    from ..control.write_gate import session_write_gate, WriteGateError
    write_gate = session_write_gate() if not cleanup else None
    if stop_epoch is None and write_gate is not None:
        stop_epoch = write_gate.snapshot().epoch
    if not callable(preflight) or not callable(stopped):
        raise TypeError("preflight and stopped callbacks are required")
    if privacy_ledger is not None and any(step.raw.type == 1 for step in steps):
        privacy_ledger._clear_gesture_privacy()
    if pointer_approach and (cleanup or owned_tokens or any(step.token is not None or step.raw.type != 0
            or step.raw.data.mi.dwFlags != (MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK)
            for step in steps)):
        raise NativeInputError("pointer_approach_must_only_move")
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
        from flower_control.privacy import require_unmasked_steps
        from flower_control.permissions import PermissionError
        try:
            require_unmasked_steps(expected, steps, geometry, check_keyboard=False, sweep_motion=pointer_approach, owned_tokens=owned_tokens)
        except PermissionError as error:
            raise _permission_input_error(error) from None
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
        waited = False
        while any(_user32.GetAsyncKeyState(key) < 0 for key in checked_keys):
            waited = True
            if stopped():
                raise NativeInputError("input_stopped")
            if not preflight():
                raise NativeInputError("execution_preflight_failed")
            assert_foreground(expected)
            if time.monotonic() >= deadline:
                raise NativeInputError("external_input_held")
            time.sleep(0.010)
        # Waiting and callbacks may have changed the receiver or geometry.
        if stopped() or waited and not preflight():
            raise NativeInputError("input_stopped")
        assert_foreground(expected)
        if geometry is not None:
            assert_geometry(geometry)
        if absolute and any(step.desktop != virtual_desktop() for step in absolute):
            raise NativeInputError("desktop_topology_changed")
    array = (INPUT * len(steps))(*(step.raw for step in steps))
    from .input_activity import INPUT_TAG
    for event in array:
        if event.type == 0:
            event.data.mi.dwExtraInfo = INPUT_TAG
        elif event.type == 1:
            event.data.ki.dwExtraInfo = INPUT_TAG
    if not cleanup:
        try:
            metadata = None
            only_owned_ups = bool(steps) and all(step.token is not None and step.pressed is False and step.token in owned_tokens for step in steps)
            if not pointer_approach and not only_owned_ups:
                from .password_pixels import password_metadata
                snapshot = privacy_ledger._gesture_privacy if privacy_ledger is not None else None
                continuing = (snapshot is not None and snapshot[0] == expected
                    and bool(steps) and any(kind == "mouse" for kind, _ in owned_tokens)
                    and all(step.raw.type == 0 and (step.token is None and step.raw.data.mi.dwFlags == 0xc001
                        or step.token is not None and step.token[0] == "mouse" and step.pressed is False and step.token in owned_tokens)
                        for step in steps))
                if continuing:
                    metadata = snapshot[1]
                else:
                    if privacy_ledger is not None: privacy_ledger._clear_gesture_privacy()
                    metadata = password_metadata(expected, preflight=lambda: preflight() and assert_foreground(expected), stopped=stopped,
                        keyboard_focus=all(step.raw.type == 1 for step in steps))
            require_unmasked_steps(expected, steps, geometry, password_info=metadata,
                check_keyboard=not pointer_approach and not only_owned_ups, sweep_motion=pointer_approach, owned_tokens=owned_tokens)
            if stopped() or not preflight(): raise NativeInputError("input_stopped")
            assert_foreground(expected)
            if geometry is not None: assert_geometry(geometry)
            if privacy_ledger is not None and metadata is not None and any(step.pressed and step.token is not None and step.token[0] == "mouse" for step in steps):
                privacy_ledger._pending_gesture_privacy = (expected, dict(metadata, focus_rectangle=None, focus_password=None))
        except PermissionError as error:
            raise _permission_input_error(error) from None
    if write_gate is not None:
        try:
            write_gate.admit(stop_epoch)
        except WriteGateError as error:
            raise NativeInputError(error.code) from error
    if final_preflight is not None and (stopped() or not final_preflight()):
        raise NativeInputError("input_stopped")
    if not cleanup and not pointer_approach and any(step.raw.type == 0 for step in steps):
        capture = assert_mouse_receiver(steps, expected, geometry)
        if capture_guard is not None:
            capture_guard(capture)
    if write_gate is not None:
        try:
            write_gate.admit(stop_epoch)
        except WriteGateError as error:
            raise NativeInputError(error.code) from error
    if before_send is not None:
        before_send()
    try:
        sent = _user32.SendInput(len(steps), array, ctypes.sizeof(INPUT))
    except Exception:
        if privacy_ledger is not None: privacy_ledger._clear_gesture_privacy()
        raise NativeInputError("input_release_unconfirmed") from None
    if sent != len(steps):
        if privacy_ledger is not None: privacy_ledger._clear_gesture_privacy()
        raise PartialInput(sent, len(steps), ctypes.get_last_error())
    return sent


def _wait_pointer_offset(started, offset_ms, ledger, stopped, preflight=None, expected=None, geometry=None):
    from ..control.write_gate import session_write_gate, WriteGateError
    while True:
        if stopped():
            raise NativeInputError("input_stopped")
        try:
            session_write_gate().admit(ledger.stop_epoch)
        except WriteGateError as error:
            raise NativeInputError(error.code) from error
        if ledger.held and time.monotonic()-ledger._last_dispatch_check >= POINTER_MOTION_CHECK_MS/1000:
            if preflight is None or not preflight():
                raise NativeInputError("execution_preflight_failed")
            assert_foreground(expected)
            if geometry is not None:
                assert_geometry(geometry)
            ledger._last_dispatch_check=time.monotonic()
        remaining=started+offset_ms/1000-time.monotonic()
        if remaining<=0:
            return
        # No input occurs here. Full authority/privacy/target checks remain
        # immediately before each actual send, rather than every wait tick.
        time.sleep(min(.004,remaining))


def _pointer_chord_guard(motion, point, final_preflight=None):
    def guard():
        if final_preflight is not None and not final_preflight():
            return False
        if motion.route is not None and motion.route.obstacles:
            from .pointer_geometry import segment_clear
            if not segment_clear(win32gui.GetCursorPos(),point,motion.route.obstacles):
                raise NativeInputError("pointer_motion_geometry_changed")
        return True
    return guard


def _play_pointer_motion(motion,ledger,expected,geometry,preflight,stopped,
                         final_preflight=None,*,desktop,include_endpoint=False):
    samples=motion.samples if include_endpoint else motion.samples[:-1]
    started=time.monotonic();index=0;last_offset=0
    required={tuple(round(value) for value in point) for _distance,point in motion.route.required} if motion.route is not None else set()
    # At most one native dispatch per 16ms slice. This keeps about 60 visible
    # positions per second while amortizing full Stop/target/permission checks;
    # each slice still rechecks the complete real cursor chord before dispatch.
    batch_window_ms=16
    while index<len(samples):
        elapsed=(time.monotonic()-started)*1000
        sample=samples[index]
        # Drop only obsolete non-semantic approach points; the normal margin
        # still applies to the new real chord. Never rush through a whole route.
        from .pointer_geometry import segment_clear
        while (index+1<len(samples) and samples[index+1].offset_ms<=elapsed
                and samples[index+1].offset_ms-last_offset<=20
                and (motion.route is None or segment_clear(
                    win32gui.GetCursorPos(),samples[index+1].point,motion.route.obstacles))):
            index+=1;sample=samples[index]
        if elapsed-sample.offset_ms>20:
            started=time.monotonic()-sample.offset_ms/1000
        _wait_pointer_offset(started,sample.offset_ms,ledger,stopped,preflight,expected,geometry)
        batch=[sample];next_index=index+1
        while next_index<len(samples):
            candidate=samples[next_index]
            if candidate.offset_ms-sample.offset_ms>batch_window_ms:break
            if candidate.point in required:break
            batch.append(candidate);next_index+=1
        move=tuple(mouse_move(*item.point,desktop) for item in batch)
        def guard(points=tuple(item.point for item in batch)):
            if final_preflight is not None and not final_preflight():
                return False
            if motion.route is not None and motion.route.obstacles:
                from .pointer_geometry import segment_clear
                previous=win32gui.GetCursorPos()
                for point in points:
                    if not segment_clear(previous,point,motion.route.obstacles):
                        raise NativeInputError("pointer_motion_geometry_changed")
                    previous=point
            return True
        try:
            sent=_send_checked(move,expected=expected,geometry=geometry,preflight=preflight,
                stopped=stopped,cleanup=False,pointer_approach=not bool(ledger.held),
                owned_tokens=ledger.held,before_send=ledger._begin_send,
                stop_epoch=ledger.stop_epoch,final_preflight=guard,capture_guard=ledger._check_mouse_capture,privacy_ledger=ledger)
        except PartialInput as error:
            ledger._record(move[:error.sent]);ledger.pointer_events+=error.sent;ledger.blocked=True
            raise NativeInputError("pointer_motion_incomplete") from error
        ledger._record(move);ledger.pointer_events+=sent
        last_offset=batch[-1].offset_ms;index=next_index
    _wait_pointer_offset(started,motion.duration_ms,ledger,stopped,preflight,expected,geometry)


def _confirm_pointer_endpoint(step,ledger,expected,geometry,preflight,stopped,constraints):
    destination=absolute_point(step)
    if win32gui.GetCursorPos()==destination:
        return destination
    if stopped() or not preflight():
        raise NativeInputError("input_stopped")
    # A successful native count does not prove that the pointer is at the
    # destination. Continue only the held motion, never repeat a button-down.
    from .pointer_path import plan_pointer_motion
    desktop=step.desktop
    try:
        correction=plan_pointer_motion(win32gui.GetCursorPos(),destination,
            (desktop.left,desktop.top,desktop.left+desktop.width,desktop.top+desktop.height),
            constraints=constraints,path_mode="direct",force_motion=True,
            checkpoint=lambda: _wait_pointer_offset(time.monotonic(),0,ledger,stopped,preflight,expected,geometry))
    except ValueError as error:
        raise NativeInputError(str(error)) from error
    _play_pointer_motion(correction,ledger,expected,geometry,preflight,stopped,desktop=desktop,include_endpoint=True)
    if win32gui.GetCursorPos()!=destination:
        raise NativeInputError("pointer_endpoint_unconfirmed")
    return destination


def _owned_release_split(steps):
    if not any(s.token is not None and s.token[0]=="mouse" and s.pressed is False for s in steps):
        return None
    index=next((i for i,s in reversed(tuple(enumerate(steps)))
        if s.raw.type==0 and s.raw.data.mi.dwFlags==(MOUSEEVENTF_MOVE|MOUSEEVENTF_ABSOLUTE|MOUSEEVENTF_VIRTUALDESK)),None)
    if index is None or index==len(steps)-1 or any(
            s.token is None or s.pressed is not False for s in steps[index+1:]):
        return None
    return index+1


def _dispatch_input_steps(steps,ledger,*,expected,geometry,preflight,stopped,
                          constraints=None,motion=None,final_preflight=None,accepted=None):
    split=_owned_release_split(steps) if motion is not None else None
    groups=(steps,) if split is None else (steps[:split],steps[split:])
    total=0;endpoint=None
    for group in groups:
        def guard():
            if final_preflight is not None and not final_preflight():
                return False
            if endpoint is not None and win32gui.GetCursorPos()!=endpoint:
                raise NativeInputError("pointer_endpoint_changed_before_release")
            if constraints is not None and constraints.obstacles:
                from .pointer_geometry import MotionConstraints,segment_clear
                previous=win32gui.GetCursorPos()
                carrying={token for token in ledger.held if token[0]=="mouse"}
                point_obstacles=MotionConstraints(obstacles=constraints.obstacles,
                    uncertainty_px=constraints.uncertainty_px).expanded()
                body_obstacles=constraints.expanded()
                for step in group:
                    if step.raw.type==0 and step.raw.data.mi.dwFlags& MOUSEEVENTF_ABSOLUTE:
                        point=absolute_point(step)
                        if not segment_clear(previous,point,body_obstacles if carrying else point_obstacles):
                            raise NativeInputError("pointer_motion_geometry_changed")
                        previous=point
                    if step.token is not None and step.token[0]=="mouse":
                        if step.pressed:
                            if not segment_clear(previous,previous,body_obstacles):
                                raise NativeInputError("pointer_motion_geometry_changed")
                            carrying.add(step.token)
                        else:
                            carrying.discard(step.token)
            return True
        try:
            sent=_send_checked(group,expected=expected,geometry=geometry,
                preflight=preflight,stopped=stopped,cleanup=False,owned_tokens=ledger.held,
                before_send=ledger._begin_send,stop_epoch=ledger.stop_epoch,
                final_preflight=guard if motion is not None or constraints is not None or final_preflight else None,
                capture_guard=ledger._check_mouse_capture,privacy_ledger=ledger)
        except PartialInput as error:
            ledger._record(group[:error.sent]);ledger.blocked=True
            if accepted is not None:accepted(error.sent)
            raise PartialInput(total+error.sent,len(steps),error.winerror) from error
        ledger._record(group)
        total+=sent
        if accepted is not None:accepted(sent)
        if split is not None and endpoint is None:
            endpoint=_confirm_pointer_endpoint(group[-1],ledger,expected,geometry,preflight,stopped,constraints)
    return total


def _smooth_before(steps,ledger,expected,geometry,preflight,stopped,final_preflight=None,constraints=None):
    if suppress_pointer_approach.get() or not steps or ledger.held:
        return
    first=steps[0]
    if first.raw.type!=0 or first.raw.data.mi.dwFlags!=(MOUSEEVENTF_MOVE|MOUSEEVENTF_ABSOLUTE|MOUSEEVENTF_VIRTUALDESK):
        return
    desktop=first.desktop
    if desktop is None:
        raise NativeInputError("mouse_desktop_required")
    if stopped() or not preflight():
        raise NativeInputError("input_stopped")
    assert_foreground(expected)
    if geometry is not None:
        assert_geometry(geometry)
    if constraints is not None:
        # Before the down, the cursor is not yet carrying the dragged body.
        from .pointer_geometry import MotionConstraints
        constraints=MotionConstraints(obstacles=constraints.obstacles,uncertainty_px=constraints.uncertainty_px)
    from .pointer_path import plan_pointer_motion
    motion=plan_pointer_motion(win32gui.GetCursorPos(),absolute_point(first),
        (desktop.left,desktop.top,desktop.left+desktop.width,desktop.top+desktop.height),
        constraints=constraints,
        checkpoint=lambda: _wait_pointer_offset(time.monotonic(),0,ledger,stopped,preflight,expected,geometry))
    if motion.duration_ms:
        _play_pointer_motion(motion,ledger,expected,geometry,preflight,stopped,
            final_preflight,desktop=desktop)


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
    _smooth_before(steps, ledger, expected, geometry, preflight, stopped, final_preflight,
        constraints=batch.pointer_constraints)
    return _dispatch_input_steps(steps,ledger,expected=expected,geometry=geometry,
        preflight=preflight,stopped=stopped,constraints=batch.pointer_constraints,
        motion=batch.pointer_motion,final_preflight=final_preflight)


def send_timed_plan(plan: TimedInputPlan, ledger: HeldInputLedger, *, expected: WindowIdentity,
                    geometry: WindowGeometry | None, preflight: Callable[[], bool],
                    stopped: Callable[[], bool], progress: dict, before_segment=None,
                    final_preflight=None, after_segment=None) -> int:
    with input_privacy_session():
        return _send_timed_plan(plan, ledger, expected=expected, geometry=geometry,
            preflight=preflight, stopped=stopped, progress=progress,
            before_segment=before_segment, final_preflight=final_preflight, after_segment=after_segment)


def _send_timed_plan(plan: TimedInputPlan, ledger: HeldInputLedger, *, expected: WindowIdentity,
                    geometry: WindowGeometry | None, preflight: Callable[[], bool],
                    stopped: Callable[[], bool], progress: dict, before_segment=None,
                    final_preflight=None, after_segment=None) -> int:
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
    snapshot = plan_timed(segments, plan.duration_ms, pointer_constraints=plan.pointer_constraints,
        pointer_motion=plan.pointer_motion)
    if geometry is not None and geometry.identity != expected:
        raise NativeInputError("geometry_target_mismatch")
    if geometry is None and any(step.raw.type == 0 for step in snapshot.steps):
        raise NativeInputError("mouse_geometry_required")
    if set(progress) != {"sent_events", "sent_segments"} or any(progress[name] != 0 for name in progress):
        raise ValueError("timed progress must start empty")
    started = None
    last_offset=0
    mandatory={point for _,point in snapshot.pointer_motion.route.required} if snapshot.pointer_motion and snapshot.pointer_motion.route else set()
    index=0
    last_full_check=float("-inf")
    cached_result=True
    def cached_final(steps,force=False):
        nonlocal last_full_check,cached_result
        now=time.monotonic()
        if force or now-last_full_check>=POINTER_MOTION_CHECK_MS/1000:
            cached_result=True if final_preflight is None else bool(final_preflight(steps))
            last_full_check=now
        return cached_result
    while index<len(snapshot.segments):
        offset,steps=snapshot.segments[index]
        if before_segment is not None:
            before_segment(steps)
        final_check = None if final_preflight is None else lambda steps=steps: cached_final(steps,True)
        if started is None:
            _smooth_before(snapshot.steps, ledger, expected, geometry, preflight, stopped,
                final_check, constraints=snapshot.pointer_constraints)
        if started is not None:
            elapsed=(time.monotonic()-started)*1000
            automatic=bool(snapshot.pointer_motion and snapshot.pointer_motion.automatic)
            if automatic and len(steps)==1 and steps[0].token is None and index+1<len(snapshot.segments):
                next_offset,next_steps=snapshot.segments[index+1]
                from .pointer_geometry import segment_clear
                if (absolute_point(steps[0]) not in mandatory and next_offset<=elapsed
                        and next_offset-last_offset<=20 and next_steps[0].raw.type==0
                        and next_steps[0].raw.data.mi.dwFlags& MOUSEEVENTF_ABSOLUTE
                        and segment_clear(win32gui.GetCursorPos(),absolute_point(next_steps[0]),
                            snapshot.pointer_motion.route.obstacles)):
                    progress["skipped_motion_segments"]=progress.get("skipped_motion_segments",0)+1
                    index+=1
                    continue
            if automatic and elapsed-offset>20:
                started=time.monotonic()-offset/1000
                progress["motion_clock_rebases"]=progress.get("motion_clock_rebases",0)+1
            _wait_pointer_offset(started,offset,ledger,stopped,preflight,expected,geometry)
        grouped=list(steps);group_end=offset;next_index=index+1
        automatic=bool(snapshot.pointer_motion and snapshot.pointer_motion.automatic)
        if automatic and len(steps)==1 and steps[0].token is None:
            from .pointer_geometry import segment_clear
            while next_index<len(snapshot.segments):
                next_offset,next_steps=snapshot.segments[next_index]
                if next_offset-offset>POINTER_MOTION_GROUP_MS or len(next_steps)!=1:break
                candidate=next_steps[0]
                if (candidate.token is not None or candidate.raw.type!=0
                        or candidate.raw.data.mi.dwFlags!=0xc001
                        or absolute_point(candidate) in mandatory
                        or not segment_clear(absolute_point(grouped[-1]),absolute_point(candidate),
                            snapshot.pointer_motion.route.obstacles)):
                    break
                if before_segment is not None:before_segment(next_steps)
                grouped.extend(next_steps);group_end=next_offset;next_index+=1
        steps=tuple(grouped)
        force=(any(step.token is not None or step.raw.type!=0 for step in steps)
            or absolute_point(steps[0]) in mandatory)
        final_check = None if final_preflight is None else lambda steps=steps,force=force: cached_final(steps,force)
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
        def accepted(count):
            progress["sent_events"]+=count
        _dispatch_input_steps(steps,ledger,expected=expected,geometry=geometry,
            preflight=preflight,stopped=stopped,constraints=snapshot.pointer_constraints,
            motion=snapshot.pointer_motion,accepted=accepted,final_preflight=final_check)
        progress["sent_segments"] += 1
        progress["sent_segments"] += next_index-index-1
        last_offset=group_end
        if after_segment is not None:
            for included in snapshot.segments[index:next_index]:after_segment(included[1])
        if started is None:
            started = time.monotonic()
        index=next_index
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
    ledger._clear_gesture_privacy()
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
