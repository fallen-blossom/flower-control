"""Local first-control countdown and cooperative focus handoff; no input."""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import math
import threading
import time

import win32gui

from .computer_native import NativeInputError


class LastInputInfo(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.UINT), ("dwTime", wintypes.DWORD)]


def user_idle_seconds():
    user = ctypes.WinDLL("user32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    user.GetLastInputInfo.argtypes = [ctypes.POINTER(LastInputInfo)]
    user.GetLastInputInfo.restype = wintypes.BOOL
    kernel.GetTickCount.restype = wintypes.DWORD
    user.GetAsyncKeyState.argtypes = [ctypes.c_int]
    user.GetAsyncKeyState.restype = wintypes.SHORT
    info = LastInputInfo(ctypes.sizeof(LastInputInfo), 0)
    if not user.GetLastInputInfo(ctypes.byref(info)):
        raise NativeInputError("user_activity_unavailable")
    # Activity includes typing, mouse and IME interaction. A held key/button
    # keeps control with the user even if no new event arrives.
    if any(user.GetAsyncKeyState(key) & 0x8000 for key in range(1, 255)):
        return 0.0
    return ((kernel.GetTickCount() - info.dwTime) & 0xffffffff) / 1000


class ComputerTakeover:
    IDLE_SECONDS = .8
    COUNTDOWN_SECONDS = 2
    SAMPLE_SECONDS = .05
    MAX_SAMPLE_SECONDS = .1

    def __init__(self, *, idle=user_idle_seconds, foreground=win32gui.GetForegroundWindow,
                 clock=time.monotonic, wait=None):
        self.idle, self.foreground, self.clock = idle, foreground, clock
        self.wait = wait or (lambda stop, seconds: stop.wait(seconds))
        self.sessions = {}
        self._pending = {}
        self.gate = threading.RLock()

    def prepare(self, task, identity, *, stop, check, progress, allow_first=True, recheck_activity=False):
        with self.gate:
            session = self.sessions.get(task)
            # Only activate owns the initial countdown and immediate foreground
            # transition. Input must not finish a countdown then return to the
            # model with the target still in the background.
            if session is None and not allow_first:
                raise NativeInputError("first_takeover_requires_activation")
            pending = self._pending.get(task)
            # Do not re-arm the first-takeover countdown for an established
            # task: GetLastInputInfo also includes our own SendInput events.
            immediate = (session is not None and pending is None and
                         (not recheck_activity or self.idle() >= self.IDLE_SECONDS))
            leader = not immediate and pending is None
            if leader:
                pending = self._pending[task] = object()
        if immediate:
            # This is a new requested foreground phase, not a window event.
            # Existing tasks may restore their exact approved target once; the
            # executor still checks Stop, identity, held input and fresh pixels.
            self.check_dispatch(task, identity, allow_activation=True)
            return False
        if not leader:
            while True:
                check()
                if stop.is_set():
                    raise NativeInputError("input_stopped")
                with self.gate:
                    completed = task in self.sessions
                    still_pending = self._pending.get(task) is pending
                if completed and not still_pending:
                    self.check_dispatch(task, identity)
                    return False
                if not still_pending:
                    raise NativeInputError("input_stopped")
                self.wait(stop, .05)
        try:
            return self._prepare_first(task, pending, identity, stop=stop, check=check, progress=progress)
        finally:
            with self.gate:
                if self._pending.get(task) is pending:
                    self._pending.pop(task)

    def _prepare_first(self, task, pending, identity, *, stop, check, progress):
        remaining = float(self.COUNTDOWN_SECONDS)
        while True:
            check()
            if stop.is_set():
                raise NativeInputError("input_stopped")
            with self.gate:
                if self._pending.get(task) is not pending:
                    raise NativeInputError("input_stopped")
            idle = self.idle() >= self.IDLE_SECONDS
            if remaining <= 0 and idle:
                with self.gate:
                    if self._pending.get(task) is not pending:
                        raise NativeInputError("input_stopped")
                    self.sessions[task] = dict(identity=identity, initial_foreground=self.foreground(),
                                               initial_activation=True, explicit_resume=False)
                return True
            seconds = max(1, math.ceil(remaining))
            text = f"{seconds} 秒后开始；" + ("可点停止拒绝" if idle else "等待你操作完；可点停止拒绝")
            visible = progress(text)
            if stop.is_set():
                raise NativeInputError("input_stopped")
            # Count only the bounded wait between fresh activity samples. In
            # particular, UI startup, progress and authorization checks may
            # block; none of their elapsed time establishes a visible countdown.
            idle_before = self.idle()
            started = self.clock()
            self.wait(stop, self.SAMPLE_SECONDS)
            elapsed = max(0.0, self.clock() - started)
            idle_after = self.idle()
            visible_after = progress(text) if visible is True and not stop.is_set() else visible
            # A long scheduler gap is unobserved. The last-input age must also
            # cover the whole interval, not just exceed the idle threshold at
            # its end: input may have occurred and then gone idle in the gap.
            if (visible is not False and visible_after is not False and not stop.is_set()
                    and 0 < elapsed <= self.MAX_SAMPLE_SECONDS
                    and idle_before >= self.IDLE_SECONDS
                    and idle_after >= self.IDLE_SECONDS + elapsed):
                remaining = max(0.0, remaining - elapsed)

    def check_dispatch(self, task, identity, *, allow_activation=False):
        current = self.foreground()
        with self.gate:
            session = self.sessions.get(task)
            if session is None:
                raise NativeInputError("first_takeover_required")
            if current == identity.hwnd:
                session["identity"] = identity
                session["initial_activation"] = False
                session["explicit_resume"] = False
                return
            # Only the preparation of a newly requested foreground phase may
            # restore focus. Event callbacks and already-active input checks
            # never use this allowance, so switching cannot start a focus loop.
            if allow_activation:
                return
            if session["explicit_resume"] or (
                    session["initial_activation"] and current == session["initial_foreground"]):
                return
            raise NativeInputError("waiting_for_target_foreground")

    def confirm_activation(self, task, identity=None):
        """Consume focus permission from the executor's confirmed receipt.

        The user may have switched back before Python reads the receipt, so a
        later foreground sample must not leave first/resume permission armed.
        A finished task is never recreated by a late acknowledgement.
        """
        with self.gate:
            session = self.sessions.get(task)
            if session is not None:
                if identity is not None:
                    session["identity"] = identity
                session["initial_activation"] = False
                session["explicit_resume"] = False

    def resume(self, task):
        with self.gate:
            if task in self.sessions:
                self.sessions[task]["explicit_resume"] = True

    def finish(self, task):
        with self.gate:
            self.sessions.pop(task, None)
            self._pending.pop(task, None)
