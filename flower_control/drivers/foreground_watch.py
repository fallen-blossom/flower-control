"""Short-lived WinEvent observer for an authorized foreground execution.

No keyboard hook, screenshots, activation, restoration or input injection.
https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwineventhook
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import threading

from flower_control.control.state import ControlError
from flower_control.control.takeover import TakeoverBarrier


_user32 = ctypes.WinDLL("user32", use_last_error=True)
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_callback_type = ctypes.WINFUNCTYPE(None, wintypes.HANDLE, wintypes.DWORD,
                                   wintypes.HWND, wintypes.LONG, wintypes.LONG,
                                   wintypes.DWORD, wintypes.DWORD)
_user32.SetWinEventHook.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.HMODULE,
                                  _callback_type, wintypes.DWORD, wintypes.DWORD,
                                  wintypes.DWORD]
_user32.SetWinEventHook.restype = wintypes.HANDLE
_user32.UnhookWinEvent.argtypes = [wintypes.HANDLE]
_user32.UnhookWinEvent.restype = wintypes.BOOL
_user32.GetForegroundWindow.restype = wintypes.HWND
_user32.GetAncestor.argtypes = [wintypes.HWND, wintypes.UINT]
_user32.GetAncestor.restype = wintypes.HWND
_user32.IsWindow.argtypes = [wintypes.HWND]
_user32.IsWindow.restype = wintypes.BOOL
_user32.IsIconic.argtypes = [wintypes.HWND]
_user32.IsIconic.restype = wintypes.BOOL
_user32.SetTimer.argtypes = [wintypes.HWND, ctypes.c_size_t, wintypes.UINT,
                             ctypes.c_void_p]
_user32.SetTimer.restype = ctypes.c_size_t
_user32.KillTimer.argtypes = [wintypes.HWND, ctypes.c_size_t]
_user32.KillTimer.restype = wintypes.BOOL
_user32.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND,
                               wintypes.UINT, wintypes.UINT]
_user32.GetMessageW.restype = wintypes.BOOL
_user32.PeekMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND,
                                wintypes.UINT, wintypes.UINT, wintypes.UINT]
_user32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
_user32.DispatchMessageW.restype = ctypes.c_ssize_t
_user32.PostThreadMessageW.argtypes = [wintypes.DWORD, wintypes.UINT,
                                      wintypes.WPARAM, wintypes.LPARAM]
_user32.PostThreadMessageW.restype = wintypes.BOOL
_kernel32.GetCurrentThreadId.restype = wintypes.DWORD


def _foreground_root(hwnd: int) -> int:
    if not hwnd:
        return 0
    return int(_user32.GetAncestor(hwnd, 2) or hwnd)


class ForegroundWatch:
    def __init__(self, barrier: TakeoverBarrier):
        self.barrier = barrier
        self.ready = threading.Event()
        self.closed = threading.Event()
        self._stop_requested = threading.Event()
        self.error: BaseException | None = None
        self.thread_id: int | None = None
        self.thread: threading.Thread | None = None
        self._callback = _callback_type(self._event)

    def _event(self, _hook, event, hwnd, object_id, child_id, _thread, _time):
        try:
            if event == 0x0003:  # EVENT_SYSTEM_FOREGROUND
                self.barrier.foreground_changed(_foreground_root(int(hwnd or 0)))
            elif event == 0x0016:  # EVENT_SYSTEM_MINIMIZESTART
                self.barrier.minimized(int(hwnd or 0))
            elif event == 0x8001 and object_id == 0 and child_id == 0:
                self.barrier.target_destroyed(int(hwnd or 0),
                                              int(_user32.GetForegroundWindow() or 0))
        except BaseException as error:
            # Never let a ctypes callback swallow a failed persistent pause.
            self.error = error
            self.barrier.stopped.set()

    def _sample_live(self):
        """Reconcile missed WinEvents with current state before the next input.

        Events still catch an away-and-back transition that a sample can miss.
        """
        target = self.barrier.target_hwnd
        if not _user32.IsWindow(target):
            self.barrier.target_destroyed(target,
                                          int(_user32.GetForegroundWindow() or 0))
        elif _user32.IsIconic(target):
            self.barrier.minimized(target)
        else:
            self.barrier.foreground_changed(_foreground_root(
                int(_user32.GetForegroundWindow() or 0)))

    def _run(self):
        handles = []
        timer_id = 0
        try:
            self.thread_id = int(_kernel32.GetCurrentThreadId())
            message = wintypes.MSG()
            _user32.PeekMessageW(ctypes.byref(message), None, 0, 0, 0)
            if self._stop_requested.is_set():
                return
            for event in (0x0003, 0x0016, 0x8001):
                handle = _user32.SetWinEventHook(event, event, None, self._callback, 0, 0, 0)
                if not handle:
                    raise ctypes.WinError(ctypes.get_last_error())
                handles.append(handle)
            timer_id = _user32.SetTimer(None, 0, 50, None)
            if not timer_id:
                raise ctypes.WinError(ctypes.get_last_error())
            self._sample_live()
            self.ready.set()
            while True:
                if self._stop_requested.is_set():
                    break
                result = _user32.GetMessageW(ctypes.byref(message), None, 0, 0)
                if result == -1:
                    raise ctypes.WinError(ctypes.get_last_error())
                if result == 0:
                    break
                _user32.DispatchMessageW(ctypes.byref(message))
                self._sample_live()
        except BaseException as error:
            self.error = error
            self.barrier.stopped.set()
        finally:
            if timer_id and not _user32.KillTimer(None, timer_id) and self.error is None:
                self.error = ctypes.WinError(ctypes.get_last_error())
            for handle in handles:
                if not _user32.UnhookWinEvent(handle) and self.error is None:
                    self.error = ctypes.WinError(ctypes.get_last_error())
            self.ready.set()
            self.closed.set()

    def start(self):
        if self.thread is not None:
            raise ControlError("foreground_watch_already_started")
        self.thread = threading.Thread(target=self._run, name="flower-foreground-watch", daemon=True)
        self.thread.start()
        try:
            if not self.ready.wait(6):
                raise ControlError("foreground_watch_start_timeout")
            if self.error:
                raise ControlError("foreground_watch_failed") from self.error
            self.barrier.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        if self.error or not self.ready.is_set() or self.closed.is_set():
            raise ControlError("foreground_watch_unavailable")
        self._sample_live()
        self.barrier.check()

    def close(self):
        self._stop_requested.set()
        if self.thread is None or self.closed.is_set():
            return
        if self.thread_id is not None:
            if not _user32.PostThreadMessageW(self.thread_id, 0x0012, 0, 0):
                raise ControlError("foreground_watch_stop_failed")
        if not self.closed.wait(6):
            raise ControlError("foreground_watch_stop_timeout")
