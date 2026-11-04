"""Phase-local input activity only; no key text, values or event log."""
import ctypes
from ctypes import wintypes
import secrets
import threading

from flower_control.control.state import ControlError

# Windows' LL mouse path truncates SendInput extra information to DWORD even
# for this x64 sender. A random nonzero DWORD survives both mouse and keyboard
# unchanged; comparison remains exact, with no blanket injected-input exemption.
INPUT_TAG = secrets.randbits(32) or 1


class InputActivityLatch:
    def __init__(self, tag=INPUT_TAG):
        self.tag, self.reason = tag, None

    def observe(self, kind, tag):
        if tag != self.tag and self.reason is None:
            self.reason = "external_keyboard_activity" if kind == "keyboard" else "external_mouse_activity"

    def check(self):
        if self.reason:
            raise ControlError(self.reason)


class _Keyboard(ctypes.Structure):
    _fields_ = [("unused_vk", wintypes.DWORD), ("unused_scan", wintypes.DWORD),
        ("unused_flags", wintypes.DWORD), ("unused_time", wintypes.DWORD), ("tag", ctypes.c_size_t)]


class _Mouse(ctypes.Structure):
    _fields_ = [("unused_point", wintypes.POINT), ("unused_data", wintypes.DWORD),
        ("unused_flags", wintypes.DWORD), ("unused_time", wintypes.DWORD), ("tag", ctypes.c_size_t)]


_u = ctypes.WinDLL("user32", use_last_error=True)
_k = ctypes.WinDLL("kernel32", use_last_error=True)
_proc = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM)
_u.SetWindowsHookExW.argtypes = [ctypes.c_int, _proc, wintypes.HINSTANCE, wintypes.DWORD]
_u.SetWindowsHookExW.restype = wintypes.HANDLE
_u.CallNextHookEx.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM]
_u.CallNextHookEx.restype = ctypes.c_ssize_t
_u.UnhookWindowsHookEx.argtypes = [wintypes.HANDLE]
_u.UnhookWindowsHookEx.restype = wintypes.BOOL
_u.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
_u.GetMessageW.restype = ctypes.c_int
_u.PeekMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT, wintypes.UINT]
_u.PostThreadMessageW.argtypes = [wintypes.DWORD, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
_u.PostThreadMessageW.restype = wintypes.BOOL
_k.GetCurrentThreadId.restype = wintypes.DWORD
_k.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
_k.GetModuleHandleW.restype = wintypes.HMODULE
_retained = []  # Never free a callback while native unhook remains unconfirmed.


class InputActivityWatch:
    def __init__(self):
        self.latch = InputActivityLatch()
        self.ready, self.closed = threading.Event(), threading.Event()
        self.stop_requested = threading.Event()
        self.checkpoint = threading.Event()
        self.check_gate = threading.Lock()
        self.thread_id, self.error = None, None
        self.thread = None
        self.callbacks = []

    def _callback(self, kind, data_type):
        @_proc
        def callback(code, message, data):
            if code >= 0 and data:
                try:
                    # Read only the injected ownership tag. The structure's
                    # key/position fields are never accessed or retained.
                    tag = ctypes.c_size_t.from_address(data + data_type.tag.offset).value
                    self.latch.observe(kind, int(tag))
                except BaseException:
                    self.error = "input_activity_watch_failed"
            return _u.CallNextHookEx(None, code, message, data)
        return callback

    def _run(self):
        hooks = []
        try:
            self.thread_id = _k.GetCurrentThreadId()
            message = wintypes.MSG()
            _u.PeekMessageW(ctypes.byref(message), None, 0, 0, 0)
            for hook_kind, kind, data_type in ((13, "keyboard", _Keyboard), (14, "mouse", _Mouse)):
                if self.stop_requested.is_set():
                    return
                callback = self._callback(kind, data_type)
                self.callbacks.append(callback)
                hook = _u.SetWindowsHookExW(hook_kind, callback, _k.GetModuleHandleW(None), 0)
                if not hook:
                    raise OSError("input_activity_watch_unavailable")
                hooks.append(hook)
            self.ready.set()
            while not self.stop_requested.is_set():
                status = _u.GetMessageW(ctypes.byref(message), None, 0, 0)
                if status == 0:
                    break
                if status < 0:
                    raise OSError("input_activity_watch_failed")
                if message.message == 0x8000:
                    # Pump already pending synchronous hook deliveries before
                    # another business dispatch can cross this phase fence.
                    while _u.PeekMessageW(ctypes.byref(message), None, 0, 0, 1):
                        if message.message == 0x12:
                            return
                    self.checkpoint.set()
        except BaseException:
            self.error = "input_activity_watch_unavailable"
            self.ready.set()
        finally:
            releases = [bool(_u.UnhookWindowsHookEx(hook)) for hook in hooks]
            if not all(releases):
                self.error = "input_activity_release_unconfirmed"
                _retained.append(self)
            self.closed.set()

    def start(self):
        self.thread = threading.Thread(target=self._run, name="Flower phase input activity", daemon=True)
        self.thread.start()
        if not self.ready.wait(.5) or self.error:
            self.close()
            raise ControlError(self.error or "input_activity_watch_unavailable")

    def check(self):
        if self.error or self.closed.is_set():
            raise ControlError(self.error or "input_activity_watch_unavailable")
        self.latch.check()
        with self.check_gate:
            self.checkpoint.clear()
            if (self.stop_requested.is_set() or self.thread_id is None
                    or not _u.PostThreadMessageW(self.thread_id, 0x8000, 0, 0)
                    or not self.checkpoint.wait(.5)):
                raise ControlError("input_activity_watch_failed")
        if self.error:
            raise ControlError(self.error)
        self.latch.check()

    def close(self):
        self.stop_requested.set()
        if self.thread is None or self.closed.is_set():
            return
        if self.thread_id is not None:
            _u.PostThreadMessageW(self.thread_id, 0x12, 0, 0)
        if not self.closed.wait(.5):
            raise ControlError("input_activity_release_unconfirmed")
        if self.error == "input_activity_release_unconfirmed":
            raise ControlError(self.error)
