"""Session-wide Stop and short write admission, independent of SQLite.

The byte layout and object names are shared with High's SharedWriteGate.cs.
Only admission is serialized; callers never retain this mutex during work.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
from contextlib import contextmanager
from dataclasses import dataclass
import struct
import threading

import win32api
import win32con
import win32security


class WriteGateError(RuntimeError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class WriteGateStatus:
    stopped: bool
    epoch: int
    resume_all_epoch: int


class _Attributes(ctypes.Structure):
    _fields_ = [("size", wintypes.DWORD), ("descriptor", ctypes.c_void_p),
                ("inherit", wintypes.BOOL)]


_kernel = ctypes.WinDLL("kernel32", use_last_error=True)
for _name, _args, _result in (
    ("CreateMutexW", [ctypes.POINTER(_Attributes), wintypes.BOOL, wintypes.LPCWSTR], wintypes.HANDLE),
    ("CreateFileMappingW", [wintypes.HANDLE, ctypes.POINTER(_Attributes), wintypes.DWORD,
                            wintypes.DWORD, wintypes.DWORD, wintypes.LPCWSTR], wintypes.HANDLE),
    ("MapViewOfFile", [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_size_t], ctypes.c_void_p),
    ("UnmapViewOfFile", [ctypes.c_void_p], wintypes.BOOL),
    ("WaitForSingleObject", [wintypes.HANDLE, wintypes.DWORD], wintypes.DWORD),
    ("ReleaseMutex", [wintypes.HANDLE], wintypes.BOOL),
    ("CloseHandle", [wintypes.HANDLE], wintypes.BOOL),
):
    _function = getattr(_kernel, _name)
    _function.argtypes, _function.restype = _args, _result


class SharedWriteGate:
    MAGIC = 0x46435731
    SIZE = 32

    def __init__(self, *, namespace: str | None = None):
        self._mutex = self._mapping = self._view = None
        token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
        try:
            sid = win32security.ConvertSidToStringSid(win32security.GetTokenInformation(token, win32security.TokenUser)[0])
        finally:
            token.Close()
        self.name = "Local\\FlowerControl.WriteGate.v1." + sid
        if namespace is not None:
            if not namespace or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in namespace):
                raise ValueError("invalid_write_gate_namespace")
            self.name += ".test." + namespace
        descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
            f"D:P(A;;GA;;;SY)(A;;GA;;;{sid})S:(ML;;NW;;;ME)", 1)
        buffer = ctypes.create_string_buffer(bytes(descriptor))
        attributes = _Attributes(ctypes.sizeof(_Attributes), ctypes.addressof(buffer), False)
        try:
            self._mutex = _kernel.CreateMutexW(ctypes.byref(attributes), False, self.name + ".lock")
            self._mapping = _kernel.CreateFileMappingW(wintypes.HANDLE(-1), ctypes.byref(attributes), 4, 0, self.SIZE, self.name)
            if not self._mutex or not self._mapping:
                raise WriteGateError("write_gate_unavailable")
            self._view = _kernel.MapViewOfFile(self._mapping, 6, 0, 0, self.SIZE)
            if not self._view:
                raise WriteGateError("write_gate_unavailable")
            with self._locked():
                magic = struct.unpack("<I", ctypes.string_at(self._view, 4))[0]
                if magic == 0:
                    self._write(False, 0, 0)
                elif magic != self.MAGIC:
                    raise WriteGateError("write_gate_layout_rejected")
        except BaseException:
            self.close()
            raise

    @contextmanager
    def _locked(self):
        if not self._mutex or not self._view:
            raise WriteGateError("write_gate_unavailable")
        result = _kernel.WaitForSingleObject(self._mutex, 250)
        if result not in (0, 0x80):
            raise WriteGateError("write_gate_busy")
        try:
            if result == 0x80:
                # A dead admission owner is never permission to keep writing.
                status = self._read()
                self._write(True, status.epoch + 1, status.resume_all_epoch)
            yield
        finally:
            if not _kernel.ReleaseMutex(self._mutex):
                raise WriteGateError("write_gate_release_unconfirmed")

    def _read(self):
        magic, stopped, epoch, resumed, reserved = struct.unpack("<IIqqq", ctypes.string_at(self._view, self.SIZE))
        if magic != self.MAGIC or stopped not in (0, 1) or not 0 <= resumed <= epoch or reserved:
            raise WriteGateError("write_gate_layout_rejected")
        return WriteGateStatus(bool(stopped), epoch, resumed)

    def _write(self, stopped, epoch, resumed):
        ctypes.memmove(self._view, struct.pack("<IIqqq", self.MAGIC, int(stopped), epoch, resumed, 0), self.SIZE)

    def snapshot(self):
        with self._locked():
            return self._read()

    def stop(self):
        with self._locked():
            status = self._read()
            if not status.stopped:
                self._write(True, status.epoch + 1, status.resume_all_epoch)
            return self._read()

    def resume(self, *, all_tasks: bool, expected_epoch: int | None = None):
        with self._locked():
            status = self._read()
            if expected_epoch is not None and status.epoch != expected_epoch:
                raise WriteGateError("resume_state_changed")
            self._write(False, status.epoch, status.epoch if all_tasks else status.resume_all_epoch)
            return self._read()

    def admit(self, epoch: int):
        with self._locked():
            status = self._read()
            if status.stopped or epoch != status.epoch:
                raise WriteGateError("global_write_stopped")
            return status.epoch

    def close(self):
        view, self._view = self._view, None
        if view:
            _kernel.UnmapViewOfFile(view)
        for name in ("_mapping", "_mutex"):
            handle = getattr(self, name, None)
            setattr(self, name, None)
            if handle:
                _kernel.CloseHandle(handle)

    def __del__(self):
        self.close()


_default = None
_default_lock = threading.Lock()


def session_write_gate():
    global _default
    with _default_lock:
        if _default is None:
            _default = SharedWriteGate()
        return _default
