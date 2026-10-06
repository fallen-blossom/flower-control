"""Windows execution locks; lease expiry never substitutes for these locks."""

from __future__ import annotations

import hashlib
import threading
import ctypes
from ctypes import wintypes
from functools import lru_cache

import win32api
import win32con
import win32event
import win32gui
import win32process


class ResourceBusy(RuntimeError):
    pass


class AbandonedResource(RuntimeError):
    pass


# Shared, unowned scheduling resource. Window resources remain task-owned, but
# all operations that may use or take the foreground must also queue on this.
FOREGROUND_INPUT_RESOURCE = "desktop-foreground-input-v1"


_user32 = ctypes.WinDLL("user32", use_last_error=True)
_user32.GetAsyncKeyState.argtypes = [ctypes.c_int]
_user32.GetAsyncKeyState.restype = ctypes.c_short


def foreground_input_quiescent() -> bool:
    """One extra refusal check before a shared input lane is recovered."""
    if not win32gui.GetForegroundWindow():
        return False
    return not any(_user32.GetAsyncKeyState(vk) < 0 for vk in range(1, 255))


_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_kernel32.GetProcessTimes.argtypes = (
    wintypes.HANDLE, ctypes.POINTER(wintypes.FILETIME),
    ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME),
    ctypes.POINTER(wintypes.FILETIME))
_kernel32.GetProcessTimes.restype = wintypes.BOOL


def process_creation_filetime(pid: int, *, expected_iso: str | None = None) -> int:
    """Read the raw Windows creation FILETIME, with optional pywin32 identity check."""
    if type(pid) is not int or pid <= 0:
        raise ValueError("invalid_process_id")
    process = win32api.OpenProcess(win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    try:
        if expected_iso is not None:
            if (type(expected_iso) is not str or
                    win32process.GetProcessTimes(process)["CreationTime"].isoformat() != expected_iso):
                raise ValueError("process_instance_changed")
        created = wintypes.FILETIME()
        exited = wintypes.FILETIME()
        kernel = wintypes.FILETIME()
        user = wintypes.FILETIME()
        if not _kernel32.GetProcessTimes(int(process), ctypes.byref(created),
                                         ctypes.byref(exited), ctypes.byref(kernel),
                                         ctypes.byref(user)):
            raise ctypes.WinError(ctypes.get_last_error())
        return (created.dwHighDateTime << 32) | created.dwLowDateTime
    finally:
        process.Close()


def physical_window_resource(pid: int, creation_filetime: int, hwnd: int) -> str:
    """One physical HWND has one lock key across App and Computer channels."""
    if any(type(value) is not int or value <= 0 for value in
           (pid, creation_filetime, hwnd)):
        raise ValueError("invalid_physical_window_identity")
    return f"physical-window-v1:{pid}:{creation_filetime}:{hwnd}"


_guard = threading.Lock()
_held: set[tuple[int, str]] = set()


def process_identity(pid: int | None = None) -> str:
    """PID plus creation time, preventing PID reuse from reviving an owner."""
    pid = pid or win32api.GetCurrentProcessId()
    process = win32api.OpenProcess(win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    try:
        created = win32process.GetProcessTimes(process)["CreationTime"]
        return f"{pid}:{created.isoformat()}"
    finally:
        process.Close()


def process_is_alive(identity: str) -> bool:
    """Access denial is inconclusive and must never authorize recovery."""
    try:
        pid = int(identity.partition(":")[0])
        process = win32api.OpenProcess(win32con.PROCESS_QUERY_LIMITED_INFORMATION |
                                      win32con.SYNCHRONIZE, False, pid)
        try:
            if win32event.WaitForSingleObject(process, 0) == win32event.WAIT_OBJECT_0:
                return False
            created = win32process.GetProcessTimes(process)["CreationTime"]
            return f"{pid}:{created.isoformat()}" == identity
        finally:
            process.Close()
    except win32api.error as error:
        if error.winerror in (87, 1168):
            return False
        return True


@lru_cache(maxsize=1)
def boot_identity() -> str:
    """A documented Windows boot identity for persisted monotonic timestamps."""
    import pythoncom
    import win32com.client

    pythoncom.CoInitialize()
    service = rows = None
    try:
        service = win32com.client.GetObject("winmgmts:")
        rows = service.ExecQuery("SELECT LastBootUpTime FROM Win32_OperatingSystem")
        values = [str(row.LastBootUpTime) for row in rows]
        if len(values) != 1:
            raise RuntimeError("Windows boot identity is unavailable")
        return values[0]
    finally:
        rows = service = None
        pythoncom.CoUninitialize()


class ExecutionLocks:
    """All-or-none nonblocking acquisition by the actual dispatch thread.

    The stable namespace is independent of plugin install path and version.
    The in-process set also rejects native mutex recursion by another coroutine
    on the same OS thread. A recovered abandoned lock is not permission to act.
    """

    def __init__(self, resources: tuple[str, ...]):
        if not resources or len(resources) > 32:
            raise ValueError("one to 32 resources are required")
        self.resources = tuple(sorted(set(resources)))
        self.handles: list[tuple[str, object]] = []
        self.thread_id: int | None = None

    def __enter__(self):
        self.thread_id = threading.get_ident()
        try:
            for resource in self.resources:
                key = (self.thread_id, resource)
                with _guard:
                    if key in _held:
                        raise ResourceBusy(resource)
                    name = "Local\\FlowerControl.Resource.v1." + hashlib.sha256(resource.encode()).hexdigest()
                    handle = win32event.CreateMutex(None, False, name)
                    status = win32event.WaitForSingleObject(handle, 0)
                    if status not in (win32event.WAIT_OBJECT_0, win32event.WAIT_ABANDONED):
                        handle.Close()
                        raise ResourceBusy(resource)
                    _held.add(key)
                    self.handles.append((resource, handle))
                if status == win32event.WAIT_ABANDONED:
                    raise AbandonedResource(resource)
            return self
        except BaseException:
            self.release()
            raise

    def release(self):
        if self.handles and self.thread_id != threading.get_ident():
            raise RuntimeError("execution locks must be released by their owning thread")
        while self.handles:
            resource, handle = self.handles[-1]
            win32event.ReleaseMutex(handle)
            handle.Close()
            self.handles.pop()
            with _guard:
                _held.discard((self.thread_id, resource))

    def __exit__(self, *_):
        self.release()
