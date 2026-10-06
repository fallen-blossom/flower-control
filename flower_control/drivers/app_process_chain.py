"""Bounded Toolhelp lineage, checked against exact process lifetime intervals.

No executable/title matching, adoption, process termination or retained cache.
https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32w
"""
import ctypes
import time
from ctypes import wintypes

import win32api
import win32con
import win32event


_kernel = ctypes.WinDLL("kernel32", use_last_error=True)


class ProcessEntry(ctypes.Structure):
    _fields_ = [("size", wintypes.DWORD), ("usage", wintypes.DWORD),
        ("pid", wintypes.DWORD), ("heap", ctypes.c_size_t), ("module", wintypes.DWORD),
        ("threads", wintypes.DWORD), ("parent", wintypes.DWORD),
        ("priority", wintypes.LONG), ("flags", wintypes.DWORD), ("name", wintypes.WCHAR * 260)]


_kernel.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
_kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
for _name in ("Process32FirstW", "Process32NextW"):
    getattr(_kernel, _name).argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry)]
    getattr(_kernel, _name).restype = wintypes.BOOL
_kernel.CloseHandle.argtypes = [wintypes.HANDLE]
_kernel.CloseHandle.restype = wintypes.BOOL
_kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
_kernel.GetProcessTimes.restype = wintypes.BOOL


def handle_times(handle):
    fields = [wintypes.FILETIME() for _ in range(4)]
    if not _kernel.GetProcessTimes(int(handle), *(ctypes.byref(f) for f in fields)):
        raise ctypes.WinError(ctypes.get_last_error())
    raw = lambda f: (f.dwHighDateTime << 32) | f.dwLowDateTime
    exited = win32event.WaitForSingleObject(handle, 0) == win32event.WAIT_OBJECT_0
    return raw(fields[0]), raw(fields[1]) if exited else None


def parent_snapshot():
    handle = _kernel.CreateToolhelp32Snapshot(2, 0)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        entry = ProcessEntry()
        entry.size = ctypes.sizeof(entry)
        result = {}
        more = _kernel.Process32FirstW(handle, ctypes.byref(entry))
        while more:
            if len(result) >= 8192:
                raise OSError("process_snapshot_limit")
            result[int(entry.pid)] = int(entry.parent)
            more = _kernel.Process32NextW(handle, ctypes.byref(entry))
        if ctypes.get_last_error() != 18:  # ERROR_NO_MORE_FILES
            raise ctypes.WinError(ctypes.get_last_error())
        return result
    finally:
        _kernel.CloseHandle(handle)


class LaunchChain:
    def __init__(self, process, created):
        # Popen retains this handle even after the launcher exits; reopening a
        # numeric PID would lose that identity or accidentally bind a reuse.
        self.root_pid = process.pid
        self.nodes = {process.pid: {"pid": process.pid, "created": created,
            "depth": 0, "handle": process._handle, "owned": False}}
        self.incomplete = False

    def sample(self):
        snapshot_ceiling = time.time_ns() // 100 + 116444736000000000
        parents = parent_snapshot()
        for node in self.nodes.values():
            created, exited = handle_times(node["handle"])
            if created != node["created"]:
                raise OSError("launch_identity_changed")
            node["exited"] = exited
        # Resolve only descendants of the original instance. New nodes can
        # be parents in this same bounded snapshot, without name guessing.
        for _ in range(8):
            added = False
            for pid, parent_pid in parents.items():
                parent = self.nodes.get(parent_pid)
                if pid in self.nodes or parent is None:
                    continue
                if parent["depth"] >= 8:
                    self.incomplete = True
                    continue
                if len(self.nodes) >= 16:
                    self.incomplete = True
                    return
                handle = None
                try:
                    handle = win32api.OpenProcess(win32con.PROCESS_QUERY_LIMITED_INFORMATION |
                                                  win32con.SYNCHRONIZE, False, pid)
                    created, exited = handle_times(handle)
                    parent_created, parent_exit = handle_times(parent["handle"])
                    # A stale parent PID cannot authorize a child born after
                    # the exact parent's exit (including PID reuse).
                    if (parent_created != parent["created"] or created > snapshot_ceiling
                            or created < parent_created or (parent_exit is not None and created > parent_exit)):
                        continue
                    self.nodes[pid] = {"pid": pid, "created": created, "exited": exited,
                        "parent_pid": parent_pid, "depth": parent["depth"] + 1,
                        "handle": handle, "owned": True}
                    handle = None
                    added = True
                except (OSError, win32api.error):
                    self.incomplete = True
                finally:
                    if handle is not None:
                        handle.Close()
            if not added:
                break

    def identities(self):
        return [{"pid": node["pid"], "process_start_filetime": node["created"],
                 "parent_pid": node.get("parent_pid"), "depth": node["depth"],
                 "process_running": node.get("exited") is None}
                for node in self.nodes.values()]

    def close(self):
        for node in self.nodes.values():
            if node["owned"]:
                node["handle"].Close()
                node["owned"] = False
