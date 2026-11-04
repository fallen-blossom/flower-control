"""Refresh recorded process instances only; no launch, title read or selection."""
import time
import pywintypes

import win32api
import win32con
import win32gui
import win32process

from flower_control.drivers.app_process_chain import handle_times


class _LimitReached(Exception):
    pass


def refresh_launch(diagnostic: dict, *, allowed=lambda: True) -> dict:
    result = {"dispatched": False, "historical": False,
              "recorded_instances_only": True, "process_set_complete": False,
              "automatic_window_selection": False, "processes": [],
              "next_step": "list_windows_and_match_exact_process_identity_then_select"}
    if not allowed():
        return {**result, "state": "unavailable", "reason": "launch_refresh_stopped"}
    identities = [diagnostic, *diagnostic.get("related_processes", [])[:16]]
    identities = {(row["pid"], row["process_start_filetime"]) for row in identities
                  if type(row.get("pid")) is int and row["pid"] > 0
                  and type(row.get("process_start_filetime")) is int
                  and row["process_start_filetime"] > 0}
    if not identities:
        return {**result, "state": "unavailable", "reason": "launch_identity_unavailable"}
    handles = []
    try:
        for pid, created in sorted(identities):
            if not allowed():
                return {**result, "processes": [], "state": "unavailable", "reason": "launch_refresh_stopped"}
            row = {"pid": pid, "process_start_filetime": created, "state": "identity_unavailable"}
            result["processes"].append(row)
            try:
                handle = win32api.OpenProcess(0x1000 | win32con.SYNCHRONIZE, False, pid)
                handles.append(handle)
                actual, exited = handle_times(handle)
                if actual != created:
                    row["state"] = "process_reused"
                elif exited is not None:
                    row["state"] = "process_exited"
                else:
                    row.update(state="running", window_count=0)
                    row["_handle"] = handle
            except (OSError, pywintypes.error) as error:
                if getattr(error, "winerror", None) == 87:
                    row["state"] = "process_exited"
        live = {row["pid"]: row for row in result["processes"] if row["state"] == "running"}
        complete = True
        if live:
            visited = 0
            deadline = time.monotonic() + .5

            def collect(hwnd, _):
                nonlocal visited
                visited += 1
                if visited > 1024 or time.monotonic() > deadline or not allowed():
                    raise _LimitReached()
                if win32gui.IsWindowVisible(hwnd) and win32gui.GetAncestor(hwnd, 2) == hwnd:
                    pid = win32process.GetWindowThreadProcessId(hwnd)[1]
                    if pid in live:
                        live[pid]["window_count"] = min(64, live[pid]["window_count"] + 1)
                        if live[pid]["window_count"] >= 64:
                            raise _LimitReached()
                return True

            try:
                win32gui.EnumWindows(collect, None)
            except (_LimitReached, OSError, pywintypes.error):
                complete = False
        for row in live.values():
            try:
                actual, exited = handle_times(row.pop("_handle"))
                if actual != row["process_start_filetime"] or exited is not None:
                    row["state"] = "process_exited" if exited is not None else "process_reused"
                    row.pop("window_count", None)
                    complete = False
            except (OSError, pywintypes.error):
                row.pop("_handle", None)
                row.pop("window_count", None)
                row["state"] = "identity_unavailable"
                complete = False
        if not allowed():
            return {**result, "processes": [], "state": "unavailable", "reason": "launch_refresh_stopped"}
        result["window_enumeration_complete"] = complete
        result["state"] = ("window_candidates" if any(row.get("window_count", 0) for row in result["processes"])
                           else "window_pending" if any(row["state"] == "running" for row in result["processes"])
                           else "recorded_processes_unavailable")
        return result
    finally:
        for handle in handles:
            handle.Close()
