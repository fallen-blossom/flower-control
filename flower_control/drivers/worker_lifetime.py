"""Exact Windows worker process tree ownership, independent of the event loop."""
from __future__ import annotations

import sys
import threading

import win32api
import win32con
import win32event
import win32job

from flower_control.control.native import process_identity


class WorkerLifetime:
    def __init__(self, owner_identity: str, stop_event: str, *, diagnostic=None):
        self.diagnostic = diagnostic
        owner_pid = int(owner_identity.partition(":")[0])
        self.parent = win32api.OpenProcess(win32con.SYNCHRONIZE | win32con.PROCESS_QUERY_LIMITED_INFORMATION,
                                          False, owner_pid)
        if process_identity(owner_pid) != owner_identity:
            raise RuntimeError("worker_parent_identity_changed")
        self.stop = win32event.OpenEvent(win32con.SYNCHRONIZE, False, stop_event)
        self.job = win32job.CreateJobObject(None, "")
        limits = win32job.QueryInformationJobObject(self.job, win32job.JobObjectExtendedLimitInformation)
        limits["BasicLimitInformation"]["LimitFlags"] |= win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        win32job.SetInformationJobObject(self.job, win32job.JobObjectExtendedLimitInformation, limits)
        win32job.AssignProcessToJobObject(self.job, win32api.GetCurrentProcess())
        self.monitor = threading.Thread(target=self._watch, name="flower-worker-lifetime", daemon=True)
        self.monitor.start()

    def _watch(self):
        # A blocked UI/API loop cannot suppress parent death or explicit stop.
        result = win32event.WaitForMultipleObjects([self.parent, self.stop], False, win32event.INFINITE)
        try:
            if self.diagnostic is not None:
                phase = "owner_exit" if result == win32event.WAIT_OBJECT_0 else "explicit_worker_stop"
                emitter = threading.Thread(target=self._diagnose, args=(phase, 1),
                                           name="flower-worker-exit-diagnostic", daemon=True)
                emitter.start()
                # Give healthy stderr a short opportunity to retain the cause.
                # Logging locks or a full pipe cannot delay ownership stop forever.
                emitter.join(.05)
        finally:
            win32job.TerminateJobObject(self.job, 1)

    def _diagnose(self, phase, code):
        try:
            if self.diagnostic is not None:
                self.diagnostic(phase, code)
        except Exception:
            pass  # Diagnostics cannot suppress the exact Job stop.

    def exit(self, code: int):
        self._diagnose("worker_exit", code)
        sys.stdout.flush()
        sys.stderr.flush()
        # This job contains self and only its descendants, including Node.
        win32job.TerminateJobObject(self.job, code)
