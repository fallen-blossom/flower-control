"""Finite exact-target capture reuse with fresh authorization on every frame."""
from __future__ import annotations

import threading
import time

from .computer_capture import CaptureError
from .computer_native import window_geometry
from .computer_capture_session import SESSION_IDLE_SECONDS


class ComputerCaptureCache:
    def __init__(self, factory, *, idle_seconds=SESSION_IDLE_SECONDS, timer_factory=threading.Timer):
        self.factory = factory
        self.sessions = {}
        self.gate = threading.RLock()
        self.idle_seconds = idle_seconds
        self._timer_factory = timer_factory
        self._idle_timers = {}

    def _close_session(self, key, session, *, abort=False):
        timer = self._idle_timers.pop(key, None)
        if timer is not None:
            timer.cancel()
        if abort:
            session.close(abort=True)
        else:
            session.close()
        if self.sessions.get(key) is session:
            self.sessions.pop(key)

    def _arm_idle_close(self, key, session):
        old = self._idle_timers.pop(key, None)
        if old is not None:
            old.cancel()

        def expire():
            with self.gate:
                # A cancelled callback may already be waiting for this lock.
                # It cannot close a later frame's timer or replacement session.
                if (self._idle_timers.get(key) is not timer or
                        self.sessions.get(key) is not session):
                    return
                try:
                    self._close_session(key, session)
                except Exception as error:
                    from .host_cleanup import cleanup_warning
                    cleanup_warning('computer', 'capture_idle_close', error)

        delay = max(0, min(self.idle_seconds, session.expires - time.monotonic()))
        timer = self._timer_factory(delay, expire)
        timer.daemon = True
        self._idle_timers[key] = timer
        timer.start()

    def capture(self, grant, *, preflight, stopped, fallback):
        began = time.monotonic()
        deadline = began + 5
        phase = "capture_lock"
        while not self.gate.acquire(timeout=.02):
            preflight()
            if stopped():
                raise CaptureError("capture_cancelled")
            if time.monotonic() >= deadline:
                raise CaptureError("capture_timeout", diagnostics={"stage": phase, "elapsed_ms": 5000})
        try:
            preflight()
            if stopped():
                raise CaptureError("capture_cancelled")
            geometry = window_geometry(grant.identity)
            key = (grant.task_id, grant.identity)
            phase = "session_cleanup"
            for old_key, session in tuple(self.sessions.items()):
                if (old_key != key or session.closed or time.monotonic() >= session.expires or
                        session.request_id >= 16 or session.worker.poll() is not None or session.geometry != geometry):
                    self._close_session(old_key, session)
            session = self.sessions.get(key)
            try:
                if session is None:
                    phase = "session_start"
                    session = self.factory(grant.identity, preflight=preflight, stopped=stopped)
                    self.sessions[key] = session
                phase = "frame_request"
                remaining = min(3, deadline - time.monotonic() - 1)
                if remaining <= .01:
                    raise CaptureError("capture_timeout")
                result = session.frame(preflight=preflight, stopped=stopped, budget=remaining).capture
                try:
                    self._arm_idle_close(key, session)
                except Exception as cleanup_error:
                    from .host_cleanup import cleanup_warning
                    cleanup_warning('computer', 'capture_idle_timer', cleanup_error)
                    try:
                        self._close_session(key, session)
                    except Exception as close_error:
                        # The frame is already valid; retain the exact session
                        # for normal cleanup instead of losing its sole handle.
                        cleanup_warning('computer', 'capture_idle_close', close_error)
                return result
            except BaseException as error:
                details = {}
                if session is not None:
                    try:
                        self._close_session(key, session, abort=True)
                    except Exception as cleanup_error:
                        from .host_cleanup import cleanup_warning
                        cleanup_warning("computer", "capture_abort", cleanup_error)
                        raise error
                    details = session.diagnostics()
                from .computer_capture_session import safe_diagnostic
                import json
                stages = [checked for row in details.get("stages", ())
                          if (checked := safe_diagnostic(json.dumps(row).encode())) is not None][-16:]
                diagnostic = {"stage": phase, "elapsed_ms": round((time.monotonic() - began) * 1000, 3),
                    "worker_exited": session is not None and session.worker.poll() is not None,
                    "stages": stages}
                if isinstance(error, CaptureError):
                    error.diagnostics = diagnostic
                codes = {item.get("code") for item in stages}
                remaining = min(1, deadline - time.monotonic())
                retryable = isinstance(error, CaptureError) and (
                    error.code == "capture_timeout" or error.code == "capture_session_eof" and
                    bool(codes & {"wgc_unsupported", "wgc_binary_missing", "fresh_frame_timeout"}))
                if retryable and diagnostic["worker_exited"] and remaining >= .1:
                    # Only another exact-window read, after the old worker has
                    # exited. Stop/identity/permission failures never retry.
                    preflight()
                    if stopped():
                        raise CaptureError("capture_cancelled", diagnostics=diagnostic)
                    try:
                        recovered = fallback(grant.identity, preflight=preflight, stopped=stopped,
                            backend="PrintWindow", timeout=remaining)
                    except CaptureError as fallback_error:
                        fallback_error.diagnostics = {**diagnostic, "fallback": "PrintWindow",
                            "fallback_reason": fallback_error.code}
                        raise
                    from dataclasses import replace
                    return replace(recovered, fallback_reason=error.code)
                raise
        finally:
            self.gate.release()

    def close(self, task=None):
        with self.gate:
            sessions = [(key, session) for key, session in self.sessions.items()
                        if task is None or key[0] == task]
            first_error = None
            for key, session in sessions:
                try:
                    self._close_session(key, session)
                except Exception as error:
                    if first_error is None:
                        first_error = error
            if first_error is not None:
                raise first_error
