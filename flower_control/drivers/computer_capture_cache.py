"""Finite exact-target capture reuse with fresh authorization on every frame."""
from __future__ import annotations

import threading
import time

from .computer_capture import CaptureError
from .computer_native import window_geometry


class ComputerCaptureCache:
    def __init__(self, factory):
        self.factory = factory
        self.sessions = {}
        self.gate = threading.RLock()

    def capture(self, grant, *, preflight, stopped, fallback):
        began = time.monotonic()
        with self.gate:
            preflight()
            if stopped():
                raise CaptureError("capture_cancelled")
            geometry = window_geometry(grant.identity)
            key = (grant.task_id, grant.identity)
            for old_key, session in tuple(self.sessions.items()):
                if (old_key != key or session.closed or time.monotonic() >= session.expires or
                        session.request_id >= 16 or session.worker.poll() is not None or session.geometry != geometry):
                    del self.sessions[old_key]
                    session.close()
            session = self.sessions.get(key)
            if session is None:
                session = self.factory(grant.identity, preflight=preflight, stopped=stopped)
                self.sessions[key] = session
            try:
                remaining = 3 - (time.monotonic() - began)
                if remaining <= 0:
                    raise CaptureError("capture_timeout")
                return session.frame(preflight=preflight, stopped=stopped, budget=remaining).capture
            except BaseException as error:
                self.sessions.pop(key, None)
                session.close(abort=True)
                # Preserve the existing explicit unavailable -> PrintWindow
                # route. Timeout/Stop/identity/errors never retry a backend.
                codes = {item.get("code") for item in session.diagnostics().get("stages", ())}
                remaining = 3 - (time.monotonic() - began)
                if (isinstance(error, CaptureError) and error.code == "capture_session_eof" and
                        codes & {"wgc_unsupported", "wgc_binary_missing"} and remaining >= .1):
                    return fallback(grant.identity, preflight=preflight, stopped=stopped,
                                    backend="PrintWindow", timeout=remaining)
                raise

    def close(self):
        with self.gate:
            sessions = tuple(self.sessions.values())
            self.sessions.clear()
            for session in sessions:
                session.close()
