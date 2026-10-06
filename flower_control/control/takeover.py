"""One-way foreground phase barrier; it never activates or restores a window.

The Windows event adapter supplies observed HWND transitions. Keeping this
policy separate lets an away-and-back event still interrupt the old phase.
Ordinary switching needs a new observation, while explicit Stop and target
destruction retain the persistent pause and release-ordering contract.
"""
from __future__ import annotations

import threading
from typing import Callable

from .state import ControlError


class TakeoverBarrier:
    def __init__(self, target_hwnd: int, persist_pause: Callable[[], None],
                 return_hwnd: int | None = None):
        if type(target_hwnd) is not int or target_hwnd <= 0:
            raise ValueError("a bound target HWND is required")
        self.target_hwnd = target_hwnd
        self.return_hwnd = return_hwnd
        self.persist_pause = persist_pause
        self.stopped = threading.Event()
        self.pause_persisted = threading.Event()
        self._pause_required = threading.Event()
        self.reason: str | None = None
        self._guard = threading.Lock()

    def _stop(self, reason: str, *, persistent: bool = False):
        # Publish a persistent request before stopping so release cannot treat
        # an in-progress or failed Stop write as an ordinary interruption.
        if persistent:
            self._pause_required.set()
        self.stopped.set()
        with self._guard:
            priority = {None: 0, "foreground_left_target": 1, "target_minimized": 2,
                        "user_stop": 3, "target_destroyed": 4}
            if priority[reason] > priority[self.reason]:
                self.reason = reason
            if persistent and not self.pause_persisted.is_set():
                self.persist_pause()
                self.pause_persisted.set()

    def foreground_changed(self, hwnd: int):
        # Windows may report a momentary null foreground while an owned
        # dialog destroys itself and focus returns to its parent.
        if self.return_hwnd is not None and hwnd == 0:
            return
        if hwnd not in (self.target_hwnd, self.return_hwnd):
            self._stop("foreground_left_target")

    def minimized(self, hwnd: int):
        if hwnd == self.target_hwnd:
            self._stop("target_minimized")

    def stop_clicked(self):
        self._stop("user_stop", persistent=True)

    def target_destroyed(self, hwnd: int, current_foreground: int | None = None):
        if hwnd == self.target_hwnd:
            if (self.return_hwnd is not None and
                    current_foreground in (0, self.target_hwnd, self.return_hwnd)):
                return
            self._stop("target_destroyed", persistent=True)

    def check(self):
        if self.stopped.is_set():
            raise ControlError("user_takeover_paused" if self._pause_required.is_set()
                               else "foreground_phase_interrupted")

    def require_persisted_before_release(self):
        if self._pause_required.is_set() and not self.pause_persisted.is_set():
            raise ControlError("takeover_pause_not_persisted")
