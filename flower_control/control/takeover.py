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
                 return_hwnd: int | None = None, owned_followup: Callable[[int], bool] | None = None):
        if type(target_hwnd) is not int or target_hwnd <= 0:
            raise ValueError("a bound target HWND is required")
        self.target_hwnd = target_hwnd
        self.return_hwnd = return_hwnd
        self.owned_followup = owned_followup
        self.followup_hwnd = None
        self.persist_pause = persist_pause
        self.stopped = threading.Event()
        self.pause_persisted = threading.Event()
        self._pause_finished = threading.Event()
        self._pause_required = threading.Event()
        self.reason: str | None = None
        self._guard = threading.Lock()

    def _stop(self, reason: str, *, persistent: bool = False, followup_hwnd=None):
        # Publish a persistent request before stopping so release cannot treat
        # an in-progress or failed Stop write as an ordinary interruption.
        if persistent:
            self._pause_required.set()
        self.stopped.set()
        with self._guard:
            # A concurrent transient restart may have cleared the old event
            # while this Stop waited for the guard. Permanent intent wins.
            self.stopped.set()
            priority = {None: 0, "foreground_left_target": 1, "target_minimized": 2,
                        "new_window_detected": 3, "user_stop": 5, "target_destroyed": 4}
            if reason == "new_window_detected" and self.followup_hwnd is None:
                self.followup_hwnd = followup_hwnd
            if priority[reason] > priority[self.reason]:
                self.reason = reason
            if persistent and not self.pause_persisted.is_set():
                self._pause_finished.clear()
                try:
                    self.persist_pause()
                    self.pause_persisted.set()
                finally:
                    self._pause_finished.set()

    def foreground_changed(self, hwnd: int):
        # Windows may report a momentary null foreground while an owned
        # dialog destroys itself and focus returns to its parent.
        if self.return_hwnd is not None and hwnd == 0:
            return
        if hwnd not in (self.target_hwnd, self.return_hwnd):
            if self.owned_followup is not None and self.owned_followup(hwnd):
                self._stop("new_window_detected", followup_hwnd=hwnd)
            else:
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
        if self._pause_required.is_set() or self.stopped.is_set():
            raise ControlError("user_takeover_paused" if self._pause_required.is_set()
                               else "foreground_phase_interrupted")

    def restart_transient(self):
        """Adopt a new watched phase after the same executor rechecks its target.

        The old observer must be closed first. Only its ordinary focus/minimize
        signal is consumed; a concurrent explicit Stop or closed target wins.
        This method neither grants authority nor activates a window.
        """
        with self._guard:
            if self._pause_required.is_set() or self.reason not in {
                    None, "foreground_left_target", "target_minimized"}:
                self.check()
                raise ControlError("foreground_phase_interrupted")
            self.reason = None
            self.stopped.clear()
            if self._pause_required.is_set():
                self.stopped.set()
                self.check()

    @property
    def persistent_stop_requested(self):
        return self._pause_required.is_set()

    def require_persisted_before_release(self):
        if self._pause_required.is_set() and not self.pause_persisted.is_set():
            # Held input has already been released by the executor. Give the
            # in-progress explicit Stop metadata write a finite completion
            # fence; an already failed persistence still refuses immediately.
            self._pause_finished.wait(.5)
            if not self.pause_persisted.is_set():
                raise ControlError("takeover_pause_not_persisted")
