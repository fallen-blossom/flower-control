"""Best-effort return of an automatically borrowed ordinary foreground.

The original dispatcher must still hold its native foreground lock. This
helper never acquires authority, injects input, retries focus, or clears Stop.
"""
from __future__ import annotations

import win32con
import win32gui

from flower_control.control.native import FOREGROUND_INPUT_RESOURCE
from flower_control.control.state import ControlError
from .computer_native import WindowIdentity, assert_window, bind_window
from .input_activity import InputActivityWatch


def _root():
    hwnd = win32gui.GetForegroundWindow()
    return win32gui.GetAncestor(hwnd, win32con.GA_ROOT) if hwnd else 0


class FocusBorrow:
    def __init__(self, target):
        self.target = target
        self.original = None
        self.activity = None
        self.report = {"state": "skipped", "reason": "original_unavailable", "attempted": False}
        self.used = False

    def start(self):
        try:
            if not isinstance(self.target, WindowIdentity):
                return
            if _root() == self.target.hwnd:
                self.report["reason"] = "already_foreground"
                return
            # Start before binding/sampling so manual activity during automatic
            # activation also invalidates the later return. No key text is read.
            self.activity = InputActivityWatch()
            self.activity.start()
            hwnd = _root()
            if hwnd == self.target.hwnd:
                self.report["reason"] = "already_foreground"
                self.close()
                return
            from flower_control.permissions import require_window
            require_window(hwnd)
            self.original = bind_window(hwnd)
            assert_window(self.original)
            self.activity.check()
            if _root() != hwnd:
                raise RuntimeError("foreground_changed")
            self.report["reason"] = "not_returned"
        except Exception as error:
            self.original = None
            self.close()
            # Ordinary activity cancels this optional return. It does not
            # cancel the admitted task or its exact target activation.

    def check_activity(self):
        if self.activity is not None:
            try:
                self.activity.check()
            except ControlError as error:
                if error.code not in {"external_keyboard_activity", "external_mouse_activity"}:
                    raise
                self.original = None
                self.report["reason"] = "user_activity"
                self.close()

    def restore(self, stage, *, released, check):
        if self.used:
            return dict(self.report)
        self.used = True
        if self.original is None or self.activity is None:
            return dict(self.report)
        self.report["reason"] = "conditions_changed"
        try:
            if released is not True:
                return dict(self.report)
            # Stage.check verifies the original running owner/thread and native
            # lock. Never insert a return after another owner has acquired it.
            stage.check()
            locks = stage.store._dispatch_locks.get(stage.action_id)
            if not locks or not any(r == FOREGROUND_INPUT_RESOURCE for r, _ in locks.handles):
                return dict(self.report)
            check()
            self.activity.check()
            assert_window(self.target)
            assert_window(self.original)
            if (win32gui.IsIconic(self.original.hwnd) or not win32gui.IsWindowVisible(self.original.hwnd)
                    or _root() != self.target.hwnd):
                return dict(self.report)
            # Recheck cancellation, policy, exact identities and activity at
            # dispatch. SetForegroundWindow is the only request; no Alt retry.
            check()
            self.activity.check()
            assert_window(self.original)
            if _root() != self.target.hwnd:
                return dict(self.report)
            self.report.update(state="unverified", reason="focus_request_unverified", attempted=True)
            win32gui.SetForegroundWindow(self.original.hwnd)
            if _root() == self.original.hwnd:
                self.report.update(state="returned", reason="exact_original_foreground")
            else:
                self.report.update(state="unverified", reason="original_not_foreground")
        except Exception:
            # Optional focus recovery cannot erase the original business result
            # or turn a successful input into a replayable failure.
            if self.report["attempted"]:
                self.report.update(state="unverified", reason="focus_request_unverified")
        return dict(self.report)

    def close(self):
        if self.activity is not None:
            try:
                self.activity.close()
            except Exception:
                self.original = None
                self.report["reason"] = "activity_watch_unavailable"
            self.activity = None
