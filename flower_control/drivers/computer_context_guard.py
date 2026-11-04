"""Consume an own focus transition before read-only input preparation."""
from dataclasses import replace

from .computer_native import NativeInputError


class InputContextGuard:
    def __init__(self, baseline):
        self.baseline = baseline
        self.expected_focus = None
        self.deadline = 0.0
        self.traversal = False
        self.traversal_unconfirmed = False

    @property
    def has_pending(self):
        return self.expected_focus is not None or self.traversal or self.traversal_unconfirmed

    def mouse_dispatched(self, receiver, now):
        self.expected_focus = receiver
        self.traversal = self.traversal_unconfirmed = False
        self.deadline = now + .150

    def traversal_dispatched(self, now):
        self.expected_focus = None
        self.traversal_unconfirmed = False
        self.traversal = True
        self.deadline = now + .150

    def recheck(self, current, now):
        if now > self.deadline:
            self.expected_focus = None
            self.traversal_unconfirmed |= self.traversal
            self.traversal = False
        if not self.baseline.changed(current):
            return
        if (self.baseline.focus is not None and current.focus is not None
                and (current.focus == self.expected_focus or self.traversal)
                and not replace(self.baseline, focus=current.focus).changed(current)):
            self.baseline = replace(self.baseline, focus=current.focus)
            self.expected_focus = None
            self.traversal = False
            return
        raise NativeInputError('input_context_changed')

    def settle_pending(self, read, now, check, sleep):
        while True:
            check()
            self.recheck(read(), now())
            if self.traversal_unconfirmed:
                raise NativeInputError('input_focus_transition_unconfirmed')
            if not self.traversal and self.expected_focus == self.baseline.focus:
                self.expected_focus = None
            if self.expected_focus is None and not self.traversal:
                return
            remaining = max(0.0, min(.010, self.deadline - now()))
            if remaining <= 0:
                if self.traversal:
                    self.traversal_unconfirmed = True
                    self.traversal = False
                    raise NativeInputError('input_focus_transition_unconfirmed')
                self.expected_focus = None
                return
            sleep(remaining)
