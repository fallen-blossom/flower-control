"""Computer adapter for a real shared foreground stage and exact input ledgers.

This helper does not activate, send, replay or infer release from OS key state.
The dispatcher registers every ledger before its first down and seals the
aggregate only after its native dispatch context has exited.
"""
from __future__ import annotations

import hashlib
import threading
import uuid

from flower_control.control.foreground_stage import ForegroundStage, begin_foreground_stage
from flower_control.control.foreground_recovery import confirm_input_release
from flower_control.control.state import ControlError
from .computer_native import HeldInputLedger


class ComputerForegroundPhase:
    def __init__(self, store, owner, key, resource, operation, *, existing_stage=None):
        if existing_stage is None:
            self.stage = begin_foreground_stage(store, owner, key, target_resource=resource,
                channel="computer", operation=operation)
        else:
            if (not isinstance(existing_stage, ForegroundStage) or existing_stage.store is not store
                    or existing_stage.owner != owner or existing_stage.action_id != key):
                raise ControlError("input_executor_binding_mismatch")
            existing_stage.check()
            summary = existing_stage.snapshot()["foreground_stage"]
            if (summary["target_resource"] != resource or summary["operation"] != operation
                    or summary["channel"] not in {"app", "computer"}):
                raise ControlError("stage_context_mismatch")
            self.stage = existing_stage
        self.ledger_identity = hashlib.sha256(uuid.uuid4().bytes).hexdigest()
        self.binding = None
        self.ledgers = []
        self.sealed = False
        self.thread = threading.get_ident()

    def track(self, ledger):
        if (self.sealed or not isinstance(ledger, HeldInputLedger) or
                ledger.thread_id != self.thread or threading.get_ident() != self.thread):
            raise ControlError("input_executor_binding_mismatch")
        if self.binding is None:
            self.binding = self.stage.bind_input_release(self.ledger_identity)
        if not any(item is ledger for item in self.ledgers):
            self.ledgers.append(ledger)

    @property
    def release_state(self):
        if not self.ledgers:
            return "not_used"
        states = {item.release_state for item in self.ledgers}
        return "unknown" if "unknown" in states else "release_pending" if "release_pending" in states else "released"

    def seal(self):
        # Never convert process death, empty OS samples or a Stop click into
        # a completion fact. Only exact native ledger acknowledgements count.
        receipt = self.stage.snapshot()
        if receipt["state"] in {"queued", "running"} or receipt["foreground_stage"]["lease_state"] == "held":
            raise ControlError("release_action_still_active")
        self.sealed = True
        if self.binding is not None and self.release_state == "released":
            return confirm_input_release(self.stage.store, self.binding,
                lambda binding: binding == self.binding and self.sealed and self.release_state == "released")
        return None

    def interrupted(self, reason):
        return self.stage.interrupt(reason)
