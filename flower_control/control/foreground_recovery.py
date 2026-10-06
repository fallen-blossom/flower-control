"""Recover only the shared foreground scheduler after old execution is quiet.

The old target keeps its own quarantine and uncertain action receipt. This
helper never clears a user pause and never repeats input or activation.
"""

from __future__ import annotations

import secrets
import json
import hashlib
import hmac
import time
from typing import Callable

from .native import (FOREGROUND_INPUT_RESOURCE, foreground_input_quiescent,
                     ExecutionLocks, AbandonedResource, ResourceBusy)
from .state import ControlError, StateStore
from .foreground_stage import ReleaseBinding


def confirm_input_release(store: StateStore, binding: ReleaseBinding,
                          verify: Callable[[ReleaseBinding], bool]) -> dict:
    """Reconcile terminal release debt with an exact local supervisor fact.

    verify only observes its pre-bound ledger; it must not dispatch cleanup or
    infer release from process death/current OS key state. A successful result
    leaves business uncertainty, user pauses and target quarantine untouched.
    """
    if (not isinstance(binding, ReleaseBinding) or not callable(verify)
            or type(binding.token) is not str):
        raise ControlError("invalid_release_confirmation")

    def checked(db):
        row = db.execute("SELECT * FROM input_release_bindings WHERE action=?", (binding.action_id,)).fetchone()
        action = db.execute("SELECT * FROM actions WHERE id=?", (binding.action_id,)).fetchone()
        if (row is None or action is None or row["executor_process"] != binding.executor_process
                or row["ledger_identity"] != binding.ledger_identity
                or not hmac.compare_digest(row["token_hash"], hashlib.sha256(binding.token.encode()).hexdigest())):
            raise ControlError("input_release_binding_mismatch")
        if action["state"] in {"queued", "running"}:
            raise ControlError("release_action_still_active")
        for active in db.execute("SELECT resources FROM actions WHERE state='running'"):
            if FOREGROUND_INPUT_RESOURCE in json.loads(active[0]):
                raise ControlError("release_execution_not_quiescent")
        return row, action

    try:
        with ExecutionLocks((FOREGROUND_INPUT_RESOURCE,)):
            with store.transaction() as db:
                row, action = checked(db)
                if row["confirmed"] is not None:
                    return {"action_id": binding.action_id, "input_release": "released", "release_confirmed_at": row["confirmed"],
                            "release_confirmation_clock": "unix_wall_time", "business_state": action["state"], "target_quarantine_preserved": True}
            # No transaction is held while the native adapter reads its exact
            # immutable completion record. Final adoption rechecks the binding.
            try:
                confirmed = verify(binding) is True
            except Exception:
                raise ControlError("input_release_unconfirmed") from None
            if not confirmed:
                raise ControlError("input_release_unconfirmed")
            with store.transaction() as db:
                row, action = checked(db)
                now = store.clock()
                confirmed_at = time.time()
                db.execute("UPDATE input_release_bindings SET confirmed=? WHERE action=?", (confirmed_at, binding.action_id))
                db.execute("UPDATE action_effects SET input_release='released' WHERE action=?", (binding.action_id,))
                db.execute("UPDATE computer_sequence_progress SET input_release='released',updated=? WHERE action=?", (now, binding.action_id))
                store._record_event(db, "input_release_confirmed", task=action["task"], action=binding.action_id,
                                    details={"executor_process": binding.executor_process, "ledger_identity": binding.ledger_identity,
                                             "business_state": action["state"], "target_quarantine_preserved": True})
            return {"action_id": binding.action_id, "input_release": "released", "release_confirmed_at": confirmed_at,
                    "release_confirmation_clock": "unix_wall_time",
                    "business_state": action["state"], "target_quarantine_preserved": True}
    except (ResourceBusy, AbandonedResource):
        raise ControlError("release_execution_not_quiescent") from None


def recover_shared_foreground_for_new_target(
        store: StateStore, target_resource: str,
        assert_target: Callable[[], None]) -> None:
    with store.transaction() as db:
        front = db.execute("SELECT paused,quarantined FROM resources WHERE id=?",
                           (FOREGROUND_INPUT_RESOURCE,)).fetchone()
        target = db.execute("SELECT quarantined FROM resources WHERE id=?",
                            (target_resource,)).fetchone()
    if (not front or not front["quarantined"] or front["paused"] or
            not target or target["quarantined"]):
        return

    def probe() -> dict[str, str]:
        # A sample of current OS key state cannot prove that this executor's
        # input was released. Same-boot debt remains blocked on a new target.
        # Only StateStore's recorded native Windows boot transition can retire
        # an earlier OS input context; that keeps its old receipt unknown.
        with store.transaction() as db:
            store._require_input_release_confirmed(db)
        assert_target()
        if not foreground_input_quiescent():
            raise ControlError("foreground_input_not_quiescent")
        return {FOREGROUND_INPUT_RESOURCE:
                target_resource + ":recovered:" + secrets.token_hex(8)}

    # StateStore enforces no running action and holds the native execution
    # mutex throughout probe and revision update. Queued actions are cancelled.
    store.recover_resources((FOREGROUND_INPUT_RESOURCE,), probe)
