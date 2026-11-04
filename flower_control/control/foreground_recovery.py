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
                     ExecutionLocks, AbandonedResource, ResourceBusy,
                     process_identity, process_is_alive)
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
        for active in db.execute("SELECT * FROM actions WHERE state='running'"):
            if FOREGROUND_INPUT_RESOURCE in store._running_resources(db, active):
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
        # This raw bit protects older clients. Even an expired Web permit must
        # not be converted into a general clear by the new-target shortcut.
        web_permit = db.execute("SELECT 1 FROM web_quarantine_recovery_debts WHERE resource=?",
                                (FOREGROUND_INPUT_RESOURCE,)).fetchone()
    if web_permit:
        _refresh_closed_web_foreground(store, assert_target, target_resource=target_resource)
        return
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


def _closed_web_resource_evidence(store, db, resource, *, target_resource=None):
    """Recheck recorded closure and every subsequent resource revision."""
    debt = db.execute("SELECT pending FROM web_quarantine_recovery_debts WHERE resource=?", (resource,)).fetchone()
    pending = db.execute("SELECT * FROM web_created_targets WHERE id=?", (debt[0],)).fetchone() if debt else None
    original = db.execute("SELECT * FROM actions WHERE id=?", (pending["action"],)).fetchone() if pending else None
    receipt = db.execute("SELECT * FROM web_target_close_receipts WHERE pending=?", (debt[0],)).fetchone() if debt else None
    close = db.execute("SELECT * FROM actions WHERE id=?", (receipt["action"],)).fetchone() if receipt else None
    if (not pending or not original or not receipt or not close or pending["state"] != "closed"
            or not pending["target"] or original["state"] != "outcome_uncertain"
            or close["state"] != "verified" or original["task"] != pending["task"]
            or close["task"] != pending["task"] or resource not in json.loads(original["resources"])
            or (resource != FOREGROUND_INPUT_RESOURCE and resource != pending["resource"])
            or receipt["resource"] != pending["resource"] or receipt["target"] != pending["target"]
            or receipt["browser_process"] != pending["browser_process"]
            or not store._is_web_instance_close(db, close, pending["resource"])):
        raise ControlError("web_recovery_evidence_missing")
    context = db.execute("SELECT details FROM action_context WHERE action=?", (original["id"],)).fetchone()
    context = json.loads(context[0]) if context else {}
    effects = db.execute("SELECT * FROM action_effects WHERE action=?", (original["id"],)).fetchone()
    has_foreground = FOREGROUND_INPUT_RESOURCE in json.loads(original["resources"])
    if (context.get("channel") != "web" or context.get("operation") != "new_page"
            or not effects or effects["read_only"] or effects["activation_dispatched"] != 0
            or effects["input_release"] not in (("released",) if has_foreground else (None, "released"))):
        raise ControlError("web_recovery_evidence_missing")
    for action in (original, close):
        permit = db.execute("SELECT * FROM worker_permits WHERE action=?", (action["id"],)).fetchone()
        if (not permit or not permit["consumed"] or permit["command_hash"] != action["fingerprint"]
                or process_is_alive(permit["worker_process"])):
            raise ControlError("web_recovery_executor_unverified")
    event = db.execute("SELECT seq FROM web_recovery_dispatch_order WHERE action=?", (original["id"],)).fetchone()
    if event is None:
        event = db.execute("SELECT seq FROM control_events WHERE event='action_dispatched' AND action=?", (original["id"],)).fetchone()
    baseline = db.execute("SELECT revision FROM web_create_resource_baselines WHERE action=? AND resource=?",
                          (original["id"], resource)).fetchone()
    if not event or not baseline:
        raise ControlError("web_recovery_evidence_missing")
    durable = db.execute("SELECT * FROM web_recovery_count_baselines WHERE action=? AND resource=?",
                         (original["id"], resource)).fetchone()
    incidents = db.execute("SELECT * FROM web_quarantine_incidents WHERE resource=? AND revision>? "
                           "AND (action IS NULL OR action<>?) ORDER BY revision",
                           (resource, baseline[0], original["id"])).fetchall()
    resolved_actions = set()
    if incidents and (resource != FOREGROUND_INPUT_RESOURCE or not target_resource):
        raise ControlError("web_recovery_other_quarantine")
    for incident in incidents:
        action = db.execute("SELECT * FROM actions WHERE id=?", (incident["action"],)).fetchone() if incident["action"] else None
        stage = db.execute("SELECT * FROM foreground_stages WHERE action=?", (incident["action"],)).fetchone() if action else None
        binding = db.execute("SELECT * FROM input_release_bindings WHERE action=?", (incident["action"],)).fetchone() if action else None
        effects = db.execute("SELECT * FROM action_effects WHERE action=?", (incident["action"],)).fetchone() if action else None
        worker = db.execute("SELECT * FROM worker_permits WHERE action=?", (incident["action"],)).fetchone() if action else None
        old_target = db.execute("SELECT quarantined FROM resources WHERE id=?", (stage["target"],)).fetchone() if stage else None
        if (not action or action["state"] != "outcome_uncertain" or resource not in json.loads(action["resources"])
                or not stage or stage["boot"] != store.boot or stage["ended"] is None
                or stage["lease_released"] is None and process_is_alive(stage["dispatcher_process"])
                or stage["target"] == target_resource or target_resource in json.loads(action["resources"])
                or not old_target or not old_target["quarantined"] or not binding or binding["confirmed"] is None
                or not effects or effects["input_release"] != "released"
                or binding["executor_process"] not in {stage["dispatcher_process"], worker["worker_process"] if worker else None}
                or worker and (not worker["consumed"] or process_is_alive(worker["worker_process"]))):
            raise ControlError("web_recovery_other_quarantine")
        resolved_actions.add(action["id"])
    for quarantine in db.execute("SELECT action,details FROM control_events WHERE event='resource_quarantined' AND seq>=?", (event[0],)):
        if resource in json.loads(quarantine["details"])["resources"] and quarantine["action"] not in resolved_actions:
            raise ControlError("web_recovery_other_quarantine")
    for other in db.execute("SELECT * FROM actions WHERE state IN ('running','outcome_uncertain')"):
        if other["id"] == original["id"] or resource not in json.loads(other["resources"]):
            continue
        order = db.execute("SELECT seq FROM web_recovery_dispatch_order WHERE action=?", (other["id"],)).fetchone()
        later = (order[0] >= event[0]) if order else db.execute("SELECT 1 FROM control_events WHERE action=? AND event IN ('action_dispatched','action_finished') AND seq>=? LIMIT 1",
                           (other["id"], event[0])).fetchone()
        if durable and not order and not later:
            raise ControlError("web_recovery_other_quarantine")
        if other["state"] == "running" or later and other["id"] not in resolved_actions:
            raise ControlError("web_recovery_other_quarantine")
    dispatches = sum(resource in json.loads(row[0]) for row in db.execute(
        "SELECT a.resources FROM control_events e JOIN actions a ON a.id=e.action "
        "WHERE e.event='action_dispatched' AND e.seq>=?", (event[0],)))
    reissue_event = "web_foreground_refreshed" if resource == FOREGROUND_INPUT_RESOURCE else "web_borrower_refreshed"
    reissues = db.execute("SELECT COUNT(*) FROM control_events WHERE action=? AND seq>=? "
                          "AND event IN ('web_creation_recovered',?)",
                          (original["id"], event[0], reissue_event)).fetchone()[0]
    if durable:
        totals = db.execute("SELECT * FROM web_recovery_resource_counts WHERE resource=?", (resource,)).fetchone()
        issued = db.execute("SELECT count FROM web_recovery_reissues WHERE action=? AND resource=?",
                            (original["id"], resource)).fetchone()
        if (not totals or totals["quarantines"] - durable["quarantines"] != 1 + len(incidents)
                or totals["reissues"] - durable["reissues"] != (issued[0] if issued else 0)):
            raise ControlError("web_recovery_other_quarantine")
        dispatches = totals["dispatches"] - durable["dispatches"]
        reissues = issued[0] if issued else 0
    current = db.execute("SELECT * FROM resources WHERE id=?", (resource,)).fetchone()
    if (not current or current["paused"] or not current["quarantined"]
            or current["revision"] != baseline[0] + dispatches + 1 + reissues + len(incidents)):
        raise ControlError("web_recovery_state_changed")
    if resource == FOREGROUND_INPUT_RESOURCE:
        store._require_input_release_confirmed(db)
    return debt[0], original["id"], current["revision"]


def _refresh_closed_web_foreground(store, assert_target, *, target_resource=None):
    """Reissue only foreground use after explicit resume or keeper exit."""
    resource = FOREGROUND_INPUT_RESOURCE
    try:
        with ExecutionLocks((resource,)):
            with store.transaction() as db:
                if store._quarantine_permit_active(db, resource):
                    return
                gate = store.write_gate.snapshot()
                if gate.stopped:
                    raise ControlError("global_write_stopped")
                evidence = _closed_web_resource_evidence(store, db, resource, target_resource=target_resource)
            assert_target()
            if not foreground_input_quiescent():
                raise ControlError("foreground_input_not_quiescent")
            with store.transaction() as db:
                current = store.write_gate.snapshot()
                if current.stopped or current.epoch != gate.epoch or _closed_web_resource_evidence(store, db, resource, target_resource=target_resource) != evidence:
                    raise ControlError("web_recovery_state_changed")
                for queued in db.execute("SELECT id,resources FROM actions WHERE state='queued'").fetchall():
                    if resource in json.loads(queued["resources"]):
                        db.execute("UPDATE actions SET state='cancelled',updated=? WHERE id=?", (store.clock(), queued["id"]))
                db.execute("UPDATE resources SET revision=revision+1 WHERE id=?", (resource,))
                db.execute("INSERT OR REPLACE INTO web_quarantine_recovery_permits(resource,pending,epoch,boot,keeper) VALUES (?,?,?,?,?)",
                           (resource, evidence[0], current.epoch, store.boot, process_identity()))
                store._record_event(db, "web_foreground_refreshed", action=evidence[1],
                                    details={"original_state_preserved": True, "new_observation_required": True})
    except (ResourceBusy, AbandonedResource):
        raise ControlError("recovery_execution_not_quiescent") from None
