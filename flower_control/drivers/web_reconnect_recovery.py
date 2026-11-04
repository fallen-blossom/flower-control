"""Recover durably completed viewport scrolls after exact executor exit.

No old result is promoted, no command is replayed and no user pause is cleared.
The reconnect caller first obtains a fresh read through the new exact browser
connection; a stopped executor alone never proves a command completed. A
scroll completion proves no page business outcome or asynchronous network idle.
"""
import json

from flower_control.control.native import process_is_alive, process_is_verified_alive
from flower_control.control.state import ControlError


def require_fresh_reconnect_read(response):
    if (type(response) is not dict or type(response.get("receipt")) is not dict
            or response["receipt"].get("state") != "verified"
            or type(response.get("result")) is not list
            or any(type(page) is not str for page in response["result"])):
        raise ControlError("web_reconnect_fresh_read_required")


def recover_completed_calls(control, browser_identity, worker_identity):
    store, resource, task = control.store, control.resource, control.task
    epoch = store.write_gate.snapshot().epoch
    with store.read_transaction() as db:
        row = db.execute("SELECT quarantined FROM resources WHERE id=?", (resource,)).fetchone()
    if row is None or not row[0]:
        return {"recovered": False, "required": False}

    def validate(db):
        store._owner(db, control.owner)
        store._task(db, task)
        if store.task_write_stopped(task):
            raise ControlError("global_write_stopped")
        if store.write_gate.snapshot().epoch != epoch:
            raise ControlError("web_recovery_stop_epoch_changed")
        if not process_is_verified_alive(browser_identity) or not process_is_verified_alive(worker_identity):
            raise ControlError("web_reconnect_identity_unverified")
        store._require_scope(db, task, control.scope)
        if db.execute("SELECT paused FROM resources WHERE id=?", (resource,)).fetchone()[0]:
            raise ControlError("resource_paused_or_quarantined")
        unknown = [r for r in db.execute("SELECT * FROM actions WHERE state='outcome_uncertain'")
                   if resource in json.loads(r["resources"])]
        if not unknown:
            raise ControlError("web_reconnect_completion_evidence_missing")
        for action in unknown:
            # Never clear a foreground/native, other-chat or legacy debt
            # using an unrelated browser read. All original calls require
            # their own consumed permit and independent terminal fact.
            if action["task"] != task or json.loads(action["resources"]) != [resource]:
                raise ControlError("web_reconnect_completion_evidence_missing")
            proof = db.execute("SELECT p.*,c.worker_process AS completed_worker,c.command_hash AS completed_hash "
                "FROM worker_permits p JOIN worker_completions c ON c.action=p.action WHERE p.action=?",
                (action["id"],)).fetchone()
            context = db.execute("SELECT details FROM action_context WHERE action=?", (action["id"],)).fetchone()
            if (not proof or not proof["consumed"] or proof["command_hash"] != action["fingerprint"]
                    or proof["completed_hash"] != proof["command_hash"]
                    or proof["completed_worker"] != proof["worker_process"]
                    or proof["worker_process"] == worker_identity or process_is_alive(proof["worker_process"])
                    or not context or json.loads(context[0]).get("channel") != "web"
                    or json.loads(context[0]).get("operation") != "scroll"):
                raise ControlError("web_reconnect_completion_evidence_missing")
        baseline = db.execute("SELECT revision FROM web_worker_recovery_baselines WHERE resource=?", (resource,)).fetchone()
        incidents = db.execute("SELECT revision,action FROM web_worker_quarantine_incidents WHERE resource=? AND revision>?",
                               (resource, baseline[0] if baseline else -1)).fetchall()
        if (not incidents
                or any(r["action"] not in {a["id"] for a in unknown} for r in incidents)):
            raise ControlError("web_reconnect_quarantine_incident_unbound")

    def probe():
        with store.read_transaction() as db:
            validate(db)
        return {resource: "web-completed-reconnect:" + browser_identity + ":" + worker_identity}

    def commit(db):
        validate(db)
        current = db.execute("SELECT revision FROM resources WHERE id=?", (resource,)).fetchone()[0]
        db.execute("INSERT OR REPLACE INTO web_worker_recovery_baselines VALUES (?,?)", (resource, current + 1))

    result = store.recover_resources((resource,), probe, validate_commit=commit)
    return {**result, "required": True, "unknown_receipts_preserved": True}
