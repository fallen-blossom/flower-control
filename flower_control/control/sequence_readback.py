"""Yield only a completed Computer sequence's final visual verification.

The original action/thread, target/profile exclusion and cancellation stay live.
This marker never authorizes another input step or changes a business outcome.
"""
import hashlib
import hmac
import threading
import time

from .native import FOREGROUND_INPUT_RESOURCE
from .state import ControlError


def foreground_released(db, action):
    marker = db.execute("SELECT owner FROM sequence_final_readbacks WHERE action=?", (action["id"],)).fetchone()
    if marker is None or marker[0] != action["owner"]:
        return False
    release = db.execute("SELECT confirmed FROM input_release_bindings WHERE action=?", (action["id"],)).fetchone()
    progress = db.execute("SELECT * FROM computer_sequence_progress WHERE action=?", (action["id"],)).fetchone()
    proof = db.execute("SELECT e.input_release,s.lease_released,s.channel,s.operation "
        "FROM action_effects e JOIN foreground_stages s ON s.action=e.action WHERE e.action=?", (action["id"],)).fetchone()
    return bool(release and release[0] is not None and progress and proof
        and proof[0] == "released" and proof[1] is not None and proof[2:] == ("computer", "sequence")
        and progress["sent_prefix"] == progress["total_steps"] and progress["partial_step"] is None
        and progress["input_release"] == "released")


def begin(store, owner, action_id, *, binding=None, verify=None):
    if store._dispatch_threads.get(action_id) != threading.get_ident():
        raise ControlError("sequence_readback_requires_dispatch_thread")

    def checked(db):
        store._owner(db, owner)
        action = db.execute("SELECT * FROM actions WHERE id=? AND owner=?", (action_id, owner)).fetchone()
        store._check_running_action(db, action)
        progress = db.execute("SELECT * FROM computer_sequence_progress WHERE action=?", (action_id,)).fetchone()
        stage = db.execute("SELECT * FROM foreground_stages WHERE action=?", (action_id,)).fetchone()
        released = db.execute("SELECT * FROM input_release_bindings WHERE action=?", (action_id,)).fetchone()
        effects = db.execute("SELECT input_release FROM action_effects WHERE action=?", (action_id,)).fetchone()
        if (not progress or progress["sent_prefix"] != progress["total_steps"]
                or progress["partial_step"] is not None or progress["final_state"] is not None
                or progress["input_release"] != "released" or not stage
                or stage["channel"] != "computer" or stage["operation"] != "sequence"
                or not released or not effects or effects[0] != "released"
                or db.execute("SELECT 1 FROM sequence_final_readbacks WHERE action=?", (action_id,)).fetchone()):
            raise ControlError("sequence_final_readback_not_ready")
        return action, released

    with store.transaction() as db:
        action, released = checked(db)
        external = store._external_dispatches.get(action_id)
        locks = store._dispatch_locks.get(action_id)
        if external is not None:
            result = external.result
            if (result is None or released["confirmed"] is None or not result["MutexReleased"]
                    or result["InputRelease"] != "released" or not result["NativeCountKnown"]
                    or result["SemanticExecutorExited"] is False
                    or result["State"] != "dispatched_unverified" or result["InputResult"] is None
                    or not result["InputResult"]["BusinessComplete"]
                    or released["executor_process"] != external.executor_process
                    or released["ledger_identity"] != external.ledger_identity):
                raise ControlError("input_release_unconfirmed")
        else:
            from .foreground_stage import ReleaseBinding
            if (not isinstance(binding, ReleaseBinding) or not callable(verify)
                    or binding.action_id != action_id or type(binding.token) is not str or not locks
                    or not any(resource == FOREGROUND_INPUT_RESOURCE for resource, _ in locks.handles)
                    or binding.executor_process != released["executor_process"]
                    or binding.ledger_identity != released["ledger_identity"]
                    or not hmac.compare_digest(hashlib.sha256(binding.token.encode()).hexdigest(), released["token_hash"])):
                raise ControlError("input_release_unconfirmed")
    if external is None:
        # Read the exact adapter-owned ledgers, never OS key samples or TTL.
        try:
            confirmed = verify(binding) is True
        except Exception:
            confirmed = False
        if not confirmed:
            raise ControlError("input_release_unconfirmed")
    with store.transaction() as db:
        action, _released = checked(db)
        # No authority recheck after the mutex release: a concurrent Stop/EOF
        # must still retain this exact cleanup fact. Other dispatchers cannot
        # see the yielded ledger projection until this short transaction commits.
        if external is None:
            locks.release_resource(FOREGROUND_INPUT_RESOURCE)
        now = store.clock()
        db.execute("UPDATE input_release_bindings SET confirmed=COALESCE(confirmed,?) WHERE action=?",
                   (time.time(), action_id))
        db.execute("INSERT INTO sequence_final_readbacks VALUES (?,?,?)", (action_id, owner, now))
        db.execute("UPDATE foreground_stages SET ended=COALESCE(ended,?),lease_released=? WHERE action=?",
                   (now, now, action_id))
        db.execute("UPDATE occupancy SET ended=COALESCE(ended,?) WHERE action=?", (now, action_id))
        store._record_event(db, "sequence_final_readback_started", task=action["task"], action=action_id,
                            details={"foreground_released": True, "sequence_running": True})
    return {"foreground_released": True, "sequence_running": True}
