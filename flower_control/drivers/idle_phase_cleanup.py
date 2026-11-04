"""Retry exact completed-call metadata cleanup, never input or call decrement."""
import sqlite3

from flower_control.control.state import ControlError


def idle_release_callback(runtime, task, owner, prefix):
    """Created by end_host_call's actual owner snapshot, never later maps."""
    def retry():
        _release_idle(runtime, task, owner, prefix)
    return retry


def remember_idle_release(cleanup, task, token, retry):
    cleanup.remember((token, "idle_phase"), task, "idle_phase_release", retry,
        ControlError("phase_release_pending"), threaded=True)


def _release_idle(runtime, task, owner, prefix, *, phase_release_check=None, presentation_terminal=None):
    """Borrow only the existing admission guard; preserve refs and all Stops."""
    guard = (runtime._finishing_tasks if hasattr(runtime, "_finishing_tasks")
             else runtime._phase_releasing)
    with runtime._host_gate:
        if task in guard:
            raise ControlError("phase_cleanup_in_progress")
        if any(current == task for current in runtime._host_tasks.values()):
            raise ControlError("phase_cleanup_calls_in_flight")
        guard.add(task)
    try:
        with runtime._gate:
            if any(key.startswith(prefix) for key in runtime._stops) or any(
                    key.startswith(prefix) for key in getattr(runtime, "_high_inflight", ())):
                raise ControlError("phase_cleanup_calls_in_flight")
        store = runtime.store
        with store.read_transaction(timeout=.02) as db:
            store._task(db, task)
            if db.execute("SELECT 1 FROM actions WHERE task=? AND substr(id,1,?)=? "
                    "AND state IN ('queued','running') LIMIT 1", (task, len(prefix), prefix)).fetchone():
                raise ControlError("phase_cleanup_calls_in_flight")
            store._require_input_release_confirmed(db, task=task, action_prefix=prefix)
        if store.task_write_stopped(task):
            raise ControlError("task_paused_or_stopped")
        if owner is not None:
            options = ({"phase_release_check": phase_release_check} if phase_release_check is not None else {})
            store.finish_owned_resources(owner, phase_release=True, preserve_observations=True, **options)
            # Known released input may leave an old unknown/quarantined claim.
            # Hiding/closing its display must not wait for that business debt,
            # and does not resolve the claim or permit another input.
            if presentation_terminal is not None and hasattr(runtime, "_release_phase_presentation"):
                runtime._release_phase_presentation(task, owner, terminal=presentation_terminal,
                    validate=phase_release_check)
            # A peer can retain the shared target while our own idle claim was
            # withdrawn. Uncertain effects/quarantine retain OUR claim too.
            with store.read_transaction(timeout=.02) as db:
                if db.execute("SELECT 1 FROM owned_resource_claims WHERE owner=? LIMIT 1", (owner,)).fetchone():
                    if presentation_terminal is not None and hasattr(runtime, "_release_phase_presentation"):
                        return {"presentation_released": True, "resources_retained": True}
                    # A retained claim is business isolation, not unfinished
                    # metadata cleanup. Require every residual claim to be
                    # explained by an old uncertain action or quarantine;
                    # unexplained/newly reacquired claims still fail closed.
                    unexplained = db.execute("SELECT 1 FROM owned_resource_claims c "
                        "JOIN resources r ON r.id=c.resource WHERE c.owner=? AND r.quarantined=0 "
                        "AND NOT EXISTS (SELECT 1 FROM actions a WHERE a.state='outcome_uncertain' "
                        "AND EXISTS (SELECT 1 FROM json_each(a.resources) WHERE value=c.resource)) LIMIT 1",
                        (owner,)).fetchone()
                    if unexplained:
                        raise ControlError("phase_cleanup_resources_unresolved")
                    return {"resources_retained": True}
    except sqlite3.Error:
        raise ControlError("control_ledger_unavailable") from None
    finally:
        with runtime._host_gate:
            guard.discard(task)
