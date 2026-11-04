"""Cooperative chat authorization; the host AI interprets the user's intent.

This records the decision, not proof of a human click or password verification.
No user prompt, page text, token, or private content is saved here.
"""

from __future__ import annotations

from collections.abc import Callable

from .luohua_policy import PROFILE_SCOPE
from flower_control.control.state import ControlError, StateStore, _id
from flower_control.control.write_gate import WriteGateError
from flower_control.browsers import personal_profile_scope


class ChatProfileAuthorization:
    def __init__(self, store: StateStore, *, browser: str = "brave"):
        self.store = store
        self.browser = browser
        self.scope = personal_profile_scope(browser=browser)

    def _decision(self, db, task):
        if self.browser == "brave":
            return db.execute("SELECT state FROM profile_authorizations WHERE task=?", (task,)).fetchone()
        return db.execute("SELECT state FROM browser_profile_authorizations WHERE task=? AND browser=?",
                          (task, self.browser)).fetchone()

    def _save_decision(self, db, task, state, now):
        if self.browser == "brave":
            db.execute("INSERT OR REPLACE INTO profile_authorizations VALUES (?,?,?)", (task, state, now))
        else:
            db.execute("INSERT OR REPLACE INTO browser_profile_authorizations VALUES (?,?,?,?)", (task, self.browser, state, now))

    def _status(self, db, task: str) -> dict:
        row = self.store._task(db, task)
        decision = self._decision(db, task)
        grant = db.execute("SELECT expires FROM grants WHERE task=? AND scope=?",
                           (task, self.scope)).fetchone()
        allowed = bool(grant and grant[0] > self.store.clock())
        if decision and decision[0] in ("denied", "revoked"):
            return {"state": decision[0], "authorized": False}
        if row["paused"]:
            return {"state": "paused", "authorized": False}
        return {"state": "allowed" if allowed else "not_requested", "authorized": allowed}

    def status(self, task: str) -> dict:
        with self.store.transaction() as db:
            return self._status(db, task)

    def decide(self, task: str, decision: str, *, stopped: Callable[[], bool] | None = None) -> dict:
        def check_stopped():
            if stopped is not None and stopped():
                raise ControlError("action_cancelled")

        if type(decision) is not str or decision not in {"allow", "pause", "resume", "deny", "revoke"}:
            raise ControlError("invalid_authorization_decision")
        check_stopped()
        # Freeze before waiting for SQLite: a newer Stop must defeat this request.
        try:
            resume_epoch = (self.store.write_gate.snapshot().epoch
                            if decision in ("allow", "resume") else None)
        except WriteGateError as error:
            raise ControlError(error.code) from error
        with self.store.transaction() as db:
            # Cancellation can arrive while SQLite waits for its writer lock.
            # All checks remain inside the transaction before it commits.
            check_stopped()
            row = self.store._task(db, task)
            if not row["host_binding"] or not row["host_binding"].startswith("origin:"):
                raise ControlError("trusted_chat_binding_required")
            previous = self._decision(db, task)
            now = self.store.clock()
            if decision == "allow":
                # A repeat allow must not clear an explicit Stop. A new grant
                # after deny/revoke is a new user decision, and resumes the chat.
                if row["paused"] and (not previous or previous[0] not in ("denied", "revoked")):
                    raise ControlError("user_paused")
                if previous and previous[0] == "allowed" and self._status(db, task)["authorized"]:
                    return self._status(db, task)
                event_id = "semantic:" + _id()
                check_stopped()
                db.execute("INSERT INTO grant_events VALUES (?,?,?,?)",
                           (event_id, task, self.scope, 1e300))
                db.execute("INSERT OR REPLACE INTO grants VALUES (?,?,?,?)",
                           (task, self.scope, event_id, 1e300))
                if previous and previous[0] in ("denied", "revoked"):
                    self.store._resume_from_user_event(db, task, expected_epoch=resume_epoch)
                else:
                    db.execute("UPDATE tasks SET paused=0,revision=revision+1 WHERE id=?", (task,))
                state = "allowed"
            elif decision == "resume":
                grant = db.execute("SELECT expires FROM grants WHERE task=? AND scope=?",
                                   (task, self.scope)).fetchone()
                # Continuing ordinary work is independent of private-profile
                # permission. Resume never inserts or restores a grant.
                check_stopped()
                self.store._resume_from_user_event(db, task, expected_epoch=resume_epoch)
                state = (previous[0] if previous and previous[0] in ("denied", "revoked")
                         else "allowed" if grant and grant[0] > now else "paused")
            else:
                state = {"pause": "paused", "deny": "denied", "revoke": "revoked"}[decision]
                check_stopped()
                if decision in ("deny", "revoke"):
                    db.execute("DELETE FROM grants WHERE task=? AND scope=?", (task, self.scope))
                db.execute("UPDATE tasks SET paused=1,revision=revision+1 WHERE id=?", (task,))
                self.store._stop_task_actions(db, task)
            check_stopped()
            self._save_decision(db, task, state, now)
            self.store._record_event(db, "profile_authorization", task=task,
                                     details={"decision": decision, "state": state})
            result = self._status(db, task)
            if decision in ("pause", "deny", "revoke"):
                in_flight = bool(db.execute("SELECT 1 FROM actions WHERE task=? AND state='running'",
                                            (task,)).fetchone())
                result.update(stop_received=True, in_flight=in_flight)
            if decision in ("allow", "resume"):
                result["new_observation_required"] = True
            if decision == "resume":
                result["execution_resumed"] = True
            check_stopped()
            return result
