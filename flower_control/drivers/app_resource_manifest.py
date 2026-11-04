"""Task-scoped launch purpose metadata; never process ownership or cleanup authority.

Only the trusted launch adapter records a result after its original action ends.
Reading or classifying an old action cannot retroactively register its process.
"""
from __future__ import annotations

import json

from flower_control.control.state import ControlError


PURPOSES = frozenset({"temporary", "result", "preserve"})
MAX_PAGE_ITEMS = 32
MAX_PAGE_BYTES = 16384
_STATES = frozenset({"window_candidates", "window_pending", "process_exited",
                     "outcome_uncertain", "rejected"})
_SCHEMA = """
CREATE TABLE IF NOT EXISTS app_resource_manifest(
 task TEXT NOT NULL REFERENCES tasks(id), action_key TEXT NOT NULL REFERENCES actions(id),
 launch_facts TEXT NOT NULL, initial_purpose TEXT NOT NULL, purpose TEXT NOT NULL,
 unresolved INTEGER NOT NULL, created REAL NOT NULL,
 PRIMARY KEY(task,action_key),
 CHECK(purpose IN ('temporary','result','preserve')),
 CHECK(initial_purpose IN ('temporary','result','preserve')));
"""


def _purpose(value):
    if type(value) is not str or value not in PURPOSES:
        raise ControlError("invalid_app_resource_purpose")
    return value


def _key(task, action):
    if (type(task) is not str or not 1 <= len(task) <= 256
            or type(action) is not str or not action.startswith(task + ":app:")
            or not 1 <= len(action[len(task) + 5:]) <= 128
            or any(ord(char) < 32 or ord(char) == 127 for char in action)):
        raise ControlError("invalid_app_resource_action")
    return action


def _identity_number(value):
    if value is None:
        return None
    if type(value) is not int or not 1 <= value <= 0x7FFFFFFFFFFFFFFF:
        raise ControlError("invalid_app_resource_identity")
    return value


def _facts(result, kind):
    if type(result) is not dict or type(kind) is not str or kind not in {"exe", "aumid"}:
        raise ControlError("invalid_app_resource_launch")
    state = result.get("state")
    dispatched = result.get("dispatched")
    if (type(state) is not str or state not in _STATES
            or dispatched is not None and type(dispatched) is not bool):
        raise ControlError("invalid_app_resource_launch")
    pid = _identity_number(result.get("pid"))
    created = _identity_number(result.get("process_start_filetime"))
    existing = type(result.get("existing_instance")) is dict
    facts = {"launch_kind": kind, "launch_state": state, "pid": pid,
             "process_start_filetime": created, "dispatched": dispatched,
             "existing_instance_reported": existing}
    unresolved = (state in {"window_pending", "outcome_uncertain"} or existing
                  or dispatched is None or dispatched is True and (pid is None or created is None))
    return facts, unresolved


def _item(row):
    return {**json.loads(row["launch_facts"]), "action_key": row["action_key"],
            "purpose": row["purpose"], "unresolved": bool(row["unresolved"]),
            "process_ownership_granted": False, "physical_cleanup_authority": False,
            "preserve_process": True}


class AppResourceManifest:
    def __init__(self, store):
        self.store = store
        with store.transaction() as db:
            db.execute(_SCHEMA)

    def record_launch(self, task, action_key, result, *, purpose="preserve", launch_kind="exe"):
        """Internal only: associate an actual original launch result, without adopting it."""
        action_key = _key(task, action_key)
        purpose = _purpose(purpose)
        facts, unresolved = _facts(result, launch_kind)
        encoded = json.dumps(facts, sort_keys=True, separators=(",", ":"))
        with self.store.transaction() as db:
            self.store._task(db, task)
            action = db.execute("SELECT state FROM actions WHERE id=? AND task=?",
                                (action_key, task)).fetchone()
            context = db.execute("SELECT details FROM action_context WHERE action=?",
                                 (action_key,)).fetchone()
            details = json.loads(context[0]) if context is not None else {}
            if (action is None or action["state"] in {"queued", "running"}
                    or details.get("channel") != "app" or details.get("operation") != "launch"):
                raise ControlError("app_resource_launch_unavailable")
            prior = db.execute("SELECT * FROM app_resource_manifest WHERE task=? AND action_key=?",
                               (task, action_key)).fetchone()
            if prior is not None:
                if prior["launch_facts"] != encoded or prior["initial_purpose"] != purpose:
                    raise ControlError("app_resource_launch_conflict")
                return {**_item(prior), "idempotent": True}
            db.execute("INSERT INTO app_resource_manifest VALUES (?,?,?,?,?,?,?)",
                       (task, action_key, encoded, purpose, purpose, int(unresolved), self.store.clock()))
            row = db.execute("SELECT * FROM app_resource_manifest WHERE task=? AND action_key=?",
                             (task, action_key)).fetchone()
            return {**_item(row), "idempotent": False}

    def action_resource(self, task, action_key):
        action_key = _key(task, action_key)
        with self.store.read_transaction() as db:
            self.store._task(db, task)
            row = db.execute("SELECT * FROM app_resource_manifest WHERE task=? AND action_key=?",
                             (task, action_key)).fetchone()
            if row is None:
                raise ControlError("app_resource_unavailable")
            return _item(row)

    def classify(self, task, action_key, purpose):
        action_key = _key(task, action_key)
        purpose = _purpose(purpose)
        with self.store.transaction() as db:
            self.store._task(db, task)
            changed = db.execute("UPDATE app_resource_manifest SET purpose=? WHERE task=? AND action_key=?",
                                 (purpose, task, action_key))
            if changed.rowcount != 1:
                raise ControlError("app_resource_unavailable")
            row = db.execute("SELECT * FROM app_resource_manifest WHERE task=? AND action_key=?",
                             (task, action_key)).fetchone()
            return _item(row)

    def require_temporary_close(self, task, action_key, target):
        """Validate provenance for an explicit normal-close request.

        This is not window permission. The normal App close still requires a
        fresh exact window grant and owns its once-only dispatch/recheck.
        Packaged/reused/pending/unknown launches cannot be adopted for cleanup.
        """
        action_key = _key(task, action_key)
        if (type(target) is not dict or any(type(target.get(key)) is not int or target[key] <= 0
                for key in ("pid", "hwnd", "process_start_filetime"))):
            raise ControlError("app_temporary_target_invalid")
        with self.store.read_transaction() as db:
            self.store._task(db, task)
            row = db.execute("SELECT * FROM app_resource_manifest WHERE task=? AND action_key=?",
                (task, action_key)).fetchone()
            action = db.execute("SELECT * FROM actions WHERE task=? AND id=?", (task, action_key)).fetchone()
            if row is None or action is None:
                raise ControlError("app_resource_unavailable")
            facts = json.loads(row["launch_facts"])
            if (row["purpose"] != "temporary" or row["unresolved"] or facts.get("launch_kind") != "exe"
                    or facts.get("dispatched") is not True or facts.get("existing_instance_reported") is not False
                    or action["state"] not in {"verified", "not_verified"} or not action["dispatched"]
                    or action["cancel_requested"] or facts.get("pid") != target["pid"]
                    or facts.get("process_start_filetime") != target["process_start_filetime"]):
                raise ControlError("app_temporary_close_not_owned")
            return {"original_launch": action_key, "purpose": "temporary", "normal_close_only": True,
                    "window_permission_required": True, "force_termination_available": False}

    def task_manifest(self, task, *, after=None, limit=MAX_PAGE_ITEMS):
        if type(limit) is not int or not 1 <= limit <= MAX_PAGE_ITEMS:
            raise ControlError("invalid_app_resource_page")
        if after is not None:
            _key(task, after)
        with self.store.read_transaction() as db:
            self.store._task(db, task)
            rows = db.execute("SELECT * FROM app_resource_manifest WHERE task=? AND action_key>? "
                              "ORDER BY action_key LIMIT ?", (task, after or "", limit + 1)).fetchall()
            counts = {row["purpose"]: row["count"] for row in db.execute(
                "SELECT purpose,count(*) AS count FROM app_resource_manifest WHERE task=? GROUP BY purpose",
                (task,))}
            unresolved = db.execute("SELECT count(*) FROM app_resource_manifest WHERE task=? AND unresolved=1",
                                    (task,)).fetchone()[0]
            items, size = [], 0
            for row in rows[:limit]:
                item = _item(row)
                encoded_size = len(json.dumps(item, ensure_ascii=False).encode("utf-8"))
                if size + encoded_size > MAX_PAGE_BYTES:
                    break
                items.append(item)
                size += encoded_size
            truncated = len(rows) > len(items)
            if truncated and not items:
                raise ControlError("app_resource_row_too_large")
            return {"items": items, "total": sum(counts.values()), "counts_by_purpose": counts,
                    "unresolved_count": unresolved, "truncated": truncated,
                    "next_after": items[-1]["action_key"] if truncated else None,
                    "row_bytes": size, "row_bytes_limit": MAX_PAGE_BYTES,
                    "consistent_snapshot": False, "unregistered_history_included": False,
                    "grants_authorization": False, "physical_cleanup_authority": False}

    def finish_manifest(self, task, *, after=None, limit=MAX_PAGE_ITEMS):
        """Describe preservation policy, not proof that an external process is alive."""
        return {**self.task_manifest(task, after=after, limit=limit),
                "all_processes_preserved": True, "physical_cleanup_performed": False,
                "process_liveness_verified": False, "old_actions_replayed": False}
