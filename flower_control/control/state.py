"""SQLite control ledger. It stores identifiers and receipts, never page content.

Authority mutation methods are INTERNAL adapter entrypoints, not MCP tools.
No host confirmation adapter is implicitly trusted by this module.
"""

from __future__ import annotations

import hashlib
import asyncio
import json
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager, nullcontext
from pathlib import Path
from typing import Callable, Iterator

from .native import (AbandonedResource, ExecutionLocks, FOREGROUND_INPUT_RESOURCE,
                     ResourceBusy, boot_identity, process_identity, process_is_alive)
from .scheduling import Candidate, Phase, Policy, choose_local, build_jev_request
from .diagnostics import safe_metadata
from .targets import target_description
from .write_gate import WriteGateError, session_write_gate


class ControlError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _id() -> str:
    return secrets.token_urlsafe(24)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS task_write_epochs(task TEXT PRIMARY KEY, epoch INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS action_write_epochs(action TEXT PRIMARY KEY, epoch INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS observation_write_epochs(observation TEXT PRIMARY KEY, epoch INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS tasks(
 id TEXT PRIMARY KEY, host_binding TEXT, revision INTEGER NOT NULL DEFAULT 0,
 paused INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0,
 focus INTEGER NOT NULL DEFAULT 0, focus_sequence INTEGER NOT NULL DEFAULT -1,
 created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS grants(
 task TEXT NOT NULL REFERENCES tasks(id), scope TEXT NOT NULL, event_id TEXT NOT NULL,
 expires REAL NOT NULL, PRIMARY KEY(task,scope));
CREATE TABLE IF NOT EXISTS grant_events(
 id TEXT PRIMARY KEY, task TEXT NOT NULL, scope TEXT NOT NULL, expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS profile_authorizations(
 task TEXT PRIMARY KEY REFERENCES tasks(id),
 state TEXT NOT NULL CHECK(state IN ('allowed','paused','denied','revoked')),
 updated REAL NOT NULL);
CREATE TABLE IF NOT EXISTS owners(
 id TEXT PRIMARY KEY, task TEXT NOT NULL REFERENCES tasks(id), process TEXT NOT NULL,
 live_until REAL NOT NULL, retired INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS resources(
 id TEXT PRIMARY KEY, revision INTEGER NOT NULL DEFAULT 0,
 quarantined INTEGER NOT NULL DEFAULT 0, paused INTEGER NOT NULL DEFAULT 0,
 required_scope TEXT, generation TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS observations(
 id TEXT PRIMARY KEY, task TEXT NOT NULL, resource TEXT NOT NULL,
 revision INTEGER NOT NULL, generation TEXT NOT NULL, expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS actions(
 id TEXT PRIMARY KEY, owner TEXT NOT NULL REFERENCES owners(id), task TEXT NOT NULL,
 fingerprint TEXT NOT NULL, resources TEXT NOT NULL, scope TEXT,
 observation TEXT, generation TEXT, state TEXT NOT NULL, cancel_requested INTEGER NOT NULL DEFAULT 0,
 created REAL NOT NULL, updated REAL NOT NULL, dispatched INTEGER NOT NULL DEFAULT 0,
 result_code TEXT);
CREATE TABLE IF NOT EXISTS decisions(
 id TEXT PRIMARY KEY, resources TEXT NOT NULL, fingerprint TEXT NOT NULL,
 candidates TEXT NOT NULL, expires REAL NOT NULL, state TEXT NOT NULL,
 chosen TEXT, reason TEXT);
CREATE INDEX IF NOT EXISTS action_state ON actions(state);
CREATE TABLE IF NOT EXISTS action_effects(
 action TEXT PRIMARY KEY REFERENCES actions(id), read_only INTEGER NOT NULL DEFAULT 0,
 activation_dispatched INTEGER, business_dispatched INTEGER, input_release TEXT);
CREATE TABLE IF NOT EXISTS action_hints(
 action TEXT PRIMARY KEY, phase TEXT NOT NULL, estimated_ms INTEGER);
CREATE TABLE IF NOT EXISTS occupancy(
 action TEXT PRIMARY KEY, task TEXT NOT NULL, resources TEXT NOT NULL,
 started REAL NOT NULL, ended REAL);
CREATE TABLE IF NOT EXISTS worker_permits(
 action TEXT PRIMARY KEY REFERENCES actions(id), token_hash TEXT NOT NULL,
 worker_process TEXT NOT NULL, command_hash TEXT NOT NULL, consumed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS owned_resources(
 resource TEXT PRIMARY KEY REFERENCES resources(id), task TEXT NOT NULL REFERENCES tasks(id));
CREATE TABLE IF NOT EXISTS decision_requests(
 decision TEXT PRIMARY KEY REFERENCES decisions(id), process TEXT NOT NULL,
 token TEXT NOT NULL, expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS control_events(
 seq INTEGER PRIMARY KEY AUTOINCREMENT, wall_time REAL NOT NULL,
 monotonic REAL NOT NULL, event TEXT NOT NULL, task TEXT, action TEXT,
 details TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS control_events_task ON control_events(task,seq);
CREATE TABLE IF NOT EXISTS window_handoffs(
 id TEXT PRIMARY KEY, task TEXT NOT NULL, target TEXT NOT NULL,
 expires REAL NOT NULL, consumed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS action_waiters(
 action TEXT PRIMARY KEY REFERENCES actions(id), expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS waiter_calls(
 action TEXT NOT NULL REFERENCES actions(id), token TEXT NOT NULL,
 expires REAL NOT NULL, process TEXT NOT NULL, decision TEXT,
 PRIMARY KEY(action,token));
CREATE TABLE IF NOT EXISTS action_context(
 action TEXT PRIMARY KEY REFERENCES actions(id), details TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS foreground_stages(
 action TEXT PRIMARY KEY REFERENCES actions(id), target TEXT NOT NULL,
 channel TEXT NOT NULL, operation TEXT NOT NULL, dispatcher_process TEXT NOT NULL,
 boot TEXT NOT NULL, started REAL NOT NULL, deadline REAL,
 ended REAL, lease_released REAL, interruption TEXT, interrupted REAL,
 stop_received REAL);
CREATE TABLE IF NOT EXISTS input_release_bindings(
 action TEXT PRIMARY KEY REFERENCES actions(id), executor_process TEXT NOT NULL,
 ledger_identity TEXT NOT NULL, token_hash TEXT NOT NULL, confirmed REAL);
"""

_CARD_SCHEMA = """
CREATE TABLE IF NOT EXISTS card_requests(
 id TEXT PRIMARY KEY,
 task TEXT NOT NULL UNIQUE REFERENCES tasks(id),
 host_binding TEXT NOT NULL,
 scopes TEXT NOT NULL,
 scopes_hash TEXT NOT NULL,
 description_hash TEXT NOT NULL,
 nonce_hash TEXT NOT NULL,
 created REAL NOT NULL,
 expires REAL NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('pending','allowed','denied','expired')),
 decided REAL
);
"""

_COMPUTER_SEQUENCE_SCHEMA = """
CREATE TABLE computer_sequence_progress(
 action TEXT PRIMARY KEY REFERENCES actions(id),
 total_steps INTEGER NOT NULL CHECK(total_steps BETWEEN 2 AND 3),
 sent_prefix INTEGER NOT NULL DEFAULT 0 CHECK(sent_prefix BETWEEN 0 AND 3),
 partial_step INTEGER CHECK(partial_step BETWEEN 0 AND 2),
 input_release TEXT NOT NULL CHECK(input_release IN ('released','unknown','release_pending')),
 final_state TEXT CHECK(final_state IN ('sequence_completed','sequence_stopped','outcome_uncertain')),
 updated REAL NOT NULL);
"""


class _ExternalSequence:
    def __init__(self, store, owner, action_id, decision_id, total_steps):
        if type(total_steps) is not int or not 2 <= total_steps <= 3:
            raise ControlError("invalid_sequence_progress")
        self.store, self.owner, self.action_id, self.decision_id = store, owner, action_id, decision_id
        self.total_steps, self.index, self.previous, self.dispatch = total_steps, 0, None, None
        self.thread = threading.get_ident()
        self.active = self.in_step = False

    def __enter__(self):
        if self.active or self.dispatch is not None:
            raise ControlError("external_sequence_reused")
        self.active = True
        return self

    def __exit__(self, *error):
        self.active = False
        if self.dispatch is not None:
            return self.dispatch.__exit__(*error)

    @contextmanager
    def before_go(self, lease):
        if (not self.active or self.in_step or self.thread != threading.get_ident()
                or self.index >= self.total_steps or lease.binding is None
                or lease.binding.sequence_step != self.index):
            raise ControlError("invalid_sequence_progress")
        self.in_step = True
        try:
            if self.previous is None:
                with self.store.transaction() as db:
                    action = db.execute("SELECT observation,generation FROM actions WHERE id=? AND owner=?",
                                        (self.action_id, self.owner)).fetchone()
                    if (not action or action["observation"] != lease.binding.observation_id
                            or action["generation"] != lease.binding.generation):
                        raise ControlError("external_continuation_fresh_observation_required")
                self.dispatch = self.store.dispatch_external(self.owner, self.action_id, self.decision_id, lease)
                self.dispatch.__enter__()
            else:
                self.store._continue_external(self.owner, self.action_id, self.previous, lease, self.index)
            yield
            # The facade has accepted actual done before exiting this callback.
            if lease.result is None:
                raise ControlError("external_continuation_release_required")
            self.previous = lease
            self.index += 1
        finally:
            self.in_step = False


class StateStore:
    schema_version = "2"
    # All store instances in this process share the physical dispatch view.
    _native_dispatches: dict[tuple[int, str], ExecutionLocks] = {}
    _external_native_dispatches: dict[tuple[int, str], object] = {}

    def __init__(self, directory: Path, *, clock: Callable[[], float] = time.monotonic,
                 boot: str | None = None, policy: Policy | None = None,
                 jev_enabled: Callable[[], bool] | None = None, write_gate=None):
        self.directory = Path(directory)
        if self.directory.exists() and (self.directory.is_symlink() or self.directory.is_junction()):
            raise ControlError("data_root_is_link")
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / "control.sqlite3"
        if self.path.exists() and (self.path.is_symlink() or not self.path.is_file()):
            raise ControlError("database_is_not_regular_file")
        self.clock = clock
        self.boot = boot or boot_identity()
        self._native_boot = boot is None
        # Initial conservative bounds, to be calibrated by runtime benchmarks.
        self.policy = policy or Policy(15000, 5000, 1500)
        self.jev_enabled = jev_enabled
        self.write_gate = write_gate if write_gate is not None else session_write_gate()
        self._dispatch_threads: dict[str, int] = {}
        # These are the actual acquired native locks, not scheduler leases.
        self._dispatch_locks: dict[str, ExecutionLocks] = {}
        # Authenticated helper ownership is separate from this thread's handles.
        self._external_dispatches: dict[str, object] = {}
        self._last_stop_recorded = -1
        self._stop_record_lock = threading.Lock()
        db = self._connect()
        try:
            db.executescript(_SCHEMA)
        finally:
            db.close()
        with self.transaction() as db:
            version = db.execute("SELECT value FROM meta WHERE key='schema'").fetchone()
            if version and version[0] not in ("1", self.schema_version):
                raise ControlError("incompatible_schema")
            if version and version[0] == "1" and db.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='card_requests'").fetchone():
                raise ControlError("incompatible_schema")
            # v1 -> v2 DDL and version update share this BEGIN IMMEDIATE
            # transaction. A failed upgrade leaves the old ledger intact.
            for statement in _CARD_SCHEMA.split(";"):
                if statement.strip():
                    db.execute(statement)
            columns = db.execute("PRAGMA table_info(card_requests)").fetchall()
            if [(col["name"], col["type"], col["notnull"], col["pk"]) for col in columns] != [
                    ("id", "TEXT", 0, 1), ("task", "TEXT", 1, 0),
                    ("host_binding", "TEXT", 1, 0), ("scopes", "TEXT", 1, 0),
                    ("scopes_hash", "TEXT", 1, 0), ("description_hash", "TEXT", 1, 0),
                    ("nonce_hash", "TEXT", 1, 0), ("created", "REAL", 1, 0),
                    ("expires", "REAL", 1, 0), ("state", "TEXT", 1, 0),
                    ("decided", "REAL", 0, 0)]:
                raise ControlError("incompatible_schema")
            indexes = db.execute("PRAGMA index_list(card_requests)").fetchall()
            if not any(index["unique"] and [column["name"] for column in
                       db.execute("SELECT name FROM pragma_index_info(?)",
                                  (index["name"],)).fetchall()] == ["task"]
                       for index in indexes):
                raise ControlError("incompatible_schema")
            sequence_table = db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='computer_sequence_progress'").fetchone()
            if not sequence_table:
                db.execute(_COMPUTER_SEQUENCE_SCHEMA)
            sequence_columns = db.execute(
                "PRAGMA table_info(computer_sequence_progress)").fetchall()
            if [(col["name"], col["type"], col["notnull"], col["pk"])
                for col in sequence_columns] != [
                    ("action", "TEXT", 0, 1), ("total_steps", "INTEGER", 1, 0),
                    ("sent_prefix", "INTEGER", 1, 0), ("partial_step", "INTEGER", 0, 0),
                    ("input_release", "TEXT", 1, 0), ("final_state", "TEXT", 0, 0),
                    ("updated", "REAL", 1, 0)]:
                raise ControlError("incompatible_schema")
            foreign_keys = db.execute(
                "PRAGMA foreign_key_list(computer_sequence_progress)").fetchall()
            if [(key["table"], key["from"], key["to"]) for key in foreign_keys] != [
                    ("actions", "action", "id")]:
                raise ControlError("incompatible_schema")
            from .input_boot import SCHEMA as input_context_schema
            if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
                              "AND name='input_context_resets'").fetchone():
                db.execute(input_context_schema)
            context_columns = db.execute("PRAGMA table_info(input_context_resets)").fetchall()
            if [(col["name"], col["type"], col["notnull"], col["pk"])
                    for col in context_columns] != [
                    ("action", "TEXT", 0, 1), ("action_boot", "TEXT", 1, 0),
                    ("reset_boot", "TEXT", 1, 0), ("observed", "REAL", 1, 0),
                    ("reason", "TEXT", 1, 0)]:
                raise ControlError("incompatible_schema")
            context_keys = db.execute("PRAGMA foreign_key_list(input_context_resets)").fetchall()
            if [(key["table"], key["from"], key["to"]) for key in context_keys] != [
                    ("actions", "action", "id")]:
                raise ControlError("incompatible_schema")
            policy_value = _json((self.policy.starvation_ms, self.policy.occupancy_budget_ms,
                                  self.policy.continuation_budget_ms))
            prior_policy = db.execute("SELECT value FROM meta WHERE key='policy'").fetchone()
            if prior_policy and prior_policy[0] != policy_value:
                raise ControlError("incompatible_scheduling_policy")
            db.execute("INSERT OR IGNORE INTO meta VALUES ('policy',?)", (policy_value,))
            old_boot = db.execute("SELECT value FROM meta WHERE key='boot'").fetchone()
            if old_boot and old_boot[0] != self.boot:
                db.execute("UPDATE tasks SET revoked=1,revision=revision+1")
                db.execute("DELETE FROM grants")
                for row in db.execute("SELECT * FROM actions WHERE state='running'").fetchall():
                    self._interrupt_action(db, row, "boot_changed")
                db.execute("UPDATE actions SET state='cancelled' WHERE state='queued'")
                db.execute("UPDATE owners SET retired=1")
                db.execute("UPDATE decisions SET state='expired'")
                db.execute("DELETE FROM occupancy")
                from .input_boot import retire_previous_input_contexts
                retired = retire_previous_input_contexts(db, old_boot[0], self.boot,
                    native_boot=boot_identity() if self._native_boot else None, observed=time.time())
                for row in retired:
                    self._record_event(db, "input_context_retired_after_windows_boot", task=row["task"],
                        action=row["id"], details={"previous_boot": row["boot"], "current_boot": self.boot,
                        "original_release_preserved": True, "new_target_required": True})
            db.execute("INSERT OR REPLACE INTO meta VALUES ('schema',?)", (self.schema_version,))
            db.execute("INSERT OR REPLACE INTO meta VALUES ('boot',?)", (self.boot,))

    def _connect(self, *, timeout=5):
        db = sqlite3.connect(self.path, timeout=timeout, isolation_level=None)
        try:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA journal_mode=DELETE")
            db.execute("PRAGMA synchronous=FULL")
        except BaseException:
            db.close()
            raise
        return db

    @contextmanager
    def transaction(self, *, timeout=5) -> Iterator[sqlite3.Connection]:
        try:
            db = self._connect(timeout=timeout)
        except sqlite3.OperationalError as error:
            if timeout < 5 and error.sqlite_errorcode in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED):
                raise ControlError("control_ledger_busy") from error
            raise
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except sqlite3.OperationalError as error:
            db.rollback()
            if timeout < 5 and error.sqlite_errorcode in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED):
                raise ControlError("control_ledger_busy") from error
            raise
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    @contextmanager
    def read_transaction(self, *, timeout=.25) -> Iterator[sqlite3.Connection]:
        """One committed permission snapshot without reserving the writer lock.

        No journal/settings writes or schema setup belong in a live recheck.
        Each call opens a fresh snapshot; an unreadable ledger still rejects.
        Permit consumption and all authority mutations use transaction instead.
        """
        db = None
        try:
            db = sqlite3.connect(self.path.resolve().as_uri() + "?mode=ro", uri=True,
                                 timeout=timeout, isolation_level=None)
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            yield db
        except sqlite3.OperationalError as error:
            if error.sqlite_errorcode in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED):
                raise ControlError("control_ledger_busy") from error
            raise
        finally:
            if db is not None:
                try:
                    db.rollback()
                finally:
                    db.close()

    def _record_event(self, db, event: str, *, task: str | None = None,
                      action: str | None = None, details: dict | None = None):
        metadata = safe_metadata(details or {})
        payload = _json(metadata)
        if len(payload.encode("utf-8")) > 4096:
            metadata.pop("candidates", None)
            metadata["candidates_omitted"] = "metadata_limit"
            payload = _json(metadata)
            if len(payload.encode("utf-8")) > 4096:
                payload = _json({"details_omitted": "metadata_limit"})
        if task is None and action is not None:
            bound = db.execute("SELECT task FROM actions WHERE id=?", (action,)).fetchone()
            task = bound[0] if bound else None
        cursor = db.execute("INSERT INTO control_events(wall_time,monotonic,event,task,action,details) "
                            "VALUES (?,?,?,?,?,?)",
                            (time.time(), self.clock(), event, task, action, payload))
        # This table contains only generated diagnostics. Keep 20,000 records;
        # no extra timer/service and no unknown file cleanup are involved.
        if cursor.lastrowid % 128 == 0:
            db.execute("DELETE FROM control_events WHERE seq<=?", (cursor.lastrowid - 20000,))

    def record_event(self, event: str, *, task: str | None = None,
                     action: str | None = None, details: dict | None = None):
        with self.transaction() as db:
            self._record_event(db, event, task=task, action=action, details=details)

    def decision_outcome(self, decision_id: str):
        with self.transaction() as db:
            row = db.execute("SELECT * FROM decisions WHERE id=?", (decision_id,)).fetchone()
            if not row or row["expires"] <= self.clock():
                return None
            if row["state"] not in {"pending", "adopted"}:
                return {"id": row["id"], "chosen": None, "reason": "queue_changed"}
            if row["state"] == "adopted":
                _, _, fingerprint = self._snapshot(db, tuple(json.loads(row["resources"])))
                if fingerprint == row["fingerprint"]:
                    return dict(row)
            return None

    def claim_decision_request(self, decision_id: str) -> str | None:
        with self.transaction() as db:
            row = db.execute("SELECT * FROM decisions WHERE id=?", (decision_id,)).fetchone()
            if not row or row["state"] != "pending" or row["expires"] <= self.clock():
                return None
            claim = db.execute("SELECT * FROM decision_requests WHERE decision=?", (decision_id,)).fetchone()
            if claim and claim["expires"] > self.clock() and process_is_alive(claim["process"]):
                return None
            token = _id()
            db.execute("INSERT OR REPLACE INTO decision_requests VALUES (?,?,?,?)",
                       (decision_id, process_identity(), token, row["expires"]))
            return token

    def release_decision_request(self, decision_id: str, token: str):
        with self.transaction() as db:
            db.execute("DELETE FROM decision_requests WHERE decision=? AND token=?", (decision_id, token))

    def retain_execution_call(self, owner: str, action_id: str, *, lifetime: float):
        if type(lifetime) not in (int, float) or not 0 < lifetime <= 10:
            raise ValueError("invalid_execution_call_lifetime")
        with self.transaction() as db:
            self._owner(db, owner)
            action = db.execute("SELECT owner,state FROM actions WHERE id=?", (action_id,)).fetchone()
            if not action or action["owner"] != owner or action["state"] != "queued":
                raise ControlError("action_not_queued")
            token = _id()
            db.execute("INSERT INTO waiter_calls VALUES (?,?,?,?,NULL)",
                       (action_id, token, self.clock() + lifetime, process_identity()))
            return token

    def release_execution_call(self, action_id: str, token: str, *, decision_id: str | None = None):
        with self.transaction() as db:
            # A completed wait can pass its adopted decision to immediate
            # dispatch, but cannot leave a general ten-second live waiter.
            decision = db.execute("SELECT expires FROM decisions WHERE id=? AND chosen=? "
                                  "AND state='adopted' AND expires>?",
                                  (decision_id, action_id, self.clock())).fetchone()
            db.execute("UPDATE waiter_calls SET expires=0,decision=? WHERE action=? AND token=?",
                       (decision_id if decision else None, action_id, token))

    def create_task(self, host_binding: str | None = None) -> str:
        task = _id()
        with self.transaction() as db:
            db.execute("INSERT INTO tasks(id,host_binding,created) VALUES (?,?,?)",
                       (task, host_binding, self.clock()))
            self._initialize_task_write_epoch(db, task)
        return task

    def _initialize_task_write_epoch(self, db, task: str):
        """A new task starts in the current gate; reconnects never call this."""
        status = self.write_gate.snapshot()
        db.execute("INSERT INTO task_write_epochs VALUES (?,?)",
                   (task, status.resume_all_epoch if status.stopped else status.epoch))

    def global_stop_status(self):
        from dataclasses import asdict
        return asdict(self.write_gate.snapshot())

    def task_write_stopped(self, task, *, observation=None):
        if self.write_stopped():
            return True
        try:
            with self.read_transaction() as db:
                row = self._task(db, task)
                status = self.write_gate.snapshot()
                ack = db.execute("SELECT epoch FROM task_write_epochs WHERE task=?", (task,)).fetchone()
                if row["paused"] or max(ack[0] if ack else 0, status.resume_all_epoch) < status.epoch:
                    return True
                if observation:
                    epoch = db.execute("SELECT epoch FROM observation_write_epochs WHERE observation=?", (observation,)).fetchone()
                    return (epoch[0] if epoch else 0) != status.epoch
                return False
        except (ControlError, WriteGateError):
            return True

    def write_stopped(self):
        try:
            status = self.write_gate.snapshot()
            if status.stopped:
                self._schedule_stop_record(status.epoch)
            return status.stopped
        except WriteGateError:
            return True

    def request_global_stop(self):
        status = self.write_gate.stop()  # No SQLite, driver or model can delay this.
        self._schedule_stop_record(status.epoch)
        return self.global_stop_status()

    def _schedule_stop_record(self, epoch):
        with self._stop_record_lock:
            if self._last_stop_recorded >= epoch:
                return
            self._last_stop_recorded = epoch
        threading.Thread(target=self._record_global_stop, args=(epoch,),
                         name="flower-stop-ledger", daemon=True).start()

    def _record_global_stop(self, epoch):
        try:
            with self.transaction() as db:
                rows = db.execute("SELECT a.* FROM actions a LEFT JOIN action_effects e ON e.action=a.id "
                    "LEFT JOIN action_write_epochs w ON w.action=a.id "
                    "WHERE a.state IN ('queued','running') AND COALESCE(e.read_only,0)=0 "
                    "AND COALESCE(w.epoch,0)<?", (epoch,)).fetchall()
                for row in rows:
                    db.execute("UPDATE actions SET cancel_requested=1,state=CASE WHEN state='queued' "
                               "THEN 'cancelled' ELSE state END,updated=? WHERE id=?", (self.clock(), row["id"]))
                    self._mark_stage_stop(db, row["id"])
                db.execute("UPDATE observations SET expires=0 WHERE id IN (SELECT o.id FROM observations o "
                    "LEFT JOIN observation_write_epochs e ON e.observation=o.id WHERE COALESCE(e.epoch,0)<?)", (epoch,))
                self._record_event(db, "global_stop_recorded", details={"reason": "explicit_stop"})
        except (sqlite3.Error, ControlError):
            # The gate remains stopped even if the best-effort journal is busy.
            pass

    def resume_global_from_user_event(self):
        epoch = self.write_gate.snapshot().epoch
        return self.write_gate.resume(all_tasks=True, expected_epoch=epoch)

    def _check_write_epoch(self, db, action):
        effects = db.execute("SELECT read_only FROM action_effects WHERE action=?", (action["id"],)).fetchone()
        if effects and effects[0]:
            return None
        status = self.write_gate.snapshot()
        task_epoch = db.execute("SELECT epoch FROM task_write_epochs WHERE task=?", (action["task"],)).fetchone()
        action_epoch = db.execute("SELECT epoch FROM action_write_epochs WHERE action=?", (action["id"],)).fetchone()
        epoch = action_epoch[0] if action_epoch else 0
        if (status.stopped or epoch != status.epoch or
                max(task_epoch[0] if task_epoch else 0, status.resume_all_epoch) < status.epoch):
            raise ControlError("global_write_stopped")
        return epoch

    @contextmanager
    def write_admission(self, owner, action_id):
        """Order the start of one short write against Stop; never lock its work."""
        if self.write_stopped():
            raise ControlError("global_write_stopped")
        with self.transaction() as db:
            self._owner(db, owner)
            row = db.execute("SELECT * FROM actions WHERE id=? AND owner=?", (action_id, owner)).fetchone()
            self._check_running_action(db, row)
            epoch = self._check_write_epoch(db, row)
        try:
            if epoch is not None:
                self.write_gate.admit(epoch)
        except WriteGateError as error:
            raise ControlError(error.code) from error
        yield

    @contextmanager
    def worker_write_admission(self, action_id, token, command_hash):
        """Same admission for the real permitted worker, without impersonating its owner."""
        if self.write_stopped():
            raise ControlError("global_write_stopped")
        self.check_worker_permit(action_id, token, command_hash)
        with self.transaction() as db:
            action = db.execute("SELECT * FROM actions WHERE id=?", (action_id,)).fetchone()
            epoch = self._check_write_epoch(db, action)
        try:
            if epoch is not None:
                self.write_gate.admit(epoch)
        except WriteGateError as error:
            raise ControlError(error.code) from error
        yield

    def create_window_handoff(self, task: str, target: dict) -> str:
        with self.transaction() as db:
            row = self._task(db, task)
            if row["paused"]:
                raise ControlError("user_paused")
            token = "app-handoff:" + _id()
            db.execute("INSERT INTO window_handoffs VALUES (?,?,?,?,0)",
                       (token, task, _json(target), self.clock() + 30))
            return token

    def consume_window_handoff(self, task: str, token: str) -> dict:
        with self.transaction() as db:
            row = db.execute("SELECT * FROM window_handoffs WHERE id=? AND task=?",
                             (token, task)).fetchone()
            if not row or row["consumed"] or row["expires"] <= self.clock():
                raise ControlError("handoff_unavailable")
            if self._task(db, task)["paused"]:
                raise ControlError("user_paused")
            db.execute("UPDATE window_handoffs SET consumed=1 WHERE id=?", (token,))
            return json.loads(row["target"])

    def register_owner(self, task: str, *, lifetime: float = 120) -> str:
        if not 0 < lifetime <= 600:
            raise ControlError("invalid_owner_lifetime")
        owner = _id()
        with self.transaction() as db:
            self._task(db, task)
            db.execute("INSERT INTO owners(id,task,process,live_until) VALUES (?,?,?,?)",
                       (owner, task, process_identity(), self.clock() + lifetime))
        return owner

    def heartbeat(self, owner: str):
        with self.transaction() as db:
            self._owner(db, owner)
            db.execute("UPDATE owners SET live_until=? WHERE id=?", (self.clock() + 120, owner))

    def renew_or_replace_owner(self, task: str, owner: str) -> str:
        """Keep a live owner, or replace its expired/retired instance for this task."""
        with self.transaction() as db:
            row = db.execute("SELECT * FROM owners WHERE id=?", (owner,)).fetchone()
            if not row or row["task"] != task:
                raise ControlError("owner_expired_or_missing")
            if row["process"] != process_identity():
                raise ControlError("owner_process_mismatch")
            self._task(db, task)
            now = self.clock()
            if not row["retired"] and row["live_until"] > now:
                db.execute("UPDATE owners SET live_until=? WHERE id=?", (now + 120, owner))
                return owner
            if not row["retired"]:
                self._retire_owner(db, owner)
            replacement = _id()
            db.execute("INSERT INTO owners(id,task,process,live_until) VALUES (?,?,?,?)",
                       (replacement, task, process_identity(), now + 120))
            return replacement

    def _task(self, db, task):
        row = db.execute("SELECT * FROM tasks WHERE id=?", (task,)).fetchone()
        if not row or row["revoked"]:
            raise ControlError("task_revoked_or_missing")
        return row

    def _owner(self, db, owner, *, diagnostics=False):
        row = db.execute("SELECT * FROM owners WHERE id=?", (owner,)).fetchone()
        if not row or (not diagnostics and (row["retired"] or row["live_until"] <= self.clock())):
            raise ControlError("owner_expired_or_missing")
        if row["process"] != process_identity():
            raise ControlError("owner_process_mismatch")
        if not diagnostics:
            self._task(db, row["task"])
        return row

    def register_resource(self, resource: str, *, required_scope: str | None = None):
        """Driver-owned target mapping; the model cannot downgrade its policy."""
        with self.transaction() as db:
            row = db.execute("SELECT required_scope FROM resources WHERE id=?", (resource,)).fetchone()
            if row and row[0] != required_scope:
                raise ControlError("resource_policy_conflict")
            db.execute("INSERT OR IGNORE INTO resources(id,required_scope) VALUES (?,?)",
                       (resource, required_scope))

    def _require_scope(self, db, task, scope):
        if scope:
            grant = db.execute("SELECT expires FROM grants WHERE task=? AND scope=?", (task, scope)).fetchone()
            if not grant or grant[0] <= self.clock():
                raise ControlError("task_authorization_required")

    def bind_owned_resource(self, owner: str, resource: str):
        """Bind a newly owned temporary target; never infer sharing from its ID."""
        with self.transaction() as db:
            connection = self._owner(db, owner)
            existing = db.execute("SELECT task FROM owned_resources WHERE resource=?", (resource,)).fetchone()
            if existing and existing[0] != connection["task"]:
                raise ControlError("target_belongs_to_another_task")
            db.execute("INSERT OR IGNORE INTO owned_resources VALUES (?,?)", (resource, connection["task"]))

    def same_chat_after_reboot(self, task: str, previous: object) -> bool:
        """Identify a prior boot's chat task without reviving its authority."""
        if not isinstance(previous, str) or not previous or previous == task:
            return False
        with self.transaction() as db:
            current = self._task(db, task)
            old = db.execute("SELECT host_binding,revoked FROM tasks WHERE id=?", (previous,)).fetchone()
            if (not old or not old["revoked"] or not current["host_binding"]
                    or not current["host_binding"].startswith("origin:")
                    or old["host_binding"] != current["host_binding"]):
                return False
            if not db.execute("SELECT 1 FROM sqlite_master WHERE name='origin_task_boots'").fetchone():
                return False
            epochs = dict(db.execute("SELECT task,boot FROM origin_task_boots WHERE task IN (?,?)",
                                     (task, previous)).fetchall())
            return (epochs.get(task) == self.boot and previous in epochs
                    and epochs[previous] != self.boot)

    def _require_owned_resource(self, db, task, resource):
        existing = db.execute("SELECT task FROM owned_resources WHERE resource=?", (resource,)).fetchone()
        if existing and existing[0] != task:
            raise ControlError("target_belongs_to_another_task")

    def record_confirmed_grant(self, task: str, scope: str, event_id: str, *, lifetime: float):
        """Internal trusted-adapter entry; never expose as model-supplied approval."""
        if not event_id or not scope or not 0 < lifetime <= 86400:
            raise ControlError("invalid_grant")
        with self.transaction() as db:
            self._task(db, task)
            previous = db.execute("SELECT * FROM grant_events WHERE id=?", (event_id,)).fetchone()
            if previous:
                if previous["task"] != task or previous["scope"] != scope:
                    raise ControlError("grant_event_scope_conflict")
                return False
            expiry = self.clock() + lifetime
            db.execute("INSERT INTO grant_events VALUES (?,?,?,?)", (event_id, task, scope, expiry))
            db.execute("INSERT OR REPLACE INTO grants VALUES (?,?,?,?)",
                       (task, scope, event_id, expiry))
            db.execute("UPDATE tasks SET revision=revision+1 WHERE id=?", (task,))
            return True

    def begin_card_request(self, task: str, scopes: tuple[str, ...],
                           description_hash: str, nonce_hash: str, *, lifetime: float = 300) -> str:
        """Internal card controller only: freeze one request for a bound chat.

        Scope values are supplied by a trusted target-policy resolver, never by
        model arguments. The caller must first consume a trusted Hook ticket.
        """
        if (not isinstance(scopes, tuple) or not scopes or len(scopes) > 32
                or any(type(scope) is not str or not scope or len(scope) > 256
                       or any(ord(character) < 32 for character in scope)
                       or scope.startswith("jev:") for scope in scopes)
                or len(set(scopes)) != len(scopes) or tuple(sorted(scopes)) != scopes
                or not isinstance(description_hash, str) or len(description_hash) != 64
                or not isinstance(nonce_hash, str) or len(nonce_hash) != 64
                or not isinstance(lifetime, (int, float)) or not 0 < lifetime <= 300):
            raise ControlError("invalid_card_request")
        request_id = _id()
        now = self.clock()
        with self.transaction() as db:
            row = self._task(db, task)
            if row["paused"]:
                raise ControlError("user_paused")
            binding = row["host_binding"]
            if not binding or not binding.startswith("origin:"):
                raise ControlError("trusted_chat_binding_required")
            previous = db.execute("SELECT state,expires FROM card_requests WHERE task=?",
                                  (task,)).fetchone()
            if previous:
                if previous["state"] == "allowed" or (
                        previous["state"] == "pending" and previous["expires"] > now):
                    raise ControlError("card_request_already_exists")
                # Explicitly denied or expired cards may be requested again.
                # The old nonce cannot resolve a replacement request.
                db.execute("DELETE FROM card_requests WHERE task=?", (task,))
            encoded = _json(scopes)
            scope_hash = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
            db.execute("INSERT INTO card_requests VALUES (?,?,?,?,?,?,?,?,?,'pending',NULL)",
                       (request_id, task, binding, encoded, scope_hash,
                        description_hash, nonce_hash, now, now + lifetime))
        return request_id

    @staticmethod
    def _card_nonce_hash(nonce: str) -> str:
        if not isinstance(nonce, str) or len(nonce) < 32:
            raise ControlError("invalid_card_nonce")
        return hashlib.sha256(b"flower-card-nonce-v1\0" + nonce.encode()).hexdigest()

    def card_request_active(self, request_id: str, nonce: str) -> bool:
        nonce_hash = self._card_nonce_hash(nonce)
        with self.transaction() as db:
            row = db.execute("SELECT r.*,t.host_binding AS current_binding,t.paused,t.revoked "
                             "FROM card_requests r JOIN tasks t ON t.id=r.task WHERE r.id=?",
                             (request_id,)).fetchone()
            return bool(row and secrets.compare_digest(row["nonce_hash"], nonce_hash)
                        and row["state"] == "pending"
                        and row["expires"] > self.clock() and not row["paused"]
                        and not row["revoked"] and row["host_binding"] == row["current_binding"])

    def resolve_card_request(self, request_id: str, nonce: str,
                             description_hash: str, scopes: tuple[str, ...], *, allow: bool) -> bool:
        """Commit one native click and all scopes together; fail closed on drift."""
        if type(allow) is not bool:
            raise ControlError("invalid_card_decision")
        nonce_hash = self._card_nonce_hash(nonce)
        encoded = _json(scopes)
        scope_hash = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        with self.transaction() as db:
            row = db.execute("SELECT r.*,t.host_binding AS current_binding,t.paused,t.revoked "
                             "FROM card_requests r JOIN tasks t ON t.id=r.task WHERE r.id=?",
                             (request_id,)).fetchone()
            if not row or not secrets.compare_digest(row["nonce_hash"], nonce_hash):
                raise ControlError("card_request_missing")
            if row["state"] != "pending":
                raise ControlError("card_request_replayed")
            if row["expires"] <= self.clock():
                raise ControlError("card_request_expired")
            if (row["host_binding"] != row["current_binding"] or row["revoked"]
                    or row["paused"]):
                raise ControlError("card_request_inactive")
            if (row["scopes"] != encoded or row["scopes_hash"] != scope_hash
                    or row["description_hash"] != description_hash):
                raise ControlError("card_request_drift")
            now = self.clock()
            if allow:
                # Card grants last for this same-boot task, not a new 24h
                # window on each turn. Boot changes revoke the task above.
                card_event = "card:" + request_id
                expiry = 1e300
                db.execute("INSERT INTO grant_events VALUES (?,?,?,?)",
                           (card_event, row["task"], scope_hash, expiry))
                for scope in scopes:
                    db.execute("INSERT OR REPLACE INTO grants VALUES (?,?,?,?)",
                               (row["task"], scope, card_event, expiry))
                db.execute("UPDATE tasks SET revision=revision+1 WHERE id=?", (row["task"],))
            db.execute("UPDATE card_requests SET state=?,decided=? WHERE id=?",
                       ("allowed" if allow else "denied", now, request_id))
            return allow

    def set_focus_from_user_event(self, task: str, sequence: int, focused: bool):
        """Only a verified adapter calls this; ordinary tool requests cannot."""
        with self.transaction() as db:
            row = self._task(db, task)
            latest = db.execute("SELECT value FROM meta WHERE key='focus_sequence'").fetchone()
            if sequence <= row["focus_sequence"] or (latest and sequence <= int(latest[0])):
                return False
            if focused:
                db.execute("UPDATE tasks SET focus=0,revision=revision+1 WHERE focus=1 AND id<>?", (task,))
            db.execute("UPDATE tasks SET focus=?,focus_sequence=?,revision=revision+1 WHERE id=?",
                       (int(focused), sequence, task))
            db.execute("INSERT OR REPLACE INTO meta VALUES ('focus_sequence',?)", (str(sequence),))
            return True

    def pause_task(self, task: str):
        with self.transaction() as db:
            self._task(db, task)
            db.execute("UPDATE tasks SET paused=1,revision=revision+1 WHERE id=?", (task,))
            self._stop_task_actions(db, task)

    def _stop_task_actions(self, db, task: str):
        """Record Stop in the same transaction as its authorization mutation."""
        db.execute("UPDATE observations SET expires=0 WHERE task=?", (task,))
        db.execute("UPDATE actions SET cancel_requested=1 WHERE task=? AND state='running'", (task,))
        db.execute("UPDATE actions SET state='cancelled',cancel_requested=1,updated=? "
                   "WHERE task=? AND state='queued'", (self.clock(), task))
        db.execute("UPDATE foreground_stages SET stop_received=COALESCE(stop_received,?),"
                   "interruption='explicit_stop',interrupted=COALESCE(interrupted,?) "
                   "WHERE action IN (SELECT id FROM actions WHERE task=?) AND lease_released IS NULL",
                   (self.clock(), self.clock(), task))

    def _mark_stage_stop(self, db, action_id: str):
        now = self.clock()
        db.execute("UPDATE foreground_stages SET stop_received=COALESCE(stop_received,?),"
                   "interruption='explicit_stop',interrupted=COALESCE(interrupted,?) WHERE action=?",
                   (now, now, action_id))

    def resume_from_user_event(self, task: str):
        epoch = self.write_gate.snapshot().epoch
        with self.transaction() as db:
            self._resume_from_user_event(db, task, expected_epoch=epoch)

    def _resume_from_user_event(self, db, task: str, *, expected_epoch: int):
        """Join an existing decision transaction, acknowledging only this task."""
        self._task(db, task)
        try:
            status = self.write_gate.resume(all_tasks=False, expected_epoch=expected_epoch)
        except WriteGateError as error:
            raise ControlError(error.code) from error
        db.execute("INSERT OR REPLACE INTO task_write_epochs VALUES (?,?)", (task, status.epoch))
        db.execute("UPDATE tasks SET paused=0,revision=revision+1 WHERE id=?", (task,))

    def pause_resources(self, resources: tuple[str, ...]):
        """Persist user takeover BEFORE releasing any current execution lock."""
        with self.transaction() as db:
            for resource in resources:
                db.execute("INSERT OR IGNORE INTO resources(id) VALUES (?)", (resource,))
                db.execute("UPDATE resources SET paused=1,revision=revision+1 WHERE id=?", (resource,))

    def resume_resources_from_user_event(self, resources: tuple[str, ...]):
        with self.transaction() as db:
            for resource in resources:
                db.execute("UPDATE resources SET paused=0,revision=revision+1 WHERE id=?", (resource,))

    def pause_computer_target(self, task: str, resource: str) -> None:
        """Stop only one owned window and cancel its pending Computer actions."""
        with self.transaction() as db:
            self._task(db, task)
            owned = db.execute("SELECT task FROM owned_resources WHERE resource=?",
                               (resource,)).fetchone()
            if not owned or owned["task"] != task:
                raise ControlError("target_belongs_to_another_task")
            row = db.execute("SELECT id FROM resources WHERE id=?", (resource,)).fetchone()
            if not row:
                raise ControlError("resource_not_found")
            db.execute("UPDATE resources SET paused=1,revision=revision+1 WHERE id=?",
                       (resource,))
            for action in db.execute(
                    "SELECT id,resources,state FROM actions WHERE task=? "
                    "AND state IN ('queued','running')", (task,)).fetchall():
                if resource not in json.loads(action["resources"]):
                    continue
                if action["state"] == "queued":
                    db.execute("UPDATE actions SET state='cancelled',cancel_requested=1,updated=? "
                               "WHERE id=?", (self.clock(), action["id"]))
                else:
                    db.execute("UPDATE actions SET cancel_requested=1 WHERE id=?",
                               (action["id"],))
                self._mark_stage_stop(db, action["id"])

    def _legacy_released_computer_stop(self, db, task, resource):
        """Identify only the old known broker Stop misclassified by the driver.

        The accepted High validator forbids unknown counts with released input.
        An original confirmation before finish therefore proves known cleanup;
        a later recovery confirmation cannot substitute for that terminal fact.
        This query grants nothing and never changes the original action.
        """
        affected = {resource, FOREGROUND_INPUT_RESOURCE}
        rows = [row for row in db.execute("SELECT rowid AS record_order,* FROM actions WHERE state='outcome_uncertain'")
                if resource in json.loads(row["resources"])]
        if len(rows) != 1:
            return None
        action = rows[0]
        if (action["task"] != task or action["result_code"] != "broker_paused"
                or not action["cancel_requested"] or not action["dispatched"]
                or set(json.loads(action["resources"])) != affected):
            return None
        stage = db.execute("SELECT * FROM foreground_stages WHERE action=?", (action["id"],)).fetchone()
        binding = db.execute("SELECT * FROM input_release_bindings WHERE action=?", (action["id"],)).fetchone()
        effects = db.execute("SELECT * FROM action_effects WHERE action=?", (action["id"],)).fetchone()
        occupancy = db.execute("SELECT ended FROM occupancy WHERE action=?", (action["id"],)).fetchone()
        owner = db.execute("SELECT process FROM owners WHERE id=?", (action["owner"],)).fetchone()
        if (not stage or stage["channel"] != "computer" or stage["operation"] != "key"
                or stage["target"] != resource or stage["boot"] != self.boot
                or stage["interruption"] != "explicit_stop" or stage["stop_received"] is None
                or stage["ended"] is None or stage["lease_released"] is None
                or not occupancy or occupancy["ended"] is None
                or not binding or binding["confirmed"] is None
                or not stage["started"] <= binding["confirmed"] <= action["updated"] <= stage["ended"]
                or binding["executor_process"] != stage["dispatcher_process"]
                or not owner or binding["executor_process"] == owner["process"]
                or not effects or effects["read_only"] or effects["input_release"] != "released"
                or effects["activation_dispatched"] is None or effects["business_dispatched"] != 1
                or db.execute("SELECT 1 FROM computer_sequence_progress WHERE action=?", (action["id"],)).fetchone()
                or db.execute("SELECT 1 FROM control_events WHERE action=? AND event IN "
                              "('external_input_release_recovered','input_release_confirmed')", (action["id"],)).fetchone()):
            return None
        # Successful original dispatch already checked both resources were not
        # quarantined. Older uncertainty may have recovered shared foreground
        # while retaining its original target; it is not this Stop's blocker.
        dispatched = db.execute("SELECT seq FROM control_events WHERE event='action_dispatched' AND action=?",
                                (action["id"],)).fetchone()
        if dispatched is None:
            return None
        for other in db.execute("SELECT rowid AS record_order,* FROM actions WHERE state IN ('running','outcome_uncertain')"):
            if other["id"] == action["id"] or not affected.intersection(json.loads(other["resources"])):
                continue
            finished = db.execute("SELECT MAX(seq) FROM control_events WHERE event='action_finished' AND action=?",
                                  (other["id"],)).fetchone()[0]
            later_dispatch = db.execute("SELECT 1 FROM control_events WHERE event='action_dispatched' "
                                        "AND action=? AND seq>=?", (other["id"], dispatched[0])).fetchone()
            # Monotonic timestamps from earlier boots are not comparable.
            # Existing terminal rows without events can also predate this
            # healthy dispatch; insertion order keeps that history unchanged.
            if (other["state"] == "running" or later_dispatch or
                    (finished >= dispatched[0] if finished is not None else
                     other["record_order"] >= action["record_order"])):
                return None
        for event in db.execute("SELECT details FROM control_events WHERE event='resource_quarantined' "
                                "AND seq>=?", (dispatched[0],)):
            if affected.intersection(json.loads(event[0])["resources"]):
                return None
        # Bound the legacy window revision to its original observation, all
        # subsequent dispatches (including stopped read-only observe), and the
        # one erroneous finish quarantine. Unexplained target changes fail shut.
        observed = db.execute("SELECT * FROM observations WHERE id=?", (action["observation"],)).fetchone()
        target = db.execute("SELECT * FROM resources WHERE id=?", (resource,)).fetchone()
        if (not observed or observed["task"] != task or observed["resource"] != resource
                or observed["generation"] != action["generation"] or not target
                or target["generation"] != action["generation"] or target["paused"]):
            return None
        dispatches = sum(resource in json.loads(row[0]) for row in db.execute(
            "SELECT a.resources FROM control_events e JOIN actions a ON a.id=e.action "
            "WHERE e.event='action_dispatched' AND e.seq>=?", (dispatched[0],)))
        if target["revision"] != observed["revision"] + dispatches + 1:
            return None
        return action["id"]

    def computer_resume_snapshot(self, task: str, resource: str) -> tuple[int, ...] | None:
        """Freeze the exact paused target for a trusted chat's resume request."""
        with self.transaction() as db:
            task_row = self._task(db, task)
            owned = db.execute("SELECT task FROM owned_resources WHERE resource=?",
                               (resource,)).fetchone()
            if not owned or owned["task"] != task:
                raise ControlError("target_belongs_to_another_task")
            target = db.execute("SELECT paused,quarantined,revision,required_scope FROM resources WHERE id=?",
                                (resource,)).fetchone()
            front = db.execute("SELECT paused,quarantined,revision FROM resources WHERE id=?",
                               (FOREGROUND_INPUT_RESOURCE,)).fetchone()
            quarantined = bool(target and target["quarantined"] or front and front["quarantined"])
            legacy_stop = self._legacy_released_computer_stop(db, task, resource) if quarantined else None
            if not target or quarantined and legacy_stop is None:
                raise ControlError("computer_recovery_required")
            self._require_scope(db, task, target["required_scope"])
            if front and front["paused"]:
                raise ControlError("foreground_user_resume_required")
            if task_row["paused"] and not target["paused"]:
                raise ControlError("paused_target_mismatch")
            status = self.write_gate.snapshot()
            task_epoch = db.execute("SELECT epoch FROM task_write_epochs WHERE task=?", (task,)).fetchone()
            global_paused = status.stopped or max(task_epoch[0] if task_epoch else 0, status.resume_all_epoch) < status.epoch
            if not task_row["paused"] and not target["paused"] and not global_paused and not legacy_stop:
                return None
            for action in db.execute("SELECT resources FROM actions WHERE state='running'"):
                if resource in json.loads(action[0]):
                    raise ControlError("resource_execution_unresolved")
            self._require_input_release_confirmed(db)
            if legacy_stop:
                return task_row["revision"], target["revision"], front["revision"], status.epoch
            return task_row["revision"], target["revision"], status.epoch

    def resume_computer_from_chat_request(self, task: str, resource: str,
                                          snapshot: tuple[int, ...]) -> bool:
        """Resume after explicit trusted-chat intent, using the same exact state.

        This internal adapter does not infer intent. Explicit task resume lifts
        only its write epoch; all other task acknowledgements remain stopped.
        It preserves original stopped action receipts; new actions need new observations.
        """
        if (type(snapshot) is not tuple or len(snapshot) not in (3, 4) or
                any(type(value) is not int for value in snapshot)):
            raise ControlError("resume_snapshot_invalid")
        try:
            with (ExecutionLocks((resource, FOREGROUND_INPUT_RESOURCE)) if len(snapshot) == 4 else nullcontext()):
                return self._resume_computer_from_chat_request(task, resource, snapshot)
        except (ResourceBusy, AbandonedResource):
            raise ControlError("resource_execution_unresolved") from None
        except WriteGateError as error:
            raise ControlError(error.code) from None

    def _resume_computer_from_chat_request(self, task, resource, snapshot):
        with self.transaction() as db:
            task_row = self._task(db, task)
            owned = db.execute("SELECT task FROM owned_resources WHERE resource=?",
                               (resource,)).fetchone()
            if not owned or owned["task"] != task:
                raise ControlError("target_belongs_to_another_task")
            target = db.execute("SELECT paused,quarantined,revision,required_scope FROM resources WHERE id=?",
                                (resource,)).fetchone()
            front = db.execute("SELECT paused,quarantined,revision FROM resources WHERE id=?",
                               (FOREGROUND_INPUT_RESOURCE,)).fetchone()
            quarantined = bool(target and target["quarantined"] or front and front["quarantined"])
            legacy_stop = self._legacy_released_computer_stop(db, task, resource) if quarantined else None
            if (not target or quarantined and (legacy_stop is None or len(snapshot) != 4)
                    or front and front["paused"]):
                raise ControlError("computer_recovery_required")
            self._require_scope(db, task, target["required_scope"])
            status = self.write_gate.snapshot()
            current = (task_row["revision"], target["revision"])
            if len(snapshot) == 4:
                if front is None:
                    raise ControlError("resume_state_changed")
                current += (front["revision"], status.epoch)
            else:
                current += (status.epoch,)
            if current != snapshot:
                raise ControlError("resume_state_changed")
            for action in db.execute("SELECT resources FROM actions WHERE state='running'"):
                if resource in json.loads(action[0]) or legacy_stop and FOREGROUND_INPUT_RESOURCE in json.loads(action[0]):
                    raise ControlError("resource_execution_unresolved")
            self._require_input_release_confirmed(db)
            task_epoch = db.execute("SELECT epoch FROM task_write_epochs WHERE task=?", (task,)).fetchone()
            global_paused = status.stopped or max(task_epoch[0] if task_epoch else 0, status.resume_all_epoch) < status.epoch
            if legacy_stop:
                for affected in (resource, FOREGROUND_INPUT_RESOURCE):
                    db.execute("UPDATE resources SET quarantined=0,revision=revision+1 WHERE id=?", (affected,))
                db.execute("UPDATE observations SET expires=0 WHERE task=? AND resource=?", (task, resource))
                self._record_event(db, "computer_known_stop_resumed", task=task, action=legacy_stop,
                    details={"original_state_preserved": True, "new_observation_required": True,
                             "replay_old_action": False})
            resumed = self.write_gate.resume(all_tasks=False, expected_epoch=snapshot[-1])
            db.execute("INSERT OR REPLACE INTO task_write_epochs VALUES (?,?)", (task, resumed.epoch))
            if task_row["paused"]:
                db.execute("UPDATE tasks SET paused=0,revision=revision+1 WHERE id=?", (task,))
            if target["paused"]:
                db.execute("UPDATE resources SET paused=0,revision=revision+1 WHERE id=?",
                           (resource,))
            return bool(task_row["paused"] or target["paused"] or global_paused or legacy_stop)

    def resume_computer_from_user_event(self, task: str, resource: str,
                                        snapshot: tuple[int, ...]) -> bool:
        """Historical internal name; the name alone does not prove human input."""
        return self.resume_computer_from_chat_request(task, resource, snapshot)

    def retire_owner(self, owner: str):
        with self.transaction() as db:
            self._owner(db, owner, diagnostics=True)
            self._retire_owner(db, owner)

    def _retire_owner(self, db, owner: str):
        db.execute("UPDATE owners SET retired=1 WHERE id=?", (owner,))
        for action in db.execute("SELECT * FROM actions WHERE owner=? AND state='running'", (owner,)).fetchall():
            self._interrupt_action(db, action, "owner_retired")
            db.execute("UPDATE actions SET cancel_requested=1 WHERE id=?", (action["id"],))
        db.execute("UPDATE actions SET state='cancelled' WHERE owner=? AND state='queued'", (owner,))
        db.execute("UPDATE occupancy SET ended=? WHERE ended IS NULL AND action IN "
                   "(SELECT id FROM actions WHERE owner=?)", (self.clock(), owner))

    def revoke_task(self, task: str):
        with self.transaction() as db:
            db.execute("UPDATE tasks SET revoked=1,revision=revision+1 WHERE id=?", (task,))
            db.execute("DELETE FROM grants WHERE task=?", (task,))
            self._stop_task_actions(db, task)
            db.execute("UPDATE foreground_stages SET interruption='authorization_revoked' "
                       "WHERE action IN (SELECT id FROM actions WHERE task=?) AND lease_released IS NULL", (task,))

    def observe(self, owner: str, resource: str, generation: str, *, ttl: float = 15,
                purpose: str | None = None) -> str:
        # Only the internal App TextPattern page continuation needs the already
        # accepted 300s idle window. General/UIA references keep their defaults.
        maximum = 300 if purpose == "app_text_page" else 120
        if purpose not in (None, "app_text_page") or type(ttl) not in (int, float) or not 0 < ttl <= maximum or not generation:
            raise ControlError("invalid_observation")
        with self.transaction() as db:
            connection = self._owner(db, owner)
            if self._task(db, connection["task"])["paused"]:
                raise ControlError("user_paused")
            db.execute("INSERT OR IGNORE INTO resources(id) VALUES (?)", (resource,))
            self._require_owned_resource(db, connection["task"], resource)
            row = db.execute("SELECT * FROM resources WHERE id=?", (resource,)).fetchone()
            if row["paused"]:
                raise ControlError("user_paused")
            self._require_scope(db, connection["task"], row["required_scope"])
            if row["generation"] != generation:
                db.execute("UPDATE resources SET generation=?,revision=revision+1 WHERE id=?",
                           (generation, resource))
                row = db.execute("SELECT * FROM resources WHERE id=?", (resource,)).fetchone()
            observation = _id()
            db.execute("INSERT INTO observations VALUES (?,?,?,?,?,?)",
                       (observation, connection["task"], resource, row["revision"], generation,
                        self.clock() + ttl))
            db.execute("INSERT INTO observation_write_epochs VALUES (?,?)", (observation, self.write_gate.snapshot().epoch))
            return observation

    def enqueue(self, owner: str, *, action_id: str, fingerprint: str, resources: tuple[str, ...],
                scope: str | None = None, observation: str | None = None,
                generation: str | None = None, phase: Phase = Phase.WORK,
                estimated_ms: int | None = None, context: dict | None = None,
                read_only: bool = False):
        if type(read_only) is not bool or (read_only and FOREGROUND_INPUT_RESOURCE in resources):
            raise ControlError("invalid_read_only_action")
        if not isinstance(phase, Phase) or (estimated_ms is not None and
                (isinstance(estimated_ms, bool) or not isinstance(estimated_ms, int) or estimated_ms < 0)):
            raise ControlError("invalid_action_hints")
        context = safe_metadata(context or {})
        if set(context) - {"task_hint", "operation", "channel", "foreground_needed", "continuation_cost_ms",
                           "estimate_source", "estimate_reference", "continuation_source", "continuation_reference"}:
            raise ControlError("invalid_action_context")
        from .foreground_stage import validate_cost_context
        validate_cost_context(estimated_ms, context)
        for name, limit in (("task_hint", 160), ("operation", 96)):
            if name in context:
                if type(context[name]) is not str:
                    raise ControlError("invalid_action_context")
                context[name] = target_description(context[name], limit)
        resources = tuple(sorted(set(resources)))
        if not action_id or not fingerprint or not resources or len(resources) > 32:
            raise ControlError("invalid_action")
        with self.transaction() as db:
            connection = self._owner(db, owner)
            previous = db.execute("SELECT * FROM actions WHERE id=?", (action_id,)).fetchone()
            if previous:
                effects = db.execute("SELECT read_only FROM action_effects WHERE action=?", (action_id,)).fetchone()
                if bool(effects and effects[0]) != read_only:
                    raise ControlError("action_id_conflict")
                old_context = db.execute("SELECT details FROM action_context WHERE action=?", (action_id,)).fetchone()
                if (json.loads(old_context[0]) if old_context else {}) != context:
                    raise ControlError("action_id_conflict")
                hints = db.execute("SELECT * FROM action_hints WHERE action=?", (action_id,)).fetchone()
                if (previous["task"] != connection["task"] or previous["fingerprint"] != fingerprint
                        or previous["resources"] != _json(resources) or previous["scope"] != scope
                        or previous["observation"] != observation or previous["generation"] != generation
                        or hints["phase"] != phase.value or hints["estimated_ms"] != estimated_ms):
                    raise ControlError("action_id_conflict")
                return dict(previous)
            for resource in resources:
                db.execute("INSERT OR IGNORE INTO resources(id) VALUES (?)", (resource,))
            now = self.clock()
            db.execute("INSERT INTO actions(id,owner,task,fingerprint,resources,scope,observation,"
                       "generation,state,created,updated) VALUES (?,?,?,?,?,?,?,?,'queued',?,?)",
                       (action_id, owner, connection["task"], fingerprint, _json(resources), scope,
                        observation, generation, now, now))
            action = db.execute("SELECT * FROM actions WHERE id=?", (action_id,)).fetchone()
            db.execute("INSERT INTO action_write_epochs VALUES (?,?)", (action_id, self.write_gate.snapshot().epoch))
            if read_only:
                db.execute("INSERT INTO action_effects VALUES (?,1,0,0,NULL)", (action_id,))
            db.execute("INSERT INTO action_hints VALUES (?,?,?)", (action_id, phase.value, estimated_ms))
            db.execute("INSERT INTO action_context VALUES (?,?)", (action_id, _json(context)))
            self._check_action(db, action)
            self._record_event(db, "action_queued", task=connection["task"], action=action_id,
                               details={"phase": phase.value, "estimated_ms": estimated_ms,
                                        "resources": [r.split(":", 1)[0] for r in resources]})
            return dict(action)

    def _metadata_binding(self, db, action_id, *, read_only=None):
        if read_only is None:
            effects = db.execute("SELECT read_only FROM action_effects WHERE action=?", (action_id,)).fetchone()
            read_only = bool(effects and effects[0])
        if not read_only:
            return False
        context = db.execute("SELECT details FROM action_context WHERE action=?", (action_id,)).fetchone()
        context = json.loads(context[0]) if context else {}
        return context.get("operation") == "bind" and context.get("channel") in {"app", "computer"}

    def _check_action(self, db, action):
        try:
            self._check_write_epoch(db, action)
        except WriteGateError as error:
            raise ControlError(error.code) from error
        task = self._task(db, action["task"])
        owner = db.execute("SELECT * FROM owners WHERE id=?", (action["owner"],)).fetchone()
        if not owner or owner["retired"] or owner["live_until"] <= self.clock():
            raise ControlError("owner_expired_or_missing")
        effects = db.execute("SELECT read_only FROM action_effects WHERE action=?", (action["id"],)).fetchone()
        read_only = bool(effects and effects[0])
        binding = self._metadata_binding(db, action["id"], read_only=read_only)
        if action["cancel_requested"] or task["paused"] and not binding:
            raise ControlError("user_paused_or_cancelled")
        waiter = db.execute("SELECT expires FROM action_waiters WHERE action=?", (action["id"],)).fetchone()
        calls = db.execute("SELECT * FROM waiter_calls WHERE action=?", (action["id"],)).fetchall()
        if action["state"] == "queued" and (waiter or calls):
            live = bool(waiter and waiter[0] > self.clock())
            for call in calls:
                if not process_is_alive(call["process"]):
                    continue
                if call["expires"] > self.clock():
                    live = True
                    break
                if call["decision"] and db.execute(
                    "SELECT 1 FROM decisions WHERE id=? AND chosen=? AND state='adopted' AND expires>?",
                    (call["decision"], action["id"], self.clock())
                ).fetchone():
                    live = True
                    break
            if not live:
                raise ControlError("execution_call_ended")
        resources = json.loads(action["resources"])
        for resource in resources:
            self._require_owned_resource(db, action["task"], resource)
            row = db.execute("SELECT * FROM resources WHERE id=?", (resource,)).fetchone()
            if row["paused"] and not binding or row["quarantined"] and not read_only:
                raise ControlError("resource_paused_or_quarantined")
            self._require_scope(db, action["task"], row["required_scope"])
        if action["scope"]:
            self._require_scope(db, action["task"], action["scope"])
        if action["observation"]:
            if not read_only:
                observed_epoch = db.execute("SELECT epoch FROM observation_write_epochs WHERE observation=?",
                                            (action["observation"],)).fetchone()
                if (observed_epoch[0] if observed_epoch else 0) != self.write_gate.snapshot().epoch:
                    raise ControlError("observation_stale")
            obs = db.execute("SELECT * FROM observations WHERE id=?", (action["observation"],)).fetchone()
            if not obs or obs["task"] != action["task"] or obs["resource"] not in resources:
                raise ControlError("observation_scope_mismatch")
            revision = db.execute("SELECT revision FROM resources WHERE id=?", (obs["resource"],)).fetchone()[0]
            if obs["expires"] <= self.clock() or obs["revision"] != revision or obs["generation"] != action["generation"]:
                raise ControlError("observation_stale")

    def _snapshot(self, db, seed: tuple[str, ...]):
        queued = db.execute("SELECT * FROM actions WHERE state='queued' ORDER BY created,id").fetchall()
        eligibility_by_id = {}
        for action in queued:
            try:
                self._check_action(db, action)
                eligibility_by_id[action["id"]] = "ready"
            except ControlError as error:
                eligibility_by_id[action["id"]] = error.code
        domain = set(seed)
        selected = {}
        changed = True
        while changed:
            changed = False
            for action in queued:
                resources = set(json.loads(action["resources"]))
                if domain.intersection(resources) and action["id"] not in selected:
                    selected[action["id"]] = action
                    if eligibility_by_id[action["id"]] == "ready":
                        domain.update(resources)
                        changed = True
        data = []
        candidates = []
        for action in selected.values():
            task = db.execute("SELECT revision FROM tasks WHERE id=?", (action["task"],)).fetchone()
            eligibility = eligibility_by_id[action["id"]]
            if eligibility == "ready":
                candidates.append(action["id"])
            data.append((action["id"], task[0], eligibility))
        resource_state = []
        for resource in sorted(domain):
            row = db.execute("SELECT revision,quarantined,paused FROM resources WHERE id=?", (resource,)).fetchone()
            resource_state.append((resource, tuple(row) if row else None))
        jev_mode = bool(self.jev_enabled and self.jev_enabled())
        fingerprint = hashlib.sha256(_json((sorted(data), resource_state, jev_mode)).encode()).hexdigest()
        return tuple(sorted(domain)), tuple(sorted(candidates)), fingerprint

    def prepare_decision(self, resources: tuple[str, ...], *, ttl: float = 1.0):
        if not 0 < ttl <= 5:
            raise ControlError("invalid_decision_deadline")
        with self.transaction() as db:
            domain, candidates, fingerprint = self._snapshot(db, resources)
            if not candidates:
                raise ControlError("no_eligible_actions")
            prior = db.execute("SELECT * FROM decisions WHERE resources=? AND fingerprint=? "
                               "AND state IN ('pending','adopted') AND expires>?", (_json(domain), fingerprint, self.clock())).fetchone()
            if prior:
                return dict(prior)
            decision = _id()
            db.execute("INSERT INTO decisions VALUES (?,?,?,?,?,'pending',NULL,NULL)",
                       (decision, _json(domain), fingerprint, _json(candidates), self.clock() + ttl))
            return dict(db.execute("SELECT * FROM decisions WHERE id=?", (decision,)).fetchone())

    def adopt_decision(self, decision_id: str, action_id: str, reason: str = "local") -> bool:
        if reason not in {"local", "jev", "fallback", "user_order"}:
            raise ControlError("invalid_decision_reason")
        with self.transaction() as db:
            row = db.execute("SELECT * FROM decisions WHERE id=?", (decision_id,)).fetchone()
            if not row or row["state"] != "pending" or row["expires"] <= self.clock():
                return False
            domain, candidates, fingerprint = self._snapshot(db, tuple(json.loads(row["resources"])))
            if fingerprint != row["fingerprint"] or action_id not in candidates:
                db.execute("UPDATE decisions SET state='expired' WHERE id=?", (decision_id,))
                return False
            ranked = self._scheduling_candidates(db, domain, candidates)
            local = choose_local(ranked, self.clock(), self.policy)
            if reason == "jev":
                if build_jev_request(ranked, self.clock(), self.policy, secrets.token_bytes(24)) is None:
                    return False
            elif not local or action_id != local.action_id:
                return False
            db.execute("UPDATE decisions SET state='adopted',chosen=?,reason=? WHERE id=?",
                       (action_id, reason, decision_id))
            return True

    def _scheduling_candidates(self, db, domain, action_ids):
        now = self.clock()
        local_jev_enabled = bool(self.jev_enabled and self.jev_enabled())
        history = [row for row in db.execute("SELECT * FROM occupancy WHERE ended IS NULL OR ended>?",
                                            (now - 30,)).fetchall()
                   if set(domain).intersection(json.loads(row["resources"]))]
        used = {}
        for row in history:
            elapsed = max(0, (row["ended"] or now) - max(row["started"], now - 30))
            used[row["task"]] = used.get(row["task"], 0) + int(elapsed * 1000)
        finished = sorted((row for row in history if row["ended"] is not None),
                          key=lambda r: r["ended"], reverse=True)
        last_task = finished[0]["task"] if finished and now - finished[0]["ended"] <= 2 else None
        continuation_ms = 0
        prior_end = now
        for row in finished:
            if row["task"] != last_task or prior_end - row["ended"] > 2:
                break
            continuation_ms += max(0, int((row["ended"] - row["started"]) * 1000))
            prior_end = row["started"]
        result = []
        for action_id in action_ids:
            action = db.execute("SELECT * FROM actions WHERE id=?", (action_id,)).fetchone()
            task = self._task(db, action["task"])
            hints = db.execute("SELECT * FROM action_hints WHERE action=?", (action_id,)).fetchone()
            context_row = db.execute("SELECT details FROM action_context WHERE action=?", (action_id,)).fetchone()
            context = json.loads(context_row[0]) if context_row else {}
            # Provenance stays in local metadata; Candidate has a fixed public
            # schema and Jev never receives arbitrary local reference strings.
            candidate_context = {key: context[key] for key in (
                "task_hint", "operation", "channel", "foreground_needed", "continuation_cost_ms") if key in context}
            result.append(Candidate(action_id, task["id"], tuple(json.loads(action["resources"])),
                                    action["created"], bool(task["focus"]), last_task == task["id"],
                                    continuation_ms if last_task == task["id"] else 0,
                                    used.get(task["id"], 0), hints["estimated_ms"], Phase(hints["phase"]),
                                    None, local_jev_enabled, True, **candidate_context))
        return tuple(result)

    def scheduling_request(self, decision_id: str):
        """Internal adapter: return a sanitized request plus its local resolver."""
        with self.transaction() as db:
            row = db.execute("SELECT * FROM decisions WHERE id=?", (decision_id,)).fetchone()
            if not row or row["state"] != "pending" or row["expires"] <= self.clock():
                raise ControlError("decision_expired")
            domain, candidates, fingerprint = self._snapshot(db, tuple(json.loads(row["resources"])))
            if fingerprint != row["fingerprint"]:
                raise ControlError("decision_stale")
            ranked = self._scheduling_candidates(db, domain, candidates)
            return (choose_local(ranked, self.clock(), self.policy),
                    build_jev_request(ranked, self.clock(), self.policy, secrets.token_bytes(24)))

    def _start_locked_dispatch(self, db, owner, action_id, decision_id, resources):
        """Shared ledger checks, after the actual native executor acquired locks."""
        self._owner(db, owner)
        action = db.execute("SELECT * FROM actions WHERE id=?", (action_id,)).fetchone()
        decision = db.execute("SELECT * FROM decisions WHERE id=?", (decision_id,)).fetchone()
        if not action or action["owner"] != owner or action["state"] != "queued":
            raise ControlError("action_not_dispatchable")
        if not decision or decision["chosen"] != action_id or decision["state"] != "adopted":
            raise ControlError("decision_not_adopted")
        if decision["expires"] <= self.clock():
            raise ControlError("decision_expired")
        _, _, fingerprint = self._snapshot(db, tuple(json.loads(decision["resources"])))
        if fingerprint != decision["fingerprint"]:
            raise ControlError("decision_stale")
        self._check_action(db, action)
        for running in db.execute("SELECT resources FROM actions WHERE state='running'"):
            if set(resources).intersection(json.loads(running[0])):
                raise ControlError("resource_execution_unresolved")
        db.execute("UPDATE decisions SET state='consumed' WHERE id=?", (decision_id,))
        db.execute("UPDATE actions SET state='running',dispatched=1,updated=? WHERE id=?", (self.clock(), action_id))
        db.execute("INSERT INTO occupancy VALUES (?,?,?,?,NULL)",
                   (action_id, action["task"], action["resources"], self.clock()))
        self._record_event(db, "action_dispatched", task=action["task"], action=action_id,
                           details={"decision_id": decision_id, "choice_reason": decision["reason"],
                                    "queue_ms": max(0, round((self.clock() - action["created"]) * 1000))})
        for resource in resources:
            db.execute("UPDATE resources SET revision=revision+1 WHERE id=?", (resource,))
        return dict(action)

    @contextmanager
    def dispatch(self, owner: str, action_id: str, decision_id: str):
        with self.transaction() as db:
            self._owner(db, owner)
            action = db.execute("SELECT resources FROM actions WHERE id=? AND owner=?",
                                (action_id, owner)).fetchone()
            if not action:
                raise ControlError("action_not_dispatchable")
            resources = tuple(json.loads(action["resources"]))
        locks = ExecutionLocks(resources)
        began = False
        try:
            locks.__enter__()
            with self.transaction() as db:
                action = self._start_locked_dispatch(db, owner, action_id, decision_id, resources)
                began = True
            self._dispatch_threads[action_id] = threading.get_ident()
            self._dispatch_locks[action_id] = locks
            self._native_dispatches[(id(self), action_id)] = locks
            yield dict(action)
        except AbandonedResource:
            self.quarantine(resources)
            raise ControlError("abandoned_execution_requires_recovery") from None
        except ResourceBusy:
            raise ControlError("resource_busy") from None
        finally:
            try:
                if began:
                    with self.transaction() as db:
                        row = db.execute("SELECT * FROM actions WHERE id=?", (action_id,)).fetchone()
                        if row and row["state"] == "running":
                            self._interrupt_action(db, row, "dispatch_interrupted")
                        db.execute("UPDATE occupancy SET ended=? WHERE action=? AND ended IS NULL",
                                   (self.clock(), action_id))
            finally:
                locks.release()
                self._dispatch_threads.pop(action_id, None)
                self._dispatch_locks.pop(action_id, None)
                self._native_dispatches.pop((id(self), action_id), None)
                if began:
                    # Record physical release only after ReleaseMutex returned.
                    # A crashed dispatcher leaves NULL, never a false success.
                    with self.transaction() as db:
                        now = self.clock()
                        db.execute("UPDATE foreground_stages SET ended=COALESCE(ended,?),"
                                   "lease_released=? WHERE action=?", (now, now, action_id))

    @contextmanager
    def dispatch_external(self, owner: str, action_id: str, decision_id: str, lease):
        """The fixed authenticated helper owns locks; this thread owns ledger work."""
        from flower_control.drivers.high_helper import ExternalDispatchLease, HighHelperError
        if type(lease) is not ExternalDispatchLease:
            raise ControlError("external_executor_unverified")
        with self.transaction() as db:
            connection = self._owner(db, owner)
            if lease.chat_id != connection["task"]:
                raise ControlError("external_executor_chat_mismatch")
            action = db.execute("SELECT resources FROM actions WHERE id=? AND owner=?", (action_id, owner)).fetchone()
            if not action:
                raise ControlError("action_not_dispatchable")
            resources = tuple(json.loads(action["resources"]))

        def record_helper_receipt(result):
            self._external_receipt(owner, action_id, lease, result)

        try:
            lease.claim(action_id, resources, record_helper_receipt)
        except HighHelperError as error:
            raise ControlError("external_executor_unverified") from error
        began = False
        try:
            with self.transaction() as db:
                lease.verify()
                action = self._start_locked_dispatch(db, owner, action_id, decision_id, resources)
                self._dispatch_threads[action_id] = threading.get_ident()
                self._external_dispatches[action_id] = lease
                self._external_native_dispatches[(id(self), action_id)] = lease
                self._bind_external_ledger(db, action_id, lease)
                self._external_pending(owner, action_id, lease, _db=db)
                began = True
            # Durable pre-go uncertainty; only this exact helper's terminal
            # native receipt may confirm its ledger. Exit is not a receipt.
            yield action
        finally:
            if began:
                # A bounded sequence replaces the native lease between steps,
                # while this original action/occupancy context remains alive.
                lease = self._external_dispatches.get(action_id, lease)
                try:
                    if lease.result is None and not lease.go_sent:
                        self._external_effects(owner, action_id, False, False, "released")
                        # No go confirms no down, but not a free native mutex.
                        # Leave the binding unconfirmed until a terminal receipt.
                    with self.transaction() as db:
                        row = db.execute("SELECT * FROM actions WHERE id=?", (action_id,)).fetchone()
                        if row and row["state"] == "running":
                            self._interrupt_action(db, row, "dispatch_interrupted")
                        now = self.clock()
                        db.execute("UPDATE occupancy SET ended=? WHERE action=? AND ended IS NULL", (now, action_id))
                        db.execute("UPDATE foreground_stages SET ended=COALESCE(ended,?),"
                                   "lease_released=CASE WHEN ? THEN ? ELSE lease_released END WHERE action=?",
                                   (now, bool(lease.result and lease.result["MutexReleased"]), now, action_id))
                finally:
                    self._dispatch_threads.pop(action_id, None)
                    self._external_dispatches.pop(action_id, None)
                    if not lease.wait_requires_yield(FOREGROUND_INPUT_RESOURCE):
                        self._external_native_dispatches.pop((id(self), action_id), None)
            elif self._external_dispatches.get(action_id) is lease:
                self._dispatch_threads.pop(action_id, None)
                self._external_dispatches.pop(action_id, None)
                self._external_native_dispatches.pop((id(self), action_id), None)

    def _external_effects(self, owner, action_id, activation, business, release, *, _db=None):
        """OR known sent prefixes; a new uncertain step cannot erase them."""
        if self._dispatch_threads.get(action_id) != threading.get_ident():
            raise ControlError("effects_require_dispatch_thread")
        with (self.transaction() if _db is None else nullcontext(_db)) as db:
            action = db.execute("SELECT state,resources FROM actions WHERE id=? AND owner=?", (action_id, owner)).fetchone()
            if not action or action["state"] != "running":
                raise ControlError("action_not_running")
            foreground = FOREGROUND_INPUT_RESOURCE in json.loads(action["resources"])
            if release in ("unknown", "release_pending") and not foreground:
                raise ControlError("input_effect_requires_foreground_resource")
            db.execute("INSERT OR IGNORE INTO action_effects(action,activation_dispatched) VALUES (?,?)",
                       (action_id, None if foreground else 0))
            row = db.execute("SELECT * FROM action_effects WHERE action=?", (action_id,)).fetchone()
            values = [True if row and row[field] == 1 else value for field, value in
                      (("activation_dispatched", activation), ("business_dispatched", business))]
            if row["read_only"] and (any(value is True for value in values) or release in ("unknown", "release_pending")):
                raise ControlError("read_only_effect_conflict")
            db.execute("UPDATE action_effects SET activation_dispatched=?,business_dispatched=?,input_release=? WHERE action=?",
                       (None if values[0] is None else int(values[0]), None if values[1] is None else int(values[1]), release, action_id))

    def _external_pending(self, owner, action_id, lease, *, _db=None):
        self._external_effects(owner, action_id, None if lease.physical_input_expected else False,
                               None if lease.business_write_expected else False,
                               "unknown" if lease.physical_input_expected else "released", _db=_db)

    @staticmethod
    def _bind_external_ledger(db, action_id, lease):
        if FOREGROUND_INPUT_RESOURCE not in lease.resources:
            return
        prior = db.execute("SELECT confirmed FROM input_release_bindings WHERE action=?", (action_id,)).fetchone()
        if prior is not None and prior[0] is None:
            raise ControlError("input_release_unconfirmed")
        # Persist the exact ready ledger before yielding to any consumer code;
        # dying before HUD binding must not leave an older confirmed ledger.
        db.execute("INSERT OR REPLACE INTO input_release_bindings VALUES (?,?,?,?,NULL)",
                   (action_id, lease.executor_process, lease.ledger_identity,
                    hashlib.sha256(secrets.token_bytes(32)).hexdigest()))

    def _external_receipt(self, owner, action_id, lease, result):
        layout = result.get("LayoutResult")
        business = (layout["Dispatched"] if layout is not None else
                    result["SemanticBusinessDispatched"] if result["SemanticExecutor"] is not None else
                    True if result["BusinessEvents"] else
                    False if not result["BusinessAttempted"] or result["NativeCountKnown"] else None)
        self._external_effects(owner, action_id, result["ActivationRequested"], business, result["InputRelease"])
        with self.transaction() as db:
            if result["RequiresNewObservation"]:
                db.execute("UPDATE observations SET expires=0 WHERE task=?", (lease.chat_id,))
            if result["MutexReleased"]:
                db.execute("UPDATE foreground_stages SET lease_released=COALESCE(lease_released,?) WHERE action=?",
                           (self.clock(), action_id))
            if result["InputRelease"] == "released" and result["MutexReleased"] and (layout is not None or result["SemanticExecutorExited"] is not False):
                db.execute("UPDATE input_release_bindings SET confirmed=? WHERE action=? "
                           "AND executor_process=? AND ledger_identity=?",
                           (self.clock(), action_id, lease.executor_process, lease.ledger_identity))
        if not result["MutexReleased"] or layout is None and result["SemanticExecutorExited"] is False:
            self.quarantine(lease.resources)
        if layout is not None and layout["DispatchAttempted"] and (layout["CallReturned"] is not True or result["SemanticExecutorExited"] is not True):
            self.quarantine(tuple(r for r in lease.resources if r != FOREGROUND_INPUT_RESOURCE))

    def external_sequence(self, owner, action_id, decision_id, *, total_steps):
        """Keep one action alive across 2..3 separately checked native requests.

        Use chain.before_go as the facade callback. The consumer still owns
        start/begin/finish sequence progress, fresh captures, expect and Stop.
        """
        return _ExternalSequence(self, owner, action_id, decision_id, total_steps)

    def external_release_pending(self, owner, action_id):
        """The fresh owner can recover only a persisted exact task/action ledger."""
        with self.transaction() as db:
            connection = self._owner(db, owner)
            action = db.execute("SELECT * FROM actions WHERE id=? AND task=?", (action_id, connection["task"])).fetchone()
            binding = db.execute("SELECT * FROM input_release_bindings WHERE action=?", (action_id,)).fetchone()
            if not action or not binding:
                raise ControlError("external_release_binding_missing")
            old = db.execute("SELECT process FROM owners WHERE id=?", (action["owner"],)).fetchone()
            if action["owner"] != owner and old and process_is_alive(old[0]):
                raise ControlError("external_dispatcher_still_alive")
            if action["owner"] == owner and action_id in self._dispatch_threads:
                raise ControlError("external_dispatcher_still_alive")
            return dict(task_id=connection["task"], action_id=action_id,
                        executor_process=binding["executor_process"], ledger_identity=binding["ledger_identity"])

    def confirm_external_release(self, owner, action_id, recovery):
        from flower_control.drivers.high_helper import ReleaseRecovery, HighHelperError
        if type(recovery) is not ReleaseRecovery:
            raise ControlError("external_release_unverified")
        try:
            recovery.verify()
        except HighHelperError as error:
            raise ControlError("external_release_unverified") from error
        expected = self.external_release_pending(owner, action_id)
        if (recovery.task_id != expected["task_id"] or recovery.action_id != action_id
                or recovery.executor_process != expected["executor_process"]
                or recovery.ledger_identity != expected["ledger_identity"]):
            raise ControlError("input_release_binding_mismatch")
        with self.transaction() as db:
            connection = self._owner(db, owner)
            action = db.execute("SELECT * FROM actions WHERE id=? AND task=?", (action_id, connection["task"])).fetchone()
            old = db.execute("SELECT process FROM owners WHERE id=?", (action["owner"],)).fetchone()
            if action["owner"] != owner and old and process_is_alive(old[0]):
                raise ControlError("external_dispatcher_still_alive")
            recovery.verify()
            updated = db.execute("UPDATE input_release_bindings SET confirmed=COALESCE(confirmed,?) "
                "WHERE action=? AND executor_process=? AND ledger_identity=?",
                (self.clock(), action_id, recovery.executor_process, recovery.ledger_identity)).rowcount
            if updated != 1:
                raise ControlError("input_release_binding_mismatch")
            # Known cleanup does not turn interrupted business into success.
            db.execute("UPDATE action_effects SET input_release='released' WHERE action=?", (action_id,))
            db.execute("UPDATE computer_sequence_progress SET input_release='released' WHERE action=?", (action_id,))
            db.execute("UPDATE foreground_stages SET lease_released=COALESCE(lease_released,?) WHERE action=?",
                       (self.clock(), action_id))
            if action["state"] == "running":
                self._interrupt_action(db, action, "dispatcher_dead")
            self._record_event(db, "external_input_release_recovered", task=connection["task"], action=action_id,
                               details={"new_observation_required": True, "replay_old_action": False})
        self._external_native_dispatches.pop((id(self), action_id), None)
        return {"input_release": "released", "new_observation_required": True, "replay_old_action": False}

    def _continue_external(self, owner, action_id, previous, lease, index):
        from flower_control.drivers.high_helper import ExternalDispatchLease, HighHelperError
        result = previous.result
        if (type(lease) is not ExternalDispatchLease or result is None or not previous.go_sent
                or result["InputRelease"] != "released" or not result["MutexReleased"]
                or not result["NativeCountKnown"] or result["SemanticExecutorExited"] is False
                or result["State"] != "dispatched_unverified" or result["RequiresNewObservation"]
                or result["InputResult"] is None or not result["InputResult"]["BusinessComplete"]
                or lease._helper != previous._helper or lease.desktop_revision != previous.desktop_revision
                or lease.resources != previous.resources or lease.chat_id != previous.chat_id
                or any(lease.target[k] != previous.target[k] for k in ("Hwnd", "Pid", "Created", "WindowNonce"))
                or lease.ledger_identity == previous.ledger_identity):
            raise ControlError("external_continuation_release_required")
        binding = lease.binding
        if binding is None or binding.sequence_step != index or binding.observation_id == previous.binding.observation_id:
            raise ControlError("external_continuation_fresh_observation_required")
        with self.transaction() as db:
            action = db.execute("SELECT * FROM actions WHERE id=? AND owner=?", (action_id, owner)).fetchone()
            self._check_running_action(db, action)
            progress = db.execute("SELECT * FROM computer_sequence_progress WHERE action=?", (action_id,)).fetchone()
            if (not progress or progress["sent_prefix"] != index or progress["partial_step"] is not None
                    or progress["input_release"] != "released" or progress["final_state"] is not None):
                raise ControlError("invalid_sequence_progress")
            fresh = dict(action, observation=binding.observation_id, generation=binding.generation)
            self._check_action(db, fresh)
            old = db.execute("SELECT confirmed FROM input_release_bindings WHERE action=?", (action_id,)).fetchone()
            if old and old[0] is None:
                raise ControlError("input_release_unconfirmed")
            try:
                lease.claim(action_id, lease.resources, lambda receipt: self._external_receipt(owner, action_id, lease, receipt))
            except HighHelperError as error:
                raise ControlError("external_executor_unverified") from error
            # Keep original observation identity for action-status provenance.
            # Consume only this fresh continuation observation's revisions.
            for resource in lease.resources:
                db.execute("UPDATE resources SET revision=revision+1 WHERE id=?", (resource,))
            db.execute("UPDATE foreground_stages SET lease_released=NULL WHERE action=?", (action_id,))
            self._external_dispatches[action_id] = lease
            self._external_native_dispatches[(id(self), action_id)] = lease
            self._bind_external_ledger(db, action_id, lease)
            self._external_pending(owner, action_id, lease, _db=db)

    def start_computer_sequence(self, owner: str, action_id: str, total_steps: int) -> None:
        if type(total_steps) is not int or not 2 <= total_steps <= 3:
            raise ControlError("invalid_sequence_progress")
        if self._dispatch_threads.get(action_id) != threading.get_ident():
            raise ControlError("sequence_requires_dispatch_thread")
        with self.transaction() as db:
            action = db.execute("SELECT * FROM actions WHERE id=? AND owner=?",
                                (action_id, owner)).fetchone()
            self._check_running_action(db, action)
            if db.execute("SELECT 1 FROM computer_sequence_progress WHERE action=?",
                          (action_id,)).fetchone():
                raise ControlError("sequence_progress_already_exists")
            db.execute("INSERT INTO computer_sequence_progress VALUES (?,?,0,NULL,'released',NULL,?)",
                       (action_id, total_steps, self.clock()))

    def begin_computer_sequence_step(self, owner: str, action_id: str, index: int) -> None:
        """Durably mark a step as possibly in flight before SendInput."""
        if self._dispatch_threads.get(action_id) != threading.get_ident():
            raise ControlError("sequence_requires_dispatch_thread")
        with self.transaction() as db:
            action = db.execute("SELECT * FROM actions WHERE id=? AND owner=?",
                                (action_id, owner)).fetchone()
            self._check_running_action(db, action)
            row = db.execute("SELECT * FROM computer_sequence_progress WHERE action=?",
                             (action_id,)).fetchone()
            if (not row or type(index) is not int or index != row["sent_prefix"] or
                    index >= row["total_steps"] or row["partial_step"] is not None or
                    row["input_release"] != "released" or row["final_state"] is not None):
                raise ControlError("invalid_sequence_progress")
            db.execute("UPDATE computer_sequence_progress SET partial_step=?,"
                       "input_release='unknown',updated=? WHERE action=?",
                       (index, self.clock(), action_id))

    def finish_computer_sequence_step(self, owner: str, action_id: str, index: int,
                                      *, complete: bool, input_release: str) -> None:
        if (self._dispatch_threads.get(action_id) != threading.get_ident() or
                type(complete) is not bool or input_release not in
                ("released", "release_pending")):
            raise ControlError("invalid_sequence_progress")
        with self.transaction() as db:
            action = db.execute("SELECT * FROM actions WHERE id=? AND owner=?",
                                (action_id, owner)).fetchone()
            if not action or action["state"] != "running":
                raise ControlError("action_not_running")
            row = db.execute("SELECT * FROM computer_sequence_progress WHERE action=?",
                             (action_id,)).fetchone()
            if (not row or type(index) is not int or row["partial_step"] != index or
                    row["sent_prefix"] != index or row["final_state"] is not None):
                raise ControlError("invalid_sequence_progress")
            db.execute("UPDATE computer_sequence_progress SET sent_prefix=?,"
                       "partial_step=?,input_release=?,updated=? WHERE action=?",
                       (index + 1 if complete else index,
                        None if complete else index, input_release,
                        self.clock(), action_id))

    @staticmethod
    def _failure_state(db, action_id: str) -> str:
        effects = db.execute("SELECT * FROM action_effects WHERE action=?", (action_id,)).fetchone()
        if effects and (effects["read_only"] or (
                effects["business_dispatched"] == 0 and effects["activation_dispatched"] is not None
                and effects["input_release"] in (None, "released"))):
            return "not_verified"
        return "outcome_uncertain"

    def _interrupt_action(self, db, action, reason: str):
        state = self._failure_state(db, action["id"])
        db.execute("UPDATE actions SET state=?,result_code=?,updated=? WHERE id=?",
                   (state, reason, self.clock(), action["id"]))
        self._record_event(db, "action_finished", action=action["id"],
                           details={"state": state, "reason": reason})
        db.execute("UPDATE computer_sequence_progress SET final_state=?,updated=? "
                   "WHERE action=? AND final_state IS NULL",
                   ("outcome_uncertain" if state == "outcome_uncertain" else "sequence_stopped",
                    self.clock(), action["id"]))
        if state == "outcome_uncertain":
            for resource in self._uncertain_resources(db, action):
                db.execute("UPDATE resources SET quarantined=1,revision=revision+1 WHERE id=?", (resource,))

    def _uncertain_resources(self, db, action):
        resources = json.loads(action["resources"])
        external = self._external_dispatches.get(action["id"])
        # Only the sealed fixed layout role qualifies. A missing terminal is
        # no mutex release proof: the actual lock and release binding remain
        # unconfirmed. Keep its window and managed Web/effect resources so
        # another channel cannot write the same target during unknown layout.
        if (external is not None and external.layout_plan is not None
                and (external.result is None or external.result.get("LayoutResult") is not None
                     and external.result["NativeCountKnown"] and external.result["InputRelease"] == "released"
                     and external.result["MutexReleased"])):
            return [resource for resource in resources if resource != FOREGROUND_INPUT_RESOURCE]
        # An App semantic write can remain unknown after showing an owned
        # modal. Its exited worker plus exact confirmed cleanup permits a new
        # popup to use input; keep all original business/effect resources.
        if (external is not None and external.binding is not None and external.business_write_expected
                and external.binding.task_id == action["task"] and external.binding.action_id == action["id"]):
            from flower_control.drivers.high_helper import HighHelperError
            try:
                terminal = external.terminal_for_interruption()
            except HighHelperError:
                return resources
            binding = db.execute("SELECT executor_process,ledger_identity,confirmed FROM input_release_bindings WHERE action=?",
                                 (action["id"],)).fetchone()
            if (terminal.get("LayoutResult") is None and terminal["InputResult"] is None
                    and terminal["SemanticExecutor"] is not None and terminal["SemanticExecutorExited"] is True
                    and terminal["NativeCountKnown"] is True and terminal["InputRelease"] == "released"
                    and terminal["MutexReleased"] is True and binding is not None and binding["confirmed"] is not None
                    and binding["executor_process"] == external.executor_process
                    and binding["ledger_identity"] == external.ledger_identity):
                return [resource for resource in resources if resource != FOREGROUND_INPUT_RESOURCE]
        return resources

    def record_action_effects(self, owner: str, action_id: str, *,
                              activation_dispatched: bool | None = None,
                              business_dispatched: bool | None = None,
                              input_release: str | None = None):
        """Driver evidence only, after actual effects; missing evidence stays unknown.

        Do not record False before calling an API that may write. True is
        monotonic; later read failures cannot erase the already sent prefix.
        """
        if (activation_dispatched is not None and type(activation_dispatched) is not bool
                or business_dispatched is not None and type(business_dispatched) is not bool
                or input_release not in (None, "released", "unknown", "release_pending")):
            raise ControlError("invalid_action_effects")
        if self._dispatch_threads.get(action_id) != threading.get_ident():
            raise ControlError("effects_require_dispatch_thread")
        with self.transaction() as db:
            action = db.execute("SELECT state,resources FROM actions WHERE id=? AND owner=?", (action_id, owner)).fetchone()
            if not action or action["state"] != "running":
                raise ControlError("action_not_running")
            if (input_release in ("unknown", "release_pending")
                    and FOREGROUND_INPUT_RESOURCE not in json.loads(action["resources"])):
                raise ControlError("input_effect_requires_foreground_resource")
            # A non-foreground driver cannot dispatch an explicit activation.
            db.execute("INSERT OR IGNORE INTO action_effects(action,activation_dispatched) VALUES (?,?)",
                       (action_id, None if FOREGROUND_INPUT_RESOURCE in json.loads(action["resources"]) else 0))
            row = db.execute("SELECT * FROM action_effects WHERE action=?", (action_id,)).fetchone()
            if row["read_only"] and (activation_dispatched is True or business_dispatched is True
                                     or input_release in ("unknown", "release_pending")):
                raise ControlError("read_only_effect_conflict")
            for field, value in (("activation_dispatched", activation_dispatched),
                                 ("business_dispatched", business_dispatched)):
                if row[field] == 1 and value is False:
                    raise ControlError("action_effect_regression")
            db.execute("UPDATE action_effects SET activation_dispatched=?,business_dispatched=?,input_release=? "
                       "WHERE action=?",
                       (row["activation_dispatched"] if activation_dispatched is None else int(activation_dispatched),
                        row["business_dispatched"] if business_dispatched is None else int(business_dispatched),
                        row["input_release"] if input_release is None else input_release, action_id))

    def _action_effect_summary(self, db, action) -> dict:
        from .foreground_stage import stage_summary
        from .feedback import aggregate_input_release, receipt_feedback
        # Cancel callers may hold the pre-update row; feedback uses current facts.
        current = db.execute("SELECT * FROM actions WHERE id=?", (action["id"],)).fetchone()
        task = db.execute("SELECT paused,revoked FROM tasks WHERE id=?", (current["task"],)).fetchone()
        resources = json.loads(current["resources"])
        targets = db.execute("SELECT paused,quarantined FROM resources WHERE id IN ("
                             + ",".join("?" for _ in resources) + ")", resources).fetchall()
        stage = stage_summary(self, db, action)
        effects = db.execute("SELECT * FROM action_effects WHERE action=?", (action["id"],)).fetchone()
        progress = db.execute("SELECT input_release FROM computer_sequence_progress WHERE action=?",
                              (action["id"],)).fetchone()
        release = aggregate_input_release(effects["input_release"] if effects else None,
                                          progress[0] if progress else None)
        stage["feedback"] = receipt_feedback(current["task"], current["id"], current["state"],
            cancel_requested=bool(current["cancel_requested"]),
            persistent_stop=bool(task["paused"] or task["revoked"]
                         or any(row is not None and row["paused"] for row in targets)),
            recovery_required=any(row is not None and row["quarantined"] for row in targets),
            input_release=release, result_code=current["result_code"],
            effects={"activation_dispatched": None if effects["activation_dispatched"] is None else bool(effects["activation_dispatched"]),
                     "business_dispatched": None if effects["business_dispatched"] is None else bool(effects["business_dispatched"]),
                     "input_release": release} if effects else None)
        stage["feedback"]["input_release"] = release
        if not effects:
            return stage
        activation = None if effects["activation_dispatched"] is None else bool(effects["activation_dispatched"])
        business = None if effects["business_dispatched"] is None else bool(effects["business_dispatched"])
        dispatched = True if activation is True or business is True else (
            False if activation is False and business is False else None)
        return {**stage, "read_only": bool(effects["read_only"]), "execution_started": bool(action["dispatched"]),
                "activation_dispatched": activation, "business_dispatched": business,
                "dispatched": dispatched, "input_release": effects["input_release"]}

    def finish(self, owner: str, action_id: str, state: str, *, result_code: str = "checked",
               sequence_final_state: str | None = None):
        if state not in {"verified", "not_verified", "outcome_uncertain"}:
            raise ControlError("invalid_terminal_state")
        if sequence_final_state is not None and sequence_final_state not in (
                "sequence_completed", "sequence_stopped", "outcome_uncertain"):
            raise ControlError("invalid_sequence_progress")
        if self._dispatch_threads.get(action_id) != threading.get_ident():
            raise ControlError("finish_requires_dispatch_thread")
        with self.transaction() as db:
            row = db.execute("SELECT * FROM actions WHERE id=? AND owner=?", (action_id, owner)).fetchone()
            if not row or row["state"] != "running":
                raise ControlError("action_not_running")
            effects = db.execute("SELECT input_release FROM action_effects WHERE action=?", (action_id,)).fetchone()
            if effects and effects[0] in ("unknown", "release_pending"):
                state = "outcome_uncertain"
            elif state == "outcome_uncertain":
                state = self._failure_state(db, action_id)
            external = self._external_dispatches.get(action_id)
            if external is not None and external.result is not None and (
                    not external.result["MutexReleased"] or external.result["SemanticExecutorExited"] is False):
                state = "outcome_uncertain"
            db.execute("UPDATE actions SET state=?,result_code=?,updated=? WHERE id=?",
                       (state, result_code, self.clock(), action_id))
            occupancy = db.execute("SELECT started FROM occupancy WHERE action=?", (action_id,)).fetchone()
            self._record_event(db, "action_finished", task=row["task"], action=action_id,
                               details={"state": state, "result_code": result_code,
                                        "execution_ms": max(0, round((self.clock() - occupancy[0]) * 1000))
                                        if occupancy else None})
            if sequence_final_state is not None:
                progress = db.execute(
                    "SELECT * FROM computer_sequence_progress WHERE action=?",
                    (action_id,)).fetchone()
                if not progress or progress["final_state"] is not None:
                    raise ControlError("invalid_sequence_progress")
                clear_unsent = (state == "not_verified" and
                                sequence_final_state == "sequence_stopped" and
                                progress["partial_step"] is not None)
                if clear_unsent and progress["input_release"] != "released":
                    raise ControlError("input_release_unconfirmed")
                db.execute("UPDATE computer_sequence_progress SET final_state=?,"
                           "partial_step=?,updated=? WHERE action=?",
                           (sequence_final_state,
                            None if clear_unsent else progress["partial_step"],
                            self.clock(), action_id))
            if state == "outcome_uncertain":
                for resource in self._uncertain_resources(db, row):
                    db.execute("UPDATE resources SET quarantined=1,revision=revision+1 WHERE id=?", (resource,))

    def issue_worker_permit(self, owner: str, action_id: str, worker_process: str,
                            command_hash: str) -> str:
        """Internal dispatcher only: bind one IPC command to the live child.

        The dispatch thread continues to hold all native locks. This permit
        does not transfer ownership or create a grant, and never survives the
        action becoming terminal. No body or plaintext token is persisted.
        """
        if self._dispatch_threads.get(action_id) != threading.get_ident():
            raise ControlError("permit_requires_dispatch_thread")
        if len(command_hash) != 64 or not process_is_alive(worker_process):
            raise ControlError("invalid_worker_binding")
        token = _id()
        with self.transaction() as db:
            self._owner(db, owner)
            action = db.execute("SELECT * FROM actions WHERE id=? AND owner=?", (action_id, owner)).fetchone()
            self._check_running_action(db, action)
            if action["fingerprint"] != command_hash:
                raise ControlError("worker_command_mismatch")
            if db.execute("SELECT 1 FROM worker_permits WHERE action=?", (action_id,)).fetchone():
                raise ControlError("worker_permit_already_issued")
            db.execute("INSERT INTO worker_permits VALUES (?,?,?,?,0)",
                       (action_id, hashlib.sha256(token.encode()).hexdigest(), worker_process, command_hash))
        return token

    def _check_running_action(self, db, action):
        if not action or action["state"] != "running":
            raise ControlError("action_not_running")
        # dispatch already consumed the observation and advanced revisions;
        # rechecking its old revision would reject our own write. The driver
        # separately checks the exact live DOM/window reference before input.
        running = dict(action)
        running["observation"] = None
        self._check_action(db, running)
        owner = db.execute("SELECT process FROM owners WHERE id=?", (action["owner"],)).fetchone()
        if not process_is_alive(owner[0]):
            raise ControlError("dispatcher_dead")

    def check_worker_permit(self, action_id: str, token: str, command_hash: str,
                            *, consume: bool = False):
        """Worker checks at entry, before actual input and before publication."""
        if consume and self.write_stopped():
            # Stop must reject writes before waiting for an unrelated writer.
            # Diagnostic read-only actions retain their existing Stop contract;
            # the atomic claim below repeats all checks before consuming.
            with self.read_transaction() as db:
                action = db.execute("SELECT * FROM actions WHERE id=?", (action_id,)).fetchone()
                self._check_running_action(db, action)
        transaction = self.transaction(timeout=.25) if consume else self.read_transaction()
        with transaction as db:
            permit = db.execute("SELECT * FROM worker_permits WHERE action=?", (action_id,)).fetchone()
            if (not permit or permit["token_hash"] != hashlib.sha256(token.encode()).hexdigest()
                    or permit["worker_process"] != process_identity()
                    or permit["command_hash"] != command_hash):
                raise ControlError("worker_permit_mismatch")
            if consume and permit["consumed"]:
                raise ControlError("worker_permit_consumed")
            if not consume and not permit["consumed"]:
                raise ControlError("worker_permit_not_consumed")
            action = db.execute("SELECT * FROM actions WHERE id=?", (action_id,)).fetchone()
            self._check_running_action(db, action)
            if consume:
                db.execute("UPDATE worker_permits SET consumed=1 WHERE action=?", (action_id,))

    def check_dispatch(self, owner: str, action_id: str):
        if self._dispatch_threads.get(action_id) != threading.get_ident():
            raise ControlError("check_requires_dispatch_thread")
        with self.read_transaction() as db:
            self._owner(db, owner)
            row = db.execute("SELECT * FROM actions WHERE id=? AND owner=?", (action_id, owner)).fetchone()
            self._check_running_action(db, row)

    def external_dispatch_stopped(self, owner: str, action_id: str) -> bool:
        """Thread-safe existing scope/Stop checks for the helper pipe watcher."""
        if self.write_stopped():
            try:
                with self.read_transaction() as db:
                    if not self._metadata_binding(db, action_id):
                        return True
            except (ControlError, sqlite3.Error):
                return True
        if action_id not in self._external_dispatches:
            return True
        try:
            with self.read_transaction() as db:
                self._owner(db, owner)
                row = db.execute("SELECT * FROM actions WHERE id=? AND owner=?", (action_id, owner)).fetchone()
                self._check_running_action(db, row)
            return False
        except ControlError:
            return True

    def quarantine(self, resources: tuple[str, ...]):
        with self.transaction() as db:
            for resource in resources:
                db.execute("INSERT OR IGNORE INTO resources(id) VALUES (?)", (resource,))
                db.execute("UPDATE resources SET quarantined=1,revision=revision+1 WHERE id=?", (resource,))
            self._record_event(db, "resource_quarantined", details={"resources": list(resources)})

    def reap_dead_owners(self) -> int:
        """Death proves the worker stopped, never that its target stopped writing."""
        with self.transaction() as db:
            owners = db.execute("SELECT id,process FROM owners WHERE retired=0").fetchall()
        dead = [(row["id"], row["process"]) for row in owners
                if not process_is_alive(row["process"])]
        with self.transaction() as db:
            for owner, identity in dead:
                row = db.execute("SELECT process,retired FROM owners WHERE id=?", (owner,)).fetchone()
                if not row or row["retired"] or row["process"] != identity:
                    continue
                for action in db.execute("SELECT * FROM actions WHERE owner=? AND state='running'",
                                         (owner,)).fetchall():
                    self._interrupt_action(db, action, "owner_died")
                db.execute("UPDATE owners SET retired=1 WHERE id=?", (owner,))
                db.execute("UPDATE actions SET state='cancelled',updated=? "
                           "WHERE owner=? AND state='queued'", (self.clock(), owner))
                db.execute("UPDATE occupancy SET ended=? WHERE ended IS NULL AND action IN "
                           "(SELECT id FROM actions WHERE owner=?)", (self.clock(), owner))
        return len(dead)

    def recover_resources(self, resources: tuple[str, ...], probe: Callable[[], dict[str, str]]):
        """Internal driver recovery under execution locks.

        probe must independently establish target quiescence (e.g. a new target
        process/document), and return fresh generations for every resource.
        Worker death or an unchanged screenshot alone is not such evidence.
        This callback and method are never a model-supplied recovery boolean.
        User takeover remains paused until a separate user resume event.
        """
        self.reap_dead_owners()
        resources = tuple(sorted(set(resources)))
        try:
            with ExecutionLocks(resources):
                with self.transaction() as db:
                    if FOREGROUND_INPUT_RESOURCE in resources:
                        self._require_input_release_confirmed(db)
                    for action in db.execute("SELECT resources FROM actions WHERE state='running'"):
                        if set(resources).intersection(json.loads(action[0])):
                            raise ControlError("resource_execution_unresolved")
                    versions = {}
                    for resource in resources:
                        row = db.execute("SELECT revision FROM resources WHERE id=?", (resource,)).fetchone()
                        if not row:
                            raise ControlError("resource_not_found")
                        versions[resource] = row[0]
                generations = probe()
                if (not isinstance(generations, dict) or set(generations) != set(resources)
                        or any(not isinstance(v, str) or not v for v in generations.values())):
                    raise ControlError("recovery_evidence_missing")
                with self.transaction() as db:
                    if FOREGROUND_INPUT_RESOURCE in resources:
                        self._require_input_release_confirmed(db)
                    for resource, revision in versions.items():
                        row = db.execute("SELECT revision FROM resources WHERE id=?", (resource,)).fetchone()
                        if row[0] != revision:
                            raise ControlError("recovery_state_changed")
                    for row in db.execute("SELECT id,resources FROM actions WHERE state='queued'").fetchall():
                        if set(resources).intersection(json.loads(row["resources"])):
                            db.execute("UPDATE actions SET state='cancelled',updated=? WHERE id=?",
                                       (self.clock(), row["id"]))
                    for resource in resources:
                        db.execute("UPDATE resources SET quarantined=0,generation=?,revision=revision+1 WHERE id=?",
                                   (generations[resource], resource))
                return {"recovered": True, "new_observation_required": True}
        except ResourceBusy:
            raise ControlError("recovery_execution_not_quiescent") from None
        except AbandonedResource:
            self.quarantine(resources)
            raise ControlError("recovery_execution_not_quiescent") from None

    def _require_input_release_confirmed(self, db):
        """Block live-context debt; an observed new Windows boot is distinct
        from claiming that the old executor ever released its input.
        """
        pending = db.execute(
            "SELECT a.id,a.resources FROM actions a JOIN action_effects e ON e.action=a.id "
            "WHERE e.input_release IN ('unknown','release_pending') UNION ALL "
            "SELECT a.id,a.resources FROM actions a JOIN computer_sequence_progress p ON p.action=a.id "
            "WHERE p.input_release IN ('unknown','release_pending')").fetchall()
        from .input_boot import context_was_reset
        active_boot = boot_identity() if self._native_boot else None
        stored_boot = db.execute("SELECT value FROM meta WHERE key='boot'").fetchone()
        native_current = active_boot == self.boot and stored_boot is not None and stored_boot[0] == self.boot
        for row in pending:
            if FOREGROUND_INPUT_RESOURCE not in json.loads(row["resources"]):
                continue
            reset = db.execute("SELECT r.*,f.boot AS stage_boot FROM input_context_resets r "
                               "JOIN foreground_stages f ON f.action=r.action WHERE r.action=?",
                               (row["id"],)).fetchone()
            if not native_current or reset is None or not context_was_reset(reset, active_boot):
                raise ControlError("input_release_unconfirmed")

    def diagnostic_action_for_task(self, task: str, action_id: str, *, cancel: bool = False):
        """A trusted chat may inspect/stop its receipt after its window exits."""
        with self.transaction() as db:
            self._task(db, task)
            row = db.execute("SELECT * FROM actions WHERE id=? AND task=?", (action_id, task)).fetchone()
            if not row:
                raise ControlError("action_not_found")
            if cancel:
                state = "cancelled" if row["state"] == "queued" else row["state"]
                db.execute("UPDATE actions SET cancel_requested=1,state=?,updated=? WHERE id=?",
                           (state, self.clock(), action_id))
                self._mark_stage_stop(db, action_id)
                return {"state": state, "stop_received": True, "in_flight": state == "running",
                        **self._action_effect_summary(db, row), **self._computer_sequence_summary(db, row)}
            result = {key: row[key] for key in
                      ("id", "state", "cancel_requested", "dispatched", "result_code")}
            return {**result, **self._action_effect_summary(db, row), **self._computer_sequence_summary(db, row)}

    def cancel(self, owner: str, action_id: str):
        with self.transaction() as db:
            connection = self._owner(db, owner, diagnostics=True)
            row = db.execute("SELECT * FROM actions WHERE id=? AND task=?", (action_id, connection["task"])).fetchone()
            if not row:
                raise ControlError("action_not_found")
            state = "cancelled" if row["state"] == "queued" else row["state"]
            db.execute("UPDATE actions SET cancel_requested=1,state=?,updated=? WHERE id=?",
                       (state, self.clock(), action_id))
            self._mark_stage_stop(db, action_id)
            return {"state": state, "stop_received": True, "in_flight": state == "running",
                    **self._action_effect_summary(db, row), **self._computer_sequence_summary(db, row)}

    @staticmethod
    def _computer_sequence_summary(db, action) -> dict:
        from .feedback import aggregate_input_release
        row = db.execute("SELECT * FROM computer_sequence_progress WHERE action=?",
                         (action["id"],)).fetchone()
        if row is None:
            return {}
        final = row["final_state"]
        final_persisted = final is not None
        if final is None and action["state"] == "outcome_uncertain":
            final = "outcome_uncertain"
        elif final is None and action["state"] == "running":
            owner = db.execute("SELECT process FROM owners WHERE id=?",
                               (action["owner"],)).fetchone()
            if not owner or not process_is_alive(owner["process"]):
                final = "outcome_uncertain"
        prefix = row["sent_prefix"]
        effects = db.execute("SELECT input_release FROM action_effects WHERE action=?",
                             (action["id"],)).fetchone()
        return {"total_steps": row["total_steps"],
                "sent_prefix": list(range(prefix)),
                "undispatched_suffix": list(range(prefix, row["total_steps"])),
                "partial_step": row["partial_step"],
                "sequence_input_release": row["input_release"],
                "input_release": aggregate_input_release(effects[0] if effects else None, row["input_release"]),
                "sequence_final_state": final,
                "sequence_final_state_persisted": final_persisted,
                "sequence_progress_updated": row["updated"]}

    def status(self, owner: str, action_id: str):
        with self.transaction() as db:
            connection = self._owner(db, owner, diagnostics=True)
            row = db.execute("SELECT * FROM actions WHERE id=? AND task=?", (action_id, connection["task"])).fetchone()
            if not row:
                raise ControlError("action_not_found")
            result = {key: row[key] for key in
                      ("id", "state", "cancel_requested", "created", "updated",
                       "dispatched", "result_code")}
            return {**result, **self._action_effect_summary(db, row), **self._computer_sequence_summary(db, row)}

    def computer_sequence_status_for_task(self, task: str, action_id: str,
                                          resource: str) -> dict:
        """Read a sequence after a stdio restart without reusing its old owner."""
        with self.transaction() as db:
            action = db.execute("SELECT * FROM actions WHERE id=? AND task=?",
                                (action_id, task)).fetchone()
            if (not action or resource not in json.loads(action["resources"]) or
                    not db.execute("SELECT 1 FROM computer_sequence_progress WHERE action=?",
                                   (action_id,)).fetchone()):
                raise ControlError("action_not_found")
            result = {key: action[key] for key in
                      ("id", "state", "cancel_requested", "dispatched", "result_code")}
            return {**result, **self._action_effect_summary(db, action), **self._computer_sequence_summary(db, action)}

    def queue_status(self, owner: str, action_id: str):
        """Expose occupancy reasons, never another task's name or contents."""
        from .feedback import queue_feedback, resource_kind, status_revision
        with self.transaction() as db:
            connection = self._owner(db, owner, diagnostics=True)
            action = db.execute("SELECT * FROM actions WHERE id=? AND task=?",
                                (action_id, connection["task"])).fetchone()
            if not action:
                raise ControlError("action_not_found")
            result = {key: action[key] for key in
                      ("id", "state", "cancel_requested", "dispatched", "result_code")}
            result.update(self._action_effect_summary(db, action))
            result.update(self._computer_sequence_summary(db, action))
            if connection["retired"] or connection["live_until"] <= self.clock():
                result["connection"] = "retired"
                result["status_revision"] = status_revision(result)
                return result
            task = db.execute("SELECT paused,revoked FROM tasks WHERE id=?", (connection["task"],)).fetchone()
            if task["revoked"]:
                result["connection"] = "revoked"
                result["status_revision"] = status_revision(result)
                return result
            resources = set(json.loads(action["resources"]))
            reasons = set()
            if task["paused"]:
                reasons.add("user_paused")
            resource_status = []
            for resource in sorted(resources):
                row = db.execute("SELECT paused,quarantined FROM resources WHERE id=?", (resource,)).fetchone()
                resource_status.append({"kind": resource_kind(resource), "paused": bool(row["paused"]),
                                        "recovery_required": bool(row["quarantined"])})
                if row["paused"]:
                    reasons.add("user_takeover")
                if row["quarantined"]:
                    reasons.add("target_recovery_required")
            conflicts = []
            total_conflicts = 0
            for other in db.execute("SELECT id,owner,resources,state FROM actions WHERE state IN ('queued','running') ORDER BY id"):
                overlap = resources.intersection(json.loads(other["resources"]))
                if other["id"] != action_id and overlap:
                    reasons.add("another_action_running" if other["state"] == "running" else "competing_requests")
                    total_conflicts += 1
                    if len(conflicts) < 32:
                        anonymous = hashlib.sha256(_json([connection["task"], self.boot, other["owner"]]).encode()).hexdigest()[:16]
                        conflicts.append({"owner": anonymous, "state": other["state"],
                                          "resource_kinds": sorted({resource_kind(item) for item in overlap})})
            result["waiting_reasons"] = sorted(reasons)
            result["resource_status"] = resource_status
            result["conflicts"] = conflicts
            result["conflicts_complete"] = total_conflicts <= 32
            result["occupancy_evidence"] = "ledger_actions_not_native_lock_proof"
            if action["state"] == "queued":
                try:
                    self._check_action(db, action)
                    result["eligibility"] = "ready"
                except ControlError as error:
                    result["eligibility"] = error.code
                result["resume_by"] = "repeat_same_action"
                result["retry_after_ms"] = 250
            result["can_work_on_independent_resources"] = not bool(task["paused"])
            result["input_release_verified"] = False  # the input worker owns this evidence
            result["queue_wait_ms"] = (max(0, round((self.clock() - action["created"]) * 1000))
                                       if action["state"] == "queued" else None)
            if action["state"] == "queued":
                result["feedback"] = queue_feedback(result["feedback"], waited_ms=result["queue_wait_ms"],
                    reasons=result["waiting_reasons"], independent_allowed=result["can_work_on_independent_resources"])
            result["status_revision"] = status_revision(result)
            return result

    async def wait(self, owner: str, action_id: str, *, timeout: float = 2):
        """Bounded observation; does not hold execution locks or replay actions."""
        if not 0 <= timeout <= 5:
            raise ControlError("invalid_wait_timeout")
        deadline = time.monotonic() + timeout
        initial = self.queue_status(owner, action_id)
        current = initial
        while initial["state"] in {"queued", "running"} and time.monotonic() < deadline:
            await asyncio.sleep(min(0.05, max(0, deadline - time.monotonic())))
            current = self.queue_status(owner, action_id)
            if current["status_revision"] != initial["status_revision"]:
                return current
        return current
