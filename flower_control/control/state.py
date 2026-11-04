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
from typing import Callable, Iterator, Literal, get_args

from .native import (AbandonedResource, ExecutionLocks, FOREGROUND_INPUT_RESOURCE,
                     ResourceBusy, boot_identity, process_identity, process_is_alive, process_is_verified_alive)
from .scheduling import Candidate, Phase, Policy, choose_local, build_jev_request
from .diagnostics import safe_metadata
from .targets import target_description
from .write_gate import WriteGateError, session_write_gate


class ControlError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


HumanHandoffKind = Literal["UAC", "login_secret", "MFA", "captcha", "license_or_key",
    "payment_or_private_data", "external_auth_or_redirect", "system_permission",
    "physical_action", "inaccessible_modal", "legal_or_account_decision", "unknown_blocker"]
HUMAN_HANDOFF_KINDS = frozenset(get_args(HumanHandoffKind))


def human_handoff_kind(value=None) -> HumanHandoffKind:
    """Classify a blocker; this metadata never grants sensitive-action authority."""
    value = "unknown_blocker" if value is None else value
    if type(value) is not str or value not in HUMAN_HANDOFF_KINDS:
        raise ControlError("invalid_handoff_kind")
    return value


def _json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _id() -> str:
    return secrets.token_urlsafe(24)


def _permission_revision():
    from flower_control.permissions import revision, PermissionError
    try:
        return revision()
    except PermissionError as error:
        raise ControlError(error.code) from None


_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS task_write_epochs(task TEXT PRIMARY KEY, epoch INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS action_write_epochs(action TEXT PRIMARY KEY, epoch INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS observation_write_epochs(observation TEXT PRIMARY KEY, epoch INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS observation_policy_revisions(observation TEXT PRIMARY KEY, revision TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS app_expired_refresh_reads(
 action TEXT PRIMARY KEY, parent TEXT NOT NULL, source TEXT NOT NULL,
 shared_resource TEXT, shared_revision INTEGER);
CREATE TABLE IF NOT EXISTS action_policy_revisions(action TEXT PRIMARY KEY, revision TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS action_pointer_effects(action TEXT PRIMARY KEY, events INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS action_pointer_receipts(ledger TEXT PRIMARY KEY, action TEXT NOT NULL, events INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS tasks(
 id TEXT PRIMARY KEY, host_binding TEXT, revision INTEGER NOT NULL DEFAULT 0,
 paused INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0,
 focus INTEGER NOT NULL DEFAULT 0, focus_sequence INTEGER NOT NULL DEFAULT -1,
 created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS task_lifecycle(
 task TEXT PRIMARY KEY REFERENCES tasks(id), sequence INTEGER NOT NULL DEFAULT 0);
CREATE TRIGGER IF NOT EXISTS task_lifecycle_transition
AFTER UPDATE OF paused, revoked ON tasks
WHEN old.paused != new.paused OR old.revoked != new.revoked
BEGIN
  INSERT INTO task_lifecycle(task,sequence) VALUES(new.id,1)
  ON CONFLICT(task) DO UPDATE SET sequence=sequence+1;
END;
CREATE TABLE IF NOT EXISTS task_service_settings(
 task TEXT PRIMARY KEY REFERENCES tasks(id), jev_allowed INTEGER NOT NULL DEFAULT 1,
 revision INTEGER NOT NULL DEFAULT 0, updated REAL NOT NULL,
 CHECK(jev_allowed IN (0,1)));
CREATE TABLE IF NOT EXISTS human_handoffs(
 id TEXT PRIMARY KEY, task TEXT NOT NULL REFERENCES tasks(id), boot TEXT NOT NULL,
 created REAL NOT NULL, expires REAL NOT NULL, state TEXT NOT NULL,
 extensions INTEGER NOT NULL DEFAULT 0, updated REAL NOT NULL,
 kind TEXT NOT NULL DEFAULT 'unknown_blocker');
CREATE TABLE IF NOT EXISTS grants(
 task TEXT NOT NULL REFERENCES tasks(id), scope TEXT NOT NULL, event_id TEXT NOT NULL,
 expires REAL NOT NULL, PRIMARY KEY(task,scope));
CREATE TABLE IF NOT EXISTS grant_events(
 id TEXT PRIMARY KEY, task TEXT NOT NULL, scope TEXT NOT NULL, expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS profile_authorizations(
 task TEXT PRIMARY KEY REFERENCES tasks(id),
 state TEXT NOT NULL CHECK(state IN ('allowed','paused','denied','revoked')),
 updated REAL NOT NULL);
CREATE TABLE IF NOT EXISTS browser_profile_authorizations(
 task TEXT NOT NULL REFERENCES tasks(id), browser TEXT NOT NULL CHECK(browser IN ('edge','chrome')),
 state TEXT NOT NULL CHECK(state IN ('allowed','paused','denied','revoked')),
 updated REAL NOT NULL, PRIMARY KEY(task,browser));
CREATE TABLE IF NOT EXISTS owners(
 id TEXT PRIMARY KEY, task TEXT NOT NULL REFERENCES tasks(id), process TEXT NOT NULL,
 live_until REAL NOT NULL, retired INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS owner_replacements(
 prior TEXT PRIMARY KEY REFERENCES owners(id), replacement TEXT NOT NULL UNIQUE REFERENCES owners(id),
 task TEXT NOT NULL REFERENCES tasks(id));
CREATE TABLE IF NOT EXISTS web_created_targets(
 id TEXT PRIMARY KEY, action TEXT NOT NULL UNIQUE REFERENCES actions(id), task TEXT NOT NULL REFERENCES tasks(id),
 resource TEXT NOT NULL, browser_process TEXT NOT NULL, target TEXT, page_id TEXT,
 state TEXT NOT NULL, created REAL NOT NULL, hidden_requested INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS web_create_resource_baselines(
 action TEXT NOT NULL REFERENCES actions(id), resource TEXT NOT NULL,
 revision INTEGER NOT NULL, PRIMARY KEY(action,resource));
CREATE TABLE IF NOT EXISTS web_target_close_receipts(
 pending TEXT PRIMARY KEY REFERENCES web_created_targets(id), action TEXT NOT NULL REFERENCES actions(id),
 resource TEXT NOT NULL, browser_process TEXT NOT NULL, target TEXT NOT NULL, created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS web_creation_recovery_proofs(
 pending TEXT PRIMARY KEY REFERENCES web_created_targets(id), action TEXT NOT NULL REFERENCES actions(id),
 close_action TEXT NOT NULL REFERENCES actions(id), browser_process TEXT NOT NULL, target TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS web_action_page_targets(
 action TEXT PRIMARY KEY REFERENCES actions(id), browser_process TEXT NOT NULL, target TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS web_user_tab_claims(
 browser_process TEXT NOT NULL, target TEXT NOT NULL, task TEXT NOT NULL REFERENCES tasks(id),
 page_id TEXT NOT NULL, PRIMARY KEY(browser_process,target));
CREATE TABLE IF NOT EXISTS resources(
 id TEXT PRIMARY KEY, revision INTEGER NOT NULL DEFAULT 0,
 quarantined INTEGER NOT NULL DEFAULT 0, paused INTEGER NOT NULL DEFAULT 0,
 required_scope TEXT, generation TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS web_quarantine_recovery_permits(
 resource TEXT PRIMARY KEY REFERENCES resources(id), pending TEXT NOT NULL REFERENCES web_created_targets(id),
 epoch INTEGER NOT NULL, boot TEXT NOT NULL DEFAULT '', keeper TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS web_quarantine_recovery_debts(
 resource TEXT PRIMARY KEY REFERENCES resources(id), pending TEXT NOT NULL REFERENCES web_created_targets(id));
CREATE TABLE IF NOT EXISTS web_quarantine_incidents(
 resource TEXT NOT NULL REFERENCES resources(id), revision INTEGER NOT NULL,
 action TEXT REFERENCES actions(id), PRIMARY KEY(resource,revision));
CREATE TRIGGER IF NOT EXISTS web_quarantine_incident_capture
AFTER UPDATE OF quarantined ON resources
WHEN NEW.quarantined=1 AND EXISTS(SELECT 1 FROM web_quarantine_recovery_debts WHERE resource=NEW.id)
BEGIN
 INSERT INTO web_quarantine_incidents(resource,revision,action) VALUES(NEW.id,NEW.revision,NULL);
END;
CREATE TRIGGER IF NOT EXISTS web_quarantine_debt_preserve
BEFORE UPDATE OF quarantined ON resources
WHEN NEW.quarantined=0 AND EXISTS(SELECT 1 FROM web_quarantine_recovery_debts WHERE resource=NEW.id)
BEGIN
 SELECT RAISE(ABORT, 'web_recovery_epoch_bound');
END;
CREATE TRIGGER IF NOT EXISTS web_quarantine_permit_invalidate
AFTER UPDATE OF quarantined ON resources
BEGIN
 DELETE FROM web_quarantine_recovery_permits WHERE resource=NEW.id;
END;
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
CREATE TABLE IF NOT EXISTS worker_completions(
 action TEXT PRIMARY KEY REFERENCES actions(id), worker_process TEXT NOT NULL, command_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS web_worker_quarantine_incidents(
 resource TEXT NOT NULL, revision INTEGER NOT NULL, action TEXT, PRIMARY KEY(resource,revision));
CREATE TABLE IF NOT EXISTS web_worker_recovery_baselines(resource TEXT PRIMARY KEY, revision INTEGER NOT NULL);
CREATE TRIGGER IF NOT EXISTS web_worker_quarantine_capture
AFTER UPDATE OF quarantined ON resources WHEN NEW.quarantined=1
BEGIN
 INSERT OR REPLACE INTO web_worker_quarantine_incidents VALUES(NEW.id,NEW.revision,NULL);
END;
CREATE TABLE IF NOT EXISTS owned_resources(
 resource TEXT PRIMARY KEY REFERENCES resources(id), task TEXT NOT NULL REFERENCES tasks(id));
CREATE TABLE IF NOT EXISTS owned_resource_claims(
 resource TEXT NOT NULL REFERENCES resources(id), owner TEXT NOT NULL REFERENCES owners(id),
 PRIMARY KEY(resource,owner));
CREATE TABLE IF NOT EXISTS released_resource_claims(
 resource TEXT NOT NULL REFERENCES resources(id), owner TEXT NOT NULL REFERENCES owners(id),
 PRIMARY KEY(resource,owner));
CREATE TABLE IF NOT EXISTS decision_requests(
 decision TEXT PRIMARY KEY REFERENCES decisions(id), process TEXT NOT NULL,
 token TEXT NOT NULL, expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS control_events(
 seq INTEGER PRIMARY KEY AUTOINCREMENT, wall_time REAL NOT NULL,
 monotonic REAL NOT NULL, event TEXT NOT NULL, task TEXT, action TEXT,
 details TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS control_events_task ON control_events(task,seq);
-- Recovery facts are independent of the rotating diagnostic event log.
CREATE TABLE IF NOT EXISTS web_recovery_resource_counts(
 resource TEXT PRIMARY KEY, dispatches INTEGER NOT NULL DEFAULT 0,
 quarantines INTEGER NOT NULL DEFAULT 0, reissues INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS web_recovery_count_baselines(
 action TEXT NOT NULL, resource TEXT NOT NULL, dispatches INTEGER NOT NULL,
 quarantines INTEGER NOT NULL, reissues INTEGER NOT NULL, PRIMARY KEY(action,resource));
CREATE TABLE IF NOT EXISTS web_recovery_dispatch_order(action TEXT PRIMARY KEY, seq INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS web_recovery_reissues(
 action TEXT NOT NULL, resource TEXT NOT NULL, count INTEGER NOT NULL, PRIMARY KEY(action,resource));
CREATE TABLE IF NOT EXISTS web_recovery_proof_order(pending TEXT PRIMARY KEY, seq INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS computer_stop_count_baselines(
 action TEXT NOT NULL, resource TEXT NOT NULL, revision INTEGER NOT NULL,
 dispatches INTEGER NOT NULL, quarantines INTEGER NOT NULL, reissues INTEGER NOT NULL,
 PRIMARY KEY(action,resource));
CREATE TABLE IF NOT EXISTS computer_stop_late_release(action TEXT PRIMARY KEY);
CREATE TRIGGER IF NOT EXISTS web_recovery_count_quarantine
AFTER UPDATE OF quarantined ON resources WHEN NEW.quarantined=1
BEGIN
 INSERT OR IGNORE INTO web_recovery_resource_counts(resource) VALUES(NEW.id);
 UPDATE web_recovery_resource_counts SET quarantines=quarantines+1 WHERE resource=NEW.id;
END;
CREATE TRIGGER IF NOT EXISTS web_recovery_count_dispatch
AFTER INSERT ON control_events WHEN NEW.event='action_dispatched'
BEGIN
 INSERT OR IGNORE INTO web_recovery_resource_counts(resource)
 SELECT value FROM actions,json_each(actions.resources) WHERE actions.id=NEW.action;
 UPDATE web_recovery_resource_counts SET dispatches=dispatches+1 WHERE resource IN
 (SELECT value FROM actions,json_each(actions.resources) WHERE actions.id=NEW.action);
 INSERT OR IGNORE INTO web_recovery_dispatch_order VALUES(NEW.action,NEW.seq);
END;
CREATE TRIGGER IF NOT EXISTS web_recovery_finish_order
AFTER INSERT ON control_events WHEN NEW.event='action_finished'
BEGIN
 DELETE FROM web_recovery_dispatch_order WHERE action=NEW.action AND EXISTS
 (SELECT 1 FROM actions WHERE id=NEW.action AND state NOT IN ('running','outcome_uncertain'));
 DELETE FROM web_action_page_targets WHERE action=NEW.action AND EXISTS
 (SELECT 1 FROM actions WHERE id=NEW.action AND state NOT IN ('running','outcome_uncertain'));
 DELETE FROM web_recovery_count_baselines WHERE action=NEW.action AND EXISTS
 (SELECT 1 FROM actions WHERE id=NEW.action AND state NOT IN ('running','outcome_uncertain'));
 DELETE FROM computer_stop_count_baselines WHERE action=NEW.action AND EXISTS
 (SELECT 1 FROM actions WHERE id=NEW.action AND state NOT IN ('running','outcome_uncertain'));
 DELETE FROM computer_stop_late_release WHERE action=NEW.action AND EXISTS
 (SELECT 1 FROM actions WHERE id=NEW.action AND state NOT IN ('running','outcome_uncertain'));
END;
CREATE TRIGGER IF NOT EXISTS computer_stop_late_release_capture
AFTER INSERT ON control_events WHEN NEW.event IN ('external_input_release_recovered','input_release_confirmed') AND NEW.action IS NOT NULL
BEGIN
 INSERT OR IGNORE INTO computer_stop_late_release SELECT id FROM actions
 WHERE id=NEW.action AND state IN ('running','outcome_uncertain');
END;
CREATE TRIGGER IF NOT EXISTS web_recovery_count_reissue
AFTER INSERT ON control_events WHEN NEW.event IN ('web_creation_recovered','web_foreground_refreshed','web_borrower_refreshed')
BEGIN
 INSERT OR IGNORE INTO web_recovery_resource_counts(resource)
 SELECT value FROM actions,json_each(actions.resources) WHERE actions.id=NEW.action AND
 (NEW.event='web_creation_recovered' OR (NEW.event='web_foreground_refreshed' AND value='desktop-foreground-input-v1') OR
 (NEW.event='web_borrower_refreshed' AND value IN (SELECT resource FROM web_created_targets WHERE action=NEW.action)));
 INSERT OR IGNORE INTO web_recovery_reissues(action,resource,count)
 SELECT NEW.action,value,0 FROM actions,json_each(actions.resources) WHERE actions.id=NEW.action AND
 (NEW.event='web_creation_recovered' OR (NEW.event='web_foreground_refreshed' AND value='desktop-foreground-input-v1') OR
 (NEW.event='web_borrower_refreshed' AND value IN (SELECT resource FROM web_created_targets WHERE action=NEW.action)));
 UPDATE web_recovery_resource_counts SET reissues=reissues+1 WHERE resource IN
 (SELECT resource FROM web_recovery_reissues WHERE action=NEW.action AND
 (NEW.event='web_creation_recovered' OR (NEW.event='web_foreground_refreshed' AND resource='desktop-foreground-input-v1') OR
 (NEW.event='web_borrower_refreshed' AND resource IN (SELECT resource FROM web_created_targets WHERE action=NEW.action))));
 UPDATE web_recovery_reissues SET count=count+1 WHERE action=NEW.action AND
 (NEW.event='web_creation_recovered' OR (NEW.event='web_foreground_refreshed' AND resource='desktop-foreground-input-v1') OR
 (NEW.event='web_borrower_refreshed' AND resource IN (SELECT resource FROM web_created_targets WHERE action=NEW.action)));
END;
CREATE TABLE IF NOT EXISTS window_handoffs(
 id TEXT PRIMARY KEY, task TEXT NOT NULL, target TEXT NOT NULL,
 expires REAL NOT NULL, consumed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS business_runs(
 id TEXT PRIMARY KEY, task TEXT NOT NULL REFERENCES tasks(id), goal TEXT NOT NULL,
 state TEXT NOT NULL, created REAL NOT NULL, updated REAL NOT NULL,
 revision INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS business_steps(
 id TEXT PRIMARY KEY, run TEXT NOT NULL REFERENCES business_runs(id), task TEXT NOT NULL,
 channel TEXT NOT NULL, parent TEXT, state TEXT NOT NULL, summary TEXT NOT NULL,
 created REAL NOT NULL, updated REAL NOT NULL);
CREATE INDEX IF NOT EXISTS business_steps_run ON business_steps(run,created);
CREATE TABLE IF NOT EXISTS business_run_finishes(
 run TEXT PRIMARY KEY REFERENCES business_runs(id), summary TEXT NOT NULL);
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
 stop_received REAL, requires_observation INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS input_release_bindings(
 action TEXT PRIMARY KEY REFERENCES actions(id), executor_process TEXT NOT NULL,
 ledger_identity TEXT NOT NULL, token_hash TEXT NOT NULL, confirmed REAL);
CREATE TABLE IF NOT EXISTS sequence_final_readbacks(
 action TEXT PRIMARY KEY REFERENCES actions(id), owner TEXT NOT NULL,
 started REAL NOT NULL);
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
 total_steps INTEGER NOT NULL CHECK(total_steps BETWEEN 2 AND 8),
 sent_prefix INTEGER NOT NULL DEFAULT 0 CHECK(sent_prefix BETWEEN 0 AND 8),
 partial_step INTEGER CHECK(partial_step BETWEEN 0 AND 7),
 input_release TEXT NOT NULL CHECK(input_release IN ('released','unknown','release_pending')),
 final_state TEXT CHECK(final_state IN ('sequence_completed','sequence_stopped','outcome_uncertain')),
 updated REAL NOT NULL);
"""


class _ExternalSequence:
    def __init__(self, store, owner, action_id, decision_id, total_steps):
        if type(total_steps) is not int or not 2 <= total_steps <= 8:
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
        # Stop uses this only to reject ordinary work without waiting for SQLite.
        # An exact active metadata lease still repeats every durable check.
        self._external_metadata_bindings: dict[str, tuple[str, object]] = {}
        self._last_stop_recorded = -1
        self._stop_record_lock = threading.Lock()
        db = self._connect()
        try:
            from .business_plan import SCHEMA as business_schema
            from .business_calls import SCHEMA as public_call_schema
            db.executescript(_SCHEMA + business_schema + public_call_schema)
        finally:
            db.close()
        with self.transaction() as db:
            version = db.execute("SELECT value FROM meta WHERE key='schema'").fetchone()
            if version and version[0] not in ("1", self.schema_version):
                raise ControlError("incompatible_schema")
            if version and version[0] == "1" and db.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='card_requests'").fetchone():
                raise ControlError("incompatible_schema")
            if "kind" not in {column["name"] for column in
                    db.execute("PRAGMA table_info(human_handoffs)")}:
                db.execute("ALTER TABLE human_handoffs ADD COLUMN kind TEXT NOT NULL DEFAULT 'unknown_blocker'")
            if "requires_observation" not in {column["name"] for column in
                    db.execute("PRAGMA table_info(foreground_stages)")}:
                db.execute("ALTER TABLE foreground_stages ADD COLUMN requires_observation INTEGER NOT NULL DEFAULT 0")
            if "hidden_requested" not in {column["name"] for column in db.execute("PRAGMA table_info(web_created_targets)")}:
                db.execute("ALTER TABLE web_created_targets ADD COLUMN hidden_requested INTEGER NOT NULL DEFAULT 0")
            permit_columns = {column["name"] for column in db.execute("PRAGMA table_info(web_quarantine_recovery_permits)")}
            for column in ("boot", "keeper"):
                if column not in permit_columns:
                    db.execute(f"ALTER TABLE web_quarantine_recovery_permits ADD COLUMN {column} TEXT NOT NULL DEFAULT ''")
            # An earlier interrupted candidate may already contain a permit.
            # Preserve its debt but never make missing keeper/boot valid.
            db.execute("INSERT OR IGNORE INTO web_quarantine_recovery_debts(resource,pending) "
                       "SELECT resource,pending FROM web_quarantine_recovery_permits")
            self._migrate_web_recovery_evidence(db)
            self._migrate_computer_stop_evidence(db)
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
            # Widen the old finite plan bounds in one transaction. Every old
            # prefix, unknown/release fact and action foreign key is copied;
            # no input/action is revived and a failed copy rolls back intact.
            import re
            normalize_schema = lambda text: re.sub(r"\s+", " ", text.strip().rstrip(";"))
            table_sql = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='computer_sequence_progress'").fetchone()[0]
            old_schema = _COMPUTER_SEQUENCE_SCHEMA.replace("BETWEEN 2 AND 8", "BETWEEN 2 AND 3").replace("BETWEEN 0 AND 8", "BETWEEN 0 AND 3").replace("BETWEEN 0 AND 7", "BETWEEN 0 AND 2")
            if normalize_schema(table_sql) == normalize_schema(old_schema):
                db.execute("ALTER TABLE computer_sequence_progress RENAME TO computer_sequence_progress_previous_bounds")
                db.execute(_COMPUTER_SEQUENCE_SCHEMA)
                db.execute("INSERT INTO computer_sequence_progress SELECT * FROM computer_sequence_progress_previous_bounds")
                db.execute("DROP TABLE computer_sequence_progress_previous_bounds")
            elif normalize_schema(table_sql) != normalize_schema(_COMPUTER_SEQUENCE_SCHEMA):
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
            if old_boot and old_boot[0] == self.boot:
                from .input_boot import retire_missed_released_bindings
                retired = retire_missed_released_bindings(db, old_boot[0], self.boot,
                    native_boot=boot_identity() if self._native_boot else None, observed=time.time())
                for row in retired:
                    self._record_event(db, "input_context_retired_after_windows_boot", task=row["task"],
                        action=row["id"], details={"previous_boot": row["boot"], "current_boot": self.boot,
                        "original_release_preserved": True, "new_target_required": True,
                        "missed_binding_migration": True})
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

    @staticmethod
    def _task_jev_allowed(db, task):
        row = db.execute("SELECT jev_allowed FROM task_service_settings WHERE task=?", (task,)).fetchone()
        return row is None or bool(row[0])

    def task_jev_enabled(self, task: str) -> bool:
        """Task opt-out is an upper bound, never permission to enable the service."""
        with self.read_transaction() as db:
            self._task(db, task)
            return self._task_jev_allowed(db, task)

    def task_jev_policy(self, task: str, *, enabled: bool | None = None) -> dict:
        if enabled is not None and type(enabled) is not bool:
            raise ControlError("invalid_jev_task_setting")
        context = self.transaction() if enabled is not None else self.read_transaction()
        with context as db:
            self._task(db, task)
            if enabled is not None:
                previous = self._task_jev_allowed(db, task)
                if previous != enabled:
                    db.execute("INSERT INTO task_service_settings(task,jev_allowed,revision,updated) VALUES (?,?,1,?) "
                               "ON CONFLICT(task) DO UPDATE SET jev_allowed=excluded.jev_allowed,"
                               "revision=revision+1,updated=excluded.updated", (task, int(enabled), self.clock()))
                    db.execute("UPDATE tasks SET revision=revision+1 WHERE id=?", (task,))
            row = db.execute("SELECT jev_allowed,revision FROM task_service_settings WHERE task=?", (task,)).fetchone()
            allowed, revision = (bool(row[0]), row[1]) if row else (True, 0)
        global_enabled = bool(self.jev_enabled and self.jev_enabled())
        return {"scope": "this_chat", "allowed": allowed, "revision": revision,
                "global_enabled": global_enabled, "effective": allowed and global_enabled,
                "enables_new_provider": False, "grants_authorization": False}

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
    def worker_write_admission(self, action_id, token, command_hash, *, guard_resource=None):
        """Same admission for the real permitted worker, without impersonating its owner."""
        if self.write_stopped():
            raise ControlError("global_write_stopped")
        self.check_worker_permit(action_id, token, command_hash)
        with self.transaction() as db:
            action = db.execute("SELECT * FROM actions WHERE id=?", (action_id,)).fetchone()
            epoch = self._check_write_epoch(db, action)
            if guard_resource is not None:
                # Driver-only shared-browser fence, checked at actual context
                # entry alongside the existing epoch, never at construction.
                # It is not claimed as an exclusive action resource: separate
                # tabs may run concurrently. No writer crosses browser awaits.
                row = db.execute("SELECT paused,quarantined,required_scope FROM resources WHERE id=?",
                                 (guard_resource,)).fetchone()
                if (row is None or row["paused"] or row["quarantined"]
                        and not self._quarantine_permit_active(db, guard_resource)):
                    raise ControlError("shared_profile_action_recovery_required")
                self._require_scope(db, action["task"], row["required_scope"])
                if db.execute("SELECT 1 FROM actions a,json_each(a.resources) r "
                              "WHERE a.state IN ('queued','running') AND r.value=? LIMIT 1",
                              (guard_resource,)).fetchone():
                    raise ControlError("shared_profile_legacy_action_in_flight")
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
            self._task(db, task)
            for _ in range(128):
                row = db.execute("SELECT * FROM owners WHERE id=?", (owner,)).fetchone()
                if not row or row["task"] != task:
                    raise ControlError("owner_expired_or_missing")
                if row["process"] != process_identity():
                    raise ControlError("owner_process_mismatch")
                now = self.clock()
                if not row["retired"] and row["live_until"] > now:
                    db.execute("UPDATE owners SET live_until=? WHERE id=?", (now + 120, owner))
                    return owner
                following = db.execute("SELECT replacement FROM owner_replacements WHERE prior=? AND task=?", (owner, task)).fetchone()
                if following:
                    owner = following[0]
                    continue
                if not row["retired"]:
                    self._retire_owner(db, owner)
                replacement = _id()
                db.execute("INSERT INTO owners(id,task,process,live_until) VALUES (?,?,?,?)",
                           (replacement, task, process_identity(), now + 120))
                db.execute("INSERT INTO owner_replacements(prior,replacement,task) VALUES (?,?,?)",
                           (owner, replacement, task))
                return replacement
            raise ControlError("owner_replacement_limit")

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

    def _quarantine_permit_active(self, db, resource):
        """A recovery is valid only in its original uninterrupted Stop epoch.

        The resource's quarantine bit stays set, so older clients cannot
        consume a recovery they do not understand. Any later quarantine write
        invalidates this permit through a database trigger, including old code.
        """
        permit = db.execute("SELECT epoch,boot,keeper FROM web_quarantine_recovery_permits WHERE resource=?",
                            (resource,)).fetchone()
        if not permit:
            return False
        try:
            # The issuing MCP process retains the session gate singleton for
            # its whole life. If it exits, a recreated epoch-zero gate cannot
            # revive this permit, even within the same Windows boot.
            keeper = permit["keeper"]
            if permit["boot"] != self.boot or not process_is_verified_alive(keeper):
                return False
            status = self.write_gate.snapshot()
            return not status.stopped and status.epoch == permit["epoch"]
        except Exception:
            return False

    def _effective_quarantine(self, db, resource, row):
        return bool(row and row["quarantined"] and not self._quarantine_permit_active(db, resource))

    def bind_owned_resource(self, owner: str, resource: str):
        """Bind a newly owned temporary target; never infer sharing from its ID."""
        with self.transaction() as db:
            connection = self._owner(db, owner)
            existing = db.execute("SELECT task FROM owned_resources WHERE resource=?", (resource,)).fetchone()
            if existing and existing[0] != connection["task"]:
                raise ControlError("target_belongs_to_another_task")
            db.execute("INSERT OR IGNORE INTO owned_resources VALUES (?,?)", (resource, connection["task"]))
            db.execute("DELETE FROM released_resource_claims WHERE resource=? AND owner=?", (resource, owner))
            db.execute("INSERT OR IGNORE INTO owned_resource_claims VALUES (?,?)", (resource, owner))
            # Preserve live pre-upgrade clients using this same target. New
            # clients register explicit claims above; this covers legacy rows.
            db.execute("INSERT OR IGNORE INTO owned_resource_claims "
                       "SELECT ?,a.owner FROM actions a JOIN owners o ON a.owner=o.id "
                       "WHERE a.task=? AND o.retired=0 AND o.live_until>? "
                       "AND EXISTS (SELECT 1 FROM json_each(a.resources) WHERE value=?) "
                       "AND NOT EXISTS (SELECT 1 FROM released_resource_claims r WHERE r.resource=? AND r.owner=a.owner)",
                       (resource, connection["task"], self.clock(), resource, resource))

    def finish_owned_resources(self, owner: str, *, phase_release=False,
                               preserve_observations=False, phase_release_check=None) -> dict:
        """Release this connection's claims, preserving peers and unknown effects."""
        if phase_release_check is not None and not phase_release:
            raise ValueError("phase_check_requires_phase_release")
        with (self.transaction(timeout=.02) if phase_release_check is not None else self.transaction()) as db:
            connection = self._owner(db, owner, diagnostics=True)
            if phase_release_check is not None:
                phase_release_check(db)
            resources = [row[0] for row in db.execute(
                "SELECT resource FROM owned_resource_claims WHERE owner=?", (owner,))]
            released = retained = 0
            for resource in resources:
                peers = db.execute("SELECT o.id,o.process,o.live_until FROM owned_resource_claims c "
                    "JOIN owners o ON c.owner=o.id WHERE c.resource=? AND c.owner<>? AND o.retired=0",
                    (resource, owner)).fetchall()
                peer = False
                for row in peers:
                    if not process_is_alive(row["process"]):
                        # Only peers of this target are considered. Their old
                        # running effects retain normal unknown-result rules.
                        self._retire_owner(db, row["id"], release_orphan=True)
                    elif row["live_until"] > self.clock():
                        peer = True
                unresolved = db.execute("SELECT 1 FROM actions a "
                    "WHERE a.state IN ('queued','running','outcome_uncertain') "
                    "AND EXISTS (SELECT 1 FROM json_each(a.resources) WHERE value=?) LIMIT 1",
                    (resource,)).fetchone()
                target = db.execute("SELECT quarantined FROM resources WHERE id=?", (resource,)).fetchone()
                if peer or unresolved or target and target[0]:
                    if phase_release and peer and not unresolved and not (target and target[0]):
                        # Withdraw this idle connection's claim while a peer
                        # still owns the task resource. Do not retire the
                        # connection or resolve unknown effects.
                        db.execute("DELETE FROM owned_resource_claims WHERE owner=? AND resource=?", (owner, resource))
                        db.execute("INSERT OR IGNORE INTO released_resource_claims VALUES (?,?)", (resource, owner))
                    retained += 1
                    continue
                db.execute("DELETE FROM owned_resources WHERE resource=? AND task=?",
                           (resource, connection["task"]))
                if not preserve_observations:
                    db.execute("UPDATE resources SET revision=revision+1 WHERE id=?", (resource,))
                if not preserve_observations:
                    db.execute("UPDATE observations SET expires=0 WHERE resource=? AND task=?",
                               (resource, connection["task"]))
                released += 1
                db.execute("DELETE FROM owned_resource_claims WHERE owner=? AND resource=?", (owner, resource))
                if phase_release:
                    db.execute("INSERT OR IGNORE INTO released_resource_claims VALUES (?,?)", (resource, owner))
            return {"released": released, "retained_for_peer_or_unresolved": retained}

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

    def pause_task(self, task: str, *, reason="explicit_stop"):
        with self.transaction() as db:
            self._task(db, task)
            db.execute("UPDATE tasks SET paused=1,revision=revision+1 WHERE id=?", (task,))
            self._stop_task_actions(db, task, reason=reason)

    def _stop_task_actions(self, db, task: str, *, reason="explicit_stop"):
        """Record Stop in the same transaction as its authorization mutation."""
        db.execute("UPDATE observations SET expires=0 WHERE task=?", (task,))
        db.execute("UPDATE actions SET cancel_requested=1 WHERE task=? AND state='running'", (task,))
        db.execute("UPDATE actions SET state='cancelled',cancel_requested=1,updated=? "
                   "WHERE task=? AND state='queued'", (self.clock(), task))
        for row in db.execute("SELECT action FROM foreground_stages WHERE action IN "
                "(SELECT id FROM actions WHERE task=?) AND lease_released IS NULL", (task,)).fetchall():
            self._mark_stage_interruption(db, row["action"], reason)

    def _mark_stage_stop(self, db, action_id: str):
        self._mark_stage_interruption(db, action_id, "explicit_stop")

    def _mark_stage_interruption(self, db, action_id: str, reason):
        if reason not in {"explicit_stop", "user_pause", "human_handoff", "target_closed"}:
            raise ControlError("invalid_pause_reason")
        now = self.clock()
        db.execute("UPDATE foreground_stages SET "
                   "stop_received=CASE WHEN ?='explicit_stop' THEN COALESCE(stop_received,?) ELSE stop_received END,"
                   "interruption=CASE WHEN stop_received IS NOT NULL THEN interruption ELSE ? END,"
                   "interrupted=COALESCE(interrupted,?) WHERE action=?", (reason, now, reason, now, action_id))

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

    def pause_computer_target(self, task: str, resource: str, *, reason="explicit_stop") -> None:
        """Stop only one owned window and cancel its pending Computer actions."""
        if reason not in {"explicit_stop", "user_pause", "human_handoff", "target_closed"}:
            raise ControlError("invalid_pause_reason")
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
                self._mark_stage_interruption(db, action["id"], reason)

    def _migrate_computer_stop_evidence(self, db):
        if db.execute("SELECT 1 FROM meta WHERE key='computer_stop_counts_v1'").fetchone():
            return
        db.execute("INSERT OR IGNORE INTO computer_stop_late_release SELECT DISTINCT action FROM control_events "
                   "WHERE action IS NOT NULL AND event IN ('external_input_release_recovered','input_release_confirmed')")
        rows = db.execute("SELECT * FROM actions WHERE state='outcome_uncertain' AND result_code='broker_paused'").fetchall()
        for action in rows:
            resources = json.loads(action["resources"])
            targets = [r for r in resources if r != FOREGROUND_INPUT_RESOURCE]
            event = db.execute("SELECT seq FROM control_events WHERE event='action_dispatched' AND action=?", (action["id"],)).fetchone()
            if (len(targets) != 1 or not event or
                    self._legacy_released_computer_stop(db, action["task"], targets[0]) != action["id"]):
                continue
            dispatches = [json.loads(row[0]) for row in db.execute(
                "SELECT a.resources FROM control_events e JOIN actions a ON a.id=e.action "
                "WHERE e.event='action_dispatched' AND e.seq>=?", (event[0],))]
            for resource in resources:
                db.execute("INSERT OR IGNORE INTO web_recovery_resource_counts(resource) VALUES (?)", (resource,))
                count = sum(resource in values for values in dispatches)
                db.execute("INSERT OR IGNORE INTO computer_stop_count_baselines "
                           "SELECT ?,r.id,r.revision-?-1,c.dispatches-?,c.quarantines-1,c.reissues "
                           "FROM resources r JOIN web_recovery_resource_counts c ON c.resource=r.id WHERE r.id=?",
                           (action["id"], count, count, resource))
        db.execute("INSERT INTO meta VALUES ('computer_stop_counts_v1','1')")

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
                or db.execute("SELECT 1 FROM computer_stop_late_release WHERE action=?", (action["id"],)).fetchone()
                or db.execute("SELECT 1 FROM control_events WHERE action=? AND event IN "
                              "('external_input_release_recovered','input_release_confirmed')", (action["id"],)).fetchone()):
            return None
        # Successful original dispatch already checked both resources were not
        # quarantined. Older uncertainty may have recovered shared foreground
        # while retaining its original target; it is not this Stop's blocker.
        dispatched = db.execute("SELECT seq FROM web_recovery_dispatch_order WHERE action=?", (action["id"],)).fetchone()
        if dispatched is None:
            dispatched = db.execute("SELECT seq FROM control_events WHERE event='action_dispatched' AND action=?",
                                (action["id"],)).fetchone()
        if dispatched is None:
            return None
        durable = {r["resource"]: r for r in db.execute("SELECT * FROM computer_stop_count_baselines WHERE action=?", (action["id"],))}
        if durable and set(durable) != affected:
            return None
        for other in db.execute("SELECT rowid AS record_order,* FROM actions WHERE state IN ('running','outcome_uncertain')"):
            if other["id"] == action["id"] or not affected.intersection(json.loads(other["resources"])):
                continue
            finished = db.execute("SELECT MAX(seq) FROM control_events WHERE event='action_finished' AND action=?",
                                  (other["id"],)).fetchone()[0]
            later_dispatch = db.execute("SELECT 1 FROM control_events WHERE event='action_dispatched' "
                                        "AND action=? AND seq>=?", (other["id"], dispatched[0])).fetchone()
            order = db.execute("SELECT seq FROM web_recovery_dispatch_order WHERE action=?", (other["id"],)).fetchone()
            if order and order[0] >= dispatched[0]:
                return None
            if (durable and not order and not later_dispatch and finished is None
                    and (other["dispatched"] or other["record_order"] >= action["record_order"])):
                return None
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
        if durable:
            for member in affected:
                totals = db.execute("SELECT * FROM web_recovery_resource_counts WHERE resource=?", (member,)).fetchone()
                base = durable[member]
                if (not totals or totals["quarantines"] - base["quarantines"] != 1
                        or totals["reissues"] != base["reissues"]):
                    return None
            if durable[resource]["revision"] != observed["revision"]:
                return None
            totals = db.execute("SELECT dispatches FROM web_recovery_resource_counts WHERE resource=?", (resource,)).fetchone()
            dispatches = totals[0] - durable[resource]["dispatches"]
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
            quarantined = (self._effective_quarantine(db, resource, target) or
                           self._effective_quarantine(db, FOREGROUND_INPUT_RESOURCE, front))
            legacy_stop = self._legacy_released_computer_stop(db, task, resource) if quarantined else None
            if legacy_stop and db.execute("SELECT 1 FROM web_quarantine_recovery_debts WHERE resource IN (?,?) LIMIT 1",
                                          (resource, FOREGROUND_INPUT_RESOURCE)).fetchone():
                raise ControlError("computer_recovery_required")
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
            quarantined = (self._effective_quarantine(db, resource, target) or
                           self._effective_quarantine(db, FOREGROUND_INPUT_RESOURCE, front))
            legacy_stop = self._legacy_released_computer_stop(db, task, resource) if quarantined else None
            if legacy_stop and db.execute("SELECT 1 FROM web_quarantine_recovery_debts WHERE resource IN (?,?) LIMIT 1",
                                          (resource, FOREGROUND_INPUT_RESOURCE)).fetchone():
                raise ControlError("computer_recovery_required")
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

    def retire_owner(self, owner: str, *, release_orphan: bool = False):
        with self.transaction() as db:
            self._owner(db, owner, diagnostics=True)
            self._retire_owner(db, owner, release_orphan=release_orphan)

    def _retire_owner(self, db, owner: str, *, release_orphan: bool = False):
        db.execute("UPDATE owners SET retired=1 WHERE id=?", (owner,))
        task_row = db.execute("SELECT task FROM owners WHERE id=?", (owner,)).fetchone()
        task = task_row["task"] if task_row is not None else None
        claimed = [row[0] for row in db.execute(
            "SELECT resource FROM owned_resource_claims WHERE owner=?", (owner,))]
        if release_orphan:
            db.execute("DELETE FROM owned_resource_claims WHERE owner=?", (owner,))
        for action in db.execute("SELECT * FROM actions WHERE owner=? AND state='running'", (owner,)).fetchall():
            self._interrupt_action(db, action, "owner_retired")
            db.execute("UPDATE actions SET cancel_requested=1 WHERE id=?", (action["id"],))
        db.execute("UPDATE actions SET state='cancelled' WHERE owner=? AND state='queued'", (owner,))
        db.execute("UPDATE occupancy SET ended=? WHERE ended IS NULL AND action IN "
                   "(SELECT id FROM actions WHERE owner=?)", (self.clock(), owner))
        if task is not None and release_orphan:
            # A dead/EOF owner must not keep a target reserved after all of its
            # peers are gone. Preserve ownership for live peers and for any
            # still-unresolved effect on this exact resource.
            for resource in claimed:
                live_peer = db.execute(
                    "SELECT 1 FROM owned_resource_claims c JOIN owners o ON c.owner=o.id "
                    "WHERE c.resource=? AND o.retired=0 AND o.live_until>? LIMIT 1",
                    (resource, self.clock())).fetchone()
                unresolved = db.execute(
                    "SELECT 1 FROM actions a WHERE a.state IN ('queued','running','outcome_uncertain') "
                    "AND EXISTS (SELECT 1 FROM json_each(a.resources) WHERE value=?) LIMIT 1",
                    (resource,)).fetchone()
                if live_peer is None and unresolved is None:
                    db.execute("DELETE FROM owned_resources WHERE resource=? AND task=?",
                               (resource, task))
                    db.execute("UPDATE resources SET revision=revision+1 WHERE id=?", (resource,))
                    db.execute("UPDATE observations SET expires=0 WHERE resource=? AND task=?",
                               (resource, task))

    def revoke_task(self, task: str):
        with self.transaction() as db:
            db.execute("UPDATE tasks SET revoked=1,revision=revision+1 WHERE id=?", (task,))
            db.execute("DELETE FROM grants WHERE task=?", (task,))
            self._stop_task_actions(db, task)
            db.execute("UPDATE foreground_stages SET interruption='authorization_revoked' "
                       "WHERE action IN (SELECT id FROM actions WHERE task=?) AND lease_released IS NULL", (task,))

    def observe(self, owner: str, resource: str, generation: str, *, ttl: float = 15,
                purpose: str | None = None, policy_revision: str | None = None) -> str:
        # Only the internal App TextPattern page continuation needs the already
        # accepted 300s idle window. General/UIA references keep their defaults.
        maximum = 300 if purpose == "app_text_page" else 120
        if purpose not in (None, "app_text_page") or type(ttl) not in (int, float) or not 0 < ttl <= maximum or not generation:
            raise ControlError("invalid_observation")
        with self.transaction() as db:
            observed_policy = _permission_revision()
            if policy_revision is not None and observed_policy != policy_revision:
                raise ControlError("user_policy_requires_new_observation")
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
            db.execute("INSERT INTO observation_policy_revisions VALUES (?,?)", (observation, observed_policy))
            return observation

    def reserve_expired_app_write(self, owner: str, *, action_id: str, fingerprint: str,
                                  resource: str, scope: str, observation: str,
                                  generation: str, policy_revision: str, refresh_action: str,
                                  shared_resource: str | None, shared_revision: int | None) -> bool:
        """Atomically consume an expired App write ID without dispatching it."""
        with self.transaction() as db:
            connection = self._owner(db, owner)
            if db.execute("SELECT 1 FROM actions WHERE id=?", (action_id,)).fetchone():
                return False
            task = self._task(db, connection["task"])
            self._require_owned_resource(db, connection["task"], resource)
            self._require_scope(db, connection["task"], scope)
            old = db.execute("SELECT * FROM observations WHERE id=?", (observation,)).fetchone()
            row = db.execute("SELECT * FROM resources WHERE id=?", (resource,)).fetchone()
            old_policy = db.execute("SELECT revision FROM observation_policy_revisions WHERE observation=?", (observation,)).fetchone()
            old_epoch = db.execute("SELECT epoch FROM observation_write_epochs WHERE observation=?", (observation,)).fetchone()
            task_epoch = db.execute("SELECT epoch FROM task_write_epochs WHERE task=?", (connection["task"],)).fetchone()
            gate = self.write_gate.snapshot()
            if (task["paused"] or gate.stopped or not old or not row or not old_policy or not old_epoch
                    or old["task"] != connection["task"] or old["resource"] != resource
                    or not 0 < old["expires"] <= self.clock()
                    or old["revision"] != row["revision"] or old["generation"] != generation
                    or row["generation"] != generation or row["paused"] or self._effective_quarantine(db, resource, row)
                    or old_policy[0] != policy_revision or _permission_revision() != policy_revision
                    or old_epoch[0] != gate.epoch
                    or max(task_epoch[0] if task_epoch else 0, gate.resume_all_epoch) < gate.epoch):
                raise ControlError("observation_unavailable")
            now = self.clock()
            db.execute("INSERT INTO actions(id,owner,task,fingerprint,resources,scope,observation,"
                       "generation,state,created,updated,dispatched,result_code) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (action_id, owner, connection["task"], fingerprint, _json([resource]), scope,
                        observation, generation, "not_verified", now, now, 0, "observation_expired_reselection_required"))
            db.execute("INSERT INTO action_write_epochs VALUES (?,?)", (action_id, gate.epoch))
            db.execute("INSERT INTO action_policy_revisions VALUES (?,?)", (action_id, policy_revision))
            db.execute("INSERT INTO action_effects(action,read_only,activation_dispatched,business_dispatched,input_release) VALUES (?,0,0,0,NULL)", (action_id,))
            db.execute("INSERT INTO action_hints VALUES (?,?,NULL)", (action_id, Phase.WORK.value))
            db.execute("INSERT INTO action_context VALUES (?,?)", (action_id, "{}"))
            db.execute("INSERT INTO app_expired_refresh_reads VALUES (?,?,?,?,?)", (refresh_action,
                action_id, observation, shared_resource, shared_revision))
            self._record_event(db, "action_finished", task=connection["task"], action=action_id,
                               details={"state": "not_verified", "reason": "observation_expired_reselection_required"})
            return True

    def enqueue(self, owner: str, *, action_id: str, fingerprint: str, resources: tuple[str, ...],
                scope: str | None = None, observation: str | None = None,
                generation: str | None = None, phase: Phase = Phase.WORK,
                estimated_ms: int | None = None, context: dict | None = None,
                read_only: bool = False):
        result = self._enqueue(owner, action_id=action_id, fingerprint=fingerprint, resources=resources,
            scope=scope, observation=observation, generation=generation, phase=phase,
            estimated_ms=estimated_ms, context=context, read_only=read_only)
        from .call_cancellation import current_call_cancel, CallCancellation
        cancellation = current_call_cancel.get()
        if isinstance(cancellation, CallCancellation):
            cancellation.track(self, owner, action_id)
        return result

    def _enqueue(self, owner: str, *, action_id: str, fingerprint: str, resources: tuple[str, ...],
                 scope: str | None = None, observation: str | None = None,
                 generation: str | None = None, phase: Phase = Phase.WORK,
                 estimated_ms: int | None = None, context: dict | None = None,
                 read_only: bool = False):
        from .call_cancellation import call_cancelled
        if call_cancelled():
            raise ControlError("call_cancelled")
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
            db.execute("INSERT INTO action_policy_revisions VALUES (?,?)", (action_id, _permission_revision()))
            if read_only:
                db.execute("INSERT INTO action_effects VALUES (?,1,0,0,NULL)", (action_id,))
            db.execute("INSERT INTO action_hints VALUES (?,?,?)", (action_id, phase.value, estimated_ms))
            db.execute("INSERT INTO action_context VALUES (?,?)", (action_id, _json(context)))
            self._check_action(db, action, business_dependencies=False)
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

    def _check_action(self, db, action, *, business_dependencies=True):
        from .call_cancellation import call_cancelled
        if call_cancelled():
            raise ControlError("call_cancelled")
        from .business_plan import check_action
        check_action(db, action, dependencies=business_dependencies)
        policy_revision = _permission_revision()
        recorded = db.execute("SELECT revision FROM action_policy_revisions WHERE action=?", (action["id"],)).fetchone()
        if (recorded[0] if recorded else "absent") != policy_revision:
            raise ControlError("user_policy_requires_new_observation")
        if action["observation"]:
            recorded = db.execute("SELECT revision FROM observation_policy_revisions WHERE observation=?",
                                  (action["observation"],)).fetchone()
            if (recorded[0] if recorded else "absent") != policy_revision:
                raise ControlError("user_policy_requires_new_observation")
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
        refresh = db.execute("SELECT * FROM app_expired_refresh_reads WHERE action=?", (action["id"],)).fetchone()
        if refresh:
            parent = db.execute("SELECT task,state,result_code FROM actions WHERE id=?", (refresh["parent"],)).fetchone()
            original = db.execute("SELECT * FROM observations WHERE id=?", (refresh["source"],)).fetchone()
            original_epoch = db.execute("SELECT epoch FROM observation_write_epochs WHERE observation=?", (refresh["source"],)).fetchone()
            original_policy = db.execute("SELECT revision FROM observation_policy_revisions WHERE observation=?", (refresh["source"],)).fetchone()
            original_resource = db.execute("SELECT * FROM resources WHERE id=?", (original["resource"],)).fetchone() if original else None
            gate = self.write_gate.snapshot()
            delta = 1 if action["state"] == "running" else 0
            if (not read_only or not parent or parent["task"] != action["task"]
                    or parent["state"] != "not_verified" or parent["result_code"] != "observation_expired_reselection_required"
                    or not original or original["task"] != action["task"] or not 0 < original["expires"] <= self.clock()
                    or not original_epoch or gate.stopped or original_epoch[0] != gate.epoch
                    or not original_policy or original_policy[0] != policy_revision
                    or not original_resource or original_resource["revision"] != original["revision"] + delta
                    or original_resource["generation"] != original["generation"]
                    or original_resource["paused"] or self._effective_quarantine(db, original["resource"], original_resource)):
                raise ControlError("observation_unavailable")
            if refresh["shared_resource"] is not None:
                shared = db.execute("SELECT revision,paused,quarantined FROM resources WHERE id=?", (refresh["shared_resource"],)).fetchone()
                if (not shared or refresh["shared_revision"] is None or shared["revision"] != refresh["shared_revision"] + delta
                        or shared["paused"] or self._effective_quarantine(db, refresh["shared_resource"], shared)):
                    raise ControlError("observation_unavailable")
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
            if (row["paused"] and not binding or row["quarantined"] and not read_only
                    and not self._quarantine_permit_active(db, resource)
                    and not self._is_web_instance_close(db, action, resource)):
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

    @staticmethod
    def _is_web_instance_close(db, action, resource):
        """Narrow native lifecycle exception, never an ordinary Web write.

        Only the existing trusted close adapter can create this FINISH action.
        The exact empty close_browser fingerprint also binds the worker permit,
        so context metadata cannot authorize click/navigate/fill. This does not
        clear quarantine; closed-process evidence must establish recovery later.
        """
        from .worker_call import command_hash
        if (not action["id"].startswith("web-close:")
                or len(action["id"]) != len("web-close:") + 32
                or action["fingerprint"] != command_hash("close_browser", {})
                or json.loads(action["resources"]) != [resource]
                or not resource.startswith(("web-profile:", "web-session:", "web-borrower:"))):
            return False
        hint = db.execute("SELECT phase FROM action_hints WHERE action=?", (action["id"],)).fetchone()
        context = db.execute("SELECT details FROM action_context WHERE action=?", (action["id"],)).fetchone()
        return (hint is not None and hint[0] == Phase.FINISH.value and context is not None
                and json.loads(context[0]) == {"channel":"web", "operation":"close_browser",
                                             "foreground_needed":False})

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
        history = [row for row in db.execute("SELECT rowid AS turn_sequence,* FROM occupancy WHERE ended IS NULL OR ended>?",
                                            (now - 30,)).fetchall()
                   if set(domain).intersection(json.loads(row["resources"]))]
        used = {}
        for row in history:
            elapsed = max(0, (row["ended"] or now) - max(row["started"], now - 30))
            used[row["task"]] = used.get(row["task"], 0) + int(elapsed * 1000)
        resource_turns = {}
        for row in history:
            # Every actual use of this conflict domain consumes a turn. A
            # background-only request sharing the same target must not retain
            # perpetual "never used foreground" priority over waiting input.
            resource_turns[row["task"]] = max(resource_turns.get(row["task"], 0), row["turn_sequence"])
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
            action = db.execute("SELECT rowid AS queued_sequence,* FROM actions WHERE id=?", (action_id,)).fetchone()
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
                                    None, local_jev_enabled and self._task_jev_allowed(db, task["id"]), True,
                                    queued_sequence=action["queued_sequence"],
                                    last_resource_turn=resource_turns.get(task["id"]), **candidate_context))
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
        from .call_cancellation import call_cancelled
        if call_cancelled():
            raise ControlError("call_cancelled")
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
        for running in db.execute("SELECT * FROM actions WHERE state='running'"):
            if set(resources).intersection(self._running_resources(db, running)):
                raise ControlError("resource_execution_unresolved")
        context = db.execute("SELECT details FROM action_context WHERE action=?", (action_id,)).fetchone()
        context = json.loads(context[0]) if context else {}
        borrowers = [resource for resource in resources if resource.startswith("web-borrower:")]
        if (context.get("channel") == "web" and context.get("operation") == "new_page"
                and len(borrowers) == 1):
            # Record the actual checked resource revisions before dispatch.
            # The baseline cannot be reconstructed from later screenshots or
            # from a previous action's uncertain receipt.
            for resource in resources:
                revision = db.execute("SELECT revision FROM resources WHERE id=?", (resource,)).fetchone()
                if revision is None:
                    raise ControlError("resource_not_found")
                db.execute("INSERT INTO web_create_resource_baselines VALUES (?,?,?)",
                           (action_id, resource, revision[0]))
                db.execute("INSERT OR IGNORE INTO web_recovery_resource_counts(resource) VALUES (?)", (resource,))
                db.execute("INSERT INTO web_recovery_count_baselines "
                           "SELECT ?,resource,dispatches,quarantines,reissues FROM web_recovery_resource_counts WHERE resource=?",
                           (action_id, resource))
        if (context.get("channel") == "computer" and context.get("operation") == "key"
                and len(resources) == 2 and FOREGROUND_INPUT_RESOURCE in resources):
            for resource in resources:
                db.execute("INSERT OR IGNORE INTO web_recovery_resource_counts(resource) VALUES (?)", (resource,))
                db.execute("INSERT INTO computer_stop_count_baselines "
                           "SELECT ?,r.id,r.revision,c.dispatches,c.quarantines,c.reissues FROM resources r "
                           "JOIN web_recovery_resource_counts c ON c.resource=r.id WHERE r.id=?", (action_id, resource))
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
        except ControlError as error:
            if error.code == "call_cancelled":
                self.cancel(owner, action_id)
            raise
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
                                   "lease_released=COALESCE(lease_released,?) WHERE action=?", (now, now, action_id))

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
                metadata_binding = self._metadata_binding(db, action_id)
                self._dispatch_threads[action_id] = threading.get_ident()
                self._external_dispatches[action_id] = lease
                self._external_native_dispatches[(id(self), action_id)] = lease
                self._bind_external_ledger(db, action_id, lease)
                self._external_pending(owner, action_id, lease, _db=db)
                began = True
            # Publish the exception only after the running action committed.
            if metadata_binding and self._external_dispatches.get(action_id) is lease:
                self._external_metadata_bindings[action_id] = (owner, lease)
            # Durable pre-go uncertainty; only this exact helper's terminal
            # native receipt may confirm its ledger. Exit is not a receipt.
            yield action
        except ControlError as error:
            if error.code == "call_cancelled":
                self.cancel(owner, action_id)
            raise
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
                                   "lease_released=CASE WHEN ? THEN COALESCE(lease_released,?) ELSE lease_released END WHERE action=?",
                                   (now, bool(lease.result and lease.result["MutexReleased"]), now, action_id))
                finally:
                    self._dispatch_threads.pop(action_id, None)
                    self._external_dispatches.pop(action_id, None)
                    self._external_metadata_bindings.pop(action_id, None)
                    if not lease.wait_requires_yield(FOREGROUND_INPUT_RESOURCE):
                        self._external_native_dispatches.pop((id(self), action_id), None)
            elif self._external_dispatches.get(action_id) is lease:
                self._dispatch_threads.pop(action_id, None)
                self._external_dispatches.pop(action_id, None)
                self._external_metadata_bindings.pop(action_id, None)
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
        self._external_effects(owner, action_id,
            result["ActivationRequested"] or bool(result.get("KeyboardReleaseEvents", 0)), business, result["InputRelease"])
        with self.transaction() as db:
            db.execute("INSERT OR IGNORE INTO action_pointer_receipts VALUES (?,?,?)",
                       (lease.ledger_identity, action_id, result.get("PointerEvents", 0)))
            pointer_events = db.execute("SELECT COALESCE(SUM(events),0) FROM action_pointer_receipts WHERE action=?", (action_id,)).fetchone()[0]
            db.execute("INSERT OR REPLACE INTO action_pointer_effects VALUES (?,?)", (action_id, pointer_events))
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
            self.quarantine(lease.resources, action_id=action_id)
        if layout is not None and layout["DispatchAttempted"] and (layout["CallReturned"] is not True or result["SemanticExecutorExited"] is not True):
            self.quarantine(tuple(r for r in lease.resources if r != FOREGROUND_INPUT_RESOURCE), action_id=action_id)

    def external_sequence(self, owner, action_id, decision_id, *, total_steps):
        """Keep one action alive across 2..3 separately checked native requests.

        Use chain.before_go as the facade callback. The consumer still owns
        start/begin/finish sequence progress, fresh captures, expect and Stop.
        """
        return _ExternalSequence(self, owner, action_id, decision_id, total_steps)

    def begin_sequence_final_readback(self, owner, action_id, *, binding=None, verify=None):
        from .sequence_readback import begin
        return begin(self, owner, action_id, binding=binding, verify=verify)

    @staticmethod
    def _running_resources(db, action):
        from .sequence_readback import foreground_released
        resources = json.loads(action["resources"])
        if foreground_released(db, action):
            return [resource for resource in resources if resource != FOREGROUND_INPUT_RESOURCE]
        return resources

    def external_release_pending(self, owner, action_id):
        """The fresh owner can recover only a persisted exact task/action ledger."""
        with self.transaction() as db:
            connection = self._owner(db, owner)
            action = db.execute("SELECT * FROM actions WHERE id=? AND task=?", (action_id, connection["task"])).fetchone()
            binding = db.execute("SELECT * FROM input_release_bindings WHERE action=?", (action_id,)).fetchone()
            if not action or not binding:
                raise ControlError("external_release_binding_missing")
            old = db.execute("SELECT process FROM owners WHERE id=?", (action["owner"],)).fetchone()
            if (action["state"] in {"queued", "running"} and action["owner"] != owner
                    and old and process_is_alive(old[0])):
                raise ControlError("external_dispatcher_still_alive")
            if action_id in self._dispatch_threads:
                raise ControlError("external_dispatcher_still_alive")
            # Querying a terminal ledger is not transferring execution authority.
            # An authenticated exact completion is still required for adoption.
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
            action = db.execute("SELECT resources FROM actions WHERE id=? AND task=?",
                                (action_id, expected["task_id"])).fetchone()
            if action is None:
                raise ControlError("external_release_binding_missing")
            resources = tuple(json.loads(action["resources"]))
        try:
            with ExecutionLocks(resources):
                with self.transaction() as db:
                    connection = self._owner(db, owner)
                    action = db.execute("SELECT * FROM actions WHERE id=? AND task=?", (action_id, connection["task"])).fetchone()
                    binding = db.execute("SELECT * FROM input_release_bindings WHERE action=?", (action_id,)).fetchone()
                    if (action is None or binding is None or tuple(json.loads(action["resources"])) != resources
                            or binding["executor_process"] != recovery.executor_process
                            or binding["ledger_identity"] != recovery.ledger_identity):
                        raise ControlError("input_release_binding_mismatch")
                    old = db.execute("SELECT process FROM owners WHERE id=?", (action["owner"],)).fetchone()
                    old_alive = old is not None and process_is_alive(old[0])
                    if (action_id in self._dispatch_threads
                            or action["state"] in {"queued", "running"} and old_alive):
                        raise ControlError("external_dispatcher_still_alive")
                    if old_alive and recovery.semantic_executor_exited is False and not recovery.physical_input_free:
                        raise ControlError("external_dispatcher_still_alive")
                    for running in db.execute("SELECT * FROM actions WHERE state='running'"):
                        if running["id"] != action_id and set(resources).intersection(self._running_resources(db, running)):
                            raise ControlError("release_execution_not_quiescent")
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
        except (ResourceBusy, AbandonedResource):
            raise ControlError("release_execution_not_quiescent") from None
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
        metadata_binding = self._external_metadata_bindings.get(action_id)
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
        if (metadata_binding == (owner, previous)
                and self._external_metadata_bindings.get(action_id) is metadata_binding
                and self._external_dispatches.get(action_id) is lease):
            self._external_metadata_bindings[action_id] = (owner, lease)

    def start_computer_sequence(self, owner: str, action_id: str, total_steps: int) -> None:
        if type(total_steps) is not int or not 2 <= total_steps <= 8:
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
                self._quarantine_for_action(db, resource, action["id"])

    @staticmethod
    def _quarantine_for_action(db, resource, action_id):
        db.execute("UPDATE resources SET quarantined=1,revision=revision+1 WHERE id=?", (resource,))
        db.execute("UPDATE web_worker_quarantine_incidents SET action=? WHERE resource=? AND revision="
                   "(SELECT revision FROM resources WHERE id=?) AND action IS NULL", (action_id, resource, resource))
        # The trigger captures old clients and unidentified isolation too. Only
        # this transaction can bind a new incident to its actual action.
        db.execute("UPDATE web_quarantine_incidents SET action=? WHERE resource=? AND revision="
                   "(SELECT revision FROM resources WHERE id=?) AND action IS NULL",
                   (action_id, resource, resource))

    def _uncertain_resources(self, db, action):
        resources = self._running_resources(db, action)
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
                              input_release: str | None = None, pointer_events: int | None = None):
        """Driver evidence only, after actual effects; missing evidence stays unknown.

        Do not record False before calling an API that may write. True is
        monotonic; later read failures cannot erase the already sent prefix.
        """
        if (activation_dispatched is not None and type(activation_dispatched) is not bool
                or business_dispatched is not None and type(business_dispatched) is not bool
                or input_release not in (None, "released", "unknown", "release_pending")
                or pointer_events is not None and (type(pointer_events) is not int or pointer_events < 0)):
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
            if pointer_events is not None:
                if pointer_events and (row["read_only"] or FOREGROUND_INPUT_RESOURCE not in json.loads(action["resources"])):
                    raise ControlError("read_only_effect_conflict")
                old_pointer = db.execute("SELECT events FROM action_pointer_effects WHERE action=?", (action_id,)).fetchone()
                if old_pointer and pointer_events < old_pointer[0]:
                    raise ControlError("action_effect_regression")
                db.execute("INSERT OR REPLACE INTO action_pointer_effects VALUES (?,?)", (action_id, pointer_events))
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
        targets = db.execute("SELECT id,paused,quarantined FROM resources WHERE id IN ("
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
            recovery_required=any(self._effective_quarantine(db, row["id"], row) for row in targets),
            input_release=release, result_code=current["result_code"],
            effects={"activation_dispatched": None if effects["activation_dispatched"] is None else bool(effects["activation_dispatched"]),
                     "business_dispatched": None if effects["business_dispatched"] is None else bool(effects["business_dispatched"]),
                     "input_release": release} if effects else None)
        stage["feedback"]["input_release"] = release
        if not effects:
            return stage
        activation = None if effects["activation_dispatched"] is None else bool(effects["activation_dispatched"])
        business = None if effects["business_dispatched"] is None else bool(effects["business_dispatched"])
        pointer = db.execute("SELECT events FROM action_pointer_effects WHERE action=?", (action["id"],)).fetchone()
        pointer_events = pointer[0] if pointer else 0
        dispatched = True if activation is True or business is True or pointer_events else (
            False if activation is False and business is False else None)
        return {**stage, "read_only": bool(effects["read_only"]), "execution_started": bool(action["dispatched"]),
                "activation_dispatched": activation, "business_dispatched": business,
                "dispatched": dispatched, "pointer_events": pointer_events,
                "input_release": effects["input_release"]}

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
                    self._quarantine_for_action(db, resource, action_id)

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

    def record_worker_completion(self, action_id: str, token: str, command_hash: str):
        """Worker-only terminal fact, not a business receipt or new authority.

        A successful command can finish after its parent loses the IPC reply.
        Preserve that fact before publication; never change the old unknown or
        clear Stop. Tokens, exact process identity and the consumed immutable
        command permit still bind this late, non-executing observation.
        """
        with self.transaction() as db:
            permit = db.execute("SELECT * FROM worker_permits WHERE action=?", (action_id,)).fetchone()
            identity = process_identity()
            if (not permit or not permit["consumed"] or permit["worker_process"] != identity
                    or permit["command_hash"] != command_hash
                    or permit["token_hash"] != hashlib.sha256(token.encode()).hexdigest()):
                raise ControlError("worker_permit_mismatch")
            db.execute("INSERT OR IGNORE INTO worker_completions VALUES (?,?,?)", (action_id, identity, command_hash))

    def check_dispatch(self, owner: str, action_id: str):
        if self._dispatch_threads.get(action_id) != threading.get_ident():
            raise ControlError("check_requires_dispatch_thread")
        with self.read_transaction() as db:
            self._owner(db, owner)
            row = db.execute("SELECT * FROM actions WHERE id=? AND owner=?", (action_id, owner)).fetchone()
            self._check_running_action(db, row)

    def external_dispatch_stopped(self, owner: str, action_id: str) -> bool:
        """Thread-safe existing scope/Stop checks for the helper pipe watcher."""
        stopped = self.write_stopped()
        if stopped:
            binding = self._external_metadata_bindings.get(action_id)
            if (binding is None or binding[0] != owner
                    or self._external_dispatches.get(action_id) is not binding[1]):
                return True
        if action_id not in self._external_dispatches:
            return True
        try:
            with self.read_transaction() as db:
                if stopped and not self._metadata_binding(db, action_id):
                    return True
                self._owner(db, owner)
                row = db.execute("SELECT * FROM actions WHERE id=? AND owner=?", (action_id, owner)).fetchone()
                self._check_running_action(db, row)
            return False
        except ControlError:
            return True

    def quarantine(self, resources: tuple[str, ...], *, action_id: str | None = None):
        with self.transaction() as db:
            for resource in resources:
                db.execute("INSERT OR IGNORE INTO resources(id) VALUES (?)", (resource,))
                if action_id is None:
                    db.execute("UPDATE resources SET quarantined=1,revision=revision+1 WHERE id=?", (resource,))
                else:
                    self._quarantine_for_action(db, resource, action_id)
            self._record_event(db, "resource_quarantined", action=action_id, details={"resources": list(resources)})

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
                self._retire_owner(db, owner, release_orphan=True)
        return len(dead)

    def _migrate_web_recovery_evidence(self, db):
        """Retain old evidence only while its complete diagnostic interval exists."""
        if db.execute("SELECT 1 FROM meta WHERE key='web_recovery_counts_v1'").fetchone():
            return
        db.execute("INSERT OR IGNORE INTO web_recovery_dispatch_order "
                   "SELECT e.action,e.seq FROM control_events e JOIN actions a ON a.id=e.action "
                   "WHERE e.event='action_dispatched' AND a.state IN ('running','outcome_uncertain')")
        for action in db.execute("SELECT * FROM actions WHERE state='outcome_uncertain'").fetchall():
            baselines = db.execute("SELECT * FROM web_create_resource_baselines WHERE action=?", (action["id"],)).fetchall()
            event = db.execute("SELECT seq FROM control_events WHERE event='action_dispatched' AND action=?", (action["id"],)).fetchone()
            resources = json.loads(action["resources"])
            if not event or {r["resource"] for r in baselines} != set(resources):
                continue
            dispatches = [json.loads(r[0]) for r in db.execute(
                "SELECT a.resources FROM control_events e JOIN actions a ON a.id=e.action "
                "WHERE e.event='action_dispatched' AND e.seq>=?", (event[0],))]
            prepared = []
            for baseline in baselines:
                resource = baseline["resource"]
                current = db.execute("SELECT revision,quarantined FROM resources WHERE id=?", (resource,)).fetchone()
                incidents = db.execute("SELECT COUNT(*) FROM web_quarantine_incidents WHERE resource=? AND revision>? "
                                       "AND (action IS NULL OR action<>?)", (resource, baseline["revision"], action["id"])).fetchone()[0]
                event_type = 'web_foreground_refreshed' if resource == FOREGROUND_INPUT_RESOURCE else 'web_borrower_refreshed'
                reissues = db.execute("SELECT COUNT(*) FROM control_events WHERE action=? AND seq>=? "
                                      "AND event IN ('web_creation_recovered',?)", (action["id"], event[0], event_type)).fetchone()[0]
                count = sum(resource in values for values in dispatches)
                if not current or not current["quarantined"] or current["revision"] != baseline["revision"] + count + 1 + incidents + reissues:
                    break
                prepared.append((resource, count, 1 + incidents, reissues))
            else:
                for resource, count, quarantines, reissues in prepared:
                    db.execute("INSERT OR IGNORE INTO web_recovery_resource_counts(resource) VALUES (?)", (resource,))
                    db.execute("INSERT OR IGNORE INTO web_recovery_count_baselines "
                               "SELECT ?,resource,dispatches-?,quarantines-?,reissues-? FROM web_recovery_resource_counts WHERE resource=?",
                               (action["id"], count, quarantines, reissues, resource))
                    if reissues:
                        db.execute("INSERT OR REPLACE INTO web_recovery_reissues VALUES (?,?,?)", (action["id"], resource, reissues))
        for row in db.execute("SELECT p.id,p.action,p.browser_process,p.target,r.action AS close_action,MIN(e.seq) AS seq "
                              "FROM web_created_targets p JOIN web_target_close_receipts r ON r.pending=p.id "
                              "JOIN actions c ON c.id=r.action AND c.state='verified' "
                              "JOIN control_events e ON e.action=p.action AND e.event='web_creation_recovered' "
                              "WHERE p.state='closed' AND p.target=r.target AND p.browser_process=r.browser_process "
                              "AND p.resource=r.resource GROUP BY p.id").fetchall():
            db.execute("INSERT OR IGNORE INTO web_creation_recovery_proofs VALUES (?,?,?,?,?)",
                       (row["id"], row["action"], row["close_action"], row["browser_process"], row["target"]))
            db.execute("INSERT OR IGNORE INTO web_recovery_proof_order VALUES (?,?)", (row["id"], row["seq"]))
        db.execute("INSERT INTO meta VALUES ('web_recovery_counts_v1','1')")

    def recover_closed_web_creation(self, owner: str, pending_id: str):
        """Recover only an exactly closed shared-Web creation, never its result.

        This internal adapter requires a worker-issued exact close receipt and
        revisions captured before the original dispatch. Older unknown actions
        without these facts deliberately keep their existing quarantine.
        """
        if type(pending_id) is not str or not pending_id or len(pending_id) > 128:
            raise ControlError("web_recovery_evidence_missing")
        with self.read_transaction() as db:
            row = db.execute("SELECT a.resources FROM web_created_targets p "
                             "JOIN actions a ON a.id=p.action WHERE p.id=?", (pending_id,)).fetchone()
            if row is None:
                raise ControlError("web_recovery_evidence_missing")
            resources = tuple(json.loads(row[0]))
        if not resources or len(resources) > 2:
            raise ControlError("web_recovery_evidence_missing")
        try:
            with ExecutionLocks(resources), self.transaction() as db:
                connection = self._owner(db, owner)
                pending = db.execute("SELECT * FROM web_created_targets WHERE id=?", (pending_id,)).fetchone()
                original = db.execute("SELECT * FROM actions WHERE id=?", (pending["action"],)).fetchone() if pending else None
                receipt = db.execute("SELECT * FROM web_target_close_receipts WHERE pending=?", (pending_id,)).fetchone()
                close = db.execute("SELECT * FROM actions WHERE id=?", (receipt["action"],)).fetchone() if receipt else None
                if (not pending or not original or not receipt or not close or pending["task"] != connection["task"]
                        or original["task"] != connection["task"] or close["task"] != connection["task"]
                        or close["owner"] != owner or close["state"] != "verified"
                        or original["state"] != "outcome_uncertain" or not original["dispatched"]
                        or tuple(json.loads(original["resources"])) != resources
                        or pending["resource"] not in resources or not pending["resource"].startswith("web-borrower:")
                        or pending["state"] != "closed" or not pending["target"]
                        or receipt["resource"] != pending["resource"]
                        or receipt["browser_process"] != pending["browser_process"]
                        or receipt["target"] != pending["target"]
                        or not self._is_web_instance_close(db, close, pending["resource"])):
                    raise ControlError("web_recovery_evidence_missing")
                context = db.execute("SELECT details FROM action_context WHERE action=?", (original["id"],)).fetchone()
                context = json.loads(context[0]) if context else {}
                if context.get("channel") != "web" or context.get("operation") != "new_page":
                    raise ControlError("web_recovery_evidence_missing")
                for action in (original, close):
                    permit = db.execute("SELECT * FROM worker_permits WHERE action=?", (action["id"],)).fetchone()
                    if (not permit or not permit["consumed"] or permit["command_hash"] != action["fingerprint"]
                            or process_is_alive(permit["worker_process"])):
                        raise ControlError("web_recovery_executor_unverified")
                if not process_is_verified_alive(pending["browser_process"]):
                    raise ControlError("web_recovery_browser_unverified")
                task = self._task(db, connection["task"])
                gate = self.write_gate.snapshot()
                original_epoch = db.execute("SELECT epoch FROM action_write_epochs WHERE action=?", (original["id"],)).fetchone()
                task_epoch = db.execute("SELECT epoch FROM task_write_epochs WHERE task=?", (connection["task"],)).fetchone()
                policy = db.execute("SELECT revision FROM action_policy_revisions WHERE action=?", (original["id"],)).fetchone()
                if (task["paused"] or gate.stopped or not original_epoch or original_epoch[0] != gate.epoch
                        or max(task_epoch[0] if task_epoch else 0, gate.resume_all_epoch) < gate.epoch
                        or not policy or policy[0] != _permission_revision()):
                    raise ControlError("web_recovery_state_changed")
                self._require_scope(db, connection["task"], original["scope"])
                effects = db.execute("SELECT * FROM action_effects WHERE action=?", (original["id"],)).fetchone()
                if (not effects or effects["read_only"] or effects["activation_dispatched"] != 0
                        or effects["input_release"] not in (("released",) if FOREGROUND_INPUT_RESOURCE in resources else (None, "released"))):
                    raise ControlError("web_recovery_input_unverified")
                if FOREGROUND_INPUT_RESOURCE in resources:
                    self._require_input_release_confirmed(db)
                event = db.execute("SELECT seq FROM web_recovery_dispatch_order WHERE action=?", (original["id"],)).fetchone()
                if event is None:
                    event = db.execute("SELECT seq FROM control_events WHERE event='action_dispatched' AND action=?", (original["id"],)).fetchone()
                baselines = {row["resource"]: row["revision"] for row in db.execute(
                    "SELECT resource,revision FROM web_create_resource_baselines WHERE action=?", (original["id"],))}
                if not event or set(baselines) != set(resources):
                    raise ControlError("web_recovery_evidence_missing")
                durable = {row["resource"]: row for row in db.execute(
                    "SELECT * FROM web_recovery_count_baselines WHERE action=?", (original["id"],))}
                if durable and set(durable) != set(resources):
                    raise ControlError("web_recovery_evidence_missing")
                for quarantine in db.execute("SELECT details FROM control_events WHERE event='resource_quarantined' AND seq>=?", (event[0],)):
                    if set(resources).intersection(json.loads(quarantine[0])["resources"]):
                        raise ControlError("web_recovery_other_quarantine")
                for other in db.execute("SELECT rowid AS record_order,* FROM actions WHERE state IN ('running','outcome_uncertain')"):
                    if other["id"] == original["id"] or not set(resources).intersection(json.loads(other["resources"])):
                        continue
                    order = db.execute("SELECT seq FROM web_recovery_dispatch_order WHERE action=?", (other["id"],)).fetchone()
                    later = (order[0] >= event[0]) if order else db.execute("SELECT 1 FROM control_events WHERE action=? AND event IN ('action_dispatched','action_finished') AND seq>=? LIMIT 1",
                                       (other["id"], event[0])).fetchone()
                    if durable and not order and not later:
                        raise ControlError("web_recovery_other_quarantine")
                    if other["state"] == "running" or later:
                        raise ControlError("web_recovery_other_quarantine")
                dispatches = [json.loads(row[0]) for row in db.execute(
                    "SELECT a.resources FROM control_events e JOIN actions a ON a.id=e.action "
                    "WHERE e.event='action_dispatched' AND e.seq>=?", (event[0],))]
                for resource in resources:
                    row = db.execute("SELECT * FROM resources WHERE id=?", (resource,)).fetchone()
                    count = sum(resource in values for values in dispatches)
                    if durable:
                        totals = db.execute("SELECT * FROM web_recovery_resource_counts WHERE resource=?", (resource,)).fetchone()
                        base = durable[resource]
                        if (not totals or totals["quarantines"] - base["quarantines"] != 1
                                or totals["reissues"] != base["reissues"]):
                            raise ControlError("web_recovery_other_quarantine")
                        count = totals["dispatches"] - base["dispatches"]
                    if (not row or row["paused"] or not row["quarantined"]
                            or row["revision"] != baselines[resource] + count + 1):
                        raise ControlError("web_recovery_state_changed")
                    self._require_owned_resource(db, connection["task"], resource)
                    self._require_scope(db, connection["task"], row["required_scope"])
                    prior_debt = db.execute("SELECT pending FROM web_quarantine_recovery_debts WHERE resource=?", (resource,)).fetchone()
                    if prior_debt and prior_debt[0] != pending_id:
                        # The later action was admitted only while the earlier
                        # debt had a valid permit. Prove that recovery predates
                        # this dispatch, and that its sole new isolation is this
                        # exact creation. Preserve both unknown receipts.
                        prior = db.execute("SELECT 1 FROM web_recovery_proof_order WHERE pending=? AND seq<?", (prior_debt[0], event[0])).fetchone()
                        prior = prior or db.execute("SELECT 1 FROM web_created_targets p JOIN control_events e ON e.action=p.action "
                                           "WHERE p.id=? AND e.event='web_creation_recovered' AND e.seq<?",
                                           (prior_debt[0], event[0])).fetchone()
                        incidents = db.execute("SELECT action,revision FROM web_quarantine_incidents "
                                               "WHERE resource=? AND revision>? ORDER BY revision",
                                               (resource, baselines[resource])).fetchall()
                        if (not prior or len(incidents) != 1 or incidents[0]["action"] != original["id"]
                                or incidents[0]["revision"] != baselines[resource] + 2):
                            raise ControlError("web_recovery_other_quarantine")
                owned = db.execute("SELECT task FROM owned_resources WHERE resource=?", (pending["resource"],)).fetchone()
                if not owned or owned[0] != connection["task"]:
                    raise ControlError("web_recovery_evidence_missing")
                # Queued work is never silently revived after an unknown action.
                for queued in db.execute("SELECT id,resources FROM actions WHERE state='queued'").fetchall():
                    if set(resources).intersection(json.loads(queued["resources"])):
                        db.execute("UPDATE actions SET state='cancelled',updated=? WHERE id=?", (self.clock(), queued["id"]))
                for resource in resources:
                    db.execute("UPDATE resources SET generation=?,revision=revision+1 WHERE id=?",
                               ("closed-web:" + pending_id, resource))
                    db.execute("INSERT OR REPLACE INTO web_quarantine_recovery_debts(resource,pending) VALUES (?,?)",
                               (resource, pending_id))
                    db.execute("INSERT OR REPLACE INTO web_quarantine_recovery_permits(resource,pending,epoch,boot,keeper) VALUES (?,?,?,?,?)",
                               (resource, pending_id, gate.epoch, self.boot, connection["process"]))
                db.execute("INSERT OR IGNORE INTO web_creation_recovery_proofs VALUES (?,?,?,?,?)",
                           (pending_id, original["id"], close["id"], pending["browser_process"], pending["target"]))
                proof = db.execute("SELECT * FROM web_creation_recovery_proofs WHERE pending=?", (pending_id,)).fetchone()
                if (not proof or proof["action"] != original["id"] or proof["close_action"] != close["id"]
                        or proof["browser_process"] != pending["browser_process"] or proof["target"] != pending["target"]):
                    raise ControlError("web_recovery_evidence_missing")
                db.execute("UPDATE observations SET expires=0 WHERE task=?", (connection["task"],))
                self._record_event(db, "web_creation_recovered", task=connection["task"], action=original["id"],
                                   details={"original_state_preserved": True, "new_observation_required": True})
                db.execute("INSERT OR IGNORE INTO web_recovery_proof_order VALUES (?,(SELECT MAX(seq) FROM control_events))", (pending_id,))
            with self.read_transaction() as db:
                still_active = all(self._quarantine_permit_active(db, resource) for resource in resources)
            if not still_active:
                return {"recovered": False, "reason": "web_recovery_stop_epoch_changed",
                        "original_action_outcome": "outcome_uncertain", "old_clients_remain_quarantined": True}
            return {"recovered": True, "original_action_outcome": "outcome_uncertain",
                    "new_observation_required": True, "old_clients_remain_quarantined": True}
        except (ResourceBusy, AbandonedResource):
            raise ControlError("recovery_execution_not_quiescent") from None

    def refresh_closed_web_borrower(self, owner: str, resource: str):
        """Revalidate the same chat's exact closed page after resume/EOF."""
        if type(resource) is not str or not resource.startswith("web-borrower:"):
            raise ControlError("web_recovery_evidence_missing")
        from .foreground_recovery import _closed_web_resource_evidence
        try:
            with ExecutionLocks((resource,)), self.transaction() as db:
                connection = self._owner(db, owner)
                task = self._task(db, connection["task"])
                row = db.execute("SELECT * FROM resources WHERE id=?", (resource,)).fetchone()
                owned = db.execute("SELECT task FROM owned_resources WHERE resource=?", (resource,)).fetchone()
                if not row or not owned or owned[0] != connection["task"] or task["paused"]:
                    raise ControlError("web_recovery_state_changed")
                if self._quarantine_permit_active(db, resource):
                    return {"recovered": True, "new_observation_required": True}
                gate = self.write_gate.snapshot()
                task_epoch = db.execute("SELECT epoch FROM task_write_epochs WHERE task=?", (connection["task"],)).fetchone()
                if (gate.stopped or max(task_epoch[0] if task_epoch else 0, gate.resume_all_epoch) < gate.epoch):
                    raise ControlError("global_write_stopped")
                self._require_scope(db, connection["task"], row["required_scope"])
                pending_id, action_id, _ = _closed_web_resource_evidence(self, db, resource)
                pending = db.execute("SELECT task FROM web_created_targets WHERE id=?", (pending_id,)).fetchone()
                original = db.execute("SELECT scope FROM actions WHERE id=?", (action_id,)).fetchone()
                policy = db.execute("SELECT revision FROM action_policy_revisions WHERE action=?", (action_id,)).fetchone()
                if (not pending or pending[0] != connection["task"] or not original
                        or not policy or policy[0] != _permission_revision()):
                    raise ControlError("web_recovery_state_changed")
                self._require_scope(db, connection["task"], original["scope"])
                for queued in db.execute("SELECT id,resources FROM actions WHERE state='queued'").fetchall():
                    if resource in json.loads(queued["resources"]):
                        db.execute("UPDATE actions SET state='cancelled',updated=? WHERE id=?", (self.clock(), queued["id"]))
                db.execute("UPDATE resources SET revision=revision+1 WHERE id=?", (resource,))
                db.execute("INSERT OR REPLACE INTO web_quarantine_recovery_permits(resource,pending,epoch,boot,keeper) VALUES (?,?,?,?,?)",
                           (resource, pending_id, gate.epoch, self.boot, connection["process"]))
                db.execute("UPDATE observations SET expires=0 WHERE task=? AND resource=?", (connection["task"], resource))
                self._record_event(db, "web_borrower_refreshed", task=connection["task"], action=action_id,
                                   details={"original_state_preserved": True, "new_observation_required": True})
            with self.read_transaction() as db:
                active = self._quarantine_permit_active(db, resource)
            return {"recovered": active, "new_observation_required": True,
                    **({} if active else {"reason": "web_recovery_stop_epoch_changed"})}
        except (ResourceBusy, AbandonedResource):
            raise ControlError("recovery_execution_not_quiescent") from None

    def recover_resources(self, resources: tuple[str, ...], probe: Callable[[], dict[str, str]], *, validate_commit=None):
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
                        if db.execute("SELECT 1 FROM web_quarantine_recovery_debts WHERE resource=?", (resource,)).fetchone():
                            raise ControlError("web_recovery_epoch_bound")
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
                    if validate_commit is not None:
                        validate_commit(db)
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

    def _require_input_release_confirmed(self, db, *, task=None, action_prefix=None):
        """Block live-context debt; an observed new Windows boot is distinct
        from claiming that the old executor ever released its input.
        """
        if self._pending_input_release_rows(db, task=task, action_prefix=action_prefix):
            raise ControlError("input_release_unconfirmed")

    def _pending_input_release_rows(self, db, *, task=None, action_prefix=None):
        pending = db.execute("SELECT * FROM (" +
            "SELECT a.id,a.task,a.resources FROM actions a JOIN action_effects e ON e.action=a.id "
            "WHERE e.input_release IN ('unknown','release_pending') UNION ALL "
            "SELECT a.id,a.task,a.resources FROM actions a JOIN computer_sequence_progress p ON p.action=a.id "
            "WHERE p.input_release IN ('unknown','release_pending') UNION ALL "
            "SELECT a.id,a.task,a.resources FROM actions a JOIN input_release_bindings b ON b.action=a.id "
            "WHERE b.confirmed IS NULL) WHERE (? IS NULL OR task=?) "
            "AND (? IS NULL OR substr(id,1,length(?))=?)", (task, task, action_prefix, action_prefix, action_prefix)).fetchall()
        from .input_boot import context_was_reset
        active_boot = boot_identity() if self._native_boot else None
        stored_boot = db.execute("SELECT value FROM meta WHERE key='boot'").fetchone()
        native_current = active_boot == self.boot and stored_boot is not None and stored_boot[0] == self.boot
        unresolved = {}
        for row in pending:
            if FOREGROUND_INPUT_RESOURCE not in json.loads(row["resources"]):
                continue
            reset = db.execute("SELECT r.*,f.boot AS stage_boot FROM input_context_resets r "
                               "JOIN foreground_stages f ON f.action=r.action WHERE r.action=?",
                               (row["id"],)).fetchone()
            if not native_current or reset is None or not context_was_reset(reset, active_boot):
                unresolved[row["id"]] = row
        return list(unresolved.values())

    def diagnostic_action_for_task(self, task: str, action_id: str, *, cancel: bool = False, reason="explicit_stop"):
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
                self._mark_stage_interruption(db, action_id, reason)
                return {"state": state, "stop_received": reason == "explicit_stop", "interruption": reason, "in_flight": state == "running",
                        **self._action_effect_summary(db, row), **self._computer_sequence_summary(db, row)}
            result = {key: row[key] for key in
                      ("id", "state", "cancel_requested", "dispatched", "result_code")}
            return {**result, **self._action_effect_summary(db, row), **self._computer_sequence_summary(db, row)}

    def begin_human_handoff(self, task: str, *, timeout_seconds=300, kind: HumanHandoffKind | None = None):
        kind = human_handoff_kind(kind)
        if type(timeout_seconds) is not int or not 10 <= timeout_seconds <= 3600:
            raise ControlError("invalid_handoff_timeout")
        with self.transaction() as db:
            current = self._task(db, task)
            if not current["paused"]:
                raise ControlError("handoff_requires_paused_task")
            now = self.clock()
            db.execute("UPDATE human_handoffs SET state='expired',updated=? WHERE task=? AND state='pending' AND (boot<>? OR expires<=?)",
                (now, task, self.boot, now))
            existing = db.execute("SELECT * FROM human_handoffs WHERE task=? AND state='pending' ORDER BY created DESC LIMIT 1", (task,)).fetchone()
            if existing:
                return {"request_id": existing["id"], "state": "pending", "kind": existing["kind"],
                        "remaining_seconds": max(0, round(existing["expires"]-now)),
                        "resume_requires_explicit_chat_request": True, "grants_authorization": False, "reused": True}
            request = "handoff-" + secrets.token_hex(16)
            db.execute("INSERT INTO human_handoffs(id,task,boot,created,expires,state,updated,kind) VALUES (?,?,?,?,?,'pending',?,?)",
                (request, task, self.boot, now, now+timeout_seconds, now, kind))
            return {"request_id": request, "state": "pending", "kind": kind, "remaining_seconds": timeout_seconds,
                    "resume_requires_explicit_chat_request": True, "grants_authorization": False}

    def human_handoff_status(self, task, request, *, resolution=None, extend_seconds=300):
        if resolution not in {None, "completed", "cancelled", "expired", "stopped", "extend"}:
            raise ControlError("invalid_handoff_resolution")
        if type(extend_seconds) is not int or not 10 <= extend_seconds <= 3600:
            raise ControlError("invalid_handoff_timeout")
        context = self.read_transaction if resolution is None else self.transaction
        with context() as db:
            task_row = self._task(db, task)
            row = db.execute("SELECT * FROM human_handoffs WHERE id=? AND task=?", (request, task)).fetchone()
            if row is None:
                raise ControlError("handoff_not_found")
            now, state = self.clock(), row["state"]
            if state == "pending" and (row["boot"] != self.boot or row["expires"] <= now):
                state = "expired"
            if state == "pending" and resolution == "extend":
                db.execute("UPDATE human_handoffs SET expires=?,extensions=extensions+1,updated=? WHERE id=?",
                    (min(max(row["expires"], now)+extend_seconds, row["created"]+3600), now, request))
            elif state == "pending" and resolution is not None:
                state = resolution
            if resolution is not None:
                db.execute("UPDATE human_handoffs SET state=?,updated=? WHERE id=?", (state, now, request))
                row = db.execute("SELECT * FROM human_handoffs WHERE id=?", (request,)).fetchone()
            return {"request_id": request, "state": state, "kind": row["kind"],
                    "remaining_seconds": max(0, round(row["expires"]-now)),
                    "extensions": row["extensions"], "task_still_paused": bool(task_row['paused']),
                    "resume_requires_explicit_chat_request": True, "grants_authorization": False,
                    "foreground_activated": False}

    _BUSINESS_FINAL = frozenset({"completed", "partial", "cancelled", "failed", "outcome_uncertain"})
    _BUSINESS_STEP_STATES = frozenset({"planned", "running", "verified", "not_verified",
                                       "outcome_uncertain", "cancelled", "skipped"})
    _BUSINESS_CHANNELS = frozenset({"web", "app", "computer"})

    @staticmethod
    def _business_text(value, field, maximum=240):
        if (type(value) is not str or not 1 <= len(value.strip()) <= maximum
                or any(ord(char) < 32 for char in value)):
            raise ControlError("invalid_business_" + field)
        return value.strip()

    @staticmethod
    def _business_id(value, field):
        import re
        if type(value) is not str or re.fullmatch("[a-f0-9]{32}", value) is None:
            raise ControlError("invalid_business_" + field)
        return value

    def create_business_run(self, task: str, goal: str) -> dict:
        """Start one business chain; the id only associates evidence."""
        goal = self._business_text(goal, "goal")
        run_id = secrets.token_hex(16)
        now = self.clock()
        with self.transaction() as db:
            self._task(db, task)
            db.execute("INSERT INTO business_runs(id,task,goal,state,created,updated,revision) "
                       "VALUES (?,?,?,'open',?,?,0)", (run_id, task, goal, now, now))
            self._record_event(db, "business_run_started", task=task, details={"run_id": run_id})
        return {"run_id": run_id, "state": "open", "revision": 0,
                "business_finished": False, "business_result_verified": False,
                "grants_authorization": False}

    def append_business_step(self, task: str, run_id: str, channel: str, state: str,
                             summary: str, *, parent_step_id: str | None = None,
                             step_id: str | None = None) -> dict:
        """Append one immutable step fact; duplicate ids must match exactly."""
        run_id = self._business_id(run_id, "run_id")
        if channel not in self._BUSINESS_CHANNELS:
            raise ControlError("invalid_business_channel")
        if state not in self._BUSINESS_STEP_STATES:
            raise ControlError("invalid_business_step_state")
        summary = self._business_text(summary, "summary")
        step_id = self._business_id(step_id, "step_id") if step_id is not None else secrets.token_hex(16)
        parent = self._business_id(parent_step_id, "parent_step_id") if parent_step_id is not None else None
        now = self.clock()
        with self.transaction() as db:
            run = db.execute("SELECT * FROM business_runs WHERE id=? AND task=?", (run_id, task)).fetchone()
            if run is None:
                raise ControlError("business_run_unavailable")
            if run["state"] in self._BUSINESS_FINAL:
                raise ControlError("business_run_finished")
            if parent is not None:
                parent_row = db.execute("SELECT run,task FROM business_steps WHERE id=?", (parent,)).fetchone()
                if parent_row is None or parent_row["run"] != run_id or parent_row["task"] != task:
                    raise ControlError("business_parent_unavailable")
            existing = db.execute("SELECT * FROM business_steps WHERE id=?", (step_id,)).fetchone()
            if existing is not None:
                if (existing["run"] != run_id or existing["task"] != task
                        or existing["channel"] != channel or existing["state"] != state
                        or existing["summary"] != summary or existing["parent"] != parent):
                    raise ControlError("business_step_conflict")
                return {"step_id": step_id, "run_id": run_id, "state": state,
                        "created": existing["created"], "idempotent": True,
                        "grants_authorization": False}
            db.execute("INSERT INTO business_steps(id,run,task,channel,parent,state,summary,created,updated) "
                       "VALUES (?,?,?,?,?,?,?,?,?)",
                       (step_id, run_id, task, channel, parent, state, summary, now, now))
            db.execute("UPDATE business_runs SET revision=revision+1,updated=? WHERE id=?", (now, run_id))
            self._record_event(db, "business_step_recorded", task=task, details={
                "run_id": run_id, "step_id": step_id, "channel": channel, "state": state})
        return {"step_id": step_id, "run_id": run_id, "state": state,
                "created": now, "idempotent": False, "grants_authorization": False}

    def finish_business_run(self, task: str, run_id: str, state: str, summary: str) -> dict:
        run_id = self._business_id(run_id, "run_id")
        if state not in self._BUSINESS_FINAL:
            raise ControlError("invalid_business_final_state")
        summary = self._business_text(summary, "summary")
        now = self.clock()
        with self.transaction() as db:
            run = db.execute("SELECT * FROM business_runs WHERE id=? AND task=?", (run_id, task)).fetchone()
            if run is None:
                raise ControlError("business_run_unavailable")
            if run["state"] in self._BUSINESS_FINAL:
                if run["state"] != state:
                    raise ControlError("business_run_finished")
                return self._business_run_status(db, task, run_id)
            from .business_plan import status as plan_status
            plan = plan_status(db, task, run_id, include_all=True)
            if plan is not None:
                receipts = [step["receipt"] for step in plan["steps"]]
                if any(receipt is not None and (receipt["active_members"] or receipt["call_in_flight"] or receipt["state"] == "running") for receipt in receipts):
                    raise ControlError("business_plan_in_flight")
                if state == "completed" and any(receipt is None or not receipt["execution_finished"] for receipt in receipts):
                    raise ControlError("business_plan_not_verified")
                if state not in {"partial", "outcome_uncertain"} and any(
                        receipt is not None and receipt["state"] == "outcome_uncertain" for receipt in receipts):
                    raise ControlError("business_run_has_uncertain_steps")
            if state not in {"partial", "outcome_uncertain"} and db.execute(
                    "SELECT 1 FROM business_steps WHERE run=? AND task=? AND state='outcome_uncertain' LIMIT 1",
                    (run_id, task)).fetchone():
                raise ControlError("business_run_has_uncertain_steps")
            db.execute("INSERT INTO business_run_finishes(run,summary) VALUES (?,?)", (run_id, summary))
            db.execute("UPDATE business_runs SET state=?,revision=revision+1,updated=? WHERE id=?",
                       (state, now, run_id))
            self._record_event(db, "business_run_finished", task=task,
                               details={"run_id": run_id, "state": state})
            return self._business_run_status(db, task, run_id)

    def business_run_status(self, task: str, run_id: str) -> dict:
        run_id = self._business_id(run_id, "run_id")
        with self.read_transaction() as db:
            return self._business_run_status(db, task, run_id)

    def _business_run_status(self, db, task: str, run_id: str) -> dict:
        run = db.execute("SELECT * FROM business_runs WHERE id=? AND task=?", (run_id, task)).fetchone()
        if run is None:
            raise ControlError("business_run_unavailable")
        from .business_pages import page
        step_page = page(db, task, run_id, 'steps')
        steps = step_page['items']
        counts = db.execute("SELECT COUNT(*),COALESCE(SUM(state='verified'),0),"
            "COALESCE(SUM(state='outcome_uncertain'),0) FROM business_steps WHERE run=? AND task=?",
            (run_id, task)).fetchone()
        final = db.execute("SELECT summary FROM business_run_finishes WHERE run=?", (run_id,)).fetchone()
        return {"run_id": run_id, "state": run["state"], "goal": run["goal"],
                "summary": final[0] if final is not None else None,
                "summary_recorded": final is not None,
                "revision": run["revision"], "created": run["created"], "updated": run["updated"],
                "business_finished": run["state"] in self._BUSINESS_FINAL,
                "business_result_verified": False,
                "verified_steps": counts[1], "uncertain_steps": counts[2],
                "step_count": counts[0], "steps_truncated": step_page['truncated'],
                "next_steps_after": step_page['next_after'],
                "channels": [row[0] for row in db.execute("SELECT DISTINCT channel FROM business_steps WHERE run=? AND task=? ORDER BY channel", (run_id, task))],
                "steps": steps, "grants_authorization": False,
                "cleanup_only": False,
                **self._business_plan_details(db, task, run_id)}

    @staticmethod
    def _business_plan_details(db, task, run_id):
        from .business_plan import status
        from .business_pages import page
        artifacts = page(db, task, run_id, 'artifacts')
        return {"plan": status(db, task, run_id), "artifacts": artifacts['items'],
            "artifact_count": artifacts['total'], "artifacts_truncated": artifacts['truncated'],
            "next_artifacts_after": artifacts['next_after'], "bounded_summary": True}

    def business_run_page(self, task, run_id, section, *, after=None, limit=32, step_id=None):
        from .business_pages import page
        run_id = self._business_id(run_id, "run_id")
        with self.read_transaction() as db:
            return page(db, task, run_id, section, after=after, limit=limit, step_id=step_id)

    def plan_business_run(self, task, run_id, steps):
        from .business_plan import install
        return install(self, task, run_id, steps)

    def stop_business_run(self, task, run_id):
        from .business_plan import stop
        return stop(self, task, run_id)

    def attach_business_artifact(self, task, run_id, step_id, artifact_id):
        from .business_plan import attach_artifact
        return attach_artifact(self, task, run_id, step_id, artifact_id)

    def task_cleanup_status(self, task: str) -> dict:
        """Whole-chat cleanup facts; history truncation never means pending."""
        with self.read_transaction() as db:
            self._task(db, task)
            active = db.execute("SELECT COUNT(*) FROM actions WHERE task=? AND state IN ('queued','running')", (task,)).fetchone()[0]
            unknown_history = db.execute("SELECT COUNT(*) FROM actions WHERE task=? AND state='outcome_uncertain'", (task,)).fetchone()[0]
            claimed_unknown_query = ("SELECT DISTINCT a.id FROM actions a JOIN json_each(a.resources) j "
                "JOIN owned_resources o ON o.resource=j.value WHERE a.task=? AND o.task=? AND a.state='outcome_uncertain'")
            claimed_unknown = db.execute("SELECT COUNT(*) FROM ("+claimed_unknown_query+")", (task, task)).fetchone()[0]
            claimed_quarantine = db.execute("SELECT COUNT(*) FROM owned_resources o JOIN resources r ON r.id=o.resource "
                "WHERE o.task=? AND r.quarantined<>0", (task,)).fetchone()[0]
            stale_claims = db.execute("SELECT COUNT(*) FROM owned_resource_claims c JOIN owners o ON c.owner=o.id "
                "WHERE o.task=? AND o.retired<>0", (task,)).fetchone()[0]
            inputs = self._pending_input_release_rows(db, task=task)
            pending = {row[0] for row in db.execute("SELECT id FROM actions WHERE task=? AND state IN ('queued','running') LIMIT 65", (task,))}
            pending.update(row[0] for row in db.execute(claimed_unknown_query+" LIMIT 65", (task, task)))
            pending.update(row['id'] for row in inputs[:65])
            return {"scope": "this_chat", "active_actions": active, "unknown_history": unknown_history,
                    "unknown_with_retained_claim": claimed_unknown, "quarantined_claims": claimed_quarantine,
                    "stale_owner_claims": stale_claims,
                    "unconfirmed_input_actions": len(inputs), "input_release": "pending" if inputs else "released",
                    "cleanup_ready": not (active or claimed_unknown or claimed_quarantine or inputs),
                    "pending_action_ids": sorted(pending)[:64],
                    "pending_ids_truncated": active > 64 or claimed_unknown > 64 or len(inputs) > 64 or len(pending) > 64,
                    "history_preserved": True, "business_success_verified": False, "old_actions_replayed": False}

    def task_control_status(self, task: str) -> dict:
        """Finite own-chat control metadata; never another chat's content."""
        from .feedback import resource_kind
        with self.read_transaction() as db:
            current = self._task(db, task)
            actions = []
            rows = db.execute("SELECT * FROM actions WHERE task=? ORDER BY updated DESC,id LIMIT 65", (task,)).fetchall()
            for row in rows[:64]:
                result = {key: row[key] for key in ("id", "state", "cancel_requested", "dispatched", "result_code", "updated")}
                result["resource_kinds"] = sorted({resource_kind(item) for item in json.loads(row["resources"])})
                result.update(self._action_effect_summary(db, row))
                result.update(self._computer_sequence_summary(db, row))
                actions.append(result)
            owners = [dict(row) for row in db.execute("SELECT retired,COUNT(*) AS count FROM owners WHERE task=? GROUP BY retired", (task,))]
            resources = [{"kind": resource_kind(row["resource"]), "paused": bool(row["paused"]),
                          "recovery_required": self._effective_quarantine(db, row["resource"], row)} for row in db.execute(
                "SELECT o.resource,r.paused,r.quarantined FROM owned_resources o JOIN resources r ON r.id=o.resource WHERE o.task=?", (task,))]
            active = db.execute("SELECT COUNT(*) FROM actions WHERE task=? AND state IN ('queued','running')", (task,)).fetchone()[0]
            handoffs = [{"request_id": row["id"], "state": row["state"] if row["boot"] == self.boot and row["expires"] > self.clock()
                        or row["state"] != "pending" else "expired", "extensions": row["extensions"], "kind": row["kind"]}
                        for row in db.execute("SELECT * FROM human_handoffs WHERE task=? ORDER BY created DESC LIMIT 8", (task,))]
            runs = [{"run_id": row["id"], "state": row["state"], "goal": row["goal"],
                     "revision": row["revision"], "updated": row["updated"],
                     "step_count": db.execute("SELECT COUNT(*) FROM business_steps WHERE run=?",
                                              (row["id"],)).fetchone()[0]}
                    for row in db.execute("SELECT * FROM business_runs WHERE task=? "
                                          "ORDER BY updated DESC,id LIMIT 8", (task,))]
            app_lifecycle = db.execute(
                "SELECT event FROM control_events WHERE task=? AND event IN "
                "('app_control_attempted','app_channel_finished') ORDER BY seq DESC LIMIT 1", (task,)).fetchone()
            app_phase = ("finished" if app_lifecycle and app_lifecycle[0] == "app_channel_finished"
                         else "control_attempted" if app_lifecycle else "not_recorded")
            computer_lifecycle = db.execute(
                "SELECT event FROM control_events WHERE task=? AND event IN "
                "('computer_control_attempted','computer_channel_finished') ORDER BY seq DESC LIMIT 1", (task,)).fetchone()
            computer_phase = ("finished" if computer_lifecycle and computer_lifecycle[0] == "computer_channel_finished"
                              else "control_attempted" if computer_lifecycle else "not_recorded")
            return {"scope": "this_chat", "task": task, "paused": bool(current["paused"]), "revoked": bool(current["revoked"]),
                    "revision": current["revision"], "actions": actions, "truncated": len(rows) > 64,
                    "active_actions": active, "owners": owners, "target_claims": resources,
                    "human_handoffs": handoffs, "business_runs": runs,
                    "old_actions_replayed": False, "task_finished": None,
                    "task_finished_scope": "chat_task_has_no_finish_state",
                    "app_channel_last_lifecycle": app_phase, "computer_channel_last_lifecycle": computer_phase,
                    "private_content_included": False}

    def withdraw_queued_call(self, owner: str, action_id: str):
        """Trusted cancelled call only; never retire running/terminal receipts."""
        with self.transaction() as db:
            row = db.execute("SELECT task FROM actions WHERE id=? AND owner=? AND state='queued'",
                             (action_id, owner)).fetchone()
            if row is not None:
                db.execute("UPDATE actions SET cancel_requested=1,state='cancelled',updated=? WHERE id=? AND owner=? AND state='queued'",
                           (self.clock(), action_id, owner))
                self._mark_stage_stop(db, action_id)
                self._record_event(db, "mcp_call_cancelled", task=row["task"], action=action_id)

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
                blocked = self._effective_quarantine(db, resource, row)
                resource_status.append({"kind": resource_kind(resource), "paused": bool(row["paused"]),
                                        "recovery_required": blocked})
                if row["paused"]:
                    reasons.add("user_takeover")
                if blocked:
                    reasons.add("target_recovery_required")
            conflicts = []
            total_conflicts = 0
            for other in db.execute("SELECT id,owner,resources,state FROM actions WHERE state IN ('queued','running') ORDER BY id"):
                overlap = resources.intersection(self._running_resources(db, other) if other["state"] == "running"
                                                  else json.loads(other["resources"]))
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
