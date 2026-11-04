"""Trusted local Hook metadata requests, consumed only by the original owner.

No public MCP entrypoint, tool payload, transcript, grant, Stop mutation or input
dispatch belongs here. Receipt sequence is local database order, not host order.
"""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import threading
import time

from .native import process_identity, process_is_alive
from .state import ControlError, StateStore
from .write_gate import WriteGateError

EVENT_TTL = 5.0
MAX_BATCH = 8
POLL_SECONDS = .2
_EVENTS = {"PreToolUse", "PostToolUse", "Stop", "Interrupt", "SessionEnd"}
_TERMINAL = {"Stop", "Interrupt", "SessionEnd", "DshTurnEnd"}
_SCHEMA = """
CREATE TABLE IF NOT EXISTS host_phase_events(
 receipt INTEGER PRIMARY KEY AUTOINCREMENT, event_key TEXT NOT NULL UNIQUE,
 task TEXT NOT NULL, boot TEXT NOT NULL, kind TEXT NOT NULL, call_key TEXT,
 watermark TEXT NOT NULL, created REAL NOT NULL, expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS host_phase_targets(
 receipt INTEGER NOT NULL, owner TEXT NOT NULL, process TEXT NOT NULL,
 state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(receipt,owner));
CREATE INDEX IF NOT EXISTS host_phase_targets_pending ON host_phase_targets(process,state,receipt);
CREATE TABLE IF NOT EXISTS host_phase_terminals(
 call_key TEXT PRIMARY KEY, expires REAL NOT NULL);
"""


class PhasePublisher:
    """Open an existing ledger for display-only metadata, never initialize it.

    The active server owns schema migration and boot verification. Publication
    copies its committed boot; the original live consumer independently checks
    that boot and owner before any cleanup. This path opens no input gate and
    never performs a per-tool WMI boot query or full StateStore migration.
    """
    def __init__(self, directory):
        directory = Path(directory)
        self.path = directory / "control.sqlite3"
        if (directory.is_symlink() or directory.is_junction() or not directory.is_dir()
                or self.path.is_symlink() or self.path.is_junction() or not self.path.is_file()):
            raise ControlError("phase_ledger_not_regular")
        self.clock = time.monotonic
        self.boot = None

    @contextmanager
    def transaction(self, *, timeout):
        db = sqlite3.connect(self.path.absolute().as_uri() + "?mode=rw", uri=True,
                             timeout=timeout, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("BEGIN IMMEDIATE")
            values = dict(db.execute("SELECT key,value FROM meta WHERE key IN ('schema','boot')"))
            if values.get("schema") != StateStore.schema_version or not values.get("boot"):
                raise ControlError("phase_ledger_not_initialized")
            self.boot = values["boot"]
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

def _digest(parts):
    return hashlib.sha256(json.dumps(parts, separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()

def _identifier(value):
    return (type(value) is str and 1 <= len(value) <= 256 and value == value.strip()
        and all(ord(char) >= 32 and ord(char) != 127 for char in value))

def _exists(db, table):
    return db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is not None

def _watermark(db, task):
    row = db.execute("SELECT token_hash FROM origin_tickets WHERE task=? ORDER BY rowid DESC LIMIT 1", (task,)).fetchone()
    return row[0] if row else None

def publish_event(store, event):
    """Called only by the trusted command adapter, never by model arguments.

    Lookup an existing Codex binding. Parent-session subagents share the same
    task; an event never proves exclusive work, native focus or business success.
    """
    if type(event) is not dict or event.get("hook_event_name") not in _EVENTS:
        return None
    kind, session = event["hook_event_name"], event.get("session_id")
    turn = event.get("turn_id")
    if not _identifier(session) or (kind != "SessionEnd" and not _identifier(turn)):
        return None
    call_key = None
    if kind in {"PreToolUse", "PostToolUse"}:
        tool, use = event.get("tool_name"), event.get("tool_use_id")
        if (type(tool) is not str or re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", tool) is None
                or not _identifier(use) or re.match(r"mcp__(?:plugin_flower-control_)?flower[-_](?:web|app|computer)__", tool)):
            return None
        call_key = _digest([session, turn, use, tool])
    # Identifiers are retained only as opaque hashes. Never inspect/copy other
    # keys, including tool_input, tool_response, prompt or transcript_path.
    session_hash = hashlib.sha256(b"flower-session-v1\0" + session.encode("utf-8")).hexdigest()
    event_key = _digest([kind, session_hash, turn, call_key])
    return _publish_bound(store, session_hash, event_key, kind, call_key)


def publish_dsh_event(store, event):
    """Fixed direct-host adapter only; never a Codex Hook or an origin ticket.

    Node hrtime and this Windows CPython monotonic clock use the system QPC.
    The original event time also bounds late helper children after a timeout;
    a later ticket can never be adopted as the old terminal's watermark.
    """
    if (type(event) is not dict or set(event) != {"session_id", "instance_id", "event_seq", "kind", "observed_ns"}
            or not _identifier(event["session_id"]) or type(event["instance_id"]) is not str
            or re.fullmatch(r"[a-f0-9]{32}", event["instance_id"]) is None
            or type(event["event_seq"]) is not int or not 0 <= event["event_seq"] <= 2**53-1
            or type(event["kind"]) is not str or event["kind"] not in {"idle", "turn_end"}
            or type(event["observed_ns"]) is not str or re.fullmatch(r"[0-9]{1,20}", event["observed_ns"]) is None):
        return None
    observed = int(event["observed_ns"]) / 1_000_000_000
    if not 0 <= store.clock() - observed < EVENT_TTL:
        return None
    session = event["session_id"]
    session_hash = hashlib.sha256(b"flower-session-v1\0dsh-desktop\0" + session.encode("utf-8")).hexdigest()
    kind = "DshTurnEnd" if event["kind"] == "turn_end" else "DshIdle"
    return _publish_bound(store, session_hash,
        _digest([kind, session_hash, event["instance_id"], event["event_seq"]]), kind, None,
        observed=observed, dsh_session=session)


def _publish_bound(store, session_hash, event_key, kind, call_key, *, observed=None, dsh_session=None):
    now = store.clock()
    with store.transaction(timeout=.05) as db:
        if not all(_exists(db, name) for name in ("origin_sessions", "origin_tickets", "origin_task_boots")):
            return None
        binding = db.execute("SELECT s.task FROM origin_sessions s JOIN tasks t ON t.id=s.task "
            "JOIN origin_task_boots b ON b.task=s.task WHERE s.session_hash=? AND t.revoked=0 AND b.boot=?",
            (session_hash, store.boot)).fetchone()
        if binding is None:
            return None
        task = binding[0]
        if dsh_session is not None:
            if not _exists(db, "origin_task_threads") or db.execute(
                    "SELECT 1 FROM origin_task_threads WHERE task=? AND session_hash=? AND host_kind='dsh-desktop' AND thread_id=?",
                    (task, session_hash, dsh_session)).fetchone() is None:
                return None
            latest = db.execute("SELECT issued FROM origin_tickets WHERE task=? ORDER BY rowid DESC LIMIT 1", (task,)).fetchone()
            # Equal/rounding-overlapping clock ticks are ambiguous too. Drop
            # metadata conservatively instead of closing a newer control run.
            if (not 0 <= now - observed < EVENT_TTL or latest is None
                    or latest[0] + .000001 >= observed):
                return None
        watermark = _watermark(db, task)
        if watermark is None:
            return None
        for statement in _SCHEMA.split(";"):
            if statement.strip():
                db.execute(statement)
        # A registered hint retains cleanup responsibility for its original
        # live owner. It never gains input/resume authority or a new watermark.
        for old in db.execute("SELECT DISTINCT x.process FROM host_phase_targets x "
                "JOIN host_phase_events e ON e.receipt=x.receipt WHERE x.state IN ('pending','deferred') "
                "AND e.expires<?", (now - 60,)).fetchall():
            if not process_is_alive(old[0]):
                db.execute("UPDATE host_phase_targets SET state='closed' WHERE process=? AND state IN ('pending','deferred')", (old[0],))
        db.execute("UPDATE host_phase_targets SET state='superseded' WHERE state IN ('pending','deferred') AND receipt IN "
            "(SELECT receipt FROM host_phase_events WHERE boot<>?)", (store.boot,))
        # Persistent cleanup cannot accumulate against retired owners or a new
        # GUI call. A later event must never acquire the old event's authority.
        db.execute("UPDATE host_phase_targets SET state='superseded' WHERE state IN ('pending','deferred') AND ("
            "NOT EXISTS (SELECT 1 FROM owners o WHERE o.id=host_phase_targets.owner AND o.retired=0 "
            "AND o.process=host_phase_targets.process) OR receipt IN ("
            "SELECT e.receipt FROM host_phase_events e WHERE e.watermark IS NOT ("
            "SELECT t.token_hash FROM origin_tickets t WHERE t.task=e.task ORDER BY t.rowid DESC LIMIT 1)))")
        # Bounded local lifecycle. Old events have no execution authority.
        db.execute("DELETE FROM host_phase_targets WHERE receipt IN "
            "(SELECT receipt FROM host_phase_events e WHERE expires<? AND NOT EXISTS "
            "(SELECT 1 FROM host_phase_targets x WHERE x.receipt=e.receipt AND x.state IN ('pending','deferred')))", (now - 60,))
        db.execute("DELETE FROM host_phase_events WHERE expires<? AND NOT EXISTS "
            "(SELECT 1 FROM host_phase_targets x WHERE x.receipt=host_phase_events.receipt AND x.state IN ('pending','deferred'))", (now - 60,))
        db.execute("DELETE FROM host_phase_terminals WHERE expires<?", (now,))
        if kind == "PostToolUse":
            if db.execute("SELECT COUNT(*) FROM host_phase_terminals").fetchone()[0] >= 2048:
                return None
            db.execute("INSERT OR REPLACE INTO host_phase_terminals VALUES (?,?)", (call_key, now + 60))
            # A short backend call still ends the GUI phase. Its Post must not
            # erase an unconsumed Pre before the 200ms consumer observes it.
            return None
        if call_key is not None and db.execute("SELECT 1 FROM host_phase_terminals WHERE call_key=?", (call_key,)).fetchone():
            return None  # A delayed Pre cannot reopen a completed call.
        prior = db.execute("SELECT receipt FROM host_phase_events WHERE event_key=?", (event_key,)).fetchone()
        if prior:
            return prior[0]
        if db.execute("SELECT COUNT(*) FROM host_phase_events").fetchone()[0] >= 1024:
            return None
        cursor = db.execute("INSERT INTO host_phase_events(event_key,task,boot,kind,call_key,watermark,created,expires) "
            "VALUES (?,?,?,?,?,?,?,?)", (event_key, task, store.boot, kind, call_key, watermark, now,
                (observed if observed is not None else now) + EVENT_TTL))
        receipt = cursor.lastrowid
        # Exact owners are sealed at publication, not discovered after a later
        # selection/rebind. Other channels/processes can consume only their own.
        db.execute("INSERT INTO host_phase_targets(receipt,owner,process,state) SELECT DISTINCT ?,o.id,o.process,'pending' "
            "FROM owners o JOIN (SELECT owner FROM owned_resource_claims UNION SELECT owner FROM released_resource_claims) c "
            "ON c.owner=o.id WHERE o.task=? AND o.retired=0", (receipt, task))
        return receipt

def _check(db, store, row, *, deferred=False, allow_pending=False):
    # A published cleanup hint is sealed to an owner, boot and ticket watermark.
    # It grants no input and remains consumable after scheduling delays. Incoming
    # DSH events still have their source-time TTL checked before publication.
    if row["boot"] != store.boot:
        raise ControlError("host_phase_expired")
    current = db.execute("SELECT s.task,b.boot,t.revoked,t.paused FROM origin_sessions s "
        "JOIN tasks t ON t.id=s.task JOIN origin_task_boots b ON b.task=s.task WHERE s.task=?", (row["task"],)).fetchone()
    if current is None or current[1] != store.boot or current[2] or _watermark(db, row["task"]) != row["watermark"]:
        raise ControlError("host_phase_superseded")
    # The existing task_write_stopped predicate, using this writer's snapshot
    # and a read of the shared gate. Do not open a second reader or schedule a
    # Stop journal thread merely for this metadata recheck.
    try:
        gate = store.write_gate.snapshot()
    except WriteGateError:
        raise ControlError("host_phase_stopped") from None
    ack = db.execute("SELECT epoch FROM task_write_epochs WHERE task=?", (row["task"],)).fetchone()
    if current[3] or gate.stopped or max(ack[0] if ack else 0, gate.resume_all_epoch) < gate.epoch:
        raise ControlError("host_phase_stopped")
    pending = db.execute("SELECT 1 FROM origin_tickets WHERE task=? AND consumed IS NULL AND expires>? LIMIT 1",
                         (row["task"], store.clock())).fetchone()
    if pending is not None and not allow_pending:
        raise ControlError("host_phase_call_not_consumed")
    state = db.execute("SELECT state FROM host_phase_targets WHERE receipt=? AND owner=?",
                       (row["receipt"], row["owner"])).fetchone()
    if state is None or state[0] not in {"pending", "deferred"}:
        raise ControlError("host_phase_closed")
    owner = db.execute("SELECT task,process,retired FROM owners WHERE id=?", (row["owner"],)).fetchone()
    if owner is None or tuple(owner[:2]) != (row["task"], row["process"]) or owner[2] or row["process"] != process_identity():
        raise ControlError("host_phase_wrong_owner")
    # Public tails and late native workers (including abandoned ones) cannot be
    # mistaken for known completed control. No token is removed here.
    if not allow_pending and _exists(db, "business_public_calls") and db.execute(
            "SELECT 1 FROM business_public_calls WHERE task=? LIMIT 1", (row["task"],)).fetchone():
        raise ControlError("host_phase_public_call_pending")

class PhaseConsumer:
    """One original server's bounded, local metadata consumer."""
    def __init__(self, runtimes, *, busy=lambda task: False):
        self.runtimes = runtimes
        self.busy = busy
        self.closed = threading.Event()
        self.worker = None
        self.wake = asyncio.Event()
        self._owner_turns = {}
        self._turn = 0

    def drain_once(self):
        from flower_control.drivers.idle_phase_cleanup import _release_idle
        active = tuple(self.runtimes())
        by_store = {}
        for runtime in active:
            by_store.setdefault(str(runtime.store.path.resolve()), []).append(runtime)
        remaining = MAX_BATCH
        deadline = time.monotonic() + .1
        for runtimes in by_store.values():
            if self.closed.is_set() or remaining <= 0 or time.monotonic() >= deadline:
                break
            store = runtimes[0].store
            owners = []
            for runtime in runtimes:
                with runtime._gate:
                    owners.extend(runtime._owners.values())
            if not owners:
                continue
            with store.read_transaction(timeout=.02) as db:
                if not _exists(db, "host_phase_events"):
                    continue
                rows = db.execute("SELECT * FROM (SELECT e.*,x.owner,x.process,x.state AS target_state, "
                    "ROW_NUMBER() OVER (PARTITION BY x.owner ORDER BY x.attempts, "
                    "CASE WHEN e.kind IN ('Stop','Interrupt','SessionEnd','DshTurnEnd') THEN 0 ELSE 1 END,e.receipt) AS owner_position "
                    "FROM host_phase_events e JOIN host_phase_targets x "
                    "ON e.receipt=x.receipt WHERE x.process=? AND x.state IN ('pending','deferred') AND x.owner IN ("
                    + ",".join("?" for _ in owners) + ")) WHERE owner_position=1",
                    (process_identity(), *owners)).fetchall()
            # One row per owner per poll, with round-robin owner priority even
            # when the 100ms metadata budget ends after the first row. An old
            # task's many terminal hints cannot monopolize another task's HUD.
            rows = sorted(rows, key=lambda row: (self._owner_turns.get(row['owner'], 0),
                row['kind'] not in _TERMINAL, row['receipt']))[:remaining]
            for row in rows:
                if self.closed.is_set() or time.monotonic() >= deadline:
                    break
                remaining -= 1
                runtime = next((item for item in runtimes if self._matches(item, row)), None)
                if runtime is None:
                    continue  # Never create a runtime, adopt an owner or a task.
                self._turn += 1
                self._owner_turns[row['owner']] = self._turn
                deferred = row["target_state"] == "deferred"
                try:
                    # Every delayed attempt rechecks original identity and
                    # watermark before considering busy; metadata grants no
                    # input or permission lifetime extension.
                    with store.transaction(timeout=.02) as db:
                        _check(db, store, row, deferred=deferred, allow_pending=True)
                        if row["kind"] in _TERMINAL and not deferred:
                            db.execute("UPDATE host_phase_targets SET state='deferred' "
                                "WHERE receipt=? AND owner=? AND state='pending'", (row["receipt"], row["owner"]))
                            deferred = True
                    if self.busy(row["task"]):
                        # Still acknowledge this scheduling attempt so a busy
                        # owner's first eight rows cannot starve other tasks.
                        raise ControlError("phase_cleanup_calls_in_flight")
                    with store.read_transaction(timeout=.02) as db:
                        _check(db, store, row, deferred=deferred)
                    prefix = (runtime._action_prefix(row["task"]) if hasattr(runtime, "_action_prefix")
                              else row["task"] + ":app:")
                    result = _release_idle(runtime, row["task"], row["owner"], prefix,
                        phase_release_check=lambda db, row=row, deferred=deferred: _check(db, store, row, deferred=deferred),
                        presentation_terminal=row["kind"] in _TERMINAL)
                    state = "presentation_released" if result and result.get("resources_retained") else "released"
                except ControlError as error:
                    state = ("expired" if error.code == "host_phase_expired" else "superseded"
                        if error.code == "host_phase_superseded" else "closed"
                        if error.code in {"host_phase_closed", "host_phase_wrong_owner"} else "deferred" if deferred else "pending")
                with store.transaction(timeout=.02) as db:
                    db.execute("UPDATE host_phase_targets SET state=?,attempts=attempts+1 "
                        "WHERE receipt=? AND owner=? AND state IN ('pending','deferred')", (state, row["receipt"], row["owner"]))

    @staticmethod
    def _matches(runtime, row):
        with runtime._gate:
            return runtime._owners.get(row["task"]) == row["owner"]

    async def run(self):
        while not self.closed.is_set():
            try:
                await asyncio.to_thread(self.drain_once)
            except (ControlError, sqlite3.Error, OSError):
                # Advisory cleanup cannot reject ordinary host work. A failed
                # transaction leaves the exact request pending until its TTL.
                pass
            if not self.closed.is_set():
                try:
                    await asyncio.wait_for(self.wake.wait(), POLL_SECONDS)
                except TimeoutError:
                    pass

    def start(self):
        self.worker = asyncio.create_task(self.run())
        self.worker.add_done_callback(lambda done: done.exception() if not done.cancelled() else None)

    async def close(self):
        self.closed.set()
        self.wake.set()
        if self.worker is not None:
            # No cancellation of a real synchronous attempt and no unbounded
            # extension of native worker cleanup. Its exact thread owns exit.
            await asyncio.wait({self.worker}, timeout=POLL_SECONDS)
