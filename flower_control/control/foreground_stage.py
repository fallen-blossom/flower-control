"""Internal short foreground stages, local costs and yielded wait metadata.

This module neither acquires dispatch authority nor sends input. Adapters must
enter the existing native-locked dispatch before beginning a stage, leave it
before model/network waits, and create a fresh action after interference.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import hashlib
import json
import math
import secrets
import threading

from .native import FOREGROUND_INPUT_RESOURCE, process_is_alive
from .state import ControlError
from .targets import target_description

_SOURCES = frozenset({"stage_bound", "measurement", "host"})
_ORDINARY = frozenset({"foreground_changed", "target_minimized", "geometry_changed",
    "external_keyboard", "external_mouse", "ime_changed", "new_window_detected",
    "content_changed", "capture_changed", "provider_changed"})
_INTERRUPTIONS = _ORDINARY | {"explicit_stop", "target_closed", "authorization_revoked", "deadline_exceeded"}


def validate_cost_context(estimated_ms, context):
    """Keep old unannotated callers compatible, without inventing their source."""
    for value, prefix in ((estimated_ms, "estimate"), (context.get("continuation_cost_ms"), "continuation")):
        if value is not None and (type(value) is not int or value < 0):
            raise ControlError("invalid_action_hints")
        source, reference = context.get(prefix + "_source"), context.get(prefix + "_reference")
        if source is None and reference is None:
            continue
        if (value is None or type(source) is not str or source not in _SOURCES or type(reference) is not str
                or not reference.strip() or len(reference) > 160):
            raise ControlError("invalid_cost_provenance")


@dataclass(frozen=True)
class StageCost:
    estimated_ms: int | None = None
    estimate_source: str | None = None
    estimate_reference: str | None = None
    continuation_cost_ms: int | None = None
    continuation_source: str | None = None
    continuation_reference: str | None = None

    def __post_init__(self):
        context = {name: getattr(self, name) for name in (
            "estimate_source", "estimate_reference", "continuation_cost_ms",
            "continuation_source", "continuation_reference")}
        validate_cost_context(self.estimated_ms, context)
        for value, source in ((self.estimated_ms, self.estimate_source),
                              (self.continuation_cost_ms, self.continuation_source)):
            if value is not None and source is None:
                raise ControlError("cost_source_required")
        for name in ("estimate_reference", "continuation_reference"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, target_description(value, 160))

    def enqueue_options(self, context=None):
        context = dict(context or {})
        # Never silently override a producer's different estimate contract.
        for name in ("estimate_source", "estimate_reference", "continuation_cost_ms",
                     "continuation_source", "continuation_reference"):
            value = getattr(self, name)
            if name in context and context[name] != value:
                raise ControlError("cost_context_conflict")
            if value is not None:
                context[name] = value
        return {"estimated_ms": self.estimated_ms, "context": context}


@dataclass(frozen=True)
class ReleaseBinding:
    action_id: str
    executor_process: str
    ledger_identity: str
    token: str = field(repr=False)


def _active(store, db, owner, action_id, *, allow_sequence_gap=False):
    locks = store._dispatch_locks.get(action_id)
    if (store._dispatch_threads.get(action_id) != threading.get_ident()
            or not (_holds_foreground(locks, store._external_dispatches.get(action_id))
                    or allow_sequence_gap and _sequence_gap(store, db, action_id))):
        raise ControlError("stage_requires_foreground_dispatch")
    connection = store._owner(db, owner)
    action = db.execute("SELECT * FROM actions WHERE id=? AND owner=?", (action_id, owner)).fetchone()
    store._check_running_action(db, action)
    return connection, action


def _holds_foreground(locks, external=None):
    if locks is not None:
        return any(resource == FOREGROUND_INPUT_RESOURCE for resource, _ in locks.handles)
    return external is not None and external.holds_resource(FOREGROUND_INPUT_RESOURCE)


def _sequence_gap(store, db, action_id):
    external = store._external_dispatches.get(action_id)
    progress = db.execute("SELECT final_state FROM computer_sequence_progress WHERE action=?", (action_id,)).fetchone()
    result = external.result if external is not None else None
    return bool(progress and progress[0] is None and result and result["MutexReleased"]
                and result["InputRelease"] == "released" and result["NativeCountKnown"]
                and result["SemanticExecutorExited"] is not False)


def stage_summary(store, db, action):
    from .feedback import aggregate_input_release
    row = db.execute("SELECT * FROM foreground_stages WHERE action=?", (action["id"],)).fetchone()
    if row is None:
        return {}
    locks = store._dispatch_locks.get(action["id"])
    binding = db.execute("SELECT executor_process,confirmed FROM input_release_bindings WHERE action=?", (action["id"],)).fetchone()
    if _holds_foreground(locks, store._external_dispatches.get(action["id"])):
        lease = "held"
    elif row["lease_released"] is not None:
        lease = "released"
    elif binding is not None and binding[1] is not None:
        # The exact terminal confirmation itself held the now-free native
        # mutex. This is a later recovery observation, not the old release time.
        lease = "recovered"
    else:
        # Persisted identity is not proof that a remote/dead dispatcher still
        # owns a mutex. Do not turn owner expiry into a release observation.
        lease = "unconfirmed" if row["boot"] == store.boot and process_is_alive(row["dispatcher_process"]) else "unknown"
    effects = db.execute("SELECT input_release FROM action_effects WHERE action=?", (action["id"],)).fetchone()
    progress = db.execute("SELECT input_release FROM computer_sequence_progress WHERE action=?", (action["id"],)).fetchone()
    release = aggregate_input_release(effects[0] if effects else None, progress[0] if progress else None)
    task = db.execute("SELECT paused,revoked FROM tasks WHERE id=?", (action["task"],)).fetchone()
    target = db.execute("SELECT paused,quarantined FROM resources WHERE id=?", (row["target"],)).fetchone()
    front = db.execute("SELECT paused,quarantined FROM resources WHERE id=?", (FOREGROUND_INPUT_RESOURCE,)).fetchone()
    automatic = (row["interruption"] in _ORDINARY and row["stop_received"] is None
        and not task["paused"] and not task["revoked"] and target is not None
        and not target["paused"] and not target["quarantined"]
        and front is not None and not front["paused"] and not front["quarantined"])
    hints = db.execute("SELECT estimated_ms FROM action_hints WHERE action=?", (action["id"],)).fetchone()
    context_row = db.execute("SELECT details FROM action_context WHERE action=?", (action["id"],)).fetchone()
    context = json.loads(context_row[0]) if context_row else {}
    return {"foreground_stage": {
        "action_id": action["id"], "owner": action["owner"], "channel": row["channel"],
        "target_resource": row["target"], "operation": row["operation"],
        "dispatcher_process": row["dispatcher_process"], "executor_process": binding[0] if binding else None, "lease_state": lease,
        "started": row["started"], "clock_boot": row["boot"],
        "elapsed_ms": (max(0, round(((row["ended"] if row["ended"] is not None else store.clock()) - row["started"]) * 1000))
                       if row["ended"] is not None or row["boot"] == store.boot else None),
        "deadline": row["deadline"], "ended": row["ended"], "lease_released": row["lease_released"],
        "estimated_ms": hints[0] if hints else None,
        **{key: context.get(key) for key in ("task_hint", "estimate_source", "estimate_reference",
            "continuation_cost_ms", "continuation_source", "continuation_reference")},
        "interruption": row["interruption"], "stop_received": row["stop_received"] is not None,
        "stop_received_at": row["stop_received"], "input_release": release,
        "input_release_confirmed_at": binding[1] if binding else None,
        "input_release_confirmation_clock": "unix_wall_time" if binding is not None and binding[1] is not None else None,
        "release_completed": True if release == "released" else False if release == "release_pending" else None,
        "requires_new_observation": row["interruption"] is not None,
        "automatic_reentry": bool(automatic),
        "reobserve_without_user_resume": bool(automatic and lease in {"released", "recovered"} and release not in {"unknown", "release_pending"}),
        "replay_old_action": False,
    }}


@dataclass(frozen=True)
class ForegroundStage:
    store: object = field(repr=False)
    owner: str
    action_id: str

    def snapshot(self):
        return self.store.status(self.owner, self.action_id)

    def check(self):
        self.store.check_dispatch(self.owner, self.action_id)
        with self.store.transaction(timeout=.02) as db:
            _active(self.store, db, self.owner, self.action_id, allow_sequence_gap=True)
            row = db.execute("SELECT deadline FROM foreground_stages WHERE action=?", (self.action_id,)).fetchone()
        if row is None:
            raise ControlError("foreground_stage_not_found")
        if row[0] is not None and self.store.clock() >= row[0]:
            self.interrupt("deadline_exceeded")
            raise ControlError("foreground_stage_deadline_exceeded")

    def interrupt(self, reason):
        if type(reason) is not str or reason not in _INTERRUPTIONS:
            raise ControlError("invalid_stage_interruption")
        with self.store.transaction() as db:
            # Cleanup/interruption must remain possible after Stop or revoke.
            locks = self.store._dispatch_locks.get(self.action_id)
            action = db.execute("SELECT * FROM actions WHERE id=? AND owner=?", (self.action_id, self.owner)).fetchone()
            if (not action or action["state"] != "running" or not (
                    _holds_foreground(locks, self.store._external_dispatches.get(self.action_id))
                    or _sequence_gap(self.store, db, self.action_id))
                    or self.store._dispatch_threads.get(self.action_id) != threading.get_ident()):
                raise ControlError("stage_requires_foreground_dispatch")
            self._record_interruption(db, action, reason)
        return self.snapshot()

    def interrupt_after_external(self, lease, reason):
        """Record a terminal native interruption inside its original dispatch.

        The facade has accepted done and the native mutex may already be free.
        This method records metadata only, preserving authoritative release state.
        Call before StateStore.finish and before leaving the before_go context.
        """
        from flower_control.drivers.high_helper import ExternalDispatchLease, HighHelperError
        if type(reason) is not str or reason not in _INTERRUPTIONS:
            raise ControlError("invalid_stage_interruption")
        if type(lease) is not ExternalDispatchLease:
            raise ControlError("external_terminal_unverified")
        try:
            lease.terminal_for_interruption()
        except HighHelperError as error:
            raise ControlError("external_terminal_unverified") from error
        with self.store.transaction() as db:
            action = db.execute("SELECT * FROM actions WHERE id=? AND owner=?", (self.action_id, self.owner)).fetchone()
            binding = db.execute("SELECT * FROM input_release_bindings WHERE action=?", (self.action_id,)).fetchone()
            stage = db.execute("SELECT * FROM foreground_stages WHERE action=?", (self.action_id,)).fetchone()
            if (action is None or action["state"] != "running" or binding is None or stage is None
                    or self.store._dispatch_threads.get(self.action_id) != threading.get_ident()
                    or self.store._external_dispatches.get(self.action_id) is not lease
                    or lease.action_id != self.action_id or lease.chat_id != action["task"]
                    or lease.resources != tuple(sorted(json.loads(action["resources"])))
                    or binding["executor_process"] != lease.executor_process
                    or binding["ledger_identity"] != lease.ledger_identity
                    or stage["dispatcher_process"] != lease.executor_process
                    or stage["target"] not in lease.resources):
                raise ControlError("external_terminal_binding_mismatch")
            self._record_interruption(db, action, reason)
        return self.snapshot()

    def _record_interruption(self, db, action, reason):
        row = db.execute("SELECT * FROM foreground_stages WHERE action=?", (self.action_id,)).fetchone()
        if row is None:
            raise ControlError("foreground_stage_not_found")
        now = self.store.clock()
        if reason == "explicit_stop":
            db.execute("UPDATE tasks SET paused=1,revision=revision+1 WHERE id=?", (action["task"],))
            self.store._stop_task_actions(db, action["task"])
            row = db.execute("SELECT * FROM foreground_stages WHERE action=?", (self.action_id,)).fetchone()
        # A later ordinary event cannot erase a previously received Stop.
        preserved = row["interruption"] if row["stop_received"] is not None else reason
        db.execute("UPDATE foreground_stages SET interruption=?,interrupted=COALESCE(interrupted,?),"
                   "stop_received=CASE WHEN ?='explicit_stop' THEN COALESCE(stop_received,?) ELSE stop_received END WHERE action=?",
                   (preserved, now, reason, now, self.action_id))
        db.execute("UPDATE actions SET cancel_requested=1,updated=? WHERE id=?", (now, self.action_id))
        db.execute("UPDATE observations SET expires=0 WHERE task=? AND resource=?", (action["task"], row["target"]))
        self.store._record_event(db, "foreground_interrupted", task=action["task"], action=self.action_id,
                                 details={"reason": preserved, "requires_new_observation": True, "replay_old_action": False})

    def validate_reentry(self, observation):
        """Validate a fresh observation, never replay or revive the old action."""
        with self.store.transaction() as db:
            connection = self.store._owner(db, self.owner)
            action = db.execute("SELECT * FROM actions WHERE id=? AND task=?", (self.action_id, connection["task"])).fetchone()
            if action is None:
                raise ControlError("action_not_found")
            summary = stage_summary(self.store, db, action).get("foreground_stage")
            if summary is None or not summary["reobserve_without_user_resume"]:
                raise ControlError("foreground_reentry_not_ready")
            self.store._require_input_release_confirmed(db)
            for resource in json.loads(action["resources"]):
                self.store._require_owned_resource(db, connection["task"], resource)
                required = db.execute("SELECT required_scope FROM resources WHERE id=?", (resource,)).fetchone()
                self.store._require_scope(db, connection["task"], required[0])
            if action["scope"]:
                self.store._require_scope(db, connection["task"], action["scope"])
            target = db.execute("SELECT revision,generation FROM resources WHERE id=?", (summary["target_resource"],)).fetchone()
            observed = db.execute("SELECT * FROM observations WHERE id=?", (observation,)).fetchone()
            if (observed is None or observed["task"] != connection["task"]
                    or observed["resource"] != summary["target_resource"] or observed["expires"] <= self.store.clock()
                    or observed["revision"] != target["revision"] or observed["generation"] != target["generation"]):
                raise ControlError("fresh_foreground_observation_required")
            return {"observation": observation, "target_resource": summary["target_resource"],
                    "new_action_required": True, "replay_old_action": False}

    def bind_input_release(self, ledger_identity, *, executor_process=None):
        # A caller-owned non-content digest binds the exact aggregate ledger.
        if (type(ledger_identity) is not str or len(ledger_identity) != 64
                or any(c not in "0123456789abcdef" for c in ledger_identity)):
            raise ControlError("invalid_input_ledger_identity")
        token = secrets.token_urlsafe(32)
        with self.store.transaction() as db:
            connection, action = _active(self.store, db, self.owner, self.action_id)
            if not db.execute("SELECT 1 FROM foreground_stages WHERE action=?", (self.action_id,)).fetchone():
                raise ControlError("foreground_stage_not_found")
            permit = db.execute("SELECT worker_process FROM worker_permits WHERE action=?", (self.action_id,)).fetchone()
            executor = executor_process if executor_process is not None else connection["process"]
            external = self.store._external_dispatches.get(self.action_id)
            external_executor = external.executor_process if external is not None else None
            if (executor != connection["process"] and executor != external_executor and (permit is None or executor != permit[0])
                    or not process_is_alive(executor)):
                raise ControlError("input_executor_binding_mismatch")
            old = db.execute("SELECT * FROM input_release_bindings WHERE action=?", (self.action_id,)).fetchone()
            if old:
                if (external is None or external._release_binding_issued
                        or external.ledger_identity != ledger_identity or external.executor_process != executor
                        or old["ledger_identity"] != ledger_identity or old["executor_process"] != executor
                        or old["confirmed"] is not None):
                    raise ControlError("input_release_already_bound")
                external.verify()
                # The sealed native lease persisted this ledger at dispatch.
                # Issue the optional consumer token once for the same ledger.
                db.execute("DELETE FROM input_release_bindings WHERE action=?", (self.action_id,))
            db.execute("INSERT INTO input_release_bindings VALUES (?,?,?,?,NULL)",
                       (self.action_id, executor, ledger_identity, hashlib.sha256(token.encode()).hexdigest()))
            # Pre-down durable uncertainty makes dispatcher death recoverable.
            db.execute("INSERT OR IGNORE INTO action_effects(action) VALUES (?)", (self.action_id,))
            db.execute("UPDATE action_effects SET input_release='unknown' WHERE action=?", (self.action_id,))
            if external is not None:
                external._release_binding_issued = True
        return ReleaseBinding(self.action_id, executor, ledger_identity, token)


def begin_foreground_stage(store, owner, action_id, *, target_resource, channel, operation, deadline_ms=None):
    if (type(channel) is not str or channel not in {"app", "computer", "web"} or type(operation) is not str
            or not operation.strip() or len(operation) > 96
            or deadline_ms is not None and (type(deadline_ms) is not int or deadline_ms <= 0)):
        raise ControlError("invalid_foreground_stage")
    operation = target_description(operation, 96)
    with store.transaction() as db:
        connection, action = _active(store, db, owner, action_id)
        if target_resource == FOREGROUND_INPUT_RESOURCE or target_resource not in json.loads(action["resources"]):
            raise ControlError("stage_target_mismatch")
        context_row = db.execute("SELECT details FROM action_context WHERE action=?", (action_id,)).fetchone()
        context = json.loads(context_row[0]) if context_row else {}
        if context.get("channel", channel) != channel or context.get("operation", operation) != operation:
            raise ControlError("stage_context_mismatch")
        if db.execute("SELECT 1 FROM foreground_stages WHERE action=?", (action_id,)).fetchone():
            raise ControlError("foreground_stage_already_started")
        now = store.clock()
        deadline = now + deadline_ms / 1000 if deadline_ms is not None else None
        external = store._external_dispatches.get(action_id)
        executor = external.executor_process if external is not None else connection["process"]
        db.execute("INSERT INTO foreground_stages(action,target,channel,operation,dispatcher_process,boot,started,deadline) VALUES (?,?,?,?,?,?,?,?)",
                   (action_id, target_resource, channel, operation, executor, store.boot, now, deadline))
        store._record_event(db, "foreground_stage_started", task=action["task"], action=action_id,
                            details={"channel": channel, "operation": operation, "deadline": deadline})
    return ForegroundStage(store, owner, action_id)


def measured_stage_cost(store, owner, *, channel, operation, limit=16):
    if type(channel) is not str or channel not in {"web", "app", "computer"} or type(operation) is not str or type(limit) is not int or not 1 <= limit <= 32:
        raise ControlError("invalid_stage_measurement")
    operation = target_description(operation, 96)
    with store.transaction() as db:
        connection = store._owner(db, owner, diagnostics=True)
        rows = db.execute("SELECT s.action,s.started,s.ended FROM foreground_stages s JOIN actions a ON a.id=s.action "
                          "WHERE a.task=? AND s.channel=? AND s.operation=? AND s.ended IS NOT NULL "
                          "AND s.lease_released IS NOT NULL AND s.interruption IS NULL AND s.boot=? "
                          "AND a.state IN ('verified','not_verified') ORDER BY s.ended DESC LIMIT ?",
                          (connection["task"], channel, operation, store.boot, limit)).fetchall()
    if not rows:
        return StageCost()
    duration = max(max(0, math.ceil((row["ended"] - row["started"]) * 1000)) for row in rows)
    sample_id = hashlib.sha256(json.dumps([tuple(row) for row in rows]).encode()).hexdigest()[:16]
    return StageCost(duration, "measurement", f"foreground_stages:{len(rows)}:{sample_id}")


@contextmanager
def _bound_jev_context(*, task, action, channel, observation_id):
    # The existing jev_context intentionally inherits None. These adapters
    # instead know the exact ledger binding, including genuinely unknown IDs.
    # Keep the shared usage object; never inherit another task/action's IDs.
    from .jev_diagnostics import _context, current_context
    previous = current_context()
    value = {"task": task, "action": action, "channel": channel, "observation_id": observation_id,
             "decision_id": previous.get("decision_id") if previous.get("task") == task and previous.get("action") == action else None,
             "usage": previous.get("usage") if previous.get("task") in (None, task) else None}
    token = _context.set(value)
    try:
        yield
    finally:
        _context.reset(token)


@contextmanager
def foreground_stage_context(stage):
    with stage.store.transaction() as db:
        action = db.execute("SELECT * FROM actions WHERE id=? AND owner=?", (stage.action_id, stage.owner)).fetchone()
        row = db.execute("SELECT channel FROM foreground_stages WHERE action=?", (stage.action_id,)).fetchone()
        if action is None or row is None:
            raise ControlError("foreground_stage_not_found")
    with _bound_jev_context(task=action["task"], channel=row[0], action=stage.action_id, observation_id=action["observation"]):
        yield


@contextmanager
def yielded_foreground_wait(store, owner, *, reason, action_id=None, channel=None):
    if type(reason) is not str or reason not in {"model", "network"} or (channel is not None and (type(channel) is not str or channel not in {"web", "app", "computer"})):
        raise ControlError("invalid_foreground_wait")
    # Refuse even if finish() already made the action terminal: the physical
    # mutex remains held until the enclosing dispatch context actually exits.
    for locks in tuple(store._native_dispatches.values()):
        if _holds_foreground(locks) and locks.thread_id == threading.get_ident():
            raise ControlError("foreground_wait_requires_yield")
    for key, external in tuple(store._external_native_dispatches.items()):
        must_yield = external.wait_requires_yield(FOREGROUND_INPUT_RESOURCE)
        if not must_yield:
            store._external_native_dispatches.pop(key, None)
        if external.thread_id == threading.get_ident() and must_yield:
            raise ControlError("foreground_wait_requires_yield")
    with store.transaction() as db:
        connection = store._owner(db, owner, diagnostics=True)
        observation = None
        if action_id is not None:
            action = db.execute("SELECT * FROM actions WHERE id=? AND task=?", (action_id, connection["task"])).fetchone()
            if action is None:
                raise ControlError("action_not_found")
            stage = db.execute("SELECT channel,lease_released FROM foreground_stages WHERE action=?", (action_id,)).fetchone()
            if stage is not None:
                live_stage = db.execute("SELECT dispatcher_process,boot FROM foreground_stages WHERE action=?", (action_id,)).fetchone()
                confirmation = db.execute("SELECT confirmed FROM input_release_bindings WHERE action=?", (action_id,)).fetchone()
                if (stage["lease_released"] is None and live_stage["boot"] == store.boot
                        and (confirmation is None or confirmation[0] is None)
                        and process_is_alive(live_stage["dispatcher_process"])):
                    raise ControlError("foreground_wait_requires_yield")
                if channel is not None and channel != stage["channel"]:
                    raise ControlError("stage_context_mismatch")
                channel = stage["channel"]
            observation = action["observation"]
        store._record_event(db, "foreground_wait_started", task=connection["task"], action=action_id,
                            details={"reason": reason, "channel": channel, "caller_input_mutex_held": False})
    with _bound_jev_context(task=connection["task"], channel=channel, action=action_id, observation_id=observation):
        try:
            yield
        finally:
            store.record_event("foreground_wait_finished", task=connection["task"], action=action_id,
                               details={"reason": reason, "channel": channel})
