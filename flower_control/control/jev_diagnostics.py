"""Local Jev attempt metadata; never request, response, headers or trace info."""
from __future__ import annotations

from contextlib import closing, contextmanager, asynccontextmanager
import asyncio
from contextvars import ContextVar
import json
from pathlib import Path
import sqlite3
import sys
import time
import threading
from dataclasses import dataclass, field
import math
import re
import uuid

from .diagnostics import safe_metadata


_context = ContextVar("flower_jev_diagnostic_context", default=None)
_public_tool_context = ContextVar("flower_public_tool_context", default=None)


def public_tool_name_valid(channel, tool):
    """Use the existing tool registry; this check grants no authorization."""
    from flower_control.authorization.hook_bridge import WEB_TOOLS, APP_TOOLS, COMPUTER_TOOLS
    return type(channel) is str and type(tool) is str and tool in {
        "web": WEB_TOOLS, "app": APP_TOOLS, "computer": COMPUTER_TOOLS}.get(channel, ())


def _public_tool_event(store, event, *, task, details):
    """Diagnostic persistence never replaces a business return or exception."""
    try:
        # Diagnostics alone use a short wait and cannot create a missing DB.
        # Business connections and task validation retain their own contract.
        with closing(sqlite3.connect(store.path.resolve().as_uri() + "?mode=rw",
                uri=True, timeout=0.025, isolation_level=None)) as db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            try:
                # Keep StateStore's metadata bound, attribution and retention.
                store._record_event(db, event, task=task, details=details)
                db.commit()
            except BaseException:
                db.rollback()
                raise
    except (sqlite3.Error, OSError):
        # An absent endpoint remains unknown in the retained-log summary.
        # Do not retry the business or disclose exception text to stderr.
        pass


@contextmanager
def public_tool_call(store, *, task, channel, tool):
    """Record a consumed-origin public call through public-handler completion.

    Place at the public MCP boundary after origin consumption, not in runtimes.
    The compatible scope label origin_consumed_to_response_prepared covers only
    the handler's own target/wire metadata and image-byte preparation. It excludes
    subsequent SDK ImageContent/base64/JSON serialization, transport send and
    host receipt. Completion is NOT a transport acknowledgement.
    No parameters, origin tokens, results or exception text enter this log.
    """
    if not public_tool_name_valid(channel, tool):
        raise ValueError("invalid_public_tool_binding")
    if (_public_tool_context.get() or {}).get("active"):
        raise ValueError("nested_public_tool_boundary")
    started = time.monotonic()
    # Keep domain validation outside best-effort diagnostics. A read needs no
    # BEGIN IMMEDIATE write lock merely to check that the task still exists.
    _check_public_task(store, task)
    with _public_tool_scope(store, task=task, channel=channel, tool=tool, started=started) as call_id:
        yield call_id


def _check_public_task(store, task):
    try:
        with closing(store._connect()) as db:
            store._task(db, task)
    except sqlite3.Error as error:
        from flower_control.mcp_origin import ledger_error_code
        from .state import ControlError
        raise ControlError(ledger_error_code(error, prefix="control_ledger")) from None


@asynccontextmanager
async def public_tool_call_async(store, *, task, channel, tool):
    """Validate on a worker; bind and reset ContextVars on the MCP loop."""
    if not public_tool_name_valid(channel, tool):
        raise ValueError("invalid_public_tool_binding")
    if (_public_tool_context.get() or {}).get("active"):
        raise ValueError("nested_public_tool_boundary")
    started = time.monotonic()
    await asyncio.to_thread(_check_public_task, store, task)
    with _public_tool_scope(store, task=task, channel=channel, tool=tool, started=started) as call_id:
        yield call_id


@contextmanager
def _public_tool_scope(store, *, task, channel, tool, started):
    call_id = uuid.uuid4().hex
    details = {"call_id": call_id, "channel": channel, "tool": tool,
               "source": "public_mcp_boundary", "scope": "origin_consumed_to_response_prepared"}
    _public_tool_event(store, "public_tool_received", task=task, details=details)
    context = {**details, "task": task, "path": store.path.resolve(), "active": True}
    token = _public_tool_context.set(context)
    try:
        yield call_id
    except BaseException:
        _public_tool_event(store, "public_tool_aborted", task=task, details={**details,
            "elapsed_ms": max(0, round((time.monotonic() - started) * 1000))})
        raise
    else:
        _public_tool_event(store, "public_tool_completed", task=task, details={**details,
            "elapsed_ms": max(0, round((time.monotonic() - started) * 1000))})
    finally:
        context["active"] = False
        _public_tool_context.reset(token)


def _public_tool_binding(store, task, channel):
    context = _public_tool_context.get() or {}
    if (context.get("active") and context.get("task") == task
            and context.get("channel") == channel and context.get("path") == store.path.resolve()):
        return context["call_id"]
    return None


_ATTEMPT_FIELDS = frozenset({
    "request_id", "call_id", "client_id", "request_index", "attempt_index",
    "max_attempts", "kind", "question_count", "candidate_count", "slot_wait_ms",
    "gap_ms", "reason", "http_invoked", "request_ms", "http_phase_ms",
    "status_code", "connection", "tcp_started", "tls_started", "trace_observed",
    "trace_phase_ms", "usage"})
_TRACE_PHASES = frozenset({"connection.connect_tcp", "connection.start_tls",
    "http11.send_request_headers", "http2.send_request_headers",
    "http11.receive_response_headers", "http2.receive_response_headers",
    "http11.receive_response_body", "http2.receive_response_body"})


def attempt_metadata(details):
    """Only fixed producer fields; never admit an accidental body/trace-info."""
    result = {k: v for k, v in details.items() if k in _ATTEMPT_FIELDS}
    for field, allowed in (("trace_phase_ms", _TRACE_PHASES),
                           ("usage", {"input_tokens", "output_tokens"})):
        raw = result.get(field)
        if type(raw) is dict:
            result[field] = {k: v for k, v in raw.items()
                             if k in allowed and type(v) is int and v >= 0}
        elif field in result:
            result.pop(field)
    return safe_metadata(result)


@dataclass
class JevUsage:
    """Per-operation live counters, never reconstructed from retained history."""
    _lock: object = field(default_factory=threading.Lock, repr=False)
    parent: object = field(default=None, repr=False)
    started: int = 0
    finished: int = 0
    invocations: int = 0

    def observe(self, event, details):
        with self._lock:
            if event == "jev_http_started":
                self.started += 1
            elif event == "jev_http_finished":
                self.finished += 1
                self.invocations += int(details.get("http_invoked") is True)
        if self.parent is not None:
            self.parent.observe(event, details)

    def snapshot(self):
        with self._lock:
            return {"http_attempts_started": self.started, "http_attempts_finished": self.finished,
                    "http_attempts_pending": max(0, self.started-self.finished),
                    "http_observation_complete": self.started == self.finished,
                    "http_invocations_confirmed": self.invocations,
                    "http_invocations": self.invocations if self.started == self.finished else None}


@contextmanager
def jev_context(*, task=None, decision_id=None, channel=None, action=None,
                observation_id=None, usage=None):
    previous = _context.get() or {}
    value = {"task": task if task is not None else previous.get("task"),
             "decision_id": decision_id if decision_id is not None else previous.get("decision_id"),
             "channel": channel if channel is not None else previous.get("channel"),
             "action": action if action is not None else previous.get("action"),
             "observation_id": observation_id if observation_id is not None else previous.get("observation_id"),
             "usage": usage if usage is not None else previous.get("usage")}
    token = _context.set(value)
    try:
        yield
    finally:
        _context.reset(token)


def current_context():
    return dict(_context.get() or {})


def ledger_sink(directory):
    """Reuse the existing event ledger lazily, outside physical input dispatch."""
    reported = False
    path = (Path(directory) / "control.sqlite3").absolute()

    def emit(event, context, details):
        nonlocal reported
        if event not in {"jev_http_started", "jev_http_finished"}:
            return
        try:
            metadata = safe_metadata({
                **attempt_metadata(details), "decision_id": context.get("decision_id"),
                "channel": context.get("channel"), "observation_id": context.get("observation_id")})
            payload = json.dumps(metadata, separators=(",", ":"), allow_nan=False)
            if len(payload.encode("utf-8")) > 4096:
                raise ValueError("jev_diagnostic_size_limit")
            # Logging may lose an event under contention; it must not spend the
            # control ledger's five-second lock wait before an HTTP request.
            # rw also prevents a logging callback from creating a new ledger.
            db = sqlite3.connect(path.as_uri() + "?mode=rw", uri=True,
                                 timeout=0.025, isolation_level=None)
            try:
                db.execute("BEGIN IMMEDIATE")
                cursor = db.execute("INSERT INTO control_events(wall_time,monotonic,event,task,action,details) "
                                    "VALUES (?,?,?,?,?,?)",
                                    (time.time(), time.monotonic(), event, context.get("task"), context.get("action"), payload))
                if cursor.lastrowid % 128 == 0:
                    db.execute("DELETE FROM control_events WHERE seq<=?", (cursor.lastrowid - 20000,))
                db.commit()
            finally:
                db.close()
        except Exception:
            # Logging must not change selection or expose an exception payload.
            if not reported:
                print("Flower Jev diagnostics_write_failed", file=sys.stderr)
                reported = True
    return emit


def report_host_visual_result(store, *, task: str, action: str,
                              result_observation_id: str, result_observed_at: float,
                              outcome: str, evidence_digest: str | None = None) -> dict:
    """Record a host's judgement of a follow-up image, not a program Oracle.

    The channel supplies task from linked_call and observed_at from its own
    observation metadata. No host-provided timing/counts or image body enters
    this helper. It neither changes the action receipt nor grants execution.
    """
    if any(type(value) is not str or not value or len(value) > 256
           for value in (task, action, result_observation_id)):
        raise ValueError("host_visual_invalid_binding")
    if type(outcome) is not str or outcome not in {"completed", "not_completed", "uncertain"}:
        raise ValueError("host_visual_invalid_outcome")
    if evidence_digest is not None and (type(evidence_digest) is not str
            or re.fullmatch(r"[0-9a-fA-F]{64}", evidence_digest) is None):
        raise ValueError("host_visual_invalid_digest")
    with store.transaction() as db:
        original = db.execute("SELECT * FROM actions WHERE id=? AND task=?", (action, task)).fetchone()
        if original is None or original["state"] not in {"verified", "not_verified", "outcome_uncertain", "cancelled"}:
            raise ValueError("host_visual_action_not_completed")
        observed = db.execute("SELECT * FROM observations WHERE id=?", (result_observation_id,)).fetchone()
        resources = json.loads(original["resources"])
        if (observed is None or observed["task"] != task or observed["resource"] not in resources
                or observed["id"] == original["observation"]):
            raise ValueError("host_visual_observation_binding_mismatch")
        now = store.clock()
        if (type(result_observed_at) not in (int, float) or not math.isfinite(result_observed_at)
                or result_observed_at < original["updated"] or result_observed_at > now):
            raise ValueError("host_visual_observation_time_mismatch")
        resource = db.execute("SELECT * FROM resources WHERE id=?", (observed["resource"],)).fetchone()
        if (observed["expires"] <= now or resource is None or observed["revision"] != resource["revision"]
                or observed["generation"] != resource["generation"]):
            raise ValueError("host_visual_observation_stale")
        details = {"source":"host_visual_judgement", "channel":"computer",
            "binding":"task_action_resource_followup", "result_observation_id":result_observation_id,
            "resource":observed["resource"], "outcome":outcome, "evidence_digest":evidence_digest,
            "action_completed_at":original["updated"], "result_observed_at":result_observed_at,
            "reported_at":now}
        store._record_event(db, "host_visual_result", task=task, action=action, details=details)
    return dict(details)


class BusinessResultProducer:
    """Local result evidence carrier. Never mutates action state or dispatches.

    Start after enqueue, carry across resumptions, record at the business boundary
    using an independent channel oracle. A control receipt/semantic selection is
    insufficient. Human/host counts stay unknown unless explicitly measured.
    """
    def __init__(self, store, *, task, action, channel, observation_id=None,
                 started_at=None, clock=time.monotonic):
        if channel not in {"web", "app", "computer"}:
            raise ValueError("invalid_business_channel")
        self.store, self.task, self.action, self.channel = store, task, action, channel
        self.clock = clock
        self.started = clock() if started_at is None else started_at
        if type(self.started) not in (int, float) or not math.isfinite(self.started) or self.started > clock():
            raise ValueError("invalid_business_start")
        self.observation_id = observation_id
        self.usage = JevUsage()
        self.host_round_trips = None
        self.human_interventions = None
        self.decision_ids = []
        self._finished = None
        self._gate = threading.RLock()
        self._binding()

    def _binding(self):
        with self.store.transaction() as db:
            action = db.execute("SELECT * FROM actions WHERE id=? AND task=?", (self.action, self.task)).fetchone()
            task = db.execute("SELECT created FROM tasks WHERE id=?", (self.task,)).fetchone()
            if action is None or task is None:
                raise ValueError("business_action_binding_mismatch")
            resources = json.loads(action["resources"])
            if self.observation_id is not None:
                obs = db.execute("SELECT * FROM observations WHERE id=?", (self.observation_id,)).fetchone()
                if obs is None or obs["task"] != self.task or obs["resource"] not in resources:
                    raise ValueError("business_observation_binding_mismatch")
            details = dict(action)
            effects = db.execute("SELECT business_dispatched,activation_dispatched FROM action_effects WHERE action=?",
                                 (self.action,)).fetchone()
            occupancy = db.execute("SELECT started FROM occupancy WHERE action=?", (self.action,)).fetchone()
            details["business_dispatched"] = (None if effects is None or effects[0] is None else bool(effects[0]))
            details["activation_dispatched"] = (None if effects is None or effects[1] is None else bool(effects[1]))
            details["execution_started"] = occupancy[0] if occupancy else None
            return details, task["created"], resources

    def context(self, *, decision_id=None, observation_id=None):
        return jev_context(task=self.task, action=self.action, channel=self.channel,
                           decision_id=decision_id, observation_id=observation_id or self.observation_id,
                           usage=self.usage)

    def bind_decision(self, decision_id):
        with self._gate:
            if self._finished is not None:
                raise ValueError("business_result_already_finished")
            with self.store.transaction() as db:
                decision = db.execute("SELECT chosen FROM decisions WHERE id=?", (decision_id,)).fetchone()
                bound = decision is not None and decision["chosen"] == self.action
                if not bound:
                    rows = db.execute("SELECT details FROM control_events WHERE task=? AND event='target_selection' "
                                      "AND action=? ORDER BY seq DESC LIMIT 64",
                                      (self.task, self.action)).fetchall()
                    bound = any((data := json.loads(row[0])).get("decision_id") == decision_id
                                and self.observation_id is not None
                                and data.get("observation_id") == self.observation_id for row in rows)
                if not bound:
                    raise ValueError("business_decision_binding_mismatch")
            if decision_id not in self.decision_ids:
                if len(self.decision_ids) >= 64:
                    raise ValueError("business_decision_limit")
                self.decision_ids.append(decision_id)

    def measurements(self, *, host_round_trips=None, human_interventions=None):
        with self._gate:
            if self._finished is not None:
                raise ValueError("business_result_already_finished")
            for name, value in (("host_round_trips", host_round_trips), ("human_interventions", human_interventions)):
                if value is not None:
                    if type(value) is not int or value < 0:
                        raise ValueError("invalid_business_measurement")
                    prior = getattr(self, name)
                    if prior is not None and value < prior:
                        raise ValueError("business_measurement_regressed")
                    setattr(self, name, value)

    def finish(self, *, outcome, oracle=None, verifier=None, evidence_digest=None,
               result_observation_id=None, result_observed_at=None, failure_class=None):
        """Return/record metadata once. Verification failure stays unverified.

        verifier is a synchronous bool channel oracle, run OUTSIDE a DB lock;
        callers must bind it to the exact business result and must not dispatch
        input within it. No UI text, image or raw evidence enters the log.
        """
        with self._gate:
            if self._finished is not None:
                raise ValueError("business_result_already_finished")
            if outcome not in {"verified", "unverified", "failed", "cancelled"}:
                raise ValueError("invalid_business_outcome")
            if oracle not in {None, "dom_postcondition", "uia_readback", "visual_postcondition", "file_postcondition", "process_exit"}:
                raise ValueError("invalid_business_oracle")
            if evidence_digest is not None and (type(evidence_digest) is not str or re.fullmatch(r"[0-9a-fA-F]{64}", evidence_digest) is None):
                raise ValueError("invalid_business_evidence_digest")
            if failure_class not in {None, "permission", "stale", "target_unavailable", "dispatch", "outcome_unknown",
                                     "provider", "transport", "timeout", "cancelled", "business_mismatch", "other"}:
                raise ValueError("invalid_business_failure_class")
            action, task_start, resources = self._binding()
            if result_observed_at is not None and (type(result_observed_at) not in (int, float)
                    or not math.isfinite(result_observed_at) or result_observed_at < 0):
                raise ValueError("invalid_business_observation_time")
            if result_observation_id is not None:
                with self.store.transaction() as db:
                    obs = db.execute("SELECT task,resource FROM observations WHERE id=?", (result_observation_id,)).fetchone()
                    if obs is None or obs["task"] != self.task or obs["resource"] not in resources:
                        raise ValueError("business_result_observation_binding_mismatch")
            verification = "not_requested"
            if outcome == "verified":
                if (oracle not in {"dom_postcondition", "uia_readback", "visual_postcondition", "file_postcondition", "process_exit"}
                        or not callable(verifier) or type(evidence_digest) is not str
                        or re.fullmatch(r"[0-9a-fA-F]{64}", evidence_digest) is None):
                    raise ValueError("independent_business_evidence_required")
                try:
                    verified = verifier() is True
                except Exception:
                    verified = False
                    verification = "oracle_failed"
                if not verified:
                    outcome = "unverified"
                    verification = "oracle_failed" if verification == "oracle_failed" else "oracle_mismatch"
                else:
                    verification = "oracle_verified"
                # These UI oracles need a fresh new observation, not just the
                # old plan/selected control or successful dispatch receipt.
                if oracle in {"dom_postcondition", "uia_readback", "visual_postcondition"}:
                    if (type(result_observed_at) not in (int, float) or not math.isfinite(result_observed_at)
                            or result_observed_at < max(self.started, action["execution_started"] or self.started)
                            or result_observed_at > self.clock()):
                        outcome, verification = "unverified", "result_observation_time_unbound"
                    with self.store.transaction() as db:
                        obs = db.execute("SELECT * FROM observations WHERE id=?", (result_observation_id,)).fetchone()
                        resource = db.execute("SELECT * FROM resources WHERE id=?", (obs["resource"],)).fetchone() if obs else None
                        fresh = (obs is not None and obs["task"] == self.task and obs["resource"] in resources
                                 and obs["id"] != self.observation_id and obs["id"] != action["observation"]
                                 and obs["expires"] > self.store.clock() and resource is not None
                                 and obs["revision"] == resource["revision"] and obs["generation"] == resource["generation"])
                    if not fresh:
                        outcome, verification = "unverified", "result_observation_stale_or_unbound"
            action, task_start, _ = self._binding()
            details = {"channel": self.channel, "observation_id": self.observation_id,
                "result_observation_id": result_observation_id, "decision_ids": list(self.decision_ids),
                "result_observed_at": result_observed_at,
                "outcome": outcome, "verification": verification, "oracle": oracle,
                "evidence_digest": evidence_digest, "failure_class": failure_class,
                "action_receipt_state": action["state"], "action_dispatched": bool(action["dispatched"]),
                "business_dispatched": action["business_dispatched"], "activation_dispatched": action["activation_dispatched"],
                "elapsed_ms": max(0, round((self.clock()-self.started)*1000)),
                "task_age_ms": max(0, round((self.store.clock()-task_start)*1000)),
                "host_round_trips": self.host_round_trips, "human_interventions": self.human_interventions,
                "public_tool_call_id": _public_tool_binding(self.store, self.task, self.channel),
                **self.usage.snapshot()}
            self.store.record_event("business_result", task=self.task, action=self.action, details=details)
            self._finished = details
            return dict(details)
