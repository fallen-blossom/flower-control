"""Jev may rank a current legal group; the ledger owns final adoption."""
from __future__ import annotations

import asyncio
import json
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass

from .jev import JevClient
from .state import ControlError, StateStore
from .jev_diagnostics import jev_context, JevUsage, current_context
from .scheduling import build_jev_request, choose_local, conflict_groups
from .target_selection import selection_stopped


@dataclass(frozen=True)
class AdoptedDecision:
    decision_id: str
    action_id: str | None
    reason: str


def _event_binding(store, chosen=None):
    context = current_context()
    task, action = context.get("task"), context.get("action")
    candidate = action if action is not None else chosen
    if candidate is not None:
        with store.transaction() as db:
            row = db.execute("SELECT task FROM actions WHERE id=?", (candidate,)).fetchone()
        if row is not None and (task is None or task == row[0]):
            return row[0], candidate
    # Resource overlap never establishes another owner's task identity.
    return task, None


def _skipped(store, reason, *, decision_id="", chosen=None, opportunity=None):
    task, action = _event_binding(store, chosen)
    store.record_event("scheduling_skipped", task=task, action=action, details={
        "decision_id": decision_id, "reason": reason, "skip_reason": reason,
        "opportunity": opportunity, "client_invoked": False,
        "terminal": True, "chosen_action": chosen, "http_scope": "this_arbitration_call",
        **JevUsage().snapshot(),
    })


def _admission_reason(items, now, policy, request):
    """Explain the shared builder's rejection on its exact input snapshot."""
    if request is not None:
        return None
    if len(items) < 2:
        return "insufficient_candidates"
    if len(conflict_groups(items)) != 1:
        return "disconnected_candidates"
    if any(not item.ready for item in items):
        return "candidate_not_ready"
    if any(not item.jev_allowed for item in items):
        return "jev_disabled_or_not_allowed"
    if any(item.user_order is not None for item in items):
        return "explicit_user_order"
    if any((now - item.created_at) * 1000 >= policy.starvation_ms for item in items):
        return "fair_wait_limit"
    if any(item.recent_occupancy_ms >= policy.occupancy_budget_ms for item in items):
        return "occupancy_limit"
    return "admission_unclassified"


def _scheduling_snapshot(store, decision_id):
    """Read the ledger's scheduling inputs once; never mutate Core state.

    Mirrors scheduling_request's expiry/fingerprint checks and uses its existing
    candidate adapter and pure rank/request functions. Admission diagnostics and
    the actual request use identical candidates/time, not a second reread.
    """
    with store.transaction() as db:
        row = db.execute("SELECT * FROM decisions WHERE id=?", (decision_id,)).fetchone()
        if not row or row["state"] != "pending" or row["expires"] <= store.clock():
            raise ControlError("decision_expired")
        domain, ids, fingerprint = store._snapshot(db, tuple(json.loads(row["resources"])))
        if fingerprint != row["fingerprint"]:
            raise ControlError("decision_stale")
        items = store._scheduling_candidates(db, domain, ids)
        now = store.clock()
        local = choose_local(items, now, store.policy)
        request = build_jev_request(items, now, store.policy, secrets.token_bytes(24))
        return local, request, _admission_reason(items, now, store.policy, request)


async def arbitrate(store: StateStore, resources: tuple[str, ...], *, client: JevClient | None = None,
                    client_factory: Callable[[], JevClient] | None = None,
                    deadline_seconds: float = 3.0) -> AdoptedDecision:
    if not 0 < deadline_seconds <= 5:
        raise ValueError("invalid_arbitration_deadline")
    if client is not None and client_factory is not None:
        raise ValueError("choose one Jev client source")
    if selection_stopped(store):
        # The ledger may still schedule read-only work while writes are stopped.
        # Do not create a model/credential request; _check_action filters writes.
        client = client_factory = None
    try:
        decision = store.prepare_decision(resources, ttl=deadline_seconds)
    except ControlError as error:
        if error.code in {"no_eligible_actions", "decision_expired", "decision_stale"}:
            _skipped(store, error.code, opportunity=False if error.code == "no_eligible_actions" else None)
            return AdoptedDecision("", None, error.code)
        raise
    claim = None
    claim_deadline = time.monotonic() + deadline_seconds
    try:
        while store.clock() < decision["expires"] and time.monotonic() < claim_deadline:
            outcome = store.decision_outcome(decision["id"])
            if outcome is not None:
                _skipped(store, "decision_already_adopted", decision_id=outcome["id"], chosen=outcome["chosen"])
                return AdoptedDecision(outcome["id"], outcome["chosen"], outcome["reason"])
            claim = store.claim_decision_request(decision["id"])
            if claim is not None:
                break
            await asyncio.sleep(0.02)
    except asyncio.CancelledError:
        _skipped(store, "cancelled", decision_id=decision["id"])
        raise
    if claim is None:
        _skipped(store, "decision_in_flight", decision_id=decision["id"])
        return AdoptedDecision(decision["id"], None, "decision_in_flight")
    try:
        return await _evaluate(store, resources, decision, client, client_factory)
    finally:
        store.release_decision_request(decision["id"], claim)


async def _evaluate(store, resources, decision, client, client_factory):
    started = time.monotonic()
    try:
        local, request, skip_reason = _scheduling_snapshot(store, decision["id"])
    except ControlError as error:
        _skipped(store, error.code, decision_id=decision["id"])
        return AdoptedDecision(decision["id"], None, error.code)
    if local is None:
        _skipped(store, "no_eligible_candidate", decision_id=decision["id"], opportunity=False)
        return AdoptedDecision(decision["id"], None, "no_eligible_candidate")
    baseline = local.action_id
    if selection_stopped(store):
        request, skip_reason = None, "global_write_stopped"
    requested_decision_id = decision["id"]
    usage = JevUsage(parent=current_context().get("usage"))
    opportunity = request is not None
    client_invoked = False
    def logged(result, jev_elapsed_ms=None):
        event_task, event_action = _event_binding(store, result.action_id)
        counts = usage.snapshot()
        if client_invoked and not isinstance(client, JevClient) and counts["http_attempts_started"] == 0:
            # An arbitrary Choice adapter may not expose HTTP observations.
            counts.update(http_observation_complete=False, http_invocations=None)
        store.record_event("scheduling_decision", task=event_task, action=event_action,
                           details={"decision_id": result.decision_id, "reason": result.reason,
                                    "requested_decision_id": requested_decision_id,
                                    "chosen_action": result.action_id, "terminal": True,
                                    "http_scope": "this_arbitration_call",
                                    "local_reason": local.reason.value if local else None,
                                    "opportunity": opportunity, "client_invoked": client_invoked,
                                    "skip_reason": skip_reason,
                                    "candidate_count": len(json.loads(decision["candidates"])),
                                    "local_baseline": baseline,
                                    "different_from_local": result.action_id != baseline,
                                    "elapsed_ms": round((time.monotonic() - started) * 1000),
                                    "jev_elapsed_ms": jev_elapsed_ms,
                                    "candidates": request.payload if request else None,
                                    **counts})
        return result
    reason = "local"
    jev_elapsed_ms = None
    if request is not None and (client is not None or client_factory is not None):
        def permitted_sync():
            if selection_stopped(store):
                return False
            try:
                _, fresh = store.scheduling_request(decision["id"])
                return fresh is not None and not selection_stopped(store)
            except ControlError:
                return False
        async def permitted():
            return await asyncio.to_thread(permitted_sync)
        if client_factory is not None:
            try:
                client = client_factory()
            except (OSError, ValueError, TypeError, KeyError):
                client = None
                reason = "client_unavailable"
                skip_reason = "client_unavailable"
        if client is not None:
            try:
                client_invoked = True
                event_task, event_action = _event_binding(store)
                with jev_context(task=event_task, action=event_action,
                                 decision_id=decision["id"], usage=usage):
                    selected = await client.choose_scheduling(
                        request, deadline=decision["expires"], permitted=permitted)
                jev_elapsed_ms = selected.elapsed_ms
            except asyncio.CancelledError:
                logged(AdoptedDecision(decision["id"], None, "cancelled"))
                raise
            except (OSError, RuntimeError, TypeError, ValueError):
                selected = None
                reason = "client_unavailable"
                skip_reason = "client_unavailable"
            finally:
                if client_factory is not None:
                    try:
                        await client.close()
                    except (OSError, RuntimeError):
                        pass
        else:
            selected = None
        if (not selection_stopped(store) and selected is not None
                and selected.action_id is not None
                and store.adopt_decision(decision["id"], selected.action_id, "jev")):
            return logged(AdoptedDecision(decision["id"], selected.action_id, "jev"), selected.elapsed_ms)
        reason = selected.reason if selected is not None else reason
        # One fresh local snapshot after timeout or change; never retry the
        # model and never adopt a reply against a new fingerprint.
        try:
            decision = store.prepare_decision(resources, ttl=1)
            local, _ = store.scheduling_request(decision["id"])
        except ControlError as error:
            if error.code in {"no_eligible_actions", "decision_expired", "decision_stale"}:
                return logged(AdoptedDecision("", None, error.code), jev_elapsed_ms)
            raise
    if request is not None and not client_invoked and skip_reason is None:
        skip_reason = "client_unavailable"
    if local is not None and store.adopt_decision(decision["id"], local.action_id):
        return logged(AdoptedDecision(decision["id"], local.action_id, "local:" + reason), jev_elapsed_ms)
    return logged(AdoptedDecision(decision["id"], None, "queue_changed"), jev_elapsed_ms)


async def wait_for_turn(store: StateStore, owner: str, action_id: str,
                        resources: tuple[str, ...], *, client_factory=None,
                        timeout: float = 5.0) -> AdoptedDecision:
    """Retain this execution call while an occupied resource reaches a safe point.

    Only the requesting driver dispatches its own retained arguments. Status
    queries never execute an action, and timeout leaves the same action resumable.
    """
    if not 0 <= timeout <= 5:
        raise ValueError("invalid_turn_wait")
    if store.queue_status(owner, action_id)["state"] != "queued":
        return AdoptedDecision("", None, "not_queued")
    deadline = time.monotonic() + timeout
    token = store.retain_execution_call(owner, action_id, lifetime=timeout + 5)
    adopted_id = None
    try:
        last_reason = None
        while True:
            status = store.queue_status(owner, action_id)
            if status["state"] != "queued":
                return AdoptedDecision("", None, "not_queued")
            if status.get("eligibility") != "ready":
                return AdoptedDecision("", None, status.get("eligibility", "owner_unavailable"))
            reasons = status.get("waiting_reasons", [])
            if reasons != last_reason:
                store.record_event("queue_wait", action=action_id, details={"reasons": reasons})
                last_reason = reasons
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return AdoptedDecision("", None, "waiting_for_resource")
            if "another_action_running" not in reasons:
                with store.transaction() as db:
                    row = db.execute("SELECT task FROM actions WHERE id=? AND owner=?",
                                     (action_id, owner)).fetchone()
                with jev_context(task=row[0] if row else None, action=action_id):
                    decision = await arbitrate(store, resources, client_factory=client_factory,
                                               deadline_seconds=max(0.01, min(3.0, remaining)))
                if decision.action_id == action_id:
                    adopted_id = decision.decision_id
                    return decision
            if time.monotonic() >= deadline:
                return AdoptedDecision("", None, "waiting_for_resource")
            await asyncio.sleep(min(0.05, max(0, deadline - time.monotonic())))
    finally:
        store.release_execution_call(action_id, token, decision_id=adopted_id)



def wait_for_turn_sync(store, owner, action_id, resources, *, client_factory=None, timeout=5.0):
    return asyncio.run(wait_for_turn(store, owner, action_id, resources,
                                    client_factory=client_factory, timeout=timeout))


def arbitrate_sync(store: StateStore, resources: tuple[str, ...], *,
                   client_factory: Callable[[], JevClient] | None = None,
                   deadline_seconds: float = 3.0) -> AdoptedDecision:
    """Bridge synchronous App/Computer workers to the shared selection policy."""
    return asyncio.run(arbitrate(store, resources, client_factory=client_factory,
                                 deadline_seconds=deadline_seconds))
