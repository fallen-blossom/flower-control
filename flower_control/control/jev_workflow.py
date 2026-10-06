"""Continue already-planned short stages using the existing selector/drivers.

The channel supplies local progress, dispatch and readback. This loop never
owns input, permissions or a second client. Input/business content stays in
channel callbacks; only TargetRequest.payload reaches the existing Jev client.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import json
import time
from typing import Awaitable, Callable

from .target_selection import select_target, selection_stopped
from .targets import TargetCandidate, TargetRequest


@dataclass(frozen=True)
class TargetFlowStep:
    action_id: str
    request: TargetRequest
    progress_key: str
    permitted: Callable[[], Awaitable[bool]] = field(repr=False)
    fresh: Callable[[], Awaitable[bool]] = field(repr=False)
    selection_action_id: str | None = None

    def __post_init__(self):
        if (type(self.action_id) is not str or not self.action_id
                or type(self.request) is not TargetRequest
                or type(self.progress_key) is not str or not self.progress_key
                or not self.request.task_stage or not self.request.task_stage.strip()
                or not callable(self.permitted) or not callable(self.fresh)
                or self.selection_action_id is not None and (
                    type(self.selection_action_id) is not str or not self.selection_action_id)):
            raise ValueError("invalid_target_flow_step")


@dataclass(frozen=True)
class TargetFlowReadback:
    state: str
    progress_key: str
    value: object = field(default=None, repr=False)

    def __post_init__(self):
        if (self.state not in {"progress", "complete", "needs_host", "failed", "outcome_unknown"}
                or type(self.progress_key) is not str or not self.progress_key):
            raise ValueError("invalid_target_flow_readback")


@dataclass(frozen=True)
class TargetFlowResult:
    state: str
    reason: str
    completed_actions: tuple[str, ...]
    decision_ids: tuple[str, ...]
    elapsed_ms: int
    readback: TargetFlowReadback | None = field(repr=False)


def _uncertain(outcome):
    if type(outcome) is not dict:
        return True
    receipt = outcome.get("receipt", outcome)
    return (type(receipt) is not dict or receipt.get("state") not in {
        "verified", "not_verified", "cancelled", "observed"}
        or receipt.get("input_release") in {"unknown", "release_pending"})


async def run_target_flow(store, task, next_step, execute, readback, *, client_factory=None):
    """Select, dispatch once, cheaply read actual progress, then continue.

    next_step(last_readback) returns a TargetFlowStep or a terminal readback.
    execute(step, candidate) calls the channel's existing action API with the
    stable action_id; it must recheck the exact target and use write_admission
    at the final dispatch boundary. readback(step, candidate, outcome) returns
    TargetFlowReadback from real local state, with a progress_key representing
    relevant fields/focus/modal/result, not an arbitrary observation counter.

    Waiting and safe re-observation belong in those existing channel callbacks.
    A different legal recovery action may run against unchanged progress; the
    same operation/target cannot repeat there. Unknown writes never repeat.
    The channel's existing receipt and producer retain persistence/recovery.
    """
    if not all(callable(callback) for callback in (next_step, execute, readback)):
        raise ValueError("invalid_target_flow_callbacks")
    started = time.monotonic()
    completed, decisions, attempted, seen = [], [], set(), set()
    current = None

    def finish(state, reason):
        return TargetFlowResult(state, reason, tuple(completed), tuple(decisions),
            max(0, round((time.monotonic() - started) * 1000)), current)

    while True:
        if selection_stopped(store):
            return finish("stopped", "global_write_stopped")
        step = await next_step(current)
        if type(step) is TargetFlowReadback:
            current = step
            if step.state == "progress":
                raise ValueError("terminal_target_flow_readback_required")
            return finish(step.state, "local_readback")
        if type(step) is not TargetFlowStep:
            raise ValueError("invalid_target_flow_step")
        if step.action_id in attempted:
            return finish("needs_host", "action_already_attempted")
        selected = await select_target(store, task, step.request,
            client_factory=client_factory, permitted=step.permitted, fresh=step.fresh,
            action_id=step.selection_action_id)
        decisions.append(step.request.decision_id)
        if selected.candidate is None:
            state = "stopped" if selected.reason in {"not_permitted", "permission_changed"} else "needs_host"
            return finish(state, selected.reason)
        candidate = selected.candidate
        signature = (step.progress_key,
            candidate.action, json.dumps(candidate.local_target(), sort_keys=True, separators=(",", ":")))
        if signature in seen:
            return finish("needs_host", "no_progress")
        if selection_stopped(store):
            return finish("stopped", "global_write_stopped")
        # Cheap current authority/version checks; no UI tree, screenshot or HTTP.
        remaining = step.request.expires_at - time.monotonic()
        if remaining <= 0:
            return finish("needs_host", "stale_observation")
        try:
            async with asyncio.timeout(min(5.0, remaining)):
                if await step.permitted() is not True or selection_stopped(store):
                    return finish("stopped", "not_permitted")
                if await step.fresh() is not True:
                    return finish("needs_host", "stale_observation")
        except TimeoutError:
            return finish("needs_host", "timeout")
        if step.request.expires_at <= time.monotonic():
            return finish("needs_host", "stale_observation")
        attempted.add(step.action_id)
        seen.add(signature)
        outcome = await execute(step, candidate)
        receipt = outcome.get("receipt", outcome) if type(outcome) is dict else {}
        if (type(receipt) is dict and receipt.get("state") == "queued"
                and receipt.get("dispatched") in {False, 0}):
            return finish("waiting", "waiting_for_resource")
        # Read back even uncertain execution once; it may expose useful progress
        # for the existing recovery path, but never authorizes a write replay.
        current = await readback(step, candidate, outcome)
        if type(current) is not TargetFlowReadback:
            raise ValueError("invalid_target_flow_readback")
        if _uncertain(outcome):
            return finish("outcome_unknown", "action_outcome_unknown")
        if current.state != "progress":
            if current.state == "complete":
                completed.append(step.action_id)
            return finish(current.state, "local_readback")
        completed.append(step.action_id)
