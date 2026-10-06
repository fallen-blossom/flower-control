"""Pure, local ranking of already-authorized resource requests.

The caller owns identity, trustworthy focus/order events, monotonic task age,
resource completeness, authorization, persistence, and execution locks. A
selection here is a preference only; it never grants permission to dispatch.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from hashlib import sha256
from math import isfinite
from typing import Iterable

from .targets import target_description


class Phase(str, Enum):
    START = "start"
    WORK = "work"
    CONTINUE = "continue"
    FINISH = "finish"
    RECOVER = "recover"


class SelectionReason(str, Enum):
    ONLY_CANDIDATE = "only_candidate"
    USER_ORDER = "user_order"
    FAIR_WAIT = "fair_wait"
    FAIR_OCCUPANCY = "fair_occupancy"
    USER_FOCUS = "user_focus"
    BOUNDED_CONTINUATION = "bounded_continuation"
    SHORT_FINISH = "short_finish"
    FIFO = "fifo"


@dataclass(frozen=True)
class Candidate:
    action_id: str
    task_id: str
    resources: tuple[str, ...]
    created_at: float  # monotonic; caller must retain task age across reconnects
    user_focus: bool  # caller has verified the current user event
    continuation: bool
    continuation_spent_ms: int
    recent_occupancy_ms: int
    estimated_ms: int | None
    phase: Phase
    user_order: int | None
    jev_allowed: bool
    ready: bool
    task_hint: str | None = None
    operation: str | None = None
    channel: str | None = None
    foreground_needed: bool | None = None
    continuation_cost_ms: int | None = None

    def __post_init__(self) -> None:
        for name, limit in (("task_hint", 160), ("operation", 96)):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, target_description(value, limit))
        if self.channel is not None and (type(self.channel) is not str
                                        or self.channel not in {"web", "app", "computer"}):
            raise ValueError("invalid scheduling channel")
        if self.foreground_needed is not None and type(self.foreground_needed) is not bool:
            raise ValueError("foreground_needed must be a boolean or unknown")
        if self.continuation_cost_ms is not None and (
            type(self.continuation_cost_ms) is not int or self.continuation_cost_ms < 0
        ):
            raise ValueError("continuation_cost_ms must be nonnegative or unknown")
        if not self.action_id or not self.task_id:
            raise ValueError("candidate identifiers must be nonempty")
        if not isinstance(self.resources, tuple) or any(
            not isinstance(resource, str) or not resource for resource in self.resources
        ):
            raise ValueError("resources must be a tuple of nonempty identifiers")
        if not isfinite(self.created_at):
            raise ValueError("created_at must be finite")
        for name in ("continuation_spent_ms", "recent_occupancy_ms"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a nonnegative integer")
        if self.estimated_ms is not None and (
            isinstance(self.estimated_ms, bool)
            or not isinstance(self.estimated_ms, int)
            or self.estimated_ms < 0
        ):
            raise ValueError("estimated_ms must be nonnegative or unknown")
        if not isinstance(self.phase, Phase):
            raise ValueError("phase must be a Phase enum")
        if self.user_order is not None and (
            isinstance(self.user_order, bool) or not isinstance(self.user_order, int)
        ):
            raise ValueError("user_order must be an integer or unknown")


@dataclass(frozen=True)
class Policy:
    """Caller-owned measured thresholds; no production defaults are asserted."""

    starvation_ms: int
    occupancy_budget_ms: int
    continuation_budget_ms: int

    def __post_init__(self) -> None:
        for value in (
            self.starvation_ms,
            self.occupancy_budget_ms,
            self.continuation_budget_ms,
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError("policy thresholds must be positive integers")


@dataclass(frozen=True)
class Selection:
    action_id: str
    reason: SelectionReason


@dataclass(frozen=True)
class JevRequest:
    """Only ``payload`` may leave the machine; the resolver stays local."""

    payload: dict
    _action_by_id: dict[str, str] = field(repr=False)

    def resolve(self, opaque_candidate_id: str) -> str | None:
        return self._action_by_id.get(opaque_candidate_id)


def _validated(candidates: Iterable[Candidate], now: float) -> tuple[Candidate, ...]:
    if not isfinite(now):
        raise ValueError("now must be a finite monotonic timestamp")
    items = tuple(candidates)
    if len({item.action_id for item in items}) != len(items):
        raise ValueError("action_id must be unique within a comparison")
    if any(item.created_at > now for item in items):
        raise ValueError("candidate created after now")
    return items


def conflict_groups(candidates: Iterable[Candidate]) -> tuple[tuple[Candidate, ...], ...]:
    """Connected components of complete resource sets, including singletons."""

    items = tuple(candidates)
    if len({item.action_id for item in items}) != len(items):
        raise ValueError("action_id must be unique")
    parent = list(range(len(items)))

    def root(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    owner: dict[str, int] = {}
    for index, item in enumerate(items):
        for resource in item.resources:
            previous = owner.setdefault(resource, index)
            parent[root(index)] = root(previous)

    groups: dict[int, list[Candidate]] = {}
    for index, item in enumerate(items):
        groups.setdefault(root(index), []).append(item)
    return tuple(tuple(group) for group in groups.values())


def eligible_candidates(
    candidates: Iterable[Candidate], now: float, policy: Policy
) -> tuple[tuple[Candidate, ...], ...]:
    """Return ready contenders; unavailable requests cannot bridge conflicts."""

    _ = policy  # thresholds rank contenders; they do not erase legal requests
    return conflict_groups(item for item in _validated(candidates, now) if item.ready)


def _wait_ms(item: Candidate, now: float) -> float:
    return (now - item.created_at) * 1000


def _fifo(items: Iterable[Candidate]) -> Candidate:
    return min(items, key=lambda item: (item.created_at, item.action_id))


def choose_local(group: Iterable[Candidate], now: float, policy: Policy) -> Selection | None:
    """Select one preference from one ready conflict group, without a grant."""

    items = _validated(group, now)
    if not items:
        return None
    if any(not item.ready for item in items) or len(conflict_groups(items)) != 1:
        raise ValueError("choose_local requires one ready conflict group")
    if len(items) == 1:
        return Selection(items[0].action_id, SelectionReason.ONLY_CANDIDATE)

    ordered = [item for item in items if item.user_order is not None]
    if ordered:
        best_order = min(item.user_order for item in ordered)
        pool = [item for item in ordered if item.user_order == best_order]
        if len(pool) == 1:
            return Selection(pool[0].action_id, SelectionReason.USER_ORDER)
        items = tuple(pool)

    starved = [item for item in items if _wait_ms(item, now) >= policy.starvation_ms]
    if starved:
        winner = min(
            starved,
            key=lambda item: (item.created_at, item.recent_occupancy_ms, item.action_id),
        )
        return Selection(winner.action_id, SelectionReason.FAIR_WAIT)

    under_budget = [
        item for item in items if item.recent_occupancy_ms < policy.occupancy_budget_ms
    ]
    occupancy_limited = bool(under_budget) and len(under_budget) < len(items)
    if under_budget:
        items = tuple(under_budget)

    focused = [item for item in items if item.user_focus]
    if focused:
        return Selection(_fifo(focused).action_id, SelectionReason.USER_FOCUS)

    continuing = [
        item
        for item in items
        if item.continuation
        and item.estimated_ms is not None
        and item.continuation_spent_ms + item.estimated_ms
        <= policy.continuation_budget_ms
        and item.recent_occupancy_ms + item.estimated_ms
        <= policy.occupancy_budget_ms
    ]
    if continuing:
        # Preserve FIFO when costs are unknown. Within the existing bounded
        # continuation budget, a measured costly interruption is relevant.
        winner = min(continuing, key=lambda item: (
            -(item.continuation_cost_ms or 0), item.created_at, item.action_id))
        return Selection(winner.action_id, SelectionReason.BOUNDED_CONTINUATION)

    finishing = [
        item
        for item in items
        if item.phase is Phase.FINISH
        and item.estimated_ms is not None
        and item.estimated_ms <= policy.continuation_budget_ms
        and item.recent_occupancy_ms + item.estimated_ms
        <= policy.occupancy_budget_ms
    ]
    if finishing:
        return Selection(_fifo(finishing).action_id, SelectionReason.SHORT_FINISH)

    reason = SelectionReason.FAIR_OCCUPANCY if occupancy_limited else SelectionReason.FIFO
    return Selection(_fifo(items).action_id, reason)


_RESOURCE_CATEGORIES = frozenset(
    {"browser", "page", "profile", "app", "window", "desktop", "clipboard", "target"}
)


def _resource_category(resource: str) -> str:
    category = resource.split(":", 1)[0].lower()
    return category if category in _RESOURCE_CATEGORIES else "other"


def _wait_bucket(wait_ms: float, policy: Policy) -> str:
    if wait_ms >= policy.starvation_ms / 2:
        return "near_fairness_limit"
    if wait_ms >= policy.starvation_ms / 4:
        return "waiting"
    return "recent"


def _occupancy_bucket(used_ms: int, policy: Policy) -> str:
    if used_ms >= policy.occupancy_budget_ms:
        return "at_limit"
    if used_ms >= policy.occupancy_budget_ms / 2:
        return "elevated"
    return "low"


def build_jev_request(
    group: Iterable[Candidate], now: float, policy: Policy, nonce: bytes
) -> JevRequest | None:
    """Build a whitelist payload using a fresh caller-supplied random nonce.

    Returns None for any unpermitted, non-ready or locally constrained group.
    The nonce must be generated anew for each comparison by the caller.
    """

    items = _validated(group, now)
    if len(items) < 2 or len(conflict_groups(items)) != 1:
        return None
    if not isinstance(nonce, bytes) or len(nonce) < 16:
        raise ValueError("nonce must contain at least 16 random bytes")
    if any(not item.ready or not item.jev_allowed for item in items):
        return None
    if any(item.user_order is not None for item in items):
        return None
    if any(_wait_ms(item, now) >= policy.starvation_ms for item in items):
        return None
    if any(item.recent_occupancy_ms >= policy.occupancy_budget_ms for item in items):
        return None

    payload_items: list[dict] = []
    action_by_id: dict[str, str] = {}
    for index, item in enumerate(items):
        opaque_id = sha256(nonce + index.to_bytes(8, "big")).hexdigest()[:32]
        action_by_id[opaque_id] = item.action_id
        payload_items.append(
            {
                "candidate_id": opaque_id,
                "phase": item.phase.value,
                "resource_categories": sorted(
                    {_resource_category(resource) for resource in item.resources}
                ),
                "focus": "verified" if item.user_focus else "unknown",
                "wait_bucket": _wait_bucket(_wait_ms(item, now), policy),
                "occupancy_bucket": _occupancy_bucket(item.recent_occupancy_ms, policy),
            }
        )
        context = {name: getattr(item, name) for name in (
            "task_hint", "operation", "channel", "foreground_needed", "continuation_cost_ms"
        ) if getattr(item, name) is not None}
        if context:
            # Context describes work, never input values or exact local identity.
            context.update(estimated_ms=item.estimated_ms,
                           wait_ms=max(0, round(_wait_ms(item, now))),
                           continuation=item.continuation,
                           continuation_spent_ms=item.continuation_spent_ms)
            payload_items[-1].update(context)
    return JevRequest({"candidates": payload_items}, action_by_id)


def scheduling_context(*, channel, operation, task_hint=None,
                       foreground_needed=None, continuation_cost_ms=None, task_stage=None):
    """Stable producer-to-enqueue context. No new state-schema fields required.

    Estimates are measured next-phase costs, never inferred from channel rank.
    Missing hints remain unknown; passwords/input values must not be provided.
    """
    if channel not in {"web", "app", "computer"}:
        raise ValueError("invalid scheduling channel")
    result = {"channel": channel, "operation": target_description(operation, 96)}
    if task_stage is not None:
        stage = target_description(task_stage, 96)
        hint = target_description(task_hint, 60) if task_hint is not None else ""
        result["task_hint"] = (hint + " | " if hint else "") + stage
    elif task_hint is not None:
        result["task_hint"] = target_description(task_hint, 160)
    if foreground_needed is not None:
        if type(foreground_needed) is not bool:
            raise ValueError("foreground_needed must be a boolean or unknown")
        result["foreground_needed"] = foreground_needed
    if continuation_cost_ms is not None:
        if type(continuation_cost_ms) is not int or continuation_cost_ms < 0:
            raise ValueError("continuation_cost_ms must be nonnegative or unknown")
        result["continuation_cost_ms"] = continuation_cost_ms
    return result
