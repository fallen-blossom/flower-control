"""Observed semantic candidates with local identity and bounded Jev text.

This module never observes, authorizes or dispatches. A channel supplies the
already observed exact references and rechecks them before using a selection.
Only ``TargetRequest.payload`` may be sent to Jev; references stay local.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import asyncio
import json
import math
import re
from types import MappingProxyType
import time
from typing import Awaitable, Callable, Mapping
import uuid

from .diagnostics import safe_description


CHANNEL_SOURCES = {"web": {"dom", "accessibility"}, "app": {"uia"},
                   "computer": {"uia", "ocr", "host_region"}}
ACTIONS = frozenset({"click", "invoke", "fill", "set_value", "select", "select_option",
                     "select_item", "set_checked", "set_toggle", "expand", "collapse",
                     "scroll", "press", "focus", "read", "drag", "upload", "realize_item"})
POSITIONS = frozenset({"top_left", "top", "top_right", "left", "center", "right",
                       "bottom_left", "bottom", "bottom_right", "unknown"})
EXPECTED = frozenset({"activated", "focused", "value_changed", "selected", "checked",
                      "expanded", "collapsed", "scrolled", "navigated", "opened",
                      "closed", "read", "uploaded", "unknown"})
MATCHES = frozenset({"exact", "partial", "unknown"})
_ROLES = frozenset({"button", "textbox", "checkbox", "radio", "combobox", "listitem",
                    "menuitem", "tab", "link", "slider", "canvas", "region",
                    "scrollbar", "treeitem", "unknown"})
_ROLE_ALIASES = {"input": "textbox", "edit": "textbox", "textarea": "textbox",
                 "radiobutton": "radio", "listbox": "combobox", "select": "combobox",
                 "tabitem": "tab", "hyperlink": "link", "pane": "region",
                 "custom": "region", "document": "region"}
_CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?i)(\b(?:password|passwd|pwd|api[_ -]?key|access[_ -]?token|refresh[_ -]?token|"
    r"secret|token|authorization|cookies?|credential(?:s)?)\b|密码|密钥)"
    r"([\"']?\s*(?:[:=：]|(?:是|为)|\bis\b)\s*)(\"[^\"]*\"|'[^']*'|[^\s,;，；]+)")
_COOKIE_HEADER = re.compile(r"(?im)\b(?:cookies?|set-cookie|authorization)\s*[:=：]\s*[^\r\n]+")
_KEY_MATERIAL = re.compile(
    r"-----BEGIN [^-]*(?:PRIVATE KEY|SECRET)[^-]*-----.*?(?:-----END [^-]+-----|$)"
    r"|\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{12,}|"
    r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b", re.DOTALL)


def target_description(value: str, limit: int = 160) -> str:
    """Retain ordinary target text, excluding recognizable credential values."""
    if type(value) is not str:
        raise ValueError("invalid_target_description")
    value = _COOKIE_HEADER.sub("[credential excluded]", value)
    value = _CREDENTIAL_ASSIGNMENT.sub(
        lambda match: match[1] + match[2] + "[credential excluded]", value)
    value = _KEY_MATERIAL.sub("[credential excluded]", value)
    return safe_description(value, max(limit, len(value)))[:limit]


def _freeze(value):
    if type(value) is dict:
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if type(value) is list:
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value):
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if type(value) is tuple:
        return [_thaw(item) for item in value]
    return value


def _role(value: str) -> str:
    normalized = value.lower().replace(" ", "").replace("_", "")
    normalized = _ROLE_ALIASES.get(normalized, normalized)
    return normalized if normalized in _ROLES else "unknown"


@dataclass(frozen=True)
class TargetCandidate:
    target_id: str
    channel: str
    source: str
    action: str
    role: str
    label: str
    target: Mapping = field(repr=False)
    visible: bool = True
    enabled: bool = True
    position: str = "unknown"
    expected: str = "unknown"
    match: str = "unknown"
    password: bool = False
    action_patterns: tuple[str, ...] = ()
    evidence_hint: str = ""
    _literal_label: bool = field(init=False, repr=False)

    def __post_init__(self):
        if (type(self.target_id) is not str or not self.target_id
                or self.channel not in CHANNEL_SOURCES
                or self.source not in CHANNEL_SOURCES[self.channel]
                or self.action not in ACTIONS
                or type(self.role) is not str
                or self.position not in POSITIONS or self.expected not in EXPECTED
                or self.match not in MATCHES
                or any(type(value) is not bool for value in
                       (self.visible, self.enabled, self.password))):
            raise ValueError("invalid_target_candidate")
        if (type(self.action_patterns) is not tuple or len(self.action_patterns) > 12
                or any(type(pattern) is not str or pattern not in ACTIONS for pattern in self.action_patterns)):
            raise ValueError("invalid_candidate_patterns")
        object.__setattr__(self, "evidence_hint", target_description(self.evidence_hint, 160))
        local = _thaw(self.target)
        if type(local) is not dict or not local:
            raise ValueError("exact_local_target_required")
        # Reject non-JSON objects and take an immutable identity snapshot.
        local = json.loads(json.dumps(local, allow_nan=False))
        label = target_description(self.label, 96)
        object.__setattr__(self, "target", _freeze(local))
        object.__setattr__(self, "role", _role(self.role))
        object.__setattr__(self, "_literal_label",
                           self.label.strip() == label.strip() and "[credential excluded]" not in label)
        object.__setattr__(self, "label", label)

    def local_target(self) -> dict:
        """Return a fresh ordinary dict for the channel's exact dispatch API."""
        return _thaw(self.target)


@dataclass(frozen=True)
class TargetRequest:
    goal_hint: str
    observation_id: str
    version: int | str
    candidates: tuple[TargetCandidate, ...]
    expires_at: float
    complete: bool = True
    fallback_id: str | None = None
    decision_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    task_stage: str | None = None
    candidate_scope: str = "exhaustive"
    assessment_questions: tuple[str, ...] = ()
    _candidate_by_id: Mapping = field(init=False, repr=False)
    _literal_goal: bool = field(init=False, repr=False)

    def __post_init__(self):
        if (type(self.observation_id) is not str or not self.observation_id
                or type(self.version) not in (int, str)
                or (type(self.version) is int and self.version < 0)
                or (type(self.version) is str and not self.version)
                or type(self.expires_at) not in (float, int)
                or not math.isfinite(self.expires_at)
                or type(self.complete) is not bool
                or type(self.decision_id) is not str or not self.decision_id
                or type(self.candidates) is not tuple
                or len(self.candidates) > 32
                or any(type(item) is not TargetCandidate for item in self.candidates)
                or len({item.target_id for item in self.candidates}) != len(self.candidates)):
            raise ValueError("invalid_target_request")
        if self.candidate_scope not in {"exhaustive", "bounded"}:
            raise ValueError("invalid_target_candidate_scope")
        if (type(self.assessment_questions) is not tuple
                or any(type(q) is not str or q not in {"goal_presence", "target_evidence"} for q in self.assessment_questions)
                or len(set(self.assessment_questions)) != len(self.assessment_questions)):
            raise ValueError("invalid_target_assessment_questions")
        legal = tuple(item for item in self.candidates
                      if item.visible and item.enabled and not item.password)
        if self.fallback_id is not None and self.fallback_id not in {
                item.target_id for item in legal}:
            raise ValueError("illegal_target_fallback")
        goal = target_description(self.goal_hint)
        object.__setattr__(self, "_literal_goal",
                           self.goal_hint.strip() == goal.strip() and "[credential excluded]" not in goal)
        object.__setattr__(self, "goal_hint", goal)
        if self.task_stage is not None:
            object.__setattr__(self, "task_stage", target_description(self.task_stage, 160))
        object.__setattr__(self, "candidates", legal)
        object.__setattr__(self, "_candidate_by_id", MappingProxyType({
            uuid.uuid4().hex: item for item in legal}))

    @property
    def payload(self) -> dict:
        # Both credentials and disabled/password nodes are excluded before any
        # request is made. No input value, URL, screenshot or locator is sent.
        payload = {"goal_hint": self.goal_hint, "candidates": [
            {"candidate_id": identifier, "channel": item.channel,
             "source": item.source, "action": item.action, "role": item.role,
             "label": item.label, "visible": True, "enabled": True,
             "position": item.position, "expected": item.expected,
             "match": item.match,
             **({"action_patterns": list(item.action_patterns)} if item.action_patterns else {}),
             **({"evidence_hint": item.evidence_hint} if item.evidence_hint else {})}
            for identifier, item in self._candidate_by_id.items()]}
        if self.task_stage is not None:
            payload["task_stage"] = self.task_stage
        if self.candidate_scope == "bounded":
            payload.update(candidate_scope="bounded", enumeration_complete=self.complete)
        return payload

    def resolve(self, candidate_id: str) -> TargetCandidate | None:
        return self._candidate_by_id.get(candidate_id)

    def contains(self, candidate: TargetCandidate) -> bool:
        """Only the immutable observed operation/target pair may be adopted."""
        return any(candidate is item for item in self.candidates)

    def fallback(self) -> TargetCandidate | None:
        return next((item for item in self.candidates
                     if item.target_id == self.fallback_id), None)

    def _matches_goal_locally(self, candidate: TargetCandidate) -> bool:
        # An explicit caller-verified baseline is a local decision. A bare
        # match="exact" annotation supplies no checkable goal relationship.
        if candidate.target_id == self.fallback_id:
            return True
        return (self._literal_goal and candidate._literal_label
                and bool(self.goal_hint.strip())
                and candidate.label.strip() == self.goal_hint.strip())


@dataclass(frozen=True)
class JevTargetSelection:
    candidate: TargetCandidate | None
    reason: str
    elapsed_ms: int
    assessments: Mapping | None = None

    def __post_init__(self):
        if self.assessments is not None:
            object.__setattr__(self, "assessments", _freeze(self.assessments))

    @property
    def target_id(self) -> str | None:
        return self.candidate.target_id if self.candidate is not None else None


async def local_target_selection(request: TargetRequest, *, deadline: float,
                                 permitted: Callable[[], Awaitable[bool]],
                                 fresh: Callable[[], Awaitable[bool]],
                                 clock=time.monotonic) -> JevTargetSelection | None:
    """Resolve local outcomes; None means target suitability needs ranking.

    A singleton is direct only with an explicit local baseline or an unchanged,
    nonempty exact label/goal match. Merely being the only observed legal control
    says nothing about its suitability for the goal.
    """
    if type(request) is not TargetRequest:
        raise ValueError("invalid_target_request")
    started = clock()
    def result(candidate, reason):
        return JevTargetSelection(candidate, reason, max(0, round((clock() - started) * 1000)))
    if not math.isfinite(deadline) or deadline <= clock():
        return result(None, "expired")
    if request.expires_at <= clock():
        return result(None, "stale_observation")
    # complete describes enumeration, not freshness/authority or whether an
    # already observed candidate can accomplish the goal. A producer may supply
    # a bounded goal-related set despite unrelated tree/provider gaps. Never
    # infer exhaustiveness, optimality, or permission from that declaration.
    if not request.complete and request.candidate_scope == "exhaustive":
        return result(None, "incomplete_candidates")
    if not request.candidates:
        return result(None, "no_legal_candidate")
    bounded_deadline = min(deadline, request.expires_at)
    try:
        async with asyncio.timeout(min(5.0, bounded_deadline - clock())):
            if await permitted() is not True:
                return result(None, "not_permitted")
            if await fresh() is not True:
                return result(None, "stale_observation")
            if clock() >= bounded_deadline:
                return result(None, "expired")
            if (len(request.candidates) == 1
                    and request._matches_goal_locally(request.candidates[0])):
                return result(request.candidates[0], "only_candidate")
            exact = [item for item in request.candidates
                     if request._literal_goal and item._literal_label and request.goal_hint.strip()
                     and item.label.strip() == request.goal_hint.strip()]
            if len(exact) == 1:
                return result(exact[0], "exact_unique")
    except TimeoutError:
        return result(None, "timeout")
    return None


def _credential_node(node: dict) -> bool:
    return (node.get("password") is True or node.get("is_password") is True
            or str(node.get("type") or "").lower() == "password"
            or str(node.get("autocomplete") or "").lower() in {"current-password", "new-password"}
            or node.get("credential") is True or node.get("sensitive") is True)


def candidate_from_dom(node: dict, *, action: str = "click",
                       position: str = "unknown", expected: str = "unknown") -> TargetCandidate | None:
    """Use a bounded DOM/accessibility observation, never a value/full tree."""
    if (_credential_node(node) or node.get("disabled") is True
            or node.get("visible") is False or node.get("connected") is False):
        return None
    reference = node.get("ref")
    if type(reference) is not str or not reference:
        raise ValueError("observed_dom_reference_required")
    return TargetCandidate(reference, "web", "dom", action,
                           node.get("role") or node.get("tag", "unknown"),
                           node.get("name") or node.get("text") or "",
                           {"ref": reference}, position=position, expected=expected)


def candidate_from_uia(node: dict, *, action: str = "invoke", channel: str = "app",
                       target: dict | None = None, position: str = "unknown",
                       expected: str = "unknown", require_pattern: bool = False) -> TargetCandidate | None:
    """Bind UIA RuntimeId locally; exclude password/offscreen/disabled nodes."""
    if _credential_node(node) or node.get("enabled") is not True or node.get("offscreen") is True:
        return None
    if require_pattern:
        pattern = {"invoke": "invoke_supported", "set_value": "value_supported",
                   "set_toggle": "toggle_supported", "select_item": "selection_item_supported",
                   "expand": "expand_collapse_supported", "collapse": "expand_collapse_supported",
                   "scroll": "scroll_supported", "realize_item": "item_container_supported"}.get(action)
        if pattern is None or node.get(pattern) is not True:
            return None
    runtime_id = node.get("runtime_id")
    if type(runtime_id) is not list or not runtime_id:
        raise ValueError("observed_uia_reference_required")
    automation_id = node.get("automation_id", "")
    reference = {"runtime_id": runtime_id, "automation_id": automation_id}
    target_id = "uia:" + json.dumps(reference, sort_keys=True, separators=(",", ":"))
    return TargetCandidate(target_id, channel, "uia", action,
                           node.get("control_type", "unknown"), node.get("name") or "",
                           target or {"reference": reference}, position=position, expected=expected,
                           action_patterns=tuple(action for action, flag in (
                               ("invoke", "invoke_supported"), ("set_value", "value_supported"),
                               ("set_toggle", "toggle_supported"), ("select_item", "selection_item_supported"),
                               ("expand", "expand_collapse_supported"), ("collapse", "expand_collapse_supported"),
                               ("scroll", "scroll_supported"), ("realize_item", "item_container_supported"))
                               if node.get(flag) is True))


def candidate_from_ocr(node: dict, *, target: dict, action: str = "click",
                       position: str = "unknown", expected: str = "unknown") -> TargetCandidate | None:
    """Use already admitted local OCR's text and an exact caller-bound region."""
    if _credential_node(node) or node.get("enabled") is False or node.get("visible") is False:
        return None
    identifier = node.get("candidate_id") or node.get("target_id")
    if type(identifier) is not str or not identifier:
        raise ValueError("observed_ocr_reference_required")
    return TargetCandidate(identifier, "computer", "ocr", action,
                           node.get("role", "region"), node.get("label") or node.get("text") or "",
                           target, position=position, expected=expected)
