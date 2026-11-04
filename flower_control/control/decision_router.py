"""Ordered service fallback on bounded decisions, never on unknown GUI writes."""
from __future__ import annotations

import asyncio
import math
import time

from .jev import DecisionPrimitives, JevBatchResult
from .decision_settings import DecisionSettings


class DecisionRouter(DecisionPrimitives):
    FALLBACK_REASONS = frozenset({"timeout", "transport_failed", "service_failed",
        "service_overloaded", "rate_limited", "authentication_failed", "invalid_response",
        "invalid_choice", "response_too_large", "client_unavailable"})

    def __init__(self, settings: DecisionSettings, builder, *, clock=time.monotonic):
        self.settings = settings
        self.builder = builder
        self.clock = clock
        self.event_sink = None
        self._closed = False
        self._clients = {}

    async def _request_questions(self, state, questions, *, deadline, permitted,
                                 fresh=None, kind="target", max_attempts=1, total_budget=5.0):
        from .jev import _validate_budget
        _validate_budget(max_attempts, total_budget)
        started = self.clock()
        end = min(deadline, started + total_budget)
        if not math.isfinite(deadline) or end <= started:
            return JevBatchResult(None, "expired", 0)
        from flower_control.permissions import revision, PermissionError
        try:
            policy_revision = revision()
        except PermissionError:
            return JevBatchResult(None, "user_policy_unavailable", 0)
        original_permitted = permitted
        async def permission_current():
            if self._policy_reason(policy_revision):
                return False
            allowed = await original_permitted()
            return allowed is True and self._policy_reason(policy_revision) is None
        try:
            async with asyncio.timeout(end-self.clock()):
                return await self._route(state, questions, end=end, started=started,
                    permitted=permission_current, fresh=fresh, kind=kind,
                    max_attempts=max_attempts, policy_revision=policy_revision)
        except TimeoutError:
            return JevBatchResult(None, "timeout", max(0, round((self.clock()-started)*1000)))

    @staticmethod
    def _policy_reason(expected):
        from flower_control.permissions import revision, active_policy, PermissionError
        try:
            if revision() != expected:
                return "permission_changed"
            if not active_policy.read()["JevEnabled"]:
                return "disabled_by_user"
        except PermissionError:
            return "user_policy_unavailable"
        return None

    async def _route(self, state, questions, *, end, started, permitted, fresh, kind,
                     max_attempts, policy_revision):
        providers = self.settings.active_order()
        def result(reason):
            return JevBatchResult(None, reason, max(0, round((self.clock()-started)*1000)))
        if not providers:
            return result("host_requested")
        last = None
        for index, provider in enumerate(providers):
            if self._closed:
                return result("transport_failed")
            if self.clock() >= end:
                return result("timeout")
            policy_reason = self._policy_reason(policy_revision)
            if policy_reason:
                return result(policy_reason)
            if await permitted() is not True:
                return result("not_permitted")
            if fresh is not None and await fresh() is not True:
                return result("stale_observation")
            try:
                client = self._clients.get(provider)
                if client is None:
                    client = self.builder(provider, self.settings.model(provider))
                    self._clients[provider] = client
                client.event_sink = self.event_sink
            except (OSError, ValueError, TypeError, KeyError):
                last = result("client_unavailable")
                continue
            # Reserve time for the next service instead of letting a stalled
            # first provider consume the entire shared observation lifetime.
            try:
                client._validate_questions(questions)
            except ValueError:
                # Skip a provider's unsupported rubric without truncating or
                # splitting it. The next explicitly configured provider (or
                # the host) receives the original complete question shape.
                last = result("client_unavailable")
                continue
            budget = (end-self.clock()) / (len(providers)-index)
            if budget <= 0:
                return result("timeout")
            last = await client._request_questions(state, questions,
                deadline=min(end, self.clock()+budget), permitted=permitted, fresh=fresh,
                kind=kind, max_attempts=max_attempts, total_budget=min(5.0, budget))
            policy_reason = self._policy_reason(policy_revision)
            if policy_reason:
                return result(policy_reason)
            if last.answers is not None or last.reason not in self.FALLBACK_REASONS:
                return JevBatchResult(last.answers, last.reason, max(0, round((self.clock()-started)*1000)))
        # Host fallback returns control to the existing model/tool call. It
        # does not call a third model or replay any action in the GUI.
        return result(last.reason if last is not None else "host_requested")

    async def close(self):
        self._closed = True
        clients = tuple(self._clients.values())
        self._clients.clear()
        await asyncio.gather(*(client.close() for client in clients), return_exceptions=True)
