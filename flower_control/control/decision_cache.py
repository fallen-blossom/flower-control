"""Short process-local semantic choices, never references or authorization.

Only trusted ledger observations can scope an entry. A cache hit resolves a
unique structural signature against the new request and still goes through
the selector's live authority/version checks. No content is written to disk.
"""
from __future__ import annotations

from collections import OrderedDict
import hashlib
import json
import sqlite3
import threading
import time


def _signature(candidate):
    fields = (candidate.channel, candidate.source, candidate.action, candidate.role,
              candidate.label, candidate.position, candidate.expected, candidate.match,
              candidate.action_patterns, candidate.evidence_hint)
    return hashlib.sha256(json.dumps(fields, ensure_ascii=False).encode("utf-8")).hexdigest()


def observation_cache_key(store, task, request, *, provider_stamp=None):
    # The cache stores only a choice, not independent assessment answers.
    # A request that asks for those answers must reach the batch adapter.
    if request.assessment_questions:
        return None
    try:
        with store.read_transaction() as db:
            obs = db.execute("SELECT task,resource,generation,expires FROM observations WHERE id=?",
                             (request.observation_id,)).fetchone()
            if obs is None or obs["task"] != task or obs["expires"] <= store.clock():
                return None
            policy = db.execute("SELECT revision FROM task_service_settings WHERE task=?", (task,)).fetchone()
            context = (str(store.path), task, obs["resource"], obs["generation"],
                       policy[0] if policy else 0, request.version, request.goal_hint,
                       request.task_stage, request.complete, request.candidate_scope,
                       tuple(_signature(item) for item in request.candidates), provider_stamp)
        return hashlib.sha256(json.dumps(context, ensure_ascii=False).encode("utf-8")).hexdigest()
    except (AttributeError, OSError, RuntimeError, sqlite3.Error, KeyError, TypeError):
        return None


class StructuralDecisionCache:
    def __init__(self, *, clock=time.monotonic, capacity=128, lifetime=5.0):
        self.clock, self.capacity, self.lifetime = clock, capacity, lifetime
        self._entries = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key, request):
        if key is None:
            return None
        with self._lock:
            row = self._entries.get(key)
            if row is None:
                return None
            if row[0] <= self.clock():
                self._entries.pop(key, None)
                return None
            signature = row[1]
        matches = [candidate for candidate in request.candidates if _signature(candidate) == signature]
        return matches[0] if len(matches) == 1 else None

    def put(self, key, request, candidate):
        if key is None or not request.contains(candidate):
            return
        signature = _signature(candidate)
        if sum(_signature(item) == signature for item in request.candidates) != 1:
            return
        with self._lock:
            now = self.clock()
            self._entries[key] = (min(request.expires_at, now + self.lifetime), signature)
            self._entries.move_to_end(key)
            while self._entries and (len(self._entries) > self.capacity
                                     or next(iter(self._entries.values()))[0] <= now):
                self._entries.popitem(last=False)


decision_cache = StructuralDecisionCache()
