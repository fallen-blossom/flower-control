"""Bounded retained Jev metadata for one trusted chat, never page contents."""
from __future__ import annotations

from collections import Counter
import json


def chat_jev_summary(store, task, *, limit=1000):
    if type(limit) is not int or not 1 <= limit <= 5000:
        raise ValueError("invalid_jev_report_limit")
    with store.read_transaction() as db:
        store._task(db, task)
        rows = db.execute("SELECT event,details FROM control_events WHERE task=? AND event IN "
                          "('target_selection','scheduling_decision','scheduling_skipped',"
                          "'jev_http_started','jev_http_finished') ORDER BY seq DESC LIMIT ?",
                          (task, limit + 1)).fetchall()
    truncated = len(rows) > limit
    purposes, skips = Counter(), Counter()
    attempts_started = attempts_finished = invocations = elapsed = 0
    for row in rows[:limit]:
        try:
            data = json.loads(row["details"])
        except (ValueError, TypeError):
            continue
        if type(data) is not dict:
            continue
        event = row["event"]
        if event == "jev_http_started":
            attempts_started += 1
        elif event == "jev_http_finished":
            attempts_finished += 1
            invocations += int(data.get("http_invoked") is True)
            duration = data.get("request_ms")
            if type(duration) is int and duration >= 0:
                elapsed += duration
        else:
            purposes["target_selection" if event == "target_selection" else "scheduling"] += 1
            reason = data.get("skip_reason")
            # Fixed producer categories only; never expose raw arbitrary text.
            if type(reason) is str and reason in {"structural_cache", "task_jev_disabled", "jev_disabled", "client_unavailable",
                          "exact_unique", "only_candidate", "insufficient_candidates",
                          "explicit_user_order", "foreground_turn_order", "global_write_stopped", "not_permitted",
                          "jev_disabled_or_not_allowed", "fair_wait_limit", "occupancy_limit"}:
                skips[reason] += 1
    return {"scope": "retained_chat_metadata", "state": "observed" if rows else "unknown",
            "history_complete": False, "retention_may_drop_events": True, "truncated": truncated,
            "rows_observed": min(len(rows), limit), "purposes": dict(purposes), "skip_reasons": dict(skips),
            "http_attempts_started_observed": attempts_started,
            "http_attempts_finished_observed": attempts_finished,
            "http_invocations_confirmed_observed": invocations,
            "request_ms_observed": elapsed, "proves_business_success": False}
