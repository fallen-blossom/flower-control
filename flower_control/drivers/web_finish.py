"""Explicit finite Web cleanup, preserving all prior action outcomes."""
import hashlib
import asyncio
import json
import re
import uuid

from flower_control.control.state import ControlError
from flower_control.control.targets import target_description
from .web_finish_store import FinishLedger


def validate_finish(finish_id, business_boundary, temporary_session_ids, preserve_pages, outcome, cleanup_pages=None):
    cleanup_pages = [] if cleanup_pages is None else cleanup_pages
    if (type(finish_id) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}", finish_id)
            or type(business_boundary) is not str or not 1 <= len(business_boundary.strip()) <= 160
            or any(ord(c) < 32 for c in business_boundary)
            or type(outcome) is not str or outcome not in {"completed", "cancelled"}
            or type(temporary_session_ids) is not list or len(temporary_session_ids) > 16
            or any(type(s) is not str or not re.fullmatch(r"[0-9a-f]{32}", s) for s in temporary_session_ids)
            or len(set(temporary_session_ids)) != len(temporary_session_ids)
            or type(preserve_pages) is not list or len(preserve_pages) > 64
            or type(cleanup_pages) is not list or len(cleanup_pages) > 64):
        raise ControlError("invalid_web_finish")
    kept = set()
    for row in preserve_pages:
        if (type(row) is not dict or set(row) != {"session_id", "page_id"}
                or any(type(row[k]) is not str or not re.fullmatch(r"[0-9a-f]{32}", row[k]) for k in row)):
            raise ControlError("invalid_web_finish")
        pair = (row["session_id"], row["page_id"])
        if pair in kept:
            raise ControlError("invalid_web_finish")
        kept.add(pair)
    cleaned = set()
    for row in cleanup_pages:
        if (type(row) is not dict or set(row) != {"session_id", "page_id"}
                or any(type(row[k]) is not str or not re.fullmatch(r"[0-9a-f]{32}", row[k]) for k in row)):
            raise ControlError("invalid_web_finish")
        pair = (row["session_id"], row["page_id"])
        if pair in cleaned or pair in kept:
            raise ControlError("invalid_web_finish")
        cleaned.add(pair)
    spec = {"boundary": business_boundary.strip(), "sessions": temporary_session_ids,
            "preserve": preserve_pages, "cleanup_pages": cleanup_pages, "outcome": outcome}
    fingerprint = hashlib.sha256(json.dumps(spec, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return fingerprint, kept


async def finish_web_run(runtime, task, *, finish_id, business_boundary,
                         temporary_session_ids, preserve_pages, outcome="completed", cleanup_pages=None):
    cleanup_pages = [] if cleanup_pages is None else cleanup_pages
    fingerprint, kept = validate_finish(finish_id, business_boundary, temporary_session_ids, preserve_pages, outcome, cleanup_pages)
    cleaned = {(row["session_id"], row["page_id"]) for row in cleanup_pages}
    ledger = await asyncio.to_thread(FinishLedger, runtime)
    prior = await asyncio.to_thread(ledger.load, task, finish_id)
    if prior is not None and prior["fingerprint"] != fingerprint:
        raise ControlError("finish_id_conflict")
    if prior is not None and (prior.get("result") or {}).get("state") == "finish_complete":
        return ledger.recovered(prior, finish_id=finish_id,
            business_boundary=target_description(business_boundary, 160), preserve_pages=preserve_pages, outcome=outcome)
    # Validate the entire supplied inventory before closing its first member.
    records = {}
    for session_id in set(temporary_session_ids) | {s for s, _ in kept | cleaned}:
        try:
            manager = runtime._owned(task, session_id)
            record = manager._record(task, session_id)
        except ControlError:
            if prior is None:
                raise
            # Lost host/session state never permits reissuing a prior close.
            return ledger.recovered(prior, finish_id=finish_id,
                business_boundary=target_description(business_boundary, 160), preserve_pages=preserve_pages, outcome=outcome)
        if prior is None:
            manager._require_active_chat(task)
            gate = getattr(runtime.store, "write_stopped", None)
            if callable(gate) and gate():
                raise ControlError("global_stop_active")
        if session_id in temporary_session_ids and record.browser.profile_kind != "temporary":
            raise ControlError("finish_requires_temporary_session")
        if prior is None and record.browser.profile_kind == "luohua":
            manager._require_private_grant(task)
        records[session_id] = (manager, record)
    if prior is None:
        for session_id in sorted({s for s, _ in kept}):
            manager, record = records[session_id]
            if record.closed or record.closing or record.active_actions:
                raise ControlError("finish_preserved_page_unavailable")
            observed = await manager.run(task, session_id, "list_pages", {}, "finish-pages:" + finish_id + ":" + session_id)
            page_ids = observed.get("result")
            if type(page_ids) is not list or not {p for s, p in kept if s == session_id} <= set(page_ids):
                raise ControlError("finish_preserved_page_unavailable")
        for session_id in sorted({s for s, _ in cleaned}):
            manager, record = records[session_id]
            if record.closed or record.closing or record.active_actions:
                raise ControlError("finish_cleanup_page_unavailable")
            required = {p for s, p in cleaned if s == session_id}
            available, offset, digest = {}, 0, None
            # Reuse the existing complete metadata/digest contract. No new
            # content command, ownership grant or historical-tab adoption.
            for _ in range(32):
                arguments = {"include_metadata": True, "offset": offset, "limit": 50}
                if digest is not None:
                    arguments["expected_digest"] = digest
                observed = await manager.run(task, session_id, "list_pages", arguments,
                    "finish-inventory:" + uuid.uuid4().hex)
                data = observed.get("result")
                if type(data) is not dict or type(data.get("pages")) is not list or type(data.get("digest")) is not str:
                    raise ControlError("finish_cleanup_page_unavailable")
                digest = data["digest"]
                for page in data["pages"]:
                    if type(page) is not dict or type(page.get("page_id")) is not str:
                        raise ControlError("finish_cleanup_page_unavailable")
                    available[page["page_id"]] = page.get("owned_by_chat") is True
                if required <= available.keys():
                    break
                next_offset = data.get("next_offset")
                if type(next_offset) is not int or next_offset <= offset:
                    break
                offset = next_offset
            if not required <= available.keys() or not all(available[page] for page in required):
                raise ControlError("finish_requires_owned_cleanup_pages")
        prior = {"fingerprint": fingerprint, "sessions": {}, "pages": {}}
        await asyncio.to_thread(ledger.create, task, finish_id, prior)
    for session_id, page_id in sorted(cleaned):
        manager, record = records[session_id]
        page_key = session_id + ":" + page_id
        original = prior["pages"].get(page_key)
        if original is not None and original.get("close_attempted"):
            try:
                original["original_action"] = manager.action_status(task, session_id, original["action_id"])
            except ControlError as error:
                original["original_action"] = {"state": "unavailable", "reason": error.code}
        if record.closed and record.normal_closed:
            # The exact original temporary instance exited normally. Its pages
            # no longer exist, even if a prior page-close dialog was pending.
            # Preserve uncertainty about the old action rather than replay it.
            row = prior["pages"].setdefault(page_key, {"session_id": session_id,
                "page_id": page_id, "close_attempted": False})
            if row.get("close_attempted"):
                action_state = row["original_action"].get("state")
                if action_state not in {"verified", "not_verified"}:
                    # The attempt marker may predate an uncertain result whose
                    # save was cancelled/lost. Normal exit cannot erase that.
                    row.update(closed=False, reason="original_action_unresolved")
                    if action_state == "outcome_uncertain":
                        row["state"] = "outcome_uncertain"
                    elif row.get("state") != "outcome_uncertain":
                        row["state"] = "pending"
                    continue
            row["closed"] = True
            if row.get("state") != "outcome_uncertain":
                row.update(state="exit_observed", dialog_pending=False)
                row.pop("reason", None)
            continue
        if original is not None and original.get("close_attempted"):
            # Only observe the original action and current page existence.
            # Unknown dispatch/outcome never permits another close request.
            if not original.get("closed") and not record.closed:
                try:
                    current = await manager.run(task, session_id, "close_status", {"page_ids": [page_id]},
                                                "finish-observe:" + uuid.uuid4().hex)
                    data = current.get("result")
                    facts = data.get("page_facts") if type(data) is dict else None
                    if type(facts) is list and len(facts) == 1:
                        fact = facts[0]
                        if (type(fact) is dict and fact.get("page_id") == page_id
                                and fact.get("original_close_known") is True and fact.get("closed") is True):
                            original["closed"] = True
                except ControlError:
                    pass
            continue
        attempt = (original.get("attempt", 0) if original else 0)
        row = {"session_id": session_id, "page_id": page_id, "closed": False,
               "close_attempted": False, "state": "pending", "attempt": attempt}
        prior["pages"][page_key] = row
        if record.active_actions or record.closing:
            row["reason"] = "web_action_in_flight"
            continue
        try:
            manager._require_active_chat(task)
            gate = getattr(runtime.store, "write_stopped", None)
            if callable(gate) and gate():
                raise ControlError("global_stop_active")
            action_id = "finish-page:" + finish_id + ":" + page_id + ":" + str(attempt)
            row.update(close_attempted=True, action_id=action_id, attempt=attempt + 1)
        except ControlError as error:
            row.update(reason=error.code)
            continue
        await asyncio.to_thread(ledger.save, task, finish_id, prior)
        try:
            closed = await manager.run(task, session_id, "close_page", {"page_id": page_id}, action_id)
            fact = closed.get("result")
            row.update(closed=type(fact) is dict and fact.get("closed") is True,
                       state="verified" if type(fact) is dict and fact.get("closed") is True else "pending",
                       dialog_pending=type(fact) is dict and fact.get("dialog") is not None)
            if closed.get("receipt", {}).get("state") == "outcome_uncertain":
                row["state"] = "outcome_uncertain"
        except ControlError as error:
            row.update(reason=error.code, close_attempted=row["close_attempted"]
                       and getattr(error, "web_dispatched", None) is not False)
            if row["close_attempted"]:
                row["state"] = "outcome_uncertain"
        await asyncio.to_thread(ledger.save, task, finish_id, prior)
    kept_sessions = {s for s, _ in kept}
    for session_id in temporary_session_ids:
        manager, record = records[session_id]
        if session_id in kept_sessions:
            prior["sessions"][session_id] = {"session_id": session_id, "closed": False,
                "state": "retained", "reason": "preserved_outcome_page", "close_dispatched": False}
            continue
        original = prior["sessions"].get(session_id)
        if original is not None and original.get("close_attempted", True):
            # Repeated finish observes the original request; never dispatches
            # another close or clears quarantine when the browser disappeared.
            if original.get("action_id"):
                original["original_action"] = runtime.store.diagnostic_action_for_task(task, original["action_id"])
            original["browser_running"] = record.browser.running
            if record.closed and record.normal_closed and original.get("state") != "outcome_uncertain":
                original.update(closed=True, state="exit_observed", close_dispatched=False)
            continue
        if record.closed and record.normal_closed:
            prior["sessions"][session_id] = {"session_id": session_id, "closed": True,
                "state": "exit_observed", "close_dispatched": False, "close_attempted": False}
            continue
        if record.active_actions or record.closing:
            prior["sessions"][session_id] = {"session_id": session_id, "closed": False,
                "state": "pending", "reason": "web_action_in_flight", "close_dispatched": False,
                "close_attempted": False}
            continue
        try:
            # A deferred first close is a new side effect; readonly repeated
            # receipts may be queried while paused, but a first dispatch may not.
            manager._require_active_chat(task)
        except ControlError as error:
            prior["sessions"][session_id] = {"session_id": session_id, "closed": False,
                "state": "pending", "reason": error.code, "close_dispatched": False, "close_attempted": False}
            continue
        prior["sessions"][session_id] = {"session_id": session_id, "closed": False,
            "state": "pending", "reason": "close_request_in_flight", "close_attempted": True}
        await asyncio.to_thread(ledger.save, task, finish_id, prior)
        try:
            closed = await manager.close_temp(task, session_id)
            zero_dispatch = (closed.get("dispatched") is False and closed.get("closed") is False
                             and closed.get("state") != "outcome_uncertain")
            prior["sessions"][session_id] = {**closed, "close_attempted": not zero_dispatch}
            if zero_dispatch:
                # Persist the producer's exact no-dispatch fact. Missing,
                # non-boolean or uncertain facts never permit another close.
                prior["sessions"][session_id]["close_dispatched"] = False
        except ControlError as error:
            prior["sessions"][session_id] = {"session_id": session_id, "closed": False,
                "state": "pending", "reason": error.code, "close_dispatched": False,
                "close_attempted": getattr(error, "web_dispatched", None) is not False and error.code != "temporary_browser_action_in_flight"}
        await asyncio.to_thread(ledger.save, task, finish_id, prior)
    status = runtime.store.task_control_status(task)
    unresolved = [r for r in status["actions"] if r["state"] in {"queued", "running", "outcome_uncertain"}]
    uncertain_release = [r for r in status["actions"] if r.get("held_released") is False
                         or r.get("input_release") in {"unknown", "unconfirmed", "release_pending"}]
    results = list(prior["sessions"].values())
    page_results = list(prior["pages"].values())
    pending = [r for r in results if not r.get("closed") and r.get("state") != "retained"
               or r.get("state") == "outcome_uncertain"]
    pending += [r for r in page_results if not r.get("closed") or r.get("state") == "outcome_uncertain"]
    cleanup_reader = getattr(runtime.store, "task_cleanup_status", None)
    cleanup = cleanup_reader(task) if callable(cleanup_reader) else None
    cleanup_ready = (cleanup.get("cleanup_ready") is True if cleanup is not None else
                     not unresolved and not uncertain_release and not status["active_actions"] and not status["truncated"])
    finished = not pending and cleanup_ready
    result = {"state": "finish_complete" if finished else "finish_pending", "finish_id": finish_id,
            "business_boundary": target_description(business_boundary, 160), "requested_outcome": outcome,
            "sessions": results, "pages": page_results, "preserved_pages": preserve_pages,
            "preserved_temp_lifetime": "current_host_session" if kept_sessions & set(temporary_session_ids) else None,
            "pending_action_ids": cleanup["pending_action_ids"] if cleanup is not None else [r["id"] for r in unresolved],
            "input_release": cleanup["input_release"] if cleanup is not None else "pending" if uncertain_release or status["active_actions"] else "no_active_input_observed",
            "cleanup_facts": cleanup,
            "cleanup_scope": "listed_temporary_sessions_and_owned_pages", "resources_released": finished and not kept_sessions,
            "unknown_receipts_preserved": True,
            "task_finished": False, "business_result_verified": False, "old_actions_replayed": False,
            "recovery": "query_original_action_and_release_via_original_channel" if not finished else None}
    prior["result"] = result
    await asyncio.to_thread(ledger.save, task, finish_id, prior)
    return result
