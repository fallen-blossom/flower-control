"""Versioned identifier-only finish receipts in the existing local ledger.

No browser call runs inside a transaction. A durable close-attempt marker is
committed before each side effect; an interrupted caller never retries it.
"""
import copy
import json
import sqlite3
from contextlib import contextmanager

from flower_control.control.state import ControlError


_DDL = """CREATE TABLE IF NOT EXISTS web_finish_receipts(
 task TEXT NOT NULL, finish_id TEXT NOT NULL, fingerprint TEXT NOT NULL,
 revision INTEGER NOT NULL, body TEXT NOT NULL, PRIMARY KEY(task,finish_id))"""
_ROW_FIELDS = frozenset({"session_id", "page_id", "closed", "state", "reason", "action_id",
    "close_attempted", "close_dispatched", "attempt", "dialog_pending", "browser_running"})
_RESULT_FIELDS = frozenset({"state", "finish_id", "requested_outcome", "preserved_pages",
    "preserved_temp_lifetime", "pending_action_ids", "input_release", "cleanup_scope",
    "resources_released", "unknown_receipts_preserved", "task_finished",
    "business_result_verified", "old_actions_replayed", "recovery"})


def _rows(rows):
    return {key: {name: value for name, value in row.items() if name in _ROW_FIELDS}
            for key, row in rows.items()}


class FinishLedger:
    CACHE_LIMIT = 128

    def __init__(self, runtime):
        self.store = runtime.store
        self.cache = runtime._finish_requests
        # Additive component schema: old schema-2 clients ignore this table.
        # A future body schema is rejected, never treated as a missing request.
        with self._transaction() as db:
            marker = db.execute("SELECT value FROM meta WHERE key='web_finish_schema'").fetchone()
            exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='web_finish_receipts'").fetchone()
            if marker is None and exists is None:
                db.execute(_DDL)
                db.execute("INSERT INTO meta VALUES('web_finish_schema','1')")
            elif marker is None or marker[0] != "1" or exists is None:
                # A previously initialized table disappearing is damage, not
                # permission to forget its old IDs and recreate an empty one.
                raise ControlError("finish_ledger_schema_unsupported")
            columns = [(r[1], r[2], r[3], r[5]) for r in db.execute("PRAGMA table_info(web_finish_receipts)")]
            if columns != [("task", "TEXT", 1, 1), ("finish_id", "TEXT", 1, 2),
                    ("fingerprint", "TEXT", 1, 0), ("revision", "INTEGER", 1, 0), ("body", "TEXT", 1, 0)]:
                raise ControlError("finish_ledger_schema_unsupported")
        # Preserve pre-upgrade in-memory attempts before allowing their eviction.
        for (task, finish_id), prior in tuple(self.cache.items()):
            if "_revision" not in prior:
                current = self.load(task, finish_id)
                if current is None:
                    self.create(task, finish_id, prior)
                elif current["fingerprint"] != prior["fingerprint"]:
                    raise ControlError("finish_id_conflict")

    @contextmanager
    def _transaction(self, *, read=False):
        try:
            with (self.store.read_transaction() if read else self.store.transaction()) as db:
                yield db
        except sqlite3.Error:
            # This refusal never permits a browser call or a retry of a marker.
            raise ControlError("finish_ledger_unavailable") from None

    def _encode(self, prior):
        body = {"schema": 1, "fingerprint": prior["fingerprint"],
                "sessions": _rows(prior["sessions"]), "pages": _rows(prior["pages"]), "result": None}
        if prior.get("result") is not None:
            body["result"] = {k: v for k, v in prior["result"].items() if k in _RESULT_FIELDS}
        payload = json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False)
        if len(payload.encode("utf-8")) > 262144:
            raise ControlError("finish_ledger_record_too_large")
        return payload

    def _decode(self, row):
        try:
            if len(row["body"].encode("utf-8")) > 262144:
                raise ValueError
            def unique(pairs):
                value = {}
                for key, item in pairs:
                    if key in value:
                        raise ValueError
                    value[key] = item
                return value
            body = json.loads(row["body"], object_pairs_hook=unique)
            if (type(body) is not dict or set(body) != {"schema", "fingerprint", "sessions", "pages", "result"}
                    or type(body["schema"]) is not int or body["schema"] != 1 or body["fingerprint"] != row["fingerprint"]
                    or type(row["revision"]) is not int or row["revision"] < 0):
                raise ValueError
            for rows in (body["sessions"], body["pages"]):
                if type(rows) is not dict or any(type(key) is not str or type(item) is not dict
                        or set(item) - _ROW_FIELDS for key, item in rows.items()):
                    raise ValueError
                for item in rows.values():
                    for name in ("session_id", "page_id", "state", "reason", "action_id"):
                        if name in item and item[name] is not None and type(item[name]) is not str:
                            raise ValueError
                    for name in ("closed", "close_attempted", "close_dispatched", "dialog_pending", "browser_running"):
                        if name in item and type(item[name]) is not bool:
                            raise ValueError
                    if "attempt" in item and (type(item["attempt"]) is not int or item["attempt"] < 0):
                        raise ValueError
            if any("close_attempted" not in item for item in body["pages"].values()):
                raise ValueError
            if body["result"] is not None and (type(body["result"]) is not dict
                    or set(body["result"]) - _RESULT_FIELDS or "state" not in body["result"]):
                raise ValueError
            if (body["result"] or {}).get("state") not in (None, "finish_pending", "finish_complete"):
                raise ValueError
            if (body["result"] or {}).get("state") == "finish_complete" and (
                    any(not item.get("closed") and item.get("state") != "retained" or item.get("state") == "outcome_uncertain"
                        for item in body["sessions"].values())
                    or any(not item.get("closed") or item.get("state") == "outcome_uncertain" for item in body["pages"].values())):
                raise ValueError
            return {"fingerprint": body["fingerprint"], "sessions": body["sessions"], "pages": body["pages"],
                    "result": body["result"], "_revision": row["revision"]}
        except (ValueError, TypeError, KeyError):
            raise ControlError("finish_ledger_record_invalid") from None

    def _remember(self, task, finish_id, prior):
        key = (task, finish_id)
        self.cache.pop(key, None)
        self.cache[key] = copy.deepcopy(prior)
        while len(self.cache) > self.CACHE_LIMIT:
            # Every evicted entry has already been committed to SQLite.
            self.cache.pop(next(iter(self.cache)))

    def load(self, task, finish_id):
        with self._transaction(read=True) as db:
            row = db.execute("SELECT * FROM web_finish_receipts WHERE task=? AND finish_id=?", (task, finish_id)).fetchone()
        if row is None:
            return None
        prior = self._decode(row)
        self._remember(task, finish_id, prior)
        return prior

    def create(self, task, finish_id, prior):
        payload = self._encode(prior)
        with self._transaction() as db:
            row = db.execute("SELECT * FROM web_finish_receipts WHERE task=? AND finish_id=?", (task, finish_id)).fetchone()
            if row is not None:
                current = self._decode(row)
                if current["fingerprint"] != prior["fingerprint"]:
                    raise ControlError("finish_id_conflict")
                # A concurrent or previously committed intent owns its evidence.
                raise ControlError("finish_request_changed")
            db.execute("INSERT INTO web_finish_receipts VALUES(?,?,?,?,?)", (task, finish_id, prior["fingerprint"], 0, payload))
        prior["_revision"] = 0
        self._remember(task, finish_id, prior)
        return prior

    def save(self, task, finish_id, prior):
        payload = self._encode(prior)
        with self._transaction() as db:
            changed = db.execute("UPDATE web_finish_receipts SET revision=revision+1,body=? "
                "WHERE task=? AND finish_id=? AND fingerprint=? AND revision=?",
                (payload, task, finish_id, prior["fingerprint"], prior["_revision"])).rowcount
            if changed != 1:
                raise ControlError("finish_request_changed")
        prior["_revision"] += 1
        self._remember(task, finish_id, prior)

    @staticmethod
    def recovered(prior, *, finish_id, business_boundary, preserve_pages, outcome):
        if prior.get("result") is not None:
            result = copy.deepcopy(prior["result"])
        else:
            result = {"state": "finish_pending", "finish_id": finish_id, "requested_outcome": outcome,
                "preserved_pages": preserve_pages, "input_release": "unconfirmed", "resources_released": False,
                "recovery": "query_original_action_and_release_via_original_channel",
                "unknown_receipts_preserved": True, "task_finished": False,
                "business_result_verified": False, "old_actions_replayed": False}
        result.update(sessions=list(prior["sessions"].values()), pages=list(prior["pages"].values()),
                      business_boundary=business_boundary, receipt_recovered=True,
                      receipt_scope="original_finish_snapshot", live_cleanup_rechecked=False)
        return result
