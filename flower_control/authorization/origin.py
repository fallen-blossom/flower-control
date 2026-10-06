"""Internal host-origin association; a call ticket is never a profile grant.

Only a trusted PreToolUse adapter may call :meth:`issue`. The user approved a
per-chat scope that includes subagents of that chat; current Codex PreToolUse
fields share the parent session id and do not distinguish a subagent.
No MCP tool, prompt parser, or native-card confirmation entrypoint is here.

Official field reference: https://developers.openai.com/codex/hooks
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Mapping

from flower_control.control.state import StateStore


_SCHEMA = """
CREATE TABLE IF NOT EXISTS origin_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS origin_sessions(
 session_hash TEXT PRIMARY KEY,
 task TEXT NOT NULL UNIQUE REFERENCES tasks(id),
 created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS origin_tickets(
 token_hash TEXT PRIMARY KEY,
 session_hash TEXT NOT NULL REFERENCES origin_sessions(session_hash),
 task TEXT NOT NULL REFERENCES tasks(id),
 turn_id TEXT NOT NULL,
 tool_use_id TEXT NOT NULL,
 tool_name TEXT NOT NULL,
 semantic_hash TEXT NOT NULL,
 issued REAL NOT NULL,
 expires REAL NOT NULL,
 consumed REAL,
 UNIQUE(session_hash, turn_id, tool_use_id)
);
CREATE INDEX IF NOT EXISTS origin_tickets_expiry ON origin_tickets(expires);
CREATE TABLE IF NOT EXISTS origin_ticket_workspaces(
 token_hash TEXT PRIMARY KEY REFERENCES origin_tickets(token_hash),
 cwd TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS origin_task_boots(
 task TEXT PRIMARY KEY REFERENCES tasks(id),
 boot TEXT NOT NULL
);
"""


class OriginError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class HostToolCall:
    """Values from the trusted adapter, never from MCP arguments or a prompt.

    ``hook_origin`` is an adapter assertion, not an official PreToolUse field.
    Hook hosts use an actual synchronous event. The reduced Antigravity adapter
    instead uses an independently admitted local connection, never model input.
    """

    session_id: str
    turn_id: str
    tool_use_id: str
    tool_name: str
    tool_input: Mapping[str, Any]
    hook_origin: Literal["trusted_hook", "trusted_connection", "unknown"] = "unknown"
    cwd: str | None = None  # Actual PreToolUse cwd; never read from MCP arguments.
    host: Literal["codex", "claude-code", "antigravity"] = "codex"


@dataclass(frozen=True)
class CallTicket:
    token: str
    task_id: str
    semantic_hash: str
    expires_at: float
    already_consumed: bool = False


def _identifier(value: str, field: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 256 or value != value.strip():
        raise OriginError(f"invalid_{field}")
    if any(ord(char) < 32 for char in value):
        raise OriginError(f"invalid_{field}")
    return value


def _canonical_input(value: Mapping[str, Any]) -> str:
    def valid_json(item: Any, depth: int = 0) -> bool:
        if depth > 32:
            return False
        if item is None or isinstance(item, (str, bool, int)):
            return True
        if isinstance(item, float):
            return math.isfinite(item)
        if isinstance(item, list):
            return all(valid_json(child, depth + 1) for child in item)
        if isinstance(item, dict):
            return all(isinstance(key, str) and valid_json(child, depth + 1)
                       for key, child in item.items())
        return False

    if not isinstance(value, dict) or not valid_json(value):
        raise OriginError("invalid_tool_input")
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError, RecursionError) as error:
        raise OriginError("invalid_tool_input") from error
    # A real development edit can carry a full source file. The Hook keeps no
    # payload in SQLite; this bounds in-memory canonicalization only.
    if len(encoded.encode("utf-8")) > 8 * 1024 * 1024:
        raise OriginError("tool_input_too_large")
    return encoded


def _hash(label: bytes, value: str) -> str:
    return hashlib.sha256(label + value.encode("utf-8")).hexdigest()


def _workspace(cwd: str | None) -> str | None:
    if cwd is None:
        return None
    if type(cwd) is not str or not 1 <= len(cwd) <= 32767 or "\x00" in cwd:
        raise OriginError("invalid_hook_workspace")
    path = Path(cwd)
    if not path.is_absolute():
        raise OriginError("invalid_hook_workspace")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise OriginError("invalid_hook_workspace") from error
    if not resolved.is_dir():
        raise OriginError("invalid_hook_workspace")
    return str(resolved)


def _semantic(tool_name: str, tool_input: Mapping[str, Any]) -> str:
    canonical = _canonical_input(tool_input)
    # FastMCP supplies documented defaults to handlers. Only these reviewed
    # top-level fields are omitted when handlers rebuild their signed payload.
    # Keep meaningful values, nested input and unknown fields bound exactly.
    defaults = {
        "flower_app_select_window": {"replacement": False},
        "flower_app_list_windows": {"launch": None},
        "flower_app_observe": {"limits": None, "view": None},
        "flower_app_pause": {"mode": None},
        "flower_computer_observe": {"goal_hint": None},
        "flower_computer_pause": {"mode": None},
        "flower_web_request_luohua_access": {"decision": None},
        "flower_web_start_temp": {"window_mode": None},
        "flower_web_begin_ai_login": {"initial_url": None},
    }
    payload = json.loads(canonical)
    # Namespace prefixes have an exact allowlist at issue/consume; aliases do
    # not make tickets interchangeable because the full tool stays in the hash.
    tool = tool_name.rsplit("__", 1)[-1]
    for field, default in defaults.get(tool, {}).items():
        if field in payload and type(payload[field]) is type(default) and payload[field] == default:
            del payload[field]
    return _hash(b"flower-call-v1\0", json.dumps(
        {"tool": tool_name, "input": payload},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False))


class OriginLedger:
    """Share one chat task across Flower processes through an existing store.

    Construct with an already initialized ``StateStore``; creating a store for
    every Hook event would repeat its host boot probe. ``allowed_tools`` is an
    exact plugin-owned allowlist supplied by the future trusted adapter.
    This class has no method that records or infers a private-profile grant.
    """

    def __init__(self, store: StateStore, *, allowed_tools: frozenset[str]):
        if not isinstance(store, StateStore):
            raise TypeError("store must be an existing StateStore")
        if not allowed_tools or not all(isinstance(name, str) and name.startswith("mcp__")
                                        for name in allowed_tools):
            raise ValueError("allowed_tools must be exact MCP hook names")
        self.store = store
        self.allowed_tools = frozenset(allowed_tools)
        with self.store.transaction() as db:
            # sqlite3.executescript commits an open transaction first.
            for statement in _SCHEMA.split(";"):
                if statement.strip():
                    db.execute(statement)
            db.execute("INSERT OR IGNORE INTO origin_meta(key,value) VALUES ('ticket_key',?)",
                       (secrets.token_hex(32),))
            # Older installations had no boot attached to a chat association.
            # A revoked task created beyond this boot's monotonic uptime is
            # provably pre-reboot. Unknown/same-boot revocations stay revoked.
            now = self.store.clock()
            for row in db.execute(
                    "SELECT t.id,t.created,t.revoked FROM tasks t JOIN origin_sessions s "
                    "ON s.task=t.id LEFT JOIN origin_task_boots b ON b.task=t.id "
                    "WHERE b.task IS NULL").fetchall():
                epoch = ("legacy-before-monotonic-reset" if row["revoked"] and row["created"] > now
                         else self.store.boot)
                db.execute("INSERT INTO origin_task_boots VALUES (?,?)", (row["id"], epoch))

    def _prepare(self, call: HostToolCall) -> tuple[str, str]:
        if call.hook_origin != ("trusted_connection" if call.host == "antigravity" else "trusted_hook"):
            raise OriginError("hook_origin_unverified")
        session = _identifier(call.session_id, "session_id")
        _identifier(call.turn_id, "turn_id")
        _identifier(call.tool_use_id, "tool_use_id")
        name = _identifier(call.tool_name, "tool_name")
        if name not in self.allowed_tools:
            raise OriginError("tool_not_allowed")
        if call.host not in ("codex", "claude-code", "antigravity"):
            raise OriginError("host_unrecognized")
        # Preserve existing Codex bindings; another host never inherits them.
        domain = (b"flower-session-v1\0" if call.host == "codex"
                  else b"flower-session-v1\0" + call.host.encode("ascii") + b"\0")
        session_hash = _hash(domain, session)
        semantic = _semantic(name, call.tool_input)
        return session_hash, semantic

    @staticmethod
    def _live_task(db, task: str) -> None:
        row = db.execute("SELECT revoked FROM tasks WHERE id=?", (task,)).fetchone()
        if row is None or row[0]:
            raise OriginError("task_revoked_or_missing")

    @staticmethod
    def _token(db, session_hash: str, call: HostToolCall, semantic: str) -> str:
        row = db.execute("SELECT value FROM origin_meta WHERE key='ticket_key'").fetchone()
        if row is None:
            raise OriginError("origin_key_missing")
        message = json.dumps([session_hash, call.turn_id, call.tool_use_id, semantic],
                             separators=(",", ":")).encode("utf-8")
        return hmac.new(bytes.fromhex(row[0]), b"flower-ticket-v1\0" + message,
                        hashlib.sha256).hexdigest()

    def issue(self, call: HostToolCall, *, ttl: float = 20.0) -> CallTicket:
        """Bind one chat PreToolUse attempt to a task and exact payload hash.

        Repeated delivery of the same event returns the same ticket. A changed
        payload under the same session/turn/tool-use id fails closed. The task
        remains ungranted until the host records a separate user authorization.
        """
        if not isinstance(ttl, (int, float)) or not math.isfinite(ttl) or not 0 < ttl <= 60:
            raise OriginError("invalid_ticket_lifetime")
        session_hash, semantic = self._prepare(call)
        workspace = _workspace(call.cwd)
        now = self.store.clock()
        with self.store.transaction() as db:
            binding = db.execute("SELECT task FROM origin_sessions WHERE session_hash=?",
                                 (session_hash,)).fetchone()
            epoch = (db.execute("SELECT boot FROM origin_task_boots WHERE task=?",
                                (binding[0],)).fetchone() if binding else None)
            new_epoch = binding is not None and epoch is not None and epoch[0] != self.store.boot
            if binding is None or new_epoch:
                task = secrets.token_urlsafe(24)
                db.execute("INSERT INTO tasks(id,host_binding,created) VALUES (?,?,?)",
                           (task, "origin:" + session_hash, now))
                self.store._initialize_task_write_epoch(db, task)
                db.execute("INSERT INTO origin_task_boots VALUES (?,?)", (task, self.store.boot))
                if binding is None:
                    db.execute("INSERT INTO origin_sessions VALUES (?,?,?)", (session_hash, task, now))
                else:
                    db.execute("UPDATE origin_sessions SET task=?,created=? WHERE session_hash=?",
                               (task, now, session_hash))
            else:
                task = binding[0]
                self._live_task(db, task)
            prior = db.execute(
                "SELECT * FROM origin_tickets WHERE session_hash=? AND turn_id=? AND tool_use_id=?",
                (session_hash, call.turn_id, call.tool_use_id)).fetchone()
            token = self._token(db, session_hash, call, semantic)
            token_hash = _hash(b"flower-token-v1\0", token)
            if prior is not None:
                if prior["task"] != task:
                    raise OriginError("event_boot_changed")
                if (prior["task"] != task or prior["tool_name"] != call.tool_name
                        or prior["semantic_hash"] != semantic or prior["token_hash"] != token_hash):
                    raise OriginError("event_payload_drift")
                if prior["expires"] <= now:
                    raise OriginError("event_expired")
                saved = db.execute(
                    "SELECT cwd FROM origin_ticket_workspaces WHERE token_hash=?",
                    (token_hash,)).fetchone()
                if (saved[0] if saved else None) != workspace:
                    raise OriginError("event_workspace_drift")
                return CallTicket(token, task, semantic, prior["expires"],
                                  prior["consumed"] is not None)
            expires = now + ttl
            db.execute(
                "INSERT INTO origin_tickets VALUES (?,?,?,?,?,?,?,?,?,NULL)",
                (token_hash, session_hash, task, call.turn_id, call.tool_use_id,
                 call.tool_name, semantic, now, expires))
            if workspace is not None:
                db.execute("INSERT INTO origin_ticket_workspaces VALUES (?,?)",
                           (token_hash, workspace))
            return CallTicket(token, task, semantic, expires)

    def consume(self, call: HostToolCall, token: str) -> str:
        """Consume once after checking the real tool, original input and time.

        The future transport must pass trusted Hook identity plus actual MCP
        arguments, not model-supplied identity fields. The returned task id is
        only a chat association; callers must independently check StateStore
        grants and current resource conditions before any private action.
        """
        session_hash, semantic = self._prepare(call)
        if not isinstance(token, str) or len(token) != 64:
            raise OriginError("invalid_ticket")
        token_hash = _hash(b"flower-token-v1\0", token)
        with self.store.transaction() as db:
            now = self.store.clock()
            row = db.execute("SELECT * FROM origin_tickets WHERE token_hash=?",
                             (token_hash,)).fetchone()
            if row is None:
                raise OriginError("ticket_missing")
            if (row["session_hash"] != session_hash or row["turn_id"] != call.turn_id
                    or row["tool_use_id"] != call.tool_use_id
                    or row["tool_name"] != call.tool_name
                    or row["semantic_hash"] != semantic):
                raise OriginError("ticket_call_mismatch")
            binding = db.execute("SELECT task FROM origin_sessions WHERE session_hash=?",
                                 (session_hash,)).fetchone()
            if binding is None or binding[0] != row["task"]:
                raise OriginError("session_binding_mismatch")
            self._live_task(db, row["task"])
            if row["expires"] <= now:
                raise OriginError("ticket_expired")
            if row["consumed"] is not None:
                raise OriginError("ticket_replayed")
            updated = db.execute(
                "UPDATE origin_tickets SET consumed=? WHERE token_hash=? AND consumed IS NULL",
                (now, token_hash))
            if updated.rowcount != 1:
                raise OriginError("ticket_replayed")
            return row["task"]

    def consume_token(self, tool_name: str, tool_input: Mapping[str, Any], token: str) -> str:
        """Consume a Hook-injected ticket using actual MCP arguments only.

        The server never needs a model-visible session or turn identifier. A
        missing Hook, changed argument, expired token or replay fails closed.
        This returns association, never a private-profile grant.
        """
        return self._consume_token_context(tool_name, tool_input, token,
                                           require_workspace=False)[0]

    def consume_token_context(self, tool_name: str, tool_input: Mapping[str, Any],
                              token: str) -> tuple[str, Path]:
        """Consume once and return the Hook-verified workspace for a launch."""
        task, workspace = self._consume_token_context(
            tool_name, tool_input, token, require_workspace=True)
        return task, Path(workspace)

    def _consume_token_context(self, tool_name: str, tool_input: Mapping[str, Any],
                               token: str, *, require_workspace: bool) -> tuple[str, str | None]:
        name = _identifier(tool_name, "tool_name")
        if name not in self.allowed_tools:
            raise OriginError("tool_not_allowed")
        semantic = _semantic(name, tool_input)
        if not isinstance(token, str) or len(token) != 64:
            raise OriginError("invalid_ticket")
        token_hash = _hash(b"flower-token-v1\0", token)
        with self.store.transaction() as db:
            now = self.store.clock()
            row = db.execute("SELECT * FROM origin_tickets WHERE token_hash=?",
                             (token_hash,)).fetchone()
            if row is None:
                raise OriginError("ticket_missing")
            if row["tool_name"] != name or row["semantic_hash"] != semantic:
                raise OriginError("ticket_call_mismatch")
            binding = db.execute("SELECT task FROM origin_sessions WHERE session_hash=?",
                                 (row["session_hash"],)).fetchone()
            if binding is None or binding[0] != row["task"]:
                raise OriginError("session_binding_mismatch")
            self._live_task(db, row["task"])
            if row["expires"] <= now:
                raise OriginError("ticket_expired")
            if row["consumed"] is not None:
                raise OriginError("ticket_replayed")
            saved = db.execute(
                "SELECT cwd FROM origin_ticket_workspaces WHERE token_hash=?",
                (token_hash,)).fetchone()
            workspace = saved[0] if saved else None
            if require_workspace and workspace is None:
                raise OriginError("trusted_workspace_unavailable")
            updated = db.execute(
                "UPDATE origin_tickets SET consumed=? WHERE token_hash=? AND consumed IS NULL",
                (now, token_hash))
            if updated.rowcount != 1:
                raise OriginError("ticket_replayed")
            return row["task"], workspace
