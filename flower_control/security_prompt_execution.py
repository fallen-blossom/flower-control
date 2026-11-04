"""One ordinary security-prompt continuation through existing App execution.

Internal adapter, not an MCP permission API. ``begin`` reads an already consumed
host ticket and the original driver's action from the existing ledgers. The
executor projector/current-source guard are trusted code, never tool arguments.
They must project the complete original operation and verify its actual pending
request/work/message. An Origin ticket alone proves neither of those things.

Integration supplies authorized App observations, ordinary App invoke, and a
query of the ORIGINAL executor's result. No new grants, rules, tables, watcher,
input emitter, retry loop or automatic process cleanup lives here. The normal
App invoke must persist the supplied stable action_id before any input and keep
its own final privacy/Stop/permission/identity checks. Unknown input is queried,
never replayed, including after this request-local adapter has been discarded.
"""
from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Mapping
import hashlib
import json
import threading

from .authorization.origin import HostToolCall, OriginLedger, _hash, _semantic
from .control.state import ControlError
from .control.worker_call import command_hash
from .security_prompt_observation import _ALLOW, _button_label, security_prompt_observation


class SecurityPromptExecutionError(ControlError):
    pass


@dataclass(frozen=True)
class OriginalBinding:
    task: str
    action_id: str
    fingerprint: str
    session_hash: str
    turn_id: str
    host: str
    thread_id: str


@dataclass(frozen=True)
class AllowInvocation:
    """Pass to the existing App invoke, not directly to UIA/SendInput."""
    task: str
    action_id: str
    target: tuple[int, int, int]
    observation_id: str
    ref: str


@dataclass(frozen=True)
class OriginalOutcome:
    """Produced by querying the exact original executor, not prompt dismissal."""
    action_id: str
    state: str  # pending / completed / failed / outcome_unknown
    business_verified: bool = False


_SEAL = object()
_FIELDS = frozenset({"initiating_program", "operation_type", "operation_target", "command_line"})
_OPTIONAL_FIELDS = frozenset({"program_path", "parent_process", "parent_command_line", "protection_item"})


def _deny(reason):
    raise SecurityPromptExecutionError("security_prompt_" + reason)


def _text(value):
    return (type(value) is str and 0 < len(value) <= 8192
        and not any(ord(c) < 32 or 0xd800 <= ord(c) <= 0xdfff for c in value))


def _snapshot(value, expected):
    """Accept only a complete, authorized App observation supplied by the host."""
    if type(value) is not dict or type(value.get("result")) is not dict:
        _deny("observation_unavailable")
    result = value["result"]
    hint = result.get("security_prompt")
    if (result.get("state") != "observed" or result.get("truncated") is not False
            or type(value.get("observation_id")) is not str or not value["observation_id"]
            or type(hint) is not dict):
        _deny("incomplete_or_not_pending")
    target = tuple(result.get(key) for key in ("pid", "hwnd", "process_start_filetime"))
    if any(type(number) is not int or number <= 0 for number in target):
        _deny("target_invalid")
    identity = dict(zip(("pid", "hwnd", "process_start_filetime"), target))
    source = hint.get("source_identity")
    if (hint.get("window_identity") != identity or type(source) is not dict
            or source.get("state") != "verified" or source.get("vendor_verified") is not True
            or source.get("window_identity") != identity):
        _deny("vendor_or_window_unverified")
    # Recompute visible facts from this actual observation. A stale attached
    # hint must not overrule a newly checked remember box or changed command.
    visible = security_prompt_observation(result, expected_target=identity, content_allowed=True)
    if (visible is None or visible.get("reported_decision") != "pending"
            or visible.get("uia_truncated") is not False
            or visible.get("remember_choice", {}).get("state") != "unchecked"):
        _deny("incomplete_or_not_pending")
    fields = visible.get("fields")
    if type(fields) is not dict or any(type(fields.get(key)) is not dict
            or fields[key].get("state") != "observed" or fields[key].get("text") != text
            for key, text in expected):
        _deny("original_operation_mismatch")
    entries = result.get("entries")
    root = result.get("root_runtime_id")
    if (type(entries) is not list or type(root) is not list or not 1 <= len(root) <= 64
            or any(type(n) is not int for n in root)):
        _deny("allow_control_unavailable")
    buttons = [row for row in entries if type(row) is dict and row.get("control_type") == "Button"
        and type(row.get("name")) is str and _button_label(row["name"]) in _ALLOW
        and row.get("enabled") is True and row.get("offscreen") is False
        and row.get("password") is False and row.get("invoke_supported") is True
        and row.get("name_truncated") is not True and row.get("name_read_error") is not True]
    if len(buttons) != 1:
        _deny("allow_control_ambiguous")
    button = buttons[0]
    if (type(button.get("ref")) is not str or not button["ref"].startswith("appref:")
            or type(button.get("runtime_id")) is not list or not button["runtime_id"]
            or any(type(n) is not int for n in button["runtime_id"])):
        _deny("allow_control_unavailable")
    anchor = (target, tuple(result["root_runtime_id"]), tuple(button["runtime_id"]), button.get("automation_id"))
    return anchor, value["observation_id"], button["ref"]


class SecurityPromptExecution:
    def __init__(self, seal, **values):
        if seal is not _SEAL:
            _deny("internal_source_required")
        self.__dict__.update(values)
        self._closed = threading.Event()
        self._once = threading.Lock()
        self._attempted = False
        self._uncertain = False

    @classmethod
    def begin(cls, ledger, *, host_call, origin_token, original_action_id,
              native_command, native_arguments, project_intent, current_original, prompt):
        """Called inside the trusted host/original-executor adapter.

        ``project_intent(command, arguments)`` must derive exact visible fields
        from the original executor's full operation, not from this prompt. It
        is deliberately not a JSON parameter. ``current_original(binding)``
        rechecks the actual host message/work/request before and after I/O.
        Unsupported operations without such a trusted projector remain denied.
        """
        if (type(ledger) is not OriginLedger or type(host_call) is not HostToolCall
                or type(origin_token) is not str or len(origin_token) != 64):
            _deny("internal_source_required")
        session, semantic = ledger._prepare(host_call)
        token_hash = _hash(b"flower-token-v1\0", origin_token)
        with ledger.store.read_transaction() as db:
            ticket = db.execute("SELECT * FROM origin_tickets WHERE token_hash=?", (token_hash,)).fetchone()
            if (ticket is None or ticket["session_hash"] != session or ticket["semantic_hash"] != semantic
                    or ticket["turn_id"] != host_call.turn_id or ticket["tool_use_id"] != host_call.tool_use_id):
                _deny("original_source_unbound")
        return cls.begin_consumed(ledger, tool_name=host_call.tool_name, tool_input=host_call.tool_input,
            origin_token=origin_token, original_action_id=original_action_id, native_command=native_command,
            native_arguments=native_arguments, project_intent=project_intent,
            current_original=current_original, prompt=prompt)

    @classmethod
    def begin_consumed(cls, ledger, *, tool_name, tool_input, origin_token, original_action_id,
                       native_command, native_arguments, project_intent, current_original, prompt):
        """MCP-side factory after the actual origin token has been consumed.

        Derive session/task/turn/use from that exact existing ticket. Do not
        reconstruct a HostToolCall or issue/consume another ticket. The supplied
        original tool name/input must hash to the already admitted call; these
        values are provenance to verify, never declarations of task authority.
        """
        if (type(ledger) is not OriginLedger or type(tool_name) is not str
                or tool_name not in ledger.allowed_tools or not isinstance(tool_input, Mapping)
                or not callable(project_intent) or not callable(current_original)
                or type(origin_token) is not str or len(origin_token) != 64):
            _deny("internal_source_required")
        semantic = _semantic(tool_name, tool_input)
        token_hash = _hash(b"flower-token-v1\0", origin_token)
        fingerprint = command_hash(native_command, native_arguments)
        with ledger.store.read_transaction() as db:
            ticket = db.execute("SELECT * FROM origin_tickets WHERE token_hash=?", (token_hash,)).fetchone()
            action = db.execute("SELECT * FROM actions WHERE id=?", (original_action_id,)).fetchone()
            if (ticket is None or ticket["consumed"] is None or ticket["expires"] <= ledger.store.clock()
                    or ticket["semantic_hash"] != semantic or ticket["tool_name"] != tool_name or action is None
                    or action["task"] != ticket["task"] or action["fingerprint"] != fingerprint):
                _deny("original_source_unbound")
            session = ticket["session_hash"]
            session_row = db.execute("SELECT task FROM origin_sessions WHERE session_hash=?", (session,)).fetchone()
            if session_row is None or session_row[0] != action["task"]:
                _deny("original_source_unbound")
            thread = db.execute("SELECT * FROM origin_task_threads WHERE task=?", (action["task"],)).fetchone()
            context = db.execute("SELECT details FROM action_context WHERE action=?", (original_action_id,)).fetchone()
            context = json.loads(context[0]) if context else {}
            original_input = tool_input
            source_id = original_input.get("action_id")
            if context.get("operation") == "launch" and type(original_input.get("launch")) is dict:
                source_id = original_input["launch"].get("action_id")
            if (thread is None or thread["session_hash"] != session
                    or context.get("channel") not in {"app", "computer"}
                    or context.get("operation") != native_command
                    or type(source_id) is not str
                    or original_action_id != action["task"] + ":" + context["channel"] + ":" + source_id):
                _deny("original_source_unbound")
            binding = OriginalBinding(action["task"], action["id"], fingerprint, session,
                ticket["turn_id"], thread["host_kind"], thread["thread_id"])
        # Copy the arguments so a projector cannot mutate the original request.
        fields = project_intent(native_command, json.loads(json.dumps(native_arguments, allow_nan=False)))
        if (type(fields) is not dict or not _FIELDS <= fields.keys()
                or fields.keys() - _FIELDS - _OPTIONAL_FIELDS or any(not _text(v) for v in fields.values())):
            _deny("complete_original_operation_required")
        expected = tuple(sorted(fields.items()))
        anchor, _, _ = _snapshot(prompt, expected)
        # One allow per original executor action, including a replaced prompt.
        # A new HWND must never manufacture a second attempt after an unknown.
        stable = hashlib.sha256(json.dumps([binding.action_id, binding.fingerprint],
            separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()[:40]
        value = cls(_SEAL, ledger=ledger, binding=binding, _token_hash=token_hash, _semantic=semantic,
            _tool_use_id=ticket["tool_use_id"], _tool_name=tool_name,
            _expires=ticket["expires"], _expected=expected, _anchor=anchor,
            _action_id="security-allow-" + stable, _current_original=current_original)
        value._check()
        return value

    def _check(self, *, source=True, write=True):
        if self._closed.is_set():
            _deny("closed")
        store = self.ledger.store
        if store.task_write_stopped(self.binding.task):
            _deny("stopped")
        with store.read_transaction() as db:
            ticket = db.execute("SELECT * FROM origin_tickets WHERE token_hash=?", (self._token_hash,)).fetchone()
            thread = db.execute("SELECT * FROM origin_task_threads WHERE task=?", (self.binding.task,)).fetchone()
            session = db.execute("SELECT task FROM origin_sessions WHERE session_hash=?", (self.binding.session_hash,)).fetchone()
            action = db.execute("SELECT * FROM actions WHERE id=?", (self.binding.action_id,)).fetchone()
            if (ticket is None or ticket["consumed"] is None or ticket["expires"] <= store.clock()
                    or ticket["task"] != self.binding.task or ticket["session_hash"] != self.binding.session_hash
                    or ticket["turn_id"] != self.binding.turn_id or ticket["semantic_hash"] != self._semantic
                    or ticket["tool_use_id"] != self._tool_use_id or ticket["tool_name"] != self._tool_name
                    or session is None or session[0] != self.binding.task
                    or thread is None or (thread["host_kind"], thread["thread_id"], thread["session_hash"]) !=
                        (self.binding.host, self.binding.thread_id, self.binding.session_hash)
                    or action is None or action["task"] != self.binding.task
                    or action["fingerprint"] != self.binding.fingerprint or not action["dispatched"]
                    or action["state"] not in {"running", "verified", "not_verified"}):
                _deny("original_source_changed")
            store._owner(db, action["owner"])
            # The original write already consumed its observation. This is an
            # authority check, never another dispatch or a new observation.
            check = dict(action)
            check["observation"] = None
            if write:
                store._check_action(db, check, business_dependencies=False)
            else:
                # A quarantined write cannot dispatch again. Its own bounded
                # result metadata is still queryable; this invokes no UIA or
                # business operation and grants no continuation permission.
                from .control.state import _permission_revision
                from .control.call_cancellation import call_cancelled
                recorded = db.execute("SELECT revision FROM action_policy_revisions WHERE action=?",
                    (self.binding.action_id,)).fetchone()
                if (call_cancelled() or action["cancel_requested"] or recorded is None
                        or recorded[0] != _permission_revision()):
                    _deny("original_result_context_changed")
        if source:
            if self._current_original(self.binding) is not True:
                _deny("original_request_not_current")
            # Recheck SQLite/policy too, not only Stop: the source guard can
            # do I/O while the task, grants or host association change.
            self._check(source=False, write=write)

    def close(self):
        """Disarm this request immediately; never resume/clear Stop or input."""
        self._closed.set()

    def execute(self, *, fresh_snapshot, invoke_existing, read_original_result):
        """Fresh observation -> once App invoke -> query original outcome.

        The three callbacks stay local and synchronous in the existing bounded
        executor/call lifetime. Repeated calls query only the original result.
        The adapter does not infer success from window disappearance.
        """
        try:
            return self._execute(fresh_snapshot, invoke_existing, read_original_result)
        except Exception:
            if not self._attempted:
                raise
            return {"state": "outcome_uncertain", "reason": "security_prompt_continuation_unavailable",
                "allow_attempted": True, "allow_action_id": self._action_id,
                "input_replay": False, "business_result_verified": False}

    def _execute(self, fresh_snapshot, invoke_existing, read_original_result):
        if not all(callable(v) for v in (fresh_snapshot, invoke_existing, read_original_result)):
            _deny("callbacks_required")
        with self._once:
            key = self.binding.task + ":app:" + self._action_id
            with self.ledger.store.read_transaction() as db:
                prior = db.execute("SELECT state FROM actions WHERE id=? AND task=?", (key, self.binding.task)).fetchone()
            attempted = self._attempted or prior is not None
            self._attempted = attempted
            self._check(write=not attempted)
            unknown = self._uncertain or prior is not None and prior["state"] == "outcome_uncertain"
            if not attempted:
                snapshot = fresh_snapshot()
                self._check()
                anchor, observation, ref = _snapshot(snapshot, self._expected)
                if anchor != self._anchor:
                    _deny("prompt_replaced")
                self._check()
                self._attempted = True  # Exceptions after entry are not retries.
                try:
                    invoke_existing(AllowInvocation(self.binding.task, self._action_id,
                        anchor[0], observation, ref))
                except Exception:
                    unknown = True
                with self.ledger.store.read_transaction() as db:
                    prior = db.execute("SELECT state FROM actions WHERE id=? AND task=?", (key, self.binding.task)).fetchone()
                unknown = unknown or prior is None or prior["state"] not in {"verified", "not_verified", "cancelled"}
                self._uncertain = unknown
            try:
                self._check(write=False)
                outcome = read_original_result(self.binding)
                self._check(write=False)
            except Exception:
                return {"state": "outcome_uncertain", "reason": "security_prompt_original_result_unavailable",
                    "allow_attempted": self._attempted or attempted, "input_replay": False,
                    "business_result_verified": False}
            if (type(outcome) is not OriginalOutcome or outcome.action_id != self.binding.action_id
                    or outcome.state not in {"pending", "completed", "failed", "outcome_unknown"}
                    or type(outcome.business_verified) is not bool):
                _deny("original_result_unbound")
            verified = outcome.state == "completed" and outcome.business_verified
            state = ("outcome_uncertain" if unknown or outcome.state == "outcome_unknown" else
                "completed" if verified else "original_result_failed" if outcome.state == "failed" else
                "original_result_not_verified" if outcome.state == "completed" else "original_result_pending")
            return {"state": state,
                "original_action_id": self.binding.action_id, "allow_action_id": self._action_id,
                "allow_attempted": self._attempted or attempted, "input_replay": False,
                "business_result_verified": verified, "original_state": outcome.state}
