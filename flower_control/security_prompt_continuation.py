"""Source-bound continuations of actual ordinary App launch calls.

The private context contains executable checks, never caller JSON authority.
Normal App target/IL/privacy/Stop checks remain responsible for every Invoke.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
import copy
import json
import subprocess
import threading
import uuid

from .control.state import ControlError
from .control.worker_call import command_hash
from .authorization.origin import OriginLedger, _hash, _semantic
from .security_prompt_execution import SecurityPromptExecution, OriginalOutcome


_current = ContextVar("flower_security_prompt_original_request", default=None)


def recheck_current():
    """Called at the existing ordinary/High final dispatch boundaries."""
    capture_current_recheck()()


def capture_current_recheck():
    """Capture a callable before a native callback moves to another thread."""
    guard = _current.get()
    def check():
        if guard is not None and guard() is not True:
            raise ControlError("security_prompt_original_request_not_current")
    return check


@contextmanager
def bound_current(guard):
    if not callable(guard):
        raise ControlError("security_prompt_internal_source_required")
    token = _current.set(guard)
    try:
        recheck_current()
        yield
    finally:
        _current.reset(token)


# Source profile, not a claim that every Huorong version uses these labels.
# Unknown/missing/differently formatted fields are unsupported. Nothing below
# learns expected values from the window being checked.
PROFILE = "huorong-process-create-exact-v1"


def _reject(reason):
    raise ControlError("security_prompt_" + reason)


def _ticket(ledger, tool_name, tool_input, token):
    if type(ledger) is not OriginLedger or type(token) is not str:
        _reject("internal_source_required")
    digest = _hash(b"flower-token-v1\0", token)
    with ledger.store.read_transaction() as db:
        row = db.execute("SELECT * FROM origin_tickets WHERE token_hash=?", (digest,)).fetchone()
        if (row is None or row["consumed"] is None or row["expires"] <= ledger.store.clock()
                or row["tool_name"] != tool_name or row["semantic_hash"] != _semantic(tool_name, tool_input)):
            _reject("current_call_unbound")
        return dict(row)


@dataclass
class _Launch:
    ledger: OriginLedger
    owner: str
    action: str
    tool_name: str
    tool_input_json: str
    token: str
    native_json: str
    fields: dict
    ticket: dict
    check_request: object
    result: dict | None = None
    allow_key: str | None = None
    closed: threading.Event = field(default_factory=threading.Event)
    lock: object = field(default_factory=threading.RLock)


class LaunchContinuationRegistry:
    """Request-local memory populated only inside the real launch executor.

    This registry neither launches nor manufactures actions/tickets. A second
    admitted App call must belong to the original host turn. That is the
    ordinary Hook call boundary, not UAC semantic-message registration.
    """
    def __init__(self):
        self._lock = threading.RLock()
        self._records = {}
        self._pending = set()
        self._closed = False

    def retain_call(self, call):
        with self._lock:
            self._pending.add(call)
        call.add_done_callback(self._forget_call)

    def source_expiry(self, ledger, *, tool_name, tool_input, token):
        return _ticket(ledger, tool_name, tool_input, token)["expires"]

    def _forget_call(self, call):
        with self._lock:
            self._pending.discard(call)
        if not call.cancelled():
            call.exception()

    def remember(self, ledger, *, tool_name, tool_input, token, owner, action,
                 native_arguments, executable, executor_image, check_request):
        """Called in the dispatched EXE/background branch before its Popen."""
        original = copy.deepcopy(native_arguments)
        if (original.get("mode", "normal") != "background" or "aumid" in original
                or type(executable) is not str or type(executor_image) is not str
                or not callable(check_request)):
            return None
        ticket = _ticket(ledger, tool_name, tool_input, token)
        with ledger.store.read_transaction() as db:
            row = db.execute("SELECT * FROM actions WHERE id=?", (action,)).fetchone()
            if (row is None or row["owner"] != owner or row["task"] != ticket["task"]
                    or row["state"] != "running" or not row["dispatched"]
                    or row["fingerprint"] != command_hash("launch", original)):
                _reject("original_source_unbound")
        value = _Launch(ledger, owner, action, tool_name,
            json.dumps(tool_input, ensure_ascii=False, allow_nan=False), token,
            json.dumps(original, ensure_ascii=False, allow_nan=False),
            {"initiating_program": executor_image, "operation_type": "创建进程",
             "operation_target": executable,
             "command_line": subprocess.list2cmdline([executable, *original.get("args", [])])},
            ticket, check_request)
        with self._lock:
            for key, prior in list(self._records.items()):
                if prior.ticket["expires"] <= ledger.store.clock():
                    prior.closed.set()
                    self._records.pop(key, None)
            if self._closed or len(self._records) >= 128:
                return None
            if action in self._records:
                _reject("original_request_already_recorded")
            self._records[action] = value
        return value

    def complete(self, record, result):
        if record is not None:
            with record.lock:
                record.result = copy.deepcopy(result)

    def close(self, task=None):
        with self._lock:
            if task is None:
                self._closed = True
            for key, value in list(self._records.items()):
                if task is None or value.ticket["task"] == task:
                    value.closed.set()
                    self._records.pop(key, None)

    def execute(self, active, *, ledger, task, tool_name, tool_input, token,
                original_action_id, target, observation_id, automation_id,
                current_stopped):
        """Use the normal App observer/invoker; no alternate UI input path."""
        key = task + ":app:" + original_action_id
        with self._lock:
            record = self._records.get(key)
        if record is None:
            _reject("original_operation_unsupported")
        current = _ticket(ledger, tool_name, tool_input, token)
        if (current["task"] != task or current["session_hash"] != record.ticket["session_hash"]
                or current["turn_id"] != record.ticket["turn_id"]
                or active.store.directory.resolve() != ledger.store.directory.resolve()):
            _reject("original_turn_changed")
        def current_original(_binding=None):
            if self._closed or record.closed.is_set() or current_stopped():
                return False
            record.check_request()
            actual = _ticket(ledger, tool_name, tool_input, token)
            if actual != current:
                return False
            with ledger.store.read_transaction() as db:
                latest = db.execute("SELECT turn_id FROM origin_tickets WHERE session_hash=? "
                    "ORDER BY issued DESC,rowid DESC LIMIT 1", (current["session_hash"],)).fetchone()
                action = db.execute("SELECT * FROM actions WHERE id=? AND task=?",
                    (key, task)).fetchone()
                with record.lock:
                    finished = record.result is not None and record.result.get("state") != "window_pending"
                    allow_key = record.allow_key
                if finished and (allow_key is None or db.execute(
                        "SELECT 1 FROM actions WHERE id=? AND task=?", (allow_key, task)).fetchone() is None):
                    return False
                if (action is None or action["fingerprint"] != command_hash("launch", json.loads(record.native_json))
                        or action["state"] not in {"running", "verified", "not_verified"}):
                    return False
                ledger.store._owner(db, action["owner"])
                checked = dict(action)
                checked["observation"] = None
                ledger.store._check_action(db, checked, business_dependencies=False)
            return (latest is not None and latest[0] == current["turn_id"]
                and not action["cancel_requested"])
        latest_snapshot = {}
        def snapshot():
            value = active.observe(target, content=True,
                action_id="security-observe-" + uuid.uuid4().hex, trusted_task=task,
                limits={"max_nodes": 500, "max_depth": 12})
            latest_snapshot["value"] = value
            return value
        if not current_original():
            _reject("original_request_not_current")
        # The caller must name a current observed control in the same target;
        # it cannot introduce a new window by claiming original launch facts.
        with active._gate:
            cached = active._observations.get(observation_id)
            if (cached is None or cached["task"] != task
                    or cached["target"] != tuple(target[name] for name in ("pid", "hwnd", "process_start_filetime"))
                    or cached["expires"] <= active.store.clock()
                    or not any(row.get("ref") == automation_id for row in cached["result"].get("entries", []))):
                _reject("observation_unavailable")
        with bound_current(current_original):
            first = snapshot()
            shown = first.get("result", {}).get("security_prompt", {}).get("fields", {})
            if any(type(shown.get(name)) is not dict or shown[name].get("state") != "observed"
                    or shown[name].get("text") != expected for name, expected in record.fields.items()):
                return {"state": "unsupported", "dispatched": False,
                    "reason": "security_prompt_profile_unsupported", "profile": PROFILE,
                    "profile_runtime_verified": False, "input_replay": False}
            adapter = SecurityPromptExecution.begin_consumed(record.ledger,
                tool_name=record.tool_name, tool_input=json.loads(record.tool_input_json),
                origin_token=record.token, original_action_id=key, native_command="launch",
                native_arguments=json.loads(record.native_json),
                project_intent=lambda _command, _arguments: dict(record.fields),
                current_original=current_original, prompt=first)
            with record.lock:
                record.allow_key = task + ":app:" + adapter._action_id
            def invoke(request):
                # The existing executor persists this stable action before UIA.
                # This postcondition describes only the chosen button; the
                # independent original launch query below owns its outcome.
                rows = latest_snapshot["value"]["result"]["entries"]
                names = [row.get("name") for row in rows if row.get("ref") == request.ref]
                if len(names) != 1 or type(names[0]) is not str:
                    _reject("allow_control_unavailable")
                return active.invoke(dict(zip(("pid", "hwnd", "process_start_filetime"), request.target)),
                    request.observation_id, request.ref,
                    {"automation_id": request.ref, "field": "name", "equals": names[0]},
                    request.action_id, trusted_task=task)
            last = {}
            def read_original(binding):
                nonlocal last
                last = active.action_status(original_action_id, trusted_task=task, refresh_launch=True)
                refresh = last.get("launch_refresh", {})
                with record.lock:
                    result = copy.deepcopy(record.result)
                if result is None:
                    return OriginalOutcome(binding.action_id, "pending")
                original = (result.get("pid"), result.get("process_start_filetime"))
                verified = any((row.get("pid"), row.get("process_start_filetime")) == original
                    and row.get("state") == "running" and row.get("window_count", 0) > 0
                    for row in refresh.get("processes", []))
                state = ("outcome_unknown" if result.get("state") == "outcome_uncertain" else
                    "failed" if result.get("state") == "rejected" else "completed" if verified
                    or result.get("state") == "process_exited" else "pending")
                return OriginalOutcome(binding.action_id, state, verified)
            value = adapter.execute(fresh_snapshot=snapshot, invoke_existing=invoke,
                                    read_original_result=read_original)
            value.update(profile=PROFILE, profile_runtime_verified=False,
                verification_scope="original_launch_process_and_window_only",
                original_launch_status=last if "original_state" in value else {})
            return value
