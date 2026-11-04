"""Per-stdio-process Web sessions bound to a Hook-proven chat task.

Only freshly owned, guarded profiles are exposed in this public slice.
The shared ledger, browser Job and worker permit remain the dispatch authority.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import sqlite3
import uuid
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from flower_control.authorization.luohua_policy import READ_SCOPE
from flower_control.control.state import ControlError, StateStore
from flower_control.control.write_gate import WriteGateError
from .web_window_mode import normalize_window_mode,browser_window_mode
from flower_control.control.jev import JevClient
from flower_control.control.scheduling import Phase
from flower_control.control.worker_call import command_hash
from flower_control.control.native import process_identity, process_is_alive
from flower_control.drivers.web_control import ControlledWeb
from flower_control.browsers import profile_resource_id
from flower_control.drivers.web_effects import WebClosePending
from flower_control.drivers.web_session import (DEFAULT_BRAVE, TemporaryWebSession,
                                                _visible_browser_windows)


@dataclass
class _Session:
    task: str
    browser: TemporaryWebSession
    control: ControlledWeb
    heartbeat: asyncio.Task | None = None
    closing: bool = False
    closed: bool = False
    cleanup_error: bool = False
    active_actions: int = 0
    normal_closed: bool = False
    lifecycle_error: str | None = None


def browser_window_handoff_candidates(record: _Session):
    """Return one bound identity per visible top-level window of this process.

    Several windows are listed explicitly instead of guessed. Each identity is
    rechecked when the receiving channel adopts it, and binding writes only
    Flower's window-property nonce. A single unreadable window does not hide
    the readable ones; its fixed error code is reported separately.
    """
    from flower_control.drivers.computer_native import NativeInputError, bind_window
    pid = getattr(record.browser, "process_id", None)
    if getattr(record.browser, "headless", None) is True or type(pid) is not int or pid <= 0:
        raise ControlError("browser_window_handoff_unavailable")
    windows = _visible_browser_windows(pid)
    if not windows:
        raise ControlError("browser_window_handoff_unavailable")
    identities, failures = [], []
    for hwnd in windows[:8]:
        try:
            identities.append(bind_window(hwnd))
        except NativeInputError as error:
            failures.append(error.code)
    if not identities:
        raise ControlError(failures[0] if failures else "browser_window_handoff_unavailable")
    return identities, failures


def browser_window_handoff_identity(record: _Session):
    """Return the one exact visible window for this owned browser process.

    Kept for callers that require a single unambiguous window. The public
    handoff command uses browser_window_handoff_candidates instead.
    """
    from flower_control.drivers.computer_native import NativeInputError, bind_window
    pid = getattr(record.browser, "process_id", None)
    if getattr(record.browser, "headless", None) is True or type(pid) is not int or pid <= 0:
        raise ControlError("browser_window_handoff_unavailable")
    windows = _visible_browser_windows(pid)
    if not windows:
        raise ControlError("browser_window_handoff_unavailable")
    if len(windows) != 1:
        raise ControlError("browser_window_handoff_ambiguous")
    try:
        return bind_window(windows[0])
    except NativeInputError as error:
        raise ControlError(error.code) from None


def browser_handoff_result(pairs, binding_failures=()):
    """Build the public response from (token, identity) pairs."""
    from flower_control.drivers.web_session import browser_window_candidate_summary
    common = {"target_kind": "owned_browser_window",
              "fresh_observation_required": True,
              "grants_authorization": False}
    if binding_failures:
        common["binding_failures"] = list(binding_failures)
    if len(pairs) == 1:
        token, _identity = pairs[0]
        return {"state": "handoff_ready", "candidate_id": token, **common}
    return {"state": "selection_required",
            "candidates": [{"candidate_id": token, "pid": identity.pid,
                            "hwnd": identity.hwnd,
                            **browser_window_candidate_summary(identity.hwnd)}
                           for token, identity in pairs],
            "selection_meaning": "Pass one candidate_id to flower_app_select_window or flower_computer_select_window. Each candidate is chat-bound, single-use and expires in about 30 seconds; the receiver must observe again.",
            **common}


@dataclass(frozen=True)
class _RuntimeHealth:
    """A sampled internal fact set, not an arbitrary exception payload."""
    browser_running: bool | None
    worker_running: bool | None
    transport_poisoned: bool | None
    browser_process_id: int | None = None
    browser_process_created: str | None = None
    worker_process: str | None = None
    browser_exit: dict | None = None
    worker_exit: dict | None = None
    diagnostic_invalid: int = 0
    diagnostic_omitted: int = 0
    launcher_running: bool | None = None
    launcher_process_id: int | None = None
    launcher_exit: dict | None = None

    @property
    def reason(self):
        if self.browser_running is False:
            return "owned_browser_exited"
        if self.worker_running is False or self.launcher_running is False:
            return "web_worker_unavailable"
        if self.transport_poisoned is True:
            return "web_transport_poisoned"
        if self.worker_running is not True:
            return "web_worker_unavailable"
        return None

    def public(self):
        # Only fixed fields/types; even a mistakenly attached internal value
        # cannot smuggle arbitrary strings through the public error boundary.
        def identity(value, *, pid=False):
            pattern = r"[1-9][0-9]{0,9}:\d{4}-\d{2}-\d{2}T[0-9:.]+\+00:00" if pid else r"\d{4}-\d{2}-\d{2}T[0-9:.]+\+00:00"
            return value if type(value) is str and re.fullmatch(pattern, value) else None
        def exit_info(value):
            if not isinstance(value, dict):
                return None
            return {"exit_code": value.get("exit_code") if type(value.get("exit_code")) is int else None,
                    "reported_exit_code": value.get("reported_exit_code") if type(value.get("reported_exit_code")) is int else None,
                    "observed_at": value.get("observed_at") if type(value.get("observed_at")) in (int, float) else None,
                    "os_exit_time": identity(value.get("os_exit_time")),
                    "process": identity(value.get("process"), pid=True),
                    "process_id": value.get("process_id") if type(value.get("process_id")) is int else None}
        return {"browser_running": self.browser_running if type(self.browser_running) is bool else None,
                "worker_running": self.worker_running if type(self.worker_running) is bool else None,
                "transport_poisoned": self.transport_poisoned if type(self.transport_poisoned) is bool else None,
                "browser_process_id": self.browser_process_id if type(self.browser_process_id) is int else None,
                "browser_process_created": identity(self.browser_process_created),
                "worker_process": identity(self.worker_process, pid=True),
                "browser_exit": exit_info(self.browser_exit), "worker_exit": exit_info(self.worker_exit),
                "launcher_running": self.launcher_running if type(self.launcher_running) is bool else None,
                "launcher_process_id": self.launcher_process_id if type(self.launcher_process_id) is int else None,
                "launcher_exit": exit_info(self.launcher_exit),
                "diagnostic_invalid": self.diagnostic_invalid if type(self.diagnostic_invalid) is int else 0,
                "diagnostic_omitted": self.diagnostic_omitted if type(self.diagnostic_omitted) is int else 0}


class WebMcpRuntime:
    def __init__(self, store: StateStore, *, ai_profile: Path | None = None,
                 luohua_profile: Path | None = None,
                 ai_brave_executable: Path = DEFAULT_BRAVE,
                 allow_visible_login_fixture: bool = False,
                 jev_client_factory: Callable[[], JevClient] | None = None):
        self.store = store
        from flower_control.profile_registry import profile_paths
        profile_paths(store.directory.parent)  # Reject malformed selection on construction too.
        self._profile_overrides = {"ai": ai_profile, "luohua": luohua_profile}
        self.ai_brave_executable = ai_brave_executable
        self.jev_client_factory = jev_client_factory
        # The public entry enables the supported visible login workflow;
        # isolated fixtures can keep it disabled.
        self.allow_visible_login_fixture = allow_visible_login_fixture
        self.sessions: dict[str, _Session] = {}
        self._lock = asyncio.Lock()
        self._starting = 0
        self._logins: dict[str, TemporaryWebSession] = {}
        self._mode_gate = asyncio.Lock()
        self._mode_transitions: dict[str, tuple[str, str]] = {}

    def _diagnostic(self, task):
        return lambda details: self.store.record_event("web_lifecycle", task=task, details=details)

    async def close_connection(self, tasks: frozenset[str]) -> None:
        """Release persistent control on EOF; only temporary resources close."""
        from flower_control.control.jev_diagnostics import _public_tool_event

        def cleanup_event(event, *, task, details):
            # These are best-effort lifecycle diagnostics, not authority or
            # dispatch auditing. Broken storage must not strand other sessions.
            _public_tool_event(self.store, event, task=task, details=details)

        for session_id, record in tuple(self.sessions.items()):
            if record.task not in tasks or record.closed:
                continue
            try:
                if record.browser.persistent_profile is None:
                    result = await self.close_temp(record.task, session_id)
                else:
                    if record.heartbeat is not None:
                        record.heartbeat.cancel()
                        await asyncio.gather(record.heartbeat, return_exceptions=True)
                    await record.browser.disconnect()
                    self.store.retire_owner(record.control.owner)
                    record.closed = True
                    result = {"closed": False, "state": "control_released_browser_retained"}
                cleanup_event("web_connection_cleanup", task=record.task,
                    details={"session_id": session_id, "closed": result.get("closed") is True,
                             "reason": result.get("reason"), "state": result.get("state")})
            except Exception as error:
                cleanup_event("web_connection_cleanup", task=record.task,
                    details={"session_id": session_id, "closed": False,
                             "reason": error.code if isinstance(error, ControlError) else "cleanup_failed"})
        for login_id, browser in tuple(self._logins.items()):
            if browser.owner_task not in tasks or browser.profile_kind != "ai":
                continue
            try:
                result = await self.cancel_ai_login(browser.owner_task, login_id)
                if result.get("state") == "cancel_pending_user_close":
                    await browser.disconnect()  # Keep the human's login window.
                cleanup_event("web_connection_login_cleanup", task=browser.owner_task,
                    details={"login_id": login_id, "state": result.get("state")})
            except Exception as error:
                cleanup_event("web_connection_login_cleanup", task=browser.owner_task,
                    details={"login_id": login_id, "state": "cleanup_failed",
                             "reason": error.code if isinstance(error, ControlError) else "cleanup_failed"})

    def _lifecycle(self, record, phase, trigger):
        if isinstance(record.browser, TemporaryWebSession):
            record.browser.record_lifecycle(phase, trigger=trigger)

    @staticmethod
    def _health(record):
        browser = record.browser
        if isinstance(browser, TemporaryWebSession):
            data = browser.health_snapshot()
            return _RuntimeHealth(**data)
        worker = getattr(browser, "_worker", None)
        process = getattr(worker, "process", None)
        return _RuntimeHealth(getattr(browser, "running", None),
            process is not None and getattr(process, "returncode", None) is None,
            getattr(worker, "_poisoned", None),
            launcher_running=process is not None and getattr(process, "returncode", None) is None)

    def _profile(self, kind: str) -> Path:
        if kind not in self._profile_overrides:
            raise ValueError("invalid_profile_kind")
        explicit = self._profile_overrides[kind]
        if explicit is not None:
            return explicit
        from flower_control.profile_registry import profile_paths
        return profile_paths(self.store.directory.parent)[kind]

    @property
    def ai_profile(self):
        return self._profile("ai")

    @property
    def luohua_profile(self):
        return self._profile("luohua")

    def _require_private_grant(self, task: str) -> None:
        with self.store.transaction() as db:
            if self.store._task(db, task)["paused"]:
                raise ControlError("task_paused")
            from flower_control.browsers import personal_profile_scope
            self.store._require_scope(db, task, personal_profile_scope(self.ai_brave_executable))

    def _require_active_chat(self, task: str) -> None:
        with self.store.transaction() as db:
            if self.store._task(db, task)["paused"]:
                raise ControlError("task_paused")

    def _require_lifecycle_write(self, task: str, kind: str = "temporary") -> None:
        self._require_active_chat(task)
        if self.store.write_stopped():
            raise ControlError("global_stop_active")
        if kind == "luohua":
            self._require_private_grant(task)

    def _login_browser(self, task: str, *, initial_url: str = "about:blank",
                       kind: str = "ai") -> TemporaryWebSession:
        return TemporaryWebSession(headless=False, guarded=True, login_only=True,
                                   initial_url=initial_url, persistent_profile=self._profile(kind),
                                   owner_task=task, brave_executable=self.ai_brave_executable,
                                   profile_kind=kind,
                                   owner_task_matches=lambda previous: self.store.same_chat_after_reboot(task, previous))

    def _require_quiet_profile(self, kind: str, *, for_close: bool = False) -> None:
        resource_id = profile_resource_id(kind, self.ai_brave_executable)
        self.store.reap_dead_owners()
        with self.store.transaction() as db:
            resource = db.execute("SELECT paused,quarantined FROM resources WHERE id=?",
                                  (resource_id,)).fetchone()
            actions = db.execute("SELECT resources FROM actions WHERE state IN ('queued','running')").fetchall()
            if ((resource and (resource["paused"] or resource["quarantined"] and not for_close))
                    or any(resource_id in json.loads(row["resources"])
                           for row in actions)):
                raise ControlError(f"{kind}_profile_action_recovery_required")

    def _require_quiet_ai_profile(self) -> None:
        self._require_quiet_profile("ai")

    @contextmanager
    def _close_resource(self, record: _Session, resource_id: str, *, kind: str | None = None):
        """Bind normal close to the existing task/owner/resource dispatch contract."""
        self._require_active_chat(record.task)
        if kind == "luohua":
            self._require_private_grant(record.task)
        owner = record.control.owner
        expected = getattr(record.control, "resource", resource_id)
        if expected != resource_id:
            raise ControlError("browser_close_resource_mismatch")
        self.store.register_resource(resource_id,
                                     required_scope=record.control.scope if kind == "luohua" else None)
        if kind is None:
            self.store.bind_owned_resource(owner, resource_id)
        action_id = "web-close:" + uuid.uuid4().hex
        close_arguments = ({"preserve_tabs": True} if getattr(record.browser, "retain_profile_on_close", False)
                           and getattr(record.browser, "persistent_profile", None) is None else {})
        fingerprint = command_hash("close_browser", close_arguments)
        try:
            if kind is not None:
                self._require_quiet_profile(kind, for_close=True)
            else:
                self.store.reap_dead_owners()
                with self.store.transaction() as db:
                    actions = db.execute(
                        "SELECT resources FROM actions WHERE state IN ('queued','running')"
                    ).fetchall()
                    if any(resource_id in json.loads(row["resources"]) for row in actions):
                        raise ControlError("temporary_browser_action_in_flight")
            self.store.enqueue(owner, action_id=action_id, fingerprint=fingerprint,
                               resources=(resource_id,), phase=Phase.FINISH,
                               context={"channel": "web", "operation": "close_browser",
                                        "foreground_needed": False})
            decision = self.store.prepare_decision((resource_id,), ttl=5)
            if not self.store.adopt_decision(decision["id"], action_id):
                self.store.cancel(owner, action_id)
                raise ControlError("browser_close_dispatch_changed")
            with self.store.dispatch(owner, action_id, decision["id"]):
                try:
                    worker = record.browser._require_worker()
                    token = self.store.issue_worker_permit(owner, action_id,
                                                          worker.worker_identity, fingerprint)
                except Exception:
                    self.store.record_action_effects(owner, action_id,
                                                     activation_dispatched=False,
                                                     business_dispatched=False)
                    self.store.finish(owner, action_id, "not_verified",
                                      result_code="web_close_permit_not_issued")
                    raise

                async def before_send():
                    self.store.check_dispatch(owner, action_id)

                def on_effects(dispatched):
                    self.store.record_action_effects(owner, action_id,
                                                     activation_dispatched=False,
                                                     business_dispatched=dispatched)

                envelope = {"directory": str(self.store.directory.resolve()),
                            "action": action_id, "token": token}
                yield action_id, {"execution": envelope, "before_send": before_send,
                                  "on_effects": on_effects}
        except ControlError as error:
            with self.store.transaction() as db:
                row = db.execute("SELECT state FROM actions WHERE id=?", (action_id,)).fetchone()
            if row and row[0] == "queued":
                self.store.cancel(owner, action_id)
            if error.code == "resource_busy":
                raise ControlError("browser_resource_busy") from error
            if error.code == "abandoned_execution_requires_recovery":
                raise ControlError("browser_resource_recovery_required") from error
            raise

    @staticmethod
    async def _finish_browser_close(browser: TemporaryWebSession, *, execution: dict,
                                    before_send: Callable, on_effects: Callable,
                                    on_cancel: Callable):
        """Keep the resource lock until close finishes even if the MCP call is cancelled."""
        closing = asyncio.create_task(browser.close(execution=execution, before_send=before_send,
                                                    on_effects=on_effects))
        cancelled = False
        while not closing.done():
            try:
                # wait() does not cancel its children when the caller is
                # cancelled. Consume the close result ourselves exactly once;
                # shield() logs a child exception after cancellation in 3.14.
                await asyncio.wait((closing,))
            except asyncio.CancelledError:
                cancelled = True
                on_cancel()
        try:
            result = closing.result()
        except WebClosePending as error:
            error.call_cancelled = cancelled
            raise
        if cancelled:
            raise asyncio.CancelledError
        return result

    async def _close_live_record(self, record: _Session, resource_id: str,
                                 *, kind: str | None = None) -> dict:
        dispatch_ready = [False]
        try:
            return await self._close_live_record_inner(record, resource_id, kind=kind,
                on_dispatch_ready=lambda: dispatch_ready.__setitem__(0, True))
        except ControlError as error:
            if not dispatch_ready[0]:
                # No browser-close callback has become available to the caller.
                # This is a producer fact, never inferred from the error name.
                error.web_dispatched = False
                error.web_stage = "close_preflight"
            raise

    async def _close_live_record_inner(self, record: _Session, resource_id: str,
                                      *, kind: str | None = None, on_dispatch_ready) -> dict:
        owner = record.control.owner
        with self.store.transaction() as db:
            row = db.execute("SELECT quarantined FROM resources WHERE id=?", (resource_id,)).fetchone()
            recovering = bool(row and row[0])
        identities = None
        worker = None
        recovery_probe = None
        if recovering:
            # A responsive serial worker establishes that the earlier call has
            # ended. It does NOT establish that its business effect succeeded.
            # Poisoned transport or a missing executor stays blocked.
            from .web_session import _WorkerClient
            worker = record.browser._require_worker()
            if not isinstance(worker, _WorkerClient) or worker._poisoned:
                raise ControlError("web_recovery_executor_unverified")
            self._require_active_chat(record.task)
            if kind == "luohua":
                self._require_private_grant(record.task)
            ping = await worker.call("ping", {}, before_send=lambda: self._close_check(record, kind))
            if not isinstance(ping, dict) or ping.get("process") != worker.worker_identity:
                raise ControlError("web_recovery_executor_unverified")
            browser = record.browser
            if (type(browser.process_id) is not int or not browser.process_created
                    or worker.process is None):
                raise ControlError("web_recovery_executor_unverified")
            identities = (f"{browser.process_id}:{browser.process_created}",
                          worker.worker_identity, process_identity(worker.process.pid))
        with self._close_resource(record, resource_id, kind=kind) as (action_id, callbacks):
            on_dispatch_ready()
            record.closing = True
            try:
                await self._finish_browser_close(record.browser, **callbacks,
                    on_cancel=lambda: self.store.cancel(owner, action_id))
                if record.browser.running:
                    raise ControlError("owned_browser_close_not_confirmed")
                self.store.finish(owner, action_id, "verified", result_code="browser_exit_confirmed")
                result = {"closed": True, "action_id": action_id}
                if recovering:
                    # Closure is an intentional new effect, never replay of the
                    # failed operation. Recovery requires all exact executors
                    # and the browser to have exited normally. Keep old receipts.
                    def probe():
                        self._require_active_chat(record.task)
                        if kind == "luohua":
                            self._require_private_grant(record.task)
                        if self.store.write_stopped():
                            raise ControlError("global_stop_active")
                        if (record.browser.running or worker.exit_code != 0
                                or any(not identity or process_is_alive(identity) for identity in identities)):
                            raise ControlError("web_recovery_exit_unverified")
                        return {resource_id: "closed:" + record.browser.session_id + ":" + identities[0]}
                    recovery_probe = probe
            except WebClosePending as pending:
                self.store.finish(owner, action_id, "not_verified",
                                  result_code="browser_close_stopped" if pending.result.get("state") == "close_stopped"
                                  else "browser_close_pending")
                if getattr(pending, "call_cancelled", False):
                    raise asyncio.CancelledError
                return {**pending.result, "closed": False, "action_id": action_id}
            except asyncio.CancelledError:
                self.store.finish(owner, action_id,
                    "outcome_uncertain" if record.browser.running else "verified",
                    result_code="browser_close_call_cancelled")
                if record.browser.running and self.store.status(owner, action_id)["state"] == "outcome_uncertain":
                    record.cleanup_error = True
                raise
            except Exception as error:
                callbacks["on_effects"](getattr(error, "web_dispatched", None))
                self.store.finish(owner, action_id, "outcome_uncertain",
                                  result_code=error.code if isinstance(error, ControlError)
                                  else "browser_close_failed")
                receipt = self.store.status(owner, action_id)
                if receipt["state"] != "outcome_uncertain":
                    return {"closed": False, "state": "not_verified", "action_id": action_id,
                            "reason": error.code if isinstance(error, ControlError)
                            else "browser_close_not_dispatched", "dispatched": False}
                record.cleanup_error = True
                return {"closed": not record.browser.running, "state": "outcome_uncertain", "action_id": action_id,
                        "reason": f"{kind}_browser_close_uncertain" if kind else "owned_browser_cleanup_failed"}
            finally:
                await self._settle_close_record(record)
        # The normal-close dispatch lock has now been released. Acquire the
        # recovery contract's independent lock and recheck the exact exits;
        # no other normal write can run while quarantine is still present.
        if recovery_probe is not None:
            try:
                result["recovery"] = self.store.recover_resources((resource_id,), recovery_probe)
            except ControlError as error:
                result["recovery"] = {"recovered": False, "reason": error.code}
            result["unknown_receipts_preserved"] = True
        return result

    async def _close_check(self, record, kind):
        self._require_active_chat(record.task)
        if kind == "luohua":
            self._require_private_grant(record.task)
        if self.store.write_stopped():
            raise ControlError("global_stop_active")

    async def _settle_close_record(self, record: _Session) -> None:
        """Pending/live instances keep their exact executor and diagnostic route."""
        if record.browser.running:
            record.closing = False
            return
        if record.heartbeat is not None and not record.cleanup_error:
            record.heartbeat.cancel()
            await asyncio.gather(record.heartbeat, return_exceptions=True)
        self.store.retire_owner(record.control.owner)
        record.closed = True
        record.closing = False
        record.normal_closed = not record.cleanup_error
        if record.cleanup_error and (record.heartbeat is None or record.heartbeat.done()):
            record.heartbeat = asyncio.create_task(self._heartbeat(record))

    def _login_identity(self, task: str, login_id: str, marker: dict,
                        kind: str = "ai") -> None:
        if marker.get("session_id") != login_id or not self._marker_belongs_to_task(task, marker):
            raise ControlError("session_not_found_for_chat")
        if marker.get("profile_kind") != kind:
            raise ControlError("session_not_found_for_chat")
        if marker.get("state") != "running":
            raise ControlError("ai_login_not_running")

    def _marker_belongs_to_task(self, task: str, marker: dict) -> bool:
        return (marker.get("owner_task") == task or
                self.store.same_chat_after_reboot(task, marker.get("owner_task")))

    async def begin_ai_login(self, task: str, *, initial_url: str = "about:blank") -> dict:
        return await self._begin_profile_login(task, "ai", initial_url=initial_url)

    async def begin_luohua_login(self, task: str, *, initial_url: str = "about:blank") -> dict:
        return await self._begin_profile_login(task, "luohua", initial_url=initial_url)

    async def _begin_profile_login(self, task: str, kind: str, *,
                                   initial_url: str) -> dict:
        """Open only the fixed AI profile for direct human use; no CDP or worker."""
        self._require_active_chat(task)
        if kind == "luohua":
            self._require_private_grant(task)
        if not self.allow_visible_login_fixture:
            raise ControlError("ai_login_protection_unverified")
        async with self._lock:
            self._require_lifecycle_write(task, kind)
            if any(not item.closed and item.browser.persistent_profile is not None
                   and getattr(item.browser, "profile_kind", "ai") == kind
                   for item in self.sessions.values()):
                raise ControlError(f"{kind}_background_session_must_be_closed")
            if any(browser.profile_kind == kind for browser in self._logins.values()):
                raise ControlError(f"{kind}_login_already_running")
            self._require_quiet_profile(kind)
            browser = self._login_browser(task, initial_url=initial_url, kind=kind)
            try:
                self._require_lifecycle_write(task, kind)
                await browser.start()
            except Exception:
                if (browser.process_id and browser.process_created and
                        process_is_alive(f"{browser.process_id}:{browser.process_created}")):
                    return {"state": "outcome_uncertain", "reason": "ai_login_window_unverified",
                            "login_id": browser.session_id, "profile_data": "retained",
                            "recovery": "check_ai_login_status"}
                raise
            self._logins[browser.session_id] = browser
            return self._mode_output(task, {"login_id": browser.session_id, "state": "waiting_for_human",
                    "profile": kind, "profile_data": "retained", "background_control": False})

    async def _attached_login(self, task: str, login_id: str,
                              kind: str = "ai") -> TemporaryWebSession | None:
        browser = self._logins.get(login_id)
        if browser is not None:
            if browser.owner_task != task or browser.profile_kind != kind:
                raise ControlError("session_not_found_for_chat")
            return browser
        browser = self._login_browser(task, kind=kind)
        try:
            await browser.reconnect(login_id)
        except ControlError as error:
            if error.code == "ai_browser_identity_unverified":
                return None  # The exact browser may have exited; seal it below.
            raise
        self._logins[login_id] = browser
        return browser

    async def ai_login_status(self, task: str, login_id: str) -> dict:
        return await self._profile_login_status(task, login_id, "ai")

    async def luohua_login_status(self, task: str, login_id: str) -> dict:
        return await self._profile_login_status(task, login_id, "luohua")

    async def _profile_login_status(self, task: str, login_id: str,
                                    kind: str) -> dict:
        if not isinstance(login_id, str) or len(login_id) != 32:
            raise ControlError("invalid_login_id")
        if kind == "luohua":
            self._require_private_grant(task)
        async with self._lock:
            browser = self._logins.get(login_id)
            temporary = browser is None
            if browser is None:
                browser = self._login_browser(task, kind=kind)
                browser.profile_path = browser.persistent_profile
                browser._acquire_profile_lock()
            try:
                marker = browser._read_marker()
                self._login_identity(task, login_id, marker, kind)
                pid, created = marker.get("browser_pid"), marker.get("browser_created")
                if type(pid) is not int or pid <= 0 or not isinstance(created, str):
                    raise ControlError("ai_browser_identity_unverified")
                running = process_is_alive(f"{pid}:{created}")
                if running and temporary:
                    verified = browser._open_verified_process(marker)
                    verified.close()
                windows = _visible_browser_windows(pid) if running else []
                recovery = ("close_owned_window_then_finish_or_cancel" if windows else
                            "investigate_owned_process_without_window" if running else
                            "finish_or_cancel_closed_login")
                return {"login_id": login_id,
                        "state": "waiting_for_human" if running else "browser_closed",
                        "browser_running": running,
                        "window_visible": bool(windows),
                        "cancel_requested": marker.get("login_cancel_requested", False),
                        "background_control": False, "profile_data": "retained",
                        "recovery": recovery}
            finally:
                if temporary:
                    await browser._release_profile_lock()

    async def _seal_dead_login(self, task: str, login_id: str,
                               browser: TemporaryWebSession | None,
                               kind: str = "ai") -> tuple[bool, bool]:
        temporary = browser is None
        if browser is None:
            browser = self._login_browser(task, kind=kind)
            browser.profile_path = browser.persistent_profile
            browser._acquire_profile_lock()
        try:
            marker = browser._read_marker()
            self._login_identity(task, login_id, marker, kind)
            pid, created = marker.get("browser_pid"), marker.get("browser_created")
            if type(pid) is not int or pid <= 0 or not isinstance(created, str):
                raise ControlError(f"{kind}_browser_identity_unverified")
            if process_is_alive(f"{pid}:{created}"):
                if temporary:
                    raise ControlError(f"{kind}_browser_still_running_reconnect_required")
                return False, False
            owner = marker.get("owner_process")
            if temporary and owner is not None and process_is_alive(owner):
                raise ControlError(f"{kind}_previous_host_still_running")
            self._require_quiet_profile(kind)
            cancelled = bool(marker.get("login_cancel_requested"))
            marker["state"] = "closed"
            marker.pop("owner_task", None)
            marker["owner_process"] = None
            marker["worker_process"] = None
            browser._write_marker(marker)
            if not temporary:
                # The exact process is already dead. Releasing owned handles
                # cannot interrupt the human's still-open login window.
                await browser.disconnect()
                self._logins.pop(login_id, None)
            return True, cancelled
        finally:
            if temporary:
                await browser._release_profile_lock()

    async def finish_ai_login(self, task: str, login_id: str) -> dict:
        return await self._finish_profile_login(task, login_id, "ai")

    async def finish_luohua_login(self, task: str, login_id: str) -> dict:
        return await self._finish_profile_login(task, login_id, "luohua")

    async def _finish_profile_login(self, task: str, login_id: str,
                                    kind: str) -> dict:
        if not isinstance(login_id, str) or len(login_id) != 32:
            raise ControlError("invalid_login_id")
        if kind == "luohua":
            self._require_private_grant(task)
        async with self._lock:
            browser = await self._attached_login(task, login_id, kind)
            if browser is not None:
                marker = browser._read_marker()
                if marker.get("login_cancel_requested"):
                    raise ControlError(f"{kind}_login_cancel_requested")
            sealed, cancelled = await self._seal_dead_login(task, login_id, browser, kind)
            if not sealed:
                return {"login_id": login_id, "state": "waiting_for_user_close",
                        "background_control": False, "profile_data": "retained",
                        "recovery": "close_owned_window_then_finish"}
            if cancelled:
                raise ControlError(f"{kind}_login_cancel_requested")
        try:
            opened = (await self.open_ai(task, window_mode="hidden") if kind == "ai"
                      else await self.open_luohua(task, window_mode="hidden"))
        except ControlError as error:
            return {"login_id": login_id, "state": "background_unavailable",
                    "reason": error.code, "profile_data": "retained",
                    "ready_for_background": True}
        return {**opened, "login_id": login_id, "login_finished": True,
                "new_observation_required": True}

    async def cancel_ai_login(self, task: str, login_id: str) -> dict:
        return await self._cancel_profile_login(task, login_id, "ai")

    async def cancel_luohua_login(self, task: str, login_id: str) -> dict:
        return await self._cancel_profile_login(task, login_id, "luohua")

    async def _cancel_profile_login(self, task: str, login_id: str,
                                    kind: str) -> dict:
        if not isinstance(login_id, str) or len(login_id) != 32:
            raise ControlError("invalid_login_id")
        if kind == "luohua":
            self._require_private_grant(task)
        async with self._lock:
            browser = await self._attached_login(task, login_id, kind)
            if browser is not None:
                marker = browser._read_marker()
                self._login_identity(task, login_id, marker, kind)
                marker["login_cancel_requested"] = True
                browser._write_marker(marker)
            sealed, _ = await self._seal_dead_login(task, login_id, browser, kind)
            if not sealed:
                return {"login_id": login_id, "state": "cancel_pending_user_close",
                        "browser_running": True, "profile_data": "retained",
                        "recovery": "close_owned_window_then_cancel"}
            return {"login_id": login_id, "state": "cancelled",
                    "browser_running": False, "profile_data": "retained"}

    @staticmethod
    def _healthy(record: _Session) -> bool:
        health = WebMcpRuntime._health(record)
        return bool(health.browser_running is True and health.reason is None)

    async def _heartbeat(self, record: _Session) -> None:
        while not record.closed or record.cleanup_error:
            await asyncio.sleep(30)
            if not await self._heartbeat_once(record):
                return

    async def _heartbeat_once(self, record: _Session) -> bool:
        if record.closed and not record.cleanup_error:
            return False
        if record.closing:
            # A normal close may return a pending beforeunload dialog. Its
            # monitor must survive rather than silently ending the owner lease.
            try:
                # The in-flight permit remains bound to this exact owner.
                # Replacing an expired owner would invalidate its callbacks.
                self.store.heartbeat(record.control.owner)
            except ControlError as error:
                record.lifecycle_error = error.code
            return True
        if record.browser.running:
            try:
                record.control.owner = self.store.renew_or_replace_owner(record.task, record.control.owner)
            except ControlError as error:
                record.lifecycle_error = error.code
                return True
            record.lifecycle_error = self._health(record).reason
            # A failed executor is not permission to close live user tabs.
            return True
        record.closing = True
        self._lifecycle(record, "cleanup_requested", "heartbeat")
        try:
            # With the exact browser already gone, release only owned handles
            # and profile state. This branch never requests a live tab close.
            if getattr(record.browser, "persistent_profile", None) is not None:
                await record.browser.disconnect()
            else:
                await record.browser.close()
            record.cleanup_error = False
        except asyncio.CancelledError:
            record.cleanup_error = True
            raise
        except Exception:
            record.cleanup_error = True
        finally:
            self.store.retire_owner(record.control.owner)
            record.closed = not record.browser.running
            record.closing = False
            record.lifecycle_error = "owned_browser_cleanup_failed" if record.cleanup_error else "owned_browser_exited"
            if (record.closed and not record.cleanup_error and record.heartbeat is not None
                    and record.heartbeat is not asyncio.current_task()):
                record.heartbeat.cancel()
                await asyncio.gather(record.heartbeat, return_exceptions=True)
        return not record.closed or record.cleanup_error

    def _session_diagnostics(self, record: _Session, session_id: str, *,
                             health: _RuntimeHealth | None = None) -> dict:
        """Owned lifecycle metadata; transport health never grants authority."""
        health = self._health(record) if health is None else health
        running = health.browser_running
        available = (bool(health.reason is None and not record.closed and not record.closing and record.lifecycle_error is None)
                      if running is not None and hasattr(record.browser, "_worker") else None)
        return {"session_id": session_id, "browser_running": running,
                "browser_process_id": getattr(record.browser, "process_id", None),
                "browser_process_created": getattr(record.browser, "process_created", None),
                "control_available": available,
                **self._gui_close_availability(record), "closing": record.closing, "closed": record.closed,
                "lifecycle_error": record.lifecycle_error, "cleanup_error": record.cleanup_error,
                "runtime_health": health.public()}

    @staticmethod
    def _gui_close_availability(record: _Session) -> dict:
        headless = getattr(record.browser, "headless", None)
        probe_failed = False
        try:
            visible = getattr(record.browser, "window_visible", None)
        except Exception:
            visible, probe_failed = None, True
        headless = headless if type(headless) is bool else None
        visible = visible if type(visible) is bool else None
        if getattr(record.browser, "shared_browser", False):
            available, reason = False, "shared_browser_requires_exact_web_page"
        elif headless is True:
            available, reason = False, "headless_browser_has_no_gui_window"
        elif visible is False:
            available, reason = False, "visible_owned_window_not_observed"
        elif visible is True:
            available, reason = True, None
        else:
            available, reason = None, ("visible_owned_window_probe_failed" if probe_failed
                                      else "visible_owned_window_unverified")
        return {"headless": headless, "window_visible": visible,
                "gui_close_available": available, "gui_close_unavailable_reason": reason}

    def _worker_lost(self, record: _Session, *, health: _RuntimeHealth | None = None) -> bool:
        # Real TemporaryWebSession always has _worker. Alternate internal
        # adapters still prove their worker through _close_resource's permit.
        health = self._health(record) if health is None else health
        return (health.worker_running is not True or health.launcher_running is False
                or health.transport_poisoned is True
                if hasattr(record.browser, "_worker") else record.lifecycle_error == "web_worker_unavailable")

    def _normal_close_handoff(self, record: _Session, session_id: str, *, gui: dict | None = None) -> dict:
        """Hints for the same chat's existing managed-window fallback."""
        gui = self._gui_close_availability(record) if gui is None else {
            key: gui[key] for key in ("headless", "window_visible", "gui_close_available", "gui_close_unavailable_reason")}
        available = gui["gui_close_available"]
        return {"channels": ["app", "computer"] if available is True else [], "task": record.task,
                "session_id": session_id, "browser_process_id": getattr(record.browser, "process_id", None),
                "browser_process_created": getattr(record.browser, "process_created", None),
                "shared_web_resource": getattr(record.control, "resource", f"web-session:{session_id}"),
                **gui, "next_step": ("observe_exact_owned_window_then_normal_close" if available is True
                    else "retain_exact_instance_and_receipts_gui_close_unavailable" if available is False
                    else "verify_owned_window_visibility"),
                "fresh_observation_required": True, "authorization_recheck_required": True,
                "shared_resource_recheck_required": True, "preserve_unsaved_confirmation": True,
                "forced_termination_allowed": False, "replay_unknown_business_action": False,
                "final_check": "repeat_flower_web_close_temp_after_exact_browser_exit"}

    async def start_temp(self, task: str, *, visible: bool = True,start_minimized:bool=False) -> dict:
        self._require_active_chat(task)
        from flower_control.permissions import require_channel_allowed
        require_channel_allowed()
        if type(visible) is not bool or type(start_minimized) is not bool or start_minimized and not visible:
            raise ControlError("invalid_window_mode")
        async with self._lock:
            self._require_lifecycle_write(task)
            if self._starting + sum(not item.closed for item in self.sessions.values()) >= 32:
                raise ControlError("temporary_session_limit")
            self._starting += 1
        browser = TemporaryWebSession(headless=not visible, guarded=True,
                                       owner_task=task, diagnostic=self._diagnostic(task),
                                       brave_executable=self.ai_brave_executable,
                                       **({'start_minimized':True} if start_minimized else {}))
        registered = False
        try:
            self._require_lifecycle_write(task)
            await browser.start()
            control = ControlledWeb(self.store, task, browser,
                                    jev_client_factory=self.jev_client_factory)
            record = _Session(task, browser, control)
            async with self._lock:
                self.sessions[browser.session_id] = record
            record.heartbeat = asyncio.create_task(self._heartbeat(record))
            registered = True
            return self._mode_output(task, {"session_id": browser.session_id, "profile": "temporary",
                    "background": True, "window_visible": browser.window_visible,
                    "window_mode": 'minimized' if start_minimized else "visible" if visible else "hidden", "physical_input_used": False,
                    "running": browser.running})
        except BaseException:
            if not registered:
                await browser.close()
            raise
        finally:
            async with self._lock:
                self._starting -= 1

    async def open_ai(self, task: str, *, window_mode: str | None = None) -> dict:
        return await self._open_profile(task, "ai", window_mode=window_mode)

    async def open_luohua(self, task: str, *, window_mode: str | None = None) -> dict:
        return await self._open_profile(task, "luohua", window_mode=window_mode)

    async def _open_profile(self, task: str, kind: str, *, window_mode: str | None = None,
                            transition_from: str | None = None) -> dict:
        self._require_active_chat(task)
        from flower_control.permissions import require_channel_allowed
        require_channel_allowed()
        window_mode = normalize_window_mode(window_mode)
        if kind == "luohua":
            self._require_private_grant(task)
        from .web_shared_profile import require_profile_gate
        require_profile_gate(self.store, profile_resource_id(kind, self.ai_brave_executable))
        async with self._lock:
            self._require_lifecycle_write(task, kind)
            existing = next((item for item in self.sessions.values()
                             if item.browser.persistent_profile is not None and not item.closed
                             and getattr(item.browser, "profile_kind", "ai") == kind
                             and (item.task == task or not getattr(item.browser, "shared_browser", False))), None)
            if existing is not None:
                if existing.task != task:
                    raise ControlError(f"{kind}_profile_in_use_by_another_chat")
                if existing.closing or not self._healthy(existing):
                    raise ControlError(f"{kind}_profile_recovery_required")
                if (window_mode is not None
                        and browser_window_mode(existing.browser)!=window_mode):
                    # Changing mode must not silently close live tabs.
                    raise ControlError(f"{kind}_profile_window_mode_conflict")
                return {"session_id": existing.browser.session_id, "profile": kind,
                        "window_mode": browser_window_mode(existing.browser),
                        "background": True, "window_visible": existing.browser.window_visible,
                        "physical_input_used": False,
                        "running": True, "reused": True}
            browser = TemporaryWebSession(headless=window_mode == "hidden", guarded=True,
                                          persistent_profile=self._profile(kind), owner_task=task,
                                          brave_executable=self.ai_brave_executable,
                                          profile_kind=kind,
                                          **({'start_minimized':True} if window_mode=='minimized' else {}),
                                          owner_task_matches=lambda previous: self.store.same_chat_after_reboot(task, previous))
            adopted = False
            if isinstance(browser, TemporaryWebSession):
                browser.profile_path = browser.persistent_profile
                marker_path = browser.profile_path / "flower-session.json"
                if marker_path.exists():
                    marker = browser._read_marker(ignore_mode=True, allow_closed_browser_update=True)
                    if marker.get("state") == "running":
                        identity = f"{marker['browser_pid']}:{marker['browser_created']}"
                        if process_is_alive(identity):
                            if marker.get("owner_kind") != "user" or marker.get("owner_task") is not None:
                                raise ControlError(f"{kind}_profile_existing_task_instance_requires_recovery")
                            marker_mode='hidden' if marker['headless'] else 'minimized' if marker.get('start_minimized',False) else 'visible'
                            if window_mode is not None and marker_mode!=window_mode:
                                raise ControlError(f"{kind}_profile_window_mode_conflict")
                            self._require_lifecycle_write(task, kind)
                            await browser.borrow_shared()
                            adopted = True
                if not adopted:
                    from .web_user_profile import open_user_profile
                    # User ownership survives every borrower and its EOF. A
                    # concurrent opener may still be publishing the instance.
                    deadline = asyncio.get_running_loop().time() + 15
                    while True:
                        self._require_lifecycle_write(task, kind)
                        try:
                            opened = await open_user_profile(kind, data_root=self.store.directory.parent,
                                profile_path=self._profile(kind), window_mode=window_mode or "visible",
                                brave_executable=self.ai_brave_executable, auto_started=True)
                            if not opened.get("opened"):
                                raise ControlError(opened.get("state", "shared_browser_open_unavailable"))
                            break
                        except ControlError as error:
                            if error.code != "ai_profile_in_use" or asyncio.get_running_loop().time() >= deadline:
                                raise
                            await asyncio.sleep(.05)
                    await browser.borrow_shared()
                    adopted = True
            else:
                self._require_lifecycle_write(task, kind)
                await browser.start()
            registered = False
            try:
                control = ControlledWeb(self.store, task, browser,
                                        jev_client_factory=self.jev_client_factory)
                record = _Session(task, browser, control)
                self.sessions[browser.session_id] = record
                record.heartbeat = asyncio.create_task(self._heartbeat(record))
                if transition_from is not None:
                    self._mode_transitions[transition_from] = (browser.session_id, window_mode)
                registered = True
                result = {"session_id": browser.session_id, "profile": kind,
                        "window_mode": browser_window_mode(browser),
                        "background": True, "window_visible": browser.window_visible,
                        "physical_input_used": False,
                        "running": browser.running, "reused": False, "adopted_user_instance": adopted,
                        "shared_browser": bool(getattr(browser, "shared_browser", False)),
                        "browser_session_id": getattr(browser, "browser_session_id", None),
                        "page_scope": "own_tabs" if getattr(browser, "shared_browser", False) else "session"}
                if getattr(browser, "restored_shared_borrower", False):
                    result.update(reconnected=True, reconnection_scope="borrower_identity",
                                  prior_pages_restored="not_verified", new_observation_required=True)
                return self._mode_output(task, result)
            except BaseException:
                if not registered:
                    if adopted:
                        await browser.disconnect()
                    else:
                        await browser.close()
                raise

    async def reconnect_ai(self, task: str, session_id: str) -> dict:
        return await self._reconnect_profile(task, session_id, "ai")

    async def reconnect_luohua(self, task: str, session_id: str) -> dict:
        return await self._reconnect_profile(task, session_id, "luohua")

    async def _reconnect_profile(self, task: str, session_id: str,
                                 kind: str) -> dict:
        self._require_active_chat(task)
        if not isinstance(session_id, str) or len(session_id) != 32:
            raise ControlError("invalid_session_id")
        if kind == "luohua":
            self._require_private_grant(task)
        async with self._lock:
            self._require_lifecycle_write(task, kind)
            existing = self.sessions.get(session_id)
            if existing is not None:
                if (existing.task != task or existing.browser.persistent_profile is None
                        or getattr(existing.browser, "profile_kind", "ai") != kind):
                    raise ControlError("session_not_found_for_chat")
                if self._healthy(existing) and not existing.closing:
                    return {"session_id": session_id, "profile": kind, "running": True,
                            "window_mode": browser_window_mode(existing.browser),
                            "window_visible": existing.browser.window_visible,
                            "reconnected": False}
                if existing.active_actions or (existing.closing and not existing.closed and not existing.cleanup_error):
                    raise ControlError(f"{kind}_profile_recovery_required")
                if not existing.closed or existing.cleanup_error:
                    existing.closing = True
                    self.store.retire_owner(existing.control.owner)
                    if existing.heartbeat is not None:
                        existing.heartbeat.cancel()
                        await asyncio.gather(existing.heartbeat, return_exceptions=True)
                    await existing.browser.disconnect()
                    existing.closed = True
                    existing.cleanup_error = False
            browser = TemporaryWebSession(headless=False, guarded=True,
                                          persistent_profile=self._profile(kind), owner_task=task,
                                          brave_executable=self.ai_brave_executable,
                                          profile_kind=kind,
                                          owner_task_matches=lambda previous: self.store.same_chat_after_reboot(task, previous))
            self._require_lifecycle_write(task, kind)
            browser.profile_path = browser.persistent_profile
            marker = browser._read_marker(ignore_mode=True)
            if marker.get("owner_kind") == "user" and marker.get("owner_task") is None:
                await browser.borrow_shared(session_id)
            else:
                await browser.reconnect(session_id)
            registered = False
            try:
                self.store.reap_dead_owners()
                control = ControlledWeb(self.store, task, browser,
                                        jev_client_factory=self.jev_client_factory)
                record = _Session(task, browser, control)
                self.sessions[session_id] = record
                record.heartbeat = asyncio.create_task(self._heartbeat(record))
                registered = True
                recovery = {"recovered": False, "required": False}
                with self.store.read_transaction() as db:
                    quarantined = db.execute("SELECT quarantined FROM resources WHERE id=?", (control.resource,)).fetchone()
                if quarantined is not None and quarantined[0]:
                    try:
                        # A real read round trip on the replacement connection
                        # precedes any internal recovery. It cannot replay the
                        # lost write or close the user's tabs.
                        fresh_read = await control.execute("list_pages", {}, action_id="reconnect-read-" + uuid.uuid4().hex)
                        from .web_reconnect_recovery import recover_completed_calls, require_fresh_reconnect_read
                        require_fresh_reconnect_read(fresh_read)
                        recovery = recover_completed_calls(control, f"{browser.process_id}:{browser.process_created}",
                            browser._require_worker().worker_identity)
                    except (ControlError, RuntimeError, OSError, ValueError, sqlite3.Error) as error:
                        recovery = {"recovered": False, "required": True,
                            "reason": getattr(error, "code", "web_reconnect_recovery_unavailable"),
                            "unknown_receipts_preserved": True}
                return self._mode_output(task, {"session_id": session_id, "profile": kind, "running": True,
                        "window_mode": browser_window_mode(browser),
                        "window_visible": browser.window_visible,
                        "reconnected": True, "new_observation_required": True, "write_recovery": recovery})
            except BaseException:
                if not registered:
                    await browser.disconnect()
                raise

    def _record(self, task: str, session_id: str) -> _Session:
        if not isinstance(session_id, str) or not 1 <= len(session_id) <= 64:
            raise ControlError("invalid_session_id")
        record = self.sessions.get(session_id)
        if record is None or record.task != task:
            raise ControlError("session_not_found_for_chat")
        return record

    @staticmethod
    def _action_key(task: str, session_id: str, action_id: str) -> str:
        if not isinstance(session_id, str) or not 1 <= len(session_id) <= 64:
            raise ControlError("invalid_session_id")
        if not isinstance(action_id, str) or not 1 <= len(action_id) <= 128:
            raise ControlError("invalid_action_id")
        identity = json.dumps((task, session_id, action_id), ensure_ascii=False,
                              separators=(",", ":"))
        return "web:v1:" + hashlib.sha256(identity.encode("utf-8")).hexdigest()

    @staticmethod
    def _public_receipt(receipt: dict, private_id: str, action_id: str) -> dict:
        result = dict(receipt)
        identifier = result.get("id")
        if identifier == private_id:
            result["id"] = action_id
        elif identifier == private_id + ":targets":
            result["id"] = action_id
            result["phase"] = "candidate_observation"
            result["parent_pending"] = True
            if result.get("cancel_requested"):
                result["state"] = "cancelled"
            elif result.get("state") == "verified":
                result["state"] = "selecting_target"
        return result

    async def run(self, task: str, session_id: str, command: str,
                   arguments: dict, action_id: str) -> dict:
        health = None
        try:
            record = self._record(task, session_id)
            health = self._health(record)
            if record.closing or record.closed:
                raise ControlError("session_closing_or_closed")
            if record.browser.persistent_profile is not None and health.reason is not None:
                raise ControlError(f"{getattr(record.browser, 'profile_kind', 'ai')}_profile_recovery_required")
            if record.browser.persistent_profile is None and health.reason is not None:
                raise ControlError(health.reason)
            private_id = self._action_key(task, session_id, action_id)
            if not isinstance(arguments, dict):
                raise ControlError("invalid_web_arguments")
            if command == "recipe":
                from flower_control.control.recipes import build_web_recipe
                if set(arguments) != {"name", "parameters"}:
                    raise ControlError("invalid_recipe_parameters")
                built = build_web_recipe(arguments["name"], arguments["parameters"])
                command, arguments = built["command"], built["arguments"]
        except ControlError as error:
            # This block has not entered ControlledWeb or called its worker.
            error.web_dispatched = False
            error.web_stage = "runtime_preflight"
            if health is not None:
                error.web_runtime_health = health
                try:
                    self.store.record_event("web_runtime_preflight", task=task,
                        details={"session_id": session_id, "reason": error.code, "runtime_health": health.public()})
                except Exception:
                    pass  # A diagnostic write cannot alter refusal or dispatch facts.
            raise
        record.active_actions += 1
        try:
            from flower_control.permissions import revision, PermissionError
            try:
                policy_revision = revision()
                if command != "chooser_cancel":
                    self._require_browser_policy(record)
            except PermissionError as error:
                refusal = ControlError(error.code)
                refusal.web_dispatched = False
                refusal.web_stage = "runtime_policy_preflight"
                raise refusal from None
            except ControlError as error:
                error.web_dispatched = False
                error.web_stage = "runtime_policy_preflight"
                raise
            if command == "handoff_window":
                if getattr(record.browser, "shared_browser", False):
                    if set(arguments) != {"page_id"} or type(arguments["page_id"]) is not str:
                        raise ControlError("shared_browser_requires_exact_web_page")
                    checked = await record.control.execute("native_window", arguments, action_id=private_id)
                    from flower_control.drivers.computer_native import WindowIdentity
                    identity = WindowIdentity(**checked["result"])
                    token = self.store.create_window_handoff(task, checked["result"])
                    return browser_handoff_result([(token, identity)])
                if arguments:
                    raise ControlError("invalid_browser_handoff_arguments")
                from dataclasses import asdict
                identities, failures = browser_window_handoff_candidates(record)
                pairs = [(self.store.create_window_handoff(task, asdict(identity)), identity)
                         for identity in identities]
                return browser_handoff_result(pairs, failures)
            outcome = await record.control.execute(command, arguments, action_id=private_id)
            if command != "chooser_cancel":
                self.authorize_image_return(task, session_id, policy_revision=policy_revision)
            if command in {"batch", "flow"}:
                return self._public_flow_result(outcome, private_id, action_id)
            if isinstance(outcome.get("receipt"), dict):
                return {**outcome, "receipt": self._public_receipt(
                    outcome["receipt"], private_id, action_id)}
            return outcome
        finally:
            record.active_actions -= 1

    def _public_flow_result(self, value, private_id, action_id):
        if isinstance(value, list):
            return [self._public_flow_result(item, private_id, action_id) for item in value]
        if isinstance(value, dict):
            return {key: self._public_flow_result(item, private_id, action_id) for key, item in value.items()}
        if isinstance(value, str) and (value == private_id or value.startswith(private_id + ":")):
            return action_id + value[len(private_id):]
        return value

    def _flow_status(self, task, private_id, action_id, *, cancel=False):
        with self.store.transaction() as db:
            self.store._task(db, task)
            if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='web_batch_intents'").fetchone():
                return None
            row = db.execute("SELECT result,cancel_requested FROM web_batch_intents WHERE task=? AND action=?", (task, private_id)).fetchone()
            if row is None:
                return None
            if cancel:
                db.execute("UPDATE web_batch_intents SET cancel_requested=1 WHERE task=? AND action=?", (task, private_id))
            children = [child[0] for child in db.execute("SELECT id FROM actions WHERE task=? AND id LIKE ? ORDER BY created,id", (task, private_id + ":%"))]
        receipts = [self.store.diagnostic_action_for_task(task, child, cancel=cancel) for child in children]
        try:
            self._require_cached_policy(task, private_id)
            result = json.loads(row["result"]) if row["result"] else {"state": "running", "business_result_verified": False}
        except ControlError as error:
            result = {"state": "stale", "reason": error.code, "business_result_verified": False}
        if cancel:
            result = {**result, "state": "cancelled", "stop_received": True,
                "in_flight": any(receipt.get("in_flight") for receipt in receipts)}
        return self._public_flow_result({**result, "id": private_id, "children": receipts,
            "cancel_requested": bool(cancel or row["cancel_requested"])}, private_id, action_id)

    def _require_cached_policy(self, task, action):
        from flower_control.permissions import revision, PermissionError
        try:
            current = revision()
        except PermissionError as error:
            raise ControlError(error.code) from None
        with self.store.transaction() as db:
            exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='web_policy_intents'").fetchone()
            prior = db.execute("SELECT revision FROM web_policy_intents WHERE task=? AND action=?",
                               (task, action)).fetchone() if exists else None
        if (prior[0] if prior else "absent") != current:
            raise ControlError("user_policy_requires_new_observation")

    @staticmethod
    def _require_browser_policy(record):
        from flower_control.permissions import require_browser, active_policy, PermissionError
        browser = record.browser
        executable = getattr(browser, "brave_executable", None)
        if executable is not None:
            require_browser(browser.process_id, executable)
        else:
            value = active_policy.read()
            if value["DeniedApplications"] or not value["AdminWindows"] or value["AdminScope"] != "all" or any(r["Enabled"] for r in value["Masks"]):
                raise PermissionError("browser_policy_identity_unavailable")

    def authorize_image_return(self, task: str, session_id: str, *, policy_revision=None) -> None:
        """Recheck the exact owned session before captured pixels leave MCP."""
        record = self._record(task, session_id)
        from flower_control.permissions import revision, PermissionError
        try:
            self._require_browser_policy(record)
            if policy_revision is not None and revision() != policy_revision:
                raise ControlError("user_policy_requires_new_observation")
        except PermissionError as error:
            raise ControlError(error.code) from None
        if record.closing or record.closed or not self._healthy(record):
            raise ControlError("session_closing_or_closed")
        with self.store.transaction() as db:
            task_row = self.store._task(db, task)
            if task_row["paused"]:
                raise ControlError("task_paused")
            self.store._owner(db, record.control.owner)
            if getattr(record.browser, "profile_kind", "temporary") == "luohua":
                self.store._require_scope(db, task, record.control.scope)

    def action_status(self, task: str, session_id: str, action_id: str) -> dict:
        private_id = self._action_key(task, session_id, action_id)
        flow = self._flow_status(task, private_id, action_id)
        if flow is not None:
            return flow
        key = self._pending_action_key(task, private_id)
        record = self.sessions.get(session_id)
        receipt = self.store.diagnostic_action_for_task(task, key)
        if record is not None and record.task == task:
            with self.store.transaction() as db:
                owner = db.execute("SELECT owner FROM actions WHERE id=? AND task=?", (key, task)).fetchone()
            if owner and owner[0] == record.control.owner:
                receipt = self.store.queue_status(record.control.owner, key)
            else:
                receipt["connection"] = "receipt_only"
            receipt["session"] = self._session_diagnostics(record, session_id)
        else:
            receipt["connection"] = "receipt_only"
        business_status = getattr(record.control, "business_status", None) if record is not None and record.task == task else None
        if callable(business_status):
            business = business_status(key)
        else:
            # A restarted stdio has no live browser/control object. Use the
            # backend's identical task/action event contract, never infer an
            # independent business outcome from the execution receipt.
            with self.store.transaction() as db:
                event = db.execute("SELECT details FROM control_events WHERE task=? AND action=? "
                                   "AND event='business_result' ORDER BY seq DESC LIMIT 1", (task, key)).fetchone()
            business = json.loads(event[0]) if event else None
        try:
            self._require_cached_policy(task, private_id)
            receipt["business_result"] = business
        except ControlError as error:
            receipt["business_result"] = None
            receipt["content_reason"] = error.code
        return self._public_receipt(receipt, private_id, action_id)

    def _pending_action_key(self, task, private_id):
        try:
            self.store.diagnostic_action_for_task(task, private_id)
            return private_id
        except ControlError as error:
            if error.code != "action_not_found":
                raise
        self.store.diagnostic_action_for_task(task, private_id + ":targets")
        return private_id + ":targets"

    def cancel(self, task: str, session_id: str, action_id: str) -> dict:
        private_id = self._action_key(task, session_id, action_id)
        flow = self._flow_status(task, private_id, action_id, cancel=True)
        if flow is not None:
            return flow
        key = self._pending_action_key(task, private_id)
        return self._public_receipt(
            {**self.store.diagnostic_action_for_task(task, key, cancel=True), "id": key},
            private_id, action_id)

    async def close_temp(self, task: str, session_id: str) -> dict:
        record = self._record(task, session_id)
        self._lifecycle(record, "cleanup_requested", "public_close")
        if getattr(record.browser, "persistent_profile", None) is not None:
            raise ControlError("not_temporary_session")
        if not record.closed and not record.closing and not record.browser.running:
            await self._heartbeat_once(record)
        if record.closed:
            return {"session_id": session_id, "closed": True,
                    "profile_cleanup": record.browser.profile_cleanup,
                    "cleanup_error": record.cleanup_error or
                                     record.browser.profile_cleanup_error is not None,
                    "profile_cleanup_error": record.browser.profile_cleanup_error}
        if record.cleanup_error:
            return {"session_id": session_id, "closed": False,
                    "state": "outcome_uncertain", "reason": "owned_browser_cleanup_failed",
                    "session": self._session_diagnostics(record, session_id)}
        if record.closing:
            return {"session_id": session_id, "closed": False, "closing": True,
                    "state": "outcome_uncertain" if record.cleanup_error else "closing",
                     "reason": "owned_browser_cleanup_failed" if record.cleanup_error else None}
        if record.active_actions:
            raise ControlError("temporary_browser_action_in_flight")
        health = self._health(record)
        if self._worker_lost(record, health=health):
            session = self._session_diagnostics(record, session_id, health=health)
            handoff = self._normal_close_handoff(record, session_id, gui=session)
            return {"session_id": session_id, "closed": False, "state": "not_verified",
                    "reason": health.reason or "web_worker_unavailable", "dispatched": False,
                    "session": session,
                    "web_session_reconnect_available": False,
                    "next_action": "inspect_original_action_status_then_resolve_browser_without_replay",
                    "recovery": ("continue_same_chat_app_or_computer" if handoff["gui_close_available"] is True
                        else "gui_close_unavailable" if handoff["gui_close_available"] is False
                        else "observe_gui_availability"), "handoff": handoff}
        result = await self._close_live_record(record, f"web-session:{session_id}")
        if not result["closed"]:
            return {**result, "session_id": session_id}
        return {**result, "session_id": session_id,
                "profile_cleanup": record.browser.profile_cleanup,
                "cleanup_error": record.cleanup_error or
                                 record.browser.profile_cleanup_error is not None,
                "profile_cleanup_error": record.browser.profile_cleanup_error}

    async def close_ai(self, task: str, session_id: str) -> dict:
        return await self._close_profile(task, session_id, "ai")

    async def set_window_mode(self, task: str, session_id: str, window_mode: str) -> dict:
        window_mode = normalize_window_mode(window_mode, allow_none=False)
        async with self._mode_gate:
            prior = self._mode_transitions.get(session_id)
            if prior is not None:
                if prior[1] != window_mode:
                    raise ControlError("use_current_session_for_mode_change")
                current = self._record(task, prior[0])
                result = {"session_id": prior[0], "window_mode": window_mode,
                        "profile": current.browser.profile_kind,
                        "changed": True, "same_profile": True, "new_observation_required": True,
                        "running": current.browser.running, "replayed": False}
                return self._mode_output(task, result)
            return await self._set_window_mode(task, session_id, window_mode)

    def _mode_output(self, task: str, result: dict) -> dict:
        """Keep a started exact instance discoverable when authority changes late.

        This is lifecycle metadata only. It never resumes, observes, captures,
        grants or closes restored pages in response to a pause/Stop race.
        """
        try:
            self._require_active_chat(task)
            if self.store.write_stopped():
                raise ControlError("global_stop_active")
        except ControlError as error:
            if error.code not in {"task_paused", "global_stop_active"}:
                raise
            return {**result, "state": "mode_pending_resume", "reason": error.code,
                    "control_available": False, "automatically_resumed": False,
                    "recovery": "explicit_resume_then_observe_current_session"}
        if result.get("profile") == "luohua":
            self._require_private_grant(task)
        return result

    async def _set_window_mode(self, task: str, session_id: str, window_mode: str) -> dict:
        if type(window_mode) is not str or window_mode not in {"visible", "hidden",'minimized'}:
            raise ControlError("invalid_window_mode")
        record = self._record(task, session_id)
        self._require_active_chat(task)
        kind = record.browser.profile_kind
        if kind == "luohua":
            self._require_private_grant(task)
        if record.active_actions or record.closing:
            raise ControlError("web_action_in_flight")
        if not record.closed and browser_window_mode(record.browser)==window_mode:
            return {"session_id": session_id, "window_mode": window_mode, "changed": False,
                    "window_visible": record.browser.window_visible}
        if getattr(record.browser, "shared_browser", False):
            raise ControlError("shared_browser_window_mode_busy")
        record.browser.retain_profile_on_close = True
        try:
            closed = await (self.close_temp(task, session_id) if kind == "temporary"
                else self._close_profile(task, session_id, kind))
        finally:
            if record.browser.running:
                record.browser.retain_profile_on_close = False
        if not closed.get("closed") or closed.get("state") == "outcome_uncertain":
            return {**closed, "session_id": session_id, "changed": False,
                    "requested_window_mode": window_mode, "profile_data": "retained",
                    "recovery": "query_close_status", "new_instance_started": False}
        if kind != "temporary":
            opened = await self._open_profile(task, kind, window_mode=window_mode,
                                              transition_from=session_id)
        else:
            self._require_active_chat(task)
            if self.store.write_stopped():
                raise ControlError("global_stop_active")
            browser = TemporaryWebSession(headless=window_mode == "hidden", guarded=True,
                owner_task=task, diagnostic=self._diagnostic(task), brave_executable=self.ai_brave_executable,
                owned_temp_profile=record.browser.profile_path, previous_session_id=session_id,
                **({'start_minimized':True} if window_mode=='minimized' else {}))
            registered = False
            try:
                await browser.start()
                control = ControlledWeb(self.store, task, browser, jev_client_factory=self.jev_client_factory)
                current = _Session(task, browser, control)
                self.sessions[browser.session_id] = current
                current.heartbeat = asyncio.create_task(self._heartbeat(current))
                # start() has already replaced the profile marker with this
                # new identity. Save its alias before the final authority gate
                # so a late pause does not orphan login data or the live GUI.
                self._mode_transitions[session_id] = (browser.session_id, window_mode)
                registered = True
                opened = {"session_id": browser.session_id, "profile": kind,
                          "window_mode": window_mode, "window_visible": browser.window_visible,
                          "running": browser.running, "background": True}
            except BaseException:
                if not registered:
                    browser.retain_profile_on_close = True
                    await browser.close()
                raise
        self._mode_transitions[session_id] = (opened["session_id"], window_mode)
        return self._mode_output(task, {**opened, "changed": True, "previous_session_id": session_id,
                "same_profile": True, "new_observation_required": True, "old_references_invalid": True})

    async def close_status(self, task: str, session_id: str) -> dict:
        """Observe the original close, without issuing another lifecycle write."""
        record = self._record(task, session_id)
        health = self._health(record)
        if getattr(record.browser, "shared_browser", False) and record.closed:
            return {"session_id": session_id, "state": "control_released", "dispatched": False,
                    "browser_running": process_is_alive(f"{record.browser.process_id}:{record.browser.process_created}"),
                    "unknown_receipts_preserved": True}
        if record.closed or health.browser_running is False:
            return {"session_id": session_id, "state": "exited" if health.browser_running is False else "control_released",
                    "browser_running": health.browser_running, "dispatched": False,
                    "unknown_receipts_preserved": True}
        if health.reason is not None:
            return {"session_id": session_id, "state": "unavailable", "reason": health.reason,
                    "browser_running": health.browser_running, "dispatched": False}
        result = await record.control.execute("close_status", {},
            action_id=self._action_key(task, session_id, "close-status:" + uuid.uuid4().hex))
        return {"session_id": session_id, "browser_running": health.browser_running,
                "close_status": result.get("result"), "receipt": result.get("receipt"),
                "dispatched": False, "unknown_receipts_preserved": True}

    async def close_luohua(self, task: str, session_id: str) -> dict:
        return await self._close_profile(task, session_id, "luohua")

    async def _close_profile(self, task: str, session_id: str,
                             kind: str) -> dict:
        if not isinstance(session_id, str) or len(session_id) != 32:
            raise ControlError("invalid_session_id")
        record = self.sessions.get(session_id)
        if record is None:
            return await self._close_dead_profile(task, session_id, kind)
        record = self._record(task, session_id)
        if (record.browser.persistent_profile is None or
                getattr(record.browser, "profile_kind", "ai") != kind):
            raise ControlError(f"not_{kind}_session")
        if record.active_actions:
            raise ControlError(f"{kind}_action_in_flight")
        if record.closed:
            if record.normal_closed:
                return {"session_id": session_id, "closed": True, "profile_data": "retained",
                        **({"browser_closed": False, "state": "borrower_control_released"}
                           if getattr(record.browser, "shared_browser", False) else {})}
            return await self._close_dead_profile(task, session_id, kind)
        if record.cleanup_error:
            return {"session_id": session_id, "closed": False, "profile_data": "retained",
                    "state": "outcome_uncertain", "reason": f"{kind}_browser_close_uncertain"}
        if record.closing:
            raise ControlError(f"{kind}_close_in_progress")
        if getattr(record.browser, "shared_browser", False):
            self._require_lifecycle_write(task, kind)
            record.closing = True
            try:
                with self._close_resource(record, record.control.resource, kind=kind) as (action_id, callbacks):
                    try:
                        await self._finish_browser_close(record.browser, **callbacks,
                            on_cancel=lambda: self.store.cancel(record.control.owner, action_id))
                    except WebClosePending as error:
                        self.store.finish(record.control.owner, action_id, "not_verified", result_code="borrower_close_pending")
                        return {"session_id": session_id, "closed": False, "browser_closed": False,
                                "state": "close_pending", "details": error.result, "profile_data": "retained"}
                    self.store.finish(record.control.owner, action_id, "verified", result_code="borrower_control_released")
                # The exact close has released its dispatch lock and stopped
                # this borrower's worker. Recovery is independent of closure:
                # a refused or unprovable recovery must not replay the close.
                recovered = []
                try:
                    with self.store.read_transaction() as db:
                        candidates = [row[0] for row in db.execute(
                            "SELECT r.pending FROM web_target_close_receipts r "
                            "JOIN web_created_targets p ON p.id=r.pending JOIN actions a ON a.id=p.action "
                            "WHERE r.action=? AND a.state='outcome_uncertain' ORDER BY r.pending", (action_id,))]
                except (sqlite3.Error, ControlError):
                    candidates = []
                    recovered.append({"recovered": False, "reason": "web_recovery_evidence_unavailable"})
                for pending in candidates:
                    try:
                        self._require_lifecycle_write(task, kind)
                        outcome = self.store.recover_closed_web_creation(record.control.owner, pending)
                    except (ControlError, WriteGateError, sqlite3.Error, OSError, ValueError) as error:
                        outcome = {"recovered": False, "reason": error.code if isinstance(error, ControlError)
                                   else "web_recovery_evidence_unavailable"}
                    recovered.append({"pending_id": pending, **outcome})
                try:
                    with self.store.read_transaction() as db:
                        resource = db.execute("SELECT quarantined FROM resources WHERE id=?", (record.control.resource,)).fetchone()
                        recovery_required = bool(resource and resource[0] and not
                                                 self.store._quarantine_permit_active(db, record.control.resource))
                except (sqlite3.Error, ControlError):
                    recovery_required = True
                if record.heartbeat is not None:
                    record.heartbeat.cancel()
                    await asyncio.gather(record.heartbeat, return_exceptions=True)
                self.store.retire_owner(record.control.owner)
                record.closed = record.normal_closed = True
                return {"session_id": session_id, "closed": True, "browser_closed": False,
                        "state": "borrower_control_released", "page_scope": "own_tabs", "profile_data": "retained",
                        "recovery_required": recovery_required, "recovery": recovered,
                        "unknown_receipts_preserved": True}
            finally:
                if getattr(record.browser, "_closed", False) and not getattr(record.browser, "_started", True):
                    if record.heartbeat is not None:
                        record.heartbeat.cancel()
                        await asyncio.gather(record.heartbeat, return_exceptions=True)
                    self.store.retire_owner(record.control.owner)
                    record.closed = record.normal_closed = True
                record.closing = False
        result = await self._close_live_record(record, profile_resource_id(kind, self.ai_brave_executable), kind=kind)
        return {**result, "session_id": session_id, "profile_data": "retained"}

    async def _close_dead_ai(self, task: str, session_id: str) -> dict:
        return await self._close_dead_profile(task, session_id, "ai")

    def _close_dead_borrower(self, task, session_id, kind, profile, records, original):
        from .web_shared_profile import (borrower_resource, shared_borrowers,
            exact_process_identity, require_profile_gate, write_borrower)
        path, row = original
        identities = (row["browser_process"], row.get("owner_process") or row.get("last_owner_process"),
                      row.get("worker_process") or row.get("last_worker_process"))
        if not all(exact_process_identity(value) for value in identities):
            raise ControlError("shared_browser_recovery_identity_unverified")
        resource = borrower_resource(profile, task)
        self.store.reap_dead_owners()
        with self.store.transaction() as db:
            owned = db.execute("SELECT task FROM owned_resources WHERE resource=?", (resource,)).fetchone()
            target = db.execute("SELECT paused,quarantined FROM resources WHERE id=?", (resource,)).fetchone()
            if owned is None or owned[0] != task or target is None:
                raise ControlError("session_not_found_for_chat")
            if target["paused"]:
                raise ControlError("shared_browser_resource_paused")
            recovering = bool(target["quarantined"])
        def probe():
            self._require_lifecycle_write(task, kind)
            require_profile_gate(self.store, profile_resource_id(kind, self.ai_brave_executable))
            if shared_borrowers(profile, task) != records:
                raise ControlError("shared_browser_recovery_state_changed")
            if process_is_alive(identities[0]):
                raise ControlError(f"{kind}_borrower_browser_still_running")
            if any(process_is_alive(value) for value in identities[1:]):
                raise ControlError("shared_browser_previous_executor_still_running")
            for other_path, other in records:
                if other_path != path and any(value and process_is_alive(value) for value in
                        (other.get("owner_process"), other.get("worker_process"))):
                    raise ControlError("shared_browser_current_executor_still_running")
            with self.store.read_transaction() as db:
                if db.execute("SELECT 1 FROM actions a,json_each(a.resources) r "
                        "WHERE a.state IN ('queued','running') AND r.value=? LIMIT 1", (resource,)).fetchone():
                    raise ControlError("shared_browser_action_in_flight")
            return {resource: "dead-borrower:" + session_id + ":" + identities[0]}
        probe()
        recovery = self.store.recover_resources((resource,), probe) if recovering else None
        # Only this original borrower's metadata is sealed; the current user
        # marker may describe another live browser and is never rewritten.
        write_borrower(path, {**row, "owner_process": None, "worker_process": None,
                             "last_owner_process": identities[1], "last_worker_process": identities[2],
                             "pages": {}, "browser_exit_verified": True})
        return {"session_id": session_id, "closed": True, "browser_closed_by_call": False,
                "verified_dead_instance": True, "state": "dead_borrower_control_released",
                "profile_data": "retained", "unknown_receipts_preserved": True,
                **({"recovery": recovery} if recovery else {})}

    async def _close_dead_profile(self, task: str, session_id: str,
                                  kind: str) -> dict:
        """Seal an exited exact instance only after the ledger is quiet."""
        self._require_active_chat(task)
        if kind == "luohua":
            self._require_private_grant(task)
        async with self._lock:
            browser = TemporaryWebSession(headless=False, guarded=True,
                                          persistent_profile=self._profile(kind), owner_task=task,
                                          brave_executable=self.ai_brave_executable,
                                          profile_kind=kind)
            browser.profile_path = browser.persistent_profile
            browser._acquire_profile_lock()
            try:
                from .web_shared_profile import shared_borrowers
                records = shared_borrowers(browser.profile_path, task)
                matches = [entry for entry in records if entry[1]["session_id"] == session_id]
                if len(matches) > 1:
                    raise ControlError("shared_browser_borrower_recovery_required")
                if matches:
                    return self._close_dead_borrower(task, session_id, kind, browser.profile_path, records, matches[0])
                marker = browser._read_marker(ignore_mode=True)
                if type(marker.get("headless")) is not bool or marker.get("login_only", False):
                    raise ControlError(f"{kind}_browser_identity_unverified")
                if marker.get("session_id") != session_id or not self._marker_belongs_to_task(task, marker):
                    raise ControlError("session_not_found_for_chat")
                if marker.get("state") != "running":
                    raise ControlError(f"{kind}_session_not_running")
                pid, created = marker.get("browser_pid"), marker.get("browser_created")
                if type(pid) is not int or not isinstance(created, str):
                    raise ControlError(f"{kind}_browser_identity_unverified")
                if process_is_alive(f"{pid}:{created}"):
                    raise ControlError(f"{kind}_browser_still_running_reconnect_required")
                for identity in (marker.get("owner_process"), marker.get("worker_process")):
                    if identity is not None and process_is_alive(identity):
                        raise ControlError(f"{kind}_previous_executor_still_running")
                if marker.get("owner_process") is not None and marker.get("worker_process") is None:
                    raise ControlError(f"{kind}_previous_worker_unverified")
                self.store.reap_dead_owners()
                with self.store.transaction() as db:
                    resource = db.execute("SELECT paused,quarantined FROM resources WHERE id=?",
                                          (profile_resource_id(kind, self.ai_brave_executable),)).fetchone()
                    unresolved = db.execute(
                        "SELECT 1 FROM actions WHERE resources LIKE ? AND state IN ('queued','running') LIMIT 1",
                        (f"%{profile_resource_id(kind, self.ai_brave_executable)}%",)).fetchone()
                    if unresolved or (resource and resource["paused"]):
                        raise ControlError(f"{kind}_profile_action_recovery_required")
                    recovering = bool(resource and resource["quarantined"])
                recovery = None
                if recovering:
                    resource_id = profile_resource_id(kind, self.ai_brave_executable)
                    identities = (f"{pid}:{created}", marker.get("owner_process"),
                                  marker.get("worker_process"))
                    if any(not isinstance(identity, str) or not identity for identity in identities):
                        raise ControlError(f"{kind}_profile_action_recovery_required")
                    for identity in identities:
                        identity_pid, _, identity_created = identity.partition(":")
                        try:
                            if (not identity_pid.isdecimal() or int(identity_pid) <= 0
                                    or datetime.fromisoformat(identity_created).tzinfo is None):
                                raise ValueError("incomplete exact process identity")
                        except ValueError:
                            raise ControlError(f"{kind}_profile_action_recovery_required") from None

                    def probe():
                        self._require_active_chat(task)
                        if kind == "luohua":
                            self._require_private_grant(task)
                        if self.store.write_stopped():
                            raise ControlError("global_stop_active")
                        if (browser._read_marker(ignore_mode=True) != marker
                                or any(process_is_alive(identity) for identity in identities)):
                            raise ControlError("web_recovery_exit_unverified")
                        # Independent proof includes the exact browser itself
                        # and both old executors, not just worker death. The
                        # profile's exclusive OS lock is held through sealing.
                        # No claim about the old business effect or exit code.
                        return {resource_id: "dead:" + session_id + ":" + identities[0]}

                    recovery = self.store.recover_resources((resource_id,), probe)
                marker["state"] = "closed"
                marker.pop("owner_task", None)
                marker["owner_process"] = None
                marker["worker_process"] = None
                browser._write_marker(marker)
                return {"session_id": session_id, "closed": True,
                        "profile_data": "retained", "verified_dead_instance": True,
                        **({"recovery": recovery, "unknown_receipts_preserved": True,
                            "exit_proof": "exact_dead_browser_and_previous_executors"} if recovering else {})}
            finally:
                await browser._release_profile_lock()
