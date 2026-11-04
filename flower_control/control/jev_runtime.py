"""Local decision-provider preferences and reused HTTP clients per MCP process."""
from __future__ import annotations

import asyncio
from dataclasses import replace
import atexit
from functools import lru_cache
import json
import os
from pathlib import Path
import threading
import time
import uuid
from typing import Awaitable, Callable

import win32cred
import pywintypes

from .jev import JevClient, JevSelection, JevBatchResult
from .scheduling import JevRequest
from .targets import JevTargetSelection, TargetRequest, local_target_selection
from .jev_diagnostics import ledger_sink
from .decision_client import DecisionClient
from .decision_settings import (load_settings, settings_stamp, settings_revision, save_settings,
                                credentials_ready, DEFAULT_MODELS,
                                SETTINGS_FILE as PROVIDER_SETTINGS_FILE)
from .decision_router import DecisionRouter
from .perplexity import PerplexityDecisionClient


CREDENTIAL_TARGET = "FlowerControl/JevApiKey/v1"
MODEL = DEFAULT_MODELS["jev"]
SETTINGS_FILE = "jev.json"


def enabled(directory: Path) -> bool:
    try:
        return credentials_ready(directory) and bool(load_settings(directory).active_order())
    except (OSError, ValueError, TypeError):
        return False


def set_enabled(directory: Path, value: bool) -> None:
    if type(value) is not bool:
        raise ValueError("invalid_jev_enabled_value")
    directory = Path(directory)
    if (directory / PROVIDER_SETTINGS_FILE).exists():
        revision = settings_revision(directory)
        current = load_settings(directory)
        providers = tuple(p for p in current.enabled if p != "jev") + (("jev",) if value else ())
        save_settings(directory, replace(current, enabled=providers), expected_revision=revision)
        return
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / SETTINGS_FILE
    temporary = directory / (SETTINGS_FILE + "." + uuid.uuid4().hex + ".tmp")
    payload = json.dumps({"schema": 1, "enabled": value})
    try:
        temporary.write_text(payload, encoding="ascii")
        try:
            os.replace(temporary, target)
        except OSError as error:
            if getattr(error, "winerror", None) != 17:
                raise
            # An encrypted Windows data directory can reject same-directory
            # replacement with ERROR_NOT_SAME_DEVICE. A partial tiny setting
            # fails closed in enabled(), so finish with one flushed write.
            with target.open("w", encoding="ascii") as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
    finally:
        if temporary.exists():
            temporary.unlink()


def _credential_client(provider="jev", model=None, settings=None) -> DecisionClient:
    from .decision_settings import credential_target, PROVIDERS
    if provider not in PROVIDERS:
        from .custom_decision import CustomDecisionClient
        definition = next(p for p in settings.custom if p.id == provider)
        target, client_type, default_model = credential_target(provider, settings), CustomDecisionClient, definition
    else:
        target, client_type, default_model = {
        "jev": (CREDENTIAL_TARGET, JevClient, MODEL),
        "perplexity": ("FlowerControl/PerplexityApiKey/v1", PerplexityDecisionClient, "pplx-decider-v1.2"),
        }[provider]
    try:
        credential = win32cred.CredRead(target, win32cred.CRED_TYPE_GENERIC, 0)
    except pywintypes.error:
        raise ValueError("decision_credential_unavailable") from None
    blob = credential["CredentialBlob"]
    # pywin32 returns the Unicode CredentialBlob as UTF-16LE bytes.
    key = blob.decode("utf-16-le") if isinstance(blob, bytes) else blob
    if type(key) is not str or not key or "\x00" in key:
        raise ValueError("invalid_jev_credential")
    return client_type(key, default_model if provider not in PROVIDERS else model or default_model)


class JevConnection:
    """Keep httpx.AsyncClient on one event loop, including sync desktop calls."""

    input_capabilities = JevClient.input_capabilities

    def __init__(self, directory: Path, *,
                 client_builder: Callable[[], DecisionClient] | None = None,
                 enabled_check: Callable[[], bool] | None = None,
                 event_sink=None):
        self.directory = Path(directory)
        def configured_router():
            settings = load_settings(self.directory)
            return DecisionRouter(settings, lambda provider, model: _credential_client(provider, model, settings))
        self.client_builder = client_builder or configured_router
        self.enabled_check = enabled_check or (lambda: enabled(self.directory))
        self.event_sink = event_sink
        self._gate = threading.Lock()
        self._closed = False
        self._shutdown_task: asyncio.Task | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._client: DecisionClient | None = None
        self._stamp: tuple | None = None
        self._client_gate: asyncio.Lock | None = None
        self._target_inflight: dict[tuple, asyncio.Task] = {}
        self._target_waiters: dict[tuple, int] = {}
        self._operations: set[asyncio.Task] = set()

    def _settings_stamp(self):
        return settings_stamp(self.directory)

    def _configuration_current(self, stamp):
        return not self._closed and self.enabled_check() and self._settings_stamp() == stamp

    def _submit(self, operation):
        # Serialize admission with shutdown; never construct a coroutine after
        # the connection has retired, or revive its old proxy on a new loop.
        with self._gate:
            if self._closed:
                return None
            if self._loop is None:
                loop = asyncio.new_event_loop()
                thread = threading.Thread(target=self._run, args=(loop,),
                                          name="Flower-Jev-HTTP", daemon=True)
                self._loop = loop
                self._thread = thread
                thread.start()
            return asyncio.run_coroutine_threadsafe(self._tracked(operation()), self._loop)

    @staticmethod
    def _run(loop: asyncio.AbstractEventLoop) -> None:
        asyncio.set_event_loop(loop)
        loop.run_forever()
        loop.close()

    async def _choose(self, request: JevRequest, deadline: float,
                      permitted: Callable[[], Awaitable[bool]]) -> JevSelection:
        if self._closed:
            return JevSelection(None, "closed", 0)
        if not self.enabled_check():
            return JevSelection(None, "disabled", 0)
        client = await self._current_client()
        if client is None:
            return JevSelection(None, "client_unavailable", 0)
        stamp = self._stamp
        async def permission():
            if not self._configuration_current(stamp):
                return False
            allowed = await permitted()
            return allowed is True and self._configuration_current(stamp)
        return await client.choose_scheduling(request, deadline=deadline,
                                              permitted=permission)

    async def _ask_batch(self, state, questions, deadline, permitted, fresh,
                         max_attempts, total_budget):
        if self._closed:
            return JevBatchResult(None, "closed", 0)
        if not self.enabled_check():
            return JevBatchResult(None, "disabled", 0)
        client = await self._current_client()
        if client is None:
            return JevBatchResult(None, "client_unavailable", 0)
        stamp = self._stamp
        async def permission():
            if not self._configuration_current(stamp):
                return False
            allowed = await permitted()
            return allowed is True and self._configuration_current(stamp)
        async def observation_current():
            if not self._configuration_current(stamp):
                return False
            current = await fresh()
            return current is True and self._configuration_current(stamp)
        result = await client.ask_batch(state, questions, deadline=deadline,
            permitted=permission, fresh=observation_current, max_attempts=max_attempts,
            total_budget=total_budget)
        return result if self._configuration_current(stamp) else JevBatchResult(None, "permission_changed", result.elapsed_ms)

    async def _current_client(self) -> DecisionClient | None:
        if self._client_gate is None:
            self._client_gate = asyncio.Lock()
        async with self._client_gate:
            if self._closed:
                return None
            stamp = self._settings_stamp()
            # Do not close pooled sockets underneath another in-flight caller.
            if self._client is not None and stamp != self._stamp:
                if len(self._operations) > 1 or self._target_inflight:
                    # Never send a new call to an old provider while old work
                    # drains. Its in-flight callbacks discard the late answer.
                    return None
                await self._client.close()
                self._client = None
            if self._client is None:
                try:
                    self._client = self.client_builder()
                    if self.event_sink is not None:
                        self._client.event_sink = self.event_sink
                    self._stamp = stamp
                except (OSError, ValueError, TypeError, KeyError):
                    return None
            return self._client

    async def _choose_target(self, request: TargetRequest, deadline: float,
                             permitted: Callable[[], Awaitable[bool]],
                             fresh: Callable[[], Awaitable[bool]]) -> JevTargetSelection:
        started = time.monotonic()
        if self._closed:
            return JevTargetSelection(None, "closed", 0)
        # A deterministic candidate needs neither enabled Jev nor credentials.
        local = await local_target_selection(request, deadline=deadline,
                                              permitted=permitted, fresh=fresh)
        if local is not None:
            if local.reason == "expired" and time.monotonic() >= deadline and deadline < request.expires_at:
                return JevTargetSelection(None, "timeout", local.elapsed_ms)
            return local
        if not self.enabled_check():
            return JevTargetSelection(request.fallback(),
                                      "local_fallback:disabled" if request.fallback() else "disabled", 0)
        client = await self._current_client()
        if client is None:
            checked = await local_target_selection(request, deadline=deadline,
                                                    permitted=permitted, fresh=fresh)
            if checked is not None:
                return checked
            return JevTargetSelection(request.fallback(),
                                      "local_fallback:client_unavailable" if request.fallback() else "client_unavailable", 0)
        # Merge calls only for the same immutable request object. Independent
        # observations/permissions must never share a semantic decision.
        # Different permission/version callbacks cannot share work. Each waiter
        # keeps its own deadline; the first bounded request is never extended.
        stamp = self._stamp
        key = (id(request), id(permitted), id(fresh), stamp)
        pending = self._target_inflight.get(key)
        if pending is None:
            async def permission():
                if not self._configuration_current(stamp):
                    return False
                allowed = await permitted()
                return allowed is True and self._configuration_current(stamp)
            async def observation_current():
                if not self._configuration_current(stamp):
                    return False
                current = await fresh()
                return current is True and self._configuration_current(stamp)
            pending = asyncio.create_task(client.choose_target(
                request, deadline=deadline, permitted=permission, fresh=observation_current))
            self._target_inflight[key] = pending
            def finished(task):
                if self._target_inflight.get(key) is task:
                    self._target_inflight.pop(key, None)
                if not task.cancelled():
                    task.exception()
            pending.add_done_callback(finished)
        self._target_waiters[key] = self._target_waiters.get(key, 0) + 1
        try:
            async with asyncio.timeout(min(deadline, request.expires_at) - time.monotonic()):
                result = await asyncio.shield(pending)
        except TimeoutError:
            return JevTargetSelection(None, "timeout",
                                      max(0, round((time.monotonic() - started) * 1000)))
        finally:
            remaining = self._target_waiters[key] - 1
            if remaining:
                self._target_waiters[key] = remaining
            else:
                self._target_waiters.pop(key, None)
                if not pending.done():
                    pending.cancel()
        # Each waiter must check its own permission and version after reuse.
        checked = await local_target_selection(request, deadline=deadline,
                                                permitted=permitted, fresh=fresh)
        # Adoption belongs to this waiter's original provider generation. The
        # independent fresh callback above can itself await a settings change.
        if self._closed:
            return JevTargetSelection(None, "closed", result.elapsed_ms)
        if not self.enabled_check():
            return JevTargetSelection(None, "disabled", result.elapsed_ms)
        if self._settings_stamp() != stamp:
            return JevTargetSelection(None, "permission_changed", result.elapsed_ms)
        if checked is not None:
            reason = ("timeout" if checked.reason == "expired" and time.monotonic() >= deadline
                      and deadline < request.expires_at else checked.reason)
            return JevTargetSelection(checked.candidate, reason,
                                      max(0, round((time.monotonic() - started) * 1000)))
        if self._closed:
            return JevTargetSelection(None, "closed", result.elapsed_ms)
        if not self.enabled_check():
            return JevTargetSelection(None, "disabled", result.elapsed_ms)
        return result

    async def choose_scheduling(self, request: JevRequest, *, deadline: float,
                                permitted: Callable[[], Awaitable[bool]]) -> JevSelection:
        if not self.enabled_check():
            return JevSelection(None, "disabled", 0)
        stamp = self._settings_stamp()
        future = self._submit(lambda: self._choose(request, deadline, permitted))
        if future is None:
            return JevSelection(None, "closed", 0)
        try:
            result = await asyncio.wrap_future(future)
            if result.action_id is not None and not self._closed and not self._configuration_current(stamp):
                return JevSelection(None, "permission_changed", result.elapsed_ms)
            return JevSelection(None, "closed", result.elapsed_ms) if self._closed else result
        except asyncio.CancelledError:
            future.cancel()
            raise

    async def choose_target(self, request: TargetRequest, *, deadline: float,
                            permitted: Callable[[], Awaitable[bool]],
                            fresh: Callable[[], Awaitable[bool]]) -> JevTargetSelection:
        stamp = self._settings_stamp()
        future = self._submit(lambda: self._choose_target(request, deadline, permitted, fresh))
        if future is None:
            return JevTargetSelection(None, "closed", 0)
        try:
            result = await asyncio.wrap_future(future)
            if (result.candidate is not None and result.reason == "selected"
                    and not self._closed and not self._configuration_current(stamp)):
                return JevTargetSelection(None, "permission_changed", result.elapsed_ms)
            return JevTargetSelection(None, "closed", result.elapsed_ms) if self._closed else result
        except asyncio.CancelledError:
            future.cancel()
            raise

    async def _tracked(self, operation):
        task = asyncio.current_task()
        self._operations.add(task)
        try:
            return await operation
        finally:
            self._operations.discard(task)

    async def ask_batch(self, state, questions, *, deadline, permitted, fresh,
                        max_attempts=2, total_budget=5.0):
        # Snapshot on the producer loop before crossing the shared-loop boundary.
        from .jev import _batch_payload, _validate_budget
        if not callable(permitted) or not callable(fresh):
            raise ValueError("jev_observation_checks_required")
        _validate_budget(max_attempts, total_budget)
        deadline = min(deadline, time.monotonic() + total_budget)
        state, questions = _batch_payload(state, questions)
        # Preserve the saved-switch diagnostic even for a retired proxy. Both
        # disabled and retired paths perform zero client construction or HTTP.
        if not self.enabled_check():
            return JevBatchResult(None, "disabled", 0)
        stamp = self._settings_stamp()
        future = self._submit(lambda: self._ask_batch(
            state, questions, deadline, permitted, fresh, max_attempts, total_budget))
        if future is None:
            return JevBatchResult(None, "closed", 0)
        try:
            result = await asyncio.wrap_future(future)
            if result.answers is not None and not self._closed and not self._configuration_current(stamp):
                return JevBatchResult(None, "permission_changed", result.elapsed_ms)
            return JevBatchResult(None, "closed", result.elapsed_ms) if self._closed else result
        except asyncio.CancelledError:
            future.cancel()
            raise

    async def close(self) -> None:
        # Arbitration closes its short-lived proxy; this connection stays warm.
        pass

    def shutdown(self) -> None:
        with self._gate:
            if self._closed:
                return
            self._closed = True
            loop, thread = self._loop, self._thread
            self._loop = None
            self._thread = None
        if loop is None or thread is None or not thread.is_alive():
            return
        async def finish():
            pending = tuple(set(self._target_inflight.values()) | self._operations)
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            self._target_inflight.clear()
            self._target_waiters.clear()
            if self._client is not None:
                await self._client.close()
                self._client = None
            self._client_gate = None
        if thread is threading.current_thread():
            # A permission/cancellation callback can retire its own shared
            # connection. Let that loop drain and close before stopping it;
            # waiting on its future or joining this thread would deadlock.
            async def finish_on_loop():
                try:
                    await finish()
                finally:
                    loop.stop()
            self._shutdown_task = loop.create_task(finish_on_loop())
            return
        try:
            asyncio.run_coroutine_threadsafe(finish(), loop).result(timeout=1)
        except (OSError, TimeoutError, RuntimeError):
            pass
        loop.call_soon_threadsafe(loop.stop)
        thread.join(timeout=1)


@lru_cache(maxsize=8)
def _shared(directory: Path) -> JevConnection:
    connection = JevConnection(directory, event_sink=ledger_sink(directory))
    atexit.register(connection.shutdown)
    return connection


def client_factory(directory: Path):
    """A lazy proxy factory for the three channel schedulers."""
    from flower_control.data_paths import physical_path
    directory = physical_path(Path(directory) / SETTINGS_FILE).parent
    connection = _shared(directory)

    def make_client() -> JevConnection:
        if not enabled(directory):
            raise ValueError("jev_disabled")
        return connection

    return make_client
