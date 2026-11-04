"""Tie cancellable MCP awaits to exact synchronous App executions."""
from __future__ import annotations

import asyncio
import inspect
import threading
from contextlib import nullcontext, asynccontextmanager
from contextvars import ContextVar
from .host_cleanup import CleanupAttempts, cleanup_event


class AppLaunchCall:
    """Use existing exact-key Stop bookkeeping without a window resolver."""

    def __init__(self, store, task, owner, operation):
        from .app_control import AppRuntime
        self.task, self.owner, self.operation = task, owner, operation
        self.control = AppRuntime(store, lambda *_: None)

    def begin_host_call(self, task, action_id):
        if task != self.task:
            from .app_control import AppBoundaryError
            raise AppBoundaryError("ticket_task_mismatch")
        return self.control.begin_host_call(task, action_id)

    def end_host_call(self, key, *, on_pending_cleanup=None):
        return self.control.end_host_call(key, on_pending_cleanup=on_pending_cleanup)

    def request_host_stop(self, key):
        self.control.request_host_stop(key)

    def signal_host_stop(self, key):
        return self.control.signal_host_stop(key)

    def run(self, action_id, *, trusted_task):
        if trusted_task != self.task:
            from .app_control import AppBoundaryError
            raise AppBoundaryError("ticket_task_mismatch")
        key = self.control._action_key(trusted_task, action_id)
        return self.operation(lambda: self.control._check_host_stop(self.owner, key),
                              lambda: self.control._host_stopped(key))


class AppHostLifetime:
    CLEANUP_WAIT_SECONDS = 2.0

    def __init__(self):
        self.executions: dict[asyncio.Task, tuple[object, str | None]] = {}
        self.stop_callbacks = {}
        self.business_stops = {}
        self.closing = False
        self.execution_tasks = {}
        self.task_calls = {}
        self.finishing_tasks = set()
        self.deferred_finishes = set()
        self.task_context = ContextVar("flower_app_public_task", default=None)
        self.cleanup_context = ContextVar("flower_app_finish_call", default=False)
        self.cleanup = CleanupAttempts("app")

    @asynccontextmanager
    async def task_call(self, task, *, finish=False, diagnostic=False, priority=False):
        """Cover the whole public call, including gaps between native workers."""
        from flower_control.control.state import ControlError
        if finish:
            self.cleanup.retry(task)
            self._release_finish_guard(task)
        if task in self.finishing_tasks and not diagnostic:
            raise ControlError("task_finish_in_progress")
        if finish:
            self.finishing_tasks.add(task)
        elif not diagnostic:
            self.task_calls[task] = self.task_calls.get(task, 0) + 1
        token = self.task_context.set(task)
        cleanup_token = self.cleanup_context.set(finish or diagnostic or priority)
        try:
            yield
        finally:
            self.task_context.reset(token)
            self.cleanup_context.reset(cleanup_token)
            if finish:
                # Cancellation of the MCP await does not cancel its native
                # cleanup worker. Keep admission closed until that worker
                # actually acknowledges completion.
                self.deferred_finishes.add(task)
                self._release_finish_guard(task)
            elif not diagnostic:
                count = self.task_calls.get(task, 1) - 1
                if count:
                    self.task_calls[task] = count
                else:
                    self.task_calls.pop(task, None)
                self._release_finish_guard(task)

    def busy(self, task):
        return bool(self.task_calls.get(task)) or any(current == task and not worker.done()
            for worker, current in tuple(self.execution_tasks.items()))

    def _release_finish_guard(self, task):
        if (task in self.deferred_finishes and not self.task_calls.get(task) and
                not self.cleanup.has_pending(task) and
                not any(current == task and not worker.done()
                        for worker, current in self.execution_tasks.items())):
            self.deferred_finishes.discard(task)
            self.finishing_tasks.discard(task)

    async def drain_task(self, task, timeout=2):
        """Stop exact local workers and wait; never ends a peer connection."""
        deadline = asyncio.get_running_loop().time() + timeout
        signalled = set()
        self.cleanup.retry(task)
        while True:
            workers = [worker for worker, current in tuple(self.execution_tasks.items())
                       if current == task and not worker.done()]
            for worker in workers:
                if worker in signalled:
                    continue
                signalled.add(worker)
                self._stop_worker(worker)
            if not workers and not self.task_calls.get(task):
                self.cleanup.retry(task)
                await self.cleanup.retry_threaded(task, timeout=max(0, deadline-asyncio.get_running_loop().time()))
                return not self.cleanup.has_pending(task)
            if asyncio.get_running_loop().time() >= deadline:
                return False
            await asyncio.sleep(.02)

    def _request_host_stop(self, runtime, key, *, owner_task=None):
        signal = getattr(runtime, "signal_host_stop", runtime.request_host_stop)
        cleanup = signal(key)
        if not callable(cleanup):
            return
        worker = asyncio.create_task(asyncio.to_thread(cleanup))
        self.executions[worker] = (None, None)
        self.execution_tasks[worker] = owner_task
        def completed(task):
            self.executions.pop(task, None)
            current = self.execution_tasks.pop(task, None)
            if not task.cancelled() and task.exception() is not None:
                self.cleanup.remember((task, "deferred_stop"), current, "deferred_stop",
                                      cleanup, task.exception())
            self._release_finish_guard(current)
        worker.add_done_callback(completed)

    def _stop_worker(self, worker):
        current = self.execution_tasks.get(worker)
        callback = self.stop_callbacks.get(worker)
        if callback is not None:
            self.cleanup.run((worker, "callback"), current, "stop_callback", callback)
        runtime, key = self.executions.get(worker, (None, None))
        if key is not None:
            self.cleanup.run((worker, "runtime"), current, "runtime_stop",
                             lambda: self._request_host_stop(runtime, key, owner_task=current))
        stop_queued = self.business_stops.get(worker)
        if stop_queued is not None:
            self.cleanup.run((worker, "business_queue"), current, "business_queue", stop_queued)

    async def call(self, method, *args, _on_host_stop=None, **kwargs):
        if self.closing:
            from .app_control import AppBoundaryError
            raise AppBoundaryError("app_host_stopping")
        runtime = getattr(method, "__self__", None)
        bound = inspect.signature(method).bind_partial(*args, **kwargs).arguments
        ordinary = (type(bound.get("action_id")) is str and kwargs.get("trusted_task") is not None
            and getattr(method, "__name__", "") not in {"action_status", "cancel", "pause", "finish", "release_phase"})
        cleanup_task = kwargs.get("trusted_task", self.task_context.get())
        if ordinary and type(cleanup_task) is str and not self.cleanup_context.get():
            await self.cleanup.retry_threaded(cleanup_task, timeout=self.CLEANUP_WAIT_SECONDS)
        if self.closing:
            from .app_control import AppBoundaryError
            raise AppBoundaryError("app_host_stopping")
        if self.task_context.get() in self.finishing_tasks and not self.cleanup_context.get():
            from .app_control import AppBoundaryError
            raise AppBoundaryError("task_finish_in_progress")
        if self.cleanup.has_pending(self.task_context.get()) and not self.cleanup_context.get():
            from .app_control import AppBoundaryError
            raise AppBoundaryError("app_host_cleanup_pending")
        if runtime is None and getattr(method, "__name__", "") in {
                "capture_app_screenshot", "authorize_app_screenshot_return"}:
            runtime = args[0]
        key = None
        from flower_control.control.business_calls import public_worker
        lease = public_worker()
        try:
            if (type(bound.get("action_id")) is str and kwargs.get("trusted_task") is not None
                    and getattr(method, "__name__", "") not in {"action_status", "cancel"}
                    and hasattr(runtime, "begin_host_call")):
                key = runtime.begin_host_call(kwargs["trusted_task"], bound["action_id"])
        except BaseException:
            if lease is not None:
                lease.abort()
            raise
        end_lock, end_token = threading.Lock(), object()
        ended = False
        def end_once():
            nonlocal ended
            with end_lock:
                if ended or key is None:
                    return None
                supports = "on_pending_cleanup" in inspect.signature(type(runtime).end_host_call).parameters
                def pending(retry):
                    from .idle_phase_cleanup import remember_idle_release
                    remember_idle_release(self.cleanup, kwargs["trusted_task"], end_token, retry)
                result = runtime.end_host_call(key, **({"on_pending_cleanup": pending} if supports else {}))
                ended = True
                return result
        def cancel_queued():
            if lease is not None:
                lease.abort()
        def finish_unstarted():
            cancel_queued()
            if lease is not None and lease.aborted():
                end_once()
        def execute():
            outcome = None
            try:
                if lease is not None and not lease.start():
                    from flower_control.control.state import ControlError
                    raise ControlError('business_call_closed')
                context = (runtime._host_call_context(key) if key is not None and
                           hasattr(runtime, "_host_call_context") else nullcontext())
                with context:
                    outcome = method(*args, **kwargs)
                    return outcome
            finally:
                try:
                    if key is not None:
                        release = end_once()
                        if type(outcome) is dict and type(release) is dict:
                            outcome["control_phase"] = release
                finally:
                    if lease is not None:
                        lease.finish()
        pending = asyncio.to_thread(execute)
        try:
            worker = asyncio.create_task(pending)
        except BaseException:
            pending.close()
            if lease is not None:
                lease.abort()
            self.cleanup.run((end_token, 'submission'), self.task_context.get(), 'submission', end_once)
            raise
        self.executions[worker] = (runtime, key)
        if lease is not None:
            self.business_stops[worker] = cancel_queued
        self.execution_tasks[worker] = self.task_context.get()
        if _on_host_stop is not None:
            self.stop_callbacks[worker] = _on_host_stop

        def completed(task):
            if lease is not None:
                self.cleanup.run((task, 'business_queue'), self.execution_tasks.get(task), 'business_queue', finish_unstarted)
            self.business_stops.pop(task, None)
            self.executions.pop(task, None)
            current = self.execution_tasks.pop(task, None)
            self._release_finish_guard(current)
            self.stop_callbacks.pop(task, None)
            if not task.cancelled():
                task.exception()  # Observe failures even after the host has left.
        worker.add_done_callback(completed)
        try:
            # wait does not propagate host cancellation into the running thread.
            # Unlike shield, it also leaves late failures to our exact callback.
            await asyncio.wait({worker})
            return worker.result()
        except asyncio.CancelledError:
            self._stop_worker(worker)
            try:
                done, _ = await asyncio.wait({worker}, timeout=self.CLEANUP_WAIT_SECONDS)
                if not done:
                    raise TimeoutError
            except (TimeoutError, asyncio.CancelledError):
                if key is not None:
                    cleanup_event({"event": "app_host_cancel", "stop_received": True,
                                   "execution_finished": False, "input_release": "unconfirmed"})
            except Exception:
                pass  # The durable receipt holds the worker's failure evidence.
            raise

    async def close(self):
        self.closing = True
        deadline = asyncio.get_running_loop().time() + self.CLEANUP_WAIT_SECONDS
        self.cleanup.retry()
        for worker in tuple(self.executions):
            self._stop_worker(worker)
        pending = list(self.executions)
        if pending:
            _, unfinished = await asyncio.wait(pending, timeout=max(0, deadline-asyncio.get_running_loop().time()))
            if unfinished:
                cleanup_event({"event": "app_host_shutdown", "stop_received": True,
                               "unfinished_executions": len(unfinished), "input_release": "unconfirmed"})
        self.cleanup.retry()
        await self.cleanup.retry_threaded(timeout=max(0, deadline-asyncio.get_running_loop().time()))
