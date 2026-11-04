"""Tie cancellable MCP awaits to exact synchronous Computer executions."""
from __future__ import annotations

import asyncio
import inspect
import threading
from .host_cleanup import CleanupAttempts, cleanup_event


class ComputerHostLifetime:
    CLEANUP_WAIT_SECONDS = 2.0

    def __init__(self):
        self.executions: dict[asyncio.Task, tuple[object, str | None]] = {}
        self.stop_callbacks = {}
        self.business_stops = {}
        self.execution_tasks = {}
        self.closing = False
        self.cleanup = CleanupAttempts("computer")

    def busy(self, task):
        return any(not worker.done() and self.execution_tasks.get(worker) in (None, task)
                   for worker in tuple(self.executions))

    def _stop_worker(self, worker):
        runtime, key = self.executions.get(worker, (None, None))
        callback = self.stop_callbacks.get(worker)
        if callback is not None:
            self.cleanup.run((worker, "callback"), None, "stop_callback", callback)
        if key is not None:
            self.cleanup.run((worker, "runtime"), None, "runtime_stop",
                             lambda: runtime.request_host_stop(key))
        stop_queued = self.business_stops.get(worker)
        if stop_queued is not None:
            self.cleanup.run((worker, "business_queue"), None, "business_queue", stop_queued)

    async def call(self, method, *args, _on_host_stop=None, **kwargs):
        if self.closing:
            from .computer_mcp import ComputerBoundaryError
            raise ComputerBoundaryError("computer_host_stopping")
        cleanup_task = kwargs.get("trusted_task")
        if type(cleanup_task) is str and getattr(method, "__name__", "") in {"observe", "activate", "input"}:
            await self.cleanup.retry_threaded(cleanup_task, timeout=self.CLEANUP_WAIT_SECONDS)
        if self.closing:
            from .computer_mcp import ComputerBoundaryError
            raise ComputerBoundaryError("computer_host_stopping")
        runtime = getattr(method, "__self__", None)
        # A bound method normally carries __name__, but a partial or a wrapped
        # callable does not. Treat an unnamed callable as an ordinary action.
        action_index = {"observe": 1, "activate": 2, "input": 4}.get(getattr(method, "__name__", ""))
        key = None
        from flower_control.control.business_calls import public_worker
        lease = public_worker()
        try:
            if (action_index is not None and kwargs.get("trusted_task") is not None and
                    hasattr(runtime, "begin_host_call")):
                key = runtime.begin_host_call(kwargs["trusted_task"], args[action_index])
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
            self.cleanup.run((end_token, 'submission'), None, 'submission', end_once)
            raise
        self.executions[worker] = (runtime, key)
        self.execution_tasks[worker] = (kwargs.get("trusted_task") or kwargs.get("task") or
            getattr(getattr(lease, "call", None), "task", None))
        if lease is not None:
            self.business_stops[worker] = cancel_queued
        if _on_host_stop is not None:
            self.stop_callbacks[worker] = _on_host_stop

        def completed(task):
            if lease is not None:
                self.cleanup.run((task, 'business_queue'), None, 'business_queue', finish_unstarted)
            self.business_stops.pop(task, None)
            self.executions.pop(task, None)
            self.execution_tasks.pop(task, None)
            self.stop_callbacks.pop(task, None)
            if not task.cancelled():
                task.exception()  # Observe failures even after the host has left.
        worker.add_done_callback(completed)
        try:
            # Keep the thread alive until its own Stop checks finish cleanup.
            # Our completion callback owns late failures without shield warnings.
            await asyncio.wait({worker})
            return worker.result()
        except asyncio.CancelledError:
            self._stop_worker(worker)
            try:
                done, _ = await asyncio.wait({worker}, timeout=self.CLEANUP_WAIT_SECONDS)
                if not done:
                    raise TimeoutError
            except (TimeoutError, asyncio.CancelledError):
                cleanup_event({"event": "computer_host_cancel", "stop_received": True,
                               "execution_finished": False, "input_release": "unconfirmed"})
            except Exception:
                pass  # The durable receipt holds the worker's failure evidence.
            raise

    async def close(self):
        self.closing = True
        deadline = asyncio.get_running_loop().time() + self.CLEANUP_WAIT_SECONDS
        self.cleanup.retry()
        pending = list(self.executions)
        for worker in pending:
            self._stop_worker(worker)
        if pending:
            _, unfinished = await asyncio.wait(pending, timeout=max(0, deadline-asyncio.get_running_loop().time()))
            if unfinished:
                cleanup_event({"event": "computer_host_shutdown", "stop_received": True,
                               "unfinished_executions": len(unfinished), "input_release": "unconfirmed"})
        self.cleanup.retry()
        await self.cleanup.retry_threaded(timeout=max(0, deadline-asyncio.get_running_loop().time()))
