"""Tie cancellable MCP awaits to exact synchronous App executions."""
from __future__ import annotations

import asyncio
import json
import inspect
import sys
from contextlib import nullcontext


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

    def end_host_call(self, key):
        self.control.end_host_call(key)

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
        self.closing = False

    def _request_host_stop(self, runtime, key):
        signal = getattr(runtime, "signal_host_stop", runtime.request_host_stop)
        cleanup = signal(key)
        if not callable(cleanup):
            return
        worker = asyncio.create_task(asyncio.to_thread(cleanup))
        self.executions[worker] = (None, None)
        def completed(task):
            self.executions.pop(task, None)
            if not task.cancelled() and task.exception() is not None:
                print("Flower App host Stop cleanup unavailable", file=sys.stderr, flush=True)
        worker.add_done_callback(completed)

    async def call(self, method, *args, _on_host_stop=None, **kwargs):
        if self.closing:
            from .app_control import AppBoundaryError
            raise AppBoundaryError("app_host_stopping")
        runtime = getattr(method, "__self__", None)
        bound = inspect.signature(method).bind_partial(*args, **kwargs).arguments
        if runtime is None and getattr(method, "__name__", "") in {
                "capture_app_screenshot", "authorize_app_screenshot_return"}:
            runtime = args[0]
        key = None
        if (type(bound.get("action_id")) is str and kwargs.get("trusted_task") is not None
                and getattr(method, "__name__", "") not in {"action_status", "cancel"}
                and hasattr(runtime, "begin_host_call")):
            key = runtime.begin_host_call(kwargs["trusted_task"], bound["action_id"])
        def execute():
            try:
                context = (runtime._host_call_context(key) if key is not None and
                           hasattr(runtime, "_host_call_context") else nullcontext())
                with context:
                    return method(*args, **kwargs)
            finally:
                if key is not None:
                    runtime.end_host_call(key)
        worker = asyncio.create_task(asyncio.to_thread(execute))
        self.executions[worker] = (runtime, key)
        if _on_host_stop is not None:
            self.stop_callbacks[worker] = _on_host_stop

        def completed(task):
            self.executions.pop(task, None)
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
            if _on_host_stop is not None:
                _on_host_stop()
            if key is not None:
                self._request_host_stop(runtime, key)
            try:
                done, _ = await asyncio.wait({worker}, timeout=self.CLEANUP_WAIT_SECONDS)
                if not done:
                    raise TimeoutError
            except (TimeoutError, asyncio.CancelledError):
                if key is not None:
                    print(json.dumps({"event": "app_host_cancel", "stop_received": True,
                                      "execution_finished": False, "input_release": "unconfirmed"}),
                          file=sys.stderr, flush=True)
            except Exception:
                pass  # The durable receipt holds the worker's failure evidence.
            raise

    async def close(self):
        self.closing = True
        for callback in list(self.stop_callbacks.values()):
            callback()
        for runtime, key in list(self.executions.values()):
            if key is not None:
                self._request_host_stop(runtime, key)
        pending = list(self.executions)
        if pending:
            _, unfinished = await asyncio.wait(pending, timeout=self.CLEANUP_WAIT_SECONDS)
            if unfinished:
                print(json.dumps({"event": "app_host_shutdown", "stop_received": True,
                                  "unfinished_executions": len(unfinished),
                                  "input_release": "unconfirmed"}), file=sys.stderr, flush=True)
