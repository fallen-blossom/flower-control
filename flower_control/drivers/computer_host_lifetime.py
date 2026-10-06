"""Tie cancellable MCP awaits to exact synchronous Computer executions."""
from __future__ import annotations

import asyncio
import json
import sys


class ComputerHostLifetime:
    CLEANUP_WAIT_SECONDS = 2.0

    def __init__(self):
        self.executions: dict[asyncio.Task, tuple[object, str | None]] = {}
        self.stop_callbacks = {}
        self.closing = False

    async def call(self, method, *args, _on_host_stop=None, **kwargs):
        if self.closing:
            from .computer_mcp import ComputerBoundaryError
            raise ComputerBoundaryError("computer_host_stopping")
        runtime = getattr(method, "__self__", None)
        action_index = {"observe": 1, "activate": 2, "input": 4}.get(method.__name__)
        key = None
        if (action_index is not None and kwargs.get("trusted_task") is not None and
                hasattr(runtime, "begin_host_call")):
            key = runtime.begin_host_call(kwargs["trusted_task"], args[action_index])
        def execute():
            try:
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
            # Keep the thread alive until its own Stop checks finish cleanup.
            # Our completion callback owns late failures without shield warnings.
            await asyncio.wait({worker})
            return worker.result()
        except asyncio.CancelledError:
            if _on_host_stop is not None:
                _on_host_stop()
            if key is not None:
                runtime.request_host_stop(key)
            try:
                done, _ = await asyncio.wait({worker}, timeout=self.CLEANUP_WAIT_SECONDS)
                if not done:
                    raise TimeoutError
            except (TimeoutError, asyncio.CancelledError):
                print(json.dumps({"event": "computer_host_cancel", "stop_received": True,
                                  "execution_finished": False, "input_release": "unconfirmed"}),
                      file=sys.stderr, flush=True)
            except Exception:
                pass  # The durable receipt holds the worker's failure evidence.
            raise

    async def close(self):
        self.closing = True
        pending = list(self.executions)
        for callback in list(self.stop_callbacks.values()):
            callback()
        for runtime, key in list(self.executions.values()):
            if key is not None:
                runtime.request_host_stop(key)
        if pending:
            _, unfinished = await asyncio.wait(pending, timeout=self.CLEANUP_WAIT_SECONDS)
            if unfinished:
                print(json.dumps({"event": "computer_host_shutdown", "stop_received": True,
                                  "unfinished_executions": len(unfinished),
                                  "input_release": "unconfirmed"}), file=sys.stderr, flush=True)
