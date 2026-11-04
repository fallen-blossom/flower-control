"""Exact local cleanup retries and isolated shutdown stages, never input replay."""
import asyncio
import json
import sys

import anyio


_ALL_TASKS = object()


def cleanup_event(details):
    try:
        print(json.dumps(details), file=sys.stderr, flush=True)
    except Exception:
        pass  # A closed diagnostic stream must not prevent actual Stop/cleanup.


def cleanup_warning(channel, phase, error):
    # Exception text may contain UI content, paths or provider response bodies.
    details = {"event": channel + "_host_cleanup_pending", "phase": phase,
               "failure_type": type(error).__name__}
    if phase == "idle_phase_release":
        details["metadata_cleanup_only"] = True
    else:
        details["input_release"] = "unconfirmed"
    cleanup_event(details)


class CleanupAttempts:
    """Retain only exact internal idempotent Stop/cleanup callbacks until ack."""

    def __init__(self, channel):
        self.channel = channel
        self.pending = {}
        self.threaded = set()
        self.running = {}

    def remember(self, key, task, phase, callback, error, *, threaded=False):
        self.pending[key] = (task, phase, callback)
        if threaded:
            self.threaded.add(key)
        cleanup_warning(self.channel, phase, error)

    def run(self, key, task, phase, callback):
        try:
            callback()
        except Exception as error:
            self.remember(key, task, phase, callback, error)
            return False
        self.pending.pop(key, None)
        self.threaded.discard(key)
        return True

    def retry(self, task=_ALL_TASKS):
        for key, (current, phase, callback) in tuple(self.pending.items()):
            if key not in self.threaded and (task is _ALL_TASKS or task == current):
                self.run(key, current, phase, callback)

    async def retry_threaded(self, task=_ALL_TASKS, *, timeout=2.0):
        """One metadata attempt per boundary; late workers keep their identity.

        Never cancel a synchronous cleanup or run ledger waits on the event
        loop. A running attempt is reused, not duplicated on another boundary.
        """
        waiting = []
        for key, (current, phase, callback) in tuple(self.pending.items()):
            if key not in self.threaded or not (task is _ALL_TASKS or task == current):
                continue
            worker = self.running.get(key)
            if worker is None:
                worker = asyncio.create_task(asyncio.to_thread(self.run, key, current, phase, callback))
                self.running[key] = worker
                def completed(done, key=key):
                    if self.running.get(key) is done:
                        self.running.pop(key, None)
                    if not done.cancelled():
                        done.exception()
                worker.add_done_callback(completed)
            waiting.append(worker)
        if waiting:
            await asyncio.wait(waiting, timeout=max(0, timeout))

    def has_pending(self, task=_ALL_TASKS):
        return any(task is _ALL_TASKS or current == task
                   for current, _, _ in self.pending.values())


async def close_host_resources(channel, steps):
    """One failing owned cleanup must not skip later independent resources."""
    complete = True
    cancelled = None
    # MCP uses AnyIO level cancellation. Shield owned cleanup from a host scope
    # already cancelled at EOF, while preserving explicit asyncio cancellation.
    with anyio.CancelScope(shield=True):
        for phase, operation in steps:
            try:
                await operation()
            except asyncio.CancelledError as error:
                if cancelled is None:
                    cancelled = error
                complete = False
                cleanup_warning(channel, phase, error)
            except Exception as error:
                complete = False
                cleanup_warning(channel, phase, error)
    if cancelled is not None:
        raise cancelled
    return complete
