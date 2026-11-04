"""One MCP call's cancellation, shared with its synchronous worker context."""
from contextvars import ContextVar
from threading import Event, Lock
import json
import sys


class CallCancellation(Event):
    """Retain exact enqueued actions until the MCP result is delivered."""
    def __init__(self):
        super().__init__()
        self._gate = Lock()
        self._actions = {}

    def track(self, store, owner, action_id):
        with self._gate:
            self._actions[(id(store), owner, action_id)] = (store, owner, action_id)
        # enqueue committed before registration. If cancellation won the race,
        # this worker owns the late withdrawal; no event-loop DB wait.
        if self.is_set():
            self.withdraw()

    def withdraw(self):
        with self._gate:
            actions = tuple(self._actions.values())
            self._actions.clear()
        failures = 0
        for store, owner, action_id in actions:
            try:
                store.withdraw_queued_call(owner, action_id)
            except Exception:
                failures += 1
        if failures:
            print(json.dumps({"event": "mcp_call_cancel_cleanup", "withdrawal_unconfirmed": failures}),
                  file=sys.stderr, flush=True)

current_call_cancel: ContextVar[Event | None] = ContextVar("flower_call_cancel", default=None)


def call_cancelled() -> bool:
    event = current_call_cancel.get()
    return event is not None and event.is_set()
