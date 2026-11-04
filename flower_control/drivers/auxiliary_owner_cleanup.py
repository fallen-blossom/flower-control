"""Retain exact temporary connection IDs until retirement is acknowledged."""
import json
import sys
import threading

from flower_control.control.state import ControlError


class AuxiliaryOwnerCleanup:
    def __init__(self, store):
        self.store = store
        self._pending = {}
        self._gate = threading.RLock()

    def retire(self, task, owners=(), *, primary_error=None):
        with self._gate:
            pending = self._pending.setdefault(task, set())
            pending.update(owners)
            failure_types = set()
            for owner in tuple(pending):
                try:
                    self.store.retire_owner(owner)
                except Exception as error:
                    # Keep only internally created exact owner IDs for retry.
                    # Unknown action effects remain in the durable ledger.
                    failure_types.add(type(error).__name__)
                    continue
                pending.discard(owner)
            count = len(pending)
            if not count:
                self._pending.pop(task, None)
                return
        reason = "auxiliary_owner_cleanup_pending"
        if primary_error is not None:
            primary_error.add_note(reason)
            print(json.dumps({"event": reason, "pending_owners": count,
                              "failure_types": sorted(failure_types)}),
                  file=sys.stderr, flush=True)
            return
        raise ControlError(reason)
