"""Private parent/worker binding, never a model-authored grant."""
from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path

from .state import ControlError, StateStore


@lru_cache(maxsize=4)
def _open_store(directory: str) -> StateStore:
    # Reuse schema/boot setup, never authorization rows: every check opens a
    # new transaction and sees current revocation from the parent process.
    return StateStore(Path(directory))


def command_hash(command: str, arguments: dict) -> str:
    body = json.dumps({"command": command, "arguments": arguments},
                      ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


class WorkerCallGuard:
    def __init__(self, envelope: dict, command: str, arguments: dict):
        if (type(envelope) is not dict or set(envelope) != {"directory", "action", "token"}
                or any(type(value) is not str or not value or len(value) > 4096
                       for value in envelope.values())):
            raise ControlError("invalid_worker_envelope")
        directory = Path(envelope["directory"])
        if not directory.is_absolute() or not (directory / "control.sqlite3").is_file():
            raise ControlError("worker_ledger_missing")
        self.store = _open_store(str(directory.resolve()))
        self.action = envelope["action"]
        self.token = envelope["token"]
        self.fingerprint = command_hash(command, arguments)
        self.store.check_worker_permit(self.action, self.token, self.fingerprint, consume=True)

    async def check(self):
        self.store.check_worker_permit(self.action, self.token, self.fingerprint)
