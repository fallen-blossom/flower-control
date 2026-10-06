"""Disconnect scope and uncertainty are tested without any browser process."""
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import AsyncMock

from flower_control.control.state import StateStore, ControlError
from flower_control.drivers.web_mcp import WebMcpRuntime, _Session


class ConnectionCleanupTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="flower-connection-cleanup-")
        self.addCleanup(directory.cleanup)
        self.runtime = WebMcpRuntime(StateStore(Path(directory.name)))
        self.task = self.runtime.store.create_task()
        self.other = self.runtime.store.create_task()

    def add(self, session, task, kind=None, **fields):
        browser = SimpleNamespace(persistent_profile=Path("profile") if kind else None, profile_kind=kind)
        record = _Session(task, browser, SimpleNamespace(), **fields)
        self.runtime.sessions[session] = record
        return record

    async def test_cleanup_only_owned_temp_and_ai_never_private_or_other(self):
        self.add("temp", self.task)
        self.add("ai", self.task, "ai")
        self.add("private", self.task, "luohua")
        self.add("other", self.other)
        self.add("closed", self.task, closed=True)
        self.runtime.close_temp = AsyncMock(return_value={"closed": True})
        self.runtime.close_ai = AsyncMock(return_value={"closed": True})
        await self.runtime.close_connection(frozenset({self.task}))
        self.runtime.close_temp.assert_awaited_once_with(self.task, "temp")
        self.runtime.close_ai.assert_awaited_once_with(self.task, "ai")

    async def test_unknown_and_stop_remain_unresolved_without_retry(self):
        record = self.add("unknown", self.task, cleanup_error=True)
        self.runtime.close_temp = AsyncMock(return_value={"closed": False, "state": "outcome_uncertain"})
        self.runtime.close_ai = AsyncMock(side_effect=ControlError("task_paused"))
        self.add("ai", self.task, "ai")
        self.runtime.store.pause_task(self.task)
        await self.runtime.close_connection(frozenset({self.task}))
        self.runtime.close_temp.assert_awaited_once()
        self.runtime.close_ai.assert_awaited_once()
        self.assertTrue(record.cleanup_error)
        self.assertFalse(record.closed)
        with self.runtime.store.transaction() as db:
            self.assertTrue(db.execute("SELECT paused FROM tasks WHERE id=?", (self.task,)).fetchone()[0])

    async def test_human_ai_login_disconnect_keeps_window(self):
        browser = SimpleNamespace(owner_task=self.task, profile_kind="ai", disconnect=AsyncMock())
        self.runtime._logins["login"] = browser
        self.runtime.cancel_ai_login = AsyncMock(return_value={"state": "cancel_pending_user_close"})
        await self.runtime.close_connection(frozenset({self.task}))
        browser.disconnect.assert_awaited_once()
        self.runtime.cancel_ai_login.assert_awaited_once_with(self.task, "login")


if __name__ == "__main__":
    unittest.main()
