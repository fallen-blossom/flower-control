"""Isolated persistent-profile preflight checks; never launches a browser."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from flower_control.control.state import ControlError
from flower_control.drivers.web_session import TemporaryWebSession


class ClosedBrowserUpdateTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="flower-browser-update-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.executable = root / "brave.exe"
        self.executable.write_bytes(b"new-version-not-executed")
        self.profile = root / "ai-v1"
        self.profile.mkdir()
        self.path = self.profile / "flower-session.json"
        self.marker = {
            "session_id": "a" * 32, "profile_kind": "ai", "state": "closed",
            "profile_hash": hashlib.sha256(str(self.profile.resolve()).lower().encode()).hexdigest(),
            "executable": str(self.executable),
            "brave_digest": hashlib.sha256(b"old-version").hexdigest(),
            "headless": False, "login_only": True,
            "browser_pid": 12345, "browser_created": "2026-10-01T00:00:00+00:00",
            "owner_process": None, "worker_process": None,
        }

    def session(self):
        self.path.write_text(json.dumps(self.marker), encoding="utf-8")
        browser = TemporaryWebSession(brave_executable=self.executable,
                                     persistent_profile=self.profile, guarded=True,
                                     headless=False, owner_task="new-task")
        return browser

    async def test_closed_old_login_can_reach_fresh_launch_without_rewriting_old_marker(self):
        browser = self.session()
        before = self.path.read_bytes()
        with patch("flower_control.drivers.web_session.process_is_alive", return_value=False), \
                patch.object(browser, "_launch_brave", side_effect=RuntimeError("fixture-no-launch")) as launch:
            with self.assertRaisesRegex(RuntimeError, "fixture-no-launch"):
                await browser.start()
        launch.assert_called_once()
        self.assertEqual(self.path.read_bytes(), before)
        self.assertIsNone(browser._profile_lock)

    async def test_default_read_and_reconnect_remain_strict(self):
        browser = self.session()
        browser.profile_path = self.profile
        with self.assertRaisesRegex(ControlError, "ai_profile_identity_unverified"):
            browser._read_marker(ignore_mode=True)
        browser.profile_path = None
        with self.assertRaisesRegex(ControlError, "ai_profile_identity_unverified"):
            await browser.reconnect(self.marker["session_id"])
        self.assertIsNone(browser._profile_lock)

    async def test_running_marker_cannot_use_closed_upgrade(self):
        self.marker.update(state="running", owner_task="old-task")
        browser = self.session()
        with patch.object(browser, "_launch_brave") as launch:
            with self.assertRaisesRegex(ControlError, "ai_profile_identity_unverified"):
                await browser.start()
        launch.assert_not_called()

    async def test_live_browser_owner_or_worker_each_block_update(self):
        browser_id = f"{self.marker['browser_pid']}:{self.marker['browser_created']}"
        for identity in (browser_id, "23456:owner", "34567:worker"):
            with self.subTest(identity=identity):
                self.marker.update(owner_process="23456:owner", worker_process="34567:worker")
                browser = self.session()
                with patch("flower_control.drivers.web_session.process_is_alive",
                           side_effect=lambda current: current == identity), \
                        patch.object(browser, "_launch_brave") as launch:
                    with self.assertRaisesRegex(ControlError, "ai_profile_identity_unverified"):
                        await browser.start()
                launch.assert_not_called()
                self.assertIsNone(browser._profile_lock)

    async def test_wrong_profile_path_kind_executable_or_invalid_digest_still_block(self):
        initial = self.marker.copy()
        for field, value in (("profile_hash", "0" * 64), ("profile_kind", "luohua"),
                             ("executable", str(self.profile / "brave.exe")),
                             ("brave_digest", "bad-digest"), ("browser_pid", 0),
                             ("browser_created", None)):
            with self.subTest(field=field):
                self.marker = dict(initial, **{field: value})
                browser = self.session()
                with patch("flower_control.drivers.web_session.process_is_alive", return_value=False), \
                        patch.object(browser, "_launch_brave") as launch:
                    with self.assertRaisesRegex(ControlError, "ai_profile_identity_unverified"):
                        await browser.start()
                launch.assert_not_called()

    async def test_same_digest_closed_start_unchanged(self):
        self.marker["brave_digest"] = hashlib.sha256(self.executable.read_bytes()).hexdigest()
        browser = self.session()
        with patch("flower_control.drivers.web_session.process_is_alive", return_value=False), \
                patch.object(browser, "_launch_brave", side_effect=RuntimeError("fixture-no-launch")) as launch:
            with self.assertRaisesRegex(RuntimeError, "fixture-no-launch"):
                await browser.start()
        launch.assert_called_once()

    async def test_provisional_marker_never_accepts_browser_upgrade(self):
        browser = self.session()
        browser.profile_path = self.profile
        (self.profile / "flower-session.json.new").write_bytes(self.path.read_bytes())
        with self.assertRaisesRegex(ControlError, "ai_profile_identity_unverified"):
            browser._read_marker(ignore_mode=True, provisional=True, allow_closed_browser_update=True)


if __name__ == "__main__":
    unittest.main()
