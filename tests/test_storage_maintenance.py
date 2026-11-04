import copy
import json
import hashlib
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from flower_control.install_location import prepare_location
from tools import storage_maintenance as storage


class StorageMaintenanceTests(unittest.TestCase):
    def fixture(self, temporary):
        install = prepare_location(Path(temporary) / "install", "S-1-5-21-1-2-3-1001")
        self.old = time.time() - 10 * 86400
        paths = {"candidate": install.cache_root / "diagnostics" / "old.jsonl",
            "fresh": install.cache_root / "diagnostics" / "fresh.jsonl",
            "ledger": install.data_root / "state-v1" / "control.sqlite3",
            "recovery": install.program_root / "recovery" / "unknown.json",
            "profile": install.data_root / "profiles" / "Cookies",
            "artifact": install.cache_root / "flower-web-artifacts" / "user-result.json",
            "package": install.packages_root / "setup.json"}
        for path in paths.values():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"owned test metadata")
            os.utime(path, (self.old, self.old))
        os.utime(paths["fresh"], None)
        return install, paths

    def test_usage_reads_only_metadata_and_cleanup_scope_excludes_user_results(self):
        with tempfile.TemporaryDirectory(prefix="flower-storage-") as temporary:
            install, paths = self.fixture(temporary)
            with patch("pathlib.Path.open", side_effect=AssertionError("content read")):
                usage = storage.usage(install)
            self.assertEqual(len(usage["categories"]), 4)
            self.assertEqual(sum(row["files"] for row in usage["categories"]), 7)
            plan = storage.plan_cache_cleanup(install)
            self.assertEqual(plan["file_count"], 1)
            self.assertEqual(plan["files"][0]["path"], str(paths["candidate"]))
            recycled = []
            result = storage.recycle_plan(plan, install, recycle=lambda path: recycled.append(path))
            self.assertEqual(result["state"], "recycled")
            self.assertEqual(recycled, [paths["candidate"]])

    def test_changed_identity_contents_or_outside_candidate_reject_entire_batch(self):
        with tempfile.TemporaryDirectory(prefix="flower-storage-drift-") as temporary:
            install, paths = self.fixture(temporary)
            plan = storage.plan_cache_cleanup(install)
            outside = copy.deepcopy(plan)
            outside["files"][0]["path"] = str(paths["recovery"])
            with self.assertRaises(ValueError):
                storage.recycle_plan(outside, install, recycle=lambda _: self.fail("dispatched outside cache"))
            paths["candidate"].write_bytes(b"changed")
            os.utime(paths["candidate"], (self.old, self.old))
            with self.assertRaisesRegex(ValueError, "changed"):
                storage.recycle_plan(plan, install, recycle=lambda _: self.fail("dispatched stale candidate"))

    def test_reviewed_plan_digest_binds_the_exact_bytes_used_for_cleanup(self):
        with tempfile.TemporaryDirectory(prefix="flower-storage-plan-binding-") as temporary:
            install, _ = self.fixture(temporary)
            path = Path(temporary) / "plan.json"
            path.write_text(json.dumps(storage.plan_cache_cleanup(install)))
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(storage.load_reviewed_plan(path, digest)["file_count"], 1)
            path.write_text(path.read_text() + "\n")
            with self.assertRaisesRegex(ValueError, "reviewed_plan_changed"):
                storage.load_reviewed_plan(path, digest)

    def test_junctions_and_hardlinks_never_enter_cleanup_and_failure_has_no_fallback(self):
        import _winapi
        with tempfile.TemporaryDirectory(prefix="flower-storage-links-") as temporary:
            install, paths = self.fixture(temporary)
            alias = install.cache_root / "diagnostics" / "alias"
            _winapi.CreateJunction(str(install.program_root / "recovery"), str(alias))
            os.link(paths["recovery"], install.cache_root / "diagnostics" / "hardlink.json")
            plan = storage.plan_cache_cleanup(install)
            self.assertEqual(plan["file_count"], 1)
            def failed(_):
                raise OSError("recycle unavailable")
            result = storage.recycle_plan(plan, install, recycle=failed)
            self.assertEqual(result["state"], "failed")
            self.assertTrue(paths["candidate"].is_file())
            self.assertTrue(paths["recovery"].is_file())

    def test_real_medium_recycle_only_owned_isolated_metadata(self):
        import win32api
        import win32con
        import win32security
        token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
        try:
            if win32security.GetTokenInformation(token, win32security.TokenElevation):
                self.skipTest("real recycle fixture requires an ordinary Medium token")
        finally:
            token.Close()
        with tempfile.TemporaryDirectory(prefix="flower-storage-real-recycle-") as temporary:
            install, paths = self.fixture(temporary)
            plan = storage.plan_cache_cleanup(install)
            result = storage.recycle_plan(plan, install)
            self.assertEqual(result["state"], "recycled")
            self.assertFalse(paths["candidate"].exists())
            self.assertTrue(paths["recovery"].is_file())
            self.assertTrue(paths["profile"].is_file())


if __name__ == "__main__":
    unittest.main()
