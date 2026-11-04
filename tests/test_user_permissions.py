import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from flower_control import permissions
from flower_control.control.state import ControlError, StateStore
from flower_control.drivers.web_worker import _Runtime


class UserPermissionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="flower-permission-tests-")
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "permissions.json"
        self.value = permissions.default_policy(permissions.user_sid())
        # Stored-policy cases intentionally exercise a legacy 03 record.
        # They must not obtain that role from the new no-file default.
        self.value.pop("AuthorityTier")
        self.value["AdminWindows"] = True
        self.reader = permissions.PolicyReader(self.path, protection=False)
        self.patch = patch.object(permissions, "active_policy", self.reader)
        self.patch.start(); self.addCleanup(self.patch.stop)

    def save(self):
        self.path.write_text(json.dumps(self.value), encoding="utf-8")

    def test_missing_policy_defaults_ordinary_without_writing_authority(self):
        value = self.reader.read()
        self.assertFalse(value["AdminWindows"])
        self.assertFalse(value["AdminLaunchEnabled"])
        self.assertEqual(value["AuthorityTier"], 0)
        self.assertEqual(value["UacMode"], "off")
        self.assertFalse(self.path.exists())

    def test_existing_legacy_03_and_04_keep_tiers_and_exact_bytes(self):
        for launch in (False, True):
            value = dict(self.value, AdminLaunchEnabled=launch, UacMode="off")
            raw = json.dumps(value).encode()
            self.path.write_bytes(raw)
            actual = self.reader.read()
            self.assertEqual(actual["AuthorityTier"], 2 if launch else 1)
            self.assertTrue(actual["AdminWindows"])
            self.assertEqual(actual["AdminLaunchEnabled"], launch)
            self.assertEqual(self.path.read_bytes(), raw)

    def test_parent_delete_child_permission_is_rejected(self):
        import win32security
        descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
            "O:SYG:SYD:(A;;0x00000040;;;" + permissions.user_sid() + ")S:(ML;;NW;;;HI)", 1)
        with patch.object(permissions.win32api, "GetFileAttributes", return_value=0), \
             patch.object(permissions.win32security, "GetNamedSecurityInfo", return_value=descriptor):
            with self.assertRaisesRegex(permissions.PermissionError, "user_policy_unprotected"):
                permissions._check_protection(self.path)

    def test_admin_off_keeps_ordinary_window(self):
        self.value["AdminWindows"] = False; self.save()
        permissions.require_application("C:/Test/app.exe", integrity=8192)
        with self.assertRaisesRegex(permissions.PermissionError, "administrator_window_disabled"):
            permissions.require_application("C:/Test/app.exe", integrity=12288)

    def test_deny_precedes_allow_and_case_normalizes(self):
        row = dict(Path="C:/Test/app.exe", TitleContains="", Enabled=True)
        self.value["DeniedApplications"] = [row]
        self.value["AllowedAdminApplications"] = [row]; self.save()
        with self.assertRaisesRegex(permissions.PermissionError, "window_disabled_by_user"):
            permissions.require_application("c:\\test\\APP.EXE", integrity=12288)

    def test_window_control_does_not_require_legacy_program_allowlist(self):
        self.value.update(AdminScope="allowlist", AllowedAdminApplications=[])
        self.save()
        permissions.require_application("C:/Test/app.exe", integrity=12288)

    def test_temporarily_disabled_rule_does_not_match(self):
        self.value["DeniedApplications"] = [dict(Path="C:/Test/app.exe", TitleContains="", Enabled=False)]
        self.save(); permissions.require_application("C:/Test/app.exe")

    def test_web_title_rule_is_conservative_for_headless(self):
        self.value["DeniedApplications"] = [dict(Path="C:/Test/brave.exe", TitleContains="private", Enabled=True)]
        self.save()
        with self.assertRaisesRegex(permissions.PermissionError, "window_disabled_by_user"):
            permissions.require_browser(12, "C:/Test/brave.exe")

    def test_owned_dialog_inherits_parent_title_denial(self):
        self.value["DeniedApplications"] = [dict(Path="C:/Test/app.exe", TitleContains="private", Enabled=True)]
        self.save()
        with patch.object(permissions, "process_facts", return_value=("C:/Test/app.exe", 8192)), \
             patch.object(permissions.win32process, "GetWindowThreadProcessId", return_value=(1, 2)), \
             patch.object(permissions.win32gui, "GetWindowText", side_effect=lambda hwnd: "private" if hwnd == 2 else "dialog"), \
             patch.object(permissions.win32gui, "GetWindow", side_effect=lambda hwnd, _: 2 if hwnd == 1 else 0):
            with self.assertRaisesRegex(permissions.PermissionError, "window_disabled_by_user"):
                permissions.require_window(1)

    def test_duplicate_or_corrupt_policy_fails_closed(self):
        self.path.write_text('{"Schema":1,"Schema":1}', encoding="utf-8")
        with self.assertRaises(permissions.PermissionError): self.reader.read()
        self.path.write_text('{', encoding="utf-8")
        with self.assertRaises(permissions.PermissionError): self.reader.read()

    def test_uac_cannot_be_enabled_by_json(self):
        # A legacy flag remains invalid; schema migration cannot grant UAC.
        self.value["Schema"] = 1
        self.value.pop("UacMode"); self.value.pop("UacAllowlist")
        self.value.pop("AdminLaunchEnabled"); self.value.pop("UacCancellationScope")
        self.value.pop("AdminLaunchAllowlist")
        self.value["UacEnabled"] = True; self.save()
        with self.assertRaisesRegex(permissions.PermissionError, "uac_component_unavailable"):
            self.reader.read()

    def test_old_observation_and_queued_action_stay_invalid_after_reenable(self):
        store = StateStore(Path(self.directory.name) / "ledger", boot="permission-test")
        task = store.create_task(); owner = store.register_owner(task)
        resource = "desktop:permission-test"
        observation = store.observe(owner, resource, "generation")
        store.enqueue(owner, action_id="old", fingerprint="old", resources=(resource,),
                      observation=observation, generation="generation")
        decision = store.prepare_decision((resource,), ttl=5)
        self.value["AdminWindows"] = False; self.save()
        self.assertFalse(store.adopt_decision(decision["id"], "old"))
        self.value["AdminWindows"] = True; self.value["Revision"] = "reenabled"; self.save()
        with self.assertRaisesRegex(ControlError, "user_policy_requires_new_observation"):
            store.enqueue(owner, action_id="old-observation", fingerprint="new", resources=(resource,),
                          observation=observation, generation="generation")
        fresh = store.observe(owner, resource, "generation")
        result = store.enqueue(owner, action_id="fresh", fingerprint="fresh", resources=(resource,),
                               observation=fresh, generation="generation")
        self.assertEqual(result["state"], "queued")


class AppRevokedResultTests(unittest.TestCase):
    def test_read_only_legacy_dispatch_marker_is_not_input(self):
        from flower_control.drivers.app_flow import suppress_app_content
        result = suppress_app_content({"receipt": {"state": "verified", "dispatched": 1},
            "result": {"state": "observed", "dispatched": False, "text": "FAKE-PRIVATE"}}, "revoked")
        self.assertIs(result["dispatched"], False)
        self.assertEqual(result["receipt"]["dispatched"], 1)
        self.assertNotIn("FAKE-PRIVATE", str(result))

    def test_completed_flow_keeps_each_effect_receipt_but_no_content(self):
        from flower_control.drivers.app_flow import suppress_app_content
        original = {"state": "flow_completed", "steps": [
            {"receipt": {"id": "child", "state": "verified", "dispatched": True},
             "result": {"dispatched": True, "entries": [{"value": "FAKE-PRIVATE"}]}}],
            "result": {"state": "observed", "dispatched": False, "text": "FAKE-PRIVATE"}}
        result = suppress_app_content(original, "user_policy_requires_new_observation")
        self.assertIs(result["dispatched"], True)
        self.assertEqual(result["steps"][0]["receipt"]["id"], "child")
        self.assertNotIn("FAKE-PRIVATE", str(result))

    def test_unknown_input_is_preserved_after_late_revocation(self):
        from flower_control.drivers.app_flow import suppress_app_content
        result = suppress_app_content({"receipt": {"state": "outcome_uncertain", "dispatched": None}}, "revoked")
        self.assertEqual(result["state"], "outcome_uncertain")
        self.assertIsNone(result["dispatched"])


class WorkerPolicyTests(unittest.IsolatedAsyncioTestCase):
    async def test_final_return_checks_even_branch_does_not_check(self):
        value = permissions.default_policy(permissions.user_sid())
        async def unchecked(*args, **kwargs):
            value["Revision"] = "changed"
            return {"private_text": "must-not-return"}
        runtime = _Runtime(object())
        with patch.object(permissions.active_policy, "read", side_effect=lambda: dict(value)), \
             patch.object(runtime, "_execute", side_effect=unchecked):
            with self.assertRaisesRegex(ControlError, "user_policy_requires_new_observation"):
                await runtime.execute("read_text", {})

    async def test_worker_does_not_read_pages_when_identity_unknown_under_restrictions(self):
        value = permissions.default_policy(permissions.user_sid()); value["AdminWindows"] = False
        with patch.object(permissions.active_policy, "read", return_value=value):
            with self.assertRaisesRegex(ControlError, "browser_policy_identity_unavailable"):
                await _Runtime(object()).execute("list_pages", {})


if __name__ == "__main__": unittest.main()
