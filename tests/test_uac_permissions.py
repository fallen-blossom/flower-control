"""UAC policy compatibility using only caller-owned temporary policy files."""
import hashlib
import json
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from flower_control import permissions

_legacy_spec = importlib.util.spec_from_file_location("legacy_schema1_reader", Path(__file__).parent / "fixtures/uac_permissions/legacy_schema1_reader.py")
legacy_reader = importlib.util.module_from_spec(_legacy_spec)
_legacy_spec.loader.exec_module(legacy_reader)


SID = "S-1-5-21-111-222-333-1001"


def application():
    return dict(Path="C:/Fixture/launcher.exe", IdentityKind="signed", Identity="a" * 64,
                DisplayName="Fixture launcher", Enabled=True, Arguments="")


class UacPermissionTests(unittest.TestCase):
    def setUp(self):
        self.directory = self.enterContext(tempfile.TemporaryDirectory(prefix="flower-uac-policy-"))
        self.path = Path(self.directory) / "policy.json"
        self.reader = permissions.PolicyReader(self.path, sid=SID, protection=False)
        self.policy = permissions.default_policy(SID)
        self.policy.pop("AuthorityTier")
        self.policy["AdminWindows"] = True  # Existing legacy record, not defaults.

    def read(self, value):
        raw = json.dumps(value, indent=2).encode()
        self.path.write_bytes(raw)
        result = self.reader.read()
        self.assertEqual(self.path.read_bytes(), raw)
        self.assertEqual(result["Revision"], hashlib.sha256(raw).hexdigest())
        return result

    def test_missing_policy_gets_ordinary_default_and_uac_off(self):
        value = self.reader.read()
        self.assertEqual(value["Schema"], 2)
        self.assertEqual(value["UacMode"], "off")
        self.assertEqual(value["UacAllowlist"], [])
        self.assertNotIn("UacEnabled", value)
        self.assertEqual((value["AdminWindows"], value["AdminScope"], value["JevEnabled"]), (False, "all", True))
        self.assertEqual(value["AuthorityTier"], 0)
        self.assertEqual((value["SmoothPointer"], value["HudCompact"], value["HudPosition"]), (False, False, "auto"))
        self.assertFalse(self.path.exists())

    def test_legacy_disabled_migrates_all_preferences_without_writing(self):
        old = dict(self.policy, Schema=1, UacEnabled=False, AdminWindows=False,
                   AdminScope="allowlist", JevEnabled=False, SmoothPointer=True,
                   HudCompact=True, HudPosition="bottom_right",
                   DeniedApplications=[dict(Path="C:/Fixture/private.exe", TitleContains="private", Enabled=True)],
                   AllowedAdminApplications=[dict(Path="C:/Fixture/editor.exe", TitleContains="", Enabled=False)],
                   Masks=[dict(Path="C:/Fixture/editor.exe", Rect=[1, 2, 30, 40], ClientSize=[100, 100], Enabled=True)])
        del old["UacMode"], old["UacAllowlist"]
        del old["AdminLaunchEnabled"], old["UacCancellationScope"], old["AdminLaunchAllowlist"]
        got = self.read(old)
        self.assertEqual((got["Schema"], got["UacMode"], got["UacAllowlist"]), (2, "off", []))
        self.assertNotIn("UacEnabled", got)
        for name in old.keys() - {"Schema", "UacEnabled", "Revision"}:
            self.assertEqual(got[name], old[name], name)

    def test_current_all_modes_round_trip_with_exact_revision(self):
        for mode in ("off", "observe", "cancel", "allowlist", "semantic"):
            with self.subTest(mode=mode):
                got = self.read(dict(self.policy, AdminLaunchEnabled=True, UacMode=mode, UacAllowlist=[application()]))
                self.assertEqual(got["UacMode"], mode)
                self.assertEqual(got["UacAllowlist"], [application()])

    def test_removed_full_access_reads_as_off_without_changing_original_bytes(self):
        got = self.read(dict(self.policy, UacMode="full", UacAllowlist=[application()], SmoothPointer=True))
        self.assertEqual(got["UacMode"], "off")
        self.assertTrue(got["SmoothPointer"])
        self.assertEqual(got["UacAllowlist"], [application()])

    def test_old_missing_and_null_arguments_are_preserved_but_disabled(self):
        for missing in (True, False):
            row = application()
            if missing:
                del row["Arguments"]
            else:
                row["Arguments"] = None
            got = self.read(dict(self.policy, UacMode="allowlist", UacAllowlist=[row]))
            self.assertEqual(got["UacAllowlist"], [dict(row, Enabled=False)])
            self.assertFalse(permissions.uac_allowlisted(got, application()))

    def test_arguments_are_exact_and_unknown_is_not_empty(self):
        row = dict(application(), Arguments='--profile "normal user"')
        for mode in ("allowlist",):
            policy = dict(self.policy, AdminLaunchEnabled=True, UacMode=mode, UacAllowlist=[row])
            self.assertTrue(permissions.uac_allowlisted(policy, row))
            for arguments in (None, "", '--profile "normal user" ', '--profile "other"'):
                self.assertFalse(permissions.uac_allowlisted(policy, dict(row, Arguments=arguments)))
        # Semantic authority is now first-class: matching the saved list alone
        # is not enough, a task-scoped grant must supply the next layer.
        semantic = dict(self.policy, AdminLaunchEnabled=True, UacMode="semantic", UacAllowlist=[row])
        self.assertFalse(permissions.uac_allowlisted(semantic, row))
        for arguments in ("*", "?", "bad\narg", "bad\x80arg", 1, "x" * 2049):
            with self.assertRaises(permissions.PermissionError):
                permissions.validate(dict(self.policy, UacAllowlist=[dict(row, Arguments=arguments)]))

    def test_optional_allowlist_is_empty(self):
        value = dict(self.policy, UacMode="semantic")
        del value["UacAllowlist"]
        self.assertEqual(self.read(value)["UacAllowlist"], [])

    def test_bad_schema_dual_authority_and_missing_fields_never_normalize_or_write(self):
        bad = [dict(self.policy, Schema=3), dict(self.policy, Schema=True),
               dict(self.policy, UacMode="accept"), dict(self.policy, UacEnabled=False),
               dict(self.policy, UacMode=False), dict(self.policy, UacAllowlist=None)]
        for field in self.policy.keys() - {"UacAllowlist", "AdminLaunchEnabled", "UacCancellationScope", "AdminLaunchAllowlist"}:
            value = dict(self.policy); del value[field]; bad.append(value)
        for value in bad:
            with self.subTest(value=value):
                raw = json.dumps(value).encode(); self.path.write_bytes(raw)
                with self.assertRaises(permissions.PermissionError): self.reader.read()
                self.assertEqual(self.path.read_bytes(), raw)

    def test_legacy_true_and_cross_user_are_rejected(self):
        old = dict(self.policy, Schema=1, UacEnabled=True)
        del old["UacMode"], old["UacAllowlist"]
        del old["AdminLaunchEnabled"], old["UacCancellationScope"], old["AdminLaunchAllowlist"]
        self.path.write_text(json.dumps(old))
        with self.assertRaisesRegex(permissions.PermissionError, "uac_component_unavailable"): self.reader.read()
        self.path.write_text(json.dumps(dict(self.policy, UserSid=SID + "9")))
        with self.assertRaisesRegex(permissions.PermissionError, "user_policy_identity_mismatch"): self.reader.read()

    def test_duplicate_nested_identity_is_rejected(self):
        self.path.write_text(json.dumps(dict(self.policy, UacAllowlist=[application()])).replace(
            '"IdentityKind": "signed"', '"IdentityKind": "signed", "IdentityKind": "sha256"'))
        with self.assertRaisesRegex(permissions.PermissionError, "user_policy_invalid"): self.reader.read()

    def test_uac_identity_is_not_a_title_or_publisher_name_rule(self):
        for changes in ({"IdentityKind": "publisher"}, {"Identity": "Microsoft Corporation"},
                        {"Identity": "A" * 64}, {"Identity": "a" * 63}, {"DisplayName": "bad\nname"},
                        {"Path": "launcher.exe"}, {"Path": "\\\\server\\share\\launcher.exe"},
                        {"Path": "C:/Fixture/launcher.exe:stream"}, {"TitleContains": "Fixture"}):
            row = application(); row.update(changes)
            with self.subTest(changes=changes), self.assertRaises(permissions.PermissionError):
                permissions.validate(dict(self.policy, UacAllowlist=[row]))

    def test_allowlist_and_semantic_match_complete_path_and_identity(self):
        actual = application(); row = application(); row["DisplayName"] = "A different display name"
        policy = dict(self.policy, AdminLaunchEnabled=True, UacMode="allowlist", UacAllowlist=[row])
        self.assertTrue(permissions.uac_allowlisted(policy, actual))
        self.assertFalse(permissions.uac_allowlisted(dict(policy, UacMode="semantic"), actual))
        case = dict(actual, Path="c:\\fixture\\LAUNCHER.EXE")
        self.assertTrue(permissions.uac_allowlisted(policy, case))
        for changed in (dict(actual, Path="C:/Other/launcher.exe"), dict(actual, Identity="b" * 64),
                        dict(actual, IdentityKind="sha256")):
            self.assertFalse(permissions.uac_allowlisted(policy, changed))
        policy["UacAllowlist"] = [dict(row, Enabled=False)]
        self.assertFalse(permissions.uac_allowlisted(policy, actual))

    def test_program_denial_precedes_uac_allowlist_even_when_title_is_not_yet_known(self):
        actual = application()
        policy = dict(self.policy, AdminLaunchEnabled=True, UacMode="allowlist", UacAllowlist=[actual])
        for title in ("", "future-private-window"):
            with self.subTest(title=title):
                deny = dict(Path="c:\\FIXTURE\\launcher.exe", TitleContains=title, Enabled=True)
                self.assertFalse(permissions.uac_allowlisted(dict(policy, DeniedApplications=[deny]), actual))
                self.assertTrue(permissions.uac_allowlisted(dict(policy, DeniedApplications=[dict(deny, Enabled=False)]), actual))
        unrelated = dict(Path="C:/Other/launcher.exe", TitleContains="", Enabled=True)
        self.assertTrue(permissions.uac_allowlisted(dict(policy, DeniedApplications=[unrelated]), actual))

    def test_off_cancel_and_full_do_not_consult_allowlist(self):
        class ForbiddenList:
            def __iter__(self): raise AssertionError("mode consulted allowlist")
        for mode in ("off", "cancel", "full"):
            self.assertFalse(permissions.uac_allowlisted(dict(self.policy, UacMode=mode, UacAllowlist=ForbiddenList()), application()))

    def test_allowlist_has_no_effect_on_administrator_denial_or_jev(self):
        policy = dict(self.policy, UacMode="full", AdminWindows=False, JevEnabled=False,
                      UacAllowlist=[application()], DeniedApplications=[dict(Path=application()["Path"], TitleContains="", Enabled=True)])
        with self.assertRaisesRegex(permissions.PermissionError, "window_disabled_by_user"):
            permissions.require_application(application()["Path"], integrity=12288, policy=policy)
        self.assertFalse(policy["JevEnabled"])

    def test_parent_switches_dominate_every_child_mode_without_rewriting(self):
        for master in (False, True):
            for launch in (False, True):
                for mode in ("off", "observe", "cancel", "allowlist", "semantic"):
                    with self.subTest(master=master, launch=launch, mode=mode):
                        got = self.read(dict(self.policy, AdminWindows=master, AdminLaunchEnabled=launch,
                                             UacMode=mode, UacAllowlist=[application()]))
                        expected = mode if master and launch else "off"
                        self.assertEqual(got["AdminLaunchEnabled"], master and launch)
                        self.assertEqual(got["UacMode"], expected)
                        self.assertEqual(permissions.uac_allowlisted(got, application()), expected == "allowlist")

    def test_startup_list_is_independent_and_never_borrows_uac_entries(self):
        uac = application()
        launch = dict(application(), Path="C:/Fixture/other.exe", Identity="b" * 64)
        got = self.read(dict(self.policy, AdminLaunchEnabled=True, UacMode="allowlist",
                             UacAllowlist=[uac], AdminLaunchAllowlist=[launch]))
        self.assertEqual(got["AdminLaunchAllowlist"], [launch])
        self.assertEqual(got["UacAllowlist"], [uac])
        self.assertFalse(permissions.uac_allowlisted(got, launch))
        old = dict(self.policy, AdminLaunchEnabled=True, UacMode="allowlist", UacAllowlist=[uac])
        old.pop("AdminLaunchAllowlist")
        self.assertEqual(self.read(old)["AdminLaunchAllowlist"], [])

    def test_launch_list_validates_even_when_parent_switch_is_off(self):
        for rows in (None, {}, [dict(application(), Enabled="true")], [dict(application(), TitleContains="same")]):
            with self.subTest(rows=rows):
                with self.assertRaises(permissions.PermissionError):
                    self.read(dict(self.policy, AdminWindows=False, AdminLaunchAllowlist=rows))


class CoexistingPolicyTests(unittest.TestCase):
    def setUp(self):
        self.directory = self.enterContext(tempfile.TemporaryDirectory(prefix="flower-policy-coexist-"))
        self.path = Path(self.directory) / (SID + ".json")
        self.uac_path = permissions.uac_policy_path(self.path)
        self.reader = permissions.PolicyReader(self.path, sid=SID, protection=False, uac_path=self.uac_path)
        self.common = permissions.default_policy(SID)
        self.common.pop("AuthorityTier")
        self.common.update(Schema=1, UacEnabled=False, AdminWindows=False, JevEnabled=False, SmoothPointer=True)
        del self.common["UacMode"], self.common["UacAllowlist"]
        del self.common["AdminLaunchEnabled"], self.common["UacCancellationScope"], self.common["AdminLaunchAllowlist"]
        self.raw = json.dumps(self.common, indent=2).encode()
        self.path.write_bytes(self.raw)

    def sidecar(self, **changes):
        value = dict(Schema=1, Revision="uac-fixture", UserSid=SID,
                     CommonRevision=hashlib.sha256(self.raw).hexdigest(), UacMode="allowlist", UacAllowlist=[application()])
        value.update(changes)
        raw = json.dumps(value, indent=2).encode(); self.uac_path.write_bytes(raw)
        return raw

    def test_uac_changes_keep_actual_legacy_reader_bytes_preferences_and_revision(self):
        old = legacy_reader.read(self.raw, SID)
        previous = self.reader.read()["Revision"]
        for mode in ("off", "cancel", "allowlist", "semantic", "off"):
            raw = self.sidecar(UacMode=mode)
            got = self.reader.read()
            self.assertEqual(got["UacMode"], "off")
            self.assertEqual(got["Revision"], permissions.storage_revision(self.raw, raw))
            self.assertNotEqual(got["Revision"], previous)
            self.assertEqual(self.path.read_bytes(), self.raw)
            self.assertEqual(legacy_reader.read(self.path.read_bytes(), SID), old)
            self.assertEqual((got["AdminWindows"], got["JevEnabled"], got["SmoothPointer"]), (False, False, True))
            previous = got["Revision"]

    def test_master_off_disables_all_children_and_preserves_common_bytes(self):
        for enabled in (False, True):
            for mode in ("off", "observe", "cancel", "allowlist", "semantic"):
                for scope in ("task", "selected_prompt_in_session"):
                    with self.subTest(enabled=enabled, mode=mode, scope=scope):
                        raw = self.sidecar(AdminLaunchEnabled=enabled, UacMode=mode, UacCancellationScope=scope)
                        got = self.reader.read()
                        self.assertEqual((got["AdminLaunchEnabled"], got["UacMode"], got["UacCancellationScope"]),
                                         (False, "off", scope))
                        self.assertEqual(self.path.read_bytes(), self.raw)
                        self.assertEqual(self.uac_path.read_bytes(), raw)
                        self.assertFalse(got["AdminWindows"])

    def test_old_sidecar_never_grants_new_launch_or_broader_cancellation(self):
        self.sidecar()
        got = self.reader.read()
        self.assertFalse(got["AdminLaunchEnabled"])
        self.assertEqual(got["UacCancellationScope"], "task")

    def test_malformed_new_fields_fail_closed_without_rewriting_common(self):
        for fields in ({"AdminLaunchEnabled": 1}, {"AdminLaunchEnabled": None},
                       {"UacCancellationScope": None}, {"UacCancellationScope": []},
                       {"UacCancellationScope": "all"}):
            with self.subTest(fields=fields):
                self.sidecar(**fields)
                got = self.reader.read()
                self.assertEqual((got["AdminLaunchEnabled"], got["UacMode"], got["UacCancellationScope"]),
                                 (False, "off", "task"))
                self.assertIn("UacPolicyError", got)
                self.assertEqual(self.path.read_bytes(), self.raw)

    def test_former_combined_schema2_write_is_rejected_by_frozen_daily_reader(self):
        with self.assertRaisesRegex(legacy_reader.PermissionError, "user_policy_invalid"):
            legacy_reader.read(json.dumps(permissions.default_policy(SID)).encode(), SID)

    def test_missing_sidecar_is_off_and_both_exact_byte_sequences_bind_revision(self):
        got = self.reader.read()
        self.assertEqual(got["UacMode"], "off")
        self.assertEqual(got["Revision"], permissions.storage_revision(self.raw, None))
        raw = self.sidecar()
        revision = self.reader.read()["Revision"]
        self.uac_path.write_bytes(raw + b"\n")
        self.assertNotEqual(self.reader.read()["Revision"], revision)
        self.path.write_bytes(self.raw + b"\n")
        got = self.reader.read()
        self.assertEqual((got["UacMode"], got["UacPolicyError"]), ("off", "uac_policy_common_changed"))
        self.assertEqual(got["Revision"], permissions.storage_revision(self.raw + b"\n", raw + b"\n"))

    def test_corrupt_cross_user_or_unrelated_fields_only_disable_uac(self):
        for raw in (b"{", self.sidecar(UserSid=SID + "9"), self.sidecar(AdminWindows=True), self.sidecar(Schema=True)):
            self.uac_path.write_bytes(raw)
            got = self.reader.read()
            self.assertEqual(got["UacMode"], "off")
            self.assertEqual(got["UacAllowlist"], [])
            self.assertIn("UacPolicyError", got)
            self.assertFalse(got["AdminWindows"])
            self.assertEqual(legacy_reader.read(self.path.read_bytes(), SID)["UacEnabled"], False)

    def test_unprotected_sidecar_only_disables_uac(self):
        original = self.reader._raw
        def read(path):
            if path == self.uac_path:
                raise permissions.PermissionError("user_policy_unprotected")
            return original(path)
        with patch.object(self.reader, "_raw", side_effect=read):
            got = self.reader.read()
        self.assertEqual((got["UacMode"], got["UacPolicyError"]), ("off", "user_policy_unprotected"))
        self.assertFalse(got["AdminWindows"])

    def test_mixed_snapshot_retries_and_never_lends_old_common_to_new_uac(self):
        self.sidecar()
        original = self.reader._raw
        changed = False
        def read(path):
            nonlocal changed
            raw = original(path)
            if path == self.uac_path and not changed:
                self.path.write_bytes(self.raw + b"\n")
                changed = True
            return raw
        with patch.object(self.reader, "_raw", side_effect=read):
            got = self.reader.read()
        self.assertEqual((got["UacMode"], got["UacPolicyError"]), ("off", "uac_policy_common_changed"))

    def test_continuously_changing_common_is_not_a_valid_snapshot(self):
        original = self.reader._raw
        def read(path):
            raw = original(path)
            if path == self.path:
                self.path.write_bytes(raw + b" ")
            return raw
        with patch.object(self.reader, "_raw", side_effect=read), self.assertRaisesRegex(permissions.PermissionError, "user_policy_unavailable"):
            self.reader.read()

    def test_old_combined_schema2_is_read_only_effective_off(self):
        combined = dict(permissions.default_policy(SID), UacMode="semantic", UacAllowlist=[application()])
        raw = json.dumps(combined).encode(); self.path.write_bytes(raw)
        got = self.reader.read()
        self.assertEqual((got["UacMode"], got["UacPolicyError"]), ("off", "user_policy_migration_required"))
        self.assertEqual(self.path.read_bytes(), raw)

    def test_sidecar_removed_full_and_missing_arguments_remain_non_authorizing(self):
        self.sidecar(UacMode="full")
        self.assertEqual(self.reader.read()["UacMode"], "off")
        row = application(); del row["Arguments"]
        self.sidecar(UacAllowlist=[row])
        self.assertFalse(permissions.uac_allowlisted(self.reader.read(), application()))

    def test_only_sidecar_with_absent_common_can_authorize_absent_defaults(self):
        self.path.unlink()
        self.sidecar(CommonRevision="absent", AdminLaunchEnabled=True, UacMode="cancel")
        got = self.reader.read()
        self.assertEqual(got["UacMode"], "cancel")
        self.assertTrue(got["AdminWindows"])
        self.assertFalse(self.path.exists())

    def test_absent_common_valid_old_sidecar_keeps_03_and_04_without_rewriting(self):
        self.path.unlink()
        for launch in (False, True):
            raw = self.sidecar(CommonRevision="absent", AdminLaunchEnabled=launch, UacMode="off")
            got = self.reader.read()
            self.assertEqual(got["AuthorityTier"], 2 if launch else 1)
            self.assertTrue(got["AdminWindows"])
            self.assertEqual(got["AdminLaunchEnabled"], launch)
            self.assertEqual(self.uac_path.read_bytes(), raw)
            self.assertFalse(self.path.exists())

    def test_absent_common_invalid_sidecar_and_explicit_off_never_gain_admin(self):
        self.path.unlink()
        for changes in (dict(CommonRevision="absent", UserSid=SID + "9"), dict(CommonRevision="f" * 64),
                        dict(CommonRevision="absent", AuthorityTier=0)):
            self.sidecar(AdminLaunchEnabled=True, UacMode="off", **changes)
            got = self.reader.read()
            self.assertEqual(got["AuthorityTier"], 0)
            self.assertFalse(got["AdminWindows"])
            self.assertFalse(got["AdminLaunchEnabled"])


if __name__ == "__main__":
    unittest.main()
