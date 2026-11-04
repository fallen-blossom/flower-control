import json
from pathlib import Path
import tempfile
import unittest
import subprocess
import sys

from flower_control.install_location import prepare_location
from tools import settings_portability as portable

SID = "S-1-5-21-1-2-3-1001"


class SettingsPortabilityTests(unittest.TestCase):
    def fixture(self, root):
        install = prepare_location(Path(root) / "install", SID)
        policy = install.program_root / "permissions" / (SID + ".json")
        policy.parent.mkdir(parents=True)
        install.data_root.mkdir()
        policy.write_text(json.dumps(dict(Schema=2, UserSid=SID, AuthorityTier=2, AdminWindows=True,
            SemanticDelegation={"Id": "live grant"}, HudPosition="bottom_right", HudCompact=True,
            DeniedApplications=[dict(Path="C:/Windows/private.exe", TitleContains="Private", Enabled=True)],
            AllowedAdminApplications=[dict(Path="C:/Windows/admin.exe", TitleContains="", Enabled=True)],
            ApiKey="do-not-export")))
        policy.with_suffix(".uac.json").write_text(json.dumps(dict(AuthorityTier=2, AdminLaunchEnabled=True,
            AdminLaunchAllowlist=[dict(Path="C:/Windows/admin.exe", IdentityKind="sha256", Identity="a" * 64,
                DisplayName="Local admin program", Enabled=True, Arguments="--password do-not-export")])))
        (install.data_root / "browser-preferences.json").write_text(json.dumps(dict(schema=1, default_browser="system")))
        (install.data_root / "display-preferences.json").write_text(json.dumps(dict(schema=1, language="en")))
        return install

    def test_export_is_portable_redacted_and_never_restores_allow_rule(self):
        with tempfile.TemporaryDirectory(prefix="flower-settings-backup-") as temporary:
            install = self.fixture(temporary)
            value = portable.export_document(install)
            text = json.dumps(value)
            self.assertNotIn("do-not-export", text)
            self.assertNotIn(SID, text)
            self.assertNotIn("SemanticDelegation", text)
            self.assertFalse(value["settings"]["AllowedAdminApplications"][0]["Enabled"])
            self.assertFalse(value["settings"]["AdminLaunchAllowlist"][0]["Enabled"])
            self.assertEqual(value["settings"]["AdminLaunchAllowlist"][0]["Arguments"], "")
            self.assertTrue(value["settings"]["DeniedApplications"][0]["Enabled"])
            self.assertEqual(value["preferences"], {"default_browser": "system", "language": "en"})
            self.assertEqual(value["fixed_shortcuts"]["computer_stop"], "Ctrl+Alt+9")
            self.assertEqual(value["fixed_shortcuts"]["global_stop"], "Ctrl+Alt+Shift+9")
            restored = portable.validate_portable(value)
            self.assertEqual(restored, value)

    def test_import_rejects_authority_or_extra_secret_fields_and_disables_forged_allow(self):
        with tempfile.TemporaryDirectory(prefix="flower-settings-import-") as temporary:
            value = portable.export_document(self.fixture(temporary))
            row = value["settings"]["AdminLaunchAllowlist"][0]
            row["Enabled"] = True
            row["Arguments"] = "--token hidden"
            imported = portable.validate_portable(value)
            self.assertFalse(imported["settings"]["AdminLaunchAllowlist"][0]["Enabled"])
            self.assertEqual(imported["settings"]["AdminLaunchAllowlist"][0]["Arguments"], "")
            for field in ("AuthorityTier", "AdminLaunchEnabled", "SemanticDelegation", "ApiKey"):
                broken = {**value, "settings": {**value["settings"], field: 2}}
                with self.subTest(field=field), self.assertRaises(ValueError):
                    portable.validate_portable(broken)

    def test_new_output_preserves_existing_file_and_rejects_junction(self):
        import _winapi
        with tempfile.TemporaryDirectory(prefix="flower-settings-write-") as temporary:
            root = Path(temporary)
            output = root / "keep.json"
            output.write_text("keep")
            with self.assertRaises(FileExistsError):
                portable.write_new(output, {})
            self.assertEqual(output.read_text(), "keep")
            target = root / "target"
            target.mkdir()
            _winapi.CreateJunction(str(target), str(root / "alias"))
            with self.assertRaisesRegex(ValueError, "link_rejected"):
                portable.write_new(root / "alias" / "backup.json", {})

    def test_review_cli_has_private_exact_receipt_and_no_settings_side_effect(self):
        with tempfile.TemporaryDirectory(prefix="flower-settings-cli-") as temporary:
            root = Path(temporary)
            install = self.fixture(temporary)
            source = portable.write_new(root / "backup.json", portable.export_document(install))
            before = (install.program_root / "permissions" / (SID + ".json")).read_bytes()
            receipt = root / "result.json"
            output = root / "review.json"
            result = subprocess.run([sys.executable, str(Path(portable.__file__)), "review", "--input", str(source),
                "--output", str(output), "--request-id", "a" * 32, "--result-path", str(receipt)],
                capture_output=True, text=True, check=True)
            self.assertEqual(result.stdout, "")
            value = json.loads(receipt.read_text())
            self.assertEqual(value["request_id"], "a" * 32)
            self.assertEqual(value["state"], "completed")
            self.assertFalse(value["result"]["settings_applied"])
            self.assertEqual((install.program_root / "permissions" / (SID + ".json")).read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
