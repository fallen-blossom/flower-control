import hashlib
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
import zipfile
from types import SimpleNamespace
from unittest.mock import patch

from tools.offline_install import verify_payload, safe_payload_name, resume_operations, load_resume, render_setup_wrapper
from tools.offline_release import tool_closure, locked_versions, validate_release_versions, verified_encoder_materials, PROJECTS


class OfflinePayloadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="flower-offline-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "Source").mkdir()
        (self.root / "Source/main.py").write_text("raise RuntimeError('must never execute')", encoding="utf-8")
        self.manifest = dict(schema=1, generic=True, platform="win-x64", release_version="0.1.0", files={
            "Source/main.py": hashlib.sha256((self.root / "Source/main.py").read_bytes()).hexdigest()})
        self.write()

    def write(self):
        (self.root / "payload.json").write_text(json.dumps(self.manifest), encoding="utf-8")

    def test_verify_never_executes_candidate_source(self):
        self.assertEqual(verify_payload(self.root)["platform"], "win-x64")

    def test_tampered_and_unlisted_sources_rejected(self):
        (self.root / "Source/main.py").write_text("changed", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "offline_payload_changed"):
            verify_payload(self.root)
        self.manifest["files"]["Source/main.py"] = hashlib.sha256(b"changed").hexdigest()
        self.write()
        (self.root / "Source/extra.py").write_text("unlisted", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "offline_payload_inventory_changed"):
            verify_payload(self.root)

    def test_windows_ambiguous_and_escape_names_rejected(self):
        for name in ("../escape", "C:/absolute", "/root", "a\\b", "a//b", "a./b", "a /b", "a/CON.txt", "a:ads", "a\x00b"):
            with self.subTest(name=name):
                self.assertFalse(safe_payload_name(name))
                self.manifest["files"] = {name: "a" * 64}
                self.write()
                with self.assertRaisesRegex(ValueError, "offline_payload_path_invalid"):
                    verify_payload(self.root)

    def test_duplicate_manifest_keys_rejected(self):
        (self.root / "payload.json").write_text('{"schema":1,"schema":1}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "offline_duplicate_key"):
            verify_payload(self.root)

    def test_generic_payload_has_no_recipient_authority(self):
        self.manifest["generic"] = False
        self.write()
        with self.assertRaisesRegex(ValueError, "offline_payload_manifest_invalid"):
            verify_payload(self.root)

    def test_release_label_is_required_and_is_not_a_runtime_content_identity(self):
        for version in (None, True, "", "a" * 32, "0.1", "0.1.0\nrun code", "0.1.0';write-host injected"):
            with self.subTest(version=version):
                self.manifest["release_version"] = version
                self.write()
                with self.assertRaisesRegex(ValueError, "offline_release_version_invalid"):
                    verify_payload(self.root)

    def test_registered_data_and_artifacts_follow_selected_root(self):
        from flower_control.data_paths import resolve_data_root, runtime_temp_root, DataPathError
        from flower_control.drivers.web_artifacts import artifact_path
        root = self.root / "FlowerControl"
        cache, data = root / "Cache", root / "Data"
        cache.mkdir(parents=True); data.mkdir()
        location = SimpleNamespace(legacy=False, data_root=data, cache_root=cache)
        with patch("flower_control.install_location.discover_installation", return_value=location):
            self.assertEqual(runtime_temp_root(), cache)
            self.assertEqual(resolve_data_root({"LOCALAPPDATA": str(self.root / "unrelated")}), data)
            self.assertEqual(artifact_path(None, suffix=".png").parent, cache / "flower-web-artifacts")
            with self.assertRaisesRegex(DataPathError, "registered_data_root_mismatch"):
                resolve_data_root({"FLOWER_DATA_ROOT": str(self.root / "wrong")})


class EncoderMaterialTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="flower-encoder-materials-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.media = self.root / "media"
        self.media.mkdir()
        self.encoder = self.media / "ffmpeg.exe"
        self.encoder.write_bytes(b"fixture: never execute")
        self.policy = dict(schema=1, name="FFmpeg", version="test-minimal-1", license="GPL-3.0-or-later",
            sha256=self.sha(self.encoder), build_inputs_verified=True,
            corresponding_source_review=dict(state="materials_verified"))
        for key, name in (("license_file", "LICENSE"), ("notices", "NOTICE.txt")):
            path = self.media / name
            path.write_text("original fixture " + name, encoding="utf-8")
            self.policy[key] = dict(path=name, sha256=self.sha(path))
        for key, name in (("inputs_lock", "tools/encoder_build/inputs.lock.json"),
                          ("recipe", "tools/encoder_build/build.sh")):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture " + key, encoding="utf-8")
            self.policy[key] = dict(path=name, sha256=self.sha(path))
        self.index = dict(schema=1, encoder_version=self.policy["version"],
            binary_hashes={"ffmpeg.exe": self.policy["sha256"]},
            public_input_lock_sha256=self.policy["inputs_lock"]["sha256"],
            recipe_sha256=self.policy["recipe"]["sha256"])
        self.write_source()

    @staticmethod
    def sha(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def write_source(self):
        path = self.media / "corresponding-source.zip"
        with zipfile.ZipFile(path, "w") as bundle:
            bundle.writestr("source-index.json", json.dumps(self.index))
        self.policy["corresponding_source"] = dict(artifact=path.name, sha256=self.sha(path))
        self.write_policy()

    def write_policy(self):
        (self.root / "ENCODER.json").write_text(json.dumps(self.policy), encoding="utf-8")

    def test_reviewed_material_inventory_is_bound_without_executing_binary(self):
        policy, materials = verified_encoder_materials(self.root, self.encoder)
        self.assertEqual(policy, self.policy)
        self.assertEqual(set(materials), {"ENCODER.json", "LICENSE", "NOTICE.txt", "corresponding-source.zip"})

    def test_changed_binary_notice_source_or_recipe_is_rejected(self):
        paths = [self.encoder, self.media / "LICENSE", self.media / "NOTICE.txt",
                 self.media / "corresponding-source.zip", self.root / self.policy["recipe"]["path"],
                 self.root / self.policy["inputs_lock"]["path"]]
        for path in paths:
            with self.subTest(path=path.name):
                original = path.read_bytes()
                path.write_bytes(original + b"changed")
                try:
                    with self.assertRaisesRegex(ValueError, "offline_encoder_material_changed"):
                        verified_encoder_materials(self.root, self.encoder)
                finally:
                    path.write_bytes(original)

    def test_source_with_valid_outer_hash_but_other_binary_binding_is_rejected(self):
        self.index["binary_hashes"]["ffmpeg.exe"] = "0" * 64
        self.write_source()
        with self.assertRaisesRegex(ValueError, "offline_encoder_source_binary_binding_changed"):
            verified_encoder_materials(self.root, self.encoder)

    def test_public_presentation_cannot_disagree_with_private_build_pin(self):
        presentation = self.root / "release/github/ENCODER.json"
        presentation.parent.mkdir(parents=True)
        presentation.write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "offline_encoder_presentation_pin_changed"):
            verified_encoder_materials(self.root, self.encoder)

    def test_corresponding_source_cannot_escape_material_directory(self):
        self.policy["corresponding_source"]["artifact"] = "../corresponding-source.zip"
        self.write_policy()
        with self.assertRaisesRegex(ValueError, "offline_encoder_source_name_rejected"):
            verified_encoder_materials(self.root, self.encoder)


class ReleaseVersionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="flower-release-version-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "VERSION").write_text("0.1.0\n", encoding="ascii")
        (self.root / ".codex-plugin").mkdir()
        (self.root / ".codex-plugin/plugin.json").write_text('{"version":"0.1.0"}', encoding="utf-8")
        (self.root / "pyproject.toml").write_text('[project]\nversion="0.1.0"\n', encoding="utf-8")
        for project in (*PROJECTS.values(), "tools/installer/FlowerControl.Setup.csproj"):
            path = self.root / project
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('<Project><PropertyGroup><Version>0.1.0</Version><FileVersion>0.1.0.0</FileVersion>'
                '<AssemblyVersion>0.1.0.0</AssemblyVersion><InformationalVersion>0.1.0</InformationalVersion>'
                '</PropertyGroup></Project>', encoding="utf-8")
        for name in ("tools/installer/setup.manifest", "flower_control/drivers/high_helper/app.manifest"):
            (self.root / name).write_text('<assembly xmlns="urn:schemas-microsoft-com:asm.v1">'
                '<assemblyIdentity version="0.1.0.0" /></assembly>', encoding="utf-8")

    def test_actual_repository_and_public_layout_compile_the_same_release_label(self):
        self.assertEqual(validate_release_versions(Path(__file__).resolve().parents[1]), "0.1.0")
        self.assertEqual(validate_release_versions(self.root), "0.1.0")

    def test_stale_plugin_or_windows_file_version_blocks_build(self):
        plugin = self.root / ".codex-plugin/plugin.json"
        plugin.write_text('{"version":"0.1.0-preview.4"}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "metadata_version_mismatch"):
            validate_release_versions(self.root)
        plugin.write_text('{"version":"0.1.0"}', encoding="utf-8")
        project = self.root / PROJECTS["native"]
        project.write_text(project.read_text().replace('<FileVersion>0.1.0.0', '<FileVersion>1.0.0.0'), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "project_version_mismatch"):
            validate_release_versions(self.root)

    def test_arp_shows_release_version_while_runtime_paths_keep_content_identity(self):
        package = self.root / "Package"
        package.mkdir()
        (package / "InstallCommon.ps1").write_text("# Read-only render fixture\n", encoding="utf-8")
        (package / "installation-location.request.json").write_text(json.dumps(dict(
            installation_id="b" * 32, user_sid="S-1-5-21-1-2-3-1001")), encoding="utf-8")
        runtime = "a" * 32
        root = self.root / "Installed"
        plan = dict(legacy=False, kind="install", operation_id="c" * 32, root=str(root),
            program_root=str(root / "Program"), release_version="0.1.0", version=runtime, adapters=[], guide_files=[],
            elevated_script=str(self.root / "Child.ps1"), elevated_script_sha256="d" * 64,
            maintenance_source=str(self.root / "Setup.exe"), maintenance_sha256="e" * 64)
        script = render_setup_wrapper(plan, package, root / "Packages")
        self.assertIn("$entry.SetValue('DisplayVersion','0.1.0')", script)
        self.assertNotIn("$entry.SetValue('DisplayVersion','" + runtime + "')", script)
        self.assertIn(str(root / "Packages" / (runtime + "-" + "e" * 12)), script)
        self.assertEqual(plan["version"], runtime)


class MarketplaceTransitionTests(unittest.TestCase):
    def run_case(self, initial, *, remove_failure=False, add_failure=False, lost_add_reply=False,
                 foreign_after_add=False):
        from tools.offline_install import switch_owned_marketplace
        import subprocess
        current = initial
        mutations = []
        def invoke(cli, args):
            nonlocal current
            self.assertEqual(cli, "official-cli")
            verb = args[2]
            if verb == "list":
                return SimpleNamespace(stdout=json.dumps({"marketplaces": [] if current is None else
                    [{"name": "flower-control-local", "root": current}]}))
            mutations.append(args)
            if verb == "remove":
                if remove_failure:
                    raise subprocess.CalledProcessError(1, args)
                current = None
            elif verb == "add":
                if args[3] == "new" and add_failure:
                    if foreign_after_add: current = "foreign"
                    raise subprocess.CalledProcessError(1, args)
                current = args[3]
                if lost_add_reply and current == "new":
                    raise subprocess.TimeoutExpired(args, 1)
            else:
                self.fail("Unexpected CLI action")
            return SimpleNamespace(stdout="{}")
        with patch("tools.prepare_uninstall.run_official_cli", side_effect=invoke):
            result = switch_owned_marketplace("official-cli", {"selector": "flower-control-local", "source": "new"}, {Path("old"), Path("new")})
        self.assertFalse(result["hook_trust_granted"])
        self.assertFalse(result["host_injection_verified"])
        return result, mutations, current

    def test_owned_upgrade_removes_reads_and_adds_once(self):
        result, writes, current = self.run_case("old")
        self.assertEqual(result["state"], "marketplace_registered")
        self.assertEqual([row[2] for row in writes], ["remove", "add"])
        self.assertEqual(current, "new")

    def test_registered_or_foreign_source_never_removed(self):
        for source, state in (("new", "marketplace_registered"), ("foreign", "existing_source_requires_review")):
            with self.subTest(source=source):
                result, writes, _ = self.run_case(source)
                self.assertEqual(result["state"], state)
                self.assertEqual(writes, [])

    def test_failed_removal_does_not_attempt_add(self):
        result, writes, current = self.run_case("old", remove_failure=True)
        self.assertEqual((result["state"], current), ("removal_unconfirmed", "old"))
        self.assertEqual([row[2] for row in writes], ["remove"])

    def test_lost_add_reply_observes_effect_without_replay(self):
        result, writes, current = self.run_case("old", lost_add_reply=True)
        self.assertEqual((result["state"], current), ("marketplace_registered", "new"))
        self.assertEqual([row[2] for row in writes], ["remove", "add"])

    def test_failed_new_source_restores_only_when_absent(self):
        result, writes, current = self.run_case("old", add_failure=True)
        self.assertEqual((result["state"], current), ("previous_source_restored", "old"))
        self.assertEqual([row[3] for row in writes if row[2] == "add"], ["new", "old"])
        result, writes, current = self.run_case("old", add_failure=True, foreign_after_add=True)
        self.assertEqual((result["state"], current), ("registration_unconfirmed", "foreign"))
        self.assertEqual([row[3] for row in writes if row[2] == "add"], ["new"])


class ProtectedResumeBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="flower-resume-bind-")
        self.addCleanup(self.temp.cleanup)
        from flower_control.install_location import prepare_location
        self.location = replace(prepare_location(Path(self.temp.name) / "FlowerControl", user_sid="S-1-5-21-1-2-3-1001"), installation_id="b" * 32)
        self.operation = "a" * 32
        recovery = self.location.program_root / "recovery" / ("installation-" + self.operation)
        recovery.mkdir(parents=True)
        self.script = Path(self.temp.name) / "ApplySetup.ps1"
        self.script.write_bytes(b"throw 'must never execute during discovery'")
        sha = hashlib.sha256(self.script.read_bytes()).hexdigest()
        self.plan = Path(self.temp.name) / "setup-plan.json"
        self.plan.write_text(json.dumps(dict(operation_id=self.operation, root=str(self.location.root),
            program_root=str(self.location.program_root), version="c" * 32,
            elevated_script=str(self.script), elevated_script_sha256=sha)), encoding="utf-8")
        self.anchor = dict(schema=1, kind="setup", state="incomplete", operation_id=self.operation,
            root=str(self.location.root), program_root=str(self.location.program_root),
            user_sid=self.location.user_sid, installation_id=self.location.installation_id,
            machine_binding_sha256="d" * 64, plan_path=str(self.plan),
            plan_sha256=hashlib.sha256(self.plan.read_bytes()).hexdigest(), script_path=str(self.script), script_sha256=sha)
        self.anchor_path = recovery / "resume-anchor.json"
        self.write_anchor()
        for target, arguments in (
            ("flower_control.permissions._check_protection", {"return_value": None}),
            ("tools.offline_install.machine_binding", {"return_value": "d" * 64}),
            ("flower_control.install_location.discover_installation", {"return_value": self.location}),
        ):
            mocked = patch(target, **arguments)
            mocked.start(); self.addCleanup(mocked.stop)

    def write_anchor(self):
        self.anchor_path.write_text(json.dumps(self.anchor), encoding="utf-8")

    def test_restores_only_original_plan_and_script_bytes(self):
        self.assertTrue(resume_operations(self.location)[0]["materials_verified"])
        original = load_resume(self.operation, "setup")
        self.assertEqual(original["elevated_script"], str(self.script))
        self.script.write_bytes(b"changed")
        self.assertFalse(resume_operations(self.location)[0]["materials_verified"])
        with self.assertRaisesRegex(ValueError, "offline_original_resume_material_required"):
            load_resume(self.operation, "setup")

    def test_reinstall_keeps_obsolete_receipt_without_resuming_it(self):
        self.anchor["installation_id"] = "e" * 32
        self.write_anchor()
        before = self.anchor_path.read_bytes()
        self.assertEqual(resume_operations(self.location), [])
        self.assertEqual(self.anchor_path.read_bytes(), before)

    def test_cross_machine_resume_rejected_without_writes(self):
        self.anchor["machine_binding_sha256"] = "f" * 64
        self.write_anchor()
        with self.assertRaisesRegex(ValueError, "offline_resume_machine_changed"):
            resume_operations(self.location)


if __name__ == "__main__":
    unittest.main()
