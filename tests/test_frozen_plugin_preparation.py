"""Offline plugin publication inputs; fake executable bytes are never run."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tools import prepare_frozen_plugin as delivery


class FrozenPluginPreparationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="flower-frozen-plugin-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.package, self.repository = self.root / "package", self.root / "repository"
        self.output = self.root / "local-plugin"
        self.version = "a" * 32
        self.staged = self.package / "versions" / self.version
        self.production = self.root / "program-files/FlowerControl/HighHelper"
        self.target = self.production / "versions" / self.version
        self.env = patch("flower_control.install_location.discover_installation",
                         return_value=SimpleNamespace(program_root=self.production, legacy=True))
        self.env.start()
        self.addCleanup(self.env.stop)
        for name in ("Flower.HighHelper.exe", "Flower.HighHelper.dll", "Flower.HighHelper.deps.json",
                     "Flower.HighHelper.runtimeconfig.json", "flower-python.exe", "flower-python._pth", "flower_bootstrap.py", "flower_hook_bootstrap.py",
                     "app/Flower.AppWorker.exe", "wgc/Flower.ComputerWgc.exe", "runtime/Lib/core.py"):
            self.put(self.staged / name, b"fixture only, never executed")
        registry = "WEB_TOOLS=('flower_web_run',)\nAPP_TOOLS=('flower_app_observe',)\nCOMPUTER_TOOLS=('flower_computer_input',)\n"
        self.put(self.staged / "python-source/flower_control/authorization/hook_bridge.py", registry.encode())
        self.put(self.staged / "python-source/hooks/pre_tool_use.py", b"# own fixed hook fixture\n")
        for name in ("flower_bootstrap.py", "flower_hook_bootstrap.py"):
            self.put(self.staged / "python-source/flower_control/drivers/high_helper" / name,
                     (self.staged / name).read_bytes())
        self.sources = {path.relative_to(self.staged / "python-source").as_posix(): delivery.digest(path)
                        for path in (self.staged / "python-source").rglob("*.py")}
        self.sources["@bootstrap"] = delivery.digest(self.staged / "flower_bootstrap.py")
        self.policy = {"Schema": 1, "Version": self.version, "Mode": "high", "DataRoot": str(self.root / "data"),
                       "Repository": str(self.target / "python-source"),
                       "Python": {"Path": str(self.target / "flower-python.exe"), "Sha256": delivery.digest(self.staged / "flower-python.exe")},
                       "AppWorkerHashes": {"Flower.AppWorker.exe": delivery.digest(self.staged / "app/Flower.AppWorker.exe")},
                       "WgcWorkerHashes": {"Flower.ComputerWgc.exe": delivery.digest(self.staged / "wgc/Flower.ComputerWgc.exe")},
                       "SourceHashes": self.sources}
        self.refresh()
        self.json(self.package / "preparation.json", {"version": self.version, "production_root": str(self.production),
                  "runtime_dependency_tree_fully_hash_pinned": True})
        self.entries = {"mcpServers": {channel: {"command": str(self.target / "Flower.HighHelper.exe"),
                        "args": ["--flower-client", channel], "cwd": str(self.target / "python-source")}
                        for channel in delivery.CHANNELS}}
        self.json(self.package / "mcp-entries.json", self.entries)
        matcher = "^mcp__(flower[-_]web__(flower_web_run)|flower[-_]app__(flower_app_observe)|flower[-_]computer__(flower_computer_input))$"
        command = delivery.hook_command(self.target / "flower-python.exe", str(self.target / "flower_hook_bootstrap.py"))
        self.hooks = {"hooks": {"PreToolUse": [{"matcher": matcher, "hooks": [{"type": "command", "command": command, "timeout": 5}]}],
            "UserPromptSubmit": [{"hooks": [{"type": "command", "command": delivery.hook_command(self.target / "Flower.HighHelper.exe", "--uac-host-event"), "timeout": 10}]}]}}
        self.json(self.package / "hooks-entries.json", self.hooks)
        self.metadata = {"name": "flower-control", "version": "0.1.0", "skills": "./skills/", "mcpServers": "./.mcp.json",
                         "interface": {"defaultPrompt": "preserve exact user prompt"}}
        self.json(self.repository / ".codex-plugin/plugin.json", self.metadata)
        for name in delivery.ASSETS:
            self.put(self.repository / name, b"own fixed asset fixture")
        for name in (".codex-plugin/plugin.json", *delivery.ASSETS):
            self.put(self.staged / "python-source" / name, (self.repository / name).read_bytes())
        site = self.target / "python-source/.venv/Lib/site-packages"
        self.put(self.staged / "flower-python._pth", ("\n".join(map(str, (self.target / "runtime/Lib", self.target / "runtime/DLLs", site,
                   site / "win32", site / "win32/lib", site / "pythonwin", self.target / "python-source"))) + "\n").encode())
        self.refresh()

    def put(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)

    def json(self, path, value):
        self.put(path, (json.dumps(value, indent=2) + "\n").encode())

    def refresh(self):
        nested = {path.relative_to(self.staged).as_posix(): delivery.digest(path)
                  for folder in ("runtime", "python-source") for path in (self.staged / folder).rglob("*") if path.is_file()}
        fingerprint = hashlib.sha256(json.dumps(nested, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.json(self.staged / "runtime-inventory.json", {"schema": 1, "files": nested,
                  "dependency_inventory_sha256": fingerprint, "downloads": False, "data_migrated": False})
        self.policy["RuntimeInventorySha256"] = delivery.digest(self.staged / "runtime-inventory.json")
        self.json(self.staged / "broker.json", self.policy)
        self.active = {"schema": 1, "version": self.version, "runtime_hashes": nested,
                       "hashes": {path.name: delivery.digest(path) for path in self.staged.iterdir()
                                  if path.is_file() and path.name != "installation.json"}}
        self.json(self.package / "active.json", self.active)
        self.json(self.staged / "installation.json", self.active)

    def prepare(self):
        return delivery.prepare(self.package, self.output)

    def test_matching_mcp_hook_source_and_assets_are_staged_without_publishing(self):
        report = self.prepare()
        metadata = delivery.read_json(self.output / ".codex-plugin/plugin.json")
        self.assertEqual(metadata["interface"], self.metadata["interface"])
        self.assertEqual(metadata["name"], "flower-control")
        self.assertEqual(metadata["version"], "0.1.0+codex." + self.version[:8])
        self.assertEqual(delivery.read_json(self.output / ".mcp.json"), self.entries)
        self.assertEqual(delivery.read_json(self.output / "hooks/hooks.json"), self.hooks)
        self.assertFalse(report["published"])
        self.assertFalse(report["installed"])
        self.assertFalse(report["host_injection_verified"])
        self.assertEqual(report["input_files"][".codex-plugin/plugin.json"],
                         delivery.digest(self.repository / ".codex-plugin/plugin.json"))
        self.assertEqual(delivery.read_json(self.repository / ".codex-plugin/plugin.json"), self.metadata)
        self.assertFalse(self.production.exists())

    def test_host_invalid_prompt_and_outside_icon_are_rejected_before_output(self):
        cases = (("prompt", "x" * 129), ("icon", "../outside.png"))
        for name, value in cases:
            with self.subTest(name=name):
                metadata = dict(self.metadata)
                metadata["interface"] = {"defaultPrompt": "short", "composerIcon": "./assets/branding/flower-control-icon.png"}
                if name == "prompt":
                    metadata["interface"]["defaultPrompt"] = value
                else:
                    metadata["interface"]["composerIcon"] = value
                self.json(self.repository / ".codex-plugin/plugin.json", metadata)
                self.put(self.staged / "python-source/.codex-plugin/plugin.json",
                         (self.repository / ".codex-plugin/plugin.json").read_bytes())
                self.refresh()
                output = self.root / ("invalid-" + name)
                with self.assertRaisesRegex(ValueError, "frozen_plugin_(?:default_prompt|icon_path)_invalid"):
                    delivery.prepare(self.package, output)
                self.assertFalse(output.exists())

    def test_unpackaged_icon_and_duplicate_build_version_are_rejected(self):
        self.put(self.repository / "assets/branding/flower-control-icon.ico", b"fixture not copied")
        metadata = {**self.metadata, "interface": {"defaultPrompt": "short",
                    "composerIcon": "./assets/branding/flower-control-icon.ico"}}
        self.json(self.repository / ".codex-plugin/plugin.json", metadata)
        self.put(self.staged / "python-source/.codex-plugin/plugin.json",
                 (self.repository / ".codex-plugin/plugin.json").read_bytes())
        self.refresh()
        with self.assertRaisesRegex(ValueError, "frozen_plugin_icon_asset_missing"):
            delivery.prepare(self.package, self.root / "unpackaged-icon")
        metadata["interface"]["composerIcon"] = "./assets/branding/flower-control-icon.png"
        metadata["version"] = "0.1.0+preview"
        self.json(self.repository / ".codex-plugin/plugin.json", metadata)
        self.put(self.staged / "python-source/.codex-plugin/plugin.json",
                 (self.repository / ".codex-plugin/plugin.json").read_bytes())
        self.refresh()
        with self.assertRaisesRegex(ValueError, "frozen_plugin_version_invalid"):
            delivery.prepare(self.package, self.root / "duplicate-build")

    def test_exact_legacy_launcher_requires_explicit_repair_and_preserves_runtime(self):
        self.hooks["hooks"]["PreToolUse"][0]["hooks"][0]["command"] = '"' + str(self.target / "flower-python.exe") + '" "' + str(self.target / "flower_hook_bootstrap.py") + '"'
        self.hooks["hooks"]["UserPromptSubmit"][0]["hooks"][0]["command"] = '"' + str(self.target / "Flower.HighHelper.exe") + '" --uac-host-event'
        self.json(self.package / "hooks-entries.json", self.hooks)
        with self.assertRaisesRegex(ValueError, "hook_binding_invalid"):
            self.prepare()
        active_hash = delivery.digest(self.package / "active.json")
        report = delivery.prepare(self.package, self.output, repair_legacy_hook_launcher=True)
        installed = delivery.read_json(self.output / "hooks/hooks.json")
        self.assertTrue(report["legacy_hook_launcher_repaired"])
        self.assertEqual(installed["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
            delivery.hook_command(self.target / "flower-python.exe", str(self.target / "flower_hook_bootstrap.py")))
        self.assertEqual(delivery.digest(self.package / "active.json"), active_hash)
        self.assertEqual(delivery.read_json(self.package / "hooks-entries.json"), self.hooks)

    def test_exact_fixed_browser_entry_is_sealed_without_allowing_other_tools(self):
        entry = "tools/open_flower_browser.py"
        self.put(self.staged / "python-source" / entry, b"# fixed browser entry fixture\n")
        self.policy["SourceHashes"][entry] = delivery.digest(self.staged / "python-source" / entry)
        self.refresh()
        self.assertFalse(self.prepare()["installed"])

    def test_fixed_browser_entry_still_requires_exact_source_hash_and_inventory(self):
        entry = "tools/open_flower_browser.py"
        self.put(self.staged / "python-source" / entry, b"# fixed browser entry fixture\n")
        self.refresh()
        with self.assertRaisesRegex(ValueError, "source_inventory_mismatch"):
            self.prepare()
        self.policy["SourceHashes"][entry] = "0" * 64
        self.refresh()
        with self.assertRaisesRegex(ValueError, "source_changed"):
            self.prepare()
        self.assertFalse(self.output.exists())

    def test_other_tool_source_remains_rejected_even_with_matching_hash(self):
        entry = "tools/another_entry.py"
        self.put(self.staged / "python-source" / entry, b"# not the admitted fixed entry\n")
        self.policy["SourceHashes"][entry] = delivery.digest(self.staged / "python-source" / entry)
        self.refresh()
        with self.assertRaisesRegex(ValueError, "source_changed"):
            self.prepare()
        self.assertFalse(self.output.exists())

    def test_legacy_repair_cannot_admit_added_shell_commands(self):
        self.hooks["hooks"]["PreToolUse"][0]["hooks"][0]["command"] += " & unexpected"
        self.json(self.package / "hooks-entries.json", self.hooks)
        with self.assertRaisesRegex(ValueError, "hook_binding_invalid"):
            delivery.prepare(self.package, self.output, repair_legacy_hook_launcher=True)
        self.assertFalse(self.output.exists())

    def test_moving_repository_or_stale_mcp_cwd_rejects_before_plugin_creation(self):
        self.entries["mcpServers"]["flower-app"]["cwd"] = str(self.repository)
        self.json(self.package / "mcp-entries.json", self.entries)
        with self.assertRaisesRegex(ValueError, "mcp_binding_invalid"):
            self.prepare()
        self.assertFalse(self.output.exists())

    def test_mutable_hook_command_or_wildcard_registry_rejects(self):
        row = self.hooks["hooks"]["PreToolUse"][0]
        row["matcher"] = "^mcp__(.*)$"
        self.json(self.package / "hooks-entries.json", self.hooks)
        with self.assertRaisesRegex(ValueError, "hook_registry_mismatch"):
            self.prepare()
        self.assertFalse(self.output.exists())
        row["hooks"][0]["command"] = str(self.repository / "hooks/pre_tool_use.py")
        self.json(self.package / "hooks-entries.json", self.hooks)
        with self.assertRaisesRegex(ValueError, "hook_binding_invalid"):
            self.prepare()

    def test_tampered_frozen_input_and_unlisted_companion_reject(self):
        (self.staged / "runtime/Lib/core.py").write_bytes(b"changed own input")
        with self.assertRaisesRegex(ValueError, "runtime_hash_mismatch"):
            self.prepare()
        self.refresh()
        self.put(self.staged / "wgc/unlisted.dll", b"unlisted fixture bytes")
        with self.assertRaisesRegex(ValueError, "runtime_inventory_mismatch"):
            self.prepare()
        self.assertFalse(self.output.exists())

    def test_extra_literal_hook_tool_is_not_admitted(self):
        row = self.hooks["hooks"]["PreToolUse"][0]
        row["matcher"] = row["matcher"].replace("flower_web_run", "flower_web_run|flower_web_unknown")
        self.json(self.package / "hooks-entries.json", self.hooks)
        with self.assertRaisesRegex(ValueError, "hook_registry_mismatch"):
            self.prepare()
        self.assertFalse(self.output.exists())

    def test_prompt_hook_requires_exact_sealed_native_entry(self):
        hook = self.hooks["hooks"]["UserPromptSubmit"][0]["hooks"][0]
        hook["command"] = str(self.repository / "hooks/uac_user_prompt.py")
        self.json(self.package / "hooks-entries.json", self.hooks)
        with self.assertRaisesRegex(ValueError, "hook_binding_invalid"):
            self.prepare()
        self.assertFalse(self.output.exists())

    def test_output_collision_never_overwrites_prior_files(self):
        self.output.mkdir()
        self.put(self.output / "sentinel", b"prior task work")
        with self.assertRaises(FileExistsError):
            self.prepare()
        self.assertEqual((self.output / "sentinel").read_bytes(), b"prior task work")

    def test_existing_preparation_sidecar_is_preserved_before_output_creation(self):
        sidecar = self.output.parent / (self.output.name + "-preparation.json")
        self.put(sidecar, b"prior task report")
        with self.assertRaises(FileExistsError):
            self.prepare()
        self.assertFalse(self.output.exists())
        self.assertEqual(sidecar.read_bytes(), b"prior task report")

    def test_protected_hook_and_bootstrap_must_match_frozen_source(self):
        for name in ("flower_bootstrap.py", "flower_hook_bootstrap.py"):
            with self.subTest(name=name):
                self.put(self.staged / name, b"other top protected copy")
                self.refresh()
                with self.assertRaisesRegex(ValueError, "bootstrap_changed|protected_source_binding_changed"):
                    self.prepare()
                self.put(self.staged / name, (self.staged / "python-source/flower_control/drivers/high_helper" / name).read_bytes())
                self.refresh()
        self.assertFalse(self.output.exists())

    def test_moving_assets_are_not_the_plugin_version_source(self):
        self.put(self.repository / delivery.ASSETS[0], b"later other task text")
        self.prepare()
        self.assertEqual((self.output / delivery.ASSETS[0]).read_bytes(), b"own fixed asset fixture")

    def test_later_copy_cannot_silently_change_an_earlier_output(self):
        original = delivery.shutil.copyfile
        def copy(source, target):
            result = original(source, target)
            if str(target).endswith("flower-control-icon.png"):
                (self.output / ".mcp.json").write_bytes(b"changed previously copied output")
            return result
        with patch.object(delivery.shutil, "copyfile", side_effect=copy):
            with self.assertRaisesRegex(ValueError, "prepared_output_changed"):
                self.prepare()
        self.assertFalse((self.output.parent / (self.output.name + "-preparation.json")).exists())


if __name__ == "__main__":
    unittest.main()
