"""Recipient configuration checks without installing a plugin or helper."""
from __future__ import annotations

import ctypes
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class PublicPluginConfigurationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="flower-public-config-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "source with spaces"
        self.root.mkdir()
        spec = importlib.util.spec_from_file_location("recipient_config", ROOT / "tools/configure_local_plugin.py")
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.module.ROOT = self.root
        for name, data in {
            ".venv/Scripts/python.exe": b"not executed",
            "hooks/pre_tool_use.py": b"not executed",
            "assets/branding/flower-petal/flower-petal-256.png": b"copied only",
            "hooks/hooks.template.json": json.dumps({"hooks": {"PreToolUse": [{"matcher": "flower-test", "hooks": [{"type": "command", "command": "__RECIPIENT_PYTHON_AND_HOOK__", "timeout": 5}]}]}}).encode(),
        }.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.package = Path(temporary.name) / "package"
        self.package.mkdir()
        self.output = Path(temporary.name) / "marketplace"
        production = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "FlowerControl/HighHelper"
        self.preparation = {"schema": 1, "version": "a" * 32, "source_root": str(self.root), "production_root": str(production), "installed": False}
        self.entries = {"mcpServers": {channel: {"command": str(production / "versions" / ("a" * 32) / "Flower.HighHelper.exe"), "args": ["--flower-client", channel], "cwd": str(self.root)} for channel in self.module.CHANNELS}}

    def run_configuration(self):
        (self.package / "preparation.json").write_text(json.dumps(self.preparation))
        (self.package / "mcp-entries.json").write_text(json.dumps(self.entries))
        return self.module.configure(self.package, self.output)

    def test_space_paths_roundtrip_native_windows_parser_and_no_trust_grant(self):
        result = self.run_configuration()
        self.assertFalse(result["installed"])
        self.assertFalse(result["hook_trust_granted"])
        plugin = self.output / "plugins/flower-control"
        hooks = json.loads((plugin / "hooks/hooks.json").read_bytes())
        command = hooks["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        parse = ctypes.WinDLL("shell32").CommandLineToArgvW
        parse.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_int)]
        parse.restype = ctypes.POINTER(ctypes.c_wchar_p)
        count = ctypes.c_int()
        arguments = parse(command, ctypes.byref(count))
        free = ctypes.WinDLL("kernel32").LocalFree
        free.argtypes = [ctypes.c_void_p]
        free.restype = ctypes.c_void_p
        try:
            self.assertEqual([arguments[i] for i in range(count.value)], [str(self.root / ".venv/Scripts/python.exe"), "-B", str(self.root / "hooks/pre_tool_use.py")])
        finally:
            free(arguments)
        self.assertEqual(json.loads((plugin / ".mcp.json").read_bytes()), self.entries)

    def test_other_source_rejected_before_output(self):
        self.preparation["source_root"] = str(self.root.parent)
        with self.assertRaisesRegex(ValueError, "this_source"):
            self.run_configuration()
        self.assertFalse(self.output.exists())

    def test_arbitrary_executable_and_extra_channel_rejected_before_output(self):
        for mutation in ("command", "channel"):
            with self.subTest(mutation=mutation):
                saved = json.loads(json.dumps(self.entries))
                if mutation == "command":
                    self.entries["mcpServers"]["flower-web"]["command"] = str(self.root / "other.exe")
                else:
                    self.entries["mcpServers"]["other"] = self.entries["mcpServers"]["flower-web"]
                with self.assertRaises(ValueError):
                    self.run_configuration()
                self.assertFalse(self.output.exists())
                self.entries = saved

    def test_existing_output_preserved(self):
        self.output.mkdir()
        sentinel = self.output / "keep.txt"
        sentinel.write_text("retain")
        with self.assertRaises(ValueError):
            self.run_configuration()
        self.assertEqual(sentinel.read_text(), "retain")

    def test_frozen_runtime_uses_sealed_plugin_without_source_venv(self):
        self.preparation["runtime_dependency_tree_fully_hash_pinned"] = True
        self.preparation["source_root"] = str(self.root / "old preparation source")
        production = Path(self.preparation["production_root"])
        installed_source = production / "versions" / self.preparation["version"] / "python-source"
        for entry in self.entries["mcpServers"].values():
            entry["cwd"] = str(installed_source)
        def sealed_plugin(package, output):
            output.mkdir(parents=True)
            (output / "sealed-skill-and-hooks.txt").write_text("sealed package contract")
        with patch("tools.prepare_frozen_plugin.prepare", side_effect=sealed_plugin) as prepare:
            result = self.run_configuration()
        prepare.assert_called_once_with(self.package, self.output / "plugins/flower-control")
        self.assertTrue(result["frozen_runtime"])
        self.assertFalse(result["installed"])
        self.assertTrue((self.output / ".agents/plugins/marketplace.json").is_file())


if __name__ == "__main__":
    unittest.main()
