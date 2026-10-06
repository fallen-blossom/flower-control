"""Recipient config generation with owned fixture packages, no client startup."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from release.github.tools.configure_connection_mcp import configure, CLIENT_IMAGES
from release.github.tools.configure_claude_plugin import CHANNELS, write_json


class ConnectionConfigurationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="flower-client-config-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / "source"
        self.root.mkdir()
        self.package = self.base / "package"
        self.version = "a" * 32
        self.production = self.base / "ProgramFiles/FlowerControl/HighHelper"
        self.enterContext(patch.dict(os.environ, {"ProgramFiles": str(self.base / "ProgramFiles")}))

    def prepared(self, client):
        image = next(iter(CLIENT_IMAGES[client]))
        kind = "antigravity" if client == "antigravity" else "local-mcp"
        hosts = [{"Kind": kind, "Path": str(self.base / image), "Sha256": "b" * 64}]
        policy = {"Version": self.version, "Repository": str(self.root), "NativeHosts": hosts}
        write_json(self.package / "versions" / self.version / "broker.json", policy)
        write_json(self.package / "preparation.json", {"schema": 1, "version": self.version, "source_root": str(self.root),
            "production_root": str(self.production), "installed": False, "native_hosts": hosts})
        helper = self.production / "versions" / self.version / "Flower.HighHelper.exe"
        write_json(self.package / "mcp-entries.json", {"mcpServers": {channel: {
            "command": str(helper), "args": ["--flower-client", channel], "cwd": str(self.root)} for channel in CHANNELS}})

    def test_each_native_client_gets_its_format_and_explicit_connection_flag(self):
        for client in CLIENT_IMAGES:
            with self.subTest(client=client):
                self.prepared(client)
                output = self.base / client
                record = configure(self.package, output, self.root, client=client)
                self.assertFalse(record["installed"])
                self.assertFalse(record["client_tested"])
                self.assertFalse(record["personal_browser_supported"])
                config = next(p for p in output.rglob("*.json") if p.name != "configuration.json")
                value = json.loads(config.read_text(encoding="utf-8"))
                entries = value.get("mcpServers", value.get("servers", value.get("mcp")))
                if client == "opencode-v2":
                    entries = entries["servers"]
                self.assertEqual(set(entries), set(CHANNELS))
                for channel, entry in entries.items():
                    args = entry.get("args", entry["command"][1:] if isinstance(entry["command"], list) else [])
                    self.assertEqual(args, ["--flower-connection-client", channel])

    def test_wrong_native_host_rejected_and_existing_output_preserved(self):
        self.prepared("cursor")
        with self.assertRaisesRegex(ValueError, "specific_client_not_pinned"):
            configure(self.package, self.base / "wrong", self.root, client="vscode")
        output = self.base / "existing"
        output.mkdir()
        sentinel = output / "user.txt"
        sentinel.write_text("preserve me", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "new_output_and_matching_prepared_source_required"):
            configure(self.package, output, self.root, client="cursor")
        self.assertEqual(sentinel.read_text(), "preserve me")

    def test_dot_and_node_cli_are_deferred(self):
        for client in ("dot", "gemini", "claude-node"):
            with self.assertRaisesRegex(ValueError, "client_not_supported"):
                configure(self.package, self.base / client, self.root, client=client)

    def test_codex_compatibility_is_a_second_plugin_without_original_hook(self):
        self.prepared("cursor")
        path = self.package / "versions" / self.version / "broker.json"
        policy = json.loads(path.read_bytes())
        policy["CodexPackageFamilies"] = ["OpenAI.Codex_examplefamily1"]
        write_json(path, policy)
        output = self.base / "compatibility"
        record = configure(self.package, output, self.root, client="codex-compatibility")
        self.assertEqual(record["primary_entry"], "codex-chat")
        entries = json.loads((output / ".mcp.json").read_bytes())["mcpServers"]
        self.assertEqual(set(entries), {name + "-compat" for name in CHANNELS})
        self.assertFalse((output / "hooks").exists())
        manifest = json.loads((output / ".codex-plugin/plugin.json").read_bytes())
        self.assertEqual(manifest["name"], "flower-control-compatibility")
        self.assertIn("Optional", manifest["description"])


if __name__ == "__main__":
    unittest.main()
