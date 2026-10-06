"""Real SDK requests and real origin ledger; broker facts are explicit fakes."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from mcp.server.fastmcp import FastMCP
from mcp.shared.memory import create_connected_server_and_client_session

from flower_control.authorization.hook_bridge import FLOWER_TOOLS
from flower_control.authorization.origin import HostToolCall, OriginError, OriginLedger
from flower_control.connection_adapter import install_connection_adapter
from flower_control.control.state import StateStore


class ConnectionAdapterTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="flower-connection-test-")
        self.addCleanup(temporary.cleanup)
        self.store = StateStore(Path(temporary.name))
        self.ledger = OriginLedger(self.store, allowed_tools=FLOWER_TOOLS)
        self.enterContext(patch.dict(os.environ, {"FLOWER_ORIGIN_MODE": "connection", "FLOWER_OPERATOR_HOST": "codex"}))
        self.enterContext(patch("flower_control.connection_adapter.live_ledger", return_value=self.ledger))
        self.probe = self.enterContext(patch("flower_control.drivers.high_helper.HighHelperClient.probe_status", return_value={
            "connected": True, "source_admitted": True, "high_token_verified": True, "host_source": "codex-flower"}))

    def server(self, channel="flower-web", cleanup=None):
        server = FastMCP(channel)
        tool = {"flower-web": "flower_origin_probe", "flower-app": "flower_app_origin_probe",
                "flower-computer": "flower_computer_origin_probe"}[channel]

        @server.tool(name=tool)
        def origin_probe(flower_origin: dict | None = None) -> dict:
            task = self.ledger.consume_token(flower_origin["tool_name"], {}, flower_origin["token"])
            return {"chat_ref": task}

        @server.tool(name="flower_web_open_luohua")
        def private(flower_origin: dict | None = None) -> dict:
            raise AssertionError("private handler must never execute")

        @server.tool(name="flower_status")
        def status() -> dict:
            return {"limitations": []}

        install_connection_adapter(server, channel, cleanup=cleanup)
        return server, tool

    async def test_connection_without_hook_and_cleanup(self):
        cleanup = AsyncMock()
        server, tool = self.server(cleanup=cleanup)
        async with create_connected_server_and_client_session(server) as client:
            listing = await client.list_tools()
            self.assertNotIn("flower_web_open_luohua", [t.name for t in listing.tools])
            self.assertTrue(all("flower_origin" not in t.inputSchema.get("properties", {}) for t in listing.tools))
            reply = await client.call_tool(tool, {})
            self.assertFalse(reply.isError)
            payload = reply.structuredContent
            self.assertEqual(payload["origin_scope"], "connection")
            self.assertNotIn("chat_ref", payload)
            self.assertFalse(payload["personal_browser_supported"])
            task = payload["connection_ref"]
            with self.store.transaction() as db:
                self.assertEqual(db.execute("SELECT count(*) FROM origin_tickets WHERE consumed IS NOT NULL").fetchone()[0], 1)
        cleanup.assert_awaited_once_with(frozenset({task}))

    async def test_unverified_source_or_forged_origin_never_dispatches(self):
        server, tool = self.server()
        async with create_connected_server_and_client_session(server) as client:
            for facts in ({"connected": False}, {"connected": True, "source_admitted": True, "high_token_verified": True},
                          {"connected": True, "source_admitted": True, "high_token_verified": True, "host_source": "untrusted"}):
                self.probe.return_value = facts
                self.assertTrue((await client.call_tool(tool, {})).isError)
            self.assertTrue((await client.call_tool("flower_web_open_luohua", {})).isError)
            self.assertTrue((await client.call_tool(tool, {"flower_origin": {"token": "fake"}})).isError)
        with self.store.transaction() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM origin_tickets").fetchone()[0], 0)

    async def test_channels_and_reconnections_do_not_adopt_another_task(self):
        tasks = []
        for channel in ("flower-web", "flower-app", "flower-computer", "flower-web"):
            server, tool = self.server(channel)
            async with create_connected_server_and_client_session(server) as client:
                payload = (await client.call_tool(tool, {})).structuredContent
                tasks.append(payload["connection_ref"])
                self.assertFalse(payload["managed_browser_cross_channel"])
        self.assertEqual(len(set(tasks)), 4)

    async def test_hook_mode_is_unchanged_and_does_not_fallback(self):
        with patch.dict(os.environ, {"FLOWER_ORIGIN_MODE": "hook", "FLOWER_OPERATOR_HOST": "antigravity"}):
            server, _ = self.server()
            self.assertFalse(getattr(server._mcp_server, "_flower_connection_adapter", False))
            self.assertIn("flower_web_open_luohua", [t.name for t in server._tool_manager.list_tools()])
        call = HostToolCall("same", "turn", "use", "mcp__flower-web__flower_origin_probe", {}, "trusted_connection", host="codex")
        with self.assertRaises(OriginError):
            self.ledger.issue(call)

    async def test_real_app_and_computer_entrypoints_link_without_hook(self):
        from flower_control import app, computer
        for module, channel, tool in ((app, "app", "flower_app_origin_probe"),
                                     (computer, "computer", "flower_computer_origin_probe")):
            with self.subTest(channel=channel), patch.object(module, "live_ledger", return_value=self.ledger), \
                    patch.object(module, "state_directory", return_value=self.store.directory):
                server = getattr(module, "create_" + channel + "_server")()
                async with create_connected_server_and_client_session(server) as client:
                    result = await client.call_tool(tool, {})
                    self.assertFalse(result.isError)
                    self.assertTrue(result.structuredContent["linked"])
                    self.assertEqual(result.structuredContent["origin_scope"], "connection")
                    self.assertFalse(result.structuredContent["private_grant"])

    def test_native_source_evidence_needs_both_shape_and_known_host(self):
        from flower_control.drivers.high_helper import _production_host_evidence
        for source in ("claude-code-flower", "antigravity-flower", "local-mcp-flower"):
            evidence = {"Pid": 1, "Created": 2, "Session": 3, "Channel": None,
                        "Source": source, "ProductionAdmitted": True, "LauncherPid": 4,
                        "LauncherCreated": 5, "CodexPid": None, "HostPid": 6}
            self.assertTrue(_production_host_evidence(evidence))
            evidence["HostPid"] = None
            self.assertFalse(_production_host_evidence(evidence))
        self.assertFalse(_production_host_evidence({"ProductionAdmitted": True, "Source": "local-mcp-flower", "HostPid": 6}))

    async def test_real_web_probe_uses_existing_private_authorization_rules(self):
        from flower_control import web
        from flower_control.drivers.web_mcp import WebMcpRuntime
        server = FastMCP("flower-web")
        server.add_tool(web.flower_origin_probe, name="flower_origin_probe")
        install_connection_adapter(server, "flower-web")
        with patch.object(web, "_ledger", self.ledger), patch.object(web, "_runtime", WebMcpRuntime(self.store)):
            async with create_connected_server_and_client_session(server) as client:
                result = await client.call_tool("flower_origin_probe", {})
                self.assertFalse(result.isError)
                self.assertTrue(result.structuredContent["linked"])
                self.assertFalse(result.structuredContent["private_grant"])
                self.assertFalse(result.structuredContent["cross_channel_handoff"])

    def test_generic_host_label_never_reads_codex_configuration(self):
        from flower_control.drivers import indicator_operator
        with patch.dict(os.environ, {"FLOWER_OPERATOR_HOST": "local-mcp"}), \
                patch.object(indicator_operator, "codex_home") as reader:
            result = indicator_operator.resolve_operator()
        self.assertEqual(result["label"], "AI Agent")
        self.assertIsNone(result["config_path"])
        reader.assert_not_called()


if __name__ == "__main__":
    unittest.main()
