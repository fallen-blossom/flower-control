"""Reduced Antigravity control surface, scoped to one local MCP connection.

No transcript inspection or simulated host Hook. Private Luohua tools are hidden
and denied. The actual protected broker must attest the Antigravity process chain
before this adapter can issue an internal connection ticket.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets

from mcp import types

from .authorization.hook_bridge import (APP_TOOLS, COMPUTER_TOOLS, WEB_TOOLS,
                                        ORIGIN_FIELD, live_ledger)
from .authorization.origin import HostToolCall, OriginError


def install_antigravity_adapter(server, channel: str) -> None:
    # This selects an adapter, not a permission. A forged environment alone
    # cannot pass the independent broker admission checked for every call.
    if os.environ.get("FLOWER_OPERATOR_HOST") != "antigravity":
        return
    from .drivers.high_helper import HighHelperClient
    groups = {"flower-web": WEB_TOOLS, "flower-app": APP_TOOLS,
              "flower-computer": COMPUTER_TOOLS}
    if channel not in groups:
        raise ValueError("antigravity_channel_rejected")
    allowed = frozenset(name for name in groups[channel] if "luohua" not in name)
    connection = "connection:" + secrets.token_hex(32)
    low = server._mcp_server
    if getattr(low, "_flower_antigravity_adapter", False):
        return
    for tool in server._tool_manager.list_tools():
        if tool.name != "flower_status" and tool.name not in allowed:
            server.remove_tool(tool.name)
    original_call = low.request_handlers[types.CallToolRequest]
    original_list = low.request_handlers[types.ListToolsRequest]
    client = HighHelperClient(channel=channel)

    async def list_tools(request):
        result = await original_list(request)
        result.root.tools = [tool for tool in result.root.tools
                             if tool.name in allowed or tool.name == "flower_status"]
        for tool in result.root.tools:
            if tool.name.endswith("origin_probe"):
                tool.description = "Check the admitted local Antigravity connection; no per-chat attribution or private browser grant."
        return result

    async def call_tool(request):
        name = request.params.name
        if name != "flower_status" and name not in allowed:
            return low._make_error_result("antigravity_tool_not_supported")
        arguments = dict(request.params.arguments or {})
        if ORIGIN_FIELD in arguments:
            return low._make_error_result("origin_field_reserved")
        # Use the actual JSON-RPC request ID only within this fresh connection.
        # Duplicate IDs cannot produce a second business dispatch.
        request_id = low.request_context.request_id
        use_id = hashlib.sha256(json.dumps(request_id, ensure_ascii=True,
                                          separators=(",", ":")).encode("ascii")).hexdigest()

        def issue():
            facts = client.probe_status()
            if (facts.get("connected") is not True or facts.get("source_admitted") is not True
                    or facts.get("high_token_verified") is not True
                    or facts.get("host_source") != "antigravity-flower"):
                raise OriginError("antigravity_host_unverified")
            if name == "flower_status":
                return None
            canonical = f"mcp__{channel}__{name}"
            ticket = live_ledger().issue(HostToolCall(
                session_id=connection, turn_id="connection", tool_use_id=use_id,
                tool_name=canonical, tool_input=arguments, hook_origin="trusted_connection",
                cwd=os.getcwd(), host="antigravity"))
            return {"token": ticket.token, "tool_name": canonical}

        try:
            origin = await asyncio.to_thread(issue)
        except Exception:
            # No argument, identity, exception body or transcript leaves here.
            return low._make_error_result("antigravity_host_or_origin_unavailable")
        if origin is not None:
            arguments[ORIGIN_FIELD] = origin
        forwarded = request.model_copy(update={"params": request.params.model_copy(
            update={"arguments": arguments})})
        result = await original_call(forwarded)
        if name.endswith("origin_probe") or name == "flower_status":
            # Never call a connection ticket proof of a genuine host chat.
            payload = result.root.structuredContent
            if isinstance(payload, dict):
                if "chat_ref" in payload:
                    payload["connection_ref"] = payload.pop("chat_ref")
                payload.update(origin_scope="connection", chat_isolation=False,
                               personal_browser_supported=False)
                result.root.content = [types.TextContent(type="text", text=json.dumps(
                    payload, ensure_ascii=True, separators=(",", ":")))]
        return result

    low.request_handlers[types.ListToolsRequest] = list_tools
    low.request_handlers[types.CallToolRequest] = call_tool
    low._flower_antigravity_adapter = True
