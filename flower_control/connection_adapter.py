"""Explicit stdio origin adapter; selection never replaces broker admission."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
from contextlib import asynccontextmanager

import anyio

from mcp import types

from .authorization.hook_bridge import APP_TOOLS, COMPUTER_TOOLS, WEB_TOOLS, ORIGIN_FIELD, live_ledger
from .authorization.origin import HostToolCall, OriginError

ADMITTED_SOURCES = frozenset({"codex-flower", "claude-code-flower", "antigravity-flower", "local-mcp-flower"})


def connection_mode() -> bool:
    mode = os.environ.get("FLOWER_ORIGIN_MODE")
    return mode == "connection" or (mode is None and os.environ.get("FLOWER_OPERATOR_HOST") == "antigravity")


def install_connection_adapter(server, channel: str, *, cleanup=None) -> None:
    if not connection_mode():
        return
    from .drivers.high_helper import HighHelperClient
    groups = {"flower-web": WEB_TOOLS, "flower-app": APP_TOOLS, "flower-computer": COMPUTER_TOOLS}
    if channel not in groups:
        raise ValueError("connection_channel_rejected")
    low = server._mcp_server
    if getattr(low, "_flower_connection_adapter", False):
        return
    allowed = frozenset(name for name in groups[channel] if "luohua" not in name)
    connection = "connection:" + secrets.token_hex(32)
    tasks = set()
    for tool in server._tool_manager.list_tools():
        if tool.name != "flower_status" and tool.name not in allowed:
            server.remove_tool(tool.name)
    original_call = low.request_handlers[types.CallToolRequest]
    original_list = low.request_handlers[types.ListToolsRequest]
    original_lifespan = low.lifespan
    client = HighHelperClient(channel=channel)

    @asynccontextmanager
    async def lifespan(instance):
        async with original_lifespan(instance) as context:
            try:
                yield context
            finally:
                if cleanup is not None:
                    with anyio.CancelScope(shield=True):
                        await cleanup(frozenset(tasks))

    async def list_tools(request):
        result = await original_list(request)
        result.root.tools = [tool for tool in result.root.tools if tool.name in allowed or tool.name == "flower_status"]
        for tool in result.root.tools:
            schema = dict(tool.inputSchema)
            schema["properties"] = {k: v for k, v in schema.get("properties", {}).items() if k != ORIGIN_FIELD}
            if "required" in schema:
                schema["required"] = [k for k in schema["required"] if k != ORIGIN_FIELD]
            tool.inputSchema = schema
            if tool.name.endswith("origin_probe"):
                tool.description = "Check the admitted local MCP connection; no per-chat identity or private profile grant."
        return result

    async def call_tool(request):
        name = request.params.name
        if name != "flower_status" and name not in allowed:
            return low._make_error_result("connection_tool_not_supported")
        arguments = dict(request.params.arguments or {})
        if ORIGIN_FIELD in arguments:
            return low._make_error_result("origin_field_reserved")
        request_id = low.request_context.request_id
        use_id = hashlib.sha256(json.dumps(request_id, ensure_ascii=True, separators=(",", ":")).encode("ascii")).hexdigest()

        def issue():
            facts = client.probe_status()
            if (facts.get("connected") is not True or facts.get("source_admitted") is not True
                    or facts.get("high_token_verified") is not True or facts.get("host_source") not in ADMITTED_SOURCES):
                raise OriginError("connection_host_unverified")
            if name == "flower_status":
                return None, None
            canonical = f"mcp__{channel}__{name}"
            ticket = live_ledger().issue(HostToolCall(
                session_id=connection, turn_id="connection", tool_use_id=use_id,
                tool_name=canonical, tool_input=arguments, hook_origin="trusted_connection",
                cwd=os.getcwd(), host="local-connection"))
            return {"token": ticket.token, "tool_name": canonical}, ticket.task_id

        try:
            origin, task = await asyncio.to_thread(issue)
        except Exception:
            return low._make_error_result("connection_host_or_origin_unavailable")
        if task is not None:
            tasks.add(task)
        if origin is not None:
            arguments[ORIGIN_FIELD] = origin
        forwarded = request.model_copy(update={"params": request.params.model_copy(update={"arguments": arguments})})
        result = await original_call(forwarded)
        if name.endswith("origin_probe") or name == "flower_status":
            payload = result.root.structuredContent
            # Untyped dict returns in the pinned SDK use JSON TextContent.
            if payload is None and len(result.root.content) == 1:
                content = result.root.content[0]
                if isinstance(content, types.TextContent) and len(content.text) <= 65536:
                    try:
                        payload = json.loads(content.text)
                    except ValueError:
                        payload = None
            if isinstance(payload, dict):
                if "chat_ref" in payload:
                    payload["connection_ref"] = payload.pop("chat_ref")
                payload.update(origin_scope="connection", chat_isolation=False,
                               personal_browser_supported=False, managed_browser_cross_channel=False,
                               cross_channel_handoff=False)
                result.root.structuredContent = payload
                if isinstance(payload.get("limitations"), list):
                    payload["limitations"] = ["按本次通道连接控制；不支持落花私人 profile，同一目标暂不跨通道接管。"] + payload["limitations"]
                result.root.content = [types.TextContent(type="text", text=json.dumps(payload, ensure_ascii=False, separators=(",", ":")))]
        return result

    low.request_handlers[types.ListToolsRequest] = list_tools
    low.request_handlers[types.CallToolRequest] = call_tool
    low.lifespan = lifespan
    low._flower_connection_adapter = True
