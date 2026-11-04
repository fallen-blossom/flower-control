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

ADMITTED_SOURCES = frozenset({"codex-flower", "claude-code-flower", "antigravity-flower", "local-mcp-flower", "dsh-desktop-flower"})


def connection_mode() -> bool:
    mode = os.environ.get("FLOWER_ORIGIN_MODE")
    return mode in {"connection", "dsh-chat"} or (mode is None and os.environ.get("FLOWER_OPERATOR_HOST") == "antigravity")


def install_connection_adapter(server, channel: str, *, cleanup=None) -> None:
    from .mcp_call_lifetime import install_call_cancellation
    install_call_cancellation(server)
    if not connection_mode():
        return
    from .drivers.high_helper import ActiveHelperClient
    groups = {"flower-web": WEB_TOOLS, "flower-app": APP_TOOLS, "flower-computer": COMPUTER_TOOLS}
    if channel not in groups:
        raise ValueError("connection_channel_rejected")
    low = server._mcp_server
    if getattr(low, "_flower_connection_adapter", False):
        return
    dsh = os.environ.get("FLOWER_ORIGIN_MODE") == "dsh-chat"
    chat = os.environ.get("FLOWER_DSH_CHAT_ID") if dsh else None
    if dsh and (not isinstance(chat, str) or not 1 <= len(chat) <= 256
                or chat != chat.strip() or any(ord(c) < 32 or ord(c) == 127 for c in chat)):
        raise ValueError("dsh_chat_identity_missing")
    # A real DSH chat has the same task scope as a Codex chat. Only anonymous
    # local connections retain the smaller, connection-scoped tool surface.
    allowed = (frozenset(groups[channel]) if dsh else
               frozenset(name for name in groups[channel] if "luohua" not in name and "uac" not in name
                         and name not in {"flower_app_work_authority", "flower_app_launch_admin"}))
    connection = "connection:" + secrets.token_hex(32)
    tasks = set()
    admissions = set()
    closing = False
    for tool in server._tool_manager.list_tools():
        if tool.name != "flower_status" and tool.name not in allowed:
            server.remove_tool(tool.name)
    original_call = low.request_handlers[types.CallToolRequest]
    original_list = low.request_handlers[types.ListToolsRequest]
    original_lifespan = low.lifespan
    client = ActiveHelperClient(channel=channel)

    @asynccontextmanager
    async def lifespan(instance):
        nonlocal closing
        async with original_lifespan(instance) as context:
            try:
                yield context
            finally:
                closing = True
                with anyio.CancelScope(shield=True):
                    # Request cancellation cannot stop a synchronous helper
                    # probe. Its late task must be registered before the exact
                    # connection cleanup takes its final task snapshot.
                    if admissions:
                        await asyncio.gather(*tuple(admissions))
                    if cleanup is not None:
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
                tool.description = ("Check this admitted DSH chat. This probe grants no profile or administrator permission." if dsh else
                                    "Check the admitted local MCP connection; no per-chat identity or private profile grant.")
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
                    or not (facts.get("high_token_verified") is True and facts.get("actual_integrity_rid") == 12288
                            or facts.get("ordinary_token_verified") is True and facts.get("actual_integrity_rid") == 8192)
                    or facts.get("host_source") not in ADMITTED_SOURCES):
                raise OriginError("connection_host_unverified")
            if dsh and facts.get("host_source") != "dsh-desktop-flower":
                raise OriginError("dsh_host_unverified")
            if name == "flower_status":
                return None, None
            canonical = f"mcp__{channel}__{name}"
            turn = connection
            if dsh and name in {"flower_computer_uac", "flower_computer_uac_permission"}:
                try:
                    turn = client.dsh_message_context(chat)["turn_id"]
                except Exception:
                    reducing = (name == "flower_computer_uac_permission" and arguments.get("decision") in {"status", "deny", "revoke"}
                                or name == "flower_computer_uac" and arguments.get("command") in {"status", "cancel", "release"})
                    if not reducing:
                        raise OriginError("dsh_source_context_unavailable") from None
            from flower_control.dsh_metadata import read_display
            title = read_display().get("title") if dsh else None
            ticket = live_ledger().issue(HostToolCall(
                session_id=chat if dsh else connection, turn_id=turn, tool_use_id=use_id,
                tool_name=canonical, tool_input=arguments, hook_origin="trusted_connection",
                cwd=os.environ.get("FLOWER_DSH_WORKSPACE", os.getcwd()) if dsh else os.getcwd(),
                host="dsh-desktop" if dsh else "local-connection", thread_title=title))
            return {"token": ticket.token, "tool_name": canonical}, ticket.task_id

        async def admit():
            try:
                origin, task = await asyncio.to_thread(issue)
            except Exception:
                return None
            if task is not None:
                tasks.add(task)
            return origin, task

        if closing:
            return low._make_error_result("connection_host_or_origin_unavailable")
        admission = asyncio.create_task(admit())
        admissions.add(admission)
        admission.add_done_callback(admissions.discard)
        admitted = await asyncio.shield(admission)
        if admitted is None or closing:
            return low._make_error_result("connection_host_or_origin_unavailable")
        origin, task = admitted
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
                if "chat_ref" in payload and not dsh:
                    payload["connection_ref"] = payload.pop("chat_ref")
                payload.update(origin_scope="chat" if dsh else "connection", chat_isolation=dsh,
                               personal_browser_supported=dsh, managed_browser_cross_channel=dsh,
                               cross_channel_handoff=dsh)
                result.root.structuredContent = payload
                if isinstance(payload.get("limitations"), list):
                    payload["limitations"] = [("按 DSH 聊天隔离；共用 Flower 的权限、Stop 与实际可用能力检查，来源探针不签发授权。" if dsh else
                                              "按本次通道连接控制；不支持落花私人 profile，同一目标暂不跨通道接管。")] + payload["limitations"]
                result.root.content = [types.TextContent(type="text", text=json.dumps(payload, ensure_ascii=False, separators=(",", ":")))]
        return result

    async def source_bound_call(request):
        from .authorization.dsh_source import current_source, take_source
        arguments = dict(request.params.arguments or {})
        try:
            source = take_source(request.params.name, arguments, dsh=dsh)
        except ValueError as error:
            return low._make_error_result(str(error))
        # Strip transport metadata before schema validation and business-origin
        # signing. Context copying keeps this exact tuple in an old to_thread
        # worker even after its caller is cancelled and this scope is reset.
        forwarded = request.model_copy(update={"params": request.params.model_copy(update={"arguments": arguments})})
        token = current_source.set(source)
        try:
            return await call_tool(forwarded)
        finally:
            current_source.reset(token)

    low.request_handlers[types.ListToolsRequest] = list_tools
    low.request_handlers[types.CallToolRequest] = source_bound_call
    low.lifespan = lifespan
    low._flower_connection_adapter = True
