"""Small PreToolUse to MCP ticket bridge; no profile grant or UI here."""

from __future__ import annotations

import os
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from flower_control.authorization.origin import HostToolCall, OriginError, OriginLedger
from flower_control.control.state import StateStore


ORIGIN_FIELD = "flower_origin"
WEB_TOOLS = ("flower_origin_probe", "flower_web_start_temp", "flower_web_run",
             "flower_web_screenshot",
             "flower_web_action_status", "flower_web_cancel", "flower_web_close_temp",
             "flower_web_open_ai", "flower_web_close_ai", "flower_web_reconnect_ai",
             "flower_web_begin_ai_login", "flower_web_ai_login_status",
             "flower_web_finish_ai_login", "flower_web_cancel_ai_login",
             "flower_web_request_luohua_access", "flower_web_luohua_access_status",
             "flower_web_begin_luohua_login", "flower_web_luohua_login_status",
             "flower_web_finish_luohua_login", "flower_web_cancel_luohua_login",
             "flower_web_open_luohua", "flower_web_reconnect_luohua",
             "flower_web_close_luohua")
APP_TOOLS = ("flower_app_origin_probe", "flower_app_list_windows",
             "flower_app_select_window", "flower_app_activate", "flower_app_observe",
             "flower_app_set_value",
             "flower_app_invoke", "flower_app_set_toggle", "flower_app_select_item",
             "flower_app_action_status", "flower_app_cancel", "flower_app_pause")
COMPUTER_TOOLS = ("flower_computer_origin_probe", "flower_computer_list_windows",
                  "flower_computer_select_window", "flower_computer_observe",
                  "flower_computer_activate", "flower_computer_input", "flower_computer_action_status",
                  "flower_computer_cancel", "flower_computer_pause")
FLOWER_TOOLS = frozenset(
    [f"mcp__{server}__{tool}"
     for server in ("flower_web", "flower-web") for tool in WEB_TOOLS]
    + [f"mcp__{server}__{tool}"
       for server in ("flower_app", "flower-app") for tool in APP_TOOLS]
    + [f"mcp__{server}__{tool}"
       for server in ("flower_computer", "flower-computer") for tool in COMPUTER_TOOLS])
PROBE_TOOLS = FLOWER_TOOLS  # Backward-compatible name for the first bridge tests.
CLAUDE_TOOL_ALIASES = {
    f"mcp__plugin_flower-control_{server}__{tool}": f"mcp__{server}__{tool}"
    for servers, tools in ((("flower-web", "flower_web"), WEB_TOOLS),
                           (("flower-app", "flower_app"), APP_TOOLS),
                           (("flower-computer", "flower_computer"), COMPUTER_TOOLS))
    for server in servers for tool in tools
}


def _claude_identifier(value: object, field: str) -> str:
    if (not isinstance(value, str) or not 1 <= len(value) <= 256
            or value != value.strip() or any(ord(c) < 32 for c in value)):
        raise OriginError("invalid_" + field)
    return value


def state_directory() -> Path:
    local = os.environ.get("LOCALAPPDATA")
    if not local or not Path(local).is_absolute():
        raise OriginError("local_app_data_unavailable")
    return Path(local) / "FlowerControl" / "state-v1"


def issue_for_hook(event: Mapping[str, Any], ledger: OriginLedger, *, host: str = "codex") -> dict:
    """Return the official PreToolUse rewrite for one exact Flower tool."""
    if not isinstance(event, dict) or event.get("hook_event_name") != "PreToolUse":
        raise OriginError("invalid_hook_event")
    name = event.get("tool_name")
    if host == "claude-code":
        name = CLAUDE_TOOL_ALIASES.get(name, name) if isinstance(name, str) else name
    elif host != "codex":
        raise OriginError("host_unrecognized")
    arguments = event.get("tool_input")
    if name not in FLOWER_TOOLS or not isinstance(arguments, dict):
        raise OriginError("hook_tool_unrecognized")
    if ORIGIN_FIELD in arguments:
        raise OriginError("origin_field_reserved")
    turn = event.get("turn_id")
    if host == "claude-code":
        use_id = _claude_identifier(event.get("tool_use_id"), "tool_use_id")
        prompt = event.get("prompt_id")
        prompt = (_claude_identifier(prompt, "prompt_id") if prompt is not None else use_id)
        agent = event.get("agent_id")
        agent = _claude_identifier(agent, "agent_id") if agent is not None else None
        # The host session is the authorization scope. Agent identity separates
        # duplicate-call keys without creating broader or synthetic chat grants.
        turn = "claude:" + hashlib.sha256(json.dumps(
            ["prompt" if event.get("prompt_id") is not None else "call", prompt, agent],
            separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()
    call = HostToolCall(session_id=event.get("session_id"),
                        turn_id=turn,
                        tool_use_id=event.get("tool_use_id"),
                        tool_name=name, tool_input=arguments,
                        hook_origin="trusted_hook", cwd=event.get("cwd"), host=host)
    ticket = ledger.issue(call)
    output = {
        "hookEventName": "PreToolUse",
        "updatedInput": {**arguments, ORIGIN_FIELD: {"token": ticket.token,
                                                    "tool_name": name}},
    }
    # Claude keeps its normal permission decision. This Hook adds provenance;
    # it is not permission to act on private profiles or selected windows.
    if host == "codex":
        output["permissionDecision"] = "allow"
    return {"hookSpecificOutput": output}


def consume_from_mcp(ledger: OriginLedger, *, tool_name: str,
                     arguments: Mapping[str, Any], origin: object) -> str:
    """The token proves a matched Hook event; no session id reaches the model."""
    if tool_name not in FLOWER_TOOLS or not isinstance(origin, dict) or set(origin) != {"token", "tool_name"}:
        raise OriginError("origin_missing_or_invalid")
    if origin["tool_name"] != tool_name:
        raise OriginError("ticket_call_mismatch")
    return ledger.consume_token(tool_name, arguments, origin["token"])


def live_ledger() -> OriginLedger:
    return OriginLedger(StateStore(state_directory()), allowed_tools=FLOWER_TOOLS)
