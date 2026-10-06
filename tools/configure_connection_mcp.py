"""Generate one recipient-local connection configuration; never install it."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

if __package__:
    from .configure_claude_plugin import ROOT, prepared_configuration, write_json
else:
    from configure_claude_plugin import ROOT, prepared_configuration, write_json

CLIENT_IMAGES = {"cursor": {"cursor.exe"}, "vscode": {"code.exe", "code - insiders.exe"},
                 "opencode-v1": {"opencode.exe"}, "opencode-v2": {"opencode.exe"},
                 "antigravity": {"antigravity.exe"}}


def configure(package: Path, output: Path, source_root: Path = ROOT, *, client: str) -> dict:
    if client not in {*CLIENT_IMAGES, "codex-compatibility"}:
        raise ValueError("client_not_supported")
    kind = "codex" if client == "codex-compatibility" else "antigravity" if client == "antigravity" else "local-mcp"
    package, root, output, version, servers, policy_path = prepared_configuration(
        package, output, source_root, host_kind=kind)
    policy = json.loads(policy_path.read_bytes())
    if client != "codex-compatibility" and not any(h["Kind"] == kind and Path(h["Path"]).name.lower() in CLIENT_IMAGES[client]
                                   for h in policy["NativeHosts"]):
        raise ValueError("specific_client_not_pinned")
    entries = {name: {**entry, "args": ["--flower-connection-client", name]} for name, entry in servers.items()}
    if client == "codex-compatibility":
        entries = {name + "-compat": entry for name, entry in entries.items()}
        write_json(output / ".mcp.json", {"mcpServers": entries})
        write_json(output / "mcp.json", {"mcpServers": entries})
        presentation = {"displayName": "Flower Control Compatibility", "shortDescription": "Optional compatibility preview",
                        "capabilities": ["Read", "Interactive", "Write"]}
        write_json(output / "plugin.json", {"name": "flower-control-compatibility", "version": "0.1.0+compat." + version[:8],
            "description": "Optional connection-mode preview. Original Flower Control remains the primary entry; cloud-local compatibility untested.",
            "extensions": {"com.openai": {"interface": presentation}}})
        write_json(output / ".codex-plugin/plugin.json", {"name": "flower-control-compatibility", "version": "0.1.0+compat." + version[:8],
            "description": "Optional connection-mode preview; original Flower Control remains the primary entry. No chat isolation or private profile.",
            "mcpServers": "./.mcp.json", "interface": presentation})
    elif client == "vscode":
        write_json(output / ".vscode/mcp.json", {"servers": entries})
    elif client in {"opencode-v1", "opencode-v2"}:
        local = {name: {"type": "local", "command": [entry["command"], *entry["args"]],
                        **({"enabled": True} if client == "opencode-v1" else {"disabled": False})}
                 for name, entry in entries.items()}
        write_json(output / "opencode.json", {"mcp": local if client == "opencode-v1" else {"servers": local}})
    else:
        filename = ".cursor/mcp.json" if client == "cursor" else "mcp_config.json"
        write_json(output / filename, {"mcpServers": {name: {"command": entry["command"], "args": entry["args"],
                                                            **({"type": "stdio"} if client == "cursor" else {})}
                                                     for name, entry in entries.items()}})
    record = {"schema": 1, "client": client, "helper_version": version, "origin_scope": "connection",
              "configured_only": True, "installed": False, "client_tested": False,
              "chat_isolation": False, "personal_browser_supported": False, "managed_browser_cross_channel": False}
    record["cross_channel_handoff"] = False
    record.update(integration_role="optional-compatibility", primary_entry="codex-chat", auto_imported=False)
    write_json(output / "configuration.json", record)
    return {"output": str(output), **record}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, default=ROOT)
    parser.add_argument("--client", choices=[*CLIENT_IMAGES, "codex-compatibility"], required=True)
    args = parser.parse_args()
    print(json.dumps(configure(args.package, args.output, args.source_root, client=args.client), ensure_ascii=False))


if __name__ == "__main__":
    main()
