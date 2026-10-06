"""Prepare a local Claude Code plugin; never install, launch or alter settings."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil

ROOT = Path(__file__).resolve().parents[1]
CHANNELS = ("flower-web", "flower-app", "flower-computer")


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def prepared_configuration(package: Path, output: Path, source_root: Path, *, host_kind: str):
    package = package.resolve(strict=True)
    root = source_root.resolve(strict=True)
    output = output.resolve()
    prep = json.loads((package / "preparation.json").read_bytes())
    entries = json.loads((package / "mcp-entries.json").read_bytes())
    version = prep.get("version", "")
    if (prep.get("schema") != 1 or not re.fullmatch(r"[a-f0-9]{32}", version)
            or Path(prep.get("source_root", "")).resolve() != root
            or prep.get("installed") is not False or output.exists()):
        raise ValueError("new_output_and_matching_prepared_source_required")
    production = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "FlowerControl/HighHelper"
    if Path(prep.get("production_root", "")).resolve() != production.resolve():
        raise ValueError("fixed_program_files_helper_required")
    policy_path = package / "versions" / version / "broker.json"
    policy = json.loads(policy_path.read_bytes())
    hosts = prep.get("native_hosts")
    host_names = {"claude-code": "claude.exe", "antigravity": "antigravity.exe"}
    if (host_kind not in host_names or not isinstance(hosts, list) or not hosts
            or not any(isinstance(h, dict) and h.get("Kind") == host_kind for h in hosts)
            or policy.get("NativeHosts") != hosts
            or policy.get("Version") != version or Path(policy.get("Repository", "")).resolve() != root
            or any(type(h) is not dict or set(h) != {"Kind", "Path", "Sha256"}
                   or h["Kind"] not in host_names or not Path(h["Path"]).is_absolute()
                   or Path(h["Path"]).name.lower() != host_names[h["Kind"]]
                   or not re.fullmatch(r"[a-f0-9]{64}", h["Sha256"]) for h in hosts)):
        raise ValueError("prepared_native_host_policy_required")
    if set(entries.get("mcpServers", {})) != set(CHANNELS):
        raise ValueError("three_channels_required")
    helper = production / "versions" / version / "Flower.HighHelper.exe"
    servers = {}
    for channel, entry in entries["mcpServers"].items():
        if (set(entry) != {"command", "args", "cwd"}
                or Path(entry["command"]).resolve() != helper.resolve()
                or entry["args"] != ["--flower-client", channel]
                or Path(entry["cwd"]).resolve() != root):
            raise ValueError("prepared_mcp_entry_mismatch")
        # Claude has no dependency on a Codex-specific cwd config field:
        # the fixed launcher already sets the broker's source directory.
        servers[channel] = {"type": "stdio", "command": str(helper), "args": entry["args"]}
    return package, root, output, version, servers, policy_path


def configure(package: Path, output: Path, source_root: Path = ROOT) -> dict:
    package, root, output, version, servers, policy_path = prepared_configuration(
        package, output, source_root, host_kind="claude-code")
    python = root / ".venv/Scripts/python.exe"
    hook = root / "hooks/claude_pre_tool_use.py"
    if not python.is_file() or not hook.is_file():
        raise ValueError("recipient_venv_and_claude_hook_required")
    write_json(output / ".claude-plugin/plugin.json", {
        "name": "flower-control", "version": "0.1.0-claude-preview." + version[:8],
        "description": "Local Windows browser, app controls, and screenshot/keyboard/mouse tools. Brave Web preview; optional Jev.",
    })
    # Default files are discovered once; don't redeclare them in the manifest.
    write_json(output / ".mcp.json", servers)
    write_json(output / "hooks/hooks.json", {"hooks": {"PreToolUse": [{
        "matcher": "^mcp__(?:plugin_flower-control_)?flower[-_](?:web|app|computer)__flower_",
        "hooks": [{"type": "command", "command": str(python),
                   "args": ["-B", str(hook)], "timeout": 10}],
    }]}})
    skill = output / "skills/flower-control"
    skill.mkdir(parents=True)
    shutil.copyfile(Path(__file__).with_name("claude_flower_skill.md"), skill / "SKILL.md")
    record = {"schema": 1, "host": "claude-code", "helper_version": version,
              "prepared_package_sha256": hashlib.sha256((package / "preparation.json").read_bytes()).hexdigest(),
              "broker_policy_sha256": hashlib.sha256(policy_path.read_bytes()).hexdigest(),
              "source_root": str(root), "configured_only": True, "installed": False,
              "tested": False, "host_permissions_changed": False}
    write_json(output / "configuration.json", record)
    return {"output": str(output), **record}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, default=ROOT)
    args = parser.parse_args()
    print(json.dumps(configure(args.package, args.output, args.source_root), ensure_ascii=False))


if __name__ == "__main__":
    main()
