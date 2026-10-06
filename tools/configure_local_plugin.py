"""Generate recipient-local Codex plugin files; never install or start anything."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
CHANNELS = ("flower-web", "flower-app", "flower-computer")


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def configure(package: Path, output: Path) -> dict:
    package = package.resolve(strict=True)
    output = output.resolve()
    preparation = json.loads((package / "preparation.json").read_bytes())
    entries = json.loads((package / "mcp-entries.json").read_bytes())
    version = preparation.get("version", "")
    if (preparation.get("schema") != 1 or not re.fullmatch(r"[0-9a-f]{32}", version)
            or Path(preparation.get("source_root", "")).resolve() != ROOT
            or preparation.get("installed") is not False):
        raise ValueError("package_must_be_prepared_for_this_source")
    if set(entries.get("mcpServers", {})) != set(CHANNELS):
        raise ValueError("three_channels_required")
    production = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "FlowerControl/HighHelper"
    if Path(preparation["production_root"]).resolve() != production.resolve():
        raise ValueError("fixed_program_files_helper_root_required")
    helper = production / "versions" / version / "Flower.HighHelper.exe"
    for channel, entry in entries["mcpServers"].items():
        if (set(entry) != {"command", "args", "cwd"}
                or Path(entry["command"]).resolve() != helper.resolve()
                or entry["args"] != ["--flower-client", channel]
                or Path(entry["cwd"]).resolve() != ROOT):
            raise ValueError("prepared_mcp_entry_mismatch")
    python = ROOT / ".venv/Scripts/python.exe"
    hook = ROOT / "hooks/pre_tool_use.py"
    if not python.is_file() or not hook.is_file() or output.exists():
        raise ValueError("venv_hook_required_and_output_must_be_new")
    hooks = json.loads((ROOT / "hooks/hooks.template.json").read_bytes())
    for event in hooks["hooks"]["PreToolUse"]:
        for command in event["hooks"]:
            if command.get("command") != "__RECIPIENT_PYTHON_AND_HOOK__":
                raise ValueError("unexpected_hook_template")
            command["command"] = subprocess.list2cmdline([str(python), "-B", str(hook)])
    plugin = output / "plugins/flower-control"
    manifest = {
        "name": "flower-control", "version": "0.1.0+local." + version[:8],
        "description": "Local Windows Web, App, and Computer control for Codex.",
        "interface": {
            "displayName": "Flower Control", "shortDescription": "Local Windows control",
            "longDescription": "Three local MCP channels for Brave, accessible desktop controls, and Windows input. Ctrl+Alt+9 stops writes. Jev is optional.",
            "category": "Productivity",
            "defaultPrompt": "Check all three Flower channels and their loaded source before using a selected test window.",
            "logo": "./assets/flower.png", "composerIcon": "./assets/flower.png",
        }, "mcpServers": "./.mcp.json",
    }
    write_json(plugin / ".codex-plugin/plugin.json", manifest)
    write_json(plugin / ".mcp.json", entries)
    write_json(plugin / "hooks/hooks.json", hooks)
    (plugin / "assets").mkdir()
    shutil.copyfile(ROOT / "assets/branding/flower-petal/flower-petal-256.png", plugin / "assets/flower.png")
    write_json(output / ".agents/plugins/marketplace.json", {
        "name": "flower-control-local", "interface": {"displayName": "Flower Control (local)"},
        "plugins": [{"name": "flower-control",
                     "source": {"source": "local", "path": "./plugins/flower-control"},
                     "policy": {"installation": "AVAILABLE", "authentication": "ON_INSTALL"},
                     "category": "Productivity"}],
    })
    record = {"schema": 1, "helper_version": version,
              "prepared_package_sha256": hashlib.sha256((package / "preparation.json").read_bytes()).hexdigest(),
              "configured_only": True, "installed": False, "hook_trust_granted": False}
    write_json(output / "configuration.json", record)
    return {"output": str(output), **record}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(configure(args.package, args.output), ensure_ascii=False))


if __name__ == "__main__":
    main()
