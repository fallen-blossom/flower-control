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
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
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
    frozen = preparation.get("runtime_dependency_tree_fully_hash_pinned") is True
    if (preparation.get("schema") != 1 or not re.fullmatch(r"[0-9a-f]{32}", version)
            or not frozen and Path(preparation.get("source_root", "")).resolve() != ROOT
            or preparation.get("installed") is not False):
        raise ValueError("package_must_be_prepared_for_this_source")
    if set(entries.get("mcpServers", {})) != set(CHANNELS):
        raise ValueError("three_channels_required")
    from flower_control.install_location import discover_installation
    production = discover_installation().program_root
    if Path(preparation["production_root"]).resolve() != production.resolve():
        raise ValueError("registered_installation_root_required")
    helper = production / "versions" / version / "Flower.HighHelper.exe"
    for channel, entry in entries["mcpServers"].items():
        if (set(entry) != {"command", "args", "cwd"}
                or Path(entry["command"]).resolve() != helper.resolve()
                or entry["args"] != ["--flower-client", channel]
                or Path(entry["cwd"]).resolve() != (helper.parent / "python-source" if frozen else ROOT).resolve()):
            raise ValueError("prepared_mcp_entry_mismatch")
    plugin = output / "plugins/flower-control"
    if output.exists():
        raise ValueError("output_must_be_new")
    if frozen:
        # This verifies the sealed delivery and copies its full skill, hook,
        # branding and metadata set. Commands use the installed version only.
        from tools.prepare_frozen_plugin import prepare
        prepare(package, plugin)
    else:
        configure_source_plugin(entries, plugin, version)
    write_json(output / ".agents/plugins/marketplace.json", {
        "name": "flower-control-local", "interface": {"displayName": "Flower Control (local)"},
        "plugins": [{"name": "flower-control",
                     "source": {"source": "local", "path": "./plugins/flower-control"},
                     "policy": {"installation": "AVAILABLE", "authentication": "ON_INSTALL"},
                     "category": "Productivity"}],
    })
    record = {"schema": 1, "helper_version": version,
              "prepared_package_sha256": hashlib.sha256((package / "preparation.json").read_bytes()).hexdigest(),
              "frozen_runtime": frozen, "configured_only": True, "installed": False, "hook_trust_granted": False}
    write_json(output / "configuration.json", record)
    return {"output": str(output), **record}


def configure_source_plugin(entries, plugin: Path, version: str) -> None:
    python = ROOT / ".venv/Scripts/python.exe"
    hook = ROOT / "hooks/pre_tool_use.py"
    if not python.is_file() or not hook.is_file():
        raise ValueError("venv_hook_required")
    hooks = json.loads((ROOT / "hooks/hooks.template.json").read_bytes())
    for event in hooks["hooks"]["PreToolUse"]:
        for command in event["hooks"]:
            if command.get("command") != "__RECIPIENT_PYTHON_AND_HOOK__":
                raise ValueError("unexpected_hook_template")
            command["command"] = subprocess.list2cmdline([str(python), "-B", str(hook)])
    manifest = {
        "name": "flower-control", "version": "0.1.0+local." + version[:8],
        "description": "Local Windows Web, App, and Computer control for Codex.",
        "interface": {
            "displayName": "Flower Control", "shortDescription": "Local Windows control",
            "longDescription": "Local webpage, app and Windows control. Ctrl+Alt+9 stops Computer input; Ctrl+Alt+Shift+9 stops all Flower writes. Jev is optional.",
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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(configure(args.package, args.output), ensure_ascii=False))


if __name__ == "__main__":
    main()
