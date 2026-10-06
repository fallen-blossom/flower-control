"""Prepare a reduced local Antigravity plugin, without installing or launching."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil

if __package__:
    from .configure_claude_plugin import ROOT, prepared_configuration, write_json
else:
    from configure_claude_plugin import ROOT, prepared_configuration, write_json


def configure(package: Path, output: Path, source_root: Path = ROOT) -> dict:
    package, root, output, version, servers, policy_path = prepared_configuration(
        package, output, source_root, host_kind="antigravity")
    write_json(output / "plugin.json", {
        "name": "flower-control", "version": "0.1.0-antigravity-preview." + version[:8],
        "description": "Local Windows Web, App and Computer controls. Connection scope; personal browser profiles unavailable.",
    })
    write_json(output / "mcp_config.json", {"mcpServers": {
        name: {"command": value["command"], "args": value["args"]}
        for name, value in servers.items()
    }})
    # This host intentionally uses the admitted connection adapter, no fake Hook.
    skill = output / "skills/flower-control"
    skill.mkdir(parents=True)
    shutil.copyfile(Path(__file__).with_name("antigravity_flower_skill.md"), skill / "SKILL.md")
    record = {"schema": 1, "host": "antigravity", "helper_version": version,
              "prepared_package_sha256": hashlib.sha256((package / "preparation.json").read_bytes()).hexdigest(),
              "broker_policy_sha256": hashlib.sha256(policy_path.read_bytes()).hexdigest(),
              "source_root": str(root), "configured_only": True, "installed": False, "tested": False,
              "origin_scope": "connection", "chat_isolation": False, "personal_browser_supported": False}
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
