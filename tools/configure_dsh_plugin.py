"""Generate a local DSH bundle from a fixed helper package; never install."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if (ROOT / "release/github/tools/configure_claude_plugin.py").is_file():
    from release.github.tools.configure_claude_plugin import prepared_configuration, write_json
else:
    # The public archive places the same recipient-local generator in tools/.
    from tools.configure_claude_plugin import prepared_configuration, write_json


def target_versions(manifest: dict) -> dict:
    desktop = manifest.get("flowerControl", {}).get("targetDesktopVersion")
    client = manifest.get("peerDependencies", {}).get("@deepseek-ai/dsh-mcp-client")
    exact_version = r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?"
    if any(not isinstance(value, str) or not re.fullmatch(exact_version, value)
           for value in (desktop, client)):
        raise ValueError("dsh_explicit_target_versions_required")
    return {"dsh_version": desktop, "dsh_mcp_client_version": client}


def configure(package: Path, output: Path, source_root: Path = ROOT) -> dict:
    package, root, output, version, servers, policy = prepared_configuration(
        package, output, source_root, host_kind="dsh-desktop")
    template = root / "integrations/dsh"
    names = ("package.json", "index.mjs", "plugin.mjs", "host-bridge.mjs", "metadata.mjs", "README.md")
    if any(not (template / name).is_file() or (template / name).is_symlink()
           for name in names):
        raise ValueError("dsh_plugin_source_required")
    manifest = json.loads((template / "package.json").read_bytes())
    targets = target_versions(manifest)
    output.mkdir(parents=True)
    for name in names:
        shutil.copyfile(template / name, output / name)
    skill_source = root / "skills/flower-control/SKILL.md"
    if not skill_source.is_file() or skill_source.is_symlink():
        raise ValueError("dsh_full_skill_source_required")
    skill_target = output / "skills/flower-control/SKILL.md"
    skill_target.parent.mkdir(parents=True)
    shutil.copyfile(skill_source, skill_target)
    adapter_sources = {name: hashlib.sha256((output / name).read_bytes()).hexdigest() for name in names}
    adapter_sources["skills/flower-control/SKILL.md"] = hashlib.sha256(skill_target.read_bytes()).hexdigest()
    adapter_hash = hashlib.sha256(json.dumps(adapter_sources, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    # JS-only repairs must not reuse the previous package version while the
    # fixed High binary is unchanged. The CLI/cache identity follows content.
    manifest["version"] = "0.1.0+high." + version[:12] + ".adapter5." + adapter_hash[:12]
    write_json(output / "package.json", manifest)
    helper = servers["flower-web"]["command"]
    # JSON string quoting is valid YAML scalar quoting; no shell text generated.
    # A bundle contributes a new entry. An id-only overlay only modifies an
    # existing entry and is silently skipped when the base profile has none.
    patch = ("- insert:\n  - id: flower-control-dsh\n    name: '@flower-control/dsh'\n    config:\n"
             "      helperCommand: " + json.dumps(helper, ensure_ascii=False) + "\n"
             "      toolCallTimeoutMs: 180000\n")
    (output / "cordis.patch.yml").write_text(patch, encoding="utf-8")
    record = {"schema": 1, "client": "dsh-desktop", **targets,
              "helper_version": version, "helper_count": 1, "origin_scope": "chat",
              "chat_isolation": True, "capability_profile": "same-as-codex",
              "personal_browser_supported": True, "uac_supported": False,
              "skill_sha256": hashlib.sha256(skill_source.read_bytes()).hexdigest(),
              "adapter_source_sha256": adapter_hash, "adapter_sources": adapter_sources,
              "configured_only": True, "installed": False, "client_tested": False,
              "broker_policy_sha256": hashlib.sha256(policy.read_bytes()).hexdigest()}
    write_json(output / "configuration.json", record)
    return {"output": str(output), **record}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, default=ROOT)
    args = parser.parse_args()
    print(json.dumps(configure(args.package, args.output, args.source_root), ensure_ascii=False))


if __name__ == "__main__":
    main()
