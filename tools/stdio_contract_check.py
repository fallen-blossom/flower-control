"""Bounded source or installed fixed-entry MCP probe; never call a control tool.

Run describe-only while source owners are still editing. The root chat may run
the handshake after freezing source. This does not test Codex host injection.
"""
from __future__ import annotations

import argparse
import ast
import asyncio
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from flower_control._status import loaded_source
from flower_control.authorization.hook_bridge import FLOWER_TOOLS


ROOT = Path(__file__).resolve().parents[1]
CHANNELS = {"flower-web": "flower_control.web", "flower-app": "flower_control.app",
            "flower-computer": "flower_control.computer"}


class ContractFailure(ValueError):
    """A fixed local failure code, safe to include without raw provider output."""


def failure_code(error: BaseException) -> str:
    if isinstance(error, ContractFailure):
        return str(error)
    if isinstance(error, BaseExceptionGroup):
        for child in error.exceptions:
            code = failure_code(child)
            if code != "probe_failed_unclassified":
                return code
    return "probe_failed_unclassified"


def declarations(path: Path) -> dict[str, str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    result = {}
    for node in sorted(ast.walk(tree), key=lambda node: getattr(node, "lineno", 0)):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if (not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute)
                    or decorator.func.attr != "tool" or not isinstance(decorator.func.value, ast.Name)
                    or decorator.func.value.id != "server"):
                continue
            keywords = {item.arg: item.value for item in decorator.keywords}
            name = ast.literal_eval(keywords["name"])
            description = ast.literal_eval(keywords["description"])
            if name in result or type(name) is not str or type(description) is not str or not description:
                raise ContractFailure("invalid_or_duplicate_source_tool_declaration")
            result[name] = description
    return result


def hook_registry(repository: Path) -> set[str]:
    """Read the selected version's literal registry, never import moving code."""
    groups = {"WEB_TOOLS": (), "APP_TOOLS": (), "COMPUTER_TOOLS": ()}
    found = set()
    tree = ast.parse((repository / "flower_control/authorization/hook_bridge.py").read_text(encoding="utf-8"))
    for node in tree.body:
        target = (node.targets[0] if isinstance(node, ast.Assign) and len(node.targets) == 1
                  else node.target if isinstance(node, ast.AugAssign) else None)
        if not isinstance(target, ast.Name) or target.id not in groups:
            continue
        try:
            values = ast.literal_eval(node.value)
        except (ValueError, TypeError):
            raise ContractFailure("fixed_source_hook_registry_invalid") from None
        if (type(values) not in (tuple, list) or any(type(name) is not str or not name for name in values)
                or isinstance(node, ast.AugAssign) and (not isinstance(node.op, ast.Add) or target.id not in found)
                or isinstance(node, ast.Assign) and target.id in found):
            raise ContractFailure("fixed_source_hook_registry_invalid")
        groups[target.id] = groups[target.id] + tuple(values)
        found.add(target.id)
    if found != set(groups) or any(len(values) != len(set(values)) for values in groups.values()):
        raise ContractFailure("fixed_source_hook_registry_invalid")
    return {f"mcp__{server}__{tool}" for key, servers in (
        ("WEB_TOOLS", ("flower-web", "flower_web")), ("APP_TOOLS", ("flower-app", "flower_app")),
        ("COMPUTER_TOOLS", ("flower-computer", "flower_computer")))
        for server in servers for tool in groups[key]}


def source_contract(channel: str, module: str, repository: Path | None = None) -> tuple[Path, dict[str, str]]:
    repository = ROOT if repository is None else repository
    entrypoint = repository / (module.replace(".", "/") + ".py")
    declared = declarations(entrypoint)
    if channel == "flower-web":
        status = declarations(repository / "flower_control" / "_status.py")
        declared = {"flower_status": status["flower_status"], **declared}
    admitted = {f"mcp__{server}__{name}" for name in set(declared) - {"flower_status"}
                for server in (channel, channel.replace("-", "_"))}
    registry = FLOWER_TOOLS if repository == ROOT else hook_registry(repository)
    if "flower_status" not in declared or not admitted <= registry:
        raise ContractFailure("source_tools_not_admitted_by_existing_hook_registry")
    return entrypoint, declared


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ContractFailure("duplicate_manifest_key")
        result[key] = value
    return result


def read_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_pairs)
    if type(value) is not dict:
        raise ContractFailure("manifest_not_object")
    return value


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def reject_links(path: Path) -> None:
    for item in (path, *path.parents):
        if (item.is_symlink() or item.is_junction() or item.exists() and
                getattr(item.stat(follow_symlinks=False), "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT):
            raise ContractFailure("fixed_installation_link_rejected")


def verify_hashes(directory: Path, hashes: dict) -> None:
    if type(hashes) is not dict or not hashes:
        raise ContractFailure("fixed_installation_hashes_invalid")
    for name, expected in hashes.items():
        if (type(name) is not str or not name or name in {".", ".."}
                or any(c in name for c in "\\/:*?") or type(expected) is not str
                or not re.fullmatch(r"[a-f0-9]{64}", expected)):
            raise ContractFailure("fixed_installation_hashes_invalid")
        path = directory / name
        reject_links(path)
        if not path.is_file() or digest(path) != expected:
            raise ContractFailure("fixed_installation_hash_mismatch")


def file_inventory(directory: Path) -> set[str]:
    """Reject reparse entries before traversing any version subtree."""
    pending, files = [directory], set()
    while pending:
        current = pending.pop()
        reject_links(current)
        for path in current.iterdir():
            reject_links(path)
            if path.is_dir():
                pending.append(path)
            elif path.is_file():
                files.add(path.relative_to(directory).as_posix())
            else:
                raise ContractFailure("fixed_installation_inventory_mismatch")
    return files


def verify_runtime(directory: Path, active: dict, policy: dict) -> set[str]:
    hashes = active["runtime_hashes"]
    if type(hashes) is not dict or not hashes or len(hashes) > 60000:
        raise ContractFailure("fixed_runtime_hashes_invalid")
    for name, expected in hashes.items():
        if (type(name) is not str or not name or any(c in name for c in "\\:*?")
                or len(name.split("/")) < 2 or name.split("/")[0] not in {"runtime", "python-source"}
                or any(part in {"", ".", ".."} for part in name.split("/"))
                or type(expected) is not str or re.fullmatch(r"[a-f0-9]{64}", expected) is None):
            raise ContractFailure("fixed_runtime_hashes_invalid")
        path = directory / name
        reject_links(path)
        if not path.is_file() or digest(path) != expected:
            raise ContractFailure("fixed_runtime_hash_mismatch")
    path = directory / "runtime-inventory.json"
    expected_manifest = policy.get("RuntimeInventorySha256")
    if (type(expected_manifest) is not str or re.fullmatch(r"[a-f0-9]{64}", expected_manifest) is None
            or expected_manifest != active["hashes"]["runtime-inventory.json"] or digest(path) != expected_manifest):
        raise ContractFailure("fixed_runtime_manifest_pin_mismatch")
    manifest = read_json(path)
    fingerprint = hashlib.sha256(json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if (set(manifest) != {"schema", "files", "dependency_inventory_sha256", "downloads", "data_migrated"}
            or type(manifest["schema"]) is not int or manifest["schema"] != 1 or manifest["files"] != hashes
            or manifest["dependency_inventory_sha256"] != fingerprint
            or manifest["downloads"] is not False or manifest["data_migrated"] is not False):
        raise ContractFailure("fixed_runtime_manifest_mismatch")
    return set(hashes)


def verify_frozen_python_path(directory: Path, target: Path | None = None) -> None:
    """A pinned hash must also describe the fixed isolated loader contract."""
    target = directory if target is None else target
    site = target / "python-source/.venv/Lib/site-packages"
    expected = list((target / "runtime/Lib", target / "runtime/DLLs", site,
                     site / "win32", site / "win32/lib", site / "pythonwin",
                     target / "python-source"))
    path = directory / "flower-python._pth"
    reject_links(path)
    if path.stat().st_size > 8192:
        raise ContractFailure("fixed_runtime_python_path_invalid")
    lines = path.read_text(encoding="utf-8").splitlines()
    if len(lines) != len(expected) or any(not Path(line).is_absolute() or Path(line) != wanted for line, wanted in zip(lines, expected)):
        raise ContractFailure("fixed_runtime_python_path_invalid")


def installed_entry() -> tuple[Path, dict]:
    # Same production root and active.json contract as high_helper._installed_bundle.
    from flower_control.install_location import discover_installation
    directory_root = discover_installation().program_root
    reject_links(directory_root)
    reject_links(directory_root / "active.json")
    active = read_json(directory_root / "active.json")
    if (set(active) not in ({"schema", "version", "hashes"}, {"schema", "version", "hashes", "runtime_hashes"}) or type(active["schema"]) is not int
            or active["schema"] != 1 or type(active["version"]) is not str
            or not re.fullmatch(r"[a-f0-9]{16,64}", active["version"])):
        raise ContractFailure("fixed_installation_manifest_invalid")
    directory = directory_root / "versions" / active["version"]
    reject_links(directory)
    frozen = "runtime_hashes" in active
    required = {"Flower.HighHelper.exe", "Flower.HighHelper.dll", "Flower.HighHelper.deps.json",
        "Flower.HighHelper.runtimeconfig.json", "flower-python.exe", "flower-python._pth", "flower_bootstrap.py", "broker.json"}
    if frozen:
        required |= {"runtime-inventory.json", "flower_hook_bootstrap.py"}
    if type(active["hashes"]) is not dict or not required <= set(active["hashes"]):
        raise ContractFailure("fixed_installation_required_hashes_missing")
    verify_hashes(directory, active["hashes"])
    reject_links(directory / "installation.json")
    if read_json(directory / "installation.json") != active:
        raise ContractFailure("fixed_installation_manifest_mismatch")
    policy = read_json(directory / "broker.json")
    repository = directory / "python-source" if frozen else ROOT
    if (type(policy.get("Schema")) is not int or policy["Schema"] != 1
            or policy.get("Version") != active["version"]
            or type(policy.get("Repository")) is not str or not Path(policy["Repository"]).is_absolute()
            or Path(policy["Repository"]).resolve() != repository.resolve()
            or policy.get("Mode") != "high"
            or policy.get("Python") != {"Path": str(directory / "flower-python.exe"),
                                        "Sha256": active["hashes"]["flower-python.exe"]}):
        raise ContractFailure("fixed_installation_policy_binding_mismatch")
    expected_files = set(active["hashes"]) | {"installation.json"}
    if frozen:
        expected_files |= verify_runtime(directory, active, policy)
        verify_frozen_python_path(directory)
    if "Flower.AppWorker.exe" not in policy.get("AppWorkerHashes", {}):
        raise ContractFailure("fixed_installation_app_hashes_missing")
    verify_hashes(directory / "app", policy["AppWorkerHashes"])
    expected_files |= {"app/" + name for name in policy["AppWorkerHashes"]}
    if frozen and "Flower.ComputerWgc.exe" not in policy.get("WgcWorkerHashes", {}):
        raise ContractFailure("fixed_installation_wgc_hashes_missing")
    if "WgcWorkerHashes" in policy:
        verify_hashes(directory / "wgc", policy["WgcWorkerHashes"])
        expected_files |= {"wgc/" + name for name in policy["WgcWorkerHashes"]}
    if file_inventory(directory) != expected_files:
        raise ContractFailure("fixed_installation_inventory_mismatch")
    # The entire version tree has been checked before traversing its source;
    # an unlisted reparse subtree must not make source discovery read elsewhere.
    sources = {p.relative_to(repository).as_posix(): digest(p)
               for p in (repository / "flower_control").rglob("*.py") if "__pycache__" not in p.parts}
    if (repository / "hooks").is_dir():
        sources.update({p.relative_to(repository).as_posix():digest(p) for p in (repository / "hooks").glob("*.py")})
    for name in ("tools/open_flower_browser.py", "tools/settings_portability.py", "tools/storage_maintenance.py"):
        entry = repository / name
        if entry.is_file():
            sources[name] = digest(entry)
    sources["@bootstrap"] = digest(repository / "flower_control/drivers/high_helper/flower_bootstrap.py")
    if (policy.get("SourceHashes") != sources
            or active["hashes"]["flower_bootstrap.py"] != sources["@bootstrap"]):
        raise ContractFailure("fixed_installation_source_changed")
    if frozen and (active["hashes"]["flower_hook_bootstrap.py"] !=
            sources.get("flower_control/drivers/high_helper/flower_hook_bootstrap.py")):
        raise ContractFailure("fixed_installation_hook_source_changed")
    return directory / "Flower.HighHelper.exe", active


def launch_spec(channel: str, module: str, mode: str = "source", manifest_path: Path | None = None) -> dict:
    manifest = read_json(manifest_path or ROOT / ".mcp.json")
    if set(manifest) != {"mcpServers"} or type(manifest["mcpServers"]) is not dict or set(manifest["mcpServers"]) != set(CHANNELS):
        raise ContractFailure("manifest_channels_changed")
    if mode not in {"source", "installed-fixed"}:
        raise ContractFailure("probe_mode_invalid")
    installed = installed_entry() if mode == "installed-fixed" else None
    command = installed[0] if installed else ROOT / ".venv/Scripts/flower-python.exe"
    repository = command.parent / "python-source" if installed and "runtime_hashes" in installed[1] else ROOT
    for name, entry in manifest["mcpServers"].items():
        args = ["--flower-client", name] if installed else ["-m", CHANNELS[name]]
        if (type(entry) is not dict or set(entry) != {"command", "args", "cwd"}
                or type(entry["command"]) is not str or type(entry["cwd"]) is not str
                or not Path(entry["command"]).is_absolute() or not Path(entry["cwd"]).is_absolute()
                or Path(entry["command"]).resolve() != command.resolve()
                or Path(entry["cwd"]).resolve() != repository.resolve() or entry["args"] != args):
            raise ContractFailure("manifest_launch_boundary_changed")
    spec = dict(manifest["mcpServers"][channel])
    if installed:
        spec["args"] = ["--flower-probe", channel]
        spec["installation"] = installed[1]
    return spec


def guard_provenance(stderr: str, channel: str, repository: Path | None = None) -> dict:
    repository = ROOT if repository is None else repository
    first = stderr.splitlines()[0] if stderr.splitlines() else ""
    try:
        record = json.loads(first, object_pairs_hook=unique_pairs)
    except (ValueError, TypeError):
        raise ContractFailure("fixed_probe_bootstrap_missing") from None
    if (type(record) is not dict or type(record.get("flower_bootstrap")) is not int
            or record["flower_bootstrap"] != 1 or record.get("probe_guard_active") is not True
            or record.get("channel") != channel or type(record.get("pid")) is not int or record["pid"] <= 0
            or type(record.get("source_root")) is not str or type(record.get("cwd")) is not str
            or not Path(record["source_root"]).is_absolute() or not Path(record["cwd"]).is_absolute()
            or Path(record["source_root"]).resolve() != repository.resolve() or Path(record["cwd"]).resolve() != repository.resolve()):
        raise ContractFailure("fixed_probe_guard_provenance_mismatch")
    return record


async def probe(channel: str, module: str, mode: str = "source", manifest_path: Path | None = None) -> dict:
    spec = launch_spec(channel, module, mode, manifest_path)
    repository = Path(spec["cwd"])
    entrypoint, expected = source_contract(channel, module, repository)
    before = loaded_source(str(entrypoint))
    environment = os.environ.copy()
    if mode == "source":
        environment["PYTHONPATH"] = str(ROOT / "tests" / "no_network")
    # The guard permits Windows asyncio's loopback pair, rejects external DNS
    # and connections. The only tool call below is the read-only flower_status.
    params = StdioServerParameters(command=spec["command"], args=spec["args"],
                                   cwd=spec["cwd"], env=environment)
    with tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as diagnostics:
        async with stdio_client(params, errlog=diagnostics) as (read, write):
            async with ClientSession(read, write) as session:
                initialized = await session.initialize()
                listed = await session.list_tools()
                actual = {tool.name: tool.description for tool in listed.tools}
                if len(actual) != len(listed.tools) or actual != expected:
                    raise ContractFailure("runtime_tool_names_or_descriptions_differ_from_source")
                for tool in listed.tools:
                    if tool.inputSchema.get("type") != "object":
                        raise ContractFailure("tool_input_schema_not_object")
                response = await session.call_tool("flower_status", arguments={})
                if response.isError or not response.content or response.content[0].type != "text":
                    raise ContractFailure("status_response_invalid")
                status = json.loads(response.content[0].text)
                if (status["channel"] != channel or status["ready"] is not False
                        or status["overall_complete"] is not False or status["channel_usable"] is not True
                        or status["registered_tools"] != [tool.name for tool in listed.tools]):
                    raise ContractFailure("status_registration_or_evidence_boundary_mismatch")
                after = loaded_source(str(entrypoint))
                for key in ("entrypoint_sha256_at_server_creation", "package_source_sha256_at_server_creation",
                            "package_source_files"):
                    if before[key] != after[key] or status["loaded_source"][key] != before[key]:
                        raise ContractFailure("source_changed_during_probe_or_loaded_fingerprint_mismatch")
                schema_hash = hashlib.sha256(json.dumps(
                    {tool.name: tool.inputSchema for tool in listed.tools}, sort_keys=True,
                    separators=(",", ":")).encode()).hexdigest()
                result = {"channel": channel, "protocol_version": initialized.protocolVersion,
                          "tool_count": len(actual), "registered_tools": list(actual),
                          "input_schema_sha256": schema_hash, "loaded_source": status["loaded_source"],
                          "source_contract_matched": True, "host_injection_verified": False,
                          "control_tools_called": False, "launch_mode": mode,
                          "source_sitecustomize_guard_requested": mode == "source",
                          "installed_fixed_entry_verified": mode == "installed-fixed"}
        # stdio_client closes stdin and waits for only its own server process.
        if mode == "installed-fixed":
            diagnostics.seek(0)
            result["bootstrap_provenance"] = guard_provenance(diagnostics.read(), channel, repository)
            # Bind report to the same unchanged installed bytes after the probe.
            if launch_spec(channel, module, mode, manifest_path) != spec:
                raise ContractFailure("fixed_installation_changed_during_probe")
            result["installation"] = spec["installation"]
    return result


async def run(selected: list[str], describe_only: bool, mode: str = "source", manifest_path: Path | None = None) -> list[dict]:
    results = []
    for channel in selected:
        module = CHANNELS[channel]
        if describe_only:
            spec = launch_spec(channel, module, mode, manifest_path)
            _, expected = source_contract(channel, module, Path(spec["cwd"]))
            results.append({"channel": channel, "declared_tools": list(expected),
                            "tool_count": len(expected), "handshake_run": False, "launch_mode": mode,
                            "command": spec["command"], "args": spec["args"],
                            "installed_fixed_entry_verified": mode == "installed-fixed",
                            "probe_guard_verified": False, "host_injection_verified": False})
        else:
            results.append(await asyncio.wait_for(probe(channel, module, mode, manifest_path), timeout=20))
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--describe-only", action="store_true", help="Inspect declarations and manifest without launching servers")
    parser.add_argument("--channel", choices=tuple(CHANNELS), action="append")
    parser.add_argument("--mode", choices=("source", "installed-fixed"), default="installed-fixed",
                        help="Default checks the deployed fixed manifest; source mode needs its own source-launch manifest")
    parser.add_argument("--manifest", type=Path, help="Exact source or proposed fixed MCP manifest; entries remain strictly validated")
    parser.add_argument("--output", type=Path, help="Optional local JSON report; parent directory must already exist")
    options = parser.parse_args()
    try:
        report = {"scope": options.mode + "_stdio_contract_only", "host_injection_verified": False,
                  "channels": asyncio.run(run(options.channel or list(CHANNELS), options.describe_only,
                                              options.mode, options.manifest))}
    except Exception as error:
        print(json.dumps({"scope": options.mode + "_stdio_contract_only", "passed": False,
                          "error_type": type(error).__name__,
                          "error_code": failure_code(error)},
                         ensure_ascii=False))
        return 1
    encoded = json.dumps(report, ensure_ascii=False, indent=2)
    if options.output is not None:
        with options.output.open("x", encoding="utf-8") as output:
            output.write(encoded + "\n")
    print(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
