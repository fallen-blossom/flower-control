"""Build a generic offline Windows payload from admitted local dependencies.

No installation, download, host registration, credential or user-data reads.
The recipient creates machine bindings with offline_install, after extraction.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.metadata as metadata
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.runtime_snapshot import inventory_runtime, reject_links, digest
from tools.prepare_high_broker_install import native_source_hashes, native_binary_hashes

PROJECTS = {
    "native": "flower_control/drivers/high_helper/Flower.HighHelper.csproj",
    "app": "flower_control/drivers/app_native/Flower.AppWorker.csproj",
    "wgc": "flower_control/drivers/computer_wgc/Flower.ComputerWgc.csproj",
    "probe": "tools/codex_signer_probe/Probe.csproj",
}
ENTRY_TOOLS = (
    "offline_install", "offline_release", "prepare_high_broker_install",
    "prepare_frozen_plugin", "configure_local_plugin", "configure_dsh_plugin",
    "prepare_work_authority_update", "prepare_stopped_host_update",
    "prepare_uninstall", "settings_portability", "storage_maintenance",
)
GUIDE_FILES = (
    "VERSION", "LICENSE", "THIRD_PARTY_NOTICES.md", "PRIVACY.md", "PRIVACY.zh-CN.md",
    "SECURITY.md", "START_HERE.zh-CN.txt", "README.md", "README.zh-CN.md",
    *("docs/" + name + suffix for name in (
        "ANTIGRAVITY", "BROWSER_PROFILES", "CLAUDE_CODE", "INSTALL_WITH_CODEX", "INSTALL",
        "INSTALLER", "LOCAL_CLIENTS", "PERMISSIONS", "RELEASE_NOTES", "TROUBLESHOOTING",
        "USAGE", "VALIDATION") for suffix in (".md", ".zh-CN.md")),
    "docs/SHARING.md",
)


def validate_release_versions(repository: Path) -> str:
    """Bind the human release label to the metadata actually compiled/shipped.

    The recipient's 32-hex runtime version remains a separate content identity.
    Public exports keep VERSION at their root; the implementation keeps the
    same release value in its explicit public-presentation directory.
    """
    repository = Path(repository)
    version_file = repository / "release/github/VERSION"
    if not version_file.is_file():
        version_file = repository / "VERSION"
    reject_links(version_file)
    version = version_file.read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", version):
        raise ValueError("offline_release_version_invalid")
    plugin = json.loads((repository / ".codex-plugin/plugin.json").read_bytes())
    project = tomllib.loads((repository / "pyproject.toml").read_text(encoding="utf-8-sig"))
    if plugin.get("version") != version or project.get("project", {}).get("version") != version:
        raise ValueError("offline_release_metadata_version_mismatch")
    assembly_version = version.split("-", 1)[0] + ".0"
    expected = dict(Version=version, FileVersion=assembly_version,
        AssemblyVersion=assembly_version, InformationalVersion=version)
    for name in (*PROJECTS.values(), "tools/installer/FlowerControl.Setup.csproj"):
        path = repository / name
        reject_links(path)
        tree = ET.parse(path)
        if any(tree.findtext(".//" + field) != value for field, value in expected.items()):
            raise ValueError("offline_release_project_version_mismatch:" + name)
    for name in ("tools/installer/setup.manifest", "flower_control/drivers/high_helper/app.manifest"):
        path = repository / name
        reject_links(path)
        identity = ET.parse(path).getroot().find("{urn:schemas-microsoft-com:asm.v1}assemblyIdentity")
        if identity is None or identity.get("version") != assembly_version:
            raise ValueError("offline_release_application_version_mismatch:" + name)
    return version


def tool_closure(repository: Path) -> set[Path]:
    """Resolve local tool imports, refusing an incomplete distributable."""
    result: set[Path] = set()
    pending = [repository / "tools" / (name + ".py") for name in ENTRY_TOOLS]
    while pending:
        path = pending.pop()
        if path in result:
            continue
        if not path.is_file():
            raise ValueError("offline_maintenance_entry_missing:" + path.name)
        result.add(path)
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8-sig"))):
            if isinstance(node, ast.ImportFrom) and node.module:
                names = ([node.module] if node.module.startswith("tools.") else
                         ["tools." + alias.name for alias in node.names] if node.module == "tools" else [])
            elif isinstance(node, ast.Import):
                names = [alias.name for alias in node.names if alias.name.startswith("tools.")]
            else:
                continue
            for name in names:
                candidate = repository / (name.replace(".", "/") + ".py")
                if candidate.is_file():
                    pending.append(candidate)
    return result


def locked_versions(repository: Path, site: Path) -> dict[str, str]:
    required: dict[str, str] = {}
    for lock in ("requirements.lock", "requirements-web.lock"):
        for line in (repository / lock).read_text(encoding="utf-8").splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            match = re.fullmatch(r"([\w.-]+)==([\w.+-]+)(?:\s+--hash=sha256:[a-f0-9]{64})+", line.strip())
            if not match:
                raise ValueError("offline_dependency_lock_invalid")
            name, version = match.groups()
            key = re.sub(r"[-_.]+", "-", name).lower()
            if key in required and required[key] != version:
                raise ValueError("offline_dependency_lock_conflict")
            required[key] = version
    found = {re.sub(r"[-_.]+", "-", item.metadata["Name"]).lower(): item.version
             for item in metadata.distributions(path=[str(site)])}
    if any(found.get(name) != version for name, version in required.items()):
        raise ValueError("offline_dependency_version_mismatch")
    return required


def run(command: list[str], cwd: Path, log: Path) -> None:
    env = {**os.environ, "DOTNET_CLI_TELEMETRY_OPTOUT": "1", "DOTNET_NOLOGO": "1"}
    with log.open("ab") as output:
        result = subprocess.run(command, cwd=cwd, env=env, stdout=output, stderr=subprocess.STDOUT,
                                timeout=600, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if result.returncode:
        raise RuntimeError("offline_build_failed:" + log.name)


def publish(repository: Path, work: Path, kind: str) -> tuple[Path, Path]:
    project = repository / PROJECTS[kind]
    output = work / kind
    log = work / (kind + "-build.log")
    before = (native_source_hashes(repository) if kind == "native" else
        {p.relative_to(repository).as_posix(): digest(p) for p in project.parent.iterdir()
         if p.suffix in {".cs", ".csproj"} or p.name == "packages.lock.json"})
    if kind == "probe":
        before["flower_control/drivers/high_helper/InstallationLocation.cs"] = digest(repository / "flower_control/drivers/high_helper/InstallationLocation.cs")
    if kind == "native":
        ps = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        run([str(ps), "-NoLogo", "-NoProfile", "-NonInteractive", "-File",
             str(repository / "tools/build_identity_native.ps1"), "-OutputDirectory", str(output)], repository, log)
    # An empty NuGet source allows the pre-admitted local cache, and fails
    # closed when a runtime/locked dependency is missing. This never fetches.
    empty_source = work / "empty-nuget-source"
    empty_source.mkdir(exist_ok=True)
    run(["dotnet", "restore", str(project), "-r", "win-x64", "--locked-mode",
         "--source", str(empty_source), "-p:SelfContained=true", "-p:NuGetAudit=false"], repository, log)
    run(["dotnet", "publish", str(project), "-c", "Release", "-r", "win-x64", "--self-contained", "true",
         "--no-restore", "-p:PublishSingleFile=false", "-p:DebugType=None", "-p:DebugSymbols=false",
         "-o", str(output)], repository, log)
    after = (native_source_hashes(repository) if kind == "native" else
        {p.relative_to(repository).as_posix(): digest(p) for p in project.parent.iterdir()
         if p.suffix in {".cs", ".csproj"} or p.name == "packages.lock.json"})
    if kind == "probe":
        after["flower_control/drivers/high_helper/InstallationLocation.cs"] = digest(repository / "flower_control/drivers/high_helper/InstallationLocation.cs")
    if before != after or not (output / "coreclr.dll").is_file():
        raise ValueError("offline_build_source_changed_or_runtime_missing")
    hashes = (native_binary_hashes(repository, output) if kind == "native" else
        {p.name: digest(p) for p in output.iterdir() if p.is_file() and p.suffix in {".exe", ".dll", ".json"}})
    evidence = work / (kind + "-build-evidence.json")
    evidence.write_text(json.dumps(dict(schema=1, build_exit_code=0, source_unchanged_during_build=True,
        source_hashes=before, binary_hashes=hashes, self_contained=True,
        **{kind + "_bin": str(output)}), indent=2) + "\n", encoding="utf-8")
    return output, evidence


def copy_file(source: Path, target: Path) -> None:
    reject_links(source)
    if target.exists():
        if digest(source) != digest(target):
            raise ValueError("offline_payload_path_conflict")
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    if digest(source) != digest(target):
        raise ValueError("offline_payload_copy_changed")


def verified_encoder_materials(repository: Path, media_encoder: Path) -> tuple[dict, dict[str, Path]]:
    """Bind the binary, original notices and corresponding source to review.

    This checks the reviewed material inventory. It grants no trust to a new
    executable path and is not a blanket legal-compliance assertion.
    """
    policy_path = repository / "ENCODER.json"
    reject_links(policy_path)
    policy = json.loads(policy_path.read_bytes())
    if (policy.get("schema") != 1 or policy.get("name") != "FFmpeg"
            or policy.get("license") != "GPL-3.0-or-later"
            or policy.get("build_inputs_verified") is not True
            or policy.get("corresponding_source_review", {}).get("state") != "materials_verified"):
        raise ValueError("offline_encoder_material_review_required")
    presentation = repository / "release/github/ENCODER.json"
    if presentation.is_file() and digest(presentation) != digest(policy_path):
        raise ValueError("offline_encoder_presentation_pin_changed")

    def check(path, expected):
        reject_links(path)
        if (not isinstance(expected, str) or not re.fullmatch(r"[a-f0-9]{64}", expected)
                or not path.is_file() or digest(path) != expected):
            raise ValueError("offline_encoder_material_changed:" + path.name)
        return path

    check(media_encoder, policy.get("sha256"))
    if media_encoder.name.lower() != "ffmpeg.exe":
        raise ValueError("offline_encoder_executable_name_rejected")
    materials = {"ENCODER.json": policy_path}
    for key, expected_name in (("license_file", "LICENSE"), ("notices", "NOTICE.txt")):
        item = policy.get(key, {})
        if item.get("path") != expected_name:
            raise ValueError("offline_encoder_notice_path_rejected")
        materials[expected_name] = check(media_encoder.parent / expected_name, item.get("sha256"))
    source = policy.get("corresponding_source", {})
    name = source.get("artifact", "")
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*\.zip", name):
        raise ValueError("offline_encoder_source_name_rejected")
    materials[name] = check(media_encoder.parent / name, source.get("sha256"))
    for key, expected_path in (("inputs_lock", "tools/encoder_build/inputs.lock.json"),
                               ("recipe", "tools/encoder_build/build.sh")):
        item = policy.get(key, {})
        if item.get("path") != expected_path:
            raise ValueError("offline_encoder_recipe_path_rejected")
        check(repository / expected_path, item.get("sha256"))
    with zipfile.ZipFile(materials[name]) as bundle:
        info = bundle.getinfo("source-index.json")
        if info.file_size > 1024 * 1024:
            raise ValueError("offline_encoder_source_index_too_large")
        index = json.loads(bundle.read(info))
        if (index.get("schema") != 1 or index.get("encoder_version") != policy.get("version")
                or index.get("binary_hashes", {}).get("ffmpeg.exe") != policy["sha256"]
                or index.get("public_input_lock_sha256") != policy["inputs_lock"]["sha256"]
                or index.get("recipe_sha256") != policy["recipe"]["sha256"]):
            raise ValueError("offline_encoder_source_binary_binding_changed")
    return policy, materials


def build(repository: Path, runtime: Path, site: Path, output: Path, *, media_encoder: Path, with_setup=True) -> dict:
    for path in (repository, runtime, site, output):
        reject_links(path)
    if output.exists() or sys.version_info[:2] != (3, 14):
        raise ValueError("offline_new_output_and_python314_required")
    release = validate_release_versions(repository)
    dependencies = locked_versions(repository, site)
    encoder_policy, encoder_materials = verified_encoder_materials(repository, media_encoder)
    work = Path(tempfile.mkdtemp(prefix="flower-offline-build-"))
    outputs = {kind: publish(repository, work, kind) for kind in PROJECTS}
    output.mkdir(parents=True)
    payload = output / "Payload"
    payload.mkdir()
    presentation = repository / "release/github" if (repository / "release/github/LICENSE").is_file() else repository
    for name in GUIDE_FILES:
        copy_file(presentation / name, payload / "Guides" / name)
    # Public source exports already contain the reviewed dependency inventory.
    # A private developer tree may omit it; no local environment scan is added.
    inventory = repository / "dependency-inventory.json"
    if inventory.is_file():
        copy_file(inventory, payload / "Guides/dependency-inventory.json")
    rows = inventory_runtime(repository, runtime, site)
    for name, item in rows.items():
        relative = (Path("Python") / name.removeprefix("runtime/") if name.startswith("runtime/")
                    else Path("Source") / name.removeprefix("python-source/"))
        copy_file(item["path"], payload / relative)
    for name in ("python.exe", "python3.dll", "python314.dll", "LICENSE.txt"):
        copy_file(runtime / name, payload / "Python" / name)
    for source in runtime.glob("vcruntime*.dll"):
        copy_file(source, payload / "Python" / source.name)
    copy_file(media_encoder, payload / "Encoder/ffmpeg.exe")
    copy_file(encoder_materials["LICENSE"], payload / "Encoder/LICENSE")
    copy_file(encoder_materials["NOTICE.txt"], payload / "Encoder/NOTICE.txt")
    for name, source in encoder_materials.items():
        copy_file(source, payload / "Notices/encoder" / name)
    (payload / "Python/python._pth").write_text(
        "Lib\nDLLs\n../Source/.venv/Lib/site-packages\n../Source/.venv/Lib/site-packages/win32\n"
        "../Source/.venv/Lib/site-packages/win32/lib\n../Source/.venv/Lib/site-packages/pythonwin\n../Source\n", encoding="utf-8")
    for name in native_source_hashes(repository):
        copy_file(repository / name, payload / "Source" / name)
    for source in tool_closure(repository):
        copy_file(source, payload / "Source" / source.relative_to(repository))
    for source in (repository / "integrations/dsh").iterdir():
        if source.name in {"index.mjs", "plugin.mjs", "host-bridge.mjs", "metadata.mjs", "package.json", "README.md"}:
            copy_file(source, payload / "Source/integrations/dsh" / source.name)
    for source in (repository / "tools/high_broker_install").iterdir():
        if source.suffix in {".template", ".cs"} or source.name == "legacy_source_compatibility.json":
            copy_file(source, payload / "Source/tools/high_broker_install" / source.name)
    for source in (repository / "tools/codex_signer_probe").iterdir():
        if source.suffix in {".cs", ".csproj"} or source.name == "NuGet.Config":
            copy_file(source, payload / "Source/tools/codex_signer_probe" / source.name)
    for kind, (binary, evidence) in outputs.items():
        for source in binary.iterdir():
            if source.is_file() and (source.suffix in {".dll", ".exe", ".json"}
                    or source.name.upper() in {"LICENSE.TXT", "THIRD-PARTY-NOTICES.TXT"}):
                copy_file(source, payload / "Binaries" / kind / source.name)
        copy_file(evidence, payload / "Evidence" / evidence.name)
        portable_evidence = json.loads((payload / "Evidence" / evidence.name).read_bytes())
        portable_evidence[kind + "_bin"] = "@payload/Binaries/" + kind
        (payload / "Evidence" / evidence.name).write_text(json.dumps(portable_evidence, indent=2) + "\n", encoding="utf-8")
        if kind == "native":
            identity_path = payload / "Binaries/native/build-evidence.json"
            identity = json.loads(identity_path.read_bytes())
            for field in ("compiler_setup", "compiler_binary", "linker_binary"):
                identity.pop(field, None)
            identity["source"] = "@payload/Source/flower_control/drivers/high_helper/program_identity_native.cpp"
            identity["dll"] = "@payload/Binaries/native/Flower.UacNative.dll"
            identity_path.write_text(json.dumps(identity, indent=2) + "\n", encoding="utf-8")
    probe_root = payload / "SignerProbe"
    for source in (payload / "Source/tools/codex_signer_probe").iterdir():
        if source.suffix == ".cs" or source.name in {"Probe.csproj", "NuGet.Config"}:
            copy_file(source, probe_root / source.name)
    copy_file(repository / "flower_control/drivers/high_helper/InstallationLocation.cs", probe_root / "InstallationLocation.cs")
    probe_hashes = {p.name: digest(p) for p in (payload / "Binaries/probe").iterdir()
                    if p.suffix in {".exe", ".dll", ".json"}}
    for name in probe_hashes:
        copy_file(payload / "Binaries/probe" / name, probe_root / "native" / name)
    probe_sources = {name: digest(probe_root / name) for name in ("Program.cs", "Probe.csproj", "NuGet.Config", "Boundary.cs")}
    probe_sources["@installation-location"] = digest(probe_root / "InstallationLocation.cs")
    (probe_root / "probe-build-evidence.json").write_text(json.dumps(dict(schema=1, exit_code=0,
        package_sources_cleared=True, self_contained=True, source_hashes=probe_sources,
        binary_hashes=probe_hashes, input_or_authority_operations=False), indent=2) + "\n", encoding="utf-8")
    # Export license texts, including package-provided licences; no secrets,
    # profiles, grants or settings are ever candidates for this inventory.
    for path in site.glob("*.dist-info"):
        for source in path.rglob("*"):
            if source.is_file() and ("license" in str(source.relative_to(path)).lower()
                                     or source.name.lower().startswith(("copying", "notice"))):
                copy_file(source, payload / "Notices" / path.name / source.relative_to(path))
    nuget = Path(os.environ.get("NUGET_PACKAGES", str(Path.home() / ".nuget/packages")))
    for project in PROJECTS.values():
        lock = (repository / project).parent / "packages.lock.json"
        if not lock.is_file():
            continue
        for packages in json.loads(lock.read_bytes()).get("dependencies", {}).values():
            for package, info in packages.items():
                version = info.get("resolved")
                if not version:
                    continue
                folder = nuget / package.lower() / version
                if not folder.is_dir():
                    continue
                for source in folder.iterdir():
                    if source.is_file() and (source.suffix == ".nuspec" or source.name.lower().startswith(("license", "notice", "copying"))):
                        copy_file(source, payload / "Notices" / (package + "." + version) / source.name)
    for name in ("microsoft.netcore.app.runtime.win-x64", "microsoft.windowsdesktop.app.runtime.win-x64"):
        # The exact runtime version is recorded by each .runtimeconfig.json.
        for version in {json.loads(p.read_bytes())["runtimeOptions"]["includedFrameworks"][0]["version"]
                        for p in (payload / "Binaries").glob("*/*.runtimeconfig.json")}:
            for filename in ("LICENSE.TXT", "THIRD-PARTY-NOTICES.TXT"):
                source = nuget / name / version / filename
                if source.is_file():
                    copy_file(source, payload / "Notices" / (name + "." + version) / filename)
    if validate_release_versions(repository) != release:
        raise ValueError("offline_release_version_changed_during_build")
    if verified_encoder_materials(repository, media_encoder)[0] != encoder_policy:
        raise ValueError("offline_encoder_pin_changed_during_build")
    files = {p.relative_to(payload).as_posix(): digest(p) for p in payload.rglob("*") if p.is_file()}
    record = dict(schema=1, platform="win-x64", generic=True, files=files,
        release_version=release,
        python_version=".".join(map(str, sys.version_info[:3])), dependencies=dependencies,
        recipient_binding_required=True, installed=False, downloads=False, signed=False,
        media_encoder=dict(path="Encoder/ffmpeg.exe", sha256=encoder_policy["sha256"],
            version=encoder_policy["version"], corresponding_source=encoder_policy["corresponding_source"],
            source_materials="Notices/encoder"),
        redistribution_review=dict(state="bundled_license_and_encoder_source_materials_recorded",
            blanket_legal_compliance_assertion=False))
    (payload / "payload.json").write_text(json.dumps(record, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    archive = output / "FlowerControl-offline-win-x64.zip"
    with zipfile.ZipFile(archive, "x", zipfile.ZIP_DEFLATED, compresslevel=6) as bundle:
        for path in sorted(payload.rglob("*")):
            if path.is_file():
                info = zipfile.ZipInfo(path.relative_to(payload).as_posix(), date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100644 << 16
                bundle.writestr(info, path.read_bytes())
    if with_setup:
        setup = repository / "tools/installer/FlowerControl.Setup.csproj"
        log = work / "setup-build.log"
        run(["dotnet", "restore", str(setup), "-r", "win-x64", "--locked-mode", "--source", str(work / "empty-nuget-source"),
             "-p:SelfContained=true", "-p:NuGetAudit=false"], repository, log)
        run(["dotnet", "publish", str(setup), "-c", "Release", "-r", "win-x64", "--self-contained", "true",
             "--no-restore", "-p:PublishSingleFile=true", "-p:IncludeNativeLibrariesForSelfExtract=true",
             "-p:DebugType=None", "-p:PayloadArchive=" + str(archive), "-o", str(output / "Setup")], repository, log)
    (output / "SHA256SUMS.txt").write_text("".join(digest(p) + "  " + p.relative_to(output).as_posix() + "\n"
        for p in [archive, *sorted((output / "Setup").glob("*.exe"))]), encoding="ascii")
    return dict(payload=str(payload), archive=str(archive), files=len(files), build_evidence=str(work),
                release_version=release,
                installed=False, signed=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, default=Path(sys.base_prefix))
    parser.add_argument("--site", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--media-encoder", type=Path, required=True, help="Previously admitted local FFmpeg executable with adjacent licence; never fetched by this builder")
    parser.add_argument("--without-setup", action="store_true")
    args = parser.parse_args()
    print(json.dumps(build(ROOT, args.runtime.resolve(strict=True), args.site.resolve(strict=True),
        args.output.absolute(), media_encoder=args.media_encoder.resolve(strict=True), with_setup=not args.without_setup)))


if __name__ == "__main__":
    main()
