"""Recipient-side offline setup. Preparation is read-only outside its work area.

Deployment remains an explicit elevated, reviewable script. Native host trust
is never synthesized, and an existing installation keeps its original root.
"""
from __future__ import annotations

import argparse
import base64
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tools.runtime_snapshot import reject_links, digest

MAX_FILES = 60000
MAX_BYTES = 3 * 1024 ** 3
_PYWIN_DLL_HANDLE = None


def initialize_bundled_python():
    global _PYWIN_DLL_HANDLE
    if os.name == "nt" and Path(sys.base_prefix).resolve() == (ROOT.parent / "Python").resolve():
        directory = ROOT / ".venv/Lib/site-packages/pywin32_system32"
        reject_links(directory)
        _PYWIN_DLL_HANDLE = os.add_dll_directory(str(directory))


def safe_payload_name(name):
    reserved = {"CON", "PRN", "AUX", "NUL", *["COM" + str(i) for i in range(1, 10)],
                *["LPT" + str(i) for i in range(1, 10)]}
    return (isinstance(name, str) and 1 <= len(name) <= 512 and not name.startswith("/")
        and not any(c in name for c in "\\:*?\x00")
        and all(part not in {"", ".", ".."} and not part.endswith((".", " "))
                and part.split(".")[0].upper() not in reserved and not any(ord(c) < 32 for c in part)
                for part in name.split("/")))


def read_json(path: Path):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("offline_duplicate_key")
            value[key] = item
        return value
    if path.stat().st_size > 32 * 1024 ** 2:
        raise ValueError("offline_manifest_too_large")
    return json.loads(path.read_bytes(), object_pairs_hook=unique)


def release_version(document: dict) -> str:
    value = document.get("release_version")
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", value):
        raise ValueError("offline_release_version_invalid")
    return value


def verify_payload(payload: Path) -> dict:
    reject_links(payload)
    manifest = read_json(payload / "payload.json")
    files = manifest.get("files")
    if manifest.get("schema") != 1 or manifest.get("generic") is not True or manifest.get("platform") != "win-x64" or not isinstance(files, dict) or not 1 <= len(files) <= MAX_FILES:
        raise ValueError("offline_payload_manifest_invalid")
    release_version(manifest)
    folded = set()
    size = 0
    for name, expected in files.items():
        if not safe_payload_name(name) or name.casefold() in folded:
            raise ValueError("offline_payload_path_invalid")
        folded.add(name.casefold())
        if not isinstance(expected, str) or not re.fullmatch(r"[a-f0-9]{64}", expected):
            raise ValueError("offline_payload_hash_invalid")
        path = payload / name
        reject_links(path)
        if not path.is_file() or digest(path) != expected:
            raise ValueError("offline_payload_changed")
        size += path.stat().st_size
        if size > MAX_BYTES:
            raise ValueError("offline_payload_too_large")
    actual = set()
    for path in payload.rglob("*"):
        reject_links(path)
        if path.is_file():
            actual.add(path.relative_to(payload).as_posix())
    if actual != set(files) | {"payload.json"}:
        raise ValueError("offline_payload_inventory_changed")
    return manifest


def installation_status() -> dict:
    from flower_control.install_location import discover_installation
    location = discover_installation()
    operations = resume_operations(location)
    if not operations:
        location = existing_location()
    active = location.program_root / "active.json"
    return dict(schema=1, installed=active.is_file(), legacy=location.legacy,
                root=str(location.root), program_root=str(location.program_root),
                data_root=str(location.data_root), cache_root=str(location.cache_root),
                packages_root=str(location.packages_root), resumable_operations=operations,
                host_injection_verified=False)


def machine_binding():
    import winreg
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0,
                        winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
        value = winreg.QueryValueEx(key, "MachineGuid")[0]
    return hashlib.sha256(("FlowerControl|" + uuid.UUID(value).hex).encode()).hexdigest()


def resume_operations(location, *, _unregistered=False):
    from flower_control.permissions import _check_protection
    recovery = location.program_root / "recovery"
    if not recovery.is_dir():
        return []
    result = []
    for path in sorted(recovery.glob("installation-*/resume-anchor.json")):
        reject_links(path)
        _check_protection(path, require_label=False)
        anchor = read_json(path)
        if (anchor.get("schema") != 1 or anchor.get("user_sid") != location.user_sid
                or Path(anchor.get("program_root", "")) != location.program_root
                or Path(anchor.get("root", "")) != location.root
                or not re.fullmatch(r"[a-f0-9]{32}", anchor.get("operation_id", ""))
                or anchor.get("kind") not in {"setup", "uninstall"}
                or anchor.get("state") not in {"incomplete", "completed"}):
            raise ValueError("offline_protected_resume_identity_changed")
        # Reinstalling a retained root creates a new installation identity.
        # Old operation receipts stay on disk, but cannot resume in the new one.
        if not _unregistered and anchor.get("installation_id") != location.installation_id:
            continue
        if anchor["state"] == "completed":
            continue
        if anchor.get("machine_binding_sha256") != machine_binding():
            raise ValueError("offline_resume_machine_changed")
        ready = True
        for name in ("plan", "script"):
            material = Path(anchor.get(name + "_path", ""))
            expected = anchor.get(name + "_sha256", "")
            if not material.is_absolute() or not re.fullmatch(r"[a-f0-9]{64}", expected):
                raise ValueError("offline_protected_resume_material_rejected")
            reject_links(material)
            if not material.is_file() or digest(material) != expected:
                ready = False
        result.append(dict(kind=anchor["kind"], operation_id=anchor["operation_id"],
            anchor=str(path), materials_verified=ready, root=str(location.root)))
    return result


def explicit_resume_location(root):
    from flower_control.install_location import discover_installation, prepare_location, validate_preparation_path
    current = discover_installation()
    if Path(root).absolute() == current.root:
        validate_preparation_path(root)
        return current
    selected = prepare_location(root, user_sid=current.user_sid)
    if (current.program_root / "active.json").is_file() and selected.program_root != current.program_root:
        raise ValueError("offline_existing_root_requires_explicit_migration")
    validate_preparation_path(root)
    return current if current.program_root == selected.program_root else selected


def load_resume(operation_id, kind, root=None):
    from flower_control.install_location import discover_installation
    location = discover_installation() if root is None else explicit_resume_location(root)
    matches = [row for row in resume_operations(location, _unregistered=root is not None and not location.installation_id and not location.legacy)
               if row["operation_id"] == operation_id and row["kind"] == kind]
    if len(matches) != 1 or not matches[0]["materials_verified"]:
        raise ValueError("offline_original_resume_material_required")
    anchor = read_json(Path(matches[0]["anchor"]))
    path = Path(anchor["plan_path"])
    plan = read_json(path)
    if plan.get("operation_id") != operation_id or Path(plan.get("program_root", "")) != location.program_root:
        raise ValueError("offline_resume_plan_identity_changed")
    if kind == "setup":
        if plan.get("elevated_script") != anchor["script_path"] or plan.get("elevated_script_sha256") != anchor["script_sha256"]:
            raise ValueError("offline_resume_script_binding_changed")
        return {**plan, "setup_plan_path": str(path), "setup_plan_sha256": anchor["plan_sha256"],
                "resume_anchor": matches[0]["anchor"]}
    return dict(schema=1, plan=str(path), plan_sha256=anchor["plan_sha256"],
        elevated_script=anchor["script_path"], elevated_script_sha256=anchor["script_sha256"],
        root=plan["installation_root"], files=len(plan["files"]), bytes=sum(row["bytes"] for row in plan["files"]),
        preserve=plan["preserve"], blockers=plan["blockers"], result_path=anchor["result_path"],
        operation_id=operation_id, resume_anchor=matches[0]["anchor"], complete=False)


def existing_location():
    from flower_control.install_location import discover_installation
    location = discover_installation()
    active_path = location.program_root / "active.json"
    if location.legacy and active_path.is_file():
        from flower_control.permissions import _check_protection
        _check_protection(active_path, require_label=False)
        active = read_json(active_path)
        version = active.get("version", "")
        if not re.fullmatch(r"[a-f0-9]{32}", version):
            raise ValueError("offline_legacy_manifest_invalid")
        policy_path = location.program_root / "versions" / version / "broker.json"
        _check_protection(policy_path, require_label=False)
        reject_links(policy_path)
        if digest(policy_path) != active.get("hashes", {}).get("broker.json"):
            raise ValueError("offline_legacy_policy_changed")
        policy = read_json(policy_path)
        if policy.get("UserSid") != location.user_sid or policy.get("Version") != version:
            raise ValueError("offline_legacy_policy_binding_changed")
        if policy.get("DataRoot"):
            from flower_control.data_paths import resolve_data_root
            data = resolve_data_root({"FLOWER_DATA_ROOT": policy["DataRoot"]})
            location = replace(location, data_root=data, cache_root=data / "cache")
    return location


def relocated_evidence(payload: Path, work: Path) -> dict:
    """Rebind local locations only after checking all published payload bytes.

    Build hashes and source hashes are kept verbatim. This is relocation of a
    generic build, never evidence that a recipient compiled or tested it.
    """
    result = {}
    for kind in ("native", "app", "wgc"):
        original = payload / "Binaries" / kind
        target = work / "Binaries" / kind
        shutil.copytree(original, target)
        evidence = read_json(payload / "Evidence" / (kind + "-build-evidence.json"))
        if evidence.get("self_contained") is not True or not (target / "coreclr.dll").is_file():
            raise ValueError("offline_self_contained_runtime_required")
        for name, expected in evidence["binary_hashes"].items():
            if Path(name).name != name or digest(target / name) != expected:
                raise ValueError("offline_build_binary_changed")
        evidence[kind + "_bin"] = str(target)
        evidence["relocated_from_generic_payload"] = True
        evidence_path = work / (kind + "-build-evidence.json")
        evidence_path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
        if kind == "native":
            identity_path = target / "build-evidence.json"
            identity = read_json(identity_path)
            identity["source"] = str(ROOT / "flower_control/drivers/high_helper/program_identity_native.cpp")
            identity["dll"] = str(target / "Flower.UacNative.dll")
            identity_path.write_text(json.dumps(identity, indent=2) + "\n", encoding="utf-8")
        result[kind] = (target, evidence_path)
    return result


def prepare(payload: Path, root: Path, work: Path, *, dsh_image: Path | None = None, installer: Path | None = None, codex=True) -> dict:
    if ROOT != (payload / "Source").resolve() or Path(sys.base_prefix).resolve() != (payload / "Python").resolve():
        raise ValueError("offline_bundled_interpreter_required")
    reject_links(work)
    if work.exists() or not work.is_absolute():
        raise ValueError("offline_new_work_directory_required")
    from flower_control.install_location import discover_installation, prepare_location, validate_preparation_path
    selected = prepare_location(root)
    existing = existing_location()
    installed = (existing.program_root / "active.json").is_file()
    if installed and existing.root != selected.root:
        raise ValueError("offline_existing_root_requires_explicit_migration")
    if installed:
        selected = existing
    else:
        validate_preparation_path(root)
    # Reject an unusable destination before scanning the full offline payload.
    # These are read-only checks; payload verification still precedes every
    # directory creation, copy, seal and installation operation below.
    manifest = verify_payload(payload)
    work.mkdir(parents=True)
    binaries = relocated_evidence(payload, work)
    from tools.prepare_high_broker_install import prepare as seal
    package = work / "Package"
    seal(binaries["native"][0], ROOT, binaries["app"][0], binaries["app"][1], binaries["native"][1],
         output=package, install_root=None if installed else root,
         data_root=selected.data_root, freeze_runtime=True,
         media_encoder=payload / "Encoder/ffmpeg.exe",
         wgc_bin=binaries["wgc"][0], wgc_build_evidence=binaries["wgc"][1],
         dsh_images=[dsh_image] if dsh_image else [], preserve_existing_native_host_pins=installed and dsh_image is None)
    candidate_version = read_json(package / "active.json")["version"]
    already_installed = installed and read_json(existing.program_root / "active.json")["version"] == candidate_version
    if already_installed:
        from tools.stdio_contract_check import installed_entry
        installed_entry()  # Real whole-version check, never a version-string green.
        script = work / "AlreadyInstalled.ps1"
        script.write_text((package / "InstallCommon.ps1").read_text(encoding="utf-8-sig") + "\n" + f"""
if((Get-FileHash -LiteralPath (Join-Path $brokerRoot 'active.json') -Algorithm SHA256).Hash.ToLowerInvariant() -cne {ps_literal(digest(existing.program_root / 'active.json'))}) {{throw 'installed_version_changed'}}
$task=Get-FlowerTask
if($null -eq $task) {{
 if((Get-FileHash -LiteralPath (Join-Path $packageRoot 'task.xml') -Algorithm SHA256).Hash.ToLowerInvariant() -cne $taskXmlHash) {{throw 'task_xml_changed'}}
 Register-ScheduledTask -TaskName $taskName -TaskPath '\\' -Xml (Get-Content -LiteralPath (Join-Path $packageRoot 'task.xml') -Raw) | Out-Null
 $task=Get-FlowerTask
}}
Assert-FlowerTaskSecurity
if(@($task.Actions).Count -ne 1 -or $task.Actions.Execute -ine $command -or $task.Actions.Arguments -cne '--serve') {{throw 'installed_task_changed'}}
Write-Output 'same_runtime_verified_maintenance_only'
""", encoding="utf-8-sig")
    elif installed:
        from tools.prepare_work_authority_update import prepare as update
        update_root = work / "Update"
        update(package, update_root, leave_paused=False, signer_probe=payload / "SignerProbe")
        update_plan = read_json(update_root / "plan.json")
        # The plan's named entry is used; never guess by running every script.
        script = update_root / "Update.ps1"
        if not script.is_file():
            raise ValueError("offline_update_entry_missing")
    else:
        script = package / "ApplyInstall.ps1"
        # The original developer entry dot-sources Common by path. The user
        # installer executes a single sealed in-memory script instead.
        text = script.read_text(encoding="utf-8-sig")
        marker = ". (Join-Path $PSScriptRoot 'InstallCommon.ps1')"
        if text.count(marker) != 1:
            raise ValueError("offline_install_common_binding_changed")
        script = work / "ApplyPrepared.ps1"
        script.write_text(text.replace(marker, (package / "InstallCommon.ps1").read_text(encoding="utf-8-sig")), encoding="utf-8-sig")
    result = dict(schema=1, kind="maintenance" if already_installed else "update" if installed else "install", root=str(selected.root),
        operation_id=update_plan["OperationId"] if installed and not already_installed else uuid.uuid4().hex,
        legacy=selected.legacy, program_root=str(selected.program_root),
        data_root=str(selected.data_root), cache_root=str(selected.cache_root), packages_root=str(selected.packages_root),
        package=str(package), elevated_script=str(script), elevated_script_sha256=digest(script),
        version=candidate_version, release_version=release_version(manifest),
        already_installed=already_installed, installed=False,
        host_injection_verified=False, native_trust_required=True, signed=False)
    adapters = prepare_adapters(package, work / "Integrations", selected.program_root,
                                result["version"], codex=codex, dsh=dsh_image is not None)
    result["adapters"] = adapters
    result["guide_files"] = [dict(source=str(path), name=path.relative_to(payload).as_posix(),
        sha256=digest(path), bytes=path.stat().st_size)
        for folder in (payload / "Guides", payload / "Notices")
        for path in sorted(folder.rglob("*")) if path.is_file()]
    if installed and not already_installed:
        result["core_update"] = dict(operation=update_plan["OperationId"],
            receipt=str(update_plan["ProgressPrefix"]) + "-result.json",
            old_active_sha256=update_plan["OldActiveSha256"], active_sha256=update_plan["ActiveSha256"])
        from tools.settings_portability import export_document, write_new
        backup = selected.data_root / "backups" / ("settings-before-" + result["version"] + "-" + update_plan["OperationId"] + ".json")
        reject_links(backup)
        if not backup.exists():
            write_new(backup, export_document())
        result["settings_backup"] = str(backup)
    startup = work / "StartInstalled.ps1"
    startup.write_text((package / "InstallCommon.ps1").read_text(encoding="utf-8-sig") + "\n" + r"""
$task=Get-FlowerTask
if($null -eq $task){throw 'setup_start_task_missing'}
Assert-FlowerTaskSecurity
$actions=@($task.Actions)
if($actions.Count -ne 1 -or $actions[0].Execute -ine $command -or $actions[0].Arguments -cne '--serve') {throw 'setup_start_task_changed'}
Start-ScheduledTask -TaskName $taskName -TaskPath '\'
Write-Output 'setup_role_bootstrap_requested'
""", encoding="utf-8-sig")
    result["startup_script"] = str(startup)
    result["startup_script_sha256"] = digest(startup)
    if installer is not None:
        reject_links(installer)
        if not installer.is_file() or installer.suffix.lower() != ".exe":
            raise ValueError("offline_installer_executable_required")
        # The installed maintenance entry is the same self-contained offline
        # executable. It can uninstall without a checkout or Python install.
        result["maintenance_source"] = str(installer)
        result["maintenance_sha256"] = digest(installer)
        finalizer = render_setup_wrapper(result, package, selected.packages_root)
        (work / "ApplySetup.ps1").write_text(finalizer, encoding="utf-8-sig")
        result["elevated_script"] = str(work / "ApplySetup.ps1")
        result["elevated_script_sha256"] = digest(work / "ApplySetup.ps1")
    plan_path = work / "setup-plan.json"
    plan_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    result.update(setup_plan_path=str(plan_path), setup_plan_sha256=digest(plan_path))
    return result


def ps_literal(value):
    return "'" + str(value).replace("'", "''") + "'"


def pinned_bootstrap(script, expected, arguments=""):
    """Hash and execute the same locked stream, including on Windows PS5.1."""
    return ("$ErrorActionPreference='Stop';$s=[IO.File]::Open(" + ps_literal(script)
        + ",[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);try{"
        "$h=[Security.Cryptography.SHA256]::Create();try{$v=[BitConverter]::ToString($h.ComputeHash($s)).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()};"
        "if($v -cne " + ps_literal(expected) + "){throw 'setup_script_changed'};$s.Position=0;"
        "$r=[IO.StreamReader]::new($s,[Text.Encoding]::UTF8,$true,4096,$true);try{$text=$r.ReadToEnd()}finally{$r.Dispose()};"
        "& ([scriptblock]::Create($text)) " + arguments + "}finally{$s.Dispose()}")


def prepare_adapters(package, output, program_root, version, *, codex, dsh):
    entries = []
    if codex:
        from tools.prepare_frozen_plugin import prepare as freeze_plugin
        market = output / "codex"
        freeze_plugin(package, market / "plugins/flower-control")
        manifest = market / ".agents/plugins/marketplace.json"
        manifest.parent.mkdir(parents=True)
        manifest.write_text(json.dumps(dict(name="flower-control-local",
            interface=dict(displayName="Flower Control (local)"), plugins=[dict(name="flower-control",
                source=dict(source="local", path="./plugins/flower-control"),
                policy=dict(installation="AVAILABLE", authentication="ON_INSTALL"), category="Productivity")]), indent=2) + "\n", encoding="utf-8")
        entries.append(dict(host="codex", kind="marketplace", selector="flower-control-local",
            source=str(program_root / "integrations/codex" / version), prepared_source=str(market),
            registration_state="unknown"))
    if dsh:
        from tools.configure_dsh_plugin import configure
        configure(package, output / "dsh")
        entries.append(dict(host="dsh", kind="generated_bundle", source=str(program_root / "integrations/dsh" / version),
            prepared_source=str(output / "dsh"), registration_state="not_registered"))
    for entry in entries:
        source = Path(entry["prepared_source"])
        entry["generated_files"] = {path.relative_to(source).as_posix(): digest(path)
            for path in source.rglob("*") if path.is_file()}
    return entries


def render_setup_wrapper(plan, package, packages):
    human_version = release_version(plan)
    if plan["legacy"]:
        policy = read_json(package / "versions" / plan["version"] / "broker.json")
        location = dict(installation_id="", user_sid=policy["UserSid"])
        windows_id = "legacy-" + hashlib.sha256((policy["UserSid"] + "|" + plan["root"].lower()).encode()).hexdigest()[:24]
    else:
        location = read_json(package / "installation-location.request.json")
        windows_id = location["installation_id"]
    version = plan["version"]
    maintenance_directory = packages / (version + "-" + plan["maintenance_sha256"][:12])
    maintenance = maintenance_directory / "FlowerControl-Maintenance.exe"
    key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FlowerControl." + windows_id
    host_entries = [{key: value for key, value in entry.items() if key != "prepared_source"}
                    for entry in plan["adapters"]]
    host_receipt = dict(schema=1, installation_id=location["installation_id"], user_sid=location["user_sid"],
        entries=host_entries, native_hook_trust_granted=False, host_injection_verified=False)
    adapter_commands = []
    exact_paths = [str(packages), str(maintenance_directory), str(maintenance), str(Path(plan["program_root"]) / "maintenance-files.json"),
                   str(Path(plan["program_root"]) / "host-integrations.json"), str(Path(plan["program_root"]) / "integrations")]
    for entry in plan["adapters"]:
        target_root = Path(entry["source"])
        exact_paths.extend([str(target_root.parent), str(target_root)])
        for name, expected in entry["generated_files"].items():
            source = Path(entry["prepared_source"]) / name
            target = target_root / name
            for parent in target.parents:
                if parent == target_root:
                    break
                exact_paths.append(str(parent))
            exact_paths.append(str(target))
            adapter_commands.append(f"""$inputPath={ps_literal(source)};$outputPath={ps_literal(target)}
Assert-FlowerNoLinks $inputPath
if ((Get-FileHash -LiteralPath $inputPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne {ps_literal(expected)}) {{ throw 'setup_adapter_source_changed' }}
$parents=[Collections.Generic.Stack[string]]::new();$parent=Split-Path -Parent $outputPath
while (!(Test-Path -LiteralPath $parent)) {{$parents.Push($parent);$parent=Split-Path -Parent $parent}}
while ($parents.Count -gt 0) {{$parent=$parents.Pop();New-Item -ItemType Directory -Path $parent | Out-Null;Protect-SetupPath $parent}}
Assert-FlowerNoLinks $outputPath
if (Test-Path -LiteralPath $outputPath) {{
 if ((Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne {ps_literal(expected)}) {{throw 'setup_adapter_existing_changed'}}
}} else {{Copy-Item -LiteralPath $inputPath -Destination $outputPath}}
if ((Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne {ps_literal(expected)}) {{throw 'setup_adapter_copy_changed'}}
Protect-SetupPath $outputPath
""")
    help_files = []
    for item in plan["guide_files"]:
        target = maintenance_directory / "Help" / item["name"]
        expected = item["sha256"]
        for parent in target.parents:
            if parent == maintenance_directory:
                break
            exact_paths.append(str(parent))
        exact_paths.append(str(target))
        help_files.append(dict(path=str(target), sha256=expected, bytes=item["bytes"]))
        adapter_commands.append(f"""$inputPath={ps_literal(item['source'])};$outputPath={ps_literal(target)}
Assert-FlowerNoLinks $inputPath
if((Get-FileHash -LiteralPath $inputPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne {ps_literal(expected)}) {{throw 'setup_help_source_changed'}}
$parents=[Collections.Generic.Stack[string]]::new();$parent=Split-Path -Parent $outputPath
while(!(Test-Path -LiteralPath $parent)) {{$parents.Push($parent);$parent=Split-Path -Parent $parent}}
while($parents.Count -gt 0) {{$parent=$parents.Pop();New-Item -ItemType Directory -Path $parent|Out-Null;Protect-SetupPath $parent}}
Assert-FlowerNoLinks $outputPath
if(Test-Path -LiteralPath $outputPath) {{
 if((Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne {ps_literal(expected)}) {{throw 'setup_help_existing_changed'}}
}} else {{Copy-Item -LiteralPath $inputPath -Destination $outputPath}}
if((Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne {ps_literal(expected)}) {{throw 'setup_help_copy_changed'}}
Protect-SetupPath $outputPath
""")
    allowed = "@(\n" + ",\n".join(ps_literal(value) for value in sorted(set(exact_paths))) + "\n)"
    common = (package / "InstallCommon.ps1").read_text(encoding="utf-8-sig")
    initial_source = pinned_bootstrap(plan["elevated_script"], plan["elevated_script_sha256"], "@@SETUP_ARGS@@")
    if plan["kind"] == "update":
        core = plan["core_update"]
        update_guard = f"""
function Test-SetupCoreUpdateCompleted {{
 $receipt={ps_literal(core['receipt'])}
 if(!(Test-Path -LiteralPath $receipt)) {{return $false}}
 [FlowerRecoveryProtection]::RequireProtectedFile($receipt)
 $completed=Get-Content -LiteralPath $receipt -Raw -Encoding UTF8 | ConvertFrom-Json
 if($completed.operation -cne {ps_literal(core['operation'])} -or $completed.version -cne {ps_literal(version)} -or
    $completed.state -notin @('installed_paused_verified','installed_and_running')) {{throw 'setup_update_recovery_required'}}
 if((Get-FileHash -LiteralPath (Join-Path $brokerRoot 'active.json') -Algorithm SHA256).Hash.ToLowerInvariant() -cne {ps_literal(core['active_sha256'])}) {{throw 'setup_completed_update_active_changed'}}
 Assert-FlowerVersion $versionTarget
 return $true
}}
$coreCompleted=Test-SetupCoreUpdateCompleted
if($Resume -and !$coreCompleted) {{
 if((Test-Path -LiteralPath {ps_literal(Path(core['receipt']).parent)}) -or
    (Get-FileHash -LiteralPath (Join-Path $brokerRoot 'active.json') -Algorithm SHA256).Hash.ToLowerInvariant() -cne {ps_literal(core['old_active_sha256'])}) {{throw 'setup_update_unknown_no_replay'}}
}}
"""
        post_core = "if(!(Test-SetupCoreUpdateCompleted)){throw 'setup_update_completion_unconfirmed'}"
    else:
        update_guard = "$coreCompleted=$false"
        post_core = ""
    return f"""param([switch]$Resume,[string]$SetupOperationId,[string]$SetupPlanPath,[string]$SetupPlanSha256,
 [string]$SetupScriptPath,[string]$ExpectedScriptSha256)
$ErrorActionPreference = 'Stop'
if($SetupOperationId -cne {ps_literal(plan['operation_id'])} -or
 $SetupPlanPath -ine {ps_literal(package.parent / 'setup-plan.json')} -or
 $SetupScriptPath -ine {ps_literal(package.parent / 'ApplySetup.ps1')} -or
 $SetupPlanSha256 -cnotmatch '^[a-f0-9]{{64}}$' -or $ExpectedScriptSha256 -cnotmatch '^[a-f0-9]{{64}}$') {{throw 'setup_confirmed_binding_required'}}
foreach($binding in @(@($SetupPlanPath,$SetupPlanSha256),@($SetupScriptPath,$ExpectedScriptSha256))) {{
 if((Get-FileHash -LiteralPath $binding[0] -Algorithm SHA256).Hash.ToLowerInvariant() -cne $binding[1]) {{throw 'setup_confirmed_material_changed'}}
}}
{common}
{update_guard}
$arguments=''
if({ps_literal(plan['kind'])} -ceq 'install') {{
 if($Resume) {{$arguments='-Resume '}}
 $arguments+='-SetupOperationId '+"'"+$SetupOperationId+"' -SetupPlanPath '"+$SetupPlanPath.Replace("'","''")+"' -SetupPlanSha256 '"+$SetupPlanSha256+"' -SetupScriptPath '"+$SetupScriptPath.Replace("'","''")+"' -ExpectedScriptSha256 '"+$ExpectedScriptSha256+"'"
}}
$source={ps_literal(initial_source)}
$source=$source.Replace('@@SETUP_ARGS@@',$arguments)
$childBootstrap=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($source))
if(!$coreCompleted) {{
 & (Join-Path $PSHOME 'powershell.exe') -NoLogo -NoProfile -STA -EncodedCommand $childBootstrap
 if ($LASTEXITCODE -ne 0) {{ throw 'setup_install_not_completed' }}
}}
{post_core}
$null=Write-FlowerResumeAnchor -Kind setup -OperationId $SetupOperationId -PlanPath $SetupPlanPath -PlanSha256 $SetupPlanSha256 -ScriptPath $SetupScriptPath -ScriptSha256 $ExpectedScriptSha256 -State incomplete
$allowedSetupPaths={allowed}
function Protect-SetupPath([string]$path) {{
 if ($path -cne [IO.Path]::GetFullPath($path) -or $path -notin $allowedSetupPaths) {{throw 'setup_protection_scope_rejected'}}
 Assert-FlowerNoLinks $path -Shallow
 $item=Get-Item -LiteralPath $path -Force
 Set-Acl -LiteralPath $path -AclObject (New-FlowerAcl $item.PSIsContainer)
 $acl=Get-Acl -LiteralPath $path
 if (!$acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne 'S-1-5-32-544' -or
     (Get-FlowerAclRules $acl) -cne (Get-FlowerAclRules (New-FlowerAcl $item.PSIsContainer))) {{throw 'setup_protection_readback_failed'}}
}}
$maintenanceSource = {ps_literal(plan['maintenance_source'])}
Assert-FlowerNoLinks $maintenanceSource
if ((Get-FileHash -LiteralPath $maintenanceSource -Algorithm SHA256).Hash.ToLowerInvariant() -cne {ps_literal(plan['maintenance_sha256'])}) {{ throw 'setup_maintenance_source_changed' }}
$maintenance = {ps_literal(maintenance)}
Assert-FlowerNoLinks $maintenance
if (Test-Path -LiteralPath $maintenance) {{
    if ((Get-FileHash -LiteralPath $maintenance -Algorithm SHA256).Hash.ToLowerInvariant() -cne {ps_literal(plan['maintenance_sha256'])}) {{ throw 'setup_existing_maintenance_changed' }}
}} else {{
    if(!(Test-Path -LiteralPath {ps_literal(packages)})) {{New-Item -ItemType Directory -Path {ps_literal(packages)} | Out-Null;Protect-SetupPath {ps_literal(packages)}}}
    New-Item -ItemType Directory -Path (Split-Path -Parent $maintenance) -Force | Out-Null
    Protect-SetupPath (Split-Path -Parent $maintenance)
    Copy-Item -LiteralPath $maintenanceSource -Destination $maintenance
    Protect-SetupPath $maintenance
}}
if ((Get-FileHash -LiteralPath $maintenance -Algorithm SHA256).Hash.ToLowerInvariant() -cne {ps_literal(plan['maintenance_sha256'])}) {{ throw 'setup_maintenance_copy_changed' }}
{''.join(adapter_commands)}
$hostReceipt={ps_literal(Path(plan['program_root']) / 'host-integrations.json')}
$nextReceipt={ps_literal(json.dumps(host_receipt, ensure_ascii=True))} | ConvertFrom-Json
if(Test-Path -LiteralPath $hostReceipt) {{
 Assert-FlowerNoLinks $hostReceipt -Shallow
 $previous=Get-Content -LiteralPath $hostReceipt -Raw -Encoding UTF8 | ConvertFrom-Json
 if($previous.schema -ne 1 -or $previous.installation_id -cne $nextReceipt.installation_id -or
    @($previous.entries).Count -gt 256) {{throw 'setup_previous_host_receipt_changed'}}
 foreach($oldEntry in $previous.entries) {{
  if(!$oldEntry.source.StartsWith((Join-Path $brokerRoot 'integrations')+'\',[StringComparison]::OrdinalIgnoreCase)) {{throw 'setup_previous_host_scope_rejected'}}
  if(@($nextReceipt.entries | Where-Object {{$_.source -ieq $oldEntry.source}}).Count -eq 0) {{$nextReceipt.entries=@($oldEntry)+@($nextReceipt.entries)}}
 }}
}}
[IO.File]::WriteAllText($hostReceipt,($nextReceipt|ConvertTo-Json -Depth 20),[Text.UTF8Encoding]::new($false))
Protect-SetupPath $hostReceipt
$maintenanceReceipt={ps_literal(Path(plan['program_root']) / 'maintenance-files.json')}
$owned=@()
$helpFiles={ps_literal(json.dumps(help_files))} | ConvertFrom-Json
$newPaths=@($maintenance)+@($helpFiles | ForEach-Object {{$_.path}})
if (Test-Path -LiteralPath $maintenanceReceipt) {{
 Assert-FlowerNoLinks $maintenanceReceipt -Shallow
 $old=Get-Content -LiteralPath $maintenanceReceipt -Raw -Encoding UTF8 | ConvertFrom-Json
 if($old.schema -ne 1 -or $old.installation_id -cne {ps_literal(location['installation_id'])}) {{throw 'setup_previous_maintenance_receipt_changed'}}
 foreach($file in $old.files) {{
  if(!$file.path.StartsWith({ps_literal(str(packages) + chr(92))},[StringComparison]::OrdinalIgnoreCase)) {{throw 'setup_previous_maintenance_scope_rejected'}}
  Assert-FlowerNoLinks $file.path -Shallow
  if((Get-FileHash -LiteralPath $file.path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $file.sha256) {{throw 'setup_previous_maintenance_changed'}}
  if($file.path -notin $newPaths) {{$owned+=@($file)}}
 }}
}}
$owned+=@(@{{path=$maintenance;sha256={ps_literal(plan['maintenance_sha256'])};bytes=(Get-Item -LiteralPath $maintenance).Length}})
$owned+=@($helpFiles)
$receipt=@{{schema=1;installation_id={ps_literal(location['installation_id'])};user_sid={ps_literal(location['user_sid'])};windows_uninstall_id={ps_literal(windows_id)};files=$owned}} | ConvertTo-Json -Depth 8
[IO.File]::WriteAllText($maintenanceReceipt,$receipt,[Text.UTF8Encoding]::new($false))
Protect-SetupPath $maintenanceReceipt
$base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
try {{
    $entry = $base.CreateSubKey({ps_literal(key)}, $true)
    try {{
        $entry.SetValue('DisplayName','Flower Control')
        $entry.SetValue('DisplayVersion',{ps_literal(human_version)})
        $entry.SetValue('Publisher','fallen-blossom')
        $entry.SetValue('InstallLocation',{ps_literal(plan['root'])})
        $entry.SetValue('InstallationId',{ps_literal(windows_id)})
        $entry.SetValue('UninstallString',('"' + $maintenance + '" --uninstall'))
        $entry.SetValue('NoModify',1,[Microsoft.Win32.RegistryValueKind]::DWord)
        $entry.SetValue('NoRepair',1,[Microsoft.Win32.RegistryValueKind]::DWord)
    }} finally {{ $entry.Dispose() }}
}} finally {{ $base.Dispose() }}
$null=Write-FlowerResumeAnchor -Kind setup -OperationId $SetupOperationId -PlanPath $SetupPlanPath -PlanSha256 $SetupPlanSha256 -ScriptPath $SetupScriptPath -ScriptSha256 $ExpectedScriptSha256 -State completed
Write-Output 'setup_registered_not_host_trusted'
"""


def verify_installed(plan_path):
    plan = read_json(plan_path)
    from tools.stdio_contract_check import installed_entry
    executable, active = installed_entry()
    if active["version"] != plan["version"] or executable.parent.parent.parent != Path(plan["program_root"]):
        raise ValueError("offline_installed_version_mismatch")
    return dict(schema=1, installed_files_verified=True, version=active["version"],
                release_version=plan.get("release_version"),
                runtime_started=False, host_injection_verified=False)


def start(plan_path, *, _verified=None):
    result = verify_installed(plan_path) if _verified is None else _verified
    plan = read_json(plan_path)
    target = Path(plan["program_root"]) / "versions" / plan["version"] / "Flower.HighHelper.exe"
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    def request(command):
        flag = "--flower-local-status" if command == "status" else "--flower-local-settings"
        response = subprocess.run([str(target), flag], cwd=target.parent,
            capture_output=True, timeout=10, creationflags=flags)
        if response.returncode:
            return None
        try:
            return json.loads(response.stdout)
        except (ValueError, UnicodeError):
            return None
    status = request("status")
    if status is None:
        script = Path(plan["startup_script"])
        if digest(script) != plan["startup_script_sha256"]:
            raise ValueError("offline_startup_script_changed")
        encoded = base64.b64encode(pinned_bootstrap(script, plan["startup_script_sha256"]).encode("utf-16-le")).decode("ascii")
        ps = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        # The already-installed, protected task chooses High or ordinary from
        # the existing tier. We never create a second detached settings core.
        launched = subprocess.run([str(ps), "-NoLogo", "-NoProfile", "-EncodedCommand", encoded],
            capture_output=True, timeout=30, creationflags=flags)
        if launched.returncode:
            return {**result, "runtime_started": False, "settings_open_requested": False,
                    "reason": "installed_role_start_not_confirmed"}
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            status = request("status")
            if status is not None:
                break
            time.sleep(.25)
    snapshot = status.get("Status", {}) if isinstance(status, dict) else {}
    if snapshot.get("version") != plan["version"] or not (snapshot.get("ordinary_verified") or snapshot.get("high_verified")):
        return {**result, "runtime_started": False, "settings_open_requested": False,
                "reason": "installed_role_readiness_not_confirmed"}
    opened = request("settings")
    return {**result, "runtime_started": True, "broker_role": snapshot.get("broker_role"),
        "paused": snapshot.get("paused"),
        "settings_open_requested": isinstance(opened, dict) and opened.get("Phase") == "settings_open_requested"}


def prepare_uninstall(work):
    reject_links(work)
    if work.exists():
        raise ValueError("offline_new_uninstall_work_required")
    work.mkdir(parents=True)
    from tools.prepare_uninstall import prepare as inventory
    path = work / "uninstall-plan.json"
    result = inventory(path)
    return dict(schema=1, plan=str(path), plan_sha256=result["plan_sha256"],
        elevated_script=result["apply_script"], elevated_script_sha256=result["apply_script_sha256"],
        root=result["installation_root"], files=len(result["files"]), bytes=sum(row["bytes"] for row in result["files"]),
        preserve=result["preserve"], blockers=result["blockers"],
        operation_id=result["operation_id"],
        result_path=str(work / "uninstall-result.json"), complete=False)


def complete_medium_hosts(path, expected):
    from tools.prepare_uninstall import complete_medium_host_stage
    result = complete_medium_host_stage(path, expected)
    return dict(plan=result["plan_path"], plan_sha256=result["plan_sha256"],
        elevated_script=result["apply_script"], elevated_script_sha256=result["apply_script_sha256"],
        operation_id=result["operation_id"], medium_host_stage_complete=True)


def switch_owned_marketplace(cli, entry, owned):
    """Use the official Medium CLI; never replace an unowned marketplace.

    `add` does not replace another source with the same name. Observe each
    effect, including failed replies, and restore only an absent old source.
    Host trust and actual plugin loading remain independent user steps.
    """
    from tools.prepare_uninstall import run_official_cli

    def observe():
        listing = json.loads(run_official_cli(cli, ["plugin", "marketplace", "list", "--json"]).stdout)
        matches = [row for row in listing["marketplaces"] if row["name"] == entry["selector"]]
        if len(matches) > 1:
            raise ValueError("offline_marketplace_ambiguous")
        return Path(matches[0]["root"]) if matches else None

    def attempt(arguments):
        try:
            run_official_cli(cli, arguments)
        except (OSError, ValueError, subprocess.SubprocessError):
            # A missing reply does not establish whether the command ran.
            pass
        return observe()

    target = Path(entry["source"])
    previous = observe()
    result = dict(marketplace=entry["source"], hook_trust_granted=False, host_injection_verified=False)
    if previous is not None and previous != target and previous not in owned:
        return dict(result, state="existing_source_requires_review")
    if previous == target:
        return dict(result, state="marketplace_registered")
    if previous is not None:
        # Re-read before the one removal; an unrelated replacement is never
        # treated as ours merely because the selector has the same spelling.
        if observe() != previous:
            return dict(result, state="source_changed_requires_review")
        after = attempt(["plugin", "marketplace", "remove", entry["selector"]])
        if after is not None:
            return dict(result, state="removal_unconfirmed", previous_marketplace=str(previous))
    if observe() is not None:
        return dict(result, state="source_changed_requires_review")
    after = attempt(["plugin", "marketplace", "add", entry["source"], "--json"])
    if after == target:
        return dict(result, state="marketplace_registered")
    if after is None and previous is not None and observe() is None:
        restored = attempt(["plugin", "marketplace", "add", str(previous), "--json"])
        return dict(result, state="previous_source_restored" if restored == previous else "restoration_unconfirmed",
            previous_marketplace=str(previous))
    return dict(result, state="registration_unconfirmed")


def register_hosts(path, *, _verified=None):
    if _verified is None:
        verify_installed(path)
    plan = read_json(path)
    entries = [row for row in plan["adapters"] if row["host"] == "codex"]
    if not entries:
        return dict(state="not_selected", host_injection_verified=False)
    from tools.prepare_uninstall import resolve_codex_cli
    try:
        cli = resolve_codex_cli()
        if cli is None:
            raise ValueError("official_cli_not_found")
        receipt = read_json(Path(plan["program_root"]) / "host-integrations.json")
        owned = {Path(row["source"]) for row in receipt["entries"] if row.get("host") == "codex"}
        entry = entries[0]
        result = switch_owned_marketplace(cli, entry, owned)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        result = dict(state="native_host_step_required", marketplace=entries[0]["source"],
            hook_trust_granted=False, host_injection_verified=False)
    receipt = Path(path).parent / ("host-registration-" + uuid.uuid4().hex + ".json")
    with receipt.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
    return dict(result, receipt_path=str(receipt))


def finish_install(path):
    # One complete verification in this process. Native request/CLI peers still
    # recheck their own exact identities; repeated whole-tree scans add no proof.
    verified = verify_installed(path)
    registration = register_hosts(path, _verified=verified)
    return {**start(path, _verified=verified), "registration": registration}


def configure_hosts(package: Path, output: Path, *, dsh=False) -> dict:
    """Create local adapters after root registration, preserving host trust."""
    from tools.configure_local_plugin import configure
    codex = configure(package, output / "codex")
    result = dict(schema=1, codex=codex, codex_marketplace=str(output / "codex"),
                  installed=False, hook_trust_granted=False, host_injection_verified=False)
    if dsh:
        from tools.configure_dsh_plugin import configure as configure_dsh
        result["dsh"] = configure_dsh(package, output / "dsh")
    (output / "host-configuration.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main():
    initialize_bundled_python()
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("status")
    command = sub.add_parser("verify")
    command.add_argument("--payload", type=Path, required=True)
    command = sub.add_parser("prepare")
    command.add_argument("--payload", type=Path, required=True)
    command.add_argument("--root", type=Path, required=True)
    command.add_argument("--work", type=Path, required=True)
    command.add_argument("--dsh-image", type=Path)
    command.add_argument("--installer", type=Path)
    command.add_argument("--without-codex", action="store_true")
    for action in ("verify-installed", "start", "register-hosts", "finish-install"):
        command = sub.add_parser(action)
        command.add_argument("--plan", type=Path, required=True)
    command = sub.add_parser("configure-hosts")
    command.add_argument("--package", type=Path, required=True)
    command.add_argument("--output", type=Path, required=True)
    command.add_argument("--dsh", action="store_true")
    command = sub.add_parser("prepare-uninstall")
    command.add_argument("--work", type=Path, required=True)
    command = sub.add_parser("complete-uninstall-hosts")
    command.add_argument("--plan", type=Path, required=True)
    command.add_argument("--expected-sha256", required=True)
    command = sub.add_parser("inspect-uninstall-data")
    command.add_argument("--plan", type=Path, required=True)
    command.add_argument("--expected-sha256", required=True)
    command.add_argument("--output", type=Path, required=True)
    command = sub.add_parser("recycle-uninstall-data")
    command.add_argument("--review", type=Path, required=True)
    command.add_argument("--expected-sha256", required=True)
    command.add_argument("--receipt", type=Path, required=True)
    command.add_argument("--cancel-file", type=Path)
    command.add_argument("--confirmed", action="store_true", required=True)
    command = sub.add_parser("resume")
    command.add_argument("--operation", required=True)
    command.add_argument("--kind", choices=("setup", "uninstall"), required=True)
    command.add_argument("--root", type=Path)
    command = sub.add_parser("inspect-root")
    command.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    if args.action == "status":
        result = installation_status()
    elif args.action == "verify":
        manifest = verify_payload(args.payload.absolute())
        result = dict(schema=1, verified=True, files=len(manifest["files"]), installed=False)
    elif args.action == "verify-installed":
        result = verify_installed(args.plan)
    elif args.action == "start":
        result = start(args.plan)
    elif args.action == "register-hosts":
        result = register_hosts(args.plan)
    elif args.action == "finish-install":
        result = finish_install(args.plan)
    elif args.action == "prepare-uninstall":
        result = prepare_uninstall(args.work.absolute())
    elif args.action == "complete-uninstall-hosts":
        result = complete_medium_hosts(args.plan.absolute(), args.expected_sha256)
    elif args.action == "inspect-uninstall-data":
        from tools.uninstall_personal_data import prepare as inspect_data
        result = inspect_data(args.plan.absolute(), args.expected_sha256, args.output.absolute())
    elif args.action == "recycle-uninstall-data":
        from tools.uninstall_personal_data import apply as recycle_data
        result = recycle_data(args.review.absolute(), args.expected_sha256,
            confirmed=args.confirmed, receipt_path=args.receipt.absolute(), cancel_path=args.cancel_file)
    elif args.action == "resume":
        result = load_resume(args.operation, args.kind, args.root)
    elif args.action == "inspect-root":
        if not args.root.is_dir():
            result = dict(resumable_operations=[])
        else:
            selected = explicit_resume_location(args.root)
            result = dict(resumable_operations=resume_operations(selected, _unregistered=not selected.installation_id and not selected.legacy))
    elif args.action == "configure-hosts":
        result = configure_hosts(args.package.absolute(), args.output.absolute(), dsh=args.dsh)
    else:
        result = prepare(args.payload.absolute(), args.root.absolute(), args.work.absolute(), dsh_image=args.dsh_image, installer=args.installer, codex=not args.without_codex)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
