"""Prepare an exact, reviewable uninstall inventory. Never stops or removes anything."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from flower_control.install_location import discover_installation, require_protected_path
from tools.runtime_snapshot import reject_links
from tools.prepare_high_broker_install import render_install_scripts, system_powershell_path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def version_inventory(directory):
    """Only a matched installation manifest establishes ownership of files."""
    reject_links(directory)
    manifest = directory / "installation.json"
    active = json.loads(manifest.read_bytes())
    if active.get("schema") != 1 or active.get("version") != directory.name or not re.fullmatch("[a-f0-9]{32}", directory.name):
        raise ValueError("uninstall_version_manifest_rejected")
    policy = json.loads((directory / "broker.json").read_bytes())
    expected = dict(active["hashes"])
    expected.update({"app/" + name: sha for name, sha in policy.get("AppWorkerHashes", {}).items()})
    expected.update({"wgc/" + name: sha for name, sha in policy.get("WgcWorkerHashes", {}).items()})
    expected.update(active.get("runtime_hashes", {}))
    expected["installation.json"] = digest(manifest)
    rows = []
    for name, sha in sorted(expected.items()):
        relative = PurePosixPath(name)
        if (relative.is_absolute() or ".." in relative.parts or "\\" in name or ":" in name
                or not re.fullmatch("[a-f0-9]{64}", sha)):
            raise ValueError("uninstall_file_path_rejected")
        path = directory.joinpath(*relative.parts)
        reject_links(path)
        if not path.is_file() or digest(path) != sha:
            raise ValueError("uninstall_owned_file_changed")
        rows.append(dict(path=str(path), sha256=sha, bytes=path.stat().st_size))
    actual = {p.relative_to(directory).as_posix() for p in directory.rglob("*") if p.is_file()}
    if actual != set(expected):
        raise ValueError("uninstall_unowned_version_files")
    return rows


def install_staging_inventory(directory, program, sid):
    """A protected install-operation owner binds interrupted copy artifacts."""
    match=re.fullmatch(r"\.install-staging-([a-f0-9]{32})",directory.name)
    if match is None or not directory.is_dir():
        raise ValueError('uninstall_staging_directory_rejected')
    require_protected_path(directory)
    operation=match[1]
    owner_path=program/'recovery'/('installation-'+operation)/'install-owner.json'
    require_protected_path(owner_path)
    owner=json.loads(owner_path.read_bytes())
    if (owner.get('schema') != 1 or owner.get('operation_id') != operation
            or owner.get('program_root') != str(program) or owner.get('user_sid') != sid
            or not re.fullmatch('[a-f0-9]{64}',owner.get('plan_sha256',''))
            or not re.fullmatch('[a-f0-9]{64}',owner.get('package_active_sha256',''))):
        raise ValueError('uninstall_staging_owner_changed')
    rows=[]
    for path in sorted(directory.iterdir()):
        reject_links(path)
        if not path.is_file() or not re.fullmatch(r'[a-f0-9]{32}\.partial',path.name):
            raise ValueError('uninstall_staging_file_rejected')
        require_protected_path(path)
        rows.append(dict(path=str(path),sha256=digest(path),bytes=path.stat().st_size))
    return rows


def runtime_inventory(location):
    # Query only Flower image names and emit no command lines or environment.
    script = r"""$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$root='__ROOT__';$sid='__SID__';$rows=@()
foreach($p in Get-CimInstance Win32_Process -Filter "Name='Flower.HighHelper.exe' OR Name='flower-python.exe' OR Name='Flower.AppWorker.exe' OR Name='Flower.ComputerWgc.exe'") {
 if(!$p.ExecutablePath){throw 'uninstall_process_image_unconfirmed'}
 if(!$p.ExecutablePath.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)){continue}
 $owner=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid
 if($owner.ReturnValue -ne 0 -or $owner.Sid -cne $sid){throw 'uninstall_process_owner_unconfirmed'}
 $rows+=@{pid=[int]$p.ProcessId;created=$p.CreationDate.ToUniversalTime().ToFileTimeUtc().ToString();image=$p.ExecutablePath;user_sid=$sid;session=[int]$p.SessionId}
}
ConvertTo-Json -InputObject @($rows) -Depth 4 -Compress
""".replace("__ROOT__", str(location.program_root).replace("'", "''")).replace("__SID__", location.user_sid)
    import base64
    result = subprocess.run([str(system_powershell_path()),
        "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.b64encode(script.encode("utf-16-le")).decode()],
        capture_output=True, timeout=30, creationflags=subprocess.CREATE_NO_WINDOW, check=True)
    return json.loads(result.stdout.decode("utf-8-sig"))


def require_medium():
    from flower_control.drivers.high_helper import _process
    identity,_=_process(os.getpid())
    if identity['Integrity']!=8192:raise ValueError('uninstall_host_stage_requires_medium')
    return identity


def official_codex_cli(path, location=None):
    """Ask only the protected installed helper to verify Authenticode offline."""
    require_medium()
    location=discover_installation() if location is None else location
    active=location.program_root/'active.json';reject_links(active)
    manifest=json.loads(active.read_bytes())
    version=manifest.get('version','')
    if not re.fullmatch('[a-f0-9]{32}',version):raise ValueError('uninstall_verifier_version_rejected')
    directory=location.program_root/'versions'/version
    for name in ('Flower.HighHelper.exe','Flower.HighHelper.dll'):
        source=directory/name;reject_links(source)
        if not source.is_file() or digest(source)!=manifest['hashes'].get(name):raise ValueError('uninstall_verifier_changed')
    response=subprocess.run([str(directory/'Flower.HighHelper.exe'),'--flower-verify-codex-cli',str(path)],capture_output=True,
        timeout=20,creationflags=subprocess.CREATE_NO_WINDOW,check=False)
    if response.returncode:return False
    value=json.loads(response.stdout.decode('utf-8-sig'))
    return (value.get('schema')==1 and value.get('official_codex_cli') is True and value.get('AuthorityGranted') is False
        and value.get('InputDispatched') is False and value.get('sha256')==digest(path))


@contextmanager
def pin_cli(path):
    import win32file
    import win32con
    reject_links(path)
    handle=win32file.CreateFile(str(path),win32con.GENERIC_READ,win32con.FILE_SHARE_READ,None,
        win32con.OPEN_EXISTING,0x00200000,None)
    try:yield
    finally:handle.Close()


def run_official_cli(path,arguments,*,timeout=20,check=True):
    require_medium()
    with pin_cli(path):
        if not official_codex_cli(path):raise ValueError('uninstall_codex_publisher_rejected')
        return subprocess.run([str(path),*arguments],capture_output=True,timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW,check=check)


def desktop_codex_candidates():
    import base64
    script="$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);ConvertTo-Json -InputObject @((Get-AppxPackage -Name OpenAI.Codex).InstallLocation) -Compress"
    powershell=system_powershell_path()
    result=subprocess.run([str(powershell),'-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(script.encode('utf-16-le')).decode()],
        capture_output=True,timeout=20,creationflags=subprocess.CREATE_NO_WINDOW,check=True)
    roots=json.loads(result.stdout.decode('utf-8-sig'))
    if not isinstance(roots,list) or any(not isinstance(root,str) for root in roots):raise ValueError('uninstall_codex_package_list_rejected')
    return [Path(root)/relative for root in roots for relative in ('app/resources/codex.exe','app/resources/cli/codex.exe','resources/codex.exe')]


def resolve_codex_cli(explicit=None, *, location=None):
    """Use an existing official CLI executable, never run a shell shim as code."""
    require_medium()
    selected=Path(explicit) if explicit is not None else Path(shutil.which("codex.exe") or shutil.which("codex") or "")
    candidates=[selected] if explicit is not None and selected.suffix.lower()=='.exe' else desktop_codex_candidates()
    if explicit is None and selected.suffix.lower()=='.exe':candidates.append(selected)
    if selected.suffix.lower()==".cmd":
        for package,target in (("codex-win32-x64","x86_64-pc-windows-msvc"),("codex-win32-arm64","aarch64-pc-windows-msvc")):
            for base in (selected.parent/"node_modules/@openai/codex/node_modules/@openai",selected.parent/"node_modules/@openai"):
                candidates.append(base/package/"vendor"/target/"bin/codex.exe")
    for candidate in candidates:
        if candidate.is_absolute() and candidate.name.lower()=="codex.exe" and candidate.is_file():
            reject_links(candidate)
            with pin_cli(candidate):
                if official_codex_cli(candidate,location):return candidate
    raise ValueError("uninstall_official_codex_cli_required")


def bind_codex_marketplace(entry, cli=None):
    return bind_owned_marketplaces([entry],cli)[0]


def bind_owned_marketplaces(entries,cli=None):
    """One official listing binds each selector to its matching owned version."""
    for entry in entries:
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.@-]{0,199}",entry.get("selector","")) or not Path(entry.get("source","")).is_absolute():
            raise ValueError("uninstall_codex_entry_rejected")
    executable=resolve_codex_cli(cli)
    result=run_official_cli(executable,["plugin","marketplace","list","--json"])
    listing=json.loads(result.stdout.decode("utf-8-sig"))
    rows=listing.get("marketplaces")
    if not isinstance(rows,list) or any(not isinstance(row,dict) or not isinstance(row.get("name"),str)
            or not isinstance(row.get("root"),str) for row in rows):
        raise ValueError("uninstall_codex_list_rejected")
    owned={(entry["selector"],Path(entry["source"])) for entry in entries}
    sources={source for _,source in owned}
    if any(Path(row["root"]) in sources and (row["name"],Path(row["root"])) not in owned for row in rows):
        raise ValueError("uninstall_codex_source_still_referenced")
    bound=[dict(entry,registration_state="not_registered",registration_observed=True,
        cli=dict(path=str(executable),sha256=digest(executable)),
        registration_check=dict(kind="marketplace_list",selector=entry["selector"],root=entry["source"])) for entry in entries]
    for selector in {entry["selector"] for entry in entries}:
        matches=[row for row in rows if row["name"]==selector]
        if not matches:continue
        indexes=[index for index,entry in enumerate(entries) if entry["selector"]==selector and Path(entry["source"])==Path(matches[0]["root"])]
        if len(matches)!=1 or not indexes:raise ValueError("uninstall_codex_marketplace_source_changed")
        bound[indexes[0]]["registration_state"]="registered"
    return bound


def prepare(output, *, inspect_runtime=True, codex_cli=None):
    location = discover_installation()
    program = location.program_root
    reject_links(program)
    active_path = program / "active.json"
    active = json.loads(active_path.read_bytes())
    versions = program / "versions"
    files, blockers = [], []
    for directory in sorted(versions.iterdir()):
        if not directory.is_dir():
            blockers.append(dict(path=str(directory), reason="unowned_version_entry"))
            continue
        try:
            files.extend(version_inventory(directory))
        except (ValueError, OSError, KeyError, TypeError) as error:
            blockers.append(dict(path=str(directory), reason=str(error)))
    for directory in sorted(program.glob('.install-staging-*')):
        # Empty operation directories have no bytes to remove or preserve.
        if directory.is_dir() and not any(directory.iterdir()):
            reject_links(directory)
            continue
        try:
            files.extend(install_staging_inventory(directory,program,location.user_sid))
        except (ValueError,OSError,KeyError,TypeError) as error:
            blockers.append(dict(path=str(directory),reason=str(error)))
    if active.get("version") not in {p.name for p in versions.iterdir() if p.is_dir()}:
        raise ValueError("uninstall_active_version_missing")
    files.append(dict(path=str(active_path), sha256=digest(active_path), bytes=active_path.stat().st_size))
    manifest = program / "installation-location.json"
    if not location.legacy:
        files.append(dict(path=str(manifest), sha256=digest(manifest), bytes=manifest.stat().st_size))
    host_receipt = program / "host-integrations.json"
    host_entries = []
    if host_receipt.is_file():
        reject_links(host_receipt)
        receipt = json.loads(host_receipt.read_bytes())
        if receipt.get("schema") != 1 or receipt.get("installation_id") != location.installation_id:
            raise ValueError("uninstall_host_receipt_rejected")
        host_entries = receipt.get("entries", [])
        if not isinstance(host_entries, list) or any(not isinstance(row, dict) for row in host_entries):
            raise ValueError("uninstall_host_receipt_rejected")
        codex_indexes=[index for index,entry in enumerate(host_entries) if entry.get("host")=="codex" and entry.get("kind")=="marketplace"]
        if codex_indexes:
            try:
                bound=bind_owned_marketplaces([host_entries[index] for index in codex_indexes],codex_cli)
                for index,entry in zip(codex_indexes,bound):host_entries[index]=entry
            except (OSError,ValueError,subprocess.SubprocessError) as error:
                blockers.append(dict(reason="codex_registration_observation_failed",error=type(error).__name__))
        files.append(dict(path=str(host_receipt), sha256=digest(host_receipt), bytes=host_receipt.stat().st_size))
        for entry in host_entries:
            if entry.get("registration_state") not in ("not_registered","removed"):
                if entry.get("host") == "codex" and (not entry.get("cli") or not entry.get("registration_check")):
                    blockers.append(dict(reason="codex_cli_and_registration_identity_required",host=entry.get("host"),selector=entry.get("selector")))
                elif entry.get("kind") != "json_entry" and entry.get("host") != "codex":
                    blockers.append(dict(reason="host_entry_manual_review_required",host=entry.get("host")))
            source = Path(entry.get("source", ""))
            generated = entry.get("generated_files", {})
            if not generated:
                continue
            if not source.is_absolute() or not source.is_relative_to(program) or not isinstance(generated, dict):
                raise ValueError("uninstall_integration_source_rejected")
            for relative, sha in generated.items():
                parts = PurePosixPath(relative)
                if parts.is_absolute() or ".." in parts.parts or "\\" in relative or ":" in relative:
                    raise ValueError("uninstall_integration_file_rejected")
                path = source.joinpath(*parts.parts)
                reject_links(path)
                if not path.is_file() or digest(path) != sha:
                    raise ValueError("uninstall_integration_file_changed")
                files.append(dict(path=str(path), sha256=sha, bytes=path.stat().st_size))
    else:
        blockers.append(dict(reason="host_integration_ownership_receipt_missing", action="review_host_entries_manually"))
    windows_uninstall_id=''
    maintenance_receipt = program / "maintenance-files.json"
    if maintenance_receipt.is_file():
        reject_links(maintenance_receipt)
        maintenance = json.loads(maintenance_receipt.read_bytes())
        if maintenance.get("schema") != 1 or maintenance.get("installation_id") != location.installation_id:
            raise ValueError("uninstall_maintenance_receipt_rejected")
        if maintenance.get('user_sid') != location.user_sid:
            raise ValueError('uninstall_maintenance_user_changed')
        windows_uninstall_id=maintenance.get('windows_uninstall_id','')
        expected_id=('legacy-'+hashlib.sha256((location.user_sid+'|'+str(location.root).lower()).encode()).hexdigest()[:24]) if location.legacy else location.installation_id
        if windows_uninstall_id != expected_id:
            raise ValueError('uninstall_windows_registration_identity_rejected')
        for row in maintenance.get("files", []):
            path = Path(row["path"])
            if not path.is_absolute() or not path.is_relative_to(location.packages_root):
                raise ValueError("uninstall_maintenance_scope_rejected")
            reject_links(path)
            if not path.is_file() or digest(path) != row["sha256"] or path.stat().st_size != row["bytes"]:
                raise ValueError("uninstall_maintenance_file_changed")
            files.append(dict(path=str(path),sha256=row["sha256"],bytes=row["bytes"]))
        files.append(dict(path=str(maintenance_receipt),sha256=digest(maintenance_receipt),bytes=maintenance_receipt.stat().st_size))
    processes, runtime_error = [], None
    if inspect_runtime:
        try:
            processes = runtime_inventory(location)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            runtime_error = type(error).__name__
    else:
        runtime_error = "not_observed"
    task = "FlowerControl.HighBroker." + hashlib.sha256(location.user_sid.encode()).hexdigest()[:16]
    unique={}
    for row in files:
        previous=unique.setdefault(os.path.normcase(row['path']),row)
        if previous != row:raise ValueError('uninstall_conflicting_owned_file_receipts')
    tails={os.path.normcase(str(active_path)):1,os.path.normcase(str(manifest)):2}
    files=sorted(unique.values(),key=lambda row:(tails.get(os.path.normcase(row['path']),0),os.path.normcase(row['path'])))
    plan = dict(schema=1, operation="uninstall_review", operation_id=uuid.uuid4().hex,
        installation_id=location.installation_id, legacy=location.legacy, user_sid=location.user_sid,
        windows_uninstall_id=windows_uninstall_id,
        program_root=str(program), installation_root=str(location.root), packages_root=str(location.packages_root),
        active_sha256=digest(active_path), system_changed=False,
        executed=False, ready_to_execute=False, files=files, processes=processes,
        process_observation_error=runtime_error,
        scheduled_task=dict(name=task, path="\\", required_command=str(versions / active["version"] / "Flower.HighHelper.exe"),
            required_arguments="--serve", removal_requires_definition_and_security_recheck=True),
        host_entries=host_entries, host_entries_require_exact_value_recheck=True,
        removal_method="recycle_exact_owned_files_after_review", registration_removal=None if location.legacy else location.registration_path,
        preserve=[str(location.data_root),str(location.cache_root),*[str(program/name) for name in
            ('permissions','privacy','work-authority','audit','execution-bindings','recovery')]],
        optional_cleanup=[dict(path=str(location.data_root), selected=False, purpose="personal_settings_profiles_and_history"),
                          dict(path=str(location.cache_root), selected=False, purpose="regenerable_cache")],
        blockers=blockers,
        required_sequence=["recheck_installation_and_exact_host_entries", "disable_exact_autostart",
            "bound_graceful_shutdown_and_confirm_each_exact_process_exit", "remove_only_matching_host_entries_and_task",
            "recycle_exact_owned_files", "remove_only_matching_registration"])
    output = Path(output).absolute()
    reject_links(output)
    with output.open("x", encoding="utf-8") as stream:
        json.dump(plan, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    script = render_uninstall(plan, output)
    script_path = output.with_suffix(".ApplyUninstall.ps1")
    with script_path.open("x",encoding="utf-8-sig") as stream:
        stream.write(script)
    plan.update(apply_script=str(script_path),apply_script_sha256=digest(script_path),plan_sha256=digest(output))
    return plan


def render_uninstall(plan, plan_path):
    templates = Path(__file__).with_name("high_broker_install")
    version = json.loads((Path(plan["program_root"])/"active.json").read_bytes())["version"]
    common = render_install_scripts(Path(plan["program_root"]),Path(plan["program_root"]),version,
        plan["scheduled_task"]["name"],task_xml_hash="")["InstallCommon.ps1"]
    source = (templates/"ApplyUninstall.ps1.template").read_text(encoding="utf-8")
    values = dict(COMMON=common,PLAN_PATH="'"+str(plan_path).replace("'","''")+"'",
        PLAN_HASH="'"+digest(plan_path)+"'",RECYCLE_TYPE=(templates/"RecycleOwnedFiles.cs").read_text(encoding="utf-8"))
    for key,value in values.items(): source=source.replace("@@"+key+"@@",value)
    if "@@" in source: raise ValueError("uninstall_template_unresolved")
    return source


def _atomic_json(path,value):
    temporary=path.with_name(path.name+'.'+uuid.uuid4().hex+'.tmp')
    with temporary.open('x',encoding='utf-8') as stream:
        json.dump(value,stream,ensure_ascii=False,indent=2);stream.write('\n')
    os.replace(temporary,path)


def _script_bytes(source):
    return source.replace('\r\n','\n').replace('\n',os.linesep).encode('utf-8-sig')


def _atomic_script(path,source):
    temporary=path.with_name(path.name+'.'+uuid.uuid4().hex+'.tmp')
    with temporary.open('xb') as stream:stream.write(_script_bytes(source))
    os.replace(temporary,path)


def complete_medium_host_stage(plan_path, expected_plan_sha256):
    """After local review, remove owned host entries at Medium before UAC.

    Keeps the operation ID and file inventory. Never launches a user host CLI
    with a High token. A later retry observes the exact registration first.
    """
    identity=require_medium()
    plan_path=Path(plan_path).absolute();reject_links(plan_path)
    if digest(plan_path)!=expected_plan_sha256:raise ValueError('uninstall_medium_plan_changed')
    plan=json.loads(plan_path.read_bytes())
    if plan['user_sid']!=identity['User']:raise ValueError('uninstall_medium_user_changed')
    script_path=plan_path.with_suffix('.ApplyUninstall.ps1')
    if plan.get('medium_host_receipt_path'):
        receipt_path=Path(plan['medium_host_receipt_path']);reject_links(receipt_path)
        if digest(receipt_path)!=plan.get('medium_host_receipt_sha256'):raise ValueError('uninstall_medium_receipt_changed')
        receipt=json.loads(receipt_path.read_bytes())
        if receipt.get('state')!='complete' or receipt.get('operation_id')!=plan['operation_id']:
            raise ValueError('uninstall_medium_stage_incomplete')
        expected_source=render_uninstall(plan,plan_path)
        expected_script_sha256=hashlib.sha256(_script_bytes(expected_source)).hexdigest()
        if digest(script_path)!=expected_script_sha256:
            if digest(script_path)!=plan.get('medium_previous_script_sha256'):
                raise ValueError('uninstall_medium_script_changed')
            _atomic_script(script_path,expected_source)
        return dict(plan_path=str(plan_path),plan_sha256=digest(plan_path),apply_script=str(script_path),
            apply_script_sha256=digest(script_path),operation_id=plan['operation_id'],medium_host_stage_complete=True)
    if plan.get('blockers'):raise ValueError('uninstall_medium_review_blockers')
    expected_old=hashlib.sha256(_script_bytes(render_uninstall(plan,plan_path))).hexdigest()
    if digest(script_path)!=expected_old:raise ValueError('uninstall_medium_script_changed')
    entries=plan.get('host_entries',[])
    unsupported=[entry for entry in entries if (entry.get('host')!='codex' or entry.get('kind')!='marketplace')
        and entry.get('registration_state') not in ('not_registered','removed')]
    if unsupported:raise ValueError('uninstall_medium_host_manual_review_required')
    codex_indexes=[index for index,entry in enumerate(entries) if entry.get('host')=='codex' and entry.get('kind')=='marketplace']
    codex_entries=[entries[index] for index in codex_indexes]
    observed=bind_owned_marketplaces(codex_entries) if codex_entries else []
    receipt_path=plan_path.with_name('uninstall-medium-'+plan['operation_id']+'.json')
    reject_links(receipt_path)
    receipt=dict(schema=1,operation_id=plan['operation_id'],input_plan_sha256=expected_plan_sha256,
        user_sid=identity['User'],program_root=plan['program_root'],state='observing',removed=[],observed_absent=[])
    if receipt_path.exists():
        previous=json.loads(receipt_path.read_bytes())
        if any(previous.get(key)!=receipt[key] for key in ('schema','operation_id','input_plan_sha256','user_sid','program_root')):
            raise ValueError('uninstall_medium_receipt_not_owned')
    _atomic_json(receipt_path,receipt)
    handled=set()
    for entry in observed:
        selector=entry['selector']
        if selector in handled:continue
        handled.add(selector)
        matching=[row for row in observed if row['selector']==selector and row['registration_state']=='registered']
        if not matching:
            receipt['observed_absent'].append(selector);continue
        target=matching[0]
        cli=resolve_codex_cli(target['cli']['path'])
        if digest(cli)!=target['cli']['sha256']:raise ValueError('uninstall_medium_cli_changed')
        receipt.update(state='removing',pending_selector=selector);_atomic_json(receipt_path,receipt)
        try:
            result=run_official_cli(cli,['plugin','marketplace','remove',selector],timeout=30,check=False)
            if result.returncode:raise ValueError('uninstall_medium_remove_unconfirmed')
            after=bind_owned_marketplaces(codex_entries,cli)
            if any(row['selector']==selector and row['registration_state']=='registered' for row in after):
                raise ValueError('uninstall_medium_remove_unconfirmed')
            receipt['removed'].append(selector);receipt.pop('pending_selector',None);_atomic_json(receipt_path,receipt)
        except (OSError,ValueError,subprocess.SubprocessError) as error:
            receipt.update(state='incomplete',reason=type(error).__name__);_atomic_json(receipt_path,receipt)
            raise
    final_codex=bind_owned_marketplaces(codex_entries) if codex_entries else []
    if any(row['registration_state']=='registered' for row in final_codex):raise ValueError('uninstall_medium_source_still_registered')
    final=[dict(entry) for entry in entries]
    for index,entry in zip(codex_indexes,final_codex):final[index]=entry
    receipt.update(state='complete',host_entries_observed=final);receipt.pop('pending_selector',None)
    _atomic_json(receipt_path,receipt)
    backup=plan_path.with_name(plan_path.name+'.before-medium.json')
    if not backup.exists():
        with backup.open('xb') as stream:stream.write(plan_path.read_bytes())
    elif digest(backup)!=expected_plan_sha256:raise ValueError('uninstall_medium_plan_backup_changed')
    plan.update(host_entries=final,medium_input_plan_sha256=expected_plan_sha256,
        medium_previous_script_sha256=expected_old,
        medium_host_receipt_path=str(receipt_path),medium_host_receipt_sha256=digest(receipt_path))
    _atomic_json(plan_path,plan)
    reject_links(script_path)
    _atomic_script(script_path,render_uninstall(plan,plan_path))
    return dict(plan_path=str(plan_path),plan_sha256=digest(plan_path),apply_script=str(script_path),
        apply_script_sha256=digest(script_path),operation_id=plan['operation_id'],medium_host_stage_complete=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--no-runtime-observation", action="store_true")
    parser.add_argument("--codex-cli",type=Path,help="Existing exact official codex.exe used only for read-only marketplace inspection.")
    args = parser.parse_args()
    plan = prepare(args.output, inspect_runtime=not args.no_runtime_observation,codex_cli=args.codex_cli)
    print(json.dumps(dict(plan=str(args.output.absolute()), system_changed=False, executed=False,
        apply_script=plan["apply_script"],apply_script_sha256=plan["apply_script_sha256"],plan_sha256=plan["plan_sha256"],
        files=len(plan["files"]), blockers=plan["blockers"]), ensure_ascii=False))


if __name__ == "__main__":
    main()
