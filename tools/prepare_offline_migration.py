"""Freeze a human-run, paused legacy migration; never elevate or install."""
from __future__ import annotations

import argparse
import base64
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.prepare_frozen_plugin import validate_delivery
from tools.prepare_high_broker_install import native_source_hashes, render_install_scripts, render_installer_type, system_powershell_path
from tools.prepare_work_authority_update import digest, require_unchanged_host_boundary
from tools.runtime_snapshot import reject_links

TEMPLATES = ROOT / 'tools/high_broker_install'
FUNCTIONS = ('Log', 'Hash', 'HashText', 'Admin', 'RequireStatusShape', 'RegisterTask', 'ReplaceActive')


def require_fixed_task(data: bytes, sid: str, target: Path, *, historical_task_sha256: str | None = None):
    """Require Normal for candidates; retain only hash-bound original legacy continuation bytes."""
    if historical_task_sha256 is not None and (type(historical_task_sha256) is not str
            or not re.fullmatch('[a-f0-9]{64}', historical_task_sha256)
            or hashlib.sha256(data).hexdigest() != historical_task_sha256):
        raise ValueError('offline_fixed_task_required')
    ns = '{http://schemas.microsoft.com/windows/2004/02/mit/task}'
    root = ET.fromstring(data)
    def one(parent, name):
        children = parent.findall(ns + name)
        if len(children) != 1:
            raise ValueError('offline_fixed_task_required')
        return children[0]
    def fields(parent, expected):
        if len(parent) != len(expected) or {c.tag for c in parent} != {ns + key for key in expected}:
            raise ValueError('offline_fixed_task_required')
        for key, value in expected.items():
            if one(parent, key).text != value or len(one(parent, key)):
                raise ValueError('offline_fixed_task_required')
    if root.tag != ns + 'Task' or len(root) != 5 or {c.tag for c in root} != {ns + k for k in ('RegistrationInfo','Triggers','Principals','Settings','Actions')}:
        raise ValueError('offline_fixed_task_required')
    triggers = one(root, 'Triggers'); principals = one(root, 'Principals'); actions = one(root, 'Actions')
    if len(triggers) != 1 or len(principals) != 1 or len(actions) != 1 or actions.attrib != {'Context': 'FlowerUser'}:
        raise ValueError('offline_fixed_task_required')
    fields(one(triggers, 'LogonTrigger'), {'Enabled': 'true', 'UserId': sid})
    principal = one(principals, 'Principal')
    if principal.attrib != {'id': 'FlowerUser'}:
        raise ValueError('offline_fixed_task_required')
    fields(principal, {'UserId': sid, 'LogonType': 'InteractiveToken', 'RunLevel': 'HighestAvailable'})
    fields(one(actions, 'Exec'), {'Command': str(target / 'Flower.HighHelper.exe'), 'Arguments': '--serve', 'WorkingDirectory': str(target)})
    settings = one(root, 'Settings')
    expected_settings = {'MultipleInstancesPolicy': 'Parallel', 'DisallowStartIfOnBatteries': 'false',
        'StopIfGoingOnBatteries': 'false', 'AllowHardTerminate': 'false', 'StartWhenAvailable': 'true',
        'RunOnlyIfNetworkAvailable': 'false', 'ExecutionTimeLimit': 'PT0S', 'Enabled': 'true'}
    # A new candidate cannot inherit the scheduler's background default. The
    # old shape is accepted only when continuing the exact original task bytes.
    if historical_task_sha256 is None or settings.findall(ns + 'Priority'):
        expected_settings['Priority'] = '6'
    fields(settings, expected_settings)


def ps_capture(script):
    powershell = system_powershell_path()
    result = subprocess.run([str(powershell), '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand',
                             base64.b64encode(script.encode('utf-16-le')).decode('ascii')],
                            capture_output=True, timeout=30, creationflags=subprocess.CREATE_NO_WINDOW, check=True)
    return json.loads(result.stdout.decode('utf-8-sig'))


def update_functions():
    path = str(TEMPLATES / 'UpdateWorkAuthority20261018.ps1.template').replace("'", "''")
    names = ','.join("'" + name + "'" for name in FUNCTIONS)
    result = ps_capture("""$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('__PATH__',[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'update_template_parse_failed'}
$result=@{}
foreach($name in @(__NAMES__)){
 $found=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true))
 if($found.Count -ne 1){throw 'shared_function_not_unique'}
 $result[$name]=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($found[0].Extent.Text))
}
$result|ConvertTo-Json -Compress
""".replace('__PATH__', path).replace('__NAMES__', names))
    if set(result) != set(FUNCTIONS):
        raise ValueError('shared_function_set_changed')
    return '\n'.join(base64.b64decode(result[name], validate=True).decode('utf8') for name in FUNCTIONS)


def live_original(pid: int, expected_image: Path):
    """Read metadata only; the High installer must independently retain a handle."""
    import win32api
    import win32con
    import win32security
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.GetProcessTimes.argtypes = (wintypes.HANDLE, *([ctypes.POINTER(ctypes.c_uint64)] * 4))
    kernel.GetProcessTimes.restype = wintypes.BOOL
    kernel.QueryFullProcessImageNameW.argtypes = (wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD))
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.ProcessIdToSessionId.argtypes = (wintypes.DWORD, ctypes.POINTER(wintypes.DWORD))
    kernel.ProcessIdToSessionId.restype = wintypes.BOOL
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        created, exited, system, user = (ctypes.c_uint64() for _ in range(4))
        if not kernel.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(exited), ctypes.byref(system), ctypes.byref(user)):
            raise ctypes.WinError(ctypes.get_last_error())
        path = ctypes.create_unicode_buffer(32768); length = wintypes.DWORD(len(path))
        if not kernel.QueryFullProcessImageNameW(handle, 0, path, ctypes.byref(length)):
            raise ctypes.WinError(ctypes.get_last_error())
        if Path(path.value) != expected_image or exited.value:
            raise ValueError('live_original_image_required')
    finally:
        kernel.CloseHandle(handle)
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    try:
        sid = win32security.ConvertSidToStringSid(win32security.GetTokenInformation(token, win32security.TokenUser)[0])
        groups = win32security.GetTokenInformation(token, win32security.TokenGroups)
        logons = [win32security.ConvertSidToStringSid(group) for group, flags in groups if flags & 0xC0000000 == 0xC0000000]
    finally:
        token.Close()
    session = wintypes.DWORD(); original_session = wintypes.DWORD()
    if not kernel.ProcessIdToSessionId(os.getpid(), ctypes.byref(session)) or not kernel.ProcessIdToSessionId(pid, ctypes.byref(original_session)):
        raise ctypes.WinError(ctypes.get_last_error())
    if len(logons) != 1 or not logons[0].startswith('S-1-5-5-') or original_session.value != session.value:
        raise ValueError('fixed_original_logon_required')
    return {'OldPid': pid, 'OldCreated': str(created.value), 'SessionId': session.value, 'LogonSid': logons[0], 'UserSid': sid}


def prepare(package: Path, output: Path, pid: int):
    package = package.absolute(); output = output.absolute()
    reject_links(package); reject_links(output)
    package = package.resolve(strict=True); output = output.resolve()
    if output.exists() or not output.is_relative_to(Path(os.environ['TEMP']).resolve()):
        raise ValueError('new_os_temporary_output_required')
    active, policy, staged = validate_delivery(package)
    native_proof = json.loads((staged / 'native-build-evidence.json').read_bytes())
    if (native_proof.get('source_hashes') != native_source_hashes(ROOT) or
            native_proof.get('binary_hashes', {}).get('Flower.HighHelper.dll') != active['hashes']['Flower.HighHelper.dll']):
        raise ValueError('offline_matching_native_capability_required')
    from flower_control.install_location import program_root
    production = program_root()
    reject_links(production)
    old_active = json.loads((production / 'active.json').read_bytes())
    old_version = old_active['version']; version = active['version']
    if not re.fullmatch('[a-f0-9]{32}', old_version) or old_version == version:
        raise ValueError('different_fixed_versions_required')
    old_dir = production / 'versions' / old_version
    old_policy = json.loads((old_dir / 'broker.json').read_bytes())
    require_unchanged_host_boundary(policy, old_policy)
    prep = json.loads((package / 'preparation.json').read_bytes())
    if (prep.get('installed') is not False or prep.get('version') != version or
            Path(prep['production_root']).resolve() != production.resolve()):
        raise ValueError('fixed_uninstalled_package_required')
    for name in ('Flower.HighHelper.exe', 'Flower.HighHelper.dll', 'broker.json'):
        if digest(old_dir / name) != old_active['hashes'][name]:
            raise ValueError('original_installation_hash_changed')
    identity = live_original(pid, old_dir / 'Flower.HighHelper.exe')
    if identity['UserSid'] != policy['UserSid']:
        raise ValueError('same_user_migration_required')
    sid = identity['UserSid']; task = 'FlowerControl.HighBroker.' + hashlib.sha256(sid.encode()).hexdigest()[:16]
    if prep.get('task_name') != task:
        raise ValueError('task_identity_changed')
    require_fixed_task((package / 'task.xml').read_bytes(), sid, production / 'versions' / version)
    expected_common = render_install_scripts(package, production, version, task)['InstallCommon.ps1']
    if (package / 'InstallCommon.ps1').read_text(encoding='utf-8-sig') != expected_common:
        raise ValueError('offline_matching_fixed_common_required')
    task_data = ps_capture(r"""$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSHOME 'Modules\ScheduledTasks\ScheduledTasks.psd1')
$xml=[string](Export-ScheduledTask -TaskName '__TASK__' -TaskPath '\')
$scheduler=New-Object -ComObject Schedule.Service;$folder=$null;$registered=$null
try{$scheduler.Connect();$folder=$scheduler.GetFolder('\');$registered=$folder.GetTask('__TASK__');$sddl=[string]$registered.GetSecurityDescriptor(7)}
finally{if($null -ne $registered){[Runtime.InteropServices.Marshal]::ReleaseComObject($registered)|Out-Null};if($null -ne $folder){[Runtime.InteropServices.Marshal]::ReleaseComObject($folder)|Out-Null};[Runtime.InteropServices.Marshal]::ReleaseComObject($scheduler)|Out-Null}
@{xml=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($xml));sddl=$sddl}|ConvertTo-Json -Compress
""".replace('__TASK__', task))
    operation = uuid.uuid4().hex
    journal = production / 'recovery' / (hashlib.sha256(identity['LogonSid'].encode()).hexdigest() + '.json')
    # No fabricated live status/epochs: normal-exit and stopped-start evidence
    # are obtained later by the human-run High installer itself.
    plan = {**identity, 'Schema': 1, 'Mode': 'human_offline_paused', 'OperationId': operation,
            'Package': str(package), 'BrokerRoot': str(production), 'Version': version,
            'OldVersion': old_version, 'TaskName': task, 'RecoveryJournal': str(journal),
            'OldActiveSha256': digest(production / 'active.json'), 'OldPolicySha256': digest(old_dir / 'broker.json'),
            'OldExeSha256': digest(old_dir / 'Flower.HighHelper.exe'), 'OldDllSha256': digest(old_dir / 'Flower.HighHelper.dll'),
            'ActiveSha256': digest(package / 'active.json'), 'CommonSha256': digest(package / 'InstallCommon.ps1'),
            'TaskXmlSha256': digest(package / 'task.xml'),
            'OldTaskDefinitionSha256': hashlib.sha256(base64.b64decode(task_data['xml'], validate=True)).hexdigest(),
            'OldTaskSddlSha256': hashlib.sha256(task_data['sddl'].encode()).hexdigest(),
            'ProgressPrefix': str(production / 'recovery' / ('installation-' + operation) / 'update')}
    script = (TEMPLATES / 'OfflineMigration.ps1.template').read_text(encoding='utf8')
    replacements = {'PLAN_JSON': json.dumps(plan, ensure_ascii=False, indent=2), 'UPDATE_FUNCTIONS': update_functions(),
                    'PINNED_DELIVERY_TYPE': render_installer_type('PinnedDelivery.cs', production),
                    'OFFLINE_GUARD_TYPE': (TEMPLATES / 'OfflineMigrationGuard.cs').read_text(encoding='utf8'),
                    'RECOVERY_PROTECTION_TYPE': render_installer_type('RecoveryProtection.cs', production)}
    for key, text in replacements.items():
        script = script.replace('@@' + key + '@@', text)
    if '@@' in script:
        raise ValueError('offline_template_unresolved')
    output.mkdir(parents=True)
    target = output / 'Migrate.ps1'; target.write_text(script, encoding='utf-8-sig')
    # A human may launch this exact, hash-bound script with Windows Run as
    # administrator. This preparer never launches it or creates an elevation.
    literal = str(target).replace("'", "''"); script_sha = digest(target)
    bootstrap = ("$ErrorActionPreference='Stop';$s=[IO.File]::Open('" + literal +
                 "',[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);try{" +
                 "$h=[Security.Cryptography.SHA256]::Create();try{$v=[BitConverter]::ToString($h.ComputeHash($s)).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()};" +
                 "if($v -cne '" + script_sha + "'){throw 'migration_script_changed'};$s.Position=0;" +
                 "$r=[IO.StreamReader]::new($s,[Text.Encoding]::UTF8,$true,4096,$true);try{$text=$r.ReadToEnd()}finally{$r.Dispose()};" +
                 "& ([scriptblock]::Create($text))}finally{$s.Dispose()}")
    encoded = base64.b64encode(bootstrap.encode('utf-16-le')).decode('ascii')
    powershell = str(system_powershell_path())
    launcher = '@echo off\r\n"' + powershell + '" -NoLogo -NoProfile -EncodedCommand ' + encoded + '\r\npause\r\n'
    (output / 'Run-as-administrator.cmd').write_bytes(launcher.encode('ascii'))
    record = {**plan, 'Script': str(target), 'ScriptSha256': script_sha, 'Powershell': powershell,
              'LauncherSha256': digest(output / 'Run-as-administrator.cmd'), 'Installed': False, 'Elevated': False}
    (output / 'plan.json').write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf8')
    return record


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--broker-pid', type=int, required=True)
    options = parser.parse_args()
    result = prepare(options.package, options.output, options.broker_pid)
    print(json.dumps({key: result[key] for key in ('OperationId','Mode','Version','OldVersion','Script','ScriptSha256','Installed','Elevated')}))
