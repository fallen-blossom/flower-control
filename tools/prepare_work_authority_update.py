"""Prepare one exact local update; never elevate, install or change policy."""
from __future__ import annotations

import argparse
import base64
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def hidden_bootstrap_source(powershell: Path, encoded: str) -> str:
    """WSH uses Windows SW_HIDE before PowerShell starts its console host.

    PowerShell's own -WindowStyle Hidden can hang under a delegated terminal.
    This optional local carrier does not change UAC, execution policy or Stop.
    """
    command = subprocess.list2cmdline([str(powershell), '-NoLogo', '-NoProfile',
                                     '-NonInteractive', '-EncodedCommand', encoded])
    return ('Set shell = CreateObject("WScript.Shell")\r\n'
            + 'code = shell.Run("' + command.replace('"', '""') + '", 0, True)\r\n'
            + 'WScript.Quit code\r\n')


def candidate_maintenance_protocol(executable: Path, expected_sha256: str) -> int:
    if digest(executable) != expected_sha256:
        raise ValueError('candidate_helper_changed')
    result = subprocess.run([str(executable), '--flower-capabilities'], capture_output=True,
                            timeout=15, creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode == 2:
        reply = json.loads(result.stderr or result.stdout)
        if reply.get('reason') == 'arguments_rejected':
            return 0  # Older reviewed packages have no standalone capability API.
    if result.returncode:
        raise ValueError('candidate_capabilities_unavailable')
    value = json.loads(result.stdout)
    if (value.get('schema') != 1 or value.get('AuthorityGranted') is not False
            or value.get('InputDispatched') is not False
            or type(value.get('bound_maintenance_writer_protocol')) is not int
            or value['bound_maintenance_writer_protocol'] not in (0, 1)):
        raise ValueError('candidate_capabilities_rejected')
    return value['bound_maintenance_writer_protocol']


def requires_host_native_elevation(old_protocol, new_protocol, old_role, new_role):
    return (type(old_protocol) is not int or old_protocol != 1
            or type(new_protocol) is not int or new_protocol != 1
            or old_role != 'high' or new_role != 'high')


def previous_broker_status(executable: Path):
    """One original read-only query; never retry or substitute another helper."""
    try:
        reply = subprocess.run([str(executable), '--flower-admin', 'status'], capture_output=True,
                               timeout=20, creationflags=subprocess.CREATE_NO_WINDOW, check=False)
    except subprocess.TimeoutExpired:
        raise RuntimeError('previous_broker_status_rejected:status_timeout') from None
    except OSError:
        raise RuntimeError('previous_broker_status_rejected:status_start_failed') from None
    if reply.returncode:
        code = 'status_unavailable'
        native_code = None
        try:
            error = json.loads(reply.stderr)
            reason = error.get('reason') if type(error) is dict else None
            if type(reason) is str and re.fullmatch('[a-z][a-z0-9_]{0,95}', reason):
                code = reason
            # Keep a bounded Windows diagnostic only; it cannot authorize or
            # change the result of this single original status request.
            value = error.get('winerror') if type(error) is dict else None
            if type(value) is int and 0 <= value <= 65535:
                native_code = value
        except (ValueError, UnicodeError):
            pass
        suffix = '' if native_code is None else ':winerror_' + str(native_code)
        raise RuntimeError('previous_broker_status_rejected:' + code + suffix)
    try:
        result = json.loads(reply.stdout)
        status = result['Status']
        if type(status) is not dict:
            raise ValueError('invalid status')
        return status
    except (KeyError, TypeError, ValueError, UnicodeError):
        raise RuntimeError('previous_broker_status_invalid') from None


def require_status_shape(status):
    """Reject missing/nullable/coerced safety fields before making a plan.

    Match RequireStatusShape in the elevated template. Legacy snapshots may
    omit persistence diagnostics; if present, they are null or a nonempty error.
    """
    if type(status) is not dict or type(status.get('version')) is not str or not re.fullmatch('[a-f0-9]{32}', status['version']):
        raise ValueError('broker_status_invalid')
    for key in ('paused', 'global_write_stopped', 'stopping', 'release_fault', 'high_verified', 'computer_paused'):
        if type(status.get(key)) is not bool:
            raise ValueError('broker_status_invalid')
    limits = {'pid': (1, 2**31-1), 'created': (1, 2**63-1),
              'active_requests': (0, 2**31-1), 'pending_release_recoveries': (0, 2**31-1),
              'global_stop_epoch': (0, 2**63-1), 'protected_stop_epoch': (0, 2**63-1)}
    for key, (minimum, maximum) in limits.items():
        value = status.get(key)
        if type(value) is not int or not minimum <= value <= maximum:
            raise ValueError('broker_status_invalid')
    if 'maintenance_activities' in status and (type(status['maintenance_activities']) is not int
                                              or not 0 <= status['maintenance_activities'] <= 2**31-1):
        raise ValueError('broker_status_invalid')
    for key in ('stop_persistence_error', 'computer_pause_persistence_error'):
        value = status.get(key)
        if value is not None and (type(value) is not str or not value):
            raise ValueError('broker_status_invalid')


def require_previous_idle(status, version, *, recovery, allow_paused=False):
    require_status_shape(status)
    try:
        role = require_execution_role(status)
    except ValueError:
        raise ValueError('previous_broker_not_idle_or_user_stop_preserved') from None
    # SharedWriteGate increments on Stop only; ProtectedStop increments on both
    # Stop and resume. Recovery has already applied the maintenance Stop.
    remaining = {'global_stop_epoch': 0 if recovery else 1,
                 'protected_stop_epoch': 1 if recovery or role == 'ordinary' else 2}
    if any(status[key] > 2**63-1-count for key, count in remaining.items()):
        raise ValueError('stop_epoch_exhausted')
    expected_paused = status['paused'] if allow_paused else recovery
    if (status['version'] != version or status['paused'] != expected_paused or status['global_write_stopped'] != expected_paused
            or status['stopping'] or status['release_fault'] or status.get('role_transition', False)
            or status.get('stop_persistence_error') or status.get('computer_pause_persistence_error')
            or status['active_requests'] != 0 or status['pending_release_recoveries'] != 0
            or status.get('maintenance_activities', 0) != 0):
        raise ValueError('previous_broker_not_idle_or_user_stop_preserved')
    if role == 'ordinary' and not recovery and status['role_stop']['Ordinary']['Count'] >= 1024 * 1024:
        raise ValueError('ordinary_stop_capacity')


def require_execution_role(status):
    ordinary = (status.get('maintenance_protocol') == 2 or status.get('broker_role') == 'ordinary'
                or status.get('ordinary_verified') is True)
    if not ordinary:
        if (status.get('high_verified') is not True or status.get('ordinary_verified', False) is not False
                or status.get('broker_role', 'high') != 'high'):
            raise ValueError('broker_execution_role_invalid')
        return 'high'
    if (type(status.get('maintenance_protocol')) is not int or status['maintenance_protocol'] != 2
            or status.get('broker_role') != 'ordinary' or status.get('ordinary_verified') is not True
            or status.get('high_verified') is not False or type(status.get('authority_tier')) is not int
            or status['authority_tier'] not in (-1, 0) or type(status.get('policy_revision')) is not str
            or not 1 <= len(status['policy_revision']) <= 128 or any(ord(c) < 32 for c in status['policy_revision'])):
        raise ValueError('broker_execution_role_invalid')
    stop = status.get('role_stop')
    if type(stop) is not dict or set(stop) != {'Shared', 'Protected', 'Computer', 'Ordinary', 'OrdinaryComputer'}:
        raise ValueError('broker_role_stop_invalid')
    def number(value):
        return type(value) is int and 0 <= value <= 2**63-1
    shared = stop['Shared']
    if (type(shared) is not dict or set(shared) != {'Stopped', 'Epoch', 'ResumeAllEpoch'}
            or type(shared['Stopped']) is not bool or not number(shared['Epoch'])
            or not number(shared['ResumeAllEpoch']) or shared['ResumeAllEpoch'] > shared['Epoch']):
        raise ValueError('broker_role_stop_invalid')
    for key in ('Protected', 'Computer'):
        value = stop[key]
        if (type(value) is not dict or set(value) != {'Schema', 'UserSid', 'Session', 'Stopped', 'Epoch'}
                or type(value['Schema']) is not int or value['Schema'] != 1
                or type(value['UserSid']) is not str or not re.fullmatch(r'S-1-5-21-[0-9-]+', value['UserSid'])
                or not number(value['Session']) or value['Session'] == 0 or type(value['Stopped']) is not bool
                or not number(value['Epoch'])):
            raise ValueError('broker_role_stop_invalid')
    if (stop['Protected']['UserSid'] != stop['Computer']['UserSid']
            or stop['Protected']['Session'] != stop['Computer']['Session']
            or status.get('session_id', stop['Protected']['Session']) != stop['Protected']['Session']):
        raise ValueError('broker_role_stop_invalid')
    for key in ('Ordinary', 'OrdinaryComputer'):
        value = stop[key]
        if (type(value) is not dict or set(value) != {'Count', 'Acknowledged'} or not number(value['Count'])
                or not number(value['Acknowledged']) or value['Acknowledged'] > value['Count']):
            raise ValueError('broker_role_stop_invalid')
    if (shared['Epoch'] != status['global_stop_epoch'] or shared['Stopped'] != status['global_write_stopped']
            or stop['Protected']['Epoch'] != status['protected_stop_epoch']
            or status['paused'] != (shared['Stopped'] or stop['Protected']['Stopped']
                                   or stop['Ordinary']['Count'] != stop['Ordinary']['Acknowledged'])
            or status['computer_paused'] != (stop['Computer']['Stopped']
                                            or stop['OrdinaryComputer']['Count'] != stop['OrdinaryComputer']['Acknowledged'])):
        raise ValueError('broker_role_stop_invalid')
    return 'ordinary'


def require_maintenance_support(status):
    if type(status.get('maintenance_protocol')) is not int or status['maintenance_protocol'] not in (1, 2):
        raise ValueError('maintenance_binding_unsupported')
    try:
        require_execution_role(status)
    except ValueError:
        raise ValueError('maintenance_binding_unsupported') from None
    if type(status.get('maintenance_activities')) is not int:
        raise ValueError('broker_status_invalid')


def read_candidate_role_policy(executable, expected_hashes):
    import win32file
    executable = executable.absolute()
    if executable.name != 'Flower.HighHelper.exe':
        raise ValueError('candidate_role_reader_changed')
    required = ('Flower.HighHelper.exe', 'Flower.HighHelper.dll', 'Flower.HighHelper.deps.json',
                'Flower.HighHelper.runtimeconfig.json', 'Flower.UacNative.dll')
    with ExitStack() as pinned:
        # Keep the entire pathname stable, including directories, while the
        # loader opens it. File hashes alone before/after CreateProcess leave
        # a replacement-and-restoration gap in a mutable temporary package.
        for parent in (*reversed(executable.parent.parents), executable.parent):
            handle = win32file.CreateFile(str(parent), 0x80, 3, None, 3, 0x02200000, None)
            pinned.callback(handle.Close)
            if win32file.GetFileInformationByHandle(handle)[0] & 0x400:
                raise ValueError('candidate_role_reader_changed')
        for name in required:
            path = executable.parent / name
            if (type(expected_hashes.get(name)) is not str or not re.fullmatch('[a-f0-9]{64}', expected_hashes[name])
                    or path.is_symlink() or path.is_junction()):
                raise ValueError('candidate_role_reader_changed')
            handle = win32file.CreateFile(str(path), 0x80000000, 1, None, 3, 0x00200000, None)
            pinned.callback(handle.Close)
            if win32file.GetFileInformationByHandle(handle)[0] & (0x400 | 0x10):
                raise ValueError('candidate_role_reader_changed')
            hashed = hashlib.sha256()
            while True:
                _, block = win32file.ReadFile(handle, 65536)
                if not block:
                    break
                hashed.update(block)
            if hashed.hexdigest() != expected_hashes[name]:
                raise ValueError('candidate_role_reader_changed')
        environment = {k: v for k, v in os.environ.items()
                       if not k.upper().startswith(('DOTNET_', 'COMPLUS_', 'CORECLR_', 'COR_'))}
        reply = subprocess.run([str(executable), '--flower-role-policy'], capture_output=True, timeout=20,
                               creationflags=subprocess.CREATE_NO_WINDOW, check=False, env=environment)
    if reply.returncode:
        raise ValueError('candidate_role_reader_failed')
    value = json.loads(reply.stdout)
    if (type(value) is not dict or set(value) != {'Phase', 'Revision', 'Tier', 'UserSid', 'Stop'}
            or value['Phase'] != 'role_policy' or type(value['Tier']) is not int or not -1 <= value['Tier'] <= 3
            or type(value['Revision']) is not str or not 1 <= len(value['Revision']) <= 128
            or type(value['UserSid']) is not str or not re.fullmatch(r'S-1-5-21-[0-9-]+', value['UserSid'])):
        raise ValueError('candidate_role_policy_invalid')
    anchor = value['Stop']
    if type(anchor) is not dict or set(anchor) != {'Protected', 'Computer', 'Ordinary', 'OrdinaryComputer'}:
        raise ValueError('candidate_role_policy_invalid')
    # Reuse the strict nested Stop contract. This synthetic envelope is only
    # a shape check for a read-only durable anchor; it is never sent or used as
    # executor identity/admission evidence.
    try:
        full = dict(Shared=dict(Stopped=False, Epoch=0, ResumeAllEpoch=0), **anchor)
        require_execution_role(dict(maintenance_protocol=2, broker_role='ordinary', ordinary_verified=True,
            high_verified=False, authority_tier=0, policy_revision=value['Revision'], role_stop=full,
            global_stop_epoch=0, global_write_stopped=False, protected_stop_epoch=anchor['Protected']['Epoch'],
            paused=anchor['Protected']['Stopped'] or anchor['Ordinary']['Count'] != anchor['Ordinary']['Acknowledged'],
            computer_paused=anchor['Computer']['Stopped'] or anchor['OrdinaryComputer']['Count'] != anchor['OrdinaryComputer']['Acknowledged']))
    except (KeyError, TypeError, ValueError):
        raise ValueError('candidate_role_policy_invalid') from None
    if anchor['Protected']['UserSid'] != value['UserSid']:
        raise ValueError('candidate_role_policy_invalid')
    return value


def require_unchanged_host_boundary(policy, old_policy):
    """Allow removal/tightening of legacy Codex pins, never expansion.

    Signed Codex admission is represented by an empty legacy pin list. Native
    hosts are exact image/hash identities and may not change during this update.
    """
    if type(policy) is not dict or type(old_policy) is not dict:
        raise ValueError('existing_user_data_host_boundary_changed')
    if (policy.get('UserSid') != old_policy.get('UserSid')
            or policy.get('DataRoot') != old_policy.get('DataRoot')
            or policy.get('NativeHosts') != old_policy.get('NativeHosts')):
        raise ValueError('existing_user_data_host_boundary_changed')
    for key in ('CodexPackageFamilies', 'CodexImageRoots'):
        previous = old_policy.get(key, [])
        current = policy.get(key, [])
        if (type(previous) is not list or type(current) is not list
                or any(type(value) is not str or not value for value in previous + current)
                or not set(current).issubset(previous)):
            raise ValueError('existing_user_data_host_boundary_changed')


def require_recovery_stop(status, previous, durable=None):
    """Only the exact failed update's own durable Stop may be recovered."""
    role = require_execution_role(status)
    if (role != previous.get('OldBrokerRole', 'high')
            or status['global_stop_epoch'] != previous['OldSharedEpoch'] + 1
            or status['protected_stop_epoch'] != previous['OldProtectedEpoch'] + (role == 'high')):
        raise ValueError('maintenance_stop_changed_no_recovery')
    if previous.get('RoleLifecycleSupported') is True:
        anchor = json.loads(json.dumps(previous['DurableStopAnchor']))
        if role == 'ordinary':
            anchor['Ordinary']['Count'] += 1
        else:
            anchor['Protected']['Stopped'] = True
            anchor['Protected']['Epoch'] += 1
        actual = status.get('role_stop')
        actual = {k: actual[k] for k in anchor} if actual is not None else durable
        if actual != anchor or durable is not None and durable != actual:
            raise ValueError('maintenance_stop_changed_no_recovery')
        if role == 'ordinary' and (status['policy_revision'] != previous['RolePolicyRevision']
                                   or status['authority_tier'] != previous['RolePolicyTier']):
            raise ValueError('maintenance_stop_changed_no_recovery')


def allowed_live_reuse_failure(reason):
    """Only failures proven to occur after payload verification and before start."""
    if reason == 'unparked_version_executor_present':
        return True
    return (type(reason) is str and len(reason) <= 1024
            and re.search(r'(?<![a-z0-9_])stopped_client_image_unreadable(?![a-z0-9_])', reason) is not None)


def require_failed_live_payload(previous, result, rows):
    if (previous.get('LeavePaused') is not True or previous.get('RecoveryOperation') != ''
            or result.get('operation') != previous['OperationId'] or result.get('version') != previous['Version']
            or result.get('state') != 'failed' or not allowed_live_reuse_failure(result.get('reason'))
            or result.get('rollback') != 'previous_restored_paused' or result.get('start_attempted') is not False
            or type(result.get('active_changed')) is not bool or type(result.get('task_changed')) is not bool
            or result['active_changed'] != result['task_changed']
            or result.get('resumed') is not False):
        raise ValueError('failed_live_payload_receipt_required')
    stages = {}
    names = ('started', 'payload_verified', 'rollback_recovery_keeps_original_pause', 'failed')
    for index, row in enumerate(rows):
        stage = row.get('stage')
        if stage in names:
            if stage in stages:
                raise ValueError('failed_live_payload_progress_required')
            stages[stage] = (index, row.get('detail', {}))
    if (any(name not in stages for name in names)
            or [stages[name][0] for name in names] != sorted(stages[name][0] for name in names)):
        raise ValueError('failed_live_payload_progress_required')
    start, payload, rollback, failure = (stages[name][1] for name in names)
    if (start.get('operation') != previous['OperationId'] or start.get('version') != previous['Version']
            or type(payload.get('files')) is not int or payload['files'] < 1
            or rollback.get('version') != previous['OldVersion'] or rollback.get('global_paused') is not True
            or failure.get('reason') != result['reason'] or failure.get('rollback') != result['rollback']):
        raise ValueError('failed_live_payload_progress_required')


def bind_reused_payload(package, production, active, old, previous_path, *, live=False):
    # A failed offline operation proves only the origin of these bytes. Its
    # historical Stop and process authority are never carried into this plan.
    from tools.prepare_offline_continuation import require_receipts
    from tools.prepare_frozen_plugin import validate_delivery, file_inventory
    from tools.prepare_high_broker_install import native_source_hashes
    from tools.runtime_snapshot import reject_links
    previous_path = previous_path.absolute()
    reject_links(previous_path); reject_links(production)
    previous_hash = digest(previous_path)
    previous = json.loads(previous_path.read_bytes())
    op = previous.get('OperationId')
    mode_valid = previous.get('LeavePaused') is True if live else previous.get('Mode') == 'human_offline_paused'
    if (not mode_valid or type(op) is not str
            or not re.fullmatch('[a-f0-9]{32}', op) or Path(previous['BrokerRoot']) != production
            or previous['Version'] != active['version'] or previous['OldVersion'] != old['version']
            or previous['ActiveSha256'] != digest(package / 'active.json')
            or previous['OldActiveSha256'] != digest(production / 'active.json')
            or previous['CommonSha256'] != digest(package / 'InstallCommon.ps1')
            or previous['TaskXmlSha256'] != digest(package / 'task.xml')):
        raise ValueError('same_offline_payload_required')
    old_dir = production / 'versions' / old['version']
    for field, name in (('OldPolicySha256', 'broker.json'), ('OldExeSha256', 'Flower.HighHelper.exe'),
                        ('OldDllSha256', 'Flower.HighHelper.dll')):
        if (digest(old_dir / name) != old['hashes'][name]
                or (not live or field == 'OldDllSha256') and previous.get(field) != old['hashes'][name]):
            raise ValueError('offline_original_installation_changed')
    if digest(old_dir / 'installation.json') != previous['OldActiveSha256']:
        raise ValueError('offline_original_manifest_changed')
    prefix = production / 'recovery' / ('installation-' + op) / 'update'
    result_path = Path(str(prefix) + '-result.json'); progress_path = Path(str(prefix) + '-progress.jsonl')
    reject_links(result_path); reject_links(progress_path)
    result_bytes = result_path.read_bytes(); progress_bytes = progress_path.read_bytes()
    result_hash = hashlib.sha256(result_bytes).hexdigest(); progress_hash = hashlib.sha256(progress_bytes).hexdigest()
    result = json.loads(result_bytes)
    rows = [json.loads(row) for row in progress_bytes.decode('utf8').splitlines()]
    if live:
        require_failed_live_payload(previous, result, rows)
        for filename, encoding, field in (('update-previous-task.xml', 'utf-16', 'OldTaskDefinitionSha256'),
                                          ('update-previous-task-sddl.txt', 'utf-8-sig', 'OldTaskSddlSha256')):
            saved = prefix.parent / filename; reject_links(saved)
            if hashlib.sha256(saved.read_bytes().decode(encoding).encode('utf-8')).hexdigest() != previous[field]:
                raise ValueError('failed_live_original_task_changed')
    else:
        require_receipts(previous, result, rows)
        if result.get('reason') != 'offline_independent_executor_present':
            raise ValueError('offline_payload_reuse_failure_required')
    validated, _, staged = validate_delivery(package)
    proof = json.loads((staged / 'native-build-evidence.json').read_bytes())
    if validated != active or proof.get('source_hashes') != native_source_hashes(ROOT):
        raise ValueError('offline_payload_source_changed')
    target = production / 'versions' / active['version']
    reject_links(target)
    staged_files = file_inventory(staged)
    if file_inventory(target) != staged_files:
        raise ValueError('offline_payload_inventory_changed')
    for name in staged_files:
        left = staged / name; right = target / name
        reject_links(right)
        if digest(left) != digest(right):
            raise ValueError('offline_payload_bytes_changed')
    if (digest(previous_path) != previous_hash or digest(result_path) != result_hash
            or digest(progress_path) != progress_hash):
        raise ValueError('offline_evidence_changed')
    return dict(**({'ReuseKind': 'failed_live'} if live else {}), ReusePayload=True, ReuseOperation=op, ReusePlan=str(previous_path), ReusePlanSha256=previous_hash,
                ReuseResultPath=str(result_path), ReuseResultSha256=result_hash,
                ReuseProgressPath=str(progress_path), ReuseProgressSha256=progress_hash)


def require_retained_high_status(status):
    shared = status.get('role_stop', {}).get('Shared') if type(status.get('role_stop')) is dict else None
    session = status.get('session_id')
    if (require_execution_role(status) != 'high' or type(session) is not int or session <= 0
            or type(shared) is not dict or set(shared) != {'Stopped', 'Epoch', 'ResumeAllEpoch'}
            or type(shared['Stopped']) is not bool or type(status.get('global_write_stopped')) is not bool
            or shared['Stopped'] != status['global_write_stopped']
            or type(shared['Epoch']) is not int or shared['Epoch'] != status['global_stop_epoch']
            or type(shared['ResumeAllEpoch']) is not int or not 0 <= shared['ResumeAllEpoch'] <= shared['Epoch']
            or shared['Epoch'] > 2**63 - 3):
        raise ValueError('retained_high_status_unsupported')
    return session, shared['ResumeAllEpoch']


def prepare(package: Path, output: Path, *, recovery_plan: Path | None = None, recovery_sha256: str = '',
            leave_paused: bool = False, reuse_offline_plan: Path | None = None, signer_probe: Path | None = None,
            reuse_live_plan: Path | None = None):
    package = package.absolute()
    output = output.absolute()
    if output.exists() or not output.is_relative_to(Path(os.environ['TEMP']).resolve()):
        raise ValueError('new_os_temporary_output_required')
    for path in (package, output, *package.parents, *output.parents):
        if path.is_symlink() or path.is_junction():
            raise ValueError('delivery_path_link_rejected')
    package = package.resolve(strict=True)
    active = json.loads((package / 'active.json').read_bytes())
    prep = json.loads((package / 'preparation.json').read_bytes())
    version = active['version']
    production = Path(os.environ['ProgramFiles']) / 'FlowerControl/HighHelper'
    old = json.loads((production / 'active.json').read_bytes())
    if type(version) is not str or not re.fullmatch('[a-f0-9]{32}', version):
        raise ValueError('fixed_new_update_required')
    target = production / 'versions' / version
    if reuse_offline_plan is not None and reuse_live_plan is not None:
        raise ValueError('one_payload_reuse_source_required')
    reuse_source = reuse_offline_plan or reuse_live_plan
    if reuse_source is None and (target.exists() or target.is_symlink() or target.is_junction()):
        raise ValueError('new_target_exists_no_replay')
    if reuse_source is not None and recovery_plan is not None:
        raise ValueError('reuse_requires_new_leave_paused_update')
    reuse = bind_reused_payload(package, production, active, old, reuse_source, live=reuse_live_plan is not None) if reuse_source else {}
    recovery = None
    recovery_result = None
    recovery_result_path = None
    if recovery_plan is not None:
        if not re.fullmatch('[a-f0-9]{64}', recovery_sha256) or digest(recovery_plan) != recovery_sha256:
            raise ValueError('exact_previous_update_plan_required')
        recovery = json.loads(recovery_plan.read_bytes())
        if (not re.fullmatch('[a-f0-9]{32}', recovery['OperationId'])
                or recovery['Version'] != version or recovery['OldVersion'] != old['version']
                or recovery['ActiveSha256'] != digest(package / 'active.json')
                or recovery['OldActiveSha256'] != digest(production / 'active.json')):
            raise ValueError('same_failed_update_required')
        recovery_result_path = production / 'recovery' / ('installation-' + recovery['OperationId']) / 'update-result.json'
        recovery_result = json.loads(recovery_result_path.read_bytes())
        if (recovery_result.get('state') != 'failed'
                or recovery_result.get('rollback') != 'previous_restored_legacy_pause_manual_recovery'
                or recovery_result.get('operation') != recovery['OperationId']
                or recovery_result.get('version') != version):
            raise ValueError('protected_failed_update_receipt_required')
    elif recovery_sha256:
        raise ValueError('recovery_plan_required')
    if (not re.fullmatch('[a-f0-9]{32}', version) or not re.fullmatch('[a-f0-9]{32}', old['version'])
            or prep.get('version') != version
            or Path(prep['production_root']).resolve() != production.resolve()
            or prep.get('installed') is not False or old['version'] == version):
        raise ValueError('fixed_new_update_required')
    new_root = package / 'versions' / version
    policy = json.loads((new_root / 'broker.json').read_bytes())
    if (policy.get('Version') != version or policy.get('Schema') != 1
            or digest(new_root / 'broker.json') != active['hashes']['broker.json']
            or digest(new_root / 'installation.json') != digest(package / 'active.json')):
        raise ValueError('fixed_policy_manifest_required')
    old_policy = json.loads((production / 'versions' / old['version'] / 'broker.json').read_bytes())
    require_unchanged_host_boundary(policy, old_policy)
    old_exe = production / 'versions' / old['version'] / 'Flower.HighHelper.exe'
    status = previous_broker_status(old_exe)
    # Retaining clients is a transport choice, independent of the final Stop
    # state. Ordinary-role and recovery updates keep their established route.
    retain_clients = leave_paused or (not recovery and require_execution_role(status) == 'high')
    require_previous_idle(status, old['version'], recovery=bool(recovery), allow_paused=retain_clients)
    require_maintenance_support(status)
    retained_session, shared_resume = require_retained_high_status(status) if retain_clients else (None, None)
    sid = policy['UserSid']
    if not re.fullmatch('S-1-5-21-[0-9-]+', sid):
        raise ValueError('fixed_user_required')
    old_role = require_execution_role(status)
    role_policy = read_candidate_role_policy(new_root / 'Flower.HighHelper.exe', active['hashes']) \
        if prep.get('role_lifecycle_supported') is True else None
    if old_role == 'ordinary' and role_policy is None:
        raise ValueError('ordinary_role_update_requires_role_aware_candidate')
    if role_policy is not None and (role_policy['UserSid'] != sid or old_role == 'ordinary'
            and (role_policy['Revision'] != status['policy_revision'] or role_policy['Tier'] != status['authority_tier'])):
        raise ValueError('broker_role_policy_changed')
    if role_policy is not None and (role_policy['Stop']['Protected']['Epoch'] != status['protected_stop_epoch']
            or (role_policy['Stop']['Computer']['Stopped'] or role_policy['Stop']['OrdinaryComputer']['Count'] != role_policy['Stop']['OrdinaryComputer']['Acknowledged']) != status['computer_paused']):
        raise ValueError('broker_role_stop_changed')
    if retain_clients and not leave_paused and not status['paused'] and (
            role_policy is None or role_policy['Tier'] <= 0 or 'computer_pause_persistence_error' not in status):
        raise ValueError('running_restore_requires_current_role_aware_high_candidate')
    if recovery:
        if recovery.get('RoleLifecycleSupported') is True and (role_policy is None
                or role_policy['Revision'] != recovery['RolePolicyRevision'] or role_policy['Tier'] != recovery['RolePolicyTier']):
            raise ValueError('maintenance_stop_changed_no_recovery')
        require_recovery_stop(status, recovery, role_policy['Stop'] if role_policy is not None else None)
    task = 'FlowerControl.HighBroker.' + hashlib.sha256(sid.encode()).hexdigest()[:16]
    if prep.get('task_name') != task:
        raise ValueError('prepared_task_identity_changed')
    # Read only this known task definition. Emit base64/JSON to avoid PS5's
    # redirected console encoding changing Chinese task text before hashing.
    script = r"""$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSHOME 'Modules\ScheduledTasks\ScheduledTasks.psd1')
$xml=[string](Export-ScheduledTask -TaskName '__TASK__' -TaskPath '\')
$scheduler=New-Object -ComObject Schedule.Service
$folder=$null;$registered=$null
try {$scheduler.Connect();$folder=$scheduler.GetFolder('\');$registered=$folder.GetTask('__TASK__');$sddl=[string]$registered.GetSecurityDescriptor(7)}
finally {if($null -ne $registered){[Runtime.InteropServices.Marshal]::ReleaseComObject($registered)|Out-Null};if($null -ne $folder){[Runtime.InteropServices.Marshal]::ReleaseComObject($folder)|Out-Null};[Runtime.InteropServices.Marshal]::ReleaseComObject($scheduler)|Out-Null}
@{xml=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($xml));sddl=$sddl}|ConvertTo-Json -Compress
""".replace('__TASK__', task)
    powershell = Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    capture = subprocess.run([str(powershell), '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand',
                              base64.b64encode(script.encode('utf-16-le')).decode('ascii')], capture_output=True,
                             timeout=30, creationflags=subprocess.CREATE_NO_WINDOW, check=True)
    task_data = json.loads(capture.stdout.decode('utf-8-sig'))
    old_xml = base64.b64decode(task_data['xml'], validate=True)
    operation = uuid.uuid4().hex
    log_root = production / 'recovery' / ('installation-' + operation)
    plan = {'Schema': 1, 'OperationId': operation, 'Package': str(package), 'BrokerRoot': str(production),
            'Version': version, 'OldVersion': old['version'], 'UserSid': sid, 'TaskName': task,
            'OldPid': status['pid'], 'OldCreated': str(status['created']),
            'OldSharedEpoch': status['global_stop_epoch'], 'OldProtectedEpoch': status['protected_stop_epoch'],
            'LegacyComputerPause': 'computer_pause_persistence_error' not in status,
            'OldComputerPaused': status['computer_paused'],
            'OldBrokerRole': old_role, 'NewBrokerRole': 'ordinary' if role_policy is not None and role_policy['Tier'] <= 0 else 'high',
            'RoleLifecycleSupported': role_policy is not None, 'RolePolicyRevision': role_policy['Revision'] if role_policy is not None else None,
            'RolePolicyTier': role_policy['Tier'] if role_policy is not None else None,
            'OldRoleStop': status['role_stop'] if old_role == 'ordinary' else None,
            'DurableStopAnchor': role_policy['Stop'] if role_policy is not None else None,
            'ActiveSha256': digest(package / 'active.json'), 'OldActiveSha256': digest(production / 'active.json'),
            'CommonSha256': digest(package / 'InstallCommon.ps1'), 'TaskXmlSha256': digest(package / 'task.xml'),
            'OldTaskDefinitionSha256': hashlib.sha256(old_xml).hexdigest(),
            'OldTaskSddlSha256': hashlib.sha256(task_data['sddl'].encode()).hexdigest(),
            'RecoveryOperation': recovery['OperationId'] if recovery else '',
            'RecoveryPlan': str(recovery_plan.absolute()) if recovery else '',
            'RecoveryPlanSha256': recovery_sha256 if recovery else '',
            'RecoveryResultSha256': digest(recovery_result_path) if recovery else '',
            'ProgressPrefix': str(log_root / 'update')}
    if retain_clients:
        from tools.prepare_stopped_host_update import bind_retained_clients
        old_dir = production / 'versions' / old['version']
        plan.update(LeavePaused=True, OriginalPaused=status['paused'],
                    RestoreRunningAfterInstall=not leave_paused and not status['paused'],
                    SessionId=retained_session, SharedResumeAllEpoch=shared_resume,
                    OldDllSha256=digest(old_dir / 'Flower.HighHelper.dll'))
        if digest(old_dir / 'broker.json') != old['hashes']['broker.json'] or plan['OldDllSha256'] != old['hashes']['Flower.HighHelper.dll']:
            raise ValueError('original_policy_or_library_changed')
        output.mkdir(parents=True)
        plan.update(bind_retained_clients(plan, old_policy, output, signer_probe, live_core=dict(
            Pid=status['pid'], Created=str(status['created']), Image=str(old_exe), User=sid, Session=retained_session)))
    plan.update(reuse)
    if reuse and (plan['OldTaskDefinitionSha256'] != json.loads(reuse_source.read_bytes())['OldTaskDefinitionSha256']
                  or plan['OldTaskSddlSha256'] != json.loads(reuse_source.read_bytes())['OldTaskSddlSha256']
                  or digest(reuse_source) != reuse['ReusePlanSha256']):
        raise ValueError('offline_original_task_changed')
    if recovery and (plan['OldTaskDefinitionSha256'] != recovery['OldTaskDefinitionSha256']
                     or plan['OldTaskSddlSha256'] != recovery['OldTaskSddlSha256']):
        raise ValueError('previous_task_not_restored_exactly')
    template_root = ROOT / 'tools/high_broker_install'
    old_writer_protocol = status.get('bound_maintenance_writer_protocol', 0)
    plan['OldBoundMaintenanceWriterProtocol'] = 1 if type(old_writer_protocol) is int and old_writer_protocol == 1 else 0
    plan['NewBoundMaintenanceWriterProtocol'] = candidate_maintenance_protocol(
        package/'versions'/version/'Flower.HighHelper.exe', active['hashes']['Flower.HighHelper.exe'])
    plan['RequiresHostNativeElevation'] = requires_host_native_elevation(
        plan['OldBoundMaintenanceWriterProtocol'], plan['NewBoundMaintenanceWriterProtocol'],
        plan['OldBrokerRole'], plan['NewBrokerRole'])
    body = (template_root / 'UpdateWorkAuthority20261018.ps1.template').read_text(encoding='utf-8')
    body = body.replace('@@PLAN_JSON@@', json.dumps(plan, ensure_ascii=False, indent=2))
    body = body.replace('@@PINNED_DELIVERY_TYPE@@', (template_root / 'PinnedDelivery.cs').read_text(encoding='utf-8'))
    if '@@' in body:
        raise ValueError('update_template_unresolved')
    if not retain_clients:
        output.mkdir(parents=True)
    script_path = output / 'Update.ps1'
    script_path.write_text(body, encoding='utf-8-sig')
    script_hash = digest(script_path)
    # The fixed high command reads one pinned stream, checks its exact bytes,
    # then executes that in-memory text. It never dot-sources a mutable path.
    path_literal = str(script_path).replace("'", "''")
    bootstrap = ("$ErrorActionPreference='Stop';$s=[IO.File]::Open('" + path_literal
                 + "',[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);try{"
                 "$h=[Security.Cryptography.SHA256]::Create();try{$v=[BitConverter]::ToString($h.ComputeHash($s)).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()};"
                 "if($v -cne '" + script_hash + "'){throw 'update_script_changed'};$s.Position=0;"
                 "$r=[IO.StreamReader]::new($s,[Text.Encoding]::UTF8,$true,4096,$true);try{$text=$r.ReadToEnd()}finally{$r.Dispose()};"
                 "& ([scriptblock]::Create($text))}finally{$s.Dispose()}")
    encoded = base64.b64encode(bootstrap.encode('utf-16-le')).decode('ascii')
    record = {**plan, 'UpdateScript': str(script_path), 'UpdateScriptSha256': script_hash,
              'BootstrapSha256': hashlib.sha256(bootstrap.encode('utf-16-le')).hexdigest(),
              'Powershell': str(powershell), 'EncodedBootstrap': encoded, 'Installed': False, 'Elevated': False}
    hidden_launcher = Path(os.environ['SystemRoot']) / 'System32/wscript.exe'
    if hidden_launcher.is_file():
        hidden_path = output / 'LaunchHidden.vbs'
        hidden_path.write_text(hidden_bootstrap_source(powershell, encoded), encoding='utf-16')
        record.update(HiddenLauncher=str(hidden_launcher), HiddenLauncherSha256=digest(hidden_launcher),
                      HiddenBootstrap=str(hidden_path), HiddenBootstrapSha256=digest(hidden_path),
                      HiddenWindowMechanism='windows-sw-hide')
    (output / 'plan.json').write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return {k: record[k] for k in ('OperationId', 'Version', 'OldVersion', 'OldPid', 'OldCreated', 'UpdateScript',
                                  'UpdateScriptSha256', 'ProgressPrefix', 'RequiresHostNativeElevation', 'Installed', 'Elevated')}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--recovery-plan', type=Path)
    parser.add_argument('--recovery-sha256', default='')
    parser.add_argument('--leave-paused', action='store_true',
                        help='Explicitly keep the maintenance Stop; default restores the original running state.')
    parser.add_argument('--reuse-offline-plan', type=Path)
    parser.add_argument('--reuse-live-plan', type=Path)
    parser.add_argument('--signer-probe', type=Path)
    options = parser.parse_args()
    print(json.dumps(prepare(options.package, options.output, recovery_plan=options.recovery_plan,
                             recovery_sha256=options.recovery_sha256, leave_paused=options.leave_paused,
                             reuse_offline_plan=options.reuse_offline_plan, signer_probe=options.signer_probe,
                             reuse_live_plan=options.reuse_live_plan), ensure_ascii=False))
