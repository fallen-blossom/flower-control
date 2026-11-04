"""Review and explicitly recycle retained Data/Cache after a verified uninstall.

Runs only as the interactive Medium user. Program metadata and directory
structure are retained. There is no permanent-delete or automatic-resume path.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager, ExitStack
from datetime import datetime, timezone
import base64
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
from flower_control.install_location import require_protected_path
from tools.prepare_high_broker_install import system_powershell_path


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _path(value):
    value = os.fspath(value)
    path = Path(value)
    if (not path.is_absolute() or value != os.path.abspath(value) or str(path) != value
            or value.startswith('\\\\') or path == Path(path.anchor)
            or any(c in value for c in ('*', '?', '\0'))
            or any(part.endswith((' ', '.')) for part in path.parts[1:])):
        raise ValueError('personal_data_literal_local_path_required')
    return path


def _no_links(path):
    for current in [*reversed(path.parents), path]:
        if not current.exists():
            # lexists catches a dangling symlink before treating it as absent.
            if os.path.lexists(current):
                raise ValueError('personal_data_link_rejected')
            continue
        if getattr(current.lstat(), 'st_file_attributes', 0) & 0x400 or current.is_symlink():
            raise ValueError('personal_data_link_rejected')


@contextmanager
def _read_pin(path):
    _no_links(path)
    handle = _open_file(path, 0x80000000, 1, 0x00200000, 'personal_data_material_unavailable')
    try:
        yield handle
    finally:
        handle.Close()


def _open_file(path, access, sharing, flags, reason):
    import pywintypes
    import win32file
    try:
        return win32file.CreateFile(str(path), access, sharing, None, 3, flags, None)
    except pywintypes.error as error:
        raise ValueError(reason+':'+str(error.winerror)) from None


def _pinned_bytes(path):
    import win32file
    with _read_pin(path) as handle:
        chunks = []
        while True:
            _, chunk = win32file.ReadFile(handle, 1024 * 1024)
            if not chunk:
                return b''.join(chunks)
            chunks.append(chunk)


def _decode(data):
    def unique(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise ValueError('personal_data_duplicate_json_field')
            result[name] = value
        return result
    return json.loads(data, object_pairs_hook=unique)


def _read_json(path, expected):
    if not isinstance(expected, str) or not re.fullmatch('[a-f0-9]{64}', expected):
        raise ValueError('personal_data_sha256_required')
    data = _pinned_bytes(path)
    if _sha(data) != expected:
        raise ValueError('personal_data_material_changed')
    return _decode(data)


def _identity():
    import win32api
    import win32security
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), 8)
    try:
        sid = win32security.ConvertSidToStringSid(win32security.GetTokenInformation(token, 1)[0])
        level = win32security.GetTokenInformation(token, 25)
        integrity = int(win32security.ConvertSidToStringSid(level[0] if isinstance(level, tuple) else level).split('-')[-1])
        return dict(user_sid=sid, integrity=integrity,
            elevated=bool(win32security.GetTokenInformation(token, 20)),
            ui_access=bool(win32security.GetTokenInformation(token, 26)))
    finally:
        token.Close()


def _require_medium():
    identity = _identity()
    if identity['integrity'] != 8192 or identity['elevated'] or identity['ui_access']:
        raise ValueError('personal_data_medium_user_required')
    return identity['user_sid']


def _machine_binding():
    import winreg
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Cryptography', 0,
                       winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
        value, kind = winreg.QueryValueEx(key, 'MachineGuid')
    if kind != winreg.REG_SZ:
        raise ValueError('personal_data_machine_binding_unavailable')
    return _sha(('FlowerControl|' + uuid.UUID(value).hex).encode('utf-8'))


def _validate_authority(plan_path, plan_sha256):
    sid = _require_medium()
    plan_path = _path(plan_path)
    plan = _read_json(plan_path, plan_sha256)
    if plan.get('legacy') is not False:
        raise ValueError('personal_data_cleanup_legacy_requires_manual_review')
    root = _path(plan['installation_root'])
    program = _path(plan['program_root'])
    operation = plan.get('operation_id', '')
    installation = plan.get('installation_id', '')
    if (plan.get('schema') != 1 or plan.get('operation') != 'uninstall_review'
            or plan.get('user_sid') != sid or program != root/'Program'
            or not re.fullmatch('[a-f0-9]{32}', operation)
            or not re.fullmatch('[a-f0-9]{32}', installation)):
        raise ValueError('personal_data_uninstall_identity_rejected')
    require_protected_path(program)
    anchor_path = program/'recovery'/('installation-'+operation)/'resume-anchor.json'
    require_protected_path(anchor_path)
    anchor_bytes = _pinned_bytes(anchor_path)
    anchor = _decode(anchor_bytes)
    expected = dict(schema=1, kind='uninstall', state='completed', operation_id=operation,
        user_sid=sid, installation_id=installation, root=str(root), program_root=str(program),
        machine_binding_sha256=_machine_binding(), plan_path=str(plan_path), plan_sha256=plan_sha256)
    if any(type(anchor.get(key)) is not type(value) or anchor.get(key) != value for key, value in expected.items()):
        raise ValueError('personal_data_completed_protected_uninstall_required')
    roots = dict(data=root/'Data', cache=root/'Cache')
    optional = plan.get('optional_cleanup', [])
    if (not isinstance(optional, list) or len(optional) != 2
            or {row.get('path') for row in optional if isinstance(row, dict)} != {str(p) for p in roots.values()}
            or any(str(p) not in plan.get('preserve', []) for p in roots.values())):
        raise ValueError('personal_data_original_roots_rejected')
    return dict(uninstall_plan_path=str(plan_path), uninstall_plan_sha256=plan_sha256,
        anchor_path=str(anchor_path), anchor_sha256=_sha(anchor_bytes),
        anchor_mtime_ns=anchor_path.stat().st_mtime_ns, user_sid=sid,
        installation_id=installation, operation_id=operation, root=str(root),
        program_root=str(program), roots={name: str(path) for name, path in roots.items()})


def _lifecycle_guard(authority):
    program = Path(authority['program_root'])
    if any((program/name).exists() for name in ('active.json', 'installation-location.json')):
        raise ValueError('personal_data_installation_is_active')
    # A newly approved install owner precedes copying and root registration.
    recovery = program/'recovery'
    for directory in recovery.iterdir():
        if not directory.is_dir() or not re.fullmatch('installation-[a-f0-9]{32}', directory.name):
            continue
        for name in ('install-owner.json', 'resume-anchor.json'):
            path = directory/name
            if path.exists() and path != Path(authority['anchor_path']) and path.stat().st_mtime_ns > authority['anchor_mtime_ns']:
                raise ValueError('personal_data_new_install_operation_detected')
    for directory in (program/'versions', Path(authority['root'])/'Packages'):
        if directory.exists() and any(p.is_file() for p in directory.rglob('*')):
            raise ValueError('personal_data_program_files_still_present')


def _runtime_guard(authority):
    from types import SimpleNamespace
    from tools.prepare_uninstall import runtime_inventory
    if runtime_inventory(SimpleNamespace(program_root=Path(authority['program_root']), user_sid=authority['user_sid'])):
        raise ValueError('personal_data_owned_processes_still_running')


def _mutex_name(authority):
    return 'Local\\FlowerControl.PersonalDataCleanup.' + _sha((authority['user_sid']+'|'+authority['root'].lower()).encode())


def _require_idle_cleanup(authority):
    import win32event
    handle = win32event.CreateMutex(None, False, _mutex_name(authority))
    try:
        result = win32event.WaitForSingleObject(handle, 0)
        if result not in (0, 0x80):
            raise ValueError('personal_data_cleanup_still_running')
        win32event.ReleaseMutex(handle)
    finally:
        handle.Close()


@contextmanager
def _pin_directory(path):
    import win32file
    _no_links(path)
    handle = _open_file(path, 0x80, 3, 0x02200000, 'personal_data_directory_busy_or_unavailable')
    try:
        info = win32file.GetFileInformationByHandle(handle)
        if info[0] & 0x400 or not info[0] & 0x10:
            raise ValueError('personal_data_directory_changed')
        yield f'{info[4]:x}:{info[8]:08x}{info[9]:08x}'
    finally:
        handle.Close()


def _file_row(path):
    import win32file
    _no_links(path)
    # DELETE is a permission/occupancy probe, never a delete dispatch. Denying
    # WRITE/DELETE sharing detects profiles still open by another process.
    handle = _open_file(path, 0x80010000, 1, 0x00200000, 'personal_data_file_busy_or_unavailable')
    try:
        info = win32file.GetFileInformationByHandle(handle)
        if info[0] & (0x400 | 0x10) or info[7] != 1:
            raise ValueError('personal_data_file_identity_rejected')
        digest = hashlib.sha256()
        while True:
            _, chunk = win32file.ReadFile(handle, 1024*1024)
            if not chunk:
                break
            digest.update(chunk)
        return dict(path=str(path), bytes=(info[5] << 32) | info[6], sha256=digest.hexdigest(),
            file_id=f'{info[4]:x}:{info[8]:08x}{info[9]:08x}', modified=info[3].isoformat())
    finally:
        handle.Close()


def _inventory(roots):
    rows, directories = [], []
    with ExitStack() as pins:
        pending = list(reversed(roots))
        while pending:
            path = pending.pop()
            _no_links(path)
            if not path.exists():
                if path not in roots:
                    raise ValueError('personal_data_tree_changed')
                directories.append(dict(path=str(path), exists=False))
                continue
            identity = pins.enter_context(_pin_directory(path))
            directories.append(dict(path=str(path), exists=True, file_id=identity))
            for child in sorted(path.iterdir(), reverse=True):
                _no_links(child)
                if child.is_dir():
                    pending.append(child)
                elif child.is_file():
                    rows.append(_file_row(child))
                else:
                    raise ValueError('personal_data_special_entry_rejected')
    return dict(files=sorted(rows, key=lambda row: row['path']),
        directories=sorted(directories, key=lambda row: row['path']))


def _new_json(path, value):
    _no_links(path)
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write('\n')


def _outside_install(path, authority):
    path = _path(path)
    if path.is_relative_to(Path(authority['root'])):
        raise ValueError('personal_data_receipt_must_be_outside_installation')
    _no_links(path)
    return path


def prepare(plan_path, plan_sha256, output, *, kinds=('data', 'cache')):
    authority = _validate_authority(plan_path, plan_sha256)
    kinds = sorted(set(kinds))
    if not kinds or any(kind not in ('data', 'cache') for kind in kinds):
        raise ValueError('personal_data_only_data_and_cache_supported')
    _require_idle_cleanup(authority)
    _lifecycle_guard(authority)
    _runtime_guard(authority)
    roots = [Path(authority['roots'][kind]) for kind in kinds]
    inventory = _inventory(roots)
    if inventory != _inventory(roots):
        raise ValueError('personal_data_tree_changed_reinspect_required')
    _lifecycle_guard(authority)
    _require_idle_cleanup(authority)
    review = dict(schema=1, operation='uninstall_personal_data_review', review_id=uuid.uuid4().hex,
        authority=authority, kinds=kinds, selected_roots=[str(path) for path in roots],
        **inventory, file_count=len(inventory['files']), bytes=sum(row['bytes'] for row in inventory['files']),
        directories_preserved=True, permanent_delete=False, executed=False,
        fingerprint_sha256=_sha(json.dumps(inventory, sort_keys=True).encode()),
        created_utc=datetime.now(timezone.utc).isoformat())
    output = _outside_install(output, authority)
    _new_json(output, review)
    return dict(review_path=str(output), review_sha256=_sha(_pinned_bytes(output)),
        file_count=review['file_count'], bytes=review['bytes'], selected_roots=review['selected_roots'],
        directories_preserved=True, executed=False)


def _guarded_recycle_source():
    source = (Path(__file__).with_name('high_broker_install')/'RecycleOwnedFiles.cs').read_text(encoding='utf-8')
    additions = r'''
    public static bool DispatchAttempted;
    public static string GuardProgramRoot, GuardAnchorPath, GuardAnchorHash, GuardCancelPath, GuardReviewHash;
    static void RequirePersonalDataIdle()
    {
        bool cancellationPresent=false;
        if(!String.IsNullOrEmpty(GuardCancelPath))
            try {File.GetAttributes(GuardCancelPath);cancellationPresent=true;}
            catch(FileNotFoundException){} catch(DirectoryNotFoundException){}
        if(cancellationPresent) {
            for(string p=GuardCancelPath;p!=null;p=Path.GetDirectoryName(p))
                if((File.GetAttributes(p)&FileAttributes.ReparsePoint)!=0) throw new IOException("personal_data_link_rejected");
            byte[] cancellation=File.ReadAllBytes(GuardCancelPath);
            if(cancellation.Length!=64 || System.Text.Encoding.ASCII.GetString(cancellation)!=GuardReviewHash)
                throw new IOException("personal_data_cancel_binding_changed");
            throw new IOException("personal_data_cancel_requested");
        }
        if(File.Exists(Path.Combine(GuardProgramRoot,"active.json")) || File.Exists(Path.Combine(GuardProgramRoot,"installation-location.json")))
            throw new IOException("personal_data_installation_is_active");
        string anchorHash;
        using(var sha=SHA256.Create()) anchorHash=BitConverter.ToString(sha.ComputeHash(File.ReadAllBytes(GuardAnchorPath))).Replace("-","").ToLowerInvariant();
        if(anchorHash!=GuardAnchorHash) throw new IOException("personal_data_uninstall_authority_changed");
        DateTime completed=File.GetLastWriteTimeUtc(GuardAnchorPath);
        foreach(string directory in Directory.GetDirectories(Path.Combine(GuardProgramRoot,"recovery"),"installation-*"))
            foreach(string name in new[]{"install-owner.json","resume-anchor.json"}) {
                string p=Path.Combine(directory,name);
                if(p!=GuardAnchorPath && File.Exists(p) && File.GetLastWriteTimeUtc(p)>completed)
                    throw new IOException("personal_data_new_install_operation_detected");
            }
    }
'''
    # Extend the existing reviewed recycler only in this Medium worker. Exact
    # markers fail closed when that source contract changes; shared code stays
    # untouched. The late guard runs after its potentially slow file hash.
    changes = {
        'public static class FlowerUninstallRecycle\n{': 'public static class FlowerUninstallRecycle\n{'+additions,
        'public static void Recycle(string path, string expectedHash)\n    {':
            'public static void Recycle(string path, string expectedHash)\n    {\n        DispatchAttempted=false;',
        '        IShellItem item=null; IFileOperation operation=null;':
            '        RequirePersonalDataIdle();\n        IShellItem item=null; IFileOperation operation=null;',
        '            Check(operation.PerformOperations());':
            '            DispatchAttempted=true;\n            Check(operation.PerformOperations());',
    }
    for before, after in changes.items():
        if source.count(before) != 1:
            raise ValueError('personal_data_recycler_source_contract_changed')
        source = source.replace(before, after)
    return source


class _Recycler:
    def __init__(self, authority, cancel_file=None, review_sha256=''):
        self.authority = authority
        self.cancel_file, self.review_sha256 = cancel_file, review_sha256
        self.process = None

    def __enter__(self):
        source = _guarded_recycle_source()
        script = "$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)\nAdd-Type -TypeDefinition @'\n" + source + "\n'@\n"
        fields = dict(GuardProgramRoot=self.authority['program_root'], GuardAnchorPath=self.authority['anchor_path'],
            GuardAnchorHash=self.authority['anchor_sha256'], GuardCancelPath=str(self.cancel_file) if self.cancel_file else '',
            GuardReviewHash=self.review_sha256)
        for name, value in fields.items():
            script += "[FlowerUninstallRecycle]::"+name+"='"+value.replace("'", "''")+"'\n"
        script += "$mutex=[Threading.Mutex]::new($false,'"+_mutex_name(self.authority)+"');$held=$false\n"
        script += r"""
try {
 $held=$mutex.WaitOne(0);if(!$held){throw 'personal_data_cleanup_still_running'}
 [Console]::WriteLine('{"ready":true}')
 while($null -ne ($line=[Console]::ReadLine())) {
  try {
   $item=$line|ConvertFrom-Json
   [FlowerUninstallRecycle]::Recycle([string]$item.path,[string]$item.sha256)
   [Console]::WriteLine((@{ok=$true;path=$item.path}|ConvertTo-Json -Compress))
  } catch {
   [Console]::WriteLine((@{ok=$false;reason=$_.Exception.GetBaseException().Message;
    dispatched=[FlowerUninstallRecycle]::DispatchAttempted;hresult=$_.Exception.HResult}|ConvertTo-Json -Compress));break
  }
 }
} finally {if($held){$mutex.ReleaseMutex()};$mutex.Dispose()}
"""
        encoded = base64.b64encode(script.encode('utf-16-le')).decode('ascii')
        self.process = subprocess.Popen([str(system_powershell_path()), '-NoLogo', '-NoProfile', '-NonInteractive', '-STA',
            '-EncodedCommand', encoded], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding='utf-8', creationflags=subprocess.CREATE_NO_WINDOW)
        ready = self.process.stdout.readline()
        if not ready or _decode(ready).get('ready') is not True:
            self.__exit__(None, None, None)
            raise ValueError('personal_data_recycle_worker_unavailable')
        return self

    def recycle(self, row):
        self.process.stdin.write(json.dumps(dict(path=row['path'], sha256=row['sha256']), ensure_ascii=True)+'\n')
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        result = _decode(line) if line else {}
        if result.get('ok') is not True or result.get('path') != row['path']:
            if result.get('dispatched') is False:
                reason = result.get('reason', '')
                if reason == 'personal_data_cancel_requested':
                    raise _CleanupCancelled()
                raise _RecycleNotDispatched(reason if re.fullmatch('[a-z_]{1,100}', reason)
                    else 'personal_data_recycle_rejected_before_dispatch')
            raise ValueError('personal_data_recycle_outcome_unconfirmed')

    def __exit__(self, *_):
        if self.process is not None:
            try:
                self.process.stdin.close()
                self.process.wait(timeout=5)
            except (BrokenPipeError, subprocess.TimeoutExpired):
                pass  # Never kill an in-flight recycling operation or retry it.
            if self.process.poll() is not None:
                self.process.stdout.close()
                self.process.stderr.close()


class _CleanupCancelled(Exception):
    pass


class _RecycleNotDispatched(ValueError):
    pass


def apply(review_path, review_sha256, *, confirmed=False, receipt_path=None, cancel_path=None):
    if confirmed is not True:
        raise ValueError('personal_data_exact_review_confirmation_required')
    review_path = _path(review_path)
    review = _read_json(review_path, review_sha256)
    if review.get('schema') != 1 or review.get('operation') != 'uninstall_personal_data_review':
        raise ValueError('personal_data_review_rejected')
    original = review['authority']
    authority = _validate_authority(original['uninstall_plan_path'], original['uninstall_plan_sha256'])
    if authority != original:
        raise ValueError('personal_data_uninstall_authority_changed')
    kinds = review['kinds']
    if not kinds or kinds != sorted(set(kinds)) or any(kind not in authority['roots'] for kind in kinds):
        raise ValueError('personal_data_review_scope_rejected')
    roots = [Path(authority['roots'][kind]) for kind in kinds]
    if review['selected_roots'] != [str(path) for path in roots]:
        raise ValueError('personal_data_review_scope_rejected')
    _require_idle_cleanup(authority)
    _lifecycle_guard(authority)
    _runtime_guard(authority)
    expected = {name: review[name] for name in ('files', 'directories')}
    if (_inventory(roots) != expected or review['file_count'] != len(expected['files'])
            or review['bytes'] != sum(row['bytes'] for row in expected['files'])
            or review.get('fingerprint_sha256') != _sha(json.dumps(expected, sort_keys=True).encode())):
        raise ValueError('personal_data_tree_changed_reinspect_required')
    receipt_path = _outside_install(receipt_path or review_path.with_suffix('.result.json'), authority)
    journal_path = _outside_install(receipt_path.with_name(receipt_path.name+'.events.jsonl'), authority)
    cancel_file = _outside_install(cancel_path, authority) if cancel_path is not None else None
    if cancel_file in (review_path, receipt_path, journal_path, Path(authority['uninstall_plan_path'])):
        raise ValueError('personal_data_cancel_path_conflicts_with_material')
    if receipt_path.exists() or journal_path.exists():
        raise ValueError('personal_data_previous_receipt_requires_new_review')
    result = dict(schema=1, operation='uninstall_personal_data', review_sha256=review_sha256,
        review_id=review['review_id'], state='prepared', complete=False, system_changed=False,
        selected_roots=review['selected_roots'], recycled=[], outcome_unknown=[], directories_preserved=True,
        program_metadata_preserved=True, permanent_delete=False, receipt_path=str(receipt_path),
        journal_path=str(journal_path), journal_events=0, journal_tip_sha256='0'*64,
        cancel_path=str(cancel_file) if cancel_file is not None else None, cancelled=False)

    def snapshot(full=False):
        value = dict(result, recycled_count=len(result['recycled']), outcome_unknown_count=len(result['outcome_unknown']))
        if not full:
            value.pop('recycled')
            value.pop('outcome_unknown')
        return value

    _new_json(receipt_path, snapshot())  # A prior receipt never authorizes a retry.

    def save(full=False):
        _no_links(receipt_path)
        temporary = receipt_path.with_name(receipt_path.name+'.'+uuid.uuid4().hex+'.tmp')
        _new_json(temporary, snapshot(full))
        os.replace(temporary, receipt_path)

    try:
        with ExitStack() as pins:
            _no_links(journal_path)
            journal = pins.enter_context(journal_path.open('x', encoding='utf-8', newline='\n'))

            def event(kind, **fields):
                value = dict(schema=1, sequence=result['journal_events']+1,
                    previous_sha256=result['journal_tip_sha256'], kind=kind, **fields)
                tip = _sha(json.dumps(value, sort_keys=True, separators=(',', ':')).encode('utf-8'))
                journal.write(json.dumps(dict(value, sha256=tip), ensure_ascii=True, separators=(',', ':'))+'\n')
                journal.flush()
                os.fsync(journal.fileno())
                result.update(journal_events=value['sequence'], journal_tip_sha256=tip)

            def require_continue():
                if cancel_file is not None and os.path.lexists(cancel_file):
                    _no_links(cancel_file)
                    if cancel_file.stat().st_size != 64 or _pinned_bytes(cancel_file) != review_sha256.encode('ascii'):
                        raise ValueError('personal_data_cancel_binding_changed')
                    event('cancelled', before_path=result.get('pending_path'))
                    raise _CleanupCancelled()

            require_continue()
            for directory in expected['directories']:
                if directory['exists'] and pins.enter_context(_pin_directory(Path(directory['path']))) != directory['file_id']:
                    raise ValueError('personal_data_directory_changed')
            if _inventory(roots) != expected:
                raise ValueError('personal_data_tree_changed_reinspect_required')
            with _Recycler(authority, cancel_file, review_sha256) as recycler:
                result['worker_pid'] = recycler.process.pid
                for offset in range(0, len(expected['files']), 256):
                    require_continue()
                    batch = expected['files'][offset:offset+256]
                    # This durable bounded intent names every possible dispatch
                    # before effects. A crash never grants replay permission.
                    event('batch_intent', paths=[row['path'] for row in batch])
                    result['pending_batch_sequence'] = result['journal_events']
                    save()
                    for row in batch:
                        require_continue()
                        _lifecycle_guard(authority)
                        if _file_row(Path(row['path'])) != row:
                            raise ValueError('personal_data_file_changed_reinspect_required')
                        result.update(state='recycling', pending_path=row['path'])
                        save()
                        require_continue()
                        _lifecycle_guard(authority)
                        try:
                            recycler.recycle(row)
                        except _CleanupCancelled:
                            event('cancelled', before_path=row['path'])
                            raise
                        except _RecycleNotDispatched as error:
                            result['rejected_before_dispatch'] = row['path']
                            event('rejected_before_dispatch', path=row['path'], reason=str(error))
                            raise
                        except Exception:
                            result['outcome_unknown'].append(row['path'])
                            event('outcome_unknown', path=row['path'])
                            raise
                        result['recycled'].append(row['path'])
                        result['system_changed'] = True
                        result.pop('pending_path', None)
                        event('recycled', path=row['path'])
                        save()
                    result.pop('pending_batch_sequence', None)
                    save()
            if _inventory(roots)['files']:
                raise ValueError('personal_data_new_files_detected_reinspect_required')
        result.update(state='recycled_personal_files_directories_preserved', complete=True)
    except _CleanupCancelled:
        result.update(state='cancelled_reinspect_required', cancelled=True,
            system_changed=bool(result['recycled'] or result['outcome_unknown']))
        result.pop('pending_path', None)
    except Exception as error:
        result.update(state='incomplete_reinspect_required', reason=str(error),
            system_changed=bool(result['recycled'] or result['outcome_unknown']))
    save(full=True)
    return snapshot(full=True)


def main():
    from tools.offline_install import initialize_bundled_python
    initialize_bundled_python()
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    inspect = commands.add_parser('inspect')
    inspect.add_argument('--uninstall-plan', type=Path, required=True)
    inspect.add_argument('--uninstall-sha256', required=True)
    inspect.add_argument('--output', type=Path, required=True)
    inspect.add_argument('--kind', choices=('data', 'cache'), action='append')
    execute = commands.add_parser('apply')
    execute.add_argument('--review', type=Path, required=True)
    execute.add_argument('--review-sha256', required=True)
    execute.add_argument('--receipt', type=Path)
    execute.add_argument('--cancel-file', type=Path)
    execute.add_argument('--confirmed', action='store_true')
    args = parser.parse_args()
    if args.action == 'inspect':
        result = prepare(args.uninstall_plan, args.uninstall_sha256, args.output, kinds=args.kind or ('data', 'cache'))
    else:
        result = apply(args.review, args.review_sha256, confirmed=args.confirmed, receipt_path=args.receipt,
            cancel_path=args.cancel_file)
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result.get('complete', True) else 2


if __name__ == '__main__':
    raise SystemExit(main())
