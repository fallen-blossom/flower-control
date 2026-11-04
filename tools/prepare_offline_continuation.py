"""Freeze an exact stopped continuation from protected failed-install receipts."""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tools import prepare_offline_migration as migration
from tools.prepare_frozen_plugin import validate_delivery
from tools.prepare_high_broker_install import native_source_hashes, render_installer_type
from tools.prepare_work_authority_update import digest
from tools.runtime_snapshot import reject_links


def require_receipts(plan, result, progress):
    client_quiescence = (result.get('reason') == 'offline_independent_executor_present' and
                         result.get('recovery') == 'original_metadata_restored_stopped_start_submitted')
    if (result.get('schema') != 1 or result.get('operation') != plan['OperationId'] or
        result.get('version') != plan['Version'] or result.get('state') != 'failed' or
        result.get('stage') != 'offline_checks' or result.get('task_changed') is not False or
        result.get('active_changed') is not False or result.get('resumed') is not False or
        not (client_quiescence or 'user_policy_unprotected' in result.get('reason', ''))):
        raise ValueError('exact_failed_before_publication_required')
    stages = [row.get('stage') for row in progress]
    expected = ['original_live_handle_bound', 'payload_verified_original_still_bound',
                'offline_stop_latched_no_resume', 'original_exit_zero_singleton_held',
                'offline_migration_failed_no_resume']
    if client_quiescence:
        expected.insert(4, 'waiting_for_executor_quiescence')
    if stages != expected:
        raise ValueError('exact_original_exit_receipt_required')
    bound, payload, closed, exited = [row['detail'] for row in progress[:4]]
    failure = progress[-1]['detail']
    if client_quiescence:
        waiting = progress[4]['detail']
        actors = waiting.get('actors')
        count = waiting.get('count')
        if (waiting.get('input_dispatched') is not False or type(count) is not int or count < 1 or
            not isinstance(actors, list) or not 1 <= len(actors) <= min(count, 16) or
            failure.get('reason') != result['reason'] or failure.get('recovery') != result['recovery']):
            raise ValueError('exact_client_quiescence_failure_required')
        versions = str(Path(plan['BrokerRoot']) / 'versions').replace('\\', '/').lower() + '/'
        for actor in actors:
            if (type(actor.get('pid')) is not int or actor['pid'] < 1 or
                not isinstance(actor.get('image'), str) or
                not actor['image'].replace('\\', '/').lower().startswith(versions)):
                raise ValueError('exact_client_quiescence_failure_required')
    if (bound != {'created': plan['OldCreated'], 'pid': plan['OldPid'], 'version': plan['OldVersion']} or
        payload.get('version') != plan['Version'] or type(payload.get('files')) is not int or payload['files'] < 1 or
        exited != {'release_scope': 'original_broker_handlers', 'pid': plan['OldPid']} or
        failure.get('active_changed') is not False or failure.get('task_changed') is not False or
        failure.get('stage') != 'offline_checks' or closed.get('version') != plan['Version'] or
        closed.get('nativeInputExecuted') is not False or closed.get('resumed') is not False):
        raise ValueError('original_drain_or_stop_receipt_changed')
    for name in ('Stop', 'Computer'):
        state = closed[name]
        if (set(state) != {'Schema', 'UserSid', 'Session', 'Stopped', 'Epoch'} or state['Schema'] != 1 or
            state['UserSid'] != plan['UserSid'] or state['Session'] != plan['SessionId'] or
            type(state['Stopped']) is not bool or type(state['Epoch']) is not int or state['Epoch'] < 0):
            raise ValueError('original_stop_receipt_invalid')
    shared = closed['Shared']
    if (closed['Stop']['Stopped'] is not True or shared.get('Stopped') is not True or
        set(shared) != {'Stopped','Epoch','ResumeAllEpoch'} or
        type(shared['Epoch']) is not int or type(shared['ResumeAllEpoch']) is not int or
        not 0 <= shared['ResumeAllEpoch'] <= shared['Epoch']):
        raise ValueError('original_stop_receipt_invalid')
    return closed


def offline_functions():
    path = str(migration.TEMPLATES / 'OfflineMigration.ps1.template').replace("'", "''")
    names = ('RequirePreviousTask', 'RequireReleasedJournal', 'RequireNoActors',
             'RoleFileInventory', 'RequireRoleAnchor', 'EnsureRecoveryProtection')
    result = migration.ps_capture(r"""$tokens=$null;$errors=$null
$text=[IO.File]::ReadAllText('__PATH__',[Text.Encoding]::UTF8)
$text=[regex]::Replace($text,'@@[A-Z_]+@@','')
$ast=[Management.Automation.Language.Parser]::ParseInput($text,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'offline_function_template_parse_failed'}
$out=@{}
foreach($name in @(__NAMES__)) {
 $f=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true))
 if($f.Count -ne 1){throw 'offline_function_missing'}
 $out[$name]=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($f[0].Extent.Text))
}
$out|ConvertTo-Json -Compress
""".replace('__PATH__', path).replace('__NAMES__', ','.join("'" + name + "'" for name in names)))
    return '\n'.join(base64.b64decode(result[name]).decode('utf8') for name in names)


def journal_digest(path: Path, allow_missing: bool):
    """Only exact FILE_NOT_FOUND under an existing parent is absence."""
    for candidate in (path.with_name(path.name + '.new'), path):
        reject_links(candidate)
        try:
            candidate.stat()
        except FileNotFoundError as error:
            if getattr(error, 'winerror', None) not in (None, 2) or not candidate.parent.is_dir():
                raise ValueError('continuation_journal_metadata_unreadable') from error
            if candidate == path:
                if not allow_missing:
                    raise ValueError('continuation_existing_journal_required') from error
                return None
        else:
            if candidate != path:
                raise ValueError('continuation_partial_journal_present')
            if not candidate.is_file():
                raise ValueError('continuation_journal_rejected')
            return digest(candidate)


def existing_shared_snapshot(sid, *, allow_absent=False):
    # Open existing objects only. Never initialize, Stop or resume the gate.
    source=(migration.TEMPLATES/'PinnedDelivery.cs').read_text(encoding='utf8')
    script="$ErrorActionPreference='Stop'\nAdd-Type -TypeDefinition @'\n"+source+"\n'@\n"
    absence="if(![FlowerPinnedDelivery]::ExistingWriteGatePresent('"+sid+"')){@{Absent=$true}|ConvertTo-Json -Compress;return};" if allow_absent else ''
    script+="try{"+absence+"[FlowerPinnedDelivery]::HoldWriteGate('"+sid+"');$s=[FlowerPinnedDelivery]::SnapshotWriteGate();@{Stopped=($s[0] -eq 1);Epoch=$s[1];ResumeAllEpoch=$s[2]}|ConvertTo-Json -Compress}finally{[FlowerPinnedDelivery]::Close()}"
    with tempfile.TemporaryDirectory(prefix='flower-existing-shared-read-') as folder:
        path=Path(folder)/'Read.ps1';path.write_text(script,encoding='utf-8-sig')
        result=subprocess.run([str(migration.system_powershell_path()),'-NoLogo','-NoProfile','-NonInteractive','-File',str(path)],capture_output=True,timeout=20,creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode:
        raise ValueError('existing_shared_snapshot_rejected:'+result.stderr.decode('utf8',errors='replace'))
    return json.loads(result.stdout.decode('utf-8-sig'))


def require_selected_task(package: Path, previous: dict, target: Path, *, new_candidate: bool):
    """New payloads require Normal; old continuations keep the original pinned XML."""
    historical = None
    if not new_candidate:
        historical = previous.get('TaskXmlSha256')
        if type(historical) is not str:
            raise ValueError('offline_fixed_task_required')
    migration.require_fixed_task((package / 'task.xml').read_bytes(), previous['UserSid'], target,
        historical_task_sha256=historical)


def prepare(previous_plan: Path, output: Path, failed_continuation: Path | None = None, *, candidate_package: Path | None = None):
    old = json.loads(previous_plan.read_bytes())
    from flower_control.install_location import program_root
    production = program_root()
    reject_links(production)
    if Path(old['BrokerRoot']) != production or not output.absolute().is_relative_to(Path(os.environ['TEMP']).resolve()) or output.exists():
        raise ValueError('fixed_production_and_new_temp_output_required')
    reject_links(output)
    prefix = production / 'recovery' / ('installation-' + old['OperationId']) / 'update'
    previous_result = Path(str(prefix) + '-result.json'); previous_progress = Path(str(prefix) + '-progress.jsonl')
    result = json.loads(previous_result.read_bytes())
    rows = [json.loads(row) for row in previous_progress.read_text(encoding='utf8').splitlines()]
    closed = require_receipts(old, result, rows)
    client_quiescence = result.get('reason') == 'offline_independent_executor_present'
    current_shared=existing_shared_snapshot(old['UserSid'], allow_absent=client_quiescence)
    create_fresh_shared = current_shared == {'Absent': True} and client_quiescence
    if not create_fresh_shared and (current_shared.get('Stopped') is not True or type(current_shared.get('Epoch')) is not int or
        current_shared['Epoch'] < closed['Shared']['Epoch'] or
        current_shared.get('ResumeAllEpoch') != closed['Shared']['ResumeAllEpoch']):
        raise ValueError('current_stopped_shared_snapshot_required')
    selected_package=Path(old['Package']) if candidate_package is None else candidate_package
    active, policy, staged = validate_delivery(selected_package)
    if (candidate_package is None and active['version'] != old['Version'] or
        digest(production / 'active.json') != old['OldActiveSha256']):
        raise ValueError('continuation_versions_changed')
    # The old broker's protected exit/Stop receipt is historical evidence. A
    # later candidate must independently verify its full delivery and preserve
    # all installed host/data boundaries; it never inherits payload verification.
    old_policy_path=production/'versions'/old['OldVersion']/'broker.json'
    if digest(old_policy_path)!=old['OldPolicySha256']:raise ValueError('continuation_old_policy_changed')
    old_policy=json.loads(old_policy_path.read_bytes())
    for field in ('UserSid','Mode','DataRoot','NativeHosts','CodexPackageFamilies','CodexImageRoots','AdditionalAgents'):
        if policy.get(field)!=old_policy.get(field):raise ValueError('continuation_host_or_data_boundary_changed')
    proof = json.loads((staged / 'native-build-evidence.json').read_bytes())
    if proof['source_hashes'] != native_source_hashes(ROOT):
        raise ValueError('continuation_native_source_changed')
    require_selected_task(selected_package, old, production / 'versions' / active['version'],
        new_candidate=candidate_package is not None)
    operation = uuid.uuid4().hex
    plan = {k:v for k,v in old.items() if k not in ('Script','ScriptSha256','LauncherSha256','Installed','Elevated')}
    plan.update(Mode='human_stopped_continuation', OperationId=operation, PreviousOperation=old['OperationId'],
        Package=str(selected_package),Version=active['version'],OriginalExitPayloadVersion=old['Version'],
        CopyNewTarget=candidate_package is not None,
        ActiveSha256=digest(selected_package/'active.json'),CommonSha256=digest(selected_package/'InstallCommon.ps1'),
        TaskXmlSha256=digest(selected_package/'task.xml'),
        PreviousResult=str(previous_result), PreviousResultSha256=digest(previous_result),
        PreviousProgress=str(previous_progress), PreviousProgressSha256=digest(previous_progress),
        ProgressPrefix=str(production / 'recovery' / ('installation-' + operation) / 'update'),
        ProtectedEpoch=closed['Stop']['Epoch'], ComputerStopped=closed['Computer']['Stopped'],
        ComputerEpoch=closed['Computer']['Epoch'], SharedEpoch=1 if create_fresh_shared else current_shared['Epoch'],
        ResumeAllEpoch=0 if create_fresh_shared else current_shared['ResumeAllEpoch'],
        SharedGateMode='create_fresh_stopped' if create_fresh_shared else 'retain_existing_stopped',
        OriginalShared=closed['Shared'], CurrentShared=current_shared,
        JournalSha256=journal_digest(Path(old['RecoveryJournal']), client_quiescence),
        ClientQuiescenceContinuation=client_quiescence,
        OriginalExitEvidenceOperation=old['OperationId'])
    for name, folder in (('Stop','stop'),('Computer','computer-pause')):
        path = production / 'recovery' / folder / (old['UserSid'] + '.' + str(old['SessionId']) + '.json')
        if json.loads(path.read_bytes()) != closed[name]:
            raise ValueError('continuation_stop_record_changed')
        plan[name+'Path'] = str(path); plan[name+'Sha256'] = digest(path)
    if failed_continuation is not None:
        previous = json.loads(failed_continuation.read_bytes())
        if (previous.get('PreviousOperation') != old['OperationId'] or previous.get('Version') != old['Version'] or
            Path(previous['BrokerRoot']) != production or candidate_package is not None):
            raise ValueError('fixed_failed_continuation_required')
        prior_prefix=production/'recovery'/('installation-'+previous['OperationId'])/'update'
        failed_result=Path(str(prior_prefix)+'-result.json'); failed_progress=Path(str(prior_prefix)+'-progress.jsonl')
        failed=json.loads(failed_result.read_bytes())
        if (failed.get('state')!='failed' or failed.get('operation')!=previous['OperationId'] or
            failed.get('stage')!='repairing_recovery_inheritance' or failed.get('resumed') is not False or
            failed.get('task_changed') is not False or failed.get('active_changed') is not False or
            failed.get('start_attempted') is not False or 'recovery_high_label_missing' not in failed.get('reason','')):
            raise ValueError('fixed_prepublication_label_failure_required')
        plan.update(FailedContinuationOperation=previous['OperationId'], FailedContinuationResult=str(failed_result),
            FailedContinuationResultSha256=digest(failed_result),FailedContinuationProgress=str(failed_progress),
            FailedContinuationProgressSha256=digest(failed_progress))
    template = migration.TEMPLATES / 'OfflineContinuation.ps1.template'
    script = template.read_text(encoding='utf8')
    values = {'PLAN_JSON':json.dumps(plan,ensure_ascii=False,indent=2), 'UPDATE_FUNCTIONS':migration.update_functions(), 'OFFLINE_FUNCTIONS':offline_functions()}
    for key, filename in (('PINNED_DELIVERY_TYPE','PinnedDelivery.cs'),('OFFLINE_GUARD_TYPE','OfflineMigrationGuard.cs'),('RECOVERY_PROTECTION_TYPE','RecoveryProtection.cs')):
        values[key] = render_installer_type(filename, production)
    for key,value in values.items(): script=script.replace('@@'+key+'@@',value)
    if '@@' in script: raise ValueError('continuation_template_unresolved')
    output.mkdir(parents=True)
    target=output/'Continue.ps1'; target.write_text(script,encoding='utf-8-sig')
    path=str(target).replace("'","''"); sha=digest(target)
    bootstrap=("$ErrorActionPreference='Stop';$f=[IO.File]::Open('"+path+"',[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);try{"+
        "$h=[Security.Cryptography.SHA256]::Create();try{$v=[BitConverter]::ToString($h.ComputeHash($f)).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()};"+
        "if($v -cne '"+sha+"'){throw 'continuation_script_changed'};$f.Position=0;$r=[IO.StreamReader]::new($f,[Text.Encoding]::UTF8,$true,4096,$true);try{$s=$r.ReadToEnd()}finally{$r.Dispose()};& ([scriptblock]::Create($s))}finally{$f.Dispose()}")
    arguments=['-NoLogo','-NoProfile','-EncodedCommand',base64.b64encode(bootstrap.encode('utf-16-le')).decode('ascii')]
    record={**plan,'Script':str(target),'ScriptSha256':sha,'Arguments':arguments,'Installed':False,'Elevated':False}
    (output/'plan.json').write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    return record


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--previous-plan',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--failed-continuation',type=Path)
    args=p.parse_args();result=prepare(args.previous_plan,args.output,args.failed_continuation)
    print(json.dumps({k:result[k] for k in ('OperationId','Version','Script','ScriptSha256','Installed','Elevated')}))
