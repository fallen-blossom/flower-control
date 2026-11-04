"""Actual PS5.1 installer class, isolated Medium metadata repair; no elevation."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
import uuid
from tools import prepare_offline_continuation as continuation
from tests.test_offline_migration import run_ps, TEMPLATES


class ContinuationTests(unittest.TestCase):
    def test_real_handoff_block_finishes_payload_before_requesting_host_exit(self):
        template=(TEMPLATES/'OfflineContinuation.ps1.template').read_text(encoding='utf-8')
        body=template.split("    $stage='verifying_existing_payload'",1)[1].split("    $stage='repairing_recovery_inheritance'",1)[0]
        script=r'''$ErrorActionPreference='Stop'
Add-Type -TypeDefinition @'
public static class FlowerPinnedDelivery { public static string ReadText(string path,string hash){return "fixture-task-xml";} }
'@
$plan=[pscustomobject]@{TaskXmlSha256='fixture';ClientQuiescenceContinuation=$true;OriginalExitEvidenceOperation='original';PreviousOperation='original'}
$version='new';$package='fixture';$newDir=$env:TEMP
$script:events=[Collections.Generic.List[string]]::new();$script:failPayload=$false
function Write-Host {param($Object,$ForegroundColor)}
function Write-Progress {param($Activity,$Status,$PercentComplete,[switch]$Completed)}
function Log {param($Name,$Detail);$script:events.Add($Name)}
function Assert-FlowerVersion {param($Path);$script:events.Add('version')}
function Assert-FlowerSource {param($Path);$script:events.Add('source');if($script:failPayload){throw 'fixture_bad_source'}}
function Assert-FlowerAcl {param($Path);$script:events.Add('acl')}
function Get-ChildItem {param($LiteralPath,[switch]$Recurse,[switch]$Force);[pscustomobject]@{FullName='fixture-file'}}
function Get-FlowerTaskSecurityDescriptor {'fixture-sddl'}
function RequirePreviousTask {$script:events.Add('task')}
function RequireFixedStop {$script:events.Add('stop')}
function WaitForHostConnectionsToClose {$script:events.Add('host_close')}
function RequireNoActors {$script:events.Add('strict_quiescence')}
function RequireUpdateActors {RequireNoActors}
function CopyNewCandidateIfMissing {$false}
$handoff={
__BODY__
}
& $handoff
$observed=@($script:events.ToArray())
$close=[Array]::IndexOf($observed,'host_close')
foreach($name in @('version','source','acl','payload_verified_before_host_exit')) {
 if([Array]::IndexOf($observed,$name) -lt 0 -or [Array]::LastIndexOf($observed,$name) -ge $close){throw 'payload_not_before_host_close'}
}
if([Array]::IndexOf($observed,'stopped_continuation_bound') -le $close -or [Array]::IndexOf($observed,'strict_quiescence') -le $close){throw 'offline_checks_not_after_close'}
$script:events.Clear();$script:failPayload=$true;$rejected=$false
try{& $handoff}catch{if($_.Exception.Message -cne 'fixture_bad_source'){throw};$rejected=$true}
if(!$rejected -or $script:events.Contains('host_close')){throw 'invalid_payload_requested_host_exit'}
$script:events.Clear();$script:failPayload=$false
function Add-Type {param($AssemblyName);throw 'fixture_optional_forms_unavailable'}
function Write-Warning {param($Message)}
& $handoff
if(!$script:events.Contains('host_close') -or !$script:events.Contains('strict_quiescence')){throw 'optional_ui_became_installation_gate'}
@{valid_order=$observed;invalid_payload_rejected_before_exit=$rejected;optional_ui_failure_did_not_block=$true}|ConvertTo-Json -Depth 3 -Compress
'''.replace('__BODY__',body)
        result=run_ps(script)
        self.assertTrue(result['invalid_payload_rejected_before_exit'])
        self.assertIn('strict_quiescence',result['valid_order'])
        self.assertTrue(result['optional_ui_failure_did_not_block'])

    def test_completion_dialog_distinguishes_paused_install_from_failure_without_opening_ui(self):
        template=(TEMPLATES/'OfflineContinuation.ps1.template').read_text(encoding='utf-8')
        function='function ShowContinuationResult'+template.split('function ShowContinuationResult',1)[1].split('\ntry {',1)[0]
        # Keep the actual dialog function; replace only its Windows UI receiver.
        fixture=r'''$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
Add-Type -TypeDefinition @'
namespace System.Windows.Forms {
 public enum MessageBoxIcon { Information,Error }
 public enum MessageBoxButtons { OK }
 public static class MessageBox {
  public static string Message,Title;public static MessageBoxIcon Icon;
  public static int Show(string message,string title,MessageBoxButtons buttons,MessageBoxIcon icon) {
   Message=message;Title=title;Icon=icon;return 0;
  }
 }
}
'@
__FUNCTION__
ShowContinuationResult $true
$success=@{title=[System.Windows.Forms.MessageBox]::Title;message=[System.Windows.Forms.MessageBox]::Message;icon=[string][System.Windows.Forms.MessageBox]::Icon}
ShowContinuationResult $false
$failure=@{title=[System.Windows.Forms.MessageBox]::Title;message=[System.Windows.Forms.MessageBox]::Message;icon=[string][System.Windows.Forms.MessageBox]::Icon}
@{success=$success;failure=$failure}|ConvertTo-Json -Depth 3 -Compress
'''.replace('__FUNCTION__',function)
        result=run_ps(fixture)
        self.assertIn('安装换版完成',result['success']['title'])
        self.assertIn('保持停止状态',result['success']['message'])
        self.assertIn('不代表功能测试已通过',result['success']['message'])
        self.assertEqual(result['success']['icon'],'Information')
        self.assertIn('安装未完成',result['failure']['title'])
        self.assertIn('不要重跑',result['failure']['message'])
        self.assertEqual(result['failure']['icon'],'Error')

    def test_fresh_stopped_namespace_uses_real_mutex_mapping_and_preserves_existing_generation(self):
        prefix='Local\\FlowerControl.WriteGate.test.'+uuid.uuid4().hex+'.'
        source=(TEMPLATES/'PinnedDelivery.cs').read_text(encoding='utf-8')
        source=source.replace('Local\\\\FlowerControl.WriteGate.v1.',prefix.replace('\\','\\\\'))
        script="$ErrorActionPreference='Stop'\nAdd-Type -TypeDefinition @'\n"+source+"\n'@\n"
        script+="$prefix='"+prefix+"'\n"+r'''
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$name=$prefix+$sid
if([FlowerPinnedDelivery]::ExistingWriteGatePresent($sid)){throw 'fixture_not_absent'}
$fresh=[FlowerPinnedDelivery]::CreateFreshStoppedWriteGate($sid)
if($fresh[0] -ne 1 -or $fresh[1] -ne 1 -or $fresh[2] -ne 0){throw 'fresh_not_stopped'}
$overwriteRejected=$false
try{[FlowerPinnedDelivery]::CreateFreshStoppedWriteGate($sid)|Out-Null}catch{$overwriteRejected=$true}
$unchanged=[FlowerPinnedDelivery]::SnapshotWriteGate()
if($unchanged[0] -ne 1 -or $unchanged[1] -ne 1 -or $unchanged[2] -ne 0){throw 'fresh_overwritten'}
[FlowerPinnedDelivery]::Close()
if([FlowerPinnedDelivery]::ExistingWriteGatePresent($sid)){throw 'fixture_handles_leaked'}
$mutex=[Threading.Mutex]::new($false,$name+'.lock')
try {
 $partialRejected=$false
 try{[FlowerPinnedDelivery]::CreateFreshStoppedWriteGate($sid)|Out-Null}catch{$partialRejected=$true}
 if(!$partialRejected){throw 'partial_mutex_accepted'}
 $map=[IO.MemoryMappedFiles.MemoryMappedFile]::CreateNew($name,32)
 try {
  $view=$map.CreateViewAccessor()
  try {
   $view.Write(0,[int]0x46435731);$view.Write(4,[int]1)
   $view.Write(8,[long]7);$view.Write(16,[long]2);$view.Write(24,[long]0)
   $existingRejected=$false
   try{[FlowerPinnedDelivery]::CreateFreshStoppedWriteGate($sid)|Out-Null}catch{$existingRejected=$true}
   [FlowerPinnedDelivery]::HoldWriteGate($sid)
   try{$existing=[FlowerPinnedDelivery]::SnapshotWriteGate()}finally{[FlowerPinnedDelivery]::Close()}
   if($existing[0] -ne 1 -or $existing[1] -ne 7 -or $existing[2] -ne 2){throw 'existing_generation_changed'}
  } finally {$view.Dispose()}
 } finally {$map.Dispose()}
} finally {$mutex.Dispose()}
$map=[IO.MemoryMappedFiles.MemoryMappedFile]::CreateNew($name,32)
try {
 $partialMapRejected=$false
 try{[FlowerPinnedDelivery]::CreateFreshStoppedWriteGate($sid)|Out-Null}catch{$partialMapRejected=$true}
 if(!$partialMapRejected){throw 'partial_map_accepted'}
} finally {$map.Dispose()}
@{fresh=@($fresh);overwriteRejected=$overwriteRejected;partialRejected=$partialRejected;partialMapRejected=$partialMapRejected;existingRejected=$existingRejected;existing=@($existing);real_windows_objects=$true}|ConvertTo-Json -Depth 4 -Compress
'''
        result=run_ps(script)
        self.assertEqual(result['fresh'],[1,1,0])
        self.assertEqual(result['existing'],[1,7,2])
        for key in ('overwriteRejected','partialRejected','partialMapRejected','existingRejected','real_windows_objects'):
            self.assertTrue(result[key])

    def test_client_quiescence_receipt_and_drift(self):
        plan = dict(OperationId='fixture-op', Version='new', OldVersion='old',
                    BrokerRoot='C:/Program Files/FlowerControl/HighHelper',
                    OldCreated='123456789012345678', OldPid=42, UserSid='fixture-user', SessionId=1)
        stop = dict(Schema=1, UserSid='fixture-user', Session=1, Stopped=True, Epoch=7)
        closed = dict(version='new', Stop=stop, Computer={**stop, 'Stopped':False},
                      Shared=dict(Stopped=True,Epoch=4,ResumeAllEpoch=3),
                      nativeInputExecuted=False,resumed=False,JournalSha256=None)
        result = dict(schema=1, operation='fixture-op', version='new',state='failed',stage='offline_checks',
                      reason='offline_independent_executor_present',
                      recovery='original_metadata_restored_stopped_start_submitted',
                      task_changed=False,active_changed=False,resumed=False)
        waiting = dict(input_dispatched=False,count=2,actors=[dict(pid=43,
            image=plan['BrokerRoot']+'/versions/old/flower-python.exe')])
        rows = [dict(stage=stage,detail=detail) for stage,detail in [
            ('original_live_handle_bound',dict(created=plan['OldCreated'],pid=42,version='old')),
            ('payload_verified_original_still_bound',dict(version='new',files=5394)),
            ('offline_stop_latched_no_resume',closed),
            ('original_exit_zero_singleton_held',dict(release_scope='original_broker_handlers',pid=42)),
            ('waiting_for_executor_quiescence',waiting),
            ('offline_migration_failed_no_resume',dict(result))]]
        self.assertEqual(continuation.require_receipts(plan,result,rows),closed)
        for key,value in [('reason','other'),('recovery','other'),('resumed',True),
                          ('task_changed',True),('active_changed',True),('stage','publishing')]:
            with self.subTest(result=key),self.assertRaises(ValueError):
                continuation.require_receipts(plan,{**result,key:value},rows)
        changes = [(4,'input_dispatched',True),(4,'count',0),(4,'actors',[]),
                   (5,'reason','other'),(5,'recovery','other'),(3,'pid',43)]
        for index,key,value in changes:
            changed=copy.deepcopy(rows);changed[index]['detail'][key]=value
            with self.subTest(stage=index,field=key),self.assertRaises(ValueError):
                continuation.require_receipts(plan,result,changed)
        for changed in (rows[:4]+rows[5:],rows[:5]+[rows[4]]+rows[5:],rows[:4]+[rows[5],rows[4]]):
            with self.assertRaises(ValueError): continuation.require_receipts(plan,result,changed)
        changed=copy.deepcopy(rows);changed[4]['detail']['actors'][0]['image']='C:/other/flower-python.exe'
        with self.assertRaises(ValueError): continuation.require_receipts(plan,result,changed)

    def test_missing_journal_is_explicit_and_partial_write_rejected(self):
        with tempfile.TemporaryDirectory(prefix='flower-journal-absence-') as directory:
            path=Path(directory)/'journal.json'
            self.assertIsNone(continuation.journal_digest(path,True))
            with self.assertRaises(ValueError): continuation.journal_digest(path,False)
            partial=path.with_name(path.name+'.new');partial.write_bytes(b'partial')
            with self.assertRaises(ValueError): continuation.journal_digest(path,True)
            path.write_bytes(b'original')
            with self.assertRaises(ValueError): continuation.journal_digest(path,True)
            partial.unlink()
            self.assertEqual(continuation.journal_digest(path,False),continuation.digest(path))
            with self.assertRaises(ValueError): continuation.journal_digest(Path(directory)/'missing-parent/journal.json',True)

    def test_host_close_wait_retries_only_known_live_clients(self):
        template=str(TEMPLATES/'OfflineContinuation.ps1.template').replace("'","''")
        script=r'''$ErrorActionPreference='Stop'
$t=$null;$e=$null
$text=[IO.File]::ReadAllText('__TEMPLATE__',[Text.Encoding]::UTF8)
$text=[regex]::Replace($text,'@@[A-Z_]+@@','')
$ast=[Management.Automation.Language.Parser]::ParseInput($text,[ref]$t,[ref]$e)
if($e.Count){throw 'wait_template_parse_failed'}
$f=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'WaitForHostConnectionsToClose'},$true))
if($f.Count -ne 1){throw 'wait_function_missing'}
. ([scriptblock]::Create($f[0].Extent.Text))
$script:attempt=0;$script:fixed=0;$script:previous=0
function Write-Host { }
function RequireNoActors { $script:attempt++;if($script:attempt -eq 1){throw 'offline_independent_executor_present'} }
function RequireFixedStop { $script:fixed++ }
function RequirePreviousTask { $script:previous++ }
$null=WaitForHostConnectionsToClose
if($script:attempt -ne 2 -or $script:fixed -ne 1 -or $script:previous -ne 1){throw 'retry_contract_changed'}
function RequireNoActors { throw 'offline_executor_path_unreadable' }
$rejected=$false
try {$null=WaitForHostConnectionsToClose}catch{if($_.Exception.Message -cne 'offline_executor_path_unreadable'){throw};$rejected=$true}
if(!$rejected){throw 'unreadable_actor_ignored'}
@{known_live_retried=$true;unreadable_rejected=$true}|ConvertTo-Json -Compress
'''.replace('__TEMPLATE__',template)
        result=run_ps(script)
        self.assertTrue(result['known_live_retried'])
        self.assertTrue(result['unreadable_rejected'])

    def test_windows_job_membership_is_diagnostic_without_rejecting_installation(self):
        template=(TEMPLATES/'OfflineContinuation.ps1.template').read_text(encoding='utf-8')
        blocks=[part.split("\n'@",1)[0] for part in template.split("Add-Type -TypeDefinition @'\n")[1:]]
        source=next(part for part in blocks if 'public static class FlowerContinuationLifetime' in part)
        result=run_ps("$ErrorActionPreference='Stop'\nAdd-Type -TypeDefinition @'\n"+source+
                      "\n'@\n$v=[FlowerContinuationLifetime]::ObserveMembership();@{membership=$v;diagnostic_completed=$true}|ConvertTo-Json -Compress")
        self.assertIn(result['membership'],(-1,0,1))
        self.assertTrue(result['diagnostic_completed'])

    def test_protected_receipt_drift_rejected(self):
        root=Path(__file__).resolve().parents[1]/'docs/evidence/2026-10-23-offline-migration'
        plan=json.loads((root/'installation-plan.json').read_bytes())
        prefix=Path(plan['ProgressPrefix'])
        result=json.loads(Path(str(prefix)+'-result.json').read_bytes())
        rows=[json.loads(line) for line in Path(str(prefix)+'-progress.jsonl').read_text().splitlines()]
        self.assertTrue(continuation.require_receipts(plan,result,rows)['Stop']['Stopped'])
        for key,value in [('task_changed',True),('active_changed',True),('resumed',True),('operation','foreign'),('stage','publishing')]:
            changed={**result,key:value}
            with self.assertRaises(ValueError): continuation.require_receipts(plan,changed,rows)
        for index in range(len(rows)):
            changed=copy.deepcopy(rows);changed[index]['stage']='foreign'
            with self.assertRaises(ValueError): continuation.require_receipts(plan,result,changed)
        changed=copy.deepcopy(rows);changed[2]['detail']['Shared']['Stopped']=False
        with self.assertRaises(ValueError): continuation.require_receipts(plan,result,changed)

    def test_actual_classes_compile_and_medium_repair_preserves_data(self):
        source=(TEMPLATES/'RecoveryProtection.cs').read_text()
        # The production algorithm is unchanged. Only root, owner allowlist and
        # target integrity are replaced with this test user's TEMP/Medium role.
        source=source.replace('FlowerRecoveryProtection','FixtureRecoveryProtection')
        source=source.replace('Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "FlowerControl", "HighHelper", "recovery")','TestRoot')
        source=source.replace('public static class FixtureRecoveryProtection\n{','public static class FixtureRecoveryProtection\n{\n public static string TestRoot;')
        source=source.replace('S-1-16-12288','S-1-16-8192').replace('NW;;;HI','NW;;;ME')
        with tempfile.TemporaryDirectory(prefix='flower-continuation-medium-') as directory:
            root=Path(directory)/'recovery';literal=str(root).replace("'","''")
            script="$ErrorActionPreference='Stop'\nImport-Module (Join-Path $PSHOME 'Modules/Microsoft.PowerShell.Security/Microsoft.PowerShell.Security.psd1') -Global\n"
            for name in ('PinnedDelivery.cs','OfflineMigrationGuard.cs'):
                script+="Add-Type -TypeDefinition @'\n"+(TEMPLATES/name).read_text()+"\n'@\n"
            script+="$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value\n$src=@'\n"+source+"\n'@\n"
            script+="$src=$src.Replace('S-1-5-32-544',$sid);Add-Type -TypeDefinition $src\n"
            script+="[FixtureRecoveryProtection]::TestRoot='"+literal+"'\n$r=[FixtureRecoveryProtection]::TestRoot\n"
            script+=r'''
[IO.Directory]::CreateDirectory($r)|Out-Null
$acl=[Security.AccessControl.DirectorySecurity]::new()
$acl.SetOwner([Security.Principal.SecurityIdentifier]::new($sid));$acl.SetAccessRuleProtection($true,$false)
foreach($who in @($sid,'S-1-5-18')) {$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($who),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
Set-Acl -LiteralPath $r -AclObject $acl
$p=Join-Path $r 'journal.json';$n=$p+'.new'
[IO.File]::WriteAllText($p,'retained-original');[IO.File]::WriteAllText($n,'retained-new')
$a=[FixtureRecoveryProtection]::TightenStopped($r)
if([IO.File]::ReadAllText($p) -cne 'retained-original' -or [IO.File]::ReadAllText($n) -cne 'retained-new'){throw 'bytes_changed'}
for($i=0;$i -lt 2;$i++) {
 $s=[IO.File]::Open($n,[IO.FileMode]::Create,[IO.FileAccess]::Write,[IO.FileShare]::None)
 try {$b=[Text.Encoding]::UTF8.GetBytes('round-'+$i);$s.Write($b,0,$b.Length);$s.Flush($true)}finally{$s.Dispose()}
 # PS5.1 File.Move has no overwrite bool; equivalent native producer replace.
 [FlowerPinnedDelivery]::ReplaceFile($n,$p)
 $b=[FixtureRecoveryProtection]::TightenStopped($r)
 if([IO.File]::ReadAllText($p) -cne ('round-'+$i)){throw 'replacement_changed'}
}
@{first=$a;last=$b;replacement_rounds=2;version=$PSVersionTable.PSVersion.ToString();medium_fixture_only=$true}|ConvertTo-Json -Depth 5 -Compress
'''
            result=run_ps(script)
        self.assertTrue(result['version'].startswith('5.1.'))
        self.assertTrue(result['first']['BytesUnchanged'])
        self.assertEqual(result['first']['Files'],2)
        self.assertEqual(result['last']['Files'],1)

    def test_continuation_and_fresh_install_render_without_parser_errors(self):
        values={'PLAN_JSON':'{}','UPDATE_FUNCTIONS':continuation.migration.update_functions(),'OFFLINE_FUNCTIONS':continuation.offline_functions()}
        for key,file in [('PINNED_DELIVERY_TYPE','PinnedDelivery.cs'),('OFFLINE_GUARD_TYPE','OfflineMigrationGuard.cs'),('RECOVERY_PROTECTION_TYPE','RecoveryProtection.cs')]:
            values[key]=continuation.render_installer_type(file,Path('C:/Program Files/FlowerControl/HighHelper'))
        body=(TEMPLATES/'OfflineContinuation.ps1.template').read_text()
        for key,value in values.items():body=body.replace('@@'+key+'@@',value)
        self.assertNotIn('@@',body)
        with tempfile.TemporaryDirectory(prefix='flower-continuation-parse-') as directory:
            path=Path(directory)/'Continue.ps1';path.write_text(body,encoding='utf-8-sig')
            result=run_ps("$t=$null;$e=$null;[Management.Automation.Language.Parser]::ParseFile('"+str(path).replace("'","''")+"',[ref]$t,[ref]$e)|Out-Null;@{errors=@($e|ForEach-Object {$_.Message})}|ConvertTo-Json -Compress")
        self.assertEqual(result['errors'],[])


if __name__=='__main__':unittest.main()
