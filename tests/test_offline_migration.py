"""Real PS5.1 + native handles in TEMP; never use a production High process."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tools import prepare_offline_migration as migration

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / 'tools/high_broker_install'
PS = Path(os.environ.get('SystemRoot', 'C:/Windows')) / 'System32/WindowsPowerShell/v1.0/powershell.exe'


def run_ps(script, timeout=40):
    with tempfile.TemporaryDirectory(prefix='flower-offline-ps51-') as folder:
        path = Path(folder) / 'Fixture.ps1'
        path.write_text(script, encoding='utf-8-sig')
        result = subprocess.run([str(PS), '-NoLogo', '-NoProfile', '-NonInteractive', '-File', str(path)],
                                capture_output=True, timeout=timeout, creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode:
        raise AssertionError((result.stdout + result.stderr).decode('utf8', errors='replace'))
    return json.loads(result.stdout.decode('utf-8-sig'))


@unittest.skipUnless(os.name == 'nt' and PS.is_file(), 'Windows PowerShell 5.1 required')
class OfflineMigrationTests(unittest.TestCase):
    def test_metadata_uses_real_windows_sid_and_filetime(self):
        value = migration.live_original(os.getpid(), Path(sys._base_executable))
        self.assertEqual(value['OldPid'], os.getpid())
        self.assertTrue(value['UserSid'].startswith('S-1-5-21-'))
        self.assertTrue(value['LogonSid'].startswith('S-1-5-5-'))
        self.assertGreater(int(value['OldCreated']), 0)
        self.assertGreater(value['SessionId'], 0)

    def test_recovery_restores_only_exact_owned_metadata_and_never_resumes(self):
        body = (TEMPLATES / 'OfflineMigration.ps1.template').read_text(encoding='utf8')
        for key, value in {'PLAN_JSON': '{}', 'UPDATE_FUNCTIONS': migration.update_functions(),
                           'PINNED_DELIVERY_TYPE': (TEMPLATES / 'PinnedDelivery.cs').read_text(encoding='utf8'),
                           'OFFLINE_GUARD_TYPE': (TEMPLATES / 'OfflineMigrationGuard.cs').read_text(encoding='utf8'),
                           'RECOVERY_PROTECTION_TYPE': (TEMPLATES / 'RecoveryProtection.cs').read_text(encoding='utf8')}.items():
            body = body.replace('@@' + key + '@@', value)
        with tempfile.TemporaryDirectory(prefix='flower-offline-recovery-tests-') as directory:
            script = Path(directory) / 'Parsed.ps1'; script.write_text(body, encoding='utf-8-sig')
            path = str(script).replace("'", "''")
            result = run_ps("$ErrorActionPreference='Stop'\n$tokens=$null;$errors=$null;" +
                "$ast=[Management.Automation.Language.Parser]::ParseFile('" + path + "',[ref]$tokens,[ref]$errors)\n" +
                "if($errors.Count){throw ($errors.Message -join ';')}\n" +
                "foreach($name in @('VerifiedStopForRecovery','RecoverStoppedOriginal','RequirePreviousTask')){$f=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true));. ([scriptblock]::Create($f[0].Extent.Text))}\n" + r'''
# Only actual recovery comparisons run; all system mutations are counters.
function HashText([string]$text){return $text}
function Hash([string]$path){return $script:active}
function Export-ScheduledTask {return $script:task}
function Get-FlowerTaskSecurityDescriptor {return $script:sddl}
function Admin([string]$exe,[string]$commandLine){
 if($commandLine -cne '--offline-update-state'){throw 'unexpected_native_command'}
 return [pscustomobject]@{Stop=[pscustomobject]@{Stopped=$script:stop;UserSid='test-user';Session=1}}
}
function RegisterTask([string]$xml,[string]$sddl){
 if($xml -cne 'old-task' -or $sddl -cne 'original-sddl'){throw 'wrong_restore_task'}
 $script:task=$xml;$script:register++
}
function ReplaceActive([string]$source,[string]$expected,[string]$previous){
 if($source -cne 'C:\isolated\old\installation.json' -or $expected -cne 'old-active' -or $previous -cne 'new-active'){throw 'wrong_restore_active'}
 $script:active=$expected;$script:replace++
}
function Start-ScheduledTask {$script:starts++}
$answers=@()
foreach($mode in @('original-live','start-unknown','restore','foreign-task','foreign-active','foreign-sddl','stop-changed','already-old')){
 $plan=[pscustomobject]@{UserSid='test-user';SessionId=1;OldTaskDefinitionSha256='old-task';OldTaskSddlSha256='original-sddl';OldActiveSha256='old-active';ActiveSha256='new-active'}
 $brokerRoot='C:\isolated';$oldDir='C:\isolated\old';$newExe='C:\isolated\new\Flower.HighHelper.exe';$taskName='isolated-task'
 $originalExited=$mode -ne 'original-live';$startAttempted=$mode -eq 'start-unknown';$stopLatched=$true
 $taskChanged=$true;$activeChanged=$true;$publishedTaskHash='new-task';$oldXml='old-task';$oldSddl='original-sddl'
 $script:task='new-task';$script:active='new-active';$script:sddl='original-sddl';$script:stop=$mode -ne 'stop-changed'
 $script:register=0;$script:replace=0;$script:starts=0;$script:disposed=0
 $guard=[pscustomobject]@{};$guard|Add-Member ScriptMethod Dispose {$script:disposed++}
 if($mode -eq 'foreign-task'){$script:task='foreign-task'}
 if($mode -eq 'foreign-active'){$script:active='foreign-active'}
 if($mode -eq 'foreign-sddl'){$script:sddl='foreign-sddl'}
 if($mode -eq 'already-old'){$script:task='old-task';$script:active='old-active'}
 try{$answer=RecoverStoppedOriginal}catch{$answer=$_.Exception.GetBaseException().Message}
 $answers+=,@{mode=$mode;answer=$answer;register=$script:register;replace=$script:replace;starts=$script:starts;disposed=$script:disposed;stop=$script:stop}
}
@{cases=$answers;version=$PSVersionTable.PSVersion.ToString()}|ConvertTo-Json -Compress
''')
        cases = {case['mode']: case for case in result['cases']}
        self.assertTrue(result['version'].startswith('5.1.'))
        for mode in ('original-live', 'start-unknown', 'foreign-task', 'foreign-active', 'foreign-sddl', 'stop-changed'):
            self.assertEqual([cases[mode][key] for key in ('register', 'replace', 'starts', 'disposed')], [0, 0, 0, 0], cases[mode])
        for mode in ('restore', 'already-old'):
            self.assertEqual(cases[mode]['answer'], 'original_metadata_restored_stopped_start_submitted', cases[mode])
            self.assertEqual([cases[mode][key] for key in ('register','replace','starts','disposed')],
                             [1, 1, 1, 1] if mode == 'restore' else [0, 0, 1, 1])
            self.assertTrue(cases[mode]['stop'])

    def test_native_process_exit_and_mutex_fail_closed(self):
        source = (TEMPLATES / 'OfflineMigrationGuard.cs').read_text(encoding='utf8')
        # Only the wait method is tested through uninitialized objects. Every
        # process and mutex below belongs to this TEMP test, never production.
        result = run_ps("$ErrorActionPreference='Stop'\nAdd-Type -TypeDefinition @'\n" + source + "\n'@\n" + r'''
$flags=[Reflection.BindingFlags]'Instance,NonPublic'
function Case([int]$code,[int]$wait,[string]$mode){
 $info=[Diagnostics.ProcessStartInfo]::new()
 $info.FileName=Join-Path $PSHOME 'powershell.exe'
 $info.Arguments='-NoLogo -NoProfile -NonInteractive -Command "[Threading.Thread]::Sleep(300); exit '+$code+'"'
 $info.UseShellExecute=$false;$info.CreateNoWindow=$true
 $child=[Diagnostics.Process]::Start($info)
 $mutex=[Threading.Mutex]::new($false,'Local\FlowerOfflineTest.'+[Guid]::NewGuid().ToString('N'))
 $guard=[Runtime.Serialization.FormatterServices]::GetUninitializedObject([FlowerOfflineGuard])
 [FlowerOfflineGuard].GetField('process',$flags).SetValue($guard,[Microsoft.Win32.SafeHandles.SafeProcessHandle]::new($child.Handle,$false))
 [FlowerOfflineGuard].GetField('singleton',$flags).SetValue($guard,$mutex)
 $thread=$null;$ready=$null;$release=$null
 if($mode -in @('busy','abandoned')){
  $ready=[Threading.ManualResetEvent]::new($false);$release=[Threading.ManualResetEvent]::new($false)
  $thread=[OfflineMutexFixture]::Hold($mutex,$ready,$release,($mode -eq 'abandoned'))
  if(!$ready.WaitOne(5000)){throw 'test_barrier_failed'}
  if($mode -eq 'abandoned'){[OfflineMutexFixture]::JoinExited($thread)}
 }
 $answer='accepted'
 try{$guard.WaitForNormalExit($wait)}catch{$answer=$_.Exception.GetBaseException().Message}
 finally{
  if($null -ne $release){$release.Set()|Out-Null;[OfflineMutexFixture]::JoinExited($thread);$ready.Dispose();$release.Dispose()}
  $guard.Dispose()
  $child.WaitForExit();$child.Dispose()
 }
 return $answer
}
Add-Type -TypeDefinition @'
using System;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Threading;
public static class OfflineMutexFixture {
 private static readonly ConcurrentDictionary<int,IntPtr> handles = new ConcurrentDictionary<int,IntPtr>();
 [DllImport("kernel32.dll",SetLastError=true)] private static extern IntPtr OpenThread(uint access,bool inherit,uint id);
 [DllImport("kernel32.dll")] private static extern uint GetCurrentThreadId();
 [DllImport("kernel32.dll")] private static extern uint WaitForSingleObject(IntPtr handle,uint timeout);
 [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
 public static Thread Hold(Mutex mutex, ManualResetEvent ready, ManualResetEvent release, bool abandon) {
  var thread = new Thread(() => {
   mutex.WaitOne();
   var handle=OpenThread(0x100000,false,GetCurrentThreadId());
   if(handle==IntPtr.Zero) throw new InvalidOperationException("fixture_native_thread_handle_unavailable");
   handles[Thread.CurrentThread.ManagedThreadId]=handle;ready.Set();
   if(!abandon){release.WaitOne();mutex.ReleaseMutex();}
  });
  thread.Start();return thread;
 }
 public static void JoinExited(Thread thread) {
  thread.Join();IntPtr handle;
  if(!handles.TryRemove(thread.ManagedThreadId,out handle))return;
  try {
   // The managed Join can precede native teardown of the owned mutex.
   // Observe kernel thread exit before asking production's zero-wait gate.
   if(WaitForSingleObject(handle,5000)!=0)throw new InvalidOperationException("fixture_native_thread_exit_unconfirmed");
  } finally {CloseHandle(handle);}
 }
}
'@
function InputCase([string]$mode){
 $name='Local\FlowerOfflineInputTest.'+[Guid]::NewGuid().ToString('N')
 $mutex=$null;$thread=$null;$ready=$null;$release=$null
 if($mode -ne 'missing'){$mutex=[Threading.Mutex]::new($false,$name)}
 $guard=[Runtime.Serialization.FormatterServices]::GetUninitializedObject([FlowerOfflineGuard])
 if($mode -in @('busy','abandoned')){
  $ready=[Threading.ManualResetEvent]::new($false);$release=[Threading.ManualResetEvent]::new($false)
  $thread=[OfflineMutexFixture]::Hold($mutex,$ready,$release,($mode -eq 'abandoned'))
  if(!$ready.WaitOne(5000)){throw 'input_fixture_barrier_failed'}
  if($mode -eq 'abandoned'){[OfflineMutexFixture]::JoinExited($thread)}
 }
 $answer='accepted'
 try{[FlowerOfflineGuard].GetMethod('HoldInputResourceAt',$flags).Invoke($guard,@($name))|Out-Null}
 catch{$answer=$_.Exception.GetBaseException().Message}
 finally{
  if($null -ne $release){$release.Set()|Out-Null;[OfflineMutexFixture]::JoinExited($thread);$ready.Dispose();$release.Dispose()}
  $guard.Dispose();if($null -ne $mutex){$mutex.Dispose()}
 }
 return $answer
}
@{version=$PSVersionTable.PSVersion.ToString();logon=[FlowerOfflineGuard]::LogonSid();
 ok=(Case 0 10000 'normal');failure=(Case 2 10000 'normal');
 timeout=(Case 0 1 'normal');busy=(Case 0 10000 'busy');abandoned=(Case 0 10000 'abandoned');
 invalid=(Case 0 0 'normal');inputFree=(InputCase 'free');inputMissing=(InputCase 'missing');
 inputBusy=(InputCase 'busy');inputAbandoned=(InputCase 'abandoned')}|ConvertTo-Json -Compress
''')
        self.assertTrue(result['version'].startswith('5.1.'))
        self.assertTrue(result['logon'].startswith('S-1-5-5-'))
        self.assertEqual(result['ok'], 'accepted')
        self.assertEqual(result['failure'], 'offline_original_drain_failed')
        self.assertEqual(result['timeout'], 'offline_normal_exit_not_observed')
        self.assertEqual(result['busy'], 'offline_broker_restarted')
        self.assertEqual(result['abandoned'], 'offline_original_singleton_abandoned')
        self.assertEqual(result['invalid'], 'offline_wait_rejected')
        self.assertEqual(result['inputFree'], 'accepted')
        self.assertEqual(result['inputMissing'], 'accepted')
        self.assertEqual(result['inputBusy'], 'offline_input_resource_busy')
        self.assertEqual(result['inputAbandoned'], 'offline_input_resource_abandoned')

    def test_rendered_installer_parses_in_real_host_and_journal_keeps_unacknowledged_history(self):
        body = (TEMPLATES / 'OfflineMigration.ps1.template').read_text(encoding='utf8')
        for key, value in {'PLAN_JSON': '{}', 'UPDATE_FUNCTIONS': migration.update_functions(),
                           'PINNED_DELIVERY_TYPE': (TEMPLATES / 'PinnedDelivery.cs').read_text(encoding='utf8'),
                           'OFFLINE_GUARD_TYPE': (TEMPLATES / 'OfflineMigrationGuard.cs').read_text(encoding='utf8')}.items():
            body = body.replace('@@' + key + '@@', value)
        with tempfile.TemporaryDirectory(prefix='flower-offline-tests-') as directory:
            script = Path(directory) / 'Parsed.ps1'; script.write_text(body, encoding='utf-8-sig')
            journal = Path(directory) / 'journal.json'
            released = dict(InputRelease='released', MutexReleased=True, NativeCountKnown=True,
                            Acknowledged=False, SemanticExecutorExited=None, PhysicalInputFree=False)
            cases = [dict(Schema=1, Pending=[]), dict(Schema=1, Pending=[released])]
            cases += [dict(Schema=1, Pending=[{**released, **change}]) for change in (
                dict(InputRelease='unknown'), dict(InputRelease='release_pending'), dict(MutexReleased=False),
                dict(MutexReleased='true'), dict(NativeCountKnown=False), dict(Acknowledged=True),
                dict(SemanticExecutorExited=False), dict(SemanticExecutorExited='false'),
                dict(SemanticExecutorExited=False, PhysicalInputFree='true'))]
            cases += [dict(Schema=1, Pending=None), dict(Schema=1, Pending='invalid'), dict(Schema=2, Pending=[])]
            cases_path = Path(directory) / 'cases.json'; cases_path.write_text(json.dumps(cases), encoding='utf8')
            def quoted(path):
                return "'" + str(path).replace("'", "''") + "'"
            result = run_ps("$ErrorActionPreference='Stop'\nImport-Module (Join-Path $PSHOME 'Modules/Microsoft.PowerShell.Utility/Microsoft.PowerShell.Utility.psd1') -Global\n" +
                "$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile(" + quoted(script) + ",[ref]$tokens,[ref]$errors)\n" +
                "if($errors.Count){throw ($errors.Message -join ';')}\n" +
                "foreach($name in @('RequireReleasedJournal','Hash')){$f=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true));. ([scriptblock]::Create($f[0].Extent.Text))}\n" +
                "function Assert-FlowerNoLinks([string]$path,[switch]$Shallow){}\n" +
                "$plan=[pscustomobject]@{RecoveryJournal=" + quoted(journal) + "};$answers=@()\n" +
                "foreach($case in ([IO.File]::ReadAllText(" + quoted(cases_path) + ")|ConvertFrom-Json)){\n" +
                "[IO.File]::WriteAllText($plan.RecoveryJournal,($case|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false));$before=[IO.File]::ReadAllBytes($plan.RecoveryJournal);\n" +
                "$accepted=$true;$reason=$null;try{$null=RequireReleasedJournal}catch{$accepted=$false;$reason=$_.Exception.Message};$after=[IO.File]::ReadAllBytes($plan.RecoveryJournal);\n" +
                "if([Convert]::ToBase64String($before) -cne [Convert]::ToBase64String($after)){throw 'journal_was_modified'};$answers+=,@{ok=$accepted;reason=$reason}}\n" +
                r'''
function Accepted([scriptblock]$action) {try {$null=& $action;return $true}catch{return $false}}
$plan.RecoveryJournal=$plan.RecoveryJournal+'.never'
$strictMissing=Accepted {RequireReleasedJournal}
$allowedMissing=Accepted {RequireReleasedJournal -AllowMissing}
$absencePreserved=!(Test-Path -LiteralPath $plan.RecoveryJournal)
[IO.File]::WriteAllText(($plan.RecoveryJournal+'.new'),'partial')
$partialMissing=Accepted {RequireReleasedJournal -AllowMissing}
[IO.File]::WriteAllText($plan.RecoveryJournal,'{"Schema":1,"Pending":[]}')
$partialExisting=Accepted {RequireReleasedJournal -AllowMissing}
$plan.RecoveryJournal=$plan.RecoveryJournal+'.directory'
[IO.Directory]::CreateDirectory($plan.RecoveryJournal)|Out-Null
$sameNameDirectory=Accepted {RequireReleasedJournal -AllowMissing}
$plan.RecoveryJournal=Join-Path $plan.RecoveryJournal 'absent-parent\journal.json'
$missingParent=Accepted {RequireReleasedJournal -AllowMissing}
@{accepted=$answers;version=$PSVersionTable.PSVersion.ToString();strictMissing=$strictMissing;
 allowedMissing=$allowedMissing;absencePreserved=$absencePreserved;partialMissing=$partialMissing;
 partialExisting=$partialExisting;sameNameDirectory=$sameNameDirectory;missingParent=$missingParent}|ConvertTo-Json -Compress
''')
            self.assertTrue(result['version'].startswith('5.1.'))
            self.assertEqual([item['ok'] for item in result['accepted']], [True, True] + [False] * (len(cases) - 2), result)
            self.assertFalse(result['strictMissing'])
            self.assertTrue(result['allowedMissing'])
            self.assertTrue(result['absencePreserved'])
            for key in ('partialMissing', 'partialExisting', 'sameNameDirectory', 'missingParent'):
                self.assertFalse(result[key], (key, result))

    def test_role_and_real_file_drift_abort_without_writes(self):
        body = (TEMPLATES / 'OfflineMigration.ps1.template').read_text(encoding='utf8')
        body = body.replace('@@PLAN_JSON@@', '{}').replace('@@UPDATE_FUNCTIONS@@', migration.update_functions())
        with tempfile.TemporaryDirectory(prefix='flower-offline-role-tests-') as directory:
            script=Path(directory)/'Parsed.ps1'; script.write_text(body,encoding='utf-8-sig')
            fixture=Path(directory)/'isolated'; fixture.mkdir()
            result=run_ps("$ErrorActionPreference='Stop'\nImport-Module (Join-Path $PSHOME 'Modules/Microsoft.PowerShell.Utility/Microsoft.PowerShell.Utility.psd1') -Global\n$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile('"+str(script).replace("'","''")+"',[ref]$tokens,[ref]$errors)\n"+
                "if($errors.Count){throw ($errors.Message -join ';')}\n"+
                "foreach($name in @('RequireReleasedJournal','RoleFileInventory','RequireRoleAnchor','VerifiedStopForRecovery','Hash','HashText')){$f=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true));. ([scriptblock]::Create($f[0].Extent.Text))}\n"+
                "$brokerRoot='"+str(fixture).replace("'","''")+"'\n"+r'''
function Assert-FlowerNoLinks([string]$path,[switch]$Shallow){}
$utf8=New-Object Text.UTF8Encoding($false)
function Admin([string]$exe,[string]$commandLine) {
 if($commandLine -cne '--flower-role-policy'){throw 'unexpected_native_write'}
 return $script:role
}
$plan=[pscustomobject]@{UserSid='test-user';SessionId=1;RecoveryJournal=(Join-Path $brokerRoot 'journal.json')}
$null=RequireReleasedJournal -AllowMissing
$newExe='never-executed-fixture'
foreach($part in @('stop','computer-pause','ordinary-stop')){[IO.Directory]::CreateDirectory((Join-Path $brokerRoot ('recovery\'+$part)))|Out-Null}
$paths=@('stop\test-user.1.json','computer-pause\test-user.1.json','ordinary-stop\test-user.1.global.bin','ordinary-stop\test-user.1.computer.bin')
foreach($path in $paths){[IO.File]::WriteAllText((Join-Path $brokerRoot ('recovery\'+$path)),'original')}
$roleText='{"Phase":"role_policy","UserSid":"test-user","Tier":2,"Revision":"original","Stop":{"Protected":{"Schema":1,"UserSid":"test-user","Session":1,"Stopped":true,"Epoch":7},"Computer":{"Schema":1,"UserSid":"test-user","Session":1,"Stopped":false,"Epoch":5},"Ordinary":{"Count":0,"Acknowledged":0},"OrdinaryComputer":{"Count":0,"Acknowledged":0}}}'
$roleAnchorHash=HashText (($roleText|ConvertFrom-Json)|ConvertTo-Json -Depth 8 -Compress)
$roleFilesHash=HashText (RoleFileInventory)
$script:role=$roleText|ConvertFrom-Json
$journalAbsent=$true
$savedFilesHash=$roleFilesHash;$roleFilesHash=$null
$unverifiedAccepted=$true;try{$null=VerifiedStopForRecovery}catch{$unverifiedAccepted=$false}
$roleFilesHash=$savedFilesHash
$recoveredStop=VerifiedStopForRecovery
[IO.File]::WriteAllText($plan.RecoveryJournal,'{"Schema":1,"Pending":[]}')
$appearedAccepted=$true;try{$null=VerifiedStopForRecovery}catch{$appearedAccepted=$false}
$answers=@()
foreach($mode in @('same','tier','revision','protected','computer','ordinary','file-bytes','new-ack')){
 $script:role=$roleText|ConvertFrom-Json
 switch($mode){
  'tier'{$script:role.Tier=1}
  'revision'{$script:role.Revision='changed'}
  'protected'{$script:role.Stop.Protected.Epoch=8}
  'computer'{$script:role.Stop.Computer.Stopped=$true}
  'ordinary'{$script:role.Stop.Ordinary.Count=1}
  'file-bytes'{[IO.File]::WriteAllText((Join-Path $brokerRoot 'recovery\stop\test-user.1.json'),'changed')}
  'new-ack'{[IO.File]::WriteAllText((Join-Path $brokerRoot 'recovery\ordinary-stop\test-user.1.global.bin.ack.json'),'new')}
 }
 $accepted=$true;try{$null=RequireRoleAnchor}catch{$accepted=$false}
 $answers+=,@{mode=$mode;accepted=$accepted}
 if($mode -eq 'file-bytes'){[IO.File]::WriteAllText((Join-Path $brokerRoot 'recovery\stop\test-user.1.json'),'original')}
}
@{cases=$answers;unverifiedAccepted=$unverifiedAccepted;verifiedStop=$recoveredStop;
 appearedAccepted=$appearedAccepted}|ConvertTo-Json -Compress
''')
            self.assertEqual([case['accepted'] for case in result['cases']], [True]+[False]*7, result)
            self.assertFalse(result['unverifiedAccepted'])
            self.assertTrue(result['verifiedStop']['Stopped'])
            self.assertEqual(result['verifiedStop']['Epoch'],7)
            self.assertFalse(result['appearedAccepted'])

    def test_shutdown_access_denied_is_rechecked_without_dropping_unknown_pids(self):
        template=str(TEMPLATES/'OfflineMigration.ps1.template').replace("'","''")
        script=r'''$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$text=[IO.File]::ReadAllText('__TEMPLATE__',[Text.Encoding]::UTF8)
$text=[regex]::Replace($text,'@@[A-Z_]+@@','')
$ast=[Management.Automation.Language.Parser]::ParseInput($text,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'template_parse_failed'}
$function=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'RequireNoActors'},$true))
. ([scriptblock]::Create($function[0].Extent.Text))
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
public static class FlowerOfflineProcessMetadata {
 public static string Scenario,Inside;
 public static int Calls;
 public static string LiveImage(int pid) {
  Calls++;
  if(Scenario=="other_error") throw new Win32Exception(6,"fixture_metadata_error");
  if(Calls==1 || Scenario=="persistent" || Scenario=="omitted_but_unreadable")
   throw new Win32Exception(5,"fixture_access_denied");
  if(Scenario=="reused_inside") return Inside;
  if(Scenario=="reused_outside") return "C:\\unrelated\\worker.exe";
  return null;
 }
}
'@
$brokerRoot=Join-Path $env:TEMP 'flower-actor-rescan-fixture'
$newPolicy=[pscustomobject]@{WgcWorkerHashes=[pscustomobject]@{}}
[FlowerOfflineProcessMetadata]::Inside=Join-Path $brokerRoot 'versions\fixture\flower-python.exe'
function Get-ScheduledTask {return @()}
function Get-CimInstance {
 $script:reads++
 if($script:reads -gt 1 -and $script:scenario -ne 'persistent'){return @()}
 return [pscustomobject]@{ProcessId=50001;Name='flower-python.exe';ExecutablePath=$null}
}
function Log([string]$stage,$detail) {$script:diagnostics+=,@{stage=$stage;detail=$detail}}
function RunCase([string]$scenario) {
 $script:scenario=$scenario;$script:reads=0;$script:diagnostics=@()
 [FlowerOfflineProcessMetadata]::Scenario=$scenario;[FlowerOfflineProcessMetadata]::Calls=0
 $accepted=$false;$reason=$null
 try {RequireNoActors -WaitMilliseconds 600;$accepted=$true}catch{$reason=$_.Exception.Message}
 return @{accepted=$accepted;reason=$reason;reads=$script:reads;queries=[FlowerOfflineProcessMetadata]::Calls;diagnostics=$script:diagnostics}
}
$results=@{}
foreach($scenario in @('exited','persistent','omitted_but_unreadable','reused_inside','reused_outside','other_error')) {$results[$scenario]=RunCase $scenario}
$results|ConvertTo-Json -Depth 7 -Compress
'''.replace('__TEMPLATE__',template)
        result=run_ps(script)
        for key in ('exited','reused_outside'):
            self.assertTrue(result[key]['accepted'],(key,result[key]))
            self.assertGreaterEqual(result[key]['queries'],2)
            self.assertGreaterEqual(result[key]['reads'],2)
            self.assertTrue(any(row['stage']=='executor_quiescence_verified_after_metadata_retry'
                                for row in result[key]['diagnostics']))
        for key in ('persistent','omitted_but_unreadable'):
            self.assertFalse(result[key]['accepted'])
            self.assertEqual(result[key]['reason'],'offline_executor_path_unreadable')
            self.assertGreaterEqual(result[key]['queries'],2)
            self.assertFalse(any(row['stage']=='executor_quiescence_verified_after_metadata_retry'
                                 for row in result[key]['diagnostics']))
        self.assertFalse(result['reused_inside']['accepted'])
        self.assertEqual(result['reused_inside']['reason'],'offline_independent_executor_present')
        self.assertFalse(result['other_error']['accepted'])
        self.assertEqual(result['other_error']['queries'],1)

    def test_actor_cim_candidates_use_live_readonly_process_handles(self):
        body = (TEMPLATES / 'OfflineMigration.ps1.template').read_text(encoding='utf8')
        body = body.replace('@@PLAN_JSON@@', '{}').replace('@@UPDATE_FUNCTIONS@@', migration.update_functions())
        with tempfile.TemporaryDirectory(prefix='flower-offline-actors-') as directory:
            root=Path(directory);script=root/'Parsed.ps1';script.write_text(body,encoding='utf-8-sig')
            target=root/'versions/fixture/cmd.exe';target.parent.mkdir(parents=True)
            import shutil
            shutil.copyfile(Path(os.environ['SystemRoot'])/'System32/cmd.exe',target)
            result=run_ps("$ErrorActionPreference='Stop'\n$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile('"+str(script).replace("'","''")+"',[ref]$tokens,[ref]$errors)\n"+
                "if($errors.Count){throw ($errors.Message -join ';')}\n$f=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'RequireNoActors'},$true));. ([scriptblock]::Create($f[0].Extent.Text))\n"+
                "$brokerRoot='"+str(root).replace("'","''")+"'\n$childPath='"+str(target).replace("'","''")+"'\n"+r'''
$newPolicy=[pscustomobject]@{WgcWorkerHashes=[pscustomobject]@{}}
function Get-ScheduledTask {
 $script:taskReads++
 if($script:taskRunningOnRead -gt 0 -and $script:taskReads -ge $script:taskRunningOnRead){return [pscustomobject]@{TaskName='FlowerControl.fixture';State='Running'}}
 return @()
}
function Get-CimInstance {
 $script:reads++
 if($script:releaseOnRead -gt 0 -and $script:reads -ge $script:releaseOnRead){
  $child.StandardInput.WriteLine('fixture');$child.StandardInput.Close();$child.WaitForExit();$script:releaseOnRead=0
 }
 return $script:rows
}
function Log([string]$stage,$detail) {$script:diagnostics+=,@{stage=$stage;detail=$detail}}
function Accepted([int]$wait=0) {try{RequireNoActors -WaitMilliseconds $wait;return $true}catch{return $false}}
$script:diagnostics=@()
$script:reads=0;$script:releaseOnRead=0
$script:taskReads=0;$script:taskRunningOnRead=0
$script:rows=@([pscustomobject]@{ProcessId=0;Name='System';ExecutablePath=$null})
$unrelated=Accepted
$script:rows=@([pscustomobject]@{ProcessId=$PID;Name='Flower.HighHelper.exe';ExecutablePath=$null})
$outside=Accepted
$script:rows=@([pscustomobject]@{ProcessId=2147483647;Name='Flower.HighHelper.exe';ExecutablePath=$null})
$gone=Accepted
$script:rows=@([pscustomobject]@{ProcessId=0;Name='Flower.HighHelper.exe';ExecutablePath=$null})
$invalid=Accepted
$info=[Diagnostics.ProcessStartInfo]::new($childPath)
$info.Arguments='/d /s /c "set /p exitToken="'
$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardInput=$true
$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
$child=[Diagnostics.Process]::Start($info)
try {
 if($child.WaitForExit(100)){throw 'controlled_child_did_not_wait'}
 $script:rows=@([pscustomobject]@{ProcessId=$child.Id;Name='Flower.HighHelper.exe';ExecutablePath=$null})
 $inside=Accepted
 $script:taskReads=0;$script:taskRunningOnRead=2
 $taskChangedAccepted=Accepted 3000
 $script:taskRunningOnRead=0
 $script:reads=0;$script:releaseOnRead=3
 $quiescent=Accepted 3000
 if(!$child.WaitForExit(5000)){throw 'controlled_child_exit_unconfirmed'}
 $exited=Accepted
} finally {$child.Dispose()}
@{unrelated=$unrelated;outside=$outside;gone=$gone;invalid=$invalid;inside=$inside;exited=$exited;quiescent=$quiescent;taskChangedAccepted=$taskChangedAccepted;diagnostics=$script:diagnostics}|ConvertTo-Json -Depth 6 -Compress
''')
            for key in ('unrelated','outside','gone','exited','quiescent'):
                self.assertTrue(result[key], (key,result))
            self.assertFalse(result['invalid'])
            self.assertFalse(result['inside'])
            self.assertFalse(result['taskChangedAccepted'])
            self.assertEqual(result['diagnostics'][0]['detail']['pid'],0)


if __name__ == '__main__':
    unittest.main()
