"""Execute generated script branches with owned files and mocked system APIs.

No real scheduler call, ACL write, Program Files write, broker input or install.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from tools.prepare_high_broker_install import digest, media_encoder_license, render_install_scripts, save_source_snapshot, write_json, validate_build_evidence, verify_sealed_inputs


WINDOWS_POWERSHELL = Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"


@unittest.skipUnless(os.name == "nt" and WINDOWS_POWERSHELL.is_file(), "Windows PowerShell 5.1 required")
class InstallScriptTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="flower-install-contract-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.package, self.target, self.repo = [self.root / name for name in ("package", "target", "repo")]
        self.version = "a" * 32
        self.source = self.package / "versions" / self.version
        self.source.mkdir(parents=True)
        self.repo.mkdir()
        (self.repo / "flower.py").write_text("# exact fixture source\n", encoding="utf-8")
        (self.source / "Flower.HighHelper.exe").write_bytes(b"fixture-only-not-executable")
        policy = dict(Repository=str(self.repo), UserSid="S-1-5-21-1-2-3-1001", SourceHashes={"flower.py": digest(self.repo / "flower.py")}, AppWorkerHashes={})
        write_json(self.source / "broker.json", policy)
        active = dict(schema=1, version=self.version, hashes={p.name: digest(p) for p in self.source.iterdir()})
        write_json(self.package / "active.json", active)
        write_json(self.source / "installation.json", active)
        (self.package / "task.xml").write_text("<Task>fixed-fixture</Task>", encoding="utf-16")
        save_source_snapshot(self.repo, self.package, policy["SourceHashes"])
        for name, content in render_install_scripts(self.package, self.target, self.version, "Exact.Fixture.Task").items():
            (self.package / name).write_text(content, encoding="utf-8-sig")

    def run_ps(self, body, *, powershell=WINDOWS_POWERSHELL, expected_major=5):
        fixture = self.root / "run.ps1"
        prefix = r"""
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -ne __EXPECTED_MAJOR__ -or (__EXPECTED_MAJOR__ -eq 5 -and $PSVersionTable.PSVersion.Minor -ne 1)) { throw 'fixture_wrong_powershell_host' }
. (Join-Path $PSScriptRoot 'package\InstallCommon.ps1')
$script:task = $null
$script:registered = 0
$script:disabled = 0
$script:registrationFails = $false
$script:aclFails = $false
$script:adminCalls = @()
$script:labels = @{}
$script:labelWrites = @()
$script:recoveryInitialized = $false
# This scheduler fixture has always mocked system ACL writes. The actual
# recovery class is separately exercised in test_offline_continuation.
function Initialize-FlowerRecovery { $script:recoveryInitialized = $true }
function Get-FlowerMachineBinding {return ('e'*64)}
$script:installOwner=$false
function Write-FlowerInstallOwner {$script:installOwner=$true}
function Assert-FlowerInstallOwner {if(!$script:installOwner){throw 'fixture_install_owner_missing'}}
function Assert-FlowerRetainedMetadata {}
function Initialize-FlowerExitWriter($operation){return $false}
function Close-FlowerExitWriter{}
$script:taskSecurity = 'O:BAG:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;GR;;;BU)'
# Replace only the scheduler readback, retaining the real descriptor validation.
function Get-FlowerTaskSecurityDescriptor { return $script:taskSecurity }
function Get-FlowerIntegritySddl($path) {
 if ($script:labels.ContainsKey($path)) { return $script:labels[$path] }
 return 'S:PAINO_ACCESS_CONTROL'
}
function Set-FlowerHighLabel($path) {
 $script:labelWrites += $path
 $script:labels[$path] = 'S:PAI(ML;;NW;;;HI)'
}
function Get-ScheduledTask { [CmdletBinding()] param($TaskName, $TaskPath)
 if ($TaskName -ne 'Exact.Fixture.Task' -or $TaskPath -ne '\') { throw 'fixture_task_scope' }
 return $script:task
}
function Disable-ScheduledTask { param($TaskName, $TaskPath)
 if ($TaskName -ne 'Exact.Fixture.Task' -or $TaskPath -ne '\') { throw 'fixture_task_scope' }
 $script:disabled++
 $script:task.Settings.Enabled = $false
}
function Register-ScheduledTask { param($TaskName, $TaskPath, $Xml)
 if (!$script:recoveryInitialized) { throw 'fixture_recovery_must_precede_registration' }
 if ($TaskName -ne 'Exact.Fixture.Task' -or $TaskPath -ne '\' -or $Xml -notlike '<Task>*') { throw 'fixture_task_scope' }
 $script:registered++
 if ($script:registrationFails) { throw 'fixture_registration_failed' }
 $script:task = [pscustomobject]@{ Settings = [pscustomobject]@{ Enabled = $true };
  Actions=@([pscustomobject]@{Execute=$command;Arguments='--serve';WorkingDirectory=$versionTarget});
  Principal=[pscustomobject]@{UserId='S-1-5-21-1-2-3-1001';RunLevel='Highest';LogonType='Interactive'} }
}
function Export-ScheduledTask { param($TaskName,$TaskPath) return [IO.File]::ReadAllText((Join-Path $packageRoot 'task.xml')) }
function Set-Acl { param($LiteralPath, $AclObject)
 if (!$LiteralPath.StartsWith($brokerRoot)) { throw 'fixture_acl_scope' }
}
function Assert-FlowerAcl { param($path)
 if ($script:aclFails) { throw 'installation_acl_changed' }
 Assert-FlowerIntegrity $path
}
function Assert-FlowerCopiedFileAccess { param($path) if($script:aclFails){throw 'installation_acl_changed'} }
function Assert-Fixture($condition, $message) { if (!$condition) { throw ('fixture_assert:' + $message) } }
function Invoke-FixtureScript([string]$name, [switch]$Resume, [hashtable]$SetupArguments=@{}) {
 $text = Get-Content -LiteralPath (Join-Path $packageRoot $name) -Raw
 # Import already happened above. Override only system calls in this fixture.
 $text = $text -replace '(?m)^\. \(Join-Path \$PSScriptRoot ''InstallCommon.ps1''\)\r?\n', ''
 if ($Resume) { & ([scriptblock]::Create($text)) -Resume @SetupArguments }
 else { & ([scriptblock]::Create($text)) @SetupArguments }
}
"""
        fixture.write_text(prefix.replace('__EXPECTED_MAJOR__',str(expected_major)) + body + "\nWrite-Output 'fixture_passed'\n", encoding="utf-8-sig")
        environment = dict(os.environ)
        # PowerShell 7's inherited module path can hide built-in Windows
        # PowerShell modules in a new 5.1 process. Let that process use defaults.
        environment.pop("PSModulePath", None)
        environment.pop("PSMODULEPATH", None)
        result = subprocess.run([str(powershell), "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(fixture)],
                                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
                                creationflags=subprocess.CREATE_NO_WINDOW, env=environment)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("fixture_passed", result.stdout)

    def test_all_generated_scripts_parse_as_powershell(self):
        self.run_ps("""
foreach ($file in Get-ChildItem -LiteralPath $packageRoot -Filter '*.ps1') {
 $tokens = $null; $errors = $null
 [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors) | Out-Null
 Assert-Fixture ($errors.Count -eq 0) ('syntax:' + $file.Name)
}
""")

    def test_replaced_package_manifest_rejects_before_task_or_install_in_both_hosts(self):
        body=r"""
$activePath=Join-Path $packageRoot 'active.json'
$active=Get-Content -LiteralPath $activePath -Raw -Encoding UTF8|ConvertFrom-Json
$active.hashes.'broker.json'='0'*64
[IO.File]::WriteAllText($activePath,($active|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
function Get-FlowerTask{throw 'fixture_scheduler_must_not_run'}
$rejected=$false
try{Invoke-FixtureScript 'ApplyInstall.ps1'}catch{
 if($_.Exception.Message -ceq 'fixture_scheduler_must_not_run'){throw}
 $rejected=$true
}
Assert-Fixture $rejected 'fixed active SHA rejects substituted manifest'
Assert-Fixture (!(Test-Path -LiteralPath $brokerRoot)) 'manifest replacement had no installation effect'
"""
        self.run_ps(body)
        if shutil.which('pwsh'):
            self.setUp()
            self.run_ps(body,powershell=shutil.which('pwsh'),expected_major=7)

    def test_resume_anchor_pins_material_and_preserves_binding_in_both_hosts(self):
        body=r"""
Add-Type -TypeDefinition @'
using System;using System.IO;
public static class FixtureAnchorStore {
 public static string Root;
 public static string CreateLogDirectory(string op,string sid){string p=Path.Combine(Root,"recovery","installation-"+op);Directory.CreateDirectory(p);return p;}
 public static string RequireLogDirectory(string op,string sid){return CreateLogDirectory(op,sid);}
 public static void RequireProtectedFile(string p){if(!p.StartsWith(Root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new IOException("fixture_anchor_scope");}
}
'@
[FixtureAnchorStore]::Root=$brokerRoot
$body=(Get-Item Function:\Write-FlowerResumeAnchor).ScriptBlock.ToString()
$body=$body.Replace('[FlowerPinnedDelivery]::RequireLogDirectory','[FixtureAnchorStore]::RequireLogDirectory').Replace('[FlowerPinnedDelivery]::CreateLogDirectory','[FixtureAnchorStore]::CreateLogDirectory').Replace('[FlowerRecoveryProtection]::RequireProtectedFile','[FixtureAnchorStore]::RequireProtectedFile')
Set-Item Function:\Write-FlowerResumeAnchor ([scriptblock]::Create($body))
function Assert-FlowerInstallParent($path){}
New-Item -ItemType Directory -Path $brokerRoot|Out-Null
Set-FlowerProtection $brokerRoot
$outer=Join-Path $packageRoot 'ApplySetup.ps1';[IO.File]::WriteAllText($outer,'# fixture only')
$outerHash=(Get-FileHash -LiteralPath $outer -Algorithm SHA256).Hash.ToLowerInvariant()
$planPath=Join-Path $packageRoot 'setup-plan.json';$op='c'*32
$plan=[ordered]@{operation_id=$op;program_root=$brokerRoot;root=[IO.Path]::GetDirectoryName($brokerRoot);elevated_script=$outer;elevated_script_sha256=$outerHash;version=$version}
[IO.File]::WriteAllText($planPath,($plan|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
$planHash=(Get-FileHash -LiteralPath $planPath -Algorithm SHA256).Hash.ToLowerInvariant()
$path=Write-FlowerResumeAnchor 'setup' $op $planPath $planHash $outer $outerHash
$anchor=Get-Content -LiteralPath $path -Raw -Encoding UTF8|ConvertFrom-Json
Assert-Fixture ($anchor.state -ceq 'incomplete' -and $anchor.plan_sha256 -ceq $planHash -and $anchor.script_sha256 -ceq $outerHash) 'anchor binds original materials'
$failed=$false;try{Write-FlowerResumeAnchor 'setup' $op $planPath $planHash $outer ('0'*64)|Out-Null}catch{$failed=$true}
Assert-Fixture $failed 'changed material hash rejected'
$null=Write-FlowerResumeAnchor 'setup' $op $planPath $planHash $outer $outerHash 'completed'
$done=Get-Content -LiteralPath $path -Raw -Encoding UTF8|ConvertFrom-Json
Assert-Fixture ($done.state -ceq 'completed' -and $done.plan_sha256 -ceq $planHash) 'only state updated for same binding'
"""
        self.run_ps(body)
        if shutil.which('pwsh'):
            self.setUp()
            self.run_ps(body,powershell=shutil.which('pwsh'),expected_major=7)

    def test_registered_task_security_rejects_unprivileged_mutation(self):
        self.run_ps(r"""
Assert-FlowerTaskSecurity
foreach ($descriptor in @(
 'O:BUG:BAD:P(A;;FA;;;BA)',
 'O:BAG:BAD:P(A;;FA;;;BU)',
 'O:BAG:BAD:P(A;;GW;;;AU)',
 'O:BAG:BAD:P(A;;WD;;;BU)',
 'O:BAG:BAD:P(A;;WO;;;BU)',
 'O:BAG:BAD:P(A;;SD;;;BU)',
 'O:BAG:BA')) {
 $script:taskSecurity = $descriptor
 try { Assert-FlowerTaskSecurity; throw 'unexpected_success' }
 catch { Assert-Fixture ($_.Exception.Message -eq 'task_security_unprotected') 'unsafe scheduler descriptor rejected' }
}
""")

    def test_integrity_layout_exact_images_and_fail_closed_readback(self):
        self.run_ps(r"""
Invoke-FixtureScript 'ApplyInstall.ps1'
foreach ($path in @($brokerRoot, (Join-Path $brokerRoot 'versions'), $versionTarget,
                   (Join-Path $brokerRoot 'active.json'), (Join-Path $versionTarget 'broker.json'))) {
 Assert-Fixture ($script:labels[$path] -ceq 'S:PAI(ML;;NW;;;HI)') 'explicit noninheriting High with real outer control flags'
}
Assert-Fixture ($script:labelWrites -notcontains $command) 'dual-role image never labelled'
foreach ($name in @('Flower.HighHelper.exe','uac-witness-baseline.exe','uac-witness-moved.exe','uac-witness-decoy.exe')) {
 $path = Join-Path $versionTarget $name
 if (!(Test-Path -LiteralPath $path)) { [IO.File]::WriteAllText($path, 'fixture') }
 Set-FlowerProtection $path
 Assert-Fixture ($script:labelWrites -notcontains $path) 'exact image exemption'
 $script:labels[$path] = 'S:(ML;;NW;;;HI)'
 try { Assert-FlowerIntegrity $path; throw 'unexpected_success' }
 catch { Assert-Fixture ($_.Exception.Message -eq 'installation_image_label_would_demote_system') 'labelled image rejected' }
 $script:labels.Remove($path)
}
foreach ($name in @('Flower.HighHelper.dll','uac-witness-extra.exe','uac-proof.json')) {
 $path = Join-Path $versionTarget $name
 [IO.File]::WriteAllText($path, 'fixture')
 Set-FlowerProtection $path
 Assert-Fixture ($script:labels[$path] -ceq 'S:PAI(ML;;NW;;;HI)') 'no wildcard image exemption'
 foreach ($bad in @('', 'S:(ML;OICI;NW;;;HI)', 'S:(ML;;NW;;;ME)', 'S:(ML;;NR;;;HI)')) {
  $script:labels[$path] = $bad
  try { Assert-FlowerIntegrity $path; throw 'unexpected_success' }
  catch { Assert-Fixture ($_.Exception.Message -eq 'installation_high_label_changed') 'wrong High label rejected' }
 }
}
$nested = Join-Path $versionTarget 'sub'
New-Item -ItemType Directory -Path $nested | Out-Null
$nestedImage = Join-Path $nested 'Flower.HighHelper.exe'
[IO.File]::WriteAllText($nestedImage, 'fixture')
Set-FlowerProtection $nestedImage
Assert-Fixture ($script:labels[$nestedImage] -ceq 'S:PAI(ML;;NW;;;HI)') 'nested basename not exempt'
$before = $script:labelWrites.Count
foreach ($outside in @($versionSource, (Join-Path $brokerRoot 'versions\old'), ($versionTarget + '-sibling'), ($versionTarget + '\..\escape'))) {
 try { Set-FlowerProtection $outside; throw 'unexpected_success' }
 catch { Assert-Fixture ($_.Exception.Message -eq 'installation_protection_scope_rejected') 'outside scope rejected' }
}
Assert-Fixture ($script:labelWrites.Count -eq $before) 'outside scope not relabelled'
""")

    def test_resume_rejects_changed_integrity_before_registration(self):
        self.run_ps(r"""
$script:registrationFails = $true
try { Invoke-FixtureScript 'ApplyInstall.ps1' } catch { if ($_.Exception.Message -ne 'fixture_registration_failed') { throw } }
$script:registrationFails = $false
$script:labels[$versionTarget] = 'S:(ML;OICI;NW;;;HI)'
try { Invoke-FixtureScript 'ApplyInstall.ps1' -Resume; throw 'unexpected_success' }
catch { Assert-Fixture ($_.Exception.Message -eq 'installation_high_label_changed') 'resume reads exact directory label' }
Assert-Fixture ($script:registered -eq 1) 'registration not retried on changed label'
""")

    def test_integrity_descriptor_accepts_outer_flags_but_exact_label_ace_only(self):
        self.run_ps(r"""
New-Item -ItemType Directory -Path $versionTarget -Force | Out-Null
$path = Join-Path $versionTarget 'Flower.HighHelper.dll'
[IO.File]::WriteAllText($path, 'fixture')
foreach ($outer in @('', 'P', 'AI', 'AR', 'PAI', 'PAIAR', 'ARPAI', 'AIPAR', 'ARAI')) {
 $script:labels[$path] = 'S:' + $outer + '(ML;;NW;;;HI)'
 Assert-FlowerIntegrity $path
 $script:labels[$path] = 'S:' + $outer + '(ML;;0x1;;;S-1-16-12288)'
 Assert-FlowerIntegrity $path
}
$bad = @('', 'S:', 'S:PAINO_ACCESS_CONTROL', 'O:BAG:BA', 'not-a-security-descriptor',
 'S:PAI(ML;;NW;;;HI)(ML;;NW;;;HI)', 'S:PAI(ML;;NW;;;HI)(ML;;NW;;;ME)',
 'S:PAI(AU;SA;GR;;;WD)', 'S:PAI(AU;SA;GR;;;WD)(ML;;NW;;;HI)',
 'S:PAI(ML;;NW;;;ME)', 'S:PAI(ML;;NW;;;LW)', 'S:PAI(ML;;NW;;;SI)',
 'S:PAI(ML;;NW;;;S-1-16-12289)', 'S:PAI(ML;;NW;;;SY)',
 'S:PAI(ML;;NR;;;HI)', 'S:PAI(ML;;NX;;;HI)', 'S:PAI(ML;;NWNR;;;HI)',
 'S:PAI(ML;;NWNX;;;HI)', 'S:PAI(ML;;0x0;;;HI)', 'S:PAI(ML;;0x8;;;HI)')
foreach ($flags in @('OI','CI','NP','IO','ID','OICI','OIIO','CIID')) { $bad += 'S:PAI(ML;' + $flags + ';NW;;;HI)' }
foreach ($label in $bad) {
 $script:labels[$path] = $label
 try { Assert-FlowerIntegrity $path; throw 'unexpected_success' }
 catch { Assert-Fixture ($_.Exception.Message -eq 'installation_high_label_changed') ('unsafe label rejected:' + $label) }
}
foreach ($name in @('Flower.HighHelper.exe','uac-witness-baseline.exe','uac-witness-moved.exe','uac-witness-decoy.exe')) {
 $image = Join-Path $versionTarget $name
 [IO.File]::WriteAllText($image, 'fixture')
 foreach ($label in @('', 'S:', 'S:PAINO_ACCESS_CONTROL', 'O:BAG:BA')) {
  $script:labels[$image] = $label; Assert-FlowerIntegrity $image
 }
 foreach ($label in @('S:PAI(ML;;NW;;;HI)', 'S:ARPAI(ML;;NR;;;LW)', 'S:PAI(ML;IO;NW;;;HI)',
                     'S:PAI(ML;;NW;;;HI)(ML;;NW;;;HI)', 'not-a-security-descriptor')) {
  $script:labels[$image] = $label
  try { Assert-FlowerIntegrity $image; throw 'unexpected_success' }
  catch { Assert-Fixture ($_.Exception.Message -eq 'installation_image_label_would_demote_system') 'any image label or malformed descriptor rejected' }
 }
}
Assert-Fixture ($script:labelWrites.Count -eq 0) 'descriptor validation never writes labels'
""")

    def test_integrity_read_error_is_not_an_absent_label(self):
        self.run_ps(r"""
New-Item -ItemType Directory -Path $versionTarget -Force | Out-Null
function Get-FlowerIntegritySddl($path) { throw 'installation_label_unreadable:5' }
foreach ($name in @('Flower.HighHelper.exe', 'Flower.HighHelper.dll')) {
 $path = Join-Path $versionTarget $name
 [IO.File]::WriteAllText($path, 'fixture')
 try { Assert-FlowerIntegrity $path; throw 'unexpected_success' }
 catch { Assert-Fixture ($_.Exception.Message -eq 'installation_label_unreadable:5') 'unreadable label is not exemption or valid High' }
}
Assert-Fixture ($script:labelWrites.Count -eq 0 -and $script:registered -eq 0) 'failed read never writes or registers'
""")

    def test_label_failure_or_link_prevents_registration_and_protection(self):
        self.run_ps(r"""
function Set-FlowerHighLabel($path) { throw 'installation_high_label_not_applied' }
try { Invoke-FixtureScript 'ApplyInstall.ps1'; throw 'unexpected_success' }
catch { Assert-Fixture ($_.Exception.Message -eq 'installation_high_label_not_applied') 'label write failure retained' }
Assert-Fixture ($script:registered -eq 0) 'failed protection never registers task'
function Set-FlowerHighLabel($path) { $script:labelWrites += $path }
try { Set-FlowerProtection $brokerRoot; throw 'unexpected_success' }
catch { Assert-Fixture ($_.Exception.Message -eq 'installation_high_label_changed') 'successful writer still requires readback' }
$before = $script:labelWrites.Count
function Get-Item { param($LiteralPath,[switch]$Force)
 return [pscustomobject]@{Attributes=[IO.FileAttributes]::ReparsePoint;FullName=$LiteralPath;PSIsContainer=$true}
}
try { Set-FlowerProtection $brokerRoot; throw 'unexpected_success' }
catch { Assert-Fixture ($_.Exception.Message -eq 'installation_link_rejected') 'link rejected before writes' }
Assert-Fixture ($script:labelWrites.Count -eq $before) 'linked target never relabelled'
""")

    def test_native_integrity_reader_compiles_in_windows_powershell(self):
        # The real LABEL_SECURITY_INFORMATION getter reads only an owned temp
        # fixture. No SACL/DACL write, installer, scheduler or elevation.
        self.run_ps(r"""
Remove-Item Function:\Get-FlowerIntegritySddl
. (Join-Path $packageRoot 'InstallCommon.ps1')
$label = Get-FlowerIntegritySddl (Join-Path $versionSource 'Flower.HighHelper.exe')
Assert-Fixture ($label -notmatch '\(ML;') 'owned default temp fixture has no explicit label'
Assert-Fixture ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -eq 1) 'actual Windows PowerShell 5.1'
""")

    def test_disable_task_succeeds_with_unavailable_broker_and_preserves_unknown(self):
        self.run_ps("""
$script:task = [pscustomobject]@{ Settings = [pscustomobject]@{ Enabled = $true } }
function Invoke-FlowerAdmin($operation) { $script:adminCalls += $operation; throw 'fixture_pipe_unavailable' }
$result = Invoke-FixtureScript 'Disable.ps1' | ConvertFrom-Json
Assert-Fixture ($script:disabled -eq 1 -and !$script:task.Settings.Enabled) 'task disabled independently'
Assert-Fixture ($result.task_state -eq 'disabled' -and $result.broker_state -eq 'unknown' -and !$result.instance_stopped) 'unknown retained'
$script:task = $null
$absent = Invoke-FixtureScript 'Disable.ps1' | ConvertFrom-Json
Assert-Fixture ($absent.task_state -eq 'absent' -and !$absent.instance_stopped) 'absent task not stopped instance'
""")

    def test_disable_reads_exact_process_exit_after_pause_and_shutdown(self):
        self.run_ps("""
function Invoke-FlowerAdmin($operation) {
 $script:adminCalls += $operation
 $phase = if ($operation -eq 'status') { 'status' } else { 'control' }
 return [pscustomobject]@{ Phase=$phase; Command=$operation; Status=[pscustomobject]@{pid=900001;created=123;high_verified=$true} }
}
function Get-Process { [CmdletBinding()] param($Id)
 Assert-Fixture ($Id -eq 900001) 'exact PID only'
 return $null
}
$result = Invoke-FixtureScript 'Disable.ps1' | ConvertFrom-Json
Assert-Fixture (($script:adminCalls -join ',') -eq 'status,pause,shutdown') 'pause before shutdown'
Assert-Fixture ($result.instance_stopped -and $result.broker_state -eq 'stopped') 'exact instance exit confirmed'
""")

    def test_disable_does_not_treat_process_query_access_error_as_exit(self):
        self.run_ps("""
function Invoke-FlowerAdmin($operation) {
 $phase = if ($operation -eq 'status') { 'status' } else { 'control' }
 return [pscustomobject]@{ Phase=$phase; Command=$operation; Status=[pscustomobject]@{pid=900001;created=123;high_verified=$true} }
}
function Get-Process { [CmdletBinding()] param($Id) Write-Error 'fixture_access_denied' -ErrorId 'AccessDenied' }
$result = Invoke-FixtureScript 'Disable.ps1' | ConvertFrom-Json
Assert-Fixture (!$result.instance_stopped -and $result.broker_state -eq 'shutdown_pending') 'query error not exit proof'
Assert-Fixture ($result.instance_error -eq 'broker_exit_query_unconfirmed') 'query error preserved'
""")

    def test_ordinary_disable_binds_both_commands_and_keeps_existing_stop_in_both_hosts(self):
        body=r"""
$script:initialPaused=$false
function Invoke-FlowerAdmin($operation,$expected=$null) {
 $script:adminCalls += $operation
 if($operation -eq 'status') {
  Assert-Fixture ($null -eq $expected) 'status is read-only'
 } else {
  Assert-Fixture ($expected.broker_role -ceq 'ordinary' -and $expected.pid -eq 900001 -and $expected.created -eq 123) 'bound ordinary identity'
  Assert-Fixture ($expected.paused -eq ($operation -eq 'shutdown')) 'bound phase Stop state'
 }
 $phase=if($operation -eq 'status'){'status'}else{'control'}
 return [pscustomobject]@{Phase=$phase;Command=$operation;Status=[pscustomobject]@{
  pid=900001;created=123;high_verified=$false;ordinary_verified=$true;broker_role='ordinary';maintenance_protocol=2;
  paused=($operation -ne 'status' -or $script:initialPaused)} }
}
function Get-Process { [CmdletBinding()] param($Id) return $null }
$reply=Invoke-FixtureScript 'Disable.ps1'|ConvertFrom-Json
Assert-Fixture ($reply.instance_stopped -and $reply.broker_role -ceq 'ordinary') 'ordinary exit confirmed'
Assert-Fixture (Test-Path -LiteralPath $reply.result_path) 'observable independent receipt'
$saved=Get-Content -LiteralPath $reply.result_path -Raw -Encoding UTF8|ConvertFrom-Json
Assert-Fixture ($saved.instance_pid -eq 900001 -and $saved.instance_stopped) 'receipt matches exact process'
Assert-Fixture (($script:adminCalls -join ',') -ceq 'status,pause,shutdown') 'ordinary bound pause and shutdown'
$script:initialPaused=$true;$script:adminCalls=@()
$stopped=Invoke-FixtureScript 'Disable.ps1'|ConvertFrom-Json
Assert-Fixture ($stopped.instance_stopped -and ($script:adminCalls -join ',') -ceq 'status,shutdown') 'existing Stop not incremented'
"""
        self.run_ps(body)
        pwsh=shutil.which("pwsh")
        if pwsh:
            self.run_ps(body,powershell=pwsh,expected_major=7)

    def test_registration_failure_keeps_exact_version_and_can_finish_once(self):
        self.run_ps("""
$script:registrationFails = $true
try { Invoke-FixtureScript 'ApplyInstall.ps1'; throw 'unexpected_success' }
catch { if ($_.Exception.Message -ne 'fixture_registration_failed') { throw } }
Assert-Fixture (Test-Path -LiteralPath (Join-Path $brokerRoot 'active.json')) 'published active retained'
Assert-FlowerVersion $versionTarget
$script:registrationFails = $false
Invoke-FixtureScript 'ApplyInstall.ps1' -Resume
Assert-Fixture ($script:registered -eq 2 -and $null -ne $script:task) 'precise registration completed'
$again=Invoke-FixtureScript 'ApplyInstall.ps1' -Resume|ConvertFrom-Json
Assert-Fixture ($again.state -ceq 'installed_not_started' -and $script:registered -eq 2) 'same registered plan verified without duplicate registration'
""")

    def test_partial_first_install_resumes_only_missing_files_in_both_hosts(self):
        body=r"""
Add-Type -TypeDefinition @'
using System;using System.IO;
public static class FixtureEarlyAnchorStore {
 public static string Root;
 public static string CreateLogDirectory(string op,string sid){string p=Path.Combine(Root,"recovery","installation-"+op);Directory.CreateDirectory(p);return p;}
 public static string RequireLogDirectory(string op,string sid){return CreateLogDirectory(op,sid);}
 public static void RequireProtectedFile(string p){if(!p.StartsWith(Root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new IOException("fixture_anchor_scope");}
}
'@
[FixtureEarlyAnchorStore]::Root=$brokerRoot
$body=(Get-Item Function:\Write-FlowerResumeAnchor).ScriptBlock.ToString()
$body=$body.Replace('[FlowerPinnedDelivery]::RequireLogDirectory','[FixtureEarlyAnchorStore]::RequireLogDirectory').Replace('[FlowerPinnedDelivery]::CreateLogDirectory','[FixtureEarlyAnchorStore]::CreateLogDirectory').Replace('[FlowerRecoveryProtection]::RequireProtectedFile','[FixtureEarlyAnchorStore]::RequireProtectedFile')
Set-Item Function:\Write-FlowerResumeAnchor ([scriptblock]::Create($body))
function Assert-FlowerInstallParent($path){}
$outer=Join-Path $packageRoot 'ApplySetup.ps1';[IO.File]::WriteAllText($outer,'# fixture only')
$outerHash=(Get-FileHash -LiteralPath $outer -Algorithm SHA256).Hash.ToLowerInvariant()
$planPath=Join-Path $packageRoot 'setup-plan.json';$op='c'*32
$plan=[ordered]@{operation_id=$op;program_root=$brokerRoot;root=[IO.Path]::GetDirectoryName($brokerRoot);elevated_script=$outer;elevated_script_sha256=$outerHash;version=$version}
[IO.File]::WriteAllText($planPath,($plan|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
$planHash=(Get-FileHash -LiteralPath $planPath -Algorithm SHA256).Hash.ToLowerInvariant()
$setup=@{SetupOperationId=$op;SetupPlanPath=$planPath;SetupPlanSha256=$planHash;SetupScriptPath=$outer;ExpectedScriptSha256=$outerHash}
$anchorPath=Join-Path $brokerRoot ('recovery\installation-'+$op+'\resume-anchor.json')
$script:copyOriginal=(Get-Item Function:\Copy-FlowerInstallFile).ScriptBlock
$script:copyCount=0;$script:firstCopied=$null
function Copy-FlowerInstallFile($source,$target,$hash) {
 Assert-Fixture ($script:installOwner -and (Test-Path -LiteralPath $anchorPath)) 'protected operation owner and anchor precede copying'
 $script:copyCount++
 if($script:copyCount -eq 2){throw 'fixture_copy_interrupted'}
 & $script:copyOriginal $source $target $hash
 if($null -eq $script:firstCopied){$script:firstCopied=$target}
}
try{Invoke-FixtureScript 'ApplyInstall.ps1' -SetupArguments $setup;throw 'unexpected_success'}catch{Assert-Fixture ($_.Exception.Message -ceq 'fixture_copy_interrupted') 'copy interruption retained'}
Assert-Fixture (!(Test-Path -LiteralPath (Join-Path $brokerRoot 'active.json')) -and (Test-Path -LiteralPath $script:firstCopied)) 'partial version exists before active'
Assert-Fixture ($script:registered -eq 0) 'no task after partial copy'
$anchor=Get-Content -LiteralPath $anchorPath -Raw -Encoding UTF8|ConvertFrom-Json
Assert-Fixture ($anchor.state -ceq 'incomplete' -and $anchor.plan_sha256 -ceq $planHash -and $anchor.script_sha256 -ceq $outerHash) 'interrupted copy already has material-bound recovery anchor'
Set-Item Function:\Copy-FlowerInstallFile $script:copyOriginal
$pin=[IO.File]::Open($script:firstCopied,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
try{$done=Invoke-FixtureScript 'ApplyInstall.ps1' -Resume -SetupArguments $setup|ConvertFrom-Json}finally{$pin.Dispose()}
Assert-Fixture ($done.state -ceq 'installed_not_started' -and $script:registered -eq 1) 'same plan resumed without overwriting pinned published bytes'
$receipt=Get-Content -LiteralPath $done.result_path -Raw -Encoding UTF8|ConvertFrom-Json
Assert-Fixture ($receipt.completed -and $receipt.completed_stages -contains 'version_verified') 'durable phase receipt complete'
"""
        self.run_ps(body)
        if shutil.which("pwsh"):
            self.setUp()
            self.run_ps(body,powershell=shutil.which("pwsh"),expected_major=7)

    def test_retained_root_reinstalls_preserving_state_and_rejects_foreign_or_live_root_in_both_hosts(self):
        body=r"""
Add-Type -TypeDefinition @'
using System;using System.IO;
public static class FixtureRetainedStore {
 public static string Root;
 public static void RequireProtectedFile(string p){if(!p.StartsWith(Root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))throw new IOException("fixture_anchor_scope");}
}
'@
[FixtureRetainedStore]::Root=$brokerRoot
$body=(Get-Item Function:\Test-FlowerRetainedRoot).ScriptBlock.ToString().Replace('[FlowerRecoveryProtection]::RequireProtectedFile','[FixtureRetainedStore]::RequireProtectedFile')
Set-Item Function:\Test-FlowerRetainedRoot ([scriptblock]::Create($body))
function Assert-FlowerInstallParent($path){}
$installRoot=[IO.Path]::GetDirectoryName($brokerRoot)
$script:location=[pscustomobject]@{root=$installRoot;program_root=$brokerRoot;packages_root=(Join-Path $installRoot 'Packages')}
function Get-FlowerLocationRequest{return $script:location}
function Register-FlowerInstallLocation{}
function Initialize-FlowerInstallLayout([switch]$Resume){Assert-Fixture $Resume 'retained layout reuses data/cache'}
$script:retainedMetadataChecks=0
function Assert-FlowerRetainedMetadata{
 Assert-Fixture (!(Test-Path -LiteralPath (Join-Path $brokerRoot 'active.json'))) 'metadata validated before active publication'
 $script:retainedMetadataChecks++
}
$script:processes=@()
function Get-CimInstance {param($ClassName) Assert-Fixture ($ClassName -ceq 'Win32_Process') 'read-only process query';return $script:processes}
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$op='d'*32
New-Item -ItemType Directory -Path (Join-Path $brokerRoot ('recovery\installation-'+$op)) -Force|Out-Null
Set-FlowerProtection $brokerRoot
$anchorPath=Join-Path $brokerRoot ('recovery\installation-'+$op+'\resume-anchor.json')
$anchor=[ordered]@{schema=1;kind='uninstall';state='completed';user_sid=$sid;root=$installRoot;program_root=$brokerRoot;
 installation_id=('b'*32);operation_id=$op;machine_binding_sha256=('e'*64)}
function Save-FixtureAnchor{[IO.File]::WriteAllText($anchorPath,($anchor|ConvertTo-Json),[Text.UTF8Encoding]::new($false))}
Save-FixtureAnchor
$before=@{}
foreach($relative in @(('permissions\'+$sid+'.json'),'privacy\sensitive-words.txt',('work-authority\'+('1'*64)+'\writer.lock'),
 ('audit\'+('1'*64)+'\00000001.jsonl'),('execution-bindings\'+('1'*64)+'\old.json.blocked'),
 ('recovery\stop\'+$sid+'.1.json'),('recovery\ordinary-stop\'+$sid+'.1.global.bin'),'recovery\uac\unknown.json')){
 $path=Join-Path $brokerRoot $relative;New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($path)) -Force|Out-Null
 [IO.File]::WriteAllText($path,'opaque preserved fixture');$before[$path]=(Get-FileHash -LiteralPath $path).Hash
}
foreach($folder in @('Data','Cache')){
 $path=Join-Path $installRoot ($folder+'\personal.txt');New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($path)) -Force|Out-Null
 [IO.File]::WriteAllText($path,'personal retained fixture');$before[$path]=(Get-FileHash -LiteralPath $path).Hash
}
Assert-Fixture (Test-FlowerRetainedRoot) 'same machine completed uninstall recognizes retained layout'
$anchor.machine_binding_sha256='f'*64;Save-FixtureAnchor
Assert-Fixture (!(Test-FlowerRetainedRoot)) 'cross machine authority is not reused'
$anchor.machine_binding_sha256='e'*64;$anchor.user_sid='S-1-5-21-1-2-3-9999';Save-FixtureAnchor
Assert-Fixture (!(Test-FlowerRetainedRoot)) 'other SID is not reused'
$anchor.user_sid=$sid;$anchor.state='incomplete';Save-FixtureAnchor
Assert-Fixture (!(Test-FlowerRetainedRoot)) 'incomplete uninstall cannot be a fresh install'
$anchor.state='completed';Save-FixtureAnchor
$foreign=Join-Path $brokerRoot 'unowned.exe';[IO.File]::WriteAllText($foreign,'foreign')
Assert-Fixture (!(Test-FlowerRetainedRoot)) 'unknown extra program file is not adopted'
[IO.File]::Move($foreign,(Join-Path $PSScriptRoot 'unowned-kept.exe'))
$script:processes=@([pscustomobject]@{Name='Flower.HighHelper.exe';ExecutablePath=(Join-Path $brokerRoot 'versions\old\Flower.HighHelper.exe')})
$failed=$false;try{Test-FlowerRetainedRoot|Out-Null}catch{Assert-Fixture ($_.Exception.Message -ceq 'retained_installation_process_still_running') 'running instance exact rejection';$failed=$true}
Assert-Fixture $failed 'running instance prevents reinstall'
$script:processes=@()
$done=Invoke-FixtureScript 'ApplyInstall.ps1'|ConvertFrom-Json
Assert-Fixture ($done.state -ceq 'installed_not_started' -and $script:registered -eq 1) 'original root can reinstall'
Assert-Fixture ($script:retainedMetadataChecks -eq 1) 'new-layout retained metadata validator is required'
foreach($path in $before.Keys){Assert-Fixture ((Get-FileHash -LiteralPath $path).Hash -ceq $before[$path]) 'retained authority Stop unknown bytes preserved'}
"""
        self.target=self.root/"FlowerControl"/"Program"
        for name,content in render_install_scripts(self.package,self.target,self.version,"Exact.Fixture.Task").items():
            (self.package/name).write_text(content,encoding="utf-8-sig")
        self.run_ps(body)
        if shutil.which("pwsh"):
            self.setUp()
            self.target=self.root/"FlowerControl"/"Program"
            for name,content in render_install_scripts(self.package,self.target,self.version,"Exact.Fixture.Task").items():
                (self.package/name).write_text(content,encoding="utf-8-sig")
            self.run_ps(body,powershell=shutil.which("pwsh"),expected_major=7)

    def test_legacy_install_keeps_fixed_root_without_new_layout_validator_in_both_hosts(self):
        body=r"""
function Assert-FlowerRetainedMetadata{throw 'fixture_legacy_cannot_enter_new_layout_validator'}
Assert-Fixture ($null -eq (Get-FlowerLocationRequest)) 'legacy has no new-layout request'
$done=Invoke-FixtureScript 'ApplyInstall.ps1'|ConvertFrom-Json
Assert-Fixture ($done.state -ceq 'installed_not_started' -and $script:registered -eq 1) 'legacy fixed-root install remains available'
"""
        self.run_ps(body)
        if shutil.which("pwsh"):
            self.setUp()
            self.run_ps(body,powershell=shutil.which("pwsh"),expected_major=7)

    def test_registered_task_with_lost_reply_is_verified_without_register_replay_in_both_hosts(self):
        body=r"""
$script:registerOriginal=(Get-Item Function:\Register-ScheduledTask).ScriptBlock
function Register-ScheduledTask($TaskName,$TaskPath,$Xml) {
 & $script:registerOriginal $TaskName $TaskPath $Xml
 throw 'fixture_registration_reply_lost'
}
try{Invoke-FixtureScript 'ApplyInstall.ps1';throw 'unexpected_success'}catch{Assert-Fixture ($_.Exception.Message -ceq 'fixture_registration_reply_lost') 'unknown registration receipt preserved'}
Assert-Fixture ($script:registered -eq 1 -and $null -ne $script:task) 'task actually registered before lost reply'
Set-Item Function:\Register-ScheduledTask $script:registerOriginal
$script:task.Actions[0].Arguments='--changed'
try{Invoke-FixtureScript 'ApplyInstall.ps1' -Resume;throw 'unexpected_success'}catch{Assert-Fixture ($_.Exception.Message -ceq 'installed_task_identity_changed') 'changed task never adopted'}
$script:task.Actions[0].Arguments='--serve'
$done=Invoke-FixtureScript 'ApplyInstall.ps1' -Resume|ConvertFrom-Json
Assert-Fixture ($done.state -ceq 'installed_not_started' -and $script:registered -eq 1) 'accurate task verified without replay'
$again=Invoke-FixtureScript 'ApplyInstall.ps1' -Resume|ConvertFrom-Json
Assert-Fixture ($again.state -ceq 'installed_not_started' -and $script:registered -eq 1) 'completed resume idempotent'
"""
        self.run_ps(body)
        if shutil.which("pwsh"):
            self.setUp()
            self.run_ps(body,powershell=shutil.which("pwsh"),expected_major=7)

    def test_resume_rejects_different_installed_bytes_acl_and_source(self):
        self.run_ps("""
$script:registrationFails = $true
try { Invoke-FixtureScript 'ApplyInstall.ps1' } catch { if ($_.Exception.Message -ne 'fixture_registration_failed') { throw } }
$script:registrationFails = $false
$script:aclFails = $true
try { Invoke-FixtureScript 'ApplyInstall.ps1' -Resume; throw 'unexpected_success' }
catch { Assert-Fixture ($_.Exception.Message -eq 'installation_acl_changed') 'changed ACL rejected' }
$script:aclFails = $false
$exe = Join-Path $versionTarget 'Flower.HighHelper.exe'
[IO.File]::WriteAllText($exe, 'modified')
try { Invoke-FixtureScript 'ApplyInstall.ps1' -Resume; throw 'unexpected_success' }
catch { Assert-Fixture ($_.Exception.Message -eq 'install_existing_file_changed') 'changed installed bytes rejected' }
Assert-Fixture ([IO.File]::ReadAllText($exe) -ceq 'modified') 'changed installed bytes never overwritten'
Copy-Item -LiteralPath (Join-Path $versionSource 'Flower.HighHelper.exe') -Destination $exe
$policy = Get-Content -LiteralPath (Join-Path $versionSource 'broker.json') -Raw | ConvertFrom-Json
[IO.File]::WriteAllText((Join-Path $policy.Repository 'flower.py'), 'changed Python')
try { Invoke-FixtureScript 'ApplyInstall.ps1' -Resume; throw 'unexpected_success' }
catch { Assert-Fixture ($_.Exception.Message -eq 'matching_python_source_required') 'changed source rejected' }
Assert-Fixture ($script:registered -eq 1) 'no resumed registration on mismatch'
""")

    def test_saved_snapshot_alone_does_not_make_old_rollback_source_match(self):
        self.run_ps("""
Invoke-FixtureScript 'CheckRollbackSource.ps1'
$policy = Get-Content -LiteralPath (Join-Path $versionSource 'broker.json') -Raw | ConvertFrom-Json
[IO.File]::WriteAllText((Join-Path $policy.Repository 'flower.py'), 'changed Python')
try { Invoke-FixtureScript 'CheckRollbackSource.ps1'; throw 'unexpected_success' }
catch { Assert-Fixture ($_.Exception.Message -eq 'matching_python_source_required') 'old runtime source must match'
}
Assert-Fixture ([IO.File]::ReadAllText((Join-Path $policy.Repository 'flower.py')) -eq 'changed Python') 'dirty source not overwritten'
""")

    def test_frozen_package_ignores_live_source_edits_but_rejects_own_dependency_tamper(self):
        frozen = self.source / "python-source"
        frozen.mkdir()
        shutil.copyfile(self.repo / "flower.py", frozen / "flower.py")
        dependency = self.source / "runtime/Lib/fixed.py"
        dependency.parent.mkdir(parents=True)
        dependency.write_text("# fixed dependency\n")
        files = {"python-source/flower.py": digest(frozen / "flower.py"),
                 "runtime/Lib/fixed.py": digest(dependency)}
        write_json(self.source / "runtime-inventory.json", {"schema": 1, "files": files})
        policy = json.loads((self.source / "broker.json").read_bytes())
        policy.update(Repository=str(self.target / "versions" / self.version / "python-source"),
                      RuntimeInventorySha256=digest(self.source / "runtime-inventory.json"))
        write_json(self.source / "broker.json", policy)
        active = dict(schema=1, version=self.version, runtime_hashes=files,
                      hashes={p.name: digest(p) for p in self.source.iterdir()
                              if p.is_file() and p.name != "installation.json"})
        write_json(self.package / "active.json", active)
        write_json(self.source / "installation.json", active)
        for name,content in render_install_scripts(self.package,self.target,self.version,"Exact.Fixture.Task").items():
            (self.package/name).write_text(content,encoding='utf-8-sig')
        self.run_ps("""
Assert-FlowerVersion $versionSource
Assert-FlowerSource
[IO.File]::WriteAllText((Join-Path $PSScriptRoot 'repo\\flower.py'), 'later foreign dirty')
Assert-FlowerSource
[IO.File]::WriteAllText((Join-Path $versionSource 'runtime\\Lib\\fixed.py'), 'modified dependency')
try { Assert-FlowerVersion $versionSource; throw 'unexpected_success' }
catch { Assert-Fixture ($_.Exception.Message -eq 'runtime_snapshot_hash_changed') 'dependency mismatch rejected' }
Assert-Fixture ([IO.File]::ReadAllText((Join-Path $PSScriptRoot 'repo\\flower.py')) -eq 'later foreign dirty') 'live source preserved'
""")

    def test_wgc_companion_exact_inventory_and_hash_are_verified(self):
        companion = self.source / "wgc/Flower.ComputerWgc.exe"
        companion.parent.mkdir()
        companion.write_bytes(b"fixture-only-wgc-not-executable")
        policy = json.loads((self.source / "broker.json").read_bytes())
        policy["WgcWorkerHashes"] = {companion.name: digest(companion)}
        write_json(self.source / "broker.json", policy)
        active = dict(schema=1, version=self.version, hashes={p.name:digest(p) for p in self.source.iterdir()
                      if p.is_file() and p.name != "installation.json"})
        write_json(self.package / "active.json", active)
        write_json(self.source / "installation.json", active)
        for name,content in render_install_scripts(self.package,self.target,self.version,"Exact.Fixture.Task").items():
            (self.package/name).write_text(content,encoding='utf-8-sig')
        self.run_ps("""
Assert-FlowerVersion $versionSource
[IO.File]::WriteAllText((Join-Path $versionSource 'wgc\\Flower.ComputerWgc.exe'), 'mutated')
try { Assert-FlowerVersion $versionSource; throw 'unexpected_success' }
catch { Assert-Fixture ($_.Exception.Message -eq 'wgc_version_hash_changed') 'WGC tamper rejected' }
""")


class SourceSnapshotTests(unittest.TestCase):
    def test_media_encoder_license_prefers_adjacent_and_retains_legacy_layout(self):
        with tempfile.TemporaryDirectory(prefix="flower-media-license-") as directory:
            root = Path(directory)
            encoder = root / "bin/ffmpeg.exe"
            encoder.parent.mkdir()
            encoder.write_bytes(b"fixture-only-not-an-executable")
            (root / "LICENSE").write_text("legacy layout\n", encoding="utf-8")
            self.assertEqual(media_encoder_license(encoder), root / "LICENSE")
            (encoder.parent / "LICENSE").write_text("frozen version layout\n", encoding="utf-8")
            self.assertEqual(media_encoder_license(encoder), encoder.parent / "LICENSE")
            (encoder.parent / "LICENSE").unlink()
            (root / "LICENSE").unlink()
            with self.assertRaisesRegex(ValueError, "media_encoder_license_required"):
                media_encoder_license(encoder)

    def test_binary_changed_during_copy_cannot_be_sealed_as_old_build(self):
        with tempfile.TemporaryDirectory(prefix="flower-copy-race-") as directory:
            root = Path(directory)
            original, saved = root / "built.exe", root / "copied.exe"
            original.write_bytes(b"verified build")
            expected = digest(original)
            shutil.copyfile(original, saved)
            verify_sealed_inputs([(original, saved, expected)])
            # Both sides agree with each other but no longer with the build.
            original.write_bytes(b"changed during dependency snapshot")
            shutil.copyfile(original, saved)
            with self.assertRaisesRegex(RuntimeError, "input_changed_before_seal"):
                verify_sealed_inputs([(original, saved, expected)])
            original.write_bytes(b"verified build")
            with self.assertRaisesRegex(RuntimeError, "input_changed_before_seal"):
                verify_sealed_inputs([(original, saved, expected)])

    def test_current_sources_and_binaries_must_both_match_successful_build(self):
        with tempfile.TemporaryDirectory(prefix="flower-build-evidence-contract-") as directory:
            root = Path(directory).resolve()
            evidence_path = root / "build.json"
            source = {"source.cs": "a" * 64}
            binary = {"helper.exe": "b" * 64}
            for kind in ("native", "app"):
                evidence = dict(schema=1, build_exit_code=0, source_hashes=source, binary_hashes=binary)
                evidence[kind + "_bin"] = str(root)
                write_json(evidence_path, evidence)
                self.assertEqual(validate_build_evidence(evidence_path, root, source, binary, kind=kind), evidence)
                for field, changed in (("source_hashes", {}), ("binary_hashes", {}), ("build_exit_code", 1),
                                       (kind + "_bin", str(root / "other")), ("schema", 0)):
                    with self.subTest(kind=kind, field=field):
                        write_json(evidence_path, {**evidence, field: changed})
                        with self.assertRaisesRegex(RuntimeError, "current_" + kind + "_build_evidence_required"):
                            validate_build_evidence(evidence_path, root, source, binary, kind=kind)

    def test_snapshot_keeps_dirty_bytes_and_rejects_changed_expected_hash(self):
        with tempfile.TemporaryDirectory(prefix="flower-source-snapshot-") as directory:
            root = Path(directory)
            repo, package = root / "repo", root / "package"
            repo.mkdir(); package.mkdir()
            source = repo / "dirty.py"
            source.write_text("dirty = True\n", encoding="utf-8")
            original = digest(source)
            save_source_snapshot(repo, package, {"dirty.py": original, "@bootstrap": original})
            self.assertEqual(digest(package / "source-snapshot/dirty.py"), original)
            manifest = json.loads((package / "source-snapshot.json").read_bytes())
            self.assertFalse(manifest["automatically_restored"])
            source.write_text("newer = True\n", encoding="utf-8")
            other = root / "other"
            other.mkdir()
            with self.assertRaisesRegex(RuntimeError, "snapshot_source_changed"):
                save_source_snapshot(repo, other, {"dirty.py": original})
            self.assertEqual(source.read_text(encoding="utf-8"), "newer = True\n")
