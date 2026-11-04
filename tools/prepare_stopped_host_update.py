"""Prepare one stopped update that parks fixed legacy stdio clients in place."""
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

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from tools import prepare_offline_continuation as continuation
from tools.prepare_work_authority_update import digest
from tools.prepare_codex_signer_probe import validate_probe


def _normal(path):return str(path).replace('\\','/').rstrip('/').lower()


COMPATIBILITY_REVIEW = continuation.migration.TEMPLATES / 'legacy_source_compatibility.json'


def compatibility_review_snapshot():
    continuation.reject_links(COMPATIBILITY_REVIEW)
    content = COMPATIBILITY_REVIEW.read_bytes()
    continuation.reject_links(COMPATIBILITY_REVIEW)
    review = json.loads(content)
    if review.get('schema') != 1 or not isinstance(review.get('reviewed_pairs'), list):
        raise ValueError('legacy_compatibility_review_rejected')
    return review, hashlib.sha256(content).hexdigest()


def legacy_source_pair_accepted(relative, installed_sha256, candidate_sha256, *, _review=None):
    if installed_sha256 == candidate_sha256:
        return True
    review = compatibility_review_snapshot()[0] if _review is None else _review
    if review.get('schema') != 1 or not isinstance(review.get('reviewed_pairs'), list):
        raise ValueError('legacy_compatibility_review_rejected')
    return any(row.get('relative') == relative and row.get('installed_sha256') == installed_sha256
               and row.get('candidate_sha256') == candidate_sha256
               and row.get('contract') == 'retained-stop-admission-v1'
               for row in review['reviewed_pairs'])


def validate_clients(observed, policy, old_exe, sid, session, verifier_sha256=None, *, allow_empty=False):
    facts=observed['Facts']; actors=observed['ActorPids']; families=observed['Families']
    if allow_empty and facts == [] and actors == [] and families == {} and observed.get('OfficialSigners', {}) == {}:
        names = observed['ExecutableNames']
        if not isinstance(names, list) or not names or any(type(name) is not str or '/' in name or '\\' in name or not name.lower().endswith('.exe') for name in names):
            raise ValueError('version_executable_inventory_required')
        return dict(ActorPids=[], HostPids=[], Facts=[])
    if not isinstance(facts,list) or not isinstance(actors,list) or not 2<=len(actors)<=256 or len(actors)%2:
        raise ValueError('fixed_client_pairs_required')
    by_pid={}
    for fact in facts:
        if (type(fact.get('Pid')) is not int or fact['Pid']<=0 or fact['Pid'] in by_pid or
            type(fact.get('Created')) is not str or not fact['Created'].isdigit() or int(fact['Created'])<=0 or
            type(fact.get('ParentPid')) is not int or fact['ParentPid']<=0 or
            fact.get('User')!=sid or type(fact.get('Session')) is not int or fact['Session']!=session or
            type(fact.get('Integrity')) is not int or fact['Integrity']!=8192 or fact.get('UiAccess') is not False or
            type(fact.get('Image')) is not str or not Path(fact['Image']).is_absolute()):
            raise ValueError('fixed_client_identity_required')
        by_pid[fact['Pid']]=fact
    if len(set(actors))!=len(actors) or any(type(pid) is not int or pid not in by_pid for pid in actors):
        raise ValueError('fixed_client_pairs_required')
    native=_normal(old_exe); python=_normal(policy['Python']['Path'])
    native_pids={pid for pid in actors if _normal(by_pid[pid]['Image'])==native}
    python_pids={pid for pid in actors if _normal(by_pid[pid]['Image'])==python}
    if not native_pids or len(native_pids)!=len(python_pids) or native_pids|python_pids!=set(actors):
        raise ValueError('fixed_client_pairs_required')
    host_pids=set();used=set(actors)
    for pid in native_pids:
        children=[child for child in python_pids if by_pid[child]['ParentPid']==pid]
        if len(children)!=1 or int(by_pid[children[0]]['Created'])<int(by_pid[pid]['Created']):
            raise ValueError('fixed_client_pairs_required')
        child=by_pid[pid];seen={pid}
        for _ in range(12):
            parent=by_pid.get(child['ParentPid'])
            if parent is None or parent['Pid'] in seen or int(parent['Created'])>int(child['Created']):
                raise ValueError('fixed_client_host_required')
            used.add(parent['Pid']);host_pids.add(parent['Pid']);seen.add(parent['Pid'])
            family=families.get(str(parent['Pid']))
            in_root=any(_normal(parent['Image']).startswith(_normal(root)+'/') for root in policy['CodexImageRoots'])
            signed=observed.get('OfficialSigners',{}).get(str(parent['Pid']),{})
            official=(Path(parent['Image']).name.lower()=='codex.exe' and
                      signed.get('Accepted') is True and signed.get('Pid')==parent['Pid'] and
                      signed.get('Created')==parent['Created'] and type(verifier_sha256) is str and
                      signed.get('NativeSha256')==verifier_sha256 and signed.get('ReadOnly') is True and
                      signed.get('AuthorityGranted') is False and signed.get('InputDispatched') is False)
            native = observed.get('NativeHostEvidence', {}).get(str(parent['Pid']), {})
            native_rule = next((rule for rule in policy.get('NativeHosts', [])
                                if _normal(rule['Path']) == _normal(parent['Image'])), None)
            native_ok = (native_rule is not None and native.get('Pid') == parent['Pid']
                         and native.get('Created') == parent['Created']
                         and native.get('Kind') == native_rule['Kind']
                         and _normal(native.get('Path', '')) == _normal(native_rule['Path'])
                         and native.get('Sha256') == native_rule['Sha256']
                         and native.get('RuntimeSha256') == native_rule.get('RuntimeSha256')
                         and native.get('ReadOnly') is True and native.get('AuthorityGranted') is False
                         and native.get('InputDispatched') is False
                         and (native_rule['Kind'] != 'dsh-desktop' or child['Pid'] == pid))
            if (native_ok or family in policy['CodexPackageFamilies'] or
                Path(parent['Image']).name.lower()=='codex.exe' and (in_root or official)):break
            child=parent
        else:raise ValueError('fixed_client_host_required')
    if used!=set(by_pid):raise ValueError('unrelated_retained_process_rejected')
    names=observed['ExecutableNames']
    if not isinstance(names,list) or not names or any(type(name) is not str or '/' in name or '\\' in name or not name.lower().endswith('.exe') for name in names):
        raise ValueError('version_executable_inventory_required')
    return dict(ActorPids=sorted(actors),HostPids=sorted(host_pids),Facts=[by_pid[pid] for pid in sorted(by_pid)])


# Used only for metadata inventory; a bound live core is managed by the
# maintenance protocol and is never treated as a client or host ancestor.
RETAINED_CANDIDATE_FUNCTION = r"""function ReadRetainedCandidates($candidatePids, $settings) {
 $facts=@{};$actors=@();$coreFound=$false
 foreach($candidatePid in $candidatePids) {
  $fact=[FlowerStoppedClientRetention]::Read($candidatePid)
  if($null -ne $settings.LiveCore -and $candidatePid -eq $settings.LiveCore.Pid) {
   $expected=$settings.LiveCore
   if($null -eq $fact -or $fact.Pid -ne $expected.Pid -or $fact.Created -cne $expected.Created -or
      $fact.Image -ine $expected.Image -or $fact.User -cne $expected.User -or
      $fact.Session -ne $expected.Session -or $fact.Integrity -ne 12288 -or $fact.UiAccess -ne $false) {
    throw 'bound_live_core_changed'
   }
   $coreFound=$true;continue
  }
  if($null -eq $fact -or !$fact.Image.StartsWith($settings.Versions,[StringComparison]::OrdinalIgnoreCase)){continue}
  if($fact.Image -ine $settings.OldExe -and $fact.Image -ine $settings.Python){throw 'independent_version_executor_present'}
  $facts[[int]$fact.Pid]=$fact;$actors+=[int]$fact.Pid
 }
 if($null -ne $settings.LiveCore -and !$coreFound){throw 'bound_live_core_missing'}
 return @{Facts=$facts;Actors=$actors}
}"""


def inspect_clients(plan, policy, signer_probe:Path|None=None, *, live_core=None):
    helper=(continuation.migration.TEMPLATES/'StoppedClientRetention.cs').read_text(encoding='utf-8')
    settings=dict(Root=plan['BrokerRoot'],OldExe=str(Path(plan['BrokerRoot'])/'versions'/plan['OldVersion']/'Flower.HighHelper.exe'),
                  Python=policy['Python']['Path'],Roots=policy['CodexImageRoots'],Families=policy['CodexPackageFamilies'],
                  NativeHosts=policy.get('NativeHosts',[]) if live_core is not None else [])
    # Installed manifests already enumerate sealed runtime files. Avoid a
    # recursive walk of every retained Python runtime just to find exe names.
    executable_names={'Flower.HighHelper.exe','flower-python.exe','Flower.AppWorker.exe','Flower.ComputerWgc.exe'}
    version_count=0
    for directory in (Path(plan['BrokerRoot'])/'versions').iterdir():
        if not directory.is_dir():continue
        continuation.reject_links(directory)
        manifest=directory/'installation.json';continuation.reject_links(manifest)
        inventory=json.loads(manifest.read_bytes())
        if inventory.get('version')!=directory.name:raise ValueError('installed_version_inventory_changed')
        for field in ('hashes','runtime_hashes'):
            for relative in inventory.get(field,{}):
                if relative.lower().endswith('.exe'):executable_names.add(relative.replace('\\','/').rsplit('/',1)[-1])
        version_count+=1
    executable_names.update(name for name in policy.get('AppWorkerHashes',{}) if name.lower().endswith('.exe'))
    executable_names.update(name for name in policy.get('WgcWorkerHashes',{}) if name.lower().endswith('.exe'))
    settings.update(ExecutableNames=sorted(executable_names),VersionManifestCount=version_count,
                    Versions=str(Path(plan['BrokerRoot'])/'versions')+'\\', LiveCore=live_core)
    if signer_probe is not None:
        proof=validate_probe(signer_probe)
        settings.update(SignerProbe=str(signer_probe/'native/Probe.exe'),
                        NativeLibrary=str(Path(plan['BrokerRoot'])/'versions'/plan['OldVersion']/'Flower.HighHelper.dll'),
                        NativeLibrarySha256=plan['OldDllSha256'],
                        SignerInputs=[dict(Path=str(signer_probe/'native'/name),Sha256=sha) for name,sha in proof['binary_hashes'].items()])
    settings64=base64.b64encode(json.dumps(settings).encode()).decode()
    source64=base64.b64encode(helper.encode()).decode()
    pin_source64=base64.b64encode((continuation.migration.TEMPLATES/'PinnedDelivery.cs').read_bytes()).decode()
    script=r'''$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$settings=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__SETTINGS__'))|ConvertFrom-Json
Add-Type -TypeDefinition ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__SOURCE__')))
Add-Type -TypeDefinition ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__PIN_SOURCE__')))
Add-Type -TypeDefinition @'
using System;using System.Text;using System.Runtime.InteropServices;using Microsoft.Win32.SafeHandles;
public static class FlowerRetainedFamilyReader {
 [DllImport("kernel32.dll",SetLastError=true)]static extern SafeProcessHandle OpenProcess(uint access,bool inherit,int pid);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode)]static extern int GetPackageFamilyName(SafeProcessHandle process,ref uint length,StringBuilder name);
 public static string Read(int pid){using(var p=OpenProcess(0x1000,false,pid)){
  if(p.IsInvalid)throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
  uint size=0;int code=GetPackageFamilyName(p,ref size,null);if(code==15700)return null;
  if(code!=122||size<1||size>512)throw new System.IO.IOException("retained_family_unreadable");
  var value=new StringBuilder((int)size);if(GetPackageFamilyName(p,ref size,value)!=0)throw new System.IO.IOException("retained_family_unreadable");return value.ToString();
 }}
}
'@
__CANDIDATE_FUNCTION__
$versions=$settings.Versions
$names=@($settings.ExecutableNames)
$pins=[Collections.Generic.List[IO.FileStream]]::new()
try {
if($settings.PSObject.Properties.Name -contains 'SignerProbe') {
 [FlowerPinnedDelivery]::PinDirectory([IO.Path]::GetDirectoryName($settings.SignerProbe))
 foreach($asset in @($settings.SignerInputs)+@([pscustomobject]@{Path=$settings.NativeLibrary;Sha256=$settings.NativeLibrarySha256})) {
  $pin=[IO.File]::Open($asset.Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$pins.Add($pin)
  $hash=[Security.Cryptography.SHA256]::Create()
  try{$actual=[BitConverter]::ToString($hash.ComputeHash($pin)).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
  if($actual -cne $asset.Sha256){throw 'retained_signer_input_changed'}
 }
}
$facts=@{};$families=@{};$signers=@{};$nativeHosts=@{};$actors=@();$candidatePids=[Collections.Generic.HashSet[int]]::new()
foreach($row in @(Get-CimInstance Win32_Process)) {
 $known=$names -icontains $row.Name
 $inside=![string]::IsNullOrWhiteSpace($row.ExecutablePath) -and $row.ExecutablePath.StartsWith($versions,[StringComparison]::OrdinalIgnoreCase)
 if($known -or $inside){$null=$candidatePids.Add([int]$row.ProcessId)}
}
foreach($row in [FlowerStoppedClientRetention]::ProcessNames()){if($names -icontains $row.Name){$null=$candidatePids.Add([int]$row.Pid)}}
if($null -ne $settings.LiveCore){$null=$candidatePids.Add([int]$settings.LiveCore.Pid)}
$selected=ReadRetainedCandidates $candidatePids $settings
$facts=$selected.Facts;$actors=@($selected.Actors)
foreach($pidValue in @($actors)) {
 $current=$facts[$pidValue]
 if($current.Image -ine $settings.OldExe){continue}
 for($depth=0;$depth -lt 12;$depth++) {
  $parent=[FlowerStoppedClientRetention]::Read([int]$current.ParentPid)
  if($null -eq $parent){throw 'retained_host_missing'}
  $family=[FlowerRetainedFamilyReader]::Read([int]$parent.Pid)
  $again=[FlowerStoppedClientRetention]::Read([int]$parent.Pid)
  if($null -eq $again -or $again.Created -cne $parent.Created){throw 'retained_host_changed'}
  $facts[[int]$parent.Pid]=$parent;$families[[string]$parent.Pid]=$family
  $inRoot=$false;foreach($root in $settings.Roots){if($parent.Image.StartsWith($root.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)){$inRoot=$true}}
  $official=$false
  if($signers.ContainsKey([string]$parent.Pid) -and $signers[[string]$parent.Pid].Created -ceq $parent.Created){$official=$true}
  if([IO.Path]::GetFileName($parent.Image) -ieq 'codex.exe' -and !$inRoot -and
     $settings.Families -notcontains $family -and !($settings.PSObject.Properties.Name -contains 'SignerProbe')) {
   throw 'retained_official_verifier_required'
  }
  if(!$official -and [IO.Path]::GetFileName($parent.Image) -ieq 'codex.exe' -and !$inRoot -and $settings.PSObject.Properties.Name -contains 'SignerProbe') {
   $hostPin=[IO.File]::Open($parent.Image,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$pins.Add($hostPin)
   $info=New-Object Diagnostics.ProcessStartInfo
   $info.FileName=$settings.SignerProbe
   $info.Arguments='"'+$settings.NativeLibrary+'" '+$settings.NativeLibrarySha256+' "'+$parent.Image+'" '+$parent.Pid+' '+$parent.Created
   $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
   $probe=New-Object Diagnostics.Process;$probe.StartInfo=$info
   try {
    if(!$probe.Start()){throw 'retained_signer_probe_not_started'}
    $stdout=$probe.StandardOutput.ReadToEndAsync();$stderr=$probe.StandardError.ReadToEndAsync()
    if(!$probe.WaitForExit(10000)){throw 'retained_signer_probe_outcome_unknown'}
    $text=$stdout.GetAwaiter().GetResult();$null=$stderr.GetAwaiter().GetResult()
    if($probe.ExitCode -eq 0) {
     $proof=$text|ConvertFrom-Json
     $official=$proof.Accepted -eq $true -and $proof.Pid -eq $parent.Pid -and $proof.Created -ceq $parent.Created -and $proof.NativeSha256 -ceq $settings.NativeLibrarySha256 -and $proof.ReadOnly -eq $true -and $proof.AuthorityGranted -eq $false -and $proof.InputDispatched -eq $false
     if($official){$signers[[string]$parent.Pid]=$proof}
    } elseif($probe.ExitCode -ne 1) {throw 'retained_signer_probe_rejected'}
   } finally {$probe.Dispose()}
  }
  $native=$false
  foreach($rule in @($settings.NativeHosts)) {
   if($parent.Image -ine $rule.Path){continue}
   if($rule.Kind -ceq 'dsh-desktop' -and $depth -ne 0){throw 'retained_native_host_direct_parent_required'}
   foreach($asset in @([pscustomobject]@{Path=$rule.Path;Sha256=$rule.Sha256}) + $(if($rule.RuntimeSha256){@([pscustomobject]@{Path=(Join-Path (Split-Path -Parent $rule.Path) 'resources\app.asar');Sha256=$rule.RuntimeSha256})}else{@()})) {
    [FlowerPinnedDelivery]::PinDirectory((Split-Path -Parent $asset.Path))
    [FlowerPinnedDelivery]::VerifyFile($asset.Path,$asset.Sha256)
   }
   $nativeHosts[[string]$parent.Pid]=@{Pid=$parent.Pid;Created=$parent.Created;Kind=$rule.Kind;Path=$rule.Path;Sha256=$rule.Sha256;RuntimeSha256=$rule.RuntimeSha256;ReadOnly=$true;AuthorityGranted=$false;InputDispatched=$false}
   $native=$true;break
  }
  if($native -or $settings.Families -contains $family -or ([IO.Path]::GetFileName($parent.Image) -ieq 'codex.exe' -and ($inRoot -or $official))){break}
  $current=$parent
 }
}
@{Facts=@($facts.Values);ActorPids=@($actors);Families=$families;OfficialSigners=$signers;NativeHostEvidence=$nativeHosts;ExecutableNames=$names;VersionManifestCount=$settings.VersionManifestCount}|ConvertTo-Json -Depth 5 -Compress
} finally {try{foreach($pin in $pins){$pin.Dispose()}}finally{[FlowerPinnedDelivery]::Close()}}
'''.replace('__CANDIDATE_FUNCTION__',RETAINED_CANDIDATE_FUNCTION).replace('__SETTINGS__',settings64).replace('__SOURCE__',source64).replace('__PIN_SOURCE__',pin_source64)
    # The reviewed metadata type exceeds Windows' command-line limit once
    # nested Base64 encoded. Run this local read-only script from TEMP.
    with tempfile.TemporaryDirectory(prefix='flower-retained-client-inventory-') as folder:
        target=Path(folder)/'Inspect.ps1';target.write_text(script,encoding='utf-8-sig')
        result=subprocess.run([str(continuation.migration.system_powershell_path()),
                               '-NoLogo','-NoProfile','-NonInteractive','-File',str(target)],
                              capture_output=True,timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode:raise ValueError('retained_client_inventory_failed:'+result.stderr.decode('utf-8',errors='replace'))
    return json.loads(result.stdout.decode('utf-8-sig'))


def resolve_signer_probe(output, signer_probe, *, live_core=None):
    if live_core is not None and signer_probe is None:
        from tools.prepare_codex_signer_probe import prepare
        signer_probe = output / 'readonly-signer-probe'
        prepare(signer_probe)
    return signer_probe


def bind_retained_clients(record, policy, output, signer_probe=None, *, live_core=None):
    signer_probe=resolve_signer_probe(output,signer_probe,live_core=live_core)
    observed=inspect_clients(record,policy,signer_probe,live_core=live_core)
    clients=validate_clients(observed,policy,Path(record['BrokerRoot'])/'versions'/record['OldVersion']/'Flower.HighHelper.exe',record['UserSid'],record['SessionId'],record['OldDllSha256'],allow_empty=live_core is not None)
    old_dir=Path(record['BrokerRoot'])/'versions'/record['OldVersion']
    manifest=old_dir/'installation.json';continuation.reject_links(manifest)
    if digest(manifest)!=record['OldActiveSha256']:raise ValueError('legacy_installation_changed')
    inventory=json.loads(manifest.read_bytes())['runtime_hashes']
    # Compare the actual installed and frozen candidate bytes. Exact matches
    # are compatible; a changed state source needs a version-controlled,
    # content-addressed review pair, never a caller-supplied approval or version.
    legacy_hashes={}
    compatibility_review,compatibility_sha=compatibility_review_snapshot()
    candidate_dir=Path(record['Package'])/'versions'/record['Version']
    candidate_manifest=candidate_dir/'installation.json';continuation.reject_links(candidate_manifest)
    candidate_inventory=json.loads(candidate_manifest.read_bytes())['runtime_hashes']
    for relative in ('python-source/flower_control/control/state.py','python-source/flower_control/control/write_gate.py',
                     'python-source/flower_control/authorization/semantic.py'):
        path=old_dir/relative;candidate_path=candidate_dir/relative
        continuation.reject_links(path);continuation.reject_links(candidate_path)
        installed_sha=digest(path);candidate_sha=digest(candidate_path)
        if (installed_sha!=inventory[relative] or candidate_sha!=candidate_inventory[relative]
                or not legacy_source_pair_accepted(relative,installed_sha,candidate_sha,_review=compatibility_review)):
            raise ValueError('legacy_resume_admission_source_changed')
        legacy_hashes[str(path)]=installed_sha
    library=old_dir/'runtime/DLLs/sqlite3.dll';continuation.reject_links(library)
    if digest(library)!=inventory['runtime/DLLs/sqlite3.dll']:raise ValueError('legacy_sqlite_changed')
    ledger=Path(policy['DataRoot'])/'state-v1/control.sqlite3';continuation.reject_links(ledger)
    with ledger.open('rb') as file:header=file.read(20)
    if len(header)!=20 or header[:16]!=b'SQLite format 3\0' or header[18:20]!=b'\x01\x01':
        raise ValueError('legacy_rollback_ledger_required')
    helper=output/'StoppedClientRetention.cs'
    helper.write_bytes((continuation.migration.TEMPLATES/'StoppedClientRetention.cs').read_bytes())
    return dict(RetainedStoppedClients=True, RetainedActorPids=clients['ActorPids'], RetainedHostPids=clients['HostPids'],
                RetainedProcessFacts=clients['Facts'], VersionExecutableNames=observed['ExecutableNames'],
                RetainedHostFamilyEvidence=observed['Families'], RetainedOfficialSignerEvidence=observed['OfficialSigners'],
                RetainedNativeHostEvidence=observed.get('NativeHostEvidence',{}),
                LedgerPath=str(ledger), LedgerLibrary=str(library), LedgerLibrarySha256=inventory['runtime/DLLs/sqlite3.dll'],
                LegacyResumeSourceHashes=legacy_hashes,
                LegacyResumeCompatibilityReview=dict(Path=str(COMPATIBILITY_REVIEW),Sha256=compatibility_sha),
                HostRetentionTypePath=str(helper), HostRetentionTypeSha256=digest(helper))


def prepare(previous_plan:Path,output:Path,signer_probe:Path|None=None,candidate_package:Path|None=None):
    # Reuse all original protected exit/Stop/payload/task bindings. No install,
    # process retirement, elevation, gate creation or Stop writes during prepare.
    record=continuation.prepare(previous_plan,output,candidate_package=candidate_package)
    if record['SharedGateMode']!='create_fresh_stopped' or not record['ClientQuiescenceContinuation']:
        raise ValueError('fresh_stopped_namespace_required_for_retained_clients')
    policy=json.loads((Path(record['BrokerRoot'])/'versions'/record['OldVersion']/'broker.json').read_bytes())
    if digest(Path(record['BrokerRoot'])/'versions'/record['OldVersion']/'broker.json')!=record['OldPolicySha256']:
        raise ValueError('original_policy_changed')
    bindings=bind_retained_clients(record, policy, output, signer_probe)
    plan={k:v for k,v in record.items() if k not in ('Script','ScriptSha256','Arguments','Installed','Elevated')}
    plan.update(Mode='stopped_host_retained_update', **bindings)
    template=(continuation.migration.TEMPLATES/'OfflineContinuation.ps1.template').read_text(encoding='utf-8')
    values=dict(PLAN_JSON=json.dumps(plan,ensure_ascii=False,indent=2),UPDATE_FUNCTIONS=continuation.migration.update_functions(),OFFLINE_FUNCTIONS=continuation.offline_functions())
    for key,name in [('PINNED_DELIVERY_TYPE','PinnedDelivery.cs'),('OFFLINE_GUARD_TYPE','OfflineMigrationGuard.cs'),('RECOVERY_PROTECTION_TYPE','RecoveryProtection.cs')]:
        values[key]=continuation.render_installer_type(name, Path(plan['BrokerRoot']))
    for key,value in values.items():template=template.replace('@@'+key+'@@',value)
    if '@@' in template:raise ValueError('retained_update_template_unresolved')
    script=output/'Continue.ps1';script.write_text(template,encoding='utf-8-sig')
    sha=digest(script);path=str(script).replace("'","''")
    bootstrap=("$ErrorActionPreference='Stop';$f=[IO.File]::Open('"+path+"',[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);try{"+
      "$h=[Security.Cryptography.SHA256]::Create();try{$v=[BitConverter]::ToString($h.ComputeHash($f)).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()};"+
      "if($v -cne '"+sha+"'){throw 'continuation_script_changed'};$f.Position=0;$r=[IO.StreamReader]::new($f,[Text.Encoding]::UTF8,$true,4096,$true);try{$s=$r.ReadToEnd()}finally{$r.Dispose()};& ([scriptblock]::Create($s))}finally{$f.Dispose()}")
    encoded=base64.b64encode(bootstrap.encode('utf-16-le')).decode()
    record={**plan,'Script':str(script),'ScriptSha256':sha,'Arguments':['-NoLogo','-NoProfile','-EncodedCommand',encoded],
            'Powershell':str(continuation.migration.system_powershell_path()),
            'EncodedBootstrap':encoded,'BootstrapSha256':hashlib.sha256(bootstrap.encode('utf-16-le')).hexdigest(),
            'Installed':False,'Elevated':False}
    (output/'plan.json').write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    return record


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--previous-plan',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--signer-probe',type=Path);parser.add_argument('--candidate-package',type=Path)
    args=parser.parse_args();record=prepare(args.previous_plan,args.output,args.signer_probe,args.candidate_package)
    print(json.dumps({key:record[key] for key in ['OperationId','Version','Script','ScriptSha256','RetainedActorPids','Installed','Elevated']}))
