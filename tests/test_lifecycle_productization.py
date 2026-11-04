"""Exercise prepared lifecycle artifacts without touching a real installation."""
import json
import base64
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from flower_control.install_location import InstallationLocation
from tools.prepare_high_broker_install import digest, native_binary_hashes, preparation_location, render_installer_type, write_json
from tools import prepare_uninstall as uninstall

HOSTS = [p for p in [shutil.which("powershell"), shutil.which("pwsh")] if p]


class ProductLifecycleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="flower-lifecycle-owned-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        install = self.root/"FlowerControl"
        self.location = InstallationLocation(install,install/"Program",install/"Data",install/"Cache",install/"Packages",
            user_sid="S-1-5-21-1-2-3-1001",installation_id="b"*32)
        self.version="a"*32
        self.directory=self.location.program_root/"versions"/self.version
        self.directory.mkdir(parents=True)
        write_json(self.directory/"broker.json",dict(AppWorkerHashes={},WgcWorkerHashes={}))
        (self.directory/"Flower.HighHelper.exe").write_bytes(b"owned-not-executable-fixture")
        active=dict(schema=1,version=self.version,hashes={p.name:digest(p) for p in self.directory.iterdir()})
        write_json(self.directory/"installation.json",active)
        write_json(self.location.program_root/"active.json",active)
        write_json(self.location.program_root/"installation-location.json",dict(schema=1,installation_id="b"*32))
        write_json(self.location.program_root/"host-integrations.json",dict(schema=1,installation_id="b"*32,entries=[]))

    def make_plan(self):
        output=self.root/"uninstall-plan.json"
        with patch.object(uninstall,"discover_installation",return_value=self.location):
            result=uninstall.prepare(output,inspect_runtime=False)
        return output,result

    def test_existing_registered_root_keeps_identity_and_rejects_data_redirect(self):
        with patch("flower_control.install_location.discover_installation",return_value=self.location):
            self.assertEqual(preparation_location(self.location.root,user_sid=self.location.user_sid),self.location)
            with self.assertRaisesRegex(ValueError,"installation_data_root_changed"):
                preparation_location(self.location.root,user_sid=self.location.user_sid,data_root=self.root/"other")
            with self.assertRaisesRegex(ValueError,"existing_installation_root_changed"):
                preparation_location(self.root/"elsewhere",user_sid=self.location.user_sid)

    def test_self_contained_native_inventory_includes_runtime_and_rejects_changed_closure(self):
        native=self.root/"native";native.mkdir()
        for name in ("Flower.HighHelper.exe","Flower.HighHelper.dll","Flower.HighHelper.deps.json","Flower.HighHelper.runtimeconfig.json",
                     "coreclr.dll","System.Private.CoreLib.dll","hostfxr.dll","build-evidence.json"):
            (native/name).write_bytes(name.encode())
        hashes=native_binary_hashes(self.root,native)
        self.assertIn("System.Private.CoreLib.dll",hashes)
        self.assertIn("hostfxr.dll",hashes)
        self.assertNotIn("build-evidence.json",hashes)
        self.assertEqual(len(hashes),7)

    def test_uninstall_defaults_keep_personal_data_and_recovery_and_bind_each_file(self):
        output,plan=self.make_plan()
        self.assertFalse(plan["executed"])
        self.assertIn(str(self.location.data_root),plan["preserve"])
        self.assertIn(str(self.location.program_root/"recovery"),plan["preserve"])
        self.assertTrue(all(not row["selected"] for row in plan["optional_cleanup"]))
        self.assertEqual(plan["plan_sha256"],digest(output))
        self.assertEqual(plan["apply_script_sha256"],digest(Path(plan["apply_script"])))
        for row in plan["files"]:
            self.assertEqual(row["sha256"],digest(Path(row["path"])))
        self.assertEqual(plan['files'][-1]['path'],str(self.location.program_root/'installation-location.json'))
        self.assertEqual(plan['files'][-2]['path'],str(self.location.program_root/'active.json'))

    def test_interrupted_copy_staging_is_owned_by_protected_operation_receipt(self):
        operation='c'*32
        staging=self.location.program_root/('.install-staging-'+operation);staging.mkdir()
        partial=staging/('d'*32+'.partial');partial.write_bytes(b'interrupted exact owned copy')
        owner=self.location.program_root/'recovery'/('installation-'+operation)/'install-owner.json'
        owner.parent.mkdir(parents=True)
        value=dict(schema=1,operation_id=operation,program_root=str(self.location.program_root),user_sid=self.location.user_sid,
            plan_sha256='e'*64,package_active_sha256='f'*64)
        write_json(owner,value)
        with patch.object(uninstall,'require_protected_path') as protection:
            rows=uninstall.install_staging_inventory(staging,self.location.program_root,self.location.user_sid)
        self.assertEqual(rows,[dict(path=str(partial),sha256=digest(partial),bytes=partial.stat().st_size)])
        self.assertEqual([call.args[0] for call in protection.call_args_list],[staging,owner,partial])
        with patch.object(uninstall,'require_protected_path'):
            _,plan=self.make_plan()
        self.assertIn(str(partial),{row['path'] for row in plan['files']})
        value['user_sid']='S-1-5-21-1-2-3-9999';write_json(owner,value)
        with patch.object(uninstall,'require_protected_path'),self.assertRaisesRegex(ValueError,'staging_owner_changed'):
            uninstall.install_staging_inventory(staging,self.location.program_root,self.location.user_sid)
        value['user_sid']=self.location.user_sid;write_json(owner,value)
        (staging/'unknown.exe').write_bytes(b'foreign')
        with patch.object(uninstall,'require_protected_path'),self.assertRaisesRegex(ValueError,'staging_file_rejected'):
            uninstall.install_staging_inventory(staging,self.location.program_root,self.location.user_sid)

    def test_unowned_or_changed_version_is_a_blocker(self):
        (self.directory/"user-note.txt").write_text("preserve",encoding="utf-8")
        _,plan=self.make_plan()
        self.assertTrue(any(row["reason"]=="uninstall_unowned_version_files" for row in plan["blockers"]))
        self.assertNotIn(str(self.directory/"user-note.txt"),{row["path"] for row in plan["files"]})

    def test_installer_types_seal_exact_custom_root(self):
        for name in ("PinnedDelivery.cs","RecoveryProtection.cs"):
            source=render_installer_type(name,self.location.program_root)
            self.assertNotIn("@@PREPARED_PROGRAM_ROOT@@",source)
            self.assertIn(str(self.location.program_root).replace("\\","\\\\"),source)

    def test_unknown_codex_registration_is_observed_by_official_list_without_mutation(self):
        cli=self.root/"codex.exe";cli.write_bytes(b"test-only-no-execution")
        entry=dict(host="codex",kind="marketplace",selector="flower-control-local",source=str(self.location.program_root/"integrations/codex"),registration_state="unknown")
        reply=SimpleNamespace(stdout=json.dumps(dict(marketplaces=[dict(name=entry["selector"],root=entry["source"])] )).encode())
        with patch.object(uninstall,'require_medium',return_value={'Integrity':8192}),patch.object(uninstall,'official_codex_cli',return_value=True),patch.object(uninstall.subprocess,"run",return_value=reply) as run:
            bound=uninstall.bind_codex_marketplace(entry,cli)
            self.assertEqual(bound["registration_state"],"registered")
            self.assertEqual(run.call_args.args[0],[str(cli),"plugin","marketplace","list","--json"])
            self.assertEqual(bound["cli"]["sha256"],digest(cli))
        reply.stdout=b'{"marketplaces":[]}'
        with patch.object(uninstall,'require_medium',return_value={'Integrity':8192}),patch.object(uninstall,'official_codex_cli',return_value=True),patch.object(uninstall.subprocess,"run",return_value=reply):
            self.assertEqual(uninstall.bind_codex_marketplace(entry,cli)["registration_state"],"not_registered")
        reply.stdout=json.dumps(dict(marketplaces=[dict(name=entry["selector"],root=str(self.root/"someone-else"))])).encode()
        with patch.object(uninstall,'require_medium',return_value={'Integrity':8192}),patch.object(uninstall,'official_codex_cli',return_value=True),patch.object(uninstall.subprocess,"run",return_value=reply):
            with self.assertRaisesRegex(ValueError,"uninstall_codex_marketplace_source_changed"):
                uninstall.bind_codex_marketplace(entry,cli)

    def test_codex_history_binds_only_current_owned_source_and_queries_once(self):
        cli=self.root/'codex.exe';cli.write_bytes(b'never-executed')
        old=dict(host='codex',kind='marketplace',selector='flower-local',source=str(self.location.program_root/'integrations/v1'),registration_state='unknown')
        new={**old,'source':str(self.location.program_root/'integrations/v2')}
        response=SimpleNamespace(stdout=json.dumps(dict(marketplaces=[dict(name='flower-local',root=new['source'])])).encode())
        with patch.object(uninstall,'require_medium',return_value={'Integrity':8192}),patch.object(uninstall,'official_codex_cli',return_value=True),patch.object(uninstall.subprocess,'run',return_value=response) as run:
            bound=uninstall.bind_owned_marketplaces([old,new],cli)
        self.assertEqual([entry['registration_state'] for entry in bound],['not_registered','registered'])
        self.assertEqual(run.call_count,1)

    def test_fake_cli_is_never_executed_before_publisher_acceptance(self):
        cli=self.root/'codex.exe';cli.write_bytes(b'fake-cli-not-executable')
        with patch.object(uninstall,'require_medium',return_value={'Integrity':8192}),patch.object(uninstall,'official_codex_cli',return_value=False),patch.object(uninstall.subprocess,'run') as run:
            with self.assertRaisesRegex(ValueError,'uninstall_official_codex_cli_required'):
                uninstall.resolve_codex_cli(cli)
            with self.assertRaisesRegex(ValueError,'uninstall_codex_publisher_rejected'):
                uninstall.run_official_cli(cli,['plugin','marketplace','list','--json'])
        run.assert_not_called()
        template=Path(uninstall.__file__).with_name('high_broker_install').joinpath('ApplyUninstall.ps1.template').read_text(encoding='utf-8')
        self.assertNotIn('$start.FileName=$entry.cli.path',template)
        self.assertNotIn('plugin marketplace remove',template)

    def test_unregistered_dsh_bundle_passes_medium_stage_without_host_execution(self):
        output,plan=self.make_plan()
        document=json.loads(output.read_bytes())
        entry=dict(host='dsh',kind='generated_bundle',registration_state='not_registered',source=str(self.location.program_root/'integrations/dsh'))
        document['host_entries']=[entry];write_json(output,document)
        Path(plan['apply_script']).write_text(uninstall.render_uninstall(document,output),encoding='utf-8-sig')
        with patch.object(uninstall,'require_medium',return_value={'Integrity':8192,'User':self.location.user_sid}),patch.object(uninstall,'bind_owned_marketplaces') as bind,patch.object(uninstall,'run_official_cli') as run:
            result=uninstall.complete_medium_host_stage(output,digest(output))
        self.assertTrue(result['medium_host_stage_complete'])
        self.assertEqual(json.loads(output.read_bytes())['host_entries'],[entry])
        bind.assert_not_called();run.assert_not_called()

    def test_local_status_capability_and_ordinary_writer_do_not_grant_legacy_upgrade(self):
        from tools import prepare_work_authority_update as update
        reply=SimpleNamespace(returncode=0,stdout=b'{"Status":{"version":"fixture"}}')
        with patch.object(update.subprocess,'run',return_value=reply) as run:
            self.assertEqual(update.previous_broker_status(self.directory/'Flower.HighHelper.exe',capabilities={'local_settings_protocol':1}),{'version':'fixture'})
        self.assertEqual(run.call_args.args[0][-1],'--flower-local-status')
        self.assertFalse(update.requires_host_native_elevation(1,1,'ordinary','ordinary',1,1))
        self.assertTrue(update.requires_host_native_elevation(1,1,'ordinary','ordinary',0,1))

    @unittest.skipUnless(os.name=="nt" and HOSTS,"Windows PowerShell hosts required")
    def test_apply_recycles_exact_fixture_files_with_mocked_scheduler_and_registry(self):
        for host in HOSTS:
            with self.subTest(host=host):
                self.setUp()
                output,plan=self.make_plan()
                document=json.loads(output.read_bytes());document["legacy"]=True
                write_json(output,document)
                script=uninstall.render_uninstall(document,output)
                fixtures=r"""
# Isolation adapters: no registry, scheduler or runtime process operations.
$plan.user_sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
function Assert-FlowerInstallParent($path){}
function Get-FlowerTask{return $null}
function Get-OwnedProcesses{return @()}
"""
                script=script.replace("if(!$Apply) {",fixtures+"\nif(!$Apply) {",1)
                source=Path(plan["apply_script"]);source.write_text(script,encoding="utf-8-sig")
                invocation="& '"+str(source).replace("'","''")+"' -Apply -ReviewedPlanSha256 '"+digest(output)+"' -Confirm:$false"
                result=subprocess.run([host,"-NoLogo","-NoProfile","-NonInteractive","-STA","-EncodedCommand",base64.b64encode(invocation.encode("utf-16-le")).decode()],capture_output=True,
                    text=True,encoding="utf-8",errors="replace",timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                receipt=json.loads(result.stdout)
                self.assertTrue(receipt["complete"],receipt)
                self.assertEqual(set(receipt["recycled"]),{row["path"] for row in document["files"]})
                self.assertTrue(receipt["personal_data_preserved"])
                self.assertTrue(all(not Path(row["path"]).exists() for row in document["files"]))

    @unittest.skipUnless(os.name=="nt" and HOSTS,"Windows PowerShell hosts required")
    def test_pending_batch_absence_resumes_without_claiming_a_recycle_receipt(self):
        for host in HOSTS:
            with self.subTest(host=host):
                self.setUp()
                output,plan=self.make_plan();document=json.loads(output.read_bytes());document['legacy']=True
                write_json(output,document)
                source=uninstall.render_uninstall(document,output)
                fixture=r"""
$plan.user_sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
function Assert-FlowerInstallParent($path){}
function Get-FlowerTask{return $null}
function Get-OwnedProcesses{return @()}
"""
                source=source.replace('if(!$Apply) {',fixture+'\nif(!$Apply) {',1)
                script=Path(plan['apply_script']);script.write_text(source,encoding='utf-8-sig')
                missing=Path(document['files'][0]['path']);preserved=self.root/'moved-owned-fixture.bin'
                missing.rename(preserved)
                result_path=self.root/('uninstall-'+document['operation_id']+'-result.json')
                write_json(result_path,dict(schema=1,operation_id=document['operation_id'],plan_sha256=digest(output),state='incomplete',
                    complete=False,recycled=[],host_removals=[],removal_observed_absent=[],pending_files=[str(missing)]))
                invocation="& '"+str(script).replace("'","''")+"' -Apply -ReviewedPlanSha256 '"+digest(output)+"' -Confirm:$false"
                result=subprocess.run([host,'-NoLogo','-NoProfile','-NonInteractive','-STA','-EncodedCommand',base64.b64encode(invocation.encode('utf-16-le')).decode()],
                    capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                receipt=json.loads(result.stdout)
                self.assertTrue(receipt['complete'],receipt)
                self.assertIn(str(missing),receipt['removal_observed_absent'])
                self.assertNotIn(str(missing),receipt['recycled'])
                self.assertTrue(preserved.exists())

    @unittest.skipUnless(os.name=="nt" and HOSTS,"Windows PowerShell hosts required")
    def test_both_hosts_parse_and_preview_without_system_mutation(self):
        output,plan=self.make_plan()
        script=Path(plan["apply_script"])
        environment=dict(os.environ)
        environment.pop("PSModulePath",None);environment.pop("PSMODULEPATH",None)
        for host in HOSTS:
            with self.subTest(host=host):
                command="$ErrorActionPreference='Stop';$tokens=$null;$errors=$null;[Management.Automation.Language.Parser]::ParseFile('"+str(script).replace("'","''")+"',[ref]$tokens,[ref]$errors)|Out-Null;if($errors.Count){throw ($errors|Out-String)};& '"+str(script).replace("'","''")+"'"
                result=subprocess.run([host,"-NoLogo","-NoProfile","-NonInteractive","-Command",command],capture_output=True,
                    text=True,encoding="utf-8",errors="replace",timeout=30,env=environment,creationflags=subprocess.CREATE_NO_WINDOW)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                preview=json.loads(result.stdout)
                self.assertEqual(preview["state"],"review")
                self.assertFalse(preview["system_changed"])
                self.assertFalse((self.root/("uninstall-"+plan["operation_id"]+"-result.json")).exists())
        output.write_text("{}",encoding="utf-8")
        result=subprocess.run([HOSTS[0],"-NoLogo","-NoProfile","-NonInteractive","-File",str(script)],capture_output=True,
            text=True,encoding="utf-8",errors="replace",timeout=30,env=environment,creationflags=subprocess.CREATE_NO_WINDOW)
        self.assertNotEqual(result.returncode,0)
        self.assertIn("uninstall_plan_changed",result.stdout+result.stderr)

    @unittest.skipUnless(os.name=="nt" and HOSTS,"Windows PowerShell hosts required")
    def test_both_hosts_compile_installer_helpers_without_calling_system_actions(self):
        templates=Path(uninstall.__file__).with_name("high_broker_install")
        fixture=self.root/"compile.ps1"
        source="$ErrorActionPreference='Stop'\n"
        for name in ("PinnedDelivery.cs","RecoveryProtection.cs","RecycleOwnedFiles.cs"):
            source+="Add-Type -TypeDefinition @'\n"+render_installer_type(name,self.location.program_root)+"\n'@\n"
        source+="Write-Output ('compiled:'+ $PSVersionTable.PSVersion.ToString())\n"
        fixture.write_text(source,encoding="utf-8-sig")
        for host in HOSTS:
            with self.subTest(host=host):
                result=subprocess.run([host,"-NoLogo","-NoProfile","-NonInteractive","-File",str(fixture)],capture_output=True,
                    text=True,encoding="utf-8",errors="replace",timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                self.assertIn("compiled:",result.stdout)

    @unittest.skipUnless(os.name=="nt" and HOSTS,"Windows PowerShell hosts required")
    def test_both_hosts_recycle_only_a_hash_bound_owned_temporary_file(self):
        source=render_installer_type("RecycleOwnedFiles.cs",self.location.program_root)
        for index,host in enumerate(HOSTS):
            with self.subTest(host=host):
                target=self.root/("owned-recycle-"+str(index)+".txt")
                target.write_text("generated only for lifecycle recycle verification",encoding="utf-8")
                fixture=self.root/("recycle-"+str(index)+".ps1")
                literal=str(target).replace("'","''")
                fixture.write_text("$ErrorActionPreference='Stop'\nAdd-Type -TypeDefinition @'\n"+source+"\n'@\n"
                    +"$rejected=$false;try{[FlowerUninstallRecycle]::Recycle('"+literal+"','"+"0"*64+"')}catch{$rejected=$true}\n"
                    +"if(!$rejected -or !(Test-Path -LiteralPath '"+literal+"')){throw 'changed_hash_deleted'}\n"
                    +"[FlowerUninstallRecycle]::Recycle('"+literal+"','"+digest(target)+"')\n"
                    +"if(Test-Path -LiteralPath '"+literal+"'){throw 'recycle_not_completed'}\nWrite-Output 'owned_file_recycled'\n",encoding="utf-8-sig")
                result=subprocess.run([host,"-NoLogo","-NoProfile","-NonInteractive","-STA","-File",str(fixture)],capture_output=True,
                    text=True,encoding="utf-8",errors="replace",timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                self.assertIn("owned_file_recycled",result.stdout)
                self.assertFalse(target.exists())


if __name__=="__main__":unittest.main()
