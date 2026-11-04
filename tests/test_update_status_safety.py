"""Exercise update admission reducers only; never contact or administer High."""
import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools import prepare_work_authority_update as update

ROOT = Path(__file__).resolve().parents[1]


def state():
    return dict(version='a' * 32, pid=123, created=134371486987342472, maintenance_protocol=1, maintenance_activities=0,
                global_stop_epoch=4, protected_stop_epoch=35,
                active_requests=0, pending_release_recoveries=0,
                paused=False, global_write_stopped=False, stopping=False,
                release_fault=False, high_verified=True, computer_paused=False,
                stop_persistence_error=None, computer_pause_persistence_error=None)


class UpdateStatusSafetyTests(unittest.TestCase):
    def test_shape_accepts_current_and_legacy_snapshot_without_changing_it(self):
        for value in (state(), {k: v for k, v in state().items() if not k.endswith('persistence_error')}):
            with self.subTest(value=value):
                update.require_status_shape(value)
                update.require_previous_idle(value, 'a' * 32, recovery=False)

    def test_invalid_or_incomplete_snapshot_cannot_prepare_update(self):
        mutations = [dict(paused=0), dict(global_write_stopped='false'), dict(high_verified=1),
                     dict(release_fault=None), dict(active_requests=False), dict(active_requests=-1),
                     dict(active_requests=0.0), dict(pending_release_recoveries='0'),
                     dict(pid=True), dict(pid=0), dict(created=0), dict(created=2**63),
                     dict(global_stop_epoch=-1), dict(protected_stop_epoch=2**63),
                     dict(computer_paused='false'), dict(version='wrong'),
                     dict(stop_persistence_error=False)]
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, '^broker_status_invalid$'):
                update.require_status_shape({**state(), **mutation})
        for key in state():
            if key.endswith('persistence_error') or key in ('maintenance_protocol', 'maintenance_activities'):
                continue
            with self.subTest(missing=key), self.assertRaisesRegex(ValueError, '^broker_status_invalid$'):
                update.require_status_shape({k: v for k, v in state().items() if k != key})

    def test_persistence_failure_user_stop_busy_and_replacement_never_become_idle(self):
        for mutation in (dict(stop_persistence_error='write_failed'),
                         dict(computer_pause_persistence_error='write_failed'),
                         dict(paused=True), dict(global_write_stopped=True), dict(active_requests=1),
                         dict(pending_release_recoveries=1), dict(stopping=True),
                         dict(release_fault=True), dict(high_verified=False), dict(version='b'*32)):
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, 'previous_broker_not_idle'):
                update.require_previous_idle({**state(), **mutation}, 'a'*32, recovery=False)
        paused = {**state(), 'paused': True, 'global_write_stopped': True}
        update.require_previous_idle(paused, 'a'*32, recovery=True)
        with self.assertRaises(ValueError):
            update.require_previous_idle(state(), 'a'*32, recovery=True)

    def test_epoch_capacity_reserves_only_remaining_maintenance_transitions(self):
        maximum = 2**63-1
        update.require_previous_idle({**state(), 'global_stop_epoch': maximum-1,
                                      'protected_stop_epoch': maximum-2}, 'a'*32, recovery=False)
        for mutation in (dict(global_stop_epoch=maximum), dict(protected_stop_epoch=maximum-1)):
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, 'stop_epoch_exhausted'):
                update.require_previous_idle({**state(), **mutation}, 'a'*32, recovery=False)
        paused = {**state(), 'paused': True, 'global_write_stopped': True,
                  'global_stop_epoch': maximum, 'protected_stop_epoch': maximum-1}
        update.require_previous_idle(paused, 'a'*32, recovery=True)
        with self.assertRaisesRegex(ValueError, 'stop_epoch_exhausted'):
            update.require_previous_idle({**paused, 'protected_stop_epoch': maximum}, 'a'*32, recovery=True)

    def powershell_results(self, cases, invocation, setup=''):
        # Parse only these pure function bodies. The template's installation
        # body, Admin command, task APIs and rollback are never executed.
        template = ROOT / 'tools/high_broker_install/UpdateWorkAuthority20261018.ps1.template'
        literal = str(template).replace("'", "''")
        script = """$ErrorActionPreference='Stop'
Set-StrictMode -Version 2
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('__TEMPLATE__',[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'template_parse_failed'}
$names=@('ExpectedRole','RequireRolePolicy','DurableStop','RequireDurableStop','RequireStatusShape','RequireHealthy','RequireIdle','RequireResume','RequireComputerPause','RequireOriginal','RequireMaintenancePaused','MaintenanceAdmin','ResumeBroker','DrainOriginal')
$functions=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in $names},$false))
foreach($f in $functions){. ([scriptblock]::Create($f.Extent.Text))}
$oldVersion='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';$version='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
$oldRole='high';$newRole='high';$roleSupported=$false;$script:PayloadVerified=$false;$maintenanceDurable=$null
__SETUP__
$cases=[Console]::In.ReadToEnd()|ConvertFrom-Json
$results=@(foreach($case in $cases){try{__INVOKE__; 'accepted'}catch{$_.Exception.Message}})
ConvertTo-Json -InputObject $results -Compress
""".replace('__TEMPLATE__', literal).replace('__INVOKE__', invocation).replace('__SETUP__', setup)
        executable = Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
        reply = subprocess.run([str(executable), '-NoProfile', '-NonInteractive', '-EncodedCommand',
                                base64.b64encode(script.encode('utf-16-le')).decode()],
                               input=json.dumps(cases).encode(), capture_output=True, timeout=20, check=True)
        return json.loads(reply.stdout.decode('utf-8-sig'))

    def test_actual_powershell_idle_gate_rejects_malformed_and_failed_persistence(self):
        good = state()
        legacy = {k: v for k, v in good.items() if not k.endswith('persistence_error')}
        cases = [good, legacy, {**good, 'stop_persistence_error': 'write_failed'},
                 {**good, 'computer_pause_persistence_error': 'write_failed'},
                 {**good, 'high_verified': 'false'}, {**good, 'active_requests': False},
                 {**good, 'global_stop_epoch': 2**63},
                 {k: v for k, v in good.items() if k != 'created'}]
        results = self.powershell_results(cases, 'RequireIdle $case')
        self.assertEqual(results[:2], ['accepted', 'accepted'])
        self.assertEqual(results[2:4], ['stop_persistence_unconfirmed', 'computer_pause_persistence_unconfirmed'])
        self.assertEqual(results[4:], ['broker_status_invalid']*4)

    def test_resume_requires_same_broker_both_cas_epochs_and_no_release_or_persistence_fault(self):
        before = {**state(), 'paused': True, 'global_write_stopped': True}
        after = {**state(), 'global_stop_epoch': 4, 'protected_stop_epoch': 36}
        bad = [dict(global_stop_epoch=3), dict(global_stop_epoch=5), dict(protected_stop_epoch=35),
               dict(pid=124), dict(created=after['created']+1), dict(version='b'*32),
               dict(paused=True), dict(global_write_stopped=True), dict(release_fault=True),
               dict(stop_persistence_error='write_failed')]
        cases = [dict(before=before, after=after)]
        cases += [dict(before=before, after={**after, **mutation}) for mutation in bad]
        cases += [dict(before={**before, 'stop_persistence_error': 'write_failed'}, after=after),
                  dict(before={**before, 'active_requests': 1}, after=after),
                  dict(before={**before, 'global_write_stopped': False}, after=after)]
        results = self.powershell_results(cases, 'RequireResume $case.before $case.after 4 35')
        self.assertEqual(results[0], 'accepted')
        self.assertTrue(all(value in ('resume_unconfirmed', 'maintenance_pause_unconfirmed', 'broker_not_healthy', 'broker_not_idle', 'stop_persistence_unconfirmed')
                            for value in results[1:]), results)
        # The successful resume opens admission before its response is read.
        concurrent = [dict(before=before, after={**after, key: 1})
                      for key in ('active_requests', 'pending_release_recoveries')]
        self.assertEqual(self.powershell_results(concurrent, 'RequireResume $case.before $case.after 4 35'),
                         ['accepted', 'accepted'])

    def test_actual_resume_dispatch_is_zero_when_either_pause_is_inconsistent(self):
        before = {**state(), 'paused': True, 'global_write_stopped': True}
        after = {**state(), 'global_stop_epoch': 4, 'protected_stop_epoch': 36}
        cases = [dict(before={**before, **change}, after=after) for change in
                 (dict(paused=False), dict(global_write_stopped=False), dict(global_stop_epoch=5),
                  dict(stop_persistence_error='write_failed'), dict(active_requests=1))]
        setup = """$maintenanceShared=4;$maintenanceProtected=35
$plan=[pscustomobject]@{LegacyComputerPause=$false;OldComputerPaused=$false}
function Admin($exe,$arguments){$script:dispatches++;return [pscustomobject]@{Status=$script:current.after}}
"""
        invoke = """$script:dispatches=0;$script:current=$case;$rejected=$false
try{$null=ResumeBroker 'fixture-only' $case.before}catch{$rejected=$true}
if(!$rejected -or $script:dispatches -ne 0){throw 'unexpected_resume_dispatch'}
"""
        self.assertEqual(self.powershell_results(cases, invoke, setup), ['accepted']*len(cases))

    def test_actual_drain_binds_original_instance_before_pause_and_shutdown(self):
        running = state()
        stopped = {**state(), 'paused': True, 'global_write_stopped': True,
                   'global_stop_epoch': 5, 'protected_stop_epoch': 36}
        cases = [dict(before={**running, **mutation}, paused=stopped, before_shutdown=stopped,
                      expected_pause=0, expected_shutdown=0) for mutation in
                 (dict(pid=124), dict(created=running['created']+1), dict(version='b'*32),
                  dict(global_stop_epoch=5), dict(paused=True))]
        cases += [dict(before=running, paused={**stopped, 'pid': 124}, before_shutdown=stopped,
                       expected_pause=1, expected_shutdown=0),
                  dict(before=running, paused=stopped, before_shutdown={**stopped, 'created': stopped['created']+1},
                       expected_pause=1, expected_shutdown=0),
                  dict(before=running, paused=stopped, before_shutdown=stopped,
                       expected_pause=1, expected_shutdown=1)]
        setup = """$maintenanceShared=5;$maintenanceProtected=36;$recovering=$false;$oldExe='fixture-only';$oldVersion='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
$plan=[pscustomobject]@{OldPid=123;OldCreated=134371486987342472;OldSharedEpoch=4;OldProtectedEpoch=35;OldComputerPaused=$false;LegacyComputerPause=$false}
function Status($exe){$script:observations++;if($script:observations -eq 1){return $script:current.before};return $script:current.before_shutdown}
function Admin($exe,$arguments){if($arguments -match '^--flower-maintenance pause '){$script:pauses++;return [pscustomobject]@{Status=$script:current.paused}};if($arguments -match '^--flower-maintenance shutdown '){$script:shutdowns++;return};throw 'unexpected_admin'}
function WaitExit($pidValue,$created){}
"""
        invoke = """$script:current=$case;$script:observations=0;$script:pauses=0;$script:shutdowns=0
try{DrainOriginal}catch{}
if($script:pauses -ne $case.expected_pause -or $script:shutdowns -ne $case.expected_shutdown){throw 'unexpected_drain_dispatch'}
"""
        self.assertEqual(self.powershell_results(cases, invoke, setup), ['accepted']*len(cases))

    def test_legacy_or_unknown_capability_never_falls_back_to_generic_control(self):
        cases = [{**state(), 'maintenance_protocol': value} for value in (None, True, '1', 2)]
        cases += [{k: v for k, v in state().items() if k != 'maintenance_protocol'}]
        for value in cases:
            with self.assertRaisesRegex(ValueError, 'maintenance_binding_unsupported'):
                update.require_maintenance_support(value)
        setup = "function Admin($exe,$arguments){throw 'generic_or_fixed_dispatch_forbidden'}"
        self.assertEqual(self.powershell_results(cases, "$null=MaintenanceAdmin 'fixture-only' 'pause' $case", setup),
                         ['maintenance_binding_unsupported']*len(cases))

    def test_rejected_or_corrupt_old_status_creates_no_plan_and_queries_only_original_helper(self):
        with tempfile.TemporaryDirectory(prefix='flower-update-reject-') as directory:
            folder = Path(directory)
            production = folder / 'program-files/FlowerControl/HighHelper'
            package = folder / 'package'
            old = production / 'versions' / ('b'*32)
            new = package / 'versions' / ('a'*32)
            old.mkdir(parents=True)
            new.mkdir(parents=True)
            policy = dict(Version='a'*32, Schema=1, UserSid='S-1-5-21-1-2-3-1001', DataRoot='unchanged',
                          NativeHosts=[], CodexPackageFamilies=[], CodexImageRoots=[])
            (new / 'broker.json').write_text(json.dumps(policy))
            (old / 'broker.json').write_text(json.dumps({**policy, 'Version': 'b'*32}))
            active = dict(version='a'*32, hashes={'broker.json': update.digest(new / 'broker.json')})
            (package / 'active.json').write_text(json.dumps(active))
            (new / 'installation.json').write_bytes((package / 'active.json').read_bytes())
            (production / 'active.json').write_text(json.dumps(dict(version='b'*32)))
            (package / 'preparation.json').write_text(json.dumps(dict(version='a'*32, installed=False, production_root=str(production))))
            output = folder / 'not-created'
            replies = [SimpleNamespace(returncode=2, stderr=b'{"reason":"process_unavailable"}', stdout=b''),
                       SimpleNamespace(returncode=0, stderr=b'', stdout=json.dumps({'Status': {**state(), 'version': 'b'*32,
                           'stop_persistence_error': 'write_failed'}}).encode()),
                       SimpleNamespace(returncode=0, stderr=b'', stdout=json.dumps({'Status': {**state(), 'version': 'b'*32,
                           'active_requests': False}}).encode())]
            for reply in replies:
                with self.subTest(reply=reply), patch.dict(os.environ, {'TEMP': directory, 'ProgramFiles': str(folder / 'program-files')}), \
                        patch('flower_control.install_location.program_root',return_value=production), \
                        patch.object(update,'helper_capabilities',return_value={'local_settings_protocol':0}), \
                        patch.object(update.subprocess, 'run', return_value=reply) as run:
                    with self.assertRaises((ValueError, RuntimeError)):
                        update.prepare(package, output)
                    self.assertFalse(output.exists())
                    self.assertEqual(run.call_count, 1)
                    self.assertEqual(run.call_args.args[0], [str(old / 'Flower.HighHelper.exe'), '--flower-admin', 'status'])


if __name__ == '__main__':
    unittest.main()
