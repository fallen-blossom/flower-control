"""Actual execution parser/pins; only private storage root/ACL replaced in TEMP.

All current C# sources are compiled with a dedicated fixture StartupObject.
No broker Main, real permission files, elevation, UAC, or requested image runs.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'flower_control/drivers/high_helper'
FIXTURE = ROOT / 'tests/fixtures/execution_forms/Program.cs'


def replace_method(source, signature, body):
    start = source.index(signature)
    opening = source.index('{', start)
    depth, end = 1, opening + 1
    while depth:
        if source[end] == '{':
            depth += 1
        elif source[end] == '}':
            depth -= 1
        end += 1
    return source[:opening] + body + source[end:]


class SemanticExecutionFormsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='flower-execution-forms-build-')
        cls.addClassCleanup(cls.temporary.cleanup)
        directory = Path(cls.temporary.name)
        sources = directory / 'sources'
        sources.mkdir()
        cls.source_hashes = {}
        for path in SOURCE.glob('*.cs'):
            raw = path.read_bytes()
            cls.source_hashes[str(path.relative_to(ROOT))] = hashlib.sha256(raw).hexdigest()
            text = raw.decode('utf-8-sig')
            if path.name == 'SemanticExecution.cs':
                text = replace_method(text, 'private static string BindingPath(',
                    '{ return ExecutionFormsFixture.BindingPath(requestId); }')
                text = text.replace('AuditFiles.Check(', 'ExecutionFormsFixture.Check(')
                text = text.replace('AuditFiles.WriteNew(', 'ExecutionFormsFixture.WriteNew(')
            (sources / path.name).write_text(text, encoding='utf-8')
        cls.source_hashes[str(FIXTURE.relative_to(ROOT))] = hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
        tree = ET.parse(SOURCE / 'Flower.HighHelper.csproj')
        project = tree.getroot()
        group = project.find('PropertyGroup')
        group.find('OutputType').text = 'Exe'
        for name, value in [('StartupObject', 'Flower.HighHelper.ExecutionFormsFixture'),
                            ('AssemblyName', 'Flower.ExecutionFormsFixture'), ('EnableDefaultCompileItems', 'false'),
                            ('NuGetAudit', 'false'), ('UseSharedCompilation', 'false')]:
            ET.SubElement(group, name).text = value
        for name in ('ApplicationManifest', 'ApplicationIcon'):
            group.find(name).text = str((SOURCE / group.find(name).text).resolve())
        for resource in project.findall('.//EmbeddedResource'):
            resource.set('Include', str((SOURCE / resource.get('Include')).resolve()))
        items = ET.SubElement(project, 'ItemGroup')
        ET.SubElement(items, 'Compile', Include=str(sources / '*.cs'))
        ET.SubElement(items, 'Compile', Include=str(FIXTURE))
        tree.write(directory / 'ExecutionForms.csproj', encoding='utf-8')
        (directory / 'NuGet.Config').write_text('<configuration><packageSources><clear/></packageSources></configuration>', encoding='utf-8')
        output = directory / 'build-output'
        built = subprocess.run(['dotnet', 'build', str(directory / 'ExecutionForms.csproj'), '--nologo', '-v:q', '--output', str(output),
            '-p:RestoreConfigFile=' + str(directory / 'NuGet.Config')], capture_output=True, text=True,
            encoding='utf-8', timeout=90, env={**os.environ, 'DOTNET_CLI_TELEMETRY_OPTOUT': '1'})
        if built.returncode:
            raise AssertionError(built.stdout + built.stderr)
        cls.executable = output / 'Flower.ExecutionFormsFixture.exe'
        if not cls.executable.is_file():
            raise AssertionError('fixture executable missing from explicit build output: ' + built.stdout + built.stderr)
        cls.build_output = built.stdout + built.stderr
        cls.source_replacements = ['SemanticExecution.BindingPath: private TEMP only',
            'SemanticExecution AuditFiles.Check/WriteNew calls: TEMP containment/existence/flush boundary only']

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='flower-execution-forms-data-')
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)

    def payload(self, name, content=b'fixture data'):
        path = self.directory / name
        path.write_bytes(content)
        return {'Path': str(path), 'Sha256': hashlib.sha256(content).hexdigest()}

    def call(self, host, argv, payloads=(), **extra):
        image = str(self.directory / host) if not Path(host).is_absolute() else str(host)
        data = {'image': image, 'spec': {'Argv': argv, 'WorkingDirectory': str(self.directory),
            'ExecutableSha256': 'a' * 64, 'Payloads': list(payloads), 'Purpose': 'isolated parser/pin check'}, **extra}
        result = subprocess.run([str(self.executable), str(self.directory)], input=json.dumps(data),
            capture_output=True, text=True, encoding='utf-8', timeout=12)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return json.loads(result.stdout)

    def test_batch_literal_uses_cmd_quotes_and_preserves_body(self):
        batch = self.payload('任务 space.cmd', b'@echo off\r\nsetlocal EnableDelayedExpansion\r\nfor %%a in (1) do echo !a!\r\n')
        argv = ['/d', '/s', '/c', batch['Path'], 'two words', '', 'trailing\\']
        value = self.call('cmd.exe', argv, [batch])
        self.assertEqual(value['state'], 'supported')
        self.assertEqual(value['entry']['File'], batch['Path'])
        expected = '/d /s /v:off /c "' + ' '.join('"' + a + '"' for a in argv[3:]) + '"'
        self.assertEqual(value['Arguments'], expected)
        self.assertEqual(Path(batch['Path']).read_bytes(), b'@echo off\r\nsetlocal EnableDelayedExpansion\r\nfor %%a in (1) do echo !a!\r\n')

    def test_cmd_inline_is_one_exact_code_string_without_crt_escaping(self):
        code = 'echo "first" & echo %TEMP% > "out file.txt"'
        value = self.call('cmd.exe', ['/d', '/s', '/v:off', '/c', code])
        self.assertEqual(value['state'], 'supported')
        self.assertEqual(value['entry']['Kind'], 'inline_argv')
        self.assertEqual(value['Arguments'], '/d /s /v:off /c "' + code + '"')

    def test_cmd_literal_rejects_expansion_operators_and_unbound_file(self):
        batch = self.payload('script.bat')
        self.assertEqual(self.call('cmd.exe', ['/d', '/s', '/c', batch['Path']])['reason'], 'program_launch_entry_file_not_bound')
        for value in ['%X%', '!X!', 'a&b', 'a|b', 'a>b', 'a<b', 'a^b', 'a"b', '(arg)']:
            with self.subTest(value=value):
                result = self.call('cmd.exe', ['/d', '/s', '/c', batch['Path'], value], [batch])
                self.assertEqual(result['reason'], 'program_launch_cmd_literal_arguments_required')
        for argv in [['/s', '/c', 'echo safe'], ['/d', '/c', 'echo safe'], ['/d', '/s', '/k', 'echo safe'],
                     ['/d', '/s', '/c', 'echo safe', 'unjoined second command']]:
            with self.subTest(argv=argv):
                self.assertEqual(self.call('cmd.exe', argv)['state'], 'rejected')
        self.assertEqual(self.call('cmd.exe', ['/d', '/s', '/c', 'x' * 8190])['reason'], 'program_launch_cmd_command_line_too_long')

    def test_msi_package_transform_patch_and_nonrestart_are_exact(self):
        package, transform, patch = [self.payload(name) for name in ['job.msi', 'first.mst', 'fix.msp']]
        for action in ['/i', '/package', '/x', '/uninstall', '/a', '/fomus']:
            with self.subTest(action=action):
                value = self.call('msiexec.exe', [action, package['Path'], '/norestart', '/qn',
                    'TRANSFORMS=' + transform['Path'], 'PATCH=' + patch['Path'], 'NAME=two words'], [package, transform, patch])
                self.assertEqual(value['state'], 'supported')
                self.assertEqual(value['entry']['AdditionalFiles'], [transform['Path'], patch['Path']])
                self.assertIn('"NAME=two words"', value['Arguments'])

    def test_msi_missing_changed_or_implicit_payload_fails(self):
        package, transform = self.payload('job.msi'), self.payload('first.mst')
        value = self.call('msiexec.exe', ['/i', package['Path'], '/norestart', 'TRANSFORMS=' + transform['Path']], [package])
        self.assertEqual(value['reason'], 'program_launch_entry_file_not_bound')
        Path(transform['Path']).write_bytes(b'changed')
        value = self.call('msiexec.exe', ['/i', package['Path'], '/norestart', 'TRANSFORMS=' + transform['Path']], [package, transform])
        self.assertEqual(value['reason'], 'program_launch_payload_changed')
        for suffix in [[], ['/forcerestart'], ['/norestart', 'REBOOT=Force'], ['/norestart', '/update', 'other.msp'],
                       ['/norestart', 'TRANSFORMS=https://remote/a.mst'], ['/norestart', 'transforms=a.mst'],
                       ['/norestart', 'NAME=one" /i second.msi "']]:
            with self.subTest(suffix=suffix):
                self.assertEqual(self.call('msiexec.exe', ['/i', package['Path'], *suffix], [package])['state'], 'rejected')
        self.assertEqual(self.call('msiexec.exe', ['/x', '{00000000-0000-0000-0000-000000000000}', '/norestart'])['reason'], 'program_launch_msi_package_required')

    def test_payload_hashes_used_by_msi_change_execution_key(self):
        package, transform, unrelated = self.payload('job.msi'), self.payload('one.mst'), self.payload('unrelated.txt')
        argv = ['/i', package['Path'], '/norestart', 'TRANSFORMS=' + transform['Path']]
        first = self.call('msiexec.exe', argv, [package, transform])
        same = self.call('msiexec.exe', argv, [package, transform, unrelated])
        self.assertEqual(first['key'], same['key'])
        changed = self.payload('one.mst', b'actual new transform')
        second = self.call('msiexec.exe', argv, [package, changed])
        self.assertNotEqual(first['key'], second['key'])

    def test_python_module_and_launcher_are_explicitly_rejected_without_rewrite(self):
        module = self.payload('task.py')
        self.assertEqual(self.call('python.exe', ['-m', 'task'], [module])['reason'], 'program_launch_module_resolution_unbound')
        self.assertEqual(self.call('py.exe', ['-3', module['Path']], [module])['reason'], 'program_launch_python_launcher_resolution_unbound')
        self.assertEqual(self.call('python.exe', ['-B', module['Path'], '-m'], [module])['state'], 'supported')
        self.assertEqual(self.call('python.exe', ['-P', module['Path']], [module])['state'], 'supported')

    def test_dotnet_explicit_configuration_is_bound_and_preserves_original_argv(self):
        main, config, deps = [self.payload(name) for name in ['main.dll', 'main.runtimeconfig.json', 'main.deps.json']]
        argv = ['exec', '--runtimeconfig', config['Path'], '--depsfile', deps['Path'],
                '--fx-version', '10.0.10', '--roll-forward', 'Disable', main['Path'], 'two words']
        value = self.call('dotnet.exe', argv, [main, config, deps])
        self.assertEqual(value['state'], 'supported')
        self.assertEqual(value['entry']['AdditionalFiles'], [config['Path'], deps['Path']])
        self.assertTrue(value['Arguments'].endswith('"' + main['Path'] + '" "two words"'))
        self.assertEqual(self.call('dotnet.exe', argv, [main, deps])['reason'], 'program_launch_entry_file_not_bound')

    def test_dotnet_unknown_or_duplicate_configuration_does_not_guess_an_entry(self):
        main, config = self.payload('main.dll'), self.payload('main.runtimeconfig.json')
        for prefix in [['--runtimeconfig', config['Path'], '--runtimeconfig', config['Path']],
                       ['--additionalprobingpath', str(self.directory)], ['--fx-version', 'latest'], ['--roll-forward', 'guess']]:
            with self.subTest(prefix=prefix):
                self.assertEqual(self.call('dotnet.exe', ['exec', *prefix, main['Path']], [main, config])['reason'],
                                 'program_launch_dotnet_option_unbound')

    def test_embedded_managed_pe_supported_but_native_apphost_dll_not_guessed(self):
        managed = self.directory / 'managed.exe'
        managed.write_bytes(self.executable.with_suffix('.dll').read_bytes())
        self.assertEqual(self.call(managed, [])['entry']['Kind'], 'native_image')
        self.assertEqual(self.call(self.executable, [])['reason'], 'program_launch_apphost_payload_unbound')

    def test_new_workload_states_require_known_exit_and_known_entry_kind(self):
        script = self.payload('task.py')
        for state in ['running', 'unknown', 'untracked']:
            with self.subTest(state=state):
                value = self.call('python.exe', [script['Path']], [script], mode='binding', kind='file', workload=state)
                self.assertFalse(value['allowed'])
        for state, kind, expected in [('legacy', 'file', True), ('legacy', 'native_image', False),
                                      ('exited', 'native_image', True), ('exited', 'file', True),
                                      ('exited', 'inline_argv', True), ('exited', 'damaged-kind', False)]:
            with self.subTest(state=state, kind=kind):
                value = self.call('python.exe', [script['Path']], [script], mode='binding', kind=kind, workload=state)
                self.assertEqual(value['allowed'], expected)

    def test_independent_work_can_request_new_run_without_inheriting_old_chat(self):
        script=self.payload('job.py')
        value=self.call('python.exe',[script['Path']],[script],mode='independent_run')
        self.assertTrue(value['originalBlocked'])
        self.assertTrue(value['allowed'])
        self.assertTrue(value['originalPreserved'])
        self.assertTrue(value['referenceChanged'])
        self.assertTrue(value['executionKeyPreserved'])
        self.assertFalse(value['actualProgramExecuted'])
        self.assertFalse(value['productionWorkAuthorityCreated'])
        self.assertEqual(set(value['review']),{'Eligible','ExitReference','ExitCode','PreviousTreeExited','PreviousBusinessState','AuthorityTransferred'})
        self.assertEqual(value['review']['PreviousBusinessState'],'unknown')
        self.assertFalse(value['review']['AuthorityTransferred'])
        self.assertFalse(value['nativeReport']['Dispatched'])
        self.assertEqual(value['nativeReport']['IndependentNewRunReview'],value['review'])

    def test_semantic_root_exit_tracking_lost_requires_explicit_new_run(self):
        script=self.payload('root-job.py')
        value=self.call('python.exe',[script['Path']],[script],mode='root_exit_tracking_lost')
        self.assertTrue(value['eligible'])
        self.assertTrue(value['allowed'])
        self.assertFalse(value['actualProgramExecuted'])
        self.assertTrue(value['rootProcessExited'])
        self.assertFalse(value['previousTreeExited'])
        self.assertEqual(value['proofKind'],'root_exit_tracking_lost')
        self.assertEqual(value['review']['TreeEvidence'],'helper_restart_workload_tracking_unavailable')
        self.assertFalse(value['review']['AuthorityTransferred'])
        for change in ('tracked','running_root','unknown_root','same_work'):
            with self.subTest(change=change),tempfile.TemporaryDirectory(prefix='flower-root-exit-case-') as directory:
                original=self.directory;self.directory=Path(directory)
                try:
                    item=self.payload('root-job.py')
                    rejected=self.call('python.exe',[item['Path']],[item],mode='root_exit_tracking_lost',change=change)
                finally:self.directory=original
                self.assertFalse(rejected['eligible'])
                self.assertFalse(rejected['allowed'])
        with tempfile.TemporaryDirectory(prefix='flower-root-exit-forged-') as directory:
            original=self.directory;self.directory=Path(directory)
            try:
                item=self.payload('root-job.py')
                forged=self.call('python.exe',[item['Path']],[item],mode='root_exit_tracking_lost',change='forged_reference')
            finally:self.directory=original
        self.assertTrue(forged['eligible'])
        self.assertFalse(forged['allowed'])
        self.assertEqual(forged['rejection'],'program_launch_new_run_exit_reference_changed')

    def test_handle_defers_nested_new_run_until_after_blocker_root_proof(self):
        # The direct fixture above exercises the proof API. This source-order
        # check keeps the public Handle path from reintroducing an early
        # freshness call that cannot see the helper-restart root proof.
        source = (SOURCE / 'AdminProgramLaunch.cs').read_text(encoding='utf-8')
        start = source.index('internal static object Handle(')
        opening = source.index('{', start)
        depth, end = 1, opening + 1
        while depth:
            depth += (source[end] == '{') - (source[end] == '}')
            end += 1
        body = source[opening:end]
        blocker = body.index('var blockers = entries.Where')
        review = body.index('independentNewRunReview = execution.IndependentNewRunReview')
        first_fresh = body.index('if (!execution.HasNewRun)')
        second_fresh = body.index('if (execution is not null && !execution.HasNewRun)')
        root_fresh = body.index('if (execution!.HasNewRun)')
        self.assertLess(review, blocker)
        self.assertLess(first_fresh, blocker)
        self.assertLess(second_fresh, blocker)
        self.assertGreater(root_fresh, blocker)
        self.assertIn('execution!.RequireFreshExecution(policy, own, target, workGrant, rootExitReference)',
                      body[root_fresh:])
        self.assertNotIn('execution?.RequireFreshExecution', body)
        self.assertIn('if (rootReview is not null) independentNewRunReview = rootReview;', body)

    def test_missing_or_mismatched_root_binding_is_reported_without_unlocking(self):
        cases = (
            ('missing_binding', 'program_launch_execution_binding_missing'),
            ('different_execution', 'program_launch_new_run_exit_binding_rejected'),
            ('same_work', 'program_launch_new_run_current_work_required'),
            ('same_work_binding', 'program_launch_new_run_independent_work_required'),
        )
        for change, reason in cases:
            with self.subTest(change=change), tempfile.TemporaryDirectory(prefix='flower-root-review-denied-') as directory:
                original = self.directory
                self.directory = Path(directory)
                try:
                    item = self.payload('root-job.py')
                    value = self.call('python.exe', [item['Path']], [item], mode='root_exit_tracking_lost', change=change)
                finally:
                    self.directory = original
                self.assertFalse(value['eligible'])
                self.assertFalse(value['allowed'])
                self.assertIsNone(value['reference'])
                self.assertEqual(value['review'], {'Eligible': False, 'Reason': reason, 'AuthorityTransferred': False})
                self.assertEqual(value['nativeReport']['IndependentNewRunReview'], value['review'])
                self.assertFalse(value['nativeReport']['Dispatched'])
                self.assertTrue(value['originalPreserved'])
                self.assertFalse(value['actualProgramExecuted'])
                self.assertFalse(value['productionWorkAuthorityCreated'])

    def test_independent_new_run_rejects_incomplete_exit_or_changed_proof(self):
        for change in ('legacy','running','unknown_dispatch','missing_exit','same_work','work_revision','other_thread',
                       'stale_head','foreign_task','forged_reference','missing_current_work','same_old_request'):
            with self.subTest(change=change),tempfile.TemporaryDirectory(prefix='flower-next-run-case-') as directory:
                original=self.directory;self.directory=Path(directory)
                try:
                    script=self.payload('job.py')
                    value=self.call('python.exe',[script['Path']],[script],mode='independent_run',change=change)
                finally:self.directory=original
                self.assertTrue(value['originalBlocked'])
                self.assertFalse(value['allowed'])

    def test_python_and_native_new_run_reference_match_and_review_changes_bind(self):
        from flower_control.drivers.semantic_execution import bind_execution
        script=self.payload('job.py');image=str(self.directory/'python.exe')
        value={'argv':[script['Path']],'working_directory':str(self.directory),'executable_sha256':'a'*64,
               'payloads':[{'path':script['Path'],'sha256':script['Sha256']}],'purpose':'explicit independent run',
               'new_run':{'exit_reference':'b'*64,'evidence':'User requests a new run after the old tree exited.'}}
        reference,wire=bind_execution(image,value)
        p=subprocess.run([str(self.executable),str(self.directory)],input=json.dumps({'image':image,'spec':wire}),
                         capture_output=True,text=True,encoding='utf-8',timeout=12)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(json.loads(p.stdout)['ProgramRef'],reference)
        changed=json.loads(json.dumps(value));changed['new_run']['exit_reference']='c'*64
        self.assertNotEqual(bind_execution(image,changed)[0],reference)
        for malformed in ({'exit_reference':'bad','evidence':'new run'}, {'exit_reference':'b'*64,'evidence':''}):
            changed={**value,'new_run':malformed}
            with self.assertRaises(ValueError):bind_execution(image,changed)
        with self.assertRaises(ValueError):bind_execution(image,{**value,'continuation':{}})

    def test_large_binding_is_read_without_retiring_original_unknown(self):
        script = self.payload('task.py')
        value = self.call('python.exe', [script['Path']], [script], mode='binding', kind='file', workload='exited', large=True)
        self.assertGreater(value['binding_bytes'], 180000)
        self.assertTrue(value['allowed'])

    def test_failed_workload_retention_keeps_payload_pinned(self):
        script = self.payload('task.py')
        value = self.call('python.exe', [script['Path']], [script], mode='retention')
        self.assertTrue(value['retainFailureKeptPins'])


if __name__ == '__main__':
    unittest.main()
