"""Owned TEMP data only; protected-authority fixtures never admit production."""
from contextlib import ExitStack, contextmanager
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools import uninstall_personal_data as personal


@unittest.skipUnless(os.name == 'nt', 'Windows file identity and sharing required')
class PersonalDataTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='flower-personal-data-owned-')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base/'FlowerControl'
        self.program = self.root/'Program'
        self.data, self.cache = self.root/'Data', self.root/'Cache'
        self.operation = 'a'*32
        self.sid = 'S-1-5-21-1-2-3-1001'
        self.anchor = self.program/'recovery'/('installation-'+self.operation)/'resume-anchor.json'
        self.anchor.parent.mkdir(parents=True)
        self.data.mkdir(); self.cache.mkdir()
        (self.program/'versions').mkdir(); (self.root/'Packages').mkdir()
        (self.data/'nested').mkdir()
        (self.data/'empty').mkdir()
        (self.data/'profile.json').write_bytes(b'private fixture')
        (self.data/'nested'/'session.db').write_bytes(b'owned fixture database')
        (self.cache/'cached.bin').write_bytes(b'cached fixture')
        self.sentinel = self.program/'recovery'/'unknown.json'
        self.sentinel.write_bytes(b'preserve Stop unknown and pending state')
        self.plan_path = self.base/'uninstall-plan.json'
        self.plan = dict(schema=1, operation='uninstall_review', operation_id=self.operation,
            legacy=False, user_sid=self.sid, installation_id='b'*32,
            installation_root=str(self.root), program_root=str(self.program),
            optional_cleanup=[dict(path=str(self.data), selected=False), dict(path=str(self.cache), selected=False)],
            preserve=[str(self.data), str(self.cache), str(self.program/'recovery')])
        self.write(self.plan_path, self.plan)
        self.plan_sha = self.digest(self.plan_path)
        self.anchor_value = dict(schema=1, kind='uninstall', state='completed', operation_id=self.operation,
            user_sid=self.sid, installation_id='b'*32, root=str(self.root), program_root=str(self.program),
            machine_binding_sha256='e'*64, plan_path=str(self.plan_path), plan_sha256=self.plan_sha)
        self.write(self.anchor, self.anchor_value)
        self.review_path = self.base/'personal-review.json'

    @staticmethod
    def write(path, value):
        path.write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')

    @staticmethod
    def digest(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    @contextmanager
    def trust(self, *, identity=None):
        with ExitStack() as patches:
            patches.enter_context(patch.object(personal, 'require_protected_path'))
            patches.enter_context(patch.object(personal, '_machine_binding', return_value='e'*64))
            patches.enter_context(patch.object(personal, '_identity', return_value=identity or
                dict(user_sid=self.sid, integrity=8192, elevated=False, ui_access=False)))
            patches.enter_context(patch.object(personal, '_runtime_guard'))
            yield

    def prepare(self, **kwargs):
        with self.trust():
            return personal.prepare(self.plan_path, self.plan_sha, self.review_path, **kwargs)

    def test_inspection_is_read_only_and_binds_complete_paths_counts_bytes_and_ids(self):
        before = {str(p): self.digest(p) for p in self.root.rglob('*') if p.is_file()}
        result = self.prepare()
        self.assertFalse(result['executed'])
        self.assertEqual(result['selected_roots'], [str(self.cache), str(self.data)])
        self.assertEqual(result['file_count'], 3)
        self.assertEqual(result['bytes'], sum(p.stat().st_size for p in (self.data/'profile.json', self.data/'nested'/'session.db', self.cache/'cached.bin')))
        review = json.loads(self.review_path.read_bytes())
        self.assertEqual(result['review_sha256'], self.digest(self.review_path))
        self.assertTrue(all(row['file_id'] and row['sha256'] and Path(row['path']).is_absolute() for row in review['files']))
        self.assertTrue(review['directories_preserved'])
        self.assertEqual(before, {str(p): self.digest(p) for p in self.root.rglob('*') if p.is_file()})

    def test_confirmation_is_required_and_high_uiaccess_or_elevated_token_rejects(self):
        result = self.prepare()
        with self.assertRaisesRegex(ValueError, 'confirmation_required'):
            personal.apply(self.review_path, result['review_sha256'])
        for changes in (dict(integrity=12288), dict(ui_access=True), dict(elevated=True)):
            identity = dict(user_sid=self.sid, integrity=8192, elevated=False, ui_access=False, **{})
            identity.update(changes)
            with self.trust(identity=identity), self.assertRaisesRegex(ValueError, 'medium_user_required'):
                personal._validate_authority(self.plan_path, self.plan_sha)

    def test_completed_protected_anchor_is_required_and_fake_result_never_authorizes(self):
        fake_result = self.base/'uninstall-success.json'
        self.write(fake_result, dict(complete=True, state='uninstalled_personal_data_preserved'))
        self.anchor.rename(self.base/'kept-real-anchor.json')
        with self.trust(), self.assertRaises((OSError, ValueError)):
            personal._validate_authority(self.plan_path, self.plan_sha)
        self.assertTrue((self.data/'profile.json').is_file())

    def test_anchor_sid_machine_root_plan_and_completion_drift_reject(self):
        for field, value in (('user_sid','S-1-5-21-1-2-3-9999'), ('machine_binding_sha256','f'*64),
                             ('root',str(self.base)), ('plan_sha256','0'*64), ('state','incomplete')):
            changed = dict(self.anchor_value); changed[field] = value; self.write(self.anchor, changed)
            with self.trust(), self.assertRaisesRegex(ValueError, 'completed_protected_uninstall_required'):
                personal._validate_authority(self.plan_path, self.plan_sha)

    def test_legacy_and_root_redirection_are_explicitly_rejected(self):
        for change, reason in ((dict(legacy=True), 'legacy_requires_manual_review'),
                               (dict(program_root=str(self.root/'HighHelper')), 'identity_rejected')):
            value = dict(self.plan); value.update(change); self.write(self.plan_path, value)
            with self.trust(), self.assertRaisesRegex(ValueError, reason):
                personal._validate_authority(self.plan_path, self.digest(self.plan_path))
        value = dict(self.plan); value['optional_cleanup'] = [dict(path=str(self.base)), dict(path=str(self.cache))]
        self.write(self.plan_path, value)
        anchored = dict(self.anchor_value, plan_sha256=self.digest(self.plan_path)); self.write(self.anchor, anchored)
        with self.trust(), self.assertRaisesRegex(ValueError, 'original_roots_rejected'):
            personal._validate_authority(self.plan_path, self.digest(self.plan_path))

    def test_actual_protection_check_rejects_user_writable_temp_anchor(self):
        with patch.object(personal, '_machine_binding', return_value='e'*64), patch.object(personal, '_identity',
            return_value=dict(user_sid=self.sid,integrity=8192,elevated=False,ui_access=False)):
            with self.assertRaises(ValueError):
                personal._validate_authority(self.plan_path, self.plan_sha)

    def test_busy_file_and_junction_reject_without_any_recycling(self):
        import win32file
        occupied = win32file.CreateFile(str(self.data/'profile.json'),0x40000000,1,None,3,0,None)
        try:
            with self.trust(), self.assertRaisesRegex(ValueError,'file_busy_or_unavailable:32'):
                personal.prepare(self.plan_path,self.plan_sha,self.review_path)
        finally:
            occupied.Close()
        outside = self.base/'outside'; outside.mkdir(); (outside/'keep.txt').write_bytes(b'keep external')
        link = self.data/'junction'
        result = subprocess.run(['cmd','/d','/c','mklink','/J',str(link),str(outside)],capture_output=True)
        if result.returncode:
            self.skipTest('owned TEMP junction creation unavailable')
        with self.trust(), self.assertRaisesRegex(ValueError,'link_rejected'):
            personal.prepare(self.plan_path,self.plan_sha,self.review_path)
        self.assertTrue((outside/'keep.txt').is_file())

    def test_new_instance_or_install_owner_blocks_preparation(self):
        (self.program/'active.json').write_bytes(b'new active')
        with self.trust(),self.assertRaisesRegex(ValueError,'installation_is_active'):
            personal.prepare(self.plan_path,self.plan_sha,self.review_path)
        (self.program/'active.json').rename(self.base/'kept-active.json')
        owner=self.program/'recovery'/('installation-'+('c'*32))/'install-owner.json'
        owner.parent.mkdir();owner.write_bytes(b'new protected install owner')
        timestamp=self.anchor.stat().st_mtime_ns+1_000_000_000
        os.utime(owner,ns=(timestamp,timestamp))
        with self.trust(),self.assertRaisesRegex(ValueError,'new_install_operation'):
            personal.prepare(self.plan_path,self.plan_sha,self.review_path)

    def test_runtime_probe_is_bound_to_original_program_root_and_sid(self):
        with self.trust():
            authority=personal._validate_authority(self.plan_path,self.plan_sha)
        with patch('tools.prepare_uninstall.runtime_inventory',return_value=[dict(pid=900001)]) as inventory:
            with self.assertRaisesRegex(ValueError,'owned_processes_still_running'):
                personal._runtime_guard(authority)
        location=inventory.call_args.args[0]
        self.assertEqual(location.program_root,self.program)
        self.assertEqual(location.user_sid,self.sid)

    def test_review_and_receipt_paths_cannot_be_inside_any_installation_subtree(self):
        for output in (self.data/'review.json',self.program/'review.json'):
            with self.trust(),self.assertRaisesRegex(ValueError,'outside_installation'):
                personal.prepare(self.plan_path,self.plan_sha,output)
            self.assertFalse(output.exists())
        result=self.prepare()
        with self.trust(),self.assertRaisesRegex(ValueError,'outside_installation'):
            personal.apply(self.review_path,result['review_sha256'],confirmed=True,receipt_path=self.cache/'receipt.json')
        self.assertTrue((self.cache/'cached.bin').is_file())

    def test_changed_review_or_tree_rejects_before_dispatch(self):
        result = self.prepare()
        with self.trust(),patch.object(personal,'_Recycler') as worker:
            with self.assertRaisesRegex(ValueError,'material_changed'):
                personal.apply(self.review_path,'0'*64,confirmed=True)
            (self.data/'profile.json').write_bytes(b'edited after review')
            with self.assertRaisesRegex(ValueError,'tree_changed_reinspect_required'):
                personal.apply(self.review_path,result['review_sha256'],confirmed=True)
            worker.assert_not_called()

    def test_scope_can_select_cache_without_touching_data_or_program(self):
        result=self.prepare(kinds=('cache',))
        self.assertEqual(result['selected_roots'],[str(self.cache)])
        self.assertEqual(result['file_count'],1)
        review=json.loads(self.review_path.read_bytes())
        review['files'][0]['path']=str(self.sentinel)
        self.write(self.review_path,review)
        with self.trust(),patch.object(personal,'_Recycler') as worker,self.assertRaisesRegex(ValueError,'tree_changed'):
            personal.apply(self.review_path,self.digest(self.review_path),confirmed=True)
        worker.assert_not_called()

    def test_partial_dispatch_has_exact_receipt_and_requires_fresh_inventory(self):
        result=self.prepare()
        kept=self.base/'simulated-recycle';kept.mkdir()
        class PartialRecycler:
            process=SimpleNamespace(pid=999999)
            count=0
            def __init__(self,*_):pass
            def __enter__(self):return self
            def __exit__(self,*_):pass
            def recycle(self,row):
                self.count+=1
                if self.count==2:raise OSError('fixture cancellation after one effect')
                Path(row['path']).rename(kept/str(self.count))
        with self.trust(),patch.object(personal,'_Recycler',PartialRecycler):
            receipt=personal.apply(self.review_path,result['review_sha256'],confirmed=True)
        self.assertFalse(receipt['complete']);self.assertTrue(receipt['system_changed'])
        self.assertEqual(len(receipt['recycled']),1);self.assertEqual(len(receipt['outcome_unknown']),1)
        self.assertEqual(receipt['state'],'incomplete_reinspect_required')
        self.assertTrue(Path(receipt['outcome_unknown'][0]).is_file())
        self.assertTrue(self.sentinel.is_file())
        saved=json.loads(Path(receipt['receipt_path']).read_bytes())
        self.assertEqual(saved,receipt)
        with self.trust(),self.assertRaisesRegex(ValueError,'tree_changed'):
            personal.apply(self.review_path,result['review_sha256'],confirmed=True)
        with self.trust():
            remaining=personal.prepare(self.plan_path,self.plan_sha,self.base/'new-review.json')
        self.assertEqual(remaining['file_count'],2)

    def test_actual_medium_worker_recycles_only_one_owned_temp_file_and_keeps_directories(self):
        actual=personal._identity()
        if actual['integrity']!=8192 or actual['elevated'] or actual['ui_access']:
            self.skipTest('actual Medium non-UIAccess test token required')
        target=self.cache/'会话 ü 资料.txt'
        (self.cache/'cached.bin').rename(target)
        result=self.prepare(kinds=('cache',))
        sentinel=self.digest(self.sentinel)
        with self.trust():
            receipt=personal.apply(self.review_path,result['review_sha256'],confirmed=True)
        self.assertTrue(receipt['complete'],receipt)
        self.assertEqual(receipt['recycled'],[str(target)])
        self.assertFalse(target.exists())
        self.assertTrue(self.cache.is_dir());self.assertTrue((self.data/'profile.json').is_file())
        self.assertEqual(self.digest(self.sentinel),sentinel)
        self.assertFalse(receipt['permanent_delete'])

    def test_cancel_before_first_dispatch_does_not_start_worker(self):
        review=self.prepare()
        cancel=self.base/'cancel.json';cancel.write_text(review['review_sha256'],encoding='ascii')
        with self.trust(),patch.object(personal,'_Recycler') as worker:
            result=personal.apply(self.review_path,review['review_sha256'],confirmed=True,cancel_path=cancel)
        worker.assert_not_called()
        self.assertEqual(result['state'],'cancelled_reinspect_required')
        self.assertTrue(result['cancelled']);self.assertFalse(result['complete']);self.assertFalse(result['system_changed'])
        self.assertEqual(result['recycled'],[]);self.assertEqual(result['outcome_unknown'],[])
        self.assertEqual(len(personal._inventory([self.data,self.cache])['files']),3)

    def test_cancel_after_one_confirmed_item_stops_future_dispatches_and_keeps_exact_result(self):
        review=self.prepare()
        cancel=self.base/'cancel-after-one.txt';kept=self.base/'simulated-recycled-one'
        calls=[]
        class CancelAfterOne:
            process=SimpleNamespace(pid=999999)
            def __init__(self,*_):pass
            def __enter__(self):return self
            def __exit__(self,*_):pass
            def recycle(self,row):
                calls.append(row['path']);Path(row['path']).rename(kept)
                cancel.write_text(review['review_sha256'],encoding='ascii')
        with self.trust(),patch.object(personal,'_Recycler',CancelAfterOne):
            result=personal.apply(self.review_path,review['review_sha256'],confirmed=True,cancel_path=cancel)
        self.assertEqual(len(calls),1);self.assertEqual(result['recycled'],calls)
        self.assertEqual(result['state'],'cancelled_reinspect_required');self.assertTrue(result['cancelled'])
        self.assertFalse(result['complete']);self.assertTrue(result['system_changed']);self.assertEqual(result['outcome_unknown'],[])
        events=[json.loads(line) for line in Path(result['journal_path']).read_text().splitlines()]
        self.assertEqual([event['kind'] for event in events],['batch_intent','recycled','cancelled'])
        self.assertEqual(len(personal._inventory([self.data,self.cache])['files']),2)

    def test_cancel_marker_must_be_exact_hash_and_outside_installation_materials(self):
        review=self.prepare()
        for cancel in (self.data/'cancel.txt',self.review_path):
            with self.trust(),self.assertRaises(ValueError):
                personal.apply(self.review_path,review['review_sha256'],confirmed=True,cancel_path=cancel)
        cancel=self.base/'wrong-cancel.txt';cancel.write_text('0'*64,encoding='ascii')
        with self.trust(),patch.object(personal,'_Recycler') as worker:
            result=personal.apply(self.review_path,review['review_sha256'],confirmed=True,cancel_path=cancel)
        worker.assert_not_called();self.assertFalse(result['cancelled']);self.assertFalse(result['system_changed'])
        self.assertEqual(result['reason'],'personal_data_cancel_binding_changed')

    def test_many_file_progress_has_bounded_intents_compact_receipts_and_verified_hash_chain(self):
        for index in range(260):
            (self.cache/(str(index)+'.bin')).write_bytes(b'owned many-file fixture')
        review=self.prepare(kinds=('cache',))
        kept=self.base/'simulated-recycle-many';kept.mkdir()
        snapshots=[];original=personal._new_json
        class Recycler:
            process=SimpleNamespace(pid=999999)
            def __init__(self,*_):pass
            def __enter__(self):return self
            def __exit__(self,*_):pass
            def recycle(self,row):Path(row['path']).rename(kept/Path(row['path']).name)
        def capture(path,value):
            if value.get('operation')=='uninstall_personal_data':
                snapshots.append(json.loads(json.dumps(value)))
            original(path,value)
        with self.trust(),patch.object(personal,'_Recycler',Recycler),patch.object(personal,'_new_json',side_effect=capture):
            result=personal.apply(self.review_path,review['review_sha256'],confirmed=True)
        self.assertTrue(result['complete']);self.assertEqual(result['recycled_count'],261)
        self.assertEqual(sum('recycled' in value for value in snapshots),1)
        self.assertTrue(all('outcome_unknown' not in value for value in snapshots[:-1]))
        events=[json.loads(line) for line in Path(result['journal_path']).read_text().splitlines()]
        self.assertEqual([len(value['paths']) for value in events if value['kind']=='batch_intent'],[256,5])
        tip='0'*64
        for sequence,value in enumerate(events,1):
            self.assertEqual(value['sequence'],sequence);self.assertEqual(value['previous_sha256'],tip)
            tip=value.pop('sha256')
            self.assertEqual(tip,personal._sha(json.dumps(value,sort_keys=True,separators=(',',':')).encode('utf-8')))
        self.assertEqual(result['journal_tip_sha256'],tip)
        self.assertEqual(result['journal_events'],len(events))

    def test_python_slow_hash_then_new_install_rejects_before_dispatch(self):
        review=self.prepare(kinds=('cache',))
        started=False;calls=[];original=personal._file_row
        class Recycler:
            process=SimpleNamespace(pid=999999)
            def __init__(self,*_):pass
            def __enter__(self):
                nonlocal started
                started=True
                return self
            def __exit__(self,*_):pass
            def recycle(self,row):calls.append(row['path'])
        def slow_file_row(path):
            result=original(path)
            if started:(self.program/'active.json').write_bytes(b'fixture install became active during hash')
            return result
        with self.trust(),patch.object(personal,'_Recycler',Recycler),patch.object(personal,'_file_row',side_effect=slow_file_row):
            result=personal.apply(self.review_path,review['review_sha256'],confirmed=True)
        self.assertEqual(calls,[]);self.assertFalse(result['system_changed'])
        self.assertEqual(result['reason'],'personal_data_installation_is_active')
        self.assertTrue((self.cache/'cached.bin').is_file())

    def test_worker_slow_hash_then_new_install_rejects_before_com_without_unknown_effect(self):
        review=self.prepare(kinds=('cache',))
        source=personal._guarded_recycle_source()
        marker='        RequirePersonalDataIdle();'
        self.assertEqual(source.count(marker),1)
        injected=source.replace(marker,'        File.WriteAllText(Path.Combine(GuardProgramRoot,"active.json"),"owned fixture after hash");\n'+marker)
        with self.trust(),patch.object(personal,'_guarded_recycle_source',return_value=injected):
            result=personal.apply(self.review_path,review['review_sha256'],confirmed=True)
        self.assertFalse(result['complete']);self.assertFalse(result['system_changed'])
        self.assertEqual(result['reason'],'personal_data_installation_is_active')
        self.assertEqual(result['outcome_unknown'],[]);self.assertEqual(result['recycled'],[])
        self.assertEqual(result['rejected_before_dispatch'],str(self.cache/'cached.bin'))
        self.assertTrue((self.cache/'cached.bin').is_file())

    def test_worker_cancel_after_hash_is_acknowledged_before_com_without_unknown_effect(self):
        review=self.prepare(kinds=('cache',));cancel=self.base/'late-cancel.txt'
        source=personal._guarded_recycle_source()
        marker='        RequirePersonalDataIdle();'
        injected=source.replace(marker,'        File.WriteAllText(GuardCancelPath,GuardReviewHash,System.Text.Encoding.ASCII);\n'+marker)
        with self.trust(),patch.object(personal,'_guarded_recycle_source',return_value=injected):
            result=personal.apply(self.review_path,review['review_sha256'],confirmed=True,cancel_path=cancel)
        self.assertEqual(result['state'],'cancelled_reinspect_required');self.assertTrue(result['cancelled'])
        self.assertFalse(result['system_changed']);self.assertEqual(result['outcome_unknown'],[])
        self.assertTrue((self.cache/'cached.bin').is_file())


if __name__=='__main__':
    unittest.main()
