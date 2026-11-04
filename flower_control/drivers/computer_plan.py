"""Finite legacy plans composed from the current guarded window operations.

No old runtime, indefinite holds, script evaluator or uncertain-input retry.
"""
from contextvars import ContextVar
from dataclasses import replace
import base64
import hashlib
import io
import json
import math
import sqlite3
import threading
import time
import uuid
import zlib

from PIL import Image

from flower_control.control.native import process_identity,process_is_alive
from flower_control.control.state import ControlError
from .computer_capture import CaptureResult
from .computer_legacy_actions import canonical_batch
from .computer_native import assert_window,assert_geometry
from .computer_returned_points import map_returned_points
from .desktop_ordinary_authority import _snapshot
from .visual_conditions import VisualCondition


compound_guard=ContextVar('flower_window_compound_guard',default=None)
expected_control_cycle=ContextVar('flower_window_control_cycle',default=None)


def number(value,low,high):
    if type(value) not in (int,float) or not low<=value<=high or not math.isfinite(value):
        raise ControlError('invalid_plan_number')
    return value


def validate_steps(steps,observed,planning_checkpoint=None):
    from .computer_mcp import _plan_input
    if type(steps) is not list or not 1<=len(steps)<=8:raise ControlError('invalid_plan_steps')
    result=[];samples=0;budget=0
    for raw in steps:
        if type(raw) is not dict:raise ControlError('invalid_plan_step')
        kind=raw.get('type');step=dict(raw)
        if kind=='dwell':
            if set(raw)!={'type','duration'}:raise ControlError('invalid_plan_step')
            budget+=number(raw['duration'],.1,30)
        elif kind=='sample':
            if set(raw)-{'type','max_size'}:raise ControlError('invalid_plan_step')
            size=raw.get('max_size',1024)
            if type(size) is not int or not 256<=size<=1024:raise ControlError('invalid_plan_sample_size')
            samples+=1;step['max_size']=size
        elif kind in {'act','scroll','repeat_visual'}:
            allowed=({'type','actions'} if kind=='act' else {'type','x','y','dx','dy','clicks','coordinate_space'}
                if kind=='scroll' else {'type','actions','roi','roi_anchor','roi_units','state','threshold',
                    'settle','stop','keyframes','max_iterations','max_duration'})
            if set(raw)-allowed:raise ControlError('invalid_plan_step')
            actions=[raw] if kind=='scroll' else raw.get('actions')
            canonical=canonical_batch({'actions':actions})
            mapped=map_returned_points('batch',canonical,observed)['steps']
            # Validate all actions before reserving/starting the plan. Each
            # action stays a separate current executor call and exact receipt.
            for action in mapped:
                if action['command'] not in {'text','key','move','hover','click','double_click','scroll',
                        'drag','mouse_hold','key_mouse','move_relative'}:raise ControlError('invalid_plan_action')
                _plan_input(action['command'],action['arguments'],observed['geometry'],
                    planning_checkpoint=planning_checkpoint)
            step['prepared_actions']=mapped
            if kind=='repeat_visual':
                count=raw.get('max_iterations',20)
                if type(count) is not int or not 1<=count<=100:raise ControlError('invalid_plan_iterations')
                step['max_iterations']=count
                step['max_duration']=number(raw.get('max_duration',30),1,120)
                budget+=step['max_duration']
                settle=raw.get('settle',dict(state='stable',threshold=5,timeout=3))
                stop=raw.get('stop',dict(state='unchanged' if raw.get('state','stable')=='stable' else 'changed',threshold=raw.get('threshold',5)))
                if (type(settle) is not dict or set(settle)-{'state','threshold','timeout'} or settle.get('state','stable')!='stable'
                        or type(stop) is not dict or set(stop)-{'state','threshold'} or stop.get('state') not in {'changed','unchanged'}
                        or raw.get('keyframes','start_change_failure_end')!='start_change_failure_end'):
                    raise ControlError('invalid_repeat_condition')
                step['settle']=dict(timeout=number(settle.get('timeout',3),.1,30),threshold=number(settle.get('threshold',5),0,255))
                step['stop']=dict(state=stop['state'],threshold=number(stop.get('threshold',5),0,255))
        elif kind=='wait_visual':
            if set(raw)-{'type','roi','state','timeout','threshold'}:raise ControlError('invalid_plan_step')
            step['timeout']=number(raw.get('timeout',3),.1,30);budget+=step['timeout']
        else:raise ControlError('invalid_plan_step')
        if kind in {'wait_visual','repeat_visual'}:
            if raw.get('state','stable') not in {'changed','stable'}:raise ControlError('invalid_plan_visual_state')
            step['state']=raw.get('state','stable');step['threshold']=number(raw.get('threshold',5),0,255)
            roi=raw.get('roi');units=raw.get('roi_units','pixels');anchor=raw.get('roi_anchor','returned_image')
            if (type(roi) is not list or len(roi)!=4 or any(type(v) is not int for v in roi)
                    or not 0<=roi[0]<roi[2] or not 0<=roi[1]<roi[3]
                    or units not in {'pixels','normalized_1000'} or anchor not in {'returned_image','window','client'}):
                raise ControlError('invalid_plan_visual_roi')
            # Convert the originally observed coordinate frame once. No later
            # screenshot is allowed to silently reinterpret the requested ROI.
            geometry=observed['geometry'];capture=observed['capture_descriptor']
            if anchor=='returned_image':
                view=observed.get('returned_image_view')
                if view is None:
                    from .computer_returned_points import ReturnedImageView
                    view=ReturnedImageView((capture.width,capture.height),(0,0,capture.width,capture.height),(capture.width,capture.height))
                size=view.size;origin=(capture.source_bounds.left+view.box[0],capture.source_bounds.top+view.box[1])
                extent=(view.box[2]-view.box[0],view.box[3]-view.box[1])
            else:
                origin=geometry.client_origin if anchor=='client' else (geometry.window.left,geometry.window.top)
                extent=geometry.client_size if anchor=='client' else (geometry.window.width,geometry.window.height)
                size=extent
            denominator=(1000,1000) if units=='normalized_1000' else size
            if roi[2]>denominator[0] or roi[3]>denominator[1]:raise ControlError('invalid_plan_visual_roi')
            physical=[origin[i%2]+roi[i]*extent[i%2]//denominator[i%2] for i in range(4)]
            local=[physical[i]-(capture.source_bounds.left if i%2==0 else capture.source_bounds.top) for i in range(4)]
            if not 0<=local[0]<local[2]<=capture.width or not 0<=local[1]<local[3]<=capture.height:
                raise ControlError('invalid_plan_visual_roi')
            step['prepared_roi']=local
        result.append(step)
    if samples>4 or budget>120:raise ControlError('plan_budget_exceeded')
    return result


class ComputerPlans:
    def __init__(self):
        self.lock=threading.RLock();self.plans={};self.closed=False
        # Stop signals must not share a lock with metadata transactions.
        self._stop_gate=threading.RLock();self._stop_plans={};self._draining={}
        self._drain_gate=threading.RLock()

    def _signal_plan(self,task,identifier):
        with self._stop_gate:
            plan=self._stop_plans.get(identifier)
            if plan is None:return
            if plan['task']!=task:raise ControlError('plan_not_found')
            if plan['state']!='pending':return
            plan['stop'].set();active=plan['active'];runtime=plan['runtime']
        if active is not None:runtime.request_host_stop(runtime._key(task,active))

    def _signal_task(self,task,*,drain=False):
        token=object()
        with self._stop_gate:
            if drain:
                current=self._draining.setdefault(task,dict(pending=set(),epoch=None))
                current['pending'].add(token)
            plans=[p for p in self._stop_plans.values() if p['task']==task and p['state']=='pending']
            for plan in plans:plan['stop'].set()
        for plan in plans:
            active=plan['active']
            if active is not None:plan['runtime'].request_host_stop(plan['runtime']._key(task,active))
        return token

    def busy(self, task):
        with self.lock:
            return any(plan['task']==task and not plan['done'].is_set()
                       for plan in self.plans.values())

    @staticmethod
    def table(store):
        with store.transaction() as db:
            db.execute('CREATE TABLE IF NOT EXISTS legacy_computer_plans('
                'id TEXT PRIMARY KEY,task TEXT NOT NULL,action TEXT NOT NULL,digest TEXT NOT NULL,'
                'state TEXT NOT NULL,reason TEXT,owner TEXT NOT NULL,updated REAL NOT NULL,'
                'cancel_requested INTEGER NOT NULL DEFAULT 0,'
                'deadline REAL,'
                'UNIQUE(task,action))')
            if 'cancel_requested' not in {r[1] for r in db.execute('PRAGMA table_info(legacy_computer_plans)')}:
                db.execute('ALTER TABLE legacy_computer_plans ADD COLUMN cancel_requested INTEGER NOT NULL DEFAULT 0')
            if 'deadline' not in {r[1] for r in db.execute('PRAGMA table_info(legacy_computer_plans)')}:
                db.execute('ALTER TABLE legacy_computer_plans ADD COLUMN deadline REAL')
            db.execute('CREATE TABLE IF NOT EXISTS legacy_plan_task_epochs('
                'task TEXT PRIMARY KEY,epoch INTEGER NOT NULL,draining INTEGER NOT NULL)')

    def start(self,runtime,target,observation_id,steps,action_id,*,task,stopped,ownership=None,raw_arguments=None):
        with self._stop_gate:
            if self.closed or task in self._draining:raise ControlError('plan_task_finishing')
        store=runtime.store;self.table(store)
        from flower_control.control.business_plan import require_root
        require_root(store, task, runtime._key(task, action_id))
        with store.transaction() as db:
            db.execute('INSERT OR IGNORE INTO legacy_plan_task_epochs VALUES(?,0,0)',(task,))
            epoch=db.execute('SELECT epoch FROM legacy_plan_task_epochs WHERE task=?',(task,)).fetchone()[0]
        payload=dict(target=target,observation_id=observation_id,steps=steps,action_id=action_id)
        from .computer_mcp import valid_task_purpose,valid_next_step
        source=raw_arguments or {}
        display={key:value for key,value in {'task_purpose':valid_task_purpose(source.get('task_purpose')),
            'next_step':valid_next_step(source.get('next_step'))}.items() if value is not None}
        payload.update(display)
        if type(action_id) is not str or not 1<=len(action_id)<=128:raise ControlError('invalid_plan_action_id')
        digest=hashlib.sha256(json.dumps(payload if raw_arguments is None else raw_arguments,
            sort_keys=True,ensure_ascii=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
        with store.read_transaction() as db:
            previous=db.execute('SELECT * FROM legacy_computer_plans WHERE task=? AND action=?',(task,action_id)).fetchone()
        if previous is not None:
            if previous['digest']!=digest:raise ControlError('action_id_conflict')
            return dict(self.status(store,task,previous['id']),replayed=True)
        grant=runtime._authorized('flower_computer_plan',payload,target,'input',trusted_task=task)
        with runtime._gate:observed=runtime._observations.get(observation_id)
        if (observed is None or observed['task']!=task or observed['identity']!=grant.identity
                or observed['expires']<=store.clock() or observed.get('shared_resource')!=grant.shared_resource):
            raise ControlError('observation_unavailable')
        last_planning_check=[None]
        def planning_checkpoint():
            now=time.monotonic()
            if last_planning_check[0] is not None and now-last_planning_check[0]<.02:return
            last_planning_check[0]=now
            if stopped() or store.task_write_stopped(task,observation=observation_id):
                raise ControlError('plan_cancelled')
        prepared=validate_steps(steps,observed,planning_checkpoint)
        state,_=_snapshot(store,task,'capture')
        assert_window(grant.identity);assert_geometry(observed['geometry'])
        if not runtime._shared_observation_current(grant,observed):raise ControlError('observation_unavailable')
        control_cycle = runtime._pin_control_run(grant)
        with self.lock:
            if self.closed or stopped():raise ControlError('plan_cancelled')
            for plan in self.plans.values():
                if plan['task']==task and plan['state']=='pending':raise ControlError('plan_busy')
            for key,old in list(self.plans.items()):
                if old['done'].is_set() and old.get('metadata_pending'):
                    try:self.save(old);old['metadata_pending']=False
                    except sqlite3.Error:pass
                if old['done'].is_set() and old['state']!='pending' and not old.get('metadata_pending') and time.monotonic()-old['finished']>900:
                    self.plans.pop(key)
                    with self._stop_gate:self._stop_plans.pop(key,None)
            if len(self.plans)>=32:raise ControlError('plan_capacity')
            identifier=uuid.uuid4().hex
            plan=dict(id=identifier,task=task,action=action_id,state='pending',reason=None,index=0,iteration=0,
                stop=threading.Event(),done=threading.Event(),samples=[],events=[],active=None,
                runtime=runtime,target=target,identity=grant.identity,geometry=observed['geometry'],authority=state,
                steps=prepared,initial=observed,last_observed=observed,finished=None,launch_stopped=stopped,epoch=epoch,
                samples_remaining=sum(s['type']=='sample' for s in prepared),control_cycle=control_cycle,
                display=display)
            with store.transaction() as db:
                fence=db.execute('SELECT epoch,draining FROM legacy_plan_task_epochs WHERE task=?',(task,)).fetchone()
                if fence is None or fence['draining'] or fence['epoch']!=epoch:raise ControlError('plan_task_finishing')
                for other in db.execute("SELECT id,owner FROM legacy_computer_plans WHERE task=? AND state='pending'",(task,)):
                    if process_is_alive(other['owner']):
                        old=self.plans.get(other['id'])
                        raise ControlError('plan_metadata_persistence_pending' if old is not None and old.get('metadata_pending') else 'plan_busy')
                db.execute('INSERT INTO legacy_computer_plans(id,task,action,digest,state,reason,owner,updated,deadline) VALUES(?,?,?,?,?,?,?,?,?)',
                    (identifier,task,action_id,digest,'pending',None,process_identity(),store.clock(),store.clock()+125))
            self.plans[identifier]=plan
            if ownership is not None:ownership['plan_id']=identifier
            thread=threading.Thread(target=self.run,args=(plan,),name='flower-finite-plan',daemon=True)
            plan['thread']=thread
            try:
                with self._stop_gate:
                    if self.closed or task in self._draining:raise ControlError('plan_task_finishing')
                    self._stop_plans[identifier]=plan
                store.record_event('computer_plan_created',task=task,action=identifier,details={'steps':len(prepared),'request_digest':digest})
                thread.start()
            except BaseException:
                plan.update(state='stopped',reason='plan_worker_unavailable',finished=time.monotonic());plan['done'].set()
                try:self.save(plan)
                except sqlite3.Error:plan['metadata_pending']=True
                raise
        return dict(plan_id=identifier,state='pending',dispatched=None,business_outcome_verified=False,
            dispatch_status='query_original_child_receipts')

    def save(self,plan):
        with plan['runtime'].store.transaction() as db:
            db.execute('UPDATE legacy_computer_plans SET state=?,reason=?,updated=? WHERE id=? AND task=?',
                (plan['state'],plan['reason'],plan['runtime'].store.clock(),plan['id'],plan['task']))

    def check(self,plan,*,deadline=True):
        with self._stop_gate:
            if plan['task'] in self._draining:raise ControlError('plan_cancelled')
        if self.closed or plan['stop'].is_set() or plan['launch_stopped']():raise ControlError('plan_cancelled')
        cycle=plan.get('control_cycle')
        if cycle is not None and (cycle['stop'].is_set() or cycle['ended']):
            plan['stop'].set();raise ControlError('computer_stopped')
        from flower_control.control.business_plan import require_root
        try:
            require_root(plan['runtime'].store, plan['task'], plan['runtime']._key(plan['task'], plan['action']))
        except ControlError as error:
            if error.code == 'business_chain_stopped':plan['stop'].set()
            raise
        if deadline and time.monotonic()>=plan['deadline']:raise ControlError('plan_deadline')
        if deadline and time.monotonic()>=plan.get('repeat_deadline',float('inf')):
            raise ControlError('plan_repeat_deadline')
        state,_=_snapshot(plan['runtime'].store,plan['task'],'capture')
        if state!=plan['authority']:raise ControlError('plan_authority_changed')
        assert_window(plan['identity']);assert_geometry(plan['geometry'])
        from flower_control.control.native import FOREGROUND_INPUT_RESOURCE
        resources=(plan['runtime']._resource(plan['identity']),FOREGROUND_INPUT_RESOURCE)
        with plan['runtime'].store.read_transaction() as db:
            fence=db.execute('SELECT epoch,draining FROM legacy_plan_task_epochs WHERE task=?',(plan['task'],)).fetchone()
            if fence is None or fence['draining'] or fence['epoch']!=plan['epoch']:
                plan['stop'].set();raise ControlError('plan_cancelled')
            row=db.execute('SELECT cancel_requested FROM legacy_computer_plans WHERE id=? AND task=?',
                (plan['id'],plan['task'])).fetchone()
            if row is None or row['cancel_requested']:
                plan['stop'].set();raise ControlError('plan_cancelled')
            for resource in resources:
                row=db.execute('SELECT paused,quarantined FROM resources WHERE id=?',(resource,)).fetchone()
                if row is not None and (row['paused'] or plan['runtime'].store._effective_quarantine(db,resource,row)):raise ControlError('resource_paused_or_quarantined')
        return True

    def operation(self,plan,name,*args,**kwargs):
        self.check(plan)
        runtime=plan['runtime'];action='plan-'+plan['id']+'-'+uuid.uuid4().hex
        from flower_control.control.business_plan import bind_child
        bind_child(runtime.store, plan['task'], runtime._key(plan['task'], plan['action']), runtime._key(plan['task'], action))
        with self.lock:plan['active']=action
        key=runtime.begin_host_call(plan['task'],action);recorded=False
        try:
            if name=='observe':result=runtime.observe(plan['target'],action,trusted_task=plan['task'],**plan.get('display',{}))
            else:result=runtime.input(plan['target'],args[0],args[1],args[2],action,trusted_task=plan['task'],**plan.get('display',{}))
            detail=result.get('result',{})
            if result.get('queued'):
                runtime.cancel(action,trusted_task=plan['task']);raise ControlError('plan_operation_busy')
            if name=='observe':
                self.check(plan)
                handle=detail.get('observation_id')
                if handle is None:raise ControlError(result.get('reason',detail.get('reason','plan_capture_unavailable')))
                with runtime._gate:observed=runtime._observations.get(handle)
                plan['last_observed']=observed
                return handle,observed
            receipt=result.get('receipt',{})
            with self.lock:plan['events'].append(dict(action_id=action,state=receipt.get('state'),
                business_dispatched=receipt.get('business_dispatched'),input_release=receipt.get('input_release'),
                elapsed_ms=round((time.monotonic()-plan['started'])*1000,3)))
            recorded=True
            self.check(plan)
            if (receipt.get('state')=='outcome_uncertain' or receipt.get('input_release') not in {'released','not_used'}
                    or detail.get('dispatched') is not True or detail.get('state') not in {'outcome_unverified','input_dispatched'}
                    or detail.get('reason') is not None or detail.get('timed_plan_completed') is False):
                raise ControlError(detail.get('reason',result.get('reason','plan_input_not_completed')))
            return result
        except BaseException:
            if name!='observe' and not recorded:
                try:receipt=runtime.action_status(action,trusted_task=plan['task'])
                except Exception:receipt={}
                with self.lock:plan['events'].append(dict(action_id=action,state=receipt.get('state','unavailable'),
                    business_dispatched=receipt.get('business_dispatched'),input_release=receipt.get('input_release'),
                    elapsed_ms=round((time.monotonic()-plan['started'])*1000,3)))
            raise
        finally:
            runtime.end_host_call(key)
            with self.lock:plan['active']=None

    @staticmethod
    def capture(observed):
        return replace(observed['capture_descriptor'],bmp=zlib.decompress(observed['capture_compressed']))

    def sample(self,plan,observed,size=1024,kind='sample'):
        if kind!='sample' and (any(s['kind']==kind for s in plan['samples'])
                or len(plan['samples'])>=4-plan['samples_remaining']):return
        if len(plan['samples'])>=4:raise ControlError('plan_sample_capacity')
        from .computer_png import bmp_to_png
        raw=bmp_to_png(self.capture(observed).bmp)
        with Image.open(io.BytesIO(raw)) as image:
            image.thumbnail((size,size),Image.Resampling.LANCZOS);output=io.BytesIO();image.save(output,format='PNG')
            data=output.getvalue();width,height=image.size
        if sum(len(s['png']) for s in plan['samples'])+len(data)>16_000_000:raise ControlError('plan_sample_capacity')
        self.check(plan)
        with self.lock:plan['samples'].append(dict(kind=kind,png=data,width=width,height=height,
            policy_revision=observed['capture_descriptor'].privacy_revision,offset_ms=round((time.monotonic()-plan['started'])*1000,3)))
        if kind=='sample':plan['samples_remaining']-=1

    def actions(self,plan,step):
        before=None
        for action in step['prepared_actions']:
            handle,observed=self.operation(plan,'observe')
            if before is None:before=observed
            self.operation(plan,'input',handle,action['command'],action['arguments'])
        return before

    def wait_visual(self,plan,baseline,step,*,repeat=False):
        timeout=step['settle']['timeout'] if repeat else step['timeout']
        threshold=step['settle']['threshold'] if repeat else step['threshold']
        condition='image_stable' if repeat or step['state']=='stable' else 'image_changed'
        matcher=VisualCondition(condition,self.capture(baseline),roi=step['prepared_roi'],threshold=threshold,stable_ms=100)
        changed=VisualCondition('image_changed',self.capture(baseline),roi=step['prepared_roi'],threshold=threshold)
        began=time.monotonic();saw_change=False;last=baseline
        while time.monotonic()-began<timeout:
            self.check(plan);_handle,last=self.operation(plan,'observe');frame=self.capture(last)
            elapsed=(time.monotonic()-began)*1000
            now_changed=changed.sample(frame,elapsed)
            if repeat and now_changed and not saw_change:self.sample(plan,last,kind='repeat_change')
            saw_change=now_changed or saw_change
            if matcher.sample(frame,elapsed) and (not repeat or saw_change):return last
            plan['stop'].wait(.05)
        if repeat and not saw_change:return last
        raise ControlError('plan_visual_timeout')

    def run(self,plan):
        plan['started']=time.monotonic();plan['deadline']=plan['started']+120
        token=compound_guard.set(lambda:self.check(plan));baseline=plan['initial']
        cycle_token=expected_control_cycle.set(plan.get('control_cycle'))
        try:
            for index,step in enumerate(plan['steps']):
                with self.lock:plan['index']=index
                self.check(plan);kind=step['type']
                if kind=='dwell':
                    until=time.monotonic()+step['duration']
                    while time.monotonic()<until:
                        self.check(plan);plan['stop'].wait(min(.05,max(0,until-time.monotonic())))
                elif kind=='sample':
                    _handle,current=self.operation(plan,'observe');self.sample(plan,current,step['max_size'])
                elif kind in {'act','scroll'}:baseline=self.actions(plan,step)
                elif kind=='wait_visual':baseline=self.wait_visual(plan,baseline,step)
                else:
                    began=time.monotonic();matched=False
                    plan['repeat_deadline']=began+step['max_duration']
                    for iteration in range(step['max_iterations']):
                        plan['iteration']=iteration
                        if time.monotonic()-began>=step['max_duration']:raise ControlError('plan_repeat_deadline')
                        before=self.actions(plan,step)
                        if iteration==0:self.sample(plan,before,kind='repeat_start')
                        current=self.wait_visual(plan,before,step,repeat=True)
                        match=VisualCondition('image_changed' if step['stop']['state']=='changed' else 'image_unchanged',
                            self.capture(before),roi=step['prepared_roi'],threshold=step['stop']['threshold'])
                        if match.sample(self.capture(current),0):matched=True;baseline=current;self.sample(plan,current,kind='repeat_end');break
                    if not matched:raise ControlError('plan_iteration_limit')
                    plan.pop('repeat_deadline',None)
            self.check(plan);plan['state']='completed'
        except BaseException as error:
            plan['state']='cancelled' if plan['stop'].is_set() or self.closed else 'stopped'
            plan['reason']=getattr(error,'code','plan_execution_unavailable')
            if any(s['type']=='repeat_visual' for s in plan['steps']):
                try:self.sample(plan,plan['last_observed'],kind='repeat_failure')
                except Exception:pass
        finally:
            expected_control_cycle.reset(cycle_token)
            compound_guard.reset(token);plan['finished']=time.monotonic();plan['metadata_pending']=True
            plan['steps']=None;plan['initial']=None
            try:
                for attempt in range(3):
                    try:self.save(plan);plan['metadata_pending']=False;break
                    except sqlite3.Error:
                        plan['metadata_pending']=True
                        if attempt<2:time.sleep(.02)
            finally:plan['done'].set()

    def status(self,store,task,identifier,*,wait_seconds=0,cancel=False,stopped=lambda:False):
        if (type(identifier) is not str or not 1<=len(identifier)<=128 or type(wait_seconds) is not int
                or not 0<=wait_seconds<=30):raise ControlError('invalid_plan_status_request')
        if cancel:self._signal_plan(task,identifier)
        self.table(store)
        with self.lock:plan=self.plans.get(identifier)
        if plan is not None and plan['task']!=task:raise ControlError('plan_not_found')
        if plan is not None:
            if plan['done'].is_set() and plan.get('metadata_pending'):
                try:self.save(plan);plan['metadata_pending']=False
                except sqlite3.Error:pass
            if cancel and plan['state']=='pending':
                with store.transaction() as db:
                    db.execute('UPDATE legacy_computer_plans SET cancel_requested=1 WHERE id=? AND task=?',(identifier,task))
                plan['stop'].set()
                if plan['active'] is not None:plan['runtime'].request_host_stop(plan['runtime']._key(task,plan['active']))
            deadline=time.monotonic()+wait_seconds
            while not plan['done'].is_set() and time.monotonic()<deadline and not stopped():
                plan['done'].wait(min(.05,max(0,deadline-time.monotonic())))
            with self.lock:
                return dict(plan_id=identifier,state=plan['state'],reason=plan['reason'],current_step=plan['index'],
                    iteration=plan['iteration'],dispatch_receipts=list(plan['events']),sample_count=len(plan['samples']),
                    metadata_persistence='pending' if plan.get('metadata_pending') or plan['state']!='pending' and not plan['done'].is_set() else 'recorded',
                    business_outcome_verified=False,replay_old_action=False)
        with store.read_transaction() as db:
            row=db.execute('SELECT * FROM legacy_computer_plans WHERE id=? AND task=?',(identifier,task)).fetchone()
        if row is None:raise ControlError('plan_not_found')
        alive=row['state']=='pending' and process_is_alive(row['owner'])
        if cancel and alive:
            with store.transaction() as db:
                db.execute('UPDATE legacy_computer_plans SET cancel_requested=1 WHERE id=? AND task=?',(identifier,task))
        prefix=task+':computer:plan-'+identifier+'-'
        with store.read_transaction() as db:
            receipts=[dict(r) for r in db.execute('SELECT a.id AS action_id,a.state,e.business_dispatched,e.input_release '
                'FROM actions a LEFT JOIN action_effects e ON e.action=a.id '
                'WHERE a.task=? AND substr(a.id,1,?)=? AND COALESCE(e.read_only,0)=0 ORDER BY a.created,a.id',
                (task,len(prefix),prefix))]
        for receipt in receipts:
            receipt['ledger_action_id']=receipt['action_id']
            receipt['action_id']=receipt['action_id'][len(task+':computer:'):]
            if receipt['business_dispatched'] is not None:receipt['business_dispatched']=bool(receipt['business_dispatched'])
        return dict(plan_id=identifier,state='pending' if alive else 'interrupted' if row['state']=='pending' else row['state'],
            running_elsewhere=alive,cancel_requested=bool(row['cancel_requested'] or cancel and alive),
            owner_metadata_deadline_elapsed=bool(alive and row['deadline'] is not None and row['deadline']<=store.clock()),
            recovery='read_original_owner_plan_status_or_original_child_receipts' if alive else None,
            reason='plan_owner_unavailable' if row['state']=='pending' and not alive else row['reason'],
            dispatch_receipts=receipts,samples_available=False,business_outcome_verified=False,replay_old_action=False)

    def samples(self,store,task,identifier):
        with self.lock:plan=self.plans.get(identifier)
        if plan is None or plan['task']!=task:raise ControlError('plan_samples_unavailable')
        self.check(plan,deadline=False)
        for scope in ('target_scope','capture_scope'):
            grant=plan['runtime']._authorized('flower_computer_observe',dict(target=plan['target']),plan['target'],'capture',trusted_task=task)
            with store.read_transaction() as db:store._require_scope(db,task,getattr(grant,scope))
        with self.lock:return list(plan['samples'])

    def stop_task(self,store,task):
        drain_token=self._signal_task(task,drain=True)
        # Serialize only drain bookkeeping, never the immediate Stop signal.
        # Arrival order can differ from SQLite commit order; a later end_drain
        # must not strand an older RAM epoch or clear an uncommitted signal.
        with self._drain_gate:
            epoch=None
            try:
                self.table(store)
                with store.transaction() as db:
                    db.execute('INSERT OR IGNORE INTO legacy_plan_task_epochs VALUES(?,0,0)',(task,))
                    db.execute('UPDATE legacy_plan_task_epochs SET epoch=epoch+1,draining=1 WHERE task=?',(task,))
                    epoch=db.execute('SELECT epoch FROM legacy_plan_task_epochs WHERE task=?',(task,)).fetchone()[0]
                    db.execute("UPDATE legacy_computer_plans SET cancel_requested=1 WHERE task=? AND state='pending'",(task,))
            finally:
                with self._stop_gate:
                    current=self._draining.get(task)
                    if current is not None:
                        current['pending'].discard(drain_token)
                        current['epoch']=epoch
        with self.lock:
            plans=[p for p in self.plans.values() if p['task']==task and p['state']=='pending']
            ended=[p for p in self.plans.values() if p['task']==task and p['done'].is_set() and p.get('metadata_pending')]
        for plan in ended:
            try:self.save(plan);plan['metadata_pending']=False
            except sqlite3.Error:pass
        for plan in plans:
            plan['stop'].set()
            if plan['active'] is not None:plan['runtime'].request_host_stop(plan['runtime']._key(task,plan['active']))
        deadline=time.monotonic()+2
        for plan in plans:plan['done'].wait(max(0,deadline-time.monotonic()))
        while True:
            with store.read_transaction() as db:
                pending=list(db.execute("SELECT owner FROM legacy_computer_plans WHERE task=? AND state='pending'",(task,)))
            if not any(process_is_alive(row['owner']) for row in pending):return dict(drained=True,epoch=epoch)
            if time.monotonic()>=deadline:return dict(drained=False,epoch=epoch)
            time.sleep(.02)

    def end_drain(self,store,task,epoch):
        with self._drain_gate:
            with store.transaction() as db:
                changed=db.execute('UPDATE legacy_plan_task_epochs SET draining=0 WHERE task=? AND epoch=?',(task,epoch)).rowcount
            if changed:
                with self._stop_gate:
                    current=self._draining.get(task)
                    if current is not None and not current['pending'] and current['epoch']==epoch:self._draining.pop(task)

    def close(self):
        with self._stop_gate:
            self.closed=True
            tasks={p['task'] for p in self._stop_plans.values()}
        for task in tasks:self._signal_task(task)
        with self.lock:plans=list(self.plans.values())
        for plan in plans:
            plan['stop'].set()
            if plan['active'] is not None:plan['runtime'].request_host_stop(plan['runtime']._key(plan['task'],plan['active']))
        deadline=time.monotonic()+2
        for plan in plans:plan['done'].wait(max(0,deadline-time.monotonic()))
