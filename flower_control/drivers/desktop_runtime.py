"""Task-isolated ordinary desktop mode; existing window selection is untouched."""
from dataclasses import dataclass
import threading
import uuid
import time

from flower_control.control.state import ControlError
from flower_control.control.native import process_identity,process_is_alive
from .desktop_capture import DesktopCaptureError
from .desktop_capture_job import capture_in_owned_job,DesktopCaptureCleanupError
from .desktop_ordinary_authority import issue_ordinary_desktop_admission,call_digest,_snapshot
from .desktop_policy_capture import DesktopFrameProducer


@dataclass(frozen=True)
class DesktopObservation:
    task: str
    action: str
    digest: str
    frame: object
    expires: float
    authority_state: tuple
    epoch: int


@dataclass
class DesktopObservationOwnership:
    reference: str | None = None
    created: bool = False


class DesktopRuntime:
    def __init__(self,high_client_factory=None):
        self._gate=threading.RLock();self._capture_gate=threading.Lock()
        self._observations={};self._closed=threading.Event()
        self._epochs={};self._active={};self._draining=set()
        self._cleanup_debt=None
        self._input_adapters={};self._input_gate=threading.Lock();self._high_factory=high_client_factory

    def close(self):
        self._closed.set()
        with self._gate:
            for stop,_done in self._active.values():stop.set()
            self._observations.clear()
            adapters=list(self._input_adapters.values())
        for adapter in adapters:adapter.close()

    def _current(self,task,epoch):
        with self._gate:
            if self._closed.is_set() or task in self._draining or self._epochs.get(task,0)!=epoch:
                raise ControlError('desktop_capture_cancelled')

    def drain_task(self,task,mode='finish'):
        with self._gate:
            self._draining.add(task);self._epochs[task]=self._epochs.get(task,0)+1
            epoch=self._epochs[task]
            active=[value for key,value in self._active.items() if key[0]==task]
            for stop,_done in active:stop.set()
            adapter=self._input_adapters.get(task)
            if adapter is not None and adapter.active_action is not None:adapter.stop(adapter.active_action)
            for reference,row in list(self._observations.items()):
                if row.task==task:self._observations.pop(reference)
        deadline=time.monotonic()+2
        for _stop,done in active:
            if not done.wait(max(0,deadline-time.monotonic())):
                return dict(state='desktop_cleanup_pending',dispatched=False)
        # Other chats' captures are unrelated to this chat's finish. A gate is
        # needed only to retry this chat's retained exact worker cleanup debt.
        if self._cleanup_debt is not None and self._cleanup_debt[0]==task:
            if not self._capture_gate.acquire(timeout=max(0,deadline-time.monotonic())):
                return dict(state='desktop_cleanup_pending',dispatched=False)
            try:
                try:self._cleanup_debt[1].retry_cleanup()
                except Exception:return dict(state='desktop_cleanup_pending',dispatched=False)
                self._cleanup_debt=None
            finally:self._capture_gate.release()
        if adapter is not None:
            if adapter._native_fault is not None:
                return dict(state='desktop_cleanup_pending',dispatched=False)
            outcome=adapter.runtime.pause(mode,trusted_task=task)
            if outcome.get('state') not in {'task_finished','phase_released'}:
                return dict(state='desktop_cleanup_pending',dispatched=False,desktop_cleanup=outcome)
        return dict(state='desktop_calls_drained',dispatched=False,epoch=epoch)

    def end_drain(self,task,epoch):
        with self._gate:
            if self._epochs.get(task,0)==epoch:self._draining.discard(task)

    def discard(self,store,*,task,reference):
        with self._gate:
            row=self._observations.get(reference)
            if row is not None and row.task==task:self._observations.pop(reference)
        if row is not None and row.task==task:
            with store.transaction() as db:
                db.execute("UPDATE desktop_observe_actions SET state='failed' WHERE task=? AND reference=?",
                    (task,reference))

    @staticmethod
    def _ensure_actions(store):
        with store.transaction() as db:
            db.execute('CREATE TABLE IF NOT EXISTS desktop_observe_actions('
                'task TEXT NOT NULL,action TEXT NOT NULL,digest TEXT NOT NULL,reference TEXT,state TEXT NOT NULL,'
                'owner TEXT,deadline REAL,PRIMARY KEY(task,action))')
            columns={row[1] for row in db.execute('PRAGMA table_info(desktop_observe_actions)')}
            for name,kind in (('owner','TEXT'),('deadline','REAL')):
                if name not in columns:db.execute(f'ALTER TABLE desktop_observe_actions ADD COLUMN {name} {kind}')

    def publish(self,store,*,task,reference,stopped):
        self.authorize_visual_return(store,task=task,reference=reference,stopped=stopped)
        with store.transaction() as db:
            db.execute("UPDATE desktop_observe_actions SET state='published' WHERE task=? AND reference=? AND state IN ('ready','published')",
                (task,reference))
        self.authorize_visual_return(store,task=task,reference=reference,stopped=stopped)
        return True

    def authorize_visual_return(self,store,*,task,reference,stopped):
        if stopped() or self._closed.is_set():raise ControlError('desktop_capture_cancelled')
        with self._gate:row=self._observations.get(reference)
        if row is None or row.task!=task or row.expires<=store.clock():
            raise ControlError('desktop_observation_stale')
        self._current(task,row.epoch)
        state,_=_snapshot(store,task,'capture')
        if row.authority_state!=state:raise ControlError('desktop_observation_stale')
        if stopped():raise ControlError('desktop_capture_cancelled')
        return True

    def observe(self,store,*,task,action_id,max_size,stopped,raw_arguments=None,ownership=None):
        if (type(action_id) is not str or not 1<=len(action_id)<=128
                or type(max_size) is not list or len(max_size)!=2
                or any(type(v) is not int or not 1<=v<=3840 for v in max_size)
                or max_size[0]*max_size[1]>3840*2160):
            raise ControlError('invalid_desktop_observation_request')
        payload=dict(action_id=action_id,max_size=max_size) if raw_arguments is None else raw_arguments
        self._ensure_actions(store)
        admission=issue_ordinary_desktop_admission(store,trusted_task=task,
            tool_name='flower_computer_desktop_observe',arguments=payload,capability='capture')
        with self._gate:epoch=self._epochs.get(task,0)
        own_stop=threading.Event();done=threading.Event();reserved=False;reference=None
        def is_stopped():return stopped() or own_stop.is_set() or self._closed.is_set()
        def check():
            if is_stopped():raise ControlError('desktop_capture_cancelled')
            self._current(task,epoch)
            return admission.check()
        try:
            check()
            digest=call_digest('flower_computer_desktop_observe',payload)
            with self._gate:
                for expired_reference,expired_row in list(self._observations.items()):
                    if expired_row.expires<=store.clock():self._observations.pop(expired_reference)
            # No SQLite or authority/provider wait may hold the RAM lock used
            # by Stop, close and drain. The post-transaction epoch/row recheck
            # prevents this gap from admitting a canceled or replaced capture.
            with store.transaction() as db:
                previous=db.execute('SELECT * FROM desktop_observe_actions WHERE task=? AND action=?',(task,action_id)).fetchone()
                if previous is not None:
                    if previous['digest']!=digest:raise ControlError('action_id_conflict')
                    if previous['state'] in ('pending','ready'):
                        if (previous['owner'] is None or previous['deadline'] is None
                                or previous['deadline']<=store.clock() or not process_is_alive(previous['owner'])):
                            raise ControlError('desktop_observation_stale')
                        raise ControlError('desktop_observation_in_progress')
                else:
                    db.execute('INSERT INTO desktop_observe_actions(task,action,digest,reference,state,owner,deadline) '
                        'VALUES(?,?,?,?,?,?,?)',(task,action_id,digest,None,'pending',process_identity(),admission.stamp.deadline))
            if previous is not None:
                check()
                with self._gate:
                    old=self._observations.get(previous['reference'])
                    self._current(task,epoch)
                    if old is None or old.authority_state!=admission.stamp.state:
                        raise ControlError('desktop_observation_stale')
                if ownership is not None:ownership.reference=previous['reference']
                return previous['reference'],old.frame,True
            reserved=True
            with self._gate:
                self._current(task,epoch)
                if len(self._observations)>=32:raise ControlError('desktop_observation_capacity')
                self._active[(task,'observe',action_id)]=(own_stop,done)
            while not self._capture_gate.acquire(timeout=.02):check()
            try:
                check()
                if self._cleanup_debt is not None:
                    self._cleanup_debt[1].retry_cleanup()
                    self._cleanup_debt=None
                try:
                    frame=capture_in_owned_job(producer=DesktopFrameProducer(str(store.directory),
                        admission.stamp,tuple(max_size)),authorize=check,
                        validate_frame=lambda value:check() and value.state.privacy_revision==admission.stamp.state[0].policy_revision,
                        stopped=is_stopped,timeout=8)
                except DesktopCaptureCleanupError as error:
                    self._cleanup_debt=(task,error)
                    raise
            finally:self._capture_gate.release()
            check();reference=uuid.uuid4().hex
            if ownership is not None:
                ownership.reference=reference;ownership.created=True
            row=DesktopObservation(task,action_id,digest,frame,store.clock()+60,admission.stamp.state,epoch)
            with self._gate:
                # Concurrent same-ID reads must not replace an earlier image.
                if any(r.task==task and r.action==action_id for r in self._observations.values()):
                    raise ControlError('desktop_observation_conflict')
                if (len(self._observations)>=32 or
                        sum(len(r.frame.png) for r in self._observations.values())+len(frame.png)>64_000_000):
                    raise ControlError('desktop_observation_capacity')
                self._observations[reference]=row
            with store.transaction() as db:
                db.execute("UPDATE desktop_observe_actions SET reference=?,state='ready' WHERE task=? AND action=?",
                    (reference,task,action_id))
            store.record_event('desktop_observed',task=task,action=action_id,details={
                'mode':'desktop','observation_id':reference,'image_digest':frame.digest,
                'masked_regions':len(frame.state.protected_rects),'monitor_count':len(frame.state.topology.monitors)})
            check()
            return reference,frame,False
        except BaseException:
            if reserved:
                if reference is not None:
                    with self._gate:self._observations.pop(reference,None)
                with store.transaction() as db:
                    db.execute("UPDATE desktop_observe_actions SET state='failed' WHERE task=? AND action=?",(task,action_id))
            raise
        finally:
            admission.close()
            if reserved:
                with self._gate:self._active.pop((task,'observe',action_id),None)
                done.set()

    def _adapter(self,store,task):
        from .desktop_input_runtime import DesktopInputAdapter
        with self._gate:
            adapter=self._input_adapters.get(task)
            if adapter is None:
                adapter=DesktopInputAdapter(store,task,self._high_factory)
                self._input_adapters[task]=adapter
            return adapter

    def stop_action(self,task,action_id):
        with self._gate:
            adapter=self._input_adapters.get(task)
            active=self._active.get((task,'input',action_id))
        if active is not None:active[0].set()
        if adapter is not None:adapter.stop(action_id)

    def input(self,store,*,task,observation_id,command,arguments,action_id,stopped,
              task_purpose=None,next_step=None):
        from .computer_mcp import valid_task_purpose,valid_next_step
        display={key:value for key,value in {'task_purpose':valid_task_purpose(task_purpose),
            'next_step':valid_next_step(next_step)}.items() if value is not None}
        payload=dict(observation_id=observation_id,command=command,arguments=arguments,action_id=action_id)
        payload.update(display)
        if (type(action_id) is not str or not 1<=len(action_id)<=128
                or type(observation_id) is not str or type(command) is not str or type(arguments) is not dict):
            raise ControlError('invalid_desktop_input_request')
        admission=issue_ordinary_desktop_admission(store,trusted_task=task,
            tool_name='flower_computer_desktop_input',arguments=payload,capability='input')
        own_stop=threading.Event();done=threading.Event();locked=False;registered=False
        adapter=self._adapter(store,task);key=adapter.runtime._key(task,action_id)
        try:
            with store.read_transaction() as db:
                previous=db.execute('SELECT fingerprint FROM actions WHERE task=? AND id=?',(task,key)).fetchone()
            if previous is not None:
                if previous['fingerprint']!=admission.stamp.call_digest:raise ControlError('action_id_conflict')
                return dict(mode='desktop',receipt=adapter.runtime.action_status(action_id,trusted_task=task),replayed=True,
                    requires_new_observation=True,next_action='flower_computer_desktop_action_status')
            with self._gate:row=self._observations.get(observation_id)
            if row is None or row.task!=task or row.expires<=store.clock():
                raise ControlError('desktop_observation_stale')
            with store.read_transaction() as db:
                published=db.execute("SELECT 1 FROM desktop_observe_actions WHERE task=? AND reference=? AND state='published'",
                    (task,observation_id)).fetchone()
            if published is None:raise ControlError('desktop_observation_unpublished')
            with self._gate:
                if self._observations.get(observation_id) is not row or row.expires<=store.clock():
                    raise ControlError('desktop_observation_stale')
                self._current(task,row.epoch)
                if (row.authority_state[0]!=admission.stamp.state[0]
                        or row.authority_state[2]!=admission.stamp.state[2]):
                    raise ControlError('desktop_observation_stale')
                active_key=(task,'input',action_id)
                if active_key in self._active:raise ControlError('desktop_action_in_progress')
                self._active[active_key]=(own_stop,done);registered=True
            def is_stopped():return stopped() or own_stop.is_set() or self._closed.is_set()
            def current():
                if is_stopped():raise ControlError('input_stopped')
                self._current(task,row.epoch);admission.check()
                with self._gate:
                    if self._observations.get(observation_id) is not row:raise ControlError('desktop_observation_stale')
                if row.expires<=store.clock():raise ControlError('desktop_observation_stale')
                return True
            while not locked:
                current();locked=self._input_gate.acquire(timeout=.02)
            current()
            try:
                return adapter.execute(row,command,arguments,action_id,admission,is_stopped,current,**display)
            except Exception as error:
                try:receipt=adapter.runtime.action_status(action_id,trusted_task=task)
                except ControlError as missing:
                    if missing.code=='action_not_found':raise error
                    receipt=None
                # An exception after dispatch must never be returned as zero
                # input merely because the last host read failed.
                return dict(state='outcome_uncertain',dispatched=None,reason=getattr(error,'code',
                    'desktop_input_result_unavailable'),receipt=receipt,mode='desktop',
                    requires_new_observation=True,next_action='flower_computer_desktop_action_status')
        finally:
            if locked:self._input_gate.release()
            if registered:
                with self._gate:self._active.pop((task,'input',action_id),None)
                done.set()
            admission.close()

    def action_status(self,store,*,task,action_id,cancel=False,wait_seconds=None,stopped=None):
        adapter=self._adapter(store,task)
        if cancel:
            self.stop_action(task,action_id)
            return adapter.runtime.cancel(action_id,trusted_task=task)
        return adapter.runtime.action_status(action_id,trusted_task=task,wait_seconds=wait_seconds,stopped=stopped)
