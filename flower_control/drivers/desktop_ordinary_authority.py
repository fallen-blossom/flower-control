"""Policy-derived per-call desktop admission; never a confirmed user grant."""
from dataclasses import dataclass, replace
import hashlib
import json

from flower_control.control.native import FOREGROUND_INPUT_RESOURCE
from .desktop_authority import _read,DesktopAuthorityError


def call_digest(tool,arguments):
    return hashlib.sha256(json.dumps([tool,arguments],sort_keys=True,
        separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')).hexdigest()


def _snapshot(store,task,capability,*,initial=False,stable_usage=False):
    base,now=_read(store,None,task,'metadata')
    resource=None
    with store.read_transaction() as db:
        grants=tuple(tuple(row) for row in db.execute(
            'SELECT scope,event_id,expires FROM grants WHERE task=? AND expires>? ORDER BY scope',(task,now)))
    if capability=='input':
        with store.read_transaction() as db:
            store._task(db,task)
            if initial:store._require_input_release_confirmed(db)
            row=db.execute('SELECT * FROM resources WHERE id=?',(FOREGROUND_INPUT_RESOURCE,)).fetchone()
            if row is not None:
                if row['paused'] or store._effective_quarantine(db,FOREGROUND_INPUT_RESOURCE,row):
                    raise DesktopAuthorityError('resource_paused_or_quarantined')
                if row['required_scope']:store._require_scope(db,task,row['required_scope'])
                # Dispatch owns changing revision/release epochs. The original
                # observation and Runtime enforce those, including this action;
                # per-call policy checks must not reject their own down/up pair.
                resource=row['required_scope']
    after,checked_at=_read(store,None,task,'metadata')
    if base!=after or any(row[2]<=checked_at for row in grants):
        raise DesktopAuthorityError('desktop_authority_changed')
    if stable_usage:
        # A normal same-scope authorization refresh bumps the task revision and
        # replaces the grant event/expiry. That is continued use, not a
        # revocation. Every other authority fact was compared exactly above.
        base=replace(base,task_revision=0)
        grants=tuple(sorted({row[0] for row in grants}))
        return (base,resource,grants),checked_at
    return (base,resource,grants),checked_at


@dataclass(frozen=True)
class OrdinaryDesktopStamp:
    task: str
    capability: str
    call_digest: str
    state: tuple
    deadline: float


class OrdinaryDesktopAdmission:
    def __init__(self,store,stamp):self.store,self.stamp,self.closed=store,stamp,False
    def check(self):
        if self.closed:raise DesktopAuthorityError('desktop_admission_closed')
        state,now=_snapshot(self.store,self.stamp.task,self.stamp.capability)
        if now>=self.stamp.deadline:raise DesktopAuthorityError('desktop_admission_expired')
        if state!=self.stamp.state:raise DesktopAuthorityError('desktop_authority_changed')
        return True
    def close(self):self.closed=True


def issue_ordinary_desktop_admission(store,*,trusted_task,tool_name,arguments,capability):
    """Internal adapter only, after actual Origin consumption of these raw args."""
    expected={'capture':'flower_computer_desktop_observe','input':'flower_computer_desktop_input'}
    if capability not in expected or tool_name!=expected[capability] or type(arguments) is not dict:
        raise DesktopAuthorityError('invalid_desktop_authority_request')
    state,now=_snapshot(store,trusted_task,capability,initial=True)
    stamp=OrdinaryDesktopStamp(trusted_task,capability,call_digest(tool_name,arguments),
        state,now+(10 if capability=='capture' else 30))
    store.record_event('desktop_ordinary_call_admitted',task=trusted_task,details={
        'authority_source':'ordinary_task_policy','capability':capability,
        'call_digest':stamp.call_digest,'deadline':stamp.deadline})
    result=OrdinaryDesktopAdmission(store,stamp);result.check()
    return result
