"""Read existing task grants for desktop work; never issue or widen a grant.

Only an internal host adapter that already consumed an origin ticket may pass
trusted_task. This module is not an MCP route, an approval parser or dispatch
lock. Native desktop identity, scene privacy and final input admission remain
separate checks. Callers must not cache a successful check as execution power.
"""
from dataclasses import dataclass
import math
import sqlite3

from flower_control import permissions
from flower_control.control.state import ControlError
from flower_control.control.native import FOREGROUND_INPUT_RESOURCE
from flower_control.control.write_gate import WriteGateError


CAPTURE_SCOPE = 'computer-desktop:capture'
INPUT_SCOPE = 'computer-desktop:input'


class DesktopAuthorityError(ControlError):
    pass


@dataclass(frozen=True)
class _Stamp:
    task: str
    owner: str | None
    capability: str
    boot: str
    host_binding: str
    task_revision: int
    lifecycle: int
    stop_epoch: int
    policy_revision: str
    grants: tuple
    input_resource: tuple | None


def _identifier(value):
    return (type(value) is str and 1 <= len(value) <= 256
            and value == value.strip() and not any(ord(c) < 32 for c in value))


def _read(store, owner, task, capability):
    if (not _identifier(task) or type(capability) is not str
            or capability not in {'capture', 'input', 'metadata'}
            or (owner is not None if capability == 'metadata' else not _identifier(owner))):
        raise DesktopAuthorityError('invalid_desktop_authority_request')
    # Reads honor Stop too. A Stop/resume cycle invalidates old observations;
    # admitting a new call never resumes a task or repairs input release debt.
    before = store.write_gate.snapshot()
    if before.stopped:
        raise DesktopAuthorityError('desktop_task_stopped')
    policy = permissions.active_policy.read()
    permissions.require_channel_allowed(policy)
    now = store.clock()
    if type(now) not in (int, float) or not math.isfinite(now):
        raise DesktopAuthorityError('invalid_desktop_authority_clock')
    with store.read_transaction() as db:
        connection = None if capability == 'metadata' else store._owner(db, owner)
        if connection is not None and connection['task'] != task:
            raise DesktopAuthorityError('ticket_task_mismatch')
        row = store._task(db, task)
        if row['paused']:
            raise DesktopAuthorityError('desktop_task_stopped')
        binding = row['host_binding']
        if not binding or not binding.startswith('origin:'):
            raise DesktopAuthorityError('trusted_chat_binding_required')
        epoch = db.execute('SELECT epoch FROM task_write_epochs WHERE task=?', (task,)).fetchone()
        if epoch is None or max(epoch[0], before.resume_all_epoch) < before.epoch:
            raise DesktopAuthorityError('desktop_task_stopped')
        # Fail closed for an unlinked or previous-boot task, including a DB
        # snapshot opened by another process after this StateStore was created.
        boot = db.execute("SELECT value FROM meta WHERE key='boot'").fetchone()
        linked = db.execute('SELECT boot FROM origin_task_boots WHERE task=?', (task,)).fetchone()
        if boot is None or linked is None or boot[0] != store.boot or linked[0] != store.boot:
            raise DesktopAuthorityError('desktop_task_boot_changed')
        scopes = (() if capability == 'metadata' else
                  (CAPTURE_SCOPE,) if capability == 'capture' else (CAPTURE_SCOPE, INPUT_SCOPE))
        grants = []
        def require_scope(scope):
            if any(item[0] == scope for item in grants):
                return
            grant = db.execute('SELECT event_id,expires FROM grants WHERE task=? AND scope=?',
                               (task, scope)).fetchone()
            if grant is None or grant['expires'] <= now:
                raise DesktopAuthorityError('desktop_task_authorization_required')
            grants.append((scope, grant['event_id'], grant['expires']))
        for scope in scopes:
            require_scope(scope)
        input_resource = None
        if capability == 'input':
            store._require_input_release_confirmed(db)
            resource = db.execute('SELECT * FROM resources WHERE id=?', (FOREGROUND_INPUT_RESOURCE,)).fetchone()
            if resource is not None:
                if resource['paused'] or store._effective_quarantine(db, FOREGROUND_INPUT_RESOURCE, resource):
                    raise DesktopAuthorityError('resource_paused_or_quarantined')
                if resource['required_scope']:
                    require_scope(resource['required_scope'])
                input_resource = (resource['revision'], resource['required_scope'])
        lifecycle = db.execute('SELECT sequence FROM task_lifecycle WHERE task=?', (task,)).fetchone()
        stamp = _Stamp(task, owner, capability, store.boot, binding, row['revision'],
                       lifecycle[0] if lifecycle is not None else 0,
                       before.epoch, policy['Revision'], tuple(grants), input_resource)
    after = store.write_gate.snapshot()
    current_policy = permissions.active_policy.read()
    permissions.require_channel_allowed(current_policy)
    if after != before or current_policy['Revision'] != policy['Revision']:
        raise DesktopAuthorityError('desktop_authority_changed')
    checked_at = store.clock()
    if (type(checked_at) not in (int, float) or not math.isfinite(checked_at)
            or checked_at < now):
        raise DesktopAuthorityError('invalid_desktop_authority_clock')
    if (connection is not None and connection['live_until'] <= checked_at
            or any(grant[2] <= checked_at for grant in grants)):
        raise DesktopAuthorityError('desktop_authority_expired')
    return stamp, checked_at


class DesktopAdmission:
    """Short-lived read capability, pinned to a caller and exact grant epochs.

    Construct through acquire_desktop_admission, not model arguments. No new
    authorization rows or resources are created; success is only preflight.
    """
    def __init__(self, store, stamp, deadline):
        self._store, self._stamp, self._deadline = store, stamp, deadline
        self._closed = False

    def close(self):
        self._closed = True

    def check(self):
        if self._closed:
            raise DesktopAuthorityError('desktop_admission_closed')
        try:
            stamp, now = _read(self._store, self._stamp.owner, self._stamp.task, self._stamp.capability)
        except (sqlite3.Error, OSError, WriteGateError) as error:
            raise DesktopAuthorityError('desktop_authority_unavailable') from error
        if now >= self._deadline:
            raise DesktopAuthorityError('desktop_admission_expired')
        if stamp != self._stamp:
            raise DesktopAuthorityError('desktop_authority_changed')
        return True


def acquire_desktop_admission(store, *, owner, trusted_task, capability):
    """Consume existing scopes only. The trusted host still must issue them.

    A window grant, administrator work grant or origin ticket alone never
    qualifies. This function cannot be used to authorize a different task.
    """
    if type(capability) is not str or capability not in {'capture','input'}:
        raise DesktopAuthorityError('invalid_desktop_authority_request')
    try:
        stamp, now = _read(store, owner, trusted_task, capability)
        deadline = min(now + 30, *(grant[2] for grant in stamp.grants))
        return DesktopAdmission(store, stamp, deadline)
    except (sqlite3.Error, OSError, WriteGateError) as error:
        raise DesktopAuthorityError('desktop_authority_unavailable') from error


def acquire_desktop_metadata_admission(store, *, trusted_task):
    """Fixed ten-second cursor/geometry read after consuming a real origin.

    No owner, grant, resource or task revision is created. This cannot be used
    for pixels, titles, window identities or input. Capture/input keep their
    original owner and explicit-scope admission above.
    """
    try:
        stamp,now = _read(store,None,trusted_task,'metadata')
        return DesktopAdmission(store,stamp,now+10)
    except (sqlite3.Error,OSError,WriteGateError) as error:
        raise DesktopAuthorityError('desktop_authority_unavailable') from error
