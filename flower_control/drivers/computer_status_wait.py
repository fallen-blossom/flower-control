"""Wait for ledger status only; never redispatch or repeat native recovery."""
import time

from flower_control.control.feedback import status_revision
from flower_control.control.state import ControlError
from .computer_mcp import ComputerBoundaryError


def wait_action_receipt(initial,snapshot,*,seconds,stopped,task_stopped,
                        clock=time.monotonic,sleep=time.sleep):
    if type(seconds) is not int or not 0 <= seconds <= 30:
        raise ComputerBoundaryError('invalid_status_wait')
    started=clock();deadline=started+seconds
    revision=initial.get('status_revision') or status_revision(initial)
    current=initial;reason='terminal'
    while current.get('state') in {'queued','running'}:
        if stopped(): raise ComputerBoundaryError('status_wait_cancelled')
        if current.get('cancel_requested'):
            reason='cancel_requested';break
        if task_stopped():
            reason='task_stopped';break
        remaining=deadline-clock()
        if remaining<=0:
            reason='timeout';break
        sleep(min(.05,remaining))
        if stopped(): raise ComputerBoundaryError('status_wait_cancelled')
        if task_stopped():
            reason='task_stopped';break
        try:
            current=snapshot()
        except ControlError as exc:
            if exc.code != 'task_revoked_or_missing' or not task_stopped():
                raise
            reason='task_stopped';break
        if (current.get('status_revision') or status_revision(current))!=revision:
            reason='status_changed';break
    if stopped(): raise ComputerBoundaryError('status_wait_cancelled')
    return {**current,'status_wait':dict(reason=reason,elapsed_ms=round((clock()-started)*1000),
        timed_out=reason=='timeout',input_replayed=False,
        last_authorized_receipt=reason=='task_stopped')}
