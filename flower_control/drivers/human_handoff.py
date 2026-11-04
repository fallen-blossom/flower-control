"""Native human-action popup; it never observes or resumes the paused target."""
import atexit
import asyncio
import json
import subprocess
import threading
import time

import win32api

from .app_worker import _child_job, _native_environment
from .high_helper import _installed_bundle

_gate, _sessions = threading.Lock(), {}


def close_handoffs(store, task=None):
    with _gate:
        sessions = [value for value in _sessions.values() if value.store is store and (task is None or value.task == task)]
    for session in sessions:
        session.close()


def show_handoff(store, task, request, message):
    try:
        bundle, _version = _installed_bundle()
        with _gate:
            if request in _sessions:
                return {"state": "shown" if _sessions[request].shown.is_set() else "starting", "request_id": request}
            session = _Handoff(store, task, request, message, bundle)
            _sessions[request] = session
        session.start()
        return {"state": "shown" if session.shown.wait(.5) else "starting", "request_id": request}
    except Exception:
        return {"state": "unavailable", "request_id": request, "reason": "human_popup_unavailable",
                "ask_user_via_host_popup": True}


class _Handoff:
    def __init__(self, store, task, request, message, bundle):
        self.store, self.task, self.request = store, task, request
        self.closed, self.input_gate = threading.Event(), threading.Lock()
        self.shown = threading.Event()
        self.process = subprocess.Popen([str(bundle.directory / 'Flower.HighHelper.exe'), '--human-handoff'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=_native_environment(), creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            self.job = _child_job(self.process)
            remaining = store.human_handoff_status(task, request)['remaining_seconds']
            self.process.stdin.write((json.dumps({'RequestId': request, 'Message': message,
                'TimeoutSeconds': max(10, min(3600, remaining))}, ensure_ascii=False)+'\n').encode('utf-8'))
            self.process.stdin.flush()
        except BaseException:
            self.process.kill()
            self.process.wait(timeout=2)
            if hasattr(self, 'job'):
                win32api.CloseHandle(self.job)
            raise

    def start(self):
        threading.Thread(target=self._read, name='Flower human handoff results', daemon=True).start()
        threading.Thread(target=self._monitor, name='Flower human handoff lifetime', daemon=True).start()

    def _read(self):
        try:
            for line in self.process.stdout:
                if len(line) > 2048:
                    break
                value = json.loads(line)
                if value.get('RequestId') != self.request:
                    break
                action = value.get('Resolution') or value.get('Action')
                if action == 'shown':
                    self.shown.set()
                    continue
                if action not in {'completed', 'cancelled', 'expired', 'stopped', 'extend'}:
                    break
                if action == 'stopped':
                    self.store.pause_task(self.task)  # Explicit native Stop wins.
                if action in {'extend', 'stopped'} or value.get('Terminal') is True:
                    self.store.human_handoff_status(self.task, self.request, resolution=action)
                if value.get('Terminal') is True:
                    return
        except Exception:
            pass  # An absent/unverified terminal never means completed.
        finally:
            self.close()

    def _monitor(self):
        while not self.closed.wait(.05):
            try:
                status = self.store.human_handoff_status(self.task, self.request)
                if self.store.write_stopped():
                    self.store.pause_task(self.task)
                    self.store.human_handoff_status(self.task, self.request, resolution='stopped')
                    self.close()
                elif status['state'] != 'pending':
                    self.close()
            except Exception:
                self.close()

    def close(self):
        if self.closed.is_set():
            return
        self.closed.set()
        with _gate:
            if _sessions.get(self.request) is self:
                _sessions.pop(self.request, None)
        try:
            self.store.human_handoff_status(self.task, self.request, resolution='cancelled')
        except Exception:
            pass
        try:
            # The exact popup is inert on stdin EOF. Closing its own Job also
            # bounds a stuck UI; no user/result application belongs to this Job.
            self.process.stdin.close()
        finally:
            win32api.CloseHandle(self.job)


def _shutdown():
    with _gate:
        sessions = list(_sessions.values())
    for session in sessions:
        session.close()


atexit.register(_shutdown)


def explicit_resume_handoffs(store, task):
    for request in store.task_control_status(task)['human_handoffs']:
        if request['state'] == 'pending':
            store.human_handoff_status(task, request['request_id'], resolution='completed')
    close_handoffs(store, task)


def handoff_metadata_request(store, task, mode, request_id, timeout_seconds=None):
    if type(request_id) is not str or not request_id.startswith('handoff-'):
        raise ValueError('invalid_handoff_request')
    resolution = {'handoff_status': None, 'handoff_complete': 'completed',
                  'handoff_cancel': 'cancelled', 'handoff_extend': 'extend'}[mode]
    result = store.human_handoff_status(task, request_id, resolution=resolution,
        extend_seconds=300 if timeout_seconds is None else timeout_seconds)
    if resolution in {'completed', 'cancelled'}:
        close_handoffs(store, task)
    return result


async def wait_handoff_status(store, task, request_id, seconds, timeout_seconds=None, *, clock=time.monotonic, sleep=asyncio.sleep):
    """Read one exact request; waiting never completes, extends or resumes it."""
    from flower_control.control.state import ControlError
    if type(seconds) is not int or not 0 <= seconds <= 30:
        raise ValueError('invalid_handoff_wait')
    started=clock();deadline=started+seconds
    current=await asyncio.to_thread(handoff_metadata_request,store,task,'handoff_status',request_id,timeout_seconds)
    if not seconds: return current
    revision=(current['state'],current['extensions'])
    reason='terminal'
    while current['state']=='pending':
        if store.write_stopped():
            reason='global_stop';break
        remaining=deadline-clock()
        if remaining<=0:
            reason='timeout';break
        await sleep(min(.1,remaining))
        try:
            value=await asyncio.to_thread(handoff_metadata_request,store,task,'handoff_status',request_id,timeout_seconds)
        except ControlError as exc:
            if exc.code!='task_revoked_or_missing':raise
            reason='task_revoked';break
        current=value
        if (value['state'],value['extensions'])!=revision:
            reason='status_changed';break
    return {**current,'status_wait':dict(reason=reason,timed_out=reason=='timeout',
        elapsed_ms=round((clock()-started)*1000),last_authorized_receipt=reason=='task_revoked',
        resumed=False,input_dispatched=False)}
