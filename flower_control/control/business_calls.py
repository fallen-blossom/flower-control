"""Public-call presence, including exact synchronous workers after cancellation.

This metadata never authorizes a channel or extends its existing cleanup budget.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from contextvars import ContextVar
import threading
import uuid
import sys
import time

from .native import process_identity, process_is_alive
from .state import ControlError


SCHEMA = """
CREATE TABLE IF NOT EXISTS business_public_calls(
 token TEXT PRIMARY KEY, task TEXT NOT NULL, action TEXT NOT NULL,
 process TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS business_public_calls_root
 ON business_public_calls(task,action);
"""

_current = ContextVar('flower_business_public_call', default=None)
_pending = {}
_pending_lock = threading.Lock()


def retry_pending():
    with _pending_lock:
        calls = list(_pending.values())[:4]
        for call in calls:
            _pending.pop(call.token, None)
            _pending[call.token] = call
    deadline = time.monotonic() + .05
    for call in calls:
        if time.monotonic() >= deadline:
            break
        call.cleanup()


def in_flight(db, task, action):
    return presence(db, task, action)[0]


def presence(db, task, action):
    states = [process_is_alive(row[0]) for row in db.execute(
        'SELECT DISTINCT process FROM business_public_calls WHERE task=? AND action=?', (task, action))]
    return any(states), any(not alive for alive in states)


def public_action_key(task, channel, action):
    if type(action) is not str or not 1 <= len(action) <= 128:
        raise ControlError('invalid_action_id')
    if channel not in {'app', 'computer'}:
        raise ControlError('invalid_business_channel')
    return task + ':' + channel + ':' + action


class _Call:
    def __init__(self, store, task, action):
        self.store, self.task, self.action = store, task, action
        self.token = uuid.uuid4().hex
        self.lock = threading.Lock()
        self.workers = 0
        self.ended = self.opened = self.cleaned = self.cleaning = False

    def open(self):
        from .business_plan import check_action
        with self.lock:
            if self.ended:
                return
        with self.store.transaction() as db:
            check_action(db, {'task': self.task, 'id': self.action})
            db.execute('INSERT INTO business_public_calls VALUES (?,?,?,?)',
                (self.token, self.task, self.action, process_identity()))
        with self.lock:
            self.opened = True
            clean = self.ended and not self.workers
        if clean:
            self.cleanup()

    def bind(self, task, action):
        from .business_plan import bind_child
        if task != self.task:
            raise ControlError('ticket_task_mismatch')
        with self.lock:
            if self.ended:
                raise ControlError('business_call_closed')
        bind_child(self.store, task, self.action, action)

    def worker(self):
        with self.lock:
            if self.ended:
                raise ControlError('business_call_closed')
            self.workers += 1
        return _Worker(self)

    def cleanup(self):
        with self.lock:
            if not self.opened or not self.ended or self.workers or self.cleaned or self.cleaning:
                return
            self.cleaning = True
        try:
            with self.store.transaction(timeout=.025) as db:
                db.execute('DELETE FROM business_public_calls WHERE token=? AND task=? AND action=?',
                    (self.token, self.task, self.action))
        except Exception:
            with _pending_lock:
                _pending[self.token] = self
            try:
                print('business_call_cleanup_pending', file=sys.stderr)
            except Exception:
                pass
        else:
            with self.lock:
                self.cleaned = True
            with _pending_lock:
                _pending.pop(self.token, None)
        finally:
            with self.lock:
                self.cleaning = False

    def worker_done(self):
        with self.lock:
            self.workers -= 1
            clean = self.ended and not self.workers
        if clean:
            self.cleanup()

    def end(self):
        with self.lock:
            self.ended = True
            clean = not self.workers and self.opened
        if clean:
            # Retain exact cleanup responsibility even if its asyncio wrapper
            # is cancelled before the executor ever starts the DELETE.
            with _pending_lock:
                if not self.cleaned:
                    _pending[self.token] = self
        return self.cleanup if clean else None


class _Worker:
    def __init__(self, call):
        self.call = call
        self.lock = threading.Lock()
        self.state = 'queued'

    def start(self):
        with self.lock:
            if self.state != 'queued':
                return False
            with self.call.lock:
                ended = self.call.ended
                self.state = 'aborted' if ended else 'running'
        if ended:
            self.call.worker_done()
        return not ended

    def abort(self):
        with self.lock:
            release = self.state == 'queued'
            if release:
                self.state = 'aborted'
        if release:
            self.call.worker_done()
        return release

    def aborted(self):
        with self.lock:
            return self.state == 'aborted'

    def finish(self):
        with self.lock:
            release = self.state == 'running'
            if release:
                self.state = 'done'
        if release:
            self.call.worker_done()


@asynccontextmanager
async def public_call(store, task, action):
    await asyncio.to_thread(retry_pending)
    if action is None:
        yield None
        return
    call = _Call(store, task, action)
    # The synchronous open owns late cleanup once ended is set. Repeated host
    # cancellation never cancels that responsibility or races a late INSERT.
    opening = asyncio.create_task(asyncio.to_thread(call.open))
    try:
        await asyncio.shield(opening)
    except asyncio.CancelledError:
        cleanup = call.end()
        opening.add_done_callback(lambda done: done.exception() if not done.cancelled() else None)
        if cleanup is not None:
            closing = asyncio.create_task(asyncio.to_thread(cleanup))
            closing.add_done_callback(lambda done: done.exception() if not done.cancelled() else None)
        raise
    token = _current.set(call)
    try:
        yield call
    finally:
        _current.reset(token)
        cleanup = call.end()
        if cleanup is not None:
            closing = asyncio.create_task(asyncio.to_thread(cleanup))
            closing.add_done_callback(lambda done: done.exception() if not done.cancelled() else None)
            await asyncio.shield(closing)


def bind_runtime_call(task, action):
    call = _current.get()
    if call is not None:
        call.bind(task, action)


def public_worker():
    call = _current.get()
    return call.worker() if call is not None else None
