"""Isolated native pipe cancellation and private-status diagnostics.

Every pipe has a random test name. No broker, production status, input, UAC,
task grant or installed-state mutation is used.
"""
from contextlib import contextmanager
import gc
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch
import uuid

import pywintypes
import win32event
import win32file
import win32pipe

from flower_control.drivers import high_helper as helper


@contextmanager
def connected_pipe():
    name = 'Flower.Test.PipeCancel.' + uuid.uuid4().hex
    server = win32pipe.CreateNamedPipe('\\\\.\\pipe\\' + name, win32pipe.PIPE_ACCESS_DUPLEX,
        win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_WAIT,
        1, 65536, 65536, 1000, None)
    errors = []

    def accept():
        try:
            win32pipe.ConnectNamedPipe(server, None)
        except pywintypes.error as error:
            if error.winerror != 535:  # A client may connect before ConnectNamedPipe.
                errors.append(error)

    accepting = threading.Thread(target=accept, daemon=True)
    accepting.start()
    client = helper._Pipe(name)
    try:
        client.connect(timeout=1)
        accepting.join(2)
        if accepting.is_alive() or errors:
            raise AssertionError(('isolated connect failed', errors))
        yield client, server
    finally:
        client.close()
        server.Close()


@unittest.skipUnless(os.name == 'nt', 'Windows native pipes required')
class PipeCancellationTests(unittest.TestCase):
    def test_disconnected_peer_preserves_read_operation_and_native_error_only(self):
        with connected_pipe() as (client, server):
            win32pipe.DisconnectNamedPipe(server)
            with self.assertRaises(helper.HighHelperError) as raised:
                client.read(.5)
            self.assertEqual(raised.exception.code, 'pipe_disconnected')
            self.assertEqual(set(raised.exception.details), {'pipe_operation', 'winerror'})
            self.assertEqual(raised.exception.details['pipe_operation'], 'read')
            # DisconnectNamedPipe can report NO_DATA/PIPE_NOT_CONNECTED rather
            # than the BROKEN_PIPE produced by closing the peer handle.
            self.assertIn(raised.exception.details['winerror'], (109, 233))

    def test_real_pending_read_times_out_and_can_read_after_confirmed_cancel(self):
        with connected_pipe() as (client, server):
            started = time.monotonic()
            with self.assertRaisesRegex(helper.HighHelperError, '^pipe_deadline$'):
                client.read(.025)
            self.assertLess(time.monotonic() - started, 1.5)
            win32file.WriteFile(server, b'{"after_cancel":true}\n')
            self.assertEqual(client.read(1), {'after_cancel': True})

    def test_normal_same_thread_read_and_write(self):
        with connected_pipe() as (client, server):
            client.write({'client': 'normal'})
            _, sent = win32file.ReadFile(server, 1024)
            self.assertEqual(json.loads(sent), {'client': 'normal'})
            win32file.WriteFile(server, b'{"server":"normal"}\n')
            self.assertEqual(client.read(1), {'server': 'normal'})

    def test_timeout_does_not_cancel_read_issued_by_another_thread(self):
        with connected_pipe() as (client, server):
            ready = threading.Event()
            worker_state = {}
            event = win32event.CreateEvent(None, True, False, None)

            def read_elsewhere():
                overlapped = pywintypes.OVERLAPPED()
                overlapped.hEvent = event
                try:
                    _, buffer = win32file.ReadFile(client.handle, 128, overlapped)
                    ready.set()
                    if win32event.WaitForSingleObject(event, 3000) != win32event.WAIT_OBJECT_0:
                        win32file.CancelIo(client.handle)
                        win32event.WaitForSingleObject(event, win32event.INFINITE)
                        raise AssertionError('other thread read did not finish')
                    count = win32file.GetOverlappedResult(client.handle, overlapped, False)
                    worker_state['value'] = bytes(buffer[:count])
                except Exception as error:
                    worker_state['error'] = type(error).__name__
                    ready.set()

            worker = threading.Thread(target=read_elsewhere, daemon=True)
            worker.start()
            try:
                self.assertTrue(ready.wait(2))
                self.assertNotIn('error', worker_state)
                with self.assertRaisesRegex(helper.HighHelperError, '^pipe_deadline$'):
                    client.read(.025)
                self.assertEqual(win32event.WaitForSingleObject(event, 0), win32event.WAIT_TIMEOUT)
                win32file.WriteFile(server, b'other-thread-intact')
                worker.join(2)
                self.assertFalse(worker.is_alive())
                self.assertEqual(worker_state, {'value': b'other-thread-intact'})
            finally:
                if worker.is_alive():
                    client.close()
                    worker.join(3)
                event.Close()

    def test_unconfirmed_cancel_keeps_native_buffer_and_event_until_completion(self):
        with connected_pipe() as (client, server):
            actual_wait = win32event.WaitForSingleObject

            def bounded_drain_wait(event, milliseconds):
                # Simulate a slow cancel completion, retaining a real pending
                # kernel ReadFile. The daemon's INFINITE wait stays real.
                if milliseconds == 1000:
                    return win32event.WAIT_TIMEOUT
                return actual_wait(event, milliseconds)

            baseline = set(helper._retired_pipe_io)
            with patch.object(win32file, 'CancelIo', return_value=None), \
                    patch.object(win32event, 'WaitForSingleObject', side_effect=bounded_drain_wait):
                started = time.monotonic()
                with self.assertRaisesRegex(helper.HighHelperError, '^pipe_cancel_unconfirmed$'):
                    client.read(.025)
                self.assertLess(time.monotonic() - started, .75)
            retired, = set(helper._retired_pipe_io) - baseline
            self.assertIsNotNone(retired.buffer)
            self.assertIsNotNone(retired.overlapped)
            gc.collect()
            self.assertEqual(actual_wait(retired.event, 0), win32event.WAIT_TIMEOUT)
            with self.assertRaisesRegex(helper.HighHelperError, '^pipe_cancel_unconfirmed$'):
                client.write({'must_not_dispatch': True})
            win32file.WriteFile(server, b'{"late_completion":true}\n')
            until = time.monotonic() + 2
            while retired in helper._retired_pipe_io and time.monotonic() < until:
                threading.Event().wait(.01)
            self.assertNotIn(retired, helper._retired_pipe_io)
            with self.assertRaises(pywintypes.error):
                actual_wait(retired.event, 0)

    def test_cancel_error_is_not_falsely_reported_as_deadline(self):
        with connected_pipe() as (client, server):
            def failed_cancel(_):
                # The real I/O completes during drain, so releasing its buffer
                # is safe; cancellation itself still failed and stays distinct.
                win32file.WriteFile(server, b'late\n')
                raise OSError(5, 'private exception text must not become status')

            with patch.object(win32file, 'CancelIo', side_effect=failed_cancel):
                with self.assertRaisesRegex(helper.HighHelperError, '^pipe_cancel_failed$'):
                    client.read(.025)

    def test_connection_close_during_deferred_drain_keeps_buffer_until_kernel_completion(self):
        with connected_pipe() as (client, _):
            actual_wait = win32event.WaitForSingleObject
            baseline = set(helper._retired_pipe_io)

            def delay_drain(event, milliseconds):
                return win32event.WAIT_TIMEOUT if milliseconds == 1000 else actual_wait(event, milliseconds)

            with patch.object(win32file, 'CancelIo', return_value=None), \
                    patch.object(win32event, 'WaitForSingleObject', side_effect=delay_drain):
                with self.assertRaisesRegex(helper.HighHelperError, '^pipe_cancel_unconfirmed$'):
                    client.read(.025)
            retired, = set(helper._retired_pipe_io) - baseline
            self.assertIsNotNone(retired.buffer)
            self.assertEqual(actual_wait(retired.event, 0), win32event.WAIT_TIMEOUT)
            # Closing the actual native handle invalidates the PyHANDLE, but
            # must not discard the retained OVERLAPPED/buffer/event early.
            client.close()
            until = time.monotonic() + 2
            while retired in helper._retired_pipe_io and time.monotonic() < until:
                threading.Event().wait(.01)
            self.assertNotIn(retired, helper._retired_pipe_io)
            with self.assertRaises(pywintypes.error):
                actual_wait(retired.event, 0)

    def test_wait_error_is_preserved_after_actual_cancel_drain(self):
        with connected_pipe() as (client, _):
            actual_wait = win32event.WaitForSingleObject
            first = True

            def fail_first_wait(event, milliseconds):
                nonlocal first
                if first:
                    first = False
                    raise OSError(6, 'private-wait-path')
                return actual_wait(event, milliseconds)

            with patch.object(win32event, 'WaitForSingleObject', side_effect=fail_first_wait):
                with self.assertRaises(OSError) as caught:
                    client.read(1)
            self.assertEqual(caught.exception.errno, 6)

    def test_baseexception_wait_and_worker_start_preserve_pending_io_lifetime(self):
        with connected_pipe() as (client, server):
            actual_wait = win32event.WaitForSingleObject
            actual_cancel = win32file.CancelIo
            first = True

            def interrupted_wait(event, milliseconds):
                nonlocal first
                if first:
                    first = False
                    raise KeyboardInterrupt()
                return actual_wait(event, milliseconds)

            with patch.object(win32event, 'WaitForSingleObject', side_effect=interrupted_wait), \
                    patch.object(win32file, 'CancelIo', wraps=actual_cancel) as cancelled:
                with self.assertRaises(KeyboardInterrupt):
                    client.read(1)
                cancelled.assert_called_once()
            win32file.WriteFile(server, b'{"after_interrupt":true}\n')
            self.assertEqual(client.read(1), {'after_interrupt': True})
        with connected_pipe() as (client, server):
            baseline = set(helper._retired_pipe_io)

            def delay_drain(event, milliseconds):
                return win32event.WAIT_TIMEOUT if milliseconds == 1000 else actual_wait(event, milliseconds)

            with patch.object(win32file, 'CancelIo', return_value=None), \
                    patch.object(win32event, 'WaitForSingleObject', side_effect=delay_drain), \
                    patch.object(threading.Thread, 'start', side_effect=SystemExit(23)):
                with self.assertRaises(SystemExit) as caught:
                    client.read(.025)
            self.assertEqual(caught.exception.code, 23)
            retired, = set(helper._retired_pipe_io) - baseline
            try:
                self.assertIsNotNone(retired.buffer)
                self.assertEqual(actual_wait(retired.event, 0), win32event.WAIT_TIMEOUT)
                win32file.WriteFile(server, b'completed-without-worker\n')
                self.assertEqual(actual_wait(retired.event, 1000), win32event.WAIT_OBJECT_0)
            finally:
                # The simulated worker never started. Its real event is now
                # complete, so perform the same drain explicitly in this test.
                retired._drain()
            self.assertNotIn(retired, helper._retired_pipe_io)


class StatusProbeDiagnosticsTests(unittest.TestCase):
    @contextmanager
    def fixture(self):
        with tempfile.TemporaryDirectory(prefix='flower-probe-isolated-') as directory, \
                patch.object(helper, 'program_root', return_value=Path(directory) / 'FlowerControl/HighHelper'):
            active = Path(directory) / 'FlowerControl/HighHelper/active.json'
            active.parent.mkdir(parents=True)
            active.write_text('isolated', encoding='utf8')
            facts = dict(version='a'*32, pid=5, created=7, session_id=1, desktop_revision=1,
                         paused=True, desktop_locked=False, stopping=False, release_fault=False,
                         high_verified=True, ui_access=False)
            session = MagicMock()
            session._helper = dict(Pid=5, Created=7, Session=1, Integrity=12288)
            session._evidence = dict(Pid=10, Created=11, Session=1, Channel='flower-app',
                ProductionAdmitted=True, Source='codex-flower', CodexPid=99, LauncherPid=12, LauncherCreated=13)
            session._pipe.read.return_value = dict(Phase='status', Status=facts)
            client = helper.HighHelperClient(channel='flower-app')
            installed = SimpleNamespace(hashes=(('Flower.HighHelper.exe', 'b'*64),)), 'a'*32
            with patch.object(helper, '_installed_bundle', return_value=installed), \
                    patch.object(client, 'open_session', return_value=session):
                yield client, session

    def test_default_waits_preserve_true_paused_status(self):
        with self.fixture() as (client, session):
            result = client.probe_status()
            self.assertEqual(result['state'], 'paused')
            self.assertTrue(result['paused'])
            self.assertFalse(result['high_control_available'])
            session._start.assert_called_once_with()
            session._pipe.read.assert_called_once_with(2)

    def test_unknown_failure_reports_only_stage_type_and_native_integer_codes(self):
        for method, stage in (('_verify_peer', 'verify_peer'), ('write', 'write_status'), ('read', 'read_status')):
            with self.subTest(stage=stage), self.fixture() as (client, session):
                error = OSError(5, 'SECRET-path-and-original-JSON')
                error.winerror = 87
                target = getattr(session if method == '_verify_peer' else session._pipe, method)
                target.side_effect = error
                result = client.probe_status()
                self.assertEqual(result['reason'], 'broker_status_probe_failed')
                self.assertEqual(result['probe_error'], dict(stage=stage, exception_type='OSError', errno=5, winerror=87))
                self.assertNotIn('SECRET', json.dumps(result))
                self.assertIsNone(result['running'])
                self.assertFalse(result['high_control_available'])

    def test_start_stage_and_cleanup_failure_are_bounded_identifiers(self):
        with self.fixture() as (client, session):
            session._start_stage = 'start_read_hello'
            session._start.side_effect = AttributeError('SECRET')
            result = client.probe_status()
            self.assertEqual(result['probe_error'], dict(stage='start_read_hello', exception_type='AttributeError'))
        with self.fixture() as (client, session):
            session.close.side_effect = RuntimeError('SECRET')
            result = client.probe_status()
            self.assertEqual(result['probe_error'], dict(stage='close', exception_type='RuntimeError'))
            self.assertFalse(result['high_control_available'])

    def test_known_boundary_error_keeps_its_real_code(self):
        with self.fixture() as (client, session):
            session._start_stage = 'start_read_hello'
            session._start.side_effect = helper.HighHelperError('pipe_deadline')
            result = client.probe_status()
            self.assertEqual(result['reason'], 'pipe_deadline')
            self.assertEqual(result['probe_stage'], 'start_read_hello')
            self.assertNotIn('probe_error', result)


if __name__ == '__main__':
    unittest.main()
