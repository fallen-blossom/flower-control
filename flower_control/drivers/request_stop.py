"""Send at most one cancellation for one already-bound native lease."""
import sqlite3
import threading
import time


class RequestStopSender:
    def __init__(self, *, done, stopped, signal, close, stop_signal=None, already_sent=False):
        self.done, self.stopped = done, stopped
        self.signal, self.close = signal, close
        self.stop_signal = stop_signal
        self._sent = already_sent
        self._gate = threading.Lock()
        self._failure_gate = threading.Lock()
        self._failure = None
        self._threads = [threading.Thread(target=self._poll, daemon=True, name="flower-request-guard")]
        if stop_signal is not None:
            self._threads.append(threading.Thread(target=self._immediate, daemon=True, name="flower-request-stop"))
        self._started = []

    def _send(self):
        try:
            with self._gate:
                if self._sent or self.done.is_set():
                    return
                self._sent = True
                self.signal("stop")
        except BaseException as error:
            self._fail("stop_signal", error)

    @property
    def failure(self):
        with self._failure_gate:
            return dict(self._failure) if self._failure is not None else None

    def _fail(self, stage, error):
        # Keep the first local cause before closing the transport. Exception
        # messages/arguments can contain private input and are never retained.
        with self._failure_gate:
            if self._failure is not None:
                return
            category = "BaseException"
            if isinstance(error, sqlite3.Error):
                category = "sqlite3.Error"
            else:
                for known in (KeyboardInterrupt, SystemExit, TimeoutError, PermissionError,
                        FileNotFoundError, MemoryError, OSError, RuntimeError, ValueError,
                        TypeError, AttributeError, KeyError, AssertionError, Exception):
                    if isinstance(error, known):
                        category = known.__name__
                        break
            self._failure = {"stage": stage, "exception_type": category}
        try:
            self.close()
        except BaseException:
            with self._failure_gate:
                self._failure["close_failed"] = True

    def _poll(self):
        try:
            while not self.done.wait(.01):
                if self.stopped():
                    self._send()
                    return
        except BaseException as error:
            self._fail("authority_probe", error)

    def _immediate(self):
        try:
            while not self.done.is_set():
                if self.stop_signal.wait(.01):
                    self._send()
                    return
        except BaseException as error:
            self._fail("stop_wait", error)

    def start(self):
        for thread in self._threads:
            thread.start()
            self._started.append(thread)

    def join(self, timeout):
        deadline = time.monotonic() + timeout
        for thread in self._started:
            thread.join(max(0, deadline - time.monotonic()))

    def is_alive(self):
        return any(thread.is_alive() for thread in self._threads)
