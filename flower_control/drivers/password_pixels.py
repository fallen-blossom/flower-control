"""Short-lived local UIA metadata read; no names, values or arbitrary paths."""
from dataclasses import asdict
from contextlib import contextmanager
from contextvars import ContextVar
import json
import queue
import subprocess
import threading
import time

import win32job
import pywintypes

from flower_control.permissions import PermissionError
from flower_control.control.state import ControlError
from .app_worker import native_executable

_action_session = ContextVar("flower_action_privacy_session", default=None)


class _MetadataSession:
    """No cached observations: a fresh scan for every exact input segment."""
    def __init__(self, identity):
        self.identity = identity
        self.responses = queue.Queue(maxsize=1)
        self.job = None
        self.process = None
        self.assigned = False
        self.scans = 0
        self.started = time.monotonic()
        try:
            executable = native_executable()
            if not executable.is_file(): raise PermissionError("privacy_password_scan_unavailable")
            self.job = win32job.CreateJobObject(None, "")
            settings = win32job.QueryInformationJobObject(self.job, win32job.JobObjectExtendedLimitInformation)
            settings["BasicLimitInformation"]["LimitFlags"] |= win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            win32job.SetInformationJobObject(self.job, win32job.JobObjectExtendedLimitInformation, settings)
            self.process = subprocess.Popen((str(executable), "--privacy-session"), stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
            win32job.AssignProcessToJobObject(self.job, int(self.process._handle))
            self.assigned = True
            self.reader = threading.Thread(target=self._read, name="flower-action-privacy", daemon=True)
            self.reader.start()
        except (OSError, ValueError, TypeError, pywintypes.error, ControlError):
            self.close()
            raise PermissionError("privacy_password_scan_unavailable") from None

    def _read(self):
        try:
            while True:
                line = self.process.stdout.readline(20_001)
                if not line or len(line) > 20_000 or not line.endswith(b"\n"):
                    self.responses.put(None, timeout=.1)
                    return
                self.responses.put(line, timeout=.1)
        except (OSError, ValueError, queue.Full):
            try: self.responses.put_nowait(None)
            except queue.Full: pass

    def scan(self, identity, preflight, stopped, *, keyboard_focus=False):
        if identity != self.identity or self.process.poll() is not None:
            raise PermissionError("privacy_password_scan_incomplete")
        preflight()
        if stopped(): raise PermissionError("privacy_scan_cancelled")
        try:
            query = asdict(identity)
            if keyboard_focus:
                query['scope'] = 'keyboard_focus'
            self.process.stdin.write((json.dumps(query, separators=(",", ":")) + "\n").encode())
            self.process.stdin.flush()
            deadline = time.monotonic() + 2.5
            while True:
                preflight()
                if stopped(): raise PermissionError("privacy_scan_cancelled")
                remaining = deadline - time.monotonic()
                if remaining <= 0: raise PermissionError("privacy_password_scan_incomplete")
                try: line = self.responses.get(timeout=min(.02, remaining))
                except queue.Empty: continue
                if line is None: raise PermissionError("privacy_password_scan_incomplete")
                preflight()
                if stopped(): raise PermissionError("privacy_scan_cancelled")
                result = _validate(json.loads(line), keyboard_focus=keyboard_focus)
                self.scans += 1
                return result
        except (OSError, ValueError, TypeError):
            raise PermissionError("privacy_password_scan_incomplete") from None

    def close(self):
        failures = []
        job_failed = False
        if self.job is not None:
            try:
                self.job.Close()
                self.job = None
            except Exception as error:
                failures.append(error)
                job_failed = True
        if self.process is not None:
            try:
                if self.process.poll() is None:
                    terminated = not self.assigned or job_failed
                    if terminated:
                        try: self.process.terminate()
                        except Exception as error: failures.append(error)
                    try:
                        self.process.wait(timeout=.15)
                    except subprocess.TimeoutExpired:
                        if terminated:
                            raise
                        # The exact owned Popen handle is retained. Never guess
                        # a PID or leave a child alive just because Job exit is late.
                        self.process.terminate()
                        self.process.wait(timeout=.15)
                if self.process.poll() is None:
                    raise PermissionError("privacy_scan_exit_unconfirmed")
            except Exception as error:
                failures.append(error)
            reader_alive = False
            if hasattr(self, "reader"):
                try:
                    self.reader.join(timeout=.15)
                    reader_alive = self.reader.is_alive()
                    if reader_alive: raise PermissionError("privacy_scan_exit_unconfirmed")
                except Exception as error:
                    failures.append(error)
                    reader_alive = True
            for pipe in (self.process.stdin, self.process.stdout):
                if pipe is not None:
                    # BufferedReader.close can wait on a readline lock. Retain
                    # the exact pipe if its reader has not stopped; never turn
                    # bounded cleanup into an unbounded cross-thread close.
                    if pipe is self.process.stdout and reader_alive:
                        continue
                    try: pipe.close()
                    except Exception as error: failures.append(error)
        if failures:
            raise PermissionError("privacy_scan_exit_unconfirmed") from None


@contextmanager
def action_privacy_session():
    """Lazy, exact-action lifetime; never shares scans or processes across calls."""
    if _action_session.get() is not None:
        yield
        return
    sessions = []
    token = _action_session.set(sessions)
    primary = None
    try:
        yield
    except BaseException as error:
        primary = error
        raise
    finally:
        _action_session.reset(token)
        cleanup_failed = False
        for session in sessions:
            try: session.close()
            except Exception: cleanup_failed = True
        if cleanup_failed:
            if primary is not None:
                primary.privacy_cleanup_reason = "privacy_scan_exit_unconfirmed"
            else:
                raise PermissionError("privacy_scan_exit_unconfirmed") from None


def _scan_failure(result):
    from .privacy_diagnostics import scan_diagnostics
    error = PermissionError("privacy_password_scan_incomplete")
    if (type(result) is dict and set(result) == {"state", "dispatched", "reason", "stage", "exception_type", "hresult"}
            and result["state"] == "rejected" and result["dispatched"] is False
            and result["reason"] == "privacy_scan_incomplete"):
        diagnostic = scan_diagnostics({key: result[key] for key in ('stage', 'exception_type', 'hresult')})
        if diagnostic:
            error.privacy_diagnostics = diagnostic
    raise error


def _validate(result, *, keyboard_focus=False):
    if type(result) is not dict or result.get("state") != "observed":
        _scan_failure(result)
    rows = result.get("rectangles")
    focus = result.get("focus_rectangle")
    def valid(row):
        return (type(row) is list and len(row) == 4 and all(type(n) is int for n in row)
                and row[0] < row[2] and row[1] < row[3])
    if (set(result) != {"state", "rectangles", "focus_rectangle", "focus_password", "coverage", "dispatched"}
        or result["state"] != "observed" or result["coverage"] != ('uia_password_focus' if keyboard_focus else 'uia_password_property') or result["dispatched"] is not False
        or type(rows) is not list or len(rows) > 128 or any(not valid(row) for row in rows)
        or focus is not None and not valid(focus) or result["focus_password"] is not None and type(result["focus_password"]) is not bool):
        raise PermissionError("privacy_password_scan_incomplete")
    if keyboard_focus and (rows or type(result['focus_password']) is not bool):
        raise PermissionError('privacy_keyboard_focus_unverified')
    return {"rectangles": tuple(tuple(row) for row in rows),
            "focus_rectangle": tuple(focus) if focus else None, "focus_password": result["focus_password"]}


def password_metadata(identity, *, preflight, stopped, task=None, keyboard_focus=False):
    preflight()
    if stopped():
        raise PermissionError("privacy_scan_cancelled")
    from flower_control._executor_metadata import executor_metadata
    from flower_control.permissions import process_facts
    try:
        _, target_integrity = process_facts(identity.pid)
    except (OSError, pywintypes.error, PermissionError):
        raise PermissionError("privacy_password_scan_unavailable") from None
    actor = executor_metadata()
    if not actor["metadata_available"]:
        raise PermissionError("privacy_password_scan_unavailable")
    if target_integrity > actor["integrity_rid"]:
        if not task: raise PermissionError("privacy_high_scan_requires_task")
        from .high_helper import ActiveHelperClient, HighTarget, HighHelperError
        try:
            with ActiveHelperClient(channel="flower-computer").open_session(task) as session:
                state = session.status()
                target = HighTarget.inspect(identity.hwnd, identity.pid, nonce=identity.window_nonce,
                    broker_revision=state.desktop_revision)
                metadata = _validate(session.password_metadata(target, preflight=preflight, stopped=stopped))
                if keyboard_focus and metadata['focus_password'] is None:
                    raise PermissionError('privacy_keyboard_focus_unverified')
                return metadata
        except HighHelperError as error:
            from .privacy_diagnostics import scan_diagnostics
            failure = PermissionError(error.code)
            diagnostic = scan_diagnostics(error.details.get('privacy_diagnostics'))
            if diagnostic:
                failure.privacy_diagnostics = diagnostic
            raise failure from None
    sessions = _action_session.get()
    if sessions is not None:
        if sessions and (sessions[0].scans >= 128 or time.monotonic() - sessions[0].started >= 14):
            sessions[0].close()
            sessions.clear()
        if not sessions: sessions.append(_MetadataSession(identity))
        return sessions[0].scan(identity, preflight, stopped, keyboard_focus=keyboard_focus)
    try:
        native_exe = native_executable()
    except ControlError:
        raise PermissionError("privacy_password_scan_unavailable") from None
    if not native_exe.is_file():
        raise PermissionError("privacy_password_scan_unavailable")
    job = None
    process = None
    assigned = False
    try:
        job = win32job.CreateJobObject(None, "")
        settings = win32job.QueryInformationJobObject(job, win32job.JobObjectExtendedLimitInformation)
        settings["BasicLimitInformation"]["LimitFlags"] |= win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        win32job.SetInformationJobObject(job, win32job.JobObjectExtendedLimitInformation, settings)
        process = subprocess.Popen((str(native_exe), "--privacy-only"), stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
        win32job.AssignProcessToJobObject(job, int(process._handle))
        assigned = True
        query = asdict(identity)
        if keyboard_focus:
            query['scope'] = 'keyboard_focus'
        payload = (json.dumps(query, separators=(",", ":")) + "\n").encode()
        deadline = time.monotonic() + 2.5
        first = True
        while True:
            preflight()
            if stopped() or time.monotonic() >= deadline:
                raise PermissionError("privacy_password_scan_incomplete")
            try:
                output, _ = process.communicate(input=payload if first else None, timeout=.05)
                break
            except subprocess.TimeoutExpired:
                first = False
        preflight()
        if len(output) > 20_000:
            raise PermissionError("privacy_password_scan_incomplete")
        result = json.loads(output)
        if process.returncode != 0:
            _scan_failure(result)
        return _validate(result, keyboard_focus=keyboard_focus)
    except (OSError, ValueError, TypeError, pywintypes.error):
        raise PermissionError("privacy_password_scan_incomplete") from None
    finally:
        if job is not None: job.Close()
        try:
            if process is not None and process.poll() is None:
                if not assigned:
                    process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    raise PermissionError("privacy_scan_exit_unconfirmed") from None
        finally:
            if process is not None:
                for pipe in (process.stdin, process.stdout):
                    if pipe is not None: pipe.close()


def password_rectangles(identity, *, preflight, stopped, task=None):
    return password_metadata(identity, preflight=preflight, stopped=stopped, task=task)["rectangles"]
