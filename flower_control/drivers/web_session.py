"""Owned temporary Brave lifecycle and bounded IPC to a Playwright worker.

The caller owns authorization, operation receipts and cross-session locks.
No browser is discovered, resumed, foregrounded or relaunched here.
Use guarded=True with the control-ledger dispatcher. Unguarded mode remains
only for isolated driver experiments; neither mode establishes host authority.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
import tempfile
import threading
import time
import uuid
import hashlib
import ctypes
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Awaitable, Callable

import win32con
import win32api
import win32event
import win32job
import win32process
import win32file
import win32gui
import pythoncom
import win32com.client

from flower_control.control.state import ControlError
from flower_control.control.native import process_identity, process_is_alive
from flower_control.drivers.worker_python import worker_python
from .web_effects import CLOSE_STOP_CODES, KNOWN_STAGES, WebClosePending, error_with_effect


DEFAULT_BRAVE = Path(r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe")
_CDP_PATH = re.compile(r"/devtools/browser/[0-9a-fA-F-]{36}\Z")
_START_TIMEOUT = 25.0
_MAX_MESSAGE = 16_000_000
_WORKER_RESPONSE_TIMEOUT = 30.0
# Download can wait 10 s for its page event and 30 s for save_as. Give the
# bounded artifact copy and IPC reply another 10 s before declaring uncertainty.
_DOWNLOAD_RESPONSE_TIMEOUT = 50.0
_DIAGNOSTIC_LINE_LIMIT = 1024
_DIAGNOSTIC_RECORD_LIMIT = 32
WEB_WORKER_PHASES = frozenset({"worker_ready", "stdin_eof", "invalid_frame",
    "runtime_cleanup_started", "runtime_cleanup_finished", "unhandled_exception",
    "owner_exit", "explicit_worker_stop", "worker_exit"})
WEB_EXCEPTION_TYPES = frozenset({"Exception", "RuntimeError", "ValueError", "OSError",
    "BrokenPipeError", "ConnectionError", "TimeoutError", "CancelledError", "Error",
    "TargetClosedError", "JSONDecodeError", "ControlError"})


def _worker_running(identity: str) -> bool | None:
    """Diagnostic query of the verified instance; access denial is unknown."""
    try:
        pid = int(identity.partition(":")[0])
        handle = win32api.OpenProcess(win32con.PROCESS_QUERY_LIMITED_INFORMATION | win32con.SYNCHRONIZE,
                                     False, pid)
        try:
            if win32event.WaitForSingleObject(handle, 0) == win32event.WAIT_OBJECT_0:
                return False
            return f'{pid}:{win32process.GetProcessTimes(handle)["CreationTime"].isoformat()}' == identity
        finally:
            handle.Close()
    except win32api.error as error:
        return False if error.winerror in (87, 1168) else None
    except (ValueError, TypeError):
        return None


def _minimal_environment() -> dict[str, str]:
    """Do not inherit proxy, Playwright/Node overrides or debug hooks."""
    allowed = ("SystemRoot", "WINDIR", "TEMP", "TMP", "ComSpec")
    result = {key: os.environ[key] for key in allowed if key in os.environ}
    result.setdefault("SystemRoot", os.environ.get("SystemRoot", r"C:\Windows"))
    result.setdefault("WINDIR", result["SystemRoot"])
    result.setdefault("TEMP", tempfile.gettempdir())
    result.setdefault("TMP", result["TEMP"])
    return result


def _visible_browser_windows(pid: int) -> list[int]:
    """Only HWND identity and visibility for the exact owned process."""
    windows: list[int] = []

    def visit(hwnd: int, _unused: object) -> None:
        if win32process.GetWindowThreadProcessId(hwnd)[1] != pid:
            return
        if (win32gui.IsWindowVisible(hwnd)
                and win32gui.GetWindow(hwnd, win32con.GW_OWNER) == 0
                and win32gui.GetClassName(hwnd) == "Chrome_WidgetWin_1"):
            windows.append(hwnd)

    win32gui.EnumWindows(visit, None)
    return windows


def _taskbar_browser_windows(pid: int) -> list[int]:
    """Visible, unowned Brave windows that Windows may show on the taskbar."""
    return [hwnd for hwnd in _visible_browser_windows(pid)
            if not win32gui.GetWindowLong(hwnd, win32con.GWL_EXSTYLE)
            & win32con.WS_EX_TOOLWINDOW]


def _headless_window_size() -> tuple[int, int]:
    """Give hidden pages a useful viewport without creating a desktop window."""
    width = win32api.GetSystemMetrics(win32con.SM_CXSCREEN)
    height = win32api.GetSystemMetrics(win32con.SM_CYSCREEN)
    return max(1280, min(width, 3840)), max(800, min(height, 2160))


class _OwnedProcess:
    def __init__(self, handle, pid: int, created: str) -> None:
        self.handle = handle
        self.pid = pid
        self.created = created

    def running(self) -> bool:
        return win32event.WaitForSingleObject(self.handle, 0) == win32event.WAIT_TIMEOUT

    def wait(self, timeout: float) -> None:
        if win32event.WaitForSingleObject(self.handle, int(timeout * 1000)) == win32event.WAIT_TIMEOUT:
            raise TimeoutError("owned_browser_did_not_exit")

    def close(self) -> None:
        self.handle.Close()

    def exit_metadata(self) -> dict:
        if self.running():
            return {}
        times = win32process.GetProcessTimes(self.handle)
        return {"exit_code": win32process.GetExitCodeProcess(self.handle),
                "os_exit_time": times["ExitTime"].isoformat()}


class _WorkerClient:
    """One request at a time over a private JSONL pipe; no command replay."""

    def __init__(self, environment: dict[str, str], *, guarded: bool = False,
                 profile_kind: str = "temporary", diagnostic=None) -> None:
        self.environment = dict(environment)
        self.guarded = guarded
        self.profile_kind = profile_kind
        self.process: asyncio.subprocess.Process | None = None
        self._lock = asyncio.Lock()
        self._sequence = 0
        self._poisoned = False
        self.worker_identity: str | None = None
        self._stop_event = None
        self._diagnostic = diagnostic
        self._diagnostic_task: asyncio.Task | None = None
        self.diagnostics: list[dict] = []
        self.diagnostic_invalid = 0
        self.diagnostic_omitted = 0
        self.exit_code: int | None = None
        self.exit_observed_at: float | None = None

    async def _drain_diagnostics(self, stream) -> None:
        # Consume after collection fills; never retain or forward raw stderr.
        pending = bytearray()
        discarding = False
        try:
            while chunk := await stream.read(4096):
                for piece in chunk.splitlines(keepends=True):
                    ended = piece.endswith(b"\n")
                    if not discarding:
                        if len(pending) + len(piece) > _DIAGNOSTIC_LINE_LIMIT:
                            pending.clear()
                            discarding = True
                            self.diagnostic_invalid += 1
                        else:
                            pending.extend(piece)
                    if ended:
                        if not discarding:
                            self._accept_diagnostic(bytes(pending))
                        pending.clear()
                        discarding = False
            if pending:
                self.diagnostic_invalid += 1
        except (OSError, ValueError):
            self.diagnostic_invalid += 1

    def _accept_diagnostic(self, line: bytes) -> None:
        try:
            item = json.loads(line)
            allowed = {"kind", "phase", "process", "exit_code", "exception_type"}
            if (not isinstance(item, dict) or set(item) != allowed
                    or item["kind"] != "flower_web_lifecycle"
                    or item["phase"] not in WEB_WORKER_PHASES
                    or type(item["process"]) is not str
                    or not re.fullmatch(r"[1-9][0-9]{0,9}:\d{4}-\d{2}-\d{2}T[0-9:.]+\+00:00", item["process"])
                    or (item["exit_code"] is not None and type(item["exit_code"]) is not int)
                    or (item["exception_type"] is not None and item["exception_type"] not in WEB_EXCEPTION_TYPES)):
                raise ValueError
        except (ValueError, UnicodeError, TypeError):
            self.diagnostic_invalid += 1
            return
        if len(self.diagnostics) >= _DIAGNOSTIC_RECORD_LIMIT:
            self.diagnostic_omitted += 1
            return
        item = {key: item[key] for key in allowed if key != "kind"}
        if self.worker_identity is not None and item["process"] != self.worker_identity:
            self.diagnostic_invalid += 1
            return
        item["observed_at"] = time.monotonic()
        self.diagnostics.append(item)
        if self._diagnostic is not None:
            try:
                self._diagnostic(item)
            except Exception:
                pass

    def observe_exit(self, code=None) -> None:
        if self.exit_observed_at is not None:
            return
        if type(code) is not int:
            code = getattr(self.process, "returncode", None)
        if type(code) is int:
            self.exit_code = code
            self.exit_observed_at = time.monotonic()

    async def start(self, endpoint: str) -> None:
        # -m resolves this same repository package without inheriting PYTHONPATH.
        project_root = Path(__file__).resolve().parents[2]
        environment = dict(self.environment)
        environment["PYTHONIOENCODING"] = "utf-8"
        startup = subprocess.STARTUPINFO()
        startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startup.wShowWindow = subprocess.SW_HIDE
        stop_name = "Local\\FlowerControl.WorkerStop." + uuid.uuid4().hex
        self._stop_event = win32event.CreateEvent(None, True, False, stop_name)
        self.process = await asyncio.create_subprocess_exec(
            worker_python(), "-B", "-m", "flower_control.drivers.web_worker", endpoint,
            "--owner", process_identity(), "--stop-event", stop_name,
            *(["--guarded"] if self.guarded else []),
            "--profile-kind", self.profile_kind,
            cwd=str(project_root), env=environment,
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, limit=_MAX_MESSAGE + 1, startupinfo=startup,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        self._diagnostic_task = asyncio.create_task(self._drain_diagnostics(self.process.stderr))
        identity = await self.call("ping", {})
        # Windows venv python.exe may be a redirector with a distinct child.
        # The handshake arrives over this exact child's private stdout pipe.
        if (not isinstance(identity, dict) or type(identity.get("pid")) is not int
                or (identity["pid"] != self.process.pid and identity.get("parent_pid") != self.process.pid)
                or identity.get("process") != process_identity(identity["pid"])):
            raise RuntimeError("web_worker_identity_mismatch")
        self.worker_identity = identity["process"]

    async def call(self, command: str, arguments: dict, *,
                   before_send: Callable[[], Awaitable[None]] | None = None,
                   execution: dict | None = None,
                   on_effects: Callable[[bool | None], None] | None = None) -> object:
        try:
            await self._lock.acquire()
        except asyncio.CancelledError as error:
            raise error_with_effect(error, dispatched=False, stage="transport_preflight")
        try:
            process = self.process
            if (self._poisoned or process is None or process.stdin is None
                    or process.stdout is None or process.returncode is not None):
                raise error_with_effect(RuntimeError("web_worker_unavailable"),
                                        dispatched=False, stage="transport_preflight")
            sequence = self._sequence + 1
            request = {"id": sequence, "command": command, "arguments": arguments}
            if execution is not None:
                request["execution"] = execution
            encoded = (json.dumps(request, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
            if len(encoded) > _MAX_MESSAGE:
                raise error_with_effect(ValueError("web_worker_request_too_large"),
                                        dispatched=False, stage="transport_preflight")
            if before_send is not None:
                try:
                    await before_send()
                except (Exception, asyncio.CancelledError) as error:
                    raise error_with_effect(error, dispatched=False, stage="transport_preflight")
            if process.returncode is not None or self._poisoned:
                raise error_with_effect(RuntimeError("web_worker_unavailable"),
                                        dispatched=False, stage="transport_preflight")
            self._sequence = sequence
            try:
                process.stdin.write(encoded)
                await process.stdin.drain()
                line = await asyncio.wait_for(
                    process.stdout.readline(),
                    timeout=(_DOWNLOAD_RESPONSE_TIMEOUT if command == "download"
                             else _WORKER_RESPONSE_TIMEOUT))
            except (OSError, ValueError, asyncio.IncompleteReadError, asyncio.TimeoutError) as exc:
                self._poisoned = True
                raise RuntimeError("web_worker_outcome_uncertain") from exc
            except asyncio.CancelledError:
                self._poisoned = True
                raise
            if not line or len(line) > _MAX_MESSAGE:
                self._poisoned = True
                raise RuntimeError("web_worker_outcome_uncertain")
            try:
                response = json.loads(line)
            except (ValueError, UnicodeError) as exc:
                self._poisoned = True
                raise RuntimeError("web_worker_invalid_response") from exc
            if not isinstance(response, dict) or response.get("id") != self._sequence:
                self._poisoned = True
                raise RuntimeError("web_worker_invalid_response")
            dispatched = response.get("dispatched")
            dispatched = dispatched if type(dispatched) is bool else None
            if on_effects is not None:
                on_effects(dispatched)
            if response.get("ok") is True:
                return response.get("result")
            code = response.get("error")
            stage = response.get("stage")
            stage = stage if type(stage) is str and stage in KNOWN_STAGES else "unknown"
            if isinstance(code, str) and code.startswith("control:"):
                raise error_with_effect(ControlError(code.removeprefix("control:")),
                                        dispatched=dispatched, stage=stage)
            raise error_with_effect(RuntimeError(code if isinstance(code, str) and len(code) <= 100 else "web_worker_command_failed"),
                                    dispatched=dispatched, stage=stage)
        finally:
            self._lock.release()

    async def stop(self) -> None:
        process = self.process
        self.process = None
        if process is None:
            if self._stop_event is not None:
                self._stop_event.Close()
                self._stop_event = None
            return
        if process.returncode is None:
            try:
                await asyncio.wait_for(self._call_close(process), timeout=5)
            except Exception:
                pass
        if process.returncode is None:
            if self._stop_event is not None:
                win32event.SetEvent(self._stop_event)
            try:
                process.terminate()  # exact child PID only
            except ProcessLookupError:
                pass
        try:
            await asyncio.wait_for(process.wait(), timeout=5)
        except asyncio.TimeoutError:
            try:
                process.kill()  # exact child PID only
            except ProcessLookupError:
                pass
            await process.wait()
        self.observe_exit(process.returncode)
        if self._diagnostic_task is not None:
            try:
                await asyncio.wait_for(asyncio.shield(self._diagnostic_task), timeout=5)
            except (asyncio.TimeoutError, OSError, ValueError):
                self.diagnostic_invalid += 1
                self._diagnostic_task.cancel()
                await asyncio.gather(self._diagnostic_task, return_exceptions=True)
            self._diagnostic_task = None
        if self._stop_event is not None:
            self._stop_event.Close()
            self._stop_event = None

    async def _call_close(self, process: asyncio.subprocess.Process) -> None:
        if process.stdin is not None:
            process.stdin.close()  # EOF asks the worker to stop and release Playwright
        await process.wait()


class RemotePageDriver:
    """Thin PageDriver proxy; every user-visible call rechecks in the parent."""

    def __init__(self, worker: _WorkerClient, page_id: str) -> None:
        self.worker = worker
        self.page_id = page_id

    async def _read(self, command: str, arguments: dict, check: Callable[[], Awaitable[None]]) -> dict:
        result = await self.worker.call(command, {"page_id": self.page_id, **arguments},
                                        before_send=check)
        await check()
        if not isinstance(result, dict):
            raise RuntimeError("web_worker_invalid_response")
        return result

    async def _write(self, command: str, arguments: dict, check: Callable[[], Awaitable[None]]) -> dict:
        # The upper control layer must commit its at-most-once receipt before
        # calling this method. A lost reply is uncertain and never retried.
        try:
            result = await self.worker.call(command, {"page_id": self.page_id, **arguments},
                                            before_send=check)
        except ControlError:
            raise
        except RuntimeError as exc:
            if str(exc) in {"web_worker_outcome_uncertain", "web_worker_invalid_response",
                            "web_worker_unavailable", "worker_command_failed"}:
                raise ControlError("outcome_uncertain") from exc
            raise
        await check()
        if not isinstance(result, dict):
            raise RuntimeError("web_worker_invalid_response")
        return result

    async def observe(self, *, check: Callable[[], Awaitable[None]], frame_index: int = 0,
                      selector: str = "button,input,textarea,select,a,[role],[contenteditable]",
                      offset: int = 0, limit: int = 100, ttl: float = 15) -> dict:
        return await self._read("observe", dict(frame_index=frame_index, selector=selector,
                                                offset=offset, limit=limit, ttl=ttl), check)

    async def read_text(self, reference: str, *, check: Callable[[], Awaitable[None]],
                        offset: int = 0, limit: int = 16000) -> dict:
        return await self._read("read_text", dict(reference=reference, offset=offset, limit=limit), check)

    async def page_diagnostics(self, *, check: Callable[[], Awaitable[None]],
                               after_seq: int = 0, limit: int = 30) -> dict:
        return await self._read("page_diagnostics",
                                dict(after_seq=after_seq, limit=limit), check)

    async def fill(self, reference: str, text: str, *, check: Callable[[], Awaitable[None]]) -> dict:
        return await self._write("fill", dict(reference=reference, text=text), check)

    async def click(self, reference: str, *, check: Callable[[], Awaitable[None]]) -> dict:
        return await self._write("click", dict(reference=reference), check)

    async def navigate(self, url: str, *, check: Callable[[], Awaitable[None]]) -> dict:
        return await self._write("navigate", dict(url=url), check)

    async def dispose(self) -> None:
        try:
            await self.worker.call("dispose_page", {"page_id": self.page_id})
        except RuntimeError:
            pass


@dataclass(frozen=True)
class SessionPage:
    page_id: str
    driver: RemotePageDriver


class TemporaryWebSession:
    """A fresh OS-temp profile and exact owned Brave Job."""

    def __init__(self, *, brave_executable: Path = DEFAULT_BRAVE, headless: bool = True,
                 guarded: bool = False, persistent_profile: Path | None = None,
                 owner_task: str | None = None, login_only: bool = False,
                 initial_url: str = "about:blank", profile_kind: str = "ai",
                 owner_task_matches: Callable[[object], bool] | None = None,
                 diagnostic: Callable[[dict], None] | None = None) -> None:
        executable = Path(brave_executable)
        if not executable.is_absolute() or executable.name.lower() != "brave.exe":
            raise ValueError("exact_brave_executable_required")
        self.brave_executable = executable
        self.headless = bool(headless)
        self.guarded = bool(guarded)
        if persistent_profile is not None:
            candidate = Path(persistent_profile)
            if not candidate.is_absolute() or any(
                    part.is_symlink() or os.path.isjunction(part)
                    for part in (candidate, *candidate.parents) if part.exists()):
                raise ValueError("invalid_persistent_profile")
            self._profile_requested_path = candidate
            self.persistent_profile = candidate.resolve()
        else:
            self._profile_requested_path = None
            self.persistent_profile = None
        if self.persistent_profile is not None and (not self.persistent_profile.is_absolute()
                                                   or not owner_task or not guarded):
            raise ValueError("invalid_persistent_profile")
        if self.persistent_profile is not None and profile_kind not in ("ai", "luohua"):
            raise ValueError("invalid_profile_kind")
        self.profile_kind = profile_kind if self.persistent_profile is not None else "temporary"
        self.owner_task = owner_task
        self._owner_task_matches = owner_task_matches
        self.login_only = bool(login_only)
        if self.login_only and (self.persistent_profile is None or self.headless or not self.guarded):
            raise ValueError("invalid_login_session")
        if initial_url != "about:blank":
            from urllib.parse import urlsplit
            parsed = urlsplit(initial_url)
            if (parsed.username or parsed.password or parsed.fragment or
                    not parsed.hostname or
                    not (parsed.scheme == "https" or
                         parsed.scheme == "http" and
                         parsed.hostname in {"127.0.0.1", "localhost"} and parsed.port)):
                raise ValueError("invalid_visible_login_url")
        self.initial_url = initial_url
        self._profile_lock = None
        self.session_id = uuid.uuid4().hex
        self.profile_path: Path | None = None
        self._created_temp_profile: Path | None = None
        self.profile_cleanup = "not_applicable"
        self.profile_cleanup_error: str | None = None
        self.process_id: int | None = None
        self.process_created: str | None = None
        self.cdp_endpoint: str | None = None
        self._environment = _minimal_environment()
        self._job = None
        self._job_close_lock = threading.Lock()
        self._process: _OwnedProcess | None = None
        self._worker: _WorkerClient | None = None
        self._launch_task: asyncio.Task | None = None
        self._worker_start_task: asyncio.Task | None = None
        self._close_task: asyncio.Task | None = None
        # Irreversible evidence from the exact owned process handle. Retained
        # after handle release so partial terminal cleanup can be retried.
        self._browser_exit_verified = False
        self._worker_watch: asyncio.Task | None = None
        self._pages: dict[str, SessionPage] = {}
        self._started = False
        self._closed = False
        self._diagnostic = diagnostic
        self.lifecycle: list[dict] = []
        self.browser_exit: dict | None = None
        self.worker_exit: dict | None = None
        self.launcher_exit: dict | None = None

    def record_lifecycle(self, phase: str, *, trigger: str | None = None, worker: dict | None = None) -> None:
        phases = {"browser_started", "worker_observed_exit", "browser_observed_exit",
                  "cleanup_requested", "cleanup_started", "cleanup_finished", "cleanup_failed", "worker_diagnostic"}
        if phase not in phases or trigger not in {None, "heartbeat", "public_close", "worker_watch", "startup_failure"}:
            raise ValueError("invalid_lifecycle_phase")
        event = {"phase": phase, "session_id": self.session_id, "observed_at": time.monotonic(),
                 "trigger": trigger, "browser_process_id": self.process_id,
                 "browser_process_created": self.process_created,
                 "browser_exit": self.browser_exit, "worker_exit": self.worker_exit,
                 "launcher_exit": self.launcher_exit}
        if worker is not None:
            event["worker"] = dict(worker)
        self.lifecycle.append(event)
        del self.lifecycle[:-_DIAGNOSTIC_RECORD_LIMIT]
        try:
            if self._diagnostic is not None:
                self._diagnostic(event)
        except Exception:
            pass

    def _observe_browser_exit(self) -> None:
        if self.browser_exit is not None or self._process is None or self.running:
            return
        metadata = {}
        try:
            if callable(getattr(self._process, "exit_metadata", None)):
                metadata = self._process.exit_metadata()
        except Exception:
            pass
        self.browser_exit = {"observed_at": time.monotonic(),
            "exit_code": metadata.get("exit_code") if type(metadata.get("exit_code")) is int else None,
            "os_exit_time": metadata.get("os_exit_time") if type(metadata.get("os_exit_time")) is str else None}
        self.record_lifecycle("browser_observed_exit")

    def health_snapshot(self) -> dict:
        browser_running = self.running
        if not browser_running:
            self._observe_browser_exit()
        worker = self._worker
        process = getattr(worker, "process", None)
        code = getattr(process, "returncode", None)
        if type(code) is int and self.launcher_exit is None:
            self.launcher_exit = {"exit_code": code, "observed_at": time.monotonic(),
                                  "process_id": getattr(process, "pid", None)}
            self.record_lifecycle("worker_observed_exit")
        identity = getattr(worker, "worker_identity", None)
        worker_running = None
        if type(identity) is str:
            worker_running = _worker_running(identity)
        elif worker is None:
            worker_running = False
        return {"browser_running": browser_running,
            "browser_process_id": self.process_id, "browser_process_created": self.process_created,
            "browser_exit": self.browser_exit, "worker_running": worker_running,
            "worker_process": identity, "worker_exit": self.worker_exit,
            "launcher_running": process is not None and code is None,
            "launcher_process_id": getattr(process, "pid", None), "launcher_exit": self.launcher_exit,
            "transport_poisoned": bool(getattr(worker, "_poisoned", False)),
            "diagnostic_invalid": getattr(worker, "diagnostic_invalid", 0),
            "diagnostic_omitted": getattr(worker, "diagnostic_omitted", 0)}

    def _worker_diagnostic(self, item):
        if item["phase"] == "worker_exit" and self.worker_exit is None:
            self.worker_exit = {"reported_exit_code": item["exit_code"],
                                "observed_at": item["observed_at"], "process": item["process"]}
        self.record_lifecycle("worker_diagnostic", worker=item)

    @property
    def running(self) -> bool:
        return bool(self._process and self._process.running())

    @property
    def window_visible(self) -> bool:
        return bool(not self.headless and self.running and self.process_id
                    and _taskbar_browser_windows(self.process_id))

    def _wait_for_taskbar_window(self, deadline: float) -> list[int]:
        assert self.process_id is not None and self._process is not None
        while time.monotonic() < deadline:
            if not self._process.running():
                raise RuntimeError("owned_brave_exited_before_visible_window")
            windows = _taskbar_browser_windows(self.process_id)
            if windows:
                return windows
            time.sleep(0.05)
        raise TimeoutError("owned_brave_taskbar_window_timeout")

    def _maximize_visible_window(self, deadline: float) -> None:
        hwnd = self._wait_for_taskbar_window(deadline)[0]
        flags, _, minimum, maximum, normal = win32gui.GetWindowPlacement(hwnd)
        win32gui.SetWindowPlacement(
            hwnd, (flags, win32con.SW_SHOWMAXIMIZED, minimum, maximum, normal))
        if win32gui.GetWindowPlacement(hwnd)[1] != win32con.SW_SHOWMAXIMIZED:
            raise RuntimeError("owned_brave_window_not_maximized")

    def _launch_brave(self) -> str:
        if not self.brave_executable.is_file():
            raise FileNotFoundError(self.brave_executable)
        assert self.profile_path is not None
        port_file = self.profile_path / "DevToolsActivePort"
        if port_file.is_symlink() or os.path.isjunction(port_file):
            raise ControlError("ai_browser_endpoint_unverified")
        if port_file.is_file() and port_file.stat().st_size > 256:
            raise ControlError("ai_browser_endpoint_unverified")
        stale_port_file = port_file.read_bytes() if port_file.is_file() else None
        self._job = win32job.CreateJobObject(None, "")
        if self.persistent_profile is None:
            info = win32job.QueryInformationJobObject(self._job, win32job.JobObjectExtendedLimitInformation)
            info["BasicLimitInformation"]["LimitFlags"] |= win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            win32job.SetInformationJobObject(self._job, win32job.JobObjectExtendedLimitInformation, info)
        args = [str(self.brave_executable), f"--user-data-dir={self.profile_path}",
                "--no-first-run", "--no-default-browser-check", "--disable-background-networking",
                "--disable-default-apps", "--disable-component-update", "--disable-sync",
                "--disable-extensions", "--disable-background-mode",
                "--disable-client-side-phishing-detection", "--safebrowsing-disable-auto-update",
                "--disable-domain-reliability", "--no-pings", "--disable-breakpad"]
        if not self.login_only:
            args.extend(("--remote-debugging-address=127.0.0.1", "--remote-debugging-port=0"))
        if self.headless:
            args.append("--headless=new")
            width, height = _headless_window_size()
            args.append(f"--window-size={width},{height}")
        args.append(self.initial_url)
        startup = win32process.STARTUPINFO()
        startup.dwFlags |= win32con.STARTF_USESHOWWINDOW
        startup.wShowWindow = win32con.SW_HIDE if self.headless else win32con.SW_SHOWNOACTIVATE
        handle, thread, pid, _ = win32process.CreateProcess(
            str(self.brave_executable), subprocess.list2cmdline(args), None, None, False,
            win32con.CREATE_SUSPENDED | win32con.CREATE_UNICODE_ENVIRONMENT
            | (win32con.CREATE_NO_WINDOW if self.headless else 0)
            # A persistent profile must outlive the Codex-owned MCP Job.
            | (win32process.CREATE_BREAKAWAY_FROM_JOB
               if self.persistent_profile is not None else 0),
            self._environment, None, startup,
        )
        try:
            win32job.AssignProcessToJobObject(self._job, handle)
            created = win32process.GetProcessTimes(handle)["CreationTime"].isoformat()
            self.process_id, self.process_created = pid, created
            marker = {"session_id": self.session_id, "owner_pid": os.getpid(),
                      "owner_task": self.owner_task,
                      "browser_pid": pid, "browser_created": created,
                      "executable": str(self.brave_executable), "headless": self.headless,
                      "created_utc": datetime.now(timezone.utc).isoformat()}
            if self.persistent_profile is not None:
                marker.update(profile_kind=self.profile_kind, owner_task=self.owner_task,
                              profile_hash=hashlib.sha256(str(self.profile_path).lower().encode()).hexdigest(),
                              state="running", brave_digest=self._brave_digest(),
                              owner_process=process_identity(), worker_process=None,
                              login_only=self.login_only, login_cancel_requested=False)
            if self.persistent_profile is not None:
                self._write_marker(marker)
            else:
                with (self.profile_path / "flower-session.json").open("x", encoding="utf-8") as file:
                    file.write(json.dumps(marker, ensure_ascii=False, indent=2) + "\n")
            if win32process.ResumeThread(thread) != 1:
                raise RuntimeError("browser_thread_not_suspended")
            self._process = _OwnedProcess(handle, pid, created)
        except BaseException:
            if win32event.WaitForSingleObject(handle, 0) == win32event.WAIT_TIMEOUT:
                win32process.TerminateProcess(handle, 1)
                win32event.WaitForSingleObject(handle, 10_000)
            handle.Close()
            raise
        finally:
            thread.Close()
        if self.login_only:
            deadline = time.monotonic() + _START_TIMEOUT
            self._maximize_visible_window(deadline)
            windows = _taskbar_browser_windows(self.process_id)
            marker = self._read_marker()
            marker["login_window_hwnds"] = windows
            self._write_marker(marker)
            return ""
        deadline = time.monotonic() + _START_TIMEOUT
        while time.monotonic() < deadline:
            if not self._process.running():
                raise RuntimeError("owned_brave_exited_before_cdp")
            if port_file.is_file():
                try:
                    if port_file.stat().st_size > 256:
                        raise RuntimeError("invalid_owned_cdp_endpoint_file")
                    current_port_file = port_file.read_bytes()
                except (PermissionError, FileNotFoundError):
                    # Brave publishes this exact file during startup. Windows
                    # can briefly deny sharing while its writer still owns it.
                    time.sleep(0.05)
                    continue
                if current_port_file == stale_port_file:
                    time.sleep(0.05)
                    continue
                parts = current_port_file.decode("ascii").splitlines()
                if len(parts) == 2 and parts[0].isdigit() and _CDP_PATH.fullmatch(parts[1]):
                    port = int(parts[0])
                    if 1 <= port <= 65535:
                        endpoint = f"ws://127.0.0.1:{port}{parts[1]}"
                        if self.persistent_profile is not None:
                            marker = self._read_marker()
                            marker["cdp_endpoint"] = endpoint
                            self._write_marker(marker)
                        if not self.headless:
                            self._maximize_visible_window(deadline)
                        return endpoint
            time.sleep(0.05)
        raise TimeoutError("owned_brave_cdp_endpoint_timeout")

    async def _watch_worker(self, process: asyncio.subprocess.Process) -> None:
        code = await process.wait()
        if self.launcher_exit is None:
            self.launcher_exit = {"exit_code": code if type(code) is int else None,
                "observed_at": time.monotonic(), "process_id": getattr(process, "pid", None)}
        self.record_lifecycle("worker_observed_exit", trigger="worker_watch")
        if not self._closed and self.persistent_profile is None and not self.running:
            # Worker loss is not permission to close live tabs. Retain the exact
            # process and KILL_ON_JOB_CLOSE handle for same-chat normal recovery;
            # only an already exited browser can release its owned job here.
            self.record_lifecycle("cleanup_requested", trigger="worker_watch")
            await asyncio.to_thread(self._close_job)

    def _marker_owner_matches(self, marker: dict) -> bool:
        return (marker.get("owner_task") == self.owner_task or
                (self._owner_task_matches is not None and
                 self._owner_task_matches(marker.get("owner_task"))))

    async def start(self) -> TemporaryWebSession:
        if self._closed or self._started or self.profile_path is not None:
            raise RuntimeError("session_start_not_available")
        if self.persistent_profile is None:
            self.profile_path = Path(tempfile.mkdtemp(prefix="flower-web-temp-"))
            self._created_temp_profile = self.profile_path
            self.profile_cleanup = "pending_controlled_recycle"
        else:
            self.profile_path = self.persistent_profile
            self._acquire_profile_lock()
            try:
                # A missing directory can resolve differently from the same
                # directory once created on Windows. Seal new markers against
                # the existing, locked directory's spelling.
                self.profile_path = self.profile_path.resolve()
                self.persistent_profile = self.profile_path
                marker_path = self.profile_path / "flower-session.json"
                if not marker_path.exists():
                    self._recover_interrupted_marker()
                if marker_path.exists():
                    marker = self._read_marker(ignore_mode=True, allow_closed_browser_update=True)
                    if (marker.get("state") == "running" and
                            marker.get("owner_task") != self.owner_task and
                            self._marker_owner_matches(marker)):
                        identities = [f"{marker['browser_pid']}:{marker['browser_created']}",
                                      marker.get("owner_process"), marker.get("worker_process")]
                        if all(identity is None or not process_is_alive(identity)
                               for identity in identities):
                            marker.update(state="closed", owner_process=None, worker_process=None)
                            marker.pop("owner_task", None)
                            self._write_marker(marker)
                    if marker.get("state") != "closed":
                        raise ControlError("ai_profile_existing_instance_requires_reconnect")
                    if process_is_alive(f"{marker['browser_pid']}:{marker['browser_created']}"):
                        raise ControlError("ai_profile_existing_instance_unresolved")
                elif any(item.name != "flower-profile.lock" for item in self.profile_path.iterdir()):
                    raise ControlError("ai_profile_unrecognized_data")
            except BaseException:
                await self._release_profile_lock()
                raise
        self._launch_task = asyncio.create_task(asyncio.to_thread(self._launch_brave))
        try:
            self.cdp_endpoint = await asyncio.shield(self._launch_task)
            self.record_lifecycle("browser_started")
            if self._closed:
                raise RuntimeError("session_closed_during_start")
            if self.login_only:
                if not self.running:
                    raise RuntimeError("owned_login_browser_exited")
                self._started = True
                return self
            self._worker = _WorkerClient(self._environment, guarded=self.guarded,
                                         profile_kind=self.profile_kind,
                                         diagnostic=self._worker_diagnostic)
            self._worker_start_task = asyncio.create_task(self._worker.start(self.cdp_endpoint))
            await asyncio.shield(self._worker_start_task)
            if self._closed:
                raise RuntimeError("session_closed_during_start")
            if self.persistent_profile is not None:
                marker = self._read_marker()
                marker["worker_process"] = self._worker.worker_identity
                self._write_marker(marker)
            assert self._worker.process is not None
            self._worker_watch = asyncio.create_task(self._watch_worker(self._worker.process))
            if not self.running:
                raise RuntimeError("owned_browser_connection_invalid")
            self._started = True
            return self
        except BaseException:
            if self.login_only and self.running:
                # A visible login window may already be in use. Never kill it
                # merely because startup verification or the host failed.
                await self.disconnect()
                raise
            # close() waits for both startup tasks before touching their jobs
            # or process handles. This also handles a concurrent caller close.
            self.record_lifecycle("cleanup_requested", trigger="startup_failure")
            cleanup_task = asyncio.create_task(self.close())
            while not cleanup_task.done():
                try:
                    await asyncio.shield(cleanup_task)
                except asyncio.CancelledError:
                    continue
                except Exception:
                    break
            raise

    def _acquire_profile_lock(self) -> None:
        assert self.profile_path is not None
        if self.profile_path.is_symlink() or os.path.isjunction(self.profile_path):
            raise ControlError("ai_profile_reparse_point")
        self.profile_path.mkdir(parents=True, exist_ok=True)
        lock_path = self.profile_path / "flower-profile.lock"
        if lock_path.is_symlink() or os.path.isjunction(lock_path):
            raise ControlError("ai_profile_reparse_point")
        try:
            self._profile_lock = win32file.CreateFile(
                str(lock_path), win32con.GENERIC_READ | win32con.GENERIC_WRITE,
                0, None, win32con.OPEN_ALWAYS, win32con.FILE_ATTRIBUTE_NORMAL, None)
        except Exception as exc:
            raise ControlError("ai_profile_in_use") from exc

    async def _release_profile_lock(self) -> None:
        if self._profile_lock is not None:
            self._profile_lock.Close()
            self._profile_lock = None

    def _read_marker(self, *, ignore_mode: bool = False,
                     provisional: bool = False,
                     allow_closed_browser_update: bool = False) -> dict:
        assert self.profile_path is not None
        try:
            marker_path = self.profile_path / (
                "flower-session.json.new" if provisional else "flower-session.json")
            if marker_path.is_symlink() or os.path.isjunction(marker_path):
                raise ValueError("marker reparse point")
            if marker_path.stat().st_size > 4096:
                raise ValueError("oversized marker")
            marker = json.loads(marker_path.read_text(encoding="utf-8"))
            expected = hashlib.sha256(str(self.profile_path).lower().encode()).hexdigest()
            profile_hash = marker.get("profile_hash") if isinstance(marker, dict) else None
            if profile_hash != expected:
                original = self._profile_requested_path
                legacy_hash = (hashlib.sha256(str(original).lower().encode()).hexdigest()
                               if original is not None else None)
                if (profile_hash != legacy_hash or original is None
                        or original.is_symlink() or os.path.isjunction(original)
                        or not original.samefile(self.profile_path)):
                    raise ValueError("profile path identity mismatch")
            if (not isinstance(marker, dict) or marker.get("profile_kind") != self.profile_kind
                    or marker.get("executable", "").lower() != str(self.brave_executable).lower()
                    or (not ignore_mode and marker.get("headless") != self.headless)
                    or (not ignore_mode and marker.get("login_only", False) != self.login_only)
                    or (not ignore_mode and self.login_only and
                        (type(marker.get("login_cancel_requested")) is not bool
                         or marker.get("worker_process") is not None
                         or marker.get("cdp_endpoint") is not None))
                    or (marker.get("owner_process") is not None and
                        not isinstance(marker.get("owner_process"), str))
                    or (marker.get("worker_process") is not None and
                        not isinstance(marker.get("worker_process"), str))
                    or (marker.get("state") == "running" and
                        not isinstance(marker.get("owner_task"), str))
                    or marker.get("state") not in {"running", "closed"}
                    or not re.fullmatch(r"[0-9a-f]{32}", marker.get("session_id", ""))):
                raise ValueError("marker mismatch")
            if marker.get("brave_digest") != self._brave_digest():
                # A closed profile survives normal updates of the same Brave
                # executable. This is a fresh launch, never a live reconnect.
                pid, created = marker.get("browser_pid"), marker.get("browser_created")
                if (not allow_closed_browser_update or provisional
                        or marker.get("state") != "closed"
                        or not re.fullmatch(r"[0-9a-f]{64}", marker.get("brave_digest", ""))
                        or type(pid) is not int or pid <= 0
                        or not isinstance(created, str) or not created):
                    raise ValueError("browser digest mismatch")
                identities = [f"{pid}:{created}", marker.get("owner_process"),
                              marker.get("worker_process")]
                if any(identity is not None and process_is_alive(identity)
                       for identity in identities):
                    raise ValueError("previous browser processes still running")
            return marker
        except (OSError, ValueError, TypeError, KeyError) as exc:
            raise ControlError("ai_profile_identity_unverified") from exc

    def _brave_digest(self) -> str:
        try:
            with self.brave_executable.open("rb") as file:
                digest = hashlib.file_digest(file, "sha256")
            return digest.hexdigest()
        except OSError as exc:
            raise ControlError("ai_brave_executable_unavailable") from exc

    def _write_marker(self, marker: dict) -> None:
        assert self.profile_path is not None
        path = self.profile_path / "flower-session.json"
        temporary = self.profile_path / "flower-session.json.new"
        if temporary.is_symlink() or os.path.isjunction(temporary):
            raise ControlError("ai_profile_reparse_point")
        marker["profile_hash"] = hashlib.sha256(
            str(self.profile_path).lower().encode()).hexdigest()
        payload = json.dumps(marker, ensure_ascii=False, indent=2) + "\n"
        temporary.write_text(payload, encoding="utf-8")
        try:
            os.replace(temporary, path)
        except OSError as error:
            if getattr(error, "winerror", None) != 17:
                raise
            # Encrypted Windows profile directories can reject replacement
            # across their internal storage boundary. A partial direct write
            # is rejected by _read_marker; keep .new as recovery evidence.
            with path.open("w", encoding="utf-8") as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
            if path.read_text(encoding="utf-8") != payload:
                raise ControlError("ai_profile_marker_write_unverified")

    def _recover_interrupted_marker(self) -> None:
        """Seal only our own pre-resume launch when Windows replace failed."""
        assert self.profile_path is not None
        temporary = self.profile_path / "flower-session.json.new"
        if not temporary.exists():
            return
        if temporary.is_symlink() or os.path.isjunction(temporary):
            raise ControlError("ai_profile_reparse_point")
        if {entry.name for entry in self.profile_path.iterdir()} != {
                "flower-profile.lock", "flower-session.json.new"}:
            raise ControlError("ai_profile_incomplete_unverified")
        marker = self._read_marker(ignore_mode=True, provisional=True)
        pid, created = marker.get("browser_pid"), marker.get("browser_created")
        if (marker.get("state") != "running" or type(pid) is not int or pid <= 0
                or not isinstance(created, str) or not created
                or marker.get("worker_process") is not None
                or marker.get("cdp_endpoint") is not None
                or process_is_alive(f"{pid}:{created}")):
            raise ControlError("ai_profile_incomplete_unverified")
        marker.update(state="closed", owner_process=None, worker_process=None)
        self._write_marker(marker)

    def _open_verified_process(self, marker: dict) -> _OwnedProcess:
        try:
            pid = marker["browser_pid"]
            created = marker["browser_created"]
            if type(pid) is not int or pid <= 0 or not isinstance(created, str):
                raise ValueError("bad process identity")
            rights = win32con.PROCESS_QUERY_LIMITED_INFORMATION | win32con.SYNCHRONIZE
            if not self.login_only:
                rights |= win32con.PROCESS_TERMINATE
            handle = win32api.OpenProcess(rights,
                                          False, pid)
            process = _OwnedProcess(handle, pid, created)
            if not process.running() or process_identity(pid) != f"{pid}:{created}":
                raise ValueError("old process exited")
            buffer = ctypes.create_unicode_buffer(32768)
            length = ctypes.c_ulong(len(buffer))
            query_image = ctypes.windll.kernel32.QueryFullProcessImageNameW
            query_image.argtypes = [ctypes.c_void_p, ctypes.c_ulong,
                                    ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_ulong)]
            query_image.restype = ctypes.c_int
            if not query_image(int(handle), 0, buffer, ctypes.byref(length)):
                raise ValueError("process executable unavailable")
            if Path(buffer.value).resolve() != self.brave_executable.resolve():
                raise ValueError("process executable mismatch")
            if not self._process_uses_profile(pid):
                raise ValueError("process profile mismatch")
            return process
        except Exception as exc:
            if "handle" in locals():
                handle.Close()
            raise ControlError("ai_browser_identity_unverified") from exc

    def _process_uses_profile(self, pid: int) -> bool:
        """Inspect only this exact PID's launch args; never read another profile."""
        pythoncom.CoInitialize()
        try:
            service = win32com.client.GetObject("winmgmts:")
            rows = list(service.ExecQuery(
                f"SELECT CommandLine FROM Win32_Process WHERE ProcessId={pid}"))
            if len(rows) != 1 or not rows[0].CommandLine:
                return False
            count = ctypes.c_int()
            shell32 = ctypes.windll.shell32
            shell32.CommandLineToArgvW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_int)]
            shell32.CommandLineToArgvW.restype = ctypes.POINTER(ctypes.c_wchar_p)
            argv = shell32.CommandLineToArgvW(str(rows[0].CommandLine), ctypes.byref(count))
            if not argv:
                return False
            try:
                args = [argv[index] for index in range(count.value)]
            finally:
                local_free = ctypes.windll.kernel32.LocalFree
                local_free.argtypes = [ctypes.c_void_p]
                local_free.restype = ctypes.c_void_p
                local_free(ctypes.cast(argv, ctypes.c_void_p))
            prefix = "--user-data-dir="
            directories = [Path(arg[len(prefix):]).resolve()
                           for arg in args if arg.lower().startswith(prefix)]
            if len(directories) != 1 or directories[0] != self.profile_path:
                return False
            if self.login_only:
                forbidden = ("--remote-debugging-", "--headless", "--enable-automation")
                if any(arg.lower().startswith(forbidden) for arg in args):
                    return False
            return True
        finally:
            pythoncom.CoUninitialize()

    def _verified_endpoint(self, marker: dict) -> str:
        assert self.profile_path is not None
        try:
            path = self.profile_path / "DevToolsActivePort"
            if path.is_symlink() or os.path.isjunction(path):
                raise ValueError("endpoint reparse point")
            if path.stat().st_size > 256:
                raise ValueError("invalid endpoint file")
            parts = path.read_text(encoding="ascii").splitlines()
            if (len(parts) != 2 or not parts[0].isdigit()
                    or not 1 <= int(parts[0]) <= 65535 or not _CDP_PATH.fullmatch(parts[1])):
                raise ValueError("invalid endpoint")
            endpoint = f"ws://127.0.0.1:{int(parts[0])}{parts[1]}"
            if endpoint != marker.get("cdp_endpoint"):
                raise ValueError("endpoint changed")
            return endpoint
        except (OSError, ValueError) as exc:
            raise ControlError("ai_browser_endpoint_unverified") from exc

    async def reconnect(self, session_id: str) -> TemporaryWebSession:
        if self.persistent_profile is None or self._started or self._closed:
            raise ControlError("ai_reconnect_unavailable")
        self.profile_path = self.persistent_profile
        self._acquire_profile_lock()
        try:
            marker = self._read_marker(ignore_mode=True)
            if type(marker.get("headless")) is not bool or marker.get("login_only", False) != self.login_only:
                raise ControlError("ai_profile_identity_unverified")
            # An existing profile may have been launched by an older headless
            # version. Reconnect to that exact process without claiming a window.
            self.headless = marker["headless"]
            if marker.get("state") != "running" or marker.get("session_id") != session_id:
                raise ControlError("ai_session_not_running")
            if not self._marker_owner_matches(marker):
                raise ControlError("session_not_found_for_chat")
            owner_process = marker.get("owner_process")
            worker_process = marker.get("worker_process")
            if owner_process is not None and process_is_alive(owner_process):
                raise ControlError("ai_previous_host_still_running")
            if worker_process is not None and process_is_alive(worker_process):
                raise ControlError("ai_previous_worker_still_running")
            if not self.login_only and owner_process is not None and worker_process is None:
                raise ControlError("ai_previous_worker_unverified")
            self._process = self._open_verified_process(marker)
            self.process_id, self.process_created = self._process.pid, self._process.created
            self.session_id = session_id
            if self.login_only:
                marker["owner_task"] = self.owner_task
                marker["owner_process"] = process_identity()
                marker["worker_process"] = None
                self._write_marker(marker)
                self._started = True
                return self
            self.cdp_endpoint = self._verified_endpoint(marker)
            self._worker = _WorkerClient(self._environment, guarded=self.guarded,
                                         profile_kind=self.profile_kind)
            await self._worker.start(self.cdp_endpoint)
            marker["owner_task"] = self.owner_task
            marker["owner_process"] = process_identity()
            marker["worker_process"] = self._worker.worker_identity
            self._write_marker(marker)
            self._started = True
            assert self._worker.process is not None
            self._worker_watch = asyncio.create_task(self._watch_worker(self._worker.process))
            return self
        except BaseException:
            try:
                if self._worker is not None:
                    await self._worker.stop()
                    self._worker = None
                if self._process is not None:
                    self._process.close()
                    self._process = None
            finally:
                await self._release_profile_lock()
            raise

    async def disconnect(self) -> None:
        """Release this MCP's handles without closing a persistent browser."""
        if self.persistent_profile is None:
            raise RuntimeError("disconnect_requires_persistent_profile")
        self._closed = True
        # Reacquire on retry after a failed marker write; never edit a profile
        # owned by another live executor without the exclusive directory lock.
        if self.profile_path is not None and self._profile_lock is None:
            self._acquire_profile_lock()
        try:
            if self._worker is not None:
                await self._worker.stop()
                self._worker = None
            if self._worker_watch is not None:
                await asyncio.gather(self._worker_watch, return_exceptions=True)
                self._worker_watch = None
            if self._process is not None:
                self._process.close()
                self._process = None
            if self._job is not None:
                self._job.Close()
                self._job = None
            if self.profile_path is not None and self._profile_lock is not None:
                marker = self._read_marker()
                if marker.get("session_id") == self.session_id:
                    marker["owner_process"] = None
                    marker["worker_process"] = None
                    self._write_marker(marker)
        finally:
            self._pages.clear()
            self._started = False
            await self._release_profile_lock()

    def _require_worker(self) -> _WorkerClient:
        if not self._started or self._closed or not self.running or self._worker is None:
            raise RuntimeError("session_not_running")
        return self._worker

    async def new_page(self) -> SessionPage:
        worker = self._require_worker()
        result = await worker.call("new_page", {})
        if not isinstance(result, dict) or not isinstance(result.get("page_id"), str):
            raise RuntimeError("web_worker_invalid_response")
        page_id = result["page_id"]
        managed = SessionPage(page_id, RemotePageDriver(worker, page_id))
        self._pages[page_id] = managed
        return managed

    async def list_pages(self) -> list[SessionPage]:
        worker = self._require_worker()
        result = await worker.call("list_pages", {})
        if not isinstance(result, list) or not all(isinstance(id_, str) for id_ in result):
            raise RuntimeError("web_worker_invalid_response")
        for page_id in list(self._pages):
            if page_id not in result:
                self._pages.pop(page_id)
        for page_id in result:
            self._pages.setdefault(page_id, SessionPage(page_id, RemotePageDriver(worker, page_id)))
        return [self._pages[page_id] for page_id in result]

    def _close_job(self) -> None:
        with self._job_close_lock:
            self._observe_browser_exit()
            if self._process is not None and not self._process.running():
                self._browser_exit_verified = True
            if self.persistent_profile is not None and self._process is not None:
                if self._process.running():
                    if self._started and not self.headless:
                        # Browser.close is sent through the verified worker
                        # before it disconnects. A failed close leaves the
                        # instance intact for exact reconnection.
                        self._process.wait(10)
                    else:
                        # Incomplete startup has no user tab state to preserve.
                        win32process.TerminateProcess(self._process.handle, 0)
            if self._job is not None:
                self._job.Close()
                self._job = None
            if self._process is not None:
                try:
                    self._process.wait(10)
                    self._observe_browser_exit()
                    self._browser_exit_verified = True
                finally:
                    self._process.close()
                    self._process = None

    def _recycle_temp_profile(self) -> None:
        path = self._created_temp_profile
        if path is None or self.profile_path != path:
            return
        try:
            root = Path(tempfile.gettempdir()).resolve(strict=True)
            if (not re.fullmatch(r"flower-web-temp-[A-Za-z0-9_-]+", path.name) or
                    path.parent.resolve(strict=True) != root or
                    path.is_symlink() or os.path.isjunction(path)):
                raise ValueError("temporary_profile_identity_changed")
            if not path.exists():
                self.profile_cleanup = "absent"
                return
            pending = [path]
            while pending:
                current = pending.pop()
                for child in current.iterdir():
                    if child.is_symlink() or os.path.isjunction(child):
                        raise ValueError("temporary_profile_reparse_point")
                    if child.is_dir():
                        pending.append(child)
                    elif not child.is_file():
                        raise ValueError("temporary_profile_unexpected_entry")

            class SHFILEOPSTRUCTW(ctypes.Structure):
                _fields_ = [("hwnd", ctypes.c_void_p), ("wFunc", ctypes.c_uint),
                            ("pFrom", ctypes.c_wchar_p), ("pTo", ctypes.c_wchar_p),
                            ("fFlags", ctypes.c_ushort),
                            ("fAnyOperationsAborted", ctypes.c_bool),
                            ("hNameMappings", ctypes.c_void_p),
                            ("lpszProgressTitle", ctypes.c_wchar_p)]

            # FO_DELETE with SILENT, NOCONFIRMATION, ALLOWUNDO and NOERRORUI.
            operation = SHFILEOPSTRUCTW(None, 0x0003, f"{path}\0\0", None,
                                        0x0454, False, None, None)
            result = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(operation))
            if result != 0 or operation.fAnyOperationsAborted or path.exists():
                raise OSError("temporary_profile_recycle_failed")
            self.profile_cleanup = "recycled"
        except (OSError, ValueError) as error:
            self.profile_cleanup = "pending_controlled_recycle"
            self.profile_cleanup_error = (str(error) if isinstance(error, ValueError)
                                          else "temporary_profile_recycle_failed")

    async def _close_impl(self, *, execution=None, before_send=None, on_effects=None,
                          terminal_only: bool = False) -> None:
        self.record_lifecycle("cleanup_started")
        for task in (self._launch_task, self._worker_start_task):
            if task is not None:
                await asyncio.gather(task, return_exceptions=True)
        worker = self._worker
        worker_error: Exception | None = None
        if terminal_only and (not self._browser_exit_verified or self.running):
            raise RuntimeError("web_terminal_cleanup_requires_exact_exit")
        if (not terminal_only and self._started and
                self._process is not None and self._process.running() and
                worker is not None):
            try:
                result = await asyncio.wait_for(worker.call("close_browser", {}, execution=execution,
                    before_send=before_send, on_effects=on_effects), timeout=15)
                if isinstance(result, dict) and result.get("requested") is False:
                    raise WebClosePending(result)
            except WebClosePending:
                # Keep the exact worker, pending page references, process,
                # profile lock and owner alive so this session can answer.
                raise
            except ControlError as error:
                if error.code in CLOSE_STOP_CODES:
                    if (getattr(error, "web_dispatched", None) is False
                            and getattr(error, "web_stage", None) == "transport_preflight"
                            and on_effects is not None):
                        on_effects(False)
                    raise WebClosePending({"requested": False, "state": "close_stopped",
                        "reason": error.code, "closed_pages": [], "pending_pages": []}) from error
                raise
            except Exception:
                # CDP may end with the last normal tab. Only exact process
                # exit establishes completion; a live instance is retained.
                if self._process.running():
                    try:
                        await asyncio.to_thread(self._process.wait, 2)
                    except Exception as error:
                        raise RuntimeError("web_browser_close_outcome_uncertain") from error
        elif not terminal_only and self._started and self.running and worker is None:
            raise RuntimeError("web_browser_close_worker_unavailable")
        if self._process is not None and not self._process.running():
            self._observe_browser_exit()
            self._browser_exit_verified = True
        try:
            if worker is not None:
                await worker.stop()
                self._worker = None
        except Exception as exc:
            worker_error = exc
        try:
            await asyncio.to_thread(self._close_job)
        except Exception:
            raise
        if self._worker_watch is not None and worker_error is None:
            await asyncio.gather(self._worker_watch, return_exceptions=True)
            self._worker_watch = None
        if self.persistent_profile is None:
            await asyncio.to_thread(self._recycle_temp_profile)
        if self.persistent_profile is not None:
            try:
                if self.profile_path is not None and (self.profile_path / "flower-session.json").exists():
                    marker = self._read_marker()
                    if marker.get("session_id") == self.session_id:
                        marker["state"] = "closed"
                        marker.pop("owner_task", None)
                        self._write_marker(marker)
            finally:
                await self._release_profile_lock()
        self._pages.clear()
        self._started = False
        if worker_error is not None:
            self.record_lifecycle("cleanup_failed")
            raise RuntimeError("web_worker_cleanup_failed") from worker_error
        self.record_lifecycle("cleanup_finished")

    async def close(self, *, execution: dict | None = None, before_send=None, on_effects=None) -> None:
        terminal_only = False
        if (self._close_task is not None and self._close_task.done()
                and not self._close_task.cancelled() and self._close_task.exception() is not None):
            # Unknown live closes retain their failed future: never replay a
            # Browser.close or tab write. Only exact owned-handle exit permits
            # a new task, which performs terminal cleanup without dispatch.
            if self._process is not None and not self._process.running():
                self._browser_exit_verified = True
            if self._browser_exit_verified:
                self._close_task = None
                terminal_only = True
        if self._close_task is None:
            self._closed = True
            self._close_task = asyncio.create_task(self._close_impl(
                execution=execution, before_send=before_send, on_effects=on_effects,
                terminal_only=terminal_only))
        close_task = self._close_task
        try:
            await asyncio.shield(close_task)
        except WebClosePending:
            if self._close_task is close_task:
                self._closed = False
                self._close_task = None
            raise
        except Exception:
            if self.running:
                self._closed = False
            raise
