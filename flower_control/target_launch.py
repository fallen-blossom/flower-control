"""Internal, fixture-only Windows launch receipts. Never a public MCP resolver.

Only this module's suspended CreateProcess -> Job -> identity verification path
can add a receipt to a manager. A PID, path or HWND supplied by a caller cannot.
The fixed fixture gate is intentional until trusted launch policy is reviewed.
"""
from __future__ import annotations

import ctypes
import hashlib
import os
import secrets
import subprocess
import threading
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path

import pythoncom
import win32api
import win32com.client
import win32con
import win32event
import win32gui
import win32job
import win32process

from flower_control.control.native import process_creation_filetime
from flower_control.drivers.computer_native import WindowIdentity, assert_window, bind_window


_ROOT = Path(__file__).resolve().parents[1]
_FIXTURE = (_ROOT / "tests" / "fixtures" / "launch_window_oracle.py").resolve()
_PYTHON = Path(os.path.realpath(os.sys._base_executable)).resolve()
_KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
_KERNEL32.QueryFullProcessImageNameW.argtypes = (
    wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD))
_KERNEL32.QueryFullProcessImageNameW.restype = wintypes.BOOL
_KERNEL32.GetProcessTimes.argtypes = (
    wintypes.HANDLE, ctypes.POINTER(wintypes.FILETIME),
    ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME),
    ctypes.POINTER(wintypes.FILETIME))
_KERNEL32.GetProcessTimes.restype = wintypes.BOOL
_USER32 = ctypes.WinDLL("user32", use_last_error=True)
_USER32.GetPropW.argtypes = [wintypes.HWND, wintypes.LPCWSTR]
_USER32.GetPropW.restype = wintypes.HANDLE
_PROTECTED = ("FlowerControlAuthorizationCard", "FlowerControlAuthorizationVerifier")


class LaunchError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(eq=False, frozen=True, slots=True)
class LaunchReceipt:
    """Opaque in-memory capability; equality is object identity."""
    task_id: str
    pid: int
    creation_filetime: int
    image: Path
    image_sha256: str
    argv: tuple[str, ...]
    cwd: Path
    nonce: str


def _filetime(handle: object) -> int:
    created, exited, kernel, user = (wintypes.FILETIME() for _ in range(4))
    if not _KERNEL32.GetProcessTimes(int(handle), ctypes.byref(created), ctypes.byref(exited),
                                    ctypes.byref(kernel), ctypes.byref(user)):
        raise ctypes.WinError(ctypes.get_last_error())
    return (created.dwHighDateTime << 32) | created.dwLowDateTime


def _image(handle: object) -> Path:
    buffer = ctypes.create_unicode_buffer(32768)
    length = wintypes.DWORD(len(buffer))
    if not _KERNEL32.QueryFullProcessImageNameW(int(handle), 0, buffer, ctypes.byref(length)):
        raise ctypes.WinError(ctypes.get_last_error())
    return Path(buffer.value).resolve(strict=True)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _actual_argv(pid: int) -> tuple[str, ...]:
    pythoncom.CoInitialize()
    try:
        service = win32com.client.GetObject("winmgmts:")
        rows = service.ExecQuery(f"SELECT CommandLine FROM Win32_Process WHERE ProcessId={pid}")
        commands = [row.CommandLine for row in rows]
        del rows, service
    finally:
        pythoncom.CoUninitialize()
    if len(commands) != 1 or type(commands[0]) is not str:
        raise LaunchError("launch_command_unavailable")
    return tuple(win32api.CommandLineToArgv(commands[0]))


class LaunchManager:
    """One-process-memory owner for fixed synthetic launches and window generations."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._owned: dict[LaunchReceipt, tuple[object, object]] = {}
        self._window: dict[LaunchReceipt, WindowIdentity] = {}

    def launch_fixture(self, *, trusted_task_id: str) -> LaunchReceipt:
        if type(trusted_task_id) is not str or not trusted_task_id.strip():
            raise LaunchError("trusted_task_required")
        if not _FIXTURE.is_file() or not _PYTHON.is_file():
            raise LaunchError("fixture_missing")
        nonce = secrets.token_hex(16)
        argv = (str(_PYTHON), "-B", str(_FIXTURE), "--launch-nonce", nonce)
        environment = {"SystemRoot": os.environ["SystemRoot"],
                       "WINDIR": os.environ["SystemRoot"],
                       "PATH": str(_PYTHON.parent), "PYTHONNOUSERSITE": "1"}
        job = win32job.CreateJobObject(None, "")
        limits = win32job.QueryInformationJobObject(job, win32job.JobObjectExtendedLimitInformation)
        limits["BasicLimitInformation"]["LimitFlags"] |= win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        win32job.SetInformationJobObject(job, win32job.JobObjectExtendedLimitInformation, limits)
        process = thread = None
        try:
            startup = win32process.STARTUPINFO()
            startup.dwFlags |= win32con.STARTF_USESHOWWINDOW
            startup.wShowWindow = win32con.SW_HIDE
            process, thread, pid, _ = win32process.CreateProcess(
                str(_PYTHON), subprocess.list2cmdline(argv), None, None, False,
                win32con.CREATE_SUSPENDED | win32con.CREATE_NO_WINDOW |
                win32con.CREATE_UNICODE_ENVIRONMENT, environment, str(_ROOT), startup)
            win32job.AssignProcessToJobObject(job, process)
            if _image(process) != _PYTHON or not win32job.IsProcessInJob(process, job):
                raise LaunchError("launch_process_unapproved")
            created = _filetime(process)
            if win32process.ResumeThread(thread) != 1:
                raise LaunchError("launch_resume_failed")
            if _actual_argv(pid) != argv:
                raise LaunchError("launch_command_changed")
            receipt = LaunchReceipt(trusted_task_id, pid, created, _PYTHON,
                                    _sha256(_PYTHON), argv, _ROOT, nonce)
            with self._lock:
                self._owned[receipt] = (process, job)
            process = job = None
            return receipt
        except BaseException:
            if process is not None:
                try:
                    win32process.TerminateProcess(process, 1)
                except Exception:
                    pass
            if job is not None:
                try:
                    win32job.TerminateJobObject(job, 1)
                except Exception:
                    pass
            raise
        finally:
            if thread is not None:
                thread.Close()
            if process is not None:
                process.Close()
            if job is not None:
                job.Close()

    def _require_live(self, receipt: LaunchReceipt, task_id: str) -> None:
        if type(receipt) is not LaunchReceipt or type(task_id) is not str:
            raise LaunchError("launch_receipt_unrecognized")
        owned = self._owned.get(receipt)
        if owned is None:
            raise LaunchError("launch_receipt_unrecognized")
        if receipt.task_id != task_id:
            raise LaunchError("launch_task_mismatch")
        process, job = owned
        try:
            if (win32event.WaitForSingleObject(process, 0) != win32event.WAIT_TIMEOUT or
                    not win32job.IsProcessInJob(process, job) or
                    _filetime(process) != receipt.creation_filetime or
                    process_creation_filetime(receipt.pid) != receipt.creation_filetime or
                    _image(process) != receipt.image or
                    _sha256(receipt.image) != receipt.image_sha256 or
                    _actual_argv(receipt.pid) != receipt.argv):
                raise LaunchError("launch_identity_changed")
        except LaunchError:
            raise
        except Exception as error:
            raise LaunchError("launch_identity_unavailable") from error

    def discover(self, receipt: LaunchReceipt, *, task_id: str) -> tuple[int, ...]:
        """Return only unbound exact-fixture HWND candidates; no content is read."""
        with self._lock:
            self._require_live(receipt, task_id)
            found: list[int] = []

            def collect(hwnd: int, _: object) -> None:
                if (win32gui.IsWindowVisible(hwnd) and
                        win32process.GetWindowThreadProcessId(hwnd)[1] == receipt.pid and
                        win32gui.GetClassName(hwnd) == "FlowerLaunchFixture_" + receipt.nonce and
                        win32gui.GetAncestor(hwnd, win32con.GA_ROOT) == hwnd):
                    found.append(hwnd)

            win32gui.EnumWindows(collect, None)
            self._require_live(receipt, task_id)
            return tuple(sorted(found))

    def bind(self, receipt: LaunchReceipt, hwnd: int, *, task_id: str) -> WindowIdentity:
        with self._lock:
            if type(hwnd) is not int or hwnd not in self.discover(receipt, task_id=task_id):
                raise LaunchError("launch_window_unapproved")
            if any(_USER32.GetPropW(hwnd, marker) for marker in _PROTECTED):
                raise LaunchError("protected_window")
            identity = bind_window(hwnd)
            if identity.pid != receipt.pid:
                raise LaunchError("launch_window_changed")
            self._require_live(receipt, task_id)
            assert_window(identity)
            self._window[receipt] = identity
            return identity

    def verify_window(self, receipt: LaunchReceipt, identity: WindowIdentity,
                      *, task_id: str) -> None:
        with self._lock:
            self._require_live(receipt, task_id)
            if self._window.get(receipt) != identity:
                raise LaunchError("launch_window_generation_changed")
            if identity.hwnd not in self.discover(receipt, task_id=task_id):
                raise LaunchError("launch_window_changed")
            if any(_USER32.GetPropW(identity.hwnd, marker) for marker in _PROTECTED):
                raise LaunchError("protected_window")
            try:
                assert_window(identity)
            except Exception as error:
                raise LaunchError("launch_window_changed") from error
            self._require_live(receipt, task_id)

    def revoke(self, receipt: LaunchReceipt) -> None:
        with self._lock:
            owned = self._owned.pop(receipt, None)
            self._window.pop(receipt, None)
        if owned is not None:
            process, job = owned
            try:
                win32job.TerminateJobObject(job, 1)
            finally:
                try:
                    process.Close()
                finally:
                    job.Close()

    def close(self) -> None:
        for receipt in tuple(self._owned):
            self.revoke(receipt)

    def __enter__(self) -> "LaunchManager":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
