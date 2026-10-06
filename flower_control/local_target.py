"""Opt-in, exact synthetic-window binding for local stdio trials.

This is deliberately not a general desktop classifier.  A local test launcher
may pass one process/window identity through the inherited environment.  MCP
arguments can only refer to that identity; they cannot register a target.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
from ctypes import wintypes
from dataclasses import asdict, dataclass
from pathlib import Path

import win32api
import win32con
import win32event
import win32gui
import win32process
import pythoncom
import win32com.client

from flower_control.control.native import process_creation_filetime
from flower_control.drivers.computer_native import WindowIdentity, assert_window


ENV_NAME = "FLOWER_CONTROL_FIXTURE_TARGET_V1"
ROOT = Path(__file__).resolve().parents[1]
APP_FIXTURE = (ROOT / "tests/fixtures/app-wpf/bin/Debug/"
               "net10.0-windows10.0.19041.0/win-x64/Flower.AppFixture.exe")
COMPUTER_FIXTURE = ROOT / "tests/fixtures/computer_oracle.py"
_KIND_TITLE = {"app_wpf": "Flower App Semantic Fixture",
               "computer_tk": "Flower Computer MCP Fixture"}
_CARD_PROP = "FlowerControlAuthorizationCard"


class LocalTargetError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_kernel32.QueryFullProcessImageNameW.argtypes = (
    wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD))
_kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL


def _process_image_and_liveness(pid: int) -> Path:
    process = win32api.OpenProcess(win32con.PROCESS_QUERY_LIMITED_INFORMATION |
                                  win32con.SYNCHRONIZE, False, pid)
    try:
        if win32event.WaitForSingleObject(process, 0) != win32event.WAIT_TIMEOUT:
            raise LocalTargetError("target_process_exited")
        buffer = ctypes.create_unicode_buffer(32768)
        length = wintypes.DWORD(len(buffer))
        if not _kernel32.QueryFullProcessImageNameW(int(process), 0, buffer,
                                                    ctypes.byref(length)):
            raise LocalTargetError("target_image_unavailable")
        return Path(buffer.value).resolve(strict=True)
    finally:
        process.Close()


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _exact_tk_fixture_process(pid: int) -> bool:
    """Use the actual process command line, never an MCP supplied classification."""
    pythoncom.CoInitialize()
    try:
        rows = win32com.client.GetObject("winmgmts:").ExecQuery(
            f"SELECT CommandLine FROM Win32_Process WHERE ProcessId={pid}")
        commands = [row.CommandLine for row in rows]
    finally:
        pythoncom.CoUninitialize()
    if len(commands) != 1 or type(commands[0]) is not str:
        return False
    parts = win32api.CommandLineToArgv(commands[0])
    if len(parts) != 11:
        return False
    try:
        return (Path(parts[0]).resolve(strict=True) ==
                Path(os.path.realpath(os.sys._base_executable)).resolve(strict=True)
                and parts[1] == "-B"
                and Path(parts[2]).resolve(strict=True) == COMPUTER_FIXTURE.resolve(strict=True)
                and parts[3] == "--state" and Path(parts[4]).is_absolute()
                and parts[5:] == ["--title", _KIND_TITLE["computer_tk"],
                                  "--width", "760", "--height", "560"])
    except Exception:
        return False


def _card_marker(hwnd: int) -> bool:
    """Reject the authorization card even if a caller supplies its child HWND."""
    try:
        root = win32gui.GetAncestor(hwnd, win32con.GA_ROOT)
        if not root:
            return False
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        user32.GetPropW.argtypes = [wintypes.HWND, wintypes.LPCWSTR]
        user32.GetPropW.restype = wintypes.HANDLE
        return int(user32.GetPropW(root, _CARD_PROP) or 0) == 1
    except Exception:
        return False


@dataclass(frozen=True)
class FixtureTarget:
    kind: str
    pid: int
    hwnd: int
    process_start_filetime: int
    image_sha256: str
    process_created: str
    window_nonce: int

    @classmethod
    def from_environment(cls, expected_kind: str) -> "FixtureTarget | None":
        raw = os.environ.get(ENV_NAME)
        if raw is None:
            return None
        try:
            document = json.loads(raw)
            if type(document) is not dict or document.get("kind") != expected_kind:
                raise ValueError("kind")
            required = {"kind", "pid", "hwnd", "process_start_filetime",
                        "image_sha256"}
            if set(document) != required | {"process_created", "window_nonce"}:
                raise ValueError("fields")
            if any(type(document[key]) is not int or document[key] <= 0
                   for key in ("pid", "hwnd", "process_start_filetime")):
                raise ValueError("identity")
            digest = document["image_sha256"]
            if type(digest) is not str or len(digest) != 64 or any(
                    char not in "0123456789abcdef" for char in digest):
                raise ValueError("digest")
            WindowIdentity(document["hwnd"], document["pid"],
                           document["process_created"], document["window_nonce"])
            return cls(**document)
        except (TypeError, ValueError, KeyError) as error:
            raise LocalTargetError("fixture_registration_invalid") from error

    def target(self) -> dict:
        if self.kind == "app_wpf":
            return {"pid": self.pid, "hwnd": self.hwnd,
                    "process_start_filetime": self.process_start_filetime}
        return asdict(WindowIdentity(self.hwnd, self.pid,
                                     self.process_created, self.window_nonce))

    def verify(self, supplied_target: object | None = None) -> None:
        if supplied_target is not None and (type(supplied_target) is not dict or
                                            supplied_target != self.target()):
            raise LocalTargetError("target_not_registered")
        try:
            if _card_marker(self.hwnd):
                raise LocalTargetError("authorization_card_protected")
            if process_creation_filetime(self.pid) != self.process_start_filetime:
                raise LocalTargetError("target_process_changed")
            image = _process_image_and_liveness(self.pid)
            expected_image = (APP_FIXTURE if self.kind == "app_wpf" else
                              Path(os.path.realpath(os.sys._base_executable)))
            if image != expected_image.resolve(strict=True):
                raise LocalTargetError("target_process_unapproved")
            if _digest(image) != self.image_sha256:
                raise LocalTargetError("target_image_changed")
            if self.kind == "computer_tk" and not _exact_tk_fixture_process(self.pid):
                raise LocalTargetError("target_process_unapproved")
            if (not win32gui.IsWindow(self.hwnd) or
                    win32process.GetWindowThreadProcessId(self.hwnd)[1] != self.pid or
                    win32gui.GetAncestor(self.hwnd, win32con.GA_ROOT) != self.hwnd or
                    not win32gui.IsWindowVisible(self.hwnd) or
                    win32gui.GetWindowText(self.hwnd) != _KIND_TITLE[self.kind]):
                raise LocalTargetError("target_window_changed")
            assert_window(WindowIdentity(self.hwnd, self.pid,
                                         self.process_created, self.window_nonce))
            if self.kind == "computer_tk":
                # The trusted test launcher, not MCP, must identify the Tk script.
                if not COMPUTER_FIXTURE.is_file():
                    raise LocalTargetError("fixture_source_missing")
        except LocalTargetError:
            raise
        except Exception as error:
            raise LocalTargetError("target_identity_unavailable") from error
