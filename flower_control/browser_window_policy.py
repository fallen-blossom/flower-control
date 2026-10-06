"""Bind a visible Brave HWND to its actual profile before App/Computer use."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import json
import os
from pathlib import Path
import tempfile
import threading

import pythoncom
import win32com.client

from flower_control.control.state import ControlError, StateStore
from flower_control.control.native import process_creation_filetime, process_identity


@dataclass(frozen=True)
class BrowserWindowAccess:
    target_scope: str | None = None
    shared_resource: str | None = None


class BrowserWindowPolicy:
    def __init__(self, store: StateStore | Path):
        self.directory = store.directory if isinstance(store, StateStore) else Path(store)
        self._store = store if isinstance(store, StateStore) else None
        self._profiles: dict[tuple[int, int], Path | None] = {}
        self._lock = threading.RLock()

    def _state_store(self) -> StateStore:
        with self._lock:
            if self._store is None:
                self._store = StateStore(self.directory)
            return self._store

    def _profile_for_process(self, pid: int) -> Path | None:
        identity = (pid, process_creation_filetime(pid))
        with self._lock:
            if identity in self._profiles:
                return self._profiles[identity]
        profile = self._profile_argument(pid)
        with self._lock:
            if len(self._profiles) >= 64:
                self._profiles.pop(next(iter(self._profiles)))
            self._profiles[identity] = profile
        return profile

    @staticmethod
    def _profile_argument(pid: int) -> Path | None:
        pythoncom.CoInitialize()
        try:
            service = win32com.client.GetObject("winmgmts:")
            rows = list(service.ExecQuery(
                f"SELECT CommandLine FROM Win32_Process WHERE ProcessId={pid}"))
            if len(rows) != 1 or not rows[0].CommandLine:
                raise ControlError("browser_identity_unverified")
            count = ctypes.c_int()
            shell32 = ctypes.windll.shell32
            shell32.CommandLineToArgvW.argtypes = [wintypes.LPCWSTR,
                                                   ctypes.POINTER(ctypes.c_int)]
            shell32.CommandLineToArgvW.restype = ctypes.POINTER(wintypes.LPWSTR)
            argv = shell32.CommandLineToArgvW(str(rows[0].CommandLine),
                                              ctypes.byref(count))
            if not argv:
                raise ControlError("browser_identity_unverified")
            try:
                args = [argv[index] for index in range(count.value)]
            finally:
                ctypes.windll.kernel32.LocalFree(ctypes.cast(argv, ctypes.c_void_p))
            profiles = [Path(arg[len("--user-data-dir="):]).resolve()
                        for arg in args if arg.lower().startswith("--user-data-dir=")]
            if len(profiles) > 1:
                raise ControlError("browser_identity_unverified")
            return profiles[0] if profiles else None
        finally:
            if "rows" in locals():
                rows.clear()
            if "service" in locals():
                del service
            pythoncom.CoUninitialize()

    @staticmethod
    def _marker(profile: Path, pid: int) -> dict:
        marker_path = profile / "flower-session.json"
        if marker_path.is_symlink() or os.path.isjunction(marker_path):
            raise ControlError("browser_identity_unverified")
        try:
            marker = json.loads(marker_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise ControlError("browser_identity_unverified") from error
        if (type(marker) is not dict or marker.get("state", "running") != "running"
                or marker.get("browser_pid") != pid
                or marker.get("browser_created") != process_identity(pid).split(":", 1)[1]):
            raise ControlError("browser_identity_unverified")
        return marker

    def inspect(self, task: str, pid: int, image: Path) -> BrowserWindowAccess:
        if image.name.lower() != "brave.exe":
            return BrowserWindowAccess()
        profile = self._profile_for_process(pid)
        if profile is None:
            return BrowserWindowAccess()  # Ordinary user Brave, selected explicitly.
        root = self.directory.parent.resolve()
        private = (root / "profiles" / "luohua-v1").resolve()
        ai = (root / "profiles" / "ai-v1").resolve()
        temp_root = Path(tempfile.gettempdir()).resolve()
        if profile == private:
            marker = self._marker(profile, pid)
            if marker.get("profile_kind") != "luohua" or marker.get("owner_task") != task:
                raise ControlError("browser_belongs_to_another_chat")
            store = self._state_store()
            with store.transaction() as db:
                store._task(db, task)
                store._require_scope(db, task, "flower-private:luohua")
            return BrowserWindowAccess("flower-private:luohua",
                                       "web-profile:luohua-v1")
        if profile == ai:
            marker = self._marker(profile, pid)
            if marker.get("profile_kind") != "ai" or marker.get("owner_task") != task:
                raise ControlError("browser_belongs_to_another_chat")
            return BrowserWindowAccess(shared_resource="web-profile:ai-v1")
        if profile.parent == temp_root and profile.name.startswith("flower-web-temp-"):
            marker = self._marker(profile, pid)
            if marker.get("owner_task") != task:
                raise ControlError("browser_belongs_to_another_chat")
            return BrowserWindowAccess(shared_resource=f"web-session:{marker['session_id']}")
        if profile == root / "profiles" or root / "profiles" in profile.parents:
            raise ControlError("browser_identity_unverified")
        return BrowserWindowAccess()
