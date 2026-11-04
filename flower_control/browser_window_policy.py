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

from flower_control.browsers import (is_supported_browser_image, browser_family,
                                    profile_resource_id, personal_profile_scope)
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
        if marker.get("login_only") is True:
            raise ControlError("browser_login_only")
        return marker

    def _shared_window(self, task, pid, image, hwnd, profile, marker, kind):
        if (type(hwnd) is not int or hwnd <= 0 or marker.get("profile_kind") != kind
                or marker.get("owner_process") is not None or marker.get("worker_process") is not None):
            raise ControlError("shared_browser_requires_exact_web_page")
        from flower_control.profile_registry import direct_path
        from flower_control.drivers.web_shared_profile import task_key, read_borrower, borrower_resource
        from flower_control.drivers.web_page_registry import native_window_binding
        from flower_control.drivers.computer_native import WindowIdentity, assert_window
        import win32gui
        import win32con
        path = direct_path(profile / "flower-shared" / marker["session_id"] / (task_key(task) + ".json"))
        row = read_borrower(path, browser_process=f"{pid}:{marker['browser_created']}",
                            browser_id=marker["session_id"], task=task)
        if row is None:
            raise ControlError("shared_browser_requires_exact_web_page")
        scope = personal_profile_scope(image) if kind == "luohua" else None
        store = self._state_store()
        from flower_control.drivers.web_shared_profile import require_profile_gate
        require_profile_gate(store, profile_resource_id(kind, image))
        with store.read_transaction() as db:
            store._task(db, task)
            store._require_scope(db, task, scope)
        matches = []
        for target_id, page in row["pages"].items():
            binding = native_window_binding(page.get("native_window"))
            if not page["owned"] or binding is None:
                continue
            identity = WindowIdentity(**binding["identity"])
            if identity.pid != pid or f"{pid}:{identity.process_created}" != row["browser_process"]:
                continue
            # Preserve the existing same-process direct native-dialog route.
            # A different chat's top-level window is never covered by this row.
            if hwnd != identity.hwnd and win32gui.GetWindow(hwnd, win32con.GW_OWNER) != identity.hwnd:
                continue
            assert_window(identity)
            matches.append((identity, target_id, binding))
        if len(matches) != 1:
            raise ControlError("shared_browser_requires_exact_web_page")
        identity, target_id, binding = matches[0]
        self._verify_shared_membership(profile, marker, image, target_id, binding)
        assert_window(identity)
        # No cached sidecar or CDP result authorizes a later consumer call.
        if read_borrower(path, browser_process=row["browser_process"],
                         browser_id=marker["session_id"], task=task) != row:
            raise ControlError("shared_window_binding_changed")
        return BrowserWindowAccess(scope, borrower_resource(profile, task))

    @staticmethod
    def _verify_shared_membership(profile, marker, image, target_id, binding):
        from flower_control.drivers.web_session import TemporaryWebSession
        from flower_control.drivers.cdp_window_probe import verify_window_membership
        pid = binding["identity"]["pid"]
        expected = f"{pid}:{binding['identity']['process_created']}"
        if process_identity(pid) != expected:
            raise ControlError("shared_window_process_unverified")
        # Read the existing exact endpoint. This object never starts, adopts,
        # reconnects or closes the user browser and acquires no profile lock.
        probe = TemporaryWebSession(brave_executable=image, guarded=True,
                                    persistent_profile=profile, user_open=True)
        probe.profile_path = profile
        endpoint = probe._verified_endpoint(marker)
        verify_window_membership(endpoint, target_id, binding["window_id"], pid)
        if process_identity(pid) != expected or probe._verified_endpoint(marker) != endpoint:
            raise ControlError("shared_window_process_unverified")

    def inspect(self, task: str, pid: int, image: Path, *, hwnd: int | None = None) -> BrowserWindowAccess:
        # Brave, Chrome and Edge share this profile/marker contract; any other
        # image is not a Flower-managed Chromium window.
        if not is_supported_browser_image(image):
            return BrowserWindowAccess()
        profile = self._profile_for_process(pid)
        if profile is None:
            return BrowserWindowAccess()  # Ordinary user Brave, selected explicitly.
        root = self.directory.parent.resolve()
        # A physical data root can differ from the original LOCALAPPDATA
        # spelling under a packaged host. Treat that known namespace as
        # managed even when this process cannot establish the browser's file
        # view. It must never become an ordinary-window authorization bypass.
        local = os.environ.get("LOCALAPPDATA")
        alias_root = ((Path(local) / "FlowerControl" / "profiles").resolve()
                      if local and Path(local).is_absolute() else None)
        managed_root = root / "profiles"
        if (alias_root is not None and alias_root != managed_root
                and (profile == alias_root or alias_root in profile.parents)):
            raise ControlError("browser_data_root_view_unverified")
        from flower_control.profile_registry import direct_path, profile_paths
        active = profile_paths(root)
        private = active["luohua"].resolve()
        ai = active["ai"].resolve()
        family = browser_family(image)
        browser_ai = direct_path(root / "profiles" / f"ai-{family}-v1").resolve() if family != "brave" else ai
        browser_private = direct_path(root / "profiles" / f"luohua-{family}-v1").resolve() if family != "brave" else private
        from flower_control.data_paths import runtime_temp_root
        temp_root = runtime_temp_root().resolve()
        if family != "brave" and profile in {private, (root / "profiles" / "luohua-v1").resolve()}:
            raise ControlError("browser_profile_browser_mismatch")
        if profile in {private, (root / "profiles" / "luohua-v1").resolve(), browser_private}:
            marker = self._marker(profile, pid)
            if marker.get("owner_kind") == "user" and marker.get("owner_task") is None:
                return self._shared_window(task, pid, image, hwnd, profile, marker, "luohua")
            if marker.get("profile_kind") != "luohua" or marker.get("owner_task") != task:
                raise ControlError("browser_belongs_to_another_chat")
            store = self._state_store()
            with store.transaction() as db:
                store._task(db, task)
                store._require_scope(db, task, personal_profile_scope(image))
            return BrowserWindowAccess(personal_profile_scope(image), profile_resource_id("luohua", image))
        if profile in {ai, (root / "profiles" / "ai-v1").resolve(), browser_ai}:
            marker = self._marker(profile, pid)
            if marker.get("owner_kind") == "user" and marker.get("owner_task") is None:
                return self._shared_window(task, pid, image, hwnd, profile, marker, "ai")
            if marker.get("profile_kind") != "ai" or marker.get("owner_task") != task:
                raise ControlError("browser_belongs_to_another_chat")
            # Old/selected Brave storage keeps its legacy shared resource.
            resource = (profile_resource_id("ai", image) if profile == browser_ai and family != "brave"
                        else "web-profile:ai-v1")
            return BrowserWindowAccess(shared_resource=resource)
        if profile.parent == temp_root and profile.name.startswith("flower-web-temp-"):
            marker = self._marker(profile, pid)
            if marker.get("owner_task") != task:
                raise ControlError("browser_belongs_to_another_chat")
            return BrowserWindowAccess(shared_resource=f"web-session:{marker['session_id']}")
        if profile == root / "profiles" or root / "profiles" in profile.parents:
            raise ControlError("browser_identity_unverified")
        return BrowserWindowAccess()
