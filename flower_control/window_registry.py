"""Short-lived ordinary Windows target selection for a verified chat.

This is a practical local picker, not a private-profile permission system.
Candidates are read-only until one listed window is selected. Each call still
checks the exact process/window generation before App or Computer acts.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import asdict, dataclass
from pathlib import Path
import secrets
import threading
import time
from typing import Callable

import win32con
import win32gui
import win32process

from flower_control.control.native import process_creation_filetime
from flower_control.control.state import ControlError
from flower_control.browser_window_policy import BrowserWindowAccess, BrowserWindowPolicy
from flower_control.drivers.computer_native import (NativeInputError, WindowIdentity, assert_window,
                                                    bind_window, is_owned_popup)
from flower_control.drivers.high_helper import HighHelperError
from flower_control.local_target import _process_image_and_liveness


_USER32 = ctypes.WinDLL("user32", use_last_error=True)
_USER32.GetPropW.argtypes = [wintypes.HWND, wintypes.LPCWSTR]
_USER32.GetPropW.restype = wintypes.HANDLE
_PROTECTED_PROPS = ("FlowerControlResumePrompt", "FlowerControlTaskIndicator")
_EXCLUDED_IMAGES = {"credentialuibroker.exe", "consent.exe",
                    "logonui.exe"}
_MAX_CANDIDATES = 64
_OMISSION_REASONS = ("not_visible_or_root", "protected_flower_window", "protected_system_process",
                     "browser_scope_unavailable", "empty_title", "process_or_bounds_unavailable",
                     "window_probe_failed")


class WindowSelectionError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class _Candidate:
    hwnd: int
    pid: int
    created: int
    title: str
    image: Path
    access: BrowserWindowAccess
    expires: float


@dataclass(frozen=True)
class WindowBindingRequest:
    """Exact, local selection data for the admitted helper binding adapter."""

    task: str
    hwnd: int
    pid: int
    created: int
    image: Path
    access: BrowserWindowAccess
    expires_at: float


WindowBinder = Callable[[WindowBindingRequest, Callable[[], bool]], WindowIdentity]


def _omit_window(diagnostics: dict | None, reason: str, *, probe_failed: bool = False):
    if diagnostics is not None:
        diagnostics["omission_counts"][reason] += 1
        if probe_failed:
            diagnostics["probe_failed_count"] += 1
    return None


def _ordinary_window(hwnd: int, *, task: str, policy: BrowserWindowPolicy | None,
                     require_title: bool = True,
                     diagnostics: dict | None = None) -> tuple[int, Path, str, BrowserWindowAccess] | None:
    failure_reason = "window_probe_failed"
    try:
        if (not win32gui.IsWindow(hwnd) or not win32gui.IsWindowVisible(hwnd)
                or win32gui.GetAncestor(hwnd, win32con.GA_ROOT) != hwnd):
            return _omit_window(diagnostics, "not_visible_or_root")
        if any(_USER32.GetPropW(hwnd, marker) for marker in _PROTECTED_PROPS):
            return _omit_window(diagnostics, "protected_flower_window")
        pid = win32process.GetWindowThreadProcessId(hwnd)[1]
        if not pid:
            return _omit_window(diagnostics, "process_or_bounds_unavailable")
        failure_reason = "process_or_bounds_unavailable"
        image = _process_image_and_liveness(pid)
        if image.name.lower() in _EXCLUDED_IMAGES:
            return _omit_window(diagnostics, "protected_system_process")
        if image.name.lower() == "brave.exe" and policy is None:
            return _omit_window(diagnostics, "browser_scope_unavailable")
        failure_reason = "browser_scope_unavailable"
        access = (policy.inspect(task, pid, image) if policy is not None
                  else BrowserWindowAccess())
        failure_reason = "window_probe_failed"
        title = win32gui.GetWindowText(hwnd).strip()
        if require_title and not title:
            return _omit_window(diagnostics, "empty_title")
        return pid, image, title[:160], access
    except Exception:
        return _omit_window(diagnostics, failure_reason, probe_failed=True)


def _owned_chain(parent: WindowIdentity, hwnd: int, *, task: str,
                 policy: BrowserWindowPolicy | None, stopped=None) -> bool:
    """Accept only a visible, same-process owner chain rooted at selection."""
    seen: set[int] = set()
    for _ in range(8):
        if stopped is not None and stopped():
            raise WindowSelectionError("window_selection_cancelled")
        if hwnd == parent.hwnd:
            return True
        if hwnd in seen or _ordinary_window(hwnd, task=task, policy=policy,
                                            require_title=False) is None:
            return False
        if stopped is not None and stopped():
            raise WindowSelectionError("window_selection_cancelled")
        seen.add(hwnd)
        try:
            if win32process.GetWindowThreadProcessId(hwnd)[1] != parent.pid:
                return False
            hwnd = win32gui.GetWindow(hwnd, win32con.GW_OWNER)
        except Exception:
            return False
    return False


class WindowRegistry:
    """Each MCP process owns its own short candidate and selected task map."""

    def __init__(self, browser_policy: BrowserWindowPolicy | None = None, *,
                 window_binder: WindowBinder | None = None) -> None:
        if window_binder is not None and not callable(window_binder):
            raise TypeError("window binder must be callable")
        self._lock = threading.RLock()
        self._browser_policy = browser_policy
        self._window_binder = window_binder
        self._candidates: dict[str, dict[str, _Candidate]] = {}
        self._selected: dict[str, WindowIdentity] = {}
        self._selection_versions: dict[str, int] = {}

    def list_windows(self, task: str, *, include_diagnostics: bool = False,
                     include_untitled: bool = False, stopped=None) -> list[dict] | dict:
        """One enumeration; diagnostic counts never identify excluded windows."""
        if type(task) is not str or not task:
            raise WindowSelectionError("trusted_task_required")
        if type(include_diagnostics) is not bool or type(include_untitled) is not bool:
            raise WindowSelectionError("invalid_window_listing_options")
        def check_stop():
            if stopped is not None and stopped():
                raise WindowSelectionError("window_listing_cancelled")
        check_stop()
        found: list[dict] = []
        candidates: dict[str, _Candidate] = {}
        now = time.monotonic()
        diagnostics = ({"windows": found, "returned_count": 0, "limit": _MAX_CANDIDATES,
                        "truncated": False, "uninspected_after_limit": 0,
                        "omission_counts": {reason: 0 for reason in _OMISSION_REASONS},
                        "probe_failed_count": 0, "enumeration_complete": True,
                        "enumeration_error": None} if include_diagnostics else None)
        ordinary_options = {}
        if include_untitled:
            ordinary_options["require_title"] = False
        if diagnostics is not None:
            ordinary_options["diagnostics"] = diagnostics

        def collect(hwnd: int, _: object) -> None:
            check_stop()
            if len(found) >= _MAX_CANDIDATES:
                if diagnostics is not None:
                    diagnostics["uninspected_after_limit"] += 1
                return
            ordinary = _ordinary_window(hwnd, task=task, policy=self._browser_policy,
                                        **ordinary_options)
            check_stop()
            if ordinary is None:
                return
            pid, image, title, access = ordinary
            try:
                created = process_creation_filetime(pid)
                bounds = win32gui.GetWindowRect(hwnd)
            except Exception:
                _omit_window(diagnostics, "process_or_bounds_unavailable", probe_failed=True)
                return
            if diagnostics is not None:
                try:
                    minimized = bool(win32gui.IsIconic(hwnd))
                except Exception:
                    _omit_window(diagnostics, "window_probe_failed", probe_failed=True)
                    return
            else:
                # Preserve the legacy list's exception behavior for this probe.
                minimized = bool(win32gui.IsIconic(hwnd))
            token = secrets.token_urlsafe(16)
            candidates[token] = _Candidate(hwnd, pid, created, title, image, access,
                                           now + 30)
            entry = {"candidate_id": token, "title": title,
                     "process": image.name, "pid": pid,
                     "minimized": minimized, "bounds": list(bounds)}
            if include_untitled:
                entry["title_empty"] = not title
            found.append(entry)

        try:
            win32gui.EnumWindows(collect, None)
        except Exception:
            check_stop()
            if diagnostics is None:
                raise
            diagnostics["enumeration_complete"] = False
            diagnostics["enumeration_error"] = "enumeration_interrupted"
            diagnostics["probe_failed_count"] += 1
        with self._lock:
            check_stop()
            self._candidates[task] = candidates
        if diagnostics is not None:
            diagnostics["returned_count"] = len(found)
            diagnostics["truncated"] = diagnostics["uninspected_after_limit"] > 0
            return diagnostics
        return found

    def select(self, task: str, candidate_id: str, *, stopped=None) -> WindowIdentity:
        return self._select_candidate(task, candidate_id, replacement=False, stopped=stopped)

    def adopt_handoff(self, task: str, identity: WindowIdentity, *, stopped=None) -> WindowIdentity:
        """Internal only: recheck an exact same-chat ledger handoff."""
        assert_window(identity)
        if _ordinary_window(identity.hwnd, task=task, policy=self._browser_policy,
                            require_title=False) is None:
            raise WindowSelectionError("handoff_target_unavailable")
        with self._lock:
            if stopped is not None and stopped():
                raise WindowSelectionError("window_selection_cancelled")
            self._selection_versions[task] = self._selection_versions.get(task, 0) + 1
            self._selected[task] = identity
        return identity

    def select_replacement(self, task: str, candidate_id: str, *, stopped=None) -> WindowIdentity:
        """Explicitly bind a newly listed HWND in the selected process instance.

        A window rebuild invalidates the old HWND and its content grant. The
        caller must present a fresh candidate and authorize the new target.
        This never searches for or silently selects a likely replacement.
        """
        return self._select_candidate(task, candidate_id, replacement=True, stopped=stopped)

    def _select_candidate(self, task: str, candidate_id: str, *,
                          replacement: bool, stopped=None) -> WindowIdentity:
        if type(candidate_id) is not str:
            raise WindowSelectionError("candidate_not_found")
        with self._lock:
            candidate = self._candidates.get(task, {}).pop(candidate_id, None)
            previous = self._selected.get(task)
            version = self._selection_versions.get(task, 0) + 1
            if candidate is not None:
                self._selection_versions[task] = version
        if candidate is None or candidate.expires <= time.monotonic():
            raise WindowSelectionError("candidate_not_found")
        if replacement and (previous is None or candidate.pid != previous.pid or
                            process_creation_filetime(candidate.pid) != candidate.created):
            raise WindowSelectionError("replacement_process_changed")
        def current():
            if stopped is not None and stopped():
                return False
            with self._lock:
                if self._selection_versions.get(task) != version:
                    return False
            return self._candidate_current(task, candidate)

        if not current():
            raise WindowSelectionError("candidate_changed")
        try:
            identity = self._bind_candidate(task, candidate, current)
            if not current():
                raise WindowSelectionError("candidate_changed")
        except WindowSelectionError:
            raise
        except (ControlError, HighHelperError) as error:
            raise WindowSelectionError(error.code) from error
        except NativeInputError as error:
            if error.code in {"window_identity_access_denied", "window_identity_property_unavailable"}:
                raise WindowSelectionError(error.code) from error
            raise WindowSelectionError("candidate_changed") from error
        except Exception as error:
            raise WindowSelectionError("candidate_changed") from error
        if replacement and (identity.process_created != previous.process_created or
                            identity.hwnd == previous.hwnd):
            raise WindowSelectionError("replacement_process_changed")
        with self._lock:
            if stopped is not None and stopped():
                raise WindowSelectionError("window_selection_cancelled")
            if self._selection_versions.get(task) != version:
                raise WindowSelectionError("candidate_changed")
            self._selected[task] = identity
            self._candidates.pop(task, None)
        return identity

    def _candidate_current(self, task: str, candidate: _Candidate) -> bool:
        try:
            if candidate.expires <= time.monotonic():
                return False
            ordinary = _ordinary_window(candidate.hwnd, task=task, policy=self._browser_policy,
                                        require_title=False)
            return (ordinary is not None and (ordinary[0], ordinary[1], ordinary[3]) ==
                    (candidate.pid, candidate.image, candidate.access) and
                    process_creation_filetime(candidate.pid) == candidate.created)
        except Exception:
            return False

    def _bind_candidate(self, task: str, candidate: _Candidate,
                        current: Callable[[], bool]) -> WindowIdentity:
        if not current():
            raise WindowSelectionError("candidate_changed")
        request = WindowBindingRequest(task, candidate.hwnd, candidate.pid,
                                       candidate.created, candidate.image, candidate.access,
                                       candidate.expires)
        identity = (bind_window(candidate.hwnd) if self._window_binder is None
                    else self._window_binder(request, current))
        if not current():
            raise WindowSelectionError("candidate_changed")
        if (not isinstance(identity, WindowIdentity) or
                (identity.hwnd, identity.pid) != (candidate.hwnd, candidate.pid)):
            raise WindowSelectionError("candidate_changed")
        assert_window(identity)
        if process_creation_filetime(identity.pid, expected_iso=identity.process_created) != candidate.created:
            raise WindowSelectionError("candidate_changed")
        return identity

    def bind_owned_window(self, task: str, parent: WindowIdentity, hwnd: int, *,
                          stopped=None) -> WindowIdentity:
        """Bind only a fresh direct popup of this chat's exact approved parent."""
        if self.resolve(task, asdict(parent), stopped=stopped) != parent or not is_owned_popup(parent, hwnd):
            raise WindowSelectionError("selected_window_unavailable")
        if stopped is not None and stopped():
            raise WindowSelectionError("window_selection_cancelled")
        ordinary = _ordinary_window(hwnd, task=task, policy=self._browser_policy,
                                    require_title=False)
        if stopped is not None and stopped():
            raise WindowSelectionError("window_selection_cancelled")
        if ordinary is None or ordinary[0] != parent.pid:
            raise WindowSelectionError("selected_window_unavailable")
        candidate = _Candidate(hwnd, ordinary[0], process_creation_filetime(ordinary[0]),
                               ordinary[2], ordinary[1], ordinary[3], time.monotonic() + 30)

        def current():
            if stopped is not None and stopped():
                return False
            try:
                valid = (self.resolve(task, asdict(parent), stopped=stopped) == parent and
                         is_owned_popup(parent, hwnd) and self._candidate_current(task, candidate))
                return valid and not (stopped is not None and stopped())
            except Exception:
                return False

        identity = self._bind_candidate(task, candidate, current)
        if not current() or identity.process_created != parent.process_created:
            raise WindowSelectionError("candidate_changed")
        return identity

    def list_owned_windows(self, task: str, target: object | None = None, *,
                           stopped=None) -> list[dict]:
        """Return exact identities for visible, direct owned windows only."""
        def check_stop():
            if stopped is not None and stopped():
                raise WindowSelectionError("window_listing_cancelled")
        check_stop()
        parent = self.resolve(task, target, stopped=stopped)
        found: list[dict] = []

        def collect(hwnd: int, _: object) -> None:
            check_stop()
            if len(found) >= 16 or not is_owned_popup(parent, hwnd):
                return
            check_stop()
            ordinary = _ordinary_window(hwnd, task=task, policy=self._browser_policy,
                                        require_title=False)
            check_stop()
            if ordinary is None:
                return
            try:
                identity = self.bind_owned_window(task, parent, hwnd, stopped=stopped)
            except Exception:
                check_stop()
                return
            check_stop()
            if (identity.pid, identity.process_created) != (parent.pid, parent.process_created):
                return
            enabled = bool(win32gui.IsWindowEnabled(hwnd))
            check_stop()
            found.append({"target": asdict(identity), "title": ordinary[2], "enabled": enabled})

        try:
            win32gui.EnumWindows(collect, None)
        except Exception:
            check_stop()
            raise
        check_stop()
        return found

    def resolve(self, task: str, target: object | None = None, *, stopped=None) -> WindowIdentity:
        def check_stop():
            if stopped is not None and stopped():
                raise WindowSelectionError("window_selection_cancelled")
        check_stop()
        with self._lock:
            selected = self._selected.get(task)
        if selected is None:
            raise WindowSelectionError("target_not_selected")
        try:
            assert_window(selected)
            check_stop()
            if _ordinary_window(selected.hwnd, task=task, policy=self._browser_policy,
                                require_title=False) is None:
                raise WindowSelectionError("selected_window_unavailable")
            check_stop()
            if target is None or target == asdict(selected):
                return selected
            if type(target) is not dict:
                raise WindowSelectionError("target_not_selected")
            requested = WindowIdentity(**target)
            assert_window(requested)
            check_stop()
            if (requested.pid == selected.pid and
                    requested.process_created == selected.process_created and
                    requested.hwnd != selected.hwnd and
                    _owned_chain(selected, requested.hwnd, task=task,
                                 policy=self._browser_policy, stopped=stopped)):
                check_stop()
                return requested
        except WindowSelectionError:
            raise
        except Exception as error:
            raise WindowSelectionError("selected_window_unavailable") from error
        raise WindowSelectionError("target_not_selected")

    def selected_root(self, task: str) -> WindowIdentity:
        """Return the still-live selected parent after an owned dialog closes."""
        return self.resolve(task)

    def access(self, task: str, target: object | None = None, *, stopped=None) -> BrowserWindowAccess:
        identity = self.resolve(task, target, stopped=stopped)
        ordinary = _ordinary_window(identity.hwnd, task=task,
                                    policy=self._browser_policy, require_title=False)
        if stopped is not None and stopped():
            raise WindowSelectionError("window_selection_cancelled")
        if ordinary is None:
            raise WindowSelectionError("selected_window_unavailable")
        return ordinary[3]
