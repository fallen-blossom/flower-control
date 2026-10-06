"""Client for the fixed global broker. No import or client call starts High."""
from __future__ import annotations

from contextlib import ExitStack
import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
from types import MappingProxyType
import secrets
import threading
import time

import pywintypes
import win32api
import win32con
import win32event
import win32file
import win32pipe
import win32process
import win32security

from flower_control.control.native import (FOREGROUND_INPUT_RESOURCE,
    physical_window_resource, process_creation_filetime, process_is_alive)
from flower_control.drivers.computer_native import WindowIdentity

_LIMIT = 2 * 1024 * 1024
_SEAL = object()
_BUNDLE_NAMES = ("Flower.HighHelper.exe", "Flower.HighHelper.dll",
                 "Flower.HighHelper.deps.json", "Flower.HighHelper.runtimeconfig.json")


def _peer_evidence_shape(evidence):
    names = {"Pid", "Created", "Session", "Source", "Channel", "ProductionAdmitted",
             "LauncherPid", "LauncherCreated", "CodexPid"}
    if type(evidence) is not dict:
        return False
    return set(evidence) == (names | {"HostPid"} if evidence.get("Source") in {"claude-code-flower", "antigravity-flower", "local-mcp-flower"} else names)


def _production_host_evidence(evidence):
    if not _peer_evidence_shape(evidence) or evidence.get("ProductionAdmitted") is not True:
        return False
    source = evidence.get("Source")
    if source == "codex-flower":
        pid = evidence.get("CodexPid")
    elif source in {"claude-code-flower", "antigravity-flower", "local-mcp-flower"} and evidence.get("CodexPid") is None:
        pid = evidence.get("HostPid")
    else:
        return False
    return type(pid) is int and pid > 0


_KERNEL = ctypes.WinDLL("kernel32", use_last_error=True)
_KERNEL.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                            ctypes.POINTER(wintypes.DWORD)]
_KERNEL.QueryFullProcessImageNameW.restype = wintypes.BOOL
_KERNEL.GetProcessId.argtypes = [wintypes.HANDLE]
_KERNEL.GetProcessId.restype = wintypes.DWORD
_USER32 = ctypes.WinDLL("user32", use_last_error=True)
_USER32.SetThreadDpiAwarenessContext.argtypes = [ctypes.c_void_p]
_USER32.SetThreadDpiAwarenessContext.restype = ctypes.c_void_p
_USER32.GetDpiForWindow.argtypes = [wintypes.HWND]
_USER32.GetDpiForWindow.restype = wintypes.UINT


def _physical_bounds(hwnd):
    import win32gui
    previous = _USER32.SetThreadDpiAwarenessContext(ctypes.c_void_p(-4))
    if not previous:
        raise HighHelperError("physical_dpi_required")
    try:
        return tuple(win32gui.GetWindowRect(hwnd))
    finally:
        _USER32.SetThreadDpiAwarenessContext(previous)


class HighHelperError(RuntimeError):
    def __init__(self, code, *, details=None):
        super().__init__(code)
        self.code, self.details = code, details or {}


class ReleaseRecovery:
    """Private authenticated terminal metadata, never a caller-supplied token."""
    def __init__(self, seal, session, expected, result):
        if seal is not _SEAL:
            raise HighHelperError("release_recovery_rejected")
        self._seal, self._session = seal, session
        self._deadline = time.monotonic() + 3
        self.task_id, self.action_id, self.executor_process, self.ledger_identity = expected
        names = {"Phase", "TaskId", "ActionId", "ExecutorProcess", "LedgerIdentity", "State", "InputRelease",
                 "MutexReleased", "SemanticExecutorExited", "NativeCountKnown"}
        if (type(result) is not dict or set(result) not in (names, names | {"PhysicalInputFree"})
                or "PhysicalInputFree" in result and result["PhysicalInputFree"] is not True
                or result["Phase"] != "release_recovery"
                or tuple(result[k] for k in ("TaskId", "ActionId", "ExecutorProcess", "LedgerIdentity")) != expected
                or result["State"] != "finished" or result["InputRelease"] != "released"
                or result["MutexReleased"] is not True or result["NativeCountKnown"] is not True
                or result["SemanticExecutorExited"] is not None and type(result["SemanticExecutorExited"]) is not bool
                or result["SemanticExecutorExited"] is False and result.get("PhysicalInputFree") is not True):
            raise HighHelperError("release_recovery_unconfirmed")

    def verify(self):
        session = self._session
        if self._seal is not _SEAL or time.monotonic() >= self._deadline or session._closed:
            raise HighHelperError("release_recovery_expired")
        bundle = session.client.bundle
        if bundle is None:
            raise HighHelperError("release_recovery_peer_changed")
        bundle.verify()
        if (win32pipe.GetNamedPipeServerProcessId(session._pipe.handle) != session._helper["Pid"]
                or _process(session._helper["Pid"], expected_image=str(bundle.directory / _BUNDLE_NAMES[0]))[0] != session._helper
                or session._evidence.get("ProductionAdmitted") is not True and not session.client.medium_fixture):
            raise HighHelperError("release_recovery_peer_changed")


def _digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _process(pid, *, digest_cache=None, expected_image=None):
    handle = win32api.OpenProcess(win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    try:
        iso = win32process.GetProcessTimes(handle)["CreationTime"].isoformat()
        image = ctypes.create_unicode_buffer(2048)
        size = wintypes.DWORD(2048)
        if not _KERNEL.QueryFullProcessImageNameW(int(handle), 0, image, ctypes.byref(size)):
            raise HighHelperError("image_unavailable")
        if expected_image is not None and os.path.normcase(os.path.abspath(image.value)) != os.path.normcase(os.path.abspath(expected_image)):
            raise HighHelperError("helper_image_path_mismatch")
        token = win32security.OpenProcessToken(handle, win32con.TOKEN_QUERY)
        try:
            level = win32security.GetTokenInformation(token, win32security.TokenIntegrityLevel)
            sid = level[0] if isinstance(level, tuple) else level
            integrity = int(win32security.ConvertSidToStringSid(sid).rsplit("-", 1)[1])
            user = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
            session = win32security.GetTokenInformation(token, win32security.TokenSessionId)
        finally:
            token.Close()
        created = process_creation_filetime(pid, expected_iso=iso)
        cache_key = (pid, created, image.value)
        if digest_cache is None:
            digest = _digest(image.value)
        else:
            if cache_key not in digest_cache:
                digest_cache[cache_key] = _digest(image.value)
            digest = digest_cache[cache_key]
        return {"Pid": pid, "Created": created,
                "Session": session, "User": win32security.ConvertSidToStringSid(user),
                "ImageDigest": digest, "Integrity": integrity}, iso
    finally:
        handle.Close()


@dataclass(frozen=True)
class HelperBundle:
    directory: Path
    hashes: tuple[tuple[str, str], ...]

    @classmethod
    def snapshot(cls, directory):
        directory = Path(directory)
        if directory.is_symlink() or directory.is_junction():
            raise HighHelperError("bundle_rejected")
        directory = directory.resolve(strict=True)
        bundle = cls(directory, tuple((name, _digest(directory / name)) for name in _BUNDLE_NAMES))
        bundle.verify()
        return bundle

    def verify(self):
        if tuple(name for name, _ in self.hashes) != _BUNDLE_NAMES:
            raise HighHelperError("bundle_rejected")
        if self.directory.is_symlink() or self.directory.is_junction():
            raise HighHelperError("bundle_rejected")
        for name, expected in self.hashes:
            path = self.directory / name
            if path.is_symlink() or not path.is_file() or _digest(path) != expected:
                raise HighHelperError("bundle_changed")


@dataclass(frozen=True)
class HighTarget:
    facts: dict
    process_created: str
    hwnd: int
    bounds: tuple[int, int, int, int]
    nonce: int = 0
    broker_revision: int = 0
    client_rect: tuple[int, int, int, int] | None = None
    client_origin: tuple[int, int] | None = None
    window_dpi: int | None = None

    def __post_init__(self):
        facts = dict(self.facts)
        import re
        if (set(facts) != {"Pid", "Created", "Session", "User", "ImageDigest", "Integrity"}
                or any(type(facts[name]) is not int or facts[name] <= 0 for name in ("Pid", "Created", "Integrity"))
                or type(facts["Session"]) is not int or facts["Session"] < 0
                or type(facts["User"]) is not str or not facts["User"] or len(facts["User"]) > 184
                or type(facts["ImageDigest"]) is not str or re.fullmatch("[a-f0-9]{64}", facts["ImageDigest"]) is None
                or type(self.process_created) is not str or not self.process_created or len(self.process_created) > 128
                or type(self.hwnd) is not int or self.hwnd <= 0 or type(self.nonce) is not int or not 0 <= self.nonce < 1 << 63
                or len(self.bounds) != 4 or any(type(value) is not int for value in self.bounds)
                or self.bounds[0] >= self.bounds[2] or self.bounds[1] >= self.bounds[3]):
            raise HighHelperError("target_rejected")
        object.__setattr__(self, "facts", MappingProxyType(facts))
        object.__setattr__(self, "bounds", tuple(self.bounds))

        if type(self.broker_revision) is not int or self.broker_revision < 0:
            raise HighHelperError("desktop_revision_rejected")
        geometry = (self.client_rect, self.client_origin, self.window_dpi)
        if any(value is not None for value in geometry):
            if (self.client_rect is None or len(self.client_rect) != 4 or self.client_origin is None
                    or len(self.client_origin) != 2 or any(type(v) is not int for v in (*self.client_rect, *self.client_origin))
                    or type(self.window_dpi) is not int or not 1 <= self.window_dpi <= 1536):
                raise HighHelperError("client_geometry_rejected")
            object.__setattr__(self, "client_rect", tuple(self.client_rect))
            object.__setattr__(self, "client_origin", tuple(self.client_origin))

    @classmethod
    def inspect(cls, hwnd, pid, *, nonce=0, broker_revision=0):
        # Target routing still needs the caller's existing BrowserPolicy/grant.
        import win32gui
        if type(hwnd) is not int or type(pid) is not int or hwnd <= 0 or pid <= 0:
            raise HighHelperError("target_rejected")
        if win32process.GetWindowThreadProcessId(hwnd)[1] != pid:
            raise HighHelperError("target_identity_changed")
        facts, iso = _process(pid)
        previous = _USER32.SetThreadDpiAwarenessContext(ctypes.c_void_p(-4))
        if not previous:
            raise HighHelperError("physical_dpi_required")
        try:
            bounds = tuple(win32gui.GetWindowRect(hwnd))
            rect = tuple(win32gui.GetClientRect(hwnd))
            origin = tuple(win32gui.ClientToScreen(hwnd, (0, 0)))
            dpi = int(_USER32.GetDpiForWindow(hwnd))
            if dpi <= 0:
                raise HighHelperError("client_geometry_unavailable")
        finally:
            _USER32.SetThreadDpiAwarenessContext(previous)
        return cls(facts, iso, hwnd, bounds, nonce, broker_revision, rect, origin, dpi)

    def wire(self):
        return {"Hwnd": self.hwnd, **{name: self.facts[name] for name in
                ("Pid", "Created", "Session", "ImageDigest", "Integrity")},
                "Nonce": self.nonce, "Bounds": list(self.bounds),
                "ClientRect": None if self.client_rect is None else list(self.client_rect),
                "ClientOrigin": None if self.client_origin is None else list(self.client_origin),
                "WindowDpi": self.window_dpi}

    @property
    def resources(self):
        return (FOREGROUND_INPUT_RESOURCE,
                physical_window_resource(self.facts["Pid"], self.facts["Created"], self.hwnd))

    def resources_for(self, operation):
        return self.resources if _foreground_required(operation) else (self.resources[1],)


class _Pipe:
    def __init__(self, name):
        self.name, self.handle = name, None
        self.write_lock = threading.Lock()
        self._read_buffer = bytearray()

    def connect(self, timeout=1.5):
        until = time.monotonic() + timeout
        while True:
            try:
                # Anonymous SQOS: the elevated server never impersonates this client.
                self.handle = win32file.CreateFile("\\\\.\\pipe\\" + self.name,
                    win32con.GENERIC_READ | win32con.GENERIC_WRITE, 0, None, win32con.OPEN_EXISTING,
                    win32file.FILE_FLAG_OVERLAPPED | 0x100000, None)
                return
            except pywintypes.error as error:
                if error.winerror not in (2, 231) or time.monotonic() >= until:
                    raise HighHelperError("broker_unavailable") from None
                time.sleep(0.01)

    def close(self):
        if self.handle is not None:
            self.handle.Close()
            self.handle = None

    def _finish(self, overlapped, timeout):
        if win32event.WaitForSingleObject(overlapped.hEvent, max(1, int(timeout * 1000))) != win32event.WAIT_OBJECT_0:
            win32file.CancelIoEx(self.handle, overlapped)
            # Drain the cancelled OVERLAPPED before its buffer/event is released.
            win32event.WaitForSingleObject(overlapped.hEvent, 1000)
            raise HighHelperError("pipe_deadline")
        return win32file.GetOverlappedResult(self.handle, overlapped, False)

    def read(self, timeout):
        until = time.monotonic() + timeout
        while True:
            newline = self._read_buffer.find(b"\n")
            if newline >= 0:
                if newline >= _LIMIT:
                    raise HighHelperError("message_too_large")
                result = bytes(self._read_buffer[:newline])
                del self._read_buffer[:newline + 1]
                return json.loads(result, object_pairs_hook=_unique_pairs)
            if len(self._read_buffer) >= _LIMIT:
                raise HighHelperError("message_too_large")
            if time.monotonic() >= until:
                raise HighHelperError("pipe_deadline")
            overlapped = pywintypes.OVERLAPPED()
            event = win32event.CreateEvent(None, True, False, None)
            overlapped.hEvent = event
            try:
                _, buffer = win32file.ReadFile(self.handle, min(1024, _LIMIT - len(self._read_buffer)), overlapped)
                count = self._finish(overlapped, until - time.monotonic())
                if count <= 0:
                    raise HighHelperError("pipe_disconnected")
                value = bytes(buffer[:count])
            except pywintypes.error:
                raise HighHelperError("pipe_disconnected") from None
            finally:
                event.Close()
            self._read_buffer.extend(value)

    def write(self, message):
        data = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
        if len(data) > _LIMIT:
            raise HighHelperError("message_too_large")
        with self.write_lock:
            overlapped = pywintypes.OVERLAPPED()
            event = win32event.CreateEvent(None, True, False, None)
            overlapped.hEvent = event
            try:
                win32file.WriteFile(self.handle, data, overlapped)
                if self._finish(overlapped, 0.5) != len(data):
                    raise HighHelperError("pipe_disconnected")
            finally:
                event.Close()


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise HighHelperError("schema_rejected")
        result[key] = value
    return result


class ExternalDispatchLease:
    """Authenticated fixed-helper readiness; never a parent mutex handle list."""
    def __init__(self, seal, *, pipe, helper, bundle, target, resources, deadline, ledger_identity, chat_id, connection_id="", desktop_revision=0, peer_evidence=None, binding=None, completion_probe=None, operation=None):
        if seal is not _SEAL:
            raise HighHelperError("external_lease_rejected")
        self._seal, self._pipe, self._helper, self._bundle = seal, pipe, helper, bundle
        self.target, self.resources = target, tuple(sorted(resources))
        self.ledger_identity = ledger_identity
        self.chat_id = chat_id
        self.connection_id, self.desktop_revision = connection_id, desktop_revision
        self.peer_evidence = MappingProxyType(dict(peer_evidence or {}))
        self.binding = binding
        self.physical_input_expected = operation is None or operation["Kind"] in {"activate", "click", "text", "computer_input_plan"} or operation.get("Activate", False)
        self.business_write_expected = operation is None or operation["Kind"] in {"click", "text", "computer_input_plan"} or operation["Kind"] == "app_request" and operation["Plan"]["command"] not in {"observe", "read_text"}
        self.business_write_expected = self.business_write_expected or operation is not None and operation["Kind"] == "window_layout"
        self.layout_plan = None
        if operation is not None and operation["Kind"] == "window_layout":
            from .high_broker_types import WindowLayoutPlan
            self.layout_plan = WindowLayoutPlan.from_wire(operation["Plan"])
        self._completion_probe, self._late_release_confirmed = completion_probe, False
        self.deadline = deadline
        self.thread_id = threading.get_ident()
        self.executor_process = f"{helper['Pid']}:{_process(helper['Pid'])[1]}"
        self.result = None
        self._accepted_terminal = None
        self.go_sent = False
        self.action_id = None
        self._sink = None
        self._release_binding_issued = False
        self._identity_cache = {}
        self._bundle.verify()

    def verify(self):
        if self._seal is not _SEAL or self.thread_id != threading.get_ident() or time.monotonic() >= self.deadline:
            raise HighHelperError("external_lease_expired")
        if win32pipe.GetNamedPipeServerProcessId(self._pipe.handle) != self._helper["Pid"] or _process(
                self._helper["Pid"], digest_cache=self._identity_cache,
                expected_image=str(self._bundle.directory / _BUNDLE_NAMES[0]))[0] != self._helper:
            raise HighHelperError("helper_identity_changed")
        for resource in self.resources:
            handle = win32event.CreateMutex(None, False, _mutex_name(resource))
            try:
                outcome = win32event.WaitForSingleObject(handle, 0)
                if outcome in (win32event.WAIT_OBJECT_0, win32event.WAIT_ABANDONED):
                    win32event.ReleaseMutex(handle)
                    raise HighHelperError("helper_mutex_not_owned")
                if outcome != win32event.WAIT_TIMEOUT:
                    raise HighHelperError("helper_mutex_unconfirmed")
            finally:
                handle.Close()

    def holds_resource(self, resource):
        if self.result is not None or resource not in self.resources:
            return False
        try:
            self.verify()
            return True
        except Exception:
            return False

    def wait_requires_yield(self, resource):
        # Failure/expiry is no release proof. A live failed executor must not
        # overlap a model wait, even after its ledger action has ended.
        if resource not in self.resources:
            return False
        if (self.result is not None and self.result["SemanticExecutorExited"] is False
                and not (self.layout_plan is not None and self.result["MutexReleased"] and self.result["InputRelease"] == "released")):
            try:
                return _process(self.result["SemanticExecutor"]["Pid"])[0] == self.result["SemanticExecutor"]
            except Exception:
                return False
        if self.result is not None and self.result["MutexReleased"]:
            return False
        if self._late_release_confirmed:
            return False
        if self._completion_probe is not None:
            try:
                self._late_release_confirmed = self._completion_probe() is True
                if self._late_release_confirmed:
                    return False
            except Exception:
                pass
        return process_is_alive(self.executor_process)

    def claim(self, action_id, resources, sink):
        self.verify()
        if self.action_id is not None or tuple(sorted(resources)) != self.resources:
            raise HighHelperError("external_lease_reused")
        if self.binding is not None and (self.binding.task_id != self.chat_id or self.binding.action_id != action_id):
            raise HighHelperError("input_action_binding_mismatch")
        self.action_id, self._sink = action_id, sink

    def _accept(self, result):
        if self.result is not None:
            raise HighHelperError("duplicate_result")
        _validate_result(result, self.target)
        if (result["LedgerIdentity"] != self.ledger_identity or result["TaskId"] != self.chat_id
                or result["ConnectionId"] != self.connection_id or result["DesktopRevision"] != self.desktop_revision):
            raise HighHelperError("result_ledger_mismatch")
        if result["HighVerified"] != (self._helper["Integrity"] == 12288):
            raise HighHelperError("result_integrity_mismatch")
        if self.binding is not None and (result["RequestBinding"] != self.binding.result_wire()
                or result["InputResult"] is not None and result["InputResult"].get("Binding") != self.binding.result_wire()):
            raise HighHelperError("input_result_binding_mismatch")
        layout = result.get("LayoutResult")
        if self.layout_plan is not None:
            expected = self.layout_plan.wire()
            if (type(layout) is not dict or layout["Command"] != expected["command"]
                    or layout["RequestedRect"] != expected["requested_rect"]):
                raise HighHelperError("window_layout_result_binding_mismatch")
            peer = result["SemanticExecutor"]
            if peer is not None and (peer["Pid"] == self._helper["Pid"]
                    or any(peer[k] != self._helper[k] for k in ("Session", "User", "Integrity", "ImageDigest"))):
                raise HighHelperError("window_layout_executor_rejected")
        elif layout is not None:
            raise HighHelperError("window_layout_result_binding_mismatch")
        self.result = result
        self._accepted_terminal = json.loads(json.dumps(result))
        if self._sink is not None:
            self._sink(result)

    def terminal_for_interruption(self):
        """Accepted terminal proof for stage metadata; no mutex/authority claim."""
        if (self._seal is not _SEAL or self.thread_id != threading.get_ident()
                or not self.go_sent or self.action_id is None or self._sink is None
                or self._accepted_terminal is None or self.result != self._accepted_terminal):
            raise HighHelperError("external_terminal_unverified")
        result = self._accepted_terminal
        _validate_result(result, self.target)
        if (result["TaskId"] != self.chat_id or result["LedgerIdentity"] != self.ledger_identity
                or result["ConnectionId"] != self.connection_id or result["DesktopRevision"] != self.desktop_revision
                or self.binding is not None and result["RequestBinding"] != self.binding.result_wire()):
            raise HighHelperError("external_terminal_binding_mismatch")
        return json.loads(json.dumps(result))


def _mutex_name(resource):
    return "Local\\FlowerControl.Resource.v1." + hashlib.sha256(resource.encode("utf-8")).hexdigest()


def _validate_result(result, target):
    names = {"Phase", "LedgerIdentity", "TaskId", "ConnectionId", "DesktopRevision", "RequiresNewObservation",
             "State", "Reason", "Winerror", "Target", "SentEvents", "ActivationEvents", "BusinessEvents", "ImeEvents",
             "BusinessAttempted", "NativeCountKnown", "ImePreparation", "InputResult", "RequestBinding", "SemanticExecutor", "SemanticExecutorExited",
             "SemanticBusinessDispatched", "AppResult", "RequestedEvents", "ReleaseEvents",
             "InputRelease", "ActivationRequested", "ActivationDiagnostics", "Foreground", "MutexReleased",
             "HighVerified", "BusinessVerified", "TimingsMs"}
    if (type(result) is not dict or set(result) not in (names, names | {"LayoutResult"}) or result["Phase"] != "done" or result["Target"] != target
            or result["InputRelease"] not in {"released", "release_pending", "unknown"}
            or result["State"] not in {"rejected", "interrupted", "bound", "activated", "dispatched_unverified"}
            or result["BusinessVerified"] is not False):
        raise HighHelperError("result_rejected")
    for name in ("SentEvents", "ActivationEvents", "BusinessEvents", "ImeEvents", "RequestedEvents", "ReleaseEvents"):
        if type(result[name]) is not int or not 0 <= result[name] <= 16400:
            raise HighHelperError("result_rejected")
    for name in ("ActivationRequested", "Foreground", "MutexReleased", "HighVerified", "RequiresNewObservation", "BusinessAttempted", "NativeCountKnown"):
        if type(result[name]) is not bool:
            raise HighHelperError("result_rejected")
    if (result["SentEvents"] != result["ActivationEvents"] + result["BusinessEvents"] + result["ImeEvents"]
            or result["SentEvents"] > result["RequestedEvents"]
            or not result["NativeCountKnown"] and result["InputRelease"] == "released"):
        raise HighHelperError("result_rejected")
    if type(result["ActivationDiagnostics"]) is not list or len(result["ActivationDiagnostics"]) > 4:
        raise HighHelperError("result_rejected")
    import math
    if (type(result["TimingsMs"]) is not dict
            or set(result["TimingsMs"]) - {"queue_wait", "activation", "dispatch", "prepare_ready", "wait_go", "execute", "cleanup", "total"}
            or any(type(value) not in (int, float) or not math.isfinite(value) or value < 0 for value in result["TimingsMs"].values())):
        raise HighHelperError("result_rejected")
    for attempt in result["ActivationDiagnostics"]:
        if (type(attempt) is not dict or set(attempt) != {"Api", "Succeeded", "Winerror"}
                or attempt["Api"] not in {"BringWindowToTop", "SetForegroundWindow"}
                or type(attempt["Succeeded"]) is not bool or type(attempt["Winerror"]) is not int):
            raise HighHelperError("result_rejected")
    progress = result["InputResult"]
    if result["SemanticBusinessDispatched"] is not None and type(result["SemanticBusinessDispatched"]) is not bool:
        raise HighHelperError("app_result_rejected")
    if result["SemanticExecutorExited"] is not None and type(result["SemanticExecutorExited"]) is not bool:
        raise HighHelperError("app_result_rejected")
    peer = result["SemanticExecutor"]
    if peer is not None:
        import re
        if (type(peer) is not dict or set(peer) != {"Pid", "Created", "Session", "User", "ImageDigest", "Integrity"}
                or any(type(peer[k]) is not int or peer[k] <= 0 for k in ("Pid", "Created", "Integrity"))
                or type(peer["Session"]) is not int or peer["Session"] < 0 or type(peer["User"]) is not str
                or type(peer["ImageDigest"]) is not str or re.fullmatch(r"[a-f0-9]{64}", peer["ImageDigest"]) is None):
            raise HighHelperError("app_executor_rejected")
    if progress is not None:
        if type(progress) is not dict or set(progress) != {"Binding", "BusinessStarted", "BusinessComplete", "AcceptedEvents",
                "CompletedPlans", "CompletedSegments", "PartialSegment", "CleanupEvents", "NativeCountKnown"}:
            raise HighHelperError("input_result_rejected")
        if (progress["AcceptedEvents"] != (result["BusinessEvents"] if result["NativeCountKnown"] else None)
                or progress["CleanupEvents"] != result["ReleaseEvents"] or progress["NativeCountKnown"] != result["NativeCountKnown"]):
            raise HighHelperError("input_result_rejected")
        if (progress["BusinessStarted"] is not None and type(progress["BusinessStarted"]) is not bool
                or type(progress["BusinessComplete"]) is not bool
                or any(type(progress[k]) is not int or not 0 <= progress[k] <= maximum
                       for k, maximum in (("CompletedPlans", 131), ("CompletedSegments", 2096)))):
            raise HighHelperError("input_result_rejected")

    if "LayoutResult" in result:
        from .high_broker_types import _layout_rect
        layout = result["LayoutResult"]
        if (type(layout) is not dict or set(layout) != {"Binding", "Command", "RequestedRect", "ObservedRect", "DispatchAttempted", "CallReturned", "ApiSucceeded", "Dispatched", "RequestedReached"}
                or type(layout["Command"]) is not str or layout["Command"] not in {"window_move", "window_resize"}
                or layout["Binding"] != result["RequestBinding"] or result["RequestBinding"] is None
                or type(layout["DispatchAttempted"]) is not bool
                or any(layout[k] is not None and type(layout[k]) is not bool for k in ("CallReturned", "ApiSucceeded", "Dispatched", "RequestedReached"))
                or result["BusinessAttempted"] != layout["DispatchAttempted"] or result["SemanticBusinessDispatched"] != layout["Dispatched"]
                or any(result[k] != 0 for k in ("RequestedEvents", "SentEvents", "BusinessEvents", "ActivationEvents", "ImeEvents", "ReleaseEvents"))
                or not result["NativeCountKnown"] or result["InputResult"] is not None or result["AppResult"] is not None
                or result["ActivationRequested"] or result["ImePreparation"] is not None):
            raise HighHelperError("window_layout_result_rejected")
        try:
            _layout_rect(layout["RequestedRect"])
            if layout["ObservedRect"] is not None:
                _layout_rect(layout["ObservedRect"])
        except (ValueError, TypeError):
            raise HighHelperError("window_layout_result_rejected") from None
        if (not layout["DispatchAttempted"] and (layout["CallReturned"] is not False or layout["ApiSucceeded"] is not None
                    or layout["Dispatched"] is not False or layout["RequestedReached"] is not False or layout["ObservedRect"] is not None)
                or layout["DispatchAttempted"] and (not result["RequiresNewObservation"] or peer is None
                    or type(result["SemanticExecutorExited"]) is not bool or layout["CallReturned"] is False)
                or layout["DispatchAttempted"] and layout["CallReturned"] is None and (
                    any(layout[k] is not None for k in ("ApiSucceeded", "Dispatched", "RequestedReached", "ObservedRect")))
                or layout["CallReturned"] is True and (type(layout["ApiSucceeded"]) is not bool
                    or layout["Dispatched"] is not layout["ApiSucceeded"]
                    or (layout["ObservedRect"] is None) != (layout["RequestedReached"] is None))
                or layout["CallReturned"] is True and layout["ObservedRect"] is not None
                    and layout["RequestedReached"] is not (layout["ObservedRect"] == layout["RequestedRect"])):
            raise HighHelperError("window_layout_result_rejected")


def _validate_plan(target, operation, resources):
    if type(target) is not HighTarget or type(operation) is not dict or set(operation) - {"Kind", "X", "Y", "Text", "RestoreMinimized", "Plan", "Activate"}:
        raise HighHelperError("operation_rejected")
    kind = operation.get("Kind")
    if kind not in {"bind", "activate", "click", "text", "computer_input_plan", "app_request", "window_layout"} or kind != "bind" and target.nonce <= 0:
        raise HighHelperError("operation_rejected")
    if type(operation.get("RestoreMinimized", False)) is not bool or kind in {"bind", "window_layout"} and operation.get("RestoreMinimized"):
        raise HighHelperError("operation_rejected")
    if type(operation.get("Activate", False)) is not bool or operation.get("Activate") and kind != "app_request":
        raise HighHelperError("operation_rejected")
    for key in ("X", "Y"):
        value = operation.get(key)
        if (kind == "click" and (type(value) is not int or not -(1 << 31) <= value < 1 << 31)
                or kind != "click" and value is not None):
            raise HighHelperError("operation_rejected")
    text = operation.get("Text")
    if kind == "text":
        try:
            if (type(text) is not str or not 1 <= len(text.encode("utf-16-le")) // 2 <= 64
                    or any((ord(c) < 32 or 127 <= ord(c) <= 159) and c not in "\r\n\t" for c in text)):
                raise HighHelperError("operation_rejected")
        except UnicodeError:
            raise HighHelperError("operation_rejected") from None
    elif text is not None:
        raise HighHelperError("operation_rejected")
    if kind == "computer_input_plan":
        from .high_broker_types import ComputerInputPlan
        try:
            ComputerInputPlan.from_wire(operation.get("Plan"))
        except (ValueError, TypeError):
            raise HighHelperError("input_plan_rejected") from None
        if target.client_rect is None or target.client_origin is None or target.window_dpi is None:
            raise HighHelperError("client_geometry_required")
    elif kind == "window_layout":
        from .high_broker_types import WindowLayoutPlan
        try:
            plan = WindowLayoutPlan.from_wire(operation.get("Plan")).wire()
            rect, old = plan["requested_rect"], target.bounds
            if (plan["command"] == "window_move" and (rect[2] - rect[0], rect[3] - rect[1]) != (old[2] - old[0], old[3] - old[1])
                    or plan["command"] == "window_resize" and tuple(rect[:2]) != tuple(old[:2])):
                raise ValueError("window_layout_rejected")
        except (ValueError, TypeError, KeyError):
            raise HighHelperError("window_layout_rejected") from None
        if target.client_rect is None or target.client_origin is None or target.window_dpi is None:
            raise HighHelperError("client_geometry_required")
    elif kind != "app_request" and operation.get("Plan") is not None:
        raise HighHelperError("operation_rejected")
    if kind == "app_request":
        from .high_broker_types import AppRequest, InputBinding
        try:
            plan = operation["Plan"]
            if type(plan) is not dict or set(plan) != {"schema_version", "command", "arguments", "binding"} or type(plan["schema_version"]) is not int or plan["schema_version"] != 1:
                raise ValueError()
            AppRequest.create(plan["command"], plan["arguments"], InputBinding(**plan["binding"])).operation(
                activate=operation.get("Activate", False), restore_minimized=operation.get("RestoreMinimized", False))
            destination = plan["arguments"]["target"]
            if (destination["hwnd"], destination["pid"], destination["process_start_filetime"]) != (target.hwnd, target.facts["Pid"], target.facts["Created"]):
                raise ValueError()
        except (KeyError, ValueError, TypeError):
            raise HighHelperError("app_request_rejected") from None
    import re
    required = set(target.resources_for(operation))
    canonical = set(target.resources)
    if (not 1 <= len(resources) <= 8 or len(set(resources)) != len(resources) or not required.issubset(resources)
            or any(type(r) is not str or len(r) > 128 or r not in canonical
                   and re.fullmatch(r"web-(profile|session):[a-zA-Z0-9_-]{1,96}", r) is None for r in resources)):
        raise HighHelperError("resources_rejected")


def _foreground_required(operation):
    return operation.get("Kind") != "bind" and not (operation.get("Kind") == "app_request"
        and operation.get("Activate", False) is False and type(operation.get("Plan")) is dict
        and operation["Plan"].get("command") in {"observe", "read_text"})


def assess_high_route(target: HighTarget, *, failure_code=None, foreground_integrity=None):
    """Evidence-based route hint; an integrity gap is not an API failure cause."""
    from flower_control._executor_metadata import executor_metadata
    actor = executor_metadata()
    result = {"route": "ordinary", "reason": None, "elevation_required": False,
              "activation_failure_cause_verified": False, "executor": actor}
    if not actor["metadata_available"]:
        return {**result, "route": "unverified", "reason": "executor_token_probe_failed"}
    if target.facts["Session"] != actor["session_id"] or target.facts["Integrity"] not in {8192, 12288}:
        return {**result, "route": "unsupported", "reason": "target_integrity_or_session_rejected"}
    if actor["integrity_rid"] == 8192 and not actor["ui_access"] and target.facts["Integrity"] == 12288:
        return {**result, "route": "high_helper_required", "reason": "target_integrity_higher", "elevation_required": True}
    if (actor["integrity_rid"] == 8192 and not actor["ui_access"] and foreground_integrity == 12288
            and failure_code in {"user_activation_required", "activation_access_denied", "target_unresponsive"}):
        return {**result, "route": "high_helper_available", "reason": "foreground_integrity_higher", "elevation_required": True}
    return result




@dataclass(frozen=True)
class BrokerStatus:
    facts: dict

    @property
    def desktop_revision(self):
        value = self.facts.get("desktop_revision")
        if type(value) is not int or value <= 0:
            raise HighHelperError("broker_status_rejected")
        return value


def _installed_bundle():
    root = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "FlowerControl" / "HighHelper"
    try:
        active = json.loads((root / "active.json").read_bytes(), object_pairs_hook=_unique_pairs)
        if type(active) is not dict or set(active) != {"schema", "version", "hashes"} or active["schema"] != 1:
            raise HighHelperError("installation_rejected")
        import re
        if type(active["version"]) is not str or not re.fullmatch(r"[a-f0-9]{16,64}", active["version"]):
            raise HighHelperError("installation_rejected")
        directory = root / "versions" / active["version"]
        bundle = HelperBundle(directory, tuple((name, active["hashes"][name]) for name in _BUNDLE_NAMES))
        bundle.verify()
        for path in (root, root / "versions", directory, root / "active.json"):
            if path.is_symlink() or path.is_junction():
                raise HighHelperError("installation_rejected")
        for name, expected in active["hashes"].items():
            if Path(name).name != name or _digest(directory / name) != expected:
                raise HighHelperError("installation_changed")
        return bundle, active["version"]
    except (OSError, KeyError, ValueError, TypeError):
        raise HighHelperError("broker_not_installed") from None


class HighHelperClient:
    def __init__(self, bundle: HelperBundle | None = None, *, medium_fixture=False, fixture_descriptor=None,
                 channel="flower-computer"):
        if type(medium_fixture) is not bool or channel not in {"flower-web", "flower-app", "flower-computer"}:
            raise HighHelperError("client_option_rejected")
        if not medium_fixture and (bundle is not None or fixture_descriptor is not None):
            raise HighHelperError("production_bundle_override_rejected")
        self.bundle, self.medium_fixture = bundle, medium_fixture
        self.fixture_descriptor, self.channel = fixture_descriptor, "fixture" if medium_fixture else channel

    def open_session(self, task_id: str):
        return HighHelperSession(self, task_id)

    def probe_status(self):
        """Read only the installed bundle and an existing admitted broker."""
        result = dict(state="unknown", installed=None, installation_present=None, installed_version=None,
                      running=None, connected=False, paused=None, high_token_verified=None,
                      actual_integrity_rid=None, source_admitted=None, high_control_available=False,
                      reason=None, native_binary_hashes=None, status=None)
        active = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "FlowerControl/HighHelper/active.json"
        try:
            active.stat()
            result["installation_present"] = True
        except FileNotFoundError:
            return {**result, "state": "not_installed", "installed": False,
                    "installation_present": False, "reason": "broker_not_installed"}
        except OSError:
            return {**result, "reason": "installation_status_unavailable"}
        session = None
        try:
            bundle, installed_version = _installed_bundle()
            result.update(installed=True, installed_version=installed_version, native_binary_hashes=dict(bundle.hashes))
            session = self.open_session("readonly-status-probe")  # Local connection label; never a StateStore task/grant.
            session._start(connect_timeout=.15, hello_timeout=.35)
            session._verify_peer()
            session._pipe.write({"Phase": "status"})
            reply = session._pipe.read(.35)
            if type(reply) is not dict or set(reply) != {"Phase", "Status"} or reply["Phase"] != "status":
                raise HighHelperError("broker_status_rejected")
            facts = reply["Status"]
            if (type(facts) is not dict or any(type(facts.get(k)) is not bool for k in
                    ("paused", "desktop_locked", "stopping", "release_fault", "high_verified", "ui_access"))
                    or any(type(facts.get(k)) is not int for k in ("pid", "created", "session_id"))
                    or facts.get("version") != installed_version or facts.get("pid") != session._helper["Pid"]
                    or facts.get("created") != session._helper["Created"] or facts.get("session_id") != session._helper["Session"]
                    or facts["high_verified"] is not True or facts["ui_access"] is not False
                    or session._helper["Integrity"] != 12288 or session._evidence.get("ProductionAdmitted") is not True
                    or not _production_host_evidence(session._evidence)):
                raise HighHelperError("broker_status_rejected")
            BrokerStatus(facts).desktop_revision
            available = not any(facts[k] for k in ("paused", "desktop_locked", "stopping", "release_fault"))
            reason = ("broker_stopping" if facts["stopping"] else "broker_release_fault" if facts["release_fault"] else
                      "desktop_locked" if facts["desktop_locked"] else "broker_paused" if facts["paused"] else None)
            return {**result, "state": "available" if available else "paused" if facts["paused"] else "unavailable",
                    "running": True, "connected": True, "paused": facts["paused"], "high_token_verified": True,
                    "actual_integrity_rid": session._helper["Integrity"], "source_admitted": True,
                    "high_control_available": available, "reason": reason, "status": dict(facts),
                    "host_source": session._evidence["Source"]}
        except HighHelperError as error:
            return {**result, "state": "not_connected" if result["installed"] is True else "installation_unverified",
                    "reason": error.code}
        except Exception:
            return {**result, "reason": "broker_status_probe_failed"}
        finally:
            if session is not None:
                session.close()

    def recover_release(self, store, owner, action_id):
        """Read actual terminal metadata, commit only release, then acknowledge.

        Does not resume, authorize, verify business outcome or replay any input.
        """
        pending = store.external_release_pending(owner, action_id)
        expected = tuple(pending[k] for k in ("task_id", "action_id", "executor_process", "ledger_identity"))
        with self.open_session(pending["task_id"]) as session:
            session._start()
            message = dict(Phase="release_recovery", TaskId=expected[0], ActionId=expected[1],
                           ExecutorProcess=expected[2], LedgerIdentity=expected[3])
            session._pipe.write(message)
            recovery = ReleaseRecovery(_SEAL, session, expected, session._pipe.read(1))
            result = store.confirm_external_release(owner, action_id, recovery)
            session._pipe.write({**message, "Phase": "release_recovery_ack"})
            ack = session._pipe.read(1)
            if ack != {"Phase": "release_recovery_ack", "LedgerIdentity": expected[3]}:
                raise HighHelperError("release_recovery_ack_unconfirmed")
            return result

    def _request_release(self, task_id, connection_id, ledger_identity, helper):
        with self.open_session(task_id) as query:
            query._start()
            if query._helper != helper:
                return False
            query._pipe.write({"Phase": "request_status", "TaskId": task_id,
                "ConnectionId": connection_id, "LedgerIdentity": ledger_identity})
            result = query._pipe.read(1)
            names = {"Phase", "TaskId", "ConnectionId", "LedgerIdentity", "State", "InputRelease", "MutexReleased", "SemanticExecutorExited"}
            if (type(result) is not dict or set(result) not in (names, names | {"PhysicalInputFree"})
                    or "PhysicalInputFree" in result and result["PhysicalInputFree"] is not True
                    or result["SemanticExecutorExited"] is not None and type(result["SemanticExecutorExited"]) is not bool
                    or result["Phase"] != "request_status" or result["TaskId"] != task_id
                    or result["ConnectionId"] != connection_id or result["LedgerIdentity"] != ledger_identity):
                raise HighHelperError("request_status_rejected")
            return (result["State"] == "finished" and result["InputRelease"] == "released" and result["MutexReleased"] is True
                    and (result["SemanticExecutorExited"] is not False or result.get("PhysicalInputFree") is True))

    def execute(self, target, operation, *, before_go, stopped, task_id=None, chat_id=None,
                resources=None, deadline_ms=3000):
        task_id = task_id if task_id is not None else chat_id
        with self.open_session(task_id) as session:
            result = session.execute(task_id, target, operation, before_go=before_go, stopped=stopped,
                                     resources=resources, deadline_ms=deadline_ms)
        result["helper_session_retained"] = False
        result.update(session.lifecycle)
        return result


class HighHelperSession:
    """One task's connection. Closing it never closes the shared executor."""
    def __init__(self, client, task_id):
        import re
        if type(task_id) is not str or re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", task_id) is None:
            raise HighHelperError("chat_binding_rejected")
        self.client, self.chat_id = client, task_id
        self._lock = threading.Lock()
        self._closed, self._pipe = False, None
        self._identity_cache = {}
        self._parent = self._helper = None
        self._connection_id, self._version, self._evidence = None, None, None
        self._connect_timings = {}
        self.lifecycle = {"helper_exited": None, "helper_exit_reason": None, "connection_closed": False}

    def __enter__(self):
        return self

    def __exit__(self, *errors):
        self.close()

    def _start(self, *, connect_timeout=1.5, hello_timeout=3):
        if self._pipe is not None:
            self._verify_peer()
            return False
        if self._closed:
            raise HighHelperError("helper_session_closed")
        clock = time.monotonic()
        parent, _ = _process(win32api.GetCurrentProcessId(), digest_cache=self._identity_cache)
        if parent["Integrity"] not in {8192, 12288}:
            raise HighHelperError("integrity_route_rejected")
        if self.client.medium_fixture:
            if self.client.fixture_descriptor is None:
                raise HighHelperError("fixture_descriptor_required")
            descriptor = json.loads(Path(self.client.fixture_descriptor).read_bytes(), object_pairs_hook=_unique_pairs)
            import re
            if (descriptor.get("Mode") != "medium-isolated-fixture" or parent["Integrity"] != 8192
                    or re.fullmatch(r"Flower\.HighBroker\.Fixture\.[a-f0-9]{32}", descriptor.get("FixturePipe", "")) is None):
                raise HighHelperError("fixture_descriptor_rejected")
            if self.client.bundle is None:
                self.client.bundle = HelperBundle.snapshot(Path(self.client.fixture_descriptor).parent)
            self.client.bundle.verify()
            self._version, pipe_name = descriptor["Version"], descriptor["FixturePipe"]
        else:
            self.client.bundle, self._version = _installed_bundle()
            pipe_name = "Flower.HighBroker.v1." + hashlib.sha256(f"{parent['User']}|{parent['Session']}".encode()).hexdigest()[:32]
        self._parent = parent
        self._pipe = _Pipe(pipe_name)
        if connect_timeout == 1.5:
            self._pipe.connect()
        else:
            self._pipe.connect(timeout=connect_timeout)
        self._connect_timings["connect"] = (time.monotonic() - clock) * 1000
        clock = time.monotonic()
        pid = win32pipe.GetNamedPipeServerProcessId(self._pipe.handle)
        helper, _ = _process(pid, digest_cache=self._identity_cache,
                             expected_image=str(self.client.bundle.directory / _BUNDLE_NAMES[0]))
        if (helper["User"] != parent["User"] or helper["Session"] != parent["Session"]
                or helper["Integrity"] != (8192 if self.client.medium_fixture else 12288)
                or helper["ImageDigest"] != dict(self.client.bundle.hashes)[_BUNDLE_NAMES[0]]):
            raise HighHelperError("helper_identity_mismatch")
        self._pipe.write({"Phase": "hello", "Parent": parent, "Channel": self.client.channel})
        hello = self._pipe.read(hello_timeout)
        import re
        if (type(hello) is not dict or set(hello) != {"Phase", "Helper", "AssemblyDigest", "Version", "ConnectionId", "PeerEvidence", "Status"}
                or hello["Phase"] != "hello" or hello["Helper"] != helper or hello["Version"] != self._version
                or hello["AssemblyDigest"] != dict(self.client.bundle.hashes)["Flower.HighHelper.dll"]
                or type(hello["ConnectionId"]) is not str or re.fullmatch(r"[a-f0-9]{32}", hello["ConnectionId"]) is None):
            raise HighHelperError("hello_rejected", details={"source_admitted": False})
        evidence = hello["PeerEvidence"]
        if (type(evidence) is not dict or not _peer_evidence_shape(evidence)
                or any(evidence[k] != parent[k] for k in ("Pid", "Created", "Session"))
                or evidence["Channel"] != self.client.channel
                or (evidence["Source"] != "medium-isolated-fixture" if self.client.medium_fixture
                    else not _production_host_evidence(evidence))
                or evidence["ProductionAdmitted"] is not (not self.client.medium_fixture)):
            raise HighHelperError("peer_evidence_rejected")
        self._helper, self._connection_id, self._evidence = helper, hello["ConnectionId"], evidence
        BrokerStatus(hello["Status"]).desktop_revision
        self._connect_timings["peer_auth"] = (time.monotonic() - clock) * 1000
        return True

    def _verify_peer(self):
        if (win32pipe.GetNamedPipeServerProcessId(self._pipe.handle) != self._helper["Pid"]
                or _process(self._helper["Pid"], digest_cache=self._identity_cache,
                            expected_image=str(self.client.bundle.directory / _BUNDLE_NAMES[0]))[0] != self._helper):
            raise HighHelperError("helper_identity_changed")

    def status(self):
        if not self._lock.acquire(blocking=False):
            raise HighHelperError("helper_session_busy")
        try:
            self._start()
            self._pipe.write({"Phase": "status"})
            result = self._pipe.read(2)
            if type(result) is not dict or set(result) != {"Phase", "Status"} or result["Phase"] != "status":
                raise HighHelperError("broker_status_rejected")
            status = BrokerStatus(result["Status"])
            status.desktop_revision
            return status
        except BaseException:
            self._close_locked()
            raise
        finally:
            self._lock.release()

    def execute_input(self, task_id, target, plan, **options):
        from .high_broker_types import ComputerInputPlan
        if type(plan) is not ComputerInputPlan:
            plan = ComputerInputPlan.from_wire(plan)
        return self.execute(task_id, target, plan.operation(), **options)

    def execute_app(self, task_id, target, request, *, activate=False, restore_minimized=False, **options):
        from .high_broker_types import AppRequest
        if type(request) is not AppRequest:
            raise HighHelperError("app_request_rejected")
        return self.execute(task_id, target, request.operation(activate=activate, restore_minimized=restore_minimized), **options)

    def execute_window_layout(self, task_id, target, plan, *, before_go, stopped, resources=None, deadline_ms=3000):
        from .high_broker_types import WindowLayoutPlan
        if type(plan) is not WindowLayoutPlan:
            plan = WindowLayoutPlan.from_wire(plan)
        return self.execute(task_id, target, plan.operation(), before_go=before_go, stopped=stopped,
                            resources=resources, deadline_ms=deadline_ms)

    def execute(self, task_id, target, operation, *, before_go, stopped, resources=None, deadline_ms=3000):
        if task_id != self.chat_id:
            raise HighHelperError("chat_binding_mismatch")
        if type(deadline_ms) is not int or not 100 <= deadline_ms <= 5000:
            raise HighHelperError("deadline_rejected")
        if not callable(before_go) or not callable(stopped):
            raise HighHelperError("dispatch_callback_required")
        if type(target) is not HighTarget or type(operation) is not dict:
            raise HighHelperError("operation_rejected")
        resources = tuple(target.resources_for(operation) if resources is None else resources)
        # Snapshot caller-owned mutable values before entering the dispatch protocol.
        operation = json.loads(json.dumps(operation, ensure_ascii=True, allow_nan=False))
        _validate_plan(target, operation, resources)
        binding = None
        if operation["Kind"] in {"computer_input_plan", "app_request", "window_layout"}:
            from .high_broker_types import InputBinding
            binding = InputBinding(**operation["Plan"]["binding"])
            if binding.task_id != task_id:
                raise HighHelperError("input_task_binding_mismatch")
        if target.broker_revision <= 0:
            raise HighHelperError("desktop_revision_required")
        if target.facts["Integrity"] not in ({8192} if self.client.medium_fixture else {8192, 12288}):
            raise HighHelperError("integrity_route_rejected")
        if not self._lock.acquire(blocking=False):
            raise HighHelperError("helper_session_busy")
        phase, timings = "connect", {}
        lease, watcher = None, None
        terminal_recorded, ack_attempted = False, False
        done = threading.Event()
        try:
            if self._closed:
                raise HighHelperError("helper_session_closed")
            with ExitStack() as stack:
                for resource in resources:
                    handle = win32event.CreateMutex(None, False, _mutex_name(resource))
                    stack.callback(handle.Close)
                new_connection = self._start()
                if new_connection:
                    timings.update(self._connect_timings)
                if target.facts["Session"] != self._parent["Session"]:
                    raise HighHelperError("target_session_changed")
                pipe = self._pipe
                phase, clock = "prepare_ready", time.monotonic()
                pipe.write({"Phase": "prepare", "Parent": self._parent, "Target": target.wire(), "Operation": operation,
                            "Resources": list(resources), "DeadlineMs": deadline_ms, "TaskId": task_id,
                            "ConnectionId": self._connection_id, "DesktopRevision": target.broker_revision})
                ready = pipe.read(min(3, deadline_ms / 1000 + .5))
                if type(ready) is not dict:
                    raise HighHelperError("ready_rejected")
                if ready.get("Phase") == "done" and ready.get("State") == "rejected":
                    _validate_result(ready, ready.get("Target"))
                    if (ready["TaskId"] != task_id or ready["ConnectionId"] != self._connection_id
                            or ready["DesktopRevision"] != target.broker_revision or ready["BusinessAttempted"]):
                        raise HighHelperError("ready_rejected")
                    # No ready/claim/go happened. Consume this known zero-input
                    # failure so unreachable unclaimed ledgers do not fill the
                    # durable unacknowledged-completion capacity.
                    if (ready["InputRelease"] == "released" and ready["MutexReleased"]
                            and ready["NativeCountKnown"] and ready["SentEvents"] == 0
                            and not ready["ActivationRequested"] and ready["SemanticExecutorExited"] is not False):
                        pipe.write({"Phase": "ack", "LedgerIdentity": ready["LedgerIdentity"], "TaskId": task_id,
                                    "ConnectionId": self._connection_id, "DesktopRevision": target.broker_revision,
                                    "ActionId": binding.action_id if binding is not None else ""})
                    raise HighHelperError(ready.get("Reason") or "helper_prepare_rejected", details={"input_dispatched": False, "receipt": ready})
                bound = ready.get("Target", {})
                names = {"Phase", "Helper", "AssemblyDigest", "Target", "Resources", "MutexOwned", "LedgerIdentity", "TaskId", "ConnectionId", "DesktopRevision"}
                if (set(ready) != names or ready["Phase"] != "ready" or ready["Helper"] != self._helper
                        or ready["AssemblyDigest"] != dict(self.client.bundle.hashes)["Flower.HighHelper.dll"]
                        or ready["MutexOwned"] is not True or ready["Resources"] != list(resources)
                        or ready["TaskId"] != task_id or ready["ConnectionId"] != self._connection_id
                        or ready["DesktopRevision"] != target.broker_revision or type(bound) is not dict
                        or set(bound) != {"Hwnd", "Pid", "Created", "WindowNonce"}
                        or (bound["Hwnd"], bound["Pid"], bound["Created"]) != (target.hwnd, target.facts["Pid"], target.facts["Created"])
                        or type(bound["WindowNonce"]) is not int or bound["WindowNonce"] <= 0
                        or target.nonce and bound["WindowNonce"] != target.nonce):
                    raise HighHelperError("ready_rejected")
                import re
                if type(ready["LedgerIdentity"]) is not str or re.fullmatch(r"[a-f0-9]{64}", ready["LedgerIdentity"]) is None:
                    raise HighHelperError("ready_rejected")
                timings["prepare_ready"] = (time.monotonic() - clock) * 1000
                lease = ExternalDispatchLease(_SEAL, pipe=pipe, helper=self._helper, bundle=self.client.bundle,
                    target=bound, resources=resources, deadline=clock + deadline_ms / 1000,
                    ledger_identity=ready["LedgerIdentity"], chat_id=task_id, connection_id=self._connection_id,
                    desktop_revision=target.broker_revision, peer_evidence=self._evidence, binding=binding,
                    completion_probe=lambda: self.client._request_release(task_id, self._connection_id, ready["LedgerIdentity"], self._helper),
                    operation=operation)
                def signal(value):
                    pipe.write({"Phase": value, "LedgerIdentity": lease.ledger_identity, "TaskId": task_id,
                                "ConnectionId": self._connection_id, "DesktopRevision": target.broker_revision,
                                "ActionId": lease.action_id})
                def acknowledge_terminal():
                    nonlocal ack_attempted
                    receipt = lease._accepted_terminal
                    if (ack_attempted or not terminal_recorded or receipt is None
                            or lease.result != receipt or receipt["LedgerIdentity"] != lease.ledger_identity
                            or receipt["InputRelease"] != "released" or not receipt["MutexReleased"]
                            or not receipt["NativeCountKnown"]
                            or receipt["SemanticExecutorExited"] is False and receipt.get("LayoutResult") is None):
                        return False
                    # _accept must have returned after the durable local sink.
                    # Validated layout receipts carry no physical input even
                    # when their separate geometry executor has not exited.
                    _validate_result(receipt, bound)
                    ack_attempted = True
                    signal("ack")
                    return True
                def watch_stop():
                    while not done.wait(.01):
                        try:
                            if stopped():
                                signal("stop")
                                return
                        except BaseException:
                            pipe.close()
                            return
                phase, authorize_at = "before_go", time.monotonic()
                with before_go(lease):
                    lease.verify()
                    if lease.action_id is None or lease._sink is None:
                        raise HighHelperError("external_dispatch_not_claimed")
                    timings["before_go"] = (time.monotonic() - authorize_at) * 1000
                    phase, clock = "go_done", time.monotonic()
                    if stopped():
                        signal("stop")
                    else:
                        lease.go_sent = True
                        signal("go")
                    watcher = threading.Thread(target=watch_stop, daemon=True)
                    watcher.start()
                    try:
                        lease._accept(pipe.read(max(.001, lease.deadline - clock) + 1.5))
                        terminal_recorded = True
                    finally:
                        done.set()
                        watcher.join(.6)
                        if watcher.is_alive():
                            pipe.close()
                    timings["go_done"] = (time.monotonic() - clock) * 1000
                if watcher.is_alive():
                    raise HighHelperError("stop_sender_exit_unconfirmed")
                if not acknowledge_terminal():
                    self._close_locked()
                return {"receipt": lease.result, "target": WindowIdentity(target.hwnd, target.facts["Pid"], target.process_created, bound["WindowNonce"]),
                        "executor_process": lease.executor_process, "helper_session_retained": not self._closed,
                        "helper_exited": None, "helper_exit_reason": None, "new_connection": new_connection,
                        "new_helper_process": False, "peer_evidence": dict(self._evidence), "broker_version": self._version,
                        "connection_id": self._connection_id, "parent_timings_ms": timings}
        except BaseException as error:
            done.set()
            if terminal_recorded:
                if watcher is not None:
                    watcher.join(.6)
                if watcher is not None and not watcher.is_alive():
                    try:
                        # Context-exit interruption does not invalidate a
                        # recorded release. Preserve the original exception;
                        # failed ack remains recoverable in the broker journal.
                        acknowledge_terminal()
                    except BaseException:
                        pass
            self._close_locked()
            if watcher is not None:
                watcher.join(.6)
            if isinstance(error, HighHelperError):
                error.details.update(phase=phase, **self.lifecycle, parent_timings_ms=timings)
            raise
        finally:
            self._lock.release()

    def _close_locked(self):
        self._closed = True
        if self._pipe is not None:
            self._pipe.close()
            self._pipe = None
        self.lifecycle["connection_closed"] = True

    def close(self):
        # EOF cancels only this connection's request, even while another thread dispatches.
        self._closed = True
        pipe = self._pipe
        if pipe is not None:
            pipe.close()
        self.lifecycle["connection_closed"] = True
