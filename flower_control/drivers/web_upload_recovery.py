"""Recover only DPAPI-registered, dead-owner, empty upload lease directories."""
from __future__ import annotations
import hashlib
import json
import os
import ctypes
from pathlib import Path
import re
import tempfile
import uuid

import win32con
import win32api
import win32crypt
import win32file
import win32security
import pywintypes

from flower_control.control.state import ControlError
from flower_control.control.native import process_identity, process_is_alive
from .web_artifacts import _check_no_reparse, _publication
from .web_file_snapshot import _delete_by_handle, _identity, _open_locked, _DELETE, _OPEN_REPARSE_POINT

_ENTROPY = b"FlowerControl.web-upload-lease.v1"
_BACKUP_SEMANTICS = 0x02000000
_MARKER = "lease.dpapi"
_LEASE_NAME = r"lease-(?:[a-z0-9_]{8}|[a-f0-9]{32})"
_RETIRE_SUFFIX = ".retire.dpapi"


class _UnicodeString(ctypes.Structure):
    _fields_ = [("Length", ctypes.c_ushort), ("MaximumLength", ctypes.c_ushort), ("Buffer", ctypes.c_void_p)]


class _ObjectAttributes(ctypes.Structure):
    _fields_ = [("Length", ctypes.c_ulong), ("RootDirectory", ctypes.c_void_p),
        ("ObjectName", ctypes.POINTER(_UnicodeString)), ("Attributes", ctypes.c_ulong),
        ("SecurityDescriptor", ctypes.c_void_p), ("SecurityQualityOfService", ctypes.c_void_p)]


class _IoStatusBlock(ctypes.Structure):
    _fields_ = [("Status", ctypes.c_void_p), ("Information", ctypes.c_size_t)]


def _security_descriptor():
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    try:
        sid = win32security.ConvertSidToStringSid(win32security.GetTokenInformation(token, win32security.TokenUser)[0])
    finally:
        token.Close()
    descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        f"D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)", 1)
    return ctypes.create_string_buffer(bytes(memoryview(descriptor)))


def _atomic_create_directory(root):
    """Create a new directory relative to a held parent and return its handle."""
    parents = []
    try:
        for path in reversed((root, *root.parents)):
            _check_no_reparse(path)
            parent = win32file.CreateFile(str(path), 0x21, win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
                None, win32con.OPEN_EXISTING, _OPEN_REPARSE_POINT | _BACKUP_SEMANTICS, None)
            parents.append(parent)
            info = win32file.GetFileInformationByHandle(parent)
            actual = win32file.GetFinalPathNameByHandle(parent, 0)
            if actual.startswith("\\\\?\\"):
                actual = actual[4:]
            if (not info[0] & win32con.FILE_ATTRIBUTE_DIRECTORY or info[0] & 0x400
                    or os.path.normcase(os.path.abspath(actual)) != os.path.normcase(os.path.abspath(str(path)))):
                raise ControlError("file_selection_root_unverified")
        name = "lease-" + uuid.uuid4().hex
        buffer = ctypes.create_unicode_buffer(name)
        encoded = len(name.encode("utf-16-le"))
        text = _UnicodeString(encoded, encoded, ctypes.cast(buffer, ctypes.c_void_p))
        security = _security_descriptor()
        attributes = _ObjectAttributes(ctypes.sizeof(_ObjectAttributes), int(parent), ctypes.pointer(text),
                                       0x40, ctypes.addressof(security), None)
        result, status_block = ctypes.c_void_p(), _IoStatusBlock()
        native = ctypes.WinDLL("ntdll")
        create = native.NtCreateFile
        create.argtypes = (ctypes.POINTER(ctypes.c_void_p), ctypes.c_ulong, ctypes.POINTER(_ObjectAttributes),
                           ctypes.POINTER(_IoStatusBlock), ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong,
                           ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong)
        create.restype = ctypes.c_long
        status = create(ctypes.byref(result), 0x001700A1, ctypes.byref(attributes), ctypes.byref(status_block),
                        None, 0, win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE, 2, 0x21, None, 0)
        if status < 0 or not result.value or status_block.Information != 2:
            if result.value:
                pywintypes.HANDLE(result.value).Close()
            raise ControlError("file_selection_directory_create_failed")
        handle = pywintypes.HANDLE(result.value)
        return root / name, handle, parents
    except BaseException:
        for handle in reversed(parents):
            handle.Close()
        raise


def _root():
    from flower_control.data_paths import runtime_temp_root
    root = runtime_temp_root() / "flower-web-upload-leases-v1"
    _check_no_reparse(root)
    root.mkdir(mode=0o700, exist_ok=True)
    _check_no_reparse(root)
    return root


def _directory_handle(path, *, write_dac=False):
    access = _DELETE | (win32con.WRITE_DAC | win32con.READ_CONTROL if write_dac else 0)
    handle = win32file.CreateFile(str(path), access, win32con.FILE_SHARE_READ, None,
        win32con.OPEN_EXISTING, _OPEN_REPARSE_POINT | _BACKUP_SEMANTICS, None)
    try:
        info = win32file.GetFileInformationByHandle(handle)
        if not info[0] & win32con.FILE_ATTRIBUTE_DIRECTORY or info[0] & 0x400:
            raise ValueError("lease_directory_invalid")
        return handle
    except BaseException:
        handle.Close()
        raise


def _dir_id(handle):
    return list(_identity(handle)[:3])


def _read_record(handle):
    if _identity(handle)[3] > 4096:
        raise ValueError("lease_marker_invalid")
    data = win32file.ReadFile(handle, 4097)[1]
    return json.loads(win32crypt.CryptUnprotectData(data, _ENTROPY, None, None, 4)[1])


def _retirement_path(directory):
    return directory.parent / (directory.name + _RETIRE_SUFFIX)


def _strictly_absent(path):
    try:
        path.lstat()
        return False
    except FileNotFoundError:
        return True


def _ensure_retirement_record(directory, record):
    target = _retirement_path(directory)
    if not target.exists():
        sealed = win32crypt.CryptProtectData(json.dumps(record, separators=(",", ":")).encode(),
                                             "Flower upload retirement", _ENTROPY, None, None, 4)
        with _publication(target, None) as writer:
            writer.write(sealed); writer.flush(); os.fsync(writer.fileno())
    existing = _open_locked(target)
    try:
        if _read_record(existing) != record:
            raise ValueError("lease_retirement_record_invalid")
    finally:
        existing.Close()


def finalize_retirement(directory, record):
    """Drop only the exact authenticated receipt after the directory is gone."""
    directory = Path(directory)
    root = _root()
    if directory.parent != root or not re.fullmatch(_LEASE_NAME, directory.name):
        raise ValueError("lease_directory_invalid")
    if not _strictly_absent(directory):
        raise ValueError("lease_directory_still_present")
    target = _retirement_path(directory)
    receipt = _open_locked(target, win32con.GENERIC_READ | _DELETE)
    try:
        if _read_record(receipt) != record or not _strictly_absent(directory):
            raise ValueError("lease_retirement_record_invalid")
        _delete_by_handle(receipt)
    finally:
        receipt.Close()


def create_lease(task):
    root = _root()
    directory, handle, parents = _atomic_create_directory(root)
    created_id = None
    committed = False
    try:
        created_id = _dir_id(handle)
        record = {"schema": 1, "directory": directory.name, "identity": _dir_id(handle),
                  "owner": process_identity(), "task_sha256": hashlib.sha256(task.encode()).hexdigest()}
        sealed = win32crypt.CryptProtectData(json.dumps(record, separators=(",", ":")).encode(),
            "Flower upload lease", _ENTROPY, None, None, 4)
        with (directory / _MARKER).open("xb") as marker:
            marker.write(sealed); marker.flush(); os.fsync(marker.fileno())
        committed = True
        return directory, record, [*parents, handle]
    except BaseException:
        try:
            if created_id is None or _dir_id(handle) != created_id or any(directory.iterdir()):
                raise ControlError("file_selection_cleanup_unverified")
            _delete_by_handle(handle)
        except Exception:
            raise ControlError("file_selection_cleanup_unverified") from None
        raise
    finally:
        if not committed:
            handle.Close()
            for parent in reversed(parents):
                parent.Close()


def retire_lease(directory, record, *, require_dead, pinned=None):
    root = _root()
    directory = Path(directory)
    if directory.parent != root or not re.fullmatch(_LEASE_NAME, directory.name):
        raise ValueError("lease_directory_invalid")
    _check_no_reparse(directory)
    directory_handle = pinned[-1] if pinned else _directory_handle(directory)
    try:
        marker_path = directory / _MARKER
        _check_no_reparse(marker_path)
        marker = _open_locked(marker_path, win32con.GENERIC_READ | _DELETE) if marker_path.exists() else None
        try:
            if marker is not None:
                saved = _read_record(marker)
            else:
                receipt = _open_locked(_retirement_path(directory))
                try:
                    saved = _read_record(receipt)
                finally:
                    receipt.Close()
            if (saved != record or saved.get("schema") != 1 or saved.get("directory") != directory.name
                    or saved.get("identity") != _dir_id(directory_handle)
                    or not re.fullmatch(r"[a-f0-9]{64}", saved.get("task_sha256", ""))):
                raise ValueError("lease_marker_invalid")
            if require_dead and process_is_alive(saved.get("owner")) is not False:
                raise ValueError("lease_owner_live_or_unknown")
            if {entry.name for entry in directory.iterdir()} != ({_MARKER} if marker is not None else set()):
                raise ValueError("lease_not_empty")
            _ensure_retirement_record(directory, record)
            if marker is not None:
                _delete_by_handle(marker)
        finally:
            if marker is not None:
                marker.Close()
        _delete_by_handle(directory_handle)
    finally:
        if pinned is None:
            directory_handle.Close()


def recover_dead_leases():
    root = _root()
    recovered = 0
    for directory in root.iterdir():
        if not re.fullmatch(_LEASE_NAME, directory.name):
            continue
        try:
            _check_no_reparse(directory / _MARKER)
            with (directory / _MARKER).open("rb") as marker:
                raw = marker.read(4097)
            if len(raw) > 4096:
                continue
            record = json.loads(win32crypt.CryptUnprotectData(raw, _ENTROPY, None, None, 4)[1])
            retire_lease(directory, record, require_dead=True)
            if _strictly_absent(directory):
                finalize_retirement(directory, record)
                recovered += 1
        except Exception:
            continue
    for receipt_path in root.iterdir():
        if not receipt_path.name.endswith(_RETIRE_SUFFIX):
            continue
        name = receipt_path.name[:-len(_RETIRE_SUFFIX)]
        if not re.fullmatch(_LEASE_NAME, name):
            continue
        directory = root / name
        try:
            receipt = _open_locked(receipt_path)
            try:
                record = _read_record(receipt)
            finally:
                receipt.Close()
            if (record.get("directory") != name or process_is_alive(record.get("owner")) is not False):
                continue
            if not _strictly_absent(directory):
                retire_lease(directory, record, require_dead=True)
            if _strictly_absent(directory):
                finalize_retirement(directory, record)
                recovered += 1
        except Exception:
            continue
    return recovered
