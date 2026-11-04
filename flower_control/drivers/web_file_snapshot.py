"""Internal locked snapshot primitive; it does not authorize or expose a path.

Only a future trusted native picker may supply ``selected_path``.  This module
is not a public upload entrypoint and a model-provided path is not a grant.
"""
from __future__ import annotations

import hashlib
import ctypes
import os
from pathlib import Path

import win32con
import win32file

from flower_control.control.state import ControlError
from .web_artifacts import _check_no_reparse

MAX_SELECTED_BYTES = 1_000_000_000
_OPEN_REPARSE_POINT = 0x00200000
_DELETE_ON_CLOSE = 0x04000000
_REPARSE_ATTRIBUTE = 0x400
_DELETE = 0x00010000


def _delete_by_handle(handle):
    """Delete only the opened file, never a subsequently replaced path."""
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    function = kernel.SetFileInformationByHandle
    function.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32)
    function.restype = ctypes.c_int
    delete = ctypes.c_byte(1)  # FILE_DISPOSITION_INFO.DeleteFile
    if not function(int(handle), 4, ctypes.byref(delete), ctypes.sizeof(delete)):
        raise ctypes.WinError(ctypes.get_last_error())


def _identity(handle):
    info = win32file.GetFileInformationByHandle(handle)
    return (info[4], info[8], info[9], (info[5] << 32) | info[6], info[3])


def identity_wire(identity):
    return [*identity[:4], identity[4].isoformat()]


def _open_locked(path, access=win32con.GENERIC_READ, creation=win32con.OPEN_EXISTING, *, delete_on_close=False, share_delete=False, share_write=False):
    share = (win32con.FILE_SHARE_READ | (win32con.FILE_SHARE_DELETE if delete_on_close or share_delete else 0)
             | (win32con.FILE_SHARE_WRITE if share_write else 0))
    flags = _OPEN_REPARSE_POINT | (_DELETE_ON_CLOSE if delete_on_close else 0)
    handle = win32file.CreateFile(str(path), access, share, None, creation, flags, None)
    try:
        info = win32file.GetFileInformationByHandle(handle)
        if (info[0] & _REPARSE_ATTRIBUTE or info[0] & win32con.FILE_ATTRIBUTE_DIRECTORY
                or win32file.GetFileType(handle) != win32file.FILE_TYPE_DISK):
            raise ControlError("selected_file_not_regular")
        actual = win32file.GetFinalPathNameByHandle(handle, 0)
        if actual.startswith("\\\\?\\"):
            actual = actual[4:]
        if os.path.normcase(os.path.abspath(actual)) != os.path.normcase(os.path.abspath(str(path))):
            raise ControlError("selected_file_path_changed")
        return handle
    except BaseException:
        handle.Close()
        raise


class LockedSnapshot:
    """Keep source and snapshot locked against writes/replacement until close."""
    def __init__(self, selected_path: Path, *, check, task_key="synthetic", expected_identity=None):
        self.source = Path(selected_path)
        self.directory = None
        self.path = None
        self.source_handle = self.snapshot_handle = None
        self.snapshot_id = None
        self.lease_record = None
        self.lease_handles = None
        self.sha256 = None
        self.size = None
        if not self.source.is_absolute() or ".." in self.source.parts or not self.source.name:
            raise ControlError("selected_file_path_invalid")
        try:
            check()
            _check_no_reparse(self.source)
            self.source_handle = _open_locked(self.source)
            source_id = _identity(self.source_handle)
            if expected_identity is not None and identity_wire(source_id) != expected_identity:
                raise ControlError("selected_file_changed")
            if source_id[3] > MAX_SELECTED_BYTES:
                raise ControlError("selected_file_too_large")
            from .web_upload_recovery import create_lease
            self.directory, self.lease_record, self.lease_handles = create_lease(task_key)
            self.path = self.directory / self.source.name
            self.snapshot_handle = _open_locked(self.path, win32con.GENERIC_READ | win32con.GENERIC_WRITE | _DELETE,
                                                win32con.CREATE_NEW, delete_on_close=True)
            digest = hashlib.sha256()
            copied = 0
            while True:
                check()
                _, block = win32file.ReadFile(self.source_handle, 1024 * 1024)
                if not block:
                    break
                copied += len(block)
                if copied > source_id[3]:
                    raise ControlError("selected_file_changed")
                digest.update(block)
                _, written = win32file.WriteFile(self.snapshot_handle, block)
                if written != len(block):
                    raise ControlError("selected_file_short_write")
            win32file.FlushFileBuffers(self.snapshot_handle)
            if copied != source_id[3] or _identity(self.source_handle) != source_id:
                raise ControlError("selected_file_changed")
            self.source_id = source_id
            self.snapshot_id = _identity(self.snapshot_handle)
            win32file.SetFilePointer(self.snapshot_handle, 0, win32con.FILE_BEGIN)
            reread = hashlib.sha256()
            while True:
                check()
                _, block = win32file.ReadFile(self.snapshot_handle, 1024 * 1024)
                if not block:
                    break
                reread.update(block)
            if reread.digest() != digest.digest():
                raise ControlError("selected_file_changed")
            win32file.SetFilePointer(self.snapshot_handle, 0, win32con.FILE_BEGIN)
            self.size = copied
            self.sha256 = digest.hexdigest()
            self.verify(check=check)
        except BaseException:
            try:
                self.close()
            except Exception:
                raise ControlError("file_selection_cleanup_unverified") from None
            raise

    def verify(self, *, check):
        check()
        for path, handle, expected in ((self.source, self.source_handle, self.source_id),
                                      (self.path, self.snapshot_handle, self.snapshot_id)):
            _check_no_reparse(path)
            if _identity(handle) != expected:
                raise ControlError("selected_file_changed")
            current = _open_locked(path, share_delete=(path == self.path), share_write=(path == self.path))
            try:
                if _identity(current) != expected:
                    raise ControlError("selected_file_changed")
            finally:
                current.Close()
        check()

    def close(self):
        if self.source_handle is not None:
            self.source_handle.Close()
            self.source_handle = None
        owned = self.snapshot_id
        if self.snapshot_handle is not None:
            # A partially created file is also ours while this handle is held.
            owned = _identity(self.snapshot_handle)
            self.snapshot_handle.Close()
            self.snapshot_handle = None
        if owned is not None and self.path.exists():
            try:
                current = _open_locked(self.path, win32con.GENERIC_READ | _DELETE)
                try:
                    unchanged = _identity(current) == owned
                    if unchanged:
                        _delete_by_handle(current)
                finally:
                    current.Close()
            except FileNotFoundError:
                pass
        if self.directory is not None:
            from .web_upload_recovery import retire_lease, finalize_retirement
            if self.lease_record is not None:
                if self.lease_handles is not None:
                    retire_lease(self.directory, self.lease_record, require_dead=False, pinned=self.lease_handles)
                    for handle in reversed(self.lease_handles):
                        handle.Close()
                    self.lease_handles = None
                finalize_retirement(self.directory, self.lease_record)
                self.lease_record = None
