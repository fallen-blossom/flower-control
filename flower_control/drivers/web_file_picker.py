"""Internal native file-picker process; never accepts a caller-supplied path."""
from __future__ import annotations

import ctypes
from ctypes import wintypes
from pathlib import Path
from urllib.parse import urlsplit

from flower_control.control.state import ControlError
from .web_artifacts import _check_no_reparse
from .web_file_snapshot import _open_locked, _identity, identity_wire


class _OpenFileName(ctypes.Structure):
    _fields_ = [("lStructSize", wintypes.DWORD), ("hwndOwner", wintypes.HWND),
        ("hInstance", wintypes.HINSTANCE), ("lpstrFilter", wintypes.LPCWSTR),
        ("lpstrCustomFilter", wintypes.LPWSTR), ("nMaxCustFilter", wintypes.DWORD),
        ("nFilterIndex", wintypes.DWORD), ("lpstrFile", wintypes.LPWSTR),
        ("nMaxFile", wintypes.DWORD), ("lpstrFileTitle", wintypes.LPWSTR),
        ("nMaxFileTitle", wintypes.DWORD), ("lpstrInitialDir", wintypes.LPCWSTR),
        ("lpstrTitle", wintypes.LPCWSTR), ("Flags", wintypes.DWORD),
        ("nFileOffset", wintypes.WORD), ("nFileExtension", wintypes.WORD),
        ("lpstrDefExt", wintypes.LPCWSTR), ("lCustData", wintypes.LPARAM),
        ("lpfnHook", ctypes.c_void_p), ("lpTemplateName", wintypes.LPCWSTR),
        ("pvReserved", ctypes.c_void_p), ("dwReserved", wintypes.DWORD),
        ("FlagsEx", wintypes.DWORD)]


class _NmHdr(ctypes.Structure):
    _fields_ = [("hwndFrom", wintypes.HWND), ("idFrom", ctypes.c_size_t), ("code", wintypes.UINT)]


class _OfNotify(ctypes.Structure):
    _fields_ = [("hdr", _NmHdr), ("lpOFN", ctypes.POINTER(_OpenFileName)), ("pszFile", wintypes.LPCWSTR)]


class PickerFileLock:
    """Open and hold the selected file in the dialog's FILEOK callback."""
    def __init__(self):
        self.path = None
        self.handle = None
        self.identity = None

    def accept(self, name):
        if self.handle is not None:
            self.handle.Close()
            self.handle = None
        path = Path(name)
        if not path.is_absolute() or ".." in path.parts or len(str(path)) > 8000:
            raise ControlError("selected_file_path_invalid")
        _check_no_reparse(path)
        handle = _open_locked(path)
        self.path, self.handle = str(path), handle
        self.identity = identity_wire(_identity(handle))

    def close(self):
        if self.handle is not None:
            self.handle.Close()
            self.handle = None


def picker_origin(value):
    """Accept only a canonical, non-secret origin supplied by the Web worker."""
    if type(value) is not str or not 1 <= len(value) <= 260:
        raise ControlError("picker_origin_invalid")
    try:
        parsed = urlsplit(value)
        if (parsed.scheme not in ("http", "https") or not parsed.hostname or
                parsed.username is not None or parsed.password is not None or
                parsed.path or parsed.query or parsed.fragment or
                any(ord(c) < 33 or ord(c) > 126 for c in value)):
            raise ValueError()
        host = parsed.hostname
        if ":" in host:
            host = "[" + host + "]"
        origin = parsed.scheme + "://" + host + (f":{parsed.port}" if parsed.port is not None else "")
        if value != origin:
            raise ValueError()
        return origin
    except ValueError:
        raise ControlError("picker_origin_invalid") from None


def choose_file(origin):
    """Show one Windows dialog. Result must remain on its private IPC pipe."""
    origin = picker_origin(origin)
    buffer = ctypes.create_unicode_buffer(32768)
    title = "Flower：选择本次上传到 " + origin + " 的文件"
    request = _OpenFileName()
    request.lStructSize = ctypes.sizeof(request)
    request.lpstrFilter = "所有文件\0*.*\0\0"
    request.lpstrFile = ctypes.cast(buffer, wintypes.LPWSTR)
    request.nMaxFile = len(buffer)
    request.lpstrTitle = title
    locked = PickerFileLock()
    hook_type = ctypes.WINFUNCTYPE(ctypes.c_size_t, wintypes.HWND, wintypes.UINT,
                                   wintypes.WPARAM, wintypes.LPARAM)
    user = ctypes.WinDLL("user32", use_last_error=True)
    user.SetWindowLongPtrW.argtypes = (wintypes.HWND, ctypes.c_int, ctypes.c_ssize_t)
    user.SetWindowLongPtrW.restype = ctypes.c_ssize_t
    user.MessageBoxW.argtypes = (wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.UINT)
    user.MessageBoxW.restype = ctypes.c_int
    @hook_type
    def hook(hwnd, message, _wparam, lparam):
        if message != 0x004E or not lparam:
            return 0
        notification = ctypes.cast(lparam, ctypes.POINTER(_OfNotify)).contents
        if notification.hdr.code != (-606 & 0xffffffff):
            return 0
        try:
            locked.accept(notification.lpOFN.contents.lpstrFile)
            return 0
        except Exception:
            locked.close()
            user.SetWindowLongPtrW(hwnd, 0, 1)  # DWLP_MSGRESULT
            user.MessageBoxW(hwnd, "无法锁定此文件。请关闭正在写入它的程序，或选择其他文件。",
                             "Flower 文件选择", 0x30)
            return 1
    request.lpfnHook = ctypes.cast(hook, ctypes.c_void_p)
    # One existing file; request no recent-files entry. The picker runs in its
    # own child, so any common-dialog current-directory change stays there.
    request.Flags = (0x00001000 | 0x00000800 | 0x00000008 | 0x02000000 |
                     0x00100000 | 0x00080000 | 0x00000020)
    common = ctypes.WinDLL("comdlg32", use_last_error=True)
    common.GetOpenFileNameW.argtypes = (ctypes.POINTER(_OpenFileName),)
    common.GetOpenFileNameW.restype = wintypes.BOOL
    common.CommDlgExtendedError.restype = wintypes.DWORD
    if not common.GetOpenFileNameW(ctypes.byref(request)):
        locked.close()
        if common.CommDlgExtendedError():
            raise ControlError("picker_dialog_failed")
        return None
    if locked.handle is None or locked.path != buffer.value:
        locked.close()
        raise ControlError("picker_file_binding_failed")
    return locked
