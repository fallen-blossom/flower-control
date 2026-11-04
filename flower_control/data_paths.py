"""Read-only physical data-root resolution shared by every local entrypoint.

Windows package file views can redirect an existing file without changing its
printed path. Resolve existing registry/ledger handles, never browser contents,
and refuse split roots rather than creating a second authorization ledger.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import os
from pathlib import Path


class DataPathError(ValueError):
    pass


def _final_existing(path: Path) -> Path:
    if os.name != "nt":
        return path.resolve(strict=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                       wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
    create.restype = wintypes.HANDLE
    final = kernel.GetFinalPathNameByHandleW
    final.argtypes = (wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD)
    final.restype = wintypes.DWORD
    close = kernel.CloseHandle
    close.argtypes = (wintypes.HANDLE,)
    close.restype = wintypes.BOOL
    # Zero access: metadata only. Sharing must not perturb a running browser.
    handle = create(str(path), 0, 7, None, 3, 0x02000000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise DataPathError("data_path_identity_unavailable")
    try:
        size = final(handle, None, 0, 0)
        if not 0 < size <= 32768:
            raise DataPathError("data_path_identity_unavailable")
        buffer = ctypes.create_unicode_buffer(size + 1)
        length = final(handle, buffer, len(buffer), 0)
        if not 0 < length < len(buffer):
            raise DataPathError("data_path_identity_unavailable")
        name = buffer.value
        if name.startswith("\\\\?\\UNC\\"):
            raise DataPathError("network_data_root_rejected")
        if name.startswith("\\\\?\\"):
            name = name[4:]
        return Path(name)
    finally:
        close(handle)


def physical_path(path: Path | str) -> Path:
    """Resolve a file handle or the nearest existing parent without writes."""
    path = Path(path)
    if not path.is_absolute() or str(path).startswith("\\\\"):
        raise DataPathError("data_path_must_be_local_absolute")
    suffix = []
    current = path
    while not current.exists():
        if current.parent == current:
            raise DataPathError("data_path_identity_unavailable")
        suffix.append(current.name)
        current = current.parent
    result = _final_existing(current)
    return result.joinpath(*reversed(suffix))


def resolve_data_root(environment=None) -> Path:
    """Honor a pinned root; otherwise inspect only the known current anchors.

    This does not import/migrate profiles, create files, search other packages,
    or grant authorization. The installed launcher can pin FLOWER_DATA_ROOT
    to the physical root verified while preparing a versioned update.
    """
    env = os.environ if environment is None else environment
    configured = env.get("FLOWER_DATA_ROOT")
    if configured:
        root = Path(configured)
    else:
        local = env.get("LOCALAPPDATA")
        if not local or not Path(local).is_absolute():
            raise DataPathError("local_app_data_unavailable")
        root = Path(local) / "FlowerControl"
    if not root.is_absolute() or str(root).startswith("\\\\"):
        raise DataPathError("data_path_must_be_local_absolute")
    anchors = (root / "profiles" / "active.json",
               root / "state-v1" / "control.sqlite3",
               root / "state-v1" / "jev.json")
    actual = {physical_path(anchor).parent.parent for anchor in anchors if anchor.is_file()}
    if len(actual) > 1:
        raise DataPathError("data_root_split_view")
    if actual:
        resolved = actual.pop()
        if configured and resolved != physical_path(root):
            raise DataPathError("configured_data_root_mismatch")
        return resolved
    return physical_path(root)
