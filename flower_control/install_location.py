"""Read-only installation discovery. User text and environment never select code.

The installer owns the HKLM record and the matching protected manifest. An
explicit layout is only a preparation value, not an admitted installation.
"""
from __future__ import annotations

from contextlib import ExitStack
import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import uuid

REGISTRATION_BASE = r"SOFTWARE\FlowerControl\Installations"
MANIFEST_NAME = "installation-location.json"
_TRUSTED = {"S-1-5-18", "S-1-5-32-544",
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"}
_MUTATION = 0x500D0156  # Includes DELETE, WRITE_DAC/OWNER, FILE_DELETE_CHILD.
_PARENT_MUTATION = 0x100C0040  # A volume root cannot itself be renamed/deleted.
_SID = re.compile(r"S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+")


class InstallLocationError(ValueError):
    pass


@dataclass(frozen=True)
class InstallationLocation:
    root: Path
    program_root: Path
    data_root: Path
    cache_root: Path
    packages_root: Path
    legacy: bool = False
    user_sid: str = ""
    installation_id: str = ""

    @property
    def registration_path(self):
        return "HKEY_LOCAL_MACHINE\\" + REGISTRATION_BASE + "\\" + self.user_sid


def _local_path(value):
    if not isinstance(value, (str, Path)):
        raise InstallLocationError("installation_path_rejected")
    text = str(value)
    path = Path(text)
    if (not path.is_absolute() or text.startswith("\\\\") or path.parent == path
            or any(p in {".", ".."} or p.endswith((" ", ".")) for p in text.replace("\\", "/").split("/")[1:])
            or any(c in text for c in "*?\x00") or ":" in text[2:]):
        raise InstallLocationError("installation_path_rejected")
    return Path(os.path.abspath(path))


def prepare_location(root, user_sid=""):
    """Calculate a candidate layout; does not read/write registration or grant trust."""
    root = _local_path(root)
    if user_sid and not _SID.fullmatch(user_sid):
        raise InstallLocationError("installation_user_rejected")
    return InstallationLocation(root, root / "Program", root / "Data", root / "Cache", root / "Packages", user_sid=user_sid)


def known_folder(name):
    """Windows known folders, independent of caller-controlled environment."""
    ids = {"ProgramFiles": "905e63b6-c1bf-494e-b29c-65b732d3d21a",
           "LocalAppData": "f1b32785-6fba-4fcf-9d55-7b8e7f157091"}
    class GUID(ctypes.Structure):
        _fields_ = [("bytes", ctypes.c_byte * 16)]
    guid = GUID.from_buffer_copy(uuid.UUID(ids[name]).bytes_le)
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    function = shell.SHGetKnownFolderPath
    function.argtypes = [ctypes.POINTER(GUID), wintypes.DWORD, wintypes.HANDLE, ctypes.POINTER(ctypes.c_void_p)]
    function.restype = ctypes.c_long
    pointer = ctypes.c_void_p()
    if function(ctypes.byref(guid), 0, None, ctypes.byref(pointer)) != 0:
        raise InstallLocationError("installation_known_folder_unavailable")
    try:
        return Path(ctypes.wstring_at(pointer))
    finally:
        free = ctypes.WinDLL("ole32").CoTaskMemFree
        free.argtypes = [ctypes.c_void_p]
        free(pointer)


def _current_sid():
    import win32api
    import win32con
    import win32security
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    try:
        return win32security.ConvertSidToStringSid(win32security.GetTokenInformation(token, win32security.TokenUser)[0])
    finally:
        token.Close()


def _require_acl(descriptor, mutation):
    import win32security
    owner = descriptor.GetSecurityDescriptorOwner()
    acl = descriptor.GetSecurityDescriptorDacl()
    if owner is None or win32security.ConvertSidToStringSid(owner) not in _TRUSTED or acl is None:
        raise InstallLocationError("installation_unprotected")
    for index in range(acl.GetAceCount()):
        ace = acl.GetAce(index)
        kind, flags = ace[0]
        # Object/callback allow ACEs cannot be safely treated as a deny.
        if kind in {0, 5, 9, 11} and not flags & 8 and ace[1] & mutation:
            # CREATOR_OWNER is an inheritance placeholder, not a token SID.
            # The real owner of every admitted object is checked above.
            if win32security.ConvertSidToStringSid(ace[-1]) not in _TRUSTED | {"S-1-3-0"}:
                raise InstallLocationError("installation_unprotected")


def require_protected_path(path, *, _parent_only=False):
    """Verify every existing component and pin names while inspecting ACLs.

    A writable ancestor can replace a protected child via DELETE_CHILD. We
    reject that ancestor; we never change the volume's permissions to admit it.
    """
    import win32con
    import win32file
    import win32security
    from flower_control.data_paths import _final_existing
    path = _local_path(path)
    chain = list(reversed(path.parents)) + ([] if _parent_only else [path])
    with ExitStack() as stack:
        for current in chain:
            if not current.exists():
                raise InstallLocationError("installation_path_missing")
            attributes = win32file.GetFileAttributes(str(current))
            if attributes & 0x400:
                raise InstallLocationError("installation_link_rejected")
            handle = win32file.CreateFile(str(current), win32con.READ_CONTROL,
                win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE, None,
                win32con.OPEN_EXISTING, win32con.FILE_FLAG_BACKUP_SEMANTICS | 0x00200000, None)
            stack.callback(handle.Close)
            if os.path.normcase(str(_final_existing(current))) != os.path.normcase(str(current)):
                raise InstallLocationError("installation_path_identity_changed")
            descriptor = win32security.GetSecurityInfo(handle, win32security.SE_FILE_OBJECT,
                win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION)
            _require_acl(descriptor, _PARENT_MUTATION if current.parent == current else _MUTATION)


def validate_preparation_path(root):
    """Read-only preflight before UAC; never take ownership of user folders."""
    root = _local_path(root)
    if not root.parent.is_dir():
        raise InstallLocationError("installation_parent_must_exist")
    require_protected_path(root, _parent_only=not root.exists())
    return root


def _read_registration(sid):
    import winreg
    import win32security
    key_path = REGISTRATION_BASE + "\\" + sid
    parts = key_path.split("\\")
    for index in range(1, len(parts) + 1):
        try:
            parent = _open_registry_key("\\".join(parts[:index]))
        except FileNotFoundError:
            return None
        with parent:
            descriptor = win32security.GetSecurityInfo(int(parent), win32security.SE_REGISTRY_KEY,
                win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION)
            _require_acl(descriptor, 0x500D0026)  # SetValue/CreateSubKey/CreateLink/delete/security.
            try:
                winreg.QueryValueEx(int(parent), "SymbolicLinkValue")
            except FileNotFoundError:
                pass
            else:
                raise InstallLocationError("installation_registry_link_rejected")
            if index == len(parts):
                text, kind = winreg.QueryValueEx(int(parent), "Record")
                if kind != winreg.REG_SZ or not isinstance(text, str) or len(text) > 32768:
                    raise InstallLocationError("installation_registration_rejected")
                return _decode(text)


def _open_registry_key(path):
    import winreg
    function = ctypes.WinDLL("advapi32", use_last_error=True).RegOpenKeyExW
    function.argtypes = [wintypes.HKEY, wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.HKEY)]
    function.restype = wintypes.LONG
    handle = wintypes.HKEY()
    # REG_OPTION_OPEN_LINK opens the registry link itself. Normal OpenKey
    # follows it before callers can distinguish a damaged link from absence.
    machine = wintypes.HKEY(ctypes.c_int(int(winreg.HKEY_LOCAL_MACHINE)).value)
    result = function(machine, path, 8, winreg.KEY_READ | winreg.KEY_WOW64_64KEY, ctypes.byref(handle))
    if result in {2, 3}:
        raise FileNotFoundError(result, "installation_registration_missing")
    if result:
        raise InstallLocationError("installation_registration_unavailable")
    class RegistryHandle:
        def __int__(self):
            return handle.value
        def __enter__(self):
            return self
        def __exit__(self, *_):
            winreg.CloseKey(handle.value)
    return RegistryHandle()


def _decode(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise InstallLocationError("installation_schema_rejected")
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique)


def discover_installation(user_sid=None):
    sid = user_sid or _current_sid()
    if not _SID.fullmatch(sid):
        raise InstallLocationError("installation_user_rejected")
    try:
        record = _read_registration(sid)
        if record is None:
            root = known_folder("ProgramFiles") / "FlowerControl"
            data = known_folder("LocalAppData") / "FlowerControl"
            return InstallationLocation(root, root / "HighHelper", data, data / "cache", root / "Packages", True, sid)
        if (type(record) is not dict or set(record) != {"schema", "installation_id", "user_sid", "root", "manifest_sha256"}
                or type(record["schema"]) is not int or record["schema"] != 1 or record["user_sid"] != sid
                or not re.fullmatch(r"[a-f0-9]{32}", record["installation_id"])
                or not re.fullmatch(r"[a-f0-9]{64}", record["manifest_sha256"])):
            raise InstallLocationError("installation_registration_rejected")
        location = prepare_location(record["root"], sid)
        manifest_path = location.program_root / MANIFEST_NAME
        require_protected_path(manifest_path)
        if manifest_path.stat().st_size > 131072:
            raise InstallLocationError("installation_manifest_rejected")
        raw = manifest_path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != record["manifest_sha256"]:
            raise InstallLocationError("installation_manifest_changed")
        manifest = _decode(raw)
        fields = {"schema", "installation_id", "user_sid", "root", "program_root", "data_root", "cache_root", "packages_root", "host_bindings"}
        if (type(manifest) is not dict or set(manifest) != fields or type(manifest["schema"]) is not int
                or manifest["schema"] != 1 or manifest["user_sid"] != sid
                or manifest["installation_id"] != record["installation_id"]
                or type(manifest["host_bindings"]) is not list or len(manifest["host_bindings"]) > 32
                or any(type(row) is not dict for row in manifest["host_bindings"])):
            raise InstallLocationError("installation_manifest_rejected")
        for field in ("root", "program_root", "data_root", "cache_root", "packages_root"):
            if _local_path(manifest[field]) != getattr(location, field):
                raise InstallLocationError("installation_layout_mismatch")
        return InstallationLocation(**{**location.__dict__, "installation_id": record["installation_id"]})
    except InstallLocationError:
        raise
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise InstallLocationError("installation_discovery_failed") from error


def program_root(user_sid=None):
    return discover_installation(user_sid).program_root
