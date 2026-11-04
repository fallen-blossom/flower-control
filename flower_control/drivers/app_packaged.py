"""Thin Windows registered-package activation; no shell, elevation or new grants."""
from __future__ import annotations
import ctypes as c
from ctypes import wintypes as w
from pathlib import Path
import re
import time
import uuid
import xml.etree.ElementTree as ET
import pythoncom
import win32api
import win32con

from .app_lifecycle import AppLifecycleError, _visible_windows
from .app_process_chain import handle_times
from flower_control.browsers import is_supported_browser_image

U32 = c.c_uint32
kernel = c.WinDLL("kernel32")


def _api(name, args):
    fn = getattr(kernel, name)
    fn.argtypes, fn.restype = args, w.LONG
    return fn


_packages = _api("GetPackagesByPackageFamily", [w.LPCWSTR, c.POINTER(U32),
    c.POINTER(w.LPWSTR), c.POINTER(U32), w.LPWSTR])
_open = _api("OpenPackageInfoByFullName", [w.LPCWSTR, U32, c.POINTER(c.c_void_p)])
_close = _api("ClosePackageInfo", [c.c_void_p])
_ids = _api("GetPackageApplicationIds", [c.c_void_p, c.POINTER(U32), c.POINTER(c.c_ubyte), c.POINTER(U32)])


def _string(name, first):
    fn = _api(name, [w.LPCWSTR if isinstance(first, str) else w.HANDLE, c.POINTER(U32), w.LPWSTR])
    length = U32()
    if fn(first, c.byref(length), None) != 122 or not 1 <= length.value <= 65536:
        raise AppLifecycleError("package_identity_unavailable")
    buffer = c.create_unicode_buffer(length.value)
    if fn(first, c.byref(length), buffer) != 0:
        raise AppLifecycleError("package_identity_unavailable")
    return buffer.value


def parse_ids(buffer, count):
    """Pointers and UTF-16 strings must remain inside the same SDK buffer."""
    size, start = c.sizeof(buffer), c.addressof(buffer)
    pointers_size = count*c.sizeof(c.c_void_p)
    if not 0 < count <= 128 or pointers_size > size:
        raise AppLifecycleError("package_registration_unverified")
    result = []
    for pointer in (c.c_void_p*count).from_buffer(buffer):
        if pointer is None or not start+pointers_size <= pointer < start+size or (pointer-start)%2:
            raise AppLifecycleError("package_registration_unverified")
        raw = bytes(buffer)[pointer-start:]
        end = next((i for i in range(0, min(len(raw), 2048), 2) if raw[i:i+2] == b"\0\0"), None)
        if end is None:
            raise AppLifecycleError("package_registration_unverified")
        result.append(raw[:end].decode("utf-16-le"))
    return result


def registered_application(aumid):
    if type(aumid) is not str or not re.fullmatch(r"[A-Za-z0-9_.-]{1,192}![A-Za-z0-9_.-]{1,64}", aumid):
        raise AppLifecycleError("invalid_application_id")
    family, app_id = aumid.split("!")
    count, length = U32(), U32()
    error = _packages(family, c.byref(count), None, c.byref(length), None)
    if error != 122 or not 0 < count.value <= 32 or not 0 < length.value <= 65536:
        raise AppLifecycleError("application_not_registered")
    names, strings = (w.LPWSTR*count.value)(), c.create_unicode_buffer(length.value)
    if _packages(family, c.byref(count), names, c.byref(length), strings) != 0:
        raise AppLifecycleError("package_registration_changed")
    registered = []
    for full_name in names[:count.value]:
        ref = c.c_void_p()
        if _open(full_name, 0, c.byref(ref)) != 0:
            raise AppLifecycleError("package_registration_unverified")
        try:
            size, apps = U32(), U32()
            if _ids(ref, c.byref(size), None, c.byref(apps)) != 122 or not 0 < size.value <= 65536:
                raise AppLifecycleError("package_registration_unverified")
            buffer = (c.c_ubyte*size.value)()
            if _ids(ref, c.byref(size), buffer, c.byref(apps)) != 0:
                raise AppLifecycleError("package_registration_changed")
            if aumid not in parse_ids(buffer, apps.value):
                continue
            root = Path(_string("GetPackagePathByFullName", full_name)).resolve(strict=True)
            manifest = root/"AppxManifest.xml"
            if manifest.stat().st_size > 4_000_000:
                raise AppLifecycleError("package_manifest_unverified")
            app = next((e for e in ET.fromstring(manifest.read_bytes()).iter()
                        if e.tag.rsplit('}', 1)[-1] == "Application" and e.get("Id") == app_id), None)
            relative = app.get("Executable") if app is not None else None
            if not relative or Path(relative).is_absolute():
                raise AppLifecycleError("package_executable_unverified")
            executable = (root/relative).resolve(strict=True)
            if root not in executable.parents or executable.suffix.lower() != ".exe" or not executable.is_file():
                raise AppLifecycleError("package_executable_unverified")
            if is_supported_browser_image(executable) or executable.name.lower() in {"consent.exe", "credentialuibroker.exe", "logonui.exe"}:
                raise AppLifecycleError("app_launch_target_excluded")
            registered.append((full_name, str(executable)))
        finally:
            _close(ref)
    if not registered:
        raise AppLifecycleError("application_not_registered")
    return family, registered


class GUID(c.Structure):
    _fields_ = [("bytes", c.c_ubyte*16)]

    @classmethod
    def from_string(cls, value):
        return cls((c.c_ubyte*16).from_buffer_copy(uuid.UUID(value).bytes_le))


def activate(aumid):
    ole = c.OleDLL("ole32")
    create = ole.CoCreateInstance
    create.argtypes = [c.POINTER(GUID), c.c_void_p, U32, c.POINTER(GUID), c.POINTER(c.c_void_p)]
    create.restype = w.HRESULT
    clsid = GUID.from_string("45BA127D-10A8-46EA-8AB7-56EA9078943C")
    iid = GUID.from_string("2e941141-7f97-4756-ba1d-9decde894a3d")
    pointer = c.c_void_p()
    pythoncom.CoInitialize()
    try:
        create(c.byref(clsid), None, 4, c.byref(iid), c.byref(pointer))
        table = c.cast(pointer, c.POINTER(c.POINTER(c.c_void_p))).contents
        release = c.WINFUNCTYPE(U32, c.c_void_p)(table[2])
        try:
            fn = c.WINFUNCTYPE(w.HRESULT, c.c_void_p, w.LPCWSTR, w.LPCWSTR, U32, c.POINTER(U32))(table[3])
            pid = U32()
            # AO_NONE. No background/prelaunch, debugging or admin options.
            hresult = fn(pointer, aumid, "", 0, c.byref(pid))
            if hresult < 0 or not pid.value:
                # The call crossed the OS boundary. Do not infer zero effect
                # from a failing HRESULT, or automatically try another launcher.
                raise RuntimeError("application_activation_outcome_uncertain")
            return pid.value
        finally:
            release(pointer)
    finally:
        pythoncom.CoUninitialize()


def launch_packaged_application(aumid, *, mode, args, preflight, window_wait_seconds=3):
    if mode != "normal" or args != []:
        raise AppLifecycleError("packaged_launch_normal_without_arguments_required")
    family, registered = registered_application(aumid)
    preflight()
    pid = activate(aumid)  # Exactly one OS activation; failures are never retried.
    result = {"dispatched": True, "aumid": aumid, "pid": pid,
              "requested_mode": mode, "automatic_window_selection": False,
              "next_step": "list_windows_and_match_exact_process_identity_then_select"}
    try:
        # handle_times also waits on process liveness; querying its creation
        # time alone does not grant WaitForSingleObject access.
        handle = win32api.OpenProcess(
            win32con.PROCESS_QUERY_LIMITED_INFORMATION | win32con.SYNCHRONIZE, False, pid)
        try:
            created = handle_times(int(handle))[0]
            if (_string("GetApplicationUserModelId", int(handle)) != aumid
                    or _string("GetPackageFamilyName", int(handle)) != family
                    or _string("GetPackageFullName", int(handle)) not in {item[0] for item in registered}):
                raise AppLifecycleError("package_process_identity_mismatch")
        finally:
            handle.Close()
        result["process_start_filetime"] = created
        deadline = time.monotonic() + window_wait_seconds
        while True:
            preflight()
            windows = _visible_windows(pid, created)
            if windows or time.monotonic() >= deadline:
                return {**result, "state": "window_candidates" if windows else "window_pending",
                        "windows": windows, "window_selection_required": bool(windows),
                        "identity_basis": "registered_package_and_os_activation_process",
                        "package_full_names": [item[0] for item in registered]}
            time.sleep(.05)
    except Exception as error:
        return {**result, "state": "outcome_uncertain", "reason": getattr(error, "code", "package_process_identity_unavailable")}
