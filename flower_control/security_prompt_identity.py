"""Local, read-only provenance for an already selected Huorong candidate.

This is evidence about one window and the current image on disk, never a task
match or an authorization. No process command lines, logs or other windows are
read. Signature verification reuses the sealed installed native verifier.
"""
from __future__ import annotations

import ctypes
import json
from _ctypes import FreeLibrary
from pathlib import Path
import re

import win32api
import win32con
import win32event
import win32gui
import win32process
import win32file
from win32com.shell import shell, shellcon

from flower_control.control.native import process_creation_filetime
from flower_control.permissions import process_facts


# The legal entity in the trusted signing certificate, not a product resource.
HUORONG_SIGNER_NAMES = frozenset({"北京火绒网络科技有限公司"})


def _expected_images():
    roots = {shell.SHGetFolderPath(0, folder, 0, 0) for folder in
             (shellcon.CSIDL_PROGRAM_FILES, shellcon.CSIDL_PROGRAM_FILESX86)}
    return {str(Path(root) / "Huorong/Sysdiag/bin/HipsTray.exe").casefold() for root in roots}


def _reject_links(path):
    candidate = Path(path)
    if any(item.is_symlink() or item.is_junction() for item in (candidate, *candidate.parents)):
        raise ValueError("security_prompt_image_link_rejected")


def _publisher(path):
    # This is a pure file-verification export. It neither contacts the broker
    # nor opens a desktop. The existing installation seal pins the exact DLL.
    from flower_control.drivers.high_helper import _installed_bundle, _unique_pairs, _digest
    bundle, version = _installed_bundle()
    library_path = bundle.directory / "Flower.UacNative.dll"
    active = json.loads((bundle.directory.parent.parent / "active.json").read_bytes(), object_pairs_hook=_unique_pairs)
    expected = active.get("hashes", {}).get(library_path.name)
    if (active.get("version") != version or type(expected) is not str
            or not re.fullmatch(r"[a-f0-9]{64}", expected)):
        raise ValueError("security_prompt_verifier_unavailable")
    _reject_links(library_path)
    # Retain a read-only handle with no write/delete sharing across loading.
    handle = win32file.CreateFile(str(library_path), win32con.GENERIC_READ, win32con.FILE_SHARE_READ,
                                 None, win32con.OPEN_EXISTING, 0x00200000, None)  # FILE_FLAG_OPEN_REPARSE_POINT
    try:
        if _digest(library_path) != expected:
            raise ValueError("security_prompt_verifier_changed")
        library = ctypes.CDLL(str(library_path), winmode=0x1100)
        try:
            try:
                verify = library.FlowerUacPublisherDetails
                details_available = True
            except AttributeError:
                # Old sealed runtimes still provide useful signer evidence,
                # but cannot establish a vendor for automatic prompt action.
                verify = library.FlowerUacPublisher
                details_available = False
            verify.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint]
            verify.restype = ctypes.c_int
            output = ctypes.create_unicode_buffer(2048)
            code = verify(str(path), output, len(output))
        finally:
            FreeLibrary(library._handle)
    finally:
        handle.Close()
    if code != 0:
        raise ValueError("security_prompt_signature_unavailable")
    if details_available:
        try:
            value = json.loads(output.value, object_pairs_hook=_unique_pairs)
        except Exception:
            raise ValueError("security_prompt_signature_unavailable") from None
        if (type(value) is not dict or set(value) != {"schema", "publisher_key_sha256", "signer_common_name", "signature"}
                or type(value["schema"]) is not int or value["schema"] != 1
                or value["signature"] != "trusted_offline"
                or type(value["signer_common_name"]) is not str
                or not 1 <= len(value["signer_common_name"]) <= 511
                or any(ord(unit) < 32 for unit in value["signer_common_name"])):
            raise ValueError("security_prompt_signature_unavailable")
        signer, subject = value["publisher_key_sha256"], value["signer_common_name"]
    else:
        signer, subject = output.value, None
    if type(signer) is not str or not re.fullmatch(r"[a-fA-F0-9]{64}", signer):
        raise ValueError("security_prompt_signature_unavailable")
    return {"key": signer.lower(), "common_name": subject}


def _window_matches(target):
    return (win32gui.IsWindow(target["hwnd"])
            and win32process.GetWindowThreadProcessId(target["hwnd"])[1] == target["pid"]
            and process_creation_filetime(target["pid"]) == target["process_start_filetime"])


def security_prompt_identity(target):
    """No caller-supplied path/publisher can establish identity.

    A valid signer at the known protected installation path is reported with
    its public key. A signed arbitrary executable or a product/company string
    is insufficient. Fresh native target and permission checks still precede
    every later App/Computer action.
    """
    result = {"state": "unavailable", "not_authorization": True,
              "scope": "selected_window_process_and_current_image", "input_dispatched": False}
    if (type(target) is not dict or any(type(target.get(key)) is not int or target[key] <= 0
            for key in ("pid", "hwnd", "process_start_filetime"))):
        return {**result, "reason": "security_prompt_target_invalid"}
    process = None
    try:
        if not _window_matches(target):
            return {**result, "reason": "security_prompt_target_changed"}
        process = win32api.OpenProcess(win32con.PROCESS_QUERY_LIMITED_INFORMATION | win32con.SYNCHRONIZE,
                                      False, target["pid"])
        if win32event.WaitForSingleObject(process, 0) != win32event.WAIT_TIMEOUT:
            return {**result, "reason": "security_prompt_target_changed"}
        image, integrity = process_facts(target["pid"])
        if str(Path(image)).casefold() not in _expected_images():
            return {**result, "state": "rejected", "reason": "security_prompt_image_not_expected"}
        _reject_links(image)
        signer = _publisher(image)
        _reject_links(image)
        after_image, after_integrity = process_facts(target["pid"])
        if (not _window_matches(target) or after_image != image or after_integrity != integrity
                or win32event.WaitForSingleObject(process, 0) != win32event.WAIT_TIMEOUT):
            return {**result, "reason": "security_prompt_target_changed"}
        return {**result, "state": "verified", "image": image,
                "integrity_rid": integrity, "publisher_key_sha256": signer["key"],
                "signer_common_name": signer["common_name"],
                "vendor_verified": signer["common_name"] in HUORONG_SIGNER_NAMES,
                "signature": "trusted_offline", "window_identity": dict(target),
                "task_match": "not_evaluated", "business_result": "unknown"}
    except Exception:
        # This optional provenance never replaces mandatory privacy/Stop checks
        # in the caller, and failures disclose no private path or exception text.
        return {**result, "reason": "security_prompt_identity_unavailable"}
    finally:
        if process is not None:
            process.Close()
