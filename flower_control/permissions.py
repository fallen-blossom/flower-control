"""Local user policy, shared by all channels; never an MCP permission writer.

Production state is owned by the High tray under the protected helper root.
Tests inject an explicit reader; environment variables cannot redirect policy.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import hashlib
import json
import ntpath
import re
import struct
from functools import lru_cache
from pathlib import Path

import win32api
import win32con
import win32gui
import win32process
import win32security
import pywintypes
import win32file
from win32com.shell import shell, shellcon

# Include deleting a child through its parent, not only deleting the file itself.
POLICY_MUTATION_RIGHTS = 0x500D0156


class PermissionError(RuntimeError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


@lru_cache(maxsize=1)
def user_sid():
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    try:
        return win32security.ConvertSidToStringSid(
            win32security.GetTokenInformation(token, win32security.TokenUser)[0])
    finally:
        token.Close()


def production_path():
    from flower_control.install_location import discover_installation
    return discover_installation(user_sid()).program_root / "permissions" / (user_sid() + ".json")


def uac_policy_path(path):
    return path.with_name(path.stem + ".uac.json")


def storage_revision(common, uac, *, uac_error=None):
    """Bind presence and exact bytes of both files, independently of JSON order."""
    if common is None and uac is None and uac_error is None:
        return "absent"
    digest = hashlib.sha256(b"FlowerControl.UserPermissions.storage.v1\0")
    for raw in (common, uac):
        digest.update(b"\0" if raw is None else b"\1" + struct.pack("<Q", len(raw)) + raw)
    if uac_error is not None:
        # Unreadable bytes cannot authorize UAC or be used for a later save.
        digest.update(b"error\0" + uac_error.encode("utf-8"))
    return digest.hexdigest()


def validate_uac_policy(value, sid):
    required = {"Schema", "Revision", "UserSid", "CommonRevision", "UacMode", "UacAllowlist"}
    optional = {"AdminLaunchEnabled", "UacCancellationScope", "AdminLaunchAllowlist", "AuthorityTier",
                "AdminLaunchMode", "DeniedAdminWindowApplications", "DeniedAdminLaunchApplications",
                "DeniedUacApplications", "SemanticDelegation"}
    if (type(value) is not dict or not required <= set(value) <= required | optional
            or type(value["Schema"]) is not int or value["Schema"] not in (1, 2)
            or type(value["CommonRevision"]) is not str
            or value["CommonRevision"] != "absent" and re.fullmatch("[a-f0-9]{64}", value["CommonRevision"]) is None):
        raise PermissionError("user_policy_invalid")
    tier = value.get("AuthorityTier")
    if tier is not None and (type(tier) is not int or not -1 <= tier <= 3):
        raise PermissionError("user_policy_invalid")
    if value.get("AdminLaunchMode", "allowlist") not in {"allowlist", "semantic"}:
        raise PermissionError("user_policy_invalid")
    delegation = value.get("SemanticDelegation")
    if delegation is not None:
        if (type(delegation) is not dict or set(delegation) not in (
                {"Schema", "Id", "UserSid", "HostKind"},
                {"Schema", "Id", "UserSid", "HostKind", "AdditionalHostKind"})
                or type(delegation["Schema"]) is not int
                or not (delegation["Schema"] == 1 and "AdditionalHostKind" not in delegation
                        or delegation["Schema"] == 2 and delegation.get("AdditionalHostKind") == "dsh-desktop")
                or type(delegation["Id"]) is not str or re.fullmatch("[a-f0-9]{32}", delegation["Id"]) is None
                or delegation["UserSid"] != sid or delegation["HostKind"] != "codex"):
            raise PermissionError("user_policy_invalid")
        # This reader cannot issue or renew the protected High delegation.
        # Its content is deliberately absent from the public policy wire.
    for name in ("DeniedAdminLaunchApplications", "DeniedUacApplications"):
        rows = value.get(name, [])
        if type(rows) is not list or len(rows) > 128:
            raise PermissionError("user_policy_invalid")
        for row in rows:
            validate_uac_application(row)
    for row in value.get("DeniedAdminWindowApplications", []):
        if (type(row) is not dict or set(row) != {"Path", "TitleContains", "Enabled"}
                or type(row["TitleContains"]) is not str or len(row["TitleContains"]) > 160
                or type(row["Enabled"]) is not bool):
            raise PermissionError("user_policy_invalid")
        canonical_path(row["Path"])
    normalized = validate(dict(default_policy(sid), Revision=value["Revision"], UserSid=value["UserSid"],
                               UacMode=value["UacMode"], UacAllowlist=value["UacAllowlist"],
                               AdminLaunchEnabled=value.get("AdminLaunchEnabled", False),
                               AdminLaunchAllowlist=value.get("AdminLaunchAllowlist", []),
                               UacCancellationScope=value.get("UacCancellationScope", "task")))
    normalized.update(AuthorityTier=tier, AdminLaunchMode=value.get("AdminLaunchMode", "allowlist"),
                      DeniedAdminWindowApplications=value.get("DeniedAdminWindowApplications", []),
                      DeniedAdminLaunchApplications=value.get("DeniedAdminLaunchApplications", []),
                      DeniedUacApplications=value.get("DeniedUacApplications", []))
    if normalized["UserSid"] != sid:
        raise PermissionError("user_policy_identity_mismatch")
    return normalized


def _unique(items):
    value = {}
    for key, item in items:
        if key in value:
            raise PermissionError("user_policy_invalid")
        value[key] = item
    return value


def canonical_path(value):
    if type(value) is not str or not ntpath.isabs(value) or "*" in value or "?" in value:
        raise PermissionError("user_policy_invalid")
    return ntpath.normcase(ntpath.normpath(value)).rstrip("\\")


def validate(value):
    common = {"Schema", "Revision", "UserSid", "AdminWindows", "AdminScope",
            "JevEnabled", "DeniedApplications", "AllowedAdminApplications", "Masks",
            "SmoothPointer", "HudCompact", "HudPosition"}
    if type(value) is not dict or type(value.get("Schema")) is not int or value["Schema"] not in (1, 2):
        raise PermissionError("user_policy_invalid")
    legacy = value["Schema"] == 1
    required = common | ({"UacEnabled"} if legacy else {"UacMode"})
    optional = set() if legacy else {"UacAllowlist", "AdminLaunchEnabled", "UacCancellationScope", "AdminLaunchAllowlist",
                                     "AuthorityTier", "AdminLaunchMode", "DeniedAdminWindowApplications",
                                     "DeniedAdminLaunchApplications", "DeniedUacApplications"}
    if (not required <= set(value) <= required | optional
            or type(value["Revision"]) is not str or not value["Revision"]
            or len(value["Revision"]) > 64 or type(value["UserSid"]) is not str
            or type(value["AdminScope"]) is not str or value["AdminScope"] not in {"all", "allowlist"}
            or type(value["HudPosition"]) is not str or value["HudPosition"] not in {"auto", "top_left", "top_right", "bottom_left", "bottom_right"}
            or any(type(value[k]) is not bool for k in
                   ("AdminWindows", "JevEnabled", "SmoothPointer", "HudCompact"))):
        raise PermissionError("user_policy_invalid")
    if legacy:
        if type(value["UacEnabled"]) is not bool:
            raise PermissionError("user_policy_invalid")
        if value["UacEnabled"]:
            raise PermissionError("uac_component_unavailable")
    elif (type(value["UacMode"]) is not str or value["UacMode"] not in {"off", "observe", "cancel", "allowlist", "semantic", "full"}
          or type(value.get("AdminLaunchEnabled", False)) is not bool
          or value.get("AuthorityTier") is not None
             and (type(value["AuthorityTier"]) is not int or not -1 <= value["AuthorityTier"] <= 3)
          or value.get("AdminLaunchMode", "allowlist") not in {"allowlist", "semantic"}
          or any(type(value.get(name, [])) is not list or len(value.get(name, [])) > 128
                 for name in ("DeniedAdminWindowApplications", "DeniedAdminLaunchApplications", "DeniedUacApplications"))
          or type(value.get("UacCancellationScope", "task")) is not str
          or value.get("UacCancellationScope", "task") not in {"task", "selected_prompt_in_session"}):
        raise PermissionError("user_policy_invalid")
    for name in ("UacAllowlist", "AdminLaunchAllowlist"):
        allowlist = value.get(name, [])
        if type(allowlist) is not list or len(allowlist) > 128:
            raise PermissionError("user_policy_invalid")
        for row in allowlist:
            validate_uac_application(row)
    for name in ("DeniedApplications", "AllowedAdminApplications"):
        rows = value[name]
        if type(rows) is not list or len(rows) > 128:
            raise PermissionError("user_policy_invalid")
        for row in rows:
            if (type(row) is not dict or set(row) != {"Path", "TitleContains", "Enabled"}
                    or type(row["TitleContains"]) is not str or len(row["TitleContains"]) > 160
                    or type(row["Enabled"]) is not bool):
                raise PermissionError("user_policy_invalid")
            canonical_path(row["Path"])
    for name in ("DeniedAdminWindowApplications",):
        for row in value.get(name, []):
            if (type(row) is not dict or set(row) != {"Path", "TitleContains", "Enabled"}
                    or type(row["TitleContains"]) is not str or len(row["TitleContains"]) > 160
                    or type(row["Enabled"]) is not bool):
                raise PermissionError("user_policy_invalid")
            canonical_path(row["Path"])
    for name in ("DeniedAdminLaunchApplications", "DeniedUacApplications"):
        for row in value.get(name, []):
            validate_uac_application(row)
    if type(value["Masks"]) is not list or len(value["Masks"]) > 128:
        raise PermissionError("user_policy_invalid")
    for row in value["Masks"]:
        if (type(row) is not dict or set(row) != {"Path", "Rect", "ClientSize", "Enabled"}
                or type(row["Enabled"]) is not bool):
            raise PermissionError("user_policy_invalid")
        canonical_path(row["Path"])
        rect, size = row["Rect"], row["ClientSize"]
        if (type(rect) is not list or len(rect) != 4 or type(size) is not list or len(size) != 2
                or any(type(n) is not int for n in rect + size)
                or not (0 <= rect[0] < rect[2] <= size[0] <= 16384
                        and 0 <= rect[1] < rect[3] <= size[1] <= 16384)):
            raise PermissionError("user_policy_invalid")
    # Only the known disabled legacy flag migrates. Reading never writes policy;
    # the caller hashes the original bytes, not this normalized representation.
    if legacy:
        value = dict(value, Schema=2, UacMode="off", UacAllowlist=[], AdminLaunchEnabled=False,
                     UacCancellationScope="task")
        del value["UacEnabled"]
    elif "UacAllowlist" not in value:
        value = dict(value, UacAllowlist=[])
    if value["UacMode"] == "full":
        value = dict(value, UacMode="off")
    value = dict(value, AdminLaunchEnabled=value.get("AdminLaunchEnabled", False),
                 AdminLaunchAllowlist=value.get("AdminLaunchAllowlist", []),
                 UacCancellationScope=value.get("UacCancellationScope", "task"))
    # Missing/null arguments retain historical identity-only entries but do not
    # grant a command. Reading never persists this effective disabled state.
    value = dict(value)
    for name in ("UacAllowlist", "AdminLaunchAllowlist"):
        value[name] = [dict(row, Enabled=False) if row.get("Arguments") is None else dict(row)
                       for row in value[name]]
    return value


def effective_policy(value):
    """Resolve the saved privilege tree without writing or restoring child grants.

    Existing administrator-window control stays unrestricted by program scope.
    Removed semantic expansion can only retain the original UAC allowlist.
    """
    tier = value.get("AuthorityTier")
    if tier is None:
        tier = (0 if not value["AdminWindows"]
                else 1 if not value.get("AdminLaunchEnabled", False)
                else 2 if value["UacMode"] == "off" else 3)
    if tier < 0:
        return dict(value, AuthorityTier=-1, FullyDisabled=True, AdminWindows=False,
                    AdminLaunchEnabled=False, UacMode="off")
    launch = tier >= 2
    mode = value["UacMode"] if tier >= 3 else "off"
    return dict(value, AuthorityTier=tier, FullyDisabled=False, AdminWindows=tier >= 1,
                AdminLaunchEnabled=launch, UacMode=mode)


def canonical_uac_path(value):
    normalized = canonical_path(value)
    drive, tail = ntpath.splitdrive(value)
    if (len(drive) != 2 or not drive[0].isascii() or not drive[0].isalpha()
            or drive[1] != ":" or not tail.startswith(("\\", "/"))
            or ":" in tail or any(ord(c) < 32 for c in value)):
        raise PermissionError("user_policy_invalid")
    return normalized


def validate_uac_application(row):
    required = {"Path", "IdentityKind", "Identity", "DisplayName", "Enabled"}
    if (type(row) is not dict or not required <= set(row) <= required | {"Arguments"}
            or type(row["IdentityKind"]) is not str or row["IdentityKind"] not in {"signed", "sha256"}
            or type(row["Identity"]) is not str or re.fullmatch("[0-9a-f]{64}", row["Identity"]) is None
            or type(row["DisplayName"]) is not str or len(row["DisplayName"]) > 160
            or any(ord(c) < 32 for c in row["DisplayName"]) or type(row["Enabled"]) is not bool
            or row.get("Arguments") is not None and (type(row["Arguments"]) is not str or len(row["Arguments"]) > 2048
                or any(ord(c) < 32 or 127 <= ord(c) <= 159 or c in "*?" for c in row["Arguments"]))):
        raise PermissionError("user_policy_invalid")
    canonical_uac_path(row["Path"])


def uac_allowlisted(value, actual):
    """The effective UAC allowlist consults preauthorization; names never match.

    `actual` must come from the runtime's verified current executable identity.
    A match alone does not bypass prompt identity, Stop or current user denial.
    Removed full access is never an executing mode.
    """
    if effective_policy(value)["UacMode"] != "allowlist":
        return False
    try:
        validate_uac_application(actual)
    except PermissionError:
        return False
    if type(actual.get("Arguments")) is not str:
        return False
    path = canonical_uac_path(actual["Path"])
    # The future elevated window title is not known yet. As with administrator
    # direct launch, any enabled denial for this exact program takes priority.
    if any(row["Enabled"] and canonical_path(row["Path"]) == path
           for row in value["DeniedApplications"]):
        return False
    if any(row["Enabled"] and canonical_uac_path(row["Path"]) == path
           and row["IdentityKind"] == actual["IdentityKind"] and row["Identity"] == actual["Identity"]
           and row.get("Arguments") == actual["Arguments"]
           for row in value.get("DeniedUacApplications", [])):
        return False
    return any(row["Enabled"] and canonical_uac_path(row["Path"]) == path
               and row["IdentityKind"] == actual["IdentityKind"] and row["Identity"] == actual["Identity"]
               and type(row.get("Arguments")) is str and row["Arguments"] == actual["Arguments"]
               for row in value["UacAllowlist"])


def default_policy(sid):
    # Only absence gets the new ordinary default. Existing records keep their
    # saved fields/legacy derivation; reading does not rewrite those records.
    return dict(Schema=2, Revision="absent", UserSid=sid, AdminWindows=False, AuthorityTier=0,
                AdminScope="all", UacMode="off", UacAllowlist=[], AdminLaunchEnabled=False, AdminLaunchAllowlist=[],
                UacCancellationScope="task", JevEnabled=True,
                DeniedApplications=[], AllowedAdminApplications=[], Masks=[],
                SmoothPointer=False, HudCompact=False, HudPosition="auto")


def _check_protection(path, *, parts=None, require_label=True):
    for ancestor in path.parents:
        if win32api.GetFileAttributes(str(ancestor)) & win32con.FILE_ATTRIBUTE_REPARSE_POINT:
            raise PermissionError("user_policy_unprotected")
    for part in ((path.parent, path) if parts is None else parts):
        if win32api.GetFileAttributes(str(part)) & win32con.FILE_ATTRIBUTE_REPARSE_POINT:
            raise PermissionError("user_policy_unprotected")
        security = win32security.GetNamedSecurityInfo(str(part), win32security.SE_FILE_OBJECT,
            win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION
            | 0x10)  # LABEL_SECURITY_INFORMATION; not arbitrary audit SACL access.
        owner = win32security.ConvertSidToStringSid(security.GetSecurityDescriptorOwner())
        if owner not in {"S-1-5-18", "S-1-5-32-544"}:
            raise PermissionError("user_policy_unprotected")
        dacl, sacl = security.GetSecurityDescriptorDacl(), security.GetSecurityDescriptorSacl()
        if dacl is None or require_label and sacl is None:
            raise PermissionError("user_policy_unprotected")
        for i in range(dacl.GetAceCount()):
            ace = dacl.GetAce(i)
            if ace[0][0] in {0, 5} and ace[1] & POLICY_MUTATION_RIGHTS:
                if win32security.ConvertSidToStringSid(ace[-1]) not in {"S-1-5-18", "S-1-5-32-544"}:
                    raise PermissionError("user_policy_unprotected")
        if require_label and not any(sacl.GetAce(i)[0][0] == 17 and sacl.GetAce(i)[1] & 1
                   and int(win32security.ConvertSidToStringSid(sacl.GetAce(i)[-1]).rsplit("-", 1)[1]) >= 12288
                   for i in range(sacl.GetAceCount())):
            raise PermissionError("user_policy_unprotected")


class PolicyReader:
    def __init__(self, path=None, *, sid=None, protection=True, uac_path=None):
        self.path = path
        self.sid = sid
        self.protection = protection
        # An explicit single path keeps the pure legacy protocol fixture. Real
        # storage and explicit two-file fixtures use the fixed sibling sidecar.
        self.uac_path = uac_path

    def _raw(self, path):
        try:
            if self.protection:
                # lstat retains broken links; stat would misclassify them as absent.
                for part in (path, *path.parents):
                    try:
                        attributes = part.lstat().st_file_attributes
                    except FileNotFoundError:
                        continue
                    if attributes & win32con.FILE_ATTRIBUTE_REPARSE_POINT:
                        raise PermissionError("user_policy_unprotected")
            try:
                metadata = path.lstat()
            except FileNotFoundError:
                if self.protection:
                    root = path.parent.parent
                    try:
                        root.lstat()
                    except FileNotFoundError:
                        pass
                    else:
                        _check_protection(root, parts=(root,), require_label=False)
                    try:
                        path.parent.lstat()
                    except FileNotFoundError:
                        pass
                    else:
                        _check_protection(path.parent, parts=(path.parent,))
                return None
            if metadata.st_file_attributes & (win32con.FILE_ATTRIBUTE_REPARSE_POINT | win32con.FILE_ATTRIBUTE_DIRECTORY):
                raise PermissionError("user_policy_invalid")
            if self.protection:
                _check_protection(path)
                handle = win32file.CreateFile(str(path), win32con.GENERIC_READ,
                    win32con.FILE_SHARE_READ | win32con.FILE_SHARE_DELETE, None,
                    win32con.OPEN_EXISTING, win32con.FILE_ATTRIBUTE_NORMAL, None)
                try:
                    size = win32file.GetFileSize(handle)
                    if size > 128_000:
                        raise PermissionError("user_policy_invalid")
                    raw = win32file.ReadFile(handle, size)[1] if size else b""
                finally:
                    handle.Close()
            else:
                raw = path.read_bytes()
            if len(raw) > 128_000:
                raise PermissionError("user_policy_invalid")
            return raw
        except PermissionError:
            raise
        except (OSError, ValueError, TypeError, pywintypes.error):
            raise PermissionError("user_policy_unavailable") from None

    def read(self):
        return effective_policy(self._read(0))

    def _read(self, attempt):
        path = self.path or production_path()
        sid = self.sid or user_sid()
        try:
            raw = self._raw(path)
            physical = None if raw is None else json.loads(raw, object_pairs_hook=_unique)
            value = default_policy(sid) if physical is None else validate(physical)
            if value["UserSid"] != sid:
                raise PermissionError("user_policy_identity_mismatch")
            sidecar = self.uac_path if self.path is not None else uac_policy_path(path)
            if sidecar is None:
                value["Revision"] = "absent" if raw is None else hashlib.sha256(raw).hexdigest()
                return value
            uac_raw, uac_error = None, None
            # A former combined Schema 2 file is read-only historical data.
            # Its embedded UAC settings never enable the new storage route.
            value = dict(value, UacMode="off", UacAllowlist=[], AdminLaunchEnabled=False, AdminLaunchAllowlist=[],
                         UacCancellationScope="task", AuthorityTier=None, AdminLaunchMode="allowlist",
                         DeniedAdminWindowApplications=[], DeniedAdminLaunchApplications=[], DeniedUacApplications=[])
            try:
                uac_raw = self._raw(sidecar)
                if uac_raw is not None:
                    uac = json.loads(uac_raw, object_pairs_hook=_unique)
                    normalized = validate_uac_policy(uac, sid)
                    common_revision = "absent" if raw is None else hashlib.sha256(raw).hexdigest()
                    if physical is not None and physical["Schema"] != 1:
                        uac_error = "user_policy_migration_required"
                    elif uac["CommonRevision"] != common_revision:
                        uac_error = "uac_policy_common_changed"
                    else:
                        # Old protected sidecars could validly bind an absent
                        # common file, whose historical default was admin-on.
                        # Retain that existing implicit tier only after exact
                        # SID/revision validation; an explicit tier/off wins.
                        if physical is None and normalized["AuthorityTier"] is None:
                            value = dict(value, AdminWindows=True)
                        value = dict(value, UacMode=normalized["UacMode"], UacAllowlist=normalized["UacAllowlist"],
                                     AdminLaunchEnabled=normalized["AdminLaunchEnabled"],
                                     AdminLaunchAllowlist=normalized["AdminLaunchAllowlist"],
                                     UacCancellationScope=normalized["UacCancellationScope"],
                                     AuthorityTier=normalized["AuthorityTier"],
                                     AdminLaunchMode=normalized["AdminLaunchMode"],
                                     DeniedAdminWindowApplications=normalized["DeniedAdminWindowApplications"],
                                     DeniedAdminLaunchApplications=normalized["DeniedAdminLaunchApplications"],
                                     DeniedUacApplications=normalized["DeniedUacApplications"])
            except (PermissionError, OSError, ValueError, TypeError, pywintypes.error) as error:
                uac_error = error.code if isinstance(error, PermissionError) else "user_policy_invalid"
            if physical is not None and physical["Schema"] != 1:
                uac_error = "user_policy_migration_required"
            stable = self._raw(path) == raw
            if uac_raw is not None or uac_error is None:
                try:
                    stable = self._raw(sidecar) == uac_raw and stable
                except PermissionError:
                    stable = False
            if not stable:
                if attempt >= 2:
                    raise PermissionError("user_policy_unavailable")
                return self._read(attempt + 1)
            value["Revision"] = storage_revision(raw, uac_raw, uac_error=uac_error if uac_raw is None else None)
            if uac_error:
                value["UacPolicyError"] = uac_error
            return value
        except PermissionError:
            raise
        except (OSError, ValueError, TypeError, pywintypes.error):
            raise PermissionError("user_policy_unavailable") from None


active_policy = PolicyReader()


def revision():
    return active_policy.read()["Revision"]


def require_application(image, *, integrity=8192, title="", policy=None):
    value = policy or active_policy.read()
    if value.get("FullyDisabled"):
        raise PermissionError("flower_fully_disabled")
    path = canonical_path(str(image))
    def matches(row):
        return row["Enabled"] and canonical_path(row["Path"]) == path and (
            not row["TitleContains"] or row["TitleContains"].casefold() in title.casefold())
    if any(matches(row) for row in value["DeniedApplications"]):
        raise PermissionError("window_disabled_by_user")
    if integrity > 8192 and any(matches(row) for row in value.get("DeniedAdminWindowApplications", [])):
        raise PermissionError("window_disabled_by_user")
    if integrity > 8192 and not value["AdminWindows"]:
        raise PermissionError("administrator_window_disabled")
    return value


def require_channel_allowed(value=None):
    """One exclusive switch also stops Web session creation."""
    value = value or active_policy.read()
    if value.get("FullyDisabled"):
        raise PermissionError("flower_fully_disabled")


def process_facts(pid):
    process = win32api.OpenProcess(win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    try:
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD,
            wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        kernel.QueryFullProcessImageNameW.restype = wintypes.BOOL
        text = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(text))
        if not kernel.QueryFullProcessImageNameW(int(process), 0, text, ctypes.byref(size)):
            raise PermissionError("window_policy_identity_unavailable")
        image = text.value
        token = win32security.OpenProcessToken(process, win32con.TOKEN_QUERY)
        try:
            level = win32security.GetTokenInformation(token, win32security.TokenIntegrityLevel)
            sid = level[0] if isinstance(level, tuple) else level
            integrity = int(win32security.ConvertSidToStringSid(sid).rsplit("-", 1)[1])
        finally:
            token.Close()
        return image, integrity
    finally:
        process.Close()


def require_window(hwnd):
    value = active_policy.read()
    # Fast path preserves ordinary native probes when the default has no restrictions.
    if value["AdminWindows"] and not value["DeniedApplications"]:
        return value
    try:
        root, seen = hwnd, set()
        for _ in range(16):
            if not root:
                return value
            if root in seen:
                raise PermissionError("window_policy_identity_unavailable")
            seen.add(root)
            pid = win32process.GetWindowThreadProcessId(root)[1]
            image, integrity = process_facts(pid)
            require_application(image, integrity=integrity, title=win32gui.GetWindowText(root), policy=value)
            root = win32gui.GetWindow(root, win32con.GW_OWNER)
        raise PermissionError("window_policy_identity_unavailable")
    except PermissionError:
        raise
    except Exception:
        raise PermissionError("window_policy_identity_unavailable") from None


def require_browser(pid, executable):
    value = active_policy.read()
    # Web has no HWND. Title-qualified rules for this browser are conservative:
    # they protect the whole browser rather than guessing a website from its title.
    rows = [dict(row, TitleContains="") for row in value["DeniedApplications"]]
    require_application(executable, policy=dict(value, DeniedApplications=rows))
    if not value["AdminWindows"]:
        image, integrity = process_facts(pid)
        if canonical_path(image) != canonical_path(str(executable)):
            raise PermissionError("window_policy_identity_unavailable")
        require_application(image, integrity=integrity, policy=value)
    return value
