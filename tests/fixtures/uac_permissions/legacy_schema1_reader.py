"""Frozen Schema 1 reader semantics from the 492fed daily policy reader.

Temporary-fixture compatibility oracle only; no runtime import or production IO.
"""
import hashlib
import json
import ntpath

class PermissionError(RuntimeError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


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
    keys = {"Schema", "Revision", "UserSid", "AdminWindows", "AdminScope", "UacEnabled",
            "JevEnabled", "DeniedApplications", "AllowedAdminApplications", "Masks",
            "SmoothPointer", "HudCompact", "HudPosition"}
    if (type(value) is not dict or set(value) != keys or type(value["Schema"]) is not int or value["Schema"] != 1
            or type(value["Revision"]) is not str or not value["Revision"]
            or len(value["Revision"]) > 64 or type(value["UserSid"]) is not str
            or value["AdminScope"] not in {"all", "allowlist"}
            or value["HudPosition"] not in {"auto", "top_left", "top_right", "bottom_left", "bottom_right"}
            or any(type(value[k]) is not bool for k in
                   ("AdminWindows", "UacEnabled", "JevEnabled", "SmoothPointer", "HudCompact"))):
        raise PermissionError("user_policy_invalid")
    # UAC capability is deliberately absent until the independent prototype
    # passes. A hand-edited enable flag cannot turn it on.
    if value["UacEnabled"]:
        raise PermissionError("uac_component_unavailable")
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
    return value

def read(raw, sid):
    value = validate(json.loads(raw, object_pairs_hook=_unique))
    if value["UserSid"] != sid:
        raise PermissionError("user_policy_identity_mismatch")
    return dict(value, Revision=hashlib.sha256(raw).hexdigest())
