"""Local profile selection and controlled data imports; never imports grants."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat

from .control.state import ControlError

KINDS = {"ai", "luohua"}
RECEIPT = "flower-profile-import.json"


def direct_path(path):
    path = Path(path)
    if not path.is_absolute():
        raise ControlError("profile_path_must_be_absolute")
    for item in (path, *path.parents):
        if os.path.lexists(item):
            attrs = item.stat(follow_symlinks=False).st_file_attributes
            if attrs & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                raise ControlError("profile_reparse_point")
    return path


def profile_paths(root, *, allow_unselected_imports=False):
    directory = direct_path(Path(root) / "profiles")
    result = {kind: directory / f"{kind}-v1" for kind in KINDS}
    registry = directory / "active.json"
    if not registry.exists():
        # First install may use defaults. Once an imported/recovered selection
        # exists, silently opening a fresh default loses the user's login/tab
        # experience. Inspect only names and our own import-receipt presence.
        if directory.is_dir() and not allow_unselected_imports:
            for child in directory.iterdir():
                if child.is_dir() and (child / RECEIPT).is_file():
                    raise ControlError("profile_selection_missing")
        return result
    direct_path(registry)
    try:
        if registry.stat().st_size > 8192:
            raise ValueError("registry size")
        data = json.loads(registry.read_bytes())
        if type(data.get("schema")) is not int or data["schema"] != 1 or set(data.get("profiles", {})) != KINDS:
            raise ValueError("registry shape")
        for kind, name in data["profiles"].items():
            if type(name) is not str or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,63}", name):
                raise ValueError("registry name")
            result[kind] = direct_path(directory / name)
        if result["ai"] == result["luohua"]:
            raise ValueError("shared profile")
        return result
    except (OSError, ValueError, TypeError, AttributeError) as error:
        raise ControlError("profile_registry_unverified") from error


def _digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def profile_identity_hashes(profile, *, anchor=RECEIPT):
    """Known old spelling is accepted only for this same existing anchor file.

    This fixes path-hash metadata after physical-root resolution without
    rewriting account data or importing authority. It does not prove a live
    browser's file view; callers still verify its exact process/argv/endpoint.
    """
    from .data_paths import physical_path, DataPathError
    profile = direct_path(profile)
    hashes = {hashlib.sha256(str(profile.resolve()).lower().encode()).hexdigest()}
    path = profile / anchor
    if not path.is_file():
        return frozenset(hashes)
    actual = physical_path(path)
    hashes.add(hashlib.sha256(str(actual.parent).lower().encode()).hexdigest())
    local = os.environ.get("LOCALAPPDATA")
    if local and Path(local).is_absolute():
        alias = Path(local) / "FlowerControl" / "profiles" / profile.name
        try:
            if (alias / anchor).is_file() and physical_path(alias / anchor) == actual:
                hashes.add(hashlib.sha256(str(alias.resolve()).lower().encode()).hexdigest())
        except (OSError, DataPathError):
            pass
    return frozenset(hashes)


def select_imported_profiles(root, names, *, ensure_quiet):
    """Select verified copies, retaining a local rollback receipt and originals."""
    directory = direct_path(Path(root) / "profiles")
    if (type(names) is not dict or set(names) != KINDS
            or any(type(name) is not str or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,63}", name)
                   for name in names.values()) or len(set(names.values())) != 2):
        raise ControlError("profile_registry_unverified")
    # This explicit selection is the only path allowed to resolve defaults
    # while verified imported copies are being prepared for first selection.
    previous = profile_paths(root, allow_unselected_imports=True)
    selected = {kind: direct_path(directory / name) for kind, name in names.items()}
    for profile in set(previous.values()) | set(selected.values()):
        ensure_quiet(profile)
    for kind, profile in selected.items():
        if not admit_import(profile, kind):
            raise ControlError("profile_import_unverified")
    receipt = direct_path(directory / "flower-selection-rollback.json")
    if previous != selected:
        # A successful second invocation must retain the pre-switch mapping.
        _write_json(receipt, {"schema": 1, "previous": {
            kind: path.name for kind, path in previous.items()}, "selected": names,
            "task_permissions_imported": False})
        _write_json(directory / "active.json", {"schema": 1, "profiles": names})
    if profile_paths(root) != selected:
        raise ControlError("profile_registry_write_unverified")
    return {"state": "selected_not_account_verified", "profiles": names,
            "rollback_receipt": str(receipt), "originals_preserved": True,
            "task_permissions_imported": False}


def _inventory(root):
    rows = []
    total = 0
    def fail(error):
        raise error

    for directory, dirs, files in os.walk(root, followlinks=False, onerror=fail):
        for name in dirs:
            direct_path(Path(directory) / name)
        for name in files:
            path = direct_path(Path(directory) / name)
            relative = path.relative_to(root)
            # Chromium transient locks and Flower ownership/authorization are
            # not browser account data. Never transplant an old session marker.
            if len(relative.parts) == 1 and (name.startswith(("flower-", ".flower-", "Singleton"))
                    or name in {"DevToolsActivePort", "lockfile"}):
                continue
            if not path.is_file():
                raise ControlError("profile_file_unverified")
            size = path.stat().st_size
            total += size
            if len(rows) >= 25000 or total > 10 * 1024 ** 3:
                raise ControlError("profile_import_too_large")
            rows.append(dict(path=relative.as_posix(), size=size, sha256=_digest(path)))
    return sorted(rows, key=lambda row: row["path"])


def import_profile(source, destination, kind, *, ensure_quiet):
    """Copy opaque browser files into a new candidate, preserving both originals.

    Caller supplies the exact source/destination and performs the approved
    pre-import backup. A failed candidate is retained but never activated.
    """
    if kind not in KINDS:
        raise ControlError("invalid_profile_kind")
    source, destination = direct_path(source), direct_path(destination)
    if not source.is_dir() or destination.exists() or source == destination or source in destination.parents:
        raise ControlError("profile_import_destination_conflict")
    ensure_quiet(source)
    rows = _inventory(source)
    if not rows or not (source / "Local State").is_file():
        raise ControlError("browser_profile_data_missing")
    destination.mkdir(parents=True, exist_ok=False)
    for row in rows:
        original = direct_path(source / row["path"])
        target = direct_path(destination / row["path"])
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, target)
        if target.stat().st_size != row["size"] or _digest(target) != row["sha256"]:
            raise ControlError("profile_import_copy_unverified")
    ensure_quiet(source)
    if _inventory(source) != rows:
        raise ControlError("profile_import_source_changed")
    receipt = dict(schema=1, kind=kind, state="prepared", files=rows,
                   profile_hash=hashlib.sha256(str(destination.resolve()).lower().encode()).hexdigest(),
                   source_data_preserved=True, task_permissions_imported=False)
    _write_json(destination / RECEIPT, receipt)
    return {"kind": kind, "files": len(rows), "bytes": sum(row["size"] for row in rows),
            "source_preserved": True, "task_permissions_imported": False}


def admit_import(profile, kind):
    """Admit only a copied candidate to the normal new-session launch path."""
    profile = direct_path(profile)
    receipt_path = direct_path(profile / RECEIPT)
    if not receipt_path.exists():
        return False
    try:
        if receipt_path.stat().st_size > 8 * 1024 ** 2:
            raise ValueError("receipt size")
        receipt = json.loads(receipt_path.read_bytes())
        if (type(receipt.get("schema")) is not int or receipt["schema"] != 1 or receipt.get("kind") != kind
                or receipt.get("task_permissions_imported") is not False
                or receipt.get("profile_hash") not in profile_identity_hashes(profile)
                or receipt.get("state") not in {"prepared", "admitted"}):
            raise ValueError("receipt identity")
        if receipt["state"] == "prepared":
            if _inventory(profile) != receipt["files"]:
                raise ValueError("candidate content changed")
            receipt["state"] = "admitted"
            # Existing launch recovery may write a provisional session marker.
            # Admission precedes launch and remains usable after an interrupted
            # launch; it creates no task owner or private authorization.
            _write_json(receipt_path, receipt)
        return True
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        raise ControlError("profile_import_unverified") from error


def _write_json(path, data):
    path = direct_path(path)
    temporary = direct_path(path.with_name(path.name + ".new"))
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    try:
        os.replace(temporary, path)
    except OSError as error:
        if getattr(error, "winerror", None) != 17:
            raise
        # Windows encrypted/package storage can reject a same-directory
        # replace as cross-volume. Retain .new and verify the direct write;
        # readers reject incomplete JSON rather than accepting partial state.
        payload = temporary.read_bytes()
        with path.open("wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        if path.read_bytes() != payload:
            raise ControlError("profile_registry_write_unverified")
