"""Inventory local installation storage and prepare/recycle exact cache files.

Only old files in Cache/diagnostics and Cache/rebuildable are candidates.
Profiles, ledgers, Program/recovery and package payloads are never candidates.
"""
from __future__ import annotations

import argparse
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
import os
import re
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from flower_control.install_location import discover_installation
from tools.settings_portability import read_json, reject_links, write_new

SAFE_CACHE_FOLDERS = {"diagnostics", "rebuildable"}
SAFE_SUFFIXES = {".log", ".json", ".jsonl", ".cache", ".tmp"}


def _installation(installation):
    value = installation or discover_installation()
    if value.legacy:
        from flower_control.data_paths import resolve_data_root
        data = resolve_data_root()
        value = replace(value, data_root=data, cache_root=data / "cache")
    return value


def _files(root):
    reject_links(root)
    if not root.exists():
        return
    for directory, folders, names in os.walk(root, followlinks=False):
        parent = Path(directory)
        folders[:] = [name for name in folders if not (parent / name).is_symlink() and not (parent / name).is_junction()]
        for name in names:
            path = parent / name
            if path.is_symlink() or path.is_junction():
                continue
            yield path


def usage(installation=None):
    install = _installation(installation)
    categories = []
    for label, path in (("Program", install.program_root), ("Data", install.data_root),
                        ("Cache", install.cache_root), ("Packages", install.packages_root)):
        count, size, errors = 0, 0, 0
        try:
            for item in _files(path):
                try:
                    size += item.stat().st_size
                    count += 1
                except OSError:
                    errors += 1
        except (OSError, ValueError):
            errors += 1
        categories.append(dict(category=label, path=str(path), files=count, bytes=size, unreadable=errors))
    return dict(schema=1, categories=categories, content_read=False, allocation_bytes=False)


def _eligible(path, cache_root, cutoff_ns):
    reject_links(path)
    relative = path.relative_to(cache_root)
    if (len(relative.parts) < 2 or relative.parts[0] not in SAFE_CACHE_FOLDERS
            or any(part.casefold() in {"profiles", "state-v1", "recovery", "permissions", "work-authority"} for part in relative.parts)
            or path.suffix.lower() not in SAFE_SUFFIXES or not path.is_file()):
        raise ValueError("cache_candidate_out_of_scope")
    stat = path.stat()
    if stat.st_mtime_ns > cutoff_ns or getattr(stat, "st_nlink", 1) != 1:
        raise ValueError("cache_candidate_not_idle")
    return stat


def _fingerprint(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def load_reviewed_plan(path, expected_sha256=None):
    reject_links(path)
    with Path(path).open("rb") as stream:
        raw = stream.read(32_000_001)
    if len(raw) > 32_000_000:
        raise ValueError("cache_plan_too_large")
    if expected_sha256 and (not re.fullmatch(r"[a-f0-9]{64}", expected_sha256)
            or hashlib.sha256(raw).hexdigest() != expected_sha256):
        raise ValueError("cache_reviewed_plan_changed")
    def unique(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise ValueError("cache_plan_duplicate_key")
            result[name] = value
        return result
    return json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique)


def plan_cache_cleanup(installation=None, *, older_than_days=7, now=None):
    install = _installation(installation)
    if type(older_than_days) is not int or older_than_days < 1:
        raise ValueError("cache_retention_invalid")
    now = time.time() if now is None else now
    cutoff = int((now - older_than_days * 86400) * 1_000_000_000)
    files = []
    for folder in sorted(SAFE_CACHE_FOLDERS):
        for path in _files(install.cache_root / folder):
            try:
                stat = _eligible(path, install.cache_root, cutoff)
                files.append(dict(path=str(path), bytes=stat.st_size, mtime_ns=stat.st_mtime_ns,
                                  file_id=stat.st_ino, sha256=_fingerprint(path)))
            except (ValueError, OSError):
                continue
    return dict(schema=1, kind="flower-cache-recycle", installation_id=install.installation_id,
                cache_root=str(install.cache_root), older_than_days=older_than_days,
                created_utc=datetime.fromtimestamp(now, timezone.utc).isoformat(), cutoff_ns=cutoff,
                files=files, file_count=len(files), bytes=sum(row["bytes"] for row in files),
                destination="windows_recycle_bin", applied=False)


def recycle_plan(plan, installation=None, *, recycle=None):
    """Revalidate the exact displayed batch. Never fall back to permanent delete."""
    install = _installation(installation)
    expected = {"schema", "kind", "installation_id", "cache_root", "older_than_days", "created_utc", "cutoff_ns", "files", "file_count", "bytes", "destination", "applied"}
    if (type(plan) is not dict or set(plan) != expected or type(plan["schema"]) is not int or plan["schema"] != 1
            or plan["kind"] != "flower-cache-recycle" or plan["installation_id"] != install.installation_id
            or Path(plan["cache_root"]) != install.cache_root or plan["destination"] != "windows_recycle_bin"
            or plan["applied"] is not False or type(plan["files"]) is not list
            or type(plan["cutoff_ns"]) is not int or type(plan["older_than_days"]) is not int
            or plan["older_than_days"] < 1 or plan["cutoff_ns"] > time.time_ns() - plan["older_than_days"] * 86400 * 1_000_000_000
            or type(plan["file_count"]) is not int or type(plan["bytes"]) is not int):
        raise ValueError("cache_plan_invalid")
    for row in plan["files"]:
        if (type(row) is not dict or set(row) != {"path", "bytes", "mtime_ns", "file_id", "sha256"}
                or any(type(row[name]) is not int for name in ("bytes", "mtime_ns", "file_id"))
                or type(row["path"]) is not str or type(row["sha256"]) is not str
                or not re.fullmatch(r"[a-f0-9]{64}", row["sha256"])):
            raise ValueError("cache_plan_file_invalid")
    if plan["file_count"] != len(plan["files"]) or plan["bytes"] != sum(row["bytes"] for row in plan["files"]):
        raise ValueError("cache_plan_totals_invalid")
    verified, seen = [], set()
    for row in plan["files"]:
        path = Path(row["path"])
        if path in seen:
            raise ValueError("cache_plan_duplicate")
        seen.add(path)
        stat = _eligible(path, install.cache_root, plan["cutoff_ns"])
        if ((stat.st_size, stat.st_mtime_ns, stat.st_ino) != (row["bytes"], row["mtime_ns"], row["file_id"])
                or _fingerprint(path) != row["sha256"]):
            raise ValueError("cache_candidate_changed")
        verified.append((path, row))
    if recycle is None:
        import pythoncom
        import win32api
        import win32con
        import win32security
        from win32com.shell import shell, shellcon
        token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
        try:
            level = win32security.GetTokenInformation(token, win32security.TokenIntegrityLevel)
            sid = level[0] if isinstance(level, tuple) else level
            if (int(win32security.ConvertSidToStringSid(sid).rsplit("-", 1)[1]) != 8192
                    or win32security.GetTokenInformation(token, win32security.TokenElevation)):
                raise ValueError("cache_recycle_requires_ordinary_user")
        finally:
            token.Close()
        def recycle(path):
            pythoncom.CoInitialize()
            try:
                operation = pythoncom.CoCreateInstance(shell.CLSID_FileOperation, None,
                    pythoncom.CLSCTX_INPROC_SERVER, shell.IID_IFileOperation)
                # RECYCLEONDELETE is explicit: ALLOWUNDO by itself can still
                # permanently delete when the recycle bin is unavailable.
                operation.SetOperationFlags(0x00080000 | 0x00100000 | 0x20000000 |
                    shellcon.FOF_NOCONFIRMATION | shellcon.FOF_NOERRORUI | shellcon.FOF_SILENT)
                item = shell.SHCreateItemFromParsingName(str(path), None, shell.IID_IShellItem)
                operation.DeleteItem(item, None)
                operation.PerformOperations()
                if operation.GetAnyOperationsAborted() or path.exists():
                    raise OSError("cache_recycle_failed")
            except pythoncom.com_error as error:
                raise OSError("cache_recycle_failed") from error
            finally:
                pythoncom.CoUninitialize()
    completed = []
    for path, row in verified:
        # Recheck immediately before each call, preserving completed prefixes
        # if another file becomes busy or changes during the batch.
        stat = _eligible(path, install.cache_root, plan["cutoff_ns"])
        if ((stat.st_size, stat.st_mtime_ns, stat.st_ino) != (row["bytes"], row["mtime_ns"], row["file_id"])
                or _fingerprint(path) != row["sha256"]):
            return dict(state="partial", recycled=completed, failed_path=str(path), error="cache_candidate_changed")
        try:
            recycle(path)
        except OSError:
            return dict(state="partial" if completed else "failed", recycled=completed, failed_path=str(path), error="cache_recycle_failed")
        completed.append(str(path))
    return dict(state="recycled", recycled=completed, file_count=len(completed), bytes=plan["bytes"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("usage")
    plan = commands.add_parser("plan")
    plan.add_argument("--older-than-days", type=int, default=7)
    plan.add_argument("--output", type=Path, required=True)
    recycle = commands.add_parser("recycle")
    recycle.add_argument("--plan", type=Path, required=True)
    recycle.add_argument("--apply", action="store_true", required=True)
    recycle.add_argument("--expected-sha256")
    for command in commands.choices.values():
        command.add_argument("--request-id")
        command.add_argument("--result-path", type=Path)
    args = parser.parse_args()
    if bool(args.request_id) != bool(args.result_path) or args.request_id and not re.fullmatch(r"[a-f0-9]{32}", args.request_id):
        parser.error("request_id_and_result_path_required_together")
    try:
        from flower_control.drivers.worker_bootstrap import initialize_dlls
        initialize_dlls()
        if args.command == "usage":
            result = usage()
        elif args.command == "plan":
            document = plan_cache_cleanup(older_than_days=args.older_than_days)
            output = write_new(args.output, document)
            result = dict(state="plan_prepared", output=str(output), file_count=document["file_count"],
                          bytes=document["bytes"], plan_sha256=_fingerprint(output))
        else:
            document = load_reviewed_plan(args.plan, args.expected_sha256)
            result = recycle_plan(document)
        receipt = dict(request_id=args.request_id, command=args.command, state="completed", result=result)
    except Exception as error:
        if not args.result_path:
            raise
        code = str(error) if isinstance(error, ValueError) and re.fullmatch(r"[a-z_]{1,80}", str(error)) else type(error).__name__
        receipt = dict(request_id=args.request_id, command=args.command, state="failed", error=code)
        result = {"state": "failed", "error": code}
    if args.result_path:
        write_new(args.result_path, receipt)
    else:
        print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
