"""Freeze existing admitted code/dependencies; no downloads or data migration."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def reject_links(path):
    path = Path(path)
    if not path.is_absolute():
        raise ValueError("runtime_path_must_be_absolute")
    for item in (path, *path.parents):
        if item.exists() and item.stat(follow_symlinks=False).st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise ValueError("runtime_link_rejected")


def inventory_tree(root, *, prefix, selected=None, excluded=()):
    root = Path(root)
    reject_links(root)
    if not root.is_dir():
        raise ValueError("runtime_tree_missing")
    rows = {}
    size = 0
    pending = [root]
    while pending:
        directory = pending.pop()
        for entry in os.scandir(directory):
            path = Path(entry.path)
            info = entry.stat(follow_symlinks=False)
            if info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                raise ValueError("runtime_link_rejected")
            relative = path.relative_to(root)
            if entry.is_dir(follow_symlinks=False):
                if entry.name not in {"__pycache__", ".git", "bin", "obj", *excluded}:
                    pending.append(path)
                continue
            if not entry.is_file(follow_symlinks=False):
                raise ValueError("runtime_file_rejected")
            if path.suffix in {".pyc", ".pyo"} or selected and not selected(relative):
                continue
            size += info.st_size
            if len(rows) >= 60000 or size > 2 * 1024 ** 3:
                raise ValueError("runtime_tree_too_large")
            rows[(Path(prefix) / relative).as_posix()] = {"path": path, "sha256": digest(path), "size": info.st_size}
    return rows


def inventory_runtime(repository, runtime, site):
    """Exact executable inputs only; never profiles, ledger, tmp or tests."""
    repository, runtime, site = map(Path, (repository, runtime, site))
    rows = inventory_tree(repository / "flower_control", prefix="python-source/flower_control",
                          selected=lambda path: path.suffix in {".py", ".cs", ".csproj", ".manifest"}
                          or path.name == "packages.lock.json")
    if (repository / "hooks").is_dir():
        rows.update(inventory_tree(repository / "hooks", prefix="python-source/hooks", selected=lambda path: path.suffix == ".py"))
    for name in ("pyproject.toml", "requirements.lock", "requirements-web.lock"):
        path = repository / name
        reject_links(path)
        if path.is_file():
            rows["python-source/" + name] = {"path": path, "sha256": digest(path), "size": path.stat().st_size}
    icon = repository / "assets/branding/flower-control-icon.ico"
    reject_links(icon)
    if icon.is_file():
        rows["python-source/assets/branding/flower-control-icon.ico"] = {
            "path": icon, "sha256": digest(icon), "size": icon.stat().st_size}
    for name in ("skills/flower-control/SKILL.md", ".codex-plugin/plugin.json",
                 "assets/branding/flower-control-icon.png", "tools/open_flower_browser.py"):
        path = repository / name
        reject_links(path)
        if not path.is_file():
            raise ValueError("runtime_plugin_presentation_missing")
        rows["python-source/" + name] = {"path": path, "sha256": digest(path), "size": path.stat().st_size}
    rows.update(inventory_tree(runtime / "Lib", prefix="runtime/Lib", excluded={"site-packages"}))
    rows.update(inventory_tree(runtime / "DLLs", prefix="runtime/DLLs"))
    if (runtime / "DLLs/_tkinter.pyd").is_file():
        # Tcl resolves its script libraries relative to the relocated Python
        # stdlib, not the original interpreter's external tcl directory.
        # Freeze the Windows packages as well as the core Tcl/Tk trees.
        tcl_root = runtime / "tcl"
        trees = ("tcl8.6", "tk8.6", "tcl8", "dde1.4", "reg1.3")
        required = (tcl_root / "tcl8.6/init.tcl", tcl_root / "tk8.6/tk.tcl",
                    tcl_root / "dde1.4/pkgIndex.tcl", tcl_root / "reg1.3/pkgIndex.tcl",
                    runtime / "DLLs/tcl86t.dll", runtime / "DLLs/tk86t.dll", runtime / "DLLs/zlib1.dll")
        if any(not path.is_file() for path in required) or any(not (tcl_root / name).is_dir() for name in trees):
            raise ValueError("runtime_tk_resources_missing")
        for name in trees:
            files = inventory_tree(tcl_root / name, prefix="runtime/Lib/" + name)
            if not files:
                raise ValueError("runtime_tk_resources_missing")
            if rows.keys() & files.keys():
                raise ValueError("runtime_tk_path_conflict")
            rows.update(files)
    rows.update(inventory_tree(site, prefix="python-source/.venv/Lib/site-packages"))
    return rows


def inventory_digest(rows):
    hashes = {name: row["sha256"] for name, row in rows.items()}
    return hashlib.sha256(json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def copy_runtime(rows, destination):
    destination = Path(destination)
    reject_links(destination)
    for name in rows:
        relative = Path(name)
        if (relative.is_absolute() or ".." in relative.parts
                or any(":" in part for part in relative.parts)
                or not relative.parts or relative.parts[0] not in {"runtime", "python-source"}):
            raise ValueError("runtime_snapshot_path_rejected")
    if any((destination / name).exists() for name in rows):
        raise ValueError("runtime_snapshot_destination_conflict")
    for name, row in rows.items():
        relative = Path(name)
        original = row["path"]
        reject_links(original)
        if digest(original) != row["sha256"]:
            raise ValueError("runtime_snapshot_source_changed")
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        reject_links(target.parent)
        with original.open("rb") as source, target.open("xb") as output:
            shutil.copyfileobj(source, output)
        if digest(target) != row["sha256"] or digest(original) != row["sha256"]:
            raise ValueError("runtime_snapshot_source_changed")
    # A later source mutation during copying must not produce a sealed package.
    if any(digest(row["path"]) != row["sha256"] for row in rows.values()):
        raise ValueError("runtime_snapshot_source_changed")
    hashes = {name: row["sha256"] for name, row in rows.items()}
    manifest = destination / "runtime-inventory.json"
    manifest.write_text(json.dumps({"schema": 1, "files": hashes,
        "dependency_inventory_sha256": inventory_digest(rows),
        "downloads": False, "data_migrated": False}, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return hashes, digest(manifest)
