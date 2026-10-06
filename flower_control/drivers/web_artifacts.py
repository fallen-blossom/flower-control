"""Persist one explicitly requested Web artifact without reading local user files."""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
import uuid
from pathlib import Path

from flower_control.control.state import ControlError


MAX_ARTIFACT_BYTES = 50_000_000
_REPARSE = 0x400


def _check_no_reparse(path: Path) -> None:
    for candidate in (path, *path.parents):
        try:
            attributes = candidate.lstat().st_file_attributes
        except FileNotFoundError:
            continue
        if attributes & _REPARSE:
            raise ControlError("artifact_reparse_path_refused")


def artifact_path(output_path: str | None, *, suffix: str, suggested: str = "web") -> Path:
    if output_path is None:
        root = Path(tempfile.gettempdir()) / "flower-web-artifacts"
        _check_no_reparse(root)
        root.mkdir(mode=0o700, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", Path(suggested).name)[:80].strip("._") or "web"
        candidate = root / f"{uuid.uuid4().hex}-{safe}{suffix}"
    else:
        if type(output_path) is not str or not output_path or "\x00" in output_path:
            raise ControlError("invalid_artifact_path")
        candidate = Path(output_path)
        if (not candidate.is_absolute() or ".." in candidate.parts or
                ":" in candidate.name or not candidate.parent.is_dir()):
            raise ControlError("invalid_artifact_path")
    _check_no_reparse(candidate.parent)
    if candidate.exists() or candidate.is_symlink():
        raise ControlError("artifact_already_exists")
    return candidate


def persist_bytes(source: bytes, output_path: str | None, *, suffix: str,
                  suggested: str = "web") -> dict:
    if type(source) is not bytes or len(source) > MAX_ARTIFACT_BYTES:
        raise ControlError("artifact_too_large")
    target = artifact_path(output_path, suffix=suffix, suggested=suggested)
    digest = hashlib.sha256(source).hexdigest()
    # Exclusive create; an existing user file is never replaced.
    with target.open("xb") as file:
        file.write(source)
        file.flush()
        os.fsync(file.fileno())
    return {"path": str(target.resolve()), "bytes": len(source), "sha256": digest}


def persist_file(source: Path, output_path: str | None, *, suffix: str,
                 suggested: str = "web") -> dict:
    size = source.stat().st_size
    if size > MAX_ARTIFACT_BYTES:
        raise ControlError("artifact_too_large")
    target = artifact_path(output_path, suffix=suffix, suggested=suggested)
    digest = hashlib.sha256()
    with source.open("rb") as reader, target.open("xb") as writer:
        for block in iter(lambda: reader.read(1024 * 1024), b""):
            digest.update(block)
            writer.write(block)
        writer.flush()
        os.fsync(writer.fileno())
    return {"path": str(target.resolve()), "bytes": size, "sha256": digest.hexdigest()}
