"""Persist one explicitly requested Web artifact without reading local user files."""

from __future__ import annotations

import hashlib
import asyncio
from contextvars import ContextVar
import json
import math
import os
import re
import tempfile
import time
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path

from flower_control.control.state import ControlError


MAX_ARTIFACT_BYTES = 50_000_000
MAX_WEB_DOWNLOAD_BYTES = 1_000_000_000
MAX_DEFAULT_RECORDING_STORAGE_BYTES = 200_000_000
RECORDING_RETENTION_SECONDS = 7 * 24 * 3600
_RECORD_SUFFIX = ".flower-recording.bin"
_RECORD_ENTROPY = b"FlowerControl.temporary-recording.v1"
_REPARSE = 0x400
_PUBLICATIONS = ContextVar("flower_artifact_publications", default=None)


def _check_no_reparse(path: Path) -> None:
    for candidate in (path, *path.parents):
        try:
            attributes = candidate.lstat().st_file_attributes
        except FileNotFoundError:
            continue
        if attributes & _REPARSE:
            raise ControlError("artifact_reparse_path_refused")


def artifact_path(output_path: str | None, *, suffix: str, suggested: str = "web", recording_budget=False) -> Path:
    if output_path is None:
        from flower_control.data_paths import runtime_temp_root
        root = runtime_temp_root() / "flower-web-artifacts"
        _check_no_reparse(root)
        if recording_budget:
            from .recording_storage import recording_write_errors
            with recording_write_errors():
                root.mkdir(mode=0o700, exist_ok=True)
        else:
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


@contextmanager
def _default_storage_write(target: Path, output_path, size: int, *, recording_budget: bool):
    if output_path is not None:
        yield
        return
    from flower_control.control.native import ExecutionLocks, ResourceBusy, AbandonedResource
    root = target.parent
    resource = "default-artifact-storage:" + os.path.normcase(str(root.resolve()))
    writing = False
    try:
        with ExecutionLocks((resource,)):
            _check_no_reparse(root)
            if recording_budget:
                _cleanup_expired_recordings(root)
                total = 0
                for item in root.iterdir():
                    _check_no_reparse(item)
                    info = item.stat()
                    if not item.is_file():
                        raise ControlError("recording_storage_inventory_unverified")
                    total += info.st_size
                if total + size > MAX_DEFAULT_RECORDING_STORAGE_BYTES:
                    raise ControlError("recording_storage_full")
            writing = True
            yield
            writing = False
    except ResourceBusy:
        raise ControlError("artifact_storage_busy") from None
    except AbandonedResource:
        raise ControlError("artifact_storage_unverified") from None
    except OSError as error:
        if writing and recording_budget:
            from .recording_storage import is_capacity_error
            if is_capacity_error(error):
                raise ControlError('recording_disk_full') from None
        raise ControlError("artifact_storage_unverified") from None


def _file_identity(path):
    info = path.stat()
    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns]


def _cleanup_expired_recordings(root):
    """Only DPAPI-registered, unchanged files created by this implementation."""
    import win32crypt
    for record in root.glob("*" + _RECORD_SUFFIX):
        _check_no_reparse(record)
        if not record.is_file() or record.stat().st_size > 2048:
            continue
        try:
            raw = win32crypt.CryptUnprotectData(record.read_bytes(), _RECORD_ENTROPY, None, None, 4)[1]
            metadata = json.loads(raw)
            name = metadata["name"]
            if (metadata.get("schema") != 1 or type(name) is not str
                    or not re.fullmatch(r"[a-f0-9]{32}-(app|web)-recording\.(zip|mp4)", name)
                    or record.name != name + _RECORD_SUFFIX
                    or type(metadata.get("expires_at")) not in (int, float)
                    or not math.isfinite(metadata["expires_at"])
                    or metadata["expires_at"] > time.time()):
                continue
            target = root / name
            _check_no_reparse(target)
            if not target.is_file() or _file_identity(target) != metadata.get("file_identity"):
                continue
            target.unlink()
            record.unlink()
        except (ValueError, KeyError, TypeError):
            continue
        except Exception as error:
            # Invalid encrypted registration does not confer cleanup authority.
            if isinstance(error, (OSError, ControlError)):
                raise
            continue


def _register_recording(target, *, identity=None):
    import win32crypt
    expires = time.time() + RECORDING_RETENTION_SECONDS
    metadata = {"schema": 1, "name": target.name, "expires_at": expires,
                "file_identity": identity if identity is not None else _file_identity(target)}
    sealed = win32crypt.CryptProtectData(json.dumps(metadata).encode(),
        "Flower temporary recording", _RECORD_ENTROPY, None, None, 4)
    if len(sealed) > 2048:
        raise ControlError("artifact_storage_unverified")
    record = target.with_name(target.name + _RECORD_SUFFIX)
    _check_no_reparse(record)
    with record.open("xb") as stream:
        try:
            stream.write(sealed); stream.flush(); os.fsync(stream.fileno())
            own_record = os.fstat(stream.fileno())
        except BaseException:
            owned = os.fstat(stream.fileno())
            stream.close()
            if record.exists():
                current = record.stat()
                if (current.st_dev, current.st_ino) == (owned.st_dev, owned.st_ino):
                    record.unlink()
            raise
    return {"temporary": True, "expires_at_unix": expires,
            "_record_identity": [own_record.st_dev, own_record.st_ino, own_record.st_size, own_record.st_mtime_ns],
            "retention_seconds": RECORDING_RETENTION_SECONDS,
            "save_instruction": "需要长期保存时，请明确指定 output_path 导出；默认临时结果七天后可在后续录制时回收。"}


def check_recording_storage(output_path):
    """Early admission only; publishing repeats the actual size under lock."""
    if output_path is None:
        target = artifact_path(None, suffix=".zip", suggested="app-recording", recording_budget=True)
        with _default_storage_write(target, None, 2049, recording_budget=True):
            pass


def persist_bytes(source: bytes, output_path: str | None, *, suffix: str,
                  suggested: str = "web", preflight=None) -> dict:
    if type(source) is not bytes or len(source) > MAX_ARTIFACT_BYTES:
        raise ControlError("artifact_too_large")
    target = artifact_path(output_path, suffix=suffix, suggested=suggested)
    digest = hashlib.sha256(source).hexdigest()
    # Exclusive create; an existing user file is never replaced.
    with _default_storage_write(target, output_path, len(source), recording_budget=False):
        with _publication(target, preflight) as file:
            file.write(source)
            file.flush()
            os.fsync(file.fileno())
    return {"path": str(target.resolve()), "bytes": len(source), "sha256": digest}


def persist_file(source: Path, output_path: str | None, *, suffix: str,
                 suggested: str = "web", recording_budget: bool = False, preflight=None,
                 _size_limit: int = MAX_ARTIFACT_BYTES) -> dict:
    size = source.stat().st_size
    if size > _size_limit:
        raise ControlError("artifact_too_large")
    target = artifact_path(output_path, suffix=suffix, suggested=suggested, recording_budget=recording_budget)
    digest = hashlib.sha256()
    lifecycle = {"temporary": False} if recording_budget and output_path is not None else {}
    with _default_storage_write(target, output_path, size + (2048 if recording_budget else 0), recording_budget=recording_budget):
        with _publication(target, preflight,
                          register=recording_budget and output_path is None) as writer:
            with source.open("rb") as reader:
                copied = 0
                for block in iter(lambda: reader.read(1024 * 1024), b""):
                    if preflight is not None:
                        preflight()
                    copied += len(block)
                    if copied > size or copied > _size_limit:
                        raise ControlError("artifact_source_changed")
                    digest.update(block)
                    writer.write(block)
                if copied != size:
                    raise ControlError("artifact_source_changed")
                writer.flush()
                os.fsync(writer.fileno())
        if recording_budget and output_path is None:
            lifecycle = writer.lifecycle
    return {"path": str(target.resolve()), "bytes": size, "sha256": digest.hexdigest(), **lifecycle}


def persist_web_download(source: Path, output_path: str | None, *, suggested: str, preflight=None) -> dict:
    """Publish a completed browser download with its own bounded size limit."""
    return persist_file(source, output_path, suffix="", suggested=suggested,
                        preflight=preflight, _size_limit=MAX_WEB_DOWNLOAD_BYTES)


@contextmanager
def _publication(target, preflight, *, register=False):
    """Stage locally; publish once with Windows no-overwrite rename.

    Failed publication owns only its exact unchanged output and registration.
    A pre-existing destination is never opened or removed.
    """
    if preflight is not None:
        preflight()
    with tempfile.TemporaryDirectory(prefix=".flower-publish-", dir=target.parent) as directory:
        staged = Path(directory) / "content"
        published = None
        record_identity = None
        record = target.with_name(target.name + _RECORD_SUFFIX)
        try:
            with staged.open("xb") as writer:
                yield writer
            if preflight is not None:
                preflight()
            _check_no_reparse(target.parent)
            # Windows rename is exclusive, unlike replace. The entire file is
            # already flushed before its public name becomes visible.
            published = _file_identity(staged)
            staged.rename(target)
            if _file_identity(target) != published:
                raise ControlError("artifact_output_changed")
            if register:
                writer.lifecycle = _register_recording(target, identity=published)
                record_identity = writer.lifecycle.pop("_record_identity")
            if preflight is not None:
                preflight()
            ownership = _PUBLICATIONS.get()
            if ownership is not None:
                ownership.append((target, published, record if record_identity is not None else None, record_identity))
        except BaseException:
            if record_identity is not None and record.exists() and _file_identity(record) == record_identity:
                record.unlink()
            if published is not None and target.exists() and _file_identity(target) == published:
                target.unlink()
            raise


async def checked_publication(function, *args, check, **kwargs):
    """Drain a local publisher before cancellation can retire its source files."""
    loop = asyncio.get_running_loop()
    cancelled = threading.Event()
    outputs = []
    def preflight():
        if cancelled.is_set():
            raise ControlError("artifact_publication_cancelled")
        future = asyncio.run_coroutine_threadsafe(check(), loop)
        try:
            future.result(timeout=5)
        except BaseException:
            future.cancel()
            raise
        if cancelled.is_set():
            raise ControlError("artifact_publication_cancelled")
    def execute():
        token = _PUBLICATIONS.set(outputs)
        try:
            return function(*args, preflight=preflight, **kwargs)
        finally:
            _PUBLICATIONS.reset(token)
    async def completed():
        # Python 3.14 reports an exceptional shielded task after cancellation,
        # even when a later waiter retrieves it. Keep the worker outcome data.
        try:
            return True, await asyncio.to_thread(execute)
        except BaseException as error:
            return False, error
    worker = asyncio.create_task(completed())
    try:
        success, result = await asyncio.shield(worker)
        if not success:
            raise result
        return result
    except asyncio.CancelledError:
        cancelled.set()
        while not worker.done():
            try:
                await asyncio.shield(worker)
            except asyncio.CancelledError:
                continue
            except Exception:
                break
        # Retrieve exceptions even if completion raced with cancellation.
        if not worker.cancelled():
            worker.exception()
        for target, identity, record, record_identity in outputs:
            if record is not None and record.exists() and _file_identity(record) == record_identity:
                record.unlink()
            if target.exists() and _file_identity(target) == identity:
                target.unlink()
        raise
