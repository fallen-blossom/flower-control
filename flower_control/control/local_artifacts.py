"""Bounded generated artifacts, encrypted locally and retrieved by chat ID."""
from __future__ import annotations

import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import struct
import time
import uuid
import zipfile
from contextlib import contextmanager

import win32crypt

from .state import ControlError
from flower_control.drivers.web_artifacts import _check_no_reparse


class LocalArtifactStore:
    MAX_BYTES = 50_000_000
    MAX_CHAT_BYTES = 100_000_000
    MAX_FILES = 64

    def __init__(self, directory, *, clock=time.time):
        self.directory = Path(directory) / "artifacts-v1"
        self.clock = clock

    def _path(self, task, artifact_id):
        if type(task) is not str or not task or len(task) > 256:
            raise ControlError("artifact_task_unverified")
        if type(artifact_id) is not str or not re.fullmatch(r"[a-f0-9]{32}", artifact_id):
            raise ControlError("artifact_id_invalid")
        chat = hashlib.sha256(task.encode()).hexdigest()
        path = self.directory / chat / (artifact_id + ".bin")
        _check_no_reparse(path)
        return path

    @staticmethod
    def _metadata(value):
        allowed = {"channel", "scope", "target", "source_bounds", "width", "height", "privacy_revision", "capture_id"}
        if (type(value) is not dict or set(value) - allowed
                or value.get("channel") not in {"web", "app", "computer"}
                or value.get("scope") not in {"one_selected_window", "one_bound_page", "chat_metadata"}):
            raise ControlError("artifact_metadata_invalid")
        raw = json.dumps(value, allow_nan=False, separators=(",", ":")).encode()
        if len(raw) > 8192:
            raise ControlError("artifact_metadata_invalid")
        return json.loads(raw)

    def put(self, task, data, *, kind, metadata):
        if type(data) is not bytes or len(data) > self.MAX_BYTES or kind not in {"image", "baseline", "trace", "video", "image_group"}:
            raise ControlError("artifact_payload_invalid")
        metadata = self._metadata(metadata)
        artifact_id = uuid.uuid4().hex
        path = self._path(task, artifact_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        _check_no_reparse(path.parent)
        header = {"schema": 1, "artifact_id": artifact_id, "kind": kind,
                  "task_sha256": hashlib.sha256(task.encode()).hexdigest(),
                  "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
                  "metadata": metadata, "created_at": self.clock(), "expires_at": self.clock() + 86400}
        encoded = json.dumps(header, allow_nan=False, separators=(",", ":")).encode()
        payload = struct.pack("<I", len(encoded)) + encoded + data
        entropy = (task + ":" + artifact_id).encode()
        sealed = win32crypt.CryptProtectData(payload, "Flower generated artifact", entropy, None, None, 4)
        # Encrypt before taking the per-chat allocation lock. Only a complete,
        # flushed ciphertext is published under its readable .bin identity.
        with self._allocation(path.parent, len(sealed)):
            staging = path.with_suffix(".pending")
            created = False
            try:
                with staging.open("xb") as stream:
                    created = True
                    if stream.write(sealed) != len(sealed):
                        raise OSError("artifact_short_write")
                    stream.flush()
                    os.fsync(stream.fileno())
                _check_no_reparse(path)
                if path.exists():
                    raise ControlError("artifact_already_exists")
                # This is a Windows-only store: rename fails if a destination
                # already exists, including one raced in after the check.
                staging.rename(path)
            except BaseException:
                if created:
                    try:
                        _check_no_reparse(staging)
                        staging.unlink(missing_ok=True)
                    except OSError:
                        raise ControlError("artifact_cleanup_pending") from None
                raise
        return {"artifact_id": artifact_id, "kind": kind, "sha256": header["sha256"],
                "bytes": len(data), "expires_at": header["expires_at"], "scope": "this_chat",
                "encrypted_at_rest": True}

    @contextmanager
    def _allocation(self, directory, size):
        with self._storage_gate(directory):
            inventory = [*directory.glob("*.bin"), *directory.glob("*.pending")]
            for item in inventory:
                _check_no_reparse(item)
                if not item.is_file():
                    raise ControlError("artifact_storage_unverified")
            # Crash leftovers consume space but are never silently deleted.
            if (len(inventory) >= self.MAX_FILES or
                    sum(item.stat().st_size for item in inventory) + size > self.MAX_CHAT_BYTES):
                raise ControlError("artifact_store_full")
            yield

    @contextmanager
    def _storage_gate(self, directory):
        from .native import ExecutionLocks, ResourceBusy, AbandonedResource
        resource = "local-artifact-storage:" + os.path.normcase(str(directory.resolve()))
        try:
            with ExecutionLocks((resource,)):
                _check_no_reparse(directory)
                yield
        except ResourceBusy:
            raise ControlError("artifact_storage_busy") from None
        except AbandonedResource:
            raise ControlError("artifact_storage_unverified") from None
        except OSError:
            raise ControlError("artifact_storage_unverified") from None

    def put_frames(self,task,frames,*,metadata,authorize):
        """One encrypted allocation; opaque member IDs retain independent reads."""
        if type(frames) is not list or not 2<=len(frames)<=12 or not callable(authorize):
            raise ControlError('artifact_payload_invalid')
        metadata=self._metadata(metadata)
        if authorize(metadata) is not True:raise ControlError('artifact_content_not_authorized')
        output=io.BytesIO();members=[];total=0
        with zipfile.ZipFile(output,'w',zipfile.ZIP_STORED) as archive:
            for data in frames:
                if type(data) is not bytes:raise ControlError('artifact_payload_invalid')
                total+=len(data)
                if total>45_000_000:raise ControlError('artifact_payload_invalid')
                from PIL import Image
                with Image.open(io.BytesIO(data)) as image:
                    if image.format!='PNG' or image.size!=(metadata.get('width'),metadata.get('height')):
                        raise ControlError('artifact_payload_invalid')
                    image.verify()
                member=uuid.uuid4().hex
                archive.writestr(member+'.png',data)
                members.append(dict(member=member,sha256=hashlib.sha256(data).hexdigest(),bytes=len(data)))
            archive.writestr('manifest.json',json.dumps(dict(schema=1,frames=members),separators=(',',':')))
        if authorize(metadata) is not True:raise ControlError('artifact_content_not_authorized')
        receipt=self.put(task,output.getvalue(),kind='image_group',metadata=metadata)
        # No plaintext is written to disk. IDs do not grant future content access.
        return dict(group=receipt,frames=[dict(artifact_id=receipt['artifact_id']+'.'+row['member'],
            sha256=row['sha256'],bytes=row['bytes'],kind='image',encrypted_at_rest=True) for row in members])

    def discard_unpublished(self,task,receipt):
        """Internal rollback for this exact, newly generated encrypted group."""
        path=self._path(task,receipt['artifact_id'])
        with self._storage_gate(path.parent):
            metadata,data=self.read(task,receipt['artifact_id'],authorize=lambda _:True)
            if metadata['kind']!='image_group' or metadata['sha256']!=receipt['sha256']:
                raise ControlError('artifact_integrity_unverified')
            path.unlink()

    def read(self, task, artifact_id, *, authorize):
        """Current content authorization is required; the stored ID grants nothing."""
        if not callable(authorize):
            raise ControlError("artifact_content_not_authorized")
        if type(artifact_id) is str and re.fullmatch(r'[a-f0-9]{32}\.[a-f0-9]{32}',artifact_id):
            parent,member=artifact_id.split('.')
            metadata,data=self.read(task,parent,authorize=authorize)
            try:
                if metadata['kind']!='image_group':raise ValueError('kind')
                with zipfile.ZipFile(io.BytesIO(data)) as archive:
                    infos=archive.infolist()
                    if not 3<=len(infos)<=13 or len({i.filename for i in infos})!=len(infos):raise ValueError('members')
                    manifest_info=archive.getinfo('manifest.json')
                    if manifest_info.file_size>8192:raise ValueError('manifest')
                    manifest=json.loads(archive.read(manifest_info))
                    rows=manifest['frames']
                    if manifest['schema']!=1 or type(rows) is not list or not 2<=len(rows)<=12:raise ValueError('manifest')
                    row=next(row for row in rows if row['member']==member)
                    info=archive.getinfo(member+'.png')
                    if not 1<=info.file_size<=self.MAX_BYTES or info.file_size!=row['bytes']:raise ValueError('size')
                    pixels=archive.read(info)
                    if hashlib.sha256(pixels).hexdigest()!=row['sha256']:raise ValueError('digest')
            except Exception:raise ControlError('artifact_integrity_unverified') from None
            content={key:value for key,value in metadata.items() if key not in {'kind','sha256','artifact_id'}}
            if authorize(content) is not True:raise ControlError('artifact_content_not_authorized')
            return {**content,'artifact_id':artifact_id,'kind':'image','sha256':row['sha256']},pixels
        header, metadata, data = self._load(task, artifact_id)
        if authorize(metadata) is not True:
            raise ControlError("artifact_content_not_authorized")
        if authorize(metadata) is not True:
            raise ControlError("artifact_content_not_authorized")
        return {**metadata, "kind": header["kind"], "sha256": header["sha256"], "artifact_id": artifact_id}, data

    def receipt(self, task, artifact_id):
        """Only task-owned integrity facts; never content, target or input authority."""
        if type(artifact_id) is str and re.fullmatch(r'[a-f0-9]{32}\.[a-f0-9]{32}', artifact_id):
            parent, member = artifact_id.split('.')
            header, _, data = self._load(task, parent)
            try:
                if header['kind'] != 'image_group':
                    raise ValueError('kind')
                with zipfile.ZipFile(io.BytesIO(data)) as archive:
                    infos = archive.infolist()
                    if not 3 <= len(infos) <= 13 or len({item.filename for item in infos}) != len(infos):
                        raise ValueError('members')
                    if archive.getinfo('manifest.json').file_size > 8192:
                        raise ValueError('manifest')
                    manifest = json.loads(archive.read('manifest.json'))
                    if manifest['schema'] != 1 or type(manifest['frames']) is not list or not 2 <= len(manifest['frames']) <= 12:
                        raise ValueError('manifest')
                    rows = [row for row in manifest['frames'] if row.get('member') == member]
                    if len(rows) != 1:
                        raise ValueError('member')
                    row = rows[0]
                    info = archive.getinfo(member + '.png')
                    if type(row['bytes']) is not int or not 1 <= info.file_size <= self.MAX_BYTES or info.file_size != row['bytes']:
                        raise ValueError('size')
                    pixels = archive.read(info)
                    if hashlib.sha256(pixels).hexdigest() != row['sha256']:
                        raise ValueError('digest')
            except Exception:
                raise ControlError('artifact_integrity_unverified') from None
            return dict(artifact_id=artifact_id, kind='image', sha256=row['sha256'], bytes=row['bytes'], expires_at=header['expires_at'])
        header, _, _data = self._load(task, artifact_id)
        return {key: header[key] for key in ("artifact_id", "kind", "sha256", "bytes", "expires_at")}

    def _load(self, task, artifact_id):
        path = self._path(task, artifact_id)
        try:
            if not path.is_file() or path.stat().st_size > self.MAX_BYTES + 20000:
                raise ValueError("missing or oversized")
            payload = win32crypt.CryptUnprotectData(path.read_bytes(), (task + ":" + artifact_id).encode(), None, None, 4)[1]
            size = struct.unpack_from("<I", payload)[0]
            if not 1 <= size <= 16384 or size + 4 > len(payload):
                raise ValueError("header")
            header = json.loads(payload[4:4 + size])
            data = payload[4 + size:]
            if (header.get("schema") != 1 or header.get("artifact_id") != artifact_id
                    or header.get("task_sha256") != hashlib.sha256(task.encode()).hexdigest()
                    or type(header.get("expires_at")) not in (int, float)
                    or not math.isfinite(header["expires_at"])
                    or header["expires_at"] < self.clock()
                    or header.get("bytes") != len(data)
                    or header.get("kind") not in {"image", "baseline", "trace", "video", "image_group"}):
                raise ValueError("identity")
            metadata = self._metadata(header["metadata"])
            if header.get("sha256") != hashlib.sha256(data).hexdigest():
                raise ValueError("digest")
        except ControlError:
            raise
        except Exception:
            raise ControlError("artifact_integrity_unverified") from None
        return header, metadata, data


def compare_png(baseline, current, *, channel_tolerance=0, max_changed_ratio=0.0, masks=()):
    """Compare an explicitly accepted local image, not adjacent-frame stability."""
    from PIL import Image, ImageChops, ImageDraw
    if (type(channel_tolerance) is not int or not 0 <= channel_tolerance <= 255
            or type(max_changed_ratio) not in (int, float) or not 0 <= max_changed_ratio <= 1
            or type(masks) not in (tuple, list) or len(masks) > 128):
        raise ControlError("visual_compare_request_invalid")
    with Image.open(io.BytesIO(baseline)) as left, Image.open(io.BytesIO(current)) as right:
        if left.format != "PNG" or right.format != "PNG" or left.size != right.size or left.width * left.height > 16_000_000:
            raise ControlError("visual_compare_geometry_changed")
        difference = ImageChops.difference(left.convert("RGBA"), right.convert("RGBA"))
        changed = Image.new("L", left.size)
        for channel in difference.split():
            changed = ImageChops.lighter(changed, channel.point(lambda value: 255 if value > channel_tolerance else 0))
        draw = ImageDraw.Draw(changed)
        for mask in masks:
            if (type(mask) not in (tuple, list) or len(mask) != 4 or any(type(n) is not int for n in mask)
                    or not 0 <= mask[0] < mask[2] <= left.width or not 0 <= mask[1] < mask[3] <= left.height):
                raise ControlError("visual_compare_mask_invalid")
            draw.rectangle((mask[0], mask[1], mask[2] - 1, mask[3] - 1), fill=0)
        count = changed.histogram()[255]
        total = left.width * left.height
        return {"state": "compared", "matched": count / total <= max_changed_ratio,
                "changed_pixels": count, "total_pixels": total, "changed_ratio": count / total,
                "channel_tolerance": channel_tolerance, "max_changed_ratio": max_changed_ratio,
                "comparison_scope": "accepted_local_baseline", "proves_business_success": False}
