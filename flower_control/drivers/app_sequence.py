"""Bounded, exact-count window samples; no old runtime or session dependency."""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import time
import zipfile
import threading

from . import app_recording as recording
from .app_screenshot import masked_frame_png
from .computer_capture import capture_window
from .computer_native import WindowIdentity
from .computer_png import bmp_to_png
from .web_artifacts import artifact_path, check_recording_storage, persist_file


class FrameGroupOwnership:
    """Late host cancellation owns only this request's unpublished group."""
    def __init__(self,store,task):
        self.store,self.task=store,task;self.lock=threading.RLock()
        self.receipt=None;self.closed=False;self.published=False
    def adopt(self,receipt):
        with self.lock:
            if self.closed:
                self.store.discard_unpublished(self.task,receipt)
                raise recording.AppRecordingError('sequence_cancelled')
            self.receipt=receipt
    def publish(self,outcome):
        result=outcome.get('result',{})
        with self.lock:
            if self.receipt is not None and not self.closed and result.get('retained_group',{}).get('artifact_id')==self.receipt['artifact_id']:
                self.published=True
    def close(self):
        with self.lock:
            self.closed=True
            if self.receipt is not None and not self.published:
                self.store.discard_unpublished(self.task,self.receipt);self.receipt=None


def sequence_options(limits):
    options = {} if limits is None else limits
    if type(options) is not dict or set(options) - {"frame_count", "duration_milliseconds", "client_area", "output_path", "retain_frames"}:
        raise recording.AppRecordingError("invalid_sequence_request")
    count = options.get("frame_count", 5)
    duration = options.get("duration_milliseconds", 1000)
    client = options.get("client_area", False)
    output = options.get("output_path")
    if (type(count) is not int or not 2 <= count <= 12
            or type(duration) is not int or not 100 <= duration <= 5000
            or type(client) is not bool
            or type(options.get('retain_frames',False)) is not bool
            or output is not None and (type(output) is not str or not output or "\0" in output)):
        raise recording.AppRecordingError("invalid_sequence_request")
    return count, duration, client, output


def capture_sequence(identity, *, resolve_identity, preflight, stopped,
                     frame_count=5, duration_milliseconds=1000, client_area=False,
                     output_path=None, task=None, retain_frames=False, artifact_store=None,retained_target=None,ownership=None):
    """Capture every slot including both endpoints; failures publish no group."""
    count, duration_ms, client, output = sequence_options(dict(frame_count=frame_count,
        duration_milliseconds=duration_milliseconds, client_area=client_area, output_path=output_path))
    if (not isinstance(identity, WindowIdentity) or not callable(resolve_identity)
            or not callable(preflight) or not callable(stopped)):
        raise recording.AppRecordingError("invalid_sequence_request")
    artifact_path(output, suffix=".zip", suggested="app-recording")
    check_recording_storage(output)
    from flower_control.permissions import PermissionError
    from flower_control.privacy import capture_private
    guard = recording._RecordingGuard(identity, resolve_identity, preflight)
    guard.check()
    if client:
        guard.geometry = recording.window_geometry(identity)
    started = time.monotonic()
    started_utc = datetime.now(timezone.utc).isoformat()
    # Each capture has a five-second budget. Slow captures are never replayed
    # or replaced by dropped slots; the whole group has an additional bound.
    deadline = started + duration_ms / 1000 + count * 5
    interval = duration_ms / 1000 / (count - 1)
    if type(retain_frames) is not bool or retain_frames and (artifact_store is None or task is None):
        raise recording.AppRecordingError('invalid_sequence_request')
    if retain_frames and (type(retained_target) is not dict or set(retained_target)!={'pid','hwnd','process_start_filetime'}
            or retained_target['pid']!=identity.pid or retained_target['hwnd']!=identity.hwnd
            or type(retained_target['process_start_filetime']) is not int):
        raise recording.AppRecordingError('invalid_sequence_request')
    rows, first_geometry, total, retained = [], None, 0, []

    def check():
        guard.check()
        if stopped():
            raise recording.AppRecordingError("sequence_cancelled")
        if time.monotonic() >= deadline:
            raise recording.AppRecordingError("sequence_deadline_exceeded")

    with tempfile.TemporaryDirectory(prefix="flower-app-sequence-") as directory:
        staged = Path(directory) / "sequence.zip"
        with zipfile.ZipFile(staged, "w", zipfile.ZIP_DEFLATED) as archive:
            for index in range(count):
                due = started + index * interval
                while True:
                    check()
                    remaining = due - time.monotonic()
                    if remaining <= 0:
                        break
                    time.sleep(min(.05, remaining))
                try:
                    capture = capture_private(identity, lambda: capture_window(identity,
                        preflight=check, stopped=stopped, timeout=min(5.0, deadline-time.monotonic()), backend="WGC"),
                        preflight=check, stopped=stopped, task=task)
                except PermissionError as error:
                    raise recording.AppRecordingError(error.code) from None
                check()
                if guard.geometry is None:
                    png = bmp_to_png(capture.bmp)
                    bounds, width, height = capture.source_bounds, capture.width, capture.height
                else:
                    png, bounds, width, height = masked_frame_png(capture, guard.geometry)
                geometry = (bounds, width, height)
                if first_geometry is not None and geometry != first_geometry:
                    raise recording.AppRecordingError("sequence_geometry_changed")
                first_geometry = geometry
                total += len(png)
                if total > 45_000_000:
                    raise recording.AppRecordingError("artifact_size_limit")
                check()
                name = f"frames/{index:03d}.png"
                archive.writestr(name, png)
                if retain_frames:retained.append(png)
                rows.append(dict(index=index, name=name, scheduled_offset_ms=round(index*interval*1000, 3),
                    actual_offset_ms=round((time.monotonic()-started)*1000, 3),
                    sha256=hashlib.sha256(png).hexdigest(), bytes=len(png), width=width, height=height,
                    source_bounds=asdict(bounds), source=capture.source, content_verified=capture.content_verified,
                    capture_elapsed_ms=capture.elapsed_ms))
            hashes = [row["sha256"] for row in rows]
            unique = len(set(hashes))
            classification = "static" if unique == 1 else "periodic_reset_candidate" if hashes[0] == hashes[-1] else "changed"
            manifest = dict(format="flower-app-window-sequence-v1", scope="one_selected_window",
                target=asdict(identity), frame_count=count, requested_duration_milliseconds=duration_ms,
                actual_duration_milliseconds=round((time.monotonic()-started)*1000, 3),
                started_utc=started_utc, frames=rows, unique_hash_count=unique,
                change_classification=classification, client_area=client, partial=False,
                task_success_verified=False)
            archive.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))
        check()
        group=None
        try:
            if retain_frames:
                meta=dict(channel='app',scope='one_selected_window',target={**retained_target,
                    'window_nonce':identity.window_nonce,'process_created':identity.process_created},
                    source_bounds=asdict(bounds),width=width,height=height,privacy_revision=capture.privacy_revision)
                group=artifact_store.put_frames(task,retained,metadata=meta,authorize=lambda _:check() is None)
                if ownership is not None:ownership.adopt(group['group'])
                for row,receipt in zip(rows,group['frames']):row['retained_artifact']=receipt
                manifest['retained_group']=group['group']
                with zipfile.ZipFile(staged,'a',zipfile.ZIP_DEFLATED) as archive:
                    archive.writestr('retained_frames.json',json.dumps(group,ensure_ascii=True))
                check()
            artifact = persist_file(staged, output, suffix=".zip", suggested="app-recording", recording_budget=True, preflight=check)
        except BaseException:
            if group is not None:
                if ownership is not None:ownership.close()
                else:artifact_store.discard_unpublished(task,group['group'])
            raise
    return {"state": "recorded", **manifest, "artifact": artifact}
