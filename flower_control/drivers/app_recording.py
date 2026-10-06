"""Short, exact-window WGC frame sequence saved as a local ZIP artifact."""

from __future__ import annotations

import hashlib
import json
import tempfile
import time
import zipfile
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from flower_control.drivers.computer_capture import CaptureError, capture_window
from flower_control.drivers.computer_native import WindowIdentity, assert_window
from flower_control.drivers.computer_png import bmp_to_png
from flower_control.drivers.web_artifacts import artifact_path, persist_file


class AppRecordingError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def record_window(identity: WindowIdentity, *,
                  resolve_identity: Callable[[], WindowIdentity],
                  preflight: Callable[[], None], stopped: Callable[[], bool],
                  duration_seconds: float, fps: int,
                  output_path: str | None = None) -> dict:
    """Capture at most 40 frames; no foreground activation or input resource."""
    if (not isinstance(identity, WindowIdentity) or not callable(resolve_identity)
            or not callable(preflight) or not callable(stopped)
            or type(duration_seconds) not in (int, float)
            or not 0 < duration_seconds <= 10 or type(fps) is not int
            or not 1 <= fps <= 4):
        raise AppRecordingError("invalid_record_request")
    artifact_path(output_path, suffix=".zip", suggested="app-recording")

    def recheck() -> None:
        preflight()
        if resolve_identity() != identity:
            raise AppRecordingError("selected_window_changed")
        assert_window(identity)

    recheck()
    if stopped():
        raise AppRecordingError("record_cancelled_before_start")
    started_utc = datetime.now(timezone.utc).isoformat()
    started = time.monotonic()
    slot_count = min(40, int(duration_seconds * fps) + (1 if duration_seconds * fps % 1 else 0))
    frames: list[dict] = []
    dropped: list[int] = []
    reason: str | None = None
    can_publish = True
    total_png_bytes = 0
    with tempfile.TemporaryDirectory(prefix="flower-app-record-") as directory:
        staged = Path(directory) / "recording.zip"
        with zipfile.ZipFile(staged, "w", zipfile.ZIP_DEFLATED) as archive:
            for slot in range(slot_count):
                due = started + slot / fps
                while True:
                    if stopped():
                        reason = "cancelled"
                        break
                    try:
                        recheck()
                    except Exception:
                        reason = "target_or_permission_changed"
                        can_publish = False
                        break
                    remaining = due - time.monotonic()
                    if remaining <= 0:
                        break
                    time.sleep(min(0.05, remaining))
                if reason is not None:
                    break
                if time.monotonic() > due + 1 / fps:
                    dropped.append(slot)
                    continue
                try:
                    capture = capture_window(identity, preflight=recheck,
                                             stopped=stopped, timeout=3.0,
                                             backend="WGC")
                    png = bmp_to_png(capture.bmp)
                    recheck()
                except (CaptureError, AppRecordingError, ValueError, OSError) as error:
                    reason = getattr(error, "code", "capture_failed")
                    if reason in {"selected_window_changed", "window_changed"}:
                        can_publish = False
                    break
                if stopped():
                    reason = "cancelled"
                    break
                if total_png_bytes + len(png) > 45_000_000:
                    reason = "artifact_size_limit"
                    break
                total_png_bytes += len(png)
                name = f"frames/{slot:03d}.png"
                archive.writestr(name, png)
                frames.append({"slot": slot, "captured_utc": datetime.now(timezone.utc).isoformat(),
                               "scheduled_offset_ms": round(slot * 1000 / fps, 1),
                               "name": name, "bytes": len(png),
                               "sha256": hashlib.sha256(png).hexdigest(),
                               "width": capture.width, "height": capture.height,
                               "source_bounds": asdict(capture.source_bounds),
                               "source": capture.source,
                               "content_verified": capture.content_verified,
                               "capture_elapsed_ms": capture.elapsed_ms})
            manifest = {"format": "flower-app-wgc-frames-v1",
                        "scope": "one_selected_window", "target": asdict(identity),
                        "started_utc": started_utc,
                        "finished_utc": datetime.now(timezone.utc).isoformat(),
                        "requested_duration_seconds": duration_seconds,
                        "requested_fps": fps, "scheduled_slots": slot_count,
                        "frames": frames, "dropped_slots": dropped,
                        "partial": bool(reason or dropped),
                        "stop_reason": reason,
                        "frame_format": "png"}
            archive.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))
        if not can_publish:
            return {"state": "rejected", "frames": len(frames), "partial": True,
                    "stop_reason": reason, "artifact": None,
                    "target": asdict(identity)}
        recheck()  # no captured content leaves a revoked or replaced target
        artifact = persist_file(staged, output_path, suffix=".zip",
                                suggested="app-recording")
    return {"state": "recorded" if frames else "not_verified",
            "format": "flower-app-wgc-frames-v1", "artifact": artifact,
            "frames": len(frames), "scheduled_slots": slot_count,
            "dropped_slots": dropped, "partial": manifest["partial"],
            "stop_reason": reason, "target": asdict(identity)}
