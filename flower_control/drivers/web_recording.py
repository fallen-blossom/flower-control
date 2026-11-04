"""Bounded page frames; reuse App's local encoder, storage and retention."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import json
import math
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from PIL import Image

from flower_control.control.state import ControlError
from flower_control.control.write_gate import session_write_gate
from .web_artifacts import artifact_path, check_recording_storage, persist_file, checked_publication
from .recording_storage import zip_storage_usage, recording_write_errors, recording_workspace


def record_options(arguments):
    if type(arguments) is not dict or set(arguments) - {"page_id", "duration_seconds", "fps", "format", "output_path"}:
        raise ControlError("invalid_record_request")
    duration, fps, format_ = arguments.get("duration_seconds", 3), arguments.get("fps", 2), arguments.get("format", "zip")
    if (type(duration) not in (int, float) or not math.isfinite(duration) or not 0 < duration <= 120
            or type(fps) is not int or not 1 <= fps <= 30
            or type(format_) is not str or format_ not in {"zip", "mp4"}):
        raise ControlError("invalid_record_request")
    return duration, fps, format_


async def record_page(runtime, driver, page_id, arguments, *, check):
    duration, fps, format_ = record_options(arguments)
    output = arguments.get("output_path")
    artifact_path(output, suffix="." + format_, suggested="web-recording", recording_budget=True)
    check_recording_storage(output)
    encoder = None
    if format_ == "mp4":
        from .local_video import approved_encoder
        encoder = approved_encoder()
        encoder.verify()
    page = driver.page

    async def recheck():
        await check()
        if session_write_gate().snapshot().stopped:
            raise ControlError("global_stop_active")
        if runtime.pages.get(page_id) is not driver or page.is_closed():
            raise ControlError("page_changed")
        runtime.verify_private_request(driver, "record", arguments)

    await recheck()
    loop = asyncio.get_running_loop()
    started = loop.time()
    slots = math.ceil(duration * fps)
    frames, dropped = [], []
    total = 0
    geometry = None
    reason = None
    with recording_workspace(prefix="flower-web-record-") as temporary:
        staged = Path(temporary) / "frames.zip"
        with recording_write_errors(), zipfile.ZipFile(staged, "w", zipfile.ZIP_DEFLATED) as archive:
            for slot in range(slots):
                due = started + slot / fps
                while loop.time() < due:
                    await recheck()
                    await asyncio.sleep(min(.025, due - loop.time()))
                await recheck()
                if loop.time() > due + 1 / fps:
                    dropped.append(slot)
                    continue
                screenshot = await runtime.execute("screenshot", {"page_id": page_id, "animations": "allow", "caret": "initial"}, check=recheck)
                captured_elapsed = loop.time() - started
                captured_utc = datetime.now(timezone.utc).isoformat()
                await recheck()
                runtime.verify_private_response("screenshot", {"page_id": page_id})
                pixels = base64.b64decode(screenshot["base64"], validate=True)
                with Image.open(io.BytesIO(pixels)) as image:
                    if image.width * image.height > 16_000_000:
                        raise ControlError("screenshot_too_large")
                    if geometry is not None and geometry != image.size:
                        reason = "video_geometry_changed"
                        break
                    geometry = image.size
                    encoded = io.BytesIO()
                    image.convert("RGB").save(encoded, "PNG")
                data = encoded.getvalue()
                if total + len(data) > 45_000_000:
                    reason = "record_size_limit"
                    break
                total += len(data)
                name = f"frames/{len(frames):03d}.png"
                archive.writestr(name, data)
                frames.append({"name": name, "slot": slot,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "captured_utc": captured_utc,
                    "captured_elapsed_seconds": captured_elapsed,
                    "width": geometry[0], "height": geometry[1]})
            # Include the final requested sampling interval, with fresh Stop checks.
            if reason is None:
                while loop.time() < started + duration:
                    await recheck()
                    await asyncio.sleep(min(.025, started + duration - loop.time()))
            capture_elapsed = loop.time() - started
            manifest = {"format": "flower-web-frames-v1", "scope": "one_bound_page", "page_id": page_id,
                "frames": frames, "finished_utc": datetime.now(timezone.utc).isoformat(),
                "finished_elapsed_seconds": capture_elapsed,
                "requested_duration_seconds": duration, "requested_fps": fps,
                "scheduled_slots": slots, "dropped_slots": dropped,
                "partial": bool(reason or dropped), "stop_reason": reason, "frame_format": "png"}
            archive.writestr("manifest.json", json.dumps(manifest))
        await recheck()
        if not frames:
            return {"state": "not_verified", "frames": 0, "partial": True, "artifact": None, "stop_reason": reason}
        if format_ == "mp4":
            from .local_video import export_recording
            result = await checked_publication(export_recording, staged, output_path=output,
                check=recheck, stopped=lambda: session_write_gate().snapshot().stopped, encoder=encoder)
            await recheck()
        else:
            with recording_write_errors():
                artifact = await checked_publication(persist_file, staged, output, suffix=".zip",
                    suggested="web-recording", recording_budget=True, check=recheck)
            result = {"state": "recorded", "format": "flower-web-frames-v1", "artifact": artifact,
                "storage_usage": zip_storage_usage(staged, artifact)}
        return {**result, "scope": "one_bound_page", "page_id": page_id, "frames": len(frames),
            "requested_duration_seconds": duration, "requested_fps": fps,
            "scheduled_slots": slots, "dropped_slots": dropped,
            "partial": manifest["partial"], "stop_reason": reason,
            "actual_duration_seconds": capture_elapsed,
            "actual_average_fps": len(frames) / capture_elapsed if capture_elapsed else 0}
