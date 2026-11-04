"""Encode only our already-redacted frame ZIP with a fixed local encoder."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import io
import json
import math
from pathlib import Path
import re
import subprocess
import tempfile
import time
import zipfile

from flower_control.control.state import ControlError
from .web_artifacts import _check_no_reparse, artifact_path, persist_file, MAX_ARTIFACT_BYTES, check_recording_storage
from .recording_storage import RecordingStorageUsage, recording_write_errors, recording_workspace


@dataclass(frozen=True)
class EncoderIdentity:
    path: Path
    sha256: str

    def verify(self):
        _check_no_reparse(self.path)
        if (not self.path.is_absolute() or self.path.name.lower() != "ffmpeg.exe"
                or type(self.sha256) is not str or not re.fullmatch(r"[a-f0-9]{64}", self.sha256)):
            raise ControlError("video_encoder_unverified")
        with self.path.open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        if actual != self.sha256:
            raise ControlError("video_encoder_changed")


def approved_encoder():
    # No PATH/environment discovery or arbitrary command from MCP parameters.
    from .high_helper import _installed_bundle
    from flower_control.permissions import _check_protection
    bundle, _ = _installed_bundle()
    policy_path = bundle.directory / "broker.json"
    _check_protection(policy_path, require_label=False)
    rule = json.loads(policy_path.read_bytes()).get("MediaEncoder")
    if type(rule) is not dict or set(rule) != {"Path", "Sha256"}:
        raise ControlError("video_encoder_unavailable")
    result = EncoderIdentity(Path(rule["Path"]), rule["Sha256"])
    if result.path != bundle.directory / "runtime/encoder/ffmpeg.exe":
        raise ControlError("video_encoder_unverified")
    result.verify()
    return result


def _capture_timeline(manifest, frames):
    """Prefer a complete monotonic timeline; UTC remains a legacy input."""
    try:
        wall_times = [datetime.fromisoformat(frame["captured_utc"]) for frame in frames]
        wall_finish = datetime.fromisoformat(manifest["finished_utc"])
        if any(value.tzinfo is None or value.utcoffset() is None for value in [*wall_times, wall_finish]):
            raise ValueError("naive recording timestamp")
        monotonic = ("finished_elapsed_seconds" in manifest or
                     any("captured_elapsed_seconds" in frame for frame in frames))
        if monotonic:
            timestamps = [frame["captured_elapsed_seconds"] for frame in frames]
            finished = manifest["finished_elapsed_seconds"]
            if any(type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 125
                   for value in [*timestamps, finished]):
                raise ValueError("invalid monotonic recording timestamp")
        else:
            timestamps = [value.timestamp() for value in wall_times]
            finished = wall_finish.timestamp()
        if (any(right < left for left, right in zip(timestamps, timestamps[1:]))
                or finished < timestamps[-1] or not 0 <= finished - timestamps[0] <= 125):
            raise ValueError("recording timeline reversed or too long")
        durations = [max(.01, right - left) for left, right in zip(timestamps, timestamps[1:] + [finished])]
        if sum(durations) > 125:
            raise ValueError("recording holds too long")
        return durations, "monotonic_capture_timestamps" if monotonic else "actual_capture_timestamps"
    except (KeyError, TypeError, ValueError, OverflowError, OSError):
        raise ControlError("video_timestamps_invalid") from None


def export_recording(source, *, output_path=None, preflight, stopped, encoder=None):
    """No raw window capture, network protocol, shell, audio or recorder replay."""
    from PIL import Image
    encoder = encoder or approved_encoder()
    encoder.verify()
    artifact_path(output_path, suffix=".mp4", suggested="app-recording", recording_budget=True)
    check_recording_storage(output_path)
    preflight()
    if stopped():
        raise ControlError("video_export_cancelled")
    with recording_workspace(prefix="flower-video-encode-") as temporary:
        root = Path(temporary)
        storage = RecordingStorageUsage(source)
        storage.sample(root)
        with zipfile.ZipFile(source) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)):
                raise ControlError("video_manifest_invalid")
            if "manifest.json" not in names:
                raise ControlError("video_manifest_invalid")
            info = archive.getinfo("manifest.json")
            if info.file_size > 3_000_000:
                raise ControlError("video_manifest_invalid")
            try:
                manifest = json.loads(archive.read(info))
            except (ValueError, UnicodeError):
                raise ControlError("video_manifest_invalid") from None
            if type(manifest) is not dict:
                raise ControlError("video_manifest_invalid")
            frames = manifest.get("frames")
            if (type(manifest.get("format")) is not str or type(manifest.get("scope")) is not str
                    or (manifest.get("format"), manifest.get("scope")) not in {
                    ("flower-app-wgc-frames-v1", "one_selected_window"),
                    ('flower-app-isolated-region-frames-v1','desktop_region_isolated_composite'),
                    ("flower-web-frames-v1", "one_bound_page")}
                    or type(frames) is not list or not 1 <= len(frames) <= 3600
                    or any(type(frame) is not dict for frame in frames)):
                raise ControlError("video_manifest_invalid")
            frame_names = [frame.get("name") for frame in frames]
            if (any(type(name) is not str or not re.fullmatch(r"frames/[0-9]{3,4}\.png", name)
                    or name not in names for name in frame_names)
                    or len(set(frame_names)) != len(frame_names)):
                raise ControlError("video_manifest_invalid")
            durations, timing_source = _capture_timeline(manifest, frames)
            total = 0
            expected_size = None
            region_bounds=None
            for index, frame in enumerate(frames):
                name = frame.get("name")
                if type(name) is not str or not re.fullmatch(r"frames/[0-9]{3,4}\.png", name):
                    raise ControlError("video_manifest_invalid")
                entry = archive.getinfo(name)
                total += entry.file_size
                if total > 45_000_000:
                    raise ControlError("video_frames_too_large")
                data = archive.read(entry)
                if hashlib.sha256(data).hexdigest() != frame.get("sha256"):
                    raise ControlError("video_frame_changed")
                with Image.open(io.BytesIO(data)) as image:
                    if image.format != "PNG" or image.width * image.height > 16_000_000:
                        raise ControlError("video_frame_invalid")
                    expected_size = expected_size or image.size
                    if image.size != expected_size:
                        raise ControlError("video_geometry_changed")
                    if manifest.get('scope')=='desktop_region_isolated_composite':
                        bounds=frame.get('source_bounds')
                        if (type(bounds) is not dict or set(bounds)!={'left','top','right','bottom'}
                                or any(type(v) is not int for v in bounds.values())
                                or not 1<=bounds['right']-bounds['left']<=3840
                                or not 1<=bounds['bottom']-bounds['top']<=2160
                                or image.size!=(bounds['right']-bounds['left'],bounds['bottom']-bounds['top'])
                                or (frame.get('width'),frame.get('height'))!=image.size
                                or region_bounds is not None and bounds!=region_bounds):
                            raise ControlError('video_manifest_invalid')
                        region_bounds=bounds
                with recording_write_errors():
                    (root / f"frame{index:03d}.png").write_bytes(data)
                storage.extracted_bytes += len(data)
                storage.sample(root)
                preflight()
                if stopped():
                    raise ControlError("video_export_cancelled")
        timeline = []
        for index, duration in enumerate(durations):
            # Include a terminal repeated sample one millisecond before the
            # requested end, so -t does not discard the final hold duration.
            held_duration = duration - .001 if index == len(durations) - 1 else duration
            timeline.extend((f"file 'frame{index:03d}.png'", "option framerate 1000", f"duration {held_duration:.6f}"))
        timeline.append(f"file 'frame{len(frames) - 1:03d}.png'")
        timeline.append("option framerate 1000")
        with recording_write_errors():
            (root / "frames.ffconcat").write_text("ffconcat version 1.0\n" + "\n".join(timeline) + "\n", encoding="ascii")
        storage.sample(root)
        target = root / "recording.mp4"
        progress = root / "encode.progress"
        args = [str(encoder.path), "-nostdin", "-hide_banner", "-loglevel", "error", "-n",
                "-protocol_whitelist", "file", "-f", "concat", "-safe", "0", "-i", "frames.ffconcat",
                "-an", "-map_metadata", "-1", "-vf", "pad=ceil(iw/2)*2:ceil(ih/2)*2",
                "-c:v", "libx264", "-preset", "veryfast", "-crf", "18", "-pix_fmt", "yuv420p",
                "-fps_mode", "vfr", "-enc_time_base", "1:1000", "-t", f"{sum(durations):.6f}",
                "-fs", str(MAX_ARTIFACT_BYTES), "-progress", str(progress), str(target)]
        preflight()
        encoder.verify()
        process = subprocess.Popen(args, shell=False, cwd=root, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   creationflags=subprocess.CREATE_NO_WINDOW)
        started = time.monotonic()
        try:
            while process.poll() is None:
                preflight()
                storage.sample(root)
                if target.exists() and target.stat().st_size >= MAX_ARTIFACT_BYTES:
                    raise ControlError("video_output_size_limit")
                if stopped() or time.monotonic() - started > 20:
                    raise ControlError("video_export_cancelled" if stopped() else "video_export_timeout")
                time.sleep(.025)
            if process.returncode != 0 or not target.is_file():
                raise ControlError("video_encode_failed")
            if target.stat().st_size >= MAX_ARTIFACT_BYTES:
                raise ControlError("video_output_size_limit")
            # -fs can finish successfully with a shortened file. Require the
            # encoder's own local output timeline before reporting completion.
            values = dict(line.split("=", 1) for line in progress.read_text(encoding="ascii").splitlines()
                          if "=" in line) if progress.is_file() else {}
            try:
                encoded_frames = int(values["frame"])
            except (KeyError, ValueError):
                raise ControlError("video_timeline_unverified") from None
            # out_time_us is the last DTS, not the display duration (B frames
            # can make it much earlier). Our VFR stream must include every
            # captured input frame instead of accepting an -fs-shortened prefix.
            if values.get("progress") != "end" or encoded_frames < len(frames):
                raise ControlError("video_timeline_incomplete")
            preflight()
            if stopped():
                raise ControlError("video_export_cancelled")
            def publish_check():
                preflight()
                if stopped():
                    raise ControlError("video_export_cancelled")
            with recording_write_errors():
                artifact = persist_file(target, output_path, suffix=".mp4", suggested="app-recording", recording_budget=True,
                                        preflight=publish_check)
            storage.sample(root, published_bytes=artifact['bytes'])
        finally:
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=2)
                except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=2)
        return {"state": "recorded", "format": "mp4", "artifact": artifact, "frames": len(frames),
                "encoded_frames": encoded_frames,
                "timeline_seconds": sum(durations), "timing_source": timing_source,
                "timestamp_quantization_seconds": .001, "partial": bool(manifest.get("partial")),
                "scope": manifest["scope"], "audio": False, "network_protocols": False,
                "encoder_sha256": encoder.sha256, "storage_usage": storage.result()}
