"""Bounded, in-memory window capture for an already authorized target.

This internal primitive does not establish target ownership or a private-profile
grant. Its caller must supply a live permission check. WGC and PrintWindow
return visual data, never proof of current app content.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
import struct
import subprocess
import time
from typing import Callable
import uuid
import zlib

import win32con
import win32event
import win32gui

from flower_control.control.native import process_identity
from .computer_native import Rect, WindowIdentity, assert_window, window_geometry
from .worker_python import worker_python


_MAX_BMP = 54 + 3840 * 2160 * 4
_MAX_COMPRESSED = 32_000_000


class CaptureError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class CaptureResult:
    bmp: bytes
    width: int
    height: int
    source: str
    source_bounds: Rect
    elapsed_ms: float
    content_verified: bool = False
    fallback_reason: str | None = None


def _safe_environment() -> dict[str, str]:
    import os

    keys = ("SystemRoot", "WINDIR", "TEMP", "TMP", "ComSpec")
    return {key: os.environ[key] for key in keys if key in os.environ}


def _decode(data: bytes) -> tuple[dict, bytes]:
    if len(data) < 4:
        raise CaptureError("capture_worker_empty")
    header_size = struct.unpack_from("<I", data)[0]
    if not 0 < header_size <= 512 or len(data) < 4 + header_size:
        raise CaptureError("capture_worker_invalid_header")
    try:
        header = json.loads(data[4:4 + header_size])
    except (ValueError, UnicodeError) as error:
        raise CaptureError("capture_worker_invalid_header") from error
    if (not isinstance(header, dict) or set(header) != {
            "width", "height", "source", "sourceBounds", "contentVerified",
            "compressedBytes", "bmpBytes"}
            or type(header["width"]) is not int or type(header["height"]) is not int
            or type(header["compressedBytes"]) is not int or type(header["bmpBytes"]) is not int
            or header["source"] not in ("WGC", "PrintWindow")
            or header["contentVerified"] is not False
            or type(header["sourceBounds"]) is not list
            or len(header["sourceBounds"]) != 4
            or any(type(value) is not int for value in header["sourceBounds"])
            or header["sourceBounds"][2] - header["sourceBounds"][0] != header["width"]
            or header["sourceBounds"][3] - header["sourceBounds"][1] != header["height"]
            or not 1 <= header["width"] <= 3840 or not 1 <= header["height"] <= 3840
            or header["width"] * header["height"] > 3840 * 2160
            or not 0 < header["compressedBytes"] <= _MAX_COMPRESSED
            or not 54 <= header["bmpBytes"] <= _MAX_BMP):
        raise CaptureError("capture_worker_invalid_header")
    compressed = data[4 + header_size:]
    if len(compressed) != header["compressedBytes"]:
        raise CaptureError("capture_worker_invalid_length")
    inflater = zlib.decompressobj()
    try:
        bmp = inflater.decompress(compressed, _MAX_BMP + 1)
    except zlib.error as error:
        raise CaptureError("capture_worker_invalid_bitmap") from error
    if (len(bmp) != header["bmpBytes"] or not inflater.eof or inflater.unused_data
            or inflater.unconsumed_tail
            or not bmp.startswith(b"BM") or len(bmp) != 54 + header["width"] * header["height"] * 4):
        raise CaptureError("capture_worker_invalid_bitmap")
    file_size, offset = struct.unpack_from("<IxxxxI", bmp, 2)
    dib_size, width, height, planes, bit_count, compression = struct.unpack_from(
        "<IiiHHI", bmp, 14)
    if (file_size != len(bmp) or offset != 54 or dib_size != 40
            or (width, height) != (header["width"], -header["height"])
            or planes != 1 or bit_count != 32 or compression != 0):
        raise CaptureError("capture_worker_invalid_bitmap")
    return header, bmp


def _attempt(identity: WindowIdentity, *, backend: str, geometry,
             preflight: Callable[[], None], stopped: Callable[[], bool],
             deadline: float) -> tuple[dict, bytes]:
    """Run one backend in a disposable worker and check the target again."""
    preflight()
    if stopped():
        raise CaptureError("capture_cancelled")
    assert_window(identity)
    if not win32gui.IsWindowVisible(identity.hwnd) or win32gui.IsIconic(identity.hwnd):
        raise CaptureError("target_not_captureable")
    if window_geometry(identity) != geometry:
        raise CaptureError("capture_target_changed")
    if deadline <= time.monotonic():
        raise CaptureError("capture_timeout")
    stop_name = "Local\\FlowerControl.CaptureStop." + uuid.uuid4().hex
    stop_event = win32event.CreateEvent(None, True, False, stop_name)
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = win32con.SW_HIDE
    process = None
    try:
        process = subprocess.Popen(
            [worker_python(), "-B", "-m", "flower_control.drivers.computer_capture_worker",
             process_identity(), stop_name],
            cwd=str(Path(__file__).resolve().parents[2]), env=_safe_environment(),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            startupinfo=startup, creationflags=subprocess.CREATE_NO_WINDOW)
        request = json.dumps({"identity": asdict(identity), "backend": backend},
                             separators=(",", ":")).encode("utf-8")
        data: bytes | None = None
        while data is None:
            if stopped():
                raise CaptureError("capture_cancelled")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CaptureError("capture_timeout")
            try:
                data, _stderr = process.communicate(input=request, timeout=min(0.1, remaining))
            except subprocess.TimeoutExpired:
                request = None
        # A stop or grant revocation can race the worker's final exit. Check
        # those states before interpreting a nonzero exit as backend failure.
        if stopped():
            raise CaptureError("capture_cancelled")
        preflight()
        if process.returncode == 4 and backend == "WGC":
            raise CaptureError("capture_wgc_unavailable")
        if process.returncode != 0:
            raise CaptureError("capture_worker_failed")
        if len(data) > _MAX_COMPRESSED + 516:
            raise CaptureError("capture_worker_too_large")
        header, bmp = _decode(data)
        if header["source"] != backend:
            raise CaptureError("capture_worker_wrong_backend")
        preflight()
        if stopped():
            raise CaptureError("capture_cancelled")
        assert_window(identity)
        if (window_geometry(identity) != geometry or win32gui.IsIconic(identity.hwnd)
                or not win32gui.IsWindowVisible(identity.hwnd)):
            raise CaptureError("capture_target_changed")
        return header, bmp
    finally:
        if process is not None and process.poll() is None:
            win32event.SetEvent(stop_event)
            try:
                process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                process.kill()  # exact worker PID; its Job owns only descendants
                process.wait(timeout=1)
        if process is not None:
            for stream in (getattr(process, "stdin", None),
                           getattr(process, "stdout", None),
                           getattr(process, "stderr", None)):
                if stream is not None and not stream.closed:
                    stream.close()
        stop_event.Close()


def capture_window(identity: WindowIdentity, *, preflight: Callable[[], None],
                   stopped: Callable[[], bool], timeout: float = 3.0,
                   backend: str = "auto") -> CaptureResult:
    """Prefer WGC; optionally fall back to PrintWindow after fresh checks.

    The full attempt shares one deadline. A worker timeout or cancellation is
    never automatically replayed through another backend.
    """
    if not isinstance(identity, WindowIdentity) or not callable(preflight) or not callable(stopped):
        raise TypeError("bound identity and live preflight/stop checks are required")
    if type(timeout) not in (int, float) or not 0.1 <= timeout <= 10:
        raise ValueError("capture timeout must be 0.1..10 seconds")
    if backend not in ("auto", "WGC", "PrintWindow"):
        raise ValueError("capture backend must be auto, WGC, or PrintWindow")
    preflight()
    if stopped():
        raise CaptureError("capture_cancelled")
    assert_window(identity)
    if not win32gui.IsWindowVisible(identity.hwnd) or win32gui.IsIconic(identity.hwnd):
        raise CaptureError("target_not_captureable")
    geometry = window_geometry(identity)
    if geometry.window.width * geometry.window.height > 3840 * 2160:
        raise CaptureError("capture_geometry_too_large")
    started = time.perf_counter()
    deadline = time.monotonic() + timeout
    fallback_reason = None
    if backend in ("auto", "WGC"):
        try:
            header, bmp = _attempt(identity, backend="WGC", geometry=geometry,
                                   preflight=preflight, stopped=stopped, deadline=deadline)
        except CaptureError as error:
            if backend != "auto" or error.code != "capture_wgc_unavailable":
                raise
            fallback_reason = error.code
        else:
            return CaptureResult(bmp, header["width"], header["height"], "WGC",
                                 Rect(*header["sourceBounds"]),
                                 round((time.perf_counter() - started) * 1000, 1))
    header, bmp = _attempt(identity, backend="PrintWindow", geometry=geometry,
                           preflight=preflight, stopped=stopped, deadline=deadline)
    return CaptureResult(bmp, header["width"], header["height"], "PrintWindow",
                         Rect(*header["sourceBounds"]),
                         round((time.perf_counter() - started) * 1000, 1),
                         fallback_reason=fallback_reason)
