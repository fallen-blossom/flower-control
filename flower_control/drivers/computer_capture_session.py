"""Internal F1 capture session; not selected by production MCP tools yet."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from collections import deque
import json
from pathlib import Path
import queue
import struct
import subprocess
import threading
import time
import uuid

import win32event

from flower_control.control.native import process_identity
from .computer_capture import CaptureError, CaptureResult, _safe_environment
from .computer_native import Rect, WindowIdentity, assert_window, window_geometry
from .worker_python import worker_python


MAX_BMP_BYTES = 54 + 3840 * 2160 * 4
_DIAGNOSTIC_STAGES = frozenset({"worker_started", "child_started", "session_ready", "request_received",
    "capture_started", "snapshot_started", "frame_written", "frame_wait", "fresh_frame_timeout", "error",
    "pool_create", "session_create", "capture_start", "frame_read", "frame_encode", "session_close", "pool_close",
    "native_eof", "native_exited", "session_closed"})
_DIAGNOSTIC_CODES = frozenset({"dpi_context_unavailable", "invalid_request_size", "invalid_request_shape",
    "invalid_request_identity", "target_identity_changed", "target_process_changed", "target_geometry_invalid",
    "target_geometry_changed", "wgc_unsupported", "frame_format_or_size_invalid", "frame_stride_invalid",
    "frame_buffer_incomplete", "fresh_frame_timeout", "wgc_error", "worker_error", "invalid_session_request",
    "invalid_frame_request", "capture_target_changed", "wgc_binary_missing", "capture_session_eof",
    "capture_session_invalid_header", "capture_session_invalid_bitmap", "native_shutdown_failed"})
_DIAGNOSTIC_NUMBERS = frozenset({"request_id", "frame_id", "compositor_ticks", "requested_ticks",
    "idle_frames", "stale_frames", "qpc_frequency", "elapsed_ms"})
_DIAGNOSTIC_TYPES = frozenset({"COMException", "ObjectDisposedException", "InvalidOperationException",
    "OperationCanceledException", "ArgumentException", "OtherException"})


def safe_diagnostic(line):
    """Allowlist non-image stage metadata; never forward raw child stderr."""
    if len(line) > 1024:
        return None
    try:
        value = json.loads(line)
        if (type(value) is not dict or value.get("origin") not in ("wgc", "worker") or
                value.get("stage") not in _DIAGNOSTIC_STAGES or
                value.get("code") not in _DIAGNOSTIC_CODES | {None} or
                value.get("error_type") not in _DIAGNOSTIC_TYPES | {None} or
                set(value) - ({"origin", "stage", "code", "hresult", "error_type"} | _DIAGNOSTIC_NUMBERS)):
            return None
        hresult = value.get("hresult")
        if hresult is not None and (type(hresult) is not int or not 0 <= hresult <= 0xffffffff):
            return None
        if any(type(number) not in (int, float) or not 0 <= number <= 10**18
               for key, number in value.items() if key in _DIAGNOSTIC_NUMBERS):
            return None
        return value
    except (ValueError, TypeError, UnicodeError):
        return None


def read_exact(stream, size):
    parts = []
    remaining = size
    while remaining:
        part = stream.read(remaining)
        if not part:
            raise CaptureError("capture_session_eof")
        parts.append(part)
        remaining -= len(part)
    return b"".join(parts)


def read_frame(stream):
    length = struct.unpack("<I", read_exact(stream, 4))[0]
    if not 1 <= length <= 1024:
        raise CaptureError("capture_session_invalid_header")
    try:
        header = json.loads(read_exact(stream, length))
        required = {"request_id", "frame_id", "captured_ticks", "timestamp_frequency", "bmp_bytes",
                    "width", "height", "source_bounds", "elapsed_ms", "content_verified", "capture_mode",
                    "snapshot_id", "requested_ticks", "acquired_ticks", "source_rendered_after_request"}
        if type(header) is not dict or set(header) != required:
            raise ValueError()
        for name in ("request_id", "frame_id", "captured_ticks", "timestamp_frequency", "bmp_bytes", "width", "height",
                     "snapshot_id", "requested_ticks", "acquired_ticks"):
            if type(header[name]) is not int or header[name] <= 0:
                raise ValueError()
        bounds = header["source_bounds"]
        if (header["capture_mode"] != "request_started_snapshot" or header["snapshot_id"] != header["request_id"] or
                header["acquired_ticks"] <= header["requested_ticks"] or
                type(header["source_rendered_after_request"]) is not bool or
                header["source_rendered_after_request"] != (header["captured_ticks"] > header["requested_ticks"]) or
                header["bmp_bytes"] != 54 + header["width"] * header["height"] * 4 or
                header["bmp_bytes"] > MAX_BMP_BYTES or not 1 <= header["width"] <= 3840 or
                not 1 <= header["height"] <= 3840 or header["content_verified"] is not False or
                type(header["elapsed_ms"]) not in (int, float) or not 0 <= header["elapsed_ms"] <= 8000 or
                type(bounds) is not list or len(bounds) != 4 or any(type(x) is not int for x in bounds) or
                bounds[2] - bounds[0] != header["width"] or bounds[3] - bounds[1] != header["height"]):
            raise ValueError()
    except (KeyError, ValueError, TypeError, UnicodeError) as error:
        raise CaptureError("capture_session_invalid_header") from error
    bmp = read_exact(stream, header["bmp_bytes"])
    if (not bmp.startswith(b"BM") or struct.unpack_from("<I", bmp, 2)[0] != len(bmp) or
            struct.unpack_from("<ii", bmp, 18) != (header["width"], -header["height"])):
        raise CaptureError("capture_session_invalid_bitmap")
    return header, bmp


@dataclass(frozen=True)
class SessionFrame:
    capture: CaptureResult
    frame_id: int
    captured_ticks: int
    timestamp_frequency: int
    snapshot_id: int
    requested_ticks: int
    acquired_ticks: int
    source_rendered_after_request: bool


class ComputerCaptureSession:
    """One exact window, serialized fresh frames, finite independent worker life."""
    def __init__(self, identity: WindowIdentity, *, preflight, stopped):
        preflight()
        if stopped():
            raise CaptureError("capture_cancelled")
        assert_window(identity)
        self.identity = identity
        self.geometry = window_geometry(identity)
        self.expires = time.monotonic() + 8
        self.request_id = 0
        self.frame_id = 0
        self.gate = threading.Lock()
        self.closed = False
        self.stop_name = "Local\\FlowerCaptureSession-" + uuid.uuid4().hex
        self.stop_event = win32event.CreateEvent(None, True, False, self.stop_name)
        self.responses = queue.Queue(maxsize=1)
        self._diagnostics = deque(maxlen=64)
        self._diagnostic_gate = threading.Lock()
        try:
            self.worker = subprocess.Popen(
                [worker_python(), "-m", "flower_control.drivers.computer_capture_session_worker"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd=str(Path(__file__).resolve().parents[2]),
                env=_safe_environment(), creationflags=subprocess.CREATE_NO_WINDOW)
            body = {"identity": asdict(identity), "owner_identity": process_identity(), "stop_event": self.stop_name}
            self.worker.stdin.write(json.dumps(body).encode() + b"\n")
            self.worker.stdin.flush()
        except BaseException:
            win32event.SetEvent(self.stop_event)
            self.stop_event.Close()
            if hasattr(self, "worker") and self.worker.poll() is None:
                self.worker.kill()
                self.worker.wait(timeout=1)
            raise
        self.reader = threading.Thread(target=self._read, name="flower-capture-session-reader", daemon=True)
        self.reader.start()
        self.diagnostic_reader = threading.Thread(target=self._read_diagnostics,
            name="flower-capture-session-diagnostics", daemon=True)
        self.diagnostic_reader.start()

    def _read_diagnostics(self):
        for line in iter(lambda: self.worker.stderr.readline(1025), b""):
            value = safe_diagnostic(line)
            if value is not None:
                with self._diagnostic_gate:
                    self._diagnostics.append(value)

    def diagnostics(self):
        with self._diagnostic_gate:
            return {"requested": self.request_id, "last_frame_id": self.frame_id,
                    "shutdown_mode": getattr(self, "shutdown_mode", None),
                    "shutdown_error": getattr(self, "shutdown_error", None),
                    "worker_returncode": self.worker.poll(), "stages": list(self._diagnostics)}

    def _read(self):
        try:
            while not self.closed:
                result = read_frame(self.worker.stdout)
                self.responses.put_nowait(result)
        except Exception as error:
            try:
                self.responses.put_nowait(error)
            except queue.Full:
                pass

    def frame(self, *, preflight, stopped, budget=3.0):
        with self.gate:
            if self.closed or time.monotonic() >= self.expires:
                self.close()
                raise CaptureError("capture_session_expired")
            if self.request_id >= 16:
                self.close()
                raise CaptureError("capture_session_expired")
            try:
                preflight()
                if stopped():
                    raise CaptureError("capture_cancelled")
                assert_window(self.identity)
                if window_geometry(self.identity) != self.geometry:
                    raise CaptureError("capture_target_changed")
            except BaseException:
                self.close(abort=True)
                raise
            self.request_id += 1
            began = time.monotonic()
            try:
                self.worker.stdin.write(json.dumps({"op": "frame", "request_id": self.request_id}).encode() + b"\n")
                self.worker.stdin.flush()
                deadline = min(self.expires, began + max(.01, min(3.0, budget)))
                while True:
                    preflight()
                    if stopped():
                        raise CaptureError("capture_cancelled")
                    if time.monotonic() >= deadline:
                        raise CaptureError("capture_timeout")
                    try:
                        response = self.responses.get(timeout=min(.01, max(.001, deadline - time.monotonic())))
                        break
                    except queue.Empty:
                        continue
                if isinstance(response, BaseException):
                    raise response
                header, bmp = response
                if header["request_id"] != self.request_id or header["frame_id"] <= self.frame_id:
                    raise CaptureError("capture_session_stale_frame")
                preflight()
                if stopped():
                    raise CaptureError("capture_cancelled")
                assert_window(self.identity)
                if window_geometry(self.identity) != self.geometry:
                    raise CaptureError("capture_target_changed")
                self.frame_id = header["frame_id"]
                return SessionFrame(CaptureResult(bmp, header["width"], header["height"], "WGC",
                    Rect(*header["source_bounds"]), (time.monotonic() - began) * 1000),
                    self.frame_id, header["captured_ticks"], header["timestamp_frequency"],
                    header["snapshot_id"], header["requested_ticks"], header["acquired_ticks"],
                    header["source_rendered_after_request"])
            except BaseException:
                self.close(abort=True)
                raise

    def close(self, *, abort=False):
        if self.closed:
            return
        self.closed = True
        # Normal EOF lets the native capture device and session dispose.
        # Abort/parent death retain exact Job termination, never a broad kill.
        self.shutdown_mode = "abort" if abort else "eof"
        self.shutdown_error = None
        try:
            if abort:
                win32event.SetEvent(self.stop_event)
            else:
                try:
                    self.worker.stdin.close()
                except OSError:
                    self.shutdown_error = "stdin_eof_failed"
                    self.shutdown_mode = "forced"
                    win32event.SetEvent(self.stop_event)
            try:
                self.worker.wait(timeout=1)
            except subprocess.TimeoutExpired:
                self.shutdown_mode = "forced"
                win32event.SetEvent(self.stop_event)
                try:
                    self.worker.wait(timeout=.25)
                except subprocess.TimeoutExpired:
                    self.worker.kill()
                self.worker.wait(timeout=1)
        finally:
            try:
                self.diagnostic_reader.join(timeout=.25)
            finally:
                try:
                    for stream in (self.worker.stdin, self.worker.stdout, self.worker.stderr):
                        try:
                            stream.close()
                        except OSError:
                            self.shutdown_error = self.shutdown_error or "stream_close_failed"
                finally:
                    self.stop_event.Close()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close(abort=_args[0] is not None)
