"""One-shot WGC or PrintWindow capture in an exact, parent-owned process.

The parent must authorize the target before launch. This worker rechecks the
Flower window identity and never activates, restores, or enumerates windows.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import asdict
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import zlib

import win32gui
import win32ui

from flower_control.drivers.computer_native import (
    WindowIdentity, assert_window, window_geometry,
)
from flower_control.drivers.worker_lifetime import WorkerLifetime


_user32 = ctypes.WinDLL("user32", use_last_error=True)
_user32.PrintWindow.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint]
_user32.PrintWindow.restype = ctypes.c_bool
_user32.SetProcessDpiAwarenessContext.argtypes = [ctypes.c_void_p]
_user32.SetProcessDpiAwarenessContext.restype = ctypes.c_bool
_dwmapi = ctypes.WinDLL("dwmapi", use_last_error=True)
_dwmapi.DwmGetWindowAttribute.argtypes = [ctypes.c_void_p, ctypes.c_uint,
                                          ctypes.c_void_p, ctypes.c_uint]
_dwmapi.DwmGetWindowAttribute.restype = ctypes.c_long
_MAX_PIXELS = 3840 * 2160
_MAX_BMP = 54 + _MAX_PIXELS * 4
_WGC_EXE = (Path(__file__).with_name("computer_wgc") / "bin" / "Release" /
            "net10.0-windows10.0.26100.0" / "win-x64" / "Flower.ComputerWgc.exe")


class WgcUnavailable(RuntimeError):
    pass


def _native_environment() -> dict[str, str]:
    keys = ("SystemRoot", "WINDIR", "TEMP", "TMP")
    return {key: os.environ[key] for key in keys if key in os.environ}


def _visible_bounds(hwnd: int) -> tuple[int, int, int, int]:
    rect = wintypes.RECT()
    if _dwmapi.DwmGetWindowAttribute(hwnd, 9, ctypes.byref(rect), ctypes.sizeof(rect)):
        raise WgcUnavailable("wgc_visible_bounds_unavailable")
    bounds = (rect.left, rect.top, rect.right, rect.bottom)
    if bounds[2] <= bounds[0] or bounds[3] <= bounds[1]:
        raise WgcUnavailable("wgc_visible_bounds_invalid")
    return bounds


def capture_wgc(identity: WindowIdentity) -> tuple[dict, bytes]:
    """The .NET child inherits this worker's kill-on-close Job."""
    if not _WGC_EXE.is_file():
        raise WgcUnavailable("wgc_binary_missing")
    assert_window(identity)
    if not win32gui.IsWindowVisible(identity.hwnd) or win32gui.IsIconic(identity.hwnd):
        raise RuntimeError("target_not_captureable")
    geometry = window_geometry(identity)
    visible_bounds = _visible_bounds(identity.hwnd)
    body = json.dumps(asdict(identity), separators=(",", ":")).encode("utf-8") + b"\n"
    child = subprocess.Popen(
        [str(_WGC_EXE)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, env=_native_environment(),
        creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        bmp, _ = child.communicate(input=body)
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=1)
    if child.returncode != 0:
        raise WgcUnavailable("wgc_child_failed")
    if not 54 <= len(bmp) <= _MAX_BMP or not bmp.startswith(b"BM"):
        raise WgcUnavailable("wgc_child_invalid_bitmap")
    assert_window(identity)
    if window_geometry(identity) != geometry:
        raise RuntimeError("capture_geometry_changed")
    if _visible_bounds(identity.hwnd) != visible_bounds:
        raise WgcUnavailable("wgc_visible_bounds_changed")
    width, height = struct.unpack_from("<ii", bmp, 18)
    if (width <= 0 or height >= 0 or width > 3840 or -height > 3840
            or width * -height > _MAX_PIXELS
            or visible_bounds[2] - visible_bounds[0] != width
            or visible_bounds[3] - visible_bounds[1] != -height):
        raise WgcUnavailable("wgc_child_invalid_dimensions")
    return ({"width": width, "height": -height, "source": "WGC",
             "contentVerified": False, "sourceBounds": visible_bounds}, bmp)


def capture(identity: WindowIdentity) -> tuple[dict, bytes]:
    assert_window(identity)
    if not win32gui.IsWindowVisible(identity.hwnd) or win32gui.IsIconic(identity.hwnd):
        raise RuntimeError("target_not_captureable")
    geometry = window_geometry(identity)
    width, height = geometry.window.width, geometry.window.height
    if width * height > _MAX_PIXELS:
        raise RuntimeError("capture_geometry_too_large")
    source_handle = win32gui.GetWindowDC(identity.hwnd)
    if not source_handle:
        raise RuntimeError("capture_dc_unavailable")
    source = win32ui.CreateDCFromHandle(source_handle)
    memory = source.CreateCompatibleDC()
    bitmap = win32ui.CreateBitmap()
    previous_bitmap = None
    try:
        bitmap.CreateCompatibleBitmap(source, width, height)
        previous_bitmap = memory.SelectObject(bitmap)
        if not _user32.PrintWindow(identity.hwnd, memory.GetSafeHdc(), 0):
            raise RuntimeError("print_window_failed")
        assert_window(identity)
        if window_geometry(identity) != geometry:
            raise RuntimeError("capture_geometry_changed")
        info = bitmap.GetInfo()
        pixels = bitmap.GetBitmapBits(True)
        if info["bmWidth"] != width or info["bmHeight"] != height or info["bmBitsPixel"] != 32:
            raise RuntimeError("capture_bitmap_format_unexpected")
        if len(pixels) != width * height * 4:
            raise RuntimeError("capture_bitmap_size_unexpected")
        # GDI's 32-bit compatible bitmap carries RGB plus an unused high byte,
        # not a defined alpha channel. Keep its top-down RGB rows and make the
        # PrintWindow image opaque before it enters the shared BGRA protocol.
        # WGC has its own alpha contract and does not pass through this path.
        opaque_pixels = bytearray(pixels)
        opaque_pixels[3::4] = b"\xff" * (width * height)
        pixels = bytes(opaque_pixels)
        file_size = 54 + len(pixels)
        bmp = (struct.pack("<2sIHHI", b"BM", file_size, 0, 0, 54)
               + struct.pack("<IiiHHIIiiII", 40, width, -height, 1, 32, 0,
                             len(pixels), 2835, 2835, 0, 0) + pixels)
        return ({"width": width, "height": height, "source": "PrintWindow",
                 "contentVerified": False,
                 "sourceBounds": (geometry.window.left, geometry.window.top,
                                  geometry.window.right, geometry.window.bottom)}, bmp)
    finally:
        if previous_bitmap is not None:
            memory.SelectObject(previous_bitmap)
        memory.DeleteDC()
        source.DeleteDC()
        win32gui.ReleaseDC(identity.hwnd, source_handle)
        win32gui.DeleteObject(bitmap.GetHandle())


def main() -> int:
    if len(sys.argv) != 3 or not _user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4)):
        return 2
    lifetime = WorkerLifetime(sys.argv[1], sys.argv[2])
    status = 0
    try:
        request = json.loads(sys.stdin.buffer.read(2048))
        if (not isinstance(request, dict) or set(request) != {"identity", "backend"}
                or request["backend"] not in ("WGC", "PrintWindow")):
            raise ValueError("invalid_capture_request")
        raw = request["identity"]
        if not isinstance(raw, dict) or set(raw) != {
                "hwnd", "pid", "process_created", "window_nonce"}:
            raise ValueError("invalid_capture_identity")
        identity = WindowIdentity(**raw)
        metadata, bmp = (capture_wgc(identity) if request["backend"] == "WGC"
                         else capture(identity))
        body = zlib.compress(bmp, level=3)
        if len(body) > 32_000_000:
            raise RuntimeError("capture_compressed_too_large")
        header = json.dumps({**metadata, "compressedBytes": len(body),
                             "bmpBytes": len(bmp)}, separators=(",", ":")).encode("utf-8")
        sys.stdout.buffer.write(struct.pack("<I", len(header)) + header + body)
        sys.stdout.buffer.flush()
    except WgcUnavailable:
        print("WgcUnavailable", file=sys.stderr)
        status = 4
    except Exception as error:
        # Only an error class goes to stderr; target content never does.
        print(type(error).__name__, file=sys.stderr)
        status = 3
    lifetime.exit(status)
    return status  # unreachable after TerminateJobObject


if __name__ == "__main__":
    raise SystemExit(main())
