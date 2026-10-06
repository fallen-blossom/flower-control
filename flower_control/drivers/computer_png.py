"""Encode the capture worker's validated top-down BGRA bitmap as PNG.

The worker protocol deliberately uses a narrow BMP format. This converter
accepts only that format and never decodes arbitrary image files. Its output is
for an already authorized MCP visual return, not for target verification.
"""

from __future__ import annotations

import struct
import zlib


_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_MAX_PIXELS = 3840 * 2160  # Match ComputerRuntime and capture worker.


def _chunk(kind: bytes, data: bytes) -> bytes:
    return (struct.pack(">I", len(data)) + kind + data
            + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF))


def bmp_to_png(bmp: bytes) -> bytes:
    """Losslessly convert one bounded 32-bit top-down BGRA BMP to RGBA PNG."""
    if type(bmp) is not bytes or len(bmp) < 54 or bmp[:2] != b"BM":
        raise ValueError("invalid_capture_bitmap")
    file_size, pixel_offset = struct.unpack_from("<IxxxxI", bmp, 2)
    dib_size, width, negative_height, planes, bit_count, compression = (
        struct.unpack_from("<IiiHHI", bmp, 14))
    height = -negative_height
    if (file_size != len(bmp) or pixel_offset != 54 or dib_size != 40
            or planes != 1 or bit_count != 32 or compression != 0
            or not 1 <= width <= 3840 or not 1 <= height <= 3840
            or width * height > _MAX_PIXELS
            or len(bmp) != 54 + width * height * 4):
        raise ValueError("invalid_capture_bitmap")

    stride = width * 4
    pixels = memoryview(bmp)[54:]
    rows = bytearray((stride + 1) * height)
    for y in range(height):
        source = pixels[y * stride:(y + 1) * stride]
        start = y * (stride + 1) + 1  # Filter byte 0 precedes each row.
        rows[start:start + stride:4] = source[2::4]  # R
        rows[start + 1:start + stride:4] = source[1::4]  # G
        rows[start + 2:start + stride:4] = source[0::4]  # B
        rows[start + 3:start + stride:4] = source[3::4]  # A

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return (_PNG_SIGNATURE + _chunk(b"IHDR", ihdr)
            + _chunk(b"IDAT", zlib.compress(rows, level=3))
            + _chunk(b"IEND", b""))
