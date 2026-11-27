"""Binary-header image dimension parsing without an image decoder."""
from __future__ import annotations

from typing import Optional

from ._util import ascii_at, bytes_equal_at, normalize_bytes, u16be, u16le, u32be, u32le
from .models import ImageDimensions

_INT32_MAX = 0x7FFFFFFF


def _make_dimensions(format_name: str, width: int, height: int) -> Optional[ImageDimensions]:
    if not isinstance(width, int) or not isinstance(height, int):
        return None
    if width <= 0 or height <= 0:
        return None
    if width > _INT32_MAX or height > _INT32_MAX:
        return None
    pixels = width * height
    return ImageDimensions(format_name, width, height, pixels)


def parse_png_dimensions(data: bytes) -> Optional[ImageDimensions]:
    if not bytes_equal_at(data, 0, b"\x89PNG\r\n\x1a\n"):
        return None
    if len(data) < 33 or u32be(data, 8) != 13 or ascii_at(data, 12, 4) != "IHDR":
        return None
    return _make_dimensions("png", u32be(data, 16), u32be(data, 20))


JPEG_SOF_MARKERS = frozenset((0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF))


def parse_jpeg_dimensions(data: bytes) -> Optional[ImageDimensions]:
    """Walk JPEG markers monotonically until a start-of-frame segment is found."""
    if not bytes_equal_at(data, 0, b"\xff\xd8"):
        return None
    position = 2
    for _segments in range(1024):
        if position >= len(data) or data[position] != 0xFF:
            return None
        while position < len(data) and data[position] == 0xFF:
            position += 1
        if position >= len(data):
            return None
        marker = data[position]
        position += 1
        if marker == 0x00:
            return None
        if marker == 0x01 or 0xD0 <= marker <= 0xD9:
            if marker == 0xD9:
                return None
            continue
        if position + 2 > len(data):
            return None
        segment_length = u16be(data, position)
        if segment_length < 2 or position + segment_length > len(data):
            return None
        if marker in JPEG_SOF_MARKERS:
            if segment_length < 7:
                return None
            height = u16be(data, position + 3)
            width = u16be(data, position + 5)
            return _make_dimensions("jpeg", width, height)
        if marker == 0xDA:
            return None
        position += segment_length
    return None


def parse_gif_dimensions(data: bytes) -> Optional[ImageDimensions]:
    if ascii_at(data, 0, 6) not in ("GIF87a", "GIF89a") or len(data) < 10:
        return None
    return _make_dimensions("gif", u16le(data, 6), u16le(data, 8))


def parse_webp_dimensions(data: bytes) -> Optional[ImageDimensions]:
    if ascii_at(data, 0, 4) != "RIFF" or ascii_at(data, 8, 4) != "WEBP":
        return None
    position = 12
    for _chunks in range(64):
        if position + 8 > len(data):
            return None
        chunk_type = ascii_at(data, position, 4)
        size = u32le(data, position + 4)
        data_start = position + 8
        if size < 0 or data_start + size > len(data):
            return None
        if chunk_type == "VP8X":
            if size < 10 or data_start + 10 > len(data):
                return None
            width = 1 + data[data_start + 4] + (data[data_start + 5] << 8) + (data[data_start + 6] << 16)
            height = 1 + data[data_start + 7] + (data[data_start + 8] << 8) + (data[data_start + 9] << 16)
            return _make_dimensions("webp", width, height)
        if chunk_type == "VP8 ":
            if size < 10 or data_start + 10 > len(data):
                return None
            if not (data[data_start + 3] == 0x9D and data[data_start + 4] == 0x01 and data[data_start + 5] == 0x2A):
                return None
            width = u16le(data, data_start + 6) & 0x3FFF
            height = u16le(data, data_start + 8) & 0x3FFF
            return _make_dimensions("webp", width, height)
        if chunk_type == "VP8L":
            if size < 5 or data_start + 5 > len(data) or data[data_start] != 0x2F:
                return None
            bits = data[data_start + 1] | (data[data_start + 2] << 8) | (data[data_start + 3] << 16) | (data[data_start + 4] << 24)
            width = (bits & 0x3FFF) + 1
            height = ((bits >> 14) & 0x3FFF) + 1
            return _make_dimensions("webp", width, height)
        position = data_start + size + (size % 2)
    return None


def _signed32(value: int) -> int:
    return value - 0x100000000 if value > 0x7FFFFFFF else value


def parse_bmp_dimensions(data: bytes) -> Optional[ImageDimensions]:
    if ascii_at(data, 0, 2) != "BM" or len(data) < 26:
        return None
    dib_size = u32le(data, 14)
    if dib_size == 12:
        return _make_dimensions("bmp", u16le(data, 18), u16le(data, 20))
    if dib_size >= 40:
        if len(data) < 26:
            return None
        width = _signed32(u32le(data, 18))
        height = _signed32(u32le(data, 22))
        if width <= 0 or height == 0:
            return None
        return _make_dimensions("bmp", width, abs(height))
    return None


def inspect_image_dimensions(input_bytes) -> Optional[ImageDimensions]:
    """Return width, height and pixels for PNG, JPEG, GIF, WebP, or BMP.

    The function reads only bounded binary headers. It never invokes Pillow,
    libmagic, a codec, or a decoder.
    """
    data = normalize_bytes(input_bytes)
    return (
        parse_png_dimensions(data)
        or parse_jpeg_dimensions(data)
        or parse_gif_dimensions(data)
        or parse_webp_dimensions(data)
        or parse_bmp_dimensions(data)
    )
