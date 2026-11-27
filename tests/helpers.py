"""Shared deterministic byte fixtures for the pyfilecage test suite."""
from __future__ import annotations

import struct
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from pyfilecage import validate_upload  # noqa: E402


def ascii_bytes(text):
    return str(text).encode("utf-8")


def concat_bytes(*parts):
    return b"".join(bytes(part) if not isinstance(part, str) else ascii_bytes(part) for part in parts)


def u16be_bytes(value):
    return struct.pack(">H", value & 0xFFFF)


def u16le_bytes(value):
    return struct.pack("<H", value & 0xFFFF)


def u32be_bytes(value):
    return struct.pack(">I", value & 0xFFFFFFFF)


def u32le_bytes(value):
    return struct.pack("<I", value & 0xFFFFFFFF)


def png(width=1, height=1, *, no_ihdr=False, idat=True, iend=True, trailing=b""):
    out = bytearray(b"\x89PNG\r\n\x1a\n")
    if no_ihdr:
        return bytes(out)
    out += u32be_bytes(13) + b"IHDR" + u32be_bytes(width) + u32be_bytes(height) + bytes((8, 2, 0, 0, 0, 0, 0, 0, 0))
    if idat:
        out += u32be_bytes(0) + b"IDAT" + b"\x00\x00\x00\x00"
    if iend:
        out += u32be_bytes(0) + b"IEND" + b"\x00\x00\x00\x00"
    return bytes(out) + trailing


def jpeg(width=1, height=1, *, marker=0xC0, components=1, length_override=None, no_dimension_payload=False,
         app0=False, padding=0, trailing_fill=0, eoi=True):
    segment_length = (8 + components * 3) if length_override is None else length_override
    out = bytearray((0xFF, 0xD8))
    if app0:
        out += bytes((0xFF, 0xE0, 0x00, 0x02))
    if padding:
        out += b"\xff" * padding
    out += bytes((0xFF, marker)) + u16be_bytes(segment_length)
    if not no_dimension_payload:
        out += bytes((8,)) + u16be_bytes(height) + u16be_bytes(width) + bytes((components,))
        for _index in range(components * 3):
            out += bytes((1, 0x11, 0))
    if trailing_fill:
        out += b"\x00" * trailing_fill
    if eoi:
        out += bytes((0xFF, 0xD9))
    return bytes(out)


def gif(width=1, height=1, *, version="GIF89a", trailer=True, trailing=b""):
    out = bytearray(ascii_bytes(version) + u16le_bytes(width) + u16le_bytes(height) + b"\x00\x00\x00")
    if trailer:
        out += b"\x3b"
    return bytes(out) + trailing


def _riff_webp(chunk_type, payload):
    padded = len(payload) + (len(payload) % 2)
    riff_size = 4 + 8 + padded
    return (
        ascii_bytes("RIFF") + u32le_bytes(riff_size) + ascii_bytes("WEBP")
        + ascii_bytes(chunk_type) + u32le_bytes(len(payload)) + payload
        + (b"\x00" if len(payload) % 2 else b"")
    )


def webp_vp8(width=1, height=1):
    payload = bytes((0, 0, 0, 0x9D, 0x01, 0x2A)) + u16le_bytes(width) + u16le_bytes(height)
    return _riff_webp("VP8 ", payload)


def webp_vp8l(width=1, height=1):
    bits = (width - 1) | ((height - 1) << 14)
    payload = bytes((0x2F, bits & 255, (bits >> 8) & 255, (bits >> 16) & 255, (bits >> 24) & 255))
    return _riff_webp("VP8L", payload)


def webp_vp8x(width=1, height=1):
    width_minus = width - 1
    height_minus = height - 1
    payload = bytes((
        0, 0, 0, 0,
        width_minus & 255, (width_minus >> 8) & 255, (width_minus >> 16) & 255,
        height_minus & 255, (height_minus >> 8) & 255, (height_minus >> 16) & 255,
    ))
    return _riff_webp("VP8X", payload)


def bmp(width=1, height=1, *, core=False):
    if core:
        return (
            ascii_bytes("BM") + u32le_bytes(26) + b"\x00\x00\x00\x00" + u32le_bytes(14)
            + u32le_bytes(12) + u16le_bytes(width) + u16le_bytes(height) + b"\x01\x00\x18\x00"
        )
    stored_height = height if height >= 0 else 0x100000000 + height
    return (
        ascii_bytes("BM") + u32le_bytes(54) + b"\x00\x00\x00\x00" + u32le_bytes(54)
        + u32le_bytes(40) + u32le_bytes(width) + u32le_bytes(stored_height)
        + b"\x01\x00\x18\x00" + u32le_bytes(0) + u32le_bytes(0) + u32le_bytes(0) + u32le_bytes(0) + u32le_bytes(0) + u32le_bytes(0)
    )


def zip_bytes(entries, *, empty_end=False):
    parts = []
    for entry in entries:
        name = ascii_bytes(entry["name"] if isinstance(entry, dict) else entry[0])
        source = entry.get("data", "") if isinstance(entry, dict) else (entry[1] if len(entry) > 1 else "")
        data = source if isinstance(source, bytes) else ascii_bytes(source)
        header = (
            b"PK\x03\x04" + u16le_bytes(20) + u16le_bytes(0) + u16le_bytes(0)
            + u16le_bytes(0) + u16le_bytes(0) + u32le_bytes(0)
            + u32le_bytes(len(data)) + u32le_bytes(len(data))
            + u16le_bytes(len(name)) + u16le_bytes(0)
        )
        parts.append(header + name + data)
    if empty_end:
        parts.append(b"PK\x05\x06" + bytes(18))
    return concat_bytes(*parts)


def central_entry(name):
    encoded = ascii_bytes(name)
    return (
        b"PK\x01\x02"
        + u16le_bytes(20) + u16le_bytes(20) + u16le_bytes(0) + u16le_bytes(0)
        + u16le_bytes(0) + u16le_bytes(0) + u32le_bytes(0) + u32le_bytes(0) + u32le_bytes(0)
        + u16le_bytes(len(encoded)) + u16le_bytes(0) + u16le_bytes(0) + u16le_bytes(0) + u16le_bytes(0)
        + u32le_bytes(0) + u32le_bytes(0) + encoded
    )


def central_only_zip(names):
    local = (
        b"PK\x03\x04"
        + u16le_bytes(20) + u16le_bytes(8) + u16le_bytes(0)
        + u16le_bytes(0) + u16le_bytes(0) + u32le_bytes(0)
        + u32le_bytes(0) + u32le_bytes(0) + u16le_bytes(1) + u16le_bytes(0)
        + ascii_bytes("a")
    )
    central = concat_bytes(*(central_entry(name) for name in names))
    eocd = (
        b"PK\x05\x06"
        + u16le_bytes(0) + u16le_bytes(0) + u16le_bytes(len(names)) + u16le_bytes(len(names))
        + u32le_bytes(len(central)) + u32le_bytes(len(local)) + u16le_bytes(0)
    )
    return local + central + eocd


def ftyp(major="isom", compatible=()):
    size = 16 + len(compatible) * 4
    brands = b"".join(ascii_bytes(str(brand).ljust(4)[:4]) for brand in compatible)
    return u32be_bytes(size) + ascii_bytes("ftyp") + ascii_bytes(str(major).ljust(4)[:4]) + u32be_bytes(0) + brands


def tar():
    out = bytearray(512)
    out[257:262] = ascii_bytes("ustar")
    return bytes(out)


def pdf(body=""):
    return ascii_bytes("%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n" + body + "\n%%EOF\n")


def compressed_object_stream_pdf(payload, compressed=True):
    data = zlib.compress(ascii_bytes(payload)) if compressed else ascii_bytes(payload)
    return concat_bytes(
        ascii_bytes("%PDF-1.7\n1 0 obj\n<< /Type /ObjStm /N 1 /First 0 /Filter /FlateDecode /Length " + str(len(data)) + " >>\nstream\n"),
        data,
        ascii_bytes("\nendstream\nendobj\n%%EOF\n"),
    )


def svg(body='<rect width="10" height="10"/>'):
    return ascii_bytes('<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10">' + body + '</svg>')


def png_chunk(chunk_type, payload):
    return u32be_bytes(len(payload)) + ascii_bytes(chunk_type) + payload + b"\x00\x00\x00\x00"


def insert_before_png_iend(base, insert):
    return base[:-12] + insert + base[-12:]


def compressed_text_png(chunk_type, text="<script>alert(1)</script>"):
    keyword = ascii_bytes("comment")
    compressed = zlib.compress(ascii_bytes(text))
    if chunk_type == "zTXt":
        payload = keyword + b"\x00\x00" + compressed
    else:
        payload = keyword + b"\x00\x01\x00\x00\x00" + compressed
    return insert_before_png_iend(png(), png_chunk(chunk_type, payload))


def validate(data, filename="file.bin", content_type=None, policy=None):
    return validate_upload({"bytes": data, "filename": filename, "content_type": content_type}, policy)


def finding_codes(result):
    return [item.code for item in result.findings]


def has_finding(result, code):
    return any(item.code == code for item in result.findings)


def add_case_methods(cls, prefix, cases, body):
    """Install one independent unittest method per adversarial matrix row."""
    for index, case in enumerate(cases):
        def test_method(self, case=case):
            body(self, *case)
        test_method.__name__ = "test_{}_{:03d}".format(prefix, index)
        test_method.__doc__ = "matrix case {}: {!r}".format(index, case[0] if case else case)
        setattr(cls, test_method.__name__, test_method)
    return cls


def case_methods(prefix, cases, body):
    """Decorator form of add_case_methods for matrix-heavy test classes."""
    def decorate(cls):
        return add_case_methods(cls, prefix, cases, body)
    return decorate
