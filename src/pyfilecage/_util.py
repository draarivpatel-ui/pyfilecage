"""Internal byte and ASCII helpers."""
from __future__ import annotations

from typing import Iterable, List, Sequence, Tuple

from .errors import invalid_input


def normalize_bytes(value, key: str = "bytes") -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return value.tobytes()
    invalid_input(key + " must be bytes, bytearray, or memoryview", key)
    raise AssertionError("unreachable")


def bytes_equal_at(data: bytes, offset: int, values) -> bool:
    if offset < 0 or offset + len(values) > len(data):
        return False
    return data[offset:offset + len(values)] == bytes(values)


def ascii_at(data: bytes, offset: int, length: int) -> str:
    if offset < 0 or offset + length > len(data):
        return ""
    return data[offset:offset + length].decode("latin-1")


def ascii_slice(data: bytes, start: int, end: int) -> str:
    first = max(0, start)
    last = min(len(data), end)
    return "".join(chr(value) if value < 128 else " " for value in data[first:last])


def u16le(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        return -1
    return data[offset] | (data[offset + 1] << 8)


def u16be(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        return -1
    return (data[offset] << 8) | data[offset + 1]


def u32le(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        return -1
    return data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24)


def u32be(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        return -1
    return ((data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3])


def ascii_lower_byte(value: int) -> int:
    return value + 32 if 65 <= value <= 90 else value


def index_of_bytes(data: bytes, needle: bytes, start: int = 0) -> int:
    if not needle or start >= len(data):
        return -1
    return data.find(needle, max(0, start))


def index_of_ascii_fold(data: bytes, needle: str, start: int = 0) -> int:
    if not needle or start >= len(data):
        return -1
    values = [ascii_lower_byte(ord(char)) for char in needle]
    end = len(data) - len(values)
    for index in range(max(0, start), end + 1):
        if ascii_lower_byte(data[index]) != values[0]:
            continue
        matched = True
        for needle_index in range(1, len(values)):
            if ascii_lower_byte(data[index + needle_index]) != values[needle_index]:
                matched = False
                break
        if matched:
            return index
    return -1


class AsciiPattern:
    __slots__ = ("id", "text", "lower")

    def __init__(self, pattern_id: str, text: str):
        self.id = pattern_id
        self.text = text
        self.lower = text.lower()


def define_pattern(pattern_id: str, text: str) -> AsciiPattern:
    return AsciiPattern(pattern_id, text)


def scan_ascii_patterns(data: bytes, patterns: Sequence[AsciiPattern], start: int = 0):
    first_map = {}
    for pattern in patterns:
        first = ascii_lower_byte(ord(pattern.lower[0]))
        first_map.setdefault(first, []).append(pattern)
    found = {}
    for index in range(max(0, start), len(data)):
        candidates = first_map.get(ascii_lower_byte(data[index]))
        if not candidates:
            continue
        for pattern in candidates:
            if pattern.id in found or index + len(pattern.lower) > len(data):
                continue
            matched = True
            for needle_index, char in enumerate(pattern.lower):
                if ascii_lower_byte(data[index + needle_index]) != ascii_lower_byte(ord(char)):
                    matched = False
                    break
            if matched:
                found[pattern.id] = (pattern, index)
        if len(found) == len(patterns):
            break
    return list(found.values())
