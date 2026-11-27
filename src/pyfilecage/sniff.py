"""Pure-Python magic-byte file type detection."""
from __future__ import annotations

import re
from typing import List, Optional

from ._util import ascii_at, ascii_slice, bytes_equal_at, normalize_bytes, u16be, u16le, u32be, u32le, u64le
from .models import SniffResult

UNKNOWN_TYPE = SniffResult(
    mime="application/octet-stream",
    ext="bin",
    kind="binary",
    format="unknown",
    executable=False,
    confident=False,
    signature="none",
    offset=0,
)


def _sniff_result(mime: str, ext: str, kind: str, format_name: str, executable: bool, confident: bool, signature: str, offset: int = 0) -> SniffResult:
    return SniffResult(mime, ext, kind, format_name, executable, confident, signature, offset)


def zip_entry_names(data: bytes) -> List[str]:
    """Read ZIP entry names from bounded local and central directory metadata."""
    names: List[str] = []
    seen = set()

    def add_name(name: str) -> None:
        normalized = name.lower()
        if normalized not in seen and len(names) < 128:
            seen.add(normalized)
            names.append(normalized)

    def read_central_directory(central_offset: int, central_size: int, total_entries: int, boundary: int) -> None:
        central_end = central_offset + central_size
        if central_offset < 0 or central_size < 0 or central_end > boundary or central_end > len(data):
            return
        position = central_offset
        entry_limit = min(total_entries, 128)
        for _count in range(entry_limit):
            if position + 46 > len(data) or u32le(data, position) != 0x02014B50:
                break
            name_length = u16le(data, position + 28)
            extra_length = u16le(data, position + 30)
            comment_length = u16le(data, position + 32)
            end = position + 46 + name_length + extra_length + comment_length
            if name_length <= 0 or end > len(data) or end > central_end:
                break
            add_name(ascii_slice(data, position + 46, position + 46 + name_length))
            if end <= position:
                break
            position = end

    position = 0
    for _entry_count in range(64):
        if position + 30 > len(data) or u32le(data, position) != 0x04034B50:
            break
        flags = u16le(data, position + 8)
        compressed_size = u32le(data, position + 18)
        name_length = u16le(data, position + 26)
        extra_length = u16le(data, position + 28)
        if name_length < 0 or extra_length < 0 or compressed_size < 0 or position + 30 + name_length > len(data):
            break
        add_name(ascii_slice(data, position + 30, position + 30 + name_length))
        if (flags & 0x08) != 0 and compressed_size == 0:
            break
        next_position = position + 30 + name_length + extra_length + compressed_size
        if next_position <= position or next_position > len(data):
            break
        position = next_position

    eocd_position = -1
    eocd_search_start = max(0, len(data) - 65557)
    for position in range(len(data) - 22, eocd_search_start - 1, -1):
        if u32le(data, position) != 0x06054B50:
            continue
        comment_length = u16le(data, position + 20)
        if comment_length == len(data) - position - 22:
            eocd_position = position
            break

    if eocd_position != -1:
        disk_number = u16le(data, eocd_position + 4)
        central_disk = u16le(data, eocd_position + 6)
        entries_on_disk = u16le(data, eocd_position + 8)
        total_entries = u16le(data, eocd_position + 10)
        central_size = u32le(data, eocd_position + 12)
        central_offset = u32le(data, eocd_position + 16)
        if disk_number == 0 and central_disk == 0 and entries_on_disk == total_entries:
            read_central_directory(central_offset, central_size, total_entries, eocd_position)

        locator_position = eocd_position - 20
        if locator_position >= 0 and u32le(data, locator_position) == 0x07064B50:
            locator_disk = u32le(data, locator_position + 4)
            zip64_offset = u64le(data, locator_position + 8)
            total_disks = u32le(data, locator_position + 16)
            if (
                locator_disk == 0
                and total_disks == 1
                and zip64_offset >= 0
                and zip64_offset + 56 <= locator_position
                and u32le(data, zip64_offset) == 0x06064B50
            ):
                record_size = u64le(data, zip64_offset + 4)
                record_end = zip64_offset + 12 + record_size
                if record_size >= 44 and record_end == locator_position:
                    zip64_disk = u32le(data, zip64_offset + 16)
                    zip64_central_disk = u32le(data, zip64_offset + 20)
                    zip64_entries_on_disk = u64le(data, zip64_offset + 24)
                    zip64_total_entries = u64le(data, zip64_offset + 32)
                    zip64_central_size = u64le(data, zip64_offset + 40)
                    zip64_central_offset = u64le(data, zip64_offset + 48)
                    if (
                        zip64_disk == 0
                        and zip64_central_disk == 0
                        and zip64_entries_on_disk == zip64_total_entries
                    ):
                        read_central_directory(zip64_central_offset, zip64_central_size, zip64_total_entries, zip64_offset)
    return names


def sniff_zip_family(data: bytes) -> SniffResult:
    names = zip_entry_names(data)
    has_content_types = "[content_types].xml" in names
    has_name = lambda name: name in names

    if has_content_types and has_name("word/document.xml"):
        if has_name("word/vbaproject.bin"):
            return _sniff_result("application/vnd.ms-word.document.macroEnabled.12", "docm", "document", "docm", True, True, "zip-ooxml-macro")
        return _sniff_result("application/vnd.openxmlformats-officedocument.wordprocessingml.document", "docx", "document", "docx", False, True, "zip-ooxml")
    if has_content_types and has_name("xl/workbook.xml"):
        if has_name("xl/vbaproject.bin"):
            return _sniff_result("application/vnd.ms-excel.sheet.macroEnabled.12", "xlsm", "document", "xlsm", True, True, "zip-ooxml-macro")
        return _sniff_result("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "xlsx", "document", "xlsx", False, True, "zip-ooxml")
    if has_content_types and has_name("ppt/presentation.xml"):
        if has_name("ppt/vbaproject.bin"):
            return _sniff_result("application/vnd.ms-powerpoint.presentation.macroEnabled.12", "pptm", "document", "pptm", True, True, "zip-ooxml-macro")
        return _sniff_result("application/vnd.openxmlformats-officedocument.presentationml.presentation", "pptx", "document", "pptx", False, True, "zip-ooxml")
    if "meta-inf/manifest.mf" in names:
        return _sniff_result("application/java-archive", "jar", "archive", "jar", False, True, "zip-jar")
    return _sniff_result("application/zip", "zip", "archive", "zip", False, True, "zip")


def _printable_four(text: str) -> bool:
    return len(text) == 4 and all(0x20 <= ord(char) <= 0x7E for char in text)


def ftyp_brands(data: bytes) -> List[str]:
    if len(data) < 12 or ascii_at(data, 4, 4) != "ftyp":
        return []
    brands = []
    major = ascii_at(data, 8, 4)
    if _printable_four(major):
        brands.append(major)
    box_size = u32be(data, 0)
    end = min(len(data), box_size if 16 <= box_size < 4096 else 96)
    for offset in range(16, end - 3, 4):
        brand = ascii_at(data, offset, 4)
        if _printable_four(brand):
            brands.append(brand)
    return brands


def sniff_ftyp(data: bytes) -> Optional[SniffResult]:
    brands = ftyp_brands(data)
    if not brands:
        return None
    lower = [brand.lower() for brand in brands]
    if any(brand in {"avif", "avis"} for brand in lower):
        return _sniff_result("image/avif", "avif", "image", "avif", False, True, "ftyp")
    if any(brand.startswith("he") or brand in {"mif1", "msf1"} for brand in lower):
        return _sniff_result("image/heif", "heic", "image", "heif", False, True, "ftyp")
    if "qt  " in lower:
        return _sniff_result("video/quicktime", "mov", "media", "quicktime", False, True, "ftyp")
    return _sniff_result("video/mp4", "mp4", "media", "mp4", False, True, "ftyp")


def valid_utf8_text(data: bytes) -> Optional[str]:
    for value in data:
        if value == 0:
            return None
        if value < 32 and value not in (9, 10, 13):
            return None
        if value == 127:
            return None
    try:
        return data.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return None


def _json_hex_digit(char: str) -> bool:
    return ("0" <= char <= "9") or ("a" <= char <= "f") or ("A" <= char <= "F")


def strict_json_validator(text: str) -> bool:
    """Validate JSON grammar without accepting NaN, Infinity, or trailing commas."""
    position = 0
    length = len(text)

    def peek(offset: int = 0) -> str:
        index = position + offset
        return text[index] if 0 <= index < length else ""

    def skip_whitespace() -> None:
        nonlocal position
        while position < length and text[position] in " \t\n\r":
            position += 1

    def parse_string() -> bool:
        nonlocal position
        if peek() != '"':
            return False
        position += 1
        while position < length:
            char = text[position]
            if char == '"':
                position += 1
                return True
            if char == "\\":
                position += 1
                if position >= length:
                    return False
                escaped = text[position]
                if escaped in '"\\/bfnrt':
                    position += 1
                    continue
                if escaped != "u" or position + 4 >= length:
                    return False
                for index in range(1, 5):
                    if not _json_hex_digit(text[position + index]):
                        return False
                position += 5
                continue
            if ord(char) < 32:
                return False
            position += 1
        return False

    def parse_number() -> bool:
        nonlocal position
        start = position
        if peek() == "-":
            position += 1
        if peek() == "0":
            position += 1
        elif "1" <= peek() <= "9":
            while "0" <= peek() <= "9":
                position += 1
        else:
            return False
        if peek() == ".":
            position += 1
            digits = position
            while "0" <= peek() <= "9":
                position += 1
            if position == digits:
                return False
        if peek() in ("e", "E"):
            position += 1
            if peek() in ("+", "-"):
                position += 1
            digits = position
            while "0" <= peek() <= "9":
                position += 1
            if position == digits:
                return False
        return position > start

    def parse_value(depth: int) -> bool:
        nonlocal position
        if depth > 256:
            return False
        skip_whitespace()
        char = peek()
        if char == '"':
            return parse_string()
        if char == "t":
            if not text.startswith("true", position):
                return False
            position += 4
            return True
        if char == "f":
            if not text.startswith("false", position):
                return False
            position += 5
            return True
        if char == "n":
            if not text.startswith("null", position):
                return False
            position += 4
            return True
        if char == "[":
            position += 1
            skip_whitespace()
            if peek() == "]":
                position += 1
                return True
            while True:
                if not parse_value(depth + 1):
                    return False
                skip_whitespace()
                if peek() == "]":
                    position += 1
                    return True
                if peek() != ",":
                    return False
                position += 1
        if char == "{":
            position += 1
            skip_whitespace()
            if peek() == "}":
                position += 1
                return True
            while True:
                skip_whitespace()
                if not parse_string():
                    return False
                skip_whitespace()
                if peek() != ":":
                    return False
                position += 1
                if not parse_value(depth + 1):
                    return False
                skip_whitespace()
                if peek() == "}":
                    position += 1
                    return True
                if peek() != ",":
                    return False
                position += 1
        return parse_number()

    valid = parse_value(0)
    skip_whitespace()
    return valid and position == length


def looks_like_json(text: str) -> bool:
    trimmed = text.strip()
    if not trimmed.startswith("{") and not trimmed.startswith("["):
        return False
    return strict_json_validator(trimmed)


def looks_like_csv(text: str) -> bool:
    trimmed = text.strip()
    if trimmed.startswith("<") or trimmed.startswith("{") or trimmed.startswith("["):
        return False
    lines = [line for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n") if line][:20]
    if len(lines) < 2:
        return False
    counts = []
    for line in lines:
        count = 0
        quoted = False
        index = 0
        while index < len(line):
            char = line[index]
            if char == '"':
                if quoted and index + 1 < len(line) and line[index + 1] == '"':
                    index += 1
                else:
                    quoted = not quoted
            elif char == "," and not quoted:
                count += 1
            index += 1
        counts.append(count)
    return counts[0] > 0 and all(count == counts[0] for count in counts)


def first_element_tag_name(lower_text: str) -> Optional[str]:
    position = 0
    length = len(lower_text)
    while position < length:
        while position < length and lower_text[position].isspace():
            position += 1
        if lower_text.startswith("<?", position):
            end = lower_text.find("?>", position + 2)
            if end == -1:
                return None
            position = end + 2
            continue
        if lower_text.startswith("<!--", position):
            end = lower_text.find("-->", position + 4)
            if end == -1:
                return None
            position = end + 3
            continue
        if lower_text.startswith("<!doctype", position):
            bracket = lower_text.find("[", position)
            greater = lower_text.find(">", position)
            if bracket != -1 and greater != -1 and bracket < greater:
                end = lower_text.find("]>", position)
                step = 2
            else:
                end = greater
                step = 1
            if end == -1:
                return None
            position = end + step
            continue
        match = re.match(r"<\s*([a-z_][a-z0-9_.:-]*)", lower_text[position:])
        return match.group(1) if match else None
    return None


_HTML_TAG_RE = re.compile(
    r"^<(script|iframe|object|embed|html|head|body|title|meta|link|div|span|p|a|img|form|input|table|h1|h2|h3|section|article|main|nav|video|audio|canvas)([\s>/])"
)
_XML_START_RE = re.compile(r"^<[a-z_][a-z0-9_.:-]*(\s|>|/)", re.IGNORECASE)
_XML_CLOSE_RE = re.compile(r"</[a-z_][a-z0-9_.:-]*\s*>", re.IGNORECASE)


def sniff_text_family(data: bytes) -> Optional[SniffResult]:
    text = valid_utf8_text(data)
    if text is None:
        return None
    without_bom = text[1:] if text.startswith("\ufeff") else text
    leading = without_bom.lstrip()
    lower = leading.lower()

    if looks_like_json(without_bom):
        return _sniff_result("application/json", "json", "data", "json", False, True, "text-json")

    first_element = first_element_tag_name(lower)
    if first_element == "svg" or (first_element and first_element.endswith(":svg")):
        return _sniff_result("image/svg+xml", "svg", "image", "svg", False, True, "text-svg")

    if lower.startswith("<!doctype html") or _HTML_TAG_RE.match(lower):
        return _sniff_result("text/html", "html", "markup", "html", False, True, "text-html")

    if lower.startswith("<?xml") or (_XML_START_RE.match(leading) and _XML_CLOSE_RE.search(without_bom)):
        return _sniff_result("application/xml", "xml", "markup", "xml", False, True, "text-xml")

    if looks_like_csv(without_bom):
        return _sniff_result("text/csv", "csv", "data", "csv", False, True, "text-csv")
    return _sniff_result("text/plain", "txt", "text", "text", False, True, "utf8-text")


def is_mp3_frame_start(data: bytes) -> bool:
    if len(data) < 3 or data[0] != 0xFF or (data[1] & 0xE0) != 0xE0:
        return False
    version = (data[1] >> 3) & 0x03
    layer = (data[1] >> 1) & 0x03
    bitrate = (data[2] >> 4) & 0x0F
    sample_rate = (data[2] >> 2) & 0x03
    return version != 1 and layer != 0 and bitrate not in (0, 15) and sample_rate != 3


def pdf_header_offset(data: bytes) -> int:
    marker = b"%PDF-"
    for index in range(1024):
        if index + len(marker) > len(data):
            break
        if data[index:index + len(marker)] == marker:
            return index
    return -1


def shebang_offset(data: bytes) -> int:
    start = 3 if bytes_equal_at(data, 0, b"\xef\xbb\xbf") else 0
    if bytes_equal_at(data, start, b"#!"):
        return start
    cursor = start
    spaces = 0
    while cursor < len(data) and data[cursor] in (0x20, 0x09):
        cursor += 1
        spaces += 1
    if spaces > 0 and bytes_equal_at(data, cursor, b"#!"):
        return cursor
    return -1


def looks_like_java_class(data: bytes) -> bool:
    if not bytes_equal_at(data, 0, b"\xca\xfe\xba\xbe") or len(data) < 8:
        return False
    minor = u16be(data, 4)
    major = u16be(data, 6)
    return major >= 45 and minor in (0, 65535)


def sniff_file_type(input_bytes) -> SniffResult:
    """Detect a file type from magic bytes and strict text structure.

    No libmagic, subprocesses, image decoders, or third-party packages are used.
    """
    data = normalize_bytes(input_bytes)
    if len(data) == 0:
        return UNKNOWN_TYPE

    if bytes_equal_at(data, 0, b"\x00asm\x01\x00\x00\x00"):
        return _sniff_result("application/wasm", "wasm", "executable", "wasm", True, True, "magic")
    if bytes_equal_at(data, 0, b"\x7fELF"):
        return _sniff_result("application/x-elf", "elf", "executable", "elf", True, True, "magic")
    if bytes_equal_at(data, 0, b"MZ"):
        return _sniff_result("application/vnd.microsoft.portable-executable", "exe", "executable", "pe", True, True, "magic")
    if looks_like_java_class(data):
        return _sniff_result("application/java-class", "class", "executable", "java-class", True, True, "magic")

    macho_magics = (
        b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
        b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca",
    )
    if any(bytes_equal_at(data, 0, magic) for magic in macho_magics):
        return _sniff_result("application/x-mach-binary", "macho", "executable", "macho", True, True, "magic")

    script_offset = shebang_offset(data)
    if script_offset != -1:
        return _sniff_result("application/x-shebang", "sh", "executable", "shebang", True, True, "shebang", script_offset)

    if bytes_equal_at(data, 0, b"\x89PNG\r\n\x1a\n"):
        return _sniff_result("image/png", "png", "image", "png", False, True, "magic")
    if bytes_equal_at(data, 0, b"\xff\xd8\xff"):
        return _sniff_result("image/jpeg", "jpg", "image", "jpeg", False, True, "magic")
    if ascii_at(data, 0, 6) in ("GIF87a", "GIF89a"):
        return _sniff_result("image/gif", "gif", "image", "gif", False, True, "magic")
    if ascii_at(data, 0, 4) == "RIFF" and ascii_at(data, 8, 4) == "WEBP":
        return _sniff_result("image/webp", "webp", "image", "webp", False, True, "riff")
    if ascii_at(data, 0, 4) == "RIFF" and ascii_at(data, 8, 4) == "WAVE":
        return _sniff_result("audio/wav", "wav", "media", "wav", False, True, "riff")
    if ascii_at(data, 0, 2) == "BM":
        return _sniff_result("image/bmp", "bmp", "image", "bmp", False, True, "magic")
    if bytes_equal_at(data, 0, b"\x00\x00\x01\x00"):
        return _sniff_result("image/vnd.microsoft.icon", "ico", "image", "ico", False, True, "magic")
    if bytes_equal_at(data, 0, b"II*\x00") or bytes_equal_at(data, 0, b"MM\x00*"):
        return _sniff_result("image/tiff", "tiff", "image", "tiff", False, True, "magic")

    ftyp = sniff_ftyp(data)
    if ftyp is not None:
        return ftyp

    pdf_offset = pdf_header_offset(data)
    if pdf_offset != -1:
        return _sniff_result("application/pdf", "pdf", "document", "pdf", False, True, "magic", pdf_offset)

    if u32le(data, 0) in (0x04034B50, 0x08074B50, 0x06054B50):
        return sniff_zip_family(data)
    if bytes_equal_at(data, 0, b"\x1f\x8b"):
        return _sniff_result("application/gzip", "gz", "archive", "gzip", False, True, "magic")
    if bytes_equal_at(data, 0, b"\x28\xb5\x2f\xfd"):
        return _sniff_result("application/zstd", "zst", "archive", "zstd", False, True, "magic")
    if len(data) > 265 and ascii_at(data, 257, 5) == "ustar":
        return _sniff_result("application/x-tar", "tar", "archive", "tar", False, True, "magic")
    if ascii_at(data, 0, 3) == "ID3" or is_mp3_frame_start(data):
        return _sniff_result("audio/mpeg", "mp3", "media", "mp3", False, True, "magic")
    if ascii_at(data, 0, 4) == "OggS":
        return _sniff_result("application/ogg", "ogg", "media", "ogg", False, True, "magic")
    if ascii_at(data, 0, 4) == "fLaC":
        return _sniff_result("audio/flac", "flac", "media", "flac", False, True, "magic")
    if bytes_equal_at(data, 0, b"\x1a\x45\xdf\xa3"):
        head = ascii_slice(data, 0, min(len(data), 4096)).lower()
        if "webm" in head:
            return _sniff_result("video/webm", "webm", "media", "webm", False, True, "ebml")
        return _sniff_result("video/x-matroska", "mkv", "media", "mkv", False, True, "ebml")

    text = sniff_text_family(data)
    if text is not None:
        return text
    return UNKNOWN_TYPE
