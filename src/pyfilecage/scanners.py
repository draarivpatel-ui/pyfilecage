"""Active-content, polyglot, PDF, SVG, and compressed-metadata scanners."""
from __future__ import annotations

import re
import zlib
from typing import List, Optional, Sequence, Tuple

from ._util import (
    ascii_at,
    bytes_equal_at,
    define_pattern,
    index_of_ascii_fold,
    index_of_bytes,
    scan_ascii_patterns,
    u32be,
)
from .errors import ERROR
from .models import Finding, make_finding
from .sniff import pdf_header_offset

GENERIC_ACTIVE_PATTERNS = (
    define_pattern("script-tag", "<script"),
    define_pattern("html-doctype", "<!doctype html"),
    define_pattern("iframe", "<iframe"),
    define_pattern("object", "<object"),
    define_pattern("embed", "<embed"),
    define_pattern("svg", "<svg"),
    define_pattern("php-tag", "<?php"),
    define_pattern("php-short-echo", "<?="),
    define_pattern("asp-tag", "<%"),
)


def _is_hex_digit(value: int) -> bool:
    return (48 <= value <= 57) or (65 <= value <= 70) or (97 <= value <= 102)


def collect_pdf_name_positions(data: bytes) -> List[Tuple[int, str]]:
    """Collect PDF names and positions after decoding PDF ``#XX`` hex escapes."""
    found = []
    for index, value in enumerate(data):
        if value != 0x2F:
            continue
        chars = []
        cursor = index + 1
        while cursor < len(data) and len(chars) < 80:
            byte = data[cursor]
            delimiter = byte <= 32 or byte in (0x25, 0x28, 0x29, 0x3C, 0x3E, 0x5B, 0x5D, 0x7B, 0x7D, 0x2F)
            if delimiter:
                break
            if byte == 0x23 and cursor + 2 < len(data) and _is_hex_digit(data[cursor + 1]) and _is_hex_digit(data[cursor + 2]):
                chars.append(chr(int(chr(data[cursor + 1]) + chr(data[cursor + 2]), 16)))
                cursor += 3
            else:
                chars.append(chr(byte))
                cursor += 1
        if chars:
            found.append((index, "".join(chars).upper()))
    return found


def collect_pdf_names(data: bytes, names: set) -> None:
    """Collect PDF names after decoding PDF ``#XX`` hex escapes."""
    for _position, name in collect_pdf_name_positions(data):
        names.add(name)


def _inflate_capped(data: bytes, cap: int) -> Tuple[bytes, bool]:
    decompressor = zlib.decompressobj()
    output = decompressor.decompress(data, cap)
    limited = bool(decompressor.unconsumed_tail) or not decompressor.eof
    return output, limited


def mask_pdf_object_prefix(data: bytes) -> Tuple[bytes, Optional[str], int]:
    """Mask a stream-object prefix, stopping before a lexical stream/endobj token."""
    masked = bytearray()
    index = 0
    length = len(data)

    def keyword_at(keyword: bytes) -> bool:
        if not data[index:index + len(keyword)].lower() == keyword:
            return False
        previous = data[index - 1] if index > 0 else 32
        return not ((65 <= previous <= 90) or (97 <= previous <= 122) or (48 <= previous <= 57) or previous == 95)

    while index < length:
        if keyword_at(b"stream"):
            return bytes(masked), "stream", index
        if keyword_at(b"endobj"):
            return bytes(masked), "endobj", index
        value = data[index]
        if value == 0x25:
            masked.append(32)
            index += 1
            while index < length and data[index] not in (10, 13):
                masked.append(32)
                index += 1
            continue
        if value == 0x28:
            depth = 1
            escaped = False
            masked.append(32)
            index += 1
            while index < length and depth:
                current = data[index]
                masked.append(32)
                if escaped:
                    escaped = False
                elif current == 0x5C:
                    escaped = True
                elif current == 0x28:
                    depth += 1
                elif current == 0x29:
                    depth -= 1
                index += 1
            continue
        if value == 0x3C and not (index + 1 < length and data[index + 1] == 0x3C) and not (index > 0 and data[index - 1] == 0x3C):
            masked.append(32)
            index += 1
            while index < length:
                current = data[index]
                masked.append(32)
                index += 1
                if current == 0x3E:
                    break
            continue
        masked.append(value)
        index += 1
    return bytes(masked), None, length


def has_interesting_pdf_stream_type(positions: List[Tuple[int, str]]) -> bool:
    for index in range(len(positions) - 1):
        if positions[index][1] == "TYPE" and positions[index + 1][1] in ("OBJSTM", "METADATA"):
            return True
    return False


PDF_OBJECT_SEPARATOR = rb"(?:[\x00\t\n\x0c\r ]|%[^\r\n]*(?:\r\n|\r|\n))+"
PDF_OBJECT_HEADER_RE = re.compile(rb"(?<![0-9])\d+" + PDF_OBJECT_SEPARATOR + rb"\d+" + PDF_OBJECT_SEPARATOR + rb"obj(?![A-Za-z0-9_])")


def _stream_data_start(data: bytes, stream_at: int) -> Tuple[int, bool]:
    cursor = stream_at + 6
    while cursor < len(data) and data[cursor] in (9, 32):
        cursor += 1
    if cursor + 1 < len(data) and data[cursor] == 13 and data[cursor + 1] == 10:
        return cursor + 2, True
    if cursor < len(data) and data[cursor] in (10, 13):
        return cursor + 1, True
    return cursor, False


def collect_compressed_pdf_names(data: bytes, names: set) -> bool:
    object_matches = list(PDF_OBJECT_HEADER_RE.finditer(data))
    if not object_matches:
        return index_of_ascii_fold(data, "stream", 0) != -1

    scan_limited = False
    interesting_streams = 0
    output_bytes = 0
    skip_before = 0
    for object_index, match in enumerate(object_matches):
        if match.start() < skip_before or interesting_streams >= 64 or output_bytes >= 4194304:
            continue
        body_start = match.end()
        object_end = object_matches[object_index + 1].start() if object_index + 1 < len(object_matches) else len(data)
        object_probe, terminator, terminator_relative = mask_pdf_object_prefix(data[body_start:object_end])
        endobj_relative = terminator_relative if terminator == "endobj" else -1
        stream_relative = terminator_relative if terminator == "stream" else -1

        if stream_relative == -1:
            if endobj_relative == -1 and object_index + 1 < len(object_matches):
                scan_limited = True
            elif has_interesting_pdf_stream_type(collect_pdf_name_positions(object_probe)):
                scan_limited = True
            continue

        stream_at = body_start + stream_relative
        prefix_names = collect_pdf_name_positions(object_probe[:stream_relative])
        interesting = has_interesting_pdf_stream_type(prefix_names)
        if not interesting:
            continue
        if not any(name == "FILTER" for _pos, name in prefix_names):
            continue

        data_start, valid_eol = _stream_data_start(data, stream_at)
        if not valid_eol:
            scan_limited = True
            continue
        end_at = index_of_ascii_fold(data, "endstream", data_start)
        if end_at == -1:
            scan_limited = True
            continue
        if data_start >= end_at:
            scan_limited = True
            skip_before = end_at + 9
            continue

        compressed_segment = data[data_start:end_at]
        try:
            decompressor = zlib.decompressobj()
            inflated = decompressor.decompress(compressed_segment, 1048576)
        except (zlib.error, ValueError):
            scan_limited = True
            skip_before = end_at + 9
            continue
        capped_or_incomplete = bool(decompressor.unconsumed_tail) or not decompressor.eof
        consumed = len(compressed_segment) - len(decompressor.unconsumed_tail) - len(decompressor.unused_data)
        trailing = compressed_segment[consumed:]
        interesting_streams += 1
        output_bytes += len(inflated)
        collect_pdf_names(inflated, names)
        if capped_or_incomplete or trailing.strip(b"\x00\x09\x0a\x0c\x0d\x20"):
            scan_limited = True
        skip_before = end_at + 9

    if interesting_streams >= 64 or output_bytes >= 4194304:
        scan_limited = True
    return scan_limited


PDF_ACTIVE_NAMES = frozenset(("JAVASCRIPT", "JS", "LAUNCH", "OPENACTION", "AA", "EMBEDDEDFILE", "EMBEDDEDFILES", "URI"))


def scan_pdf_active_content(data: bytes, policy) -> List[Finding]:
    findings = []
    names = set()
    positions = collect_pdf_name_positions(data)
    for _position, name in positions:
        names.add(name)
    scan_limited = collect_compressed_pdf_names(data, names)
    for name in sorted(names):
        if name not in PDF_ACTIVE_NAMES:
            continue
        if name == "URI" and policy.allow_pdf_uri:
            continue
        findings.append(make_finding(ERROR["PDF_ACTIVE_CONTENT"], "PDF contains an active content action", {"token": "/" + name}))
    if scan_limited:
        findings.append(make_finding(ERROR["PDF_SCAN_LIMIT"], "PDF compressed object scan reached a safety limit or malformed stream"))
    return findings


_XML_ENTITY_RE = re.compile(r"&(#x[0-9a-f]+|#\d+|amp|lt|gt|quot|apos);", re.IGNORECASE)


def decode_xml_entities(text: str) -> str:
    def replace(match) -> str:
        entity = match.group(1)
        lower = entity.lower()
        if lower == "amp":
            return "&"
        if lower == "lt":
            return "<"
        if lower == "gt":
            return ">"
        if lower == "quot":
            return '"'
        if lower == "apos":
            return "'"
        try:
            code_point = int(lower[2:], 16) if lower.startswith("#x") else int(lower[1:], 10)
            if code_point < 0 or code_point > 0x10FFFF:
                return match.group(0)
            return chr(code_point)
        except (ValueError, OverflowError):
            return match.group(0)
    return _XML_ENTITY_RE.sub(replace, text)


def compact_scheme_value(value: str) -> str:
    return re.sub(r"[\x00-\x20\x7f-\x9f]+", "", value).lower()


def local_xml_name(name: str) -> str:
    lower = name.lower()
    colon = lower.rfind(":")
    return lower if colon == -1 else lower[colon + 1:]


def _xml_name_char(char: str) -> bool:
    return char.isascii() and (char.isalnum() or char in "_-.:")


class XmlTag:
    __slots__ = ("raw", "name", "closing", "processing")

    def __init__(self, raw: str, name: str, closing: bool, processing: bool):
        self.raw = raw
        self.name = name
        self.closing = closing
        self.processing = processing


def scan_xml_tags(text: str) -> List[XmlTag]:
    """Scan XML-like tags while respecting quoted ``>`` and skipping text nodes."""
    tags = []
    position = 0
    while position < len(text):
        start = text.find("<", position)
        if start == -1:
            break
        if text.startswith("<!--", start):
            end_comment = text.find("-->", start + 4)
            position = len(text) if end_comment == -1 else end_comment + 3
            continue
        if text.startswith("<![CDATA[", start):
            end_cdata = text.find("]]>", start + 9)
            position = len(text) if end_cdata == -1 else end_cdata + 3
            continue
        quote = ""
        end = -1
        for index in range(start + 1, len(text)):
            char = text[index]
            if quote:
                if char == quote:
                    quote = ""
                continue
            if char in ('"', "'"):
                quote = char
                continue
            if char == ">":
                end = index
                break
        if end == -1:
            break
        raw = text[start:end + 1]
        position = end + 1
        cursor = 1
        processing = False
        closing = False
        if cursor < len(raw) and raw[cursor] == "?":
            processing = True
            cursor += 1
        elif cursor < len(raw) and raw[cursor] == "/":
            closing = True
            cursor += 1
        elif cursor < len(raw) and raw[cursor] == "!":
            continue
        while cursor < len(raw) and raw[cursor].isspace():
            cursor += 1
        name_start = cursor
        while cursor < len(raw) and _xml_name_char(raw[cursor]):
            cursor += 1
        name = raw[name_start:cursor]
        if name:
            tags.append(XmlTag(raw, name, closing, processing))
    return tags


_XML_ATTRIBUTE_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_.:-]*)\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s\"'=<>`]+))")


def parse_xml_attributes(raw_tag: str) -> List[dict]:
    attributes = []
    for match in _XML_ATTRIBUTE_RE.finditer(raw_tag):
        raw_value = match.group(2) if match.group(2) is not None else (match.group(3) if match.group(3) is not None else (match.group(4) or ""))
        attributes.append({
            "name": match.group(1).lower(),
            "localName": local_xml_name(match.group(1)),
            "value": decode_xml_entities(raw_value),
        })
    return attributes


_CSS_ESCAPE_RE = re.compile(r"\\([0-9a-fA-F]{1,6}\s?|.)", re.DOTALL)


def decode_css_escapes(text: str) -> str:
    def replace(match) -> str:
        escaped = match.group(1)
        if re.match(r"^[0-9a-fA-F]", escaped):
            try:
                code_point = int(escaped.rstrip(), 16)
                if 0 < code_point <= 0x10FFFF:
                    return chr(code_point)
            except (ValueError, OverflowError):
                pass
            return match.group(0)
        return escaped
    return _CSS_ESCAPE_RE.sub(replace, text)


_CSS_URL_RE = re.compile(r"url\(\s*(?:\"([^\"]*)\"|'([^']*)'|([^)]*))\)", re.IGNORECASE)


def scan_svg_css(text: str, add_once) -> None:
    decoded = decode_css_escapes(decode_xml_entities(text))
    if re.search(r"@import\b", decoded, re.IGNORECASE):
        add_once(ERROR["SVG_ACTIVE_CONTENT"], "SVG CSS imports an external stylesheet", {"pattern": "css-import"})
    for match in _CSS_URL_RE.finditer(decoded):
        raw = match.group(1) if match.group(1) is not None else (match.group(2) if match.group(2) is not None else (match.group(3) or ""))
        value = compact_scheme_value(raw)
        if value.startswith(("http:", "https:", "//", "javascript:", "data:")):
            add_once(ERROR["SVG_ACTIVE_CONTENT"], "SVG CSS references a remote or active resource", {"pattern": "css-external-url"})


def scan_svg_active_content(data: bytes) -> List[Finding]:
    findings: List[Finding] = []
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError:
        findings.append(make_finding(ERROR["INVALID_UTF8"], "SVG is not valid UTF-8"))
        return findings

    def add_once(code: str, message: str, details: Optional[dict] = None) -> None:
        key = None
        if details:
            key = details.get("pattern") or details.get("token")
        key = key or message
        for item in findings:
            item_key = getattr(item, "pattern", None) or getattr(item, "token", None) or item.message
            if item.code == code and item_key == key:
                return
        findings.append(make_finding(code, message, details))

    if re.search(r"<!doctype\b", text, re.IGNORECASE):
        add_once(ERROR["SVG_XXE"], "SVG contains a DOCTYPE declaration", {"pattern": "doctype"})
    if re.search(r"<!entity\b", text, re.IGNORECASE):
        add_once(ERROR["SVG_XXE"], "SVG contains an entity declaration", {"pattern": "entity"})

    remote_reference_elements = {"use", "image", "feimage"}
    animation_elements = {"set", "animate", "animatetransform", "animatemotion"}
    for tag in scan_xml_tags(text):
        element_name = local_xml_name(tag.name)
        if tag.processing and element_name == "xml-stylesheet":
            add_once(ERROR["SVG_ACTIVE_CONTENT"], "SVG contains an XML stylesheet processing instruction", {"pattern": "xml-stylesheet"})
        if not tag.processing and not tag.closing:
            if element_name == "script":
                add_once(ERROR["SVG_ACTIVE_CONTENT"], "SVG contains a script element", {"pattern": "script-element"})
            if element_name == "foreignobject":
                add_once(ERROR["SVG_ACTIVE_CONTENT"], "SVG contains foreignObject HTML embedding", {"pattern": "foreignObject"})

        attributes = parse_xml_attributes(tag.raw)
        for attribute in attributes:
            if not tag.processing and re.match(r"^on[a-z0-9_.:-]*$", attribute["name"], re.IGNORECASE):
                add_once(ERROR["SVG_ACTIVE_CONTENT"], "SVG contains an event handler attribute", {"pattern": "event-handler"})
            if attribute["localName"] == "href":
                value = compact_scheme_value(attribute["value"])
                if value.startswith(("javascript:", "data:")):
                    add_once(ERROR["SVG_ACTIVE_CONTENT"], "SVG contains an active href scheme", {"pattern": value.split(":", 1)[0] + "-href"})
                if not tag.processing and element_name in remote_reference_elements and value.startswith(("http:", "https:", "//")):
                    add_once(ERROR["SVG_ACTIVE_CONTENT"], "SVG element references a remote resource", {"pattern": "remote-" + element_name})

        if not tag.processing and element_name in animation_elements:
            attribute_name = next((attribute for attribute in attributes if attribute["name"] == "attributename"), None)
            if attribute_name and local_xml_name(attribute_name["value"].strip()) == "href":
                for attribute in attributes:
                    if attribute["name"] not in ("to", "values", "from", "by"):
                        continue
                    value = compact_scheme_value(attribute["value"])
                    if "javascript:" in value or "data:" in value:
                        add_once(ERROR["SVG_ACTIVE_CONTENT"], "SVG animation assigns an active href scheme", {"pattern": "animated-active-href"})

    scan_svg_css(text, add_once)
    return findings


def png_logical_end(data: bytes) -> int:
    if not bytes_equal_at(data, 0, b"\x89PNG\r\n\x1a\n"):
        return -1
    position = 8
    while True:
        if position + 12 > len(data):
            return -1
        length = u32be(data, position)
        chunk_type = ascii_at(data, position + 4, 4)
        if length < 0 or length > 0x7FFFFFFF:
            return -1
        end = position + 12 + length
        if end > len(data):
            return -1
        if chunk_type == "IEND":
            return end
        position = end


def zero_byte_index(data: bytes, start: int, end: int) -> int:
    for index in range(start, end):
        if data[index] == 0:
            return index
    return -1


def scan_png_compressed_text(data: bytes, patterns: Sequence) -> Tuple[List[dict], bool]:
    hits = []
    scan_limited = False
    if not bytes_equal_at(data, 0, b"\x89PNG\r\n\x1a\n"):
        return hits, scan_limited
    position = 8
    output_bytes = 0
    while True:
        if output_bytes >= 4194304:
            scan_limited = True
            break
        if position + 12 > len(data):
            break
        length = u32be(data, position)
        chunk_type = ascii_at(data, position + 4, 4)
        if length < 0 or length > 0x7FFFFFFF:
            break
        data_start = position + 8
        data_end = data_start + length
        end = position + 12 + length
        if end > len(data):
            break
        if chunk_type in ("zTXt", "iTXt"):
            keyword_end = zero_byte_index(data, data_start, min(data_end, data_start + 80))
            compressed_start = -1
            if keyword_end > data_start:
                if chunk_type == "zTXt":
                    if keyword_end + 1 < data_end and data[keyword_end + 1] == 0:
                        compressed_start = keyword_end + 2
                else:
                    compression_flag = data[keyword_end + 1] if keyword_end + 1 < data_end else -1
                    compression_method = data[keyword_end + 2] if keyword_end + 2 < data_end else -1
                    language_end = zero_byte_index(data, keyword_end + 3, data_end)
                    translated_end = -1 if language_end == -1 else zero_byte_index(data, language_end + 1, data_end)
                    if compression_flag == 1 and compression_method == 0 and translated_end != -1:
                        compressed_start = translated_end + 1
            if compressed_start != -1 and compressed_start < data_end:
                try:
                    inflated, limited = _inflate_capped(data[compressed_start:data_end], 1048576)
                    output_bytes += len(inflated)
                    if limited:
                        scan_limited = True
                    for pattern, _position in scan_ascii_patterns(inflated, patterns, 0):
                        hits.append({"pattern": pattern, "position": data_start})
                except (zlib.error, ValueError):
                    scan_limited = True
        if chunk_type == "IEND":
            break
        position = end
    if output_bytes >= 4194304:
        scan_limited = True
    return hits, scan_limited


def find_zip_signature(data: bytes, start: int) -> int:
    signatures = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
    best = -1
    for signature in signatures:
        position = index_of_bytes(data, signature, start)
        if position != -1 and (best == -1 or position < best):
            best = position
    return best


def scan_active_and_polyglot(data: bytes, sniffed, policy) -> List[Finding]:
    findings: List[Finding] = []
    if policy.scan_active_content:
        if sniffed.format == "pdf" or pdf_header_offset(data) != -1:
            findings.extend(scan_pdf_active_content(data, policy))
        if sniffed.format == "svg":
            findings.extend(scan_svg_active_content(data))

        patterns = []
        for pattern in GENERIC_ACTIVE_PATTERNS:
            if sniffed.format == "html" and pattern.id == "html-doctype":
                continue
            if sniffed.format == "svg" and pattern.id in ("script-tag", "svg", "html-doctype", "iframe", "object", "embed"):
                continue
            patterns.append(pattern)
        active_patterns = set()
        for pattern, position in scan_ascii_patterns(data, patterns, 0):
            active_patterns.add(pattern.id)
            findings.append(make_finding(ERROR["ACTIVE_CONTENT"], "file bytes contain active markup or server-side code", {
                "position": position,
                "pattern": pattern.id,
            }))
        if sniffed.format == "png":
            compressed_hits, png_scan_limited = scan_png_compressed_text(data, patterns)
            for hit in compressed_hits:
                if hit["pattern"].id in active_patterns:
                    continue
                active_patterns.add(hit["pattern"].id)
                findings.append(make_finding(ERROR["ACTIVE_CONTENT"], "compressed PNG text contains active markup or server-side code", {
                    "position": hit["position"],
                    "pattern": hit["pattern"].id,
                }))
            if png_scan_limited:
                findings.append(make_finding(ERROR["PNG_TEXT_SCAN_LIMIT"], "compressed PNG text scan reached a safety limit or malformed stream"))

    if policy.scan_polyglots and sniffed.format in ("png", "jpeg", "gif", "webp", "bmp"):
        pdf_at = pdf_header_offset(data)
        if pdf_at != -1:
            findings.append(make_finding(ERROR["POLYGLOT"], "image contains an embedded PDF signature", {"position": pdf_at, "pattern": "pdf-signature"}))
        zip_at = find_zip_signature(data, 2)
        if zip_at != -1:
            findings.append(make_finding(ERROR["POLYGLOT"], "image contains an embedded ZIP or JAR signature", {"position": zip_at, "pattern": "zip-signature"}))
        if sniffed.format == "png":
            logical_end = png_logical_end(data)
            if logical_end != -1 and logical_end < len(data):
                findings.append(make_finding(ERROR["TRAILING_DATA"], "PNG contains data after the IEND chunk", {
                    "position": logical_end,
                    "actual": len(data) - logical_end,
                }))
    return findings
