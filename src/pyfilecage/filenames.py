"""Filename sanitization against traversal, RTLO spoofing, and platform traps."""
from __future__ import annotations

import hashlib
import re
import unicodedata
from typing import Any, Mapping, Optional, Tuple

from .errors import ERROR, FileCageError, invalid_input
from .models import FilenameReport, Finding, make_finding

ACTIVE_DOUBLE_EXTENSIONS = frozenset((
    "exe", "dll", "com", "bat", "cmd", "scr", "ps1", "vbs", "vbe", "js", "jse", "mjs", "wsf", "wsh",
    "jar", "php", "phtml", "asp", "aspx", "jsp", "html", "htm", "svg", "xml", "msi", "msp", "lnk", "reg", "sh", "command",
))
WINDOWS_UNSAFE_CHARS = frozenset(('<', '>', ':', '"', '|', '?', '*'))
UNICODE_PATH_SEPARATORS = frozenset((0x2044, 0x2215, 0xFF0F, 0x29F8, 0x29F6, 0xFF3C))
_RESERVED_RE = re.compile(r"^(con|prn|aux|nul|conin\$|conout\$|com[1-9]|lpt[1-9])$")
_TRAILING_DOTS_SPACES_RE = re.compile(r"[. ]+$")
_LEADING_DOTS_SPACES_RE = re.compile(r"^[. ]+")
_DOT_RUNS_RE = re.compile(r"\.+")


def _is_control_code_point(code_point: int) -> bool:
    return (0 <= code_point <= 31) or (127 <= code_point <= 159)


def _is_bidi_control_code_point(code_point: int) -> bool:
    return (
        (0x202A <= code_point <= 0x202E)
        or (0x2066 <= code_point <= 0x2069)
        or code_point in (0x200E, 0x200F, 0x061C)
    )


def _is_surrogate_code_point(code_point: int) -> bool:
    return 0xD800 <= code_point <= 0xDFFF


def utf8_byte_length(text: str) -> int:
    return len(text.encode("utf-8", "replace"))


def truncate_utf8(text: str, max_bytes: int) -> str:
    if utf8_byte_length(text) <= max_bytes:
        return text
    output = []
    used = 0
    for char in text:
        size = utf8_byte_length(char)
        if used + size > max_bytes:
            break
        output.append(char)
        used += size
    return "".join(output)


def split_final_extension(filename: str) -> Tuple[str, str]:
    dot = filename.rfind(".")
    if dot <= 0 or dot == len(filename) - 1:
        return filename, ""
    return filename[:dot], filename[dot + 1:].lower()


def fit_filename_to_bytes(stem: str, extension: str, max_bytes: int, seed: str) -> str:
    suffix = "." + extension if extension else ""
    if utf8_byte_length(stem + suffix) <= max_bytes:
        return stem + suffix
    digest = hashlib.sha256(seed.encode("utf-8", "replace")).hexdigest()[:8]
    reserve = len(digest.encode("ascii")) + 1
    if utf8_byte_length(suffix) + reserve + 1 > max_bytes:
        suffix = ""
    suffix_bytes = utf8_byte_length(suffix)
    stem_budget = max(0, max_bytes - suffix_bytes - reserve)
    shortened = _TRAILING_DOTS_SPACES_RE.sub("", truncate_utf8(stem, stem_budget))
    if not shortened:
        shortened = "f"
    return shortened + "-" + digest + suffix


def windows_reserved_stem(filename: str) -> Optional[str]:
    trimmed = _TRAILING_DOTS_SPACES_RE.sub("", filename)
    first_part = re.split(r"[.:]", trimmed, maxsplit=1)[0] if trimmed else ""
    first_part = _TRAILING_DOTS_SPACES_RE.sub("", first_part)
    key = unicodedata.normalize("NFKC", first_part).lower()
    return key if _RESERVED_RE.match(key) else None


def double_extension_parts(filename: str) -> Optional[dict]:
    parts = [part for part in filename.split(".") if part]
    if len(parts) < 3:
        return None
    final_part = parts[-1].lower()
    previous = _TRAILING_DOTS_SPACES_RE.sub("", parts[-2]).lower()
    if final_part not in ACTIVE_DOUBLE_EXTENSIONS:
        return None
    if not re.match(r"^[a-z0-9]{1,12}$", previous):
        return None
    return {"previous": previous, "final": final_part}


def _normalize_filename_options(options: Optional[Mapping[str, Any]], max_bytes: Optional[int]) -> int:
    output = 255
    if options is not None:
        if not isinstance(options, Mapping):
            invalid_input("filename options must be a mapping", "options")
        for key in options:
            if key not in ("maxBytes", "max_bytes"):
                invalid_input("unknown filename option", str(key))
        if "maxBytes" in options and options["maxBytes"] is not None:
            output = options["maxBytes"]
        if "max_bytes" in options and options["max_bytes"] is not None:
            output = options["max_bytes"]
    if max_bytes is not None:
        output = max_bytes
    if isinstance(output, bool) or not isinstance(output, int) or output < 32 or output > 1024:
        invalid_input("max_bytes must be an integer from 32 through 1024", "max_bytes")
    return output


def sanitize_filename(input_value: str, options: Optional[Mapping[str, Any]] = None, *, max_bytes: Optional[int] = None) -> FilenameReport:
    """Return a deterministic safe storage filename and a finding list.

    The function does not silently pass hostile input. It reports every hostile
    property while still producing a neutralized fallback name for callers that
    explicitly choose the ``sanitize`` filename action.
    """
    if not isinstance(input_value, str):
        invalid_input("filename must be a string", "filename")
    byte_cap = _normalize_filename_options(options, max_bytes)
    original = input_value
    findings = []

    def add(code: str, message: str, details: Optional[Mapping[str, Any]] = None) -> None:
        if not any(item.code == code for item in findings):
            findings.append(make_finding(code, message, details))

    if len(input_value) == 0:
        add(ERROR["FILENAME_EMPTY"], "filename is empty")
    if input_value in (".", ".."):
        add(ERROR["FILENAME_DOT_NAME"], "filename is a relative directory alias")

    normalized = unicodedata.normalize("NFC", input_value)
    for index, char in enumerate(normalized):
        code_point = ord(char)
        if code_point == 0:
            add(ERROR["FILENAME_NUL"], "filename contains a NUL byte", {"position": index})
        elif _is_control_code_point(code_point):
            add(ERROR["FILENAME_CONTROL"], "filename contains a control character", {"position": index})
        elif _is_bidi_control_code_point(code_point):
            add(ERROR["FILENAME_BIDI"], "filename contains a Unicode bidirectional control character", {"position": index})

    had_path_separator = "/" in normalized or "\\" in normalized
    if had_path_separator:
        add(ERROR["FILENAME_PATH_SEPARATOR"], "filename contains a path separator")
    segments = re.split(r"[\\/]+", normalized)
    basename = segments[-1] if segments else ""

    if re.search(r"[. ]$", basename):
        add(ERROR["FILENAME_TRAILING_DOTS_SPACES"], "filename ends in a dot or space")
    if len(basename) > 1 and basename.startswith("."):
        add(ERROR["FILENAME_DOT_NAME"], "filename is a dotfile or relative directory alias")

    windows_comparable = _TRAILING_DOTS_SPACES_RE.sub("", basename)
    reserved_before = windows_reserved_stem(windows_comparable)
    if reserved_before:
        add(ERROR["FILENAME_RESERVED_DEVICE"], "filename uses a Windows reserved device name", {"actual": reserved_before})
    double_before = double_extension_parts(windows_comparable)
    if double_before:
        add(ERROR["FILENAME_DOUBLE_EXTENSION"], "filename uses a double extension ending in active content", {
            "extension": double_before["final"],
            "pattern": double_before["previous"] + "." + double_before["final"],
        })

    source_stem, source_extension = split_final_extension(windows_comparable)
    del source_stem

    output_chars = []
    unsafe_character = False
    for char in basename:
        code_point = ord(char)
        if code_point == 0 or _is_control_code_point(code_point) or _is_bidi_control_code_point(code_point):
            continue
        if char in WINDOWS_UNSAFE_CHARS or code_point in UNICODE_PATH_SEPARATORS or _is_surrogate_code_point(code_point):
            unsafe_character = True
            output_chars.append("_")
        else:
            output_chars.append(char)
    if unsafe_character:
        add(ERROR["FILENAME_UNSAFE_CHAR"], "filename contains a character that is unsafe on common filesystems")

    sanitized = _LEADING_DOTS_SPACES_RE.sub("", _TRAILING_DOTS_SPACES_RE.sub("", "".join(output_chars)))
    if double_before:
        final_suffix = "." + double_before["final"]
        if sanitized.lower().endswith(final_suffix):
            stem = _TRAILING_DOTS_SPACES_RE.sub("", _DOT_RUNS_RE.sub("_", sanitized[:-len(final_suffix)]))
            sanitized = stem + final_suffix
    if not sanitized or sanitized in (".", ".."):
        sanitized = "file"
    if windows_reserved_stem(sanitized):
        sanitized = "file-" + _LEADING_DOTS_SPACES_RE.sub("", sanitized)

    stem, extension = split_final_extension(sanitized)
    stem = stem or "file"
    basename_byte_length = utf8_byte_length(basename)
    if basename_byte_length > byte_cap:
        add(ERROR["FILENAME_TOO_LONG"], "filename exceeds the UTF-8 byte length limit", {"limit": byte_cap, "actual": basename_byte_length})
    filename = fit_filename_to_bytes(stem, extension, byte_cap, original)
    final_stem, final_extension = split_final_extension(filename)

    return FilenameReport(
        original=original,
        filename=filename,
        stem=final_stem,
        extension=final_extension,
        source_extension=source_extension,
        changed=filename != original,
        byte_length=utf8_byte_length(filename),
        findings=tuple(findings),
    )


def assert_safe_filename(input_value: str, options: Optional[Mapping[str, Any]] = None, *, max_bytes: Optional[int] = None) -> FilenameReport:
    """Return a clean filename report or raise the first hostile finding."""
    report = sanitize_filename(input_value, options, max_bytes=max_bytes)
    finding = next((item for item in report.findings if item.severity == "error"), None)
    if finding is not None:
        raise FileCageError(finding.code, finding.message, {
            "filename": report.filename,
            "position": getattr(finding, "position", None),
            "limit": getattr(finding, "limit", None),
            "actual": getattr(finding, "actual", None),
        })
    return report
