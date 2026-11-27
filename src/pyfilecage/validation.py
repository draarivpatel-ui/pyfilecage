"""Core upload validation, safe path validation, and bounded stream validation."""
from __future__ import annotations

import hashlib
import os
import stat as stat_module
from collections.abc import Mapping
from typing import Any, Optional

from ._util import normalize_bytes
from .errors import ERROR, invalid_input
from .filenames import fit_filename_to_bytes, sanitize_filename, split_final_extension
from .images import inspect_image_dimensions
from .models import ValidationResult, make_finding
from .policy import MIME_TOKEN_RE, Policy, merge_policy, normalize_policy
from .scanners import scan_active_and_polyglot
from .sniff import sniff_file_type

MIME_ALIAS_GROUPS = (
    ("image/jpeg", "image/jpg", "image/pjpeg"),
    ("image/vnd.microsoft.icon", "image/x-icon"),
    ("audio/wav", "audio/wave", "audio/x-wav", "audio/vnd.wave"),
    ("audio/mpeg", "audio/mp3", "audio/mpeg3"),
    ("application/zip", "application/x-zip-compressed", "application/x-zip"),
    ("application/gzip", "application/x-gzip"),
    ("application/zstd", "application/zstandard", "application/x-zstd"),
    ("application/xml", "text/xml"),
    ("application/json", "text/json"),
    ("text/csv", "application/csv", "application/vnd.ms-excel"),
    ("video/x-matroska", "video/mkv"),
    ("application/x-tar", "application/tar"),
)

EXTENSION_ALIAS_GROUPS = (
    ("jpg", "jpeg", "jpe"),
    ("tif", "tiff"),
    ("htm", "html"),
    ("heic", "heif"),
    ("gz", "gzip"),
    ("zst", "zstd"),
    ("markdown", "md"),
)


def mime_types_equivalent(left: str, right: str) -> bool:
    if left == right:
        return True
    return any(left in group and right in group for group in MIME_ALIAS_GROUPS)


def extensions_equivalent(left: str, right: str) -> bool:
    if not left or not right:
        return False
    first = left.lower()
    second = right.lower()
    if first == second:
        return True
    return any(first in group and second in group for group in EXTENSION_ALIAS_GROUPS)


def normalize_claimed_content_type(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip().split(";", 1)[0].strip().lower()


def _cap_findings(findings, policy: Policy):
    if len(findings) <= policy.max_findings:
        return tuple(findings)
    capped = list(findings[:max(0, policy.max_findings - 1)])
    capped.append(make_finding(ERROR["MAX_FINDINGS"], "finding count exceeded the reporting cap", {
        "limit": policy.max_findings,
        "actual": len(findings),
    }))
    return tuple(capped)


def _finalize_validation(fields: dict, policy: Policy) -> ValidationResult:
    findings = _cap_findings(fields["findings"], policy)
    first_error = next((item for item in findings if item.severity == "error"), None)
    first = first_error or (findings[0] if findings else None)
    return ValidationResult(
        allowed=first_error is None,
        safe_filename=fields.get("safe_filename"),
        detected_mime=fields.get("detected_mime"),
        detected_ext=fields.get("detected_ext"),
        detected_format=fields.get("detected_format"),
        kind=fields.get("kind"),
        size_bytes=fields.get("size_bytes"),
        dimensions=fields.get("dimensions"),
        sha256=fields.get("sha256"),
        findings=findings,
        code=first.code if first is not None else None,
    )


def _extension_allowed_by_list(allowed_list, detected_ext: str, source_ext: str) -> bool:
    return any(
        extensions_equivalent(allowed, detected_ext) or (source_ext and extensions_equivalent(allowed, source_ext))
        for allowed in allowed_list
    )


def _type_allowlist_permits(policy: Policy, sniffed, source_ext: str) -> bool:
    mime_configured = policy.allowed_mime_types is not None
    ext_configured = policy.allowed_extensions is not None
    if not mime_configured and not ext_configured:
        return True
    if mime_configured and any(mime_types_equivalent(allowed, sniffed.mime) for allowed in policy.allowed_mime_types or ()):
        return True
    if ext_configured and _extension_allowed_by_list(policy.allowed_extensions or (), sniffed.ext, source_ext):
        return True
    return False


def _inspect_bytes_core(data: bytes, policy: Policy, size_override: Optional[int] = None, truncated_input: bool = False) -> dict:
    findings = []
    size_bytes = len(data) if size_override is None else size_override
    if size_bytes > policy.max_bytes:
        findings.append(make_finding(ERROR["MAX_BYTES"], "file exceeds the maximum byte size", {
            "limit": policy.max_bytes,
            "actual": size_bytes,
        }))
    if size_bytes == 0 or len(data) == 0:
        findings.append(make_finding(ERROR["EMPTY_FILE"], "file is empty"))

    sniffed = sniff_file_type(data)
    if sniffed.format == "unknown" and not policy.allow_unknown_types:
        findings.append(make_finding(ERROR["UNRECOGNIZED_TYPE"], "file type could not be verified from magic bytes or strict text decoding"))
    if sniffed.executable and not policy.allow_executables:
        findings.append(make_finding(ERROR["EXECUTABLE_TYPE"], "executable binary or script content is blocked", {"mime": sniffed.mime}))
    if sniffed.kind == "archive" and not policy.allow_archives:
        findings.append(make_finding(ERROR["ARCHIVE_NOT_ALLOWED"], "archive containers require explicit opt-in", {"mime": sniffed.mime}))
    if sniffed.format in ("html", "xml") and not policy.allow_markup:
        findings.append(make_finding(ERROR["MARKUP_NOT_ALLOWED"], "HTML or XML markup requires explicit opt-in", {"mime": sniffed.mime}))
    if sniffed.format == "svg" and not policy.allow_svg:
        findings.append(make_finding(ERROR["SVG_NOT_ALLOWED"], "SVG requires explicit opt-in because it can carry active content", {"mime": sniffed.mime}))

    dimensions = None
    if sniffed.kind == "image" and sniffed.format != "svg":
        dimensions = inspect_image_dimensions(data)
        if policy.enforce_image_dimensions:
            if dimensions is None:
                findings.append(make_finding(ERROR["DIMENSIONS_UNREADABLE"], "image dimensions could not be verified from the binary header", {"mime": sniffed.mime}))
            else:
                if dimensions.width > policy.max_width:
                    findings.append(make_finding(ERROR["MAX_WIDTH"], "image width exceeds the configured limit", {
                        "limit": policy.max_width,
                        "actual": dimensions.width,
                        "width": dimensions.width,
                    }))
                if dimensions.height > policy.max_height:
                    findings.append(make_finding(ERROR["MAX_HEIGHT"], "image height exceeds the configured limit", {
                        "limit": policy.max_height,
                        "actual": dimensions.height,
                        "height": dimensions.height,
                    }))
                if dimensions.pixels > policy.max_pixels:
                    findings.append(make_finding(ERROR["MAX_PIXELS"], "image pixel count exceeds the configured limit", {
                        "limit": policy.max_pixels,
                        "actual": dimensions.pixels,
                        "pixels": dimensions.pixels,
                    }))

    findings.extend(scan_active_and_polyglot(data, sniffed, policy))
    return {
        "sniffed": sniffed,
        "dimensions": dimensions,
        "size_bytes": size_bytes,
        "sha256": None if truncated_input else hashlib.sha256(data).hexdigest(),
        "findings": findings,
    }


def _canonical_storage_filename(report, sniffed, policy: Policy) -> str:
    if not policy.canonicalize_extension or sniffed is None or sniffed.format == "unknown":
        return report.filename
    stem, _extension = split_final_extension(report.filename)
    stem = stem or "file"
    return fit_filename_to_bytes(stem, sniffed.ext, policy.max_filename_bytes, report.original)


def _input_value(input_value: Any, *names: str) -> Any:
    if isinstance(input_value, Mapping):
        for name in names:
            if name in input_value:
                return input_value[name]
        return None
    for name in names:
        if hasattr(input_value, name):
            return getattr(input_value, name)
    return None


def _validate_upload_internal(input_value: Any, policy: Policy, transfer: Optional[dict] = None) -> ValidationResult:
    if input_value is None or isinstance(input_value, (str, bytes, bytearray, memoryview)) or not isinstance(input_value, (Mapping, object)):
        invalid_input("upload input must be a mapping or object", "input")
    transfer = transfer or {}
    data = normalize_bytes(_input_value(input_value, "bytes", "data"), "bytes")
    input_filename = _input_value(input_value, "filename", "name")
    filename = input_filename if isinstance(input_filename, str) else ""
    filename_report = sanitize_filename(filename, max_bytes=policy.max_filename_bytes)
    core = _inspect_bytes_core(
        data,
        policy,
        transfer.get("size_override"),
        transfer.get("truncated") is True,
    )
    findings = list(core["findings"])
    sniffed = core["sniffed"]
    if transfer.get("executable_mode") is True and not policy.allow_executables:
        findings.append(make_finding(ERROR["EXECUTABLE_TYPE"], "file has executable permission bits", {"actual": "executable-mode"}))

    if not isinstance(input_filename, str):
        findings.append(make_finding(ERROR["INVALID_INPUT"], "filename must be supplied as a string"))
    for item in filename_report.findings:
        findings.append(make_finding(item.code, item.message, item.to_dict(), "warning" if policy.filename_action == "sanitize" else "error"))

    source_extension = filename_report.source_extension
    if not _type_allowlist_permits(policy, sniffed, source_extension):
        findings.append(make_finding(ERROR["TYPE_NOT_ALLOWED"], "verified file type is not in the configured allowlist", {
            "mime": sniffed.mime,
            "extension": sniffed.ext,
        }))

    claimed = normalize_claimed_content_type(_input_value(input_value, "content_type", "contentType", "type"))
    if not claimed:
        if policy.require_content_type:
            findings.append(make_finding(ERROR["CONTENT_TYPE_MISSING"], "Content-Type is required"))
    elif not MIME_TOKEN_RE.match(claimed):
        findings.append(make_finding(ERROR["INVALID_CONTENT_TYPE"], "Content-Type is not a valid MIME type", {"actual": claimed}))
    elif claimed == "application/octet-stream" and not policy.allow_generic_content_type:
        findings.append(make_finding(ERROR["MIME_MISMATCH"], "generic application/octet-stream is not accepted as proof of content type", {
            "mime": sniffed.mime,
            "actual": claimed,
        }))
    elif claimed == "application/octet-stream" and policy.allow_generic_content_type:
        pass
    elif not mime_types_equivalent(claimed, sniffed.mime):
        findings.append(make_finding(ERROR["MIME_MISMATCH"], "claimed Content-Type does not match verified magic bytes", {
            "mime": sniffed.mime,
            "actual": claimed,
        }))

    if not source_extension:
        if policy.require_extension and isinstance(input_filename, str):
            findings.append(make_finding(ERROR["EXTENSION_MISSING"], "filename has no extension"))
    elif sniffed.format != "unknown" and not extensions_equivalent(source_extension, sniffed.ext):
        findings.append(make_finding(ERROR["EXTENSION_MISMATCH"], "filename extension does not match verified magic bytes", {
            "extension": source_extension,
            "actual": sniffed.ext,
        }))

    safe_filename = _canonical_storage_filename(filename_report, sniffed, policy)
    return _finalize_validation({
        "safe_filename": safe_filename,
        "detected_mime": sniffed.mime,
        "detected_ext": sniffed.ext,
        "detected_format": sniffed.format,
        "kind": sniffed.kind,
        "size_bytes": core["size_bytes"],
        "dimensions": core["dimensions"],
        "sha256": core["sha256"],
        "findings": findings,
    }, policy)


def inspect_file_bytes(input_bytes, policy: Any = None) -> ValidationResult:
    """Inspect bytes without filename or Content-Type metadata."""
    normalized_policy = normalize_policy(policy)
    data = normalize_bytes(input_bytes, "bytes")
    core = _inspect_bytes_core(data, normalized_policy)
    findings = list(core["findings"])
    if not _type_allowlist_permits(normalized_policy, core["sniffed"], ""):
        findings.append(make_finding(ERROR["TYPE_NOT_ALLOWED"], "verified file type is not in the configured allowlist", {
            "mime": core["sniffed"].mime,
            "extension": core["sniffed"].ext,
        }))
    return _finalize_validation({
        "safe_filename": None,
        "detected_mime": core["sniffed"].mime,
        "detected_ext": core["sniffed"].ext,
        "detected_format": core["sniffed"].format,
        "kind": core["sniffed"].kind,
        "size_bytes": core["size_bytes"],
        "dimensions": core["dimensions"],
        "sha256": core["sha256"],
        "findings": findings,
    }, normalized_policy)


def validate_upload(input_value: Any, policy: Any = None) -> ValidationResult:
    """Validate upload bytes, filename, and caller-supplied Content-Type."""
    normalized_policy = normalize_policy(policy)
    return _validate_upload_internal(input_value, normalized_policy)


def _path_basename(file_path: str) -> str:
    parts = [part for part in os.path.splitdrive(file_path)[1].replace("\\", "/").split("/")]
    return parts[-1] if parts and parts[-1] else "file"


def _path_failure(file_path: str, policy: Policy, findings, size_bytes: Optional[int] = None) -> ValidationResult:
    try:
        report = sanitize_filename(_path_basename(file_path), max_bytes=policy.max_filename_bytes)
        safe_filename = report.filename
    except Exception:
        safe_filename = None
    return _finalize_validation({
        "safe_filename": safe_filename,
        "detected_mime": None,
        "detected_ext": None,
        "detected_format": None,
        "kind": None,
        "size_bytes": size_bytes,
        "dimensions": None,
        "sha256": None,
        "findings": list(findings),
    }, policy)


def _stat_time_ns(stat_result, name: str) -> int:
    value = getattr(stat_result, name + "_ns", None)
    if value is not None:
        return value
    return int(getattr(stat_result, name) * 1000000000)


def validate_file_path(file_path: Any, policy: Any = None) -> ValidationResult:
    """Safely validate an existing regular file without following symlinks.

    The size cap is enforced before reading. Reads are bounded by the verified
    pre-open size plus one byte so growth, shrinkage, and metadata changes are
    treated as validation failures rather than trusted input.
    """
    normalized_policy = normalize_policy(policy)
    try:
        path_value = os.fspath(file_path)
    except TypeError:
        invalid_input("file_path must be a non-empty string or path-like object", "file_path")
    if not isinstance(path_value, str) or len(path_value) == 0:
        invalid_input("file_path must be a non-empty string or path-like object", "file_path")
    if "\x00" in path_value:
        return _path_failure(path_value, normalized_policy, [make_finding(ERROR["PATH_UNSAFE"], "file path contains a NUL byte")])

    try:
        initial_stat = os.lstat(path_value)
    except (OSError, ValueError):
        return _path_failure(path_value, normalized_policy, [make_finding(ERROR["PATH_IO_ERROR"], "file path could not be inspected")])
    if stat_module.S_ISLNK(initial_stat.st_mode):
        return _path_failure(path_value, normalized_policy, [make_finding(ERROR["PATH_SYMLINK"], "symbolic links are rejected", {"actual": "symlink"})], initial_stat.st_size)
    if not stat_module.S_ISREG(initial_stat.st_mode):
        return _path_failure(path_value, normalized_policy, [make_finding(ERROR["PATH_NOT_REGULAR"], "path is not a regular file", {"actual": "non-regular"})], initial_stat.st_size)
    if initial_stat.st_size > normalized_policy.max_bytes:
        return _path_failure(path_value, normalized_policy, [
            make_finding(ERROR["PATH_TOO_LARGE"], "file exceeds the maximum byte size before reading", {
                "limit": normalized_policy.max_bytes,
                "actual": initial_stat.st_size,
            }),
            make_finding(ERROR["MAX_BYTES"], "file exceeds the maximum byte size", {
                "limit": normalized_policy.max_bytes,
                "actual": initial_stat.st_size,
            }),
        ], initial_stat.st_size)

    fd = None
    try:
        flags = os.O_RDONLY
        flags |= getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)
        fd = os.open(path_value, flags)
        opened_stat = os.fstat(fd)
        if not stat_module.S_ISREG(opened_stat.st_mode):
            return _path_failure(path_value, normalized_policy, [make_finding(ERROR["PATH_NOT_REGULAR"], "opened path is not a regular file", {"actual": "non-regular"})], opened_stat.st_size)
        if (
            opened_stat.st_size != initial_stat.st_size
            or opened_stat.st_dev != initial_stat.st_dev
            or opened_stat.st_ino != initial_stat.st_ino
        ):
            return _path_failure(path_value, normalized_policy, [make_finding(ERROR["PATH_IO_ERROR"], "file changed while it was being validated", {"actual": "identity-change"})], opened_stat.st_size)

        size = opened_stat.st_size
        before_meta = (
            opened_stat.st_size,
            _stat_time_ns(opened_stat, "st_mtime"),
            _stat_time_ns(opened_stat, "st_ctime"),
            opened_stat.st_ino,
            opened_stat.st_dev,
        )
        chunks = []
        total = 0
        cap = size + 1
        while total < cap:
            chunk = os.read(fd, min(65536, cap - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        final_stat = os.fstat(fd)
        final_meta = (
            final_stat.st_size,
            _stat_time_ns(final_stat, "st_mtime"),
            _stat_time_ns(final_stat, "st_ctime"),
            final_stat.st_ino,
            final_stat.st_dev,
        )
        if total != size or final_stat.st_size != size or final_meta != before_meta:
            return _path_failure(path_value, normalized_policy, [make_finding(ERROR["PATH_IO_ERROR"], "file changed or truncated while it was being read", {"actual": "unstable-read"})], size)
        executable_mode = os.name != "nt" and (opened_stat.st_mode & 0o111) != 0
        return _validate_upload_internal({
            "bytes": b"".join(chunks),
            "filename": _path_basename(path_value),
            "content_type": None,
        }, normalized_policy, {"executable_mode": executable_mode})
    except (OSError, ValueError):
        return _path_failure(path_value, normalized_policy, [make_finding(ERROR["PATH_IO_ERROR"], "file could not be opened or read safely")])
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def _io_failure(policy: Policy, message: str) -> ValidationResult:
    return _finalize_validation({
        "safe_filename": None,
        "detected_mime": None,
        "detected_ext": None,
        "detected_format": None,
        "kind": None,
        "size_bytes": None,
        "dimensions": None,
        "sha256": None,
        "findings": [make_finding(ERROR["IO_ERROR"], message)],
    }, policy)


def validate_file_obj(stream: Any, filename: str = "", content_type: Optional[str] = None, policy: Any = None) -> ValidationResult:
    """Validate a file-like object with strictly bounded chunked reads.

    The largest request ever made to ``read`` is ``max_bytes + 1`` minus the
    bytes already accepted. No unbounded ``read()`` call is made, which makes
    the function suitable for framework upload streams as well as BytesIO.
    """
    normalized_policy = normalize_policy(policy)
    read = getattr(stream, "read", None)
    if not callable(read):
        invalid_input("stream must expose a callable read method", "stream")
    cap = normalized_policy.max_bytes + 1
    chunks = []
    total = 0
    try:
        while total < cap:
            remaining = cap - total
            chunk = read(remaining)
            if chunk is None:
                break
            if isinstance(chunk, str):
                raise TypeError("text streams are not upload byte streams")
            try:
                chunk_bytes = normalize_bytes(chunk, "stream chunk")
            except Exception:
                raise TypeError("stream returned a non-bytes chunk")
            if len(chunk_bytes) == 0:
                break
            if len(chunk_bytes) > remaining:
                chunk_bytes = chunk_bytes[:remaining]
            chunks.append(chunk_bytes)
            total += len(chunk_bytes)
            if len(chunk_bytes) < remaining and hasattr(stream, "seekable") and not stream.seekable():
                continue
    except Exception:
        return _io_failure(normalized_policy, "file-like object bytes could not be read")

    data = b"".join(chunks)
    truncated = total > normalized_policy.max_bytes
    return _validate_upload_internal({
        "bytes": data,
        "filename": filename,
        "content_type": content_type,
    }, normalized_policy, {
        "size_override": total,
        "truncated": truncated,
    })


class FileCage:
    """Reusable immutable-policy upload guard."""

    def __init__(self, policy: Any = None, **overrides: Any):
        base = normalize_policy(policy)
        self._policy = merge_policy(base, overrides if overrides else None)

    @property
    def policy(self) -> Policy:
        return self._policy

    def inspect_file_bytes(self, data, overrides: Any = None) -> ValidationResult:
        return inspect_file_bytes(data, merge_policy(self._policy, overrides))

    def validate_upload(self, input_value: Any, overrides: Any = None) -> ValidationResult:
        return validate_upload(input_value, merge_policy(self._policy, overrides))

    def validate_file_path(self, file_path: Any, overrides: Any = None) -> ValidationResult:
        return validate_file_path(file_path, merge_policy(self._policy, overrides))

    def validate_file_obj(self, stream: Any, filename: str = "", content_type: Optional[str] = None, overrides: Any = None) -> ValidationResult:
        return validate_file_obj(stream, filename=filename, content_type=content_type, policy=merge_policy(self._policy, overrides))

    def sanitize_filename(self, filename: str, options: Optional[Mapping[str, Any]] = None):
        return sanitize_filename(filename, options)

    def assert_safe_filename(self, filename: str, options: Optional[Mapping[str, Any]] = None):
        from .filenames import assert_safe_filename
        return assert_safe_filename(filename, options)


def create_file_cage(policy: Any = None, **overrides: Any) -> FileCage:
    return FileCage(policy, **overrides)


def create_upload_guard(policy: Any = None, **overrides: Any) -> FileCage:
    return FileCage(policy, **overrides)
