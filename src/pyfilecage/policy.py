"""Validation policy normalization and presets."""
from __future__ import annotations

import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping, Optional, Tuple

from .errors import invalid_policy
from .models import RecordMapping

_POLICY_FIELDS = (
    "preset", "allowed_mime_types", "allowed_extensions", "max_bytes", "max_width", "max_height", "max_pixels",
    "max_filename_bytes", "max_findings", "require_extension", "require_content_type", "allow_generic_content_type",
    "allow_executables", "allow_unknown_types", "allow_svg", "allow_markup", "allow_archives", "allow_pdf_uri",
    "scan_active_content", "scan_polyglots", "enforce_image_dimensions", "canonicalize_extension", "filename_action",
)

_KEY_ALIASES = {
    "allowedMimeTypes": "allowed_mime_types",
    "allowedExtensions": "allowed_extensions",
    "maxBytes": "max_bytes",
    "maxWidth": "max_width",
    "maxHeight": "max_height",
    "maxPixels": "max_pixels",
    "maxFilenameBytes": "max_filename_bytes",
    "maxFindings": "max_findings",
    "requireExtension": "require_extension",
    "requireContentType": "require_content_type",
    "allowGenericContentType": "allow_generic_content_type",
    "allowExecutables": "allow_executables",
    "allowUnknownTypes": "allow_unknown_types",
    "allowSvg": "allow_svg",
    "allowMarkup": "allow_markup",
    "allowArchives": "allow_archives",
    "allowPdfUri": "allow_pdf_uri",
    "scanActiveContent": "scan_active_content",
    "scanPolyglots": "scan_polyglots",
    "enforceImageDimensions": "enforce_image_dimensions",
    "canonicalizeExtension": "canonicalize_extension",
    "filenameAction": "filename_action",
}


@dataclass(frozen=True)
class Policy(RecordMapping):
    preset: str
    allowed_mime_types: Optional[Tuple[str, ...]]
    allowed_extensions: Optional[Tuple[str, ...]]
    max_bytes: int
    max_width: int
    max_height: int
    max_pixels: int
    max_filename_bytes: int
    max_findings: int
    require_extension: bool
    require_content_type: bool
    allow_generic_content_type: bool
    allow_executables: bool
    allow_unknown_types: bool
    allow_svg: bool
    allow_markup: bool
    allow_archives: bool
    allow_pdf_uri: bool
    scan_active_content: bool
    scan_polyglots: bool
    enforce_image_dimensions: bool
    canonicalize_extension: bool
    filename_action: str

    _fields = _POLICY_FIELDS
    _aliases = _KEY_ALIASES


_DEFAULT_VALUES = {
    "preset": "default",
    "allowed_mime_types": None,
    "allowed_extensions": None,
    "max_bytes": 10 * 1024 * 1024,
    "max_width": 10000,
    "max_height": 10000,
    "max_pixels": 25000000,
    "max_filename_bytes": 255,
    "max_findings": 64,
    "require_extension": True,
    "require_content_type": False,
    "allow_generic_content_type": False,
    "allow_executables": False,
    "allow_unknown_types": False,
    "allow_svg": False,
    "allow_markup": False,
    "allow_archives": False,
    "allow_pdf_uri": False,
    "scan_active_content": True,
    "scan_polyglots": True,
    "enforce_image_dimensions": True,
    "canonicalize_extension": True,
    "filename_action": "reject",
}

_PRESET_VALUES = {
    "images-safe": dict(_DEFAULT_VALUES, **{
        "preset": "images-safe",
        "allowed_mime_types": ("image/png", "image/jpeg", "image/webp", "image/gif"),
        "max_bytes": 10 * 1024 * 1024,
        "max_width": 10000,
        "max_height": 10000,
        "max_pixels": 25000000,
    }),
    "documents-safe": dict(_DEFAULT_VALUES, **{
        "preset": "documents-safe",
        "allowed_mime_types": (
            "application/pdf",
            "text/plain",
            "text/csv",
            "application/json",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        ),
        "max_bytes": 25 * 1024 * 1024,
    }),
    "media-safe": dict(_DEFAULT_VALUES, **{
        "preset": "media-safe",
        "allowed_mime_types": ("audio/mpeg", "video/mp4", "application/ogg", "audio/wav", "audio/flac", "video/webm", "video/x-matroska", "video/quicktime"),
        "max_bytes": 100 * 1024 * 1024,
        "enforce_image_dimensions": False,
    }),
    "strict-custom": dict(_DEFAULT_VALUES, **{
        "preset": "strict-custom",
        "allowed_mime_types": (),
        "allowed_extensions": (),
        "max_bytes": 4 * 1024 * 1024,
        "max_width": 4096,
        "max_height": 4096,
        "max_pixels": 8192000,
    }),
}

_MIME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9a-z-]+/[!#$%&'*+.^_`|~0-9a-z-]+(?:\s*;.*)?$", re.IGNORECASE)
_MIME_TOKEN_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9a-z-]+/[!#$%&'*+.^_`|~0-9a-z-]+$")
_EXTENSION_RE = re.compile(r"^\.?[a-z0-9][a-z0-9_-]{0,31}$", re.IGNORECASE)

_BOOLEAN_KEYS = (
    "require_extension", "require_content_type", "allow_generic_content_type", "allow_executables", "allow_unknown_types",
    "allow_svg", "allow_markup", "allow_archives", "allow_pdf_uri", "scan_active_content", "scan_polyglots",
    "enforce_image_dimensions", "canonicalize_extension",
)

_INTEGER_RANGES = {
    "max_bytes": (1, 4294967295),
    "max_width": (1, 1000000),
    "max_height": (1, 1000000),
    "max_pixels": (1, (2 ** 53) - 1),
    "max_filename_bytes": (32, 1024),
    "max_findings": (1, 1024),
}


def _canonical_key(key: str) -> str:
    return _KEY_ALIASES.get(key, key)


def normalize_mime_list(value, key: str):
    if value is None:
        return None
    if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple)):
        invalid_policy(key + " must be a list or tuple or None", key)
    output = []
    seen = set()
    for item in value:
        if not isinstance(item, str) or not _MIME_RE.match(item.strip()):
            invalid_policy(key + " contains an invalid MIME type", key)
        normalized = item.strip().split(";", 1)[0].strip().lower()
        if normalized not in seen:
            seen.add(normalized)
            output.append(normalized)
    return tuple(output)


def normalize_extension_list(value, key: str):
    if value is None:
        return None
    if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple)):
        invalid_policy(key + " must be a list or tuple or None", key)
    output = []
    seen = set()
    for item in value:
        if not isinstance(item, str) or not _EXTENSION_RE.match(item.strip()):
            invalid_policy(key + " contains an invalid extension", key)
        normalized = item.strip().lstrip(".").lower()
        if normalized not in seen:
            seen.add(normalized)
            output.append(normalized)
    return tuple(output)


def normalize_policy(policy: Any = None) -> Policy:
    """Normalize a preset name or mapping into an immutable validated policy."""
    input_value = policy
    if input_value is None:
        input_value = {}
    if isinstance(input_value, str):
        input_value = {"preset": input_value}
    if isinstance(input_value, Policy):
        input_value = input_value.to_dict()
    if not isinstance(input_value, Mapping):
        invalid_policy("policy must be a preset name or mapping")

    values = dict(_DEFAULT_VALUES)
    canonical_input = {}
    for raw_key, raw_value in input_value.items():
        if not isinstance(raw_key, str):
            invalid_policy("policy option names must be strings")
        key = _canonical_key(raw_key)
        if key not in _POLICY_FIELDS:
            invalid_policy("unknown policy option", raw_key)
        if key in canonical_input and canonical_input[key] != raw_value:
            invalid_policy("conflicting aliases for one policy option", key)
        canonical_input[key] = raw_value

    preset = canonical_input.get("preset")
    if preset is not None and preset != "default":
        if not isinstance(preset, str) or preset not in _PRESET_VALUES:
            invalid_policy("unknown preset", "preset")
        values.update(_PRESET_VALUES[preset])
    for key, value in canonical_input.items():
        if key != "preset" and value is not None:
            values[key] = value
        elif key != "preset" and value is None:
            values[key] = None

    values["allowed_mime_types"] = normalize_mime_list(values["allowed_mime_types"], "allowed_mime_types")
    values["allowed_extensions"] = normalize_extension_list(values["allowed_extensions"], "allowed_extensions")

    for key, (minimum, maximum) in _INTEGER_RANGES.items():
        value = values[key]
        if isinstance(value, bool) or not isinstance(value, int) or value < minimum or value > maximum:
            invalid_policy(key + " must be an integer within the supported range", key)
    for key in _BOOLEAN_KEYS:
        if not isinstance(values[key], bool):
            invalid_policy(key + " must be a boolean", key)
    if values["filename_action"] not in ("reject", "sanitize"):
        invalid_policy("filename_action must be reject or sanitize", "filename_action")
    return Policy(**values)


def policy_values(policy: Any) -> dict:
    normalized = normalize_policy(policy)
    return {key: getattr(normalized, key) for key in _POLICY_FIELDS}


def merge_policy(base: Any, overrides: Any = None) -> Policy:
    if overrides is None:
        return normalize_policy(base)
    if isinstance(overrides, str):
        return normalize_policy(overrides)
    if isinstance(overrides, Mapping) and "preset" in overrides:
        return normalize_policy(overrides)
    merged = policy_values(base)
    if not isinstance(overrides, Mapping):
        invalid_policy("policy overrides must be a preset name or mapping")
    merged.update(overrides)
    return normalize_policy(merged)


def _build_presets():
    return MappingProxyType({name: normalize_policy(values) for name, values in _PRESET_VALUES.items()})


FILECAGE_PRESETS = _build_presets()
DEFAULT_POLICY = normalize_policy(None)
MIME_TOKEN_RE = _MIME_TOKEN_RE
