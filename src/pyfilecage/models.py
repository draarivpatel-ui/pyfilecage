"""Immutable result records returned by pyfilecage."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Iterator, Optional, Tuple


class RecordMapping(Mapping):
    """Small immutable mapping base that also supports attribute access."""

    _fields: Tuple[str, ...] = ()
    _aliases = {}

    def __getitem__(self, key: str) -> Any:
        key = self._aliases.get(key, key)
        if key in self._fields:
            return getattr(self, key)
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return iter(self._fields)

    def __len__(self) -> int:
        return len(self._fields)

    def to_dict(self) -> dict:
        return {key: getattr(self, key) for key in self._fields}


class Finding(Mapping):
    """One immutable validation finding.

    Detail values such as ``pattern``, ``position`` and ``actual`` are available
    both as mapping keys and as attributes.
    """

    __slots__ = ("code", "message", "severity", "_details")
    _base_fields = ("code", "message", "severity")

    def __init__(self, code: str, message: str, severity: str = "error", details: Optional[Mapping[str, Any]] = None):
        object.__setattr__(self, "code", code)
        object.__setattr__(self, "message", message)
        object.__setattr__(self, "severity", severity)
        clean = {}
        if details:
            for key, value in details.items():
                if key in self._base_fields or value is None:
                    continue
                clean[key] = value
        object.__setattr__(self, "_details", MappingProxyType(clean))

    def __setattr__(self, key: str, value: Any) -> None:
        raise AttributeError("Finding objects are immutable")

    def __getitem__(self, key: str) -> Any:
        if key in self._base_fields:
            return getattr(self, key)
        return self._details[key]

    def __getattr__(self, key: str) -> Any:
        try:
            return self._details[key]
        except KeyError as exc:
            raise AttributeError(key) from exc

    def __iter__(self) -> Iterator[str]:
        yield from self._base_fields
        for key in self._details:
            yield key

    def __len__(self) -> int:
        return len(self._base_fields) + len(self._details)

    def __repr__(self) -> str:
        return "Finding(code={!r}, severity={!r}, message={!r})".format(self.code, self.severity, self.message)

    def to_dict(self) -> dict:
        output = {"code": self.code, "message": self.message, "severity": self.severity}
        output.update(self._details)
        return output


def make_finding(code: str, message: str, details: Optional[Mapping[str, Any]] = None, severity: str = "error") -> Finding:
    return Finding(code, message, severity, details)


@dataclass(frozen=True)
class SniffResult(RecordMapping):
    mime: str
    ext: str
    kind: str
    format: str
    executable: bool
    confident: bool
    signature: str
    offset: int = 0

    _fields = ("mime", "ext", "kind", "format", "executable", "confident", "signature", "offset")


@dataclass(frozen=True)
class ImageDimensions(RecordMapping):
    format: str
    width: int
    height: int
    pixels: int

    _fields = ("format", "width", "height", "pixels")


@dataclass(frozen=True)
class FilenameReport(RecordMapping):
    original: str
    filename: str
    stem: str
    extension: str
    source_extension: str
    changed: bool
    byte_length: int
    findings: Tuple[Finding, ...] = field(default_factory=tuple)

    _fields = ("original", "filename", "stem", "extension", "source_extension", "changed", "byte_length", "findings")
    _aliases = {"sourceExtension": "source_extension", "byteLength": "byte_length"}

    def to_dict(self) -> dict:
        output = super().to_dict()
        output["findings"] = [item.to_dict() for item in self.findings]
        return output


@dataclass(frozen=True)
class ValidationResult(RecordMapping):
    allowed: bool
    safe_filename: Optional[str]
    detected_mime: Optional[str]
    detected_ext: Optional[str]
    detected_format: Optional[str]
    kind: Optional[str]
    size_bytes: Optional[int]
    dimensions: Optional[ImageDimensions]
    sha256: Optional[str]
    findings: Tuple[Finding, ...]
    code: Optional[str]

    _fields = (
        "allowed", "safe_filename", "detected_mime", "detected_ext", "detected_format",
        "kind", "size_bytes", "dimensions", "sha256", "findings", "code",
    )
    _aliases = {
        "safeFilename": "safe_filename",
        "detectedMime": "detected_mime",
        "detectedExt": "detected_ext",
        "detectedFormat": "detected_format",
        "sizeBytes": "size_bytes",
    }

    def to_dict(self) -> dict:
        output = super().to_dict()
        output["dimensions"] = self.dimensions.to_dict() if self.dimensions is not None else None
        output["findings"] = [item.to_dict() for item in self.findings]
        return output
