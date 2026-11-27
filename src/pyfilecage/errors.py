"""Error type and stable public error codes for pyfilecage."""
from __future__ import annotations

from types import MappingProxyType
from typing import Any, Mapping, Optional

FILECAGE_ERROR_CODES = MappingProxyType({
    "INVALID_INPUT": "FILECAGE_INVALID_INPUT",
    "INVALID_POLICY": "FILECAGE_INVALID_POLICY",
    "INVALID_UTF8": "FILECAGE_INVALID_UTF8",
    "EMPTY_FILE": "FILECAGE_EMPTY_FILE",
    "MAX_BYTES": "FILECAGE_MAX_BYTES",
    "UNRECOGNIZED_TYPE": "FILECAGE_UNRECOGNIZED_TYPE",
    "TYPE_NOT_ALLOWED": "FILECAGE_TYPE_NOT_ALLOWED",
    "EXECUTABLE_TYPE": "FILECAGE_EXECUTABLE_TYPE",
    "ARCHIVE_NOT_ALLOWED": "FILECAGE_ARCHIVE_NOT_ALLOWED",
    "MARKUP_NOT_ALLOWED": "FILECAGE_MARKUP_NOT_ALLOWED",
    "SVG_NOT_ALLOWED": "FILECAGE_SVG_NOT_ALLOWED",
    "CONTENT_TYPE_MISSING": "FILECAGE_CONTENT_TYPE_MISSING",
    "INVALID_CONTENT_TYPE": "FILECAGE_INVALID_CONTENT_TYPE",
    "MIME_MISMATCH": "FILECAGE_MIME_MISMATCH",
    "EXTENSION_MISSING": "FILECAGE_EXTENSION_MISSING",
    "EXTENSION_MISMATCH": "FILECAGE_EXTENSION_MISMATCH",
    "DIMENSIONS_UNREADABLE": "FILECAGE_DIMENSIONS_UNREADABLE",
    "MAX_WIDTH": "FILECAGE_MAX_WIDTH",
    "MAX_HEIGHT": "FILECAGE_MAX_HEIGHT",
    "MAX_PIXELS": "FILECAGE_MAX_PIXELS",
    "ACTIVE_CONTENT": "FILECAGE_ACTIVE_CONTENT",
    "POLYGLOT": "FILECAGE_POLYGLOT",
    "TRAILING_DATA": "FILECAGE_TRAILING_DATA",
    "PDF_ACTIVE_CONTENT": "FILECAGE_PDF_ACTIVE_CONTENT",
    "PDF_SCAN_LIMIT": "FILECAGE_PDF_SCAN_LIMIT",
    "SVG_ACTIVE_CONTENT": "FILECAGE_SVG_ACTIVE_CONTENT",
    "SVG_XXE": "FILECAGE_SVG_XXE",
    "FILENAME_EMPTY": "FILECAGE_FILENAME_EMPTY",
    "FILENAME_DOT_NAME": "FILECAGE_FILENAME_DOT_NAME",
    "FILENAME_TOO_LONG": "FILECAGE_FILENAME_TOO_LONG",
    "FILENAME_NUL": "FILECAGE_FILENAME_NUL",
    "FILENAME_CONTROL": "FILECAGE_FILENAME_CONTROL",
    "FILENAME_BIDI": "FILECAGE_FILENAME_BIDI",
    "FILENAME_PATH_SEPARATOR": "FILECAGE_FILENAME_PATH_SEPARATOR",
    "FILENAME_UNSAFE_CHAR": "FILECAGE_FILENAME_UNSAFE_CHAR",
    "FILENAME_RESERVED_DEVICE": "FILECAGE_FILENAME_RESERVED_DEVICE",
    "FILENAME_TRAILING_DOTS_SPACES": "FILECAGE_FILENAME_TRAILING_DOTS_SPACES",
    "FILENAME_DOUBLE_EXTENSION": "FILECAGE_FILENAME_DOUBLE_EXTENSION",
    "PATH_UNSAFE": "FILECAGE_PATH_UNSAFE",
    "PATH_SYMLINK": "FILECAGE_PATH_SYMLINK",
    "PATH_NOT_REGULAR": "FILECAGE_PATH_NOT_REGULAR",
    "PATH_TOO_LARGE": "FILECAGE_PATH_TOO_LARGE",
    "PATH_IO_ERROR": "FILECAGE_PATH_IO_ERROR",
    "IO_ERROR": "FILECAGE_IO_ERROR",
    "MAX_FINDINGS": "FILECAGE_MAX_FINDINGS",
})

CODE = FILECAGE_ERROR_CODES
ERROR = FILECAGE_ERROR_CODES


class FileCageError(ValueError):
    """A validation API input or policy error with a stable machine code."""

    name = "FileCageError"

    def __init__(self, code: str, message: str, details: Optional[Mapping[str, Any]] = None):
        super().__init__(code + ": " + message)
        self.code = code
        self.reason = message
        if details:
            for key, value in details.items():
                if value is not None and key not in {"code", "reason", "name"}:
                    setattr(self, key, value)

    def to_dict(self) -> dict:
        output = {"name": self.name, "code": self.code, "reason": self.reason}
        for key in (
            "position", "pattern", "token", "limit", "actual", "width", "height",
            "pixels", "filename", "extension", "mime", "key",
        ):
            if hasattr(self, key):
                output[key] = getattr(self, key)
        return output

    def toJSON(self) -> dict:  # compatibility with the JavaScript twin's shape
        return self.to_dict()


def invalid_input(message: str, key: Optional[str] = None) -> None:
    details = {"key": key} if key is not None else None
    raise FileCageError(ERROR["INVALID_INPUT"], message, details)


def invalid_policy(message: str, key: Optional[str] = None) -> None:
    details = {"key": key} if key is not None else None
    raise FileCageError(ERROR["INVALID_POLICY"], message, details)
