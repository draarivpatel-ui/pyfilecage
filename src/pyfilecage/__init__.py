"""pyfilecage: zero-dependency CWE-434 file-upload validation."""
from __future__ import annotations

from .errors import CODE, ERROR, FILECAGE_ERROR_CODES, FileCageError
from .filenames import assert_safe_filename, sanitize_filename
from .images import inspect_image_dimensions
from .models import FilenameReport, Finding, ImageDimensions, SniffResult, ValidationResult
from .policy import DEFAULT_POLICY, FILECAGE_PRESETS, Policy
from .sniff import sniff_file_type
from .validation import (
    FileCage,
    create_file_cage,
    create_upload_guard,
    inspect_file_bytes,
    validate_file_obj,
    validate_file_path,
    validate_upload,
)

FILECAGE_VERSION = "1.0.0"
__version__ = FILECAGE_VERSION

__all__ = [
    "CODE",
    "DEFAULT_POLICY",
    "ERROR",
    "FILECAGE_ERROR_CODES",
    "FILECAGE_PRESETS",
    "FILECAGE_VERSION",
    "FileCage",
    "FileCageError",
    "FilenameReport",
    "Finding",
    "ImageDimensions",
    "Policy",
    "SniffResult",
    "ValidationResult",
    "__version__",
    "assert_safe_filename",
    "create_file_cage",
    "create_upload_guard",
    "inspect_file_bytes",
    "inspect_image_dimensions",
    "sanitize_filename",
    "sniff_file_type",
    "validate_file_obj",
    "validate_file_path",
    "validate_upload",
]
