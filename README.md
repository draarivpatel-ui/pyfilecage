# pyfilecage

Zero-dependency CWE-434 file-upload defense for Python 3.9 through 3.13.

`pyfilecage` verifies what an upload actually is before application code trusts
it. It never treats a filename or caller-supplied `Content-Type` as proof. It
reads magic bytes, verifies image dimensions directly from binary headers,
rejects executable and active content, detects common polyglots, and produces a
safe storage filename.

The package has no runtime dependencies and does not use `libmagic`, Pillow,
a subprocess, or a native image decoder. The source checkout contains 806 deterministic
stdlib `unittest` tests.

## Publication status

This repository is prepared for PyPI publication, but publication is a separate
release step. Do not assume that the PyPI name is live merely because this
README exists. Until the release is published, install from a verified source
checkout or an artifact you have built yourself:

```sh
python3 -m pip install .
python3 -m unittest discover -s tests
pyfilecage --help
```

After publication, the intended install command is:

```sh
python3 -m pip install pyfilecage
```

## Threat model

File upload validation often fails because different layers parse different
things. A browser supplies a filename and a MIME type, a framework may sniff a
small prefix, and an image library may decode much more of the file. Attackers
exploit that gap with executable files renamed as images, polyglot containers,
active SVG or PDF content, malformed image headers, and pixel floods that only
become expensive after decoding.

`pyfilecage` is a fail-closed boundary for bytes your service has already
received or is about to store. It is deliberately conservative. A clean result
means the bytes passed the checks configured in your policy. It does not mean a
file is harmless in every possible viewer.

| Attack | CWE | Defense |
| --- | --- | --- |
| Executable or script uploaded with an image extension and image MIME type | CWE-434 | Magic-byte detection identifies ELF, PE, thin and universal Mach-O, Java class, WASM, and direct or obfuscated shebang content and blocks it by default. |
| Macro-enabled Office files renamed as ordinary OOXML documents | CWE-434 | ZIP and ZIP64 entry metadata distinguishes DOCX, XLSX, and PPTX from DOCM, XLSM, and PPTM files containing `vbaProject.bin`, including uppercase and central-directory-only forms. Macro-bearing files are executable by default. |
| MIME spoofing through a caller-controlled `Content-Type` header | CWE-434 | The claimed type is stripped of parameters and compared with the verified type. Mismatches reject the upload. |
| Extension spoofing such as `avatar.png` containing JPEG or executable bytes | CWE-434 | The filename extension is compared with the verified type using explicit alias groups. |
| RTLO right-to-left override names such as `report U+202E gnp.exe` | CWE-434 | Unicode bidi controls and invisible Unicode format characters are rejected and removed by the sanitizer. |
| Path traversal through slash, backslash, dot, or empty filenames | CWE-22 | Path separators are never preserved. Dot aliases, dotfiles, empty names, controls, NUL, trailing dots, and trailing spaces are rejected by default. |
| Windows device names such as `CON`, `NUL`, `COM1`, `LPT1`, and superscript variants | CWE-22 | Reserved names are detected case-insensitively after Unicode compatibility normalization and neutralized. |
| Windows drive syntax and NTFS alternate data stream syntax | CWE-22 | Colons are never preserved and are replaced before a storage name is returned. |
| Double-extension attacks such as `invoice.pdf.exe` or `avatar.png.php` | CWE-434 | Active final extensions after a plausible document or image extension are flagged and normalized, including forms hidden by trailing punctuation. |
| GIFAR, JPEG plus ZIP, image plus PDF, and similar image archive polyglots | CWE-434 | Raster images are scanned for ZIP local-header and end-of-central-directory signatures and for an embedded PDF header. PNG trailing bytes after IEND reject the file. |
| Active payloads hidden in compressed PNG text chunks | CWE-434 | PNG `zTXt` and compressed `iTXt` chunks are inflated with a strict 1 MiB output cap per chunk and scanned for markup and server-side code. Reaching that cap fails closed instead of trusting a partial scan. |
| SVG script execution, event handlers, active hrefs, animated href assignment, `foreignObject`, remote resource references, stylesheet processing instructions, and CSS network access | CWE-79 | SVG is blocked by default. Explicit opt-in still requires the XML-aware active-content scan to pass. |
| SVG XML external entities and entity declarations | CWE-611 | DOCTYPE and ENTITY declarations reject the upload. |
| PDF JavaScript, launch actions, automatic actions, singular or plural embedded-file names, and URI actions | CWE-434 | PDF headers are accepted at the specification-permitted offset within the first 1024 bytes. PDF names are decoded, including hex-escaped names such as `/J#61vaScript`. Bounded Flate stream scanning does not trust fixed-size dictionary windows and cannot be skipped by decoy uses of the word `stream`. |
| PNG, JPEG, GIF, WebP, and BMP pixel floods and decompression bombs | CWE-400 | Width, height, and total pixels are read from binary headers and capped before any image decoder is invoked. Defaults are 10000 x 10000 and 25,000,000 pixels. |
| Malformed JPEG marker loops and truncated image headers | CWE-400 | The marker walker is iterative, bounded, monotonic, and rejects impossible lengths. |
| Unknown binary content | CWE-434 | Strict UTF-8 and magic-byte detection fail closed unless unknown types are explicitly enabled. |
| FIFOs, devices, sockets, directories, symlinks, executable-mode files, and oversized paths | CWE-59, CWE-400, CWE-434 | Path validation uses `os.lstat`, regular-file checks, conditional `O_NOFOLLOW` and `O_NONBLOCK`, descriptor `os.fstat`, POSIX executable-mode rejection, size checks before reading, and a post-read stability check. |
| Memory exhaustion through framework upload streams | CWE-400 | `validate_file_obj` never calls an unbounded `read()`. It reads at most `max_bytes + 1` bytes in bounded chunks. |
| Terminal control and bidirectional-text injection through filenames in CLI output | CWE-117 | The CLI removes terminal control characters and Unicode bidi controls before printing names. |

## What pyfilecage does not do

`pyfilecage` is not a virus scanner, a sandbox, a complete PDF renderer, or a
complete XML parser. It does not execute or render content. It cannot prove that
every viewer will handle a valid file safely. Keep these additional controls in
place:

- Store uploads outside the web root and never execute them.
- Serve downloads with a strict `Content-Disposition` and a content type derived
  from the verified type, not from the original uploader.
- Re-encode user images in an isolated worker when your application can do so.
- Keep image decoding and document parsing tools patched and sandboxed.
- Use authentication, rate limits, malware scanning, and storage quotas where
  appropriate.
- Treat validation of an existing path as a read-time decision. If another
  process can replace the path after validation, do not reopen it later and
  assume the answer still applies.

PDF scanning is a security scanner, not a full PDF parser. It scans direct PDF
names and bounded Flate object streams. SVG scanning detects the dangerous
constructs listed in this README. It is not a sanitizer that makes active SVG
safe to serve inline.

## Quick start

```python
from pyfilecage import validate_upload

result = validate_upload({
    "bytes": uploaded_bytes,
    "filename": "avatar.png",
    "content_type": "image/png",
}, "images-safe")

if not result.allowed:
    print(result.code)
    for finding in result.findings:
        print(finding.code, finding.message)
else:
    print(result.safe_filename)
    print(result.detected_mime)
    print(result.dimensions)
    print(result.sha256)
```

A renamed executable does not pass even when both metadata fields lie:

```python
result = validate_upload({
    "bytes": windows_executable_bytes,
    "filename": "avatar.png",
    "content_type": "image/png",
}, "images-safe")

# result.allowed is False.
# result.findings includes FILECAGE_EXECUTABLE_TYPE,
# FILECAGE_MIME_MISMATCH, and FILECAGE_EXTENSION_MISMATCH.
```

Results are immutable records. Attribute access such as `result.allowed` and
mapping access such as `result["allowed"]` are both supported. `result.to_dict()`
returns a plain JSON-ready representation.

## FastAPI, Django, and Flask stream integration

Framework upload objects normally expose a binary file-like object. Pass that
stream to `validate_file_obj` before writing it to permanent storage. The read
is bounded, so even a hostile or misbehaving stream cannot make pyfilecage read
the whole upload into memory.

```python
from pyfilecage import validate_file_obj

# FastAPI / Starlette
async def upload_avatar(file):
    data = validate_file_obj(
        file.file,
        filename=file.filename or "upload",
        content_type=file.content_type,
        policy="images-safe",
    )
    if not data.allowed:
        return {"error": data.code, "findings": [f.to_dict() for f in data.findings]}
    # Store using data.safe_filename.

# Django
def avatar_view(request):
    upload = request.FILES["avatar"]
    result = validate_file_obj(
        upload.file,
        filename=upload.name,
        content_type=upload.content_type,
        policy="images-safe",
    )

# Flask
def flask_avatar():
    upload = request.files["avatar"]
    result = validate_file_obj(
        upload.stream,
        filename=upload.filename,
        content_type=upload.content_type,
        policy="images-safe",
    )
```

For a bytes object already in memory, use `validate_upload`. For an existing
server-side path, use `validate_file_path` so symlink, device, FIFO, executable
mode, and size checks happen before content validation.

## Presets

| Preset | Verified types | Important defaults |
| --- | --- | --- |
| `images-safe` | PNG, JPEG, WebP, GIF | 10 MiB, 10000 x 10000, 25,000,000 pixels. SVG is not included. |
| `documents-safe` | PDF, plain text, CSV, JSON, DOCX, XLSX, PPTX | 25 MiB. PDF and text active-content scans remain enabled. Macro-enabled OOXML is still executable. |
| `media-safe` | MP3, MP4, QuickTime, OGG, WAV, FLAC, WebM, MKV | 100 MiB. Image dimension enforcement is not relevant to these formats. |
| `strict-custom` | None until the caller completes the policy | 4 MiB, 4096 x 4096, 8,192,000 pixels. Use with an explicit allowlist. |

A preset can be passed by name or merged with overrides:

```python
from pyfilecage import FileCage

guard = FileCage({
    "preset": "strict-custom",
    "allowed_mime_types": ["image/png", "image/jpeg"],
    "allowed_extensions": None,
    "max_bytes": 2 * 1024 * 1024,
})

result = guard.validate_upload({
    "bytes": data,
    "filename": filename,
    "content_type": content_type,
})
```

If neither `allowed_mime_types` nor `allowed_extensions` is configured, type
allowlisting is not restrictive, but executables, unknown binary data, archives,
markup, and SVG still require the relevant explicit opt-ins. Supplying either
list, even an empty list, enables allowlist enforcement. A file passes the
allowlist when either the verified MIME type or a compatible extension matches.

## Policy reference

| Option | Default | Meaning |
| --- | --- | --- |
| `allowed_mime_types` | `None` | Verified MIME allowlist, or `None` for no MIME allowlist restriction. |
| `allowed_extensions` | `None` | Extension allowlist, or `None` for no extension allowlist restriction. |
| `max_bytes` | `10485760` | Maximum upload size. Path validation checks this before reading. |
| `max_width` | `10000` | Maximum parsed image width. |
| `max_height` | `10000` | Maximum parsed image height. |
| `max_pixels` | `25000000` | Maximum width multiplied by height. |
| `max_filename_bytes` | `255` | UTF-8 byte cap for the storage filename. |
| `max_findings` | `64` | Maximum reported findings. |
| `require_extension` | `True` | Reject names without an extension. |
| `require_content_type` | `False` | Require a caller-supplied content type. It is still never trusted by itself. |
| `allow_generic_content_type` | `False` | Tolerate `application/octet-stream` as non-informative metadata. |
| `allow_executables` | `False` | Permit executable binary, script, macro-bearing OOXML, or executable-mode path content. Almost never enable this. |
| `allow_unknown_types` | `False` | Permit content that cannot be identified. |
| `allow_svg` | `False` | Permit SVG after active-content scanning. |
| `allow_markup` | `False` | Permit inert HTML or XML after active-content scanning. |
| `allow_archives` | `False` | Permit ZIP, JAR, TAR, GZIP, or ZSTD archive containers. |
| `allow_pdf_uri` | `False` | Do not treat a PDF `/URI` name as a finding. Other PDF actions remain blocked. |
| `scan_active_content` | `True` | Scan for active markup, server-side tags, PDF actions, and SVG active content. |
| `scan_polyglots` | `True` | Scan raster images for ZIP signatures and trailing PNG data. |
| `enforce_image_dimensions` | `True` | Require parseable PNG, JPEG, GIF, WebP, or BMP dimensions and enforce caps. |
| `canonicalize_extension` | `True` | Make the returned storage filename end in the canonical verified extension. |
| `filename_action` | `reject` | `reject` treats hostile filename properties as errors. `sanitize` downgrades neutralized filename findings to warnings. |

CamelCase aliases matching the JavaScript `filecage` policy names are accepted
for compatibility, but new Python code should use the snake_case names above.

## API

### `sniff_file_type(data)`

Returns an immutable detection result:

```python
{
    "mime": "image/png",
    "ext": "png",
    "kind": "image",
    "format": "png",
    "executable": False,
    "confident": True,
    "signature": "magic",
    "offset": 0,
}
```

Detected families include PNG, JPEG, GIF 87a and 89a, WebP, BMP, ICO, AVIF,
HEIF, TIFF little-endian and big-endian, PDF, ZIP, DOCX, XLSX, PPTX, macro-bearing
DOCM, XLSM, and PPTM, JAR, GZIP, ZSTD, TAR, MP3, MP4, QuickTime, OGG, WAV,
FLAC, WebM, Matroska, WASM, ELF, PE or DOS executables, Mach-O, Java class
files, shebang scripts, HTML, SVG, XML, strict UTF-8 plain text, JSON, and
consistent-column CSV. Leading XML processing instructions do not hide an SVG or XML root element.

### `inspect_image_dimensions(data)`

Returns `ImageDimensions(format, width, height, pixels)` for PNG, JPEG, GIF,
WebP, and BMP, or `None` when the relevant binary header is malformed or
unsupported. JPEG uses an iterative marker walk for SOF0, SOF1, SOF2, SOF3,
SOF5, SOF6, SOF7, SOF9, SOF10, SOF11, SOF13, SOF14, and SOF15. No image decoder
is invoked.

### `validate_upload(input_value, policy=None)`

```python
result = validate_upload({
    "bytes": data,
    "filename": filename,
    "content_type": content_type,
}, policy)
```

Returns an immutable `ValidationResult` with these fields:

| Field | Meaning |
| --- | --- |
| `allowed` | True only when no error-severity finding exists. |
| `safe_filename` | Deterministic sanitized storage filename with canonical verified extension. |
| `detected_mime` | MIME type verified from content. |
| `detected_ext` | Canonical extension for the verified type. |
| `detected_format` | Internal format name such as `png`, `docx`, or `pe`. |
| `kind` | Broad family such as `image`, `document`, `media`, or `executable`. |
| `size_bytes` | Byte size used for validation. |
| `dimensions` | Parsed image dimensions or `None`. |
| `sha256` | Hex digest of the exact bytes inspected, or `None` for a deliberately truncated stream. |
| `findings` | Immutable tuple of finding records. |
| `code` | First error code, or first warning code when there is no error. |

### `inspect_file_bytes(data, policy=None)`

Validates bytes without filename or Content-Type metadata. This is useful for
server-generated files, cache objects, and content already detached from its
original upload metadata.

### `validate_file_obj(stream, filename=..., content_type=..., policy=None)`

Validates a binary file-like object using bounded chunked reads. The largest
single request is at most `max_bytes + 1` minus bytes already accepted, and no
unbounded `read()` call is ever made.

### `validate_file_path(path, policy=None)`

Validates an existing regular file. The function rejects symlinks, non-regular
files, oversized files before reading, POSIX executable-mode files, and paths
that change while being inspected. It does not print or return the inspected
path in findings.

### `sanitize_filename(name, max_bytes=255)` and `assert_safe_filename(name, max_bytes=255)`

`sanitize_filename` returns a report containing a deterministic safe storage
name and every hostile property found. `assert_safe_filename` returns the same
report for a clean name and raises `FileCageError` for hostile input.

## Finding codes

| Code | Meaning |
| --- | --- |
| `FILECAGE_INVALID_INPUT` | API input shape or type is invalid. |
| `FILECAGE_INVALID_POLICY` | Policy shape, preset, type, or range is invalid. |
| `FILECAGE_INVALID_UTF8` | SVG bytes are not valid UTF-8. |
| `FILECAGE_EMPTY_FILE` | Upload is empty. |
| `FILECAGE_MAX_BYTES` | Upload exceeds the byte cap. |
| `FILECAGE_UNRECOGNIZED_TYPE` | Magic bytes and strict text decoding cannot identify the content. |
| `FILECAGE_TYPE_NOT_ALLOWED` | Verified type is outside the configured allowlist. |
| `FILECAGE_EXECUTABLE_TYPE` | Executable binary, script, macro-bearing OOXML, or executable-mode file detected. |
| `FILECAGE_ARCHIVE_NOT_ALLOWED` | Archive container requires explicit opt-in. |
| `FILECAGE_MARKUP_NOT_ALLOWED` | HTML or XML requires explicit opt-in. |
| `FILECAGE_SVG_NOT_ALLOWED` | SVG requires explicit opt-in. |
| `FILECAGE_CONTENT_TYPE_MISSING` | Required caller content type is absent. |
| `FILECAGE_INVALID_CONTENT_TYPE` | Caller content type is not a valid MIME token. |
| `FILECAGE_MIME_MISMATCH` | Claimed content type disagrees with verified bytes. |
| `FILECAGE_EXTENSION_MISSING` | Required filename extension is absent. |
| `FILECAGE_EXTENSION_MISMATCH` | Filename extension disagrees with verified bytes. |
| `FILECAGE_DIMENSIONS_UNREADABLE` | Raster dimensions cannot be verified. |
| `FILECAGE_MAX_WIDTH` | Image width exceeds its cap. |
| `FILECAGE_MAX_HEIGHT` | Image height exceeds its cap. |
| `FILECAGE_MAX_PIXELS` | Image pixel count exceeds its cap. |
| `FILECAGE_ACTIVE_CONTENT` | Active markup or server-side code is present, including compressed PNG text payloads. |
| `FILECAGE_POLYGLOT` | Raster image contains an embedded ZIP or JAR signature. |
| `FILECAGE_TRAILING_DATA` | PNG contains bytes after IEND. |
| `FILECAGE_PDF_ACTIVE_CONTENT` | PDF contains an active action or embedded-file name. |
| `FILECAGE_PDF_SCAN_LIMIT` | Bounded PDF compressed-object scan reached a safety limit or malformed stream. |
| `FILECAGE_PNG_TEXT_SCAN_LIMIT` | Compressed PNG text scan reached a safety limit or malformed stream. |
| `FILECAGE_SVG_ACTIVE_CONTENT` | SVG contains script, events, active hrefs, remote references, or network-capable CSS. |
| `FILECAGE_SVG_XXE` | SVG contains DOCTYPE or ENTITY declarations. |
| `FILECAGE_FILENAME_*` | Filename is empty, relative, too long, controlled, bidi-spoofed, format-spoofed, path-bearing, unsafe, reserved, trailing-normalized, or double-extended. |
| `FILECAGE_PATH_UNSAFE` | Path contains a NUL byte. |
| `FILECAGE_PATH_SYMLINK` | Path is a symbolic link. |
| `FILECAGE_PATH_NOT_REGULAR` | Path is not a regular file. |
| `FILECAGE_PATH_TOO_LARGE` | Path size exceeds the cap before reading. |
| `FILECAGE_PATH_IO_ERROR` | Path cannot be opened, read, or kept stable during validation. |
| `FILECAGE_IO_ERROR` | File-like object bytes cannot be read. |
| `FILECAGE_MAX_FINDINGS` | Finding count reached the reporting cap. |

## CLI

```sh
pyfilecage inspect avatar.png --preset images-safe
pyfilecage inspect avatar.png --allow image/png,image/jpeg --max-bytes 5242880 --max-pixels 12000000
pyfilecage inspect document.pdf --json
python3 -m pyfilecage inspect document.pdf
```

Exit code `0` means the file passed validation. Exit code `1` means the file was
readable but rejected or has security findings. Exit code `2` means usage,
input, policy, or I/O failure. Human and JSON output neutralize terminal control
and bidirectional override characters.

## Security and contributions

Read `SECURITY.md` before reporting a vulnerability. Read `CONTRIBUTING.md` and
`docs/GOOD_FIRST_ISSUES.md` before opening a pull request. The package is MIT
licensed.
