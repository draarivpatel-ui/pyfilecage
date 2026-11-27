from __future__ import annotations

import dataclasses
import unittest

from helpers import ascii_bytes, bmp, case_methods, ftyp, gif, has_finding, jpeg, pdf, png, svg, tar, validate, webp_vp8, zip_bytes
from pyfilecage import FileCage, FileCageError, inspect_file_bytes, validate_upload
from pyfilecage.policy import normalize_policy

DEFAULT_PASS_CASES = [
    ("PNG", png(), "image.png", "image/png"),
    ("JPEG", jpeg(), "photo.jpg", "image/jpeg"),
    ("GIF", gif(), "image.gif", "image/gif"),
    ("WebP", webp_vp8(), "image.webp", "image/webp"),
    ("BMP", bmp(), "image.bmp", "image/bmp"),
    ("plain text", ascii_bytes("hello\n"), "notes.txt", "text/plain"),
    ("JSON", ascii_bytes('{"a":1}'), "data.json", "application/json"),
    ("CSV", ascii_bytes("a,b\n1,2\n"), "data.csv", "text/csv"),
    ("PDF", pdf(), "document.pdf", "application/pdf"),
]


def _default_pass_body(self, label, data, filename, content_type):
    result = validate(data, filename, content_type)
    self.assertTrue(result.allowed, label + ": " + repr([item.to_dict() for item in result.findings]))
    self.assertEqual(result.findings, ())


@case_methods("default_pass", DEFAULT_PASS_CASES, _default_pass_body)
class DefaultPassTest(unittest.TestCase):
    pass


MIME_EQUIVALENT_CASES = [
    ("image/jpg alias", jpeg(), "photo.jpeg", "image/jpg"),
    ("image/pjpeg alias", jpeg(), "photo.jpe", "image/pjpeg"),
    ("JPEG parameter stripping", jpeg(), "photo.jpg", "image/jpeg; charset=binary"),
    ("uppercase MIME", jpeg(), "photo.jpg", "IMAGE/JPEG"),
    ("JSON text alias", ascii_bytes('{"a":1}'), "data.json", "text/json"),
    ("CSV vendor alias", ascii_bytes("a,b\n1,2\n"), "data.csv", "application/vnd.ms-excel"),
    ("WAV audio/wave alias", b"RIFF" + bytes((36, 0, 0, 0)) + b"WAVEfmt ", "sound.wav", "audio/wave"),
    ("MP3 audio/mp3 alias", b"ID3" + bytes((4, 0, 0, 0, 0, 0, 0)), "sound.mp3", "audio/mp3"),
]


@case_methods("mime_equivalent", MIME_EQUIVALENT_CASES, _default_pass_body)
class MimeEquivalentTest(unittest.TestCase):
    pass


MIME_MISMATCH_CASES = [
    ("wrong image type", png(), "image.png", "image/jpeg"),
    ("text claimed image", ascii_bytes("hello\n"), "notes.txt", "image/png"),
    ("pdf claimed text", pdf(), "document.pdf", "text/plain"),
    ("json claimed csv", ascii_bytes('{"a":1}'), "data.json", "text/csv"),
    ("invalid token", png(), "image.png", "not a mime"),
    ("empty type required", png(), "image.png", ""),
]


def _mismatch_body(self, label, data, filename, content_type):
    policy = {"require_content_type": True} if label == "empty type required" else None
    result = validate(data, filename, content_type, policy)
    self.assertFalse(result.allowed, label)
    expected = "FILECAGE_CONTENT_TYPE_MISSING" if label == "empty type required" else ("FILECAGE_INVALID_CONTENT_TYPE" if label == "invalid token" else "FILECAGE_MIME_MISMATCH")
    self.assertTrue(has_finding(result, expected), label)


@case_methods("content_type_rejection", MIME_MISMATCH_CASES, _mismatch_body)
class ContentTypeRejectionTest(unittest.TestCase):
    def test_generic_octet_stream_denied_by_default(self):
        result = validate(png(), "image.png", "application/octet-stream")
        self.assertTrue(has_finding(result, "FILECAGE_MIME_MISMATCH"))

    def test_generic_octet_stream_explicitly_tolerated(self):
        result = validate(png(), "image.png", "application/octet-stream", {"allow_generic_content_type": True})
        self.assertFalse(has_finding(result, "FILECAGE_MIME_MISMATCH"))
        self.assertTrue(result.allowed)

    def test_content_type_not_required_by_default(self):
        self.assertTrue(validate(png(), "image.png", None).allowed)


DEFAULT_DENY_CASES = [
    ("ZIP archive", zip_bytes([{"name": "a.txt", "data": "a"}]), "archive.zip", "application/zip", "FILECAGE_ARCHIVE_NOT_ALLOWED"),
    ("TAR archive", tar(), "archive.tar", "application/x-tar", "FILECAGE_ARCHIVE_NOT_ALLOWED"),
    ("HTML markup", ascii_bytes("<html><body>x</body></html>"), "page.html", "text/html", "FILECAGE_MARKUP_NOT_ALLOWED"),
    ("XML markup", ascii_bytes("<?xml version=\"1.0\"?><root/>"), "data.xml", "application/xml", "FILECAGE_MARKUP_NOT_ALLOWED"),
    ("SVG", svg(), "image.svg", "image/svg+xml", "FILECAGE_SVG_NOT_ALLOWED"),
    ("unknown binary", bytes((0x66, 0, 0x99, 1)), "blob.bin", "application/octet-stream", "FILECAGE_UNRECOGNIZED_TYPE"),
    ("GZIP archive", bytes((0x1F, 0x8B, 8, 0)), "data.gz", "application/gzip", "FILECAGE_ARCHIVE_NOT_ALLOWED"),
    ("WASM executable", bytes((0, 0x61, 0x73, 0x6D, 1, 0, 0, 0)), "module.wasm", "application/wasm", "FILECAGE_EXECUTABLE_TYPE"),
]


def _default_deny_body(self, label, data, filename, content_type, code):
    result = validate(data, filename, content_type)
    self.assertFalse(result.allowed, label)
    self.assertTrue(has_finding(result, code), label)


@case_methods("default_deny", DEFAULT_DENY_CASES, _default_deny_body)
class DefaultDenyTest(unittest.TestCase):
    pass


OPTIN_CASES = [
    ("archive opt-in", zip_bytes([{"name": "a.txt", "data": "a"}]), "archive.zip", "application/zip", {"allow_archives": True}, "FILECAGE_ARCHIVE_NOT_ALLOWED"),
    ("markup opt-in", ascii_bytes("<html><body>x</body></html>"), "page.html", "text/html", {"allow_markup": True}, "FILECAGE_MARKUP_NOT_ALLOWED"),
    ("svg opt-in", svg(), "image.svg", "image/svg+xml", {"allow_svg": True}, "FILECAGE_SVG_NOT_ALLOWED"),
    ("unknown opt-in", bytes((0x66, 0, 0x99, 1)), "blob.bin", "application/octet-stream", {"allow_unknown_types": True, "allow_generic_content_type": True}, "FILECAGE_UNRECOGNIZED_TYPE"),
]


def _optin_body(self, label, data, filename, content_type, policy, removed_code):
    result = validate(data, filename, content_type, policy)
    self.assertFalse(has_finding(result, removed_code), label)


@case_methods("explicit_optin", OPTIN_CASES, _optin_body)
class ExplicitOptinTest(unittest.TestCase):
    pass


ALLOWLIST_CASES = [
    ("single MIME permits exact", {"allowed_mime_types": ["image/png"]}, True),
    ("single MIME permits alias", {"allowed_mime_types": ["image/jpg"]}, True),
    ("wrong MIME denies", {"allowed_mime_types": ["image/jpeg"]}, False),
    ("empty MIME list denies", {"allowed_mime_types": []}, False),
    ("extension permits exact", {"allowed_extensions": ["png"]}, True),
    ("extension permits dotted", {"allowed_extensions": [".png"]}, True),
    ("extension permits alias", {"allowed_extensions": ["jpeg"]}, True),
    ("wrong extension denies", {"allowed_extensions": ["gif"]}, False),
    ("empty extension list denies", {"allowed_extensions": []}, False),
    ("union extension can rescue wrong MIME list", {"allowed_mime_types": ["image/jpeg"], "allowed_extensions": ["png"]}, True),
    ("union MIME can rescue wrong extension list", {"allowed_mime_types": ["image/png"], "allowed_extensions": ["gif"]}, True),
]


def _allowlist_body(self, label, policy, expected):
    alias_case = "alias" in label
    data = jpeg() if alias_case else png()
    filename = "photo.jpe" if alias_case else "image.png"
    content_type = "image/jpeg" if alias_case else "image/png"
    result = validate(data, filename, content_type, policy)
    self.assertEqual(not has_finding(result, "FILECAGE_TYPE_NOT_ALLOWED"), expected, label)
    if not expected:
        self.assertFalse(result.allowed)


@case_methods("allowlist", ALLOWLIST_CASES, _allowlist_body)
class AllowlistTest(unittest.TestCase):
    def test_jpeg_extension_alias_allowed(self):
        result = validate(jpeg(), "photo.jpe", "image/jpeg", {"allowed_extensions": ["jpg"]})
        self.assertFalse(has_finding(result, "FILECAGE_TYPE_NOT_ALLOWED"))

    def test_denylist_does_not_exist_by_design(self):
        with self.assertRaises(FileCageError):
            normalize_policy({"blocked_mime_types": ["image/png"]})


SIZE_CASES = [
    ("one byte under cap", 99, {"max_bytes": 100}, False),
    ("exactly at cap", 100, {"max_bytes": 100}, False),
    ("one byte over cap", 101, {"max_bytes": 100}, True),
    ("much larger than tiny cap", 500, {"max_bytes": 32}, True),
]


def _size_body(self, label, size, policy, over):
    data = ascii_bytes("a,b\n" + "1,2\n" * ((size // 4) + 1))[:size]
    result = validate(data, "data.csv", "text/csv", policy)
    self.assertEqual(has_finding(result, "FILECAGE_MAX_BYTES"), over, label)


@case_methods("max_bytes", SIZE_CASES, _size_body)
class MaxBytesTest(unittest.TestCase):
    def test_default_max_bytes_enforced(self):
        result = validate(b"a" * (10 * 1024 * 1024 + 1), "large.bin", "application/octet-stream")
        self.assertTrue(has_finding(result, "FILECAGE_MAX_BYTES"))

    def test_empty_file_rejected(self):
        self.assertTrue(has_finding(validate(b"", "empty.txt", "text/plain"), "FILECAGE_EMPTY_FILE"))


INVALID_POLICY_CASES = [
    ("unknown key", {"nonsense": True}),
    ("boolean as integer", {"allow_svg": 1}),
    ("MIME string not list", {"allowed_mime_types": "image/png"}),
    ("invalid MIME item", {"allowed_mime_types": ["not a mime"]}),
    ("extension string not list", {"allowed_extensions": "png"}),
    ("invalid extension item", {"allowed_extensions": ["../x"]}),
    ("zero max bytes", {"max_bytes": 0}),
    ("negative max width", {"max_width": -1}),
    ("float max pixels", {"max_pixels": 2.5}),
    ("small filename cap", {"max_filename_bytes": 31}),
    ("zero max findings", {"max_findings": 0}),
    ("unknown preset", {"preset": "everything"}),
    ("bad filename action", {"filename_action": "rename"}),
    ("null policy object", None),
]


def _invalid_policy_body(self, label, policy):
    if label == "null policy object":
        self.assertIsInstance(normalize_policy(None), object)
        return
    with self.assertRaises(FileCageError) as caught:
        normalize_policy(policy)
    self.assertEqual(caught.exception.code, "FILECAGE_INVALID_POLICY", label)


@case_methods("invalid_policy", INVALID_POLICY_CASES, _invalid_policy_body)
class InvalidPolicyTest(unittest.TestCase):
    pass


PRESET_CASES = [
    ("images-safe accepts png", "images-safe", png(), "image.png", "image/png", True),
    ("images-safe accepts jpeg", "images-safe", jpeg(), "photo.jpg", "image/jpeg", True),
    ("images-safe rejects svg even clean", "images-safe", svg(), "image.svg", "image/svg+xml", False),
    ("images-safe rejects pdf", "images-safe", pdf(), "doc.pdf", "application/pdf", False),
    ("documents-safe accepts pdf", "documents-safe", pdf(), "doc.pdf", "application/pdf", True),
    ("documents-safe accepts csv", "documents-safe", ascii_bytes("a,b\n1,2\n"), "data.csv", "text/csv", True),
    ("documents-safe accepts docx", "documents-safe", zip_bytes([{"name": "[Content_Types].xml"}, {"name": "word/document.xml"}]), "doc.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", True),
    ("documents-safe rejects png", "documents-safe", png(), "image.png", "image/png", False),
    ("media-safe accepts mp4", "media-safe", ftyp("isom", ["mp42"]), "video.mp4", "video/mp4", True),
    ("media-safe accepts mp3", "media-safe", b"ID3" + bytes((4, 0, 0, 0, 0, 0, 0)), "sound.mp3", "audio/mpeg", True),
    ("media-safe rejects png", "media-safe", png(), "image.png", "image/png", False),
    ("strict-custom starts deny-all", "strict-custom", png(), "image.png", "image/png", False),
]


def _preset_body(self, label, preset, data, filename, content_type, expected):
    result = validate(data, filename, content_type, {"preset": preset})
    self.assertEqual(not has_finding(result, "FILECAGE_TYPE_NOT_ALLOWED"), expected, label)


@case_methods("preset", PRESET_CASES, _preset_body)
class PresetTest(unittest.TestCase):
    pass


class ValidationApiTest(unittest.TestCase):
    def test_snake_case_and_camel_case_input_keys(self):
        snake = validate_upload({"bytes": png(), "filename": "image.png", "content_type": "image/png"})
        camel = validate_upload({"bytes": png(), "filename": "image.png", "contentType": "image/png"})
        self.assertTrue(snake.allowed)
        self.assertTrue(camel.allowed)

    def test_upload_object_attributes_supported(self):
        class Upload:
            bytes = png()
            filename = "image.png"
            content_type = "image/png"
        self.assertTrue(validate_upload(Upload()).allowed)

    def test_upload_object_data_alias_supported(self):
        class Upload:
            data = png()
            name = "image.png"
            type = "image/png"
        self.assertTrue(validate_upload(Upload()).allowed)

    def test_missing_extension_rejected_by_default(self):
        result = validate(png(), "image", "image/png")
        self.assertTrue(has_finding(result, "FILECAGE_EXTENSION_MISSING"))

    def test_require_extension_can_be_disabled(self):
        result = validate(png(), "image", "image/png", {"require_extension": False})
        self.assertFalse(has_finding(result, "FILECAGE_EXTENSION_MISSING"))

    def test_nonstring_filename_is_invalid_input(self):
        result = validate_upload({"bytes": png(), "filename": 3, "content_type": "image/png"})
        self.assertTrue(has_finding(result, "FILECAGE_INVALID_INPUT"))

    def test_missing_filename_defaults_to_file(self):
        result = validate_upload({"bytes": png(), "content_type": "image/png"})
        self.assertEqual(result.safe_filename, "file.png")

    def test_inspect_file_bytes_without_metadata(self):
        result = inspect_file_bytes(png())
        self.assertTrue(result.allowed)
        self.assertIsNone(result.safe_filename)
        self.assertEqual(result.detected_format, "png")

    def test_result_is_frozen_and_tuple_backed(self):
        result = validate(png(), "image.png", "image/png")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.allowed = False
        self.assertIsInstance(result.findings, tuple)

    def test_mapping_access_and_to_dict(self):
        result = validate(png(), "image.png", "image/png")
        self.assertTrue(result["allowed"])
        self.assertTrue(result.to_dict()["allowed"])
        self.assertIn("sha256", result.to_dict())

    def test_finding_mapping_access(self):
        result = validate(png(), "image.jpg", "image/jpeg")
        first = result.findings[0]
        self.assertEqual(first["code"], first.code)
        self.assertIn("severity", first.to_dict())

    def test_filecage_reusable_policy(self):
        cage = FileCage({"preset": "images-safe"})
        self.assertTrue(cage.validate_upload({"bytes": png(), "filename": "a.png", "content_type": "image/png"}).allowed)
        self.assertFalse(cage.validate_upload({"bytes": pdf(), "filename": "a.pdf", "content_type": "application/pdf"}).allowed)

    def test_filecage_override_does_not_mutate_base_policy(self):
        cage = FileCage({"max_bytes": 100})
        cage.validate_upload({"bytes": png(), "filename": "a.png", "content_type": "image/png"}, {"max_bytes": 10})
        self.assertEqual(cage.policy.max_bytes, 100)

    def test_finding_cap_enforced(self):
        result = validate(bytes((0x4D, 0x5A, 0x90, 0)), "../evil.png", "image/png", {"max_findings": 2})
        self.assertLessEqual(len(result.findings), 2)
        self.assertEqual(result.findings[-1].code, "FILECAGE_MAX_FINDINGS")

    def test_invalid_upload_shapes_raise(self):
        for bad in (None, "x", b"x", bytearray(b"x")):
            with self.assertRaises(FileCageError):
                validate_upload(bad)

    def test_sha256_absent_for_stream_truncation_transfer(self):
        data = b"a,b\n1,2\n"
        result = validate_upload({"bytes": data, "filename": "data.csv", "content_type": "text/csv"}, {"max_bytes": 2})
        self.assertTrue(has_finding(result, "FILECAGE_MAX_BYTES"))


if __name__ == "__main__":
    unittest.main()
