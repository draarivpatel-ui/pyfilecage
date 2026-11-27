from __future__ import annotations

import unittest

from helpers import case_methods, png
from pyfilecage import FileCageError, assert_safe_filename, sanitize_filename, validate_upload


def codes(name, options=None):
    return [item.code for item in sanitize_filename(name, options).findings]


CLEAN_NAMES = [
    "photo.png", "document.pdf", "data.csv", "archive.tar.gz", "name with spaces.jpg",
    "unicode-π-image.webp", "emoji-🙂-image.gif", "file.v2-final.png", "a.jpeg", "x.txt",
]


def _clean_body(self, name):
    report = sanitize_filename(name)
    self.assertEqual(report.filename, name)
    self.assertFalse(report.changed)
    self.assertEqual(report.findings, ())
    self.assertEqual(report.byte_length, len(name.encode("utf-8")))


@case_methods("clean_filename", [(name,) for name in CLEAN_NAMES], _clean_body)
class CleanFilenameTest(unittest.TestCase):
    pass


SEPARATOR_CASES = [
    ("../photo.png", "photo.png"), ("../../photo.png", "photo.png"), ("..\\photo.png", "photo.png"),
    ("C:\\fakepath\\photo.png", "photo.png"), ("C:/fakepath/photo.png", "photo.png"),
    ("/tmp/photo.png", "photo.png"), ("//server/share/photo.png", "photo.png"),
    ("folder/subfolder/photo.png", "photo.png"), ("folder\\subfolder\\photo.png", "photo.png"),
    ("a/b/c/", "file"), ("../", "file"), ("\\\\server\\share\\", "file"),
]


def _separator_body(self, name, expected):
    report = sanitize_filename(name)
    self.assertEqual(report.filename, expected)
    self.assertNotIn("/", report.filename)
    self.assertNotIn("\\", report.filename)
    self.assertIn("FILECAGE_FILENAME_PATH_SEPARATOR", codes(name))


@case_methods("path_separator", SEPARATOR_CASES, _separator_body)
class PathSeparatorFilenameTest(unittest.TestCase):
    pass


CONTROL_CASES = [("C0 U+{:04X}".format(value), "a" + chr(value) + "b.png") for value in range(1, 32)]
CONTROL_CASES += [("C1 U+{:04X}".format(value), "a" + chr(value) + "b.png") for value in range(0x80, 0xA0)]


def _control_filename_body(self, label, name):
    report = sanitize_filename(name)
    self.assertIn("FILECAGE_FILENAME_CONTROL", codes(name), label)
    self.assertEqual(report.filename, "ab.png", label)


@case_methods("filename_control", CONTROL_CASES, _control_filename_body)
class FilenameControlTest(unittest.TestCase):
    pass


BIDI_VALUES = list(range(0x202A, 0x202F)) + list(range(0x2066, 0x206A)) + [0x200E, 0x200F, 0x061C]
BIDI_CASES = [("bidi U+{:04X}".format(value), "a" + chr(value) + "b.png") for value in BIDI_VALUES]


def _bidi_filename_body(self, label, name):
    report = sanitize_filename(name)
    self.assertIn("FILECAGE_FILENAME_BIDI", codes(name), label)
    self.assertEqual(report.filename, "ab.png", label)


@case_methods("filename_bidi", BIDI_CASES, _bidi_filename_body)
class FilenameBidiTest(unittest.TestCase):
    def test_rtlo_extension_spoof_is_detected(self):
        name = "report\u202egnp.exe"
        report = sanitize_filename(name)
        self.assertIn("FILECAGE_FILENAME_BIDI", codes(name))
        self.assertEqual(report.filename, "reportgnp.exe")
        self.assertEqual(report.source_extension, "exe")

    def test_rtlo_double_extension_spoof_rejected_during_upload(self):
        result = validate_upload({"bytes": png(), "filename": "invoice\u202egpj.exe", "content_type": "image/png"})
        self.assertFalse(result.allowed)
        self.assertTrue(any(item.code == "FILECAGE_FILENAME_BIDI" for item in result.findings))


RESERVED_BASE = ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"]
RESERVED_CASES = [(stem,) for stem in RESERVED_BASE] + [(stem + ".txt",) for stem in RESERVED_BASE]
RESERVED_CASES += [(prefix + str(number) + ".png",) for prefix in ("COM", "LPT") for number in range(1, 10)]
RESERVED_CASES += [("com¹.txt",), ("com².txt",), ("com³.txt",), ("lpt¹.txt",), ("lpt².txt",), ("lpt³.txt",), ("cOm7.PNG",)]
RESERVED_CASES += [("CON .png",), ("con .txt",), ("LPT1 .png",), ("NUL:evil",)]


def _reserved_body(self, name):
    report = sanitize_filename(name)
    self.assertIn("FILECAGE_FILENAME_RESERVED_DEVICE", codes(name), name)
    if ":" not in name:
        self.assertTrue(report.filename.startswith("file-"), name)


@case_methods("reserved_device", RESERVED_CASES, _reserved_body)
class ReservedDeviceTest(unittest.TestCase):
    pass


TRAILING_CASES = [("name.",), ("name..",), ("name ",), ("name  ",), ("name. ",), ("name .",), ("photo.png.",), ("photo.png ",)]


def _trailing_body(self, name):
    report = sanitize_filename(name)
    self.assertIn("FILECAGE_FILENAME_TRAILING_DOTS_SPACES", codes(name), repr(name))
    self.assertFalse(report.filename.endswith((".", " ")), repr(name))


@case_methods("trailing_punctuation", TRAILING_CASES, _trailing_body)
class TrailingPunctuationTest(unittest.TestCase):
    pass


ACTIVE_FINAL_EXTENSIONS = (
    "exe dll com bat cmd scr ps1 vbs vbe js jse mjs wsf wsh jar php phtml asp aspx jsp html htm svg xml msi msp lnk reg sh command"
).split()
DOUBLE_CASES = [("invoice.pdf." + extension,) for extension in ACTIVE_FINAL_EXTENSIONS]
DOUBLE_CASES += [("invoice.pdf.exe", "invoice_pdf.exe"), ("avatar.png.php", "avatar_png.php"), ("doc.jpg.html", "doc_jpg.html"),
                 ("a.png.exe ", "a_png.exe"), ("a.png.exe.", "a_png.exe"), ("a.png .exe", "a_png.exe")]


def _double_body(self, name, expected=None):
    report = sanitize_filename(name)
    self.assertIn("FILECAGE_FILENAME_DOUBLE_EXTENSION", codes(name), name)
    self.assertNotIn(".pdf.", report.filename)
    if expected:
        self.assertEqual(report.filename, expected)


@case_methods("double_extension", DOUBLE_CASES, _double_body)
class DoubleExtensionTest(unittest.TestCase):
    pass


NON_ACTIVE_CASES = [("archive.tar.gz",), ("backup.tar.zst",), ("photo.jpeg",), ("data.json",), ("readme.txt",), ("file.v2.png",), ("a.b.txt",)]


def _non_active_body(self, name):
    self.assertNotIn("FILECAGE_FILENAME_DOUBLE_EXTENSION", codes(name), name)


@case_methods("non_active_multi_dot", NON_ACTIVE_CASES, _non_active_body)
class NonActiveMultiDotTest(unittest.TestCase):
    pass


UNSAFE_CASES = [("a" + char + "b.png", "a_b.png") for char in ('<', '>', ':', '"', '|', '?', '*')]
UNSAFE_CASES += [("a" + chr(value) + "b.png", "a_b.png") for value in (0x2044, 0x2215, 0xFF0F, 0x29F8, 0x29F6, 0xFF3C)]


def _unsafe_body(self, name, expected):
    report = sanitize_filename(name)
    self.assertIn("FILECAGE_FILENAME_UNSAFE_CHAR", codes(name), repr(name))
    self.assertEqual(report.filename, expected)


@case_methods("unsafe_character", UNSAFE_CASES, _unsafe_body)
class UnsafeCharacterTest(unittest.TestCase):
    pass


DOTFILE_CASES = [(".env",), (".htaccess",), (".gitconfig",)]


def _dotfile_body(self, name):
    report = sanitize_filename(name)
    self.assertIn("FILECAGE_FILENAME_DOT_NAME", codes(name))
    self.assertFalse(report.filename.startswith("."))
    with self.assertRaises(FileCageError) as caught:
        assert_safe_filename(name)
    self.assertEqual(caught.exception.code, "FILECAGE_FILENAME_DOT_NAME")


@case_methods("dotfile", DOTFILE_CASES, _dotfile_body)
class DotfileTest(unittest.TestCase):
    pass


HOSTILE_ASSERT_CASES = [("../photo.png",), ("CON.txt",), ("invoice.pdf.exe",), ("report\u202egnp.exe",), ("a\x00b.png",)]


def _assert_hostile_body(self, name):
    with self.assertRaises(FileCageError) as caught:
        assert_safe_filename(name)
    self.assertTrue(caught.exception.code.startswith("FILECAGE_"))


@case_methods("assert_hostile", HOSTILE_ASSERT_CASES, _assert_hostile_body)
class AssertHostileFilenameTest(unittest.TestCase):
    pass


class FilenameMiscTest(unittest.TestCase):
    def test_empty_dot_and_dotdot_rejected(self):
        for name in ("", ".", ".."):
            report = sanitize_filename(name)
            self.assertEqual(report.filename, "file")
            self.assertTrue(report.findings)
            with self.assertRaises(FileCageError):
                assert_safe_filename(name)

    def test_nul_has_own_code_and_is_removed(self):
        self.assertIn("FILECAGE_FILENAME_NUL", codes("safe\x00name.png"))
        self.assertEqual(sanitize_filename("safe\x00name.png").filename, "safename.png")

    def test_long_ascii_filename_is_capped(self):
        report = sanitize_filename("a" * 300 + ".png")
        self.assertLessEqual(report.byte_length, 255)
        self.assertTrue(report.filename.endswith(".png"))
        self.assertIn("FILECAGE_FILENAME_TOO_LONG", codes("a" * 300 + ".png"))

    def test_long_filename_truncation_deterministic(self):
        name = "a" * 300 + ".png"
        self.assertEqual(sanitize_filename(name).filename, sanitize_filename(name).filename)

    def test_truncation_does_not_split_multibyte_character(self):
        report = sanitize_filename("π" * 150 + ".png")
        self.assertLessEqual(report.byte_length, 255)
        self.assertEqual(len(report.filename.encode("utf-8")), report.byte_length)
        self.assertTrue(report.filename.endswith(".png"))

    def test_custom_byte_cap(self):
        report = sanitize_filename("a" * 100 + ".png", max_bytes=32)
        self.assertLessEqual(report.byte_length, 32)

    def test_fallback_names_are_nonempty(self):
        for name in ("\x00", "\u202e", "...", "   ", "<>*"):
            report = sanitize_filename(name)
            self.assertTrue(report.filename)
            self.assertNotIn("\x00", report.filename)

    def test_assert_safe_filename_returns_clean_report(self):
        self.assertEqual(assert_safe_filename("photo.png").filename, "photo.png")

    def test_validate_upload_rejects_traversal_by_default(self):
        result = validate_upload({"bytes": png(), "filename": "../photo.png", "content_type": "image/png"})
        self.assertFalse(result.allowed)
        self.assertTrue(any(item.code == "FILECAGE_FILENAME_PATH_SEPARATOR" and item.severity == "error" for item in result.findings))

    def test_filename_action_sanitize_downgrades_neutralized_findings(self):
        result = validate_upload({"bytes": png(), "filename": "../photo.png", "content_type": "image/png"}, {"filename_action": "sanitize"})
        self.assertTrue(result.allowed)
        self.assertEqual(result.safe_filename, "photo.png")
        self.assertTrue(any(item.code == "FILECAGE_FILENAME_PATH_SEPARATOR" and item.severity == "warning" for item in result.findings))

    def test_filename_action_sanitize_does_not_downgrade_content_spoofing(self):
        result = validate_upload({"bytes": png(), "filename": "invoice.pdf.exe", "content_type": "image/png"}, {"filename_action": "sanitize"})
        self.assertFalse(result.allowed)
        self.assertTrue(any(item.code == "FILECAGE_EXTENSION_MISMATCH" and item.severity == "error" for item in result.findings))

    def test_canonicalizes_alias_extension_case(self):
        result = validate_upload({"bytes": png(), "filename": "PHOTO.PNG", "content_type": "image/png"})
        self.assertEqual(result.safe_filename, "PHOTO.png")

    def test_report_mapping_and_immutability(self):
        report = sanitize_filename("photo.png")
        self.assertEqual(report["filename"], "photo.png")
        self.assertEqual(report["byteLength"], len("photo.png"))
        with self.assertRaises(Exception):
            report.filename = "evil.png"

    def test_arabic_letter_mark_rejected(self):
        report = sanitize_filename("a\u061cb.png")
        self.assertIn("FILECAGE_FILENAME_BIDI", [item.code for item in report.findings])
        self.assertEqual(report.filename, "ab.png")

    def test_long_extension_cannot_bypass_cap(self):
        for cap in (32, 64, 255):
            report = sanitize_filename("a." + "x" * 400, max_bytes=cap)
            self.assertLessEqual(report.byte_length, cap)
            self.assertEqual(len(report.filename.encode("utf-8")), report.byte_length)

    def test_long_multibyte_extension_cannot_split_character(self):
        report = sanitize_filename("a." + "π" * 200, max_bytes=64)
        self.assertLessEqual(report.byte_length, 64)
        self.assertEqual(len(report.filename.encode("utf-8")), report.byte_length)
        self.assertNotIn("\ufffd", report.filename)


if __name__ == "__main__":
    unittest.main()
