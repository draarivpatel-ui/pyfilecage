from __future__ import annotations

import dataclasses
import unittest

from helpers import (
    case_methods,
    ascii_bytes,
    bmp,
    central_only_zip,
    concat_bytes,
    ftyp,
    gif,
    has_finding,
    jpeg,
    png,
    tar,
    validate,
    webp_vp8,
    zip_bytes,
)
from pyfilecage import FileCageError, sniff_file_type, validate_upload


def macho(magic):
    return bytes(magic) + b"\x00\x00\x00\x00"


SIGNATURE_CASES = [
    ("PNG", png(), "image/png", "png", "image", "png", False),
    ("JPEG", jpeg(), "image/jpeg", "jpg", "image", "jpeg", False),
    ("GIF 87a", gif(1, 1, version="GIF87a"), "image/gif", "gif", "image", "gif", False),
    ("GIF 89a", gif(), "image/gif", "gif", "image", "gif", False),
    ("WebP", webp_vp8(), "image/webp", "webp", "image", "webp", False),
    ("BMP", bmp(), "image/bmp", "bmp", "image", "bmp", False),
    ("ICO", bytes((0, 0, 1, 0, 1, 0)), "image/vnd.microsoft.icon", "ico", "image", "ico", False),
    ("AVIF major brand", ftyp("avif"), "image/avif", "avif", "image", "avif", False),
    ("AVIF sequence brand", ftyp("avis"), "image/avif", "avif", "image", "avif", False),
    ("HEIF major brand", ftyp("heic"), "image/heif", "heic", "image", "heif", False),
    ("HEIF compatible brand", ftyp("isom", ["mif1"]), "image/heif", "heic", "image", "heif", False),
    ("TIFF little endian", bytes((0x49, 0x49, 0x2A, 0x00, 1)), "image/tiff", "tiff", "image", "tiff", False),
    ("TIFF big endian", bytes((0x4D, 0x4D, 0x00, 0x2A, 1)), "image/tiff", "tiff", "image", "tiff", False),
    ("PDF", ascii_bytes("%PDF-1.7\n%%EOF"), "application/pdf", "pdf", "document", "pdf", False),
    ("ZIP", zip_bytes([{"name": "a.txt", "data": "a"}]), "application/zip", "zip", "archive", "zip", False),
    ("empty ZIP end record", b"PK\x05\x06" + bytes(18), "application/zip", "zip", "archive", "zip", False),
    ("DOCX", zip_bytes([{"name": "[Content_Types].xml"}, {"name": "word/document.xml"}]), "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "docx", "document", "docx", False),
    ("XLSX", zip_bytes([{"name": "[Content_Types].xml"}, {"name": "xl/workbook.xml"}]), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "xlsx", "document", "xlsx", False),
    ("PPTX", zip_bytes([{"name": "[Content_Types].xml"}, {"name": "ppt/presentation.xml"}]), "application/vnd.openxmlformats-officedocument.presentationml.presentation", "pptx", "document", "pptx", False),
    ("DOCM with VBA project", zip_bytes([{"name": "[Content_Types].xml"}, {"name": "word/document.xml"}, {"name": "word/vbaProject.bin"}]), "application/vnd.ms-word.document.macroEnabled.12", "docm", "document", "docm", True),
    ("XLSM with VBA project", zip_bytes([{"name": "[Content_Types].xml"}, {"name": "xl/workbook.xml"}, {"name": "xl/vbaProject.bin"}]), "application/vnd.ms-excel.sheet.macroEnabled.12", "xlsm", "document", "xlsm", True),
    ("PPTM with VBA project", zip_bytes([{"name": "[Content_Types].xml"}, {"name": "ppt/presentation.xml"}, {"name": "ppt/vbaProject.bin"}]), "application/vnd.ms-powerpoint.presentation.macroEnabled.12", "pptm", "document", "pptm", True),
    ("JAR", zip_bytes([{"name": "META-INF/MANIFEST.MF", "data": "Manifest-Version: 1.0"}]), "application/java-archive", "jar", "archive", "jar", False),
    ("GZIP", bytes((0x1F, 0x8B, 8, 0)), "application/gzip", "gz", "archive", "gzip", False),
    ("ZSTD", bytes((0x28, 0xB5, 0x2F, 0xFD, 0x20)), "application/zstd", "zst", "archive", "zstd", False),
    ("TAR", tar(), "application/x-tar", "tar", "archive", "tar", False),
    ("MP3 ID3", concat_bytes(ascii_bytes("ID3"), bytes((4, 0, 0, 0, 0, 0, 0))), "audio/mpeg", "mp3", "media", "mp3", False),
    ("MP3 frame sync", bytes((0xFF, 0xFB, 0x90, 0x64, 0, 0)), "audio/mpeg", "mp3", "media", "mp3", False),
    ("MP4", ftyp("isom", ["mp42"]), "video/mp4", "mp4", "media", "mp4", False),
    ("QuickTime", ftyp("qt  "), "video/quicktime", "mov", "media", "quicktime", False),
    ("OGG", concat_bytes(ascii_bytes("OggS"), bytes(32)), "application/ogg", "ogg", "media", "ogg", False),
    ("WAV", concat_bytes(ascii_bytes("RIFF"), bytes((36, 0, 0, 0)), ascii_bytes("WAVEfmt ")), "audio/wav", "wav", "media", "wav", False),
    ("FLAC", concat_bytes(ascii_bytes("fLaC"), bytes(16)), "audio/flac", "flac", "media", "flac", False),
    ("WebM", concat_bytes(bytes((0x1A, 0x45, 0xDF, 0xA3)), ascii_bytes("webm")), "video/webm", "webm", "media", "webm", False),
    ("Matroska", concat_bytes(bytes((0x1A, 0x45, 0xDF, 0xA3)), ascii_bytes("matroska")), "video/x-matroska", "mkv", "media", "mkv", False),
    ("WASM", bytes((0, 0x61, 0x73, 0x6D, 1, 0, 0, 0)), "application/wasm", "wasm", "executable", "wasm", True),
    ("ELF", bytes((0x7F, 0x45, 0x4C, 0x46, 2, 1)), "application/x-elf", "elf", "executable", "elf", True),
    ("PE or DOS executable", bytes((0x4D, 0x5A, 0x90, 0)), "application/vnd.microsoft.portable-executable", "exe", "executable", "pe", True),
    ("Mach-O big endian 32-bit", macho((0xFE, 0xED, 0xFA, 0xCE)), "application/x-mach-binary", "macho", "executable", "macho", True),
    ("Mach-O little endian 32-bit", macho((0xCE, 0xFA, 0xED, 0xFE)), "application/x-mach-binary", "macho", "executable", "macho", True),
    ("Mach-O big endian 64-bit", macho((0xFE, 0xED, 0xFA, 0xCF)), "application/x-mach-binary", "macho", "executable", "macho", True),
    ("Mach-O little endian 64-bit", macho((0xCF, 0xFA, 0xED, 0xFE)), "application/x-mach-binary", "macho", "executable", "macho", True),
    ("Mach-O fat binary", macho((0xCA, 0xFE, 0xBA, 0xBE)), "application/x-mach-binary", "macho", "executable", "macho", True),
    ("Mach-O fat 64-bit binary", macho((0xCA, 0xFE, 0xBA, 0xBF)), "application/x-mach-binary", "macho", "executable", "macho", True),
    ("Mach-O byte-swapped fat binary", macho((0xBE, 0xBA, 0xFE, 0xCA)), "application/x-mach-binary", "macho", "executable", "macho", True),
    ("Mach-O byte-swapped fat 64-bit binary", macho((0xBF, 0xBA, 0xFE, 0xCA)), "application/x-mach-binary", "macho", "executable", "macho", True),
    ("Java class sharing CAFEBABE magic", bytes((0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52)), "application/java-class", "class", "executable", "java-class", True),
    ("shebang script", ascii_bytes("#!/bin/sh\nexit 0\n"), "application/x-shebang", "sh", "executable", "shebang", True),
    ("UTF-8 BOM before shebang", "\ufeff#!/bin/sh\nexit 0\n".encode("utf-8"), "application/x-shebang", "sh", "executable", "shebang", True),
    ("leading spaces before shebang", ascii_bytes("                                                                #!/bin/sh\nexit 0\n"), "application/x-shebang", "sh", "executable", "shebang", True),
    ("leading tabs before shebang", ascii_bytes("\t\t#!/bin/sh\nexit 0\n"), "application/x-shebang", "sh", "executable", "shebang", True),
    ("HTML document", ascii_bytes("<!doctype html><html><body>x</body></html>"), "text/html", "html", "markup", "html", False),
    ("HTML fragment", ascii_bytes("<script>alert(1)</script>"), "text/html", "html", "markup", "html", False),
    ("SVG", ascii_bytes('<svg xmlns="http://www.w3.org/2000/svg"></svg>'), "image/svg+xml", "svg", "image", "svg", False),
    ("SVG with XML declaration", ascii_bytes('<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"/>'), "image/svg+xml", "svg", "image", "svg", False),
    ("SVG with comment before root", ascii_bytes('<!--x--><svg xmlns="http://www.w3.org/2000/svg"/>'), "image/svg+xml", "svg", "image", "svg", False),
    ("SVG with doctype before root", ascii_bytes('<!DOCTYPE svg><svg xmlns="http://www.w3.org/2000/svg"/>'), "image/svg+xml", "svg", "image", "svg", False),
    ("namespaced SVG", ascii_bytes('<x:svg xmlns:x="http://www.w3.org/2000/svg"/>'), "image/svg+xml", "svg", "image", "svg", False),
    ("XML", ascii_bytes('<?xml version="1.0"?><root><a/></root>'), "application/xml", "xml", "markup", "xml", False),
    ("plain UTF-8 text", ascii_bytes("hello world\nsecond line\n"), "text/plain", "txt", "text", "text", False),
    ("JSON object", ascii_bytes('{"a": [1, true, null]}'), "application/json", "json", "data", "json", False),
    ("JSON array", ascii_bytes('[{"a": 1}]'), "application/json", "json", "data", "json", False),
    ("CSV", ascii_bytes("name,value\na,1\nb,2\n"), "text/csv", "csv", "data", "csv", False),
]


def _signature_body(self, label, data, mime, ext, kind, format_name, executable):
    result = sniff_file_type(data)
    self.assertEqual(result.mime, mime, label)
    self.assertEqual(result.ext, ext, label)
    self.assertEqual(result.kind, kind, label)
    self.assertEqual(result.format, format_name, label)
    self.assertEqual(result.executable, executable, label)
    self.assertTrue(result.confident, label)
    with self.assertRaises(dataclasses.FrozenInstanceError):
        result.mime = "text/plain"


@case_methods("signature", SIGNATURE_CASES, _signature_body)
class SignatureMatrixTest(unittest.TestCase):
    pass


class PdfAndZipStructureTest(unittest.TestCase):
    def test_pdf_offset_1(self):
        result = sniff_file_type(b"x" + ascii_bytes("%PDF-1.7\n%%EOF"))
        self.assertEqual(result.format, "pdf")
        self.assertEqual(result.offset, 1)

    def test_pdf_offset_20(self):
        result = sniff_file_type(b"x" * 20 + ascii_bytes("%PDF-1.7\n%%EOF"))
        self.assertEqual(result.format, "pdf")
        self.assertEqual(result.offset, 20)

    def test_pdf_offset_1023(self):
        result = sniff_file_type(b"x" * 1023 + ascii_bytes("%PDF-1.7\n%%EOF"))
        self.assertEqual(result.format, "pdf")
        self.assertEqual(result.offset, 1023)

    def test_pdf_offset_1024_rejected(self):
        self.assertNotEqual(sniff_file_type(b"x" * 1024 + ascii_bytes("%PDF-1.7\n%%EOF")).format, "pdf")

    def test_binary_garbage_before_pdf_header(self):
        result = sniff_file_type(bytes((0, 1, 2, 3)) + ascii_bytes("%PDF-1.7\n%%EOF"))
        self.assertEqual(result.format, "pdf")
        self.assertEqual(result.offset, 4)

    def test_vba_project_hidden_only_in_central_directory(self):
        result = sniff_file_type(central_only_zip(["[Content_Types].xml", "word/document.xml", "word/vbaProject.bin"]))
        self.assertEqual(result.format, "docm")
        self.assertTrue(result.executable)

    def test_macro_ooxml_blocked_by_default(self):
        data = zip_bytes([{"name": "[Content_Types].xml"}, {"name": "word/document.xml"}, {"name": "word/vbaProject.bin"}])
        result = validate(data, "document.docm", "application/vnd.ms-word.document.macroEnabled.12")
        self.assertFalse(result.allowed)
        self.assertTrue(has_finding(result, "FILECAGE_EXECUTABLE_TYPE"))

    def test_ooxml_detected_from_central_directory_when_local_parsing_stops(self):
        self.assertEqual(sniff_file_type(central_only_zip(["[Content_Types].xml", "word/document.xml"])).format, "docx")

    def test_central_looking_bytes_without_valid_eocd_do_not_misclassify(self):
        base = zip_bytes([{"name": "a", "data": "x"}])
        injected = base + central_only_zip(["[Content_Types].xml", "word/document.xml"])[len(base):]
        self.assertEqual(sniff_file_type(injected).format, "zip")

    def test_word_directory_without_document_xml_is_zip(self):
        data = zip_bytes([{"name": "[Content_Types].xml"}, {"name": "word/styles.xml"}])
        self.assertEqual(sniff_file_type(data).format, "zip")

    def test_xl_directory_without_workbook_xml_is_zip(self):
        data = zip_bytes([{"name": "[Content_Types].xml"}, {"name": "xl/styles.xml"}])
        self.assertEqual(sniff_file_type(data).format, "zip")

    def test_ppt_directory_without_presentation_xml_is_zip(self):
        data = zip_bytes([{"name": "[Content_Types].xml"}, {"name": "ppt/theme/theme1.xml"}])
        self.assertEqual(sniff_file_type(data).format, "zip")


class TextClassifierTest(unittest.TestCase):
    def test_random_binary_is_unknown(self):
        result = sniff_file_type(bytes((0x66, 0x00, 0x99, 0x01)))
        self.assertEqual(result.mime, "application/octet-stream")
        self.assertEqual(result.format, "unknown")
        self.assertFalse(result.confident)

    def test_empty_input_is_unknown(self):
        self.assertEqual(sniff_file_type(b"").format, "unknown")

    def test_invalid_utf8_is_not_text(self):
        self.assertEqual(sniff_file_type(bytes((0x61, 0xFF, 0x62))).format, "unknown")

    def test_nul_is_not_text(self):
        self.assertEqual(sniff_file_type(b"abc\x00def").format, "unknown")

    def test_bom_json_is_json(self):
        self.assertEqual(sniff_file_type(b"\xef\xbb\xbf" + ascii_bytes('{"a":1}')).format, "json")

    def test_malformed_json_is_not_json(self):
        self.assertNotEqual(sniff_file_type(ascii_bytes('{"a":')).format, "json")

    def test_large_malformed_json_not_classified_by_shape(self):
        malformed = '{"a":[' + '1,' * 700000 + ']}'
        self.assertNotEqual(sniff_file_type(ascii_bytes(malformed)).format, "json")

    def test_inconsistent_csv_is_text(self):
        self.assertEqual(sniff_file_type(ascii_bytes("a,b,c\n1,2\n")).format, "text")

    def test_quoted_commas_do_not_break_csv_counting(self):
        self.assertEqual(sniff_file_type(ascii_bytes('name,value\n"a,b",1\n"c,d",2\n')).format, "csv")

    def test_one_column_text_is_not_csv(self):
        self.assertEqual(sniff_file_type(ascii_bytes("alpha\nbeta\n")).format, "text")

    def test_deep_valid_json_is_bounded_but_valid(self):
        self.assertEqual(sniff_file_type(ascii_bytes("[" * 20 + "1" + "]" * 20)).format, "json")


CONTROL_CASES = [("control byte {}".format(value), bytes((65, value, 66))) for value in (1, 2, 7, 11, 12, 27, 31, 127)]


def _control_body(self, label, data):
    self.assertEqual(sniff_file_type(data).format, "unknown", label)


@case_methods("control_rejection", CONTROL_CASES, _control_body)
class ControlRejectionTest(unittest.TestCase):
    pass


JSON_CASES = [
    ("leading zero number", '{"a":01}', "text"),
    ("trailing object comma", '{"a":1,}', "text"),
    ("trailing array comma", "[1,]", "text"),
    ("unescaped control", '{"a":"x\ny"}', "text"),
    ("bad unicode escape", '{"a":"\\u12xz"}', "text"),
    ("missing exponent digits", '{"a":1e+}', "text"),
    ("duplicate-looking but valid syntax", '{"a":1,"a":2}', "json"),
    ("empty object", "{}", "json"),
    ("empty array", "[]", "json"),
    ("escaped solidus", '{"a":"\\/"}', "json"),
    ("unicode escape", '{"a":"\\u0041"}', "json"),
    ("exponent number", '{"a":-12.5e+2}', "json"),
    ("bare true is text", "true", "text"),
    ("bare number is text", "123", "text"),
]


def _json_body(self, label, text, expected):
    self.assertEqual(sniff_file_type(ascii_bytes(text)).format, expected, label)


@case_methods("json_classifier", JSON_CASES, _json_body)
class JsonClassifierTest(unittest.TestCase):
    pass


INPUT_FORM_CASES = [
    ("bytes", lambda: png()),
    ("bytearray", lambda: bytearray(png())),
    ("memoryview", lambda: memoryview(png())),
    ("memoryview slice", lambda: memoryview(b"\x09\x09" + png() + b"\x09")[2:-1]),
]


def _input_form_body(self, label, make):
    self.assertEqual(sniff_file_type(make()).format, "png", label)


@case_methods("input_form", INPUT_FORM_CASES, _input_form_body)
class InputFormTest(unittest.TestCase):
    def test_string_input_is_invalid(self):
        with self.assertRaises(FileCageError) as caught:
            sniff_file_type("not bytes")
        self.assertEqual(caught.exception.code, "FILECAGE_INVALID_INPUT")


EXECUTABLE_CASES = [
    ("ELF", bytes((0x7F, 0x45, 0x4C, 0x46, 2)), "program.elf", "application/x-elf"),
    ("PE", bytes((0x4D, 0x5A, 0x90, 0)), "program.exe", "application/vnd.microsoft.portable-executable"),
    ("Mach-O", macho((0xFE, 0xED, 0xFA, 0xCE)), "program.macho", "application/x-mach-binary"),
    ("WASM", bytes((0, 0x61, 0x73, 0x6D, 1, 0, 0, 0)), "module.wasm", "application/wasm"),
    ("shebang", ascii_bytes("#!/usr/bin/env python3\n"), "script.sh", "application/x-shebang"),
]


def _executable_blocked_body(self, label, data, filename, content_type):
    result = validate(data, filename, content_type)
    self.assertFalse(result.allowed, label)
    self.assertTrue(has_finding(result, "FILECAGE_EXECUTABLE_TYPE"), label)


@case_methods("executable_blocked", EXECUTABLE_CASES, _executable_blocked_body)
class ExecutableBlockedTest(unittest.TestCase):
    pass


def _executable_optin_body(self, label, data, filename, content_type):
    result = validate(data, filename, content_type, {"allow_executables": True})
    self.assertFalse(has_finding(result, "FILECAGE_EXECUTABLE_TYPE"), label)


@case_methods("executable_optin", EXECUTABLE_CASES, _executable_optin_body)
class ExecutableOptinTest(unittest.TestCase):
    pass


SPOOF_CASES = [
    ("PNG named as executable", png(), "avatar.exe", "application/vnd.microsoft.portable-executable", "image/png"),
    ("JPEG named as PNG", jpeg(), "photo.png", "image/png", "image/jpeg"),
    ("GIF named as JPEG", gif(), "image.jpg", "image/jpeg", "image/gif"),
    ("PDF named as text", ascii_bytes("%PDF-1.4\n%%EOF"), "notes.txt", "text/plain", "application/pdf"),
    ("plain text named as PNG", ascii_bytes("hello\nworld\n"), "picture.png", "image/png", "text/plain"),
    ("JSON named as CSV", ascii_bytes('{"a":1}'), "data.csv", "text/csv", "application/json"),
    ("CSV named as JSON", ascii_bytes("a,b\n1,2\n"), "data.json", "application/json", "text/csv"),
    ("ZIP named as image", zip_bytes([{"name": "x", "data": "y"}]), "image.png", "image/png", "application/zip"),
]


def _spoof_body(self, label, data, filename, content_type, expected_mime):
    result = validate(data, filename, content_type)
    self.assertEqual(result.detected_mime, expected_mime, label)
    self.assertTrue(has_finding(result, "FILECAGE_MIME_MISMATCH"), label)
    self.assertTrue(has_finding(result, "FILECAGE_EXTENSION_MISMATCH"), label)
    self.assertFalse(result.allowed, label)


@case_methods("metadata_spoof", SPOOF_CASES, _spoof_body)
class MetadataSpoofTest(unittest.TestCase):
    pass


class StableResultTest(unittest.TestCase):
    def test_executable_content_blocked_even_when_named_and_typed_as_png(self):
        result = validate(bytes((0x4D, 0x5A, 0x90, 0)), "avatar.png", "image/png")
        self.assertEqual(result.detected_format, "pe")
        self.assertTrue(has_finding(result, "FILECAGE_EXECUTABLE_TYPE"))
        self.assertFalse(result.allowed)

    def test_validate_upload_exposes_stable_detection_fields(self):
        data = png(2, 3)
        result = validate_upload({"bytes": data, "filename": "pixel.png", "content_type": "image/png"})
        self.assertEqual(result.detected_mime, "image/png")
        self.assertEqual(result.detected_ext, "png")
        self.assertEqual(result.detected_format, "png")
        self.assertEqual(result.kind, "image")
        self.assertEqual(result.size_bytes, len(data))
        self.assertEqual(result["detectedMime"], "image/png")

    def test_sha256_is_stable_for_known_payload(self):
        result = validate(ascii_bytes("abc"), "abc.txt", "text/plain")
        self.assertEqual(result.sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_finding_codes_use_stable_prefix(self):
        result = validate(png(), "avatar.jpg", "image/jpeg")
        self.assertTrue(all(code.startswith("FILECAGE_") for code in (item.code for item in result.findings)))



class Zip64StructureTest(unittest.TestCase):
    def test_zip64_macro_ooxml_is_detected_as_executable_docm(self):
        import io
        import zipfile
        from helpers import zip64_central_only_zip
        names = ["[Content_Types].xml", "word/document.xml", "word/vbaProject.bin"]
        data = zip64_central_only_zip(names)
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            self.assertEqual(archive.namelist(), names)
        result = sniff_file_type(data)
        self.assertEqual(result.format, "docm")
        self.assertTrue(result.executable)

    def test_zip64_nonmacro_ooxml_is_detected_as_docx(self):
        from helpers import zip64_central_only_zip
        result = sniff_file_type(zip64_central_only_zip(["[Content_Types].xml", "word/document.xml"]))
        self.assertEqual(result.format, "docx")
        self.assertFalse(result.executable)


if __name__ == "__main__":
    unittest.main()
