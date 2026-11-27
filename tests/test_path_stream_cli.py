from __future__ import annotations

import contextlib
import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from helpers import ascii_bytes, bmp, case_methods, gif, has_finding, jpeg, png, validate, webp_vp8
from pyfilecage import FileCage, FileCageError, validate_file_obj, validate_file_path
from pyfilecage.cli import main, neutralize_terminal, parse_args


class RecordingStream:
    def __init__(self, chunks, seekable=True):
        self.chunks = list(chunks)
        self.calls = []
        self._seekable = seekable

    def read(self, size=-1):
        self.calls.append(size)
        if size is None or size < 0:
            raise AssertionError("unbounded read requested")
        if not self.chunks:
            return b""
        return self.chunks.pop(0)

    def seekable(self):
        return self._seekable


class ValidateFileObjTest(unittest.TestCase):
    def test_bytesio_png_passes(self):
        result = validate_file_obj(io.BytesIO(png()), filename="image.png", content_type="image/png")
        self.assertTrue(result.allowed)
        self.assertEqual(result.detected_format, "png")

    def test_read_sizes_are_always_bounded(self):
        stream = RecordingStream([png()[:10], png()[10:], b""])
        validate_file_obj(stream, filename="image.png", content_type="image/png", policy={"max_bytes": 1000})
        self.assertTrue(stream.calls)
        self.assertTrue(all(size == 1001 or (isinstance(size, int) and 0 < size <= 1001) for size in stream.calls))

    def test_no_unbounded_read_is_requested(self):
        stream = RecordingStream([png(), b""])
        validate_file_obj(stream, filename="image.png", content_type="image/png")
        self.assertNotIn(-1, stream.calls)
        self.assertNotIn(None, stream.calls)

    def test_stream_larger_than_cap_is_rejected(self):
        data = png() + b"x" * 200
        result = validate_file_obj(io.BytesIO(data), filename="image.png", content_type="image/png", policy={"max_bytes": len(png())})
        self.assertTrue(has_finding(result, "FILECAGE_MAX_BYTES"))
        self.assertIsNone(result.sha256)

    def test_exact_cap_stream_passes_size_check(self):
        data = png()
        result = validate_file_obj(io.BytesIO(data), filename="image.png", content_type="image/png", policy={"max_bytes": len(data)})
        self.assertFalse(has_finding(result, "FILECAGE_MAX_BYTES"))

    def test_oversized_chunk_is_truncated_to_remaining_cap(self):
        data = png() + b"extra"
        stream = RecordingStream([data])
        result = validate_file_obj(stream, filename="image.png", content_type="image/png", policy={"max_bytes": len(png())})
        self.assertTrue(has_finding(result, "FILECAGE_MAX_BYTES"))

    def test_text_stream_fails_as_io_error(self):
        result = validate_file_obj(io.StringIO("hello"), filename="a.txt", content_type="text/plain")
        self.assertTrue(has_finding(result, "FILECAGE_IO_ERROR"))

    def test_nonbytes_chunk_fails_as_io_error(self):
        result = validate_file_obj(RecordingStream([object()]), filename="a.bin", content_type="application/octet-stream")
        self.assertTrue(has_finding(result, "FILECAGE_IO_ERROR"))

    def test_none_chunk_terminates_read_cleanly(self):
        result = validate_file_obj(RecordingStream([png(), None]), filename="image.png", content_type="image/png")
        self.assertTrue(result.allowed)

    def test_nonseekable_stream_is_supported(self):
        result = validate_file_obj(RecordingStream([png(), b""], seekable=False), filename="image.png", content_type="image/png")
        self.assertTrue(result.allowed)

    def test_stream_without_read_raises_invalid_input(self):
        with self.assertRaises(FileCageError) as caught:
            validate_file_obj(object(), filename="a.bin")
        self.assertEqual(caught.exception.code, "FILECAGE_INVALID_INPUT")

    def test_filecage_stream_method(self):
        cage = FileCage({"preset": "images-safe"})
        self.assertTrue(cage.validate_file_obj(io.BytesIO(png()), filename="a.png", content_type="image/png").allowed)


class PathValidationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, data, mode=None):
        path = self.root / name
        path.write_bytes(data)
        if mode is not None:
            path.chmod(mode)
        return path

    def test_regular_png_path_passes(self):
        result = validate_file_path(self.write("image.png", png()))
        self.assertTrue(result.allowed, [item.to_dict() for item in result.findings])
        self.assertEqual(result.detected_format, "png")

    def test_pathlike_object_supported(self):
        result = validate_file_path(self.write("image.png", png()))
        self.assertTrue(result.allowed)

    def test_string_path_supported(self):
        result = validate_file_path(str(self.write("image.png", png())))
        self.assertTrue(result.allowed)

    def test_executable_mode_rejected(self):
        path = self.write("image.png", png(), 0o755)
        result = validate_file_path(path)
        self.assertTrue(has_finding(result, "FILECAGE_EXECUTABLE_TYPE"))
        self.assertFalse(result.allowed)

    def test_nonexecutable_mode_passes_mode_check(self):
        path = self.write("image.png", png(), 0o644)
        result = validate_file_path(path)
        self.assertFalse(any(getattr(item, "actual", None) == "executable-mode" for item in result.findings))

    def test_symlink_rejected(self):
        target = self.write("target.png", png())
        link = self.root / "link.png"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        result = validate_file_path(link)
        self.assertTrue(has_finding(result, "FILECAGE_PATH_SYMLINK"))
        self.assertFalse(result.allowed)

    def test_fifo_rejected(self):
        fifo = self.root / "pipe.png"
        try:
            os.mkfifo(str(fifo))
        except (OSError, AttributeError):
            self.skipTest("FIFO unavailable")
        result = validate_file_path(fifo)
        self.assertTrue(has_finding(result, "FILECAGE_PATH_NOT_REGULAR"))

    def test_directory_rejected(self):
        result = validate_file_path(self.root)
        self.assertTrue(has_finding(result, "FILECAGE_PATH_NOT_REGULAR"))

    def test_nonexistent_path_is_io_failure(self):
        result = validate_file_path(self.root / "missing.png")
        self.assertTrue(has_finding(result, "FILECAGE_PATH_IO_ERROR"))

    def test_nul_path_is_unsafe_failure_not_crash(self):
        result = validate_file_path("bad\x00path.png")
        self.assertTrue(has_finding(result, "FILECAGE_PATH_UNSAFE"))

    def test_empty_path_raises_invalid_input(self):
        with self.assertRaises(FileCageError):
            validate_file_path("")

    def test_precheck_large_file_is_not_read_into_memory(self):
        path = self.write("large.bin", b"x" * 128)
        result = validate_file_path(path, {"max_bytes": 64})
        self.assertTrue(has_finding(result, "FILECAGE_PATH_TOO_LARGE"))
        self.assertTrue(has_finding(result, "FILECAGE_MAX_BYTES"))

    def test_path_basename_is_used_for_safe_filename(self):
        result = validate_file_path(self.write("photo.PNG", png()))
        self.assertEqual(result.safe_filename, "photo.png")

    def test_path_validation_can_use_preset(self):
        result = validate_file_path(self.write("image.png", png()), {"preset": "images-safe"})
        self.assertTrue(result.allowed)

    def test_filecage_path_method(self):
        cage = FileCage({"preset": "images-safe"})
        self.assertTrue(cage.validate_file_path(self.write("image.png", png())).allowed)


PATH_PASS_CASES = [
    ("PNG", "image.png", png()),
    ("JPEG", "photo.jpg", jpeg()),
    ("GIF", "image.gif", gif()),
    ("WebP", "image.webp", webp_vp8()),
    ("BMP", "image.bmp", bmp()),
    ("text", "notes.txt", ascii_bytes("hello\n")),
]


def _path_pass_body(self, label, name, data):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / name
        path.write_bytes(data)
        result = validate_file_path(path)
        self.assertTrue(result.allowed, label + ": " + repr([item.to_dict() for item in result.findings]))


@case_methods("path_pass", PATH_PASS_CASES, _path_pass_body)
class PathPassMatrixTest(unittest.TestCase):
    pass


class CliTest(unittest.TestCase):
    def run_cli(self, argv):
        out = io.StringIO()
        err = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue(), err.getvalue()

    def write_temp(self, name, data):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / name
        path.write_bytes(data)
        return path

    def test_help_exit_zero(self):
        code, out, err = self.run_cli(["--help"])
        self.assertEqual(code, 0)
        self.assertIn("Usage:", out)
        self.assertEqual(err, "")

    def test_version_exit_zero(self):
        code, out, err = self.run_cli(["--version"])
        self.assertEqual((code, out.strip(), err), (0, "1.0.0", ""))

    def test_valid_png_exit_zero(self):
        path = self.write_temp("image.png", png())
        code, out, err = self.run_cli(["inspect", str(path)])
        self.assertEqual(code, 0)
        self.assertIn("safe", out)
        self.assertIn("findings: none", out)

    def test_valid_png_json_exit_zero(self):
        path = self.write_temp("image.png", png())
        code, out, err = self.run_cli(["inspect", str(path), "--json"])
        self.assertEqual(code, 0)
        parsed = json.loads(out)
        self.assertTrue(parsed["allowed"])
        self.assertEqual(parsed["detected_format"], "png")

    def test_executable_file_exit_one(self):
        path = self.write_temp("program.exe", b"MZ\x90\x00")
        code, out, err = self.run_cli(["inspect", str(path)])
        self.assertEqual(code, 1)
        self.assertIn("FILECAGE_EXECUTABLE_TYPE", out)

    def test_nonexistent_file_exit_two(self):
        code, out, err = self.run_cli(["inspect", "/definitely/missing/file.png"])
        self.assertEqual(code, 2)
        self.assertIn("FILECAGE_PATH_IO_ERROR", out)

    def test_allow_option_can_permit_type(self):
        path = self.write_temp("image.png", png())
        code, out, err = self.run_cli(["inspect", str(path), "--allow", "image/png"])
        self.assertEqual(code, 0)

    def test_allow_option_can_deny_type(self):
        path = self.write_temp("image.png", png())
        code, out, err = self.run_cli(["inspect", str(path), "--allow", "image/jpeg"])
        self.assertEqual(code, 1)
        self.assertIn("FILECAGE_TYPE_NOT_ALLOWED", out)

    def test_preset_images_safe(self):
        path = self.write_temp("image.png", png())
        self.assertEqual(self.run_cli(["inspect", str(path), "--preset", "images-safe"])[0], 0)

    def test_max_bytes_rejection(self):
        path = self.write_temp("image.png", png())
        code, out, err = self.run_cli(["inspect", str(path), "--max-bytes", "5"])
        self.assertEqual(code, 1)
        self.assertIn("FILECAGE_MAX_BYTES", out)

    def test_max_pixels_rejection(self):
        path = self.write_temp("image.png", png(10, 10))
        code, out, err = self.run_cli(["inspect", str(path), "--max-pixels", "99"])
        self.assertEqual(code, 1)
        self.assertIn("FILECAGE_MAX_PIXELS", out)

    def test_rtlo_neutralized_in_text_output(self):
        path = self.write_temp("report\u202egnp.png", png())
        code, out, err = self.run_cli(["inspect", str(path)])
        self.assertNotIn("\u202e", out + err)

    def test_ansi_neutralized_in_text_output(self):
        path = self.write_temp("bad\x1b[31m.png", png())
        code, out, err = self.run_cli(["inspect", str(path)])
        self.assertNotIn("\x1b", out + err)

    def test_neutralize_terminal_removes_controls(self):
        source = "a\x00\x1b[31m\u202e\u061c b"
        cleaned = neutralize_terminal(source)
        for char in ("\x00", "\x1b", "\u202e", "\u061c"):
            self.assertNotIn(char, cleaned)
        self.assertIn("a", cleaned)
        self.assertIn("b", cleaned)


CLI_ERROR_CASES = [
    ("no arguments", []),
    ("unknown command", ["scan"]),
    ("inspect missing file", ["inspect"]),
    ("unknown option", ["inspect", "x", "--bogus"]),
    ("two files", ["inspect", "a", "b"]),
    ("allow missing value", ["inspect", "x", "--allow"]),
    ("preset missing value", ["inspect", "x", "--preset"]),
    ("max bytes missing value", ["inspect", "x", "--max-bytes"]),
    ("max pixels missing value", ["inspect", "x", "--max-pixels"]),
    ("zero max bytes", ["inspect", "x", "--max-bytes", "0"]),
    ("negative max bytes", ["inspect", "x", "--max-bytes", "-1"]),
    ("decimal max bytes", ["inspect", "x", "--max-bytes", "1.5"]),
    ("zero max pixels", ["inspect", "x", "--max-pixels", "0"]),
]


def _cli_error_body(self, label, argv):
    out = io.StringIO()
    err = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    self.assertEqual(code, 2, label)
    self.assertIn("pyfilecage:", err.getvalue(), label)


@case_methods("cli_error", CLI_ERROR_CASES, _cli_error_body)
class CliErrorMatrixTest(unittest.TestCase):
    pass


PARSE_CASES = [
    ("file only", ["inspect", "x"], {"file": "x"}),
    ("json", ["inspect", "x", "--json"], {"json": True}),
    ("single allow", ["inspect", "x", "--allow", "image/png"], {"allow": ["image/png"]}),
    ("comma allow", ["inspect", "x", "--allow", "image/png,image/jpeg"], {"allow": ["image/png", "image/jpeg"]}),
    ("spaced comma allow", ["inspect", "x", "--allow", "image/png, image/jpeg"], {"allow": ["image/png", "image/jpeg"]}),
    ("preset", ["inspect", "x", "--preset", "images-safe"], {"preset": "images-safe"}),
    ("max bytes", ["inspect", "x", "--max-bytes", "12"], {"max_bytes": 12}),
    ("max pixels", ["inspect", "x", "--max-pixels", "12"], {"max_pixels": 12}),
]


def _parse_body(self, label, argv, expected):
    parsed = parse_args(argv)
    for key, value in expected.items():
        self.assertEqual(parsed[key], value, label)


@case_methods("parse_args", PARSE_CASES, _parse_body)
class ParseArgsMatrixTest(unittest.TestCase):
    pass



class HostileStreamFailureTest(unittest.TestCase):
    def test_runtime_error_from_stream_fails_closed_as_io_error(self):
        class EvilStream:
            def read(self, size):
                raise RuntimeError("hostile stream failure")
        result = validate_file_obj(EvilStream(), filename="image.png", content_type="image/png")
        self.assertFalse(result.allowed)
        self.assertTrue(has_finding(result, "FILECAGE_IO_ERROR"))


if __name__ == "__main__":
    unittest.main()
