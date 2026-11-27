from __future__ import annotations

import unittest

from helpers import case_methods, bmp, gif, has_finding, jpeg, png, validate, webp_vp8, webp_vp8l, webp_vp8x
from pyfilecage import inspect_image_dimensions

DIMENSION_SETS = [
    (1, 1), (2, 3), (320, 200), (640, 480), (1024, 768),
    (4096, 2160), (10000, 9999), (17, 19), (255, 254), (8192, 32),
]
FORMAT_MAKERS = [
    ("png", png), ("jpeg", jpeg), ("gif", gif), ("webp lossy", webp_vp8),
    ("webp lossless", webp_vp8l), ("webp extended", webp_vp8x), ("bmp", bmp),
]
DIMENSION_CASES = [
    ("{} {}x{}".format(label, width, height), label, maker, width, height)
    for width, height in DIMENSION_SETS for label, maker in FORMAT_MAKERS
]


def _dimension_body(self, case_label, label, maker, width, height):
    result = inspect_image_dimensions(maker(width, height))
    self.assertIsNotNone(result, case_label)
    self.assertEqual(result.width, width, case_label)
    self.assertEqual(result.height, height, case_label)
    self.assertEqual(result.pixels, width * height, case_label)
    self.assertEqual(result["format"], result.format)


@case_methods("dimensions", DIMENSION_CASES, _dimension_body)
class DimensionMatrixTest(unittest.TestCase):
    pass


SOF_CASES = [("SOF marker 0x{:02X}".format(marker), marker) for marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF)]


def _sof_body(self, label, marker):
    result = inspect_image_dimensions(jpeg(17, 19, marker=marker))
    self.assertIsNotNone(result, label)
    self.assertEqual((result.width, result.height, result.pixels), (17, 19, 323), label)


@case_methods("jpeg_sof", SOF_CASES, _sof_body)
class JpegSofTest(unittest.TestCase):
    def test_app_segments_are_walked_before_sof(self):
        result = inspect_image_dimensions(jpeg(8, 9, app0=True))
        self.assertEqual((result.width, result.height), (8, 9))

    def test_ff_fill_bytes_are_skipped(self):
        result = inspect_image_dimensions(jpeg(8, 9, padding=3))
        self.assertEqual((result.width, result.height), (8, 9))

    def test_dht_jpg_and_dac_nonframe_markers_are_skipped(self):
        prefix = bytearray((0xFF, 0xD8))
        for marker in (0xC4, 0xC8, 0xCC):
            prefix += bytes((0xFF, marker, 0x00, 0x02))
        data = bytes(prefix) + jpeg(6, 7)[2:]
        self.assertEqual((inspect_image_dimensions(data).width, inspect_image_dimensions(data).height), (6, 7))

    def test_marker_walk_is_bounded_across_many_empty_segments(self):
        parts = bytearray((0xFF, 0xD8))
        for _ in range(1100):
            parts += bytes((0xFF, 0xE1, 0x00, 0x02))
        parts += bytes((0xFF, 0xD9))
        self.assertIsNone(inspect_image_dimensions(bytes(parts)))

    def test_trailing_compressed_payload_is_not_decoded(self):
        result = inspect_image_dimensions(jpeg(40, 30, trailing_fill=64))
        self.assertEqual((result.width, result.height), (40, 30))


MALFORMED_JPEGS = [
    ("zero segment length", jpeg(1, 1, length_override=0)),
    ("one byte segment length", jpeg(1, 1, length_override=1)),
    ("declared segment beyond buffer", jpeg(1, 1, length_override=100)),
    ("too short SOF segment", jpeg(1, 1, length_override=3)),
    ("truncated length field", bytes((0xFF, 0xD8, 0xFF, 0xC0, 0x00))),
    ("missing SOF before EOI", bytes((0xFF, 0xD8, 0xFF, 0xD9))),
    ("SOS before SOF", bytes((0xFF, 0xD8, 0xFF, 0xDA, 0x00, 0x02))),
    ("zero width", jpeg(0, 10)),
    ("zero height", jpeg(10, 0)),
    ("truncated file after SOI", bytes((0xFF, 0xD8))),
    ("single byte file", bytes((0xFF,))),
    ("empty file", b""),
]


def _malformed_body(self, label, data):
    self.assertIsNone(inspect_image_dimensions(data), label)


@case_methods("malformed_jpeg", MALFORMED_JPEGS, _malformed_body)
class MalformedJpegTest(unittest.TestCase):
    pass


MALFORMED_PNGS = [
    ("signature only", png(1, 1, no_ihdr=True)),
    ("missing IHDR length", b"\x89PNG\r\n\x1a\n\x00\x00"),
    ("wrong first chunk", b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\x0dIDAT"),
    ("zero width", png(0, 1)),
    ("zero height", png(1, 0)),
]


@case_methods("malformed_png", MALFORMED_PNGS, _malformed_body)
class MalformedPngTest(unittest.TestCase):
    def test_large_png_dimensions_do_not_decode_payload(self):
        result = inspect_image_dimensions(png(65535, 65535))
        self.assertEqual((result.width, result.height, result.pixels), (65535, 65535, 65535 * 65535))


def _mutate(data, index, value):
    out = bytearray(data)
    out[index] = value
    return bytes(out)


MALFORMED_WEBPS = [
    ("empty", b""),
    ("bad RIFF type", _mutate(webp_vp8(), 9, 0x58)),
    ("truncated header", webp_vp8()[:15]),
    ("bad VP8 start code", _mutate(webp_vp8(), 23, 0)),
    ("VP8 zero width", webp_vp8(0, 1)),
    ("VP8L bad signature", _mutate(webp_vp8l(), 20, 0)),
    ("VP8L truncated payload", webp_vp8l()[:23]),
    ("VP8X truncated payload", webp_vp8x()[:27]),
]


@case_methods("malformed_webp", MALFORMED_WEBPS, _malformed_body)
class MalformedWebpTest(unittest.TestCase):
    pass


BMP_EDGE_CASES = [
    ("top-down negative height", bmp(7, -11), 7, 11),
    ("core header", bmp(5, 6, core=True), 5, 6),
    ("large positive height", bmp(8, 1000), 8, 1000),
]


def _bmp_valid_body(self, label, data, width, height):
    result = inspect_image_dimensions(data)
    self.assertEqual((result.width, result.height, result.pixels), (width, height, width * height), label)


@case_methods("bmp_valid_edge", BMP_EDGE_CASES, _bmp_valid_body)
class BmpValidEdgeTest(unittest.TestCase):
    pass


BMP_INVALID_CASES = [
    ("empty", b""),
    ("zero width", bmp(0, 5)),
    ("zero height", bmp(5, 0)),
    ("negative width", bmp(0x80000001, 5)),
    ("unsupported DIB size", b"BM" + bytes(12) + (1).to_bytes(4, "little") + bytes(10)),
    ("truncated BITMAPINFOHEADER", bmp(5, 5)[:26]),
    ("int-min top-down height rejected", bmp(5, -2147483648)),
]


@case_methods("bmp_invalid", BMP_INVALID_CASES, _malformed_body)
class BmpInvalidTest(unittest.TestCase):
    pass


LIMIT_CASES = [
    ("width over cap", png(101, 2), {"max_width": 100}, "FILECAGE_MAX_WIDTH"),
    ("height over cap", png(2, 101), {"max_height": 100}, "FILECAGE_MAX_HEIGHT"),
    ("pixels over cap", png(20, 20), {"max_pixels": 399}, "FILECAGE_MAX_PIXELS"),
    ("jpeg width over cap", jpeg(101, 2), {"max_width": 100}, "FILECAGE_MAX_WIDTH"),
    ("gif height over cap", gif(2, 101), {"max_height": 100}, "FILECAGE_MAX_HEIGHT"),
    ("webp pixels over cap", webp_vp8(30, 30), {"max_pixels": 899}, "FILECAGE_MAX_PIXELS"),
    ("bmp pixels over cap", bmp(30, 30), {"max_pixels": 899}, "FILECAGE_MAX_PIXELS"),
]


def _limit_body(self, label, data, policy, code):
    result = validate(data, "image.png", "image/png", policy)
    self.assertTrue(has_finding(result, code), label)
    self.assertFalse(result.allowed, label)


@case_methods("dimension_limit", LIMIT_CASES, _limit_body)
class DimensionLimitTest(unittest.TestCase):
    def test_dimensions_exactly_at_caps_pass(self):
        result = validate(png(10, 10), "image.png", "image/png", {"max_width": 10, "max_height": 10, "max_pixels": 100})
        self.assertFalse(has_finding(result, "FILECAGE_MAX_WIDTH"))
        self.assertFalse(has_finding(result, "FILECAGE_MAX_HEIGHT"))
        self.assertFalse(has_finding(result, "FILECAGE_MAX_PIXELS"))

    def test_malformed_image_fails_closed_when_dimensions_enforced(self):
        result = validate(png(no_ihdr=True), "image.png", "image/png")
        self.assertTrue(has_finding(result, "FILECAGE_DIMENSIONS_UNREADABLE"))
        self.assertFalse(result.allowed)

    def test_malformed_image_can_skip_dimension_enforcement_only_explicitly(self):
        result = validate(png(no_ihdr=True), "image.png", "image/png", {"enforce_image_dimensions": False})
        self.assertFalse(has_finding(result, "FILECAGE_DIMENSIONS_UNREADABLE"))

    def test_default_pixel_bomb_rejection(self):
        result = validate(png(5001, 5001), "image.png", "image/png")
        self.assertTrue(has_finding(result, "FILECAGE_MAX_PIXELS"))
        self.assertFalse(result.allowed)


if __name__ == "__main__":
    unittest.main()
