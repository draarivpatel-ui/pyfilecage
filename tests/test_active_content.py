from __future__ import annotations

import unittest
import zlib

from helpers import (
    ascii_bytes, bmp, case_methods, compressed_object_stream_pdf, compressed_text_png,
    concat_bytes, gif, jpeg, pdf, png, svg, validate, webp_vp8, has_finding,
)
from pyfilecage import validate_upload


def validate_svg(data, policy=None):
    merged = {"allow_svg": True}
    if policy:
        merged.update(policy)
    return validate_upload({"bytes": data, "filename": "image.svg", "content_type": "image/svg+xml"}, merged)


SVG_SCRIPT_CASES = [
    ("lowercase script", "<script>alert(1)</script>"),
    ("uppercase script", "<SCRIPT>alert(1)</SCRIPT>"),
    ("mixed-case script", "<sCrIpT>alert(1)</sCrIpT>"),
    ("namespaced script", '<x:script xmlns:x="http://www.w3.org/1999/xhtml">alert(1)</x:script>'),
    ("whitespace after bracket", "< script>alert(1)</script>"),
]


def _svg_active_body(self, label, body):
    result = validate_svg(svg(body))
    self.assertFalse(result.allowed, label)
    self.assertTrue(has_finding(result, "FILECAGE_SVG_ACTIVE_CONTENT"), label)


@case_methods("svg_script", SVG_SCRIPT_CASES, _svg_active_body)
class SvgScriptTest(unittest.TestCase):
    pass


SVG_EVENT_CASES = [(attribute,) for attribute in ("onload", "onclick", "onerror", "onbegin", "onrepeat", "onfocusin", "ONLOAD", "onload ")]


def _svg_event_body(self, attribute):
    result = validate_svg(svg("<rect " + attribute + '="alert(1)"/>'))
    self.assertFalse(result.allowed, attribute)
    self.assertTrue(any(item.code == "FILECAGE_SVG_ACTIVE_CONTENT" and getattr(item, "pattern", None) == "event-handler" for item in result.findings), attribute)


@case_methods("svg_event", SVG_EVENT_CASES, _svg_event_body)
class SvgEventTest(unittest.TestCase):
    pass


SVG_HREF_CASES = [
    ("javascript href", "javascript:alert(1)"),
    ("uppercase javascript href", "JaVaScRiPt:alert(1)"),
    ("whitespace-obfuscated javascript href", "java\nscript:alert(1)"),
    ("numeric entity javascript href", "java&#x73;cript:alert(1)"),
    ("decimal entity javascript href", "java&#115;cript:alert(1)"),
    ("data href", "data:text/html;base64,PHNjcmlwdD4="),
    ("single quoted javascript href", "javascript:alert(1)"),
]


def _svg_href_body(self, label, href):
    quote = "'" if label.startswith("single") else '"'
    result = validate_svg(svg("<a href=" + quote + href + quote + "><text>x</text></a>"))
    self.assertFalse(result.allowed, label)
    self.assertTrue(any(getattr(item, "pattern", "").endswith("-href") for item in result.findings), label)


@case_methods("svg_active_href", SVG_HREF_CASES, _svg_href_body)
class SvgHrefTest(unittest.TestCase):
    pass


SVG_REMOTE_USE_CASES = [
    ("http use href", 'href="http://example.invalid/a.svg#x"'),
    ("https use href", 'href="https://example.invalid/a.svg#x"'),
    ("protocol-relative use href", 'href="//example.invalid/a.svg#x"'),
    ("xlink use href", 'xlink:href="https://example.invalid/a.svg#x"'),
]


def _svg_remote_use_body(self, label, attribute):
    result = validate_svg(svg("<use " + attribute + "/>"))
    self.assertFalse(result.allowed, label)
    self.assertTrue(any(getattr(item, "pattern", None) == "remote-use" for item in result.findings), label)


@case_methods("svg_remote_use", SVG_REMOTE_USE_CASES, _svg_remote_use_body)
class SvgRemoteUseTest(unittest.TestCase):
    pass


SVG_ANIMATION_CASES = [
    ("set element", '<set attributeName="href" to="javascript:alert(1)"/>'),
    ("animate element", '<animate attributeName="xlink:href" values="none;javascript:alert(1)"/>'),
    ("entity-encoded set value", '<set attributeName="href" to="java&#x73;cript:alert(1)"/>'),
    ("animateTransform href", '<animateTransform attributeName="href" to="data:text/html,x"/>'),
]


@case_methods("svg_animation_href", SVG_ANIMATION_CASES, _svg_active_body)
class SvgAnimationHrefTest(unittest.TestCase):
    pass


SVG_REMOTE_RESOURCE_CASES = [
    ("remote image", '<image href="https://example.invalid/pixel.png"/>', "remote-image"),
    ("remote feImage", '<feImage href="https://example.invalid/pixel.png"/>', "remote-feimage"),
    ("raw greater-than in URL", '<use href="https://example.invalid/a>b"/>', "remote-use"),
    ("entity greater-than in URL", '<use href="https://example.invalid/a&gt;b"/>', "remote-use"),
]


def _svg_remote_resource_body(self, label, element, pattern):
    result = validate_svg(svg(element))
    self.assertFalse(result.allowed, label)
    self.assertTrue(any(getattr(item, "pattern", None) == pattern for item in result.findings), label)


@case_methods("svg_remote_resource", SVG_REMOTE_RESOURCE_CASES, _svg_remote_resource_body)
class SvgRemoteResourceTest(unittest.TestCase):
    pass


SVG_CSS_CASES = [
    ("stylesheet import", "@import url(https://example.invalid/a.css)"),
    ("CSS-escaped import", "@im\\70 ort url(https://example.invalid/a.css)"),
    ("external CSS url", "rect { fill: url(https://example.invalid/a.png) }"),
    ("CSS-escaped external url", "rect { fill: u\\72 l(https://example.invalid/a.png) }"),
    ("javascript CSS url", "rect { fill: url(javascript:alert(1)) }"),
    ("data CSS url", "rect { fill: url(data:image/png;base64,x) }"),
]


def _svg_css_body(self, label, css):
    result = validate_svg(svg("<style>" + css + "</style>"))
    self.assertFalse(result.allowed, label)
    self.assertTrue(any(getattr(item, "pattern", None) in ("css-import", "css-external-url") for item in result.findings), label)


@case_methods("svg_css_network", SVG_CSS_CASES, _svg_css_body)
class SvgCssNetworkTest(unittest.TestCase):
    pass


class SvgTargetedTest(unittest.TestCase):
    def test_foreignobject_rejected(self):
        result = validate_svg(svg('<foreignObject><div xmlns="http://www.w3.org/1999/xhtml">x</div></foreignObject>'))
        self.assertTrue(any(getattr(item, "pattern", None) == "foreignObject" for item in result.findings))

    def test_mixed_case_foreignobject_rejected(self):
        self.assertTrue(has_finding(validate_svg(svg("<foreignobject><div>x</div></foreignobject>")), "FILECAGE_SVG_ACTIVE_CONTENT"))

    def test_doctype_rejected_as_xxe(self):
        result = validate_svg(ascii_bytes('<!DOCTYPE svg><svg xmlns="http://www.w3.org/2000/svg"/>'))
        self.assertTrue(any(item.code == "FILECAGE_SVG_XXE" and getattr(item, "pattern", None) == "doctype" for item in result.findings))

    def test_entity_rejected_as_xxe(self):
        data = ascii_bytes('<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>')
        result = validate_svg(data)
        self.assertTrue(any(item.code == "FILECAGE_SVG_XXE" and getattr(item, "pattern", None) == "entity" for item in result.findings))

    def test_local_fragment_use_can_pass(self):
        self.assertTrue(validate_svg(svg('<use href="#shape"/>')).allowed)

    def test_clean_svg_passes_after_optin(self):
        self.assertTrue(validate_svg(svg('<circle cx="5" cy="5" r="4"/>')).allowed)

    def test_clean_svg_blocked_without_optin(self):
        self.assertTrue(has_finding(validate(svg(), "image.svg", "image/svg+xml"), "FILECAGE_SVG_NOT_ALLOWED"))

    def test_slash_separated_event_attribute_rejected(self):
        result = validate_svg(ascii_bytes("<svg/onload=alert(1)>") )
        self.assertTrue(any(getattr(item, "pattern", None) == "event-handler" for item in result.findings))

    def test_xml_stylesheet_processing_instruction_rejected(self):
        result = validate_svg(ascii_bytes('<?xml-stylesheet href="style.xsl"?><svg xmlns="http://www.w3.org/2000/svg"/>'))
        self.assertTrue(any(getattr(item, "pattern", None) == "xml-stylesheet" for item in result.findings))

    def test_entity_encoded_script_text_is_inert_control(self):
        result = validate_svg(svg("<text>&lt;script&gt; example</text>"))
        self.assertTrue(result.allowed, [item.to_dict() for item in result.findings])

    def test_local_css_fragment_does_not_false_positive(self):
        result = validate_svg(svg('<style>rect { fill: url(#gradient) }</style><use href="#shape"/>'))
        self.assertTrue(result.allowed, [item.to_dict() for item in result.findings])

    def test_invalid_utf8_svg_fails_closed(self):
        result = validate_svg(b"<svg\xff")
        self.assertFalse(result.allowed)
        self.assertTrue(has_finding(result, "FILECAGE_UNRECOGNIZED_TYPE") or has_finding(result, "FILECAGE_INVALID_UTF8"))


def validate_pdf(data, policy=None):
    return validate_upload({"bytes": data, "filename": "document.pdf", "content_type": "application/pdf"}, policy)


PDF_NAME_CASES = [("JavaScript",), ("JS",), ("Launch",), ("OpenAction",), ("AA",), ("EmbeddedFile",), ("EmbeddedFiles",), ("URI",)]


def _pdf_name_body(self, name):
    result = validate_pdf(pdf("2 0 obj << /" + name + " true >> endobj"))
    self.assertFalse(result.allowed, name)
    self.assertTrue(any(item.code == "FILECAGE_PDF_ACTIVE_CONTENT" and getattr(item, "token", None) == "/" + name.upper() for item in result.findings), name)


@case_methods("pdf_active_name", PDF_NAME_CASES, _pdf_name_body)
class PdfActiveNameTest(unittest.TestCase):
    pass


class PdfTargetedTest(unittest.TestCase):
    def test_hex_escaped_javascript_name(self):
        result = validate_pdf(pdf("2 0 obj << /J#61vaScript true >> endobj"))
        self.assertTrue(any(getattr(item, "token", None) == "/JAVASCRIPT" for item in result.findings))

    def test_hex_escaped_embeddedfiles_name(self):
        result = validate_pdf(pdf("2 0 obj << /EmbeddedF#69les true >> endobj"))
        self.assertTrue(any(getattr(item, "token", None) == "/EMBEDDEDFILES" for item in result.findings))

    def test_uri_can_be_explicitly_tolerated(self):
        result = validate_pdf(pdf("2 0 obj << /URI (https://example.invalid/) >> endobj"), {"allow_pdf_uri": True})
        self.assertFalse(any(getattr(item, "token", None) == "/URI" for item in result.findings))

    def test_clean_pdf_passes(self):
        self.assertTrue(validate_pdf(pdf()).allowed)

    def test_compressed_object_stream_javascript(self):
        result = validate_pdf(compressed_object_stream_pdf("/Type /OpenAction /S /JavaScript /JS (alert(1))"))
        self.assertTrue(any(getattr(item, "token", None) == "/JAVASCRIPT" for item in result.findings))

    def test_compressed_object_stream_launch(self):
        result = validate_pdf(compressed_object_stream_pdf("/Type /Action /S /Launch"))
        self.assertTrue(any(getattr(item, "token", None) == "/LAUNCH" for item in result.findings))

    def test_malformed_compressed_object_stream_fails_closed(self):
        result = validate_pdf(compressed_object_stream_pdf("/Type /OpenAction", compressed=False))
        self.assertTrue(has_finding(result, "FILECAGE_PDF_SCAN_LIMIT"))

    def test_offset_pdf_active_names_are_scanned(self):
        result = validate_pdf(ascii_bytes("leading garbage\n") + pdf("2 0 obj << /JavaScript true >> endobj"))
        self.assertTrue(any(getattr(item, "token", None) == "/JAVASCRIPT" for item in result.findings))


ZIP_LOCAL = ascii_bytes("PK\x03\x04payload")
ZIP_END = b"PK\x05\x06" + bytes(18)
POLYGLOT_FORMATS = [
    ("PNG", lambda: png(1, 1), "image.png", "image/png"),
    ("JPEG", lambda: jpeg(1, 1), "image.jpg", "image/jpeg"),
    ("GIF", lambda: gif(1, 1), "image.gif", "image/gif"),
    ("WebP", lambda: webp_vp8(1, 1), "image.webp", "image/webp"),
    ("BMP", lambda: bmp(1, 1), "image.bmp", "image/bmp"),
]
POLYGLOT_CASES = []
for label, maker, filename, mime in POLYGLOT_FORMATS:
    POLYGLOT_CASES.append((label + " local header", maker, ZIP_LOCAL, filename, mime))
    POLYGLOT_CASES.append((label + " end record", maker, ZIP_END, filename, mime))


def _polyglot_body(self, label, maker, trailer, filename, mime):
    result = validate(concat_bytes(maker(), trailer), filename, mime)
    self.assertFalse(result.allowed, label)
    self.assertTrue(has_finding(result, "FILECAGE_POLYGLOT"), label)


@case_methods("image_polyglot", POLYGLOT_CASES, _polyglot_body)
class ImagePolyglotTest(unittest.TestCase):
    pass


class PolyglotTargetedTest(unittest.TestCase):
    def test_gifar_style_trailer_rejected(self):
        result = validate(concat_bytes(gif(), ascii_bytes("PK\x03\x04META-INF/MANIFEST.MF")), "avatar.gif", "image/gif")
        self.assertTrue(has_finding(result, "FILECAGE_POLYGLOT"))

    def test_png_nonzip_trailing_data_rejected(self):
        result = validate(png(trailing=ascii_bytes("extra")), "image.png", "image/png")
        self.assertTrue(has_finding(result, "FILECAGE_TRAILING_DATA"))
        self.assertFalse(has_finding(result, "FILECAGE_POLYGLOT"))

    def test_clean_png_no_polyglot_or_trailing_findings(self):
        result = validate(png(), "image.png", "image/png")
        self.assertFalse(has_finding(result, "FILECAGE_POLYGLOT"))
        self.assertFalse(has_finding(result, "FILECAGE_TRAILING_DATA"))
        self.assertTrue(result.allowed)

    def test_polyglot_scanning_requires_explicit_disable(self):
        result = validate(concat_bytes(jpeg(), ZIP_LOCAL), "photo.jpg", "image/jpeg", {"scan_polyglots": False})
        self.assertFalse(has_finding(result, "FILECAGE_POLYGLOT"))


GENERIC_PAYLOAD_CASES = [
    ("script tag", "<script>alert(1)</script>", "script-tag"),
    ("HTML doctype", "<!DOCTYPE html><html></html>", "html-doctype"),
    ("iframe", '<iframe src="https://example.invalid"></iframe>', "iframe"),
    ("object", '<object data="x"></object>', "object"),
    ("embed", '<embed src="x">', "embed"),
    ("embedded SVG", "<svg><script>x</script></svg>", "svg"),
    ("PHP tag", "<?php system($_GET[1]); ?>", "php-tag"),
    ("PHP short echo", "<?= system($_GET[1]) ?>", "php-short-echo"),
    ("ASP tag", "<% eval request %>", "asp-tag"),
]


def _generic_payload_body(self, label, payload, pattern):
    result = validate(ascii_bytes("prefix text\n" + payload + "\nsuffix text\n"), "notes.txt", "text/plain")
    self.assertFalse(result.allowed, label)
    self.assertTrue(any(item.code == "FILECAGE_ACTIVE_CONTENT" and getattr(item, "pattern", None) == pattern for item in result.findings), label)


@case_methods("generic_active_payload", GENERIC_PAYLOAD_CASES, _generic_payload_body)
class GenericActivePayloadTest(unittest.TestCase):
    pass


PNG_APPENDED_CASES = [
    ("script", "<script>alert(1)</script>"),
    ("php", "<?php echo 1; ?>"),
    ("asp", "<% response.write 1 %>"),
    ("svg", "<svg><script>x</script></svg>"),
]


def _png_appended_body(self, label, payload):
    result = validate(png(trailing=ascii_bytes(payload)), "image.png", "image/png")
    self.assertFalse(result.allowed, label)
    self.assertTrue(has_finding(result, "FILECAGE_ACTIVE_CONTENT"), label)


@case_methods("png_appended_active", PNG_APPENDED_CASES, _png_appended_body)
class PngAppendedActiveTest(unittest.TestCase):
    pass


class ScanningPolicyTest(unittest.TestCase):
    def test_active_content_scanning_requires_explicit_disable(self):
        result = validate(ascii_bytes("text\n<?php echo 1; ?>\n"), "notes.txt", "text/plain", {"scan_active_content": False})
        self.assertFalse(has_finding(result, "FILECAGE_ACTIVE_CONTENT"))

    def test_html_script_rejected_even_when_markup_allowed(self):
        result = validate(ascii_bytes("<html><body><script>alert(1)</script></body></html>"), "page.html", "text/html", {"allow_markup": True})
        self.assertTrue(has_finding(result, "FILECAGE_ACTIVE_CONTENT"))

    def test_inert_html_can_pass_when_markup_allowed(self):
        self.assertTrue(validate(ascii_bytes("<html><body><p>hello</p></body></html>"), "page.html", "text/html", {"allow_markup": True}).allowed)

    def test_html_inline_svg_rejected(self):
        result = validate(ascii_bytes('<html><body><svg onload="alert(1)"></svg></body></html>'), "page.html", "text/html", {"allow_markup": True})
        self.assertTrue(any(getattr(item, "pattern", None) == "svg" for item in result.findings))

    def test_compressed_ztxt_payload_rejected(self):
        result = validate(compressed_text_png("zTXt"), "image.png", "image/png")
        self.assertTrue(any(item.code == "FILECAGE_ACTIVE_CONTENT" and getattr(item, "pattern", None) == "script-tag" for item in result.findings))

    def test_compressed_itxt_payload_rejected(self):
        result = validate(compressed_text_png("iTXt"), "image.png", "image/png")
        self.assertTrue(any(item.code == "FILECAGE_ACTIVE_CONTENT" and getattr(item, "pattern", None) == "script-tag" for item in result.findings))

    def test_inert_compressed_ztxt_control_passes(self):
        result = validate(compressed_text_png("zTXt", "ordinary metadata"), "image.png", "image/png")
        self.assertTrue(result.allowed, [item.to_dict() for item in result.findings])

    def test_compressed_png_text_inflate_is_capped(self):
        payload = zlib.compress(b"A" * (2 * 1024 * 1024))
        from helpers import insert_before_png_iend, png_chunk
        data = insert_before_png_iend(png(), png_chunk("zTXt", b"comment\x00\x00" + payload))
        result = validate(data, "image.png", "image/png")
        self.assertFalse(any(getattr(item, "pattern", None) == "script-tag" for item in result.findings))



class ProcessingInstructionSvgTest(unittest.TestCase):
    def test_namespaced_svg_after_processing_instruction_is_not_plain_text(self):
        from pyfilecage import inspect_file_bytes, sniff_file_type
        data = ascii_bytes('<?pi version="1"?><x:svg xmlns:x="http://www.w3.org/2000/svg"><x:script>alert(1)</x:script></x:svg>')
        self.assertEqual(sniff_file_type(data).format, "svg")
        result = inspect_file_bytes(data)
        self.assertFalse(result.allowed)
        self.assertTrue(has_finding(result, "FILECAGE_SVG_ACTIVE_CONTENT"))

    def test_remote_namespaced_svg_after_processing_instruction_is_scanned(self):
        from pyfilecage import inspect_file_bytes
        data = ascii_bytes('<?pi?><x:svg xmlns:x="http://www.w3.org/2000/svg"><x:use href="https://example.invalid/x.svg"/></x:svg>')
        result = inspect_file_bytes(data)
        self.assertTrue(has_finding(result, "FILECAGE_SVG_ACTIVE_CONTENT"))

    def test_many_processing_instructions_cannot_hide_svg_root(self):
        from pyfilecage import inspect_file_bytes, sniff_file_type
        data = ascii_bytes('<?pi?>' * 100 + '<x:svg xmlns:x="http://www.w3.org/2000/svg"><x:script>alert(1)</x:script></x:svg>')
        self.assertEqual(sniff_file_type(data).format, "svg")
        self.assertTrue(has_finding(inspect_file_bytes(data), "FILECAGE_SVG_ACTIVE_CONTENT"))


class PdfStreamLexicalTest(unittest.TestCase):
    def custom_stream_pdf(self, payload, type_name="/ObjStm", filter_name="/FlateDecode", padding=b"", prefix=b""):
        compressed = zlib.compress(ascii_bytes(payload))
        dictionary = ascii_bytes("<< /Type " + type_name + " /N 1 /First 0 /Filter " + filter_name + " /Length " + str(len(compressed)) + " ") + padding + b">>"
        return concat_bytes(
            ascii_bytes("%PDF-1.7\n"), prefix,
            ascii_bytes("1 0 obj\n"), dictionary,
            ascii_bytes("\nstream\n"), compressed,
            ascii_bytes("\nendstream\nendobj\n%%EOF\n"),
        )

    def test_hex_escaped_object_stream_and_filter_names_are_scanned(self):
        data = self.custom_stream_pdf("/Type /OpenAction /S /JavaScript /JS (alert(1))", "/Obj#53tm", "/Fl#61teDecode")
        result = validate_pdf(data)
        self.assertTrue(any(getattr(item, "token", None) == "/JAVASCRIPT" for item in result.findings))

    def test_long_stream_dictionary_cannot_hide_compressed_actions(self):
        padding = b"/A " + b"0" * 5000 + b" "
        data = self.custom_stream_pdf("/Type /Action /S /Launch", padding=padding)
        result = validate_pdf(data)
        self.assertTrue(any(getattr(item, "token", None) == "/LAUNCH" for item in result.findings))

    def test_fake_stream_word_in_comment_cannot_skip_real_stream(self):
        data = self.custom_stream_pdf("/Type /OpenAction /S /JavaScript /JS (alert(1))", prefix=ascii_bytes("% stream\n"))
        result = validate_pdf(data)
        self.assertTrue(any(getattr(item, "token", None) == "/JAVASCRIPT" for item in result.findings))


class ImagePdfPolyglotTest(unittest.TestCase):
    def test_clean_jpeg_pdf_polyglot_is_rejected(self):
        data = concat_bytes(jpeg(), ascii_bytes("\n%PDF-1.7\n%%EOF\n"))
        result = validate(data, "photo.jpg", "image/jpeg")
        self.assertTrue(any(item.code == "FILECAGE_POLYGLOT" and getattr(item, "pattern", None) == "pdf-signature" for item in result.findings))

    def test_clean_gif_pdf_polyglot_is_rejected(self):
        data = concat_bytes(gif(), ascii_bytes("\n%PDF-1.7\n%%EOF\n"))
        result = validate(data, "image.gif", "image/gif")
        self.assertTrue(any(item.code == "FILECAGE_POLYGLOT" and getattr(item, "pattern", None) == "pdf-signature" for item in result.findings))


class PngCompressedTextLimitTest(unittest.TestCase):
    def hidden_after_cap_png(self, chunk_type):
        plain = (b"A" * (1024 * 1024)) + b"<script>alert(1)</script>"
        compressed = zlib.compress(plain)
        from helpers import insert_before_png_iend, png_chunk
        if chunk_type == "zTXt":
            payload = b"comment\x00\x00" + compressed
        else:
            payload = b"comment\x00\x01\x00\x00\x00" + compressed
        return insert_before_png_iend(png(), png_chunk(chunk_type, payload))

    def test_ztxt_cap_fails_closed_instead_of_scanning_partial_output(self):
        result = validate(self.hidden_after_cap_png("zTXt"), "image.png", "image/png")
        self.assertFalse(result.allowed)
        self.assertTrue(has_finding(result, "FILECAGE_PNG_TEXT_SCAN_LIMIT"))

    def test_itxt_cap_fails_closed_instead_of_scanning_partial_output(self):
        result = validate(self.hidden_after_cap_png("iTXt"), "image.png", "image/png")
        self.assertFalse(result.allowed)
        self.assertTrue(has_finding(result, "FILECAGE_PNG_TEXT_SCAN_LIMIT"))


if __name__ == "__main__":
    unittest.main()
