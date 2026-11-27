# Good first issues

These ten starter specifications are intentionally narrow. Each still needs
adversarial tests and false-positive controls.

1. **AVIF sequence brands:** research the exact compatibility brands used by
   animated AVIF files and add fixture-driven sniff tests without weakening the
   current HEIF fallback.
2. **ICO dimension metadata:** design a bounded ICO directory parser and decide
   whether dimensions should be enforced for ICO. Keep PNG-in-ICO and BMP-in-ICO
   payload decoding out of scope.
3. **TIFF dimension metadata:** design a bounded TIFF IFD walker for width and
   height tags. Reject loops, overlapping entries, and impossible offsets.
4. **PDF stream filter inventory:** add tests documenting how the scanner handles
   multiple filters, unknown filters, and whitespace inside `/Filter` arrays.
5. **SVG namespace false-positive audit:** build a corpus of namespaced but inert
   SVG elements and verify local fragment references remain accepted.
6. **CSV classifier corpus:** add quoted delimiter, embedded newline, Unicode,
   and inconsistent-column cases. The classifier must remain strict and cheap.
7. **Filename Unicode corpus:** add compatibility normalization, noncharacter,
   astral-plane, and mixed-path-separator fixtures. Never weaken the bidi rule.
8. **Stream adapter conformance:** add a small test helper that mimics raw IO
   streams returning short chunks and verify `validate_file_obj` remains bounded.
9. **CLI snapshot tests:** add stable human-output snapshots for safe, rejected,
   and I/O failure cases. Control characters must remain neutralized.
10. **Packaging reproducibility:** compare two clean local builds and document
    which metadata fields are expected to differ. Do not commit build artifacts.

## Before starting

Comment on the issue you intend to implement. Keep the public API stable unless
a maintainer agrees otherwise. Every implementation must include tests and a
README update when behavior changes.
