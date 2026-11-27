"""Command line interface for pyfilecage."""
from __future__ import annotations

import json
import re
import sys
from typing import Any, Dict, List, Optional

from . import __version__
from .errors import FileCageError
from .validation import validate_file_path

_CONTROL_OR_BIDI_RE = re.compile(r"[\x00-\x1f\x7f-\x9f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]")


def neutralize_terminal(value: Any) -> str:
    """Remove terminal control and bidirectional override code points."""
    return _CONTROL_OR_BIDI_RE.sub("", str(value))


def usage() -> str:
    return "\n".join((
        "pyfilecage " + __version__,
        "",
        "Usage:",
        "  pyfilecage inspect <file> [--allow <mime1,mime2>] [--preset images-safe|documents-safe|media-safe] [--max-bytes N] [--max-pixels N] [--json]",
        "",
        "Exit codes:",
        "  0  file passes validation",
        "  1  file is rejected or has security findings",
        "  2  usage, input, or I/O error",
    ))


def _parse_positive_integer(value: str, flag: str) -> int:
    if not re.match(r"^[0-9]+$", value):
        raise ValueError(flag + " requires a positive integer")
    number = int(value, 10)
    if number < 1:
        raise ValueError(flag + " requires a positive integer")
    return number


def parse_args(args: List[str]) -> Dict[str, Any]:
    if not args:
        raise ValueError("missing command")
    if "--help" in args or "-h" in args:
        return {"help": True}
    if len(args) == 1 and args[0] in ("--version", "-v"):
        return {"version": True}
    command = args[0]
    if command != "inspect":
        raise ValueError("expected the inspect command")
    output = {
        "file": None,
        "allow": [],
        "preset": None,
        "max_bytes": None,
        "max_pixels": None,
        "json": False,
    }
    index = 1
    while index < len(args):
        arg = args[index]
        if arg == "--json":
            output["json"] = True
        elif arg in ("--allow", "--preset", "--max-bytes", "--max-pixels"):
            index += 1
            if index >= len(args):
                raise ValueError(arg + " requires a value")
            value = args[index]
            if arg == "--allow":
                for mime in value.split(","):
                    normalized = mime.strip().lower()
                    if normalized:
                        output["allow"].append(normalized)
            elif arg == "--preset":
                output["preset"] = value.strip().lower()
            elif arg == "--max-bytes":
                output["max_bytes"] = _parse_positive_integer(value, arg)
            else:
                output["max_pixels"] = _parse_positive_integer(value, arg)
        elif arg.startswith("--"):
            raise ValueError("unknown option " + neutralize_terminal(arg))
        elif output["file"] is None:
            output["file"] = arg
        else:
            raise ValueError("inspect accepts exactly one file")
        index += 1
    if output["file"] is None:
        raise ValueError("inspect requires a file")
    return output


def _json_neutralized(value: Any) -> Any:
    if isinstance(value, str):
        return neutralize_terminal(value)
    if isinstance(value, list):
        return [_json_neutralized(item) for item in value]
    if isinstance(value, tuple):
        return [_json_neutralized(item) for item in value]
    if isinstance(value, dict):
        return {key: _json_neutralized(item) for key, item in value.items()}
    return value


def main(argv: Optional[List[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        options = parse_args(args)
    except ValueError as error:
        print("pyfilecage: " + neutralize_terminal(str(error)), file=sys.stderr)
        print(usage(), file=sys.stderr)
        return 2

    if options.get("help"):
        print(usage())
        return 0
    if options.get("version"):
        print(__version__)
        return 0

    policy: Dict[str, Any] = {}
    if options["preset"]:
        policy["preset"] = options["preset"]
    if options["allow"]:
        policy["allowed_mime_types"] = options["allow"]
    if options["max_bytes"] is not None:
        policy["max_bytes"] = options["max_bytes"]
    if options["max_pixels"] is not None:
        policy["max_pixels"] = options["max_pixels"]

    try:
        result = validate_file_path(options["file"], policy)
    except FileCageError as error:
        print("pyfilecage: " + neutralize_terminal(error.reason), file=sys.stderr)
        return 2
    except Exception as error:
        print("pyfilecage: " + neutralize_terminal(str(error) or "unexpected failure"), file=sys.stderr)
        return 2

    if options["json"]:
        print(json.dumps(_json_neutralized(result.to_dict()), indent=2, ensure_ascii=True, sort_keys=True))
    else:
        print("pyfilecage: " + ("safe" if result.allowed else "rejected"))
        print("file: " + neutralize_terminal(result.safe_filename or "unknown"))
        print("type: " + neutralize_terminal(result.detected_mime or "unverified"))
        print("size: " + ("unknown" if result.size_bytes is None else str(result.size_bytes)) + " bytes")
        if result.dimensions is not None:
            print("dimensions: " + str(result.dimensions.width) + "x" + str(result.dimensions.height))
        for item in result.findings:
            print(item.severity + ": " + item.code + ": " + neutralize_terminal(item.message))
        if not result.findings:
            print("findings: none")

    io_failure = any(item.code in ("FILECAGE_PATH_IO_ERROR", "FILECAGE_PATH_UNSAFE") for item in result.findings)
    if result.allowed:
        return 0
    return 2 if io_failure else 1


if __name__ == "__main__":
    raise SystemExit(main())
