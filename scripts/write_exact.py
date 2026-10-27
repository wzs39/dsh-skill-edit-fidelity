#!/usr/bin/env python3
"""write_exact.py - write bytes to a file without any shell/quoting layer.

Use when the target content is escape-dense (regex, LaTeX, C/JS string literals,
JSON-in-JSON, Windows paths) and going through a command line risks eating a
backslash. Payload travels as base64, which contains no backslash.

Usage:
  python write_exact.py OUT --b64 "BASE64"
  python write_exact.py OUT --b64-file payload.b64
  python write_exact.py OUT --from-file SRC      # exact byte copy

Prints the written sha256 so the caller can compare with bs_audit.py.
"""
import argparse
import base64
import hashlib
import pathlib
import sys


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--b64")
    g.add_argument("--b64-file")
    g.add_argument("--from-file")
    a = ap.parse_args()

    if a.from_file:
        data = pathlib.Path(a.from_file).read_bytes()
    else:
        raw = a.b64 if a.b64 is not None else pathlib.Path(a.b64_file).read_text(encoding="ascii")
        data = base64.b64decode(raw.strip())

    out = pathlib.Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(data)
    print("wrote " + str(out) + " bytes=" + str(len(data)) + " sha256=" + hashlib.sha256(data).hexdigest())
    return 0


if __name__ == "__main__":
    sys.exit(main())
