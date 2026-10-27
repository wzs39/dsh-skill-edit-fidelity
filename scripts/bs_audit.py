#!/usr/bin/env python3
"""bs_audit.py - byte-level fidelity audit for files that contain backslashes.

Why: model-authored edits silently lose or double escape characters (most often
the backslash). This script reports the ground truth from bytes, so a claim like
"the file is correct" can be checked instead of assumed.

Usage:
  python bs_audit.py PATH
  python bs_audit.py PATH --expect 14          # fail unless backslash count == 14
  python bs_audit.py PATH --expect-file m.json # JSON {"path/to/f": 14, ...}
  python bs_audit.py PATH --has-literal lit.txt # fail unless bytes contain lit.txt verbatim
  python bs_audit.py PATH --json

Exit codes: 0 ok, 1 mismatch, 2 usage/IO error.
"""
import argparse
import hashlib
import json
import pathlib
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

BS = chr(92)          # backslash, never written literally in this source
BSB = BS.encode()


def audit(path: pathlib.Path):
    data = path.read_bytes()
    text = data.decode("utf-8", "replace")
    lines = text.split(chr(10))
    per_line = [(i, ln.count(BS)) for i, ln in enumerate(lines, 1)]
    total = data.count(BSB)
    pairs = 0
    i = 0
    while i < len(data) - 1:
        if data[i : i + 2] == BSB + BSB:
            pairs += 1
            i += 2
        else:
            i += 1
    return {
        "path": str(path),
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "lines": len(lines) - (1 if text.endswith(chr(10)) else 0),
        "backslashes": total,
        "backslash_pairs": pairs,
        "lone_backslashes": total - 2 * pairs,
        "has_crlf": chr(13).encode() in data,
        "has_bom": data[:3] == b"\xef\xbb\xbf",
        "ends_with_newline": data.endswith(b"\n"),
        "non_ascii_bytes": sum(1 for b in data if b > 127),
        "per_line": per_line,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--expect", type=int)
    ap.add_argument("--expect-file")
    ap.add_argument("--has-literal")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    p = pathlib.Path(a.path)
    if not p.is_file():
        print("ERROR not a file: " + a.path, file=sys.stderr)
        return 2
    r = audit(p)

    expect = a.expect
    if a.expect_file:
        table = json.loads(pathlib.Path(a.expect_file).read_text(encoding="utf-8"))
        key = a.path.replace(BS, "/")
        if key not in table:
            print("ERROR no expectation for " + key, file=sys.stderr)
            return 2
        expect = int(table[key])

    literal_ok = None
    if a.has_literal:
        needle = pathlib.Path(a.has_literal).read_bytes()
        literal_ok = needle in p.read_bytes()

    if a.json:
        r["expect"] = expect
        r["literal_found"] = literal_ok
        print(json.dumps(r, ensure_ascii=False))
    else:
        print("path        " + r["path"])
        print("sha256      " + r["sha256"])
        print("bytes       " + str(r["bytes"]) + "   lines " + str(r["lines"]))
        print(
            "backslashes "
            + str(r["backslashes"])
            + "   pairs "
            + str(r["backslash_pairs"])
            + "   lone "
            + str(r["lone_backslashes"])
        )
        flags = []
        if r["has_crlf"]:
            flags.append("CRLF")
        if r["has_bom"]:
            flags.append("BOM")
        if not r["ends_with_newline"]:
            flags.append("no-trailing-newline")
        if r["non_ascii_bytes"]:
            flags.append("non-ascii=" + str(r["non_ascii_bytes"]))
        print("flags       " + (", ".join(flags) if flags else "none"))
        print("per-line    " + " ".join(str(i) + ":" + str(c) for i, c in r["per_line"] if c))
        if expect is not None:
            print("expect      " + str(expect) + "  -> " + ("OK" if r["backslashes"] == expect else "MISMATCH"))
        if literal_ok is not None:
            print("literal     " + ("FOUND" if literal_ok else "MISSING"))

    if expect is not None and r["backslashes"] != expect:
        return 1
    if literal_ok is False:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
