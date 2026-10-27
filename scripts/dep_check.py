#!/usr/bin/env python3
"""dep_check.py - 抓"幻觉依赖"：代码里 import 了不存在的模块/包。

AI 写错代码最集中的一类是编造库名或路径。这个检查能机械否掉大部分：
  Python  : import x / from x.y import z  -> importlib.util.find_spec(顶层名)
  Node    : require('x') / from 'x'      -> 相对路径查文件，裸包名查 node_modules

本文件源码同样不含字面反斜杠。

用法：
  python dep_check.py PATH [PATH ...] [--root DIR] [--json]
退出码：0 全部存在，1 有缺失，2 用法错误。
"""
import argparse
import json
import pathlib
import re
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

PY_IMPORT = re.compile(r"^[ \t]*(?:from[ \t]+([A-Za-z0-9_.]+)[ \t]+import|import[ \t]+([A-Za-z0-9_., \t]+))")
NODE_IMPORT = re.compile(r"(?:require[ \t]*\(|from[ \t]+)['\"]([^'\"]+)['\"]")
STDLIB_HINT = {
    "sys", "os", "re", "json", "time", "math", "io", "ast", "subprocess", "shutil",
    "pathlib", "typing", "hashlib", "base64", "argparse", "collections", "itertools",
    "functools", "tempfile", "logging", "unittest", "dataclasses", "asyncio", "socket",
    "threading", "random", "csv", "sqlite3", "http", "urllib", "datetime", "textwrap",
}


def check_python(path: pathlib.Path, root: pathlib.Path):
    out = []
    import importlib.util

    for idx, ln in enumerate(path.read_text(encoding="utf-8", errors="replace").split(chr(10)), 1):
        m = PY_IMPORT.match(ln)
        if not m:
            continue
        mods = []
        if m.group(1):
            mods = [m.group(1)]
        elif m.group(2):
            mods = [x.strip().split(" ")[0] for x in m.group(2).split(",") if x.strip()]
        for mod in mods:
            top = mod.split(".")[0]
            if not top or top.startswith("."):
                continue
            try:
                found = importlib.util.find_spec(top) is not None
            except (ImportError, ValueError, ModuleNotFoundError):
                found = False
            if not found:
                out.append({"line": idx, "module": mod, "kind": "python", "status": "MISSING"})
    return out


def check_node(path: pathlib.Path, root: pathlib.Path):
    out = []
    for idx, ln in enumerate(path.read_text(encoding="utf-8", errors="replace").split(chr(10)), 1):
        for m in NODE_IMPORT.finditer(ln):
            spec = m.group(1)
            if spec.startswith("."):
                base = (path.parent / spec).resolve()
                ok = base.exists() or any(
                    (base.parent / (base.name + ext)).exists() for ext in (".js", ".mjs", ".cjs", ".json", ".ts")
                ) or (base / "index.js").exists()
                status = "OK" if ok else "MISSING_FILE"
            elif spec.startswith("node:"):
                status = "OK"
            else:
                pkg = "/".join(spec.split("/")[:2]) if spec.startswith("@") else spec.split("/")[0]
                ok = (root / "node_modules" / pkg).exists() or (path.parent / "node_modules" / pkg).exists()
                status = "OK" if ok else "MISSING_PACKAGE"
            if status != "OK":
                out.append({"line": idx, "module": spec, "kind": "node", "status": status})
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--root", default=".")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    root = pathlib.Path(a.root).resolve()
    results = []
    for p in a.paths:
        path = pathlib.Path(p)
        if not path.is_file():
            print("ERROR not a file: " + p, file=sys.stderr)
            return 2
        if path.suffix == ".py":
            results += check_python(path, root)
        elif path.suffix in (".js", ".mjs", ".cjs", ".ts"):
            results += check_node(path, root)

    if a.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
    else:
        if not results:
            print("all imports resolvable")
        for r in results:
            print("  [" + r["status"] + "] " + str(r["kind"]) + " " + r["module"] + "  (line " + str(r["line"]) + ")")
    return 1 if results else 0


if __name__ == "__main__":
    sys.exit(main())
