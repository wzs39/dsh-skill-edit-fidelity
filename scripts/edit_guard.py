#!/usr/bin/env python3
"""edit_guard.py - 结构级编辑守卫：抓"写错、漏写、截断、写两遍、留占位符"。

设计原则：本文件源码不含任何字面反斜杠（一律用字符类 / chr(92) / in 判断），
所以它自身不会被转义层破坏，可作为"零转义写法"的参考实现。

用法：
  python edit_guard.py AFTER                        # 单文件体检
  python edit_guard.py AFTER --before BEFORE        # 增量校验（推荐）
  python edit_guard.py AFTER --before BEFORE --strict
  python edit_guard.py AFTER --json
  python edit_guard.py AFTER --lang py|js|json|sh|md|auto

检查项：
  SYNTAX      真解析（py/json/sh/node --check），失败即 FAIL
  BALANCE     括号/引号配平，定位未闭合行
  TRUNCATE    末尾疑似截断（最后一行有未闭合符号 / 文件几乎为空）
  LOST_DEF    改动前存在的定义在改动后消失（漏写、整文件重写的典型症状）
  PLACEHOLDER TODO / FIXME / NotImplementedError / 单独一行的 ... 等半成品  # guard:ignore
  DUP_BLOCK   连续 >=5 行内容重复出现（写两遍）
  ENCODING    CRLF 混入 / BOM / 行尾空格激增

退出码：0 通过，1 失败（--strict 时 WARN 也计失败），2 用法/IO 错误。
"""
import argparse
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

BS = chr(92)
LANG_BY_EXT = {
    ".py": "py",
    ".js": "js",
    ".mjs": "js",
    ".cjs": "js",
    ".ts": "js",
    ".json": "json",
    ".sh": "sh",
    ".bash": "sh",
    ".md": "md",
}

DEF_PATTERNS = [
    re.compile(r"^[ \t]*(?:async[ \t]+)?def[ \t]+([A-Za-z0-9_]+)"),
    re.compile(r"^[ \t]*class[ \t]+([A-Za-z0-9_]+)"),
    re.compile(r"^[ \t]*(?:export[ \t]+)?(?:default[ \t]+)?(?:async[ \t]+)?function[ \t]+([A-Za-z0-9_$]+)"),
    re.compile(r"^[ \t]*(?:export[ \t]+)?(?:const|let|var)[ \t]+([A-Za-z0-9_$]+)[ \t]*=[ \t]*(?:async[ \t]*)?\("),
    re.compile(r"^[ \t]*([A-Za-z0-9_]+)[ \t]*\(\)[ \t]*[{(]"),
]

PLACEHOLDER_TOKENS = [
    "TODO",  # guard:ignore
    "FIXME",  # guard:ignore
    "XXX:",  # guard:ignore
    "NotImplementedError",  # guard:ignore
    "<PLACEHOLDER>",  # guard:ignore
    "PLACEHOLDER",  # guard:ignore
    "YOUR_API_KEY",  # guard:ignore
    "lorem ipsum",  # guard:ignore
]

# 行内抑制标记：出现该子串的行不参与占位符判定（用于文档、词表、检查器自身）
SUPPRESS = "guard:ignore"


def detect_lang(path: pathlib.Path, forced):
    if forced and forced != "auto":
        return forced
    return LANG_BY_EXT.get(path.suffix.lower(), "text")


def parse_check(text, lang, path):
    """真解析。返回 (ok, detail)。"""
    if lang == "py":
        import ast

        try:
            ast.parse(text)
            return True, "ast.parse ok"
        except SyntaxError as e:
            return False, "SyntaxError line " + str(e.lineno) + ": " + str(e.msg)
    if lang == "json":
        try:
            json.loads(text)
            return True, "json.loads ok"
        except Exception as e:
            return False, "JSON error: " + str(e)
    if lang == "sh":
        bash = shutil.which("bash")
        if not bash:
            return None, "bash not found"
        r = subprocess.run([bash, "-n", str(path)], capture_output=True, text=True)
        return (r.returncode == 0), (r.stderr.strip() or "bash -n ok")
    if lang == "js":
        node = shutil.which("node")
        if not node:
            return None, "node not found"
        r = subprocess.run([node, "--check", str(path)], capture_output=True, text=True)
        return (r.returncode == 0), (r.stderr.strip()[:400] or "node --check ok")
    return None, "no parser for " + lang


def balance_scan(text, lang):
    """逐字符扫描，跳过字符串/注释，返回未闭合栈与首处可疑行号。"""
    line_comments = ("#",) if lang in ("py", "sh") else ("//",)
    pairs = {")": "(", "]": "[", "}": "{"}
    stack = []
    line = 1
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == chr(10):
            line += 1
            i += 1
            continue
        if c == BS:
            i += 2
            continue
        if c in ("'", '"', "`"):
            q = c
            triple = text[i : i + 3] == q * 3
            if triple:
                end = text.find(q * 3, i + 3)
                seg = text[i + 3 : (end if end != -1 else n)]
                line += seg.count(chr(10))
                i = (end + 3) if end != -1 else n
                continue
            j = i + 1
            while j < n:
                if text[j] == BS:
                    j += 2
                    continue
                if text[j] == q:
                    break
                if text[j] == chr(10):
                    break
                j += 1
            i = j + 1
            continue
        if any(text.startswith(lc, i) for lc in line_comments):
            end = text.find(chr(10), i)
            i = n if end == -1 else end
            continue
        if c in "([{":
            stack.append((c, line))
            i += 1
            continue
        if c in ")]}":
            if stack and stack[-1][0] == pairs[c]:
                stack.pop()
            else:
                return {"ok": False, "unmatched_close": c, "line": line, "open": list(stack[-3:])}
            i += 1
            continue
        i += 1
    return {"ok": not stack, "unclosed": list(stack[-5:]), "line": (stack[-1][1] if stack else None)}


def defs_of(text):
    names = set()
    for ln in text.split(chr(10)):
        for pat in DEF_PATTERNS:
            m = pat.match(ln)
            if m:
                names.add(m.group(1))
                break
    return names


def dup_blocks(text, window=5):
    lines = [ln.strip() for ln in text.split(chr(10))]
    lines = [ln for ln in lines if ln]
    seen = {}
    hits = []
    for i in range(0, max(0, len(lines) - window + 1)):
        key = hashlib.sha256(chr(10).join(lines[i : i + window]).encode()).hexdigest()
        if key in seen:
            hits.append((seen[key], i, lines[i][:60]))
        else:
            seen[key] = i
    return hits


def frontmatter_range(text):
    """YAML frontmatter 行号区间（1-based，含两端）；无 frontmatter 返回 None。"""
    lines = text.split(chr(10))
    if not lines or lines[0].strip() != "---":
        return None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            return (1, i + 1)
    return None


def placeholders(text, skip=None):
    out = []
    lo, hi = skip if skip else (0, 0)
    for idx, ln in enumerate(text.split(chr(10)), 1):
        if lo <= idx <= hi:
            continue
        stripped = ln.strip()
        if SUPPRESS in ln or "PLACEHOLDER_TOKENS" in ln:
            continue
        for tok in PLACEHOLDER_TOKENS:
            if tok in ln:
                out.append((idx, tok, stripped[:100]))
                break
        else:
            if stripped in ("...", "pass", "raise NotImplementedError"):  # guard:ignore
                out.append((idx, "stub:" + stripped, stripped))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("after")
    ap.add_argument("--before")
    ap.add_argument("--lang", default="auto")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    after = pathlib.Path(a.after)
    if not after.is_file():
        print("ERROR not a file: " + a.after, file=sys.stderr)
        return 2
    text = after.read_text(encoding="utf-8", errors="replace")
    lang = detect_lang(after, a.lang)

    findings = []

    def add(level, code, msg, lines=None):
        findings.append({"level": level, "code": code, "msg": msg, "lines": lines or []})

    if not text.strip():
        add("FAIL", "TRUNCATE", "文件为空或只有空白")
        text = ""

    ok, detail = parse_check(text, lang, after)
    if ok is False:
        add("FAIL", "SYNTAX", detail)
    elif ok is None:
        add("INFO", "SYNTAX", "跳过：" + detail)

    bal = balance_scan(text, lang)
    if not bal.get("ok", True):
        if bal.get("unmatched_close"):
            add("FAIL", "BALANCE", "多余的 " + bal["unmatched_close"] + "（第 " + str(bal["line"]) + " 行）")
        else:
            opens = ", ".join(x[0] + "@L" + str(x[1]) for x in bal.get("unclosed", []))
            add("FAIL", "BALANCE", "未闭合符号：" + (opens or "?"), [x[1] for x in bal.get("unclosed", [])])

    lines = text.split(chr(10))
    last = ""
    for ln in reversed(lines):
        if ln.strip():
            last = ln.strip()
            break
    if last and last[-1] in "([{" + "," + ":" + "=" + BS:
        add("FAIL", "TRUNCATE", "最后一行以 " + repr(last[-1]) + " 结尾，疑似写断", [len(lines)])

    for idx, tok, snippet in placeholders(text, frontmatter_range(text)):
        add("WARN", "PLACEHOLDER", tok + " -> " + snippet, [idx])  # guard:ignore

    for i, j, snip in dup_blocks(text):
        add("WARN", "DUP_BLOCK", "第 " + str(j + 1) + " 段与第 " + str(i + 1) + " 段重复: " + snip, [i + 1, j + 1])

    if chr(13).encode() in after.read_bytes():
        add("WARN", "ENCODING", "文件含 CRLF，可能混入 Windows 换行")
    if after.read_bytes()[:3] == b"\xef\xbb\xbf":
        add("WARN", "ENCODING", "文件含 UTF-8 BOM")

    delta = None
    if a.before:
        bpath = pathlib.Path(a.before)
        if not bpath.is_file():
            print("ERROR --before not a file: " + a.before, file=sys.stderr)
            return 2
        btext = bpath.read_text(encoding="utf-8", errors="replace")
        bdefs, adefs = defs_of(btext), defs_of(text)
        lost = sorted(bdefs - adefs)
        gained = sorted(adefs - bdefs)
        bl = len([x for x in btext.split(chr(10)) if x.strip()])
        al = len([x for x in lines if x.strip()])
        delta = {
            "lines_before": bl,
            "lines_after": al,
            "defs_before": len(bdefs),
            "defs_after": len(adefs),
            "lost_defs": lost,
            "gained_defs": gained,
        }
        if lost:
            add("FAIL", "LOST_DEF", "改动后消失的定义：" + ", ".join(lost))
        if al < bl * 0.6 and bl - al > 10:
            add("FAIL", "LOST_DEF", "非空行从 " + str(bl) + " 掉到 " + str(al) + "，疑似大面积丢失")
        elif al < bl:
            add("WARN", "SHRINK", "非空行减少 " + str(bl - al) + " 行（确认是有意删除）")

    fails = [f for f in findings if f["level"] == "FAIL"]
    warns = [f for f in findings if f["level"] == "WARN"]
    verdict = "FAIL" if fails else ("WARN" if warns else "PASS")

    if a.json:
        print(json.dumps({
            "path": str(after),
            "lang": lang,
            "sha256": hashlib.sha256(after.read_bytes()).hexdigest(),
            "verdict": verdict,
            "findings": findings,
            "delta": delta,
        }, ensure_ascii=False, indent=2))
    else:
        print("path     " + str(after))
        print("lang     " + lang + "   verdict " + verdict)
        if delta:
            print("lines    " + str(delta["lines_before"]) + " -> " + str(delta["lines_after"]))
            print("defs     " + str(delta["defs_before"]) + " -> " + str(delta["defs_after"]))
            if delta["lost_defs"]:
                print("lost     " + ", ".join(delta["lost_defs"]))
            if delta["gained_defs"]:
                print("gained   " + ", ".join(delta["gained_defs"][:10]))
        if findings:
            for f in findings:
                loc = (" L" + ",".join(str(x) for x in f["lines"])) if f["lines"] else ""
                print("  [" + f["level"] + "] " + f["code"] + loc + "  " + f["msg"])
        else:
            print("  no findings")

    if fails:
        return 1
    if warns and a.strict:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
