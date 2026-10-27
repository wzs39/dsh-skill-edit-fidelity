#!/usr/bin/env python3
"""char_audit.py - 不可见字符 / 同形字 / 全角标点 / 混合换行缩进 审计器.

用法:
    python char_audit.py FILE [FILE ...]
    python char_audit.py --recursive DIR
    python char_audit.py FILE --mode code|text|auto
    python char_audit.py FILE --fix              # 安全清理(不可见/双向/空格/全角/引号)
    python char_audit.py FILE --fix --fix-confusables   # 连同上形字一起改写
    python char_audit.py FILE --json
    python char_audit.py FILE --strict           # medium 也判 FAIL

退出码: 0 = OK/WARN, 1 = FAIL(发现 critical/high 或 strict 下 medium), 2 = 参数/IO 错误.

设计边界:
  - 只读文件字节, 不做语言解析; 语言语法问题交给 edit_guard.py.
  - 中文正文是合法内容: text 模式下全角标点/引号降为 INFO, 不判失败.
  - 上形字默认只报告不改写, 因为改写会改变标识符语义; 需要 --fix-confusables 显式授权.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import sys
import unicodedata

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass  # guard:ignore 老 Python 无 reconfigure，忽略即可

# ---------------------------------------------------------------- 字符分类表

# 零宽 / 不可见
INVISIBLE = {
    0x200B: "ZERO WIDTH SPACE",
    0x200C: "ZERO WIDTH NON-JOINER",
    0x200D: "ZERO WIDTH JOINER",
    0x2060: "WORD JOINER",
    0xFEFF: "ZERO WIDTH NO-BREAK SPACE (BOM)",
    0x00AD: "SOFT HYPHEN",
    0x180E: "MONGOLIAN VOWEL SEPARATOR",
    0x115F: "HANGUL CHOSEONG FILLER",
    0x3164: "HANGUL FILLER",
    0xFFA0: "HALFWIDTH HANGUL FILLER",
}

# 双向控制符 (Trojan Source)
BIDI = {
    0x202A: "LEFT-TO-RIGHT EMBEDDING",
    0x202B: "RIGHT-TO-LEFT EMBEDDING",
    0x202C: "POP DIRECTIONAL FORMATTING",
    0x202D: "LEFT-TO-RIGHT OVERRIDE",
    0x202E: "RIGHT-TO-LEFT OVERRIDE",
    0x2066: "LEFT-TO-RIGHT ISOLATE",
    0x2067: "RIGHT-TO-LEFT ISOLATE",
    0x2068: "FIRST STRONG ISOLATE",
    0x2069: "POP DIRECTIONAL ISOLATE",
    0x200E: "LEFT-TO-RIGHT MARK",
    0x200F: "RIGHT-TO-LEFT MARK",
    0x061C: "ARABIC LETTER MARK",
}

# 空格仿冒
SPACE_LOOKALIKE = {
    0x00A0: "NO-BREAK SPACE",
    0x1680: "OGHAM SPACE MARK",
    0x2000: "EN QUAD",
    0x2001: "EM QUAD",
    0x2002: "EN SPACE",
    0x2003: "EM SPACE",
    0x2004: "THREE-PER-EM SPACE",
    0x2005: "FOUR-PER-EM SPACE",
    0x2006: "SIX-PER-EM SPACE",
    0x2007: "FIGURE SPACE",
    0x2008: "PUNCTUATION SPACE",
    0x2009: "THIN SPACE",
    0x200A: "HAIR SPACE",
    0x202F: "NARROW NO-BREAK SPACE",
    0x205F: "MEDIUM MATHEMATICAL SPACE",
    0x3000: "IDEOGRAPHIC SPACE",
}

# 引号仿冒
QUOTE_LOOKALIKE = {
    0x2018: ("LEFT SINGLE QUOTATION MARK", "'"),
    0x2019: ("RIGHT SINGLE QUOTATION MARK", "'"),
    0x201A: ("SINGLE LOW-9 QUOTATION MARK", "'"),
    0x201B: ("SINGLE HIGH-REVERSED-9 QUOTATION MARK", "'"),
    0x201C: ("LEFT DOUBLE QUOTATION MARK", '"'),
    0x201D: ("RIGHT DOUBLE QUOTATION MARK", '"'),
    0x201E: ("DOUBLE LOW-9 QUOTATION MARK", '"'),
    0x201F: ("DOUBLE HIGH-REVERSED-9 QUOTATION MARK", '"'),
    0x00AB: ("LEFT-POINTING DOUBLE ANGLE QUOTATION MARK", '"'),
    0x00BB: ("RIGHT-POINTING DOUBLE ANGLE QUOTATION MARK", '"'),
    0x2032: ("PRIME", "'"),
    0x2033: ("DOUBLE PRIME", '"'),
}

# 上形字 (confusables) -> ASCII 目标. 只报告, 默认不改.
CONFUSABLES = {
    # Cyrillic 小写
    0x0430: "a", 0x0435: "e", 0x043E: "o", 0x0440: "p", 0x0441: "c",
    0x0443: "y", 0x0445: "x", 0x0456: "i", 0x0458: "j", 0x0455: "s",
    0x0501: "d", 0x04BB: "h", 0x04CF: "l", 0x051B: "q", 0x051D: "w",
    0x0261: "g", 0x0459: "n", 0x043A: "k", 0x043C: "m", 0x0442: "t",
    # Cyrillic 大写
    0x0410: "A", 0x0412: "B", 0x0415: "E", 0x041A: "K", 0x041C: "M",
    0x041D: "H", 0x041E: "O", 0x0420: "P", 0x0421: "C", 0x0422: "T",
    0x0425: "X", 0x0423: "Y", 0x0406: "I", 0x0408: "J", 0x0405: "S",
    # Greek
    0x03BF: "o", 0x03B1: "a", 0x03BD: "v", 0x03B9: "i", 0x03BA: "k",
    0x03C1: "p", 0x03C4: "t", 0x03C5: "u", 0x03C7: "x", 0x03B3: "y",
    0x0391: "A", 0x0392: "B", 0x0395: "E", 0x0396: "Z", 0x0397: "H",
    0x0399: "I", 0x039A: "K", 0x039C: "M", 0x039D: "N", 0x039F: "O",
    0x03A1: "P", 0x03A4: "T", 0x03A5: "Y", 0x03A7: "X",
    # Latin 扩展 / 修饰字母
    0x0131: "i", 0x0237: "j", 0x2113: "l", 0x217C: "l", 0x1D00: "A",
    0x0299: "B", 0x1D04: "C", 0x1D07: "E", 0x0262: "G", 0x029C: "H",
    0x026A: "I", 0x1D0A: "J", 0x1D0B: "K", 0x029F: "L", 0x1D0D: "M",
    0x0274: "N", 0x1D0F: "O", 0x1D18: "P", 0x0280: "R", 0x0457: "i",
}

# 全角 ASCII
FW_LO = 0xFF01
FW_HI = 0xFF5E

TEXT_EXTS = {
    ".md", ".markdown", ".txt", ".rst", ".adoc", ".log", ".csv", ".tsv",
    ".po", ".pot",
}

CODE_EXTS = {
    ".py", ".pyw", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".json",
    ".jsonc", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".sh",
    ".bash", ".zsh", ".ps1", ".psm1", ".bat", ".cmd", ".go", ".rs", ".c",
    ".h", ".cc", ".cpp", ".hpp", ".java", ".kt", ".cs", ".php", ".rb",
    ".lua", ".sql", ".html", ".htm", ".css", ".scss", ".xml", ".vue",
    ".svelte", ".swift", ".m", ".mm", ".dart", ".ex", ".exs", ".pl",
    ".r", ".jl", ".vim", ".el", ".gradle", ".cmake", ".mk", ".dockerfile",
}

# ---------------------------------------------------------------- 数据结构


class Finding:
    __slots__ = ("kind", "severity", "line", "col", "cp", "name", "note")

    def __init__(self, kind, severity, line, col, cp, name, note=""):
        self.kind = kind
        self.severity = severity
        self.line = line
        self.col = col
        self.cp = cp
        self.name = name
        self.note = note

    def as_dict(self):
        return {
            "kind": self.kind,
            "severity": self.severity,
            "line": self.line,
            "col": self.col,
            "codepoint": "U+%04X" % self.cp if self.cp is not None else None,
            "name": self.name,
            "note": self.note,
        }


SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def classify(cp):
    """返回 (kind, code_severity, text_severity)."""
    if cp in BIDI:
        return ("BIDI", "critical", "critical")
    if cp in INVISIBLE:
        return ("INVISIBLE", "high", "medium")
    if cp in SPACE_LOOKALIKE:
        return ("SPACE", "high", "medium")
    if cp in QUOTE_LOOKALIKE:
        return ("QUOTE", "high", "low")
    if FW_LO <= cp <= FW_HI:
        return ("FULLWIDTH", "high", "info")
    if cp in CONFUSABLES:
        return ("CONFUSABLE", "critical", "low")
    return (None, None, None)


def decode_bytes(raw):
    """返回 (text, encoding, lossy)."""
    for enc in ("utf-8-sig", "utf-8"):
        try:
            txt = raw.decode(enc)
            return (txt, "utf-8", False)
        except UnicodeDecodeError:
            continue
    try:
        return (raw.decode("gb18030"), "gb18030", False)
    except UnicodeDecodeError:
        pass  # guard:ignore 落到 latin-1 兜底，下面 return
    return (raw.decode("latin-1"), "latin-1", True)


def detect_mode(path, forced):
    if forced != "auto":
        return forced
    ext = path.suffix.lower()
    if ext in TEXT_EXTS:
        return "text"
    if ext in CODE_EXTS:
        return "code"
    return "text"


# ---------------------------------------------------------------- 词法遮罩

HASH_LANGS = {".py", ".sh", ".bash", ".yaml", ".yml", ".toml", ".rb", ".pl",
              ".r", ".ps1", ".ini", ".cfg", ".conf", ".mk"}
SLASH_LANGS = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".c", ".h",
               ".cc", ".cpp", ".cxx", ".hpp", ".java", ".kt", ".rs", ".cs",
               ".swift", ".php", ".scala", ".m", ".mm", ".dart"}

MASK_CODE = 0
MASK_STRING = 1
MASK_COMMENT = 2


def lex_mask(text, ext):
    """给每个字符标出 代码/字符串/注释。返回与 text 等长的列表。

    只服务一件事：判断某个可疑字符是不是"在注释或字符串里"。
    注释里的全角标点、中文引号是正常中文写作，不该判成代码缺陷；
    而字符串里的零宽空格恰恰是 stealth.js 那类真 bug，必须保留严重度。
    不做完整语法解析，够用即可。
    """
    n = len(text)
    mask = [MASK_CODE] * n
    hash_c = ext in HASH_LANGS
    slash_c = ext in SLASH_LANGS
    i = 0
    state = MASK_CODE
    quote = ""
    while i < n:
        ch = text[i]
        if state == MASK_COMMENT:
            mask[i] = MASK_COMMENT
            if hash_c and ch == chr(10):
                state = MASK_CODE
            elif slash_c and ch == "*" and i + 1 < n and text[i + 1] == "/":
                mask[i + 1] = MASK_COMMENT
                i += 1
                state = MASK_CODE
            i += 1
            continue
        if state == MASK_STRING:
            mask[i] = MASK_STRING
            if ch == chr(92) and i + 1 < n:
                mask[i + 1] = MASK_STRING
                i += 2
                continue
            if ch == quote:
                state = MASK_CODE
            i += 1
            continue
        if hash_c and ch == "#":
            mask[i] = MASK_COMMENT
            state = MASK_COMMENT
            i += 1
            continue
        if slash_c and ch == "/" and i + 1 < n and text[i + 1] in "/*":
            mask[i] = MASK_COMMENT
            mask[i + 1] = MASK_COMMENT
            state = MASK_COMMENT
            i += 2
            continue
        if ch in (chr(34), chr(39), chr(96)):
            q3 = text[i:i + 3]
            if ext == ".py" and q3 in (chr(34) * 3, chr(39) * 3):
                end = text.find(q3, i + 3)
                stop = n if end < 0 else end + 3
                for k in range(i, stop):
                    mask[k] = MASK_COMMENT
                i = stop
                continue
            quote = ch
            mask[i] = MASK_STRING
            state = MASK_STRING
            i += 1
            continue
        i += 1
    return mask


# ---------------------------------------------------------------- 扫描主体


def scan(path, mode):
    raw = path.read_bytes()
    text, enc, lossy = decode_bytes(raw)
    findings = []
    is_code = mode == "code"

    # 换行统计
    crlf = raw.count(b"\r\n")
    bare_lf = raw.count(b"\n") - crlf
    bare_cr = raw.count(b"\r") - crlf
    if crlf and bare_lf:
        findings.append(Finding(
            "MIXED_EOL", "medium", None, None, None,
            "CRLF %d / LF %d" % (crlf, bare_lf),
            "同一文件混用两种换行, diff 与字符串匹配会错位",
        ))
    if bare_cr:
        findings.append(Finding(
            "MIXED_EOL", "medium", None, None, None,
            "bare CR %d" % bare_cr, "老式 Mac 换行, 多数工具不认",
        ))

    # 逐字符扫描
    mask = lex_mask(text, path.suffix.lower()) if is_code else [MASK_CODE] * len(text)
    line = 1
    col = 0
    for idx, ch in enumerate(text):
        if ch == "\n":
            line += 1
            col = 0
            continue
        col += 1
        cp = ord(ch)
        if cp < 128:
            continue
        kind, sev_code, sev_text = classify(cp)
        if kind is None:
            continue
        sev = sev_code if is_code else sev_text
        where = mask[idx] if idx < len(mask) else MASK_CODE
        ctx = ""
        if where == MASK_COMMENT and kind != "BIDI":
            sev = "info"
            ctx = "（在注释/文档字符串内，不影响语法）"
        elif where == MASK_STRING and kind in ("FULLWIDTH", "QUOTE"):
            sev = "info"
            ctx = "（在字符串字面量内，属正文内容）"
        name = unicodedata.name(ch, "UNKNOWN")
        note = ""
        if kind == "INVISIBLE" and cp == 0xFEFF and line == 1 and col == 1:
            sev = "info"
            note = "文件头 BOM, 无害但会破坏 shebang 与首行匹配"
        elif kind == "INVISIBLE" and cp == 0xFEFF:
            note = "行中出现 BOM, 极可能是拼接残留"
        elif kind == "SPACE":
            note = "看起来像普通空格, 但字符串比较与正则不认"
        elif kind == "QUOTE":
            note = "中文输入法带进来的弯引号, 在代码里不是字符串定界符"
        elif kind == "FULLWIDTH":
            note = "全角字符, 代码里会被当非法 token"
        elif kind == "CONFUSABLE":
            note = "上形字冒充 ASCII %r, 标识符看起来一样但不是同一个名字" % CONFUSABLES[cp]
        findings.append(Finding(kind, sev, line, col, cp, name, note + ctx))

    # 缩进混用
    lines = text.split("\n")
    tab_lines = []
    space_lines = []
    for i, ln in enumerate(lines, 1):
        stripped = ln.lstrip(" \t")
        if not stripped:
            continue
        lead = ln[: len(ln) - len(stripped)]
        if not lead:
            continue
        has_tab = "\t" in lead
        has_space = " " in lead
        if has_tab and has_space:
            findings.append(Finding(
                "MIXED_INDENT", "high", i, 1, None, "tab+space 混用缩进",
                "同一行缩进同时含 tab 与空格",
            ))
        elif has_tab:
            tab_lines.append(i)
        elif has_space:
            space_lines.append(i)
    if tab_lines and space_lines:
        findings.append(Finding(
            "MIXED_INDENT", "medium", tab_lines[0], 1, None,
            "tab 缩进 %d 行 / space 缩进 %d 行" % (len(tab_lines), len(space_lines)),
            "文件级缩进风格不一致, 首个 tab 缩进行见 line 字段",
        ))

    # 控制字符 (C0 除 tab/CR/LF)
    for i, ln in enumerate(lines, 1):
        for j, ch in enumerate(ln, 1):
            cp = ord(ch)
            if cp < 32 and cp not in (9, 10, 13):
                findings.append(Finding(
                    "CTRL", "high", i, j, cp,
                    unicodedata.name(ch, "CONTROL"),
                    "原始控制字符, 会破坏终端与日志",
                ))

    findings.sort(key=lambda f: (-SEV_ORDER.get(f.severity, 0), f.line or 0, f.col or 0))
    return {
        "path": str(path),
        "mode": mode,
        "encoding": enc,
        "lossy_decode": lossy,
        "bytes": len(raw),
        "lines": len(lines),
        "findings": findings,
    }


def summarize(findings, strict):
    worst = "info"
    for f in findings:
        if SEV_ORDER.get(f.severity, 0) > SEV_ORDER.get(worst, 0):
            worst = f.severity
    if worst in ("critical", "high"):
        return "FAIL"
    if worst == "medium":
        return "FAIL" if strict else "WARN"
    return "OK"


# ---------------------------------------------------------------- 修复


def repair_text(text, mode, fix_confusables):
    """返回 (new_text, changed_count). 只做确定性映射."""
    out = []
    changed = 0
    is_code = mode == "code"
    for ch in text:
        cp = ord(ch)
        if cp < 128:
            out.append(ch)
            continue
        repl = None
        if cp in BIDI:
            repl = ""
        elif cp in INVISIBLE:
            repl = "" if cp != 0x00AD else ""
        elif cp in SPACE_LOOKALIKE:
            repl = " "
        elif cp in QUOTE_LOOKALIKE and is_code:
            repl = QUOTE_LOOKALIKE[cp][1]
        elif FW_LO <= cp <= FW_HI and is_code:
            repl = chr(cp - 0xFEE0)
        elif cp == 0x3000 and is_code:
            repl = " "
        elif cp in CONFUSABLES and fix_confusables:
            repl = CONFUSABLES[cp]
        if repl is None:
            out.append(ch)
        else:
            out.append(repl)
            changed += 1
    return ("".join(out), changed)


# ---------------------------------------------------------------- 输出


def print_report(rep, strict, verbose):
    print("path     %s" % rep["path"])
    print("mode     %s   encoding %s%s   %d bytes / %d lines" % (
        rep["mode"], rep["encoding"],
        "  (LOSSY DECODE)" if rep["lossy_decode"] else "",
        rep["bytes"], rep["lines"],
    ))
    verdict = summarize(rep["findings"], strict)
    print("verdict  %s" % verdict)
    if rep["lossy_decode"]:
        print("  [FAIL] DECODE  字节无法按 utf-8/gb18030 解码, 已按 latin-1 兜底; 用 enc_audit.py 定编码")
    shown = 0
    for f in rep["findings"]:
        if not verbose and f.severity in ("low", "info"):
            continue
        loc = ""
        if f.line is not None:
            loc = " L%d" % f.line
            if f.col:
                loc += ":%d" % f.col
        cp = (" %s" % ("U+%04X" % f.cp)) if f.cp is not None else ""
        print("  [%-8s] %-12s%s%s  %s" % (f.severity.upper(), f.kind, loc, cp, f.name))
        if f.note:
            print("             %s" % f.note)
        shown += 1
    hidden = len(rep["findings"]) - shown
    if hidden > 0:
        print("  ... %d 条 low/info 已折叠 (--verbose 展开)" % hidden)
    if not rep["findings"]:
        print("  无异常字符")
    return verdict


def main(argv=None):
    ap = argparse.ArgumentParser(description="不可见字符/上形字/全角标点/混合换行审计")
    ap.add_argument("paths", nargs="*", help="待审计文件")
    ap.add_argument("--recursive", metavar="DIR", help="递归目录")
    ap.add_argument("--mode", choices=["code", "text", "auto"], default="auto")
    ap.add_argument("--fix", action="store_true", help="清理不可见/双向/空格/全角/引号")
    ap.add_argument("--fix-confusables", action="store_true", help="连同上形字一起改写(有语义风险)")
    ap.add_argument("--strict", action="store_true", help="medium 也判 FAIL")
    ap.add_argument("--verbose", action="store_true", help="展开 low/info")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--max-bytes", type=int, default=8 * 1024 * 1024)
    args = ap.parse_args(argv)

    targets = [pathlib.Path(p) for p in args.paths]
    if args.recursive:
        root = pathlib.Path(args.recursive)
        if not root.is_dir():
            print("not a directory: %s" % root, file=sys.stderr)
            return 2
        targets.extend(sorted(p for p in root.rglob("*") if p.is_file()))

    if not targets:
        print("no input files", file=sys.stderr)
        return 2

    reports = []
    verdicts = []
    for p in targets:
        if not p.is_file():
            print("skip (not a file): %s" % p, file=sys.stderr)
            continue
        if p.stat().st_size > args.max_bytes:
            print("skip (over %d bytes): %s" % (args.max_bytes, p), file=sys.stderr)
            continue
        mode = detect_mode(p, args.mode)
        rep = scan(p, mode)
        if args.fix:
            raw = p.read_bytes()
            text, enc, lossy = decode_bytes(raw)
            new_text, changed = repair_text(text, mode, args.fix_confusables)
            if changed and not lossy:
                bak = p.with_suffix(p.suffix + ".bak")
                shutil.copy2(p, bak)
                with open(p, "wb") as fh:
                    fh.write(new_text.encode("utf-8"))
                rep = scan(p, mode)
                rep["fixed_chars"] = changed
                rep["backup"] = str(bak)
            elif lossy:
                rep["fix_skipped"] = "有损解码, 拒绝改写"
            else:
                rep["fix_skipped"] = "无可安全清理的字符"
        reports.append(rep)
        verdicts.append(summarize(rep["findings"], args.strict))

    if args.json:
        payload = {
            "reports": [
                dict(r, findings=[f.as_dict() for f in r["findings"]],
                     verdict=summarize(r["findings"], args.strict))
                for r in reports
            ]
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        for i, rep in enumerate(reports):
            if i:
                print()
            v = print_report(rep, args.strict, args.verbose)
            if rep.get("fixed_chars"):
                print("  [FIXED] 改写 %d 个字符, 备份 %s" % (rep["fixed_chars"], rep["backup"]))
            elif rep.get("fix_skipped"):
                print("  [SKIP-FIX] %s" % rep["fix_skipped"])

    if "FAIL" in verdicts:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
