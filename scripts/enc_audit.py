#!/usr/bin/env python3
"""enc_audit.py - 中文/多语言编码体检与转换。

判定顺序（先强证据，后弱猜测）：
  1. BOM（UTF-32 先于 UTF-16，因为 UTF-32LE 的 BOM 以 FF FE 开头）
  2. 大量 NUL 字节 -> UTF-16/32 无 BOM
  3. 严格 UTF-8 解码成功 -> utf-8（UTF-8 校验很严，几乎不会误判）
  4. 严格失败 -> 试 GB18030，并用 CJK 占比确认不是"随便什么字节都能解"
  5. 全失败 -> unknown / binary

另外检测 mojibake（二次编码）：UTF-8 字节被当 latin-1/GBK 解过一遍再存，
文本会出现 "锟斤拷"、大量 U+00C0-U+00FF 连续字符、"ä¸­æ–‡" 这类形态。

本文件需要反斜杠字符时用 chr(92)，避免自身被转义层破坏。

用法：
  python enc_audit.py PATH [PATH ...]
  python enc_audit.py PATH --json
  python enc_audit.py PATH --fix                  # 转 UTF-8 无 BOM，留 .bak
  python enc_audit.py PATH --repair-mojibake      # 尝试还原二次编码
  python enc_audit.py DIR --recursive

退出码：0 全部已是 UTF-8 且无 mojibake；1 有文件需要处理；2 用法/IO 错误。
"""
import argparse
import hashlib
import json
import pathlib
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

BOM_TABLE = [
    (bytes([0xFF, 0xFE, 0x00, 0x00]), "utf-32-le"),
    (bytes([0x00, 0x00, 0xFE, 0xFF]), "utf-32-be"),
    (bytes([0xEF, 0xBB, 0xBF]), "utf-8-sig"),
    (bytes([0xFF, 0xFE]), "utf-16-le"),
    (bytes([0xFE, 0xFF]), "utf-16-be"),
]

def _latin1(bs):
    """把 UTF-8 字节按 latin-1 解出来，得到"被误解一次"的样本。

    这样写而不是直接贴字面量：这些样本里含软连字符、en dash 等不可见字符，
    源码里就不该出现它们（本技能自己的规矩）。
    """
    return bytes(bs).decode("latin-1")


MOJIBAKE_MARKERS = [
    "锟斤拷",                        # GBK 替换符被当 UTF-8 解
    "烫烫烫",                        # MSVC 未初始化栈填充
    _latin1([0xEF, 0xBF, 0xBD]),      # UTF-8 的 U+FFFD 被当 latin-1
    _latin1([0xC3, 0xA4]),            # ä
    _latin1([0xC3, 0xA5]),            # å
    _latin1([0xC3, 0xA9]),            # é
    _latin1([0xE4, 0xB8, 0xAD]),      # 中
    _latin1([0xE6, 0x96, 0x87]),      # 文
]

SCAN_EXTS = {
    ".py", ".js", ".mjs", ".cjs", ".ts", ".json", ".md", ".txt", ".yml", ".yaml",
    ".toml", ".ini", ".cfg", ".sh", ".bat", ".ps1", ".html", ".css", ".sql",
}


def cjk_ratio(text):
    if not text:
        return 0.0
    cjk = 0
    non_ascii = 0
    for ch in text:
        o = ord(ch)
        if o < 128:
            continue
        non_ascii += 1
        if (0x4E00 <= o <= 0x9FFF) or (0x3400 <= o <= 0x4DBF) or (0x3000 <= o <= 0x303F) or (0xFF00 <= o <= 0xFFEF):
            cjk += 1
    return (cjk / non_ascii) if non_ascii else 0.0


def nul_ratio(raw):
    if not raw:
        return 0.0
    return raw.count(0) / len(raw)


def try_decode(raw, codec):
    try:
        return raw.decode(codec), None
    except UnicodeDecodeError as e:
        return None, str(e)[:120]


def detect(raw):
    """返回 dict(codec, confidence, reason, convertible)"""
    for bom, codec in BOM_TABLE:
        if raw.startswith(bom):
            return {"codec": codec, "confidence": "certain", "reason": "BOM " + codec, "convertible": True}

    nr = nul_ratio(raw)
    if nr > 0.15:
        for codec in ("utf-16-le", "utf-16-be"):
            text, err = try_decode(raw, codec)
            if text is not None:
                return {"codec": codec, "confidence": "high", "reason": "NUL 占比 " + str(round(nr, 2)) + "，按 " + codec + " 可解", "convertible": True}
        return {"codec": "binary", "confidence": "low", "reason": "NUL 占比高且非 UTF-16", "convertible": False}

    text, err = try_decode(raw, "utf-8")
    if text is not None:
        conf = "certain" if any(ord(c) > 127 for c in text) else "certain-ascii"
        return {"codec": "utf-8", "confidence": conf, "reason": "严格 UTF-8 通过", "convertible": True}

    text, err = try_decode(raw, "gb18030")
    if text is not None:
        r = cjk_ratio(text)
        if r >= 0.5:
            return {"codec": "gb18030", "confidence": "high", "reason": "UTF-8 失败、GB18030 通过且 CJK 占比 " + str(round(r, 2)), "convertible": True}
        return {"codec": "gb18030?", "confidence": "low", "reason": "GB18030 可解但 CJK 占比仅 " + str(round(r, 2)) + "，可能是任意字节", "convertible": False}

    return {"codec": "unknown", "confidence": "low", "reason": "UTF-8 与 GB18030 均失败：" + str(err), "convertible": False}


BRIDGES = ("latin-1", "cp1252")
TARGETS = ("utf-8", "gb18030")


def best_repair(text):
    """自检式 mojibake 判定：尝试"误解桥接"的逆向，看中文可读性是否显著回升。

    真正的二次编码，逆向之后 CJK 占比会明显上升；正常中文经这些桥接多半直接
    UnicodeEncodeError，或解出的结果 CJK 占比更低。所以这是判据，不是猜。
    返回 (repaired_text, ratio, bridge, target) 或 None。
    """
    base = cjk_ratio(text)
    best = None
    for br in BRIDGES:
        try:
            raw = text.encode(br)
        except (UnicodeEncodeError, LookupError):
            continue
        for tgt in TARGETS:
            back, err = try_decode(raw, tgt)
            if back is None:
                continue
            r = cjk_ratio(back)
            if r >= 0.5 and r > base + 0.10:
                if best is None or r > best[1]:
                    best = (back, r, br, tgt)
    return best


IGNORE_LINE = "enc:ignore"
IGNORE_FILE = "enc:ignore-file"


def strip_ignored(text):
    """去掉带 enc:ignore 的行；整文件带 enc:ignore-file 时返回空串。

    用途：文档、测试夹具、i18n 资源表会合法地包含 mojibake 样本字符串，
    否则检查器会把"举例说明乱码"的文档本身判成乱码。
    """
    if IGNORE_FILE in text:
        return ""
    kept = [ln for ln in text.split(chr(10)) if IGNORE_LINE not in ln]
    return chr(10).join(kept)


def mojibake_score(text):
    """返回 (is_mojibake, reason, repaired_or_None)。"""
    scan = strip_ignored(text)
    if chr(0xFFFD) in scan:
        return True, "含 U+FFFD 替换符：字节已在解码时丢失，不可逆（需从源头重取）", None
    hits = [m for m in MOJIBAKE_MARKERS if m in scan]
    rep = best_repair(scan)
    if rep:
        back, r, br, tgt = rep
        return True, "CJK 占比 " + str(round(cjk_ratio(text), 2)) + " -> " + str(round(r, 2)) + "（" + br + " 解、" + tgt + " 读）", back
    if hits:
        return True, "命中标记 " + ", ".join(hits[:3]) + "（不可逆，需从源头重取）", None
    return False, "", None


def repair_mojibake(text):
    """返回 (new_text, note)。已被 best_repair 覆盖的桥接，这里复用它。"""
    rep = best_repair(text)
    if rep:
        back, r, br, tgt = rep
        return back, "经 " + br + " 解、" + tgt + " 读还原"
    return text, "无改善（不可逆，需从源头重取）"


def analyze(path, max_bytes):
    raw = path.read_bytes()
    partial = False
    if len(raw) > max_bytes:
        raw = raw[:max_bytes]
        partial = True
    info = detect(raw)
    text = None
    if info["convertible"]:
        codec = info["codec"].replace("-sig", "")
        text, _ = try_decode(raw, codec)
    moji, moji_why, moji_fix = (False, "", None)
    if text:
        moji, moji_why, moji_fix = mojibake_score(text)
    return {
        "path": str(path),
        "bytes": path.stat().st_size,
        "scanned": len(raw),
        "partial": partial,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "codec": info["codec"],
        "confidence": info["confidence"],
        "reason": info["reason"],
        "convertible": info["convertible"],
        "mojibake": moji,
        "mojibake_reason": moji_why,
        "mojibake_repairable": moji_fix is not None,
        "has_crlf": chr(13).encode() in raw,
        "has_bom": raw[:3] == bytes([0xEF, 0xBB, 0xBF]) or raw[:2] in (bytes([0xFF, 0xFE]), bytes([0xFE, 0xFF])),
    }


def do_fix(path, rec, repair):
    raw = path.read_bytes()
    codec = rec["codec"].replace("-sig", "")
    if not rec["convertible"]:
        return False, "不可转换（" + rec["codec"] + "）"
    text, err = try_decode(raw, codec)
    if text is None:
        return False, "解码失败：" + str(err)
    note = ""
    if repair and rec["mojibake"]:
        text, note = repair_mojibake(text)
    if text.startswith("\ufeff"):
        text = text[1:]
    out = text.encode("utf-8")
    bak = path.with_name(path.name + ".bak")
    if not bak.exists():
        bak.write_bytes(raw)
    path.write_bytes(out)
    return True, "已转 UTF-8 无 BOM" + (("；" + note) if note else "") + "；备份 " + bak.name


def collect(paths, recursive):
    out = []
    for p in paths:
        path = pathlib.Path(p)
        if path.is_dir():
            it = path.rglob("*") if recursive else path.glob("*")
            out += [x for x in it if x.is_file() and x.suffix.lower() in SCAN_EXTS]
        elif path.is_file():
            out.append(path)
        else:
            print("ERROR not found: " + p, file=sys.stderr)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--recursive", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fix", action="store_true")
    ap.add_argument("--repair-mojibake", action="store_true")
    ap.add_argument("--max-bytes", type=int, default=16 * 1024 * 1024)
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()

    files = collect(a.paths, a.recursive)
    if not files:
        print("no files matched", file=sys.stderr)
        return 2

    results = []
    need_action = 0
    for path in files:
        rec = analyze(path, a.max_bytes)
        rec["action"] = ""
        bad = (rec["codec"] not in ("utf-8", "utf-8-sig", "certain-ascii", "ascii")) or rec["mojibake"]
        if rec["codec"] == "utf-8" and rec["confidence"] == "certain":
            bad = rec["mojibake"]
        if rec["codec"] == "utf-8-sig":
            bad = True
        if bad:
            need_action += 1
            if a.fix:
                ok, msg = do_fix(path, rec, a.repair_mojibake)
                rec["action"] = ("FIXED: " if ok else "SKIP: ") + msg
                if ok:
                    need_action -= 1
                    bad = False
        rec["needs_action"] = bad
        results.append(rec)

    if a.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
        return 1 if need_action else 0

    for r in results:
        flag = "!! " if r.get("needs_action") else "OK "
        line = flag + r["codec"].ljust(10) + r["confidence"].ljust(16) + r["path"]
        if r["has_crlf"]:
            line += "  [CRLF]"
        if r["has_bom"]:
            line += "  [BOM]"
        if r["partial"]:
            line += "  [partial]"
        if r["mojibake"]:
            line += "  [mojibake: " + r["mojibake_reason"] + "]"
        if r["action"]:
            line += "  -> " + r["action"]
        if not a.quiet or r["action"]:
            print(line)

    if need_action:
        print(chr(10) + str(need_action) + " 个文件需要处理：加 --fix 转 UTF-8 无 BOM（自动留 .bak）", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
