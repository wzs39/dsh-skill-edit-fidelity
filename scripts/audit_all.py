#!/usr/bin/env python3
"""audit_all.py - 一次跑完四道闸, 输出统一判定.

用法:
    python audit_all.py FILE
    python audit_all.py FILE --before OLD.py
    python audit_all.py FILE --strict --json
    python audit_all.py FILE --only char,enc
    python audit_all.py FILE --skip deps

四道闸:
    1 char   char_audit.py   不可见字符 / 上形字 / 全角标点 / 混合换行缩进
    2 enc    enc_audit.py    编码判定 / 二次编码 / 不可逆替换符
    3 guard  edit_guard.py   语法 / 括号 / 截断 / 漏定义 / 占位符 / 重复块
    4 deps   dep_check.py    import 能否真正解析

退出码: 0 全通过, 1 有闸失败, 2 参数或 IO 错误.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass  # guard:ignore 老 Python 无 reconfigure，忽略即可

HERE = pathlib.Path(__file__).resolve().parent

# name -> (script, extra args builder, exit code meaning)
STAGES = ["char", "enc", "guard", "deps"]

CODE_MEANING = {
    "char":  {0: "PASS", 1: "FAIL"},
    "enc":   {0: "PASS", 1: "ACTION"},
    "guard": {0: "PASS", 1: "FAIL"},
    "deps":  {0: "PASS", 1: "MISSING"},
    "bytes": {0: "PASS", 1: "MISMATCH"},
}


def run(script, argv, timeout=180):
    cmd = [sys.executable, str(HERE / script)] + argv
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return (None, "TIMEOUT after %ds" % timeout)
    out = proc.stdout.decode("utf-8", "replace")
    return (proc.returncode, out)


def classify(stage, code):
    if code is None:
        return "ERROR"
    table = CODE_MEANING.get(stage, {0: "PASS", 1: "FAIL"})
    if code == 2:
        return "ERROR"
    return table.get(code, "FAIL" if code else "PASS")


def build_args(stage, target, args):
    t = str(target)
    if stage == "char":
        a = [t, "--mode", args.char_mode]
        if args.strict:
            a.append("--strict")
        return a
    if stage == "enc":
        return [t]
    if stage == "guard":
        a = [t]
        if args.before:
            a += ["--before", args.before]
        if args.script_body:
            a.append("--script-body")
        if args.strict:
            a.append("--strict")
        return a
    if stage == "deps":
        return [t]
    return [t]


def main(argv=None):
    ap = argparse.ArgumentParser(description="编辑保真四道闸聚合")
    ap.add_argument("path", help="待审计文件")
    ap.add_argument("--before", help="改动前的版本, 供 LOST_DEF/SHRINK 对比")
    ap.add_argument("--char-mode", choices=["code", "text", "auto"], default="auto")
    ap.add_argument("--only", help="只跑指定闸, 逗号分隔: char,enc,guard,deps")
    ap.add_argument("--skip", help="跳过指定闸, 逗号分隔")
    ap.add_argument("--script-body", action="store_true",
                    help="按函数体校验 JS（workflow 脚本顶层有 return，直接 node --check 会报 Illegal return）")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--quiet", action="store_true", help="只打印汇总, 不打印各闸明细")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    target = pathlib.Path(args.path)
    if not target.is_file():
        print("not a file: %s" % target, file=sys.stderr)
        return 2

    selected = list(STAGES)
    if args.only:
        want = [s.strip() for s in args.only.split(",") if s.strip()]
        bad = [s for s in want if s not in STAGES]
        if bad:
            print("unknown stage(s): %s" % ", ".join(bad), file=sys.stderr)
            return 2
        selected = want
    if args.skip:
        drop = {s.strip() for s in args.skip.split(",") if s.strip()}
        selected = [s for s in selected if s not in drop]

    script_map = {
        "char": "char_audit.py",
        "enc": "enc_audit.py",
        "guard": "edit_guard.py",
        "deps": "dep_check.py",
    }

    results = []
    for stage in selected:
        script = script_map[stage]
        if not (HERE / script).is_file():
            results.append({"stage": stage, "status": "MISSING-SCRIPT",
                            "code": None, "output": script + " 不存在"})
            continue
        code, out = run(script, build_args(stage, target, args))
        results.append({
            "stage": stage,
            "status": classify(stage, code),
            "code": code,
            "output": out,
        })

    bad = [r for r in results if r["status"] not in ("PASS",)]
    verdict = "PASS" if not bad else "FAIL"

    if args.json:
        print(json.dumps({
            "path": str(target),
            "verdict": verdict,
            "stages": [
                {"stage": r["stage"], "status": r["status"], "code": r["code"],
                 "output": r["output"] if not args.quiet else None}
                for r in results
            ],
        }, ensure_ascii=False, indent=2))
    else:
        print("path     %s" % target)
        print("verdict  %s" % verdict)
        width = max(len(s) for s in selected) if selected else 4
        for i, r in enumerate(results, 1):
            mark = "ok " if r["status"] == "PASS" else "!! "
            print("  %s[%d/%d] %-*s %s" % (
                mark, i, len(results), width, r["stage"], r["status"]))
        if bad and not args.quiet:
            for r in bad:
                print()
                print("--- %s (%s) ---" % (r["stage"], r["status"]))
                for line in r["output"].rstrip().splitlines():
                    print("    " + line)

    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
