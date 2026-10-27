#!/usr/bin/env python3
"""enc_env.py - 中文乱码的环境诊断：到底是"文件坏了"还是"显示层坏了"。

实测结论（Windows + DSH 管道）：
  - 控制台代码页常是 936(GBK)，Python 在管道里默认用 gbk 编码输出；
  - 上层按 UTF-8 解码，于是中文全乱；
  - 进程内把 stdout 切成 UTF-8 就正常。

用法：
  python enc_env.py                    # 打印环境与判定
  python enc_env.py --scan DIR         # 检查目录下 .py 是否都做了 UTF-8 输出修正
"""
import argparse
import io
import locale
import os
import pathlib
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def console_cp():
    try:
        import ctypes

        return ctypes.windll.kernel32.GetConsoleOutputCP()
    except Exception:
        return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scan")
    a = ap.parse_args()

    cp = console_cp()
    print("console code page   =", cp, "(936=GBK, 65001=UTF-8)" if cp else "")
    print("stdout.encoding     =", sys.stdout.encoding)
    print("stdout.isatty       =", sys.stdout.isatty())
    print("preferred encoding  =", locale.getpreferredencoding(False))
    print("fs encoding         =", sys.getfilesystemencoding())
    print("PYTHONIOENCODING    =", os.environ.get("PYTHONIOENCODING"))
    print("PYTHONUTF8          =", os.environ.get("PYTHONUTF8"))
    print("LANG / LC_ALL       =", os.environ.get("LANG"), "/", os.environ.get("LC_ALL"))

    print()
    ok = (sys.stdout.encoding or "").lower().replace("-", "") in ("utf8",)
    print("当前进程输出判定    =", "UTF-8 正常" if ok else "非 UTF-8，中文会乱码")
    print()
    print("修法（按优先级）：")
    print("  1. 脚本开头：sys.stdout.reconfigure(encoding='utf-8', errors='replace')")
    print("  2. 环境变量：PYTHONUTF8=1（或 PYTHONIOENCODING=utf-8）")
    print("  3. 会话级：chcp 65001（只影响该控制台，不影响文件编码）")
    print("  4. 文件本身不是 UTF-8 时，用 enc_audit.py --fix 转换，别靠改代码页硬解")

    if a.scan:
        root = pathlib.Path(a.scan)
        files = sorted(root.rglob("*.py")) if root.is_dir() else [root]
        print()
        print("扫描 " + str(root) + " 下 " + str(len(files)) + " 个 .py：")
        bad = 0
        for f in files:
            try:
                t = f.read_text(encoding="utf-8", errors="replace")
            except OSError as e:
                print("  [IO] " + str(f) + " " + str(e))
                continue
            has = "reconfigure(encoding" in t or "PYTHONUTF8" in t
            if not has and any(ord(c) > 127 for c in t):
                print("  [缺修正] " + str(f))
                bad += 1
        print("  需要修正：" + str(bad))
        return 1 if bad else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
