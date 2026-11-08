#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghidra_decomp.py — headless-декомпиляция через Ghidra (без GUI).

  python ghidra_decomp.py bin               # все функции в C-подобном виде
  python ghidra_decomp.py bin --grep main   # только строки/функции с main
  python ghidra_decomp.py bin --out out.c
  python ghidra_decomp.py bin --timeout 300

Ghidra ищется: $GHIDRA_HOME, F:\\dev\\ghidra_*, C:\\Users\\...\\tools\\ghidra_*.
Нужна Java (Ghidra 12.x требует JDK 21; 11.x — 17).
"""
from __future__ import annotations

try:
    import sys as _sys
    for _stream in (_sys.stdout, _sys.stderr):
        _stream.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import argparse
import glob
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(HERE, "ghidra_scripts")
sys.path.insert(0, os.path.dirname(HERE))
import common  # noqa: E402


def find_ghidra():
    cands = []
    env = os.environ.get("GHIDRA_HOME")
    if env:
        cands.append(env)
    cands += glob.glob(r"F:\dev\ghidra_*\ghidra_*")
    cands += glob.glob(r"F:\dev\ghidra_*")
    cands += glob.glob(r"C:\Users\nispa\.vscode\AIproject\tools\ghidra_*")
    for c in cands:
        for sub in (c, os.path.join(c, "support")):
            headless = os.path.join(sub, "analyzeHeadless.bat")
            if os.path.exists(headless):
                return headless
    return None


def find_jdk(min_major=25):
    """JDK >= min_major из F:\\dev или JAVA_HOME (Ghidra 12.2 требует 25)."""
    cands = []
    if os.environ.get("GHIDRA_JDK"):
        cands.append(os.environ["GHIDRA_JDK"])
    if os.environ.get("JAVA_HOME"):
        cands.append(os.environ["JAVA_HOME"])
    cands += glob.glob(r"F:\dev\jdk*\*")
    cands += glob.glob(r"F:\dev\jdk*")
    cands += glob.glob(r"C:\Program Files\Eclipse Adoptium\jdk*")
    best = None
    for c in cands:
        binp = os.path.join(c, "bin", "java.exe")
        if not os.path.exists(binp):
            continue
        m = re.search(r"jdk[-_]?(\d+)", os.path.basename(c), re.I)
        major = int(m.group(1)) if m else 0
        if major >= min_major and (best is None or major > best[0]):
            best = (major, c)
    return best[1] if best else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--grep", help="показывать только блоки, где встречается regex")
    ap.add_argument("--out", help="сохранить весь вывод декомпиляции в файл")
    ap.add_argument("--timeout", type=float, default=300)
    ap.add_argument("--keep-project", action="store_true")
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)

    headless = find_ghidra()
    if not headless:
        print("[-] Ghidra не найдена. Поставить: распаковать в F:\\dev\\ghidra_<ver>")
        print("    и/или задать GHIDRA_HOME. Нужна Java 21 для 12.x.")
        return

    proj = tempfile.mkdtemp(prefix="ghidra_proj_")
    name = "ctf"
    cmd = [headless, proj, name, "-import", os.path.abspath(args.file),
           "-postScript", "DumpDecomp.java",
           "-scriptPath", SCRIPTS,
           "-analysisTimeoutPerFile", "180"]
    if not args.keep_project:
        cmd.append("-deleteProject")
    print("[+] ghidra:", headless)
    jdk = find_jdk(25)
    env = dict(os.environ)
    if jdk:
        env["JAVA_HOME"] = jdk
        env["PATH"] = os.path.join(jdk, "bin") + os.pathsep + env.get("PATH", "")
        print("[+] java:", jdk)
    else:
        print("[i] JDK 25 не найден — Ghidra может отказаться запускаться")
    print("[+] анализ идёт (может занять минуту-две)…", flush=True)
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=args.timeout, env=env,
                           text=True, encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        print("[-] таймаут Ghidra")
        shutil.rmtree(proj, ignore_errors=True)
        return
    out = (r.stdout or "") + (r.stderr or "")
    # убрать служебный шум GhidraScript
    out = re.sub(r"(?m)^\(GhidraScript\)\s*$\n?", "", out)
    out = re.sub(r"(?m)^INFO\s+DumpDecomp\.java>\s?", "", out)
    out = re.sub(r"(?m)^\s*$\n(?=/\* ====)", "", out)
    if "ERROR" in out and "Decompiler" not in out and "/* ====" not in out:
        print("[-] Ghidra вернула ошибку (первые строки):")
        for line in out.splitlines()[:15]:
            print("   ", line[-200:])

    if "/* ====" not in out:
        print("[-] декомпиляция не дала функций")
        for line in out.splitlines()[-10:]:
            print("   ", line[-200:])
        shutil.rmtree(proj, ignore_errors=True)
        return

    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"[+] сохранено: {args.out}")

    # печатаем только блоки функций, при необходимости фильтруем
    blocks = re.split(r"(?=/\* ==== )", out)
    printed = 0
    for block in blocks:
        if not block.startswith("/* ===="):
            continue
        if args.grep and not re.search(args.grep, block, re.I):
            continue
        print(block.rstrip()[:6000])
        print()
        printed += 1
        if printed >= 60:
            print("... (дальше в --out)")
            break
    if printed == 0:
        print("[-] под фильтр ничего не попало; смотри без --grep или в --out")
    shutil.rmtree(proj, ignore_errors=True)


if __name__ == "__main__":
    main()
