#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghidra_decomp.py — headless-декомпиляция через Ghidra (без GUI).

  python ghidra_decomp.py bin               # все функции в C-подобном виде
  python ghidra_decomp.py bin --grep main   # только строки/функции с main
  python ghidra_decomp.py bin --out out.c
  python ghidra_decomp.py bin --timeout 300   # по таймауту гасится всё дерево процессов
  python ghidra_decomp.py bin --keep-project  # не удалять проект, путь печатается

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
import secrets
import shutil
import signal
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


# analyzeHeadless.bat получает аргументы через cmd.exe: имя файла вида
# «a&ver&.bin» выполнило бы команду. Поэтому имя пользователя в командную
# строку не попадает вообще (анализируется копия со случайным именем), а все
# остальные аргументы проверяются на метасимволы cmd.
CMD_META = set('&|<>^%!"()\r\n')


def cmd_safe(arg: str) -> bool:
    return not any(c in CMD_META for c in arg)


def stage_input(src: str, work: str) -> str:
    """Копия входного файла в work под именем input_<hex><ext>."""
    ext = os.path.splitext(src)[1]
    if not re.fullmatch(r"\.[A-Za-z0-9]{1,8}", ext):
        ext = ".bin"
    dst = os.path.join(work, f"input_{secrets.token_hex(8)}{ext}")
    shutil.copyfile(src, dst)
    return dst


def build_cmd(headless: str, proj: str, name: str, binary: str,
              keep_project: bool = False) -> list[str]:
    """Командная строка analyzeHeadless; ValueError, если аргумент опасен для cmd."""
    cmd = [headless, proj, name, "-import", binary,
           "-postScript", "DumpDecomp.java",
           "-scriptPath", SCRIPTS,
           "-analysisTimeoutPerFile", "180"]
    if not keep_project:
        cmd.append("-deleteProject")
    for arg in cmd:
        if not cmd_safe(arg):
            raise ValueError("метасимволы cmd.exe (&|<>^%!\"()) в аргументе: " + arg)
    return cmd


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

    src = os.path.abspath(args.file)
    if not os.path.isfile(src):
        print(f"[-] не могу открыть: {args.file}")
        return
    proj = tempfile.mkdtemp(prefix="ghidra_proj_")
    try:
        cmd = build_cmd(headless, proj, "ctf", stage_input(src, proj), args.keep_project)
    except (OSError, ValueError) as e:
        print(f"[-] {e}")
        print("    TEMP/TMP и путь к Ghidra/репозиторию должны быть без &|<>^%!\"()")
        shutil.rmtree(proj, ignore_errors=True)
        return
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
        out, timed_out = run_headless(cmd, args.timeout, env)
        if timed_out:
            print(f"[-] таймаут Ghidra ({args.timeout:g} с): процесс и его потомки остановлены")
        else:
            show(out, args)
    finally:
        if args.keep_project:
            print(f"[+] проект Ghidra сохранён: {proj}")
        else:
            shutil.rmtree(proj, ignore_errors=True)


def kill_tree(proc):
    """Убить процесс вместе с потомками: .bat -> cmd.exe -> java держат pipe открытым."""
    if os.name == "nt":
        taskkill = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                                "System32", "taskkill.exe")
        try:
            subprocess.run([taskkill, "/T", "/F", "/PID", str(proc.pid)],
                           capture_output=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            pass
    else:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (OSError, AttributeError):
            pass
    try:
        proc.kill()
    except OSError:
        pass


def run_headless(cmd, timeout, env):
    """(вывод, был_ли_таймаут). По таймауту гасится всё дерево процессов, а не
    только cmd.exe: иначе java держит stdout и communicate() ждёт её до конца."""
    kw = {} if os.name == "nt" else {"start_new_session": True}
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
                            text=True, encoding="utf-8", errors="replace", **kw)
    try:
        out, err = proc.communicate(timeout=timeout)
        return (out or "") + (err or ""), False
    except subprocess.TimeoutExpired:
        kill_tree(proc)
        try:
            out, err = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            out, err = "", ""
        return (out or "") + (err or ""), True


def show(out, args):
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


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
    except KeyboardInterrupt:
        print("\n[-] прервано")
