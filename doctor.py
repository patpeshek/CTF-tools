#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
doctor.py — проверка окружения: что есть, чего нет и что из-за этого
не работает.

  python doctor.py                 # таблица: пакеты, программы, окружение
  python doctor.py --json          # та же информация машинно
  python doctor.py --require pcap  # код 1, если pcap-путь не работает
  python doctor.py --require pcap,video,ocr
  python doctor.py --list          # какие возможности проверяются

Зачем: без этого про отсутствующий scapy/ffmpeg узнаёшь по трейсбеку
посреди задачи. Здесь это видно сразу, с честной пометкой «что деградирует».
Ничего не устанавливает и в сеть не ходит.
"""
from __future__ import annotations

# Windows: консоль/pipe не должны падать на Unicode (—, →, «», █).
try:
    import sys as _sys
    for _stream in (_sys.stdout, _sys.stderr):
        _stream.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import argparse
import glob
import importlib
import importlib.metadata
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
KIT = HERE

# модуль: (дистрибутив, что деградирует без него)
MODULES = {
    "PIL": ("pillow", "картинки и стего: lsb, alpha, gif_frames, qr, bitmap_font, ooxml"),
    "numpy": ("numpy", "звук: спектрограмма, DTMF/морзе, аудио-стего"),
    "Crypto": ("pycryptodome", "блочные шифры: aes, ecb, oracles, hashext, GCM"),
    "scapy": ("scapy", "трафик: pcap, reasm, creds, dns, http, icmp, udp"),
    "requests": ("requests", "веб-пробы: recon, ssti, param, dirfuzz, jwt"),
    "cv2": ("opencv-python-headless", "видео: кадры MP4/GIF, поиск отличий"),
    "pypdf": ("pypdf", "PDF: текст и вложения в doctext"),
    "capstone": ("capstone", "дизасм: disasm, megarev, gadget/поиск констант"),
    "pytesseract": ("pytesseract", "OCR: капчи, скриншоты, кадры видео"),
}

# программа: (аргумент версии, что деградирует без неё)
CLIS = {
    "exiftool": (["-ver"], "метаданные: останется только базовый разбор через PIL"),
    "ffmpeg": (["-version"], "видео: без OpenCV резать кадры нечем"),
    "git": (["--version"], "forensic/git_hunt: история и удалённые файлы"),
    "hashcat": (["--version"], "подбор хешей на GPU (останется john)"),
    "john": (["--version"], "CPU-фолбэк подбора хешей"),
    "tesseract": (["--version"], "OCR: pytesseract без движка бесполезен"),
    "ghidra": (None, "декомпиляция: ghidra_decomp и разбор бинарей"),
}

# возможность: (обязательные ключи, «хотя бы один из»)
CAPABILITIES = {
    "image": ({"PIL": "pillow"}, set()),
    "audio": (set(), {"numpy"}),
    "blocks": ({"Crypto": "pycryptodome"}, set()),
    "pcap": ({"scapy": "scapy"}, set()),
    "web": ({"requests": "requests"}, set()),
    "video": (set(), {"cv2", "ffmpeg"}),
    "pdf": ({"pypdf": "pypdf"}, set()),
    "disasm": ({"capstone": "capstone"}, set()),
    "ocr": ({"pytesseract": "pytesseract", "tesseract": "tesseract"}, set()),
    "hashcat": ({"hashcat": "hashcat"}, set()),
    "exif": (set(), {"exiftool", "PIL"}),
    "ghidra": ({"ghidra": "ghidra"}, set()),
    "wsl": ({"wsl": "wsl", "wsl-distro": "wsl-distro"}, set()),
    "wordlists": ({"wordlists": "wordlists"}, set()),
    "git": ({"git": "git"}, set()),
}


def _first_version_line(text: str) -> str:
    for line in (text or "").splitlines():
        line = line.strip()
        if any(ch.isdigit() for ch in line) and "." in line:
            return line[:70]
    return ""


def _run_version(exe, argv):
    try:
        p = subprocess.run([exe] + argv, capture_output=True, text=True,
                           errors="replace", timeout=8)
    except Exception as exc:
        return "", str(exc)
    return _first_version_line(p.stdout or p.stderr), ""


def _module_version(module, dist):
    try:
        return importlib.metadata.version(dist)
    except Exception:
        pass
    try:
        mod = importlib.import_module(module)
    except Exception:
        return ""
    for attr in ("__version__", "VERSION", "version"):
        val = getattr(mod, attr, None)
        if isinstance(val, str) and val:
            return val
    return "?"


def _wsl_distros():
    """Список дистрибутивов WSL. wsl.exe отдаёт UTF-16 — разбираем аккуратно."""
    try:
        p = subprocess.run(["wsl.exe", "-l", "-q"], capture_output=True, timeout=8)
    except Exception:
        return None
    raw = p.stdout or b""
    if b"\x00" in raw:
        text = raw.decode("utf-16-le", "ignore")
    else:
        text = raw.decode("utf-8", "ignore")
    return [x.strip().strip("\x00") for x in text.splitlines() if x.strip().strip("\x00")]


def _kit_module(rel):
    """Подгрузить модуль кита по пути, не завязываясь на пакеты."""
    import importlib.util

    full = os.path.join(KIT, rel)
    if not os.path.isfile(full):
        return None
    name = "kit_" + os.path.splitext(os.path.basename(full))[0]
    spec = importlib.util.spec_from_file_location(name, full)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    return mod


def _find_tool(exe):
    """Тот же поиск, что и у самих инструментов (PATH + известные каталоги)."""
    if exe in ("hashcat", "john"):
        mod = _kit_module("crypto/hashcat_run.py")
        fn = getattr(mod, f"find_{exe}", None) if mod else None
        if callable(fn):
            try:
                return fn() or shutil.which(exe) or ""
            except Exception:
                pass
    if exe == "tesseract":
        mod = _kit_module("misc/ocr.py")
        fn = getattr(mod, "tesseract_cmd", None) if mod else None
        if callable(fn):
            try:
                return fn() or ""
            except Exception:
                pass
    return shutil.which(exe) or ""


def _find_ghidra():
    env = os.environ.get("GHIDRA_HOME")
    if env and os.path.isdir(env):
        return env
    cands = []
    for pat in (r"F:\dev\ghidra_*", r"C:\Users\*\tools\ghidra_*",
                os.path.join(os.path.expanduser("~"), "ghidra*")):
        cands += [p for p in glob.glob(pat) if os.path.isdir(p)]
    return sorted(cands)[-1] if cands else ""


def _wordlists_dir():
    env = os.environ.get("WORDLISTS_DIR")
    if env and os.path.isdir(env):
        return env
    for cand in (r"F:\dev\wordlists", os.path.join(os.path.expanduser("~"), "wordlists")):
        if os.path.isdir(cand):
            return cand
    return ""


def collect():
    """Список проверок: key, kind, ok, version, degradation, cap."""
    checks = []

    py = ".".join(str(x) for x in sys.version_info[:3])
    checks.append(dict(key="python", kind="base", ok=sys.version_info >= (3, 10),
                       version=py, degradation="нужен Python 3.10+",
                       cap=""))

    for module, (dist, why) in MODULES.items():
        try:
            importlib.import_module(module)
            ok, ver = True, _module_version(module, dist)
        except Exception:
            ok, ver = False, ""
        checks.append(dict(key=module, kind="module", ok=ok, version=ver,
                           degradation=why, cap=module))

    for exe, (argv, why) in CLIS.items():
        if exe == "ghidra":
            path = _find_ghidra()
            checks.append(dict(key="ghidra", kind="cli", ok=bool(path),
                               version=os.path.basename(path) if path else "",
                               degradation=why, cap="ghidra"))
            continue
        found = _find_tool(exe)
        ver = ""
        if found and argv:
            ver, _ = _run_version(found, argv)
        checks.append(dict(key=exe, kind="cli", ok=bool(found), version=ver,
                           degradation=why, cap=exe))

    distros = _wsl_distros()
    checks.append(dict(key="wsl", kind="env", ok=distros is not None,
                       version="", degradation="запуск ELF: linux/wsl.py",
                       cap="wsl"))
    names = [d.lower() for d in (distros or [])]
    checks.append(dict(key="wsl-distro", kind="env", ok="archlinux" in names,
                       version=",".join(distros or [])[:40],
                       degradation="ELF под Linux: Arch WSL (qemu/pwntools/gdb)",
                       cap="wsl"))

    wl = _wordlists_dir()
    files = []
    if wl:
        files = [f for f in os.listdir(wl) if f.lower().endswith(".txt")]
    checks.append(dict(key="wordlists", kind="env", ok=bool(files),
                       version=f"{len(files)} .txt" if files else "",
                       degradation="hashcat/john без словарей (--wordlist auto)",
                       cap="wordlists"))

    # CUDA-DLL рядом с hashcat — не обязательны (hashcat работает и на CPU),
    # поэтому отдельная строка без деградации.
    hc = _find_tool("hashcat")
    if hc:
        dlls = glob.glob(os.path.join(os.path.dirname(hc), "cudart64_*.dll"))
        checks.append(dict(key="cuda-dll", kind="env", ok=bool(dlls),
                           version=os.path.basename(dlls[0]) if dlls else "",
                           degradation="GPU-режим hashcat (без DLL — только CPU)",
                           cap=""))
    return checks


def capability_state(checks):
    by_key = {c["key"]: c["ok"] for c in checks}
    state = {}
    for cap, (need, any_of) in CAPABILITIES.items():
        ok = all(by_key.get(k, False) for k in need)
        if ok and any_of:
            ok = any(by_key.get(k, False) for k in any_of)
        elif not need and any_of:
            ok = any(by_key.get(k, False) for k in any_of)
        state[cap] = ok
    return state


def _print_table(checks, caps, hints=True):
    print(f"[+] Python {'.'.join(str(x) for x in sys.version_info[:3])}"
          f"   кит: {KIT}")
    print("\n[+] пакеты Python")
    for c in checks:
        if c["kind"] != "module":
            continue
        mark = "ok  " if c["ok"] else "НЕТ "
        ver = c["version"] or ""
        line = (f"  {mark} {c['key']:14s} {ver:26s} "
                f"{'' if c['ok'] else '→ ' + c['degradation']}")
        print(line.rstrip())

    print("\n[+] внешние программы")
    for c in checks:
        if c["kind"] != "cli":
            continue
        mark = "ok  " if c["ok"] else "НЕТ "
        line = (f"  {mark} {c['key']:14s} {(c['version'] or '')[:26]:26s} "
                f"{'' if c['ok'] else '→ ' + c['degradation']}")
        print(line.rstrip())

    print("\n[+] окружение")
    for c in checks:
        if c["kind"] != "env":
            continue
        mark = "ok  " if c["ok"] else "НЕТ "
        note = "" if c["ok"] else "→ " + c["degradation"]
        if c["key"] == "cuda-dll" and c["ok"]:
            note = "(GPU-режим hashcat доступен)"
        line = f"  {mark} {c['key']:14s} {(c['version'] or '')[:26]:26s} {note}"
        print(line.rstrip())

    good = [k for k, v in caps.items() if v]
    bad = [k for k, v in caps.items() if not v]
    print(f"\n[=] работает: {', '.join(good) if good else '—'}")
    if bad:
        print(f"[!] деградирует: {', '.join(bad)}")
    missing = [c["key"] for c in checks
               if not c["ok"] and c["kind"] in ("module", "cli")]
    if hints and missing:
        print("\n[i] поставить (по согласованию, не автоматически):")
        mods = [MODULES[k][0] for k in missing if k in MODULES]
        if mods:
            print(f"    pip install {' '.join(mods)}")
        clis = [k for k in missing if k in CLIS]
        if clis:
            print(f"    программы: {', '.join(clis)}")


def main():
    ap = argparse.ArgumentParser(
        prog="doctor.py",
        description="что установлено, чего нет и что из-за этого не работает")
    ap.add_argument("--json", action="store_true", help="машинный вывод")
    ap.add_argument("--require", default="",
                    help="через запятую: возможности, без которых нельзя работать")
    ap.add_argument("--list", action="store_true", help="перечислить возможности")
    args = ap.parse_args()

    checks = collect()
    caps = capability_state(checks)

    if args.list:
        for cap, (need, any_of) in sorted(CAPABILITIES.items()):
            parts = sorted(need)
            if any_of:
                label = ", ".join(sorted(any_of))
                parts.append(f"любой из: {label}" if len(any_of) > 1 else label)
            print(f"{cap:10s} {' & '.join(parts) if parts else '—'}"
                  f"  {'OK' if caps[cap] else 'НЕТ'}")
        return

    required = [x.strip() for x in args.require.split(",") if x.strip()]
    unknown = [x for x in required if x not in CAPABILITIES]

    if args.json:
        payload = {
            "python": ".".join(str(x) for x in sys.version_info[:3]),
            "kit": KIT,
            "checks": checks,
            "capabilities": caps,
            "missing": [c["key"] for c in checks if not c["ok"]],
            "required": {r: caps.get(r) for r in required if r in CAPABILITIES},
            "unknown_required": unknown,
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        _print_table(checks, caps, hints=not required)

    if unknown:
        if not args.json:
            print(f"\n[-] неизвестные возможности: {', '.join(unknown)}")
            print("    список: python doctor.py --list")
        return 2

    if required and not args.json:
        by_key = {c["key"]: c["ok"] for c in checks}
        good = [r for r in required if caps.get(r)]
        if good:
            print(f"\n[=] требуется: {', '.join(good)} — OK")
        for r in required:
            if caps.get(r):
                continue
            need, any_of = CAPABILITIES[r]
            missing_keys = [k for k in need if not by_key.get(k)]
            if any_of and not any(by_key.get(k) for k in any_of):
                missing_keys.append(f"любой из {sorted(any_of)}")
            print(f"[!] требуется: {r} — НЕТ (нужно: {', '.join(missing_keys)})")

    missing = [r for r in required if not caps.get(r)]
    if missing:
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.exit(0)
