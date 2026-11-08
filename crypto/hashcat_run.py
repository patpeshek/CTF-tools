#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hashcat_run.py — подобрать пароль через hashcat с автоопределением режима.

  python hashcat_run.py <hash>
  python hashcat_run.py <hash> --wordlist rockyou.txt
  python hashcat_run.py <hash> --dry-run
  python hashcat_run.py <hash> --mode 10900 --hash-file hashes.txt

Если hashcat не установлен, печатает готовую команду (--dry-run по умолчанию).
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
import os
import re
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from hash_id import identify  # noqa: E402


def mode_of(h: str):
    _, mode = identify(h)
    digits = "".join(ch if ch.isdigit() else " " for ch in mode).split()
    return int(digits[0]) if digits else None


def find_hashcat():
    """hashcat в PATH или в известных местах на этом хосте."""
    hc = shutil.which("hashcat")
    if hc:
        return hc
    candidates = [
        r"C:\Users\nispa\.vscode\AIproject\tools\hashcat-8.0.0\hashcat.exe",
        r"C:\Users\nispa\.vscode\AIproject\tools\hashcat-8.0.0\hashcat.EXE",
    ]
    import glob
    candidates += glob.glob(r"F:\dev\hashcat*\hashcat.exe")
    candidates += glob.glob(r"C:\Users\nispa\.vscode\AIproject\tools\hashcat*\hashcat.exe")
    for c in candidates:
        if os.path.exists(c):
            return c
    return None


def find_john():
    import glob
    for pat in (r"C:\Users\nispa\.vscode\AIproject\tools\john-*\run\john.exe",
                r"F:\dev\john-*\run\john.exe",
                r"F:\dev\john\run\john.exe"):
        hits = glob.glob(pat)
        if hits:
            return hits[0]
    return shutil.which("john")


JOHN_FORMATS = {
    "md5": "raw-md5", "ntlm": "nt", "sha1": "raw-sha1", "sha256": "raw-sha256",
    "sha512": "raw-sha512", "bcrypt": "bcrypt", "md5crypt": "md5crypt",
    "sha256crypt": "sha256crypt", "sha512crypt": "sha512crypt",
}


def john_format(name: str):
    low = name.lower()
    for key, fmt in JOHN_FORMATS.items():
        if key in low:
            return fmt
    return None


def run_john(h: str, wordlist: str, fmt: str, extra=""):
    j = find_john()
    if not j:
        print("[-] john не найден")
        return None
    import tempfile
    fd, tmp = tempfile.mkstemp(suffix=".txt")
    os.close(fd)
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(h + "\n")
    fd, pot = tempfile.mkstemp(suffix=".pot")
    os.close(fd)
    cmd = [j, f"--format={fmt}", f"--wordlist={wordlist}", f"--pot={pot}", tmp]
    print("[+] john:", " ".join(cmd))
    if extra:
        cmd += extra.split()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True)
    except OSError as e:
        print("[-] john не запустился:", e)
        return None
    for line in (r.stdout or "").splitlines()[-3:]:
        print("   ", line.strip())
    show = subprocess.run([j, "--show", f"--format={fmt}", f"--pot={pot}", tmp],
                          capture_output=True, text=True)
    result = None
    for line in (show.stdout or "").splitlines():
        if ":" in line and not line.startswith("0 password"):
            result = line.split(":", 1)[1].strip()
            break
    for p in (tmp, pot):
        try:
            os.remove(p)
        except OSError:
            pass
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("hash", nargs="?")
    ap.add_argument("--hash-file")
    ap.add_argument("--wordlist")
    ap.add_argument("--mode", type=int)
    ap.add_argument("--attack", default="0", help="hashcat -a: 0 словарь, 1 комбинация, 3 маска")
    ap.add_argument("--mask", help="маска для -a 3, напр. ?d?d?d?d")
    ap.add_argument("--rules", action="store_true", help="включить правила best64")
    ap.add_argument("--potfile", help="свой potfile")
    ap.add_argument("--engine", default="auto", choices=["auto", "hashcat", "john"],
                    help="auto: hashcat, при провале — john (CPU)")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--extra", default="", help="доп. аргументы hashcat")
    args = ap.parse_args()

    if not args.hash and not args.hash_file:
        ap.error("нужен hash или --hash-file")

    h = args.hash or open(args.hash_file, encoding="utf-8", errors="replace").readline().strip()
    name, mode_s = identify(h)
    print(f"[+] похоже на: {name}  (hashcat: {mode_s})")

    mode = args.mode if args.mode is not None else mode_of(h)
    if mode is None:
        print("[-] режим не определён, укажи --mode")
        return

    wordlist = args.wordlist
    if not wordlist:
        for cand in (r"F:\dev\wordlists\rockyou.txt",
                     r"F:\dev\wordlists\10m-top-1000000.txt",
                     r"F:\dev\wordlists\best110k.txt",
                     r"C:\Users\nispa\.vscode\AIproject\tools\wordlists\rockyou.txt"):
            if os.path.exists(cand):
                wordlist = cand
                break
    wordlist = wordlist or "rockyou.txt"
    hc = find_hashcat()
    hash_target = args.hash_file or h
    cmd = [hc or "hashcat", "-m", str(mode), "-a", str(args.attack)]
    if args.attack == "3":
        if not args.mask:
            print("[-] для -a 3 нужен --mask")
            return
        cmd += [hash_target, args.mask]
    else:
        cmd += [hash_target, wordlist]
        if args.rules:
            cmd += ["-r", os.path.join(os.path.dirname(hc or ""), "rules", "best64.rule")]
    if args.potfile:
        cmd += ["--potfile-path", args.potfile]
    if args.extra:
        cmd += args.extra.split()

    print("[+] команда:")
    print("   ", " ".join(cmd))

    if args.dry_run or not hc:
        if not hc:
            print("[i] hashcat не найден в PATH — команда выше для ручного запуска")
            print("[i] поставить: распаковать hashcat в F:\\dev и добавить в PATH;")
            print("[i] 3070 даёт миллиарды H/s против миллионов на CPU")
        return

    if args.engine != "john":
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               encoding="utf-8", errors="replace")
        except OSError as e:
            print("[-] не удалось запустить hashcat:", e)
            r = None
        if r is not None:
            out = (r.stdout or "") + (r.stderr or "")
            cracked = False
            for line in out.splitlines():
                if "Status" in line and "Cracked" in line:
                    cracked = True
                if "Recovered" in line or "Status" in line:
                    print("   ", line.strip())
            if "All hashes found" in out:
                cracked = True
            if cracked:
                m2 = re.search(r"(?m)^[0-9a-fA-F]{8,}:(.+)$", out)
                if m2:
                    print("[+] пароль:", m2.group(1).strip())
                    return
                try:
                    show = subprocess.run([cmd[0], "-m", str(mode), hash_target, "--show"],
                                          capture_output=True, text=True)
                    for line in (show.stdout or "").splitlines():
                        if ":" in line and not line.startswith("0 password"):
                            print("[+] пароль:", line.split(":", 1)[1].strip())
                            return
                except OSError:
                    pass
                pot = args.potfile or os.path.join(os.environ.get("APPDATA", ""),
                                                   "hashcat", "hashcat.potfile")
                if os.path.exists(pot):
                    with open(pot, encoding="utf-8", errors="replace") as f:
                        for line in f:
                            if line.lower().startswith(h.lower()[:32]):
                                print("[+] пароль:", line.strip().split(":", 1)[-1])
                                return
                print("[+] hashcat: пароль восстановлен (см. potfile/вывод)")
                return
            ran = cracked or "Speed.#" in out
            if ran:
                if not cracked:
                    print("[-] hashcat посчитал, но пароля в словаре нет")
                return

    if args.engine in ("auto", "john"):
        fmt = john_format(name)
        if fmt:
            print("[i] hashcat не считает — переключаюсь на john (CPU)")
            pw = run_john(h, wordlist, fmt, args.extra)
            if pw:
                print("[+] пароль (john):", pw)
                return
        else:
            print("[-] для john не знаю формат этого хеша")


if __name__ == "__main__":
    main()
