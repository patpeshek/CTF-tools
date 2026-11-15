#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
source_check.py — решить «crackme в исходнике»: восстановить строку по массиву.

  python source_check.py chall.cpp
  python source_check.py chall.cpp --json

В задачах часто есть функция вида `mix_byte(c, i)` и массив ожидаемых байт.
Если функция зависит только от байта и индекса, то для каждой позиции хватает
перебора 0..255: подставляем в **настоящую** функцию и сравниваем с target[i].
Понимать функцию не нужно — её компилирует gcc.
"""
from __future__ import annotations

try:
    import sys as _sys
    for _stream in (_sys.stdout, _sys.stderr):
        _stream.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile

BYTE_ARRAY_RX = re.compile(
    r"\{\s*((?:0x[0-9A-Fa-f]{1,2}\s*,\s*){3,}0x[0-9A-Fa-f]{1,2})\s*\}")
FUNC_RX = re.compile(
    r"(?:static\s+)?(?:inline\s+)?(?:unsigned\s+char|uint8_t|char|int)\s+"
    r"(\w+)\s*\(\s*(?:unsigned\s+char|uint8_t|char)\s+\w+\s*,\s*int\s+\w+\s*\)\s*\{")
BASE = os.environ.get("SRC_CHECK_DIR") or r"F:\AIproject\_scratch\srccheck"


def find_array(src: str):
    best = None
    for m in BYTE_ARRAY_RX.finditer(src):
        vals = [int(x, 16) for x in re.findall(r"0x[0-9A-Fa-f]{1,2}", m.group(1))]
        if len(vals) >= 8 and (best is None or len(vals) > len(best)):
            best = vals
    return best


def find_func(src: str):
    for m in FUNC_RX.finditer(src):
        start, depth, pos = m.start(), 0, m.end() - 1
        while pos < len(src):
            if src[pos] == "{":
                depth += 1
            elif src[pos] == "}":
                depth -= 1
                if depth == 0:
                    return m.group(1), src[start:pos + 1]
            pos += 1
    return None, None


def to_wsl(path: str) -> str:
    p = path.replace("\\", "/")
    if len(p) > 1 and p[1] == ":":
        return "/mnt/" + p[0].lower() + p[2:]
    return p


def build(func_src: str, target):
    arr = ", ".join(str(x) for x in target)
    if not func_src.lstrip().startswith("static"):
        func_src = "static " + func_src.lstrip()
    return f"""#include <stdio.h>
#include <stdint.h>
{func_src}

int main(void) {{
    unsigned char target[] = {{{arr}}};
    int n = (int)sizeof(target);
    char out[512] = {{0}};
    for (int i = 0; i < n; i++) {{
        int hit = -1;
        for (int c = 1; c < 256; c++) {{
            if (mix_byte((unsigned char)c, i) == target[i]) {{
                if (hit >= 0) {{ hit = -2; break; }}
                hit = c;
            }}
        }}
        out[i] = hit > 0 ? (char)hit : '?';
    }}
    printf("RESULT:%s\\n", out);
    return 0;
}}
"""


def run_gcc(code: str, cpp: bool = False):
    os.makedirs(BASE, exist_ok=True)
    tmp = tempfile.mkdtemp(dir=BASE)
    c_path = os.path.join(tmp, "harness.c")
    with open(c_path, "w", encoding="utf-8") as fh:
        fh.write(code)
    gcc = shutil.which("g++" if cpp else "gcc")
    if gcc:                                    # Windows/MINGW gcc
        exe = os.path.join(tmp, "harness.exe")
        comp = subprocess.run([gcc, "-O0", "-o", exe, c_path],
                              capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=120)
        if comp.returncode != 0:
            return None, "компиляция: " + (comp.stderr or "")[:300]
        rr = subprocess.run([exe], capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=30)
        return rr.stdout, ""
    # WSL: путь должен быть на смонтированном диске (F: -> /mnt/f)
    distro = os.environ.get("WSL_DISTRO", "archlinux")
    exe = os.path.join(tmp, "harness")
    comp = subprocess.run(["wsl", "-d", distro, "--", "gcc", "-O0",
                           "-o", to_wsl(exe), to_wsl(c_path)]
                          + (["-x", "c++"] if cpp else []),
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=120)
    if comp.returncode != 0:
        return None, "компиляция: " + (comp.stderr or "")[:300]
    rr = subprocess.run(["wsl", "-d", distro, "--", to_wsl(exe)],
                        capture_output=True, text=True, encoding="utf-8",
                        errors="replace", timeout=30)
    return rr.stdout, ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    src = open(args.file, encoding="utf-8", errors="replace").read()
    target = find_array(src)
    name, func_src = find_func(src)
    res = {"file": args.file, "target_len": len(target or []),
           "func": name, "string": None, "note": ""}
    if not target:
        res["note"] = "массив байт не найден"
    elif not func_src:
        res["note"] = "функция преобразования не найдена"
    else:
        if name != "mix_byte":
            func_src = func_src.replace(name, "mix_byte", 1)
        out, err = run_gcc(build(func_src, target),
                           cpp=args.file.lower().endswith((".cpp", ".cc", ".cxx")))
        m = re.search(r"RESULT:(.*)", out or "") if out else None
        res["string"] = m.group(1).strip() if m else None
        if not res["string"]:
            res["note"] = err or "не восстановилось"

    if args.json:
        print(json.dumps(res, ensure_ascii=False))
        return 0 if res["string"] else 1
    print(f"[+] {args.file}: байт {res['target_len']}, функция {name or '-'}")
    if res["string"]:
        print(f"[!] строка: {res['string']}")
        m = re.search(r"[A-Za-z0-9_]{2,20}\{[ -~]{3,80}\}", res["string"])
        if m:
            print(f"[!!!] ФЛАГ: {m.group(0)}")
    else:
        print("[-]", res["note"] or "не восстановилось")
    return 0 if res["string"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
