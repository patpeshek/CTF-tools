#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
script_audit.py — аудит shell-скрипта: что он запускает, что source-ит,
какие файлы читает и можно ли их подменить.

Типовой кейс: sudo-скрипт делает `source /srv/app/runtime.conf`, а конфиг
доступен на запись пользователю → подмена конфига = root.

  python script_audit.py /usr/local/sbin/reconcile
  python script_audit.py /usr/local/sbin/reconcile --check-writable
  python script_audit.py script.sh --all-paths
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
import stat


def perms(path):
    try:
        st = os.stat(path)
    except OSError:
        return "нет файла"
    return stat.filemode(st.st_mode) + f" uid={st.st_uid} gid={st.st_gid}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("script")
    ap.add_argument("--check-writable", action="store_true")
    ap.add_argument("--all-paths", action="store_true")
    args = ap.parse_args()

    text = open(args.script, encoding="utf-8", errors="replace").read()
    lines = text.splitlines()
    print(f"[+] файл: {args.script} ({len(lines)} строк)")

    sources = []
    cmds = []
    cats = []

    for i, line in enumerate(lines, 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = re.match(r"(?:source|\.)\s+(\S+)", s)
        if m:
            sources.append((i, m.group(1)))
        for m in re.finditer(r"\$\(\s*cat\s+([^\s)]+)|<\s*([^\s)]+)", line):
            p = m.group(1) or m.group(2)
            cats.append((i, p))
        first = s.split()[0]
        if re.fullmatch(r"[A-Za-z0-9_./-]+", first):
            cmds.append((i, first))

    print("\n[+] source / точки входа:")
    for i, p in sources:
        print(f"  {i}: {p}   {perms(p)}")
    print("\n[+] чтение файлов через cat/<:")
    for i, p in cats:
        print(f"  {i}: {p}   {perms(p)}")

    print("\n[+] команды (уникальные):")
    print(" ", sorted(set(c for _, c in cmds)))

    all_paths = set(p for _, p in sources + cats)
    if args.all_paths:
        for m in re.finditer(r"(/(?:etc|srv|opt|var|usr|home|root|tmp)/[A-Za-z0-9_./-]+)", text):
            all_paths.add(m.group(1))

    if args.check_writable:
        print("\n[+] проверка записи (от текущего пользователя):")
        any_w = False
        for p in sorted(all_paths):
            if not os.path.exists(p):
                print(f"  {p:50s} нет файла")
                continue
            w = os.access(p, os.W_OK)
            any_w = any_w or w
            print(f"  {p:50s} {'WRITABLE!' if w else 'нет записи'}  {perms(p)}")
        if any_w:
            print("\n[!] Есть записываемые файлы, которые скрипт исполняет/читает. "
                  "Если скрипт запускается через sudo — это путь к root.")
        else:
            print("\n[i] Записываемых файлов не видно. Проверь права группы и ACL.")

    print("\n[i] Если скрипт запускается от root, ищи: source/writable config, "
          "вызовы без абсолютного пути (PATH hijack), eval, chmod/chown.")


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
