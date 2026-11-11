#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
android_backup.py — разбор выгрузки Android-приложения: XML, SQLite, логи.

  python android_backup.py dump_dir
  python android_backup.py dump_dir --db-limit 20
  python android_backup.py dump_dir --json out.json

Ищет: android_id, seed, nonce, key, token, password, uuid, package, version.
Для .db печатает таблицы и первые строки; для XML — интересные теги/атрибуты;
для текстовых файлов — KEY=VALUE и секреты.
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
import json
import os
import re
import sqlite3
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common

INTEREST = re.compile(
    r"(?i)(android_id|device_id|seed|nonce|key|token|password|passwd|uuid|"
    r"package|version|user|email|phone|salt|iv)"
)
KV = re.compile(r"(?m)^\s*([A-Za-z0-9_.-]{2,40})\s*[:=]\s*(\S+)")
SQLITE_MAGIC = b"SQLite format 3\x00"


def sniff(path):
    """Тип по содержимому: в databases/ файлы часто без расширения."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(64)
    except OSError:
        return None
    if head.startswith(SQLITE_MAGIC):
        return "db"
    if head.lstrip(b"\xef\xbb\xbf \t\r\n").startswith((b"<?xml", b"<map")):
        return "xml"
    return None


def scan_flags(path, out, max_bytes=20_000_000):
    """Флаги в сырых байтах файла (XML, БД, всё неизвестное)."""
    try:
        with open(path, "rb") as fh:
            data = fh.read(max_bytes)
    except OSError:
        return
    for f in common.find_flags(data):
        out.append({"file": path, "flag": f})


def scan_xml(path, out):
    scan_flags(path, out)
    try:
        tree = ET.parse(path)
    except Exception as e:
        out.append({"file": path, "error": f"xml: {e}"})
        return
    for el in tree.iter():
        attrs = {k: v for k, v in el.attrib.items() if INTEREST.search(k) or INTEREST.search(v or "")}
        text = (el.text or "").strip()
        if attrs or (text and INTEREST.search(text)):
            out.append({"file": path, "tag": el.tag, "attrs": attrs, "text": text[:200]})


def scan_text(path, out):
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return
    for m in KV.finditer(text):
        if INTEREST.search(m.group(1)) or INTEREST.search(m.group(2)):
            out.append({"file": path, "var": m.group(1), "value": m.group(2)[:200]})
    for f in common.find_flags(text.encode("utf-8", "replace")):
        out.append({"file": path, "flag": f})


def scan_db(path, out, limit):
    scan_flags(path, out)       # строки дальше --db-limit и удалённые записи
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        cur = con.cursor()
        tables = [r[0] for r in cur.execute(
            "select name from sqlite_master where type='table'")]
        out.append({"file": path, "tables": tables})
        for t in tables:
            try:
                cols = [d[0] for d in cur.execute(f"select * from {t} limit 1").description]
                rows = cur.execute(f"select * from {t} limit {limit}").fetchall()
                out.append({"file": path, "table": t, "columns": cols,
                            "rows": [[str(c)[:120] for c in row] for row in rows]})
            except Exception as e:
                out.append({"file": path, "table": t, "error": str(e)})
        con.close()
    except Exception as e:
        out.append({"file": path, "error": f"db: {e}"})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--db-limit", type=int, default=10)
    ap.add_argument("--json")
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)

    targets = []
    if os.path.isdir(args.path):
        for root, _, files in os.walk(args.path):
            for f in files:
                targets.append(os.path.join(root, f))
    else:
        targets = [args.path]

    out = []
    for p in targets:
        low = p.lower()
        if low.endswith(".xml"):
            scan_xml(p, out)
        elif low.endswith((".db", ".sqlite", ".sqlite3")):
            scan_db(p, out, args.db_limit)
        elif low.endswith((".txt", ".log", ".json", ".conf", ".properties")):
            scan_text(p, out)
        else:
            # без расширения/незнакомое: тип по сигнатуре, иначе только флаги
            kind = sniff(p)
            if kind == "db":
                scan_db(p, out, args.db_limit)
            elif kind == "xml":
                scan_xml(p, out)
            else:
                scan_flags(p, out)

    for item in out:
        print(json.dumps(item, ensure_ascii=False))

    if args.json:
        json.dump(out, open(args.json, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
        print(f"\n[+] сохранено: {args.json}")


if __name__ == "__main__":
    main()
