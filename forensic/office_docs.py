#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
office_docs.py — Office/PDF: макросы, вложенные объекты, ссылки, JS.

  python office_docs.py document.docx
  python office_docs.py document.docx --out extracted
  python office_docs.py document.pdf --json

DOCX/XLSX/PPTX: макросы (vbaProject.bin), embeddings, activeX, externalLinks.
PDF: /JS, /JavaScript, /OpenAction, /AA, /EmbeddedFiles, URI, текст.
RTF: objupdate/objemb/URL.
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
import sys
import zipfile
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common  # noqa: E402

URL = re.compile(rb"(?:https?|ftp)://[^\s\"'<>]{4,200}")


def ooxml(path, out):
    info = {"file": path, "type": "ooxml", "macros": [], "embeddings": [],
            "externals": [], "flags": [], "urls": []}
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        for n in names:
            low = n.lower()
            if "vbaproject" in low or low.endswith(".bin") and "vba" in low:
                info["macros"].append(n)
            if "embeddings/" in low or "oleobject" in low:
                info["embeddings"].append(n)
            if "externallink" in low or "external" in low:
                info["externals"].append(n)
            try:
                data = z.read(n)
            except Exception:
                continue
            for f in common.find_flags(data):
                info["flags"].append(f)
            info["urls"] += [m.group().decode("latin-1") for m in URL.finditer(data)]
            if out and (n in info["macros"] or "embeddings/" in low):
                dst = os.path.join(out, n.replace("/", "_"))
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                open(dst, "wb").write(data)
    info["urls"] = sorted(set(info["urls"]))[:20]
    return info


def pdf_raw(raw, info):
    """Сырой поиск по байтам PDF — работает без pypdf. FlateDecode-потоки
    распаковываем zlib-ом: текст страниц почти всегда сжат."""
    if b"/JavaScript" in raw or b"/JS" in raw:
        info["js"].append("найден /JavaScript или /JS")
    if b"/EmbeddedFiles" in raw:
        info["embedded"].append("найден /EmbeddedFiles")
    for key in (b"/OpenAction", b"/Launch"):
        if key in raw:
            info["open_action"].append(f"найден {key.decode()}")
    blobs, pos = [raw], 0
    while len(blobs) <= 5000:
        s = raw.find(b"stream", pos)
        e = raw.find(b"endstream", s + 6) if s >= 0 else -1
        if e < 0:
            break
        body, pos = raw[s + 6:e], e + 9
        body = body[2:] if body[:2] == b"\r\n" else body[1:] if body[:1] in b"\r\n" else body
        try:
            blobs.append(zlib.decompressobj().decompress(body, 20_000_000))
        except zlib.error:
            pass
    for b in blobs:
        info["urls"] += [m.group().decode("latin-1") for m in URL.finditer(b)]
        info["flags"] += common.find_flags(b)


def pdf_info(path, out):
    info = {"file": path, "type": "pdf", "js": [], "open_action": [], "embedded": [],
            "urls": [], "flags": []}
    try:
        raw = open(path, "rb").read(50_000_000)
    except OSError as e:
        info["error"] = str(e)
        return info
    pdf_raw(raw, info)
    info["urls"] = sorted(set(info["urls"]))[:30]
    if out:
        os.makedirs(out, exist_ok=True)
        open(os.path.join(out, "raw.pdf"), "wb").write(raw)
    try:
        from pypdf import PdfReader
    except ImportError:
        info["note"] = "нет pypdf — только сырой поиск (pip install pypdf)"
        return info
    try:
        r = PdfReader(path)
        info["pages"] = len(r.pages)
        root = r.trailer.get("/Root", {})
        for key in ("/OpenAction", "/AA"):
            if key in root:
                info["open_action"].append(str(root[key])[:300])
        for i, page in enumerate(r.pages[:100]):
            try:
                if "/AA" in page:
                    info["open_action"].append(f"page {i+1}: {str(page['/AA'])[:200]}")
                if "/Annots" in page:
                    for a in page["/Annots"]:
                        obj = a.get_object()
                        if obj.get("/A", {}).get("/URI"):
                            info["urls"].append(str(obj["/A"]["/URI"]))
            except Exception:
                pass
            text = page.extract_text() or ""
            for f in common.find_flags(text.encode("utf-8", "replace")):
                info["flags"].append(f)
        info["urls"] = sorted(set(info["urls"]))[:30]
    except Exception as e:
        info["error"] = str(e)
    return info


def rtf_info(path, out):
    raw = open(path, "rb").read(50_000_000)
    info = {"file": path, "type": "rtf", "flags": [], "urls": [],
            "objects": [], "macros": []}
    for key in (b"\\objupdate", b"\\objemb", b"\\objlink", b"\\macros"):
        if key in raw:
            info["objects"].append(key.decode())
    info["urls"] = sorted({m.group().decode("latin-1") for m in URL.finditer(raw)})[:20]
    info["flags"] = common.find_flags(raw)
    return info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--out")
    ap.add_argument("--json", action="store_true")
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)

    if args.out:
        os.makedirs(args.out, exist_ok=True)
    low = args.file.lower()
    if low.endswith((".docx", ".xlsx", ".pptx", ".docm", ".xlsm")):
        info = ooxml(args.file, args.out)
    elif low.endswith(".pdf"):
        info = pdf_info(args.file, args.out)
    elif low.endswith(".rtf"):
        info = rtf_info(args.file, args.out)
    else:
        print("[-] поддержаны docx/xlsx/pptx/docm/xlsm/pdf/rtf")
        return

    print(json.dumps(info, ensure_ascii=False, indent=2, default=str))
    for f in sorted(set(info.get("flags", []))):
        print("!!! ФЛАГ:", f)


if __name__ == "__main__":
    main()
