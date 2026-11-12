#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cloud_creds.py — поиск облачных ключей и метаданных.

  python cloud_creds.py dump_dir
  python cloud_creds.py dump_dir --json
  python cloud_creds.py --metadata

Ищет AWS/GCP/Azure ключи, service account JSON, connection strings.
С --metadata пробует 169.254.169.254 (AWS/GCP/Azure) с таймаутом.
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

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common  # noqa: E402

PATTERNS = [
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("aws_secret", re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})")),
    ("gcp_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("gcp_private_key", re.compile(r"-----BEGIN PRIVATE KEY-----")),
    ("azure_account_key", re.compile(r"(?i)AccountKey\s*=\s*([A-Za-z0-9+/=]{20,})")),
    ("azure_conn", re.compile(r"(?i)DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[^;\s]+")),
    ("generic_secret", re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key)\b\s*[:=]\s*['\"]?([^\s'\"]{6,120})")),
]


def scan_text(text, source, out):
    for kind, rx in PATTERNS:
        for m in rx.finditer(text):
            if m.lastindex is None:
                value = m.group(0)
            elif m.lastindex >= 2:
                # generic_secret: группа 1 — имя ключа, 2 — значение
                value = f"{m.group(1)}={m.group(2)}"
            else:
                value = m.group(1)
            out.append({"source": source, "kind": kind, "value": value[:200]})


def scan_file(path, out):
    try:
        data = open(path, "rb").read(20_000_000)
    except OSError:
        return
    text = data.decode("utf-8", "replace")
    scan_text(text, path, out)
    for f in common.find_flags(data):
        out.append({"source": path, "kind": "flag", "value": f})
    if path.lower().endswith(".json"):
        try:
            obj = json.loads(text)
            if isinstance(obj, dict) and obj.get("type") == "service_account":
                out.append({"source": path, "kind": "gcp_service_account",
                            "value": obj.get("client_email", "")})
        except Exception:
            pass


def metadata():
    import requests
    results = {}
    checks = [
        ("aws", "http://169.254.169.254/latest/meta-data/"),
        ("aws_creds", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
        ("gcp", "http://metadata.google.internal/computeMetadata/v1/",
         {"Metadata-Flavor": "Google"}),
        ("azure", "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
         {"Metadata": "true"}),
    ]
    for item in checks:
        name, url = item[0], item[1]
        headers = item[2] if len(item) > 2 else {}
        try:
            r = requests.get(url, headers=headers, timeout=2)
            results[name] = r.text[:1000]
        except Exception as e:
            results[name] = f"нет ({e.__class__.__name__})"
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--metadata", action="store_true")
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)

    out = []
    if args.path:
        targets = []
        if os.path.isdir(args.path):
            for root, _, files in os.walk(args.path):
                for f in files:
                    targets.append(os.path.join(root, f))
        else:
            targets = [args.path]
        for p in targets:
            scan_file(p, out)

    meta = metadata() if args.metadata else {}
    if out:
        print(f"[+] находок: {len(out)}")
        seen = set()
        for x in out:
            key = (x["kind"], x["value"])
            if key in seen:
                continue
            seen.add(key)
            print(f"  {x['kind']}: {x['value']}  ({x['source']})")
    if meta:
        print("\n[+] metadata:")
        for k, v in meta.items():
            print(f"  {k}: {v[:300]}")

    if args.json:
        print(json.dumps({"findings": out, "metadata": meta}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
