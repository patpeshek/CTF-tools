#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
k8s_api.py — работа с Kubernetes API по токену service account.

  python k8s_api.py --host https://10.0.0.1:6443 --token <token> --insecure --list
  python k8s_api.py --host https://... --token ... --ca ca.crt --secrets
  python k8s_api.py --host https://... --token ... --secret my-secret

Читает namespaces/pods/secrets/configmaps; декодирует секреты из base64.
Только для CTF/своих стендов.
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
import base64
import json
import sys

import requests


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True, help="https://ip:6443")
    ap.add_argument("--token")
    ap.add_argument("--token-file", default="/var/run/secrets/kubernetes.io/serviceaccount/token")
    ap.add_argument("--ca", default="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
    ap.add_argument("--namespace", default="default")
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--secrets", action="store_true")
    ap.add_argument("--secret")
    ap.add_argument("--configmaps", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    token = args.token
    if not token:
        try:
            token = open(args.token_file).read().strip()
        except OSError:
            print("[-] нет токена: укажи --token")
            return
    verify = False if args.insecure else (args.ca if args.ca else False)
    headers = {"Authorization": f"Bearer {token}"}
    base = args.host.rstrip("/")

    def get(path):
        return requests.get(base + path, headers=headers, verify=verify, timeout=10)

    out = {}
    try:
        r = get("/version")
        out["version"] = r.json()
        print("[+] Kubernetes", out["version"].get("gitVersion"))
    except Exception as e:
        print("[-] API недоступен:", e)
        return

    ns = args.namespace
    if args.list or not (args.secrets or args.secret or args.configmaps):
        for path, name in ((f"/api/v1/namespaces/{ns}/pods", "pods"),
                           (f"/api/v1/namespaces/{ns}/secrets", "secrets"),
                           ("/api/v1/nodes", "nodes")):
            try:
                r = get(path)
                data = r.json()
                items = data.get("items", [])
                out[name] = [x.get("metadata", {}).get("name") for x in items]
                print(f"\n[+] {name}: {len(items)}")
                for x in items[:30]:
                    print("  ", x.get("metadata", {}).get("name"))
            except Exception as e:
                print(f"[-] {name}: {e}")

    if args.secrets:
        try:
            data = get(f"/api/v1/namespaces/{ns}/secrets").json()
            for s in data.get("items", []):
                name = s.get("metadata", {}).get("name")
                keys = list((s.get("data") or {}).keys())
                print(f"\n[+] secret {name}: {keys}")
                for k, v in (s.get("data") or {}).items():
                    try:
                        dec = base64.b64decode(v).decode("utf-8", "replace")
                        print(f"    {k} = {dec[:200]}")
                    except Exception:
                        pass
        except Exception as e:
            print("[-] secrets:", e)

    if args.secret:
        try:
            data = get(f"/api/v1/namespaces/{ns}/secrets/{args.secret}").json()
            for k, v in (data.get("data") or {}).items():
                dec = base64.b64decode(v).decode("utf-8", "replace")
                print(f"{k} = {dec}")
        except Exception as e:
            print("[-] secret:", e)

    if args.configmaps:
        try:
            data = get(f"/api/v1/namespaces/{ns}/configmaps").json()
            for c in data.get("items", []):
                print(f"\n[+] configmap {c.get('metadata', {}).get('name')}")
                for k, v in (c.get("data") or {}).items():
                    print(f"    {k} = {str(v)[:200]}")
        except Exception as e:
            print("[-] configmaps:", e)

    if args.json:
        print(json.dumps(out, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
