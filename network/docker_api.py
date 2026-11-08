#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
docker_api.py — работа с открытым Docker API (2375/2376).

  python docker_api.py --host http://1.2.3.4:2375 --list
  python docker_api.py --host http://1.2.3.4:2375 --inspect <container_id>
  python docker_api.py --host http://1.2.3.4:2375 --logs <container_id>
  python docker_api.py --host http://1.2.3.4:2375 --exec <container_id> --cmd "id" --yes

Только для CTF/своих стендов. --exec реально выполняет команду в контейнере.
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
import sys

import requests


def get(base, path, **kw):
    r = requests.get(base.rstrip("/") + path, timeout=10, **kw)
    r.raise_for_status()
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True, help="http://ip:2375")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--inspect")
    ap.add_argument("--logs")
    ap.add_argument("--exec")
    ap.add_argument("--cmd", default="id")
    ap.add_argument("--yes", action="store_true", help="подтвердить выполнение команды")
    ap.add_argument("--insecure", action="store_true", help="не проверять TLS")
    args = ap.parse_args()

    base = args.host.rstrip("/")
    verify = not args.insecure
    session = requests.Session()
    session.verify = verify

    try:
        v = get(base, "/version", verify=verify).json()
        print(f"[+] Docker {v.get('Version')} API {v.get('ApiVersion')} "
              f"({v.get('Os')}/{v.get('Arch')})")
    except Exception as e:
        print("[-] API недоступен:", e)
        sys.exit(1)

    if args.list or not (args.inspect or args.logs or args.exec):
        try:
            cs = get(base, "/containers/json?all=1", verify=verify).json()
            print(f"\n[+] контейнеров: {len(cs)}")
            for c in cs:
                names = ",".join(n.strip("/") for n in c.get("Names", []))
                print(f"  {c['Id'][:12]}  {c.get('Image','')}  {c.get('State','')}  {names}")
        except Exception as e:
            print("[-] containers:", e)

        try:
            imgs = get(base, "/images/json", verify=verify).json()
            print(f"\n[+] образов: {len(imgs)}")
            for i in imgs[:20]:
                tags = ",".join(i.get("RepoTags") or [])
                print(f"  {i['Id'][:19]}  {tags}")
        except Exception as e:
            print("[-] images:", e)

        try:
            info = get(base, "/info", verify=verify).json()
            print(f"\n[+] containers={info.get('Containers')} images={info.get('Images')} "
                  f"root={info.get('DockerRootDir')}")
        except Exception:
            pass

    if args.inspect:
        try:
            c = get(base, f"/containers/{args.inspect}/json", verify=verify).json()
            cfg = c.get("Config", {})
            print(f"\n[+] {c.get('Name')} image={cfg.get('Image')}")
            print("  Env:")
            for e in cfg.get("Env") or []:
                print("   ", e)
            print("  Cmd:", cfg.get("Cmd"))
            print("  Mounts:")
            for m in c.get("Mounts") or []:
                print("   ", m.get("Source"), "->", m.get("Destination"), m.get("Mode"))
            print("  State:", c.get("State", {}).get("Status"))
        except Exception as e:
            print("[-] inspect:", e)

    if args.logs:
        try:
            r = get(base, f"/containers/{args.logs}/logs?stdout=1&stderr=1&tail=200",
                    verify=verify)
            text = r.content.decode("utf-8", "replace")
            # docker logs streams have 8-byte headers
            clean = "".join(ch for ch in text if ch == "\n" or 32 <= ord(ch) < 127)
            print(clean[:20000])
        except Exception as e:
            print("[-] logs:", e)

    if args.exec:
        if not args.yes:
            print("[-] для --exec нужен --yes (команда реально выполнится)")
            return
        try:
            created = requests.post(
                base + f"/containers/{args.exec}/exec",
                json={"AttachStdout": True, "AttachStderr": True,
                      "Tty": False, "Cmd": ["/bin/sh", "-c", args.cmd]},
                verify=verify, timeout=10).json()
            exec_id = created["Id"]
            r = requests.post(base + f"/exec/{exec_id}/start",
                              json={"Detach": False, "Tty": False},
                              verify=verify, timeout=30, stream=True)
            raw = r.content
            # срезаем 8-байтные заголовки потока, если они есть
            text = raw.decode("utf-8", "replace")
            clean = "".join(ch for ch in text if ch == "\n" or 32 <= ord(ch) < 127)
            print(clean[:20000])
        except Exception as e:
            print("[-] exec:", e)


if __name__ == "__main__":
    main()
