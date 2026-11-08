#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
git_hunt.py — что спрятано в git-репозитории.

  python git_hunt.py /path/to/repo
  python git_hunt.py /path/to/repo/.git --json
  python git_hunt.py repo --all-objects

Ищет: флаги/секреты в истории и во всех объектах, удалённые файлы, dangling
коммиты, stash, remotes с кредами, reflog.
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
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common  # noqa: E402

SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|aws_secret)\b\s*[:=]\s*['\"]?([^\s'\"]{4,120})")
URL_CRED = re.compile(r"https?://([^:/@\s]+):([^@/\s]+)@")


def git(repo, *args, timeout=30):
    return subprocess.run(["git", "-C", repo, *args], capture_output=True,
                          text=True, encoding="utf-8", errors="replace",
                          timeout=timeout)


def find_repo(path):
    if os.path.isdir(os.path.join(path, ".git")):
        return path
    if os.path.basename(path) == ".git":
        return os.path.dirname(path)
    r = git(path, "rev-parse", "--show-toplevel")
    if r.returncode == 0:
        return r.stdout.strip()
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--max-objects", type=int, default=500)
    ap.add_argument("--max-bytes", type=int, default=20_000_000)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--all-objects", action="store_true")
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)

    repo = find_repo(args.path)
    if not repo:
        print("[-] это не git-репозиторий")
        return

    report = {"repo": repo, "flags": [], "secrets": [], "deleted": [],
              "dangling": [], "remotes": [], "log": []}
    print(f"[+] repo: {repo}")

    r = git(repo, "remote", "-v")
    if r.returncode == 0:
        for line in r.stdout.splitlines():
            report["remotes"].append(line)
            print("  remote:", line)
            m = URL_CRED.search(line)
            if m:
                report["secrets"].append({"source": "remote", "kind": "url-creds",
                                          "value": m.group(0)})

    r = git(repo, "log", "--all", "--oneline", "-n", "50")
    if r.returncode == 0:
        report["log"] = r.stdout.splitlines()
        print(f"[+] коммитов (последние): {len(report['log'])}")
        for line in report["log"][:10]:
            print("  ", line)

    # секреты в патчах всей истории
    r = git(repo, "log", "--all", "-p", "--no-color")
    patch = r.stdout[:args.max_bytes] if r.returncode == 0 else ""
    for f in common.find_flags(patch.encode("utf-8", "replace")):
        if f not in report["flags"]:
            report["flags"].append(f)
    for m in SECRET_RE.finditer(patch):
        report["secrets"].append({"source": "history", "kind": m.group(1),
                                  "value": m.group(2)[:200]})

    # удалённые файлы
    r = git(repo, "log", "--all", "--diff-filter=D", "--name-only",
            "--pretty=format:")
    if r.returncode == 0:
        report["deleted"] = sorted({x for x in r.stdout.splitlines() if x.strip()})
        if report["deleted"]:
            print(f"[+] удалённые файлы: {len(report['deleted'])}")
            for x in report["deleted"][:20]:
                print("  -", x)

    # dangling / stash / reflog
    r = git(repo, "fsck", "--lost-found", "--no-reflogs")
    if r.returncode == 0 and r.stdout.strip():
        report["dangling"] = r.stdout.splitlines()[:50]
        print(f"[+] dangling: {len(report['dangling'])}")
        for x in report["dangling"][:10]:
            print("  ", x)
    r = git(repo, "stash", "list")
    if r.returncode == 0 and r.stdout.strip():
        print("[+] stash:")
        print(r.stdout[:1000])

    # все объекты (если попросили)
    if args.all_objects:
        r = git(repo, "rev-list", "--objects", "--all")
        total = 0
        for line in (r.stdout.splitlines() if r.returncode == 0 else [])[:args.max_objects]:
            sha = line.split()[0]
            r2 = git(repo, "cat-file", "-p", sha)
            if r2.returncode != 0:
                continue
            data = r2.stdout.encode("utf-8", "replace")[:2_000_000]
            total += len(data)
            for f in common.find_flags(data):
                if f not in report["flags"]:
                    report["flags"].append(f)
            for m in SECRET_RE.finditer(r2.stdout):
                report["secrets"].append({"source": f"object:{sha[:10]}",
                                          "kind": m.group(1), "value": m.group(2)[:200]})
            if total > args.max_bytes:
                break
        print(f"[+] объектов проверено: до {args.max_objects}, {total//1024} KB")

    report["secrets"] = report["secrets"][:100]
    if report["flags"]:
        print("\n=== ФЛАГИ ===")
        for f in report["flags"]:
            print(" !!!", f)
    if report["secrets"]:
        print("\n[+] секреты:")
        seen = set()
        for s in report["secrets"]:
            key = (s["kind"], s["value"])
            if key in seen:
                continue
            seen.add(key)
            print(f"  {s['source']}: {s['kind']}={s['value']}")

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
