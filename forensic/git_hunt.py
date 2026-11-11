#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
git_hunt.py — что спрятано в git-репозитории.

  python git_hunt.py /path/to/repo
  python git_hunt.py /path/to/repo/.git --json
  python git_hunt.py repo --all-objects

Ищет: флаги/секреты в истории и во всех объектах, удалённые файлы, dangling
коммиты, stash, remotes с кредами, reflog. Содержимое недостижимых
(dangling/unreachable) объектов проверяется всегда; --all-objects — все
объекты базы (loose + pack). Репозиторий задачи не меняется (fsck без
--lost-found, чтение через cat-file).
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


# Чтение объектов — только read-only plumbing (fsck без --lost-found,
# cat-file): репозиторий задачи не меняется. Для этих вызовов глушим то,
# что может запустить команду из чужого конфига (fsmonitor, hooks,
# системный конфиг), и игнорируем refs/replace.
SAFE_CFG = ["--no-replace-objects", "-c", "core.fsmonitor=",
            "-c", "core.hooksPath=" + os.devnull]
SAFE_ENV = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0")
UNREACH_RE = re.compile(r"^(dangling|unreachable) (\w+) ([0-9a-f]{40,64})\b")


def git_ro(repo, *args, data=None, timeout=120):
    """git для чтения объектов: bytes на выходе, None при таймауте/ошибке."""
    try:
        return subprocess.run(["git", *SAFE_CFG, "-C", repo, *args], input=data,
                              capture_output=True, env=SAFE_ENV, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        return None


def batch_check(repo, shas=None):
    """[(sha, type, size)] — для списка sha или для всех объектов базы
    (loose + pack, включая недостижимые)."""
    if shas is None:
        r = git_ro(repo, "cat-file", "--batch-all-objects", "--batch-check")
    else:
        if not shas:
            return []
        r = git_ro(repo, "cat-file", "--batch-check",
                   data=("\n".join(shas) + "\n").encode())
    out = []
    for line in (r.stdout.decode("utf-8", "replace").splitlines() if r else []):
        p = line.split()
        if len(p) == 3 and p[2].isdigit():
            out.append((p[0], p[1], int(p[2])))
    return out


def read_objects(repo, shas):
    """[(sha, type, bytes)] одним вызовом cat-file --batch."""
    if not shas:
        return []
    r = git_ro(repo, "cat-file", "--batch",
               data=("\n".join(shas) + "\n").encode(), timeout=300)
    buf = r.stdout if r else b""
    out, pos = [], 0
    while pos < len(buf):
        nl = buf.find(b"\n", pos)
        if nl < 0:
            break
        head = buf[pos:nl].decode("ascii", "replace").split()
        pos = nl + 1
        if len(head) != 3 or not head[2].isdigit():
            continue          # "<sha> missing"
        size = int(head[2])
        out.append((head[0], head[1], buf[pos:pos + size]))
        pos += size + 1
    return out


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

    # dangling / unreachable: без --lost-found (он пишет в .git задачи);
    # --no-reflogs — коммиты, живые только в reflog, тоже считаем потерянными.
    # fsck может вернуть != 0 на битых объектах — строки всё равно разбираем.
    unreachable = []
    r = git_ro(repo, "fsck", "--unreachable", "--dangling", "--no-reflogs",
               "--no-progress")
    fsck_lines = r.stdout.decode("utf-8", "replace").splitlines() if r else []
    lost, unreach_set = [], set()
    for line in fsck_lines:
        m = UNREACH_RE.match(line)
        if m and m.group(3) not in unreach_set:
            unreach_set.add(m.group(3))
            unreachable.append(m.group(3))
            lost.append(line)
    if lost:
        report["dangling"] = lost[:50]
        print(f"[+] dangling/unreachable: {len(lost)}")
        for x in lost[:10]:
            print("  ", x)
    r = git(repo, "stash", "list")
    if r.returncode == 0 and r.stdout.strip():
        print("[+] stash:")
        print(r.stdout[:1000])

    # содержимое объектов: недостижимые всегда, все — по --all-objects
    # (cat-file --batch-all-objects видит loose + pack, включая dangling)
    objs = batch_check(repo, unreachable)
    if args.all_objects:
        objs += batch_check(repo)
    picked, seen_sha, budget = [], set(), 0
    for sha, kind, size in objs:
        if sha in seen_sha or len(picked) >= args.max_objects:
            continue
        if budget + size > args.max_bytes:
            continue
        seen_sha.add(sha)
        picked.append(sha)
        budget += size
    total = 0
    for sha, kind, data in read_objects(repo, picked):
        total += len(data)
        src = f"{'unreachable ' if sha in unreach_set else ''}{kind}:{sha[:10]}"
        for f in common.find_flags(data):
            if f not in report["flags"]:
                report["flags"].append(f)
                print(f"[!] флаг в объекте {src}")
        text = data.decode("utf-8", "replace")
        for m in SECRET_RE.finditer(text):
            report["secrets"].append({"source": f"object:{src}",
                                      "kind": m.group(1), "value": m.group(2)[:200]})
    n_all = len({o[0] for o in objs})
    if objs:
        print(f"[+] объектов проверено: {len(picked)} из {n_all}"
              f" (недостижимых: {len(unreachable)}), {total//1024} KB")
        if len(picked) < n_all:
            print(f"[i] пропущено {n_all - len(picked)}: подними --max-objects"
                  f" / --max-bytes")

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
