#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gitdump.py — открытый .git на сервере → исходники.

  python gitdump.py --url http://host/                 # только осмотр
  python gitdump.py --url http://host/ --dump out/     # восстановить дерево
  python gitdump.py --url http://host/app/ --dump out/ --backups

Что делает:
  1) проверяет .git/HEAD, config, index, packed-refs, objects/info/packs;
  2) тянет объекты: loose (.git/objects/xx/yyy) и pack (.pack + .idx,
     с поддержкой ofs/ref delta) — парсинг свой, git на недоверенных данных
     не запускается;
  3) собирает коммиты/деревья/блобы и раскладывает файлы в --dump;
  4) ищет флаги в восстановленных файлах.

Ограничения: глубина истории не ограничена (берём все коммиты из refs),
есть лимиты --max-files/--max-bytes; субмодули и LFS не поддерживаются.
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
import struct
import sys
import urllib.error
import urllib.request
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common  # noqa: E402

UA = {"User-Agent": "Mozilla/5.0 (ctf-toolbox)"}
BACKUP_PATHS = [
    "index.php~", "index.php.bak", "index.php.old", "index.php.swp",
    "index.php.save", ".index.php.swp", "backup.zip", "backup.tar.gz",
    "backup.sql", "db.sql", ".DS_Store", ".svn/entries", ".hg/requires",
    "www.zip", "site.zip", "src.zip", "source.zip", "app.zip",
]


def fetch(url, timeout=10, limit=64 * 1024 * 1024):
    """GET → bytes или None (404/ошибка сети)."""
    req = urllib.request.Request(url, headers=UA)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read(limit + 1)
            if len(data) > limit:
                return None
            return data
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError):
        return None


def text_of(data):
    return data.decode("utf-8", "replace") if data else ""


# ---------- осмотр ----------

def probe(base):
    """Что вообще отдаёт сервер: refs, config, паки, бекапы."""
    report = {"base": base, "git": False, "head": "", "config": "",
              "packs": [], "refs": {}, "exposed": [], "backups": []}
    head = fetch(base + ".git/HEAD")
    if head and (head.startswith(b"ref:") or re.fullmatch(rb"[0-9a-f]{40}\s*", head)):
        report["git"] = True
        report["head"] = text_of(head).strip()
        report["exposed"].append(".git/HEAD")

    cfg = fetch(base + ".git/config")
    if cfg:
        report["config"] = text_of(cfg)
        report["exposed"].append(".git/config")

    for name in ("index", "packed-refs", "objects/info/packs", "logs/HEAD"):
        if fetch(base + ".git/" + name):
            report["exposed"].append(".git/" + name)

    packs = fetch(base + ".git/objects/info/packs")
    if packs:
        report["packs"] = [ln.split()[-1] for ln in text_of(packs).splitlines()
                           if ln.strip().startswith("P ")]

    for ref in ("main", "master", "dev", "develop"):
        data = fetch(f"{base}.git/refs/heads/{ref}")
        if data:
            report["refs"][ref] = text_of(data).strip()

    packed = fetch(base + ".git/packed-refs")
    if packed:
        for line in text_of(packed).splitlines():
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split()
            if len(parts) == 2:
                report["refs"].setdefault(parts[1].split("/")[-1], parts[0])

    for path in BACKUP_PATHS:
        if fetch(base + path, limit=4 * 1024 * 1024):
            report["backups"].append(path)
    return report


def print_probe(rep):
    print(f"[+] {rep['base']}")
    if not rep["git"]:
        print("[-] .git не найден (HEAD не отдаётся)")
    else:
        print(f"[+] .git открыт; HEAD: {rep['head'][:60]}")
    if rep["exposed"]:
        print(f"[+] доступно: {', '.join(rep['exposed'])}")
    if rep["config"]:
        remote = re.search(r"url\s*=\s*(\S+)", rep["config"])
        if remote:
            print(f"[i] remote в config: {remote.group(1)}")
    if rep["refs"]:
        print("[+] refs: " + ", ".join(f"{k}={v[:10]}" for k, v in rep["refs"].items()))
    if rep["packs"]:
        print(f"[+] паки: {', '.join(rep['packs'])}")
    elif rep["git"]:
        print("[i] паков нет — только loose-объекты")
    if rep["backups"]:
        print(f"[+] бекапы: {', '.join(rep['backups'])}")
    else:
        print("[i] типовых бекапов не видно")


# ---------- объекты git ----------

def inflate_object(raw):
    """loose-объект: zlib → 'type size\\0data'."""
    try:
        body = zlib.decompress(raw)
    except zlib.error:
        return None, None
    head, _, data = body.partition(b"\x00")
    parts = head.split()
    if len(parts) != 2:
        return None, None
    return parts[0].decode(), data


def parse_commit(data):
    tree, parents = None, []
    for line in data.split(b"\n"):
        if not line:
            break
        if line.startswith(b"tree "):
            tree = line[5:].decode()
        elif line.startswith(b"parent "):
            parents.append(line[7:].decode())
    return tree, parents


def parse_tree(data):
    """[(mode, name, sha)] для дерева."""
    out, i = [], 0
    while i < len(data):
        sp = data.find(b" ", i)
        nul = data.find(b"\x00", sp + 1)
        if sp < 0 or nul < 0 or nul + 21 > len(data):
            break
        mode = data[i:sp].decode()
        name = data[sp + 1:nul].decode("utf-8", "replace")
        sha = data[nul + 1:nul + 21].hex()
        out.append((mode, name, sha))
        i = nul + 21
    return out


# ---------- pack ----------

def parse_idx(data):
    """idx v2 → {sha_hex: offset}."""
    if not data or data[:8] != b"\xfftOc\x00\x00\x00\x02":
        return {}
    count = struct.unpack_from(">I", data, 8 + 255 * 4)[0]
    base = 8 + 256 * 4
    shas = [data[base + i * 20:base + (i + 1) * 20].hex() for i in range(count)]
    off_pos = base + count * 20 + count * 4
    offsets = struct.unpack_from(f">{count}I", data, off_pos)
    large_pos = off_pos + count * 4
    large = []
    while large_pos + 8 <= len(data) - 40:
        large.append(struct.unpack_from(">Q", data, large_pos)[0])
        large_pos += 8
    out = {}
    for sha, off in zip(shas, offsets):
        real = (large[off & 0x7FFFFFFF] if off & 0x80000000
                else off)
        out[sha] = real
    return out


def _read_size(data, pos):
    b = data[pos]
    pos += 1
    typ = (b >> 4) & 7
    size = b & 0x0F
    shift = 4
    while b & 0x80:
        b = data[pos]
        pos += 1
        size |= (b & 0x7F) << shift
        shift += 7
    return typ, size, pos


def _read_ofs(data, pos):
    b = data[pos]
    pos += 1
    val = b & 0x7F
    while b & 0x80:
        b = data[pos]
        pos += 1
        val = ((val + 1) << 7) | (b & 0x7F)
    return val, pos


def _apply_delta(base, delta):
    pos = 0
    src_size, pos = _varint(delta, pos)
    dst_size, pos = _varint(delta, pos)
    if src_size != len(base):
        return None
    out = bytearray()
    while pos < len(delta):
        op = delta[pos]
        pos += 1
        if op & 0x80:
            off = 0
            size = 0
            for i in range(4):
                if op & (1 << i):
                    off |= delta[pos] << (8 * i)
                    pos += 1
            for i in range(3):
                if op & (0x10 << i):
                    size |= delta[pos] << (8 * i)
                    pos += 1
            if size == 0:
                size = 0x10000
            out += base[off:off + size]
        elif op:
            out += delta[pos:pos + op]
            pos += op
        else:
            return None
    return bytes(out) if len(out) == dst_size else None


def _varint(data, pos):
    val, shift = 0, 0
    while True:
        b = data[pos]
        pos += 1
        val |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            return val, pos


def parse_pack(pack, idx_map):
    """pack v2 → {sha: (type, data)} с разрешением дельт."""
    if not pack or pack[:4] != b"PACK":
        return {}
    version, count = struct.unpack_from(">II", pack, 4)
    if version not in (2, 3):
        return {}
    by_offset = {off: sha for sha, off in idx_map.items()}
    entries, pos = {}, 12  # "PACK" + version(4) + count(4)
    TYPES = {1: b"commit", 2: b"tree", 3: b"blob", 4: b"tag"}
    for _ in range(count):
        start = pos
        typ, size, pos = _read_size(pack, pos)
        base_sha = None
        base_off = None
        if typ == 6:
            delta_off, pos = _read_ofs(pack, pos)
            base_off = start - delta_off
        elif typ == 7:
            base_sha = pack[pos:pos + 20].hex()
            pos += 20
        d = zlib.decompressobj()
        body = d.decompress(pack[pos:])
        consumed = len(pack) - pos - len(d.unused_data)
        pos += consumed
        sha = by_offset.get(start)
        if sha is None:
            continue
        if typ in TYPES:
            entries[sha] = (TYPES[typ].decode(), body)
        else:
            base = None
            if base_off is not None:
                base = entries.get(by_offset.get(base_off))
            elif base_sha is not None:
                base = entries.get(base_sha)
            if base is None:
                continue
            resolved = _apply_delta(base[1], body)
            if resolved is not None:
                entries[sha] = (base[0], resolved)
    return entries


def load_objects(base, rep, max_bytes):
    """Все объекты: loose по refs + паки."""
    objects, total = {}, 0
    seen = set()

    def add(sha, raw):
        nonlocal total
        if sha in objects or sha in seen or total > max_bytes:
            return
        seen.add(sha)
        typ, data = inflate_object(raw)
        if typ:
            objects[sha] = (typ, data)
            total += len(data)

    # обходим refs, дотягивая по одному объекту (проще и быстрее, чем всё)
    stack = list(rep["refs"].values()) or ([rep["head"].split()[-1]]
                                           if rep["head"] and not rep["head"].startswith("ref:") else [])
    while stack:
        sha = stack.pop()
        if sha in objects or not re.fullmatch(r"[0-9a-f]{40}", sha):
            continue
        raw = fetch(f"{base}.git/objects/{sha[:2]}/{sha[2:]}")
        if not raw:
            continue
        add(sha, raw)
        if sha in objects and objects[sha][0] == "commit":
            tree, parents = parse_commit(objects[sha][1])
            stack.extend(parents)
            if tree:
                stack.append(tree)
        elif sha in objects and objects[sha][0] == "tree":
            stack.extend(s for _m, _n, s in parse_tree(objects[sha][1]))

    for pack_name in rep["packs"]:
        if not pack_name.endswith(".pack"):
            continue
        idx = fetch(f"{base}.git/objects/pack/{pack_name[:-5]}.idx",
                    limit=max_bytes)
        pack = fetch(f"{base}.git/objects/pack/{pack_name}", limit=max_bytes)
        if not idx or not pack:
            continue
        objects.update(parse_pack(pack, parse_idx(idx)))
        total += sum(len(d) for _t, d in objects.values())
        if total > max_bytes:
            break
    return objects


def write_tree(objects, commit_sha, out_dir, limits, stats, prefix=""):
    """Разложить дерево коммита в папку. Возвращает список путей."""
    obj = objects.get(commit_sha)
    if not obj:
        return []
    tree_sha = parse_commit(obj[1])[0] if obj[0] == "commit" else commit_sha
    written = []
    for mode, name, sha in parse_tree(objects.get(tree_sha, ("", b""))[1]):
        if stats["files"] >= limits["files"] or stats["bytes"] >= limits["bytes"]:
            break
        if name in (".", "..") or "/" in name or "\\" in name:
            continue
        rel = os.path.join(prefix, name)
        node = objects.get(sha)
        if not node:
            continue
        typ, data = node
        if typ == "tree":
            written += write_tree(objects, sha, out_dir, limits, stats, rel)
        elif typ == "blob":
            full = os.path.join(out_dir, rel)
            os.makedirs(os.path.dirname(full) or out_dir, exist_ok=True)
            with open(full, "wb") as f:
                f.write(data)
            stats["files"] += 1
            stats["bytes"] += len(data)
            written.append(rel)
            flags = common.find_flags(data)
            for flag in flags:
                stats["flags"].append((rel, flag))
    return written


def main():
    ap = argparse.ArgumentParser(
        prog="gitdump.py", description="открытый .git → исходники")
    ap.add_argument("--url", required=True, help="базовый URL сайта (со слэшем)")
    ap.add_argument("--dump", metavar="DIR", help="куда восстановить дерево")
    ap.add_argument("--max-files", type=int, default=2000)
    ap.add_argument("--max-bytes", type=int, default=64 * 1024 * 1024)
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--backups", action="store_true", help="проверить типовые бекапы")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    base = args.url if args.url.endswith("/") else args.url + "/"
    rep = probe(base)
    if not args.quiet:
        print_probe(rep)
    if not rep["git"]:
        return 1
    if not rep["refs"] and rep["head"].startswith("ref: "):
        ref = rep["head"].split("ref: ", 1)[1].strip()
        data = fetch(base + ".git/" + ref)
        if data:
            rep["refs"][ref.split("/")[-1]] = text_of(data).strip()
    if args.backups and rep["backups"]:
        for path in rep["backups"]:
            print(f"[+] бекап доступен: {path}")
    if not args.dump:
        print("[i] чтобы восстановить дерево: --dump DIR")
        return 0

    objects = load_objects(base, rep, args.max_bytes)
    if not objects:
        print("[-] не удалось скачать ни одного объекта (loose и паки недоступны)")
        return 1
    tips = [v for v in rep["refs"].values()] or ([rep["head"].split()[-1]]
                                                 if rep["head"] else [])
    stats = {"files": 0, "bytes": 0, "flags": []}
    limits = {"files": args.max_files, "bytes": args.max_bytes}
    os.makedirs(args.dump, exist_ok=True)
    written = []
    for sha in tips:
        written += write_tree(objects, sha, args.dump, limits, stats)

    print(f"[+] объектов: {len(objects)}, файлов: {stats['files']}, "
          f"{stats['bytes']} байт → {args.dump}")
    for rel in sorted(set(written))[:30]:
        print(f"    {rel}")
    if len(set(written)) > 30:
        print(f"    ... ещё {len(set(written)) - 30}")
    for rel, flag in stats["flags"]:
        print(f"[!!!] ФЛАГ в {rel}: {flag}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.exit(0)
