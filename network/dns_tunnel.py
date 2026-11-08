#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dns_tunnel.py — данные, спрятанные в DNS-запросах.

  python dns_tunnel.py capture.pcap
  python dns_tunnel.py capture.pcap --domain exfil.example
  python dns_tunnel.py capture.pcap --decode hex|b32|b64|auto
  python dns_tunnel.py capture.pcap --seed S --host H      # XOR sha256(seed:host)
  python dns_tunnel.py capture.pcap --xor-key K            # XOR ключом (utf8 или hex)
  python dns_tunnel.py capture.pcap --out blob.bin         # сохранить собранные байты

Понимает два вида каналов:

1. Простая склейка: левые метки идут по порядку (`68656c6c6f.exfil.test`).
2. Структурированный канал: `<session>.<index>.<data>.<домен>` — метки
   сортируются по индексу, ретрансмиты отбрасываются, данные собираются в
   байты. Это типовой эксфильтратор: порядок в pcap перемешан, а номер в
   запросе — единственный способ собрать файл.

Дальше собранные байты автоматически проверяются на zlib/gzip/bz2/lzma,
XOR (если задан ключ/seed+host), текст и флаги.
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
import bz2
import gzip
import hashlib
import lzma
import math
import os
import re
import sys
import zlib
from collections import Counter, OrderedDict

from scapy.all import DNS, PcapReader

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common  # noqa: E402

DATA_KINDS = {
    "hex": re.compile(r"^[0-9a-fA-F]+$"),
    "b32": re.compile(r"^[A-Z2-7]+=*$"),
    "b64": re.compile(r"^[A-Za-z0-9+/_=-]+$"),
}


def data_kind(label: str):
    """Метка похожа на кусок данных (hex/base32/base64), а не на имя хоста."""
    if len(label) < 6:
        return None
    if len(label) % 2 == 0 and DATA_KINDS["hex"].match(label):
        return "hex"
    if DATA_KINDS["b32"].match(label) and len(label) >= 8 and any(c.isdigit() for c in label):
        return "b32"
    if DATA_KINDS["b64"].match(label) and len(label) >= 8 and any(c.isdigit() for c in label):
        return "b64"
    return None


def decode_data(text: str, kind: str):
    if kind == "hex":
        return bytes.fromhex(text)
    if kind == "b32":
        pad = text.upper() + "=" * (-len(text) % 8)
        return base64.b32decode(pad)
    if kind == "b64":
        pad = text + "=" * (-len(text) % 4)
        return base64.b64decode(pad)
    raise ValueError(kind)


def try_decode(s: str):
    out = []
    compact = re.sub(r"[^A-Za-z0-9+/=]", "", s)
    try:
        out.append(("hex", bytes.fromhex(compact).decode("utf-8", "replace")))
    except (ValueError, UnicodeDecodeError):
        pass
    try:
        pad = compact.upper()
        pad += "=" * (-len(pad) % 8)
        out.append(("b32", base64.b32decode(pad).decode("utf-8", "replace")))
    except Exception:
        pass
    try:
        pad = compact + "=" * (-len(compact) % 4)
        out.append(("b64", base64.b64decode(pad).decode("utf-8", "replace")))
    except Exception:
        pass
    return out


def label_kind(label: str, min_len: int = 4):
    """Чем метка похожа на данные, а не на имя хоста."""
    if len(label) < min_len:
        return None
    if re.fullmatch(r"[0-9a-fA-F]+", label):
        return "hex" if len(label) % 2 == 0 else "hex?"
    if re.fullmatch(r"[A-Z2-7]+=*", label) and len(label) >= 8:
        return "b32"
    if re.fullmatch(r"[A-Za-z0-9+/_=-]+", label) and len(label) >= 8 \
            and any(ch.isdigit() for ch in label):
        return "b64"
    return None


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def score_group(labels, min_len=4):
    """0..1: насколько группа меток похожа на эксфильтрацию."""
    kinds = [label_kind(x, min_len) for x in labels]
    good = [k for k in kinds if k]
    if len(labels) < 2 or not good:
        return 0.0, "?"
    uniq = len(set(labels))
    avg_len = sum(map(len, labels)) / len(labels)
    score = (len(good) / len(labels)) * min(1.0, avg_len / 8) * min(1.0, uniq / 2)
    score *= 0.5 + min(0.5, entropy("".join(labels)) / 4)
    return score, Counter(k for k in good).most_common(1)[0][0]


def read_queries(path, domain=None):
    if path != "-" and not os.path.exists(path):
        raise FileNotFoundError(path)
    names = []
    seen = set()
    with PcapReader(path) as pr:
        for p in pr:
            if DNS not in p or p[DNS].qd is None:
                continue
            try:
                q = p[DNS].qd.qname.decode("utf-8", "replace").rstrip(".")
            except Exception:
                continue
            if domain and not q.endswith(domain.rstrip(".")):
                continue
            if q in seen:  # ретрансмит (в т.ч. не подряд)
                continue
            seen.add(q)
            names.append(q)
    return names


def group_labels(names):
    """{базовый домен: [левые метки по порядку]}"""
    groups = OrderedDict()
    for q in names:
        parts = q.split(".")
        if len(parts) < 2:
            continue
        base = ".".join(parts[-2:])
        left = parts[:-2]
        if not left:
            continue
        groups.setdefault(base, []).append(".".join(left))
    return groups


def _common_suffix(rows):
    """Общий хвост меток: у эксфильтратора это обычно `telemetry`."""
    if not rows:
        return []
    suf = []
    for items in zip(*[reversed(r) for r in rows]):
        if len(set(items)) == 1:
            suf.append(items[0])
        else:
            break
    return list(reversed(suf))


def _xor(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    return bytes(v ^ key[i % len(key)] for i, v in enumerate(data))


def _xor_key_candidates(args, pcap):
    """Все разумные ключи XOR: явные + производные от артефактов рядом."""
    keys = []  # (label, key bytes)
    if args.xor_key:
        raw = args.xor_key
        if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", raw):
            try:
                keys.append(("xor-key(hex)", bytes.fromhex(raw)))
            except ValueError:
                pass
        keys.append(("xor-key", raw.encode("utf-8")))

    seeds, hosts, direct = [], [], []
    if args.seed:
        seeds.append(args.seed)
    if args.host:
        hosts.append(args.host)

    # рядом с pcap обычно лежит live-response: environ/cmdline/конфиги
    found = {}
    if not args.no_auto_keys and pcap != "-":
        base = os.path.dirname(os.path.abspath(pcap))
        roots = [base]
        parent = os.path.dirname(base)
        if parent and parent != base:
            roots.append(parent)
        for root in roots:
            try:
                for name, vals in _collect_assignments(root).items():
                    bucket = found.setdefault(name, [])
                    for v in vals:
                        if v not in bucket:
                            bucket.append(v)
            except Exception:
                pass
        for name, vals in found.items():
            for v in vals[:4]:
                if "HOST" in name:
                    hosts.append(v)
                elif "SEED" in name or "SALT" in name:
                    seeds.append(v)
                elif "KEY" in name or "TOKEN" in name:
                    direct.append((name, v))
        if found and not getattr(args, "_keys_announced", False):
            shown = ", ".join(f"{n}={v[0][:40]}" for n, v in list(found.items())[:6])
            print(f"[i] ключи из артефактов рядом: {shown}")
            args._keys_announced = True

    for name, v in direct:
        keys.append((name, v.encode("utf-8")))
        if re.fullmatch(r"(?:[0-9a-fA-F]{2}){16,}", v):
            try:
                keys.append((name + "(hex)", bytes.fromhex(v)))
            except ValueError:
                pass

    seen = set()
    for s in dict.fromkeys(seeds):
        for h in dict.fromkeys(hosts):
            for sep in (":", "-", "_", "|", ""):
                k = hashlib.sha256(f"{s}{sep}{h}".encode()).digest()
                if k not in seen:
                    seen.add(k)
                    keys.append((f"sha256({sep!r} seed/host)", k))
        k = hashlib.sha256(s.encode()).digest()
        if k not in seen:
            seen.add(k)
            keys.append(("sha256(seed)", k))
        k = s.encode("utf-8")
        if k not in seen:
            seen.add(k)
            keys.append(("seed utf8", k))

    return keys[:64]


ASSIGN_RE = re.compile(
    rb"([A-Z][A-Z0-9_]{2,31})=(?:\"([^\"]{1,96})\"|([^\x00\r\n\s]{1,96}))")
KEY_EXTS = {"", ".txt", ".bin", ".log", ".env", ".json", ".yml", ".yaml",
            ".cfg", ".conf", ".xml", ".ini", ".properties"}
KEY_MARKS = ("SEED", "HOST", "SALT", "KEY", "TOKEN", "SECRET")


def _collect_assignments(root, max_files=100, max_size=512_000, max_depth=4,
                         max_total=8_000_000):
    """NAME=value из мелких текстовых артефактов в root и паре подпапок."""
    vals = OrderedDict()
    used = 0
    total = 0
    for dirpath, dirnames, filenames in os.walk(root):
        depth = os.path.relpath(dirpath, root).count(os.sep)
        if depth >= max_depth:
            dirnames[:] = []
        for fn in filenames:
            if used >= max_files or total >= max_total:
                return vals
            if os.path.splitext(fn)[1].lower() not in KEY_EXTS:
                continue
            p = os.path.join(dirpath, fn)
            try:
                size = os.path.getsize(p)
                if size > max_size or total + size > max_total:
                    continue
                data = open(p, "rb").read()
            except OSError:
                continue
            used += 1
            total += size
            for m in ASSIGN_RE.finditer(data):
                name = m.group(1).decode("ascii", "replace")
                if not any(mark in name for mark in KEY_MARKS):
                    continue
                value = (m.group(2) or m.group(3)).decode("utf-8", "replace")
                bucket = vals.setdefault(name, [])
                if value not in bucket:
                    bucket.append(value)
    return vals


def _expand(data: bytes, key, label, depth=2):
    """Байты + распаковки/XOR (рекурсивно на пару уровней)."""
    out = [(label, data)]
    if depth <= 0:
        return out
    for name, fn in (("zlib", zlib.decompress), ("gzip", gzip.decompress),
                     ("bz2", bz2.decompress), ("lzma", lzma.decompress)):
        try:
            out += _expand(fn(data), key, f"{label}→{name}", depth - 1)
        except Exception:
            pass
    if key:
        out += _expand(_xor(data, key), key, f"{label}+xor", depth - 1)
    return out


def _expand_all(data: bytes, keys, label):
    """Распаковки сырых байтов + цепочки XOR→распаковка по каждому ключу."""
    out = _expand(data, None, label, 2)
    for name, key in keys:
        out += _expand(_xor(data, key), None, f"{label}→{name}", 2)
    return out


def _printable_ratio(data: bytes) -> float:
    """Доля печатных символов; бинарь, который не декодируется в UTF-8, — 0."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return 0.0
    if not text:
        return 0.0
    ok = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
    return ok / len(text)


GENERIC_FLAG_RE = re.compile(rb"[A-Za-z][A-Za-z0-9_]{1,20}\{[ -~]{2,100}\}")


def report_blob(data: bytes, source: str, args):
    if getattr(args, "_key_cache", None) is None:
        args._key_cache = _xor_key_candidates(args, args.pcap)
    keys = args._key_cache
    cands = _expand_all(data, keys, source)
    shown = False
    for label, blob in cands:
        flags = common.find_flags(blob)
        if flags:
            text = blob.decode("utf-8", "replace")
            print(f"[+] {label}: {text[:300]!r}")
            for f in flags:
                print("[!!!] ФЛАГ:", f)
            return
    # префикс мог быть незнакомый (не из flags.json) — показываем шаблон целиком
    for label, blob in cands:
        m = GENERIC_FLAG_RE.search(blob)
        if m:
            print(f"[+] {label} ({len(blob)} B): {blob.decode('utf-8', 'replace')[:300]!r}")
            print("[!!!] похоже на флаг:", m.group(0).decode("utf-8", "replace"))
            return
    # текстовый кандидат (JSON, конфиг) печатаем, даже если флага в нём нет
    for label, blob in cands:
        if _printable_ratio(blob) > 0.85:
            text = blob.decode("utf-8", "replace")
            if len(text.strip()) >= 8:
                print(f"[+] {label} ({len(blob)} B): {text[:400]!r}")
                shown = True
                break
    if not shown:
        print(f"[i] собрано {len(data)} B, но это не текст и не флаг")
        print(f"    hex: {data[:64].hex()}{'…' if len(data) > 64 else ''}")
        if keys:
            names = ", ".join(n for n, _ in keys[:8])
            print(f"    XOR попробован: {names}")
        print("    подсказка: нужен другой ключ (--seed/--host, --xor-key) "
              "или это не XOR-канал")
    if args.out:
        with open(args.out, "wb") as f:
            f.write(data)
        print(f"[+] сырые байты: {args.out}")


def structured_channels(names):
    """Найти каналы <session>.<index>.<data>.<суффикс> и собрать байты."""
    found = []
    for base, joined in group_labels(names).items():
        rows = [x.split(".") for x in joined]
        if len(rows) < 3:
            continue
        n = Counter(len(r) for r in rows).most_common(1)[0][0]
        rows = [r for r in rows if len(r) == n]
        if len(rows) < 3 or n < 2:
            continue
        suf = _common_suffix(rows)
        var = [r[:n - len(suf)] if suf else r for r in rows]
        if not var or not var[0]:
            continue
        m = len(var[0])
        cols = list(zip(*var))
        idx_pos = [i for i in range(m)
                   if all(c.isdigit() for c in cols[i]) and len(set(cols[i])) > 1]
        # данные — все непостоянные колонки, кроме индекса; короткий хвост
        # последнего куска (например "7d") не должен ломать определение
        const_pos = [i for i in range(m) if len(set(cols[i])) == 1]
        data_pos = [i for i in range(m) if i not in idx_pos and i not in const_pos]
        data_pos = [i for i in data_pos
                    if sum(1 for c in cols[i] if data_kind(c))
                    >= max(1, len(cols[i]) * 0.6)]
        if not data_pos:
            continue
        rest_pos = [i for i in range(m) if i not in idx_pos and i not in data_pos]
        idx = idx_pos[0] if idx_pos else None
        groups = OrderedDict()
        for r in var:
            key = tuple(r[i] for i in rest_pos) + tuple(suf)
            groups.setdefault(key, []).append(r)
        for key, items in groups.items():
            if len(items) < 2:
                continue
            if idx is not None:
                try:
                    items.sort(key=lambda r: int(r[idx]))
                except ValueError:
                    pass
            payload, seen_idx = [], set()
            for r in items:
                if idx is not None:
                    num = int(r[idx])
                    if num in seen_idx:
                        continue
                    seen_idx.add(num)
                payload.append("".join(r[p] for p in data_pos))
            if not payload:
                continue
            kind = data_kind(payload[0])
            try:
                data = decode_data("".join(payload), kind) if kind else b""
            except Exception:
                data = b""
            if not data:
                continue
            found.append({
                "base": base,
                "session": ".".join(key),
                "indexed": idx is not None,
                "count": len(payload),
                "data": data,
                "kind": kind,
            })
    return found


def report_structured(ch, args):
    order = "по индексу" if ch["indexed"] else "по порядку в pcap"
    print(f"\n[+] структурный канал {ch['base']} ({ch['session'] or '—'}): "
          f"кусков={ch['count']}, {len(ch['data'])} B, сборка {order}")
    report_blob(ch["data"], f"{ch['kind']}-канал", args)


def report(labels_by_base, base, decode, args=None):
    labels = list(labels_by_base)
    joined = "".join(labels)
    print(f"\n[+] домен {base}: запросов={len(labels)} символов={len(joined)}")
    print("    ", joined[:200])
    cands = try_decode(joined) if decode == "auto" else []
    if decode != "auto":
        fn = {"hex": lambda s: bytes.fromhex(s),
              "b32": lambda s: base64.b32decode(s.upper() + "=" * (-len(s) % 8)),
              "b64": lambda s: base64.b64decode(s + "=" * (-len(s) % 4))}[decode]
        try:
            cands = [(decode, fn(joined).decode("utf-8", "replace"))]
        except Exception as e:
            print("[-] не декодировалось:", e)
    for how, text in cands:
        printable = sum(32 <= ord(c) < 127 for c in text) / max(1, len(text))
        if printable > 0.7 or common.find_flags(text.encode()):
            print(f"[+] {how}: {text[:300]!r}")
            for f in common.find_flags(text.encode()):
                print("[!!!] ФЛАГ:", f)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--domain", help="оставить только запросы, заканчивающиеся на этот домен")
    ap.add_argument("--decode", default="auto", choices=["auto", "hex", "b32", "b64"])
    ap.add_argument("--min-len", type=int, default=4, dest="min_len")
    ap.add_argument("--seed", help="SYNC_SEED для XOR sha256(seed:host)")
    ap.add_argument("--host", help="hostname для XOR sha256(seed:host)")
    ap.add_argument("--xor-key", dest="xor_key", help="XOR-ключ: hex или utf8-строка")
    ap.add_argument("--no-auto-keys", action="store_true",
                    help="не искать SEED/HOST/KEY в файлах рядом с pcap")
    ap.add_argument("--out", help="сохранить собранные байты в файл")
    args = ap.parse_args()

    try:
        names = read_queries(args.pcap, args.domain)
    except FileNotFoundError:
        print(f"[-] нет файла: {args.pcap}")
        return
    except Exception as e:
        print(f"[-] не смог прочитать pcap: {e}")
        return
    if not names:
        print("[-] DNS-запросов не найдено")
        return

    print(f"[+] запросов: {len(names)}")
    groups = group_labels(names)
    print("[+] топ доменов:")
    counts = Counter({k: len(v) for k, v in groups.items()})
    for d, n in counts.most_common(10):
        print(f"   {n:5d}  {d}")

    # при явном --decode не угадываем структуру, пользователь сказал как читать
    structs = structured_channels(names) if args.decode == "auto" else []
    structured_bases = {s["base"] for s in structs}

    if args.domain:
        base = ".".join(args.domain.rstrip(".").split(".")[-2:])
        for s in structs:
            report_structured(s, args)
        for d, labels in groups.items():
            if d in structured_bases:
                continue
            if d == base or d.endswith("." + base):
                report(labels, d, args.decode, args)
        return

    if structs:
        print(f"\n[i] структурированных каналов: {len(structs)}")
        for s in structs[:5]:
            report_structured(s, args)

    suspicious = []
    for d, labels in groups.items():
        if d in structured_bases:
            continue
        sc, kind = score_group(labels, args.min_len)
        if sc >= 0.35:
            suspicious.append((sc, d, labels, kind))
    suspicious.sort(reverse=True)

    if suspicious:
        for sc, d, labels, kind in suspicious[:3]:
            print(f"\n[i] похоже на канал: {d} ({kind}, score={sc:.2f})")
            report(labels, d, args.decode, args)
    elif not structs:
        print("\n[-] явного канала не видно: метки короткие/человеческие")
        for d, labels in groups.items():
            print(f"    {d}: {', '.join(labels[:6])}{' ...' if len(labels) > 6 else ''}")


if __name__ == "__main__":
    main()
