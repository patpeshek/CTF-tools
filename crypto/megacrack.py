#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
megacrack.py — комбайн: шифротекст + материалы → перебор ключей и шифров.

  python megacrack.py --cipher-file enc.bin --material note.txt
  python megacrack.py --cipher-hex ... --material "secret" --material info.json
  python megacrack.py --cipher-file enc.bin --material-dir dump/
  python megacrack.py --cipher-file enc.bin --material-dir dump/ --deep

Что перебирается:
  * материалы: строки, KEY=VALUE, JSON-скаляры, hex/base64-блоки, имена файлов;
  * ключи: сам токен, lower/upper, hex/base64-декод, md5/sha1/sha256 (hex и raw),
    пары токенов (concat с разделителями, sha256/md5, xor);
  * шифры: XOR (повторяющийся), RC4, AES-ECB, AES-CBC (IV=0/ключ/md5),
    SHA256-поток (counter 4/8, big/little), Виженер (если ключ буквенный);
  * плюс снятие hex/base64 с самого шифротекста.

Вывод — ranked-варианты с цепочкой «материал → ключ → шифр» и флагами.
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
import hashlib
import itertools
import json
import os
import re
import sys
import time

from Crypto.Cipher import AES, ARC4

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common          # noqa: E402
import autocrack as ac  # noqa: E402
import classical as cl   # noqa: E402

HEX_RUN = re.compile(r"\b[0-9a-fA-F]{8,}\b")
B64_RUN = re.compile(r"[A-Za-z0-9+/]{8,}={0,2}")
QUOTED = re.compile(r"[\"']([^\"']{2,120})[\"']")
KV = re.compile(r"^([A-Za-z0-9_.-]{2,40})\s*[:=]\s*(.+)$")


def add_token(tokens, s, label=None):
    if not s:
        return
    s = str(s).strip()
    if 1 <= len(s) <= 300 and s not in tokens:
        tokens[s] = label or s


def tokens_from_text(text, tokens, prefix=""):
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        add_token(tokens, line, prefix + line[:40])
        m = KV.match(line)
        if m:
            add_token(tokens, m.group(2), f"{prefix}{m.group(1)}={m.group(2)[:30]}")
        for q in QUOTED.findall(line):
            add_token(tokens, q, prefix + q[:40])
        for h in HEX_RUN.findall(line):
            add_token(tokens, h, prefix + "hex:" + h[:24])
        for b in B64_RUN.findall(line):
            if len(b) >= 12:
                add_token(tokens, b, prefix + "b64:" + b[:24])


def tokens_from_json(obj, tokens, prefix=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            tokens_from_json(v, tokens, f"{prefix}{k}=")
    elif isinstance(obj, list):
        for v in obj:
            tokens_from_json(v, tokens, prefix)
    else:
        add_token(tokens, obj, prefix + str(obj)[:30])


def gather_tokens(args):
    tokens = {}
    for m in args.material:
        if os.path.exists(m):
            data = open(m, "rb").read(2_000_000)
            try:
                text = data.decode("utf-8")
                if m.lower().endswith(".json"):
                    try:
                        tokens_from_json(json.loads(text), tokens)
                    except Exception:
                        tokens_from_text(text, tokens)
                else:
                    tokens_from_text(text, tokens)
            except UnicodeDecodeError:
                for s in common.strings(data, 6, 200):
                    add_token(tokens, s[1], f"{os.path.basename(m)}:")
            add_token(tokens, os.path.splitext(os.path.basename(m))[0], "filename:")
        else:
            tokens_from_text(m, tokens)
    for d in args.material_dir:
        for root, _, files in os.walk(d):
            for f in files[:200]:
                p = os.path.join(root, f)
                try:
                    if os.path.getsize(p) > 2_000_000:
                        continue
                    data = open(p, "rb").read()
                    try:
                        tokens_from_text(data.decode("utf-8"), tokens)
                    except UnicodeDecodeError:
                        for s in common.strings(data, 6, 100):
                            add_token(tokens, s[1], f"{f}:")
                    add_token(tokens, os.path.splitext(f)[0], "filename:")
                except OSError:
                    continue
    if args.material_text:
        tokens_from_text(args.material_text, tokens)
    return tokens


def key_candidates(tokens, max_tokens=40, max_pairs=12):
    keys = {}

    def put(label, b):
        if not b or len(b) > 128:
            return
        if b not in keys:
            keys[b] = label

    items = list(tokens.items())[:max_tokens]
    for s, label in items:
        raw = s.encode("utf-8", "replace")
        put(label, raw)
        put(label + "|lower", s.lower().encode())
        put(label + "|upper", s.upper().encode())
        for how, dec in common.decode_field(s):
            if how != "raw" and dec:
                put(f"{label}|{how}", dec)
        for hname in ("md5", "sha1", "sha256"):
            h = getattr(hashlib, hname)(raw)
            put(f"{label}|{hname}", h.digest())
            put(f"{label}|{hname}hex", h.hexdigest().encode())

    pair_src = items[:max_pairs]
    for (a, la), (b, lb) in itertools.combinations(pair_src, 2):
        for sep in ("", ":", "_", "-", "|"):
            combo = f"{a}{sep}{b}"
            put(f"{la}+{lb}", combo.encode("utf-8", "replace"))
        raw = a.encode() + b.encode()
        put(f"sha256({la}+{lb})", hashlib.sha256(raw).digest())
        put(f"md5({la}+{lb})", hashlib.md5(raw).digest())
        # xor двух токенов, выровненный по длине
        n = max(len(a), len(b))
        x = bytes((a.encode()[i % len(a)] ^ b.encode()[i % len(b)]) for i in range(n))
        put(f"xor({la},{lb})", x)
    return keys


def aes_decrypt(data, key, mode, iv):
    try:
        if mode == "ECB":
            dec = AES.new(key, AES.MODE_ECB).decrypt(data)
        else:
            dec = AES.new(key, AES.MODE_CBC, iv).decrypt(data)
    except Exception:
        return None
    try:
        from Crypto.Util.Padding import unpad
        return unpad(dec, 16)
    except Exception:
        return dec


def stream_sha256(data, key, csize, endian, start):
    out = bytearray()
    i = start
    while len(out) < len(data):
        out += hashlib.sha256(key + i.to_bytes(csize, endian)).digest()
        i += 1
    return bytes(a ^ b for a, b in zip(data, out))


def try_key(data, label, key, best, deep=False):
    if not key:
        return
    ac.add_candidate(best, f"{label} → xor", bytes(c ^ key[i % len(key)] for i, c in enumerate(data)))

    try:
        dec = ARC4.new(key).decrypt(data)
        ac.add_candidate(best, f"{label} → rc4", dec)
    except Exception:
        pass

    # AES: ключ как есть (если длина подходит), иначе sha256/повтор
    variants = []
    for klen in (16, 24, 32):
        if len(key) in (klen,):
            variants.append((f"key[{klen}]", key))
        variants.append((f"sha256[:{klen}]", hashlib.sha256(key).digest()[:klen]))
        variants.append((f"repeat[{klen}]", (key * (klen // len(key) + 1))[:klen]))
    for kname, kbytes in variants:
        for mode, iv in (("ECB", None), ("CBC0", b"\x00" * 16),
                         ("CBCkey", (kbytes * 2)[:16]),
                         ("CBCmd5", hashlib.md5(kbytes).digest())):
            dec = aes_decrypt(data, kbytes, mode, iv)
            if dec:
                ac.add_candidate(best, f"{label} → AES-{mode}({kname})", dec)

    for csize in ((4, 8) if deep else (4,)):
        for endian in ("big", "little"):
            for start in (0, 1):
                ac.add_candidate(best, f"{label} → sha256-stream({csize}{endian[0]},{start})",
                                 stream_sha256(data, key, csize, endian, start))

    # Виженер, если ключ буквенный
    ks = key.decode("latin-1", "ignore")
    if 2 <= len(ks) <= 40 and all(c.isalpha() for c in ks):
        text = data.decode("latin-1", "ignore")
        ac.add_candidate(best, f"{label} → vigenere({ks})",
                         cl.vigenere(text, ks).encode("latin-1", "replace"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cipher_file_pos", nargs="?", help="файл с шифротекстом (то же, что --cipher-file)")
    ap.add_argument("--cipher")
    ap.add_argument("--cipher-hex")
    ap.add_argument("--cipher-file")
    ap.add_argument("--material", action="append", default=[])
    ap.add_argument("--material-dir", action="append", default=[])
    ap.add_argument("--material-text")
    ap.add_argument("--top", type=int, default=20)
    ap.add_argument("--min-score", type=float, default=1.0)
    ap.add_argument("--show-noise", action="store_true")
    ap.add_argument("--max-tokens", type=int, default=40)
    ap.add_argument("--max-pairs", type=int, default=12)
    ap.add_argument("--deep", action="store_true")
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)

    if args.cipher_hex:
        data = bytes.fromhex(re.sub(r"(?i)0x|[\s:]", "", args.cipher_hex))
    elif args.cipher_file or args.cipher_file_pos:
        data = open(args.cipher_file or args.cipher_file_pos, "rb").read(2_000_000)
    elif args.cipher:
        data = args.cipher.encode("latin-1", "replace")
    else:
        ap.error("нужен файл с шифротекстом (позицией или --cipher-file), --cipher-hex или --cipher")
    if len(data) > 2_000_000:
        data = data[:2_000_000]

    tokens = gather_tokens(args)
    kind = common.sniff(data[:64])
    print(f"[+] шифротекст: {len(data)} b, тип {kind}")
    print(f"[+] материалов-токенов: {len(tokens)}")
    if not tokens:
        print("[-] материалов нет — нечего превращать в ключ.")
        print("    дай материалы: --material <файл|строка>, --material-dir <папка>,")
        print("                   --material-text <текст>  (ключ, пароль, nonce, seed)")
        print("    без ключа:      python toolbox.py autocrack <файл>")
        print("    числа/модули:   python toolbox.py rsa  (shared/fermat/wiener/...)")
        return

    keys = key_candidates(tokens, args.max_tokens, args.max_pairs)
    print(f"[+] кандидатов в ключи: {len(keys)}")

    # варианты самого шифротекста: raw + hex/base64
    variants = [("cipher", data)]
    for name, dec in ac.decoders(data):
        variants.append((name.strip(), dec))
    # known-plaintext: текст начинается с префикса флага
    for pre, xkey, plain in common.xor_prefix_hits(data):
        variants.append((f"xor-known({pre},k={len(xkey)})", plain))
        print(f"[+] XOR по известному префиксу: ключ {xkey!r} -> {plain[:120]!r}")
    print(f"[+] вариантов входа: {len(variants)}")

    best = {}
    t0 = time.time()
    for vname, vdata in variants:
        for key, label in keys.items():
            try_key(vdata, f"{vname} + {label}", key, best, deep=args.deep)
        if time.time() - t0 > (120 if args.deep else 45):
            print("[!] лимит времени, останавливаюсь")
            break

    ranked = sorted(best.values(), key=lambda x: -x[0])
    print(f"[+] проверено вариантов: {len(ranked)} за {time.time()-t0:.1f}s")
    shown = 0
    for sc, how, text in ranked:
        if sc < args.min_score:
            continue
        flag = ac.find_flag(text)
        if not flag and not args.show_noise and common.printable_ratio(text.encode("utf-8", "replace")) < 0.65:
            continue
        mark = "!!!" if flag else "   "
        print(f"\n{mark} score={sc:7.1f}  {how}")
        print("    " + text[:260].replace("\n", "\\n"))
        if flag:
            print("    FLAG:", flag)
        shown += 1
        if shown >= args.top:
            break
    if not shown:
        print("[-] ничего. Добавь материалов, попробуй --deep или проверь, "
              "что ключ действительно рядом с шифротекстом.")


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
