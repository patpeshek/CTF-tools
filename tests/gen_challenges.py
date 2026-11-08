#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gen_challenges.py — генератор мини-тасков для end-to-end проверки кита.

Каждый таск — папка с артефактами (как в реальном CTF) и запись в manifest.json:
  {"dir": "t003_xor_hint", "flag": "CTF{...}", "kind": "xor_hint"}

  python tests/gen_challenges.py --out F:\\AIproject\\_scratch\\gentasks --seed 1
  python tests/fuzz_solve.py --dir F:\\AIproject\\_scratch\\gentasks

Шаблоны: кодировки цепочкой, классические шифры, XOR с подсказкой, RSA (текст
и p/q), AES-ECB, LSB в PNG, комментарий ZIP, вложенный ZIP, DNS-канал в PCAP,
whitespace в DOCX. Флаги в консоль решателя не попадают.
"""
from __future__ import annotations

try:
    import sys as _sys
    for _stream in (_sys.stdout, _sys.stderr):
        _stream.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import base64
import gzip
import io
import json
import os
import random
import struct
import sys
import wave
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Crypto.Cipher import AES  # noqa: E402

rng_global = random.Random(1)


def is_prime(n: int) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_prime(rng, bits=128) -> int:
    while True:
        n = rng.getrandbits(bits) | 1 | (1 << (bits - 1))
        if is_prime(n):
            return n


def rflag(rng) -> str:
    return "CTF{" + "".join(rng.choice("0123456789abcdef") for _ in range(16)) + "}"


def w(path, data: bytes):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def t_encode_chain(rng, d, flag):
    data = flag.encode()
    chain = rng.choice([["base64"], ["hex"], ["base64", "hex"], ["rot13"],
                        ["reverse", "base64"], ["gzip"], ["hex", "gzip"]])
    for name in chain:
        if name == "base64":
            data = base64.b64encode(data)
        elif name == "hex":
            data = data.hex().encode()
        elif name == "gzip":
            data = gzip.compress(data)
        elif name == "rot13":
            import codecs
            data = codecs.encode(data.decode("latin-1"), "rot13").encode("latin-1")
        elif name == "reverse":
            data = data[::-1]
    w(os.path.join(d, "task.txt"), data)
    return " -> ".join(chain)


def t_two_symbol(rng, d, flag):
    bits = "".join(f"{b:08b}" for b in flag.encode())
    a, b = rng.choice([(".", "-"), ("A", "B"), ("#", "*")])
    w(os.path.join(d, "code.txt"), "".join(a if x == "0" else b for x in bits).encode())
    return "2sym"


def t_caesar(rng, d, flag):
    shift = rng.randint(1, 25)

    def rot(s):
        out = []
        for ch in s:
            if "a" <= ch <= "z":
                out.append(chr((ord(ch) - 97 + shift) % 26 + 97))
            elif "A" <= ch <= "Z":
                out.append(chr((ord(ch) - 65 + shift) % 26 + 65))
            else:
                out.append(ch)
        return "".join(out)

    w(os.path.join(d, "cipher.txt"), rot(flag).encode())
    return f"caesar {shift}"


def t_vigenere(rng, d, flag):
    key = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(rng.randint(4, 8)))
    text = (flag + " " + "the quick brown fox jumps over the lazy dog " * 6).strip()
    out, ki = [], 0
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + ord(key[ki % len(key)]) - 97) % 26 + 97))
            ki += 1
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + ord(key[ki % len(key)]) - 97) % 26 + 65))
            ki += 1
        else:
            out.append(ch)
    w(os.path.join(d, "cipher.txt"), "".join(out).encode())
    return f"vigenere {key}"


def t_xor_hint(rng, d, flag):
    key = bytes(rng.randrange(1, 256) for _ in range(4))
    w(os.path.join(d, "cipher.bin"),
      bytes(c ^ key[i % len(key)] for i, c in enumerate(flag.encode())))
    w(os.path.join(d, "hint.txt"),
      f"Повторяющийся XOR, ключ длиной {len(key)} байт. "
      f"Открытый текст начинается с CTF{{.\n".encode())
    return f"xor keylen={len(key)}"


def t_rsa_text(rng, d, flag):
    m = int.from_bytes(flag.encode(), "big")
    mode = rng.choice(["fermat", "small_e"])
    if mode == "small_e":
        e = 3
        n = gen_prime(rng, 512) * gen_prime(rng, 512)   # n > m^3
        c = m ** 3
    else:
        p = gen_prime(rng, 128)
        q = p + 2
        while not is_prime(q):
            q += 2
        n, e = p * q, 65537
        c = pow(m, e, n)
    w(os.path.join(d, "task.txt"),
      f"Модуль n = {n}\nЭкспонента e = {e}\nШифротекст c = {c}\n".encode())
    return f"rsa ({mode})"


def t_rsa_noise(rng, d, flag):
    """Куча мусора + настоящие n/e/c среди decoy-чисел и хешей."""
    p = gen_prime(rng, 128)
    q = p + 2
    while not is_prime(q):
        q += 2
    n, e = p * q, 65537
    m = int.from_bytes(flag.encode(), "big")
    c = pow(m, e, n)
    import hashlib
    lines = [
        "# bridge telemetry dump",
        f"session = {rng.getrandbits(96)}",
        f"nonce = {rng.getrandbits(128):x}",
        f"sha256 = {hashlib.sha256(str(rng.getrandbits(200)).encode()).hexdigest()}",
        "puzzle = " + base64.b64encode(b"not the key, keep looking").decode(),
        f"modulus n = {n}",
        f"public exponent e = {e}",
        f"payload c = {c}",
        f"checksum = {rng.getrandbits(160)}",
        f"counter = {rng.randrange(10**9)}",
        f"token = {rng.getrandbits(64):x}",
    ]
    rng.shuffle(lines)  # перемешаем, чтобы порядок не подсказывал
    w(os.path.join(d, "dump.txt"), ("\n".join(lines) + "\n").encode())
    w(os.path.join(d, "notes.txt"),
      b"hint: among the numbers only one triple is a real key: n, e, c.\n")
    return "rsa + шум"


def t_rsa_pq(rng, d, flag):
    p, q = gen_prime(rng, 128), gen_prime(rng, 128)
    e = 65537
    m = int.from_bytes(flag.encode(), "big")
    n = p * q
    if m >= n:
        p, q = gen_prime(rng, 256), gen_prime(rng, 256)
        n = p * q
    c = pow(m, e, n)
    w(os.path.join(d, "task.txt"), f"p = {p}\nq = {q}\ne = {e}\nc = {c}\n".encode())
    return "rsa p,q"


def t_aes_ecb(rng, d, flag):
    import string
    key = "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(16)).encode()
    pad = 16 - len(flag) % 16
    pt = flag.encode() + bytes([pad]) * pad
    ct = AES.new(key, AES.MODE_ECB).encrypt(pt)
    w(os.path.join(d, "cipher.bin"), ct)
    w(os.path.join(d, "hint.txt"), f"AES-ECB. key = {key.decode()}\n".encode())
    return "aes-ecb + ключ в hint"


def t_lsb_png(rng, d, flag):
    from PIL import Image
    msg = (flag + "\n").encode()
    bits = [(b >> (7 - i)) & 1 for b in msg for i in range(8)]
    wpx, h = 320, 40
    im = Image.new("RGB", (wpx, h), (rng.randrange(80, 160), 30, 60))
    px = im.load()
    idx = 0
    for y in range(h):
        for x in range(wpx):
            if idx >= len(bits):
                break
            r, g, b = px[x, y]
            px[x, y] = ((r & 0xFE) | bits[idx], g, b)
            idx += 1
    im.save(os.path.join(d, "image.png"))
    return "lsb png"


def t_zip_comment(rng, d, flag):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("readme.txt", "nothing here")
        z.comment = flag.encode()
    w(os.path.join(d, "archive.zip"), buf.getvalue())
    return "zip comment"


def t_zip_nested(rng, d, flag):
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as z:
        z.writestr("flag.txt", flag)
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w") as z:
        z.writestr("inner.zip", inner.getvalue())
        z.writestr("readme.txt", "open me")
    w(os.path.join(d, "bundle.zip"), outer.getvalue())
    return "zip in zip"


def t_embedded_zip(rng, d, flag):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("dispatch.txt", flag + "\n")
    w(os.path.join(d, "volume.bin"), b"STORAGE " + bytes(rng.randrange(256) for _ in range(300))
      + buf.getvalue())
    return "zip inside volume"


def t_dns_pcap(rng, d, flag):
    try:
        from scapy.all import DNS, DNSQR, IP, UDP, Ether, wrpcap
    except Exception:
        return None
    hexed = flag.encode().hex()
    chunks = [hexed[i:i + 20] for i in range(0, len(hexed), 20)]
    pkts = []
    for i, ch in enumerate(chunks):
        pkts.append(Ether() / IP(src="10.0.0.2", dst="10.0.0.53") / UDP(dport=53)
                    / DNS(rd=1, qd=DNSQR(qname=f"{ch}.exfil.test")))
        if i % 2 == 0:
            pkts.append(Ether() / IP(src="10.0.0.2", dst="10.0.0.53") / UDP(dport=53)
                        / DNS(rd=1, qd=DNSQR(qname="portal.office.test")))
    w(os.path.join(d, "capture.pcap"), b"")
    wrpcap(os.path.join(d, "capture.pcap"), pkts)
    return "dns exfil"


def t_docx_ws(rng, d, flag):
    bits = "".join(f"{b:08b}" for b in flag.encode())
    zw = "".join("\u200b" if b == "0" else "\u200c" for b in bits)
    body = "Quarterly report. Nothing to see here." + zw
    doc = ('<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/'
           'wordprocessingml/2006/main"><w:body><w:p><w:r><w:t xml:space="preserve">'
           + body + '</w:t></w:r></w:p></w:body></w:document>')
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", doc)
    w(os.path.join(d, "doc.docx"), buf.getvalue())
    return "docx zero-width"


def t_morse_wav(rng, d, flag):
    code = flag.strip("CTF{}")
    table = {".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
             "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
             "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
             "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
             "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
             "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
             "---..": "8", "----.": "9"}
    rev = {v: k for k, v in table.items()}
    seq = [rev.get(ch.upper(), "") for ch in code]
    if not all(seq):
        return None
    rate = 22050
    dot = int(rate * 0.06)
    samples = []

    def tone(n):
        samples.extend(int(5000 * __import__("math").sin(2 * 3.14159 * 700 * i / rate))
                       for i in range(n))

    def sil(n):
        samples.extend([0] * n)
    for morse in seq:
        for sym in morse:
            tone(dot if sym == "." else dot * 3)
            sil(dot)
        sil(dot * 2)
    path = os.path.join(d, "signal.wav")
    with wave.open(path, "w") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(rate)
        wf.writeframes(b"".join(struct.pack("<h", s) for s in samples))
    return "morse wav (код без фигурных скобок — флаг не совпадёт)"


def t_docx_trail(rng, d, flag):
    bits = "".join(f"{b:08b}" for b in flag.encode())
    paras = []
    for i, b in enumerate(bits):
        tail = " " if b == "0" else "\t"
        paras.append('<w:p><w:r><w:t xml:space="preserve">line '
                     f'{i}{tail}</w:t></w:r></w:p>')
    doc = ('<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/'
           'wordprocessingml/2006/main"><w:body>' + "".join(paras) + '</w:body></w:document>')
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", doc)
    w(os.path.join(d, "doc.docx"), buf.getvalue())
    return "docx trailing whitespace"


def t_rsa_shared_stream(rng, d, flag):
    """Реестр модулей с общим множителем + RSA-обёрнутый ключ + SHA256-поток."""
    import hashlib
    e = 65537
    shared = gen_prime(rng, 160)
    certs, target_n = [], None
    for i in range(7):
        q = gen_prime(rng, 160)
        n = shared * q if i == 2 else gen_prime(rng, 160) * gen_prime(rng, 160)
        certs.append({"id": f"office-{i:02d}", "n": str(n)})
        if i == 2:
            target_n = n
    certs.append({"id": "corinth-relay", "n": str(shared * gen_prime(rng, 160))})
    certs.append({"id": "athens-archive", "n": str(target_n)})
    rng.shuffle(certs)
    key = bytes(rng.randrange(1, 256) for _ in range(16))
    wrapped = pow(int.from_bytes(key, "big"), e, target_n)
    nonce = bytes(rng.randrange(1, 256) for _ in range(12))
    pt = flag.encode()
    ct = bytearray()
    for i in range(0, len(pt), 32):
        ks = hashlib.sha256(key + nonce + (i // 32).to_bytes(4, "big")).digest()
        ct += bytes(a ^ b for a, b in zip(pt[i:i + 32], ks))
    doc = {
        "target": "athens-archive",
        "public_exponent": e,
        "certificates": certs,
        "wrapped_session_key": str(wrapped),
        "stream": "SHA-256(session_key || nonce || counter_be_32), XOR",
        "nonce": nonce.hex(),
        "ciphertext": ct.hex(),
    }
    w(os.path.join(d, "registry.json"), json.dumps(doc, indent=2).encode())
    return "rsa shared + stream"


def t_hash_md5(rng, d, flag):
    """MD5 от самого флага + локальный словарь рядом (не зависит от rockyou)."""
    import hashlib
    import string
    h = hashlib.md5(flag.encode()).hexdigest()
    decoys = ["".join(rng.choice(string.ascii_lowercase) for _ in range(rng.randint(5, 9)))
              for _ in range(30)]
    w(os.path.join(d, "hash.txt"), (h + "\n").encode())
    w(os.path.join(d, "words.txt"), ("\n".join(decoys + [flag]) + "\n").encode())
    w(os.path.join(d, "notes.txt"),
      b"password hashed with md5; simple words only\n")
    return "md5 + локальный словарь"


TEMPLATES = [
    ("encode_chain", t_encode_chain), ("two_symbol", t_two_symbol),
    ("caesar", t_caesar), ("vigenere", t_vigenere),
    ("xor_hint", t_xor_hint), ("rsa_text", t_rsa_text), ("rsa_pq", t_rsa_pq),
    ("rsa_noise", t_rsa_noise),
    ("aes_ecb", t_aes_ecb), ("lsb_png", t_lsb_png), ("zip_comment", t_zip_comment),
    ("zip_nested", t_zip_nested), ("embedded_zip", t_embedded_zip),
    ("dns_pcap", t_dns_pcap), ("docx_ws", t_docx_ws), ("docx_trail", t_docx_trail),
    ("rsa_shared_stream", t_rsa_shared_stream),
]


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--repeat", type=int, default=1, help="сколько раз каждый шаблон")
    ap.add_argument("--only", nargs="*", help="фильтр по имени шаблона")
    args = ap.parse_args()
    rng = random.Random(args.seed)
    os.makedirs(args.out, exist_ok=True)
    manifest = []
    idx = 0
    for rep in range(args.repeat):
        for name, fn in TEMPLATES:
            if args.only and name not in args.only:
                continue
            idx += 1
            d = os.path.join(args.out, f"t{idx:03d}_{name}")
            os.makedirs(d, exist_ok=True)
            flag = rflag(rng)
            try:
                how = fn(rng, d, flag)
            except Exception as e:
                how = None
                print(f"[-] {name}: {e}")
            if not how:
                continue
            manifest.append({"dir": os.path.basename(d), "flag": flag,
                             "kind": name, "how": how})
            print(f"{os.path.basename(d):24s} {how}")
    with open(os.path.join(args.out, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=1)
    print(f"[+] тасков: {len(manifest)} -> {args.out}")


if __name__ == "__main__":
    main()
