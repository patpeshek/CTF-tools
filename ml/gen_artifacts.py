"""gen_artifacts.py — генераторы «настоящих» контейнеров, а не только кодировок.

Первая версия роутера училась на 13 семействах кодировок (b64/hex/xor/...).
На реальных файлах из `_scratch/custom_tasks` она выдавала xor1 на любой .py и
random_bin на любой png — потому что png в обучении просто не было.

Здесь собираются артефакты, которые действительно приходят в CTF:
png, gif, zip, pdf, sqlite, pcap, mp3 (ID3v2), json-лог, python-исходник.
Всё генерируется честно, без внешних библиотек (кроме stdlib), и открывается
настоящими инструментами кита.
"""
from __future__ import annotations

import base64
import bz2
import io
import json
import lzma
import math
import random
import sqlite3
import struct
import zlib
from zipfile import ZIP_DEFLATED, ZIP_STORED, ZipFile


# ---------------------------------------------------------------- png --------
def _png_chunk(kind: bytes, payload: bytes) -> bytes:
    return (struct.pack(">I", len(payload)) + kind + payload
            + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF))


def make_png(rng: random.Random) -> bytes:
    if rng.random() < 0.5:
        w, h = rng.randint(8, 64), rng.randint(8, 64)
    else:  # крупная картинка — как настоящие файлы из задач
        w, h = rng.randint(64, 192), rng.randint(64, 192)
    color_type, channels = rng.choice([((0, 1)), ((2, 3)), ((4, 2)), ((6, 4))])
    rows = []
    for _y in range(h):
        rows.append(b"\x00" + rng.randbytes(w * channels))
    raw = b"".join(rows)
    ihdr = struct.pack(">IIBBBBB", w, h, 8, color_type, 0, 0, 0)
    out = b"\x89PNG\r\n\x1a\n" + _png_chunk(b"IHDR", ihdr)
    if rng.random() < 0.5:
        out += _png_chunk(b"tEXt", b"Comment\x00" + " ".join(
            rng.choice(["alpha", "bravo", "charlie"]) for _ in range(rng.randint(1, 5))
        ).encode())
    out += _png_chunk(b"IDAT", zlib.compress(raw, 6)) + _png_chunk(b"IEND", b"")
    return out


# ---------------------------------------------------------------- gif --------
def make_gif(rng: random.Random) -> bytes:
    w, h = rng.randint(4, 32), rng.randint(4, 32)
    gct = rng.randbytes(768)
    out = bytearray(b"GIF89a")
    out += struct.pack("<HH", w, h) + bytes([0xF7, 0, 0]) + gct
    if rng.random() < 0.7:
        comment = b"".join(rng.choice([b"alpha", b"bravo", b"delta"]) for _ in range(3))
        out += b"\x21\xfe" + bytes([len(comment) & 0xFF]) + comment + b"\x00"
    out += b"\x2c" + struct.pack("<HHHH", 0, 0, w, h) + bytes([0])
    payload = rng.randbytes(rng.randint(16, 128))
    out += bytes([8]) + bytes([len(payload)]) + payload + b"\x00" + b"\x3b"
    return bytes(out)


# ---------------------------------------------------------------- zip --------
def make_zip(rng: random.Random) -> bytes:
    files = {}
    for i in range(rng.randint(1, 4)):
        name = rng.choice(["notes", "readme", "data", "flag", "photo"]) + \
            (f"{i}" if i else "") + rng.choice([".txt", ".md", ".json", ".csv", ""])
        if rng.random() < 0.5:
            body = "\n".join(
                rng.choice(["alpha bravo charlie", "key=value", "1,2,3", "{}",
                            "строка для проверки", "user=admin"])
                for _ in range(rng.randint(1, 6))
            ).encode()
        else:  # уже сжатый/случайный контент — ведёт себя как STORED
            body = rng.randbytes(rng.randint(32, 900))
        files[name] = body
    import io
    buf = io.BytesIO()
    method = ZIP_STORED if rng.random() < 0.3 else ZIP_DEFLATED
    with ZipFile(buf, "w", method) as zf:
        for name, body in files.items():
            zf.writestr(name, body)
    return buf.getvalue()


# ---------------------------------------------------------------- pdf --------
def make_pdf(rng: random.Random) -> bytes:
    pages = []
    for p in range(rng.randint(1, 12)):
        text = " ".join(rng.choice(["alpha", "bravo", "charlie", "delta", "echo",
                                    "foxtrot", "golf"])
                        for _ in range(rng.randint(3, 30)))
        hidden = ("CTF{" + "".join(rng.choice("abcdef0123456789") for _ in range(10)) + "}"
                  if p == 0 and rng.random() < 0.5 else "")
        stream = (f"BT /F1 12 Tf 72 {760 - p * 20} Td ({text}) Tj ET\n").encode()
        if hidden:
            stream += f"BT /F1 1 Tf 72 200 Td 3 Tr ({hidden}) Tj ET\n".encode()
        if rng.random() < 0.4:  # бинарный поток (изображение), как в настоящих PDF
            stream += b"stream\n" + rng.randbytes(rng.randint(500, 20000)) + b"\nendstream\n"
        pages.append(stream)
    objs, page_ids = [], []
    n_first = 3
    for i in range(len(pages)):
        page_ids.append(n_first + i * 2)
    objs.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    kids = b" ".join(b"%d 0 R" % i for i in page_ids)
    objs.append(b"<< /Type /Pages /Kids [" + kids + b"] /Count %d >>" % len(pages))
    font_id = n_first + len(pages) * 2
    for i, stream in enumerate(pages):
        objs.append(b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                    b"/Resources << /Font << /F1 %d 0 R >> >> /Contents %d 0 R >>"
                    % (font_id, page_ids[i] + 1))
        objs.append(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream")
    objs.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    out += b"% " + bytes(rng.choice(b"abcdef0123456789")
                         for _ in range(rng.randint(16, 48))) + b"\n"
    offsets = []
    for i, body in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += (b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n"
            % (len(objs) + 1, xref))
    return bytes(out)


# -------------------------------------------------------------- sqlite ------
def make_sqlite(rng: random.Random) -> bytes:
    # база собирается в памяти и сериализуется: файл на диске замедляет
    # генерацию в сотни раз (антивирус проверяет каждый временный файл)
    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, secret TEXT, blob BLOB)")
    n_rows = rng.randint(5, 200)
    rows = [(i, f"user{i}",
             "CTF{" + "".join(rng.choice("abc123") for _ in range(8)) + "}"
             if i == n_rows - 1 else f"note {i} " + "x" * rng.randint(0, 40),
             rng.randbytes(rng.randint(0, 48)))
            for i in range(n_rows)]
    con.executemany("INSERT INTO users VALUES (?,?,?,?)", rows)
    con.execute("CREATE TABLE log (ts TEXT, msg TEXT)")
    con.executemany("INSERT INTO log VALUES (?,?)",
                    [(f"2026-11-14T12:{i % 60:02d}:00Z",
                      rng.choice(["login ok", "auth failed", "upload", "query slow"]))
                     for i in range(rng.randint(5, 300))])
    con.commit()
    if rng.random() < 0.7:  # «удалённая» строка остаётся в страницах
        con.execute("DELETE FROM users WHERE id = ?", (rows[-1][0],))
        con.commit()
    blob = con.serialize()
    con.close()
    return blob


# ---------------------------------------------------------------- pcap ------
def _dns_query(name: str, qid: int) -> bytes:
    labels = b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\x00"
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + labels + struct.pack(">HH", 1, 1)


def make_pcap(rng: random.Random) -> bytes:
    # четыре варианта подписи из features.MAGICS: LE/BE и микро/наносекунды.
    # Сетевые железки пишут BE, современный dumpcap — наносекундный pcap.
    pf, magic = rng.choice((
        ("<", 0xA1B2C3D4), (">", 0xA1B2C3D4),
        ("<", 0xA1B23C4D), (">", 0xA1B23C4D),
    ))
    out = bytearray(struct.pack(pf + "IHHiIII", magic, 2, 4, 0, 0, 65535,
                                rng.choice([1, 1, 101])))
    n_packets = rng.randint(20, 200)
    for i in range(n_packets):
        qid = rng.randint(1, 65535)
        if rng.random() < 0.35:
            # DNS-запрос: имя целиком в открытом виде
            dns = _dns_query(rng.choice(["ctf.local", "a.ctf.local", "flag.ctf.local",
                                         "exfil.ctf.local", "portal.corp.local"]), qid)
            udp = struct.pack(">HHHH", 33333 + i % 20000, 53, 8 + len(dns), 0) + dns
            proto = 17
        else:
            # «шифрованный» трафик: высокая энтропия, как у настоящих дампов
            payload = rng.randbytes(rng.randint(100, 1200))
            udp = struct.pack(">HHHH", 33333 + i % 20000, rng.randint(1024, 65000),
                              8 + len(payload), 0) + payload
            proto = 6
        ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), qid, 0, 64, proto, 0,
                         bytes([10, 0, rng.randint(0, 4), i % 250 + 1]),
                         bytes([10, 0, 0, 53])) + udp
        eth = bytes.fromhex("aabbccddeeff112233445566") + b"\x08\x00" + ip
        frac = rng.randint(0, 999_999_999 if magic == 0xA1B23C4D else 999_999)
        out += struct.pack(pf + "IIII", 1700000000 + i, frac,
                           len(eth), len(eth)) + eth
    return bytes(out)


# ----------------------------------------------------------------- mp3 ------
def _id3_frame(fid: bytes, text: str) -> bytes:
    body = b"\x01\xff\xfe" + text.encode("utf-16-le")
    size = struct.pack(">I", len(body))
    return fid + size + b"\x00\x00" + body


def make_mp3(rng: random.Random) -> bytes:
    frames = rng.randbytes(rng.randint(2000, 20000))
    if rng.random() < 0.4:  # без ID3: настоящий mp3 часто начинается сразу с кадров
        return b"\xff\xfb\x90\x64" + frames
    title = rng.choice(["track one", "hidden", "alpha bravo"])
    tag = _id3_frame(b"TIT2", title) + _id3_frame(b"TPE1", "unknown")
    if rng.random() < 0.8:
        tag += _id3_frame(b"TXXX", "CTF{" + "".join(rng.choice("xyz789") for _ in range(9)) + "}")
    size = len(tag)
    synch = bytes([(size >> 21) & 0x7F, (size >> 14) & 0x7F,
                   (size >> 7) & 0x7F, size & 0x7F])
    return b"ID3\x03\x00\x00" + synch + tag + frames


# ------------------------------------------------------------ json-логи -----
def make_json_log(rng: random.Random) -> bytes:
    lines = []
    for i in range(rng.randint(3, 20)):
        rec = {"ts": f"2026-11-14T12:{rng.randint(10, 59)}:{rng.randint(10, 59)}Z",
               "lvl": rng.choice(["INFO", "WARN", "DEBUG"]),
               "msg": rng.choice(["login ok", "auth failed", "upload", "query slow"])}
        if rng.random() < 0.4:
            rec["blob"] = base64.b64encode(
                rng.randbytes(12)).decode()
        if rng.random() < 0.3:
            rec["user"] = f"user{rng.randint(1, 99)}"
        lines.append(json.dumps(rec, ensure_ascii=False))
    return ("\n".join(lines) + "\n").encode()


# ------------------------------------------------------------ python ---------
_CLEAN = '''import os
import sys


def parse_args(argv):
    """Разбор аргументов."""
    out = {}
    for item in argv:
        if "=" in item:
            k, v = item.split("=", 1)
            out[k] = v
    return out


def main():
    args = parse_args(sys.argv[1:])
    print("usage:", os.path.basename(sys.argv[0]), args)


if __name__ == "__main__":
    main()
'''

_FUNC_NAMES = ("parse_args", "load_config", "check_license", "verify_token",
               "collect_hashes", "transform", "decode_payload", "run_checks")
_ARG_NAMES = ("argv", "path", "data", "key", "payload", "blob", "src")
_DOCS = ("Разбор аргументов.", "Читает конфиг с диска.", "Проверяет подпись.",
         "Собирает хеши файлов.", "Декодирует полезную нагрузку.",
         "Возвращает результат проверки.", "Готовит данные к отправке.")
_MODULES = ("os", "sys", "json", "argparse", "pathlib", "re", "hashlib",
            "itertools", "struct", "random", "time", "logging")
_MODULE_DOCS = ("Утилита для разбора архивов.", "Скрипт проверки конфигурации.",
                "Сборщик метрик и логов.", "Декодер полезной нагрузки.",
                "Клиент внутреннего API.")
_COMMENTS = ("TODO: убрать после отладки", "оставим для совместимости",
             "здесь была проверка подписи", "FIXME: медленно на больших файлах",
             "временный обход", "согласовано с бэкендом")
_METHODS = ("run", "dump", "validate", "encode", "decode", "close", "reset")

# Реальные .py из CTF — это короткие скрипты-решения: импорт Crypto/pwn,
# числа в hex, побитовые операции, минимум слов. Именно на них модель
# спотыкалась: код выглядел как конфиг (много «=», «:», мало букв).
_CTF_IMPORTS = ("from Crypto.Util.number import *", "from Crypto.Cipher import AES",
                "from Crypto.Hash import SHA256", "from pwn import *",
                "import hashlib, os, sys", "from z3 import *", "import numpy as np",
                "from secret import flag")


def _ctf_script(rng: random.Random) -> str:
    """Скрипт в стиле «решение крипто-задачи»: hex-числа, bit-ops, print."""
    lines = list(rng.sample(_CTF_IMPORTS, rng.randint(1, 3))) + [""]
    if rng.random() < 0.6:
        lines += [f"n = 0x{rng.getrandbits(rng.choice([256, 512, 1024])):x}",
                  f"e = {rng.choice([3, 17, 65537])}",
                  f"c = 0x{rng.getrandbits(rng.choice([256, 512])):x}", ""]
    fn = rng.choice(("solve", "attack", "decrypt", "main"))
    lines += [f"def {fn}({rng.choice(['', 'data', 'n, c'])}):"]
    for _ in range(rng.randint(2, 7)):
        r = rng.random()
        if r < 0.25:
            lines.append(f"    p = {rng.choice(['getPrime(512)', 'isqrt(n)', 'next_prime(q)', 'n // q'])}")
        elif r < 0.45:
            lines.append(f"    m = {rng.choice(['pow(c, d, n)', 'c ^ k', 'bytes_to_long(flag)', 'long_to_bytes(m)'])}")
        elif r < 0.6:
            lines.append(f"    if {rng.choice(['p * q == n', 'isPrime(p)', 'len(flag) > 20'])}:")
            lines.append(f"        print({rng.choice(['long_to_bytes(m)', 'hex(m)', 'flag'])}.decode())")
        elif r < 0.75:
            lines.append(f"    {rng.choice(['d', 'phi', 'k', 'x'])} = "
                         f"{rng.choice(['inverse(e, phi)', '(p - 1) * (q - 1)', 'n >> 3', 'c & 0xff'])}")
        else:
            lines.append(f"    # {rng.choice(['sanity check', 'bruteforce the small factor', 'TODO: fix'])}")
    lines += ["    return " + rng.choice(["m", "None", "long_to_bytes(m)"]), "",
              f"print({fn}({rng.choice(['', 'n, c'])}))", ""]
    return "\n".join(lines)


def make_py(rng: random.Random) -> bytes:
    if rng.random() < 0.2:
        # shell-скрипт: это тоже код, а не конфиг (у него shebang)
        return ("#!/bin/bash\n"
                f"set -e{rng.choice(['uo', 'uox'])} pipefail\n"
                f"export TOKEN={rng.getrandbits(128):032x}\n"
                f"cd {rng.choice(['/opt/app', '/srv/www', '/home/mira/project'])}\n"
                f"./run.sh --port {rng.randint(2000, 9999)} "
                f"--user {rng.choice(['mira', 'ops', 'svc'])} "
                f">> /var/log/{rng.choice(['app', 'svc', 'worker'])}.log 2>&1\n").encode()
    if rng.random() < 0.45:
        if rng.random() < 0.6:   # половина — «скрипт-решение», как в архивах
            return _ctf_script(rng).encode()
        # настоящий исходник: 20–150 строк, docstring модуля, импорты,
        # функции и классы с методами, комментарии. Короткие «игрушки» из
        # двух функций модель путала с конфигами.
        mods = ["sys"] + rng.sample([m for m in _MODULES if m != "sys"],
                                    rng.randint(2, 6))
        rng.shuffle(mods)
        lines = [f'"""{rng.choice(_MODULE_DOCS)}"""', ""]
        lines += [f"import {m}" for m in mods] + ["", ""]
        names = rng.sample(_FUNC_NAMES, rng.randint(2, 5))
        for fn in names:
            if rng.random() < 0.4:
                lines += [f"# {rng.choice(_COMMENTS)}", ""]
            if rng.random() < 0.3:
                cname = "".join(p.title() for p in fn.split("_"))
                lines += [f"class {cname}:",
                          f'    """{rng.choice(_DOCS)}"""',
                          "",
                          f"    def __init__(self, {rng.choice(_ARG_NAMES)}):",
                          f"        self.data = {rng.choice(['None', '{}', '[]'])}",
                          ""]
                for m in rng.sample(_METHODS, rng.randint(1, 3)):
                    lines += [f"    def {m}(self, {rng.choice(_ARG_NAMES)}):",
                              f'        """{rng.choice(_DOCS)}"""',
                              f"        return {rng.choice(['None', 'self', 'True'])}",
                              ""]
            else:
                arg = rng.choice(_ARG_NAMES)
                var = rng.choice(["result", "value", "out"])
                lines += [f"def {fn}({arg}):",
                          f'    """{rng.choice(_DOCS)}"""',
                          f"    {var} = {arg}.strip()",
                          f"    return {var}",
                          ""]
        last = rng.choice(names)
        lines += ['if __name__ == "__main__":',
                  "    print(" + last + "(sys.argv[1] if len(sys.argv) > 1 else ''))",
                  ""]
        return "\n".join(lines).encode()
    payload = "print('CTF{" + "".join(rng.choice("qwe456") for _ in range(8)) + "}')"
    blob = base64.b64encode(zlib.compress(payload.encode())).decode()
    if rng.random() < 0.5:
        return (
            "import base64, zlib\n"
            f"_p = '{blob}'\n"
            "exec(zlib.decompress(base64.b64decode(_p)))\n"
        ).encode()
    parts = [blob[i:i + 20] for i in range(0, len(blob), 20)]
    head = "import base64, zlib\n" + "\n".join(
        f"_p{i} = '{part}'" for i, part in enumerate(parts))
    join = " + ".join(f"_p{i}" for i in range(len(parts)))
    return (head + f"\nexec(zlib.decompress(base64.b64decode({join})))\n").encode()


# ------------------------------------------------------------ текст задачи ---
_RU = ("Нам перехватили архив с базой пользователей. Внутри лежит флаг, "
       "запакованный дважды: сначала XOR с ключом из письма, потом base64. "
       "Ключ — это имя файла без расширения, регистр важен.",
       "В логах остался только обрывок трафика. Известно, что числа в метках "
       "DNS — это смещения байтов флага. Собери флаг по порядку.",
       "Картинка выглядит обычной, но младшие биты каналов хранят текст. "
       "Порядок каналов не RGB, а перемешан. Подсказка лежит в комментарии.",
       "Документ подписан, но подпись не сходится. Проверь, не меняли ли "
       "файл после подписания, и найди, что именно вырезали.")
_EN = ("We captured a small pcap from the internal network. The flag is split "
       "across DNS queries, one character per label. Reassemble it in order.",
       "The archive is password protected. The password is hidden in the letter "
       "next to it, but the letter is reversed and rot13'd.",
       "This PDF renders a blank page. There is text with rendering mode 3. "
       "Extract it and follow the trail.",
       "A tiny PNG. The least significant bits of the pixels spell something. "
       "Try every channel order before giving up.")

_MD = ["## Задача", "### Описание", "#### Подсказка", "- Шаг 1:", "* формат:",
       "- файл: `{}`", "1. распакуй", "2. посмотри", "```\n{}\n```",
       "> примечание: флаг в формате CTF{...}", "---"]


def make_doc(rng: random.Random) -> bytes:
    """Текст условия задачи: markdown, кириллица, имена файлов, куски кода."""
    parts = []
    for _ in range(rng.randint(2, 6)):
        parts.append(rng.choice(_MD))
    parts.append(rng.choice(_RU) if rng.random() < 0.6 else rng.choice(_EN))
    if rng.random() < 0.4:
        parts.append("files: " + ", ".join(
            rng.choice(["cipher.txt", "pubkey.pem", "photo.png", "capture.pcap",
                        "letter.txt", "backup.zip"]) for _ in range(rng.randint(1, 3))))
    if rng.random() < 0.3:
        parts.append("```\nn = 1234567890123456789012345678901234567890123456789\n"
                     "e = 65537\nc = 9876543210987654321098765432109876543210\n```")
    if rng.random() < 0.5:
        parts.append("CTF{" + "".join(rng.choice("narrative_hint") for _ in range(12)) + "}")
    return ("\n\n".join(parts) + "\n").encode()


# ---------------------------------------------------------------- jpeg -------
def make_jpeg(rng: random.Random) -> bytes:
    w, h = rng.randint(16, 512), rng.randint(16, 512)
    app0 = b"\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    dqt = b"\xff\xdb\x00\x43\x00" + rng.randbytes(64)
    sof = b"\xff\xc0\x00\x11\x08" + struct.pack(">HH", h, w) + b"\x03\x01\x22\x00\x02\x11\x01\x03\x11\x01"
    payload = rng.randbytes(rng.randint(512, 20000))
    return b"\xff\xd8" + app0 + dqt + sof + b"\xff\xda\x00\x0c\x03\x01\x00\x02\x11\x03\x11\x00\x3f\x00" + payload + b"\xff\xd9"


# ----------------------------------------------------------------- wav -------
def make_wav(rng: random.Random) -> bytes:
    import io
    import wave
    rate = rng.choice([8000, 16000, 22050, 44100])
    ch = rng.choice([1, 1, 2])
    n = rng.randint(4000, 120000)  # до ~0.5 МБ на канал
    buf = io.BytesIO()
    with wave.open(buf, "wb") as wf:
        wf.setnchannels(ch)
        wf.setsampwidth(2)
        wf.setframerate(rate)
        wf.writeframes(rng.randbytes(n * 2 * ch))
    return buf.getvalue()


# -------------------------------------------------------------- pcapng ------
def _ng_block(btype: int, body: bytes) -> bytes:
    total = 12 + len(body) + ((4 - len(body) % 4) % 4)
    return struct.pack("<II", btype, total) + body + b"\x00" * (total - 12 - len(body)) + struct.pack("<I", total)


def make_pcapng(rng: random.Random) -> bytes:
    shb = _ng_block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = _ng_block(1, struct.pack("<HHI", 1, 0, 65535))
    out = bytearray(shb + idb)
    for i in range(rng.randint(20, 160)):
        if rng.random() < 0.3:
            dns = _dns_query(rng.choice(["ctf.local", "a.ctf.local", "flag.ctf.local"]),
                             rng.randint(1, 65000))
            payload = struct.pack(">HHHH", 33333 + i % 20000, 53, 8 + len(dns), 0) + dns
        else:
            payload = struct.pack(">HHHH", 33333 + i % 20000, rng.randint(1024, 65000),
                                  0, 0) + rng.randbytes(rng.randint(100, 1200))
        ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), i, 0, 64, 17, 0,
                         bytes([10, 0, 0, i % 250 + 1]), bytes([10, 0, 0, 53])) + payload
        eth = bytes.fromhex("aabbccddeeff112233445566") + b"\x08\x00" + ip
        ts = 1700000000 + i
        body = struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(eth), len(eth)) + eth
        out += _ng_block(6, body)
    return bytes(out)


# ------------------------------------------------------------ disk image -----
def make_disk(rng: random.Random) -> bytes:
    """MBR + разметка + «файловая система»: много нулей, вкрапления данных."""
    size = rng.choice([64, 128, 256]) * 1024
    img = bytearray(size)
    mbr = bytearray(512)
    for i in range(rng.randint(1, 3)):
        base = 446 + i * 16
        mbr[base:base + 1] = b"\x80" if i == 0 else b"\x00"
        mbr[base + 4:base + 5] = b"\x83"
        mbr[base + 8:base + 12] = struct.pack("<I", rng.randint(1, 8))
        mbr[base + 12:base + 16] = struct.pack("<I", rng.randint(100, 400))
    mbr[510:512] = b"\x55\xaa"
    img[:512] = mbr
    sb = 1024
    img[sb + 56:sb + 58] = b"\x53\xef"          # ext2-магия
    img[sb + 4:sb + 8] = struct.pack("<I", rng.randint(50, 400))
    blocks = rng.randint(2, 12)
    for _ in range(blocks):
        off = rng.randrange(2048, size - 512)
        chunk = rng.randbytes(rng.randint(16, 400))
        img[off:off + len(chunk)] = chunk
    return bytes(img)


# ----------------------------------------------------------------- elf -------
def make_elf(rng: random.Random) -> bytes:
    is64 = rng.random() < 0.7
    mach = rng.choice([0x3E, 0x28, 0xB7, 0x03])  # x86-64, ARM, AArch64, x86
    hdr = bytearray(64 if is64 else 52)
    hdr[0:4] = b"\x7fELF"
    hdr[4] = 2 if is64 else 1
    hdr[5] = 1
    hdr[6] = 1
    hdr[16:18] = struct.pack("<H", 3 if rng.random() < 0.5 else 2)  # ET_DYN / ET_EXEC
    hdr[18:20] = struct.pack("<H", mach)
    hdr[20:24] = struct.pack("<I", 1)
    body = bytearray(rng.randbytes(rng.randint(2000, 200000)))
    # настоящие бинарники на 30–50% состоят из нулей: .bss, выравнивание,
    # пустые секции — без этого ELF путался с образом диска
    for _ in range(rng.randint(2, 6)):
        start = rng.randrange(0, max(1, len(body) - 8))
        end = min(len(body), start + rng.randint(len(body) // 10 + 1, len(body) // 2))
        body[start:end] = b"\x00" * (end - start)
    # куски настоящего текста внутри — как в бинарнике
    words = b"\x00".join(rng.choice([b"usage: ", b"license", b"CTF{", b"error: ",
                                     b"/proc/self/", b"libc.so.6"])
                         for _ in range(rng.randint(2, 6)))
    return bytes(hdr) + words + bytes(body)


# ------------------------------------------------------------------ pe -------
def make_pe(rng: random.Random) -> bytes:
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = struct.pack("<I", 64)
    pe = bytearray(b"PE\x00\x00")
    pe[4:6] = struct.pack("<H", rng.choice([0x8664, 0x14C]))
    pe[6:8] = struct.pack("<H", rng.randint(1, 5))
    pe += rng.randbytes(200)
    body = bytearray(rng.randbytes(rng.randint(2000, 200000)))
    for _ in range(rng.randint(2, 6)):  # нулевые паддинги секций, как в реальном PE
        start = rng.randrange(0, max(1, len(body) - 8))
        end = min(len(body), start + rng.randint(len(body) // 10 + 1, len(body) // 2))
        body[start:end] = b"\x00" * (end - start)
    strings = b"\x00".join(rng.choice([b"kernel32.dll", b"GetProcAddress",
                                       b"VirtualAlloc", b"CTF{", b"cmd.exe"])
                           for _ in range(rng.randint(2, 6)))
    return bytes(dos) + bytes(pe) + strings + bytes(body)


# ------------------------------------------------------------- plain log -----
_LVLS = ("INFO", "WARN", "ERROR", "DEBUG", "NOTICE")


def make_log(rng: random.Random) -> bytes:
    lines = []
    for i in range(rng.randint(5, 120)):
        ts = f"Aug {rng.randint(10, 28)} {rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}:{rng.randint(0, 59):02d}"
        user = rng.choice(["mira", "root", "ops", "svc_backup", "admin"])
        host = rng.choice(["web-01", "db-02", "edge", "build"])
        kind = rng.random()
        if kind < 0.4:
            ip = f"{rng.randint(10, 192)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
            lines.append(f"{ts} {host} sshd[{rng.randint(100, 9999)}]: "
                         f"Accepted password for {user} from {ip} port {rng.randint(1024, 65000)} ssh2")
        elif kind < 0.7:
            lines.append(f"{ts} {host} kernel: [{rng.randint(1, 99999)}.{rng.randint(0, 999999)}] "
                         f"{rng.choice(_LVLS)}: {rng.choice(['link up', 'usb 1-1: new device', 'oom-killer', 'eth0: renamed'])}")
        else:
            lines.append(f"{ts} {host} {rng.choice(_LVLS)} {rng.choice(['worker', 'api', 'cron'])}: "
                         f"{rng.choice(['job finished', 'retry', 'token refreshed', 'upload failed'])} "
                         f"in {rng.randint(1, 3000)} ms")
    return ("\n".join(lines) + "\n").encode()


# ---------------------------------------------------------------- config -----
_CFG_USERS = ("mira", "root", "ops", "svc_backup", "admin", "deploy", "buildbot")
_CFG_HOSTS = ("web-01", "db-02", "edge", "build", "cache-1", "worker-7", "bastion")
_CFG_DIRS = ("/opt/app", "/srv/data", "/var/lib/app", "/home/deploy", "/data/vol")
_CFG_SVCS = ("api", "web", "worker", "scheduler", "gateway", "metrics", "cron")
_CFG_KEYS = ("token", "secret", "api_key", "hmac", "passwd", "db_password",
             "session_salt", "smtp_password", "signing_key")
_CFG_SECTIONS = ("server", "auth", "cache", "db", "tls", "logging", "worker",
                 "limits", "routes")


def _cfg_stamp(rng: random.Random, kind: str) -> str:
    """Комментарий с build-id: у каждого файла свой.

    Без него конфиги выходили байт-в-байт одинаковыми (аудит находил сотни
    дублей и утечку test -> train), потому что все поля были из коротких
    списков. Теперь даже при совпадении всех полей остаётся метка сборки,
    а комментарий — обычная практика в реальных конфигах.
    """
    body = (f"build {rng.randint(2023, 2026)}-{rng.randint(1, 12):02d}-"
            f"{rng.randint(1, 28):02d}T{rng.randint(0, 23):02d}:"
            f"{rng.randint(0, 59):02d}:{rng.randint(0, 59):02d}Z "
            f"sha={rng.getrandbits(48):012x}")
    return f"<!-- {body} -->" if kind == "xml" else f"# {body}"


def _cfg_hex(rng: random.Random, n: int = 32) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


def make_config(rng: random.Random) -> bytes:
    """Конфиг в одном из текстовых форматов: yaml, ini, xml, Dockerfile, shell.

    Все поля случайные: имена, порты, пути, теги образов, пользователи,
    секреты, набор и порядок секций. Два одинаковых файла не получаются.
    """
    kind = rng.choice(["yaml", "ini", "xml", "dockerfile", "shell"])
    stamp = _cfg_stamp(rng, kind)
    if kind == "yaml":
        lines = [f"version: '{rng.randint(2, 3)}.{rng.randint(0, 9)}'", stamp,
                 "services:"]
        for svc in rng.sample(_CFG_SVCS, rng.randint(1, 3)):
            image = (f"{rng.choice(['registry.local', 'docker.io', 'ghcr.io'])}"
                     f"/{rng.choice(['app', 'svc', 'team'])}/{svc}:"
                     f"{rng.randint(1, 9)}.{rng.randint(0, 20)}.{rng.randint(0, 9)}")
            lines += [f"  {svc}:", f"    image: {image}",
                      f"    restart: {rng.choice(['always', 'unless-stopped', 'on-failure'])}",
                      "    ports:",
                      f"      - \"{rng.randint(2000, 9999)}:{rng.choice([80, 8080, 3000, 5000])}\"",
                      "    environment:"]
            for key in rng.sample(_CFG_KEYS, rng.randint(1, 3)):
                val = (rng.choice(["${" + key.upper() + "}", str(rng.randint(1, 10 ** 6)),
                                   _cfg_hex(rng, rng.choice([16, 24, 32]))]))
                lines.append(f"      {key.upper()}: \"{val}\"")
            lines += ["    volumes:",
                      f"      - {rng.choice(_CFG_DIRS)}:/data"]
            if rng.random() < 0.4:
                lines += [f"    healthcheck:",
                          f"      test: [\"CMD\", \"curl\", \"-f\", "
                          f"\"http://localhost:{rng.randint(2000, 9999)}/health\"]",
                          f"      interval: {rng.choice([10, 15, 30])}s"]
        if rng.random() < 0.5:
            lines += ["volumes:", f"  data{rng.randint(1, 9)}:"]
        body = "\n".join(lines) + "\n"
    elif kind == "ini":
        lines = [stamp]
        for sect in rng.sample(_CFG_SECTIONS, rng.randint(1, 4)):
            lines.append(f"[{sect}]")
            for key in rng.sample(_CFG_KEYS + ("host", "port", "timeout", "workers",
                                               "realm", "level"),
                                  rng.randint(2, 5)):
                if key in ("port", "timeout", "workers"):
                    lines.append(f"{key} = {rng.randint(1, 65535)}")
                elif key == "host":
                    lines.append(f"host = {rng.randint(10, 192)}.{rng.randint(0, 255)}"
                                 f".{rng.randint(0, 255)}.{rng.randint(1, 254)}")
                elif key == "level":
                    lines.append(f"level = {rng.choice(['debug', 'info', 'warn'])}")
                else:
                    lines.append(f"{key} = {_cfg_hex(rng, rng.choice([16, 32, 40]))}")
            lines.append("")
        body = "\n".join(lines) + "\n"
    elif kind == "xml":
        lines = ['<?xml version="1.0" encoding="utf-8"?>', stamp,
                 f"<settings version=\"{rng.randint(1, 9)}.{rng.randint(0, 9)}\">",
                 f"  <server host=\"{rng.choice(_CFG_HOSTS)}\" "
                 f"port=\"{rng.randint(1024, 65535)}\" "
                 f"tls=\"{rng.choice(['true', 'false'])}\"/>"]
        for _ in range(rng.randint(1, 5)):
            user = rng.choice(_CFG_USERS)
            lines.append(f"  <user id=\"{rng.randint(1, 9999)}\" name=\"{user}\" "
                         f"role=\"{rng.choice(['admin', 'operator', 'viewer'])}\">"
                         f"<pin>{rng.randint(1000, 9999)}</pin>"
                         f"<key>{_cfg_hex(rng, 24)}</key></user>")
        lines.append(f"  <limits cpu=\"{rng.randint(1, 16)}\" "
                     f"mem=\"{rng.choice([256, 512, 1024, 2048])}\"/>")
        lines.append("</settings>")
        body = "\n".join(lines) + "\n"
    elif kind == "dockerfile":
        base = rng.choice([("python", "3.12-slim"), ("python", "3.11-alpine"),
                         ("debian", "bookworm"), ("node", "20-alpine"),
                         ("ubuntu", "22.04")])
        port = rng.randint(2000, 9999)
        pkgs = " ".join(rng.sample(["curl", "git", "libpq5", "build-essential",
                                    "ca-certificates", "jq", "tini", "openssl"],
                                   rng.randint(1, 4)))
        lines = [stamp,
                 f"FROM {base[0]}:{base[1]}",
                 f"LABEL maintainer=\"{rng.choice(_CFG_USERS)}@"
                 f"{rng.choice(['corp.local', 'example.org', 'team.dev'])}\"",
                 f"RUN apt-get update && apt-get install -y {pkgs} \\",
                 "    && rm -rf /var/lib/apt/lists/*",
                 f"WORKDIR {rng.choice(_CFG_DIRS)}",
                 f"COPY {rng.choice(['.', 'src/', 'app/'])} /app",
                 f"ENV PORT={port} LOG_LEVEL={rng.choice(['debug', 'info'])} "
                 f"BUILD_ID={_cfg_hex(rng, 12)}",
                 f"EXPOSE {port}",
                 f"CMD [\"{rng.choice(['python3', 'node', 'sh'])}\", "
                 f"\"{rng.choice(['main.py', 'server.js', 'run.sh'])}\"]"]
        body = "\n".join(lines) + "\n"
    else:
        # dotenv-конфиг: это конфиг, а не код. Shell-скрипт с shebang уехал в
        # py_src — иначе модель путала исходники с конфигами (17 ошибок).
        lines = [stamp, f"APP_ENV={rng.choice(['production', 'staging', 'dev'])}",
                 f"APP_PORT={rng.randint(2000, 9999)}",
                 f"DB_HOST=db.{rng.choice(['internal', 'local', 'corp'])}",
                 f"DB_USER={rng.choice(_CFG_USERS)}",
                 f"DB_PASSWORD={_cfg_hex(rng, rng.choice([16, 24, 32]))}",
                 f"DATA_DIR={rng.choice(_CFG_DIRS)}"]
        body = "\n".join(lines) + "\n"
    return body.encode()


# =============== форматы из расширенного списка MAGICS =======================
# Ниже — всё, что приходит в CTF настоящим контейнером, а не кодировкой:
# документы (rtf, psd), архивы (xz, bz2, 7z, rar), медиа (tiff, aiff, caf, ogg,
# flac, mkv, ico) и байткод (wasm). Где stdlib даёт настоящий кодек (bz2, lzma),
# берётся он; остальным собирается правдоподобная структура: верная подпись,
# согласованные размеры/CRC/смещения и случайная полезная нагрузка.
_WORDS = ("alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo "
          "lima mike november oscar papa quebec romeo sierra tango uniform").split()


def _text_blob(rng: random.Random, lo_kb: int, hi_kb: int) -> bytes:
    """Текст заданного размера — сжимаемая нагрузка для xz/bz2."""
    need = rng.randint(lo_kb, hi_kb) * 1024
    out, size = [], 0
    while size < need:
        line = " ".join(rng.choice(_WORDS) for _ in range(rng.randint(4, 12))) + "\n"
        out.append(line)
        size += len(line)
    return "".join(out).encode()


# ----------------------------------------------------------------- xz --------
def make_xz(rng: random.Random) -> bytes:
    """Настоящий .xz: lzma.compress, файл распаковывается xz -d."""
    body = (rng.randbytes(rng.randint(16, 256) * 1024) if rng.random() < 0.5
            else _text_blob(rng, 16, 192))
    return lzma.compress(body, format=lzma.FORMAT_XZ, preset=rng.randint(0, 6))


# ---------------------------------------------------------------- bz2 --------
def make_bz2(rng: random.Random) -> bytes:
    """Настоящий .bz2 через stdlib; уровень сжатия тоже случаен."""
    body = (rng.randbytes(rng.randint(24, 96) * 1024) if rng.random() < 0.5
            else _text_blob(rng, 20, 80))
    return bz2.compress(body, rng.randint(1, 9))


# ---------------------------------------------------------------- rtf --------
def make_rtf(rng: random.Random) -> bytes:
    """RTF: таблицы шрифтов/цветов, абзацы, кириллица через \\'hh и скрытый текст."""
    fonts = rng.sample(["Calibri", "Times New Roman", "Courier New", "Arial",
                        "DejaVu Serif", "Consolas"], rng.randint(1, 3))
    font_tbl = "".join(f"{{\\f{i}\\fnil\\fcharset{rng.choice([0, 204])} {name};}}"
                       for i, name in enumerate(fonts))
    colors = "".join(f"\\red{rng.randint(0, 255)}\\green{rng.randint(0, 255)}"
                     f"\\blue{rng.randint(0, 255)};"
                     for _ in range(rng.randint(1, 3)))
    parts = [f"{{\\rtf1\\ansi\\ansicpg1252\\deff0\\nouicompat{{\\fonttbl{font_tbl}}}",
             "{\\colortbl ;" + colors + "}",
             f"{{\\*\\generator Riched20 {rng.randint(12, 16)}.0."
             f"{rng.randint(1000, 19045)};}}",
             "\\viewkind4\\uc1"]
    for _ in range(rng.randint(120, 700)):
        fid = rng.randint(0, len(fonts) - 1)
        size = rng.choice([18, 20, 22, 24, 28, 32])
        if rng.random() < 0.12:  # кириллица в RTF живёт как \'hh-escape
            text = "".join(f"\\'{ord(c):02x}" for c in
                           rng.choice(["привет", "секрет", "отчёт готов", "файл рядом"]))
        else:
            text = " ".join(rng.choice(_WORDS) for _ in range(rng.randint(3, 12)))
        parts.append(f"\\pard\\sa{rng.randint(0, 240)}\\sl276\\slmult1"
                     f"\\f{fid}\\fs{size} {text}\\par")
    if rng.random() < 0.3:  # {\v ...} — невидимый текст, любимое место для флага
        parts.append("{\\v CTF{" + "".join(rng.choice("rtf0123")
                                           for _ in range(10)) + "}}")
    parts.append("}")
    return "\n".join(parts).encode()


# --------------------------------------------------------------- tiff --------
def make_tiff(rng: random.Random) -> bytes:
    """TIFF: заголовок II/MM, IFD с настоящими тегами, затем полоса пикселей."""
    be = rng.random() < 0.3            # MM (big-endian) встречается реже, чем II
    pf = ">" if be else "<"
    w, h = rng.choice([128, 160, 200, 256, 320, 512]), rng.choice([128, 160, 200, 256, 320, 512])
    spp = rng.choice([1, 3, 3, 4])     # grayscale / RGB / RGBA
    pixel = rng.randbytes(w * h * spp)
    bits = b"".join(struct.pack(pf + "H", 8) for _ in range(spp))

    n_entries = 12
    extra = 8 + 2 + n_entries * 12 + 4  # сразу за IFD
    if len(bits) > 4:
        bits_off, extra = extra, extra + len(bits) + (len(bits) % 2)
    xres_off, extra = extra, extra + 8
    yres_off, extra = extra, extra + 8
    pix_off = extra

    def entry(tag: int, typ: int, count: int, value) -> bytes:
        """typ 3 (SHORT) держит значение в первых 2 байтах поля, 4 — целиком."""
        if isinstance(value, int):
            value = (struct.pack(pf + "H", value) + b"\x00\x00"
                     if typ == 3 else struct.pack(pf + "I", value))
        assert len(value) == 4, (tag, len(value))
        return struct.pack(pf + "HHI", tag, typ, count) + value

    entries = [
        entry(256, 3, 1, w), entry(257, 3, 1, h),
        entry(258, 3, spp, struct.pack(pf + "I", bits_off) if len(bits) > 4
              else bits + b"\x00" * (4 - len(bits))),
        entry(259, 3, 1, 1),                       # без сжатия
        entry(262, 3, 1, 1 if spp == 1 else 2),    # BlackIsZero / RGB
        entry(273, 4, 1, pix_off),                 # StripOffsets
        entry(277, 3, 1, spp),
        entry(278, 4, 1, h),                       # RowsPerStrip
        entry(279, 4, 1, len(pixel)),              # StripByteCounts
        entry(282, 5, 1, struct.pack(pf + "I", xres_off)),
        entry(283, 5, 1, struct.pack(pf + "I", yres_off)),
        entry(296, 3, 1, 2),                       # ResolutionUnit: дюймы
    ]
    out = bytearray((b"MM\x00*" if be else b"II*\x00") + struct.pack(pf + "I", 8))
    out += struct.pack(pf + "H", len(entries)) + b"".join(entries)
    out += struct.pack(pf + "I", 0)                # других IFD нет
    if len(bits) > 4:
        out += bits + b"\x00" * (len(bits) % 2)
    out += struct.pack(pf + "II", 72, 1) + struct.pack(pf + "II", 72, 1)
    out += pixel
    return bytes(out)


# --------------------------------------------------------------- aiff --------
def _ext80(value: float) -> bytes:
    """80-битный IEEE extended: так в AIFF записан sample rate."""
    mant, exp = math.frexp(value)      # value = mant * 2**exp, 0.5 <= mant < 1
    mant *= 2.0
    exp -= 1
    return struct.pack(">HQ", exp + 16383, int(mant * (1 << 63)))


def make_aiff(rng: random.Random) -> bytes:
    """AIFF/AIFC: FORM -> COMM(18) -> NAME/ANNO -> SSND с PCM."""
    ch = rng.choice([1, 1, 2])
    rate = rng.choice([8000, 16000, 22050, 44100, 48000])
    frames = rng.randint(8000, 250000)
    pcm = rng.randbytes(frames * ch * 2)
    form_type = b"AIFC" if rng.random() < 0.2 else b"AIFF"
    chunks = b"COMM" + struct.pack(">I", 18) + struct.pack(">HIH", ch, frames, 16) + _ext80(rate)
    if form_type == b"AIFC":  # у AIFC первым идёт FVER, после COMM — тип сжатия
        comp = b"NONE" + bytes([len("not compressed")]) + b"not compressed"
        comp += b"\x00" * (len(comp) % 2)          # pascal-строка выравнивается
        chunks = (b"FVER" + struct.pack(">II", 4, 0xA2805140)
                  + chunks + b"sowt" + struct.pack(">I", len(comp)) + comp)
    if rng.random() < 0.4:
        name = rng.choice(["demo", "track", "hidden", "record"]) + str(rng.randint(1, 99))
        chunks += b"NAME" + struct.pack(">I", len(name)) + name.encode()
    if rng.random() < 0.35:  # ANNO — обычное место для «комментария с флагом»
        note = "CTF{" + "".join(rng.choice("aiff789") for _ in range(9)) + "}"
        chunks += b"ANNO" + struct.pack(">I", len(note)) + note.encode()
    chunks += b"SSND" + struct.pack(">III", 8 + len(pcm), 0, 0) + pcm
    return b"FORM" + struct.pack(">I", 4 + len(chunks)) + form_type + chunks


# ---------------------------------------------------------------- caf --------
def make_caf(rng: random.Random) -> bytes:
    """CAF (Apple Core Audio): caff -> desc -> info/strg -> data."""
    ch = rng.choice([1, 2])
    rate = rng.choice([8000.0, 22050.0, 44100.0, 48000.0])
    frames = rng.randint(8000, 250000)
    pcm = rng.randbytes(frames * ch * 2)
    body = (b"desc" + struct.pack(">q", 32) + struct.pack(">d", rate) + b"lpcm"
            + struct.pack(">IIIII", 0x02, ch * 2, 1, ch, 16))
    if rng.random() < 0.5:  # info-чанк: пары ключ/значение, как в настоящем CAF
        pairs = [(b"title", rng.choice([b"demo", b"capture", b"hidden"])),
                 (b"artist", rng.choice([b"unknown", b"ops", b"mira"]))]
        if rng.random() < 0.3:
            pairs.append((b"comment", b"CTF{" + bytes(rng.choice(b"caf456")
                                                      for _ in range(9)) + b"}"))
        data = struct.pack(">I", len(pairs))
        for key, val in pairs:
            data += struct.pack(">I", len(val) + 4) + key + val
        body += b"info" + struct.pack(">q", len(data)) + data
    body += b"data" + struct.pack(">q", 4 + len(pcm)) + struct.pack(">I", 0) + pcm
    return b"caff" + struct.pack(">HH", 1, 0) + body


# ---------------------------------------------------------------- ogg --------
def _ogg_crc_table() -> tuple:
    tbl = []
    for i in range(256):
        r = i << 24
        for _ in range(8):
            r = ((r << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if r & 0x80000000 \
                else (r << 1) & 0xFFFFFFFF
        tbl.append(r)
    return tuple(tbl)


_OGG_CRC = _ogg_crc_table()


def _ogg_page(serial: int, seq: int, htype: int, granule: int, payload: bytes) -> bytes:
    """Страница Ogg с настоящим CRC32 (полином 0x04C11DB7, без отражения)."""
    segs, rest = [], len(payload)
    while rest >= 255:
        segs.append(255)
        rest -= 255
    segs.append(rest)
    hdr = (b"OggS\x00" + bytes([htype]) + struct.pack("<qII", granule, serial, seq)
           + b"\x00\x00\x00\x00" + bytes([len(segs)]) + bytes(segs))
    crc = 0
    for b in hdr + payload:
        crc = ((crc << 8) & 0xFFFFFFFF) ^ _OGG_CRC[((crc >> 24) ^ b) & 0xFF]
    return hdr[:22] + struct.pack("<I", crc) + hdr[26:] + payload


def make_ogg(rng: random.Random) -> bytes:
    """Ogg Vorbis: идентификационный и comment-заголовки + «аудио» страницы."""
    serial = rng.getrandbits(32)
    ch = rng.choice([1, 2])
    rate = rng.choice([8000, 22050, 44100, 48000])
    ident = (b"\x01vorbis" + struct.pack("<I", 0) + bytes([ch])
             + struct.pack("<Iiii", rate, -1, 128000, 0)
             + bytes([0xB8, 1]))       # blocksize 256/2048, framing=1
    vendor = rng.choice(["Xiph.Org libVorbis I 20200704", "ffmpeg 6.0",
                         "Lavf58.76.100"]).encode()
    tags = [f"TITLE={rng.choice(['demo', 'hidden', 'alpha'])}",
            f"ARTIST={rng.choice(['unknown', 'ops', 'mira'])}"]
    if rng.random() < 0.3:
        tags.append("COMMENT=CTF{" + "".join(rng.choice("ogg456")
                                             for _ in range(10)) + "}")
    comment = b"\x03vorbis" + struct.pack("<I", len(vendor)) + vendor
    comment += struct.pack("<I", len(tags))
    for tag in tags:
        line = tag.encode()
        comment += struct.pack("<I", len(line)) + line
    comment += b"\x01"
    out = bytearray(_ogg_page(serial, 0, 0x02, 0, ident))     # BOS
    out += _ogg_page(serial, 1, 0x00, 0, comment)
    total, written, seq = rng.randint(16, 400) * 1024, 0, 2
    while written < total:
        n = min(rng.randint(2000, 60000), total - written)
        last = written + n >= total
        out += _ogg_page(serial, seq, 0x04 if last else 0x00, written // 2000,
                         rng.randbytes(n))
        written += n
        seq += 1
    return bytes(out)


# --------------------------------------------------------------- flac --------
def make_flac(rng: random.Random) -> bytes:
    """FLAC: STREAMINFO (34 Б) + опциональный VORBIS_COMMENT + «кадры»."""
    rate = rng.choice([44100, 48000, 96000])
    ch = rng.choice([1, 2])
    total_samples = rng.randint(200000, 9000000)
    packed = (rate << 44) | ((ch - 1) << 41) | ((16 - 1) << 36) | total_samples
    streaminfo = (struct.pack(">HH", 4096, 4096)
                  + rng.randint(200, 4000).to_bytes(3, "big")
                  + rng.randint(4001, 20000).to_bytes(3, "big")
                  + packed.to_bytes(8, "big") + rng.randbytes(16))
    has_comment = rng.random() < 0.6
    out = bytearray(b"fLaC")
    out += bytes([0x00 if has_comment else 0x80]) + len(streaminfo).to_bytes(3, "big")
    out += streaminfo
    if has_comment:
        vendor = rng.choice(["reference libFLAC 1.4.3 20230623", "flac 1.4.2",
                             "ffmpeg"]).encode()
        tags = [("TITLE", rng.choice(["demo", "hidden", "alpha"])),
                ("ENCODER", vendor.decode())]
        if rng.random() < 0.3:
            tags.append(("COMMENT", "CTF{" + "".join(rng.choice("flac789")
                                                     for _ in range(9)) + "}"))
        body = struct.pack("<I", len(vendor)) + vendor + struct.pack("<I", len(tags))
        for key, val in tags:
            line = f"{key}={val}".encode()
            body += struct.pack("<I", len(line)) + line
        out += b"\x84" + len(body).to_bytes(3, "big") + body
    # «аудиокадры»: 14-битный синк 0xFFF8 и мусорное тело, как в потоке
    left = rng.randint(16, 300) * 1024
    while left > 0:
        n = min(rng.randint(1000, 8000), left)
        out += b"\xff\xf8" + rng.randbytes(max(0, n - 2))
        left -= n
    return bytes(out)


# ---------------------------------------------------------------- mkv --------
def _ebml_size(n: int) -> bytes:
    """VINT размера EBML: ведущие биты задают длину."""
    for length in range(1, 9):
        if n < (1 << (7 * length)) - 1:
            return ((1 << (7 * length)) | n).to_bytes(length, "big")
    raise ValueError(n)


def _ebml(eid: bytes, body: bytes) -> bytes:
    return eid + _ebml_size(len(body)) + body


def _ebml_uint(eid: bytes, value: int) -> bytes:
    return _ebml(eid, value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big"))


def make_mkv(rng: random.Random) -> bytes:
    """Matroska: EBML-заголовок, Segment -> Info/Tracks/Cluster с кадрами."""
    doc = (_ebml_uint(b"\x42\x86", 1) + _ebml_uint(b"\x42\xf7", 1)
           + _ebml_uint(b"\x42\xf2", 4) + _ebml_uint(b"\x42\xf3", 8)
           + _ebml(b"\x42\x82", b"matroska")
           + _ebml_uint(b"\x42\x87", rng.choice([2, 4]))
           + _ebml_uint(b"\x42\x85", 2))
    info = _ebml(b"\x15\x49\xa9\x66",
                 _ebml_uint(b"\x2a\xd7\xb1", 1_000_000)
                 + _ebml(b"\x7b\xa9", rng.choice(["demo", "episode", "capture"]).encode())
                 + _ebml(b"\x44\x89", struct.pack(">d", rng.uniform(10, 3600)))
                 + _ebml(b"\x4d\x80", b"libebml2 + mkvmuxer")
                 + _ebml(b"\x57\x41", b"mkvmerge v83.0"))
    track = _ebml(b"\xae",
                  _ebml_uint(b"\xd7", 1) + _ebml_uint(b"\x73\xc5", rng.getrandbits(32))
                  + _ebml_uint(b"\x83", 2) + _ebml(b"\x86", b"A_OPUS")
                  + _ebml(b"\x53\x6e", rng.choice(["Audio 1", "main", "mic"]).encode()))
    seg_body = bytearray(info + _ebml(b"\x16\x54\xae\x6b", track))
    left, ts = rng.randint(16, 400) * 1024, 0
    while left > 0:
        n = min(rng.randint(2000, 60000), left)
        block = _ebml(b"\xa3", b"\x81" + struct.pack(">hB", ts % 32768, 0x80)
                      + rng.randbytes(n))
        seg_body += _ebml(b"\x1f\x43\xb6\x75", _ebml_uint(b"\xe7", ts) + block)
        ts += 20
        left -= n
    return (_ebml(b"\x1a\x45\xdf\xa3", doc) + b"\x18\x53\x80\x67"
            + _ebml_size(len(seg_body)) + bytes(seg_body))


# --------------------------------------------------------------- wasm --------
def _leb(n: int) -> bytes:
    """LEB128 без знака — так в wasm записаны все размеры."""
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _wasm_section(sid: int, body: bytes) -> bytes:
    return bytes([sid]) + _leb(len(body)) + body


def make_wasm(rng: random.Random) -> bytes:
    """Модуль WebAssembly: type/function/memory/export/code + data-сегмент."""
    pages = rng.randint(2, 64)
    types = _wasm_section(1, b"\x01\x60\x00\x01\x7f")           # () -> i32
    funcs = _wasm_section(3, b"\x01\x00")
    mem = _wasm_section(5, b"\x01\x00" + _leb(pages))
    exports = _wasm_section(7, b"\x01" + _leb(6) + b"memory\x02\x00")
    body = b"\x00\x41" + _leb(rng.randint(0, 4096)) + b"\x1a\x0b"  # i32.const; drop; end
    code = _wasm_section(10, b"\x01" + _leb(len(body)) + body)
    payload = rng.randbytes(rng.randint(12, 400) * 1024)
    data = _wasm_section(11, b"\x01\x00\x41\x00\x0b" + _leb(len(payload)) + payload)
    out = bytearray(b"\x00asm\x01\x00\x00\x00")
    out += types + funcs + mem + exports + code
    if rng.random() < 0.5:  # custom-секция producers: обычная для бинарников
        name = b"producers"
        info = rng.choice([b"processed-by\x01\x08ffmpeg\x001.0",
                           b"language\x03\x02py\x00"])
        out += _wasm_section(0, _leb(len(name)) + name + info)
    out += data
    return bytes(out)


# ---------------------------------------------------------------- psd --------
def make_psd(rng: random.Random) -> bytes:
    """Photoshop: 8BPS, image resources с блоком версии, плоские каналы."""
    ch = rng.choice([3, 3, 4])
    h = rng.choice([128, 192, 256, 320, 512])
    w = rng.choice([128, 192, 256, 320, 512])
    out = bytearray(b"8BPS" + struct.pack(">H", 1) + b"\x00" * 6
                    + struct.pack(">HIIHH", ch, h, w, 8, 3))     # RGB, 8 бит
    out += struct.pack(">I", 0)                                  # color mode data
    ver = (struct.pack(">I", 1) + b"Adobe Photoshop 24.7 (20240101.r.1) "
           + b"20240202.r.100 2024-02-02T10:11:12+00:00")
    res = b"8BIM" + struct.pack(">H", 0x0421) + b"\x00\x00" + struct.pack(">I", len(ver)) + ver
    if len(ver) % 2:
        res += b"\x00"
    out += struct.pack(">I", len(res)) + res                     # image resources
    out += struct.pack(">I", 0)                                  # layer and mask info
    comp = rng.choice([0, 0, 1])                                 # raw или RLE
    out += struct.pack(">H", comp)
    if comp == 1:  # RLE: на каждый канал идёт таблица длин строк
        rows = b"".join(struct.pack(">H", rng.randint(1, 128)) for _ in range(h * ch))
        out += rows + rng.randbytes(h * ch * max(1, w // 2))
    else:
        out += rng.randbytes(h * w * ch)
    return bytes(out)


# ---------------------------------------------------------------- ico --------
def make_ico(rng: random.Random) -> bytes:
    """ICO: ICONDIR + записи + BMP DIB (или вложенный PNG, как в Vista+)."""
    sizes = rng.sample([64, 96, 128, 192, 256], rng.randint(1, 3))
    images = []
    for d in sizes:
        if d >= 128 and rng.random() < 0.3:   # PNG-кадр внутри .ico
            images.append((d, make_png(rng)))
            continue
        xor = rng.randbytes(d * d * 4)
        and_mask = b"\x00" * (d * ((d + 31) // 32) * 4)
        dib = struct.pack("<IiiHHIIiiII", 40, d, d * 2, 1, 32, 0,
                          len(xor) + len(and_mask), 0, 0, 0, 0)
        images.append((d, dib + xor + and_mask))
    out = bytearray(struct.pack("<HHH", 0, 1, len(images)))
    offset = 6 + 16 * len(images)
    for d, blob in images:
        out += struct.pack("<BBBBHHII", d % 256, d % 256, 0, 0, 1, 32, len(blob), offset)
        offset += len(blob)
    for _d, blob in images:
        out += blob
    return bytes(out)


# ----------------------------------------------------------------- 7z --------
def _7z_num(value: int) -> bytes:
    """Переменная длина числа 7z (алгоритм WriteNumber из LZMA SDK)."""
    first, mask, i = 0, 0x80, 0
    while i < 8:
        if value < (1 << (7 * (i + 1))):
            first |= (value >> (8 * i)) & 0xFF
            break
        first |= mask
        mask >>= 1
        i += 1
    out, rest = bytearray([first]), value
    for _ in range(i):
        out.append(rest & 0xFF)
        rest >>= 8
    return bytes(out)


def make_7z(rng: random.Random) -> bytes:
    """7z: сигнатура с CRC стартового заголовка, упакованный поток, next header."""
    packed = rng.randbytes(rng.randint(16, 400) * 1024)
    size = len(packed)
    props = bytes([93, 0, 0, 0x10, 0])          # lc/lp/pb + размер словаря
    main = (b"\x06" + _7z_num(0) + _7z_num(1) + b"\x09" + _7z_num(size) + b"\x00"
            + b"\x07" + b"\x0b" + _7z_num(1) + b"\x00"
            + _7z_num(1) + b"\x23\x03\x01\x01" + bytes([len(props)]) + props
            + b"\x0c" + _7z_num(size) + b"\x00"
            + b"\x08\x00" + b"\x00")
    nxt = b"\x01\x04" + main + b"\x00"          # kHeader -> kMainStreamsInfo -> kEnd
    start = struct.pack("<QQ", len(packed), len(nxt)) + struct.pack(
        "<I", zlib.crc32(nxt) & 0xFFFFFFFF)
    sig = (b"7z\xbc\xaf\x27\x1c" + b"\x00\x04"
           + struct.pack("<I", zlib.crc32(start) & 0xFFFFFFFF) + start)
    return sig + packed + nxt


# ---------------------------------------------------------------- rar --------
def make_rar(rng: random.Random) -> bytes:
    """RAR4: маркер + заголовок архива + файловые блоки с настоящим CRC16."""
    def block(htype: int, flags: int, body: bytes) -> bytes:
        head = struct.pack("<BHH", htype, flags, 7 + len(body)) + body
        return struct.pack("<H", zlib.crc32(head) & 0xFFFF) + head

    out = bytearray(b"Rar!\x1a\x07\x00")
    out += block(0x73, 0, b"\x00\x00" + b"\x00\x00\x00\x00")   # архивный заголовок
    for _ in range(rng.randint(1, 2)):
        name = rng.choice(["secret.txt", "backup.dat", "flag.bin", "notes.md"])
        data = rng.randbytes(rng.randint(16, 400) * 1024)
        body = (struct.pack("<II", len(data), len(data))
                + bytes([rng.choice([2, 3])])
                + struct.pack("<I", zlib.crc32(data) & 0xFFFFFFFF)
                + struct.pack("<I", rng.getrandbits(32))
                + bytes([rng.choice([20, 29]), 0x30])
                + struct.pack("<H", len(name)) + struct.pack("<I", 0x20)
                + name.encode())
        out += block(0x74, 0x0000, body)
        out += data
    return bytes(out)


# ------------------------------------------------------------ git ------------
def make_git_object(rng: random.Random) -> bytes:
    """Свободный объект (loose object): zlib от «blob N\\0…» — так лежит .git."""
    kind = rng.choice(["blob", "tree", "commit", "tag"])
    if kind == "commit":
        body = (b"tree " + bytes(rng.choice(b"0123456789abcdef") for _ in range(40))
                + b"\nauthor mira <mira@corp> 1700000000 +0300\n"
                + b"committer mira <mira@corp> 1700000000 +0300\n\n"
                + rng.choice([b"fix bug\n", b"add flag\n", b"initial commit\n"]))
    else:
        body = rng.randbytes(rng.randint(16, 400))
    return zlib.compress(b"%s %d\x00" % (kind.encode(), len(body)) + body)


def make_git_index(rng: random.Random) -> bytes:
    """Индекс: DIRC + версия + записи (путь, mtime, sha, размер)."""
    out = bytearray(b"DIRC" + struct.pack(">II", 2, rng.randint(1, 8)))
    for i in range(rng.randint(1, 8)):
        name = rng.choice([b"flag.txt", b"main.py", b"README.md", b"src/app.c"])
        out += struct.pack(">IIIIIIIIII", 0, 0, 0, 0, 33188, 0, 0, 0, 0x1234 + i, len(name))
        out += bytes(rng.choice(b"0123456789abcdef") for _ in range(40)) + b"\x00" + name
        out += b"\x00" * ((8 - (len(out) % 8)) % 8)
    return bytes(out)


def make_git_pack(rng: random.Random) -> bytes:
    """Pack-файл: PACK + версия + число объектов + сжатые куски."""
    out = bytearray(b"PACK" + struct.pack(">II", 2, rng.randint(1, 200)))
    for _ in range(rng.randint(2, 20)):
        out += b"\x00" + zlib.compress(rng.randbytes(rng.randint(20, 800)))
    return bytes(out) + bytes(rng.choice(b"0123456789abcdef") for _ in range(40))


def make_git_ref(rng: random.Random) -> bytes:
    """Ссылка: sha1 и перев.\n — HEAD, refs/heads/*, packed-refs."""
    if rng.random() < 0.3:
        return b"ref: refs/heads/" + rng.choice([b"main", b"master", b"dev"]) + b"\n"
    line = bytes(rng.choice(b"0123456789abcdef") for _ in range(40)) + b"\n"
    if rng.random() < 0.4:
        line = b"# pack-refs with: peeled\n" + line + b"^" + \
            bytes(rng.choice(b"0123456789abcdef") for _ in range(40)) + b"\n"
    return line


def make_git_config(rng: random.Random) -> bytes:
    return (f"[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n"
            f"\tbare = {rng.choice(['false', 'true'])}\n"
            f"[remote \"origin\"]\n\turl = https://git.local/{rng.choice(['app', 'infra'])}.git\n"
            f"\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
            f"[user]\n\tname = {rng.choice(['mira', 'ops', 'ci'])}\n"
            f"\temail = {rng.choice(['mira', 'ci'])}@corp\n").encode()


# --------------------------------------------------------------- ecc ---------
def make_ecc_task(rng: random.Random) -> bytes:
    """Текст ECC-задачи: параметры кривой и точки — как их дают на CTF."""
    small = rng.choice([True, False])
    if small:
        p = rng.choice([9739, 1021, 10177, 65537, 1000003])
    else:
        p = rng.choice([2 ** 61 - 1, 2 ** 127 - 1, 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF])
    a = rng.randint(1, 2000)
    b = rng.randint(1, 2000)
    gx, gy = rng.randrange(p), rng.randrange(p)
    qx, qy = rng.randrange(p), rng.randrange(p)
    n = rng.randint(p // 2, p) if p > 3 else 3
    style = rng.random()
    if style < 0.4:
        body = (f"p = {p}\na = {a}\nb = {b}\n"
                f"G = ({gx}, {gy})\nQ = ({qx}, {qy})\nn = {n}\n"
                "Find the private key d such that Q = d*G.\n")
    elif style < 0.7:
        body = (f"E = EllipticCurve(GF({p}), [{a}, {b}])\n"
                f"G = E({gx}, {gy})\nQ = E({qx}, {qy})\n"
                f"# order = {n}\n# flag = d\n")
    else:
        body = (f"Curve: y^2 = x^3 + {a}x + {b} over GF({p})\n"
                f"Generator G = ({gx}, {gy})\nPublic point Q = ({qx}, {qy})\n"
                f"Curve order n = {n}\nRecover d.\n")
    if rng.random() < 0.25:
        # «голые» параметры без единого слова-подсказки — так тоже дают
        body = (f"p = {p}\na = {a}\nb = {b}\nn = {n}\n"
                f"G = ({gx}, {gy})\nQ = ({qx}, {qy})\n")
    if rng.random() < 0.5:
        body += "flag format: CTF{d}\n"
    return body.encode()


MAKERS = {
    "png": make_png,
    "gif": make_gif,
    "jpeg": make_jpeg,
    "zip": make_zip,
    "pdf": make_pdf,
    "sqlite": make_sqlite,
    "pcap": make_pcap,
    "pcapng": make_pcapng,
    "mp3": make_mp3,
    "wav": make_wav,
    "elf": make_elf,
    "pe": make_pe,
    "disk_img": make_disk,
    "json_log": make_json_log,
    "plain_log": make_log,
    "py_src": make_py,
    "config_text": make_config,
    "doc_text": make_doc,
    # форматы из расширенного MAGICS
    "rtf": make_rtf,
    "xz": make_xz,
    "bz2": make_bz2,
    "tiff": make_tiff,
    "aiff": make_aiff,
    "caf": make_caf,
    "ogg": make_ogg,
    "flac": make_flac,
    "7z": make_7z,
    "rar": make_rar,
    "mkv": make_mkv,
    "wasm": make_wasm,
    "psd": make_psd,
    "ico": make_ico,
    # git: объекты, индекс, pack, refs, config
    "git_object": make_git_object,
    "git_index": make_git_index,
    "git_pack": make_git_pack,
    "git_ref": make_git_ref,
    "git_config": make_git_config,
    "ecc_task": make_ecc_task,
}


def make(kind: str, rng: random.Random) -> bytes:
    return MAKERS[kind](rng)
