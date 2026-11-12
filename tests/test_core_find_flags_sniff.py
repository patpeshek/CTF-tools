#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_core_find_flags_sniff.py — проверки на баги #1, #2, #3.

Падал бы до исправления:
  #1 find_flags обрезал префикс (picoCTF -> CTF);
  #2 find_flags терял флаги со спецсимволами и кириллицей;
  #3 sniff не определял TAR и ряд других форматов.

Артефакты создаются кодом (tarfile/struct), ручных ответов нет.
Запуск: python tests/test_core_find_flags_sniff.py
"""
from __future__ import annotations

import io
import os
import sys
import tarfile

sys.dont_write_bytecode = True
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common  # noqa: E402

passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"[PASS] {name}")
    else:
        failed += 1
        print(f"[FAIL] {name}  {detail}")


def ff(s):
    return common.find_flags(s.encode("utf-8"))


# ---- #1: префикс отдаётся целиком, не обрезается ----
common.configure(prefixes=None, any_prefix=False)  # набор по умолчанию
check("#1 picoCTF целиком", "picoCTF{abc_def}" in ff("flag here picoCTF{abc_def} end"),
      ff("picoCTF{abc_def}"))
check("#1 picoCTF не режется до CTF", "CTF{abc_def}" not in ff("picoCTF{abc_def}"))
check("#1 DUCTF целиком", "DUCTF{abc_def}" in ff("DUCTF{abc_def}"), ff("DUCTF{abc_def}"))
check("#1 bcactf целиком", "bcactf{abc_def}" in ff("bcactf{abc_def}"), ff("bcactf{abc_def}"))
check("#1 обычный ctf работает", "ctf{normal_flag}" in ff("ctf{normal_flag}"))

# ---- #2: спецсимволы и кириллица ----
check("#2 плюс/равно", "flag{a+b=c_is_fun}" in ff("flag{a+b=c_is_fun}"), ff("flag{a+b=c_is_fun}"))
check("#2 угловые скобки", "flag{a<b>c_d_e}" in ff("flag{a<b>c_d_e}"), ff("flag{a<b>c_d_e}"))
check("#2 кириллица", "NTO{привет_мир}" in ff("NTO{привет_мир}"), ff("NTO{привет_мир}"))

# ---- отсутствие ложных срабатываний ----
check("нет ложного флага в обычном слове", ff("note{just a note}") == [], ff("note{just a note}"))
check("нет флага без префикса", ff("data{0101010101}") == [], ff("data{0101010101}"))

# ---- any-prefix: любой правдоподобный префикс ----
common.configure(prefixes=None, any_prefix=True)
check("any-prefix ловит weird", "weird{abc_def}" in ff("weird{abc_def}"), ff("weird{abc_def}"))
check("any-prefix тоже не режет", "picoCTF{abc_def}" in ff("picoCTF{abc_def}"))
common.configure(prefixes=None, any_prefix=False)  # вернуть по умолчанию


# ---- #3: sniff определяет форматы по данным ----
def tar_bytes():
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w") as t:
        ti = tarfile.TarInfo("a.txt")
        payload = b"hello"
        ti.size = len(payload)
        t.addfile(ti, io.BytesIO(payload))
    return b.getvalue()


png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
tar = tar_bytes()
bmp = b"BM" + b"\x36\x00\x00\x00" + b"\x00" * 60
ole = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 60
pcap_ns = b"\x4d\x3c\xb2\xa1" + b"\x00" * 60
mp3 = b"\xff\xfb\x90\x64" + b"\x00" * 60
webp = b"RIFF\x24\x00\x00\x00WEBPVP8 " + b"\x00" * 40
mz_text = b"MZ is just some text, definitely not a real PE binary here at all."
pe = b"MZ" + b"\x90" * 0x3a + b"\x00" * 4 + b"PE\x00\x00" + b"\x00" * 64

check("#3 TAR", common.sniff(tar[:512]) == "TAR", common.sniff(tar[:512]))
check("#3 BMP", common.sniff(bmp) == "BMP", common.sniff(bmp))
check("#3 OLE", common.sniff(ole) == "OLE", common.sniff(ole))
check("#3 PCAP наносекунды", common.sniff(pcap_ns) == "PCAP", common.sniff(pcap_ns))
check("#3 MP3 без ID3", common.sniff(mp3) == "MP3", common.sniff(mp3))
check("#3 WEBP", common.sniff(webp) == "WEBP", common.sniff(webp))
check("#3 текст на MZ не PE", common.sniff(mz_text) == "unknown", common.sniff(mz_text))
check("#3 настоящий PE", common.sniff(pe) == "PE", common.sniff(pe))
check("#3 PNG по-прежнему PNG", common.sniff(png) == "PNG", common.sniff(png))

print(f"\n=== PASS: {passed}  FAIL: {failed} ===")
sys.exit(1 if failed else 0)
