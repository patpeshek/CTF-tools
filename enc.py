#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
enc.py — быстрые преобразования «на старте»: base64, hex, url, rot13, реверс,
бинарные/десятичные коды, base32, base85.

Использование:
  python enc.py "Q1RGe2ZsYWd9"
  python enc.py --file secret.txt
  python enc.py "text" --all      # показать все варианты, даже неоднозначные
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
import binascii
import codecs
import os
import re
import sys
import unicodedata
import urllib.parse


def printable(b: bytes) -> bool:
    if not b:
        return False
    ok = sum(32 <= c < 127 or c in (9, 10, 13) for c in b)
    return ok / len(b) > 0.85


def printable_text(s: str) -> bool:
    if not s:
        return False
    ok = sum(1 for ch in s if ch.isprintable() or ch in "\r\n\t")
    return ok / len(s) > 0.85


CODECS = ("utf-8", "utf-16", "utf-16-le", "utf-16-be", "utf-32",
          "utf-32-le", "utf-32-be", "cp1251", "cp1252", "cp866",
          "koi8-r", "koi8-u", "iso8859-5", "mac_cyrillic", "latin-1",
          "utf-7")

Z85_ALPHABET = ("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                ".-:+=^!/*?&<>()[]{}@%$#")
B92_ALPHABET = ("!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "[\\]^_abcdefghijklmnopqrstuvwxyz{|}")


def text_score(t: str) -> float:
    if not t:
        return 0.0
    good = sum(1 for c in t if c.isprintable() or c in "\r\n\t")
    return good / len(t)


def decode_bytes(b: bytes, limit: int = 3):
    """Байты -> текст: BOM, utf-8, utf-16/32, кириллица, latin-1, utf-7."""
    if not b or len(b) > 4_000_000:
        return []
    out = []

    def push(enc, t):
        if not t or text_score(t) < 0.95:
            return
        ascii_ok = sum(1 for c in t if 32 <= ord(c) < 127) / len(t)
        cyr = sum(1 for c in t if "\u0400" <= c <= "\u04FF") / len(t)
        cjk = sum(1 for c in t if "\u3040" <= c <= "\u9FFF") / len(t)
        if ascii_ok < 0.5 and cyr < 0.25 and cjk < 0.5:
            return
        if all(t != x[1] for x in out):
            out.append((enc, t))

    if b.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        for enc in ("utf-32", "utf-32-le", "utf-32-be"):
            try:
                push(enc, b.decode(enc))
                break
            except UnicodeDecodeError:
                continue
    elif b.startswith((b"\xff\xfe", b"\xfe\xff")):
        for enc in ("utf-16", "utf-16-le", "utf-16-be"):
            try:
                push(enc, b.decode(enc))
                break
            except UnicodeDecodeError:
                continue
    try:
        push("utf-8", b.decode("utf-8"))
    except UnicodeDecodeError:
        pass
    for enc in CODECS:
        if len(out) >= limit:
            break
        if enc in ("utf-8", "utf-16", "utf-32"):
            continue
        try:
            push(enc, b.decode(enc))
        except (UnicodeDecodeError, LookupError):
            continue
    return out[:limit]


def b36decode(s: str) -> bytes:
    v = int(s, 36)
    return v.to_bytes(max(1, (v.bit_length() + 7) // 8), "big")


def z85decode(s: str) -> bytes:
    if len(s) % 5:
        raise ValueError("z85 length")
    out = bytearray()
    for i in range(0, len(s), 5):
        v = 0
        for ch in s[i:i + 5]:
            v = v * 85 + Z85_ALPHABET.index(ch)
        out += v.to_bytes(4, "big")
    return bytes(out)


def b92decode(s: str) -> bytes:
    vals = [B92_ALPHABET.index(c) for c in s]
    out = bytearray()
    buf = bits = 0
    for i in range(0, len(vals) - 1, 2):
        v = vals[i] * 91 + vals[i + 1]
        if v >= 8192:
            raise ValueError("base92 pair")
        buf = (buf << 13) | v
        bits += 13
        while bits >= 8:
            bits -= 8
            out.append((buf >> bits) & 0xFF)
        buf &= (1 << bits) - 1
    if len(vals) % 2:
        v = vals[-1]
        if v >= 64:
            raise ValueError("base92 tail")
        buf = (buf << 6) | v
        bits += 6
        if bits >= 8:
            out.append((buf >> (bits - 8)) & 0xFF)
    return bytes(out)


def b100decode(s: str) -> bytes:
    out = bytearray()
    for c in s.strip():
        if c == "\ufe0f":
            continue
        v = ord(c) - 0x1F3F7
        if not 0 <= v <= 255:
            raise ValueError("not base100")
        out.append(v)
    return bytes(out)


MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
    "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
    "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
    "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
    "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9", "..--..": "?", "-.-.--": "!", ".-.-.-": ".",
    "--..--": ",", "-..-.": "/",
}


def decode_morse_text(s: str) -> str:
    """Морзе, записанный текстом: '.... . .-.. .-.. --- / .-- --- .-. .-.. -..'."""
    t = s.replace("–", "-").replace("—", "-").replace("_", "-").replace("|", "/")
    words = re.split(r"\s*/\s*", t.strip())
    out = []
    for w in words:
        letters = [MORSE.get(chunk, "?") for chunk in w.split() if chunk]
        out.append("".join(letters))
    return " ".join(x for x in out if x)


def _moji_bytes(s: str):
    """Восстановить байты из «кракозябр»: U+0000..U+00FF → байт, остальное — cp1252."""
    out = bytearray()
    for ch in s:
        o = ord(ch)
        if o < 256:
            out.append(o)
            continue
        try:
            out += ch.encode("cp1252")
        except UnicodeEncodeError:
            return None
    return bytes(out)


def repair_mojibake(s: str):
    """Текст, прочитанный не той кодировкой: UTF-8 байты, показанные как cp1251/…"""
    out = []
    raw = _moji_bytes(s)
    if raw:
        try:
            t = raw.decode("utf-8")
        except UnicodeDecodeError:
            t = None
        if t and t != s and _better(t, s):
            out.append(("utf8-mojibake", t))
    base = sum(1 for ch in s if "\u0400" <= ch <= "\u04FF")
    junk = sum(s.count(x) for x in ("Ð", "Ñ", "Ã", "Â", "â€"))
    for enc in ("cp1251", "cp866"):
        try:
            t = s.encode(enc).decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            continue
        cyr = sum(1 for ch in t if "\u0400" <= ch <= "\u04FF")
        if cyr > base + 3 or (junk > 0 and t.count("Ð") + t.count("Ñ") < junk):
            out.append((f"utf8-as-{enc}", t))
    return out


def _better(t: str, s: str) -> bool:
    def score(x):
        return sum(1 for ch in x if "\u0400" <= ch <= "\u04FF") * 2 - \
            sum(x.count(m) for m in ("Ð", "Ñ", "â€", "Ãƒ"))
    return score(t) > score(s)


def try_all(s: str, show_all: bool = False):
    out = []
    stripped = s.strip()

    def add(name, val):
        if isinstance(val, bytes):
            got = decode_bytes(val, limit=1)
            for enc, txt in got:
                add(name if enc == "utf-8" else f"{name}/{enc}", txt)
            if not got:
                m = re.search(rb"[A-Za-z][A-Za-z0-9_]{1,20}\{[ -~]{2,100}\}", val)
                if m:
                    add(name + "/latin-1", val.decode("latin-1", "replace"))
            return
        val = str(val)
        val = str(val)
        if show_all or (val and val != s and printable_text(val)):
            out.append((name, val))
            rv = val[::-1]
            if rv != val and printable_text(rv):
                out.append((name + "+reverse", rv))

    # base64 (с добивкой паддинга)
    try:
        pad = stripped + "=" * (-len(stripped) % 4)
        add("base64", base64.b64decode(pad))
    except Exception:
        pass
    try:
        add("base64url", base64.urlsafe_b64decode(stripped + "=" * (-len(stripped) % 4)))
    except Exception:
        pass
    # base32 / base85
    try:
        add("base32", base64.b32decode(stripped.upper() + "=" * (-len(stripped) % 8)))
    except Exception:
        pass
    try:
        add("base85", base64.b85decode(stripped))
    except Exception:
        pass
    try:
        add("ascii85", base64.a85decode(stripped))
    except Exception:
        pass
    if re.fullmatch(r"[0-9A-Za-z]{6,}", stripped):
        try:
            add("base36", b36decode(stripped))
        except Exception:
            pass
    if (len(stripped) >= 10 and len(stripped) % 5 == 0
            and all(c in Z85_ALPHABET for c in stripped)):
        try:
            add("z85", z85decode(stripped))
        except Exception:
            pass
    if (len(stripped) >= 4 and all(c in B92_ALPHABET for c in stripped)
            and any(not c.isalnum() for c in stripped)):
        try:
            add("base92", b92decode(stripped))
        except Exception:
            pass
    if stripped and all(0x1F3F7 <= ord(c) <= 0x1F4F6 or c == "\ufe0f" for c in stripped):
        try:
            add("base100", b100decode(stripped))
        except Exception:
            pass
    # hex
    try:
        h = re.sub(r"(?i)0x|[\s:]", "", stripped)
        add("hex", binascii.unhexlify(h + "0" * (len(h) % 2)))
    except Exception:
        pass
    # url / html
    if "%" in stripped:
        add("url", urllib.parse.unquote(stripped))
    if "&" in stripped and ";" in stripped:
        import html
        add("html", html.unescape(stripped))
    if "=?" in stripped and "?=" in stripped:
        try:
            from email.header import decode_header
            parts = []
            for chunk, enc in decode_header(stripped):
                if isinstance(chunk, bytes):
                    parts.append(chunk.decode(enc or "utf-8", "replace"))
                else:
                    parts.append(chunk)
            add("mime-header", "".join(parts))
        except Exception:
            pass
    # «кракозябры»: текст прочитан не той кодировкой — это не шифр
    for name, fixed in repair_mojibake(stripped):
        add(name, fixed)
    # rot13 / rot47 / atbash
    add("rot13", codecs.decode(stripped, "rot13"))
    add("rot18", "".join(
        chr(65 + (ord(c) - 65 + 13) % 26) if "A" <= c <= "Z" else
        chr(97 + (ord(c) - 97 + 13) % 26) if "a" <= c <= "z" else
        chr(48 + (ord(c) - 48 + 5) % 10) if "0" <= c <= "9" else c
        for c in stripped))
    if all(33 <= ord(c) <= 126 or c in "\r\n\t" for c in stripped):
        add("rot47", "".join(
            chr(33 + ((ord(c) - 33 + 47) % 94)) if 33 <= ord(c) <= 126 else c
            for c in stripped))
    add("atbash", "".join(chr(219 - ord(c)) if "a" <= c <= "z" else
                          chr(155 - ord(c)) if "A" <= c <= "Z" else c for c in stripped))
    # математические/полноширинные буквы: 𝐂𝐓𝐅{...}, ＣＴＦ{...}
    nfkc = unicodedata.normalize("NFKC", stripped)
    if nfkc != stripped:
        add("nfkc", nfkc)
    # восьмеричные коды: 103 124 106 и \103\124\106
    if re.fullmatch(r"(?:\s*\\?[0-7]{2,4}){3,}", stripped):
        try:
            vals = re.findall(r"\\?([0-7]{2,4})", stripped)
            add("octal", bytes(int(x, 8) for x in vals).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            pass
    # \uXXXX / \xNN / \n
    if re.search(r"\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}", stripped):
        try:
            add("unicode-escape", codecs.decode(stripped, "unicode_escape"))
        except Exception:
            pass
    # base58/62/91, base32hex, quoted-printable — общий модуль obscure
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from crypto import obscure as _ob
        if re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{6,}", stripped):
            try:
                add("base58", _ob.b58decode(stripped))
            except Exception:
                pass
        if re.fullmatch(r"[0-9A-Za-z]{8,}", stripped):
            try:
                add("base62", _ob.b62decode(stripped))
            except Exception:
                pass
        if re.fullmatch(r"[A-Za-z0-9!#$%&()*+,./:;<=>?@\[\]^_`{|}~\"-]{6,}", stripped):
            try:
                add("base91", _ob.b91decode(stripped))
            except Exception:
                pass
        if re.fullmatch(r"[0-9A-V]+=*", stripped) and len(stripped) >= 6:
            try:
                add("base32hex", base64.b32hexdecode(stripped + "=" * (-len(stripped) % 8)))
            except Exception:
                pass
        if re.search(r"=[0-9A-Fa-f]{2}", stripped):
            import quopri
            add("quoted-printable",
                quopri.decodestring(stripped.encode()).decode("utf-8", "replace"))
    except Exception:
        pass
    # реверс
    add("reverse", stripped[::-1])
    # бинарный / десятичный / морзе
    if re.fullmatch(r"[01\s]{8,}", stripped):
        bits = re.sub(r"\s", "", stripped)
        add("binary", "".join(chr(int(bits[i:i + 8], 2)) for i in range(0, len(bits) - 7, 8)))
    if re.fullmatch(r"[.\-–—_/| \t\r\n]+", stripped) and "." in stripped and "-" in stripped:
        add("morse", decode_morse_text(stripped))
    # алфавит из двух символов без разделителей: 0/1, .-, AB ...
    body = re.sub(r"\s", "", stripped)
    syms = sorted(set(body))
    if len(syms) == 2 and len(body) >= 16:
        for hi in (syms[1], syms[0]):
            lo = syms[0] if hi == syms[1] else syms[1]
            bits = "".join("1" if ch == hi else "0" for ch in body)
            txt = "".join(chr(int(bits[i:i + 8], 2))
                          for i in range(0, len(bits) - 7, 8))
            add(f"2sym({hi}=1)", txt)
    if re.fullmatch(r"[\d\s,;]+", stripped):
        nums = [int(x) for x in re.findall(r"\d+", stripped)]
        if all(0 <= n <= 0x10FFFF for n in nums):
            add("dec->chr", "".join(chr(n) for n in nums))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("text", nargs="?")
    ap.add_argument("--file")
    ap.add_argument("--all", action="store_true")
    args = ap.parse_args()

    data = args.text
    raw = None
    if args.file:
        raw = open(args.file, "rb").read()
        data = raw.decode("utf-8", "replace")
    if not data and not raw:
        ap.error("нужен текст или --file")

    results = try_all(data or "", args.all)
    seen = {str(v) for _, v in results}
    if raw is not None:
        for enc, txt in decode_bytes(raw, limit=6):
            if txt not in seen:
                results.append((f"codec:{enc}", txt))
                seen.add(txt)
            for name, val in try_all(txt[:200_000], args.all):
                if val not in seen and (args.all or printable_text(val)):
                    results.append((f"{name}/{enc}" if enc != "utf-8" else name, val))
                    seen.add(val)
        try:
            ascii_s = raw.decode("ascii")
        except UnicodeDecodeError:
            ascii_s = None
        if ascii_s and ascii_s != data:
            for name, val in try_all(ascii_s[:200_000], args.all):
                if val not in seen:
                    results.append((name, val))
                    seen.add(val)
    if not results:
        print("[-] ничего осмысленного. Пробуй dcode.fr / CyberChef / смотри условие.")
    for name, val in results:
        print(f"[{name}] {val[:300]}")


if __name__ == "__main__":
    main()
