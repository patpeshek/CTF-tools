"""derive.py — ключ, выведенный из данных: «сложи числа, возьми SHA».

Частая схема: готового пароля в задаче нет, но есть подсказка «ключ — это
sha256 от суммы чисел из лога». Детерминированный поиск такое не находит:
числа есть, хеша нет, а «приготовить ключ» нечем.

Здесь маленький переборный движок:

  1. собрать числа из файла/папки (с метками и без);
  2. построить кандидатов: суммы/произведения/xor по подмножествам чисел
     (в подсказке обычно не все числа файла, а конкретные три), склейки,
     hex-формы, байты little/big endian;
  3. прогнать через md5/sha1/sha256 (и без хеша);
  4. попробовать как пароль ZIP, ключ AES, ключ XOR — принять только если
     реально расшифровалось.

  python misc/derive.py notes.txt --target secret.zip --mode zip
  python misc/derive.py task/ --target flag.enc --mode aes
  python misc/derive.py log.txt --mode print
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import os
import re
import zipfile

NUM_RE = re.compile(rb"-?\d{1,24}")
LABELED_RE = re.compile(rb"(?im)^\s*([A-Za-z_][\w \-]{0,24})\s*[:=]\s*(-?\d{1,24})")
FLAG_RE = re.compile(rb"[A-Za-z][A-Za-z0-9_]{1,15}\{[^{}\r\n]{1,200}\}")

MAX_NUMBERS = 12
MAX_CANDIDATES = 6000


def _text_files(target):
    if os.path.isfile(target):
        return [target]
    out = []
    for dirpath, dirs, names in os.walk(target):
        dirs[:] = [d for d in dirs if d not in ("__pycache__", ".git")]
        for n in sorted(names):
            p = os.path.join(dirpath, n)
            try:
                if 0 < os.path.getsize(p) <= 4 * 1024 * 1024:
                    out.append(p)
            except OSError:
                continue
    return out[:20]


def harvest(target):
    """Числа (с метками) из файлов цели."""
    labeled, plain = {}, []
    for p in _text_files(target):
        try:
            with open(p, "rb") as fh:
                data = fh.read(4 * 1024 * 1024)
        except OSError:
            continue
        for m in LABELED_RE.finditer(data):
            label = m.group(1).decode("latin-1").strip().lower()
            labeled.setdefault(label.replace(" ", "_"), m.group(2).decode())
        for m in NUM_RE.finditer(data):
            num = m.group(0).decode()
            if len(num.lstrip("-")) >= 2 and num not in plain:
                plain.append(num)
    return labeled, plain[:MAX_NUMBERS]


def _subset_combos(values, max_k=4, limit=700):
    """Суммы/произведения/xor по подмножествам чисел.

    В подсказке обычно не все числа файла, а конкретные («сумма трёх чисел
    выше»): 4821 + 137 + 9004, без отметок времени.
    """
    out = []
    vals = [v for v in values if v.lstrip("-").isdigit()][:MAX_NUMBERS]
    n = len(vals)
    for k in range(2, min(max_k, n) + 1):
        for combo in itertools.combinations(vals, k):
            ints = [int(x) for x in combo]
            total = sum(ints)
            out.append(str(total))
            out.append(str(abs(total)))
            prod = 1
            for i in ints:
                prod *= i
            if abs(prod) < 10 ** 40:
                out.append(str(prod))
            x = 0
            for i in ints:
                x ^= i
            out.append(str(x))
            if len(out) >= limit:
                return out
    return out


def _variants(values):
    """Индивидуальные числа, их комбинации и склейки."""
    out = list(values)
    out += _subset_combos(values)
    for sep in ("", "-", "_", ",", " "):
        for perm in itertools.islice(itertools.permutations(values), 8):
            out.append(sep.join(perm))
        out.append(sep.join(values))
        out.append(sep.join(reversed(values)))
    for v in list(out)[:60]:
        try:
            n = int(v)
        except ValueError:
            continue
        out.append(hex(n))
        out.append(hex(n)[2:])
        if 0 <= n < 2 ** 64:
            out.append(n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big").hex())
    seen, uniq = set(), []
    for v in out:
        if v and v not in seen:
            seen.add(v)
            uniq.append(v)
    return uniq


def candidates(values):
    """Варианты как есть и с хешами."""
    out = []
    for raw in _variants(values):
        b = raw.encode("utf-8", "replace")
        out.append(("raw:" + raw[:24], b))
        for algo in ("md5", "sha1", "sha256"):
            h = hashlib.new(algo, b)
            out.append((f"{algo}:{raw[:24]}", h.digest()))
            out.append((f"{algo}hex:{raw[:24]}", h.hexdigest().encode()))
        if len(out) > MAX_CANDIDATES:
            break
    seen, uniq = set(), []
    for tag, val in out:
        if val not in seen:
            seen.add(val)
            uniq.append((tag, val))
    return uniq[:MAX_CANDIDATES]


def _flag_ok(dec: bytes) -> bool:
    """Флаг должен быть читаемым: буквы/цифры внутри, без мусорных байтов.

    Без этого случайный ключ даёт «Sm{\\x9e\\xfe...» и regex срабатывает —
    ровно так и появился ложный «ключ найден» на первом тесте.
    """
    for m in FLAG_RE.finditer(dec):
        blob = m.group(0)
        inner = blob[blob.find(b"{") + 1:-1]
        if len(inner) < 4:
            continue
        if all(32 <= b < 127 for b in inner) and any(chr(c).isalnum() for c in inner):
            return True
    return False


def _plausible_plain(dec: bytes) -> bool:
    if len(dec) < 8:
        return False
    printable = sum(1 for b in dec if 32 <= b < 127 or b in (9, 10, 13))
    if printable / len(dec) > 0.92:
        return True
    return _flag_ok(dec)


def try_zip(path, cands):
    outdir = os.path.join(os.path.dirname(os.path.abspath(path)), "_derive_out")
    for tag, val in cands:
        for pwd in (val, val.decode("latin-1", "ignore").encode()):
            try:
                with zipfile.ZipFile(path) as zf:
                    zf.extractall(path=outdir, pwd=pwd)
                    names = zf.namelist()
                print(f"[+] ZIP открыт паролем {pwd[:24]!r}: {', '.join(names[:5])}")
                for n in names[:5]:
                    p = os.path.join(outdir, n)
                    try:
                        with open(p, "rb") as fh:
                            print("    " + fh.read(400).decode("utf-8", "replace")[:200])
                    except OSError:
                        continue
                return tag, pwd
            except Exception:
                continue
    return None


def try_aes(path, cands):
    try:
        from Crypto.Cipher import AES
    except Exception:
        print("[-] нет pycryptodome — режим aes недоступен")
        return None
    with open(path, "rb") as fh:
        data = fh.read()
    if len(data) % 16:
        print("[-] размер не кратен 16 — это не AES-CBC/ECB блок")
        return None
    for tag, val in cands:
        keys = [val[:16], val[:24], val[:32],
                hashlib.sha256(val).digest(), hashlib.md5(val).digest()]
        for key in keys:
            if len(key) not in (16, 24, 32):
                continue
            for mode, iv in (("ECB", None), ("CBC", b"\x00" * 16)):
                try:
                    if mode == "ECB":
                        dec = AES.new(key, AES.MODE_ECB).decrypt(data)
                    else:
                        dec = AES.new(key, AES.MODE_CBC, iv).decrypt(data)
                except Exception:
                    continue
                last = dec[-1]
                pad_ok = 1 <= last <= 16 and dec.endswith(bytes([last]) * last)
                if pad_ok or _flag_ok(dec):
                    if _plausible_plain(dec):
                        text = dec.decode("utf-8", "replace")
                        print(f"[+] расшифровано ({mode}, ключ {key[:16]!r}):")
                        print("    " + text.replace("\n", "\n    ")[:400])
                        return tag, key
    return None


def try_xor(path, cands):
    with open(path, "rb") as fh:
        data = fh.read(2_000_000)
    for tag, val in cands:
        if not 1 <= len(val) <= 64:
            continue
        out = bytes(b ^ val[i % len(val)] for i, b in enumerate(data))
        if _flag_ok(out):
            return tag, val
    return None


def main():
    ap = argparse.ArgumentParser(description="ключ, выведенный из данных")
    ap.add_argument("target", help="файл или папка с подсказкой (числа/лог)")
    ap.add_argument("--target", dest="secret", help="что расшифровываем")
    ap.add_argument("--mode", choices=["print", "zip", "aes", "xor"], default="print")
    ap.add_argument("--limit", type=int, default=15, help="сколько кандидатов печатать")
    args = ap.parse_args()

    labeled, plain = harvest(args.target)
    values = list(labeled.values()) + plain
    if not values:
        print("[-] чисел не нашлось — тут нечего выводить")
        return 1
    print(f"[+] числа: {len(values)}"
          + (f" (с метками: {', '.join(labeled)})" if labeled else ""))
    cands = candidates(values)
    print(f"[+] кандидатов (числа × операции × хеши): {len(cands)}")

    if args.mode == "print":
        for tag, val in cands[:args.limit]:
            shown = "".join(c if 32 <= ord(c) < 127 else "." for c in
                            val.decode("latin-1", "replace"))
            print(f"    {tag:28s} {shown[:48]}")
        return 0

    if not args.secret:
        print("[-] нужен --target (что расшифровываем)")
        return 2
    found = {"zip": try_zip, "aes": try_aes, "xor": try_xor}[args.mode](
        args.secret, cands)
    if found:
        print(f"[+] ПОДОШЛО: {found[0]}  (ключ {found[1][:32]!r})")
        return 0
    print("[-] ни один кандидат не подошёл")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
