"""test_graph.py — самотесты ml/graph.py. Запуск: python ml/test_graph.py

Без pytest: только assert'ы. Код возврата 0 — всё прошло.
"""
from __future__ import annotations

import base64
import gzip
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from graph import search, to_text  # noqa: E402

FLAG = "CTF{x0r_b64_gz1p_cha1n_ok}"
PLAIN = (
    "the secret answer is " + FLAG + " and the flag is stored safely here; "
    "please use it to solve this stage of the task."
).encode()


# --- конструкторы цепочек (только stdlib) ---------------------------------
def b64(b: bytes) -> bytes:
    return base64.b64encode(b)


def b32(b: bytes) -> bytes:
    return base64.b32encode(b)


def xor(b: bytes, key: int) -> bytes:
    return bytes(c ^ key for c in b)


def rot13(b: bytes) -> bytes:
    table = bytes.maketrans(
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        b"nopqrstuvwxyzabcdefghijklmNOPQRSTUVWXYZABCDEFGHIJKLM",
    )
    return b.translate(table)


def utf16le(b: bytes) -> bytes:
    return b.decode().encode("utf-16-le")


def zero_width(b: bytes) -> bytes:
    return ("\ufeff" + "\u200b".join(b.decode()) + "\u200d").encode()


CASES = [
    ("b64", b64(PLAIN)),
    ("gzip(b64)", gzip.compress(b64(PLAIN))),
    ("xor(b64,0x2a)", xor(b64(PLAIN), 0x2A)),
    ("hex(gzip)", gzip.compress(PLAIN).hex().encode()),
    ("b32", b32(PLAIN)),
    ("reverse(rot13)", rot13(PLAIN)[::-1]),
    ("utf16le", utf16le(PLAIN)),
    ("zero_width", zero_width(PLAIN)),
    # utf-16 внутри бинарного контейнера (как ID3-тег в mp3)
    (
        "utf16_in_bin",
        b"ID3\x04\x00\x00"
        + b"\x00" * 16
        + b"TXXX"
        + b"\x00" * 3
        + ("note: " + FLAG).encode("utf-16-le")
        + b"\x00" * 8
        + b"\x01\x02\x03" * 20,
    ),
]

lines: list[str] = []
t_all = time.time()


def check(name: str, data: bytes, expect_flag: bool = True, budget: int = 400) -> dict:
    t0 = time.time()
    res = search(data, max_depth=6, beam=8, budget=budget)
    dt = time.time() - t0
    st = res["stats"]
    assert set(res) == {"found", "best", "stats"}, res.keys()
    assert set(st) == {"expanded", "pruned", "duplicates", "seconds"}, st
    assert set(res["best"]) == {"score", "path", "preview"}, res["best"]
    assert dt < 10.0, f"{name}: слишком долго ({dt:.2f}s)"

    flags = [f["flag"] for f in res["found"]]
    if expect_flag:
        assert FLAG in flags, f"{name}: флаг не найден, found={flags}"
        depth = next(f["depth"] for f in res["found"] if f["flag"] == FLAG)
        assert depth <= 6, depth
        assert any(step["op"] for f in res["found"] for step in f["path"])
    else:
        assert not flags, f"{name}: ложный флаг {flags}"
        assert res["best"]["preview"] is not None

    lines.append(
        f"[ok] {name:<16} depth={res['found'][0]['depth'] if res['found'] else '-'} "
        f"exp={st['expanded']:<3} pruned={st['pruned']:<3} dup={st['duplicates']:<3} "
        f"{dt:5.2f}s"
    )
    return res


# 1..8 — цепочки, флаг обязан найтись
for name, payload in CASES:
    check(name, payload)

# 9 — чистый рандом: ни одного ложного флага, быстро
rnd = random.Random(1337).randbytes(4096)
res = check("random_bytes", rnd, expect_flag=False)
assert res["stats"]["expanded"] >= 1

# 10 — loop guard: base64 из повторов "AAA" (reverse даёт самопетлю)
loop_a = b"QUFB" * 400
res = check("loop_base64_repeat", loop_a, expect_flag=False, budget=200)
assert res["stats"]["duplicates"] > 0, res["stats"]
assert res["stats"]["seconds"] < 10

# 11 — loop guard: rot13 и caesar(13) дают одинаковые байты
loop_b = b"attack at dawn, the flag is near. " * 20
res = check("loop_rot13_caesar", loop_b, expect_flag=False, budget=200)
assert res["stats"]["duplicates"] > 0, res["stats"]

# 12 — to_text
assert to_text(b"hello") == "hello"
assert "hello" in to_text(utf16le(b"hello"))
assert to_text(b"\x00\x01\x02")  # не падает на бинаре

print("\n".join(lines))
print(f"OK: {len(lines)}/{len(lines)} кейсов, суммарно {time.time() - t_all:.2f}s")
