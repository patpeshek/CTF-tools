"""gen_tasks.py — синтетические задачи с известным семейством.

Каждая задача — байты + метка семейства (какой инструмент должен сработать).
Это НЕ тесты кита: это датасет для роутера. Генераторы нарочно разные, чтобы
модель училась на закономерностях (длина, алфавит, энтропия, повторы), а не
на одном шаблоне.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import os
import random
import string
import zlib

import numpy as np

from features import byte_hist, byte_ids, hand_features
from gen_artifacts import MAKERS as ARTIFACT_MAKERS

FAMILIES = [
    "raw_text", "b64", "b32", "hex", "rot13", "caesar", "xor1", "reverse",
    "gzip", "zlib", "utf16", "rsa", "random_bin",
] + list(ARTIFACT_MAKERS)
# эти семейства не попадают в train: проверяем, умеет ли модель сказать
# «не знаю» на новом типе, а не выдать уверенную чушь
NOVEL = {"b32", "utf16"}

WORDS = ("alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo "
         "lima mike november oscar papa quebec romeo sierra tango uniform "
         "victor whiskey xray yankee zulu").split()


PROSE_EN = (
    "The backup server keeps a copy of every message for thirty days, after "
    "which the oldest batches are pruned automatically.",
    "Our monitoring noticed a spike in outbound traffic right after the "
    "maintenance window; the operator says nothing was changed.",
    "Please review the attached capture and tell me whether the credentials "
    "were sent in clear text or inside an encrypted tunnel.",
    "The contractor uploaded the archive on Friday and deleted it on Monday. "
    "The storage snapshot from Sunday should still hold the original file.",
)
PROSE_RU = (
    "Сервер резервного копирования хранит копию каждого сообщения тридцать дней, "
    "после чего старые пакеты удаляются автоматически.",
    "В журнале видно резкий рост исходящего трафика сразу после окна "
    "обслуживания; оператор утверждает, что ничего не менял.",
    "Посмотри вложение и скажи, передавались ли учётные данные открытым "
    "текстом или внутри зашифрованного туннеля.",
    "Подрядчик загрузил архив в пятницу и удалил в понедельник. Снимок "
    "хранилища за воскресенье должен содержать исходный файл.",
)


def plaintext(rng: random.Random) -> bytes:
    """Обычный читаемый текст: и «словесная каша», и проза на EN/RU.

    Раньше был только набор ASCII-слов, из-за чего настоящая кириллица
    выглядела для модели как XOR-блоб.
    """
    roll = rng.random()
    if roll < 0.5:
        body = " ".join(rng.choice(WORDS) for _ in range(rng.randint(2, 8)))
    elif roll < 0.75:
        body = " ".join(rng.choice(PROSE_EN) for _ in range(rng.randint(1, 3)))
    else:
        body = " ".join(rng.choice(PROSE_RU) for _ in range(rng.randint(1, 2)))
    flag = "CTF{" + "".join(rng.choice(string.ascii_lowercase + string.digits + "_")
                           for _ in range(rng.randint(6, 18))) + "}"
    if rng.random() < 0.3 and "\n" not in body:
        return f"{body} {flag}\n".encode()
    return f"{body}\n{flag}\n".encode()


def _rot(ch: str, k: int) -> str:
    if "a" <= ch <= "z":
        return chr((ord(ch) - 97 + k) % 26 + 97)
    if "A" <= ch <= "Z":
        return chr((ord(ch) - 65 + k) % 26 + 65)
    return ch


def make(family: str, rng: random.Random) -> bytes:
    if family == "raw_text":
        return plaintext(rng)
    if family == "b64":
        return base64.b64encode(plaintext(rng))
    if family == "b32":
        return base64.b32encode(plaintext(rng))
    if family == "hex":
        return plaintext(rng).hex().encode()
    if family == "rot13":
        return "".join(_rot(c, 13) for c in plaintext(rng).decode()).encode()
    if family == "caesar":
        k = rng.randint(1, 25)
        return "".join(_rot(c, k) for c in plaintext(rng).decode()).encode()
    if family == "xor1":
        key = rng.randint(1, 255)
        return bytes(b ^ key for b in plaintext(rng))
    if family == "reverse":
        return plaintext(rng)[::-1]
    if family == "gzip":
        return gzip.compress(plaintext(rng))
    if family == "zlib":
        return zlib.compress(plaintext(rng))
    if family == "utf16":
        return plaintext(rng).decode().encode("utf-16-le")
    if family == "rsa":
        n = rng.getrandbits(512) | 1
        c = rng.getrandbits(500)
        return f"n = {n}\ne = 65537\nc = {c}\n".encode()
    if family == "random_bin":
        return os.urandom(rng.randint(64, 512))
    if family in ARTIFACT_MAKERS:
        return ARTIFACT_MAKERS[family](rng)
    raise ValueError(family)


def build(n: int, seed: int, max_len: int = 256):
    rng = random.Random(seed)
    hand, hist, ids, fam, split, seeds, texts = [], [], [], [], [], [], []
    for i in range(n):
        family = rng.choice(FAMILIES)
        data = make(family, rng)
        hand.append(hand_features(data))
        hist.append(byte_hist(data))
        ids.append(byte_ids(data, max_len))
        fam.append(family)
        texts.append(data.decode("utf-8", "replace")[:512])
        r = rng.random()
        if family in NOVEL:
            part = "novel"
        elif r < 0.70:
            part = "train"
        elif r < 0.80:
            part = "val"
        elif r < 0.90:
            part = "test"
        else:
            part = "extra"
        split.append(part)
        seeds.append(seed * 10_000_000 + i)
        if (i + 1) % 5000 == 0:
            print(f"  {i + 1}/{n}", flush=True)
    return {
        "x_hand": np.stack(hand).astype(np.float32),
        "x_hist": np.stack(hist).astype(np.float32),
        "x_bytes": np.stack(ids).astype(np.uint8),
        "y": np.array([FAMILIES.index(f) for f in fam], dtype=np.int16),
        "family": np.array(fam),
        "split": np.array(split),
        "text": np.array(texts),
        "seed": np.array(seeds, dtype=np.int64),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=100_000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--max-len", type=int, default=256)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    print(f"[+] генерирую {args.n} задач → {args.out}", flush=True)
    data = build(args.n, args.seed, args.max_len)
    np.savez(args.out, **data)
    print(f"[+] готово: {args.out} ({os.path.getsize(args.out) / 1e6:.1f} МБ)", flush=True)


if __name__ == "__main__":
    main()
