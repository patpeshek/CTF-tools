#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ice.py — ICE (Matthew Kwan, Apache-2.0) в режиме 1-bit CFB, как в stegsnow.

Нужен, когда snow запускали с паролем: `snow -p ПАРОЛЬ файл`. Тогда биты,
вынутые из пробелов, — это шифротекст; ключ и IV строятся из пароля точно так
же, как в encrypt.c (password_set).

  from ice import decrypt_bits
  bits_out = decrypt_bits("314", bits_in)     # CFB симметричен

Сверено с эталонным `snow` (stegsnow 20130616) байт-в-байт.
"""
from __future__ import annotations

M32 = 0xFFFFFFFF

ICE_SMOD = ((333, 313, 505, 369),
            (379, 375, 319, 391),
            (361, 445, 451, 397),
            (397, 425, 395, 505))

ICE_SXOR = ((0x83, 0x85, 0x9b, 0xcd),
            (0xcc, 0xa7, 0xad, 0x41),
            (0x4b, 0x2e, 0xd4, 0x33),
            (0xea, 0xcb, 0x2e, 0x04))

ICE_PBOX = (0x00000001, 0x00000080, 0x00000400, 0x00002000,
            0x00080000, 0x00200000, 0x01000000, 0x40000000,
            0x00000008, 0x00000020, 0x00000100, 0x00004000,
            0x00010000, 0x00800000, 0x04000000, 0x20000000,
            0x00000004, 0x00000010, 0x00000200, 0x00008000,
            0x00020000, 0x00400000, 0x08000000, 0x10000000,
            0x00000002, 0x00000040, 0x00000800, 0x00001000,
            0x00040000, 0x00100000, 0x02000000, 0x80000000)

ICE_KEYROT = (0, 1, 2, 3, 2, 1, 3, 0, 1, 3, 2, 0, 3, 1, 0, 2)


def _gf_mult(a: int, b: int, m: int) -> int:
    res = 0
    while b:
        if b & 1:
            res ^= a
        a <<= 1
        b >>= 1
        if a >= 256:
            a ^= m
    return res


def _gf_exp7(b: int, m: int) -> int:
    if b == 0:
        return 0
    x = _gf_mult(b, b, m)
    x = _gf_mult(b, x, m)
    x = _gf_mult(x, x, m)
    return _gf_mult(b, x, m)


def _perm32(x: int) -> int:
    res, i = 0, 0
    while x:
        if x & 1:
            res |= ICE_PBOX[i]
        i += 1
        x >>= 1
    return res


def _build_sboxes():
    boxes = []
    for n in range(4):
        shift = 24 - 8 * n
        box = [0] * 1024
        for i in range(1024):
            col = (i >> 1) & 0xFF
            row = (i & 1) | ((i & 0x200) >> 8)
            val = _gf_exp7(col ^ ICE_SXOR[n][row], ICE_SMOD[n][row])
            if shift:
                val = (val << shift) & M32
            box[i] = _perm32(val)
        boxes.append(box)
    return boxes


_SBOX = None


def _sbox():
    global _SBOX
    if _SBOX is None:
        _SBOX = _build_sboxes()
    return _SBOX


def _ice_f(p: int, sk) -> int:
    sbox = _sbox()
    tl = ((p >> 16) & 0x3FF) | (((p >> 14) | (p << 18)) & 0xFFC00)
    tr = (p & 0x3FF) | ((p << 2) & 0xFFC00)
    al = sk[2] & (tl ^ tr)
    ar = al ^ tr
    al ^= tl
    al ^= sk[0]
    ar ^= sk[1]
    return (sbox[0][al >> 10] | sbox[1][al & 0x3FF]
            | sbox[2][ar >> 10] | sbox[3][ar & 0x3FF])


def _sched_build(keysched, kb, n, keyrot):
    # ВАЖНО: C меняет kb по указателю, и второй вызов видит уже сдвинутые
    # значения. Поэтому массив не копируем.
    for i in range(8):
        kr = keyrot[i]
        sk = [0, 0, 0]
        for j in range(15):
            for k in range(4):
                idx = (kr + k) & 3
                bit = kb[idx] & 1
                sk[j % 3] = ((sk[j % 3] << 1) | bit) & M32
                kb[idx] = ((kb[idx] >> 1) | ((bit ^ 1) << 15)) & 0xFFFF
        keysched[n + i] = sk


class IceKey:
    """Ключ ICE. n<1 — 8 раундов (level 0), иначе n*16."""

    def __init__(self, n: int):
        n = int(n)
        if n < 1:
            self.size, self.rounds = 1, 8
        else:
            self.size, self.rounds = n, n * 16
        self.ks = [[0, 0, 0] for _ in range(self.rounds)]

    def set_key(self, key: bytes):
        if self.rounds == 8:
            kb = [(key[i * 2] << 8) | key[i * 2 + 1] for i in range(4)]
            kb.reverse()
            _sched_build(self.ks, kb, 0, ICE_KEYROT)
            return
        for i in range(self.size):
            kb = [((key[i * 8 + j * 2] << 8) | key[i * 8 + j * 2 + 1])
                  for j in range(4)]
            kb.reverse()
            _sched_build(self.ks, kb, i * 8, ICE_KEYROT)
            _sched_build(self.ks, kb, self.rounds - 8 - i * 8, ICE_KEYROT[8:])

    def encrypt(self, pt: bytes) -> bytes:
        l = (pt[0] << 24) | (pt[1] << 16) | (pt[2] << 8) | pt[3]
        r = (pt[4] << 24) | (pt[5] << 16) | (pt[6] << 8) | pt[7]
        for i in range(0, self.rounds, 2):
            l ^= _ice_f(r, self.ks[i])
            r ^= _ice_f(l, self.ks[i + 1])
        out = bytearray(8)
        for i in range(4):
            out[3 - i] = r & 0xFF
            out[7 - i] = l & 0xFF
            r >>= 8
            l >>= 8
        return bytes(out)

    def decrypt(self, ct: bytes) -> bytes:
        l = (ct[0] << 24) | (ct[1] << 16) | (ct[2] << 8) | ct[3]
        r = (ct[4] << 24) | (ct[5] << 16) | (ct[6] << 8) | ct[7]
        for i in range(self.rounds - 1, 0, -2):
            l ^= _ice_f(r, self.ks[i])
            r ^= _ice_f(l, self.ks[i - 1])
        out = bytearray(8)
        for i in range(4):
            out[3 - i] = r & 0xFF
            out[7 - i] = l & 0xFF
            r >>= 8
            l >>= 8
        return bytes(out)


def key_from_password(passwd: str):
    """Как password_set() в snow: уровень из длины, 1024-байтовый буфер, IV=E(буфер)."""
    level = (len(passwd) * 7 + 63) // 64
    if level == 0:
        level = 1
    elif level > 128:
        level = 128
    ik = IceKey(level)
    buf = bytearray(1024)
    i = 0
    for ch in passwd:
        c = ord(ch) & 0x7F
        idx, bit = i // 8, i & 7
        if bit == 0:
            buf[idx] = (c << 1) & 0xFF
        elif bit == 1:
            buf[idx] |= c
        else:
            buf[idx] |= (c >> (bit - 1)) & 0xFF
            buf[idx + 1] = (c << (9 - bit)) & 0xFF
        i += 7
        if i > 8184:
            break
    ik.set_key(bytes(buf[:max(8, level * 8)]))
    iv = bytearray(ik.encrypt(bytes(buf[:8])))
    return ik, iv


def cfb_bits(bits, passwd: str, encrypting: bool = False):
    """1-bit CFB как в encrypt.c/decrypt.c.

    В C обратная связь — это ПЕРЕДАННЫЙ бит: при шифровании это результат
    (возможно инвертированный), при расшифровке — принятый. Поэтому флаг
    encrypting нужен только для генерации stego-файла (в задачах мы декодируем).
    """
    ik, iv = key_from_password(passwd)
    out = []
    for bit in bits:
        ks = ik.encrypt(bytes(iv))
        nb = bit ^ (1 if (ks[0] & 0x80) else 0)
        fb = nb if encrypting else bit
        v = ((int.from_bytes(iv, "big") << 1) & ((1 << 64) - 1)) | fb
        iv = bytearray(v.to_bytes(8, "big"))
        out.append(nb)
    return out


def decrypt_bits(passwd: str, bits):
    return cfb_bits(bits, passwd, encrypting=False)


def encrypt_bits(passwd: str, bits):
    return cfb_bits(bits, passwd, encrypting=True)


if __name__ == "__main__":
    import sys

    pw = sys.argv[1] if len(sys.argv) > 1 else "314"
    hexstr = sys.argv[2] if len(sys.argv) > 2 else (
        "641dcf57e9b6b2da094164ae063d9b7cd105d7978ac01eb1b1568d")
    data = bytes.fromhex(hexstr)
    bits = [(b >> (7 - k)) & 1 for b in data for k in range(8)]
    plain_bits = decrypt_bits(pw, bits)
    out = bytearray()
    for i in range(0, len(plain_bits) - 7, 8):
        v = 0
        for b in plain_bits[i:i + 8]:
            v = (v << 1) | b
        out.append(v)
    print("пароль:", pw)
    print("hex   :", data.hex())
    print("текст :", out)
