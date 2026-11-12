#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""block_oracles.py — атаки на блочные шифры через оракулы.

  # ECB byte-at-a-time: оракул дописывает секрет к нашему вводу
  python block_oracles.py ecb-recover --oracle-cmd "python oracle_ecb.py" --secret-len 32

  # padding oracle: оракул отвечает 1/0 на ciphertext
  python block_oracles.py padding-oracle --oracle-cmd "python oracle_pad.py" \
      --iv 00112233445566778899aabbccddeeff --ct aabb...

  # CBC bit-flipping: меняем IV так, чтобы первый блок стал нужным
  python block_oracles.py cbc-flip --iv 00.. --known "user=guest" --target "user=admin"

  # просто найти повторяющиеся блоки (детект ECB)
  python block_oracles.py ecb-detect --ct aabb...

Протокол оракула — построчный:
  ecb-recover:     hex(plaintext) -> hex(ciphertext)
  padding-oracle:  hex(ciphertext) -> 1/0
"""
from __future__ import annotations

try:
    import sys as _sys
    for _stream in (_sys.stdout, _sys.stderr):
        _stream.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import argparse
import subprocess
import sys


def hx(text: str) -> bytes:
    s = (text or "").strip().replace(" ", "").replace("\n", "")
    if s.lower().startswith("0x"):
        s = s[2:]
    if len(s) % 2:
        s = "0" + s
    return bytes.fromhex(s)


def blocks_of(data: bytes, bs: int):
    return [data[i:i + bs] for i in range(0, len(data), bs)]


class LineOracle:
    """Оракул как долгоживущий процесс: одна строка — один запрос."""

    def __init__(self, cmd: str):
        self.proc = subprocess.Popen(
            cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, bufsize=1)
        self.calls = 0

    def query(self, data: bytes) -> str:
        if self.proc.poll() is not None:
            raise RuntimeError(f"оракул завершился с кодом {self.proc.returncode}")
        self.proc.stdin.write(data.hex() + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError("оракул закрыл stdout (нет ответа)")
        self.calls += 1
        return line.strip()

    def close(self):
        try:
            if self.proc.poll() is None:
                self.proc.stdin.close()
                try:
                    self.proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    subprocess.run(["taskkill", "/F", "/T", "/PID",
                                    str(self.proc.pid)], capture_output=True)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass


def detect_block_size(oracle: LineOracle, max_bs: int = 64) -> int:
    """Ищем bs, при котором 2*bs одинаковых байт дают два одинаковых блока."""
    for bs in (16, 8, 32, 24, 64, 4):
        if bs > max_bs:
            continue
        ct = hx(oracle.query(b"A" * (2 * bs)))
        if len(ct) >= 2 * bs and ct[:bs] == ct[bs:2 * bs]:
            return bs
    return 16


def cmd_ecb_recover(args):
    oracle = LineOracle(args.oracle_cmd)
    try:
        bs = args.block_size or detect_block_size(oracle)
        if bs <= 0 or bs > 64:
            print(f"[-] странный размер блока: {bs}")
            return 2
        print(f"[i] размер блока: {bs}")
        limit = args.secret_len or args.max_bytes
        known = b""
        while len(known) < limit:
            i = len(known)
            pad = bs - 1 - (i % bs)
            if pad == 0:
                pad = bs  # нельзя слать пустой запрос: оракул его пропустит
            block_idx = (pad + i) // bs
            probe = hx(oracle.query(b"A" * pad))
            need = (block_idx + 1) * bs
            if len(probe) < need:
                print("[!] оракул вернул слишком короткий шифротекст")
                break
            target = probe[block_idx * bs:need]
            found = None
            for guess in range(256):
                ct = hx(oracle.query(b"A" * pad + known + bytes([guess])))
                if len(ct) >= need and ct[block_idx * bs:need] == target:
                    found = guess
                    break
            if found is None:
                print(f"[i] байт #{i} не найден — похоже, секрет кончился")
                break
            known += bytes([found])
            print(f"\r[i] восстановлено: {len(known)} байт", end="", file=sys.stderr)
            if args.stop_at and known.endswith(args.stop_at.encode()):
                break
        print(file=sys.stderr)
        print(f"[i] запросов к оракулу: {oracle.calls}")
        print(f"[+] secret hex : {known.hex()}")
        print(f"[+] secret ascii: {known.decode('utf-8', 'replace')}")
        if args.out:
            open(args.out, "wb").write(known)
            print(f"[+] записано в {args.out}")
        return 0
    finally:
        oracle.close()


def _valid(oracle: LineOracle, data: bytes) -> bool:
    return oracle.query(data).strip() in ("1", "true", "True", "yes", "ok", "OK")


def padding_oracle_decrypt(oracle: LineOracle, iv: bytes, ct: bytes, bs: int,
                           verbose=True):
    blocks = blocks_of(ct, bs)
    if not blocks:
        raise RuntimeError("пустой ciphertext")
    plain = bytearray()
    for bi in range(len(blocks) - 1, -1, -1):
        block = blocks[bi]
        prev = blocks[bi - 1] if bi > 0 else iv
        if len(prev) != bs:
            raise RuntimeError("IV/блок неверной длины")
        inter = bytearray(bs)
        for pos in range(bs - 1, -1, -1):
            pad = bs - pos
            crafted = bytearray(prev)
            for k in range(pos + 1, bs):
                crafted[k] = inter[k] ^ pad
            hit = None
            for guess in range(256):
                crafted[pos] = guess
                if not _valid(oracle, bytes(crafted) + block):
                    continue
                # ложное срабатывание: для последнего байта 02 02 тоже валидно;
                # если переворот предыдущего байта ломает padding — это много-
                # байтовое выравнивание, а не наш байт.
                if pos == bs - 1 and bs > 1:
                    check = bytearray(crafted)
                    check[pos - 1] ^= 0x01
                    if not _valid(oracle, bytes(check) + block):
                        continue
                hit = guess
                break
            if hit is None:
                raise RuntimeError(f"блок {bi}, позиция {pos}: валидный байт не найден")
            inter[pos] = hit ^ pad
        plain = bytes(a ^ b for a, b in zip(inter, prev)) + plain
        if verbose:
            print(f"[i] блок {bi}: {plain[:bs].hex()}", file=sys.stderr)
    # убираем PKCS#7
    clean = plain
    if clean:
        p = clean[-1]
        if 1 <= p <= bs and clean.endswith(bytes([p]) * p):
            clean = clean[:-p]
    return plain, clean


def cmd_padding_oracle(args):
    iv = hx(args.iv)
    ct = hx(args.ct)
    oracle = LineOracle(args.oracle_cmd)
    try:
        raw, clean = padding_oracle_decrypt(oracle, iv, ct, args.block_size)
        print(f"[i] запросов к оракулу: {oracle.calls}")
        print(f"[+] plaintext (с padding): {raw.hex()}")
        print(f"[+] plaintext hex : {clean.hex()}")
        print(f"[+] plaintext text: {clean.decode('utf-8', 'replace')}")
        if args.out:
            open(args.out, "wb").write(clean)
            print(f"[+] записано в {args.out}")
        return 0
    except RuntimeError as e:
        print(f"[-] {e}")
        return 2
    finally:
        oracle.close()


def cmd_cbc_flip(args):
    bs = args.block_size
    iv = hx(args.iv)
    known = hx(args.known) if not args.known_text else args.known_text.encode()
    target = hx(args.target) if not args.target_text else args.target_text.encode()
    if len(known) != bs or len(target) != bs:
        print(f"[-] known и target должны быть по {bs} байт "
              f"(сейчас {len(known)} и {len(target)})")
        return 2
    new_prev = bytes(a ^ b ^ c for a, b, c in zip(iv, known, target))
    print(f"[+] новый предыдущий блок: {new_prev.hex()}")
    if args.ct:
        ct = bytearray(hx(args.ct))
        idx = args.block_index
        start = (idx - 1) * bs
        if start < 0 or start + bs > len(ct):
            print("[-] block-index вне ciphertext")
            return 2
        new_ct = bytes(ct[:start]) + new_prev + bytes(ct[start + bs:])
        print(f"[+] исправленный ciphertext: {new_ct.hex()}")
    return 0


def cmd_ecb_detect(args):
    ct = hx(args.ct)
    bs = args.block_size
    blocks = blocks_of(ct, bs)
    seen = {}
    for i, b in enumerate(blocks):
        seen.setdefault(b, []).append(i)
    dup = {k: v for k, v in seen.items() if len(v) > 1}
    print(f"[i] блоков: {len(blocks)} по {bs} байт, уникальных: {len(seen)}")
    if not dup:
        print("[+] повторов нет — скорее всего не ECB (или данных мало)")
        return 0
    print(f"[!] найдено повторов: {len(dup)} — это ECB")
    for b, idx in sorted(dup.items(), key=lambda kv: kv[1][0])[:10]:
        print(f"    блок {b.hex()} в позициях {idx}")
    return 0


def main():
    ap = argparse.ArgumentParser(description="атаки на блочные шифры через оракулы")
    sub = ap.add_subparsers(dest="cmd", required=True)

    ecb = sub.add_parser("ecb-recover", help="побайтовое восстановление секрета (ECB)")
    ecb.add_argument("--oracle-cmd", required=True)
    ecb.add_argument("--block-size", type=int, default=0)
    ecb.add_argument("--secret-len", type=int, default=0)
    ecb.add_argument("--max-bytes", type=int, default=256)
    ecb.add_argument("--stop-at", default="")
    ecb.add_argument("--out")
    ecb.set_defaults(func=cmd_ecb_recover)

    pad = sub.add_parser("padding-oracle", help="padding oracle: расшифровка CBC")
    pad.add_argument("--oracle-cmd", required=True)
    pad.add_argument("--iv", required=True)
    pad.add_argument("--ct", required=True)
    pad.add_argument("--block-size", type=int, default=16)
    pad.add_argument("--out")
    pad.set_defaults(func=cmd_padding_oracle)

    flip = sub.add_parser("cbc-flip", help="переворот битов CBC: known -> target")
    flip.add_argument("--iv")
    flip.add_argument("--known")
    flip.add_argument("--known-text")
    flip.add_argument("--target")
    flip.add_argument("--target-text")
    flip.add_argument("--ct")
    flip.add_argument("--block-index", type=int, default=1)
    flip.add_argument("--block-size", type=int, default=16)
    flip.set_defaults(func=cmd_cbc_flip)

    det = sub.add_parser("ecb-detect", help="повторяющиеся блоки = ECB")
    det.add_argument("--ct", required=True)
    det.add_argument("--block-size", type=int, default=16)
    det.set_defaults(func=cmd_ecb_detect)

    args = ap.parse_args()
    sys.exit(args.func(args) or 0)


if __name__ == "__main__":
    main()
