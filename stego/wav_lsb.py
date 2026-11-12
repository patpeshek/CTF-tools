#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wav_lsb.py — LSB в сэмплах WAV и базовая детекция эхо-скрытия.

  python wav_lsb.py sound.wav                         # авто-скан LSB
  python wav_lsb.py sound.wav --channel left --bits 2 --order msb
  python wav_lsb.py sound.wav --echo --seg 4096 --d0 60 --d1 120

LSB: младшие биты PCM-сэмплов (8/16/24/32 бит, моно/стерео). Выбираются число
младших бит (--bits 1..n), канал (--channel all/left/right/interleaved) и порядок
бит в байте (--order lsb/msb). В авто-режиме первым пробуется самый частый вариант
— 1 младший бит, все сэмплы, LSB-first (little-endian порядок бит), затем
остальные комбинации; лучший по «читаемости»/флагу печатается.

Эхо-скрытие (--echo): простой кепстральный декодер. Сигнал режется на сегменты
(по одному биту на сегмент), для каждого считается вещественный кепстр и
сравниваются значения на двух квефренциях: --d0 кодирует 0, --d1 кодирует 1 (чей
пик выше — тот бит). Ограничения: нужно заранее знать параметры (длину сегмента и
задержки), сегменты не выравниваются автоматически, один эхо-ядро на сегмент. Для
разведки (какие вообще задержки есть) смотри спектрограмму: stego/audio_spectrum.py.

Только чтение; файл не меняется. Для mp3/ogg сначала сконвертируй в WAV (ffmpeg).
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
import os
import sys
import wave

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common  # noqa: E402


class NotPCMWav(Exception):
    pass


def read_wav_samples(path):
    """Прочитать PCM WAV.

    Возвращает (samples, rate, width_bytes, nchannels), где samples — целочисленный
    np.ndarray формы (nframes, nchannels) с ТОЧНЫМИ значениями сэмплов (не float и
    без усреднения каналов — для LSB важен каждый бит каждого канала).

    audio_tools.read_wav отдаёт float-моно (каналы усреднены) — для LSB это не
    годится, поэтому здесь свой читатель. 24-бит собирается вручную (wave не умеет
    отдавать его массивом), 8-бит WAV беззнаковый (0..255) по стандарту.
    """
    try:
        with wave.open(path, "rb") as w:
            nch = w.getnchannels()
            width = w.getsampwidth()
            rate = w.getframerate()
            nframes = w.getnframes()
            raw = w.readframes(nframes)
    except (wave.Error, EOFError) as e:
        head = b""
        try:
            head = open(path, "rb").read(16)
        except OSError:
            pass
        raise NotPCMWav(f"не PCM WAV ({e}); первые байты: {head.hex()}")

    if nch < 1:
        raise NotPCMWav(f"каналов={nch}")
    if width == 1:                                   # 8-бит — беззнаковый
        a = np.frombuffer(raw, dtype=np.uint8).astype(np.int64)
    elif width == 2:
        a = np.frombuffer(raw, dtype="<i2").astype(np.int64)
    elif width == 3:                                 # 24-бит LE, собираем сами
        b = np.frombuffer(raw, dtype=np.uint8)
        n = len(b) // 3
        b = b[:n * 3].reshape(n, 3).astype(np.int64)
        a = b[:, 0] | (b[:, 1] << 8) | (b[:, 2] << 16)
        a = np.where(a & 0x800000, a - 0x1000000, a)  # знак (для LSB не важно)
    elif width == 4:
        a = np.frombuffer(raw, dtype="<i4").astype(np.int64)
    else:
        raise NotPCMWav(f"sampwidth={width} байт не поддержан")

    total = (len(a) // nch) * nch
    a = a[:total].reshape(-1, nch)
    return a, rate, width, nch


def sample_stream(samples, channel):
    """Последовательность сэмплов для выбранного канала."""
    nch = samples.shape[1]
    if channel in ("all", "interleaved"):
        return samples.reshape(-1)
    if channel == "left":
        return samples[:, 0]
    if channel == "right":
        return samples[:, 1] if nch >= 2 else samples[:, 0]
    # номер канала строкой/числом
    try:
        idx = int(channel)
        if 0 <= idx < nch:
            return samples[:, idx]
    except (ValueError, TypeError):
        pass
    return samples.reshape(-1)


def extract_bits(seq, width, nbits=1):
    """nbits младших бит каждого сэмпла, от младшего к старшему."""
    mask = (1 << (width * 8)) - 1
    u = seq.astype(np.int64) & mask
    nbits = max(1, min(int(nbits), width * 8))
    planes = np.empty((len(u), nbits), dtype=np.uint8)
    for b in range(nbits):
        planes[:, b] = ((u >> b) & 1).astype(np.uint8)
    return planes.reshape(-1)


def bits_to_bytes(bits, order="lsb"):
    """Упаковать битовый поток в байты. order=lsb — первый бит в младший разряд
    байта (little-endian порядок бит), msb — первый бит в старший разряд."""
    bits = np.asarray(bits, dtype=np.int64)
    n = len(bits) // 8
    if n == 0:
        return b""
    bits = bits[:n * 8].reshape(n, 8)
    if order == "lsb":
        weights = (1 << np.arange(8))
    else:
        weights = (1 << np.arange(7, -1, -1))
    vals = (bits * weights).sum(axis=1)
    return bytes(vals.astype(np.uint8))


def _printable_preview(data, limit=400):
    text = data[:limit].decode("utf-8", "replace")
    return "".join(c if 32 <= ord(c) < 127 else "." for c in text)


def scan_lsb(samples, width, nch, channels, orders, bits_list):
    """Перебрать комбинации и вернуть список результатов, лучший — первым."""
    results = []
    for ch in channels:
        if ch == "right" and nch < 2:
            continue
        seq = sample_stream(samples, ch)
        for nbits in bits_list:
            raw_bits = extract_bits(seq, width, nbits)
            for order in orders:
                data = bits_to_bytes(raw_bits, order)
                flags = common.find_flags(data)
                pr = common.printable_ratio(data)
                results.append({
                    "channel": ch, "order": order, "bits": nbits,
                    "data": data, "flags": flags, "printable": pr,
                    "score": (10.0 if flags else 0.0) + pr,
                })
    # стабильный порядок: сначала по score, при равенстве — порядок добавления
    results.sort(key=lambda r: r["score"], reverse=True)
    return results


def _default_combos(channel, order, bits):
    """Списки каналов/порядков/бит; «1 LSB, все сэмплы, lsb» всегда первым в авто."""
    channels = ["interleaved", "left", "right"] if channel == "auto" else [channel]
    orders = ["lsb", "msb"] if order == "auto" else [order]
    bits_list = [bits] if bits else [1]
    return channels, orders, bits_list


def run_lsb(path, channel, order, bits):
    samples, rate, width, nch = read_wav_samples(path)
    print(f"[+] WAV: rate={rate} бит/сэмпл={width*8} каналов={nch} "
          f"сэмплов={samples.shape[0]} ({samples.shape[0]/rate:.2f}s)")
    channels, orders, bits_list = _default_combos(channel, order, bits)
    results = scan_lsb(samples, width, nch, channels, orders, bits_list)
    if not results:
        print("[-] нечего извлекать")
        return
    best = results[0]
    print(f"[+] лучший: channel={best['channel']} order={best['order']} "
          f"bits={best['bits']}  печатных={best['printable']*100:.0f}%")
    print("    " + _printable_preview(best["data"]))
    # флаги из всех комбинаций (не только лучшей) — LSB часто читается в одном канале
    shown = set()
    any_flag = False
    for res in results:
        for f in res["flags"]:
            if f in shown:
                continue
            shown.add(f)
            any_flag = True
            print(f" !!! ФЛАГ: {f}  (channel={res['channel']} "
                  f"order={res['order']} bits={res['bits']})")
    if not any_flag:
        # показать ещё пару читаемых вариантов — вдруг человек увидит
        for res in results[1:3]:
            if res["printable"] > 0.6 and res["data"] != best["data"]:
                print(f"[i] channel={res['channel']} order={res['order']} "
                      f"bits={res['bits']}: {_printable_preview(res['data'], 120)}")
        print("[i] флага нет: попробуй --bits 2, другой --channel/--order "
              "или эхо-скрытие (--echo) / спектрограмму (stego/audio_spectrum.py)")


def real_cepstrum(frame):
    """Вещественный кепстр: irfft(log|rfft|)."""
    spec = np.fft.rfft(frame)
    logmag = np.log(np.abs(spec) + 1e-12)
    return np.fft.irfft(logmag, n=len(frame))


def decode_echo(mono, seg_len, d0, d1, max_bits=8192):
    """По биту на сегмент: пик кепстра на d1 выше, чем на d0 -> 1, иначе 0."""
    seg_len = int(seg_len)
    if seg_len < 8 or max(d0, d1) >= seg_len // 2:
        return []
    nseg = min(len(mono) // seg_len, max_bits)
    bits = []
    for k in range(nseg):
        seg = mono[k * seg_len:(k + 1) * seg_len].astype(np.float64)
        if not np.any(seg):
            bits.append(0)
            continue
        ceps = real_cepstrum(seg)
        v0 = float(ceps[d0])
        v1 = float(ceps[d1])
        bits.append(1 if v1 > v0 else 0)
    return bits


def run_echo(path, seg_len, d0, d1):
    samples, rate, width, nch = read_wav_samples(path)
    mono = samples.mean(axis=1) if nch > 1 else samples[:, 0].astype(np.float64)
    print(f"[+] WAV: rate={rate} бит/сэмпл={width*8} каналов={nch} "
          f"сэмплов={samples.shape[0]} ({samples.shape[0]/rate:.2f}s)")
    bits = decode_echo(mono, seg_len, d0, d1)
    if not bits:
        print(f"[-] эхо: мало данных или d0/d1 ({d0}/{d1}) >= половины сегмента "
              f"({seg_len}) — проверь параметры")
        return
    bitstr = "".join(str(b) for b in bits)
    print(f"[+] эхо: сегмент={seg_len} d0={d0} d1={d1}  бит={len(bits)}")
    print("    биты:", bitstr[:256] + ("…" if len(bitstr) > 256 else ""))
    any_flag = False
    for order in ("msb", "lsb"):
        data = bits_to_bytes(np.array(bits, dtype=np.uint8), order)
        print(f"    {order}: {_printable_preview(data, 120)}")
        for f in common.find_flags(data):
            any_flag = True
            print(f" !!! ФЛАГ: {f}  (порядок {order})")
    if not any_flag:
        print("[i] флага нет: перебери seg/d0/d1, либо это не эхо-скрытие — "
              "посмотри спектрограмму (stego/audio_spectrum.py)")


def main():
    ap = argparse.ArgumentParser(description="LSB в сэмплах WAV и эхо-скрытие")
    ap.add_argument("wav")
    ap.add_argument("--channel", default="auto",
                    choices=["auto", "all", "interleaved", "left", "right"],
                    help="какой канал читать (по умолчанию перебрать)")
    ap.add_argument("--bits", type=int, default=0,
                    help="сколько младших бит на сэмпл (по умолчанию 1)")
    ap.add_argument("--order", default="auto", choices=["auto", "lsb", "msb"],
                    help="порядок бит в байте (по умолчанию перебрать)")
    ap.add_argument("--echo", action="store_true",
                    help="декодировать эхо-скрытие вместо LSB")
    ap.add_argument("--seg", type=int, default=4096, help="эхо: длина сегмента")
    ap.add_argument("--d0", type=int, default=60, help="эхо: задержка бита 0")
    ap.add_argument("--d1", type=int, default=120, help="эхо: задержка бита 1")
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)

    try:
        if args.echo:
            run_echo(args.wav, args.seg, args.d0, args.d1)
        else:
            run_lsb(args.wav, args.channel, args.order, args.bits)
    except NotPCMWav as e:
        print("[-]", e)
        print("    это не PCM WAV: проверь, что файл скачался целиком, или "
              "сконвертируй в WAV (ffmpeg)")


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
