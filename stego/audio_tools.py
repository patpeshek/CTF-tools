#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
audio_tools.py — DTMF и морзе из WAV.

  python audio_tools.py sound.wav
  python audio_tools.py sound.wav --mode dtmf
  python audio_tools.py sound.wav --mode morse

DTMF: ищет пары частот (697/770/852/941 + 1209/1336/1477/1633).
Морзе: по огибающей (RMS) определяет точки/тире и паузы.
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
import re
import sys
import wave

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common  # noqa: E402

ROWS = [697, 770, 852, 941]
COLS = [1209, 1336, 1477, 1633]
DIGITS = [
    ["1", "2", "3", "A"],
    ["4", "5", "6", "B"],
    ["7", "8", "9", "C"],
    ["*", "0", "#", "D"],
]
MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
    "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
    "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
    "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
    "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9",
}


class NotWav(Exception):
    pass


def read_wav(path):
    try:
        with wave.open(path, "rb") as w:
            ch, width, rate = w.getnchannels(), w.getsampwidth(), w.getframerate()
            raw = w.readframes(w.getnframes())
    except (wave.Error, EOFError) as e:
        head = open(path, "rb").read(64)
        raise NotWav(f"не WAV ({e}); первые байты: {head[:16].hex()} {head[:48]!r}")
    if width == 1:
        data = np.frombuffer(raw, dtype=np.uint8).astype(np.float32) - 128
    elif width == 2:
        data = np.frombuffer(raw, dtype="<i2").astype(np.float32)
    else:
        data = np.frombuffer(raw, dtype="<i4").astype(np.float32)
    if ch > 1:
        data = data.reshape(-1, ch).mean(axis=1)
    return data, rate


def nearest(freq, table, tol=0.04):
    for i, f in enumerate(table):
        if abs(freq - f) / f <= tol:
            return i
    return None


def decode_dtmf(data, rate, frame_ms=40):
    n = int(rate * frame_ms / 1000)
    out = []
    last = None
    for start in range(0, len(data) - n, n):
        seg = data[start:start + n] * np.hanning(n)
        spec = np.abs(np.fft.rfft(seg))
        freqs = np.fft.rfftfreq(n, 1 / rate)
        mag = spec.max()
        if mag <= 0:
            last = None
            continue
        thr = mag * 0.25
        peaks = []
        for table in (ROWS, COLS):
            best = None
            for f in table:
                idx = np.argmin(np.abs(freqs - f))
                val = spec[max(0, idx - 2):idx + 3].max()
                if best is None or val > best[1]:
                    best = (f, val)
            peaks.append(best)
        # нужны ОБА тона: одиночный пик (речь, шум) — не DTMF
        if peaks[0][1] < thr or peaks[1][1] < thr:
            last = None
            continue
        r = nearest(peaks[0][0], ROWS)
        c = nearest(peaks[1][0], COLS)
        if r is None or c is None:
            last = None
            continue
        d = DIGITS[r][c]
        if d != last:
            out.append(d)
            last = d
    return "".join(out)


def morse_runs(data, rate):
    """Список (состояние, длительность_в_окнах) с удалением коротких глитчей."""
    win = max(1, int(rate * 0.005))
    power = np.convolve(data.astype(np.float64) ** 2, np.ones(win) / win, mode="valid")
    rms = np.sqrt(power)
    if rms.size == 0 or rms.max() == 0:
        return []
    lo, hi = np.percentile(rms, 10), np.percentile(rms, 99.5)
    if hi <= lo:
        return []
    on = rms > lo + 0.35 * (hi - lo)
    runs = []
    cur, length = bool(on[0]), 1
    for v in on[1:]:
        v = bool(v)
        if v == cur:
            length += 1
        else:
            runs.append([cur, length])
            cur, length = v, 1
    runs.append([cur, length])
    ons = [l for s, l in runs if s]
    if not ons:
        return []
    unit = float(np.percentile(ons, 25))
    if unit < 1:
        unit = float(min(ons))
    # глитчи короче половины точки просто съедаем (состояние не меняется)
    clean = []
    for state, length in runs:
        if length < 0.5 * unit and clean:
            clean[-1][1] += length
            continue
        if clean and clean[-1][0] == state:
            clean[-1][1] += length
        else:
            clean.append([state, length])
    return [(bool(s), l / unit) for s, l in clean]


def decode_morse(data, rate, want_raw=False):
    runs = morse_runs(data, rate)
    if not runs:
        return "" if not want_raw else ""
    text = []
    raw = []
    code = ""
    for state, units in runs:
        if state:
            code += "." if units < 2 else "-"
        else:
            if units >= 5:  # пауза между словами
                if code:
                    text.append(MORSE.get(code, "?"))
                    raw.append(code)
                    code = ""
                text.append(" ")
                raw.append("/")
            elif units >= 2:  # пауза между символами
                if code:
                    text.append(MORSE.get(code, "?"))
                    raw.append(code)
                    code = ""
            # units < 2 — внутри символа
    if code:
        text.append(MORSE.get(code, "?"))
        raw.append(code)
    result = "".join(text).strip()
    if want_raw:
        return result, " ".join(raw)
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("wav")
    ap.add_argument("--mode", default="auto", choices=["auto", "dtmf", "morse"])
    ap.add_argument("--raw", action="store_true", help="показать последовательность .- для проверки")
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)

    try:
        data, rate = read_wav(args.wav)
    except NotWav as e:
        print("[-]", e)
        print("    это не WAV: проверь, что файл скачался целиком "
              "(иногда вместо файла прилетает JSON-отказ API)")
        return
    print(f"[+] rate={rate} samples={len(data)} dur={len(data)/rate:.2f}s")
    results = []
    if args.mode in ("auto", "dtmf"):
        d = decode_dtmf(data, rate)
        if d:
            if len(d) >= 4 and len(set(d)) >= 3:
                results.append(("DTMF", d))
            else:
                print(f"[-] DTMF отброшен (однотипные срабатывания): {d[:40]}")
    raw = None
    if args.mode in ("auto", "morse"):
        out = decode_morse(data, rate, want_raw=args.raw)
        if isinstance(out, tuple):
            m, raw = out
        else:
            m = out
        if m:
            results.append(("MORSE", m))
    for name, text in results:
        print(f"[+] {name}: {text[:500]}")
        if raw:
            print(f"    {raw[:500]}")
        for f in common.find_flags(text.encode()):
            print(" !!! ФЛАГ:", f)
        if re.fullmatch(r"[A-Z0-9]+", text) and 6 <= len(text) <= 64:
            code = text.lower()
            pre = (common.prefixes() or ["CTF"])[0]
            print(f"[i] похоже на код: {code}  ->  кандидат {pre}{{{code}}}")
    if not results:
        print("[-] ничего. Попробуй спектрограмму: stego/audio_spectrum.py")


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
