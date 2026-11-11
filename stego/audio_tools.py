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
    elif width == 3:
        # 24 бита: 3 байта little-endian, знак из старшего бита
        b = np.frombuffer(raw[:len(raw) - len(raw) % 3], dtype=np.uint8)
        b = b.reshape(-1, 3).astype(np.int32)
        v = b[:, 0] | (b[:, 1] << 8) | (b[:, 2] << 16)
        data = np.where(v >= 1 << 23, v - (1 << 24), v).astype(np.float32)
    else:
        data = np.frombuffer(raw, dtype="<i4").astype(np.float32)
    if ch > 1:
        data = data.reshape(-1, ch).mean(axis=1)
    return data, rate


def dtmf_frames(data, rate, frame_ms=25, hop_ms=10):
    """Цифра (или None) для каждого окна frame_ms с шагом hop_ms.

    Мощность считается ровно на 8 частотах DTMF (как Гёрцель) и
    сравнивается с мощностью полосы DTMF в этом же окне, а не с максимумом
    спектра: в паузе максимум — это сам шум, и порог от него ловит шум
    как цифру.
    """
    data = np.asarray(data)
    n = max(32, int(rate * frame_ms / 1000))
    hop = max(1, int(rate * hop_ms / 1000))
    if len(data) < n:
        return []
    win = np.hanning(n)
    freqs = np.array(ROWS + COLS, dtype=np.float64)
    basis = np.exp(-2j * np.pi * np.outer(np.arange(n) / rate, freqs))
    norm = 2.0 / win.sum() ** 2               # |X|^2 -> мощность синусоиды
    bins = np.fft.rfftfreq(n, 1 / rate)
    band = (bins >= ROWS[0] - 100) & (bins <= COLS[-1] + 100)
    bnorm = 2.0 / (n * (win ** 2).sum())      # сумма |X_k|^2 -> мощность полосы
    count = 1 + (len(data) - n) // hop
    tone = np.empty((count, 8))
    total = np.empty(count)
    offs = np.arange(n)
    for a in range(0, count, 2048):
        starts = np.arange(a, min(count, a + 2048)) * hop
        fr = data[starts[:, None] + offs].astype(np.float64) * win
        tone[a:a + len(starts)] = np.abs(fr @ basis) ** 2 * norm
        spec = np.abs(np.fft.rfft(fr, axis=1)[:, band]) ** 2
        total[a:a + len(starts)] = spec.sum(axis=1) * bnorm
    floor = total.max() * 1e-6
    labels = []
    for k in range(count):
        if total[k] <= floor or total[k] <= 0:
            labels.append(None)
            continue
        row, col = tone[k, :4], tone[k, 4:]
        r, c = int(row.argmax()), int(col.argmax())
        pr, pc = row[r], col[c]
        # нужны ОБА тона: одиночный пик (речь, шум) — не DTMF
        ok = (
            pr + pc >= 0.4 * total[k]                  # тоны — основная мощность полосы
            and max(pr, pc) <= 10 * min(pr, pc)        # перекос (twist) <= 10 дБ
            and np.sort(row)[-2] * 4 <= pr             # второй тон группы слабее
            and np.sort(col)[-2] * 4 <= pc
        )
        labels.append(DIGITS[r][c] if ok else None)
    return labels


def decode_dtmf(data, rate, frame_ms=25, hop_ms=10, min_on=2, min_off=2):
    """Цифра засчитывается после min_on окон подряд; та же цифра снова —
    только после паузы min_off окон (50 мс тон / 50 мс пауза — ок)."""
    out = []
    last = None          # последняя выданная цифра (None — была пауза)
    cur, cur_len, gap = None, 0, min_off
    for lab in dtmf_frames(data, rate, frame_ms, hop_ms):
        if lab is None:
            cur, cur_len = None, 0
            gap += 1
            if gap >= min_off:
                last = None
            continue
        gap = 0
        cur_len = cur_len + 1 if lab == cur else 1
        cur = lab
        if cur_len >= min_on and lab != last:
            out.append(lab)
            last = lab
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
    # оценка точки — по грубо очищенным отрезкам, потом чистка от точки;
    # огибающая по окну win удлиняет тоны и укорачивает паузы на ~0.75*win
    unit = morse_unit(merge_short(runs, 0.2 * float(np.median(ons))), rate,
                      bias=0.75 * win)
    # глитчи короче половины точки просто съедаем (состояние не меняется)
    clean = merge_short(runs, 0.5 * unit)
    return [(bool(s), l / unit) for s, l in clean]


def merge_short(runs, limit):
    """Отрезки короче limit приклеиваются к предыдущему (глитчи)."""
    clean = []
    for state, length in runs:
        if length < limit and clean:
            clean[-1][1] += length
            continue
        if clean and clean[-1][0] == state:
            clean[-1][1] += length
        else:
            clean.append([state, length])
    return clean


def morse_unit(runs, rate, bias=0.0):
    """Длительность точки (в сэмплах) по тонам И паузам.

    Если есть и короткие, и длинные тоны (отношение ~1:3) — точка это
    короткие. Если все тоны одной длины L, это либо точки, либо тире
    (например «MOO» = «-- --- ---»): паузы должны ложиться на 1/3/7
    единиц — сравниваем обе гипотезы (единица L или L/3). Полная
    неоднозначность («TTT» == «S» в другом темпе, одиночный знак)
    решается темпом: тон длиннее ~0.11 с — тире.
    """
    ons = sorted(max(1.0, l - bias) for s, l in runs if s)
    lo, hi = ons[0], ons[-1]
    if hi >= 2 * lo:
        cut = (lo * hi) ** 0.5
        return float(np.median([x for x in ons if x <= cut]))
    L = float(np.median(ons))
    gaps = [l + bias for i, (s, l) in enumerate(runs)
            if not s and 0 < i < len(runs) - 1]

    def misfit(unit):
        if not gaps:
            return 0.0
        return float(np.mean([min(abs(np.log(g / (unit * k))) for k in (1, 3, 7))
                              for g in gaps]))

    e_dot, e_dash = misfit(L), misfit(L / 3)
    if abs(e_dot - e_dash) < 0.1:
        return L / 3 if L >= 0.11 * rate else L
    return L if e_dot < e_dash else L / 3


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
