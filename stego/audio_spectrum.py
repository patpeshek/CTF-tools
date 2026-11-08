#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
audio_spectrum.py — спектрограмма WAV без matplotlib.

  python audio_spectrum.py sound.wav
  python audio_spectrum.py sound.wav --start 0 --end 5 --out spec.png
  python audio_spectrum.py sound.wav --peaks

WAV читается модулем wave; спектр считается numpy, картинка рисуется PIL.
Для mp3/ogg сначала сконвертируй в wav (ffmpeg).
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
import wave

import numpy as np
from PIL import Image


def read_wav(path):
    with wave.open(path, "rb") as w:
        ch = w.getnchannels()
        width = w.getsampwidth()
        rate = w.getframerate()
        frames = w.readframes(w.getnframes())
    if width == 1:
        data = np.frombuffer(frames, dtype=np.uint8).astype(np.float32) - 128
    elif width == 2:
        data = np.frombuffer(frames, dtype="<i2").astype(np.float32)
    elif width == 4:
        data = np.frombuffer(frames, dtype="<i4").astype(np.float32)
    else:
        raise ValueError(f"не поддержан sampwidth={width}")
    if ch > 1:
        data = data.reshape(-1, ch).mean(axis=1)
    return data, rate


def spectrogram(data, rate, win=1024, hop=256):
    if len(data) < win:
        data = np.pad(data, (0, win - len(data)))
    n = 1 + (len(data) - win) // hop
    window = np.hanning(win).astype(np.float32)
    frames = np.stack([data[i * hop:i * hop + win] * window for i in range(n)])
    spec = np.abs(np.fft.rfft(frames, axis=1)).T  # freq x time
    spec = 20 * np.log10(spec + 1e-6)
    return spec


def to_image(spec, width, height):
    # обрезаем/масштабируем по времени и частоте
    f, t = spec.shape
    ti = np.linspace(0, t - 1, width).astype(int)
    fi = np.linspace(0, f - 1, height).astype(int)
    img = spec[np.ix_(fi, ti)]
    img = img - img.min()
    if img.max() > 0:
        img = img / img.max() * 255
    return Image.fromarray(img.astype(np.uint8)).convert("L")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("wav")
    ap.add_argument("--start", type=float, default=0.0, help="секунды")
    ap.add_argument("--end", type=float, default=0.0, help="секунды (0 = до конца)")
    ap.add_argument("--width", type=int, default=1200)
    ap.add_argument("--height", type=int, default=600)
    ap.add_argument("--freq-max", type=int, default=0, help="Гц (0 = весь диапазон)")
    ap.add_argument("--out", default="spectrum.png")
    ap.add_argument("--peaks", action="store_true")
    args = ap.parse_args()

    data, rate = read_wav(args.wav)
    a = int(args.start * rate)
    b = int(args.end * rate) if args.end else len(data)
    data = data[a:b]
    print(f"[+] rate={rate}  samples={len(data)}  dur={len(data)/rate:.2f}s")

    spec = spectrogram(data, rate)
    if args.freq_max:
        cut = int(spec.shape[0] * args.freq_max / (rate / 2))
        spec = spec[:max(1, cut)]

    img = to_image(spec, args.width, args.height)
    img.save(args.out)
    print(f"[+] спектрограмма: {args.out}")

    if args.peaks:
        # доминирующая частота по окнам ~0.25 c
        win = 1024
        hop = max(1, rate // 4)
        print("[+] доминирующие частоты:")
        for i in range(0, max(1, len(data) - win), hop):
            seg = data[i:i + win]
            if len(seg) < win:
                break
            sp = np.abs(np.fft.rfft(seg * np.hanning(len(seg))))
            f = np.argmax(sp) * rate / win
            print(f"    t={i/rate:6.2f}s  {f:7.1f} Hz")


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
