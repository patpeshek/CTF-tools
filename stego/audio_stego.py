#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
audio_stego.py — структура и стего в аудио: RIFF/WAV (чанки, хвост за data),
AIFF/AIFC, MP3 (ID3v1/v2, кадры, хвост, filler), LSB бит-планы сэмплов,
сигнатуры (PK/PNG/RIFF/...), ASCII-спектрограмма и тоны.

  python audio_stego.py sound.wav
  python audio_stego.py sound.mp3 --chunks
  python audio_stego.py sound.wav --lsb --plane 0
  python audio_stego.py sound.wav --spectro
  python audio_stego.py sound.mp3 --json > report.json

Только stdlib (wave/struct). numpy — если есть, для спектрограммы и тонов;
без numpy работает упрощённый FFT. Картинка спектрограммы пишется, если есть PIL.
Морзе/DTMF декодирует audio_tools.py — здесь только «похоже на морзе» по бёрстам.
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
import json
import math
import os
import re
import struct
import sys

try:  # общие хелперы тулбокса: поиск флагов, printable_ratio, human
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import common  # noqa: E402
except Exception:  # noqa: BLE001
    common = None

try:
    import numpy as np
except Exception:  # noqa: BLE001
    np = None

MAGIC = [
    (b"PK\x03\x04", "zip"), (b"PK\x05\x06", "zip-end"), (b"PK\x07\x08", "zip-spanned"),
    (b"\x89PNG", "png"), (b"\xff\xd8\xff", "jpeg"), (b"GIF8", "gif"), (b"RIFF", "riff"),
    (b"7z\xbc\xaf", "7z"), (b"Rar!", "rar"), (b"BZh", "bzip2"), (b"\x1f\x8b", "gzip"),
    (b"%PDF", "pdf"), (b"OggS", "ogg"), (b"fLaC", "flac"), (b"ID3", "id3"),
    (b"SQLite format 3", "sqlite"), (b"\x7fELF", "elf"),
]

TEXT_CHUNKS = {b"LIST", b"INFO", b"tEXt", b"COMM", b"note", b"INAM", b"IART", b"ICMT",
               b"ICRD", b"IGNR", b"ISFT", b"ISBJ", b"ICOP", b"ANNO", b"COMT", b"NAME",
               b"AUTH", b"(c) ", b"CODE", b"SSND"}


def human(n: int) -> str:
    return common.human(n) if common else f"{n}"


def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    counts = [0] * 256
    for x in b:
        counts[x] += 1
    n = len(b)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def printable_runs(data: bytes, minlen: int = 8, limit: int = 20) -> list[dict]:
    """Куски печатного ASCII длиной >= minlen (с офсетами)."""
    out, start, cur = [], None, 0
    for i, x in enumerate(data):
        if 32 <= x < 127 or x in (9, 10, 13):
            if start is None:
                start = i
            cur += 1
        else:
            if cur >= minlen:
                out.append({"off": start, "len": cur,
                            "text": data[start:start + cur].decode("latin-1")})
            start, cur = None, 0
    if cur >= minlen:
        out.append({"off": start, "len": cur,
                    "text": data[start:start + cur].decode("latin-1")})
    out.sort(key=lambda d: -d["len"])
    return out[:limit]


def find_flags(data: bytes) -> list[str]:
    hits = []
    if common:
        try:
            hits += common.find_flags(data)
        except Exception:  # noqa: BLE001
            pass
    else:  # без common.py — строгий запасной вариант (иначе на шуме одни ложные)
        for m in re.finditer(rb"[A-Za-z][A-Za-z0-9_]{2,30}\{[A-Za-z0-9_!@#$%^&*()+=,.:;?/|~\-]{4,120}\}",
                             data):
            hits.append(m.group().decode("latin-1", "replace"))
    seen, uniq = set(), []
    for h in hits:
        if h not in seen:
            seen.add(h)
            uniq.append(h)
    return uniq


def text_forms(data: bytes) -> dict:
    """Строки в разных кодировках: utf-16le/be, utf-8, base64/hex в тексте."""
    res = {"utf16le": [], "utf16be": [], "base64": [], "hex": []}
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){6,}", data):
        res["utf16le"].append({"off": m.start(), "text": m.group().decode("utf-16-le")})
    for m in re.finditer(rb"(?:\x00[\x20-\x7e]){6,}", data):
        res["utf16be"].append({"off": m.start(), "text": m.group().decode("utf-16-be")})
    for m in re.finditer(rb"([A-Za-z0-9+/]{24,}={0,2})", data):
        blob = m.group(1)
        if len(set(blob)) < 6:  # UUUU..., AAAA... — не base64, а заливка
            continue
        try:
            dec = base64.b64decode(blob + b"=" * (-len(blob) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        res["base64"].append({"off": m.start(), "text": blob[:80].decode("latin-1"),
                              "decoded": dec[:200].decode("latin-1", "replace")})
    for m in re.finditer(rb"\b([0-9a-fA-F]{32,})\b", data):
        try:
            res["hex"].append({"off": m.start(), "text": m.group(1)[:80].decode(),
                               "decoded": bytes.fromhex(m.group(1)[:400].decode()).decode(
                                   "latin-1", "replace")})
        except ValueError:
            pass
    return {k: v[:5] for k, v in res.items()}


def signatures(data: bytes, limit: int = 6) -> dict:
    out = {}
    for sig, name in MAGIC:
        pos, start = [], 0
        while True:
            i = data.find(sig, start)
            if i < 0 or len(pos) >= limit:
                break
            pos.append(i)
            start = i + 1
        if pos:
            out[name] = pos
    return out


# --------------------------------------------------------------------- WAV / RIFF

def parse_riff(data: bytes) -> dict:
    info = {"kind": data[:4].decode("latin-1"), "form": data[8:12].decode("latin-1"),
            "declared": struct.unpack("<I", data[4:8])[0], "chunks": [], "notes": []}
    info["trailing_after_form"] = max(0, len(data) - 8 - info["declared"])
    if info["trailing_after_form"]:
        info["notes"].append(f"RIFF size {info['declared']} меньше файла на "
                             f"{info['trailing_after_form']} байт — данные за FORM")
    off, seen_data_end = 12, None
    while off + 8 <= len(data):
        cid = data[off:off + 4]
        size = struct.unpack("<I", data[off + 4:off + 8])[0]
        body = data[off + 8:off + 8 + size]
        avail = len(data) - off - 8
        ch = {"id": cid.decode("latin-1", "replace"), "off": off, "size": size,
              "avail": avail, "truncated": size > avail}
        if size > avail:
            ch["notes"] = [f"чанк обрезан: заявлено {size}, есть {avail}"]
            ch["entropy"] = round(entropy(body), 3)
            info["chunks"].append(ch)
            break
        if cid == b"fmt " and len(body) >= 16:
            fmt, chans, rate, brate, block, bits = struct.unpack("<HHIIHH", body[:16])
            ch["fmt"] = {"tag": fmt, "channels": chans, "rate": rate, "byte_rate": brate,
                         "block_align": block, "bits": bits}
            if len(body) > 16:
                ch["fmt"]["extra"] = body[16:64].hex()
        ch["entropy"] = round(entropy(body[:1 << 20]), 3)
        if cid == b"data":
            bits = (next((x for x in info["chunks"] if x.get("fmt")), {}) or {}).get(
                "fmt", {}).get("bits", 16)
            ch["samples"] = size * 8 // max(8, bits)
            after = len(data) - (off + 8 + size)
            ch["after_data"] = after
            seen_data_end = off + 8 + size
            if after:
                tail = data[seen_data_end:]
                ch["tail_hex"] = tail[:48].hex()
                ch["tail_sig"] = signatures(tail)
                info["notes"].append(f"за data ещё {after} байт: {tail[:32]!r}")
                txt = printable_runs(tail, 8, 5)
                if txt:
                    ch["tail_text"] = txt
        else:
            txt = printable_runs(body, 6, 8)
            if txt:
                ch["text"] = txt
        info["chunks"].append(ch)
        nxt = off + 8 + size + (size & 1)
        if nxt <= off:
            break
        off = nxt
    info["walk_end"] = off
    if off != len(data) and not info.get("_stopped"):
        rest = data[off:]
        if rest:
            info["notes"].append(f"обход чанков кончился на {off}, остаток {len(rest)} байт")
            info["rest_hex"] = rest[:64].hex()
            info["rest_sig"] = signatures(rest)
    ids = [c["id"] for c in info["chunks"]]
    if ids and ids.count("data") > 1:
        info["notes"].append("несколько data-чанков — возможно, второй поток/скрытые данные")
    unknown = [c["id"] for c in info["chunks"] if c["id"] not in
               ("fmt ", "data", "LIST", "fact", "bext", "cue ", "PEAK", "JUNK", "PAD ",
                "iXML", "id3 ", "ID3 ", "smpl", "inst", "SSND", "COMM", "FVER", "FLLR")]
    if unknown:
        info["notes"].append("нестандартные чанки: " + ", ".join(sorted(set(unknown))))
    return info


def f80_float(b: bytes) -> float | None:
    """80-битный extended float AIFF (sample rate). None, если не похоже."""
    if len(b) < 10:
        return None
    exp = int.from_bytes(b[0:2], "big")
    mant = int.from_bytes(b[2:10], "big")
    if exp == 0 and mant == 0:
        return 0.0
    if not 0x3F00 <= exp <= 0x4100 or mant == 0:
        return None
    sign = -1.0 if exp & 0x8000 else 1.0
    return sign * mant * 2.0 ** ((exp & 0x7FFF) - 16383 - 63)


def parse_aiff(data: bytes) -> dict:
    info = {"kind": "FORM", "form": data[8:12].decode("latin-1"),
            "declared": struct.unpack(">I", data[4:8])[0], "chunks": [], "notes": []}
    info["trailing_after_form"] = max(0, len(data) - 8 - info["declared"])
    off = 12
    while off + 8 <= len(data):
        cid = data[off:off + 4]
        size = struct.unpack(">I", data[off + 4:off + 8])[0]
        body = data[off + 8:off + 8 + size]
        ch = {"id": cid.decode("latin-1", "replace"), "off": off, "size": size,
              "avail": len(data) - off - 8, "entropy": round(entropy(body[:1 << 20]), 3)}
        if cid == b"COMM" and size >= 18:
            chans, nframes, bits = struct.unpack(">hIh", body[:8])
            rest = body[8:]
            rate = f80_float(rest[0:10]) or f80_float(body[-10:])
            comp = "?"
            # тип сжатия: 4 печатных байта в rest, иначе — это уже float80 (бывает у ffmpeg)
            if len(rest) >= 4 and all(32 <= x < 127 for x in rest[:4]):
                comp = rest[:4].decode("latin-1")
            name = b""
            m = re.search(rb"[\x20-\xff]{6,}", rest)
            if m:
                name = m.group()
            ch["comm"] = {"channels": chans, "frames": nframes, "bits": bits,
                          "compression": comp, "rate": rate,
                          "name_raw": name[:80].decode("latin-1", "replace")}
            if rate is None:
                info["notes"].append("sample rate в COMM не распознан")
            try:
                t = name.decode("utf-8")
                if len(t) > 1:
                    ch["text"] = [{"off": 0, "len": len(t), "text": t}]
            except UnicodeDecodeError:
                pass
        elif cid == b"SSND" and size >= 8:
            aoff = struct.unpack(">I", body[:4])[0]
            ch["ssnd"] = {"offset": aoff, "audio_bytes": size - 8 - aoff}
        else:
            txt = printable_runs(body, 6, 8)
            if txt:
                ch["text"] = txt
        info["chunks"].append(ch)
        off += 8 + size + (size & 1)
    info["walk_end"] = off
    if off != len(data):
        info["notes"].append(f"обход чанков кончился на {off}, остаток {len(data)-off} байт")
    return info


# -------------------------------------------------------------------------- MP3

BR_TABLE = {
    (1, 1): [0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448],
    (1, 2): [0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384],
    (1, 3): [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320],
    (2, 1): [0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256],
    (2, 2): [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160],
    (2, 3): [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160],
}
SR_TABLE = {3: [44100, 48000, 32000], 2: [22050, 24000, 16000], 0: [11025, 12000, 8000]}
LAYER_OF = {1: 3, 2: 2, 3: 1}


def mp3_frame(data: bytes, i: int):
    if i + 4 > len(data) or data[i] != 0xFF or (data[i + 1] & 0xE0) != 0xE0:
        return None
    ver = (data[i + 1] >> 3) & 3
    layer_bits = (data[i + 1] >> 1) & 3
    br_i = (data[i + 2] >> 4) & 0xF
    sr_i = (data[i + 2] >> 2) & 3
    pad = (data[i + 2] >> 1) & 1
    if ver == 1 or layer_bits == 0 or br_i in (0, 15) or sr_i == 3:
        return None
    layer = LAYER_OF[layer_bits]
    ver_key = 1 if ver == 3 else 2
    bitrate = BR_TABLE[(ver_key, layer)][br_i] * 1000
    rate = SR_TABLE[ver][sr_i]
    coef = 144 if (layer != 3 or ver == 3) else 72
    return {"off": i, "ver": {3: "1", 2: "2", 0: "2.5"}.get(ver, str(ver)),
            "layer": layer, "bitrate": bitrate, "rate": rate,
            "len": coef * bitrate // rate + pad, "pad": pad,
            "priv": data[i + 2] & 1, "mode": (data[i + 3] >> 6) & 3}


def parse_id3v2(data: bytes) -> dict | None:
    if data[:3] != b"ID3" or len(data) < 10:
        return None
    ver = (data[3], data[4])
    flags = data[5]
    size = (data[6] << 21) | (data[7] << 14) | (data[8] << 7) | data[9]
    body = data[10:10 + size]
    info = {"version": f"2.{ver[0]}.{ver[1]}", "flags": flags, "size": size,
            "total": size + 10, "entropy": round(entropy(body), 3), "frames": [],
            "notes": []}
    if flags & 0x80:
        info["notes"].append("unsynchronisation")
    if size > len(body):
        info["notes"].append(f"тег обрезан: заявлено {size}, есть {len(body)}")
    off = 0
    while off + 10 <= len(body):
        fid = body[off:off + 4]
        if fid == b"\x00\x00\x00\x00" or fid[:1] == b"\x00":
            pad = body[off:]
            info["padding"] = {"off": off, "len": len(pad),
                               "entropy": round(entropy(pad), 3),
                               "nonzero": sum(1 for x in pad if x)}
            break
        if ver[0] == 2:
            fsize = int.from_bytes(body[off + 3:off + 6], "big")
            fhead = off + 6
        elif ver[0] == 4:
            raw = body[off + 4:off + 8]
            fsize = (raw[0] << 21) | (raw[1] << 14) | (raw[2] << 7) | raw[3]
            fhead = off + 10
        else:
            fsize = int.from_bytes(body[off + 4:off + 8], "big")
            fhead = off + 10
        content = body[fhead:fhead + fsize]
        fr = {"id": fid.decode("latin-1", "replace"), "size": fsize,
              "flags": body[off + 8:off + 10].hex() if ver[0] != 2 else "",
              "entropy": round(entropy(content), 3) if content else 0.0}
        txt = decode_id3_text(content)
        if txt:
            fr["text"] = txt
        fr["hex"] = content[:48].hex()
        info["frames"].append(fr)
        off = fhead + fsize
        if fsize == 0:
            off += 1
    return info


def decode_id3_text(content: bytes) -> str:
    if not content:
        return ""
    enc = content[0]
    body = content[1:]
    try:
        if enc == 0:
            return body.decode("latin-1").strip("\x00")
        if enc == 1:
            return body.decode("utf-16").strip("\x00")
        if enc == 2:
            return body.decode("utf-16-be").strip("\x00")
        return body.decode("utf-8").strip("\x00")
    except (UnicodeDecodeError, LookupError):
        return ""


def parse_mp3(data: bytes) -> dict:
    info = {"id3v2": parse_id3v2(data), "notes": []}
    start = (info["id3v2"] or {}).get("total", 0)
    frames, i = [], start
    while i < len(data) - 4:
        f = mp3_frame(data, i)
        if f:
            frames.append(f)
            i += max(f["len"], 1)
        else:
            i += 1
    info["frames"] = {
        "count": len(frames),
        "first": frames[0] if frames else None,
        "last": frames[-1] if frames else None,
        "params": sorted({(f["ver"], f["layer"], f["bitrate"], f["rate"]) for f in frames}),
        "private_bits": sum(f["priv"] for f in frames),
    }
    if frames:
        end = frames[-1]["off"] + frames[-1]["len"]
        info["frames"]["end"] = end
        info["frames"]["trailing"] = len(data) - end
        if len(data) > end:
            tail = data[end:]
            info["frames"]["tail_hex"] = tail[:64].hex()
            info["frames"]["tail_sig"] = signatures(tail)
            info["notes"].append(f"за последним кадром {len(tail)} байт")
            txt = printable_runs(tail, 8, 5)
            if txt:
                info["frames"]["tail_text"] = txt
        gaps = [(a["off"] + a["len"], b["off"]) for a, b in zip(frames, frames[1:])
                if b["off"] != a["off"] + a["len"]]
        if gaps:
            info["notes"].append(f"разрывы между кадрами: {len(gaps)}, первые {gaps[:5]}")
        info["notes"].append(
            "private bit во всех кадрах = 1 — признак MP3Stego" if
            frames and all(f["priv"] for f in frames) else
            "private bit пуст — MP3Stego не похож")
        # кадры-заливки (LAME пишет 0x55/0xAA в неиспользуемом main data)
        fl = {"55": 0, "aa": 0, "00": 0}
        for f in frames:
            main = data[f["off"] + 13:f["off"] + f["len"]]
            if not main:
                continue
            top = max(set(main), key=main.count)
            if main.count(top) > 0.9 * len(main):
                fl[f"{top:02x}"] = fl.get(f"{top:02x}", 0) + 1
        info["filler_frames"] = fl
    if data[-128:-125] == b"TAG":
        tag = data[-128:]
        info["id3v1"] = {"title": tag[3:33].decode("latin-1", "replace").strip("\x00"),
                         "artist": tag[33:63].decode("latin-1", "replace").strip("\x00"),
                         "album": tag[63:93].decode("latin-1", "replace").strip("\x00"),
                         "year": tag[93:97].decode("latin-1", "replace"),
                         "comment": tag[97:127].decode("latin-1", "replace").strip("\x00")}
    for name, sig in (("ape", b"APETAGEX"), ("lyrics3", b"LYRICSBEGIN")):
        if sig in data[-4096:]:
            info["notes"].append(f"найден {name} в хвосте")
    return info


# -------------------------------------------------------------------------- LSB

def lsb_report_pcm(vals: list[float], riff: dict, planes: int = 0) -> dict:
    """LSB для AIFF: сэмплы уже распакованы, раскладываем обратно в LE-байты."""
    comm = next((c for c in riff["chunks"] if c.get("comm")), {})
    chans = comm.get("comm", {}).get("channels", 1)
    raw = struct.pack(f"<{len(vals)}h", *[max(-32768, min(32767, int(round(v)))) for v in vals])
    fake = {"chunks": [{"id": "fmt ", "fmt": {"bits": 16, "channels": chans}},
                       {"id": "data", "off": -8, "size": len(raw), "avail": len(raw)}]}
    return lsb_report(raw, fake, planes, max_samples=max(1, len(vals)))

def plane_bits(sample_bytes: bytes, width: int, plane: int) -> bytes:
    """Биты одного плана сэмплов (0 = LSB). Длина = число сэмплов."""
    byte_idx, bit = divmod(plane, 8)
    if byte_idx >= width:
        return b""
    col = sample_bytes[byte_idx::width]
    return col.translate(bytes((v >> bit) & 1 for v in range(256)))


def bits_to_bytes(bits: bytes, order: str = "msb") -> bytes:
    n = len(bits) // 8 * 8
    if not n:
        return b""
    b = bytes(bits[:n]).translate(bytes.maketrans(b"\x00\x01", b"01"))
    val = int(b, 2)
    if order == "lsb":  # биты в байт записаны от младшего
        val = int(bytes(bits[:n]).translate(bytes.maketrans(b"\x00\x01", b"10")), 2)
    return val.to_bytes(n // 8, "big")


def lsb_report(data: bytes, riff: dict, planes: int = 0, max_samples: int = 4_000_000) -> dict:
    fmt_chunk = next((c for c in riff["chunks"] if c.get("fmt")), None)
    data_chunk = next((c for c in riff["chunks"] if c["id"] == "data"), None)
    if not fmt_chunk or not data_chunk:
        return {"error": "нет fmt/data — не PCM WAV"}
    fmt = fmt_chunk["fmt"]
    bits = fmt.get("bits", 16)
    width = max(1, bits // 8) if bits % 8 == 0 else 2
    chans = fmt.get("channels", 1)
    off = data_chunk["off"] + 8
    size = min(data_chunk["size"], data_chunk["avail"], max_samples * width * chans)
    raw = data[off:off + size - (size % (width * chans))]
    n_planes = planes or min(width * 8, 16)
    chans_note = f"каналов {chans}: биты идут по кадрам подряд" if chans > 1 else "моно"
    out = {"bits": bits, "channels": chans, "bytes": len(raw),
           "samples": len(raw) // width, "note": chans_note, "planes": []}
    for p in range(n_planes):
        bits_b = plane_bits(raw, width, p)
        if not bits_b:
            break
        ones = bits_b.count(1)
        ratio = ones / len(bits_b)
        pb = {"plane": p, "ones_ratio": round(ratio, 4),
              "entropy": round(-(ratio * math.log2(ratio) + (1 - ratio) * math.log2(1 - ratio))
                               if 0 < ratio < 1 else 0.0, 3)}
        for order in ("msb", "lsb"):
            by = bits_to_bytes(bits_b, order)
            runs = printable_runs(by, 8, 3)
            pb[f"runs_{order}"] = len(runs)
            if runs:
                pb[f"text_{order}"] = runs[:2]
                pb[f"maxlen_{order}"] = runs[0]["len"]
                flags = find_flags(by)
                if flags:
                    pb["flags"] = flags
        if p < 8:
            out["planes"].append(pb)
    best = max(out["planes"], key=lambda d: d.get("maxlen_msb", 0), default=None)
    out["best"] = best["plane"] if best else None
    if best and (best.get("flags") or best.get("maxlen_msb", 0) >= 12):
        out["verdict"] = (f"план {out['best']}: текст {best['maxlen_msb']} симв. подряд — "
                          "похоже на стего")
    elif best and best.get("maxlen_msb", 0) >= 10:
        out["verdict"] = f"план {out['best']}: 10+ символов, но это может быть шум"
    else:
        out["verdict"] = "текста в LSB не видно (все планы — шум/квантование)"
    ones = [p["ones_ratio"] for p in out["planes"]]
    if ones and max(ones) - min(ones) > 0.35:
        out["verdict"] += "; планы сильно различаются по балансу 0/1 — проверь вручную"
    return out


# ------------------------------------------------------------------- спектрограмма

def load_pcm(data: bytes, riff: dict):
    """(samples list[float], rate) для RIFF/WAV и FORM/AIFC; максимум ~8M сэмплов."""
    if riff.get("kind") in ("RIFF", "RF64"):
        fmt = next((c for c in riff["chunks"] if c.get("fmt")), None)
        dch = next((c for c in riff["chunks"] if c["id"] == "data"), None)
        if not fmt or not dch:
            return None, None
        f = fmt["fmt"]
        bits, chans, rate = f["bits"], f["channels"], f["rate"]
        off = dch["off"] + 8
        raw = data[off:off + dch["size"]]
        width = bits // 8
        n = min(len(raw) // width, 8_000_000 * chans) // chans * chans
        raw = raw[:n * width]
        if width == 1:
            vals = [x - 128 for x in raw]
        elif width == 2:
            vals = list(struct.unpack(f"<{n}h", raw))
        elif width == 4:
            vals = list(struct.unpack(f"<{n}i", raw))
        else:
            vals = [int.from_bytes(raw[i:i + width], "little", signed=True)
                    for i in range(0, len(raw), width)]
        if chans > 1:
            vals = [sum(vals[i:i + chans]) / chans for i in range(0, len(vals), chans)]
        return vals, int(rate)
    if riff.get("kind") == "FORM":
        comm = next((c for c in riff["chunks"] if c["id"] == "COMM"), None)
        ssnd = next((c for c in riff["chunks"] if c["id"] == "SSND"), None)
        if not comm or not ssnd:
            return None, None
        nframes = comm["comm"]["frames"]
        rate = comm["comm"].get("rate") or 44100
        bits = comm["comm"].get("bits", 16)
        if bits != 16:
            return None, None
        aoff = ssnd.get("ssnd", {}).get("offset", 0)
        body = data[ssnd["off"] + 16 + aoff:ssnd["off"] + 8 + ssnd["size"]]
        n = min(nframes, len(body) // 2)
        return list(struct.unpack(f">{n}h", body[:n * 2])), int(rate)
    return None, None


def spectro_ascii(data: bytes, riff: dict, width: int = 110, height: int = 28,
                  out_png: str | None = None) -> dict:
    vals, rate = load_pcm(data, riff)
    if vals is None:
        return {"error": "не PCM: для mp3/ogg сначала декодируй в wav (ffmpeg -i in.mp3 out.wav)"}
    res = {"rate": rate, "samples": len(vals)}
    if np is not None:
        x = np.asarray(vals, dtype=np.float32)
        win = 1024 if len(x) > 4096 else 256
        hop = max(1, (len(x) - win) // (width * 4) or 1)
        frames = [np.abs(np.fft.rfft(x[s:s + win] * np.hanning(win)))
                  for s in range(0, max(1, len(x) - win), hop)]
        S = np.log1p(np.array(frames).T)
        fmax = rate / 2
        # доминирующая частота по «секундам»
        peaks = []
        step = max(1, len(x) // 40)
        for s in range(0, len(x) - win, step):
            seg = x[s:s + win]
            if float(np.sqrt((seg ** 2).mean())) < 1e-3:
                continue
            sp = np.abs(np.fft.rfft(seg * np.hanning(win)))
            k = int(np.argmax(sp))
            peaks.append({"t": round(s / rate, 3), "freq": round(k * rate / win, 1),
                          "rms": round(float(np.sqrt((seg ** 2).mean())), 1)})
        res["peaks"] = peaks[:20]
        dom = [p["freq"] for p in peaks if p["freq"] > 20]
        if dom and len(set(round(f) for f in dom)) <= 3:
            res["note"] = "один-два тона — похоже на морзе/DTMF/OOK (декод: audio_tools.py)"
        # буквы для ASCII-карты
        H, W = S.shape
        fi = np.linspace(0, H - 1, height).astype(int)
        ti = np.linspace(0, W - 1, width).astype(int)
        img = S[np.ix_(fi, ti)]
        img = (img - img.min()) / (float(np.ptp(img)) or 1.0)
        chars = " .:-=+*#%@"
        lines = ["".join(chars[min(9, int(v * 9.99))] for v in row) for row in img[::-1]]
        res["ascii"] = lines
        if out_png:
            try:
                from PIL import Image
                big = (S - S.min()) / ((S.max() - S.min()) or 1)
                Image.fromarray((big[::-1] ** 0.8 * 255).astype("uint8")).resize(
                    (1200, 400)).save(out_png)
                res["png"] = out_png
            except Exception as e:  # noqa: BLE001
                res["png_error"] = str(e)
        res["fmax"] = fmax
    else:
        res["note"] = "numpy нет — упрощённый режим (бёрсты/амплитуда)"
        x = vals
        blk = max(1, len(x) // width)
        env = []
        for i in range(0, len(x) - blk, blk):
            seg = x[i:i + blk]
            env.append(math.sqrt(sum(v * v for v in seg) / len(seg)))
        top = max(env) or 1
        chars = " .:-=+*#%@"
        res["ascii"] = ["".join(chars[min(9, int(e / top * 9.99))] for e in env)]
        res["rms"] = round(top, 1)
    # бёрсты (OOK/морзе) — по огибающей
    vals_f = [abs(v) for v in vals] if np is None else None
    if np is not None:
        x = np.asarray(vals, dtype=np.float32)
        w = max(1, rate // 400)
        m = len(x) // w * w
        env = np.sqrt((x[:m].reshape(-1, w) ** 2).mean(axis=1))
        on = env > (env.max() * 0.2 if len(env) else 0)
        if not len(on):
            return res
        runs, cur, val = [], 0, on[0]
        for v in on:
            if v == val:
                cur += 1
            else:
                runs.append({"on": bool(val), "ms": round(cur * w / rate * 1000, 1)})
                cur, val = 1, v
        runs.append({"on": bool(val), "ms": round(cur * w / rate * 1000, 1)})
        ons = sorted(r["ms"] for r in runs if r["on"])
        if ons and len(runs) > 3:
            res["bursts"] = {"count": len(runs), "shortest_on_ms": ons[0],
                             "longest_on_ms": ons[-1], "first": runs[:12]}
            if ons[-1] > 2.2 * ons[0]:
                res["bursts"]["hint"] = "две длины посылок — типичный морзе"
    return res


# -------------------------------------------------------------------------- main

def analyze(path: str, args) -> dict:
    data = open(path, "rb").read()
    head = data[:12]
    rep = {"file": os.path.abspath(path), "size": len(data), "size_human": human(len(data))}
    if head[:4] in (b"RIFF", b"RF64"):
        rep["format"] = "wav"
        riff = parse_riff(data)
        rep["riff"] = riff
        if args.lsb or args.all:
            rep["lsb"] = lsb_report(data, riff, args.plane)
        if args.spectro or args.all:
            rep["spectro"] = spectro_ascii(data, riff, out_png=args.spectro_png or None)
    elif head[:4] == b"FORM" and head[8:12] in (b"AIFF", b"AIFC"):
        rep["format"] = "aiff"
        riff = parse_aiff(data)
        rep["riff"] = riff
        if args.lsb or args.all:
            vals, rate = load_pcm(data, riff)
            rep["lsb"] = lsb_report_pcm(vals, riff) if vals else {"error": "не 16-bit PCM"}
        if args.spectro or args.all:
            rep["spectro"] = spectro_ascii(data, riff)
    elif head[:3] == b"ID3" or (len(data) > 3 and data[0] == 0xFF and (data[1] & 0xE0) == 0xE0):
        rep["format"] = "mp3"
        rep["mp3"] = parse_mp3(data)
        if args.lsb or args.spectro or args.all:
            rep["note_decode"] = ("MP3 сжат: LSB/спектр только по декодированному WAV "
                                  "(ffmpeg -i in.mp3 -acodec pcm_s16le out.wav)")
    else:
        rep["format"] = "unknown"
    rep["signatures"] = signatures(data)
    rep["text_forms"] = {k: v for k, v in text_forms(data).items() if v}
    rep["flags"] = find_flags(data)
    rep["printable"] = printable_runs(data, 12, 8)
    return rep


def show(rep: dict, args) -> None:
    print(f"== {rep['file']}  {rep['size']} байт ({rep['size_human']})  формат: {rep['format']}")
    riff = rep.get("riff")
    if riff and (args.chunks or args.all or not (args.lsb or args.spectro)):
        print(f"[+] {riff['kind']}/{riff['form']}: заявлено {riff['declared']}, "
              f"хвост за FORM {riff['trailing_after_form']}")
        for c in riff["chunks"]:
            extra = ""
            if "fmt" in c:
                f = c["fmt"]
                extra = f"  {f['channels']}ch {f['rate']}Hz {f['bits']}bit tag={f['tag']}"
            if "comm" in c:
                m = c["comm"]
                extra = (f"  {m['channels']}ch {m['frames']} кадров {m['bits']}bit "
                         f"{m['compression']} rate={m.get('rate')}")
            print(f"    {c['id']!r:8s} off={c['off']:<8d} size={c['size']:<9d} "
                  f"H={c['entropy']}{extra}")
            for t in c.get("text", [])[:4]:
                print(f"        текст: {t['text'][:110]!r}")
            for t in c.get("tail_text", [])[:3]:
                print(f"        после data: {t['text'][:110]!r}")
        for n in riff.get("notes", []):
            print(f"    [!] {n}")
    mp3 = rep.get("mp3")
    if mp3:
        id3 = mp3.get("id3v2")
        if id3:
            print(f"[+] ID3v2.{id3['version'].split('.', 1)[1]} size={id3['size']} "
                  f"кадров={len(id3['frames'])}")
            for fr in id3["frames"][:20]:
                print(f"    {fr['id']} size={fr['size']} H={fr['entropy']} "
                      f"{fr.get('text', '')[:80]!r}")
            if id3.get("padding", {}).get("nonzero"):
                print(f"    [!] в padding {id3['padding']['nonzero']} ненулевых байт "
                      f"(H={id3['padding']['entropy']})")
        else:
            print("[+] ID3v2 нет")
        f = mp3["frames"]
        print(f"[+] кадров {f['count']}, параметры {f['params']}, "
              f"конец {f.get('end')}, хвост {f.get('trailing', 0)} байт")
        print(f"    private bits: {f['private_bits']}, filler-кадры: {mp3.get('filler_frames')}")
        for n in mp3["notes"]:
            print(f"    [!] {n}")
        if mp3.get("id3v1"):
            print(f"    ID3v1: {mp3['id3v1']}")
    lsb = rep.get("lsb")
    if lsb:
        if "error" in lsb:
            print(f"[!] LSB: {lsb['error']}")
        else:
            print(f"[+] LSB: {lsb['bits']} бит, {lsb['samples']} сэмплов, {lsb['note']}")
            for p in lsb["planes"]:
                mark = " <-- текст" if p.get("text_msb") else ""
                print(f"    план {p['plane']}: ones={p['ones_ratio']} H={p['entropy']} "
                      f"runs={p.get('runs_msb')}{mark}")
                for t in p.get("text_msb", [])[:2]:
                    print(f"        {t['text'][:110]!r}")
                if p.get("flags"):
                    print(f"        ФЛАГИ: {p['flags']}")
            print(f"    вывод: {lsb['verdict']}")
    sp = rep.get("spectro")
    if sp:
        if "error" in sp:
            print(f"[!] спектр: {sp['error']}")
        else:
            print(f"[+] спектр: rate={sp['rate']} samples={sp['samples']} "
                  f"(низ частот внизу)")
            for line in sp.get("ascii", []):
                print("    " + line)
            if sp.get("peaks"):
                print("    пики:", ", ".join(f"{p['t']}s:{p['freq']}Hz" for p in sp["peaks"][:10]))
            if sp.get("bursts"):
                b = sp["bursts"]
                print(f"    бёрсты: {b['count']}, посылки {b['shortest_on_ms']}.."
                      f"{b['longest_on_ms']} мс {b.get('hint', '')}")
            if sp.get("note"):
                print(f"    {sp['note']}")
            if sp.get("png"):
                print(f"    картинка: {sp['png']}")
    if rep.get("note_decode"):
        print(f"[i] {rep['note_decode']}")
    if rep.get("signatures"):
        print("[+] сигнатуры внутри файла:")
        for name, pos in rep["signatures"].items():
            print(f"    {name}: {pos[:5]}")
    if rep.get("text_forms"):
        print("[+] строки в разных кодировках:")
        for enc, items in rep["text_forms"].items():
            for it in items[:3]:
                print(f"    {enc}@{it['off']}: {it['text'][:100]!r}"
                      + (f" -> {it['decoded'][:80]!r}" if it.get("decoded") else ""))
    if rep.get("printable"):
        print("[+] печатные строки (топ по длине):")
        for t in rep["printable"][:6]:
            print(f"    @{t['off']}: {t['text'][:110]!r}")
    if rep["flags"]:
        print("[+] ФЛАГИ: " + ", ".join(rep["flags"]))
    else:
        print("[-] флагов не найдено")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Структура и стего в аудио: RIFF/AIFF/MP3, чанки, хвосты, LSB, спектр.")
    ap.add_argument("file")
    ap.add_argument("--json", action="store_true", help="вывод в JSON (без украшений)")
    ap.add_argument("--chunks", action="store_true", help="только структура контейнера")
    ap.add_argument("--lsb", action="store_true", help="бит-планы LSB сэмплов (WAV)")
    ap.add_argument("--spectro", action="store_true", help="ASCII-спектрограмма + тоны/бёрсты")
    ap.add_argument("--all", action="store_true", help="всё сразу")
    ap.add_argument("--plane", type=int, default=0, help="сколько бит-планов считать (0 = все)")
    ap.add_argument("--spectro-png", default="", help="сохранить картинку спектра (нужен PIL)")
    args = ap.parse_args()

    try:
        rep = analyze(args.file, args)
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
        return
    if args.json:
        json.dump(rep, sys.stdout, ensure_ascii=False, indent=1)
        print()
    else:
        show(rep, args)


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
