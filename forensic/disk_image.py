#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
disk_image.py — образы дисков: таблицы разделов и файловые системы (read-only,
чистый Python, потоковое чтение по смещениям; образ целиком в память не грузится).

  python disk_image.py parts IMAGE                    MBR (+extended) / GPT
  python disk_image.py fat   IMAGE [--part N] [--out DIR] [--find-flags]
  python disk_image.py mft   MFTFILE [--out DIR] [--find-flags]
                             [--image IMG --cluster 4096 --offset BYTES]
  python disk_image.py ext   IMAGE [--part N] [--out DIR] [--find-flags]
  python disk_image.py scan  IMAGE [--out DIR] [--find-flags]

Поддержано: FAT12/16/32 (LFN, удалённые 0xE5, восстановление непрерывных
цепочек), NTFS $MFT (fixup, $FILE_NAME, resident/non-resident $DATA, ADS,
удалённые записи), ext2/3/4 (суперблок, дерево каталогов от корня с extents и
прямыми/косвенными блоками, остатки старых записей в slack каталогов, jbd2:
дескрипторы журнала и старые копии блоков).
Частично: ext — удалённые inode не восстанавливаются (extents обнуляются при
удалении), 64-bit группы/flex_bg/inline_data/шифрование не разбираются;
журнал разбирается эвристически (без проверки контрольных сумм, escape-блоки
не восстанавливаются). NTFS: сжатие/шифрование/sparse-runs не распаковываются;
non-resident данные читаются только при указании --image.
"""
from __future__ import annotations

try:
    import sys as _sys
    for _stream in (_sys.stdout, _sys.stderr):
        _stream.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import argparse
import os
import re
import shutil
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common  # noqa: E402

MAX_EXTRACT = 256 * 1024 * 1024
SECTOR = 512

MBR_TYPES = {
    0x01: "FAT12", 0x04: "FAT16<32M", 0x05: "Extended", 0x06: "FAT16",
    0x07: "NTFS/exFAT", 0x0B: "FAT32 CHS", 0x0C: "FAT32 LBA", 0x0E: "FAT16 LBA",
    0x0F: "Extended LBA", 0x82: "Linux swap", 0x83: "Linux", 0x8E: "Linux LVM",
    0xEE: "GPT protective", 0xEF: "EFI System", 0xFD: "Linux RAID",
}
GPT_TYPES = {
    "C12A7328-F81F-11D2-BA4B-00A0C93EC93B": "EFI System",
    "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7": "Microsoft basic data",
    "0FC63DAF-8483-4772-8E79-3D69D8477DE4": "Linux filesystem",
    "E3C9E316-0B5C-4DB8-817D-F92DF00215AE": "Microsoft reserved",
    "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F": "Linux swap",
}


# ───────────────────────── утилиты ─────────────────────────

class Img:
    """Read-only доступ к образу по смещению с базой раздела."""

    def __init__(self, path, base=0):
        self.f = open(path, "rb")
        self.path = path
        self.base = base
        self.size = os.path.getsize(path)

    def read(self, off, n):
        if n <= 0:
            return b""
        self.f.seek(self.base + off)
        return self.f.read(n)

    def close(self):
        self.f.close()


def u16(b, o=0):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o=0):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o=0):
    return struct.unpack_from("<Q", b, o)[0]


class Sink:
    """Единая обработка файла: запись в --out и поиск флагов."""

    def __init__(self, out, find_flags):
        self.out = out
        self.find = find_flags
        self.flags = []

    def handle(self, relpath, data, tag=""):
        if self.find:
            for fl in common.find_flags(data):
                self.flags.append(fl)
                print(f"    [FLAG] {fl}   ({relpath}{tag})")
        if self.out:
            safe = re.sub(r'[<>:"|?*\x00-\x1f]', "_", relpath.replace("\\", "/"))
            parts = [p for p in safe.split("/") if p not in ("", ".", "..")]
            dest = os.path.join(self.out, *parts) if parts else os.path.join(self.out, "unnamed")
            try:
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with open(dest, "wb") as fh:
                    fh.write(data)
            except OSError as e:
                print(f"    [!] не записать {dest}: {e}")


def read_limited(img, off, n, cap=MAX_EXTRACT):
    return img.read(off, min(n, cap))


def tsk_hint(path):
    fls, icat = shutil.which("fls"), shutil.which("icat")
    if fls and icat:
        print(f"[i] sleuthkit найден: fls -r -o <секторы> \"{path}\" ; "
              f"icat -o <секторы> \"{path}\" <inode> ; tsk_recover -e \"{path}\" outdir")
    else:
        print("[i] sleuthkit (fls/icat/tsk_recover) не найден — работает чистый Python; "
              "для ext также помогает debugfs (-R 'lsdel')")
    if shutil.which("debugfs"):
        print(f"[i] debugfs есть: debugfs -R 'ls -d /' \"{path}\"")


# ───────────────────────── разделы ─────────────────────────

def parse_parts(path):
    """-> [dict(n, scheme, type, start, size, offset)] в секторах/байтах."""
    parts = []
    with open(path, "rb") as f:
        head = f.read(SECTOR * 2)
        if len(head) < 512 or head[510:512] != b"\x55\xaa" and head[512:520] != b"EFI PART":
            return parts, "none"
        mbr = head[:512]
        gpt = head[512:520] == b"EFI PART"
        if mbr[510:512] == b"\x55\xaa":
            for i in range(4):
                e = mbr[446 + 16 * i: 462 + 16 * i]
                ptype = e[4]
                lba, cnt = u32(e, 8), u32(e, 12)
                if ptype == 0 or cnt == 0:
                    continue
                if ptype in (0x05, 0x0F, 0x85):
                    parts.extend(_ebr_chain(f, lba, lba, len(parts) + 1))
                    continue
                parts.append(dict(n=len(parts) + 1, scheme="MBR", type=MBR_TYPES.get(ptype, f"0x{ptype:02X}"),
                                  start=lba, size=cnt, boot=bool(e[0] & 0x80),
                                  chs=tuple(e[1:4]), code=ptype))
        if gpt:
            hdr = head[512:512 + 92]
            ent_lba = u64(hdr, 72)
            n_ent, ent_sz = u32(hdr, 80), u32(hdr, 84)
            if 0 < n_ent <= 4096 and 128 <= ent_sz <= 1024:
                f.seek(ent_lba * SECTOR)
                arr = f.read(n_ent * ent_sz)
                gparts = []
                for i in range(n_ent):
                    e = arr[i * ent_sz:(i + 1) * ent_sz]
                    if len(e) < 128 or e[:16] == b"\0" * 16:
                        continue
                    import uuid
                    tg = str(uuid.UUID(bytes_le=bytes(e[:16]))).upper()
                    first, last = u64(e, 32), u64(e, 40)
                    name = e[56:128].decode("utf-16-le", "replace").split("\0")[0]
                    gparts.append(dict(n=len(gparts) + 1, scheme="GPT", type=GPT_TYPES.get(tg, tg),
                                       start=first, size=last - first + 1, name=name, code=tg))
                if gparts:
                    parts = gparts  # защитный MBR не показываем
    for p in parts:
        p["offset"] = p["start"] * SECTOR
    return parts, ("GPT" if gpt else "MBR")


def _ebr_chain(f, base, lba, n0, depth=0):
    out = []
    seen = set()
    cur = lba
    while cur not in seen and len(out) < 64:
        seen.add(cur)
        f.seek(cur * SECTOR)
        b = f.read(512)
        if len(b) < 512 or b[510:512] != b"\x55\xaa":
            break
        e1, e2 = b[446:462], b[462:478]
        if e1[4] and u32(e1, 12):
            out.append(dict(n=n0 + len(out), scheme="MBR-logical",
                            type=MBR_TYPES.get(e1[4], f"0x{e1[4]:02X}"),
                            start=cur + u32(e1, 8), size=u32(e1, 12),
                            boot=False, chs=tuple(e1[1:4]), code=e1[4]))
        if e2[4] in (0x05, 0x0F, 0x85) and u32(e2, 8):
            cur = base + u32(e2, 8)
        else:
            break
    return out


def cmd_parts(args):
    parts, scheme = parse_parts(args.image)
    if not parts:
        print("[-] таблица разделов (MBR 0x55AA / GPT) не найдена")
        return 1
    print(f"[+] схема: {scheme}")
    print(f"{'#':>2} {'схема':<12} {'тип':<24} {'start LBA':>10} {'размер сект.':>12} {'размер':>10}  смещение")
    for p in parts:
        extra = ""
        if "chs" in p:
            c = p["chs"]
            extra = f" CHS={((c[1] & 0xC0) << 2) | c[2]}/{c[0]}/{c[1] & 0x3F}" + (" boot" if p.get("boot") else "")
        if p.get("name"):
            extra = f" «{p['name']}»"
        print(f"{p['n']:>2} {p['scheme']:<12} {p['type']:<24} {p['start']:>10} {p['size']:>12} "
              f"{p['size'] * SECTOR // 1024:>8}K  0x{p['offset']:X}{extra}")
    return 0


def pick_offset(path, part):
    if part is None:
        return 0
    parts, _ = parse_parts(path)
    for p in parts:
        if p["n"] == part:
            return p["offset"]
    raise SystemExit(f"[-] раздел {part} не найден (см. parts)")


# ───────────────────────── FAT ─────────────────────────

def detect_fs(img):
    b = img.read(0, 512)
    if len(b) < 512:
        return None
    if b[3:11] == b"NTFS    ":
        return "ntfs"
    if b[510:512] == b"\x55\xaa" and (b[54:58] == b"FAT1" or b[82:87] == b"FAT32"):
        return "fat"
    if b[510:512] == b"\x55\xaa" and b[11:13] == b"\x00\x02" and b[21] >= 0xF0 and b[13] in (1, 2, 4, 8, 16, 32, 64, 128):
        return "fat"
    sb = img.read(0x400, 0x100)
    if len(sb) >= 0x3A and u16(sb, 0x38) == 0xEF53:
        return "ext"
    return None


class Fat:
    def __init__(self, img):
        self.img = img
        b = img.read(0, 512)
        self.bps = u16(b, 11)
        self.spc = b[13]
        self.rsv = u16(b, 14)
        self.nfats = b[16]
        self.root_ents = u16(b, 17)
        tot16 = u16(b, 19)
        self.fatsz = u16(b, 22) or u32(b, 36)
        tot = tot16 or u32(b, 32)
        if self.bps not in (512, 1024, 2048, 4096) or not self.spc or not self.nfats:
            raise ValueError("не похоже на FAT BPB")
        self.root_secs = (self.root_ents * 32 + self.bps - 1) // self.bps
        self.data_start = self.rsv + self.nfats * self.fatsz + self.root_secs
        self.nclust = (tot - self.data_start) // self.spc
        self.kind = "FAT12" if self.nclust < 4085 else "FAT16" if self.nclust < 65525 else "FAT32"
        self.root_cluster = u32(b, 44) if self.kind == "FAT32" else 0
        self.cbytes = self.bps * self.spc
        self._fat = None

    def fat_entry(self, c):
        base = self.rsv * self.bps
        if self.kind == "FAT12":
            v = u16(self.img.read(base + c + c // 2, 2))
            return (v >> 4) if c & 1 else (v & 0xFFF)
        if self.kind == "FAT16":
            return u16(self.img.read(base + c * 2, 2))
        return u32(self.img.read(base + c * 4, 4)) & 0x0FFFFFFF

    def eoc(self, v):
        return v >= {"FAT12": 0xFF8, "FAT16": 0xFFF8, "FAT32": 0x0FFFFFF8}[self.kind] or v < 2

    def cluster_off(self, c):
        return (self.data_start + (c - 2) * self.spc) * self.bps

    def chain(self, c, limit=1 << 20):
        out, seen = [], set()
        while 2 <= c < self.nclust + 2 and c not in seen and len(out) < limit:
            out.append(c)
            seen.add(c)
            c = self.fat_entry(c)
            if self.eoc(c):
                break
        return out

    def read_clusters(self, cl, size=None):
        parts, left = [], size
        for c in cl:
            n = self.cbytes if left is None else min(self.cbytes, left)
            if n <= 0:
                break
            parts.append(self.img.read(self.cluster_off(c), n))
            if left is not None:
                left -= n
        return b"".join(parts)

    def dir_bytes(self, cluster, deleted=False):
        if cluster == 0 and self.kind != "FAT32":
            return self.img.read((self.rsv + self.nfats * self.fatsz) * self.bps, self.root_secs * self.bps)
        if cluster == 0:
            cluster = self.root_cluster
        cl = self.chain(cluster, 4096)
        if deleted and len(cl) <= 1:
            cl = [cluster]
        return self.read_clusters(cl)


def lfn_chars(e):
    raw = e[1:11] + e[14:26] + e[28:32]
    s = raw.decode("utf-16-le", "replace")
    return s.split("\0")[0].split("￿")[0]


def fat_walk(fat, cluster, path, sink, depth=0, deleted_dir=False):
    data = fat.dir_bytes(cluster, deleted_dir)
    lfn = []
    for i in range(0, len(data) - 31, 32):
        e = data[i:i + 32]
        if e[0] == 0x00:
            break
        attr = e[11]
        if attr == 0x0F:
            lfn.append(lfn_chars(e))
            continue
        deleted = e[0] == 0xE5
        if attr & 0x08:  # метка тома
            lfn = []
            continue
        base = e[0:8].decode("cp437", "replace").rstrip()
        ext = e[8:11].decode("cp437", "replace").rstrip()
        short = base + ("." + ext if ext else "")
        if deleted:
            short = "_" + short[1:]
        name = "".join(reversed(lfn)) if lfn else short
        if deleted and lfn:
            name = "".join(reversed(lfn))
        lfn = []
        if short in (".", "..") or base.startswith(".") and not ext and base in (".", ".."):
            continue
        start = (u16(e, 20) << 16) | u16(e, 26) if fat.kind == "FAT32" else u16(e, 26)
        size = u32(e, 28)
        full = (path + "/" + name).lstrip("/")
        mark = "DEL" if deleted else "   "
        if attr & 0x10:
            print(f"  {mark} <DIR>  {full}/  (cluster {start})")
            if depth < 16 and start >= 2:
                fat_walk(fat, start, full, sink, depth + 1, deleted)
            continue
        if start < 2 or start >= fat.nclust + 2:
            content = b""
            note = ""
        elif deleted:
            n = (size + fat.cbytes - 1) // fat.cbytes
            content = fat.read_clusters(list(range(start, start + n)), min(size, MAX_EXTRACT))
            note = " (восстановлено: цепочка считается непрерывной)"
        else:
            content = fat.read_clusters(fat.chain(start), min(size, MAX_EXTRACT))
            note = ""
        print(f"  {mark} {size:>9}  {full}  (cluster {start}){note}")
        sink.handle(("[deleted]/" if deleted else "") + full, content)


def cmd_fat(args, offset=None):
    off = pick_offset(args.image, args.part) if offset is None else offset
    img = Img(args.image, off)
    try:
        try:
            fat = Fat(img)
        except Exception as e:
            print(f"[-] FAT не распознан: {e}")
            return 1
        print(f"[+] {fat.kind}: сектор {fat.bps}, кластер {fat.cbytes} Б, кластеров {fat.nclust}, "
              f"корневой {'кластер ' + str(fat.root_cluster) if fat.kind == 'FAT32' else 'каталог фикс.'}")
        sink = Sink(args.out, args.find_flags)
        fat_walk(fat, 0, "", sink)
        if args.find_flags and not sink.flags:
            print("[-] флаги в файлах не найдены")
        return 0
    finally:
        img.close()


# ───────────────────────── NTFS $MFT ─────────────────────────

def parse_runs(b, pos):
    runs, lcn = [], 0
    while pos < len(b) and b[pos]:
        h = b[pos]
        ln, lo = h & 0xF, h >> 4
        pos += 1
        length = int.from_bytes(b[pos:pos + ln], "little")
        pos += ln
        if lo == 0:
            runs.append((None, length))  # sparse
        else:
            lcn += int.from_bytes(b[pos:pos + lo], "little", signed=True)
            runs.append((lcn, length))
        pos += lo
    return runs


def parse_mft_record(rec):
    """-> dict или None. Fixup применяется на копии."""
    if rec[:4] != b"FILE":
        return None
    rec = bytearray(rec)
    usa_off, usa_n = u16(rec, 4), u16(rec, 6)
    if usa_n and usa_off + usa_n * 2 <= len(rec):
        usn = bytes(rec[usa_off:usa_off + 2])
        for i in range(1, usa_n):
            end = i * 512
            if end > len(rec):
                break
            if bytes(rec[end - 2:end]) == usn:
                rec[end - 2:end] = rec[usa_off + 2 * i: usa_off + 2 * i + 2]
    flags = u16(rec, 0x16)
    d = dict(seq=u16(rec, 0x10), inuse=bool(flags & 1), isdir=bool(flags & 2),
             names=[], streams=[], parent=None)
    pos = u16(rec, 0x14)
    while pos + 16 <= len(rec):
        atype = u32(rec, pos)
        if atype == 0xFFFFFFFF:
            break
        alen = u32(rec, pos + 4)
        if alen < 16 or pos + alen > len(rec):
            break
        nonres, nlen, noff = rec[pos + 8], rec[pos + 9], u16(rec, pos + 10)
        aname = bytes(rec[pos + noff:pos + noff + nlen * 2]).decode("utf-16-le", "replace") if nlen else ""
        if atype == 0x30 and not nonres:
            co = u16(rec, pos + 0x14)
            c = rec[pos + co:pos + alen]
            if len(c) >= 0x42:
                ln = c[0x40]
                d["names"].append((c[0x41], bytes(c[0x42:0x42 + ln * 2]).decode("utf-16-le", "replace")))
                d["parent"] = u64(c, 0) & 0xFFFFFFFFFFFF
        elif atype == 0x80:
            if not nonres:
                cl, co = u32(rec, pos + 0x10), u16(rec, pos + 0x14)
                d["streams"].append(dict(name=aname, res=True, data=bytes(rec[pos + co:pos + co + cl]), size=cl))
            else:
                ro = u16(rec, pos + 0x20)
                d["streams"].append(dict(name=aname, res=False, size=u64(rec, pos + 0x30),
                                         runs=parse_runs(bytes(rec), pos + ro)))
        pos += alen
    return d


def best_name(d, num):
    ns = [n for n in d["names"] if n[0] != 2] or d["names"]
    return ns[0][1] if ns else f"<inode{num}>"


def read_runs(img, runs, size, cluster, cap=MAX_EXTRACT):
    out, left = [], min(size, cap)
    for lcn, ln in runs:
        n = min(ln * cluster, left)
        if n <= 0:
            break
        out.append(b"\0" * n if lcn is None else img.read(lcn * cluster, n))
        left -= n
    return b"".join(out)


def cmd_mft(args):
    try:
        f = open(args.mftfile, "rb")
    except OSError as e:
        print(f"[-] {e}")
        return 1
    first = f.read(1024)
    rsz = u32(first, 0x1C) if first[:4] == b"FILE" and u32(first, 0x1C) in (1024, 4096, 2048, 512) else 1024
    if first[:4] != b"FILE":
        print("[-] не похоже на $MFT (нет сигнатуры FILE в начале)")
        return 1
    f.seek(0)
    recs, num = {}, 0
    while True:
        b = f.read(rsz)
        if len(b) < rsz:
            break
        d = parse_mft_record(b)
        if d:
            recs[num] = d
        num += 1
    f.close()
    print(f"[+] $MFT: записей {num}, разобрано {len(recs)}, размер записи {rsz}")

    def path_of(n, depth=0):
        d = recs.get(n)
        if d is None or depth > 32:
            return "<orphan>"
        nm = best_name(d, n)
        p = d["parent"]
        if n == 5 or p is None or p == n or p == 5:
            return nm if n != 5 else ""
        return path_of(p, depth + 1) + "/" + nm

    img = Img(args.image, args.offset) if args.image else None
    sink = Sink(args.out, args.find_flags)
    for n, d in sorted(recs.items()):
        if not d["names"] and not d["streams"]:
            continue
        if d["inuse"] and not args.system and best_name(d, n).startswith("$"):
            continue
        full = path_of(n).lstrip("/")
        state = "      " if d["inuse"] else "DELETED"
        kind = "<DIR>" if d["isdir"] else "     "
        for s in d["streams"]:
            sname = full + (":" + s["name"] if s["name"] else "")
            tag = "  [ADS]" if s["name"] else ""
            where = "resident" if s["res"] else "non-resident"
            print(f"  {state} #{n:<5} {kind} {s['size']:>9} {sname}{tag} ({where})")
            if s["res"]:
                data = s["data"]
            elif img:
                data = read_runs(img, s["runs"], s["size"], args.cluster)
            else:
                data = b""
                print(f"       runs={s['runs'][:6]} — для извлечения нужен --image IMG --cluster N")
            if data:
                rel = ("[deleted]/" if not d["inuse"] else "") + full.replace(":", "_")
                sink.handle(rel + ("." + s["name"] + ".ads" if s["name"] else ""), data,
                            f" ADS:{s['name']}" if s["name"] else "")
        if not d["streams"] and d["names"]:
            print(f"  {state} #{n:<5} {kind} {'':>9} {full}")
    if img:
        img.close()
    if args.find_flags and not sink.flags:
        print("[-] флаги не найдены")
    return 0


def extract_mft_from_ntfs(img, out_dir):
    """Копирует $MFT из NTFS-раздела в out_dir/$MFT.raw, возвращает (путь, cluster)."""
    b = img.read(0, 512)
    bps, spc = u16(b, 11), b[13]
    cluster = bps * spc
    mft_lcn = u64(b, 0x30)
    cps = struct.unpack_from("<b", b, 0x40)[0]
    rsz = cps * cluster if cps > 0 else 1 << -cps
    rec0 = img.read(mft_lcn * cluster, rsz)
    d = parse_mft_record(rec0)
    if not d or not d["streams"]:
        return None, cluster
    s = [x for x in d["streams"] if not x["name"]][0]
    os.makedirs(out_dir, exist_ok=True)
    dest = os.path.join(out_dir, "$MFT.raw")
    if s["res"]:
        data = s["data"]
    else:
        data = read_runs(img, s["runs"], s["size"], cluster)
    with open(dest, "wb") as fh:
        fh.write(data)
    return dest, cluster


# ───────────────────────── ext2/3/4 ─────────────────────────

class Ext:
    def __init__(self, img):
        self.img = img
        sb = img.read(0x400, 1024)
        if len(sb) < 0x100 or u16(sb, 0x38) != 0xEF53:
            raise ValueError("нет магии ext 0xEF53")
        self.sb = sb
        self.inodes = u32(sb, 0)
        self.blocks = u32(sb, 4)
        self.bsize = 1024 << u32(sb, 0x18)
        self.first_data = u32(sb, 0x14)
        self.bpg, self.ipg = u32(sb, 0x20), u32(sb, 0x28)
        self.rev = u32(sb, 0x4C)
        self.isize = u16(sb, 0x58) if self.rev >= 1 else 128
        self.compat, self.incompat, self.rocompat = u32(sb, 0x5C), u32(sb, 0x60), u32(sb, 0x64)
        self.state = u16(sb, 0x3A)
        self.label = sb[0x78:0x88].split(b"\0")[0].decode("utf-8", "replace")
        self.journal_inum = u32(sb, 0xE0)
        self.desc_size = u16(sb, 0xFE) if self.incompat & 0x80 and u16(sb, 0xFE) >= 64 else 32
        if self.incompat & 0x80:
            self.blocks |= u32(sb, 0x150) << 32
        self.ngroups = max(1, (self.blocks - self.first_data + self.bpg - 1) // self.bpg) if self.bpg else 1

    def block(self, n):
        return self.img.read(n * self.bsize, self.bsize)

    def inode_table(self, g):
        gd_block = self.first_data + 1
        d = self.img.read(gd_block * self.bsize + g * self.desc_size, self.desc_size)
        lo = u32(d, 8)
        hi = u32(d, 0x28) if self.desc_size >= 64 else 0
        return (hi << 32) | lo

    def inode(self, n):
        g, idx = divmod(n - 1, self.ipg)
        raw = self.img.read(self.inode_table(g) * self.bsize + idx * self.isize, min(self.isize, 256))
        if len(raw) < 128:
            return None
        mode, size_lo, dtime, flags = u16(raw, 0), u32(raw, 4), u32(raw, 0x14), u32(raw, 0x20)
        size = size_lo | (u32(raw, 0x6C) << 32 if (mode & 0xF000) == 0x8000 else 0)
        return dict(n=n, mode=mode, size=size, dtime=dtime, flags=flags, links=u16(raw, 0x1A),
                    iblock=bytes(raw[0x28:0x28 + 60]))

    def extent_blocks(self, node, out, depth=0):
        if len(node) < 12 or u16(node, 0) != 0xF30A or depth > 5:
            return
        ents, dep = u16(node, 2), u16(node, 6)
        for i in range(min(ents, 340)):
            e = node[12 + i * 12:24 + i * 12]
            if len(e) < 12:
                break
            if dep == 0:
                ln = u16(e, 4)
                ln = ln - 32768 if ln > 32768 else ln
                start = u32(e, 8) | (u16(e, 6) << 32)
                out.append((u32(e, 0), start, ln))
            else:
                leaf = u32(e, 4) | (u16(e, 8) << 32)
                self.extent_blocks(self.block(leaf), out, depth + 1)

    def data_blocks(self, ino):
        """Список физических блоков по порядку (0 = дыра)."""
        nblk = (ino["size"] + self.bsize - 1) // self.bsize
        nblk = min(nblk, MAX_EXTRACT // self.bsize)
        if ino["flags"] & 0x80000:
            ext = []
            self.extent_blocks(ino["iblock"], ext)
            blocks = [0] * nblk
            for lblk, start, ln in ext:
                for k in range(ln):
                    if lblk + k < nblk:
                        blocks[lblk + k] = start + k
            return blocks
        ptrs = list(struct.unpack("<15I", ino["iblock"]))
        blocks = ptrs[:12]

        def ind(b, level):
            if not b:
                return [0] * (self.bsize // 4) ** level
            arr = struct.unpack(f"<{self.bsize // 4}I", self.block(b))
            if level == 1:
                return list(arr)
            res = []
            for x in arr:
                res += ind(x, level - 1)
            return res
        if nblk > 12:
            blocks += ind(ptrs[12], 1)
        if nblk > 12 + self.bsize // 4:
            blocks += ind(ptrs[13], 2)
        return blocks[:nblk]

    def read_file(self, ino):
        out, left = [], min(ino["size"], MAX_EXTRACT)
        for b in self.data_blocks(ino):
            n = min(self.bsize, left)
            if n <= 0:
                break
            out.append(self.block(b)[:n] if b else b"\0" * n)
            left -= n
        return b"".join(out)


def ext_dir_entries(buf, slack=True):
    """-> [(inode, type, name, is_slack)]. Заходит и в slack записей (старые копии)."""
    out, pos = [], 0
    while pos + 8 <= len(buf):
        ino, rl, nl, ft = u32(buf, pos), u16(buf, pos + 4), buf[pos + 6], buf[pos + 7]
        if rl < 8 or rl % 4 or pos + rl > len(buf) or nl + 8 > rl:
            break
        if ino and nl:
            out.append((ino, ft, buf[pos + 8:pos + 8 + nl].decode("utf-8", "replace"), False))
        if slack:
            used = (8 + nl + 3) & ~3 if ino else 8
            p2 = pos + used
            while p2 + 8 <= pos + rl:
                i2, rl2, nl2 = u32(buf, p2), u16(buf, p2 + 4), buf[p2 + 6]
                if i2 and 0 < nl2 and rl2 >= 8 + nl2 and rl2 % 4 == 0 and p2 + 8 + nl2 <= pos + rl:
                    out.append((i2, buf[p2 + 7], buf[p2 + 8:p2 + 8 + nl2].decode("utf-8", "replace"), True))
                    p2 += max(8, (8 + nl2 + 3) & ~3)
                else:
                    p2 += 4
        pos += rl
    return out


def ext_walk(fs, ino_n, path, sink, depth=0, seen=None):
    seen = seen if seen is not None else set()
    if ino_n in seen or depth > 16:
        return
    seen.add(ino_n)
    ino = fs.inode(ino_n)
    if not ino:
        return
    for child, ft, name, is_slack in ext_dir_entries(fs.read_file(ino)):
        if name in (".", ".."):
            continue
        full = (path + "/" + name).lstrip("/")
        ci = fs.inode(child) if child <= fs.inodes else None
        if ci is None:
            continue
        mode = ci["mode"] & 0xF000
        if is_slack:
            print(f"  SLACK/DEL inode {child:<6} {full}  (старая запись в slack каталога"
                  f"{'; inode занят/удалён: dtime=' + str(ci['dtime']) if ci['dtime'] else ''})")
            if mode == 0x8000 and ci["size"] and ci["links"]:
                sink.handle("[deleted]/" + full, fs.read_file(ci))
            continue
        if mode == 0x4000:
            print(f"        <DIR>  {full}/  inode {child}")
            ext_walk(fs, child, full, sink, depth + 1, seen)
        elif mode == 0x8000:
            print(f"  {ci['size']:>14}  {full}  inode {child}")
            sink.handle(full, fs.read_file(ci))
        else:
            print(f"        (type {mode:#x})  {full}  inode {child}")


def scan_journal(fs, sink):
    """jbd2: дескрипторы -> старые копии блоков. Эвристика, без проверки CRC."""
    if not fs.compat & 0x4:
        print("[i] журнала нет (has_journal не выставлен)")
        return
    ino = fs.inode(fs.journal_inum or 8)
    if not ino or not ino["size"]:
        print("[-] inode журнала не прочитан")
        return
    jb = fs.data_blocks(ino)
    first = fs.block(jb[0]) if jb and jb[0] else b""
    if len(first) < 1024 or struct.unpack(">I", first[:4])[0] != 0xC03B3998:
        print("[-] jbd2 superblock не найден (журнал внешний/пустой)")
        return
    jbs = struct.unpack(">I", first[12:16])[0] or fs.bsize
    maxlen = struct.unpack(">I", first[16:20])[0]
    jfirst = struct.unpack(">I", first[20:24])[0] or 1
    j_incompat = struct.unpack(">I", first[0x28:0x2C])[0]
    is64, csum3 = bool(j_incompat & 2), bool(j_incompat & 0x10)
    tag_sz = 16 if csum3 else (8 + (4 if is64 else 0))
    print(f"[+] jbd2: блок {jbs}, блоков {maxlen}, первый {jfirst}, tags: csum_v3={csum3} 64bit={is64}")

    def jblock(i):
        pb = jb[i] if i < len(jb) else 0
        return fs.block(pb) if pb else b""
    found = 0
    i, limit = jfirst, min(maxlen, len(jb))
    while i < limit:
        blk = jblock(i)
        if len(blk) >= 12 and struct.unpack(">I", blk[:4])[0] == 0xC03B3998 \
                and struct.unpack(">I", blk[4:8])[0] == 1:
            seq = struct.unpack(">I", blk[8:12])[0]
            p, k = 12, 1
            while p + tag_sz <= len(blk):
                tgt = struct.unpack(">I", blk[p:p + 4])[0]
                if csum3:
                    fl = struct.unpack(">I", blk[p + 4:p + 8])[0]
                else:
                    fl = struct.unpack(">H", blk[p + 6:p + 8])[0]
                    if is64:
                        pass
                step = tag_sz
                if not fl & 2:
                    step += 16
                data = jblock(i + k)
                found += 1
                if data:
                    rel = f"[journal]/seq{seq}_blk{tgt}_j{i + k}"
                    ents = ext_dir_entries(data, slack=False) if len(data) >= 12 and \
                        u32(data, 0) and u16(data, 4) >= 12 and data[8:9] and data[6] and \
                        data[8:8 + data[6]] == b"." else []
                    if ents:
                        names = ", ".join(f"{n}->{x}" for x, _, n, _ in ents[:20] if n not in (".", ".."))
                        print(f"  JOURNAL seq {seq} fs-блок {tgt} (каталог): {names}")
                    sink.handle(rel, data, f" journal seq {seq} -> fs-блок {tgt}")
                k += 1
                p += step
                if fl & 8:
                    break
            i += k
        else:
            i += 1
    print(f"[+] журнал: старых копий блоков просмотрено {found}"
          + ("" if found else " (журнал пуст или транзакции уже отработаны)"))


def cmd_ext(args, offset=None):
    off = pick_offset(args.image, args.part) if offset is None else offset
    img = Img(args.image, off)
    try:
        try:
            fs = Ext(img)
        except Exception as e:
            print(f"[-] ext не распознан: {e}")
            return 1
        ver = "ext4" if fs.incompat & 0x40 or fs.rocompat & 0x40 else "ext3" if fs.compat & 0x4 else "ext2"
        print(f"[+] {ver}: magic 0xEF53, inodes {fs.inodes}, blocks {fs.blocks}, блок {fs.bsize} Б, "
              f"inode {fs.isize} Б, групп {fs.ngroups}, rev {fs.rev}, state {fs.state}, label '{fs.label}'")
        print(f"    features compat=0x{fs.compat:X} incompat=0x{fs.incompat:X} ro_compat=0x{fs.rocompat:X}"
              f" (journal={'да' if fs.compat & 4 else 'нет'}, extents={'да' if fs.incompat & 0x40 else 'нет'})")
        sink = Sink(args.out, args.find_flags)
        print("[i] ЧАСТИЧНО: дерево от корня + slack каталогов + журнал; удалённые inode не восстанавливаются")
        try:
            ext_walk(fs, 2, "", sink)
        except Exception as e:
            print(f"[!] разбор каталогов оборван: {e}")
        try:
            scan_journal(fs, sink)
        except Exception as e:
            print(f"[!] разбор журнала оборван: {e}")
        if args.find_flags and not sink.flags:
            print("[-] флаги не найдены")
        return 0
    finally:
        img.close()


# ───────────────────────── scan ─────────────────────────

def raw_scan(path, sink_flags=True):
    found, tail = [], b""
    with open(path, "rb") as f:
        while True:
            chunk = f.read(4 << 20)
            if not chunk:
                break
            buf = tail + chunk
            for fl in common.find_flags(buf):
                if fl not in found:
                    found.append(fl)
            tail = buf[-512:]
    return found


def cmd_scan(args):
    if not os.path.isfile(args.image):
        print(f"[-] файл не найден: {args.image}")
        return 1
    out = args.out
    all_flags = []
    targets = []  # (offset, label)
    parts, scheme = parse_parts(args.image)
    img0 = Img(args.image, 0)
    try:
        if parts:
            print(f"[+] таблица разделов: {scheme}, разделов {len(parts)}")
            for p in parts:
                print(f"    #{p['n']} {p['type']} start={p['start']} sectors={p['size']}")
                targets.append((p["offset"], f"part{p['n']}"))
        if not any(detect_fs(Img(args.image, o)) for o, _ in targets):
            if detect_fs(img0):
                targets = [(0, "raw")]
    finally:
        img0.close()

    handled = False
    for off, label in targets:
        im = Img(args.image, off)
        kind = detect_fs(im)
        im.close()
        if not kind:
            continue
        handled = True
        sub = os.path.join(out, label) if out else None
        print(f"\n=== {label} @0x{off:X}: {kind.upper()} ===")
        ns = argparse.Namespace(image=args.image, part=None, out=sub, find_flags=args.find_flags,
                                mftfile=None, system=False)
        if kind == "fat":
            cmd_fat(ns, off)
        elif kind == "ext":
            cmd_ext(ns, off)
        elif kind == "ntfs":
            im = Img(args.image, off)
            try:
                mftp, cl = extract_mft_from_ntfs(im, sub or os.path.join(tempdir(), "disk_image_scan", label))
            finally:
                im.close()
            if not mftp:
                print("[-] $MFT не прочитан")
                continue
            ns.mftfile, ns.image, ns.cluster, ns.offset = mftp, args.image, cl, off
            cmd_mft(ns)
    if not handled:
        print("[i] файловая система не распознана — сырой поиск флагов")
    # всегда добавляем сырой поток: найдёт то, что не видно через ФС (slack, неразмеченное)
    raw = raw_scan(args.image)
    if args.find_flags or not handled:
        print("\n=== сырой поиск по образу ===")
        for fl in raw:
            print(f"[FLAG] {fl}")
        if not raw:
            print("[-] флагов нет")
    tsk_hint(args.image)
    return 0


def tempdir():
    import tempfile
    return tempfile.gettempdir()


def main():
    ap = argparse.ArgumentParser(description="образы дисков: разделы, FAT, NTFS $MFT, ext, journal")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common_args(p, with_part=True):
        p.add_argument("image")
        if with_part:
            p.add_argument("--part", type=int, help="номер раздела из parts (иначе файловая система с 0)")
        p.add_argument("--out", help="папка для извлечённых файлов")
        p.add_argument("--find-flags", action="store_true", help="искать флаги в содержимом")

    sub.add_parser("parts").add_argument("image")
    common_args(sub.add_parser("fat"))
    common_args(sub.add_parser("ext"))
    common_args(sub.add_parser("scan"), with_part=False)
    pm = sub.add_parser("mft")
    pm.add_argument("mftfile")
    pm.add_argument("--out")
    pm.add_argument("--find-flags", action="store_true")
    pm.add_argument("--image", help="образ NTFS для чтения non-resident данных")
    pm.add_argument("--cluster", type=int, default=4096, help="размер кластера NTFS (байт)")
    pm.add_argument("--offset", type=int, default=0, help="смещение NTFS-раздела в образе (байт)")
    pm.add_argument("--system", action="store_true", help="показать и системные записи (<16)")
    args = ap.parse_args()
    for k, v in (("part", None), ("out", None), ("find_flags", False)):
        if not hasattr(args, k):
            setattr(args, k, v)
    fn = dict(parts=cmd_parts, fat=cmd_fat, mft=cmd_mft, ext=cmd_ext, scan=cmd_scan)[args.cmd]
    try:
        return fn(args)
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main() or 0)
