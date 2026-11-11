#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vm_image.py — образы виртуальных машин без qemu/VirtualBox: QCOW2, VMDK, VDI,
VHD, OVA/OVF. Чистый Python, только чтение, потоково (многогигабайтный образ
целиком в память не грузится).

  python vm_image.py disk.qcow2                 # формат, таблицы, разделы, флаги внутри
  python vm_image.py disk.vmdk --raw disk.raw   # конвертация в raw (дырки — sparse)
  python vm_image.py vm.ova                     # OVF (имя, ОС, аннотации) + диски внутри
  python vm_image.py vm.ova --extract out       # распаковать OVA
  python vm_image.py vm.ova --raw d.raw --disk 0
  python vm_image.py disk.vdi --find flag.txt   # строка ASCII/UTF-16 в виртуальном диске
  python vm_image.py disk.vdi --next            # флаги → raw во temp → forensic/disk_image.py
  python vm_image.py disk.vhd --mount           # как смонтировать (Linux/Windows)

Поддержка:
  QCOW2 v2/v3: L1/L2, обычные, zero и zlib-сжатые кластеры, extended L2
           (подкластеры); zstd — если есть модуль; шифрование/external data
           file — понятное сообщение; backing file — дырки остаются нулями.
  VMDK:    monolithicSparse/twoGbMaxExtentSparse (KDMV, GD/GT), streamOptimized
           (сжатые грейны, GD в футере, иначе проход по маркерам),
           monolithicFlat/twoGbMaxExtentFlat (текстовый дескриптор + extents).
  VDI:     dynamic/fixed (карта блоков); differencing — нужен родитель.
  VHD:     fixed и dynamic (BAT); VHDX — подсказка (qemu-img/7z/Mount-DiskImage).
  OVA:     tar: .ovf/.mf/диски; диски читаются прямо из tar без распаковки.
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
import json
import math
import os
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import adminlib  # noqa: E402
import common  # noqa: E402

SECTOR = 512
GD_AT_END = 0xFFFFFFFFFFFFFFFF


class VMError(Exception):
    """Образ не разобрать: понятное сообщение без трейсбека."""


class Src:
    """Окно только для чтения в файл: весь файл или член tar (OVA)."""

    def __init__(self, path, offset=0, size=None, name=None):
        self.path = path
        self.name = name or os.path.basename(path)
        self.base = offset
        self.f = open(path, "rb")
        total = os.path.getsize(path)
        self.size = (total - offset) if size is None else size

    def pread(self, off, n):
        if off < 0 or off >= self.size or n <= 0:
            return b""
        n = min(n, self.size - off)
        self.f.seek(self.base + off)
        return self.f.read(n)

    def close(self):
        try:
            self.f.close()
        except Exception:
            pass


# ---------------------------------------------------------------- диски

class Disk:
    """Виртуальный диск: size, read(off, n), iter_data() по выделенным блокам."""

    fmt = "?"

    def __init__(self):
        self.size = 0
        self.unit = 65536
        self.notes = []
        self.info = {}
        self._cache = {}

    # переопределяют форматы
    def unit_data(self, idx):
        return None

    def allocated(self):
        return iter(range(0, (self.size + self.unit - 1) // self.unit))

    def _get(self, idx):
        if idx in self._cache:
            return self._cache[idx]
        d = self.unit_data(idx)
        if d is not None and len(d) < self.unit:
            d = d + bytes(self.unit - len(d))
        if len(self._cache) > 64:
            self._cache.clear()
        self._cache[idx] = d
        return d

    def read(self, off, n):
        out = bytearray()
        end = min(off + n, self.size)
        while off < end:
            idx, inner = divmod(off, self.unit)
            take = min(self.unit - inner, end - off)
            d = self._get(idx)
            out += d[inner:inner + take] if d is not None else bytes(take)
            off += take
        return bytes(out)

    def iter_data(self):
        """(виртуальное смещение, байты) только по выделенным блокам."""
        for idx in self.allocated():
            off = idx * self.unit
            if off >= self.size:
                break
            d = self.unit_data(idx)
            if d is None:
                continue
            if len(d) < self.unit:
                d = d + bytes(self.unit - len(d))
            yield off, d[:self.size - off]

    def describe(self):
        return self.fmt


class RawDisk(Disk):
    """Сырые данные: FLAT-экстент VMDK, fixed VHD, raw-образ."""

    fmt = "raw"

    def __init__(self, src, offset=0, size=None):
        super().__init__()
        self.src = src
        self.off = offset
        self.size = (src.size - offset) if size is None else size
        self.unit = 1 << 20

    def unit_data(self, idx):
        start = idx * self.unit
        return self.src.pread(self.off + start, min(self.unit, self.size - start))

    def iter_data(self):
        for idx in range((self.size + self.unit - 1) // self.unit):
            d = self.unit_data(idx)
            if not d:
                break
            if not d.strip(b"\x00"):
                continue
            yield idx * self.unit, d


class ZeroDisk(Disk):
    fmt = "zero"

    def __init__(self, size):
        super().__init__()
        self.size = size

    def allocated(self):
        return iter(())


class ConcatDisk(Disk):
    """Несколько экстентов подряд (VMDK twoGbMaxExtent*, descriptor)."""

    fmt = "concat"

    def __init__(self, parts):
        super().__init__()
        self.parts = []
        pos = 0
        for d in parts:
            self.parts.append((pos, d))
            pos += d.size
        self.size = pos

    def read(self, off, n):
        out = bytearray()
        end = min(off + n, self.size)
        for start, d in self.parts:
            if off >= end:
                break
            if start + d.size <= off:
                continue
            take = min(end, start + d.size) - off
            out += d.read(off - start, take)
            off += take
        return bytes(out)

    def iter_data(self):
        for start, d in self.parts:
            for o, data in d.iter_data():
                yield start + o, data


class Qcow2(Disk):
    fmt = "QCOW2"

    def __init__(self, src):
        super().__init__()
        self.src = src
        h = src.pread(0, 112)
        if len(h) < 72 or h[:4] != b"QFI\xfb":
            raise VMError("нет сигнатуры QFI\\xfb")
        (self.version, bfo, bfs, cbits, self.size, crypt, l1_size, l1_off,
         _rt_off, _rt_cl, nsnap, _snap_off) = struct.unpack(">IQIIQIIQQIIQ", h[4:72])
        if self.version not in (2, 3):
            raise VMError(f"QCOW версии {self.version} (QCOW1?) не поддержан: "
                          "qemu-img convert -O raw img out.raw")
        if not 9 <= cbits <= 21:
            raise VMError(f"странный cluster_bits={cbits} — заголовок битый")
        self.cbits = cbits
        self.unit = 1 << cbits
        incompat = 0
        self.compression = 0
        if self.version == 3 and len(h) >= 104:
            incompat = struct.unpack(">Q", h[72:80])[0]
            hlen = struct.unpack(">I", h[100:104])[0]
            if hlen > 104 and len(h) >= 105:
                self.compression = h[104]
        self.extended = bool(incompat & 0x10)
        self.info = {"version": self.version, "cluster": self.unit, "virtual_size": self.size,
                     "l1_size": l1_size, "snapshots": nsnap}
        if crypt:
            raise VMError(f"образ зашифрован (crypt_method={crypt}: "
                          f"{'AES' if crypt == 1 else 'LUKS'}) — нужен пароль: "
                          "qemu-img convert --object secret,id=s0,data=PASS "
                          "--image-opts encrypt.key-secret=s0,file.filename=IMG -O raw out.raw")
        if incompat & 0x04:
            raise VMError("external data file (incompatible bit 2): данные лежат "
                          "в отдельном файле — ищи его рядом и открывай qemu-img")
        if incompat & 0x02:
            self.notes.append("флаг corrupt выставлен — таблицы могут врать")
        if incompat & 0x01:
            self.notes.append("флаг dirty (refcount не сведены) — данным это не мешает")
        if self.compression not in (0, 1):
            raise VMError(f"неизвестный тип сжатия {self.compression}")
        if bfo and bfs:
            name = src.pread(bfo, min(bfs, 1023)).decode("utf-8", "replace")
            self.info["backing_file"] = name
            self.notes.append(f"есть backing file «{name}»: невыделенные кластеры берутся "
                              "оттуда, здесь они нули (сконвертируй и базовый образ)")
        if nsnap:
            self.notes.append(f"снапшотов: {nsnap} (читается активное состояние; "
                              "снапшот: qemu-img convert -l <имя>)")
        self.l2_entry = 16 if self.extended else 8
        self.l2_per = self.unit // self.l2_entry
        raw_l1 = src.pread(l1_off, l1_size * 8)
        if len(raw_l1) < l1_size * 8:
            self.notes.append("L1 обрезана — файл неполный")
        self.l1 = list(struct.unpack(f">{len(raw_l1) // 8}Q", raw_l1[:len(raw_l1) // 8 * 8]))
        self._l2 = {}
        self.compressed = 0

    def _l2_table(self, l1_idx):
        if l1_idx >= len(self.l1):
            return None
        off = self.l1[l1_idx] & 0x00FFFFFFFFFFFE00
        if not off:
            return None
        t = self._l2.get(off)
        if t is None:
            raw = self.src.pread(off, self.unit)
            raw += bytes(self.unit - len(raw))
            t = struct.unpack(f">{self.unit // 8}Q", raw)
            if len(self._l2) > 256:
                self._l2.clear()
            self._l2[off] = t
        return t

    def _entry(self, idx):
        l1_idx, l2_idx = divmod(idx, self.l2_per)
        t = self._l2_table(l1_idx)
        if t is None:
            return 0, 0
        if self.extended:
            return t[2 * l2_idx], t[2 * l2_idx + 1]
        return t[l2_idx], 0

    def _decompress(self, raw):
        if self.compression == 1:
            try:
                from compression import zstd as _z  # Python 3.14+
                return _z.decompress(raw)
            except ImportError:
                pass
            try:
                import zstandard
                return zstandard.ZstdDecompressor().decompressobj().decompress(raw)
            except ImportError:
                raise VMError("кластеры сжаты zstd, а модуля zstd нет: "
                              "pip install zstandard или qemu-img convert")
        d = zlib.decompressobj(-15)
        return d.decompress(raw, self.unit)

    def unit_data(self, idx):
        e, bitmap = self._entry(idx)
        if not e:
            return None
        if e & (1 << 62):  # сжатый кластер
            x = 62 - (self.cbits - 8)
            off = e & ((1 << x) - 1)
            nsec = (e >> x) & ((1 << (self.cbits - 8)) - 1)
            csize = (nsec + 1) * SECTOR - (off & (SECTOR - 1))
            raw = self.src.pread(off, csize)
            try:
                return self._decompress(raw)
            except zlib.error as ex:
                self.notes.append(f"кластер {idx}: zlib не распаковал ({ex})")
                return None
        off = e & 0x00FFFFFFFFFFFE00
        if (e & 1) and not self.extended:  # zero-кластер (v3)
            return None
        if not off:
            return None
        data = self.src.pread(off, self.unit)
        if self.extended and bitmap:
            alloc, zero = bitmap & 0xFFFFFFFF, bitmap >> 32
            sub = self.unit // 32
            buf = bytearray(data + bytes(self.unit - len(data)))
            for i in range(32):
                if (zero >> i) & 1 or not (alloc >> i) & 1:
                    buf[i * sub:(i + 1) * sub] = bytes(sub)
            data = bytes(buf)
        return data

    def allocated(self):
        self.compressed = 0
        for i, l1e in enumerate(self.l1):
            if not l1e & 0x00FFFFFFFFFFFE00:
                continue
            t = self._l2_table(i)
            step = 2 if self.extended else 1
            for j in range(self.l2_per):
                e = t[j * step]
                if not e:
                    continue
                if e & (1 << 62):
                    self.compressed += 1
                elif not e & 0x00FFFFFFFFFFFE00:
                    continue
                yield i * self.l2_per + j

    def describe(self):
        s = f"QCOW2 v{self.version}, кластер {common.human(self.unit)}"
        if self.extended:
            s += ", extended L2"
        if self.compression == 1:
            s += ", zstd"
        return s


class Vdi(Disk):
    fmt = "VDI"
    TYPES = {1: "dynamic", 2: "fixed", 3: "undo", 4: "differencing"}

    def __init__(self, src):
        super().__init__()
        self.src = src
        h = src.pread(0, 512)
        if len(h) < 400 or h[64:68] != b"\x7f\x10\xda\xbe":
            raise VMError("нет сигнатуры VDI 0xbeda107f")
        ver = struct.unpack("<I", h[68:72])[0]
        if ver >> 16 != 1:
            raise VMError(f"VDI версии {ver >> 16}.{ver & 0xffff} не поддержан: "
                          "VBoxManage clonemedium disk IMG out.raw --format RAW")
        (_hsize, itype, _flags) = struct.unpack("<III", h[72:84])
        comment = h[84:340].split(b"\x00", 1)[0].decode("utf-8", "replace")
        off_blocks, off_data = struct.unpack("<II", h[340:348])
        self.size, = struct.unpack("<Q", h[368:376])
        cb_block, cb_extra, n_blocks, n_alloc = struct.unpack("<IIII", h[376:392])
        if not cb_block or cb_block & (cb_block - 1):
            raise VMError(f"странный размер блока {cb_block}")
        self.unit = cb_block
        self.extra = cb_extra
        self.off_data = off_data
        self.type = self.TYPES.get(itype, str(itype))
        self.info = {"type": self.type, "block": cb_block, "blocks": n_blocks,
                     "allocated": n_alloc, "virtual_size": self.size}
        if comment:
            self.info["comment"] = comment
            self.notes.append(f"комментарий: {comment}")
        if itype == 4:
            self.notes.append("differencing-образ: невыделенные блоки — в родителе "
                              "(uuid parent), здесь нули")
        raw = src.pread(off_blocks, n_blocks * 4)
        self.bmap = struct.unpack(f"<{len(raw) // 4}I", raw[:len(raw) // 4 * 4])

    def unit_data(self, idx):
        if idx >= len(self.bmap):
            return None
        e = self.bmap[idx]
        if e >= 0xFFFFFFFE:
            return None
        return self.src.pread(self.off_data + e * (self.unit + self.extra) + self.extra,
                              self.unit)

    def allocated(self):
        for i, e in enumerate(self.bmap):
            if e < 0xFFFFFFFE:
                yield i

    def describe(self):
        return f"VDI {self.type}, блок {common.human(self.unit)}"


class VmdkSparse(Disk):
    fmt = "VMDK"

    def __init__(self, src):
        super().__init__()
        self.src = src
        h = src.pread(0, 512)
        if h[:4] != b"KDMV":
            raise VMError("нет сигнатуры KDMV")
        self._parse_header(h)
        self.descriptor = ""
        if self.desc_off and self.desc_size:
            raw = src.pread(self.desc_off * SECTOR, min(self.desc_size * SECTOR, 1 << 20))
            self.descriptor = raw.split(b"\x00", 1)[0].decode("utf-8", "replace")
        if self.gd_off == GD_AT_END:
            foot = src.pread(src.size - 1024, 512)
            if foot[:4] == b"KDMV":
                self._parse_header(foot)
        self.index = None
        if self.gd_off in (0, GD_AT_END) or self.gd_off * SECTOR >= src.size:
            if self.compressed:
                self.index = self._scan_stream()
                self.notes.append("каталог грейнов не найден — собрал индекс проходом по маркерам")
            else:
                raise VMError("нет каталога грейнов (gdOffset) — файл обрезан?")
        else:
            n_gde = math.ceil(self.capacity / (self.grain * self.n_gte))
            raw = src.pread(self.gd_off * SECTOR, n_gde * 4)
            self.gd = struct.unpack(f"<{len(raw) // 4}I", raw[:len(raw) // 4 * 4])
        self._gt = {}
        self.size = self.capacity * SECTOR
        self.unit = self.grain * SECTOR
        m = re.search(r'createType\s*=\s*"([^"]+)"', self.descriptor)
        self.create_type = m.group(1) if m else ("streamOptimized" if self.compressed else "sparse")
        m = re.search(r'parentFileNameHint\s*=\s*"([^"]+)"', self.descriptor)
        if m:
            self.notes.append(f"дочерний (snapshot) диск: родитель «{m.group(1)}», "
                              "невыделенные грейны — там")
        self.info = {"version": self.version, "createType": self.create_type,
                     "grain": self.unit, "virtual_size": self.size,
                     "compressed": self.compressed}

    def _parse_header(self, h):
        (self.version, self.flags, self.capacity, self.grain, self.desc_off,
         self.desc_size, self.n_gte, _rgd, self.gd_off, self.overhead) = struct.unpack(
            "<IIQQQQIQQQ", h[4:72])
        self.compress_alg = struct.unpack("<H", h[77:79])[0]
        self.compressed = bool(self.flags & (1 << 16)) or self.compress_alg == 1
        if not self.grain or not self.n_gte:
            raise VMError("grainSize/numGTEsPerGT = 0 — заголовок битый")

    def _scan_stream(self):
        """streamOptimized без каталога: маркеры grain/GT/GD/footer/EOS подряд."""
        idx = {}
        pos = self.overhead * SECTOR if self.overhead else SECTOR
        while pos + 16 <= self.src.size:
            head = self.src.pread(pos, 16)
            lba, sz = struct.unpack("<QI", head[:12])
            if sz:
                idx[lba // self.grain] = pos
                pos += (12 + sz + SECTOR - 1) // SECTOR * SECTOR
                continue
            mtype = struct.unpack("<I", head[12:16])[0]
            if mtype == 0:  # EOS
                break
            pos += SECTOR + lba * SECTOR
        return idx

    def _grain_pos(self, idx):
        if self.index is not None:
            return self.index.get(idx, 0)
        gdi, gti = divmod(idx, self.n_gte)
        if gdi >= len(self.gd) or not self.gd[gdi]:
            return 0
        t = self._gt.get(gdi)
        if t is None:
            raw = self.src.pread(self.gd[gdi] * SECTOR, self.n_gte * 4)
            raw += bytes(self.n_gte * 4 - len(raw))
            t = struct.unpack(f"<{self.n_gte}I", raw)
            if len(self._gt) > 512:
                self._gt.clear()
            self._gt[gdi] = t
        e = t[gti]
        return 0 if e <= 1 else e * SECTOR  # 1 = zeroed grain

    def unit_data(self, idx):
        pos = self._grain_pos(idx)
        if not pos:
            return None
        if not self.compressed:
            return self.src.pread(pos, self.unit)
        head = self.src.pread(pos, 12)
        _lba, sz = struct.unpack("<QI", head)
        raw = self.src.pread(pos + 12, sz)
        for wbits in (15, -15):
            try:
                return zlib.decompressobj(wbits).decompress(raw, self.unit)
            except zlib.error:
                continue
        self.notes.append(f"грейн {idx}: deflate не распаковался")
        return None

    def allocated(self):
        if self.index is not None:
            yield from sorted(self.index)
            return
        for gdi, g in enumerate(self.gd):
            if not g:
                continue
            for gti in range(self.n_gte):
                idx = gdi * self.n_gte + gti
                if self._grain_pos(idx):
                    yield idx

    def describe(self):
        return f"VMDK {self.create_type} v{self.version}, грейн {common.human(self.unit)}"


class Vhd(Disk):
    fmt = "VHD"

    def __init__(self, src):
        super().__init__()
        self.src = src
        foot = src.pread(src.size - 512, 512)
        if foot[:8] != b"conectix":
            foot = src.pread(0, 512)
        if foot[:8] != b"conectix":
            raise VMError("нет футера conectix")
        data_off, = struct.unpack(">Q", foot[16:24])
        self.size, = struct.unpack(">Q", foot[48:56])
        dtype, = struct.unpack(">I", foot[60:64])
        self.dtype = {2: "fixed", 3: "dynamic", 4: "differencing"}.get(dtype, str(dtype))
        self.info = {"type": self.dtype, "virtual_size": self.size}
        if dtype == 2:
            self.raw = RawDisk(src, 0, min(self.size, src.size - 512))
            self.unit = self.raw.unit
            return
        self.raw = None
        dh = src.pread(data_off, 1024)
        if dh[:8] != b"cxsparse":
            raise VMError("нет заголовка cxsparse у dynamic VHD")
        bat_off, = struct.unpack(">Q", dh[16:24])
        n_ent, block = struct.unpack(">II", dh[28:36])
        self.unit = block
        self.bitmap = ((block // SECTOR // 8) + SECTOR - 1) // SECTOR * SECTOR
        raw = src.pread(bat_off, n_ent * 4)
        self.bat = struct.unpack(f">{len(raw) // 4}I", raw[:len(raw) // 4 * 4])
        if dtype == 4:
            self.notes.append("differencing VHD: невыделенные блоки — в родителе")

    def unit_data(self, idx):
        if self.raw is not None:
            return self.raw.unit_data(idx)
        if idx >= len(self.bat) or self.bat[idx] == 0xFFFFFFFF:
            return None
        return self.src.pread(self.bat[idx] * SECTOR + self.bitmap, self.unit)

    def allocated(self):
        if self.raw is not None:
            yield from range((self.size + self.unit - 1) // self.unit)
            return
        for i, e in enumerate(self.bat):
            if e != 0xFFFFFFFF:
                yield i

    def iter_data(self):
        if self.raw is not None:
            yield from self.raw.iter_data()
            return
        yield from super().iter_data()

    def describe(self):
        return f"VHD {self.dtype}, блок {common.human(self.unit)}"


EXTENT_RE = re.compile(r'^\s*(RW|RDONLY|NOACCESS)\s+(\d+)\s+(\w+)(?:\s+"([^"]*)"(?:\s+(\d+))?)?',
                       re.M)


def open_descriptor(path, text):
    """Текстовый VMDK-дескриптор → ConcatDisk из экстентов."""
    base = os.path.dirname(os.path.abspath(path))
    parts, notes = [], []
    for m in EXTENT_RE.finditer(text):
        _acc, sectors, etype, fname, eoff = m.groups()
        size = int(sectors) * SECTOR
        etype = etype.upper()
        if etype == "ZERO" or not fname:
            parts.append(ZeroDisk(size))
            continue
        fp = os.path.join(base, fname)
        if not os.path.exists(fp):
            notes.append(f"нет файла экстента «{fname}» — его часть будет нулями")
            parts.append(ZeroDisk(size))
            continue
        src = Src(fp)
        if etype in ("FLAT", "VMFS", "VMFSRAW", "VMFSRDM"):
            parts.append(RawDisk(src, int(eoff or 0) * SECTOR, size))
        elif etype in ("SPARSE", "VMFSSPARSE"):
            head = src.pread(0, 4)
            if head != b"KDMV":
                notes.append(f"экстент {fname}: не KDMV ({head!r}) — COWD/ESX не поддержан")
                parts.append(ZeroDisk(size))
                continue
            d = VmdkSparse(src)
            d.size = size
            parts.append(d)
        else:
            notes.append(f"тип экстента {etype} не поддержан — нули")
            parts.append(ZeroDisk(size))
    if not parts:
        raise VMError("в дескрипторе нет строк экстентов (RW <секторы> FLAT|SPARSE \"файл\")")
    disk = ConcatDisk(parts)
    disk.fmt = "VMDK"
    m = re.search(r'createType\s*=\s*"([^"]+)"', text)
    ctype = m.group(1) if m else "?"
    disk.describe = lambda: f"VMDK {ctype} (дескриптор, экстентов: {len(parts)})"
    disk.info = {"createType": ctype, "extents": len(parts), "virtual_size": disk.size}
    disk.notes = notes
    m = re.search(r'parentFileNameHint\s*=\s*"([^"]+)"', text)
    if m:
        disk.notes.append(f"дочерний диск, родитель «{m.group(1)}»")
    return disk


def open_disk(src, path_for_desc=None):
    """Src → Disk по сигнатуре."""
    head = src.pread(0, 4096)
    if head[:4] == b"QFI\xfb":
        return Qcow2(src)
    if head[:4] == b"KDMV":
        return VmdkSparse(src)
    if len(head) >= 68 and head[64:68] == b"\x7f\x10\xda\xbe":
        return Vdi(src)
    if head[:8] == b"vhdxfile":
        raise VMError("VHDX пока не разбирается: qemu-img convert -O raw IMG out.raw, "
                      "7z x IMG, или в Windows: Mount-DiskImage -Access ReadOnly")
    if head[:8] == b"conectix" or src.pread(src.size - 512, 8) == b"conectix":
        return Vhd(src)
    if head[:21] == b"# Disk DescriptorFile" or b"createType=" in head[:2048]:
        if path_for_desc is None:
            raise VMError("VMDK-дескриптор внутри архива: экстенты лежат отдельными файлами")
        text = src.pread(0, 1 << 20).decode("utf-8", "replace")
        return open_descriptor(path_for_desc, text)
    raise VMError("не образ ВМ (нет сигнатур QCOW2/VMDK/VDI/VHD)")


# ---------------------------------------------------------------- разделы

MBR_TYPES = {0x01: "FAT12", 0x04: "FAT16", 0x05: "extended", 0x06: "FAT16", 0x07: "NTFS/exFAT",
             0x0b: "FAT32", 0x0c: "FAT32 LBA", 0x0e: "FAT16 LBA", 0x0f: "extended LBA",
             0x82: "Linux swap", 0x83: "Linux", 0x8e: "Linux LVM", 0xa5: "FreeBSD",
             0xee: "GPT protective", 0xef: "EFI", 0xfd: "Linux RAID", 0x27: "WinRE"}


def fs_magic(disk, off):
    b = disk.read(off, 4096)
    if len(b) < 512:
        return None
    if b[3:11] == b"NTFS    ":
        return "NTFS"
    if b[3:11] == b"EXFAT   ":
        return "exFAT"
    if b[3:11] == b"-FVE-FS-":
        return "BitLocker"
    if b[82:87] == b"FAT32":
        return "FAT32"
    if b[54:59] in (b"FAT12", b"FAT16"):
        return b[54:59].decode()
    if b[:6] == b"LUKS\xba\xbe":
        return "LUKS"
    if b[:4] == b"XFSB":
        return "XFS"
    if b[512:520] == b"LABELONE":
        return "LVM PV"
    sb = b[1024:1152]
    if len(sb) >= 100 and sb[56:58] == b"\x53\xef":
        incompat, = struct.unpack("<I", sb[96:100])
        compat, = struct.unpack("<I", sb[92:96])
        return "ext4" if incompat & 0x40 else ("ext3" if compat & 4 else "ext2")
    if disk.read(off + 0x10040, 8) == b"_BHRfS_M":
        return "btrfs"
    if disk.read(off + 4086, 10) in (b"SWAPSPACE2", b"SWAP-SPACE"):
        return "swap"
    if disk.read(off + 0x8001, 5) == b"CD001":
        return "ISO9660"
    return None


def partitions(disk):
    """[(№, старт байт, размер байт, тип, ФС)] из MBR/GPT; [] если таблицы нет."""
    out = []
    mbr = disk.read(0, 512)
    if len(mbr) == 512 and mbr[510:512] == b"\x55\xaa":
        gpt = disk.read(512, 512)
        if gpt[:8] == b"EFI PART":
            ent_lba, n_ent, ent_sz = struct.unpack("<QII", gpt[72:88])
            raw = disk.read(ent_lba * SECTOR, min(n_ent, 256) * ent_sz)
            for i in range(min(n_ent, 256)):
                e = raw[i * ent_sz:(i + 1) * ent_sz]
                if len(e) < 128 or not e[:16].strip(b"\x00"):
                    continue
                first, last = struct.unpack("<QQ", e[32:48])
                name = e[56:128].decode("utf-16-le", "replace").rstrip("\x00")
                out.append((i + 1, first * SECTOR, (last - first + 1) * SECTOR,
                            f"GPT {name or '-'}", fs_magic(disk, first * SECTOR)))
            return out
        for i in range(4):
            e = mbr[446 + i * 16:462 + i * 16]
            ptype = e[4]
            lba, n = struct.unpack("<II", e[8:16])
            if not ptype or not n:
                continue
            out.append((i + 1, lba * SECTOR, n * SECTOR,
                        f"MBR 0x{ptype:02x} {MBR_TYPES.get(ptype, '')}".rstrip(),
                        fs_magic(disk, lba * SECTOR)))
    return out


# ---------------------------------------------------------------- действия

def scan_flags(disk, limit_bytes):
    """Флаги в выделенных блоках (ASCII и UTF-16LE). → ([(флаг, смещение)], байт)."""
    found, seen = [], set()
    tail, last_end, scanned = b"", -1, 0
    for off, data in disk.iter_data():
        if scanned >= limit_bytes:
            break
        scanned += len(data)
        buf = (tail + data) if off == last_end else data
        base = off - len(tail) if off == last_end else off
        hits = common.find_flags(buf)
        if b"{\x00" in buf:
            wide = re.sub(rb"([\x20-\x7e])\x00", rb"\1", buf)
            hits += common.find_flags(wide)
        for f in hits:
            if f in seen:
                continue
            seen.add(f)
            pos = buf.find(f.encode())
            found.append((f, base + pos if pos >= 0 else off))
        tail = data[-256:]
        last_end = off + len(data)
    return found, scanned


def find_text(disk, needle, limit_bytes, max_hits=40):
    pats = [needle.encode("utf-8"), needle.encode("utf-16-le")]
    hits, scanned, tail, last_end = [], 0, b"", -1
    for off, data in disk.iter_data():
        if scanned >= limit_bytes or len(hits) >= max_hits:
            break
        scanned += len(data)
        cont = off == last_end
        buf = (tail + data) if cont else data
        base = off - len(tail) if cont else off
        for p in pats:
            i = buf.find(p)
            while i != -1 and len(hits) < max_hits:
                ctx = buf[max(0, i - 48):i + len(p) + 80]
                wide = p is pats[1]
                if wide:
                    ctx = ctx.replace(b"\x00", b"")
                txt = re.sub(rb"[^\x20-\x7e]", b".", ctx).decode()
                hits.append((base + i, "utf16" if wide else "ascii", txt))
                i = buf.find(p, i + 1)
        tail = data[-max(len(p) for p in pats):]
        last_end = off + len(data)
    uniq, seen = [], set()
    for h in hits:
        if h[0] not in seen:
            seen.add(h[0])
            uniq.append(h)
    return uniq, scanned


def _set_sparse(f):
    """Windows: пометить файл sparse, чтобы дырки диска не писались нулями."""
    if os.name != "nt":
        return
    try:
        import ctypes
        import msvcrt
        from ctypes import wintypes
        h = msvcrt.get_osfhandle(f.fileno())
        ret = wintypes.DWORD()
        ctypes.windll.kernel32.DeviceIoControl(wintypes.HANDLE(h), 0x000900C4, None, 0,
                                               None, 0, ctypes.byref(ret), None)
    except Exception:
        pass


def write_raw(disk, out):
    written = 0
    with open(out, "wb") as f:
        _set_sparse(f)
        for off, data in disk.iter_data():
            if not data.strip(b"\x00"):
                continue
            f.seek(off)
            f.write(data)
            written += len(data)
        f.truncate(disk.size)
    return written


def mount_hints(path, kind):
    q = f'"{path}"'
    have = {t: shutil.which(t) for t in ("qemu-img", "qemu-nbd", "guestmount", "7z",
                                         "VBoxManage", "vboxmanage")}
    mark = lambda t: " (есть)" if have.get(t) else ""  # noqa: E731
    print("[i] монтирование/конвертация внешними тулзами (если есть):")
    print(f"    qemu-img convert -O raw {q} disk.raw{mark('qemu-img')}")
    print(f"    sudo modprobe nbd && sudo qemu-nbd -r -c /dev/nbd0 {q} && "
          f"sudo mount -o ro /dev/nbd0p1 /mnt{mark('qemu-nbd')}")
    print(f"    guestmount -a {q} -i --ro /mnt{mark('guestmount')}")
    print(f"    7z l {q}   # 7-Zip видит разделы и ФС внутри VMDK/VDI/VHD/QCOW2{mark('7z')}")
    print(f"    VBoxManage clonemedium disk {q} disk.raw --format RAW"
          f"{mark('VBoxManage') or mark('vboxmanage')}")
    if kind in ("VHD", "VHDX"):
        print(f"    Windows: Mount-DiskImage -ImagePath {q} -Access ReadOnly")
    print("    raw без внешних тулз: python admin/vm_image.py IMG --raw disk.raw")


def next_step_hint(raw):
    di = adminlib.tool_path("forensic/disk_image.py")
    print("[i] дальше:")
    if di:
        print(f"    python forensic/disk_image.py \"{raw}\"     # разделы/ФС/файлы")
    else:
        print(f"    python toolbox.py strings \"{raw}\" --grep \"flag|pass|key\"")
        print(f"    python toolbox.py carve \"{raw}\" --out carved")
    print(f"    sudo mount -o ro,loop \"{raw}\" /mnt   # Linux, если ФС без таблицы разделов")


def report_disk(disk, label, args, quiet=False):
    """Сводка по диску + флаги. Возвращает список флагов."""
    print(f"[+] {label}: {disk.describe()}, виртуальный размер {common.human(disk.size)}")
    for n in disk.notes:
        print(f"[!] {n}")
    try:
        parts = partitions(disk)
    except VMError:
        parts = []
    if parts:
        print("[+] разделы:")
        for num, start, size, ptype, fs in parts:
            print(f"    #{num}  start={start} ({start // SECTOR} sect)  {common.human(size):>9}  "
                  f"{ptype}  {fs or ''}")
    else:
        fs = fs_magic(disk, 0)
        if fs:
            print(f"[+] ФС без таблицы разделов: {fs}")
    limit = int(args.scan_limit * 1024 * 1024)
    flags, scanned = scan_flags(disk, limit)
    alloc_note = ""
    if isinstance(disk, Qcow2) and disk.compressed:
        alloc_note = f", сжатых кластеров: {disk.compressed}"
    print(f"[+] просканировано выделенных данных: {common.human(scanned)}{alloc_note}")
    if scanned >= limit:
        print(f"[i] упёрся в --scan-limit {args.scan_limit} MB — увеличь для полного прохода")
    for f, off in flags:
        if any(w in f.lower() for w in ("missing", "placeholder", "dummy", "fake")):
            print(f"[!] заглушка, не флаг: {f} @0x{off:x}")
        else:
            print(f"[!!!] ФЛАГ: {f}  (виртуальное смещение 0x{off:x})")
    if not flags and not quiet:
        print("[-] флагов в открытом виде внутри диска нет — дальше ФС/файлы (--raw / --next)")
    return [f for f, _ in flags]


# ---------------------------------------------------------------- OVA/OVF

def _local(tag):
    return tag.rsplit("}", 1)[-1]


def _attr(el, name):
    for k, v in el.attrib.items():
        if _local(k) == name:
            return v
    return None


def parse_ovf(text):
    import xml.etree.ElementTree as ET
    info = {"files": {}, "disks": [], "names": [], "os": [], "texts": [], "props": []}
    try:
        root = ET.fromstring(text.encode("utf-8") if isinstance(text, str) else text)
    except ET.ParseError as e:
        info["error"] = str(e)
        return info
    for el in root.iter():
        t = _local(el.tag)
        if t == "File":
            info["files"][_attr(el, "id")] = {"href": _attr(el, "href"),
                                              "size": _attr(el, "size"),
                                              "compression": _attr(el, "compression")}
        elif t == "Disk":
            info["disks"].append({"id": _attr(el, "diskId"), "file": _attr(el, "fileRef"),
                                  "capacity": _attr(el, "capacity"),
                                  "units": _attr(el, "capacityAllocationUnits"),
                                  "format": (_attr(el, "format") or "").rsplit("#", 1)[-1]})
        elif t == "VirtualSystem":
            info["names"].append(_attr(el, "id"))
        elif t == "OperatingSystemSection":
            for c in el:
                if _local(c.tag) == "Description" and c.text:
                    info["os"].append(c.text.strip())
        elif t == "Property":
            info["props"].append((_attr(el, "key"), _attr(el, "value") or ""))
        elif t in ("Annotation", "Product", "Vendor", "Version", "FullVersion",
                   "ProductUrl", "VendorUrl", "Name", "Description", "Info", "License"):
            if el.text and el.text.strip():
                info["texts"].append((t, el.text.strip()))
    return info


def print_ovf(info, label):
    print(f"[+] OVF {label}")
    if info.get("error"):
        print(f"[!] XML не разобрался: {info['error']}")
        return
    for n in info["names"]:
        print(f"    VM: {n}")
    for o in info["os"]:
        print(f"    ОС: {o}")
    seen = set()
    for t, v in info["texts"]:
        if (t, v) in seen or t == "Info":
            continue
        seen.add((t, v))
        print(f"    {t}: {v[:300]}")
    for k, v in info["props"]:
        print(f"    property {k} = {v[:200]}")
    for d in info["disks"]:
        f = info["files"].get(d["file"], {})
        print(f"    диск {d['id']}: {f.get('href')} capacity={d['capacity']} "
              f"{d['units'] or ''} {d['format']}"
              + (f" compression={f['compression']}" if f.get("compression") else ""))
    # base64 в аннотациях/свойствах — частая прятка
    for _t, v in info["texts"] + [(k, v) for k, v in info["props"]]:
        for tok in re.findall(r"[A-Za-z0-9+/=_-]{12,}", v or ""):
            raw = adminlib.try_b64(tok)
            txt = adminlib.readable(raw) if raw else None
            if txt:
                print(f"    base64 «{tok[:40]}» → {txt[:200]}")


def ova_members(path):
    try:
        tf = tarfile.open(path, "r:")
    except tarfile.ReadError as e:
        raise VMError(f"OVA не читается как несжатый tar: {e}")
    with tf:
        return [m for m in tf.getmembers() if m.isfile()]


DISK_EXT = (".vmdk", ".vdi", ".vhd", ".vhdx", ".qcow2", ".qcow", ".img", ".raw")


def ova_disks(path, members):
    out = []
    for m in members:
        src = Src(path, m.offset_data, m.size, name=m.name)
        head = src.pread(0, 4096)
        looks = m.name.lower().endswith(DISK_EXT) or head[:4] in (b"QFI\xfb", b"KDMV") \
            or head[64:68] == b"\x7f\x10\xda\xbe" or head[:8] == b"conectix"
        if not looks:
            src.close()
            continue
        if head[:2] == b"\x1f\x8b":
            print(f"[!] {m.name}: gzip внутри OVA (ovf:compression=gzip) — "
                  "распакуй --extract, потом gunzip, потом снова vm_image")
            src.close()
            continue
        out.append((m, src))
    return out


def do_ova(path, args):
    members = ova_members(path)
    print(f"[+] OVA: {len(members)} файл(ов)")
    for m in members:
        print(f"    {m.name:40s} {common.human(m.size):>10}  @{m.offset_data}")
    flags = []
    for m in members:
        low = m.name.lower()
        if low.endswith((".ovf", ".mf", ".cert")) and m.size < 8 << 20:
            src = Src(path, m.offset_data, m.size)
            raw = src.pread(0, m.size)
            src.close()
            text = adminlib.decode_text(raw)
            if low.endswith(".ovf"):
                print_ovf(parse_ovf(raw), m.name)
            elif low.endswith(".mf"):
                print(f"[+] манифест {m.name}:")
                for ln in text.splitlines()[:20]:
                    print(f"    {ln[:160]}")
            found = adminlib.flags_in(text)
            adminlib.print_flags(found, m.name)
            flags += found
    if args.extract:
        os.makedirs(args.extract, exist_ok=True)
        with tarfile.open(path, "r:") as tf:
            for m in members:
                dst = os.path.join(args.extract, os.path.basename(m.name))
                if not os.path.basename(m.name):
                    continue
                with tf.extractfile(m) as fin, open(dst, "wb") as fout:
                    shutil.copyfileobj(fin, fout, 1 << 20)
                print(f"[+] извлечено: {dst}")
    disks = ova_disks(path, members)
    sel = disks
    if args.disk is not None:
        sel = [d for i, d in enumerate(disks)
               if str(i) == args.disk or os.path.basename(d[0].name) == args.disk]
        if not sel:
            print(f"[-] диска «{args.disk}» нет; есть: "
                  + ", ".join(f"{i}={d[0].name}" for i, d in enumerate(disks)))
            return flags
    for i, (m, src) in enumerate(sel):
        try:
            disk = open_disk(src)
        except VMError as e:
            print(f"[-] {m.name}: {e}")
            continue
        flags += report_disk(disk, f"диск {m.name}", args, quiet=bool(args.raw))
        if args.raw:
            n = write_raw(disk, args.raw)
            print(f"[+] raw: {args.raw} ({common.human(disk.size)}, данных {common.human(n)})")
            next_step_hint(args.raw)
            break
        if args.find:
            show_find(disk, args)
    for _m, src in disks:
        src.close()
    return flags


def do_ovf(path, args):
    raw = adminlib.read_head(path, 8 << 20)
    info = parse_ovf(raw)
    print_ovf(info, os.path.basename(path))
    flags = adminlib.flags_in(adminlib.decode_text(raw))
    adminlib.print_flags(flags, os.path.basename(path))
    base = os.path.dirname(os.path.abspath(path))
    for fid, f in info["files"].items():
        href = f.get("href") or ""
        p = os.path.join(base, os.path.basename(href))
        if not os.path.exists(p):
            print(f"[-] файла {href} рядом нет")
            continue
        if not href.lower().endswith(DISK_EXT):
            continue
        try:
            disk = open_disk(Src(p), p)
        except VMError as e:
            print(f"[-] {href}: {e}")
            continue
        flags += report_disk(disk, f"диск {href}", args)
    return flags


def show_find(disk, args):
    hits, scanned = find_text(disk, args.find, int(args.scan_limit * 1024 * 1024))
    print(f"[+] поиск «{args.find}»: {len(hits)} совпадений в {common.human(scanned)}")
    for off, enc, ctx in hits:
        print(f"    0x{off:012x} ({off // SECTOR} sect) [{enc}] {ctx}")


def run_next(disk, path, args):
    """--next: raw во temp и forensic/disk_image.py по нему (если есть)."""
    di = adminlib.tool_path("forensic/disk_image.py")
    if disk.size > args.max_raw * 1024 * 1024:
        print(f"[i] виртуальный диск {common.human(disk.size)} > --max-raw {args.max_raw} MB — "
              "raw во temp не делаю; сам: --raw OUT")
        return
    out_dir = os.path.join(tempfile.gettempdir(), "solve_vm")
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, os.path.basename(path) + ".raw")
    n = write_raw(disk, out)
    print(f"[+] raw: {out} ({common.human(disk.size)}, данных {common.human(n)})")
    if not di:
        next_step_hint(out)
        return
    print(f"[i] запускаю forensic/disk_image.py {out}")
    try:
        r = subprocess.run([sys.executable, di, out], capture_output=True,
                           timeout=args.next_timeout,
                           env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        sys.stdout.write((r.stdout + r.stderr).decode("utf-8", "replace"))
    except subprocess.TimeoutExpired:
        print(f"[-] disk_image.py не уложился в {args.next_timeout} с")


def main():
    ap = argparse.ArgumentParser(description="образы ВМ: QCOW2/VMDK/VDI/VHD/OVA → raw, флаги")
    ap.add_argument("path", help="образ (.qcow2/.vmdk/.vdi/.vhd/.ova/.ovf)")
    ap.add_argument("--raw", metavar="OUT", help="сконвертировать в raw (потоково, sparse)")
    ap.add_argument("--extract", metavar="DIR", help="OVA: распаковать файлы")
    ap.add_argument("--disk", help="OVA: какой диск (номер или имя)")
    ap.add_argument("--find", metavar="TEXT", help="найти строку (ASCII/UTF-16) в диске")
    ap.add_argument("--next", action="store_true",
                    help="после скана: raw во temp + forensic/disk_image.py")
    ap.add_argument("--mount", action="store_true", help="команды монтирования")
    ap.add_argument("--scan-limit", type=float, default=4096,
                    help="сколько МБ выделенных данных сканировать на флаги")
    ap.add_argument("--max-raw", type=float, default=4096, help="--next: предел raw, МБ")
    ap.add_argument("--next-timeout", type=float, default=150)
    ap.add_argument("--json", action="store_true", help="info в JSON")
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)

    path = args.path
    err = adminlib.open_error(path)
    if err:
        print(f"[-] {err}")
        sys.exit(2)
    if args.raw and os.path.abspath(args.raw) == os.path.abspath(path):
        print("[-] --raw совпадает с входным файлом")
        sys.exit(2)

    kind = adminlib.vm_kind(path)
    print(f"=== {path} ({common.human(os.path.getsize(path))}) ===")
    if not kind:
        print("[-] не похоже на образ ВМ (нет QFI\\xfb / KDMV / VDI / conectix / OVA tar)")
        print("[i] сырой образ диска: python forensic/disk_image.py IMG "
              "или python toolbox.py disk IMG")
        sys.exit(1)
    print(f"[+] тип по данным: {kind}")
    try:
        if kind == "OVA":
            do_ova(path, args)
            if args.mount:
                mount_hints(path, kind)
            return
        if kind == "OVF":
            do_ovf(path, args)
            return
        src = Src(path)
        disk = open_disk(src, path)
        if args.json:
            print(json.dumps({"format": disk.fmt, "describe": disk.describe(),
                              **disk.info, "notes": disk.notes}, ensure_ascii=False,
                             indent=2, default=str))
        flags = report_disk(disk, os.path.basename(path), args, quiet=bool(args.raw))
        if args.find:
            show_find(disk, args)
        if args.raw:
            n = write_raw(disk, args.raw)
            print(f"[+] raw: {args.raw} ({common.human(disk.size)}, данных {common.human(n)})")
            next_step_hint(args.raw)
        elif args.next:
            if adminlib.real_flags(flags):
                print("[i] флаг уже найден — raw/disk_image не нужен")
            else:
                run_next(disk, path, args)
        if args.mount:
            mount_hints(path, kind)
        if not (args.raw or args.next or args.mount):
            print(f"[i] raw: python admin/vm_image.py \"{path}\" --raw disk.raw   "
                  "| монтирование: --mount")
        src.close()
    except VMError as e:
        print(f"[-] {e}")
        sys.exit(1)
    except (OSError, struct.error) as e:
        print(f"[-] образ не читается: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
