#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gen_admin.py — генераторы тестовых артефактов для admin/* (чистый Python).

Используется tests/selftest.py (checks_admin); можно и руками:

  python tests/gen_admin.py --out DIR      # все артефакты в папку + manifest.json

Образы ВМ (QCOW2 c zlib-кластером, VDI, VMDK sparse/streamOptimized, OVA),
логи (auth.log, nginx, journald JSON, bash/PowerShell history), куст реестра
regf, XML задачи планировщика, дамп Linux-конфигов. Флаги генерируются кодом.
"""
from __future__ import annotations

try:
    import sys as _sys
    for _stream in (_sys.stdout, _sys.stderr):
        _stream.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import argparse
import hashlib
import io
import json
import math
import os
import struct
import tarfile
import zlib

SECTOR = 512


def gen_flag(tag: str) -> str:
    """Детерминированный флаг из тега (никаких ручных ответов)."""
    return "CTF{" + tag + "_" + hashlib.sha256(tag.encode()).hexdigest()[:10] + "}"


# ---------------------------------------------------------------- образы ВМ

def make_disk_raw(flag: str, size=2 << 20):
    """Сырой диск: MBR с разделом 0x83, суперблок ext2, флаг и «flag.txt».

    Возвращает (raw, смещение флага). Флаг лежит в 4-м кластере по 64 KB.
    """
    raw = bytearray(size)
    part_lba = 64
    entry = struct.pack("<B3sB3sII", 0x80, b"\x00\x02\x00", 0x83, b"\xfe\xff\xff",
                        part_lba, size // SECTOR - part_lba)
    raw[446:462] = entry
    raw[510:512] = b"\x55\xaa"
    sb = part_lba * SECTOR + 1024
    raw[sb + 56:sb + 58] = b"\x53\xef"
    flag_off = 0x30000 + 0x123
    raw[flag_off:flag_off + len(flag)] = flag.encode()
    note = b"flag.txt\x00secret notes"
    raw[0x50010:0x50010 + len(note)] = note
    return bytes(raw), flag_off


def make_qcow2(raw: bytes, cluster_bits=16, compress=(3,), zero=()):
    """QCOW2 v3: L1/L2, обычные кластеры, raw-deflate кластеры, zero-кластеры."""
    cs = 1 << cluster_bits
    n_cl = math.ceil(len(raw) / cs)
    l2_per = cs // 8
    l1_size = math.ceil(n_cl / l2_per)
    l1_off, rt_off, rb_off = cs, 2 * cs, 3 * cs
    l2_offs = [(4 + i) * cs for i in range(l1_size)]
    next_cl = 4 + l1_size
    l2 = [0] * (l1_size * l2_per)
    body = {}
    comp_items = []
    for idx in range(n_cl):
        chunk = raw[idx * cs:(idx + 1) * cs]
        if idx in zero:
            l2[idx] = 1
            continue
        if not chunk.strip(b"\x00"):
            continue
        if idx in compress:
            co = zlib.compressobj(9, zlib.DEFLATED, -12)
            comp_items.append((idx, co.compress(chunk) + co.flush()))
            continue
        off = next_cl * cs
        next_cl += 1
        body[off] = chunk + bytes(cs - len(chunk))
        l2[idx] = (1 << 63) | off
    pos = next_cl * cs
    comp_blob = bytearray()
    x = 62 - (cluster_bits - 8)
    for idx, data in comp_items:
        off = pos + len(comp_blob)
        nsec = (off + len(data) - 1) // SECTOR - off // SECTOR
        l2[idx] = (1 << 62) | (nsec << x) | off
        comp_blob += data
    total = pos + len(comp_blob)
    used = math.ceil(total / cs)
    hdr = struct.pack(">4sIQIIQIIQQIIQQQQII", b"QFI\xfb", 3, 0, 0, cluster_bits, len(raw),
                      0, l1_size, l1_off, rt_off, 1, 0, 0, 0, 0, 0, 4, 104)
    out = bytearray(total)
    out[:len(hdr)] = hdr
    out[l1_off:l1_off + 8 * l1_size] = struct.pack(f">{l1_size}Q",
                                                   *[(1 << 63) | o for o in l2_offs])
    out[rt_off:rt_off + 8] = struct.pack(">Q", rb_off)
    out[rb_off:rb_off + 2 * used] = struct.pack(f">{used}H", *([1] * used))
    for i, o in enumerate(l2_offs):
        out[o:o + cs] = struct.pack(f">{l2_per}Q", *l2[i * l2_per:(i + 1) * l2_per])
    for o, chunk in body.items():
        out[o:o + cs] = chunk
    out[pos:pos + len(comp_blob)] = comp_blob
    return bytes(out)


def make_vdi(raw: bytes, block=1 << 20, zero_blocks=()):
    """VDI 1.1 dynamic: заголовок, карта блоков, данные."""
    n = math.ceil(len(raw) / block)
    off_blocks = 512
    off_data = math.ceil((off_blocks + 4 * n) / 512) * 512
    bmap, data = [], bytearray()
    for i in range(n):
        chunk = raw[i * block:(i + 1) * block]
        if i in zero_blocks:
            bmap.append(0xFFFFFFFE)
        elif not chunk.strip(b"\x00"):
            bmap.append(0xFFFFFFFF)
        else:
            bmap.append(len(data) // block)
            data += chunk + bytes(block - len(chunk))
    pre = b"<<< Oracle VM VirtualBox Disk Image >>>\n".ljust(64, b"\x00")
    hdr = bytearray(512)
    hdr[:64] = pre
    struct.pack_into("<III", hdr, 64, 0xBEDA107F, 0x00010001, 400)
    struct.pack_into("<II", hdr, 76, 1, 0)
    hdr[84:84 + 9] = b"test disk"
    struct.pack_into("<II", hdr, 340, off_blocks, off_data)
    struct.pack_into("<Q", hdr, 368, len(raw))
    struct.pack_into("<IIII", hdr, 376, block, 0, n, len(data) // block)
    hdr[392:408] = hashlib.md5(b"vdi-create").digest()
    hdr[408:424] = hashlib.md5(b"vdi-modify").digest()
    out = bytearray(hdr)
    out += struct.pack(f"<{n}I", *bmap)
    out += bytes(off_data - len(out))
    out += data
    return bytes(out)


def _vmdk_header(version, flags, cap, grain, desc_off, desc_size, n_gte, rgd, gd, overhead,
                 compress=0):
    h = struct.pack("<4sIIQQQQIQQQB4sH", b"KDMV", version, flags, cap, grain, desc_off,
                    desc_size, n_gte, rgd, gd, overhead, 0, b"\n \r\n", compress)
    return h + bytes(512 - len(h))


def make_vmdk_sparse(raw: bytes, grain=128, n_gte=512):
    """monolithicSparse: заголовок KDMV, встроенный дескриптор, RGD/RGT, GD/GT, грейны."""
    cap = len(raw) // SECTOR
    gsize = grain * SECTOR
    n_gde = math.ceil(cap / (grain * n_gte))
    desc = ("# Disk DescriptorFile\nversion=1\nCID=fffffffe\nparentCID=ffffffff\n"
            'createType="monolithicSparse"\n\n# Extent description\n'
            f'RW {cap} SPARSE "disk.vmdk"\n\n# The Disk Data Base\n'
            'ddb.virtualHWVersion = "4"\n').encode()
    desc_off, desc_size = 1, 20
    gd_secs = math.ceil(n_gde * 4 / SECTOR)
    gt_secs = n_gde * math.ceil(n_gte * 4 / SECTOR)
    rgd = desc_off + desc_size
    rgt = rgd + gd_secs
    gd = rgt + gt_secs
    gt = gd + gd_secs
    overhead = math.ceil((gt + gt_secs) / grain) * grain
    gtes = [0] * (n_gde * n_gte)
    grains = bytearray()
    for i in range(math.ceil(cap / grain)):
        chunk = raw[i * gsize:(i + 1) * gsize]
        if not chunk.strip(b"\x00"):
            continue
        gtes[i] = overhead + len(grains) // SECTOR
        grains += chunk + bytes(gsize - len(chunk))
    out = bytearray(overhead * SECTOR)
    out[:512] = _vmdk_header(1, 3, cap, grain, desc_off, desc_size, n_gte, rgd, gd, overhead)
    out[desc_off * SECTOR:desc_off * SECTOR + len(desc)] = desc
    for gd_start, gt_start in ((rgd, rgt), (gd, gt)):
        dir_entries = [gt_start + k * math.ceil(n_gte * 4 / SECTOR) for k in range(n_gde)]
        out[gd_start * SECTOR:gd_start * SECTOR + 4 * n_gde] = struct.pack(f"<{n_gde}I",
                                                                           *dir_entries)
        out[gt_start * SECTOR:gt_start * SECTOR + 4 * len(gtes)] = struct.pack(
            f"<{len(gtes)}I", *gtes)
    out += grains
    return bytes(out)


def make_vmdk_stream(raw: bytes, grain=128, n_gte=512):
    """streamOptimized: сжатые грейны с маркерами, GT/GD-маркеры, футер, EOS."""
    cap = len(raw) // SECTOR
    gsize = grain * SECTOR
    n_gde = math.ceil(cap / (grain * n_gte))
    desc = ("# Disk DescriptorFile\nversion=1\nCID=fffffffe\nparentCID=ffffffff\n"
            'createType="streamOptimized"\n\n# Extent description\n'
            f'RW {cap} SPARSE "disk.vmdk"\n').encode()
    desc_off, desc_size = 1, 2
    overhead = desc_off + desc_size
    flags = 1 | (1 << 16) | (1 << 17)
    out = bytearray(_vmdk_header(3, flags, cap, grain, desc_off, desc_size, n_gte, 0,
                                 0xFFFFFFFFFFFFFFFF, overhead, 1))
    out += desc + bytes(desc_size * SECTOR - len(desc))
    gtes = [0] * (n_gde * n_gte)
    for i in range(math.ceil(cap / grain)):
        chunk = raw[i * gsize:(i + 1) * gsize]
        if not chunk.strip(b"\x00"):
            continue
        comp = zlib.compress(chunk, 9)
        gtes[i] = len(out) // SECTOR
        rec = struct.pack("<QI", i * grain, len(comp)) + comp
        out += rec + bytes((-len(rec)) % SECTOR)

    def marker(val, mtype):
        return struct.pack("<QII", val, 0, mtype) + bytes(SECTOR - 16)

    gt_secs = math.ceil(n_gte * 4 / SECTOR)
    gt_pos = []
    for k in range(n_gde):
        out += marker(gt_secs, 1)
        gt_pos.append(len(out) // SECTOR)
        tbl = struct.pack(f"<{n_gte}I", *gtes[k * n_gte:(k + 1) * n_gte])
        out += tbl + bytes(gt_secs * SECTOR - len(tbl))
    gd_secs = math.ceil(n_gde * 4 / SECTOR)
    out += marker(gd_secs, 2)
    gd_pos = len(out) // SECTOR
    tbl = struct.pack(f"<{n_gde}I", *gt_pos)
    out += tbl + bytes(gd_secs * SECTOR - len(tbl))
    out += marker(1, 3)
    out += _vmdk_header(3, flags, cap, grain, desc_off, desc_size, n_gte, 0, gd_pos,
                        overhead, 1)
    out += marker(0, 0)
    return bytes(out)


def make_ova(vmdk: bytes, name="appliance", note="test appliance"):
    """OVA = tar: .ovf первым, затем диск и манифест."""
    ovf = f"""<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1"
          xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1">
  <References><File ovf:id="file1" ovf:href="{name}-disk1.vmdk" ovf:size="{len(vmdk)}"/></References>
  <DiskSection><Info>disks</Info>
    <Disk ovf:diskId="vmdisk1" ovf:fileRef="file1" ovf:capacity="2"
          ovf:capacityAllocationUnits="byte * 2^20"
          ovf:format="http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized"/>
  </DiskSection>
  <VirtualSystem ovf:id="{name}"><Info>vm</Info><Name>{name}</Name>
    <OperatingSystemSection ovf:id="96"><Info>os</Info><Description>Debian_64</Description>
    </OperatingSystemSection>
    <AnnotationSection><Info>note</Info><Annotation>{note}</Annotation></AnnotationSection>
  </VirtualSystem>
</Envelope>
""".encode()
    mf = (f"SHA256({name}.ovf)= {hashlib.sha256(ovf).hexdigest()}\n"
          f"SHA256({name}-disk1.vmdk)= {hashlib.sha256(vmdk).hexdigest()}\n").encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for fn, data in ((f"{name}.ovf", ovf), (f"{name}-disk1.vmdk", vmdk), (f"{name}.mf", mf)):
            ti = tarfile.TarInfo(fn)
            ti.size = len(data)
            ti.mtime = 1700000000
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def write_vm_set(out_dir):
    """Все образы ВМ в папку. → {имя: (путь, флаг, ожидаемый raw)}"""
    os.makedirs(out_dir, exist_ok=True)
    res = {}
    for kind in ("qcow2", "vdi", "vmdk_sparse", "vmdk_stream", "ova"):
        flag = gen_flag("vm_" + kind)
        raw, _off = make_disk_raw(flag)
        if kind == "qcow2":
            data, fn = make_qcow2(raw), "disk.qcow2"
        elif kind == "vdi":
            data, fn = make_vdi(raw, zero_blocks=()), "disk.vdi"
        elif kind == "vmdk_sparse":
            data, fn = make_vmdk_sparse(raw), "sparse.vmdk"
        elif kind == "vmdk_stream":
            data, fn = make_vmdk_stream(raw), "stream.vmdk"
        else:
            data, fn = make_ova(make_vmdk_stream(raw)), "appliance.ova"
        p = os.path.join(out_dir, fn)
        with open(p, "wb") as f:
            f.write(data)
        res[kind] = (p, flag, raw)
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, help="папка для артефактов")
    a = ap.parse_args()
    manifest = {}
    for k, (p, flag, _raw) in write_vm_set(os.path.join(a.out, "vm")).items():
        manifest[k] = {"path": p, "flag": flag}
    with open(os.path.join(a.out, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    print(f"[+] {len(manifest)} артефактов в {a.out}")


if __name__ == "__main__":
    main()
