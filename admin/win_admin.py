#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
win_admin.py — Windows-администрирование оффлайн: реестр (regf), службы,
автозапуск, планировщик задач, история PowerShell. Чистый Python, только чтение.

  python win_admin.py dump/                     # авто: кусты, Tasks, ConsoleHost_history
  python win_admin.py NTUSER.DAT                # авто по файлу
  python win_admin.py reg SOFTWARE              # сводка куста + флаги (ASCII/UTF-16/base64)
  python win_admin.py reg NTUSER.DAT --key "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
  python win_admin.py reg SYSTEM --search flag  # по именам ключей/значений и данным
  python win_admin.py reg SAM --dump --max 500  # всё дерево
  python win_admin.py reg NTUSER.DAT --deleted  # удалённые ключи/значения в свободных ячейках
  python win_admin.py services SYSTEM           # ControlSet\\Services: ImagePath/Start/ObjectName
  python win_admin.py run SOFTWARE NTUSER.DAT   # Run/RunOnce/Winlogon/IFEO/AppInit
  python win_admin.py tasks Windows/System32/Tasks  # XML задач: команда, триггеры, автор
  python win_admin.py pshistory ConsoleHost_history.txt   # -EncodedCommand → текст

regf: base block (checksum, dirty), hbin, nk/vk/lf/lh/li/ri/db; типы REG_SZ,
EXPAND_SZ, MULTI_SZ, DWORD(BE), QWORD, BINARY. Грязный куст (.LOG1/.LOG2 не
применены) — предупреждение. Хеши SAM не расшифровываются (нужен bootkey) —
подсказка secretsdump.
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
import codecs
import datetime as dt
import mmap
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import adminlib  # noqa: E402
import common  # noqa: E402

REG_TYPES = {0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY", 4: "REG_DWORD",
             5: "REG_DWORD_BE", 6: "REG_LINK", 7: "REG_MULTI_SZ", 8: "REG_RESOURCE_LIST",
             9: "REG_FULL_RESOURCE_DESCRIPTOR", 10: "REG_RESOURCE_REQUIREMENTS_LIST",
             11: "REG_QWORD"}
BASE = 4096


class RegError(Exception):
    pass


def filetime(ft):
    if not ft:
        return None
    try:
        return dt.datetime(1601, 1, 1) + dt.timedelta(microseconds=ft // 10)
    except OverflowError:
        return None


def fmt_t(t):
    return t.strftime("%Y-%m-%d %H:%M:%S") if t else "—"


class Value:
    def __init__(self, hive, off):
        d = hive.cell(off)
        if d[:2] != b"vk":
            raise RegError(f"нет vk @0x{off:x}")
        nlen, size, doff, vtype, flags = struct.unpack("<HIIIH", d[2:18])
        raw_name = d[20:20 + nlen]
        self.name = (raw_name.decode("latin-1") if flags & 1
                     else raw_name.decode("utf-16-le", "replace")) or "(default)"
        self.type = vtype
        self.off = off
        self.hive = hive
        self._size, self._doff = size, doff

    @property
    def data(self):
        size, doff = self._size, self._doff
        if size & 0x80000000:
            return struct.pack("<I", doff)[:size & 0x7FFFFFFF]
        if size == 0:
            return b""
        cell = self.hive.cell(doff)
        if size > 16344 and cell[:2] == b"db":
            nseg, lst = struct.unpack("<HI", cell[2:8])
            segs = self.hive.cell(lst)
            out = bytearray()
            for i in range(nseg):
                so = struct.unpack("<I", segs[i * 4:i * 4 + 4])[0]
                out += self.hive.cell(so)[:16344]
            return bytes(out[:size])
        return bytes(cell[:size])

    def text(self):
        """Человеческое значение: строка/число/список/hex."""
        d, t = self.data, self.type
        try:
            if t in (1, 2, 6):
                return utf16z(d)
            if t == 7:
                parts = [p for p in utf16(d).split("\x00") if p]
                return " | ".join(parts)
            if t == 4 and len(d) >= 4:
                v = struct.unpack("<I", d[:4])[0]
                return f"{v} (0x{v:x})"
            if t == 5 and len(d) >= 4:
                v = struct.unpack(">I", d[:4])[0]
                return f"{v} (0x{v:x})"
            if t == 11 and len(d) >= 8:
                v = struct.unpack("<Q", d[:8])[0]
                return f"{v} (0x{v:x})"
        except struct.error:
            pass
        r = adminlib.readable(d)
        if r and len(d) >= 4:
            return r.rstrip("\x00")
        return d[:48].hex() + ("…" if len(d) > 48 else "")

    def strings(self):
        """Все текстовые представления данных (для поиска флагов)."""
        d = self.data
        out = [self.text()]
        if d:
            out.append(d.decode("latin-1"))
            if len(d) >= 4:
                out.append(d.decode("utf-16-le", "ignore"))
        return out


def utf16(d):
    if len(d) % 2:
        d = d[:-1]
    return d.decode("utf-16-le", "replace")


def utf16z(d):
    s = utf16(d)
    return s.split("\x00", 1)[0] if "\x00" in s else s


class Key:
    def __init__(self, hive, off, path=""):
        d = hive.cell(off)
        if d[:2] != b"nk":
            raise RegError(f"нет nk @0x{off:x}")
        self.hive, self.off = hive, off
        (self.flags,) = struct.unpack("<H", d[2:4])
        (ft,) = struct.unpack("<Q", d[4:12])
        self.mtime = filetime(ft)
        (self.parent, self.n_sub, _nvsub, self.sub_off, _vsub, self.n_val,
         self.val_off) = struct.unpack("<IIIIIII", d[16:44])
        nlen, _clen = struct.unpack("<HH", d[72:76])
        raw = d[76:76 + nlen]
        self.name = raw.decode("latin-1") if self.flags & 0x20 else raw.decode("utf-16-le", "replace")
        self.path = path

    def subkeys(self):
        if not self.n_sub or self.sub_off in (0, 0xFFFFFFFF):
            return []
        offs = self.hive.list_offsets(self.sub_off, set())
        out = []
        for o in offs:
            try:
                k = Key(self.hive, o)
            except (RegError, struct.error, IndexError):
                continue
            k.path = f"{self.path}\\{k.name}" if self.path else k.name
            out.append(k)
        return out

    def values(self):
        if not self.n_val or self.val_off in (0, 0xFFFFFFFF):
            return []
        try:
            lst = self.hive.cell(self.val_off)
        except RegError:
            return []
        out = []
        for i in range(min(self.n_val, len(lst) // 4)):
            o = struct.unpack("<I", lst[i * 4:i * 4 + 4])[0]
            try:
                out.append(Value(self.hive, o))
            except (RegError, struct.error, IndexError):
                continue
        return out

    def subkey(self, name):
        low = name.lower()
        for k in self.subkeys():
            if k.name.lower() == low:
                return k
        return None

    def value(self, name):
        low = name.lower()
        for v in self.values():
            if v.name.lower() == low:
                return v
        return None


class Hive:
    def __init__(self, path):
        self.path = path
        self.f = open(path, "rb")
        size = os.path.getsize(path)
        if size < BASE + 32:
            raise RegError("файл меньше base block + hbin")
        self.mm = mmap.mmap(self.f.fileno(), 0, access=mmap.ACCESS_READ)
        b = self.mm[:BASE]
        if b[:4] != b"regf":
            raise RegError("нет сигнатуры regf")
        self.seq1, self.seq2 = struct.unpack("<II", b[4:12])
        self.mtime = filetime(struct.unpack("<Q", b[12:20])[0])
        self.major, self.minor = struct.unpack("<II", b[20:28])
        self.root_off, self.hbins_size = struct.unpack("<II", b[36:44])
        self.fname = b[48:112].decode("utf-16-le", "replace").split("\x00", 1)[0]
        x = 0
        for i in range(127):
            x ^= struct.unpack("<I", b[i * 4:i * 4 + 4])[0]
        if x == 0xFFFFFFFF:
            x = 0xFFFFFFFE
        elif x == 0:
            x = 1
        self.checksum_ok = x == struct.unpack("<I", b[508:512])[0]
        self.dirty = self.seq1 != self.seq2
        self.limit = min(size, BASE + self.hbins_size) if self.hbins_size else size

    def cell(self, off):
        p = BASE + off
        if off == 0xFFFFFFFF or p + 4 > self.limit:
            raise RegError(f"ячейка вне куста @0x{off:x}")
        (sz,) = struct.unpack("<i", self.mm[p:p + 4])
        n = abs(sz)
        if n < 8 or p + n > self.limit:
            raise RegError(f"битая ячейка @0x{off:x}")
        return self.mm[p + 4:p + n]

    def list_offsets(self, off, seen):
        if off in seen:
            return []
        seen.add(off)
        try:
            d = self.cell(off)
        except RegError:
            return []
        sig, n = d[:2], struct.unpack("<H", d[2:4])[0]
        out = []
        if sig in (b"lf", b"lh"):
            for i in range(n):
                out.append(struct.unpack("<I", d[4 + i * 8:8 + i * 8])[0])
        elif sig == b"li":
            for i in range(n):
                out.append(struct.unpack("<I", d[4 + i * 4:8 + i * 4])[0])
        elif sig == b"ri":
            for i in range(n):
                sub = struct.unpack("<I", d[4 + i * 4:8 + i * 4])[0]
                out += self.list_offsets(sub, seen)
        return out

    def root(self):
        return Key(self, self.root_off, "")

    def walk(self, max_keys=500000):
        """Обход в глубину: (ключ, [значения]); защита от петель."""
        stack, seen, n = [self.root()], set(), 0
        while stack and n < max_keys:
            k = stack.pop()
            if k.off in seen:
                continue
            seen.add(k.off)
            n += 1
            yield k
            subs = k.subkeys()
            stack.extend(reversed(subs))

    def open(self, path):
        k = self.root()
        for part in [p for p in re.split(r"[\\/]+", path) if p]:
            k2 = k.subkey(part)
            if k2 is None:
                return None
            k2.path = f"{k.path}\\{k2.name}" if k.path else k2.name
            k = k2
        return k

    def kind(self):
        names = {k.name.lower() for k in self.root().subkeys()}
        if {"select"} & names and any(n.startswith("controlset") for n in names):
            return "SYSTEM"
        if "sam" in names and len(names) <= 3:
            return "SAM"
        if {"policy"} & names and ("cache" in names or "rxact" in names):
            return "SECURITY"
        if {"microsoft", "classes"} <= names or ("microsoft" in names and "policies" in names
                                                 and "software" not in names):
            return "SOFTWARE"
        if "software" in names and ({"environment", "console", "control panel"} & names):
            return "NTUSER"
        if "local settings" in names:
            return "USRCLASS"
        if "root" in names:
            return "AMCACHE"
        if "software" in names:
            return "NTUSER"
        return "?"

    def free_cells(self):
        """Свободные ячейки (size > 0): тут лежат удалённые nk/vk."""
        pos = BASE
        while pos + 32 <= self.limit:
            if self.mm[pos:pos + 4] != b"hbin":
                pos += 4096
                continue
            (hsize,) = struct.unpack("<I", self.mm[pos + 8:pos + 12])
            if hsize < 4096:
                hsize = 4096
            c = pos + 32
            end = min(pos + hsize, self.limit)
            while c + 4 <= end:
                (sz,) = struct.unpack("<i", self.mm[c:c + 4])
                n = abs(sz)
                if n < 8 or n % 8:
                    break
                if sz > 0:
                    yield c - BASE, self.mm[c + 4:c + n]
                c += n
            pos += hsize

    def close(self):
        try:
            self.mm.close()
            self.f.close()
        except Exception:
            pass


def open_hive(path):
    err = adminlib.open_error(path)
    if err:
        raise RegError(err)
    return Hive(path)


ROT13 = codecs.getencoder("rot13")


def value_flags(key, v):
    texts = v.strings()
    if "userassist" in key.path.lower():
        texts.append(ROT13(v.name)[0])
    texts.append(v.name)
    found = adminlib.flags_in(*texts)
    t = v.text()
    raw = adminlib.try_b64(t) if t and len(t) >= 12 else None
    r = adminlib.readable(raw) if raw else None
    if r:
        found += [f for f in adminlib.flags_in(r) if f not in found]
    for _how, dec in adminlib.decode_inline(t or ""):
        found += [f for f in adminlib.flags_in(dec) if f not in found]
    return found


def cmd_reg(args):
    try:
        h = open_hive(args.path)
    except RegError as e:
        print(f"[-] {e}")
        return 2
    try:
        print(f"=== куст {args.path} ===")
        print(f"[+] имя в base block: {h.fname or '—'}, regf {h.major}.{h.minor}, "
              f"изменён {fmt_t(h.mtime)}, checksum {'ok' if h.checksum_ok else 'НЕ СХОДИТСЯ'}")
        if h.dirty:
            print(f"[!] куст «грязный» (seq {h.seq1} != {h.seq2}): последние изменения в .LOG1/.LOG2 "
                  "не применены — yarp/regipy/Registry Explorer их накатят")
        kind = h.kind()
        print(f"[+] тип куста: {kind}")
        if args.key:
            k = h.open(args.key)
            if not k:
                print(f"[-] ключа «{args.key}» нет")
                return 1
            print_key(k, values=True, subkeys=True)
            for v in k.values():
                for f in value_flags(k, v):
                    adminlib.print_flags([f], f"{k.path}\\{v.name}")
            return 0
        nkeys = nvals = 0
        flags = []
        hits = []
        needle = (args.search or "").lower()
        lines = 0
        for k in h.walk():
            nkeys += 1
            vals = k.values()
            nvals += len(vals)
            for f in adminlib.flags_in(k.name):
                flags.append((f, k.path))
            if needle and needle in k.path.lower():
                hits.append(f"[key] {k.path}  ({fmt_t(k.mtime)})")
            if args.dump and lines < args.max:
                print(f"[{fmt_t(k.mtime)}] {k.path or '(root)'}")
                lines += 1
            for v in vals:
                for f in value_flags(k, v):
                    flags.append((f, f"{k.path}\\{v.name}"))
                if needle:
                    blob = " ".join([v.name] + v.strings()).lower()
                    if needle in blob:
                        hits.append(f"[val] {k.path}\\{v.name} = {v.text()[:200]}")
                if args.dump and lines < args.max:
                    print(f"      {v.name} [{REG_TYPES.get(v.type, v.type)}] = {v.text()[:200]}")
                    lines += 1
        print(f"[+] ключей {nkeys}, значений {nvals}")
        if kind == "SAM":
            sam_users(h)
        if needle:
            print(f"[+] поиск «{args.search}»: {len(hits)}")
            for x in hits[:args.max]:
                print("    " + x)
        live = {f for f, _ in flags}
        extra = raw_flags(h, live)   # флаги в slack/удалённых ячейках
        if args.deleted:
            deleted(h, live)
        for f, where in dict.fromkeys(flags):
            adminlib.print_flags([f], where)
        for f in extra:
            adminlib.print_flags([f], "сырые байты куста: свободные/удалённые ячейки (--deleted)")
        if kind in ("SYSTEM",) and not args.search and not args.dump:
            print("[i] службы: python admin/win_admin.py services", args.path)
        if kind in ("SOFTWARE", "NTUSER") and not args.search and not args.dump:
            print("[i] автозапуск: python admin/win_admin.py run", args.path)
        return 0
    finally:
        h.close()


def raw_flags(h, live):
    """Флаги в сырых байтах куста (ASCII и UTF-16LE), кусками по 16 МБ."""
    out, pos, step = [], 0, 16 << 20
    while pos < h.limit:
        chunk = bytes(h.mm[pos:min(h.limit, pos + step + 512)])
        found = common.find_flags(chunk)
        if b"{\x00" in chunk:
            found += common.find_flags(re.sub(rb"([\x20-\x7e])\x00", rb"\1", chunk))
        out += [f for f in found if f not in live and f not in out]
        pos += step
    return out


def print_key(k, values=True, subkeys=True):
    print(f"[+] {k.path or '(root)'}  изменён {fmt_t(k.mtime)}")
    if subkeys:
        for s in k.subkeys():
            print(f"    [key] {s.name}  ({fmt_t(s.mtime)})")
    if values:
        for v in k.values():
            print(f"    {v.name} [{REG_TYPES.get(v.type, v.type)}] = {v.text()[:300]}")


def sam_users(h):
    names = h.open("SAM\\Domains\\Account\\Users\\Names")
    if not names:
        return
    print("[+] пользователи SAM (RID из типа значения по умолчанию):")
    for k in names.subkeys():
        rid = None
        for v in k.values():
            rid = v.type
        print(f"    {k.name:24s} RID={rid}  ({fmt_t(k.mtime)})")
    print("[i] хеши: secretsdump.py -sam SAM -system SYSTEM LOCAL  (нужен bootkey из SYSTEM)")


def deleted(h, live):
    """Удалённые nk/vk в свободных ячейках."""
    found = 0
    for off, d in h.free_cells():
        for sig in (b"nk", b"vk"):
            i = d.find(sig)
            while i != -1 and found < 200:
                if i % 8:   # старые ячейки внутри свободной лежат по 8-байтной сетке
                    i = d.find(sig, i + 1)
                    continue
                try:
                    if sig == b"vk":
                        nlen, size, doff, vtype, flags = struct.unpack("<HIIIH", d[i + 2:i + 18])
                        if vtype > 11 or nlen > 256:
                            raise ValueError
                        name = d[i + 20:i + 20 + nlen]
                        name = (name.decode("latin-1") if flags & 1
                                else name.decode("utf-16-le", "replace")) or "(default)"
                        if size & 0x80000000:
                            data = struct.pack("<I", doff)[:size & 0x7FFFFFFF]
                        else:
                            try:
                                data = bytes(h.cell(doff)[:min(size, 4096)])
                            except RegError:
                                data = b""
                        txt = adminlib.readable(data) or data[:48].hex()
                        print(f"[!] удалённое значение @0x{off:x}: {name} "
                              f"[{REG_TYPES.get(vtype, vtype)}] = {txt[:200]!r}")
                        for f in adminlib.flags_in(txt, data):
                            if f not in live:
                                adminlib.print_flags([f], f"удалённое значение {name}")
                                live.add(f)
                    else:
                        (ft,) = struct.unpack("<Q", d[i + 4:i + 12])
                        nlen = struct.unpack("<H", d[i + 72:i + 74])[0]
                        flags = struct.unpack("<H", d[i + 2:i + 4])[0]
                        if not 0 < nlen <= 256:
                            raise ValueError
                        raw = d[i + 76:i + 76 + nlen]
                        name = raw.decode("latin-1") if flags & 0x20 else raw.decode("utf-16-le", "replace")
                        if common.printable_ratio(name) < 0.9:
                            raise ValueError
                        print(f"[!] удалённый ключ @0x{off:x}: {name}  ({fmt_t(filetime(ft))})")
                    found += 1
                except (ValueError, struct.error):
                    pass
                i = d.find(sig, i + 2)
    if not found:
        print("[-] удалённых nk/vk в свободных ячейках нет")


# ---------------------------------------------------------------- службы

START = {0: "boot", 1: "system", 2: "auto", 3: "manual", 4: "disabled"}
SVC_TYPE = {1: "kernel-driver", 2: "fs-driver", 16: "own-process", 32: "share-process",
            0x50: "user-own", 0x60: "user-share", 0x110: "own+interactive"}
SUSP_PATH = re.compile(r"(?i)\\(?:temp|tmp|appdata|users\\public|programdata|downloads|"
                       r"\$recycle\.bin|perflogs)\\|powershell|cmd(?:\.exe)?\s+/[ck]|mshta|"
                       r"rundll32|regsvr32|wscript|cscript|-enc|https?://|\\\\[\w.]+\\|"
                       r"certutil|bitsadmin|\.(?:bat|ps1|vbs|js|hta)\b")
SYS_PATH = re.compile(r"(?i)^\"?(?:\\systemroot\\|%systemroot%|%windir%|system32\\|"
                      r"\\\?\?\\c:\\windows\\|c:\\windows\\|\"?c:\\program files)")


def control_sets(h):
    sel = h.open("Select")
    cur = None
    if sel:
        v = sel.value("Current")
        if v and len(v.data) >= 4:
            cur = struct.unpack("<I", v.data[:4])[0]
    sets = [k for k in h.root().subkeys() if k.name.lower().startswith("controlset")]
    if cur is not None:
        want = f"controlset{cur:03d}"
        sets.sort(key=lambda k: k.name.lower() != want)
    return sets, cur


def svc_info(k):
    def val(name):
        v = k.value(name)
        return v.text() if v else ""

    def num(name):
        v = k.value(name)
        if v and len(v.data) >= 4:
            return struct.unpack("<I", v.data[:4])[0]
        return None

    params = k.subkey("Parameters")
    dll = ""
    if params:
        v = params.value("ServiceDll")
        dll = v.text() if v else ""
    return {"name": k.name, "image": val("ImagePath"), "start": num("Start"), "type": num("Type"),
            "user": val("ObjectName"), "display": val("DisplayName"),
            "desc": val("Description"), "dll": dll, "failure": val("FailureCommand"),
            "mtime": k.mtime, "key": k}


def cmd_services(args):
    try:
        h = open_hive(args.path)
    except RegError as e:
        print(f"[-] {e}")
        return 2
    try:
        sets, cur = control_sets(h)
        if not sets:
            print(f"[-] в кусте нет ControlSet00x (тип {h.kind()}) — нужен SYSTEM")
            return 1
        cs = sets[0]
        print(f"=== службы {args.path}: {cs.name} (Select\\Current={cur}) ===")
        svcs = cs.subkey("Services")
        if not svcs:
            print("[-] нет ключа Services")
            return 1
        items = [svc_info(k) for k in svcs.subkeys()]
        susp = []
        for s in items:
            blob = " ".join([s["image"], s["dll"], s["failure"]])
            why = []
            if SUSP_PATH.search(blob):
                why.append("подозрительный путь/команда")
            if s["image"] and not SYS_PATH.search(s["image"].strip()) and s["type"] in (16, 32, 0x110):
                why.append("не из Windows/Program Files")
            if s["type"] in (1, 2) and s["image"] and "drivers" not in s["image"].lower():
                why.append("драйвер не из drivers\\")
            if s["failure"]:
                why.append("FailureCommand")
            if why:
                susp.append((s, why))
        print(f"[+] служб: {len(items)}, подозрительных: {len(susp)}")
        flags = []
        for s, why in susp:
            print_svc(s, "[!]", why)
            flags += svc_flags(s)
        recent = sorted([s for s in items if s["mtime"]], key=lambda s: s["mtime"], reverse=True)
        print(f"[+] недавно изменённые ключи служб (топ {args.top}):")
        for s in recent[:args.top]:
            print(f"    {fmt_t(s['mtime'])}  {s['name']:28s} {START.get(s['start'], s['start'])}"
                  f"  {s['image'][:120]}")
        if args.all:
            for s in items:
                print_svc(s, "   ", [])
        for s in items:
            flags += [f for f in svc_flags(s) if f not in flags]
        adminlib.print_flags(flags, "службы")
        return 0
    finally:
        h.close()


def svc_flags(s):
    out = []
    for k in s["key"].values():
        out += [f for f in value_flags(s["key"], k) if f not in out]
    return out


def print_svc(s, mark, why):
    print(f"{mark} {s['name']}  [{START.get(s['start'], s['start'])}, "
          f"{SVC_TYPE.get(s['type'], s['type'])}]  ключ изменён {fmt_t(s['mtime'])}"
          + (f"   ← {', '.join(why)}" if why else ""))
    for label, key in (("ImagePath", "image"), ("ServiceDll", "dll"), ("ObjectName", "user"),
                       ("DisplayName", "display"), ("Description", "desc"),
                       ("FailureCommand", "failure")):
        if s[key]:
            print(f"      {label}: {s[key][:300]}")
    for how, text in adminlib.decode_inline(" ".join([s["image"], s["dll"], s["failure"]])):
        print(f"      {how} → {text[:300]!r}")


# ---------------------------------------------------------------- автозапуск

RUN_KEYS = [
    r"Microsoft\Windows\CurrentVersion\Run",
    r"Microsoft\Windows\CurrentVersion\RunOnce",
    r"Microsoft\Windows\CurrentVersion\RunOnceEx",
    r"Microsoft\Windows\CurrentVersion\RunServices",
    r"Microsoft\Windows\CurrentVersion\RunServicesOnce",
    r"Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"Microsoft\Windows NT\CurrentVersion\Windows",
    r"Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
    r"Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
    r"Microsoft\Active Setup\Installed Components",
]
WATCH_VALUES = {"userinit": "c:\\windows\\system32\\userinit.exe,", "shell": "explorer.exe",
                "appinit_dlls": "", "load": "", "run": ""}


def cmd_run(args):
    rc = 0
    for path in args.paths:
        try:
            h = open_hive(path)
        except RegError as e:
            print(f"[-] {e}")
            rc = 2
            continue
        try:
            kind = h.kind()
            print(f"=== автозапуск {path} ({kind}) ===")
            flags, n = [], 0
            prefixes = ["", "Software\\"]
            for rel in RUN_KEYS:
                for pre in prefixes:
                    k = h.open(pre + rel)
                    if not k:
                        continue
                    vals = k.values()
                    if rel.endswith(("Winlogon", "NT\\CurrentVersion\\Windows")):
                        vals = [v for v in vals if v.name.lower() in WATCH_VALUES]
                    if rel.endswith("Shell Folders"):
                        vals = [v for v in vals if v.name.lower() == "startup"]
                    if not vals and "Installed Components" not in rel:
                        continue
                    print(f"[+] {k.path}  (изменён {fmt_t(k.mtime)})")
                    for v in vals:
                        n += 1
                        t = v.text()
                        mark = "[!]" if SUSP_PATH.search(t) else "   "
                        lv = v.name.lower()
                        if lv in WATCH_VALUES and WATCH_VALUES[lv] and \
                                t.strip().lower() != WATCH_VALUES[lv]:
                            mark = "[!!]"
                        if lv in ("appinit_dlls", "load", "run") and t.strip():
                            mark = "[!]"
                        print(f"{mark} {v.name} = {t[:300]}")
                        for how, text in adminlib.decode_inline(t):
                            print(f"      {how} → {text[:300]!r}")
                        flags += [f for f in value_flags(k, v) if f not in flags]
                    if "Installed Components" in rel:
                        for sub in k.subkeys()[:400]:
                            sp = sub.value("StubPath")
                            if sp and SUSP_PATH.search(sp.text()):
                                print(f"[!] Active Setup {sub.name}: StubPath = {sp.text()[:300]}")
            ifeo = h.open("Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options")
            if ifeo:
                for sub in ifeo.subkeys():
                    dbg = sub.value("Debugger")
                    gf = sub.value("GlobalFlag")
                    if dbg:
                        n += 1
                        print(f"[!!] IFEO {sub.name}: Debugger = {dbg.text()[:300]}")
                    if gf and len(gf.data) >= 4 and struct.unpack("<I", gf.data[:4])[0] & 0x200:
                        print(f"[!] IFEO {sub.name}: GlobalFlag & 0x200 (SilentProcessExit-мониторинг)")
            for rel in ("Environment",):
                k = h.open(rel)
                if k:
                    v = k.value("UserInitMprLogonScript")
                    if v:
                        n += 1
                        print(f"[!!] {k.path}\\UserInitMprLogonScript = {v.text()[:300]}")
            sets, _cur = control_sets(h)
            if sets:
                sm = sets[0].subkey("Control")
                sm = sm.subkey("Session Manager") if sm else None
                v = sm.value("BootExecute") if sm else None
                if v and v.text().strip().lower() != "autocheck autochk *":
                    print(f"[!!] BootExecute = {v.text()}")
                print("[i] службы — отдельно: python admin/win_admin.py services", path)
            if not n:
                print("[-] Run/RunOnce/Winlogon/IFEO пусты или куст не тот (нужны SOFTWARE/NTUSER)")
            adminlib.print_flags(flags, "автозапуск")
        finally:
            h.close()
    return rc


# ---------------------------------------------------------------- задачи

def _local(tag):
    return tag.rsplit("}", 1)[-1]


def parse_task(raw):
    import xml.etree.ElementTree as ET
    text = adminlib.decode_text(raw)
    text = re.sub(r"^\s*<\?xml[^>]*\?>", "", text)
    root = ET.fromstring(text)
    info = {"uri": "", "author": "", "date": "", "desc": "", "user": "", "runlevel": "",
            "hidden": False, "enabled": True, "triggers": [], "actions": []}
    for el in root.iter():
        t = _local(el.tag)
        txt = (el.text or "").strip()
        if t == "URI":
            info["uri"] = txt
        elif t == "Author":
            info["author"] = txt
        elif t == "Date" and not info["date"]:
            info["date"] = txt
        elif t == "Description":
            info["desc"] = txt
        elif t in ("UserId", "GroupId") and not info["user"]:
            info["user"] = txt
        elif t == "RunLevel":
            info["runlevel"] = txt
        elif t == "Hidden":
            info["hidden"] = txt.lower() == "true"
        elif t.endswith("Trigger"):
            desc = t
            for c in el.iter():
                ct = _local(c.tag)
                if ct in ("StartBoundary", "Interval", "Delay", "UserId", "Subscription",
                          "DaysInterval") and (c.text or "").strip():
                    desc += f" {ct}={c.text.strip()[:80]}"
            info["triggers"].append(desc)
        elif t == "Exec":
            cmd = args = wd = ""
            for c in el:
                ct = _local(c.tag)
                if ct == "Command":
                    cmd = (c.text or "").strip()
                elif ct == "Arguments":
                    args = (c.text or "").strip()
                elif ct == "WorkingDirectory":
                    wd = (c.text or "").strip()
            info["actions"].append(("exec", cmd, args, wd))
        elif t == "ComHandler":
            cls = ""
            for c in el:
                if _local(c.tag) == "ClassId":
                    cls = (c.text or "").strip()
            info["actions"].append(("com", cls, "", ""))
    return info, text


def task_files(path):
    if os.path.isfile(path):
        return [path]
    out = []
    for root, dirs, files in os.walk(path):
        for fn in files:
            fp = os.path.join(root, fn)
            try:
                if os.path.getsize(fp) > 2 << 20:
                    continue
            except OSError:
                continue
            k, _d = adminlib.detect(fp)
            if k == "TASKXML":
                out.append(fp)
            elif fn.lower().endswith(".job"):
                print(f"[i] {fp}: старый формат .job (бинарный) — strings/flags только")
                out.append(fp)
    return sorted(out)


def cmd_tasks(args):
    files = task_files(args.path)
    if not files:
        print("[-] XML задач планировщика не найдено (ищу <Task xmlns=…/2004/02/mit/task>)")
        return 1
    flags = []
    print(f"=== задачи планировщика: {len(files)} ===")
    for fp in files:
        try:
            with open(fp, "rb") as f:
                raw = f.read(2 << 20)
        except OSError as e:
            print(f"[-] {fp}: {e}")
            continue
        if fp.lower().endswith(".job"):
            found = adminlib.flags_in(raw, raw.decode("utf-16-le", "ignore"))
            adminlib.print_flags(found, fp)
            continue
        try:
            info, text = parse_task(raw)
        except Exception as e:  # битый XML не должен ронять разбор остальных
            print(f"[-] {fp}: XML не разобрался ({e})")
            found = adminlib.flags_in(adminlib.decode_text(raw))
            adminlib.print_flags(found, fp)
            continue
        cmds = " ".join(f"{a[1]} {a[2]}" for a in info["actions"])
        tags, creds, decoded = adminlib.analyze_command(cmds)
        susp = bool(tags) or bool(SUSP_PATH.search(cmds)) or info["hidden"]
        mark = "[!]" if susp else "[+]"
        print(f"{mark} {info['uri'] or os.path.basename(fp)}  ({fp})")
        if info["author"] or info["date"]:
            print(f"      автор: {info['author'] or '—'}  дата: {info['date'] or '—'}")
        if info["desc"]:
            print(f"      описание: {info['desc'][:200]}")
        print(f"      от: {info['user'] or '—'} {info['runlevel']}"
              + ("  [Hidden]" if info["hidden"] else ""))
        for tr in info["triggers"]:
            print(f"      триггер: {tr}")
        for kind, cmd, a, wd in info["actions"]:
            if kind == "exec":
                print(f"      exec: {cmd} {a}".rstrip() + (f"   (cwd {wd})" if wd else ""))
            else:
                print(f"      COM-обработчик: {cmd}")
        if tags:
            print(f"      теги: {', '.join(tags)}")
        for how, t in decoded:
            print(f"      {how} → {t[:300]!r}")
        for k, v in creds:
            print(f"      кред ({k}): {v}")
        found = adminlib.flags_in(text, *[t for _h, t in decoded])
        flags += [f for f in found if f not in flags]
    adminlib.print_flags(flags, "задачи")
    return 0


# ---------------------------------------------------------------- PowerShell

def cmd_pshistory(args):
    import log_analyze
    paths = []
    if os.path.isdir(args.path):
        for root, dirs, files in os.walk(args.path):
            for fn in files:
                if fn.lower() == "consolehost_history.txt":
                    paths.append(os.path.join(root, fn))
    else:
        err = adminlib.open_error(args.path)
        if err:
            print(f"[-] {err}")
            return 2
        paths = [args.path]
    if not paths:
        print("[-] ConsoleHost_history.txt не найден "
              "(обычно Users\\<u>\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine)")
        return 1
    ns = argparse.Namespace(top=args.top, all=args.all, timeline=False)
    rep = log_analyze.Report(ns)
    for p in paths:
        lines = adminlib.read_text(p).splitlines()
        log_analyze.analyze_history(log_analyze.history_records(lines), p, rep, "PowerShell")
    if rep.creds:
        print("[!] креды/секреты:")
        for src, kind, val in rep.creds:
            print(f"    {src}: {kind}: {val}")
    for f, where in rep.flags:
        adminlib.print_flags([f], where)
    return 0


# ---------------------------------------------------------------- авто

HIVE_NAMES = {"system", "software", "sam", "security", "ntuser.dat", "usrclass.dat",
              "amcache.hve", "default"}


def cmd_auto(args):
    path = args.path
    if os.path.isfile(path):
        kind, _d = adminlib.detect(path)
        if kind == "REGF":
            return auto_hive(path, args)
        if kind == "TASKXML":
            return cmd_tasks(args)
        if kind == "PSHISTORY" or os.path.basename(path).lower() == "consolehost_history.txt":
            return cmd_pshistory(args)
        print(f"[-] {path}: не куст regf, не XML задачи и не PS-история "
              f"(тип по данным: {kind or 'неизвестен'}); явно: win_admin.py pshistory FILE")
        return 1
    if not os.path.isdir(path):
        print(f"[-] нет такого пути: {path}")
        return 2
    hives, tasks, ps = [], False, []
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in (".git", "__pycache__")]
        for fn in files:
            fp = os.path.join(root, fn)
            if fn.lower() == "consolehost_history.txt":
                ps.append(fp)
                continue
            if adminlib.read_head(fp, 4) == b"regf":
                hives.append(fp)
            elif not tasks and adminlib.detect(fp)[0] == "TASKXML":
                tasks = True
    print(f"=== {path}: кустов {len(hives)}, PS-история {len(ps)}, задачи {'да' if tasks else 'нет'} ===")
    for hp in hives:
        auto_hive(hp, args)
    if tasks:
        cmd_tasks(args)
    for p in ps:
        a2 = argparse.Namespace(**{**vars(args), "path": p})
        cmd_pshistory(a2)
    if not (hives or tasks or ps):
        print("[-] кустов/задач/PS-истории нет; строки: python toolbox.py win", path)
    return 0


def auto_hive(path, args):
    a = argparse.Namespace(**{**vars(args), "path": path, "key": None, "search": None,
                              "dump": False, "deleted": True, "max": 200})
    cmd_reg(a)
    try:
        h = open_hive(path)
        kind = h.kind()
        h.close()
    except RegError:
        return 1
    if kind == "SYSTEM":
        cmd_services(argparse.Namespace(**{**vars(args), "path": path, "all": False}))
        cmd_run(argparse.Namespace(**{**vars(args), "paths": [path]}))
    elif kind in ("SOFTWARE", "NTUSER"):
        cmd_run(argparse.Namespace(**{**vars(args), "paths": [path]}))
    return 0


def main():
    cmds = ("reg", "services", "run", "tasks", "pshistory", "auto")
    argv = sys.argv[1:]
    if argv and argv[0] not in cmds and not argv[0].startswith("-"):
        argv = ["auto"] + argv
    ap = argparse.ArgumentParser(description="Windows оффлайн: реестр, службы, автозапуск, задачи, PS")
    common.add_flag_args(ap)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("reg", help="куст regf: сводка, ключ, поиск, дамп, удалённое")
    p.add_argument("path")
    p.add_argument("--key", help="путь ключа от корня куста")
    p.add_argument("--search", help="подстрока в путях/именах/данных")
    p.add_argument("--dump", action="store_true")
    p.add_argument("--deleted", action="store_true", help="nk/vk в свободных ячейках")
    p.add_argument("--max", type=int, default=2000)
    p = sub.add_parser("services", help="службы из SYSTEM")
    p.add_argument("path")
    p.add_argument("--all", action="store_true")
    p.add_argument("--top", type=int, default=10)
    p = sub.add_parser("run", help="Run/RunOnce/Winlogon/IFEO/AppInit")
    p.add_argument("paths", nargs="+")
    p = sub.add_parser("tasks", help="XML задач планировщика (файл или папка)")
    p.add_argument("path")
    p = sub.add_parser("pshistory", help="ConsoleHost_history.txt")
    p.add_argument("path")
    p.add_argument("--all", action="store_true")
    p.add_argument("--top", type=int, default=10)
    p = sub.add_parser("auto", help="сам определить: кусты/задачи/PS-история")
    p.add_argument("path")
    p.add_argument("--top", type=int, default=10)
    p.add_argument("--all", action="store_true")
    args = ap.parse_args(argv)
    common.apply_flag_args(args)
    try:
        fn = {"reg": cmd_reg, "services": cmd_services, "run": cmd_run, "tasks": cmd_tasks,
              "pshistory": cmd_pshistory, "auto": cmd_auto}[args.cmd]
        if args.cmd != "run" and not os.path.exists(args.path):
            print(f"[-] нет такого пути: {args.path}")
            sys.exit(2)
        rc = fn(args)
    except (RegError, OSError, ValueError) as e:
        print(f"[-] {e}")
        rc = 1
    sys.exit(rc or 0)


if __name__ == "__main__":
    main()
