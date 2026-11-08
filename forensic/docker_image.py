#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
docker_image.py — форензика Docker-образа без Docker.

  python docker_image.py image.tar
  python docker_image.py image.tar --out fs
  python docker_image.py image.tar --json
  python docker_image.py Dockerfile --dockerfile

Понимает `docker save` (tar/tar.gz), отдельный layer.tar и Dockerfile.
Показывает:
  * config: Env, Cmd, Entrypoint, User, Labels;
  * историю сборки (created_by) — там часто пароли/URL;
  * слои и их размеры;
  * удалённые/перезаписанные файлы (whiteouts) — секреты, которые «стёрли»;
  * секреты и флаги в env/history/файлах;
  * предупреждения по Dockerfile.
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
import io
import json
import os
import re
import sys
import tarfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import common  # noqa: E402

SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|aws_secret|auth)\b\s*[:=]\s*['\"]?([^\s'\"]{4,120})")
FLAG_RE = common.FLAG_RE
MAX_TOTAL = 200 * 1024 * 1024


def safe_path(root: str, name: str):
    name = name.lstrip("./")
    p = os.path.normpath(os.path.join(root, name))
    if not p.startswith(os.path.abspath(root) + os.sep) and p != os.path.abspath(root):
        return None
    return p


def scan_text(text, source, findings, flags):
    for m in SECRET_RE.finditer(text):
        findings.append({"source": source, "kind": m.group(1), "value": m.group(2)[:200]})
    for f in common.find_flags(text.encode("utf-8", "replace")):
        flags.add(f)


def apply_layers(tf, layer_paths, findings, flags, max_total=MAX_TOTAL):
    fs = {}
    deleted = []
    replaced = []
    total = 0
    for lp in layer_paths:
        try:
            raw = tf.extractfile(lp).read()
            lt = tarfile.open(fileobj=io.BytesIO(raw), mode="r:*")
        except Exception as e:
            print(f"[!] слой {lp}: {e}")
            continue
        for m in lt.getmembers():
            if not m.isfile():
                continue
            name = m.name.lstrip("./")
            base = os.path.basename(name)
            if base.startswith(".wh."):
                if base == ".wh..wh..opq":
                    prefix = os.path.dirname(name).replace(os.sep, "/")
                    for p in list(fs):
                        if p == prefix or p.startswith(prefix + "/"):
                            deleted.append((p, fs.pop(p)))
                else:
                    target = os.path.join(os.path.dirname(name), base[4:]).replace(os.sep, "/")
                    if target in fs:
                        deleted.append((target, fs.pop(target)))
                continue
            try:
                content = lt.extractfile(m).read()
            except Exception:
                continue
            if total + len(content) > max_total:
                continue
            total += len(content)
            if name in fs:
                replaced.append((name, fs[name]))
            fs[name] = content

    for name, content in deleted:
        findings.append({"source": f"deleted:{name}", "kind": "deleted-file",
                         "value": f"{len(content)} b"})
        scan_text(content.decode("utf-8", "replace"), f"deleted:{name}", findings, flags)
        for f in common.find_flags(content):
            flags.add(f)
    for name, content in replaced:
        scan_text(content.decode("utf-8", "replace"), f"replaced:{name}", findings, flags)
        for f in common.find_flags(content):
            flags.add(f)
    return fs, deleted, replaced, total


def audit_dockerfile(path):
    text = open(path, "r", encoding="utf-8", errors="replace").read()
    print(f"[+] Dockerfile: {path}")
    warns = []
    for i, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        up = s.upper()
        if up.startswith("FROM ") and (":LATEST" in up or ":" not in s.split()[1]):
            warns.append((i, "FROM без фиксированного тега (latest)"))
        if up.startswith("ADD ") and ("http://" in s or "https://" in s):
            warns.append((i, "ADD по URL — может тянуть чужое"))
        if "| sh" in s or "| bash" in s:
            warns.append((i, "curl/wget | sh"))
        if up.startswith(("ARG ", "ENV ")) and re.search(r"(?i)(pass|secret|token|key)", s):
            warns.append((i, "секрет в ARG/ENV (попадёт в image history)"))
        if up.startswith("USER ROOT") or (up.startswith("USER ") and s.split()[1] == "0"):
            warns.append((i, "явный root"))
        if "CHMOD 777" in up:
            warns.append((i, "chmod 777"))
        if up.startswith("COPY . .") or up.startswith("ADD . ."):
            warns.append((i, "копируется всё подряд (могут попасть .git/.env)"))
        for m in SECRET_RE.finditer(s):
            warns.append((i, f"секрет: {m.group(1)}={m.group(2)[:60]}"))
    if not any(x.upper().startswith("USER ") for x in text.splitlines()):
        warns.append((0, "нет USER — контейнер работает от root"))
    for line, msg in warns:
        print(f"  ! строка {line}: {msg}")
    if not warns:
        print("  явных проблем не видно")
    for f in common.find_flags(text.encode()):
        print("  !!! ФЛАГ:", f)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--out")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--dockerfile", action="store_true")
    ap.add_argument("--max-size", type=int, default=200)
    ap.add_argument("--list-layers", action="store_true")
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)

    if args.dockerfile or os.path.basename(args.file).lower().startswith("dockerfile"):
        audit_dockerfile(args.file)
        return

    if not tarfile.is_tarfile(args.file):
        print("[-] это не tar и не Dockerfile")
        return

    findings, flags = [], set()
    report = {"file": args.file, "config": {}, "layers": [], "deleted": [],
              "replaced": [], "findings": [], "flags": []}
    tf = tarfile.open(args.file, "r:*")
    names = tf.getnames()

    manifest = None
    if "manifest.json" in names:
        try:
            manifest = json.load(tf.extractfile("manifest.json"))
        except Exception:
            manifest = None

    if manifest:
        entry = manifest[0]
        cfg_name = entry.get("Config")
        if cfg_name:
            try:
                cfg = json.load(tf.extractfile(cfg_name))
            except Exception:
                cfg = {}
            c = cfg.get("config", {})
            report["config"] = {
                "Env": c.get("Env", []),
                "Cmd": c.get("Cmd"),
                "Entrypoint": c.get("Entrypoint"),
                "User": c.get("User"),
                "Labels": c.get("Labels", {}),
            }
            print("[+] config:")
            for e in c.get("Env", []):
                print("   env:", e)
                scan_text(e, "env", findings, flags)
            for e in c.get("Cmd") or []:
                scan_text(str(e), "cmd", findings, flags)
            for h in cfg.get("history", []):
                cb = h.get("created_by", "")
                if cb:
                    scan_text(cb, "history", findings, flags)
        layers = entry.get("Layers", [])
    else:
        # отдельный layer.tar или простой tar
        layers = [n for n in names if n.endswith(".tar")] or []
        if not layers:
            layers = [None]

    report["layers"] = layers
    print(f"[+] слоёв: {len(layers)}")

    if layers and layers[0] is None:
        # файлы прямо в tar = один слой
        fs = {}
        total = 0
        for m in tf.getmembers():
            if m.isfile():
                name = m.name.lstrip("./")
                content = tf.extractfile(m).read()
                if total + len(content) <= args.max_size * 1024 * 1024:
                    fs[name] = content
                    total += len(content)
                    scan_text(content.decode("utf-8", "replace"), name, findings, flags)
        deleted, replaced = [], []
    else:
        fs, deleted, replaced, total = apply_layers(
            tf, layers, findings, flags, args.max_size * 1024 * 1024)

    report["deleted"] = [n for n, _ in deleted]
    report["replaced"] = [n for n, _ in replaced]
    print(f"[+] файлов в итоговой ФС: {len(fs)}  ({total//1024} KB)")
    if deleted:
        print(f"[+] удалено/скрыто whiteout: {len(deleted)}")
        for n, c in deleted[:20]:
            print(f"   - {n} ({len(c)} b)")
    if replaced:
        print(f"[+] перезаписано: {len(replaced)}")
        for n, _ in replaced[:20]:
            print(f"   ~ {n}")

    # финальные файлы тоже сканируем
    for name, content in fs.items():
        scan_text(content.decode("utf-8", "replace"), f"file:{name}", findings, flags)

    for f in common.find_flags(open(args.file, "rb").read()):
        flags.add(f)

    print(f"\n[+] секретов/находок: {len(findings)}")
    for x in findings[:30]:
        print(f"   {x['source']}: {x['kind']}={x['value']}")
    if flags:
        print("\n=== ФЛАГИ ===")
        for f in sorted(flags):
            print(" !!!", f)

    if args.out:
        os.makedirs(args.out, exist_ok=True)
        for name, content in fs.items():
            p = safe_path(args.out, name)
            if not p:
                continue
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "wb").write(content)
        print(f"\n[+] ФС распакована: {args.out}")

    report["findings"] = findings
    report["flags"] = sorted(flags)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2, default=str))


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] не могу открыть: {getattr(e, 'filename', None) or e}")
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        print("\n[-] прервано")
