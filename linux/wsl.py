#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wsl.py — запуск ELF/скриптов в WSL-дистрибутиве (Arch) с Windows.

Зачем: на Windows ELF не запускается, а статический дизасм не показывает
поведение. Здесь бинарь копируется внутрь Linux, получает +x и запускается
с нормальной libc, gdb и pwntools.

  python linux/wsl.py info
  python linux/wsl.py run ./chall
  python linux/wsl.py run ./chall -- --help
  python linux/wsl.py run ./chall --dir          # вместе с соседними libc/*.so
  python linux/wsl.py sh "checksec --file=~/inbox/chall"
  python linux/wsl.py inbox                      # что уже перенесено
  python linux/wsl.py which gdb python3
  python linux/wsl.py install [--yes]

Дистрибутив: env WSL_DISTRO (по умолчанию archlinux).

Важно: сложный shell-скрипт нельзя передавать аргументом `bash -lc` — wsl.exe
пересобирает командную строку и раскрывает `$VAR`. Поэтому скрипты пишутся
в файл через stdin и запускаются по пути.
"""
from __future__ import annotations

# Windows: консоль/pipe не должны падать на Unicode (—, →, «»).
try:
    import sys as _sys
    for _stream in (_sys.stdout, _sys.stderr):
        _stream.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import argparse
import hashlib
import os
import shlex
import subprocess
import sys

DISTRO = os.environ.get("WSL_DISTRO", "archlinux")
REMOTE_TIMEOUT = 600
MAX_COPY = 256 * 1024 * 1024

PROBES = ("python3", "gdb", "checksec", "r2", "pwntools", "ghidra", "binwalk",
          "qemu-x86_64", "qemu-aarch64", "gcc", "hashcat", "john", "nmap",
          "sqlmap", "z3", "sage")
PKG_HINT = {
    "python3": "python", "gdb": "gdb", "checksec": "checksec (AUR)",
    "r2": "radare2", "pwntools": "pipx install pwntools",
    "ghidra": "ghidra (AUR)", "binwalk": "binwalk",
    "qemu-x86_64": "qemu-user", "qemu-aarch64": "qemu-user",
    "gcc": "gcc", "hashcat": "hashcat", "john": "john", "nmap": "nmap",
    "sqlmap": "sqlmap", "z3": "python-z3", "sage": "sagemath (AUR, тяжёлый)",
}


def wsl(argv, **kw):
    return subprocess.run(["wsl.exe", "-d", DISTRO, "--"] + list(argv), **kw)


def die(msg: str, code: int = 1):
    print(f"[-] {msg}")
    print(f"[i] проверь: wsl -l -v   и   wsl -d {DISTRO} -- uname -a")
    sys.exit(code)


def check() -> None:
    try:
        r = subprocess.run(["wsl.exe", "-d", DISTRO, "--", "true"],
                           capture_output=True, timeout=120)
    except FileNotFoundError:
        die("wsl.exe не найден — WSL не установлен")
    except subprocess.TimeoutExpired:
        die("WSL не ответил за 120 с (дистрибутив завис?)")
    if r.returncode != 0:
        err = (r.stderr or b"").decode("utf-8", "replace").strip()
        die(f"дистрибутив «{DISTRO}» не запускается: {err or 'код ' + str(r.returncode)}")


def home() -> str:
    r = wsl(["bash", "-c", 'printf %s "$HOME"'], capture_output=True, timeout=120)
    return (r.stdout or b"").decode("utf-8", "replace").strip() or "/root"


def _mkdir(path: str) -> None:
    wsl(["bash", "-c", f"mkdir -p {shlex.quote(path)}"], timeout=120)


def _put_script(text: str) -> str:
    """Кладём shell-скрипт в ~/.cache/ctf-wsl/<hash>.sh через stdin."""
    h = home()
    digest = hashlib.sha1(text.encode("utf-8")).hexdigest()[:12]
    path = f"{h}/.cache/ctf-wsl/{digest}.sh"
    _mkdir(os.path.dirname(path))
    r = wsl(["bash", "-c", f"cat > {shlex.quote(path)}"], input=text.encode("utf-8"),
            timeout=180)
    if r.returncode != 0:
        die("не смог записать скрипт внутрь WSL")
    return path


def _run_script(text: str) -> int:
    return wsl(["bash", _put_script(text)]).returncode


def _copy(local: str, remote: str) -> None:
    with open(local, "rb") as fh:
        r = wsl(["bash", "-c",
                 f"cat > {shlex.quote(remote)} && chmod +x {shlex.quote(remote)}"],
                stdin=fh, timeout=REMOTE_TIMEOUT)
    if r.returncode != 0:
        die(f"не скопировал {local} -> {remote}")


def stage(src: str, with_dir: bool):
    h = home()
    base = f"{h}/inbox"
    _mkdir(base)
    if not with_dir:
        target = f"{base}/{os.path.basename(src)}"
        _copy(src, target)
        return target, base

    parent = os.path.dirname(src)
    name = os.path.basename(parent.rstrip("\\/")) or "chall"
    target_dir = f"{base}/{name}"
    wsl(["bash", "-c", f"rm -rf {shlex.quote(target_dir)} && mkdir -p {shlex.quote(target_dir)}"],
        timeout=180)
    skipped = 0
    for item in sorted(os.listdir(parent)):
        full = os.path.join(parent, item)
        if not os.path.isfile(full):
            continue
        if os.path.getsize(full) > MAX_COPY:
            skipped += 1
            continue
        _copy(full, f"{target_dir}/{item}")
    if skipped:
        print(f"[i] пропустил файлов >{MAX_COPY // (1024 * 1024)} МБ: {skipped}")
    return f"{target_dir}/{os.path.basename(src)}", target_dir


INFO = r'''
. /etc/os-release 2>/dev/null
printf 'distro : %s %s\n' "${PRETTY_NAME:-?}" "${BUILD_ID:-}"
printf 'kernel : %s\n' "$(uname -r)"
printf 'user   : %s  home: %s\n' "$(id -un)" "$HOME"
if [ -d /run/systemd/system ]; then printf 'systemd: yes\n'; else printf 'systemd: no\n'; fi
printf 'cpus   : %s\n' "$(nproc)"
printf 'ram    : %s\n' "$(awk '/MemTotal/ {printf "%.1f GB", $2/1048576}' /proc/meminfo)"
printf 'disk   : %s\n' "$(df -h / | awk 'NR==2 {printf "%s free of %s", $4, $2}')"
printf 'tools  :\n'
for t in python3 gdb checksec r2 pwntools ghidra binwalk qemu-x86_64 \
         qemu-aarch64 gcc hashcat john nmap sqlmap z3 sage; do
  p=$(command -v "$t" 2>/dev/null)
  [ -n "$p" ] && printf '  %-12s %s\n' "$t" "$p"
done
true
'''


def cmd_info(args) -> int:
    check()
    return _run_script(INFO)


def elf_arch(path: str) -> str | None:
    """Архитектура ELF по e_machine (без зависимостей)."""
    try:
        with open(path, "rb") as f:
            hdr = f.read(20)
    except OSError:
        return None
    if len(hdr) < 20 or hdr[:4] != b"\x7fELF":
        return None
    endian = "little" if hdr[5] == 1 else "big"
    machine = int.from_bytes(hdr[18:20], endian)
    return {0xB7: "aarch64", 0x3E: "x86_64", 0x03: "i386", 0x28: "arm"}.get(machine)


def cmd_run(args) -> int:
    src = os.path.abspath(args.file)
    if not os.path.isfile(src):
        print(f"[-] нет файла: {src}")
        return 2
    check()
    target, workdir = stage(src, args.dir)

    arch = args.arch
    if arch == "auto":
        arch = elf_arch(src) or "x86_64"
    argv = " ".join(shlex.quote(a) for a in args.rest)
    print(f"[i] {DISTRO}:{target} ({arch})")

    if arch in ("aarch64", "arm"):
        qemu = "qemu-aarch64" if arch == "aarch64" else "qemu-arm"
        loader = "ld-linux-aarch64.so.1" if arch == "aarch64" else "ld-linux-armhf.so.3"
        script = (f"cd {shlex.quote(workdir)} || exit 1\n"
                  f"if command -v {qemu} >/dev/null 2>&1; then\n"
                  f"  for root in /usr/aarch64-linux-gnu /usr/lib/aarch64-linux-gnu "
                  f"/usr/arm-linux-gnueabihf; do\n"
                  f"    if [ -e \"$root/lib/{loader}\" ] || [ -e \"$root/{loader}\" ]; then\n"
                  f"      exec {qemu} -L \"$root\" {shlex.quote(target)} {argv}\n"
                  f"    fi\n"
                  f"  done\n"
                  f"  {qemu} {shlex.quote(target)} {argv}\n"
                  f"  echo \"[i] нет aarch64-сисколла ({loader}): поставь aarch64-linux-gnu-glibc\" >&2\n"
                  f"  exit 127\n"
                  f"fi\n"
                  f"echo \"[i] нет {qemu}: поставь qemu-user\" >&2\n"
                  f"exit 127\n")
    else:
        script = f"cd {shlex.quote(workdir)} || exit 1\nexec {shlex.quote(target)} {argv}\n"

    r = wsl(["bash", _put_script(script)])
    print(f"[i] код возврата: {r.returncode}")
    return r.returncode


def cmd_sh(args) -> int:
    check()
    return _run_script(args.command + "\n")


def cmd_inbox(args) -> int:
    """Показывает, что уже перенесено из Windows в ~/inbox."""
    check()
    script = r'''
d="$HOME/inbox"
mkdir -p "$d"
n=$(find "$d" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)
printf 'inbox: %s (%s объектов)\n' "$d" "$n"
ls -lhA "$d" 2>/dev/null | sed '1d' | awk '{printf "  %-10s %s\n", $5, $9}'
'''
    return _run_script(script)


def cmd_which(args) -> int:
    check()
    lines = ["for t in " + " ".join(shlex.quote(a) for a in args.tools) + "; do",
             '  p=$(command -v "$t" 2>/dev/null)',
             '  if [ -n "$p" ]; then printf "  %-12s %s\\n" "$t" "$(readlink -f "$p")"; '
             'else printf "  %-12s %s\\n" "$t" "НЕТ"; fi',
             "done"]
    return _run_script("\n".join(lines) + "\n")


def cmd_install(args) -> int:
    check()
    body = ("for p in " + " ".join(PROBES) + "; do "
            'command -v "$p" >/dev/null 2>&1 || echo "$p"; done')
    r = subprocess.run(["wsl.exe", "-d", DISTRO, "--", "bash", "-s"],
                       input=body.encode(), capture_output=True, timeout=300)
    missing = [x for x in (r.stdout or b"").decode("utf-8", "replace").split() if x]
    if not missing:
        print("[+] всё из типового набора на месте")
        return 0
    print("[-] нет: " + ", ".join(missing))
    for m in missing:
        if m in PKG_HINT:
            print(f"    {m:12s} -> {PKG_HINT[m]}")
    if not args.yes:
        print("[i] поставь вручную (или повтори с --yes для pacman-части)")
        return 0
    pkgs = sorted({PKG_HINT[m] for m in missing
                   if m in PKG_HINT and "(AUR)" not in PKG_HINT[m]
                   and not PKG_HINT[m].startswith("pipx")})
    if not pkgs:
        print("[i] pacman-пакетов нет, только AUR/pip")
        return 0
    print("[i] sudo pacman -S " + " ".join(pkgs))
    return _run_script("sudo pacman -S --noconfirm --needed --disable-download-timeout "
                       + " ".join(pkgs) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description="Запуск ELF в WSL-дистрибутиве (Arch)")
    sub = ap.add_subparsers(dest="cmd")

    sub.add_parser("info", help="что внутри WSL: ядро, юзер, инструменты")

    p = sub.add_parser("run", help="скопировать бинарь в Linux и запустить")
    p.add_argument("file")
    p.add_argument("--dir", action="store_true",
                   help="тащить весь каталог (libc, ld-linux, словари)")
    p.add_argument("--arch", default="auto", choices=["auto", "x86_64", "aarch64", "arm"],
                   help="чем запускать: auto — по e_machine (aarch64/arm через qemu)")
    p.add_argument("rest", nargs=argparse.REMAINDER, help="аргументы бинаря (после --)")

    p = sub.add_parser("sh", help="любая команда внутри Linux")
    p.add_argument("command")

    p = sub.add_parser("which", help="где лежит инструмент")
    p.add_argument("tools", nargs="+")

    sub.add_parser("inbox", help="что уже перенесено из Windows (~/inbox)")

    p = sub.add_parser("install", help="чего не хватает; --yes ставит pacman-часть")
    p.add_argument("--yes", action="store_true")

    args = ap.parse_args()
    if args.cmd is None:
        ap.print_help()
        return 0
    if args.cmd == "run":
        args.rest = [x for x in args.rest if x != "--"]
    return {"info": cmd_info, "run": cmd_run, "sh": cmd_sh,
            "which": cmd_which, "install": cmd_install, "inbox": cmd_inbox}[args.cmd](args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except FileNotFoundError as e:
        print(f"[-] нет файла: {e.filename}")
        sys.exit(2)
    except (PermissionError, IsADirectoryError) as e:
        print(f"[-] не могу прочитать: {e}")
        sys.exit(2)
    except BrokenPipeError:
        sys.exit(0)
    except KeyboardInterrupt:
        sys.exit(130)
