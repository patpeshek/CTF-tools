#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
admin_triage.py — зонтик категории ADMIN: папка (выгруженная ФС, дамп конфигов)
или один файл → что это, что не так, что делать дальше.

  python admin_triage.py fs_dump/            # всё: конфиги, логи, кусты, образы ВМ
  python admin_triage.py etc/sudoers         # один конфиг/лог/куст/образ
  python admin_triage.py suid.txt            # вывод find / -perm -4000 или getcap -r /
  python admin_triage.py dump/ --no-dispatch # только проверки конфигов, без vm/logs/winadm

Раздаёт дальше: образы ВМ → vm_image, логи/история → log_analyze, кусты/задачи/
PS-история → win_admin. Проверяет Linux-конфиги: sudoers (NOPASSWD, GTFOBins,
LD_PRELOAD), SUID/capabilities из списка, cron/systemd (пути в /tmp, wildcard,
world-writable), passwd (лишний uid 0, хеш прямо в passwd), shadow (тип хеша +
режим hashcat), group (docker/lxd/disk…), sshd_config, authorized_keys, приватные
ключи, docker-compose/Dockerfile/kubeconfig/Secret (base64 раскодируется),
.env/.git-credentials/.netrc/.pgpass/.my.cnf/wp-config, NFS no_root_squash.
Подсказки по восстановлению: корзины (trashinfo, $I), .swp/.bak, lost+found.
Только чтение, без сети.
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
import datetime as dt
import os
import re
import stat
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)
import adminlib  # noqa: E402
import common  # noqa: E402

SEV = {"!!": 0, "!": 1, "+": 2}
STD_SUID = {
    "passwd", "sudo", "su", "mount", "umount", "ping", "ping6", "chsh", "chfn", "newgrp",
    "gpasswd", "pkexec", "fusermount", "fusermount3", "ssh-keysign", "dbus-daemon-launch-helper",
    "polkit-agent-helper-1", "xorg.wrap", "unix_chkpwd", "pam_timestamp_check", "at", "crontab",
    "staprun", "ntfs-3g", "snap-confine", "mount.nfs", "mount.cifs", "traceroute6.iputils",
    "vmware-user-suid-wrapper", "sg", "chage", "expiry", "wall", "write", "ssh-agent",
    "dotlockfile", "bwrap", "xorg", "sudoedit", "mount.ecryptfs_private", "doas", "procmail",
    "exim4", "lockdev", "Xorg", "kismet_cap_linux_wifi", "uuidd", "mlocate", "plocate",
}
PRIV_GROUPS = {"sudo", "wheel", "admin", "adm", "docker", "lxd", "lxc", "disk", "shadow", "root",
               "video", "libvirt", "kvm"}
WRITABLE_DIRS = re.compile(r"(?:^|[\s'\"=])(/tmp/|/var/tmp/|/dev/shm/|/home/|/opt/|/srv/|"
                           r"/usr/local/(?:bin|sbin)/|/var/www/)\S*")
SECRET_KEY = re.compile(r"(?i)(pass(?:word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|"
                        r"private[_-]?key|auth|credential|jwt|salt|db_pass|client_secret)")
CAP_DANGER = re.compile(r"cap_(?:setuid|setgid|dac_override|dac_read_search|sys_admin|sys_ptrace|"
                        r"sys_module|chown|fowner)")


class Triage:
    def __init__(self, args):
        self.args = args
        self.findings = []      # (sev, файл, текст)
        self.flags = []         # (флаг, где)
        self.next = []          # команды «дальше»
        self.found = {}         # тип → [пути]

    def add(self, sev, where, text):
        self.findings.append((sev, where, text))
        print(f"[{sev}] {text}" + (f"   ({where})" if where else ""))

    def flag(self, flags, where):
        for f in flags:
            if f not in [x for x, _ in self.flags]:
                self.flags.append((f, where))

    def hint(self, cmd):
        if cmd not in self.next:
            self.next.append(cmd)


def read(path, limit=4 << 20):
    try:
        return adminlib.read_text(path, limit)
    except (OSError, ValueError):
        return ""


def rel(path, root):
    try:
        r = os.path.relpath(path, root)
    except ValueError:
        r = path
    return r.replace("\\", "/")


# ---------------------------------------------------------------- хеши

def hash_type(h):
    h = h.strip()
    special = [(r"^\$y\$", "yescrypt", "john --format=crypt (в hashcat нет)"),
               (r"^\$gy\$", "gost-yescrypt", "john --format=crypt"),
               (r"^\$7\$", "scrypt (crypt)", "john --format=crypt"),
               (r"^\$apr1\$", "Apache MD5 (apr1)", "1600"),
               (r"^\{SSHA\}", "LDAP SSHA", "111"),
               (r"^\{SHA\}", "LDAP SHA1 base64", "101"),
               (r"^\$2[aby]\$", "bcrypt", "3200")]
    for rx, name, mode in special:
        if re.match(rx, h):
            return name, mode
    try:
        sys.path.insert(0, os.path.join(ROOT, "crypto"))
        import hash_id
        return hash_id.identify(h)
    except Exception:
        return "?", "-"


def gtfo():
    try:
        sys.path.insert(0, os.path.join(ROOT, "linux"))
        import gtfobins
        return gtfobins.DB
    except Exception:
        return {}


# ---------------------------------------------------------------- Linux-конфиги

def check_passwd(t, path, text):
    users = []
    for ln in text.splitlines():
        p = ln.strip().split(":")
        if len(p) < 7 or ln.startswith("#"):
            continue
        name, pw, uid, gid, _g, home, shell = p[:7]
        users.append(name)
        if uid == "0" and name != "root":
            t.add("!!", path, f"passwd: {name} с UID 0 — второй root")
        if pw not in ("x", "*", "!", "!!", "") and not pw.startswith("!"):
            name2, mode = hash_type(pw)
            t.add("!!", path, f"passwd: у {name} хеш прямо в passwd ({name2}, {crack_how(mode)}): {pw}")
        if pw == "":
            t.add("!!", path, f"passwd: у {name} пустой пароль (поле 2 пусто)")
    login = [ln.split(":")[0] for ln in text.splitlines()
             if ln.count(":") >= 6 and not re.search(r"(nologin|false|sync|halt|shutdown)$", ln.strip())]
    if login:
        t.add("+", path, f"passwd: юзеры с shell: {', '.join(login[:15])}")


def check_shadow(t, path, text):
    for ln in text.splitlines():
        p = ln.strip().split(":")
        if len(p) < 2 or ln.startswith("#"):
            continue
        name, h = p[0], p[1]
        if h == "":
            t.add("!!", path, f"shadow: у {name} пустой пароль")
        elif h in ("*", "!", "!!", "!*") or h.startswith("!"):
            continue
        else:
            hn, mode = hash_type(h)
            t.add("!", path, f"shadow: {name}: {hn}, {crack_how(mode)}: {h}")
            if str(mode).split()[0].isdigit():
                t.hint(f"python toolbox.py hashcat '{h}' --wordlist rockyou.txt   # {name}")
            else:
                t.hint(f"john --format=crypt --wordlist=rockyou.txt shadow   # {name}: {hn}")


def crack_how(mode):
    return f"hashcat -m {mode}" if str(mode).split()[0].isdigit() else str(mode)


def check_group(t, path, text):
    for ln in text.splitlines():
        p = ln.strip().split(":")
        if len(p) < 4:
            continue
        g, members = p[0], [m for m in p[3].split(",") if m]
        if g in PRIV_GROUPS and members:
            sev = "!!" if g in ("docker", "lxd", "lxc", "disk", "shadow", "root") else "!"
            why = {"docker": "docker run -v /:/mnt → root", "lxd": "lxd-образ с /:/mnt → root",
                   "disk": "debugfs /dev/sda1 → чтение любых файлов",
                   "shadow": "читает /etc/shadow", "adm": "читает /var/log"}.get(g, "sudo/админ")
            t.add(sev, path, f"group {g}: {', '.join(members)} — {why}")


def check_sudoers(t, path, text):
    db = gtfo()
    for raw in text.splitlines():
        ln = raw.strip()
        if not ln or (ln.startswith("#") and not ln.startswith(("#include", "#includedir"))):
            continue
        if ln.startswith(("#include", "@include")):
            t.add("+", path, f"sudoers: {ln}")
            continue
        if ln.startswith("Defaults"):
            if re.search(r"env_keep\s*\+?=.*\b(LD_PRELOAD|LD_LIBRARY_PATH|PYTHONPATH|PERL5LIB)", ln):
                t.add("!!", path, f"sudoers: {ln} — свой .so/модуль через sudo → root")
            elif re.search(r"!env_reset|!authenticate|\bsetenv\b|!requiretty|secure_path=.*(/tmp|/home)", ln):
                t.add("!", path, f"sudoers: {ln}")
            continue
        m = re.match(r"^(\S+)\s+(\S+?)\s*=\s*(?:\(([^)]*)\)\s*)?(.*)$", ln)
        if not m or m.group(1) in ("Cmnd_Alias", "User_Alias", "Host_Alias", "Runas_Alias"):
            if ln.startswith(("Cmnd_Alias", "User_Alias")):
                t.add("+", path, f"sudoers: {ln}")
            continue
        who, runas, rest = m.group(1), m.group(3) or "root", m.group(4)
        if who in ("root",) and "NOPASSWD" not in rest:
            continue
        nopw = "NOPASSWD" in rest
        cmds = [c.strip() for c in re.sub(r"\b(?:NOPASSWD|PASSWD|SETENV|NOEXEC|EXEC):", "", rest).split(",")]
        for c in cmds:
            if not c:
                continue
            base = os.path.basename(c.split()[0]) if c.split() else c
            sev = "!" if not nopw else "!!"
            note = ""
            if c == "ALL":
                note = "любая команда"
                sev = "!!"
            elif base in db:
                note = f"GTFOBins: {db[base][0]}"
                sev = "!!"
            elif "*" in c:
                note = "wildcard в аргументах — подставь свои"
            elif re.search(r"/(?:tmp|home|opt|var/tmp|dev/shm)/", c):
                note = "скрипт в записываемой папке — подмени"
                sev = "!!"
            t.add(sev, path, f"sudoers: {who} → ({runas}) {'NOPASSWD ' if nopw else ''}{c}"
                             + (f" — {note}" if note else ""))


def cron_lines(text, system):
    for ln in text.splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        if re.match(r"^[A-Z_]+=", s):
            yield "env", s
            continue
        if s.startswith("@"):
            parts = s.split(None, 2 if system else 1)
            yield ("job", parts[-1]) if len(parts) > 1 else ("job", s)
            continue
        parts = s.split(None, 6 if system else 5)
        if len(parts) >= (7 if system else 6):
            yield "job", (parts[5] + " :: " + parts[6]) if system else parts[5]


def check_cron(t, path, text, root):
    system = "/etc/crontab" in "/" + path or "/cron.d/" in "/" + path
    for kind, s in cron_lines(text, system):
        if kind == "env":
            if s.startswith("PATH=") and re.search(r"/(?:tmp|home|opt|dev/shm)|(^|:)\.(:|$)", s):
                t.add("!!", path, f"cron: {s} — записываемый каталог в PATH (подмена бинаря)")
            continue
        user, cmd = (s.split(" :: ", 1) if " :: " in s else ("", s))
        check_command(t, path, cmd, f"cron{(' (' + user + ')') if user else ''}", root)


def check_command(t, path, cmd, label, root):
    tags, creds, decoded = adminlib.analyze_command(cmd)
    if re.search(r"\b(?:tar|chown|chmod|rsync|zip|7z)\b[^|;&]*\s\*(?:\s|$)", cmd):
        t.add("!!", path, f"{label}: wildcard-инъекция: {cmd[:200]} "
                          "(файлы-аргументы вида --checkpoint-action=exec=sh x.sh)")
    for m in WRITABLE_DIRS.finditer(cmd):
        target = m.group(0).strip(" '\"=")
        t.add("!!" if "root" in label or "cron" in label else "!", path,
              f"{label}: {cmd[:200]} — запускает файл из записываемой папки {target}")
        if root:
            local = os.path.join(root, target.lstrip("/"))
            if os.path.isfile(local):
                body = read(local, 1 << 16)
                t.flag(adminlib.flags_in(body), rel(local, root))
                t.add("+", rel(local, root), f"скрипт есть в дампе ({len(body)} симв.)")
        break
    if tags:
        t.add("!!" if set(tags) & {"reverse-shell", "download-exec"} else "!", path,
              f"{label}: {cmd[:200]}   [{', '.join(tags)}]")
    for k, v in creds:
        t.add("!", path, f"{label}: кред ({k}): {v}")
    for how, text in decoded:
        t.add("!", path, f"{label}: {how} → {text[:200]!r}")
        t.flag(adminlib.flags_in(text), path)


def check_systemd(t, path, text, root):
    user = "root"
    m = re.search(r"(?m)^\s*User\s*=\s*(\S+)", text)
    if m:
        user = m.group(1)
    for m in re.finditer(r"(?m)^\s*(Exec(?:Start|StartPre|StartPost|Stop|Reload))\s*=\s*[-@+!]*(.+)$", text):
        check_command(t, path, m.group(2).strip(), f"systemd {m.group(1)} ({user})", root)
    for m in re.finditer(r"(?m)^\s*(OnCalendar|OnBootSec|OnUnitActiveSec)\s*=\s*(.+)$", text):
        t.add("+", path, f"systemd timer: {m.group(1)}={m.group(2).strip()}")


SSHD_RULES = [
    (r"(?im)^\s*PermitRootLogin\s+yes\b", "!", "PermitRootLogin yes"),
    (r"(?im)^\s*PermitEmptyPasswords\s+yes\b", "!!", "PermitEmptyPasswords yes — вход без пароля"),
    (r"(?im)^\s*PasswordAuthentication\s+yes\b", "+", "PasswordAuthentication yes (брутфорс возможен)"),
    (r"(?im)^\s*AuthorizedKeysFile\s+(?!\.ssh/authorized_keys(\s+\.ssh/authorized_keys2)?\s*$).+",
     "!", "нестандартный AuthorizedKeysFile"),
    (r"(?im)^\s*AuthorizedKeysCommand\s+\S+", "!", "AuthorizedKeysCommand — внешняя программа ключей"),
    (r"(?im)^\s*ForceCommand\s+.+", "+", "ForceCommand"),
    (r"(?im)^\s*Match\s+.+", "+", "блок Match"),
    (r"(?im)^\s*Port\s+(?!22\b)\d+", "+", "нестандартный порт"),
    (r"(?im)^\s*(?:AllowUsers|AllowGroups)\s+.+", "+", "AllowUsers/AllowGroups"),
]


def check_sshd(t, path, text):
    for rx, sev, msg in SSHD_RULES:
        for m in re.finditer(rx, text):
            t.add(sev, path, f"sshd_config: {msg}: {m.group(0).strip()[:120]}")


def check_authorized_keys(t, path, text):
    for ln in text.splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        m = re.search(r"(ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-\S+|sk-\S+)\s+(\S+)\s*(.*)$", s)
        opts = s[:m.start()].strip() if m else ""
        comment = m.group(3) if m else ""
        sev = "!" if re.search(r"command=|from=|environment=", opts) else "+"
        t.add(sev, path, f"authorized_keys: {m.group(1) if m else '?'} {comment[:60]}"
                         + (f"  опции: {opts[:120]}" if opts else ""))


def check_privkey(t, path, text):
    enc = "ENCRYPTED" in text or "Proc-Type: 4,ENCRYPTED" in text
    if "OPENSSH PRIVATE KEY" in text:
        body = "".join(text.split("-----")[2].split()) if text.count("-----") >= 4 else ""
        raw = adminlib.try_b64(body) or b""
        enc = enc or b"bcrypt" in raw[:200] or b"aes256" in raw[:200]
    t.add("!!", path, "приватный ключ" + (" (зашифрован: ssh2john → john)" if enc else
                                         " без пароля — ssh -i ключ user@host"))


def check_secrets_text(t, path, text, label):
    for ln in text.splitlines()[:5000]:
        s = ln.strip()
        if not s or s.startswith(("#", "//", ";")):
            continue
        m = re.match(r"""^(?:export\s+)?["']?([\w.\-]+)["']?\s*[:=]\s*["']?([^"'\s#][^"'#]*?)["']?\s*,?$""", s)
        if m and SECRET_KEY.search(m.group(1)) and len(m.group(2)) >= 3 and \
                m.group(2).lower() not in ("null", "none", "changeme", "true", "false", "''", '""'):
            t.add("!", path, f"{label}: {m.group(1)} = {m.group(2)[:160]}")
            raw = adminlib.try_b64(m.group(2))
            dec = adminlib.readable(raw) if raw else None
            if dec:
                t.add("!", path, f"{label}: {m.group(1)} base64 → {dec[:160]!r}")
                t.flag(adminlib.flags_in(dec), path)
        m = re.search(r"define\(\s*['\"](DB_PASSWORD|DB_USER|AUTH_KEY|SECURE_AUTH_KEY)['\"]\s*,\s*['\"]([^'\"]*)", s)
        if m:
            t.add("!", path, f"{label}: {m.group(1)} = {m.group(2)[:160]}")


def check_compose(t, path, text):
    rules = [(r"(?im)^\s*privileged:\s*true", "!!", "privileged: true — побег из контейнера"),
             (r"/var/run/docker\.sock", "!!", "docker.sock примонтирован — root на хосте"),
             (r"(?im)^\s*(?:network_mode|pid|ipc):\s*[\"']?host", "!", "host namespace"),
             (r"(?im)cap_add:[\s\S]{0,80}?\b(SYS_ADMIN|ALL|SYS_PTRACE|SYS_MODULE|DAC_READ_SEARCH)\b",
              "!!", "опасная capability"),
             (r"(?im)^\s*-\s*[\"']?/:/", "!!", "корень хоста примонтирован")]
    for rx, sev, msg in rules:
        m = re.search(rx, text)
        if m:
            t.add(sev, path, f"compose/k8s: {msg}: {m.group(0).strip()[:100]}")
    check_secrets_text(t, path, re.sub(r"(?m)^\s*-\s*", "", text), "env")


def check_dockerfile(t, path, text):
    for m in re.finditer(r"(?im)^\s*(ENV|ARG)\s+(.+)$", text):
        if SECRET_KEY.search(m.group(2)):
            t.add("!", path, f"Dockerfile {m.group(1)} {m.group(2)[:160]} — секрет в слое/истории")
    if re.search(r"(?im)^\s*(COPY|ADD)\s+.*(\.env|id_rsa|\.git|credentials)", text):
        t.add("!", path, "Dockerfile копирует секретный файл в образ")
    t.hint(f"python forensic/docker_image.py \"{path}\" --dockerfile")


def check_docker_config(t, path, text):
    for m in re.finditer(r'"auth"\s*:\s*"([A-Za-z0-9+/=]+)"', text):
        raw = adminlib.try_b64(m.group(1))
        dec = adminlib.readable(raw) if raw else None
        t.add("!!", path, f"docker config auths: {dec or m.group(1)}")
        if dec:
            t.flag(adminlib.flags_in(dec), path)


def check_k8s(t, path, text):
    if re.search(r"(?m)^kind:\s*Secret\b", text):
        sect = None
        for ln in text.splitlines():
            if re.match(r"^(data|stringData):\s*$", ln):
                sect = ln.split(":")[0]
                continue
            if sect and re.match(r"^\S", ln):
                sect = None
            m = re.match(r"^\s+([\w.\-]+):\s*['\"]?([^'\"\s]+)", ln) if sect else None
            if m:
                val = m.group(2)
                if sect == "data":
                    raw = adminlib.try_b64(val)
                    dec = adminlib.readable(raw) if raw else None
                    t.add("!!", path, f"k8s Secret {m.group(1)}: {val[:60]} → {dec!r}" if dec
                          else f"k8s Secret {m.group(1)}: {val[:80]}")
                    if dec:
                        t.flag(adminlib.flags_in(dec), path)
                else:
                    t.add("!!", path, f"k8s Secret {m.group(1)} (stringData): {val[:120]}")
    for key in ("token", "client-key-data", "client-certificate-data", "password"):
        m = re.search(rf"(?m)^\s*{key}:\s*(\S+)", text)
        if m and re.search(r"(?m)^(kind:\s*Config|clusters:|users:)", text):
            t.add("!!", path, f"kubeconfig: {key}: {m.group(1)[:80]}…")
    if re.search(r"(?m)^kind:\s*(Pod|Deployment|DaemonSet|StatefulSet)", text):
        check_compose(t, path, text)


def check_cred_file(t, path, text, name):
    for ln in text.splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        if name == ".git-credentials":
            m = re.match(r"(\w+)://([^:@/]+):([^@]+)@(\S+)", s)
            if m:
                pw = adminlib.url_unquote_all(m.group(3))
                t.add("!!", path, f".git-credentials: {m.group(2)}:{pw} @ {m.group(4)}")
        elif name == ".netrc":
            t.add("!!", path, f".netrc: {s[:200]}")
        elif name == ".pgpass":
            p = s.split(":")
            if len(p) >= 5:
                t.add("!!", path, f".pgpass: {p[3]}:{':'.join(p[4:])} @ {p[0]}:{p[1]}/{p[2]}")
        elif name in (".my.cnf", "my.cnf"):
            if re.match(r"(?i)password\s*=", s):
                t.add("!!", path, f".my.cnf: {s}")
        elif name == ".htpasswd":
            if ":" in s:
                u, h = s.split(":", 1)
                hn, mode = hash_type(h)
                t.add("!", path, f".htpasswd: {u}: {hn}, {crack_how(mode)}: {h}")


def check_suid_list(t, path, text):
    db = gtfo()
    n = 0
    for ln in text.splitlines():
        s = ln.strip()
        if not s:
            continue
        mcap = re.match(r"^(/\S+)\s*(?:=\s*)?(cap_[\w,+=]+.*)$", s)
        if mcap:
            sev = "!!" if CAP_DANGER.search(mcap.group(2)) else "+"
            base = os.path.basename(mcap.group(1))
            note = " — cap_setuid: python -c 'import os;os.setuid(0);os.system(\"sh\")'" \
                if "setuid" in mcap.group(2) else ""
            t.add(sev, path, f"capability: {mcap.group(1)} {mcap.group(2)}{note}"
                  + (f" (GTFOBins: {base})" if base in db else ""))
            n += 1
            continue
        m = re.match(r"^(?:\S*\s+\d+\s+)?([-d][rwxsStT-]{9})\S*\s.*?(/\S+)$", s) or \
            re.match(r"^(/\S+)$", s)
        if not m:
            continue
        p = m.group(m.lastindex)
        perms = m.group(1) if m.lastindex == 2 else ""
        if perms and "s" not in perms.lower():
            continue
        base = os.path.basename(p)
        n += 1
        if base in db and db[base][1]:
            t.add("!!", path, f"SUID {p} — GTFOBins: {db[base][1]}")
        elif base in db:
            t.add("!", path, f"SUID {p} — есть в GTFOBins (sudo-вариант: {db[base][0]})")
        elif base not in STD_SUID and base.lower() not in STD_SUID:
            t.add("!", path, f"SUID {p} — нестандартный: strings/ltrace, относительные пути, PATH")
    if n:
        t.add("+", path, f"SUID/capabilities в списке: {n}")


def check_exports(t, path, text):
    for ln in text.splitlines():
        if "no_root_squash" in ln and not ln.strip().startswith("#"):
            t.add("!!", path, f"NFS: {ln.strip()} — no_root_squash: SUID-бинарь с клиента")


def check_fstab(t, path, text):
    for ln in text.splitlines():
        if re.search(r"(?i)(credentials|password|username)=", ln) and not ln.strip().startswith("#"):
            t.add("!", path, f"fstab: {ln.strip()[:200]}")


def check_rc(t, path, text, root):
    for ln in text.splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        tags = [g for g in adminlib.analyze_command(s)[0] if g != "recon"]
        if tags:
            check_command(t, path, s, os.path.basename(path), root)


# ---------------------------------------------------------------- восстановление

def check_trash(t, path, name, where):
    if name.endswith(".trashinfo"):
        text = read(path, 8192)
        p = re.search(r"(?m)^Path=(.*)$", text)
        d = re.search(r"(?m)^DeletionDate=(.*)$", text)
        if p:
            t.add("!", where, f"корзина: удалён {adminlib.url_unquote_all(p.group(1))} "
                             f"({d.group(1) if d else '?'}); содержимое — Trash/files/")
        return
    if re.match(r"^\$I[\w.]{2,}", name):
        try:
            with open(path, "rb") as f:
                raw = f.read(4096)
            ver, size, ft = struct.unpack("<QQQ", raw[:24])
            if ver == 2:
                (n,) = struct.unpack("<I", raw[24:28])
                orig = raw[28:28 + n * 2].decode("utf-16-le", "replace").rstrip("\x00")
            else:
                orig = raw[24:24 + 520].decode("utf-16-le", "replace").split("\x00", 1)[0]
            when = dt.datetime(1601, 1, 1) + dt.timedelta(microseconds=ft // 10)
            t.add("!", where, f"$Recycle.Bin: {orig} ({size} байт) удалён {when:%Y-%m-%d %H:%M:%S}; "
                             f"данные — в ${'R' + name[2:]}")
        except (OSError, struct.error, OverflowError):
            pass


# ---------------------------------------------------------------- классификация

def classify(path, root):
    """Что за файл по пути и содержимому: (тип, подробность)."""
    name = os.path.basename(path)
    low = name.lower()
    r = "/" + rel(path, root) if root else "/" + path.replace("\\", "/")
    kind, detail = adminlib.detect(path)
    if kind and kind not in ("SHELLHISTORY", "PSHISTORY"):
        return kind, detail
    if kind and "history" in low:
        return kind, detail
    hist = (kind, detail)
    kind, detail = config_kind(path, low, r)
    return (kind, detail) if kind else hist


def config_kind(path, low, r):
    """Linux-конфиги и прочее по имени/пути/содержимому."""
    head = adminlib.read_head(path, 4096)
    if b"PRIVATE KEY-----" in head:
        return "PRIVKEY", None
    if low == "passwd" and "/etc/" in r or (low == "passwd" and b":x:0:0:" in head):
        return "PASSWD", None
    if low in ("shadow", "shadow-", "shadow.bak") or (low.startswith("shadow") and b":$" in head):
        return "SHADOW", None
    if low == "group" and "/etc/" in r:
        return "GROUP", None
    if low == "sudoers" or "/sudoers.d/" in r:
        return "SUDOERS", None
    if low == "crontab" or "/cron.d/" in r or "/crontabs/" in r or re.search(r"/cron\.(hourly|daily|weekly|monthly)/", r):
        return ("CRON", None) if "/cron." not in r or "/cron.d/" in r else ("SCRIPT", None)
    if low.endswith((".service", ".timer", ".socket")):
        return "SYSTEMD", None
    if low in ("sshd_config",) or r.endswith("/ssh/sshd_config"):
        return "SSHD", None
    if low in ("authorized_keys", "authorized_keys2"):
        return "AUTHKEYS", None
    if low in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
        return "COMPOSE", None
    if low == "dockerfile" or low.endswith(".dockerfile"):
        return "DOCKERFILE", None
    if low == "config.json" and "/.docker/" in r:
        return "DOCKERCFG", None
    if low.endswith((".yml", ".yaml")) or (low == "config" and "/.kube/" in r):
        if re.search(rb"(?m)^(kind:|apiVersion:|clusters:)", head):
            return "K8S", None
    if low in (".git-credentials", ".netrc", "_netrc", ".pgpass", ".my.cnf", "my.cnf", ".htpasswd"):
        return "CREDFILE", ".netrc" if low == "_netrc" else low
    if low == ".env" or low.endswith(".env") or low in ("wp-config.php", "config.php", "settings.py",
                                                        "application.properties", "application.yml",
                                                        "appsettings.json", "database.yml",
                                                        "local_settings.py", "secrets.yml"):
        return "SECRETS", None
    if low == "exports" and "/etc/" in r:
        return "EXPORTS", None
    if low == "fstab":
        return "FSTAB", None
    if low in (".bashrc", ".profile", ".bash_profile", ".zshrc", "rc.local", "profile") or "/profile.d/" in r \
            or "/init.d/" in r:
        return "RC", None
    if low.endswith(".trashinfo") or re.match(r"^\$i[\w.]{2,}", low):
        return "TRASH", None
    if low.endswith((".swp", ".swo", "~", ".bak", ".old", ".orig", ".save")):
        return "BACKUP", None
    if suid_like(path):
        return "SUIDLIST", None
    return None, None


def suid_like(path):
    """Вывод find / -perm -4000 (-ls), ls -l с s-битом или getcap -r /."""
    lines = adminlib.text_lines(path, 65536)
    if not lines:
        return False
    body = [x.strip() for x in lines if x.strip()]
    if len(body) < 2:
        return False
    paths = sum(bool(re.match(r"^(?:\S*\s+\d+\s+)?[-d][rwxsStT-]{9}\S*\s.*/\S+$|^/\S+$|"
                              r"^/\S+\s*=?\s*cap_", x)) for x in body)
    sbits = sum(bool(re.search(r"^(?:\S*\s+\d+\s+)?[-d]..[sS]|^/\S+\s*=?\s*cap_", x)) for x in body)
    names = {os.path.basename(x.split()[-1]) for x in body if x.startswith("/")}
    return paths >= len(body) * 0.7 and bool(sbits or names & STD_SUID)


def check_file(t, path, root, kind, detail):
    where = rel(path, root) if root else path
    if kind in ("VM_DONE",):
        return
    text = read(path) if kind not in adminlib.VM_KINDS + ("REGF", "TRASH") else ""
    if text:
        t.flag(adminlib.flags_in(text), where)
    fn = {
        "PASSWD": lambda: check_passwd(t, where, text),
        "SHADOW": lambda: check_shadow(t, where, text),
        "GROUP": lambda: check_group(t, where, text),
        "SUDOERS": lambda: check_sudoers(t, where, text),
        "CRON": lambda: check_cron(t, where, text, root),
        "SYSTEMD": lambda: check_systemd(t, where, text, root),
        "SSHD": lambda: check_sshd(t, where, text),
        "AUTHKEYS": lambda: check_authorized_keys(t, where, text),
        "PRIVKEY": lambda: check_privkey(t, where, text),
        "COMPOSE": lambda: check_compose(t, where, text),
        "DOCKERFILE": lambda: check_dockerfile(t, where, text),
        "DOCKERCFG": lambda: check_docker_config(t, where, text),
        "K8S": lambda: check_k8s(t, where, text),
        "CREDFILE": lambda: check_cred_file(t, where, text, detail),
        "SECRETS": lambda: check_secrets_text(t, where, text, os.path.basename(path)),
        "SUIDLIST": lambda: check_suid_list(t, where, text),
        "EXPORTS": lambda: check_exports(t, where, text),
        "FSTAB": lambda: check_fstab(t, where, text),
        "RC": lambda: check_rc(t, where, text, root),
        "SCRIPT": lambda: check_rc(t, where, text, root),
        "TRASH": lambda: check_trash(t, path, os.path.basename(path), where),
        "BACKUP": lambda: t.add("+", where, "резервная/swap-копия: vim -r для .swp, "
                                            "сравни с оригиналом (diff)"),
    }.get(kind)
    if fn:
        fn()
    # мир-записываемые конфиги (на POSIX, где есть права)
    if os.name != "nt" and kind in ("CRON", "SYSTEMD", "SUDOERS", "PASSWD", "SHADOW", "RC", "SCRIPT"):
        try:
            if os.stat(path).st_mode & stat.S_IWOTH:
                t.add("!!", where, f"{kind}: файл world-writable")
        except OSError:
            pass


# ---------------------------------------------------------------- раздача

def dispatch(t, items, root):
    args = t.args
    if args.no_dispatch:
        for kind, paths in items.items():
            for p in paths[:args.max_dispatch]:
                tool = {"VM": "vm", "LOG": "logs", "WIN": "winadm"}[kind]
                t.hint(f"python toolbox.py {tool} \"{p}\"")
        return
    if items.get("VM"):
        import vm_image
        ns = argparse.Namespace(scan_limit=args.scan_limit, raw=None, find=None, extract=None,
                                disk=None, next=False, mount=False)
        for p in items["VM"][:args.max_dispatch]:
            print(f"\n=== vm_image: {rel(p, root) if root else p} ===")
            try:
                kind = adminlib.vm_kind(p)
                if kind == "OVA":
                    found = vm_image.do_ova(p, ns)
                elif kind == "OVF":
                    found = vm_image.do_ovf(p, ns)
                else:
                    src = vm_image.Src(p)
                    found = vm_image.report_disk(vm_image.open_disk(src, p), os.path.basename(p), ns)
                    src.close()
                t.flag(adminlib.real_flags(found), f"vm {os.path.basename(p)}")
            except (vm_image.VMError, OSError, struct.error) as e:
                print(f"[-] {e}")
            t.hint(f"python admin/vm_image.py \"{p}\" --raw disk.raw   # потом ФС/файлы")
    if items.get("LOG"):
        import log_analyze
        ns = argparse.Namespace(top=args.top, examples=3, all=False, timeline=False,
                                year=args.year, brute=5, window=60, limit=400)
        rep = log_analyze.Report(ns)
        print("\n=== log_analyze ===")
        for p in items["LOG"][:args.max_dispatch]:
            try:
                log_analyze.analyze_file(p, rep)
            except (OSError, ValueError) as e:
                print(f"[-] {p}: {e}")
        for src, how, text in rep.decoded[:args.top * 2]:
            print(f"[+] раскодировано {src}: {how} → {text[:200]!r}")
        for src, kind, val in rep.creds[:args.top * 2]:
            t.add("!", src, f"лог: кред ({kind}): {val}")
        for f, where in rep.flags:
            t.flag([f], where)
        t.hint("python admin/log_analyze.py " + " ".join(f'"{p}"' for p in items["LOG"][:6])
               + " --timeline")
    if items.get("WIN"):
        import win_admin
        print("\n=== win_admin ===")
        for p in items["WIN"][:args.max_dispatch]:
            ns = argparse.Namespace(path=p, top=args.top, all=False, flag_prefix=[], flag_set=None,
                                    any_prefix=False)
            out = _capture(lambda: win_admin.cmd_auto(ns))
            sys.stdout.write(out)
            for ln in out.splitlines():
                if ln.startswith("[!!!] ФЛАГ"):
                    t.flag(common.find_flags(ln.encode("utf-8", "replace"))[:1],
                           f"winadm {os.path.basename(p)}")
            t.hint(f"python admin/win_admin.py \"{p}\"")


def _capture(fn):
    import io
    buf, old = io.StringIO(), sys.stdout
    sys.stdout = buf
    try:
        fn()
    except Exception as e:  # чужой разбор не должен ронять триаж
        print(f"[-] {e}")
    finally:
        sys.stdout = old
    return buf.getvalue()


def recovery_hints(t, root, kinds):
    tips = []
    if kinds.get("BACKUP"):
        tips.append(f"резервные/swap-файлы: {len(kinds['BACKUP'])} — vim -r file.swp, diff с оригиналом")
    if kinds.get("TRASH"):
        tips.append("корзина: Trash/files/ (Linux) и $R-файлы рядом с $I ($Recycle.Bin)")
    if root and os.path.isdir(os.path.join(root, "lost+found")) and os.listdir(os.path.join(root, "lost+found")):
        tips.append("lost+found не пуст — осиротевшие inode после fsck")
    if root:
        for d, dirs, _f in os.walk(root):
            if ".git" in dirs:
                tips.append(f"git-репозиторий {rel(d, root) or '.'}: python toolbox.py git \"{d}\" --all-objects")
                break
            if d.count(os.sep) - root.count(os.sep) > 4:
                dirs[:] = []
    tips.append("удалённые файлы в образе: forensic/disk_image.py (если есть) / extundelete / "
                "debugfs -R 'lsdel' / tsk_recover / photorec")
    print("\n--- восстановление данных ---")
    for x in tips:
        print(f"[i] {x}")


def walk(root, limit):
    n = 0
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x not in ("__pycache__", "node_modules", ".git", "proc", "sys")]
        for fn in files:
            n += 1
            if n > limit:
                print(f"[i] остановился на {limit} файлах (--max-files)")
                return
            yield os.path.join(d, fn)


def main():
    ap = argparse.ArgumentParser(description="ADMIN-триаж: конфиги, логи, кусты, образы ВМ")
    ap.add_argument("path", help="папка-дамп ФС/конфигов или файл")
    ap.add_argument("--no-dispatch", action="store_true", help="не запускать vm/logs/winadm")
    ap.add_argument("--max-files", type=int, default=50000)
    ap.add_argument("--max-dispatch", type=int, default=8, help="сколько файлов каждого типа раздать")
    ap.add_argument("--scan-limit", type=float, default=1024, help="МБ на образ ВМ")
    ap.add_argument("--year", type=int, default=dt.datetime.now().year)
    ap.add_argument("--top", type=int, default=10)
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)

    path = args.path
    if not os.path.exists(path):
        print(f"[-] нет такого пути: {path}")
        sys.exit(2)
    t = Triage(args)
    if os.path.isfile(path):
        err = adminlib.open_error(path)
        if err:
            print(f"[-] {err}")
            sys.exit(2)
        root, files = None, [path]
    else:
        root, files = path, None
    print(f"=== admin triage: {path} ===")
    kinds, items = {}, {"VM": [], "LOG": [], "WIN": []}
    win_seen = False
    for fp in (files or walk(root, args.max_files)):
        try:
            if os.path.getsize(fp) == 0:
                continue
        except OSError:
            continue
        try:
            kind, detail = classify(fp, root)
        except (OSError, ValueError):
            continue
        if not kind:
            continue
        kinds.setdefault(kind, []).append(fp)
        if kind in adminlib.VM_KINDS:
            items["VM"].append(fp)
        elif kind in ("LOG", "SHELLHISTORY"):
            items["LOG"].append(fp)
        elif kind in ("REGF", "TASKXML", "PSHISTORY"):
            if root is None:
                items["WIN"].append(fp)
            elif not win_seen:
                items["WIN"].append(root)   # win_admin auto сам найдёт кусты/задачи/PS
                win_seen = True
        else:
            check_file(t, fp, root, kind, detail)
    summary = ", ".join(f"{k}={len(v)}" for k, v in sorted(kinds.items()))
    print(f"\n[+] найдено: {summary or 'ничего админского'}")
    dispatch(t, items, root)
    if root:
        recovery_hints(t, root, kinds)
    top = sorted(t.findings, key=lambda f: SEV.get(f[0], 3))
    crit = [f for f in top if f[0] in ("!!", "!")]
    if crit:
        print(f"\n--- самое важное ({len(crit)}) ---")
        for sev, where, text in crit[:args.top * 3]:
            print(f"[{sev}] {text[:220]}   ({where})")
    if t.next:
        print("\n--- дальше ---")
        for c in t.next[:20]:
            print(f"    {c}")
    if t.flags:
        print()
        for f, where in t.flags:
            adminlib.print_flags([f], where)
    elif not kinds:
        print("[-] не нашёл конфигов/логов/кустов/образов. Для строк и флагов: "
              "python toolbox.py hunt PATH, python toolbox.py flaghunt PATH")


if __name__ == "__main__":
    main()
