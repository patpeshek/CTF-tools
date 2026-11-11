#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
adminlib.py — общее для admin/*: тип по данным, разбор команд, декодеры.

Не инструмент, а библиотека (как common.py): её импортируют vm_image,
log_analyze, win_admin, admin_triage и solve.py (определение типа).
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

import base64
import binascii
import gzip
import os
import re
import sys
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
import common  # noqa: E402

VM_KINDS = ("QCOW2", "VMDK", "VDI", "VHD", "VHDX", "OVA", "OVF")


# ---------------------------------------------------------------- файлы

def open_error(path):
    """Текст ошибки, если файл нельзя читать, иначе None (правило 5)."""
    if not os.path.exists(path):
        return f"нет такого пути: {path}"
    if os.path.isdir(path):
        return f"это папка, а нужен файл: {path}"
    try:
        with open(path, "rb") as f:
            f.read(1)
    except PermissionError:
        return f"нет прав на чтение: {path}"
    except OSError as e:
        return f"не читается: {path}: {e}"
    return None


def read_head(path, n=65536) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(n)
    except OSError:
        return b""


def read_tail(path, n=512) -> bytes:
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - n))
            return f.read(n)
    except OSError:
        return b""


def read_text(path, limit=64 * 1024 * 1024) -> str:
    """Текст файла: .gz прозрачно, UTF-16 по BOM, иначе UTF-8/cp1251."""
    with open(path, "rb") as f:
        raw = f.read(limit)
    if raw[:2] == b"\x1f\x8b":
        try:
            raw = gzip.decompress(raw)[:limit]
        except Exception:
            pass
    return decode_text(raw)


def decode_text(raw: bytes) -> str:
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", "replace")
    if raw[:3] == b"\xef\xbb\xbf":
        return raw[3:].decode("utf-8", "replace")
    # UTF-16LE без BOM: каждый второй байт ноль
    sample = raw[:400]
    if len(sample) >= 8 and sample[1::2].count(0) > len(sample) // 2 * 0.8:
        return raw.decode("utf-16-le", "replace")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("cp1251", "replace")


# ---------------------------------------------------------------- тип по данным

def vm_kind(path, head: bytes | None = None):
    """QCOW2/VMDK/VDI/VHD/VHDX/OVA/OVF или None — по сигнатурам, не по имени."""
    if head is None:
        head = read_head(path, 4096)
    if head[:4] == b"QFI\xfb":
        return "QCOW2"
    if head[:4] == b"KDMV":
        return "VMDK"
    if len(head) >= 68 and head[64:68] == b"\x7f\x10\xda\xbe":
        return "VDI"
    if head[:8] == b"vhdxfile":
        return "VHDX"
    if head[:8] == b"conectix":
        return "VHD"
    if head[:21] == b"# Disk DescriptorFile" or (
            b"createType=" in head[:2048] and b"# Extent description" in head[:4096]):
        return "VMDK"
    if len(head) >= 262 and head[257:262] == b"ustar":
        name = head[:100].split(b"\x00", 1)[0].lower()
        if name.endswith(b".ovf"):
            return "OVA"
        if path.lower().endswith(".ova"):
            return "OVA"
    low = head[:4096].lower()
    if b"<envelope" in low and b"ovf" in low:
        return "OVF"
    # fixed VHD: сырые данные + 512-байтный футер conectix в конце
    if read_tail(path, 512)[:8] == b"conectix":
        return "VHD"
    return None


TASK_NS = b"schemas.microsoft.com/windows/2004/02/mit/task"

SHELL_WORDS = {
    "ls", "cd", "cat", "sudo", "su", "wget", "curl", "echo", "python", "python3",
    "nc", "ncat", "chmod", "chown", "rm", "mv", "cp", "mkdir", "vim", "vi", "nano",
    "ssh", "scp", "exit", "whoami", "id", "uname", "ps", "kill", "top", "grep",
    "find", "history", "export", "apt", "apt-get", "yum", "pip", "git", "docker",
    "systemctl", "service", "crontab", "base64", "tar", "unzip", "zip", "mysql",
    "passwd", "useradd", "adduser", "usermod", "ifconfig", "ip", "netstat", "ss",
    "touch", "less", "more", "head", "tail", "bash", "sh", "nohup", "perl", "php",
    "openssl", "gpg", "xxd", "dd", "mount", "umount", "clear", "pwd", "env",
    "kubectl", "aws", "ping", "nmap", "socat", "tmux", "screen", "sed", "awk",
}

PS_RE = re.compile(r"(?i)^\s*(?:\$\w+\s*=|[a-z]+-[a-z]{2,}\b|\.\\|&\s|iex\b|ipconfig|"
                   r"powershell|cmd(?:\.exe)?\b|net(?:\.exe)?\s+user|whoami|cd\b|dir\b|ls\b|"
                   r"cls\b|exit\b|reg\s+(?:add|query)|schtasks|sc(?:\.exe)?\s|certutil)")
SYSLOG_RE = re.compile(
    r"^(?:<\d+>)?(?:[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d|"
    r"\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?)\s+\S+\s+[^\s:]+?(?:\[\d+\])?:\s")
ACCESS_RE = re.compile(r'^\S+ \S+ \S+ \[[^\]]+\] "[^"]*" \d{3} (?:\d+|-)')
AUDIT_RE = re.compile(r"^type=[A-Z_]+ msg=audit\(\d+\.\d+:\d+\):")
ZSH_RE = re.compile(r"^: \d{9,11}:\d+;")


def history_kind(path, lines):
    """'PSHISTORY' / 'SHELLHISTORY' / None по имени и содержимому."""
    name = os.path.basename(path).lower()
    body = [ln for ln in lines if ln.strip()][:400]
    if not body:
        return None
    if "consolehost_history" in name:
        return "PSHISTORY"
    if name in (".bash_history", ".zsh_history", ".sh_history", ".ash_history",
                "bash_history", "zsh_history", ".history", ".mysql_history",
                ".python_history", ".psql_history"):
        return "SHELLHISTORY"
    if sum(bool(ZSH_RE.match(ln)) for ln in body) >= len(body) * 0.5:
        return "SHELLHISTORY"
    ps = sum(bool(PS_RE.match(ln)) for ln in body)
    sh = 0
    for ln in body:
        s = ln.strip()
        if s.startswith("#") and s[1:].isdigit():
            sh += 1
            continue
        w = s.split()[0] if s.split() else ""
        w = w.rsplit("/", 1)[-1]
        if w in SHELL_WORDS or s.startswith(("./", "/")):
            sh += 1
    if "history" in name:
        return "PSHISTORY" if ps > sh else "SHELLHISTORY"
    if len(body) >= 4 and ps >= len(body) * 0.6 and ps > sh and \
            any(re.search(r"(?i)\b[a-z]+-[a-z]{3,}\b", ln) for ln in body):
        return "PSHISTORY"
    if len(body) >= 4 and sh >= len(body) * 0.6:
        return "SHELLHISTORY"
    return None


def log_kind(lines):
    """Формат лога: syslog / access / journal_json / journal_export / audit / None."""
    body = [ln for ln in lines if ln.strip()][:300]
    if not body:
        return None
    n = len(body)
    j = sum(ln.lstrip().startswith("{") and ('"MESSAGE"' in ln or '"__REALTIME_TIMESTAMP"' in ln)
            for ln in body)
    if j >= max(1, n * 0.5):
        return "journal_json"
    if sum(ln.startswith(("__REALTIME_TIMESTAMP=", "MESSAGE=", "__CURSOR=")) for ln in body) >= 2:
        return "journal_export"
    counts = {
        "syslog": sum(bool(SYSLOG_RE.match(ln)) for ln in body),
        "access": sum(bool(ACCESS_RE.match(ln)) for ln in body),
        "audit": sum(bool(AUDIT_RE.match(ln)) for ln in body),
    }
    best = max(counts, key=counts.get)
    if counts[best] >= max(1, n * 0.5):
        return best
    return None


def text_lines(path, limit=262144):
    raw = read_head(path, limit)
    if raw[:2] == b"\x1f\x8b":
        try:
            raw = gzip.GzipFile(fileobj=__import__("io").BytesIO(raw)).read(limit)
        except Exception:
            pass
    if not raw or (b"\x00" in raw[:4096] and raw[:2] not in (b"\xff\xfe", b"\xfe\xff")
                   and raw[1:200:2].count(0) < 50):
        return None
    txt = decode_text(raw)
    if common.printable_ratio(txt[:20000]) < 0.9:
        return None
    return txt.splitlines()


def detect(path, head: bytes | None = None):
    """Админский тип файла по данным: VM-образ, REGF, TASKXML, логи, история.

    Возвращает (kind, detail): kind из VM_KINDS | 'REGF' | 'TASKXML' |
    'LOG' | 'PSHISTORY' | 'SHELLHISTORY'; detail — формат лога. Иначе (None, None).
    """
    if not os.path.isfile(path):
        return None, None
    if head is None:
        head = read_head(path, 4096)
    if head[:4] == b"regf":
        return "REGF", None
    vk = vm_kind(path, head)
    if vk:
        return vk, None
    h16 = head[:4096]
    if h16[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            h16 = head.decode("utf-16", "ignore").encode("utf-8", "ignore")
        except Exception:
            pass
    if b"<Task" in h16 and TASK_NS in h16:
        return "TASKXML", None
    lines = text_lines(path)
    if not lines:
        return None, None
    lk = log_kind(lines)
    if lk:
        return "LOG", lk
    hk = history_kind(path, lines)
    if hk:
        return hk, None
    return None, None


# ---------------------------------------------------------------- декодеры

B64_RE = re.compile(r"[A-Za-z0-9+/]{12,}={0,2}|[A-Za-z0-9_-]{16,}={0,2}")


def try_b64(s: str):
    """base64/base64url → bytes, если похоже на настоящий base64, иначе None."""
    s = s.strip().strip("'\"")
    if len(s) < 8 or not re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", s):
        return None
    pad = "=" * ((4 - len(s) % 4) % 4)
    try:
        if "-" in s or "_" in s:
            raw = base64.urlsafe_b64decode(s + pad)
        else:
            raw = base64.b64decode(s + pad, validate=True)
    except (binascii.Error, ValueError):
        return None
    return raw or None


def readable(raw: bytes):
    """bytes → str, если это текст (UTF-8 или UTF-16LE), иначе None."""
    if not raw:
        return None
    if len(raw) >= 4 and raw[1::2].count(0) >= len(raw) // 2 * 0.8:
        try:
            t = raw.decode("utf-16-le")
            if common.printable_ratio(t) >= 0.9:
                return t
        except UnicodeDecodeError:
            pass
    try:
        t = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return t if common.printable_ratio(t) >= 0.9 else None


def url_unquote_all(s: str, rounds=3) -> str:
    for _ in range(rounds):
        t = urllib.parse.unquote_plus(s)
        if t == s:
            break
        s = t
    return s


PS_ENC_RE = re.compile(
    r"(?i)(?:^|\s)[-/](?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|"
    r"encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+[\"']?([A-Za-z0-9+/=]{8,})")
FROMB64_RE = re.compile(r"(?i)FromBase64String\(\s*[\"']([A-Za-z0-9+/=]{8,})[\"']\s*\)")
ECHO_B64_RE = re.compile(r"[\"']?([A-Za-z0-9+/]{8,}={0,2})[\"']?\s*\|\s*base64\s+(?:-d|--decode|-D)")
B64_D_RE = re.compile(r"base64\s+(?:-d|--decode|-D)\s*<<<\s*[\"']?([A-Za-z0-9+/]{8,}={0,2})")
HEX_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}|(?<![0-9A-Za-z])(?:[0-9a-fA-F]{2}){8,}(?![0-9A-Za-z])")


def decode_inline(cmd: str, depth=0):
    """Найти и раскодировать вложенные payload'ы в команде.

    PowerShell -EncodedCommand (base64 UTF-16LE), FromBase64String('..'),
    `echo .. | base64 -d`, `base64 -d <<< ..`, \\x41\\x42 и hex-строки.
    Возвращает [(как, текст)], рекурсивно до 3 слоёв.
    """
    out = []

    def push(how, raw):
        t = readable(raw)
        if t and (how, t) not in out:
            out.append((how, t))
            if depth < 2:
                for how2, t2 in decode_inline(t, depth + 1):
                    out.append((f"{how} → {how2}", t2))

    for m in PS_ENC_RE.finditer(cmd):
        raw = try_b64(m.group(1))
        if raw:
            push("-EncodedCommand", raw)
    for rx, how in ((FROMB64_RE, "FromBase64String"), (ECHO_B64_RE, "base64 -d"),
                    (B64_D_RE, "base64 -d")):
        for m in rx.finditer(cmd):
            raw = try_b64(m.group(1))
            if raw:
                push(how, raw)
    for m in HEX_RE.finditer(cmd):
        h = m.group(0).replace("\\x", "")
        try:
            raw = bytes.fromhex(h)
        except ValueError:
            continue
        push("hex", raw)
    return out


# (тег, regex) — подозрительные команды Linux/Windows; общие для логов и истории
SUSPICIOUS = [
    ("download-exec", r"(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b"),
    ("download", r"\b(?:curl|wget|fetch|tftp)\b\s+\S*(?:https?|ftp)://|\b(?:curl|wget)\s+-[A-Za-z]*[oO]\b"),
    ("reverse-shell", r"/dev/tcp/|/dev/udp/|\bnc(?:at)?\b[^|;]*\s-[a-z]*e\b|\bbash\s+-i\b|"
                      r"\bmkfifo\b|\bsocat\b[^|;]*exec|\bsh\s+-i\b|pty\.spawn|"
                      r"socket\.socket\(|TCPClient\(|\bnc(?:at)?\s+-l"),
    ("netcat", r"\bnc(?:at)?\s+(?:-\w+\s+)*\d{1,3}(?:\.\d{1,3}){3}\s+\d+"),
    ("base64-decode", r"base64\s+(?:-d|--decode|-D)\b|FromBase64String|certutil\s+-decode"),
    ("chmod-exec", r"\bchmod\s+(?:[+]x|u\+s|[+]s|[0-7]*7[0-7]{2}|4[0-7]{3})\b"),
    ("inline-code", r"\b(?:python[23]?|perl|ruby|php)\s+-[A-Za-z]*[ce]\s"),
    ("persistence", r"\bcrontab\b|/etc/cron|authorized_keys|\.bashrc|/etc/rc\.local|"
                    r"systemctl\s+enable|/etc/systemd/system|schtasks\s+/create|"
                    r"New-ScheduledTask|Register-ScheduledTask|"
                    r"\\CurrentVersion\\Run|New-Service|sc(?:\.exe)?\s+create"),
    ("account", r"\b(?:useradd|adduser|usermod\s+-aG|passwd|chpasswd|visudo)\b|"
                r"/etc/sudoers|net\s+user\s+\S+\s+\S+\s+/add|net\s+localgroup\s+administrators|"
                r"New-LocalUser|Add-LocalGroupMember"),
    ("anti-forensics", r"history\s+-c|unset\s+HISTFILE|HISTFILE=/dev/null|HISTSIZE=0|"
                       r"\bshred\b|rm\s+-[a-z]*f[a-z]*\s+\S*/var/log|>\s*/var/log/|"
                       r"wevtutil\s+cl|Clear-EventLog|Remove-EventLog|vssadmin\s+delete|"
                       r"Clear-History|Remove-Item\s+\S*ConsoleHost_history|"
                       r"\btouch\s+-[a-z]*[rd]\b|\btimestomp"),
    ("defense-evasion", r"Set-MpPreference|Add-MpPreference|DisableRealtimeMonitoring|"
                        r"-ExecutionPolicy\s+Bypass|-ep\s+bypass|\s-nop\b|-w(?:indowstyle)?\s+hidden|"
                        r"\bsetenforce\s+0|ufw\s+disable|iptables\s+-F|AMSI|amsiInitFailed"),
    ("ps-exec", r"\bIEX\b|Invoke-Expression|DownloadString|DownloadFile|Net\.WebClient|"
                r"Invoke-WebRequest|\biwr\b|Start-BitsTransfer|bitsadmin\s+/transfer|"
                r"certutil\s+-urlcache|mshta\b|regsvr32\s+/s\s+/n|rundll32\b"),
    ("encoded", r"(?i)\s-e(?:nc(?:odedcommand)?)?\s+[A-Za-z0-9+/=]{16,}"),
    ("cred-dump", r"mimikatz|sekurlsa|lsadump|comsvcs\.dll.*MiniDump|procdump.*lsass|"
                  r"reg\s+save\s+hklm\\(?:sam|system|security)|ntds\.dit|/etc/shadow|"
                  r"secretsdump|hashdump|LaZagne"),
    ("recon", r"\b(?:whoami|id|uname\s+-a|hostname|ifconfig|ip\s+a|netstat|ss\s+-|ps\s+aux|"
              r"net\s+(?:user|group|localgroup)|systeminfo|tasklist|ipconfig|"
              r"Get-(?:LocalUser|Process|NetTCPConnection|ComputerInfo))\b"),
    ("exfil", r"\bscp\s|\brsync\s|\bcurl\b[^\n]*(?:-T|--upload-file|-F|-d\s*@|--data-binary\s*@)|"
              r"\bnc\b[^\n]*<\s*\S|Invoke-RestMethod[^\n]*-Method\s+Post|ftp\s+-s:|"
              r"\btar\s+[a-z]*c[a-z]*f?\s+\S+\s+/(?:etc|home|root)|\bzip\s+-r"),
    ("crypto-tool", r"\bopenssl\s+(?:enc|aes|des)|\bgpg\s+(?:-c|--symmetric|--encrypt)|\bzip\s+-P\b|"
                    r"\b7z\s+a\b.*-p|\bsteghide\b|\bxor\b"),
    ("privesc", r"\bsudo\s+-l\b|\bsudo\s+su\b|\bsu\s+-?\s*root\b|\bsudo\s+-i\b|find\s+/\s+-perm\s+-?[u4]|"
                r"getcap\s+-r|linpeas|winpeas|pspy|GTFO"),
]
SUSPICIOUS_RX = [(t, re.compile(rx, re.I)) for t, rx in SUSPICIOUS]

CRED_RX = [
    ("url-userinfo", re.compile(r"\b[a-z][a-z0-9+.-]{1,10}://([^\s/:@]{1,64}):([^\s/@]{1,128})@[^\s/]+", re.I)),
    ("password-arg", re.compile(
        r"(?:^|\s)(?:-p|--password(?:=|\s+)|-P|--pass(?:=|\s+)|-pw\s+|/p:)([^\s\"'-][^\s\"']{2,127})")),
    ("sshpass", re.compile(r"sshpass\s+-p\s*['\"]?([^\s'\"]+)")),
    ("curl-user", re.compile(r"(?:-u|--user)\s+['\"]?([^\s:'\"]+):([^\s'\"]+)")),
    ("kv-secret", re.compile(
        r"(?i)\b(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|auth|"
        r"client[_-]?secret|private[_-]?key)\b\s*[=:]\s*[\"']?([^\s\"'&;]{3,128})")),
    ("net-user", re.compile(r"(?i)net\s+user\s+(\S+)\s+(\S+)\s+/add")),
    ("securestring", re.compile(r"(?i)ConvertTo-SecureString\s+[\"']([^\"']+)[\"']\s+-AsPlainText")),
    ("archive-pass", re.compile(r"\b(?:zip|unzip|7z|7za|rar|unrar)\b[^\n]*?\s-[Pp]\s*['\"]?([^\s'\"-][^\s'\"]*)")),
    ("basic-auth", re.compile(r"(?i)Authorization:\s*Basic\s+([A-Za-z0-9+/=]{8,})")),
]


def find_credentials(text: str):
    """[(тип, значение)] — пароли/токены в командах и URL."""
    out = []
    for tag, rx in CRED_RX:
        for m in rx.finditer(text):
            vals = [g for g in m.groups() if g]
            if not vals:
                continue
            val = ":".join(vals)
            if tag == "password-arg" and vals[0].startswith(("$", "%")):
                continue
            if tag == "basic-auth":
                raw = try_b64(vals[0])
                t = readable(raw) if raw else None
                if t:
                    val = t
            if (tag, val) not in out:
                out.append((tag, val))
    return out


def analyze_command(cmd: str):
    """Разбор одной команды: (теги подозрительности, креды, декодированное)."""
    tags = [t for t, rx in SUSPICIOUS_RX if rx.search(cmd)]
    creds = find_credentials(cmd)
    decoded = decode_inline(cmd)
    for _how, t in decoded:
        for t2, rx in SUSPICIOUS_RX:
            if rx.search(t) and t2 not in tags:
                tags.append(t2)
        for c in find_credentials(t):
            if c not in creds:
                creds.append(c)
    return tags, creds, decoded


def flags_in(*texts):
    """Флаги из нескольких текстов (с учётом URL-кодирования), без дублей."""
    out = []
    for t in texts:
        if not t:
            continue
        if isinstance(t, str):
            variants = [t]
            u = url_unquote_all(t)
            if u != t:
                variants.append(u)
            for v in variants:
                for f in common.find_flags(v.encode("utf-8", "replace")):
                    if f not in out:
                        out.append(f)
        else:
            for f in common.find_flags(t):
                if f not in out:
                    out.append(f)
    return out


def real_flags(flags):
    stub = ("missing", "placeholder", "dummy", "fake")
    return [f for f in flags if not any(w in f.lower() for w in stub)]


def print_flags(flags, where=""):
    """Флаги в формате кита: строка «[!!!] ФЛАГ:» (solve ловит именно их)."""
    shown = []
    for f in dict.fromkeys(flags):
        if any(w in f.lower() for w in ("missing", "placeholder", "dummy", "fake")):
            print(f"[!] заглушка, не флаг: {f}" + (f"  ({where})" if where else ""))
            continue
        print(f"[!!!] ФЛАГ: {f}" + (f"  ({where})" if where else ""))
        shown.append(f)
    return shown


def tool_path(rel):
    """Путь к инструменту кита, если файл существует (forensic/disk_image.py …)."""
    p = os.path.join(ROOT, rel)
    return p if os.path.exists(p) else None
