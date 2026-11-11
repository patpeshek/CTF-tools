#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
log_analyze.py — системные логи: аномалии, таймлайн, креды, флаги.

  python log_analyze.py auth.log                  # входы/брутфорс/sudo/su/новые юзеры/cron
  python log_analyze.py access.log --top 15       # nginx/apache: атаки, сканеры, всплески 4xx/5xx
  python log_analyze.py journal.json              # journalctl -o json / -o export
  python log_analyze.py audit.log                 # auditd: EXECVE/USER_CMD (hex раскодируется)
  python log_analyze.py .bash_history             # bash/zsh/PowerShell: подозрительное, креды
  python log_analyze.py var/log --timeline        # папка: все логи + общая хронология
  python log_analyze.py a.log b.log --timeline --year 2024

Формат определяется по содержимому (не по имени). .gz-ротация читается сама.
Раскодирует: URL (многократно), base64/hex в параметрах и командах,
PowerShell -EncodedCommand (UTF-16LE), hex-аргументы auditd. Восстанавливает
слепую SQLi (ASCII(SUBSTRING(..,N,1))>X) по размерам ответов. Флаги ищутся и
в сыром тексте, и в раскодированном.
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
import json
import os
import re
import statistics
import sys
import urllib.parse
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import adminlib  # noqa: E402
import common  # noqa: E402

YEAR = dt.datetime.now().year

SYSLOG_LINE = re.compile(
    r"^(?:<\d+>)?(?P<ts>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d|"
    r"\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?)\s+(?P<host>\S+)\s+"
    r"(?P<prog>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$")
ACCESS_LINE = re.compile(
    r'^(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<req>(?:[^"\\]|\\.)*)" (?P<status>\d{3}) (?P<size>\d+|-)'
    r'(?: "(?P<ref>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)")?')
AUDIT_LINE = re.compile(r"^type=(?P<type>\S+) msg=audit\((?P<ts>\d+\.\d+):(?P<serial>\d+)\):\s?(?P<body>.*)")
NGINX_ERR = re.compile(r"^(?P<ts>\d{4}/\d\d/\d\d \d\d:\d\d:\d\d) \[(?P<lvl>\w+)\] (?P<msg>.*)")

# --- auth-события (sshd/sudo/su/useradd/cron/…)
R_FAIL = re.compile(r"Failed (?:password|publickey|none|keyboard-interactive/pam) for "
                    r"(?P<inv>invalid user )?(?P<user>\S*) from (?P<ip>[\d.:a-fA-F]+)")
R_ACCEPT = re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")
R_INVALID = re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>[\d.:a-fA-F]+)")
R_PAMFAIL = re.compile(r"authentication failure;.*?rhost=(?P<ip>\S*)(?:\s+user=(?P<user>\S+))?")
R_SCAN = re.compile(r"Did not receive identification string from (?P<ip>\S+)|"
                    r"Bad protocol version identification .* from (?P<ip2>\S+)|"
                    r"Unable to negotiate with (?P<ip3>\S+)")
R_SUDO = re.compile(r"^\s*(?P<user>\S+) : (?:(?P<fail>.*?) ; )?TTY=(?P<tty>\S+) ; PWD=(?P<pwd>.*?) ; "
                    r"USER=(?P<runas>\S+) ;(?: [A-Z]+=\S+ ;)* COMMAND=(?P<cmd>.*)$")
R_SUDO_FAIL = re.compile(r"(?P<user>\S+) : (?:\d+ incorrect password attempts?|user NOT in sudoers|"
                         r"command not allowed)")
R_SU_OPEN = re.compile(r"session opened for user (?P<to>\S+?)(?:\(uid=\d+\))? by (?P<by>\S*?)(?:\(uid=\d+\))?$")
R_SU_OK = re.compile(r"(?:Successful su for (?P<to>\S+) by (?P<by>\S+))|(?:\(to (?P<to2>\S+)\) (?P<by2>\S+) on)")
R_SU_FAIL = re.compile(r"FAILED su for (?P<to>\S+) by (?P<by>\S+)|pam_authenticate: Authentication failure")
R_USERADD = re.compile(r"new user: name=(?P<name>[^,]+), UID=(?P<uid>\d+), GID=(?P<gid>\d+)"
                       r"(?:, home=(?P<home>[^,]+), shell=(?P<shell>[^,\s]+))?")
R_GROUPADD = re.compile(r"new group: name=(?P<name>[^,]+), GID=(?P<gid>\d+)")
R_USERMOD = re.compile(r"add '(?P<user>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'")
R_PASSWD = re.compile(r"password changed for (?P<user>\S+)")
R_USERDEL = re.compile(r"delete user '(?P<user>[^']+)'")
R_CRON = re.compile(r"\((?P<user>[^)]+)\) CMD \((?P<cmd>.*)\)\s*$")
R_KERNEL = re.compile(r"entered promiscuous mode|segfault at|Out of memory: Kill")
PRIV_GROUPS = {"sudo", "wheel", "admin", "adm", "root", "docker", "lxd", "disk", "shadow",
               "administrators", "libvirt"}

# --- веб-атаки (по раскодированному запросу)
WEB_ATTACKS = [
    ("sqli", r"union(?:\s|/\*.*?\*/|\+)+(?:all(?:\s|\+)+)?select|'\s*(?:or|and)\s*'?\d|"
             r"\b(?:or|and)\s+\d+\s*=\s*\d+|sleep\s*\(\s*\d|benchmark\s*\(|waitfor\s+delay|"
             r"information_schema|load_file\s*\(|into\s+(?:out|dump)file|extractvalue\s*\(|"
             r"updatexml\s*\(|(?:ascii|ord)\s*\(\s*(?:substr|mid)|'\s*--|'\s*#|;\s*drop\s+table"),
    ("lfi/traversal", r"\.\./|\.\.\\|/etc/(?:passwd|shadow|hosts)|/proc/self/|php://|file://|"
                      r"data://|expect://|zip://|phar://|c:\\windows|win\.ini|boot\.ini"),
    ("xss", r"<\s*script|javascript:|onerror\s*=|onload\s*=|alert\s*\(|document\.cookie|<\s*svg"),
    ("rce/cmdi", r"[;|&`]\s*(?:id|whoami|uname|cat|ls|wget|curl|nc|bash|sh|ping)\b|\$\(|"
                 r"\bcmd=|\bexec=|system\s*\(|passthru|shell_exec|/bin/(?:ba)?sh|powershell|"
                 r"nc\s+-e"),
    ("ssti", r"\{\{.*?\}\}|\$\{\s*\d+\s*\*|<%=|\{%.*?%\}|__class__|__globals__"),
    ("log4shell", r"\$\{jndi:"),
    ("shellshock", r"\(\)\s*\{\s*:\s*;\s*\}\s*;"),
    ("webshell", r"/(?:shell|cmd|c99|r57|wso|b374k|webshell)\w*\.(?:php|aspx?|jsp)|\.php\?(?:cmd|c|e|x)="),
    ("sensitive-file", r"/\.(?:env|git|svn|htpasswd|DS_Store|ssh)|\.(?:bak|old|sql|swp|orig|save|"
                       r"tar|tgz|zip|7z|gz|config|ini|log)(?:\?|$)|wp-config|/server-status|"
                       r"/phpinfo|/actuator|/console|/\.aws"),
]
WEB_ATTACKS_RX = [(t, re.compile(rx, re.I)) for t, rx in WEB_ATTACKS]
SCANNER_UA = re.compile(r"(?i)nikto|sqlmap|nmap|masscan|dirbuster|gobuster|wfuzz|ffuf|feroxbuster|"
                        r"nuclei|acunetix|nessus|openvas|w3af|zgrab|hydra|whatweb|wpscan|burp|"
                        r"dirsearch|python-requests|go-http-client|curl/|wget/|libwww|zmeu|"
                        r"censys|shodan|jndi")
BLIND_NUM = re.compile(
    r"(?i)(?:ascii|ord|unicode)\s*\(\s*(?:substr(?:ing)?|mid)\s*\((?P<expr>.+?),\s*(?P<pos>\d+)\s*,\s*1\s*\)\s*\)"
    r"\s*(?P<op>!=|<>|>=|<=|=|>|<)\s*(?P<val>\d+)")
BLIND_CHR = re.compile(
    r"(?i)(?:substr(?:ing)?|mid)\s*\((?P<expr>.+?),\s*(?P<pos>\d+)\s*,\s*1\s*\)\s*"
    r"(?P<op>!=|<>|=|>|<)\s*(?:'(?P<ch>[^']{1,2})'|0x(?P<hx>[0-9a-f]{2})\b|char\((?P<cv>\d+)\))")


def parse_ts_syslog(s, year):
    s = s.strip()
    if s[:4].isdigit():
        try:
            t = dt.datetime.fromisoformat(s.replace(" ", "T", 1).replace("Z", "+00:00"))
            return t.replace(tzinfo=None)
        except ValueError:
            return None
    try:
        return dt.datetime.strptime(f"{year} {s}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None


def parse_ts_access(s):
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S"):
        try:
            return dt.datetime.strptime(s, fmt).replace(tzinfo=None)
        except ValueError:
            continue
    return None


def fmt_ts(t):
    return t.strftime("%Y-%m-%d %H:%M:%S") if t else "—" * 2


def unesc(s):
    return (s or "").replace('\\"', '"').replace("\\x22", '"')


# ---------------------------------------------------------------- чтение

class Report:
    """Копилка находок по всем файлам: секции, таймлайн, флаги."""

    def __init__(self, args):
        self.args = args
        self.timeline = []          # (ts, файл, тег, текст)
        self.flags = []
        self.decoded = []           # (источник, как, текст)
        self.creds = []             # (источник, тип, значение)

    def event(self, ts, src, tag, text):
        self.timeline.append((ts, src, tag, text))

    def add_flags(self, flags, where):
        for f in flags:
            if f not in [x for x, _ in self.flags]:
                self.flags.append((f, where))

    def add_decoded(self, src, how, text):
        key = (how, text)
        if key in {(h, t) for _, h, t in self.decoded}:
            return
        self.decoded.append((src, how, text))
        self.add_flags(adminlib.flags_in(text), f"{src}: {how}")

    def add_cred(self, src, kind, val):
        if (kind, val) in {(k, v) for _, k, v in self.creds}:
            return
        self.creds.append((src, kind, val))


def load_lines(path):
    try:
        return adminlib.read_text(path).splitlines()
    except (OSError, ValueError) as e:
        print(f"[-] {path}: {e}")
        return []


def syslog_records(lines, year):
    out = []
    for i, ln in enumerate(lines, 1):
        m = SYSLOG_LINE.match(ln)
        if not m:
            continue
        out.append({"ts": parse_ts_syslog(m.group("ts"), year), "host": m.group("host"),
                    "prog": m.group("prog"), "pid": m.group("pid"), "msg": m.group("msg"),
                    "line": i, "raw": ln})
    return out


def _jmsg(v):
    if isinstance(v, list):
        try:
            return bytes(v).decode("utf-8", "replace")
        except (TypeError, ValueError):
            return str(v)
    return "" if v is None else str(v)


def journal_records(lines, kind):
    out = []
    entries = []
    if kind == "journal_json":
        for i, ln in enumerate(lines, 1):
            ln = ln.strip()
            if not ln.startswith("{"):
                continue
            try:
                entries.append((i, json.loads(ln)))
            except ValueError:
                continue
    else:
        cur, start = {}, 1
        for i, ln in enumerate(lines + [""], 1):
            if not ln.strip():
                if cur:
                    entries.append((start, cur))
                cur, start = {}, i + 1
                continue
            if "=" in ln:
                k, v = ln.split("=", 1)
                cur[k] = v
    for i, e in entries:
        ts = None
        rt = e.get("__REALTIME_TIMESTAMP")
        if rt and str(rt).isdigit():
            ts = dt.datetime.fromtimestamp(int(rt) / 1e6, dt.timezone.utc).replace(tzinfo=None)
        prog = e.get("SYSLOG_IDENTIFIER") or e.get("_COMM") or "?"
        out.append({"ts": ts, "host": e.get("_HOSTNAME", ""), "prog": str(prog),
                    "pid": e.get("_PID"), "msg": _jmsg(e.get("MESSAGE")), "line": i,
                    "raw": json.dumps(e, ensure_ascii=False)[:400],
                    "cmdline": e.get("_CMDLINE")})
    return out


def audit_records(lines):
    """auditd → syslog-подобные записи: команды (EXECVE/USER_CMD/PROCTITLE) и входы."""
    out, by_serial = [], {}
    for i, ln in enumerate(lines, 1):
        m = AUDIT_LINE.match(ln)
        if not m:
            continue
        ts = dt.datetime.fromtimestamp(float(m.group("ts")), dt.timezone.utc).replace(tzinfo=None)
        body, typ, serial = m.group("body"), m.group("type"), m.group("serial")
        kv = dict(re.findall(r'(\w+)=("[^"]*"|\S+)', body))

        def val(k):
            v = kv.get(k, "")
            if v.startswith('"'):
                return v.strip('"')
            if re.fullmatch(r"(?:[0-9A-F]{2})+", v):
                try:
                    return bytes.fromhex(v).replace(b"\x00", b" ").decode("utf-8", "replace")
                except ValueError:
                    return v
            return v

        if typ == "EXECVE":
            argc = int(kv.get("argc", "0") or 0)
            cmd = " ".join(val(f"a{j}") for j in range(argc))
            by_serial[serial] = {"ts": ts, "host": "", "prog": "audit:EXECVE", "pid": None,
                                 "msg": cmd, "line": i, "raw": ln, "command": cmd}
        elif typ == "PROCTITLE" and serial not in by_serial:
            cmd = val("proctitle")
            by_serial[serial] = {"ts": ts, "host": "", "prog": "audit:PROCTITLE", "pid": None,
                                 "msg": cmd, "line": i, "raw": ln, "command": cmd}
        elif typ == "USER_CMD":
            cmd = val("cmd")
            out.append({"ts": ts, "host": "", "prog": "sudo", "pid": None,
                        "msg": f"{val('acct') or kv.get('auid', '?')} : TTY={kv.get('terminal', '?')} ; "
                               f"PWD={val('cwd')} ; USER=root ; COMMAND={cmd}",
                        "line": i, "raw": ln})
        elif typ in ("USER_AUTH", "USER_LOGIN", "USER_ERR") and "res=failed" in body:
            out.append({"ts": ts, "host": "", "prog": "sshd", "pid": None,
                        "msg": f"Failed password for {val('acct') or '?'} from "
                               f"{val('addr') or val('hostname') or '?'} port 0 ssh2",
                        "line": i, "raw": ln})
        elif typ in ("USER_LOGIN", "USER_AUTH") and "res=success" in body and val("addr") not in ("", "?"):
            out.append({"ts": ts, "host": "", "prog": "sshd", "pid": None,
                        "msg": f"Accepted password for {val('acct') or '?'} from {val('addr')} port 0",
                        "line": i, "raw": ln})
        elif typ == "ADD_USER":
            out.append({"ts": ts, "host": "", "prog": "useradd", "pid": None,
                        "msg": f"new user: name={val('acct') or kv.get('id', '?')}, UID={kv.get('id', '?')}, GID=?",
                        "line": i, "raw": ln})
    out.extend(by_serial.values())
    out.sort(key=lambda r: (r["ts"] or dt.datetime.min, r["line"]))
    return out


def history_records(lines):
    """bash (#ts), zsh (: ts:0;cmd), PowerShell/обычная история → [(ts, cmd, №)]."""
    out, pending_ts = [], None
    for i, ln in enumerate(lines, 1):
        s = ln.rstrip("\r\n")
        if not s.strip():
            continue
        m = re.match(r"^#(\d{9,11})\s*$", s)
        if m:
            pending_ts = dt.datetime.fromtimestamp(int(m.group(1)), dt.timezone.utc).replace(tzinfo=None)
            continue
        m = re.match(r"^: (\d{9,11}):\d+;(.*)$", s)
        if m:
            ts = dt.datetime.fromtimestamp(int(m.group(1)), dt.timezone.utc).replace(tzinfo=None)
            out.append((ts, m.group(2), i))
            continue
        out.append((pending_ts, s, i))
        pending_ts = None
    return out


# ---------------------------------------------------------------- анализ

def analyze_command_into(rep, src, ts, cmd, tag_prefix="cmd"):
    tags, creds, decoded = adminlib.analyze_command(cmd)
    for kind, val in creds:
        rep.add_cred(src, kind, val)
    for how, text in decoded:
        rep.add_decoded(src, how, text)
    rep.add_flags(adminlib.flags_in(cmd), src)
    if tags:
        rep.event(ts, src, f"{tag_prefix}:{','.join(tags[:3])}", cmd[:200])
    return tags, creds, decoded


def analyze_auth(recs, src, rep):
    a = rep.args
    fails, fails_user, invalid = Counter(), Counter(), Counter()
    fail_times = defaultdict(list)
    accepted, sudo, sudo_fail, su, users, groups, pw, cron, scan, kern = ([] for _ in range(10))
    other_susp, execs = [], []
    for r in recs:
        msg, ts, prog = r["msg"], r["ts"], r["prog"].lower()
        rep.add_flags(adminlib.flags_in(msg), f"{src}:{r['line']}")
        m = R_FAIL.search(msg)
        if m:
            ip, user = m.group("ip"), m.group("user")
            fails[ip] += 1
            fails_user[user + (" (invalid)" if m.group("inv") else "")] += 1
            fail_times[ip].append((ts, user))
            continue
        m = R_ACCEPT.search(msg)
        if m:
            accepted.append((ts, m.group("user"), m.group("ip"), m.group("method"), r["line"]))
            rep.event(ts, src, "login-ok", f"{m.group('user')} from {m.group('ip')} ({m.group('method')})")
            continue
        m = R_INVALID.search(msg)
        if m:
            invalid[m.group("user")] += 1
            continue
        m = R_SCAN.search(msg)
        if m:
            scan.append(m.group("ip") or m.group("ip2") or m.group("ip3"))
            continue
        if prog == "sudo":
            m = R_SUDO.search(msg)
            if m:
                cmd = m.group("cmd")
                tags, _c, _d = analyze_command_into(rep, src, ts, cmd, "sudo")
                sudo.append((ts, m.group("user"), m.group("runas"), cmd, tags, bool(m.group("fail"))))
                if not tags:
                    rep.event(ts, src, "sudo", f"{m.group('user')} → {m.group('runas')}: {cmd[:160]}")
                continue
            m = R_SUDO_FAIL.search(msg)
            if m:
                sudo_fail.append((ts, m.group("user"), msg))
                rep.event(ts, src, "sudo-fail", msg[:160])
                continue
        if prog in ("su", "su-l") or "su:" in msg or "(su" in msg:
            m = R_SU_FAIL.search(msg)
            if m:
                su.append((ts, "FAIL", msg))
                rep.event(ts, src, "su-fail", msg[:160])
                continue
            m = R_SU_OPEN.search(msg) or R_SU_OK.search(msg)
            if m:
                d = m.groupdict()
                to = d.get("to") or d.get("to2")
                by = d.get("by") or d.get("by2")
                su.append((ts, "ok", f"{by} → {to}"))
                rep.event(ts, src, "su", f"{by} → {to}")
                continue
        m = R_USERADD.search(msg)
        if m:
            users.append((ts, m.group("name"), int(m.group("uid")), m.group("shell") or "?"))
            rep.event(ts, src, "useradd", f"{m.group('name')} uid={m.group('uid')}")
            continue
        m = R_GROUPADD.search(msg)
        if m:
            groups.append((ts, f"new group {m.group('name')} gid={m.group('gid')}"))
            continue
        m = R_USERMOD.search(msg)
        if m:
            groups.append((ts, f"{m.group('user')} → group {m.group('group')}"))
            rep.event(ts, src, "group-add", f"{m.group('user')} → {m.group('group')}")
            continue
        m = R_PASSWD.search(msg) or R_USERDEL.search(msg)
        if m:
            pw.append((ts, msg))
            rep.event(ts, src, "account", msg[:160])
            continue
        if prog in ("cron", "crond") or "CMD (" in msg:
            m = R_CRON.search(msg)
            if m:
                cron.append((ts, m.group("user"), m.group("cmd")))
                analyze_command_into(rep, src, ts, m.group("cmd"), "cron")
                continue
        if R_KERNEL.search(msg):
            kern.append((ts, msg))
            rep.event(ts, src, "kernel", msg[:160])
            continue
        if r.get("command"):
            tags, _c, _d = analyze_command_into(rep, src, ts, r["command"], "exec")
            execs.append((ts, r["command"], tags))
            if not tags:
                rep.event(ts, src, "exec", r["command"][:200])
            continue
        tags, _c, _d = adminlib.analyze_command(msg)
        strong = [t for t in tags if t not in ("recon",)]
        if strong:
            analyze_command_into(rep, src, ts, msg, prog)
            other_susp.append((ts, prog, msg, strong))
        else:
            for how, text in _d:
                rep.add_decoded(src, how, text)

    total_fail = sum(fails.values())
    print(f"\n[+] auth/syslog {src}: записей {len(recs)}, неудачных входов {total_fail}, "
          f"успешных {len(accepted)}")
    if fails:
        print("    неудачи по IP: " + ", ".join(f"{ip}={n}" for ip, n in fails.most_common(a.top)))
        print("    по логину:    " + ", ".join(f"{u}={n}" for u, n in fails_user.most_common(a.top)))
    if invalid:
        print("    несуществующие юзеры: " + ", ".join(f"{u}={n}" for u, n in invalid.most_common(a.top)))
    # всплески: >= brute неудач с одного IP за window секунд
    for ip, items in sorted(fail_times.items(), key=lambda kv: -len(kv[1])):
        times = [t for t, _ in items if t]
        best, best_start = 0, None
        j = 0
        for i in range(len(times)):
            while times[i] - times[j] > dt.timedelta(seconds=a.window):
                j += 1
            if i - j + 1 > best:
                best, best_start = i - j + 1, times[j]
        if best >= a.brute:
            print(f"[!] брутфорс: {ip} — {best} неудач за {a.window} с (с {fmt_ts(best_start)}), "
                  f"логины: {', '.join(sorted({u for _, u in items})[:6])}")
            rep.event(best_start, src, "bruteforce", f"{ip}: {best} неудач за {a.window} с")
    for ts, user, ip, method, _ln in accepted:
        before = [t for t, _ in fail_times.get(ip, []) if t is None or ts is None or t <= ts]
        mark = "[!!]" if len(before) >= a.brute else "[+]"
        extra = f"  ← {len(before)} неудач до входа с этого IP: брутфорс удался" if before else ""
        print(f"{mark} вход: {fmt_ts(ts)} {user} from {ip} ({method}){extra}")
    if scan:
        c = Counter(scan)
        print("[!] сканирование SSH (нет banner/плохой протокол): "
              + ", ".join(f"{ip}={n}" for ip, n in c.most_common(a.top)))
    for ts, user, runas, cmd, tags, failed in sudo:
        mark = "[!]" if tags else "   "
        st = " (ОТКАЗ)" if failed else ""
        print(f"{mark} sudo {fmt_ts(ts)} {user} → {runas}{st}: {cmd[:220]}"
              + (f"   [{', '.join(tags)}]" if tags else ""))
    for ts, user, msg in sudo_fail:
        print(f"[!] sudo отказ {fmt_ts(ts)}: {msg[:200]}")
    for ts, st, txt in su:
        print(f"{'[!]' if st == 'FAIL' else '   '} su {fmt_ts(ts)} {txt[:200]}")
    for ts, name, uid, shell in users:
        mark = "[!!]" if uid == 0 else "[!]"
        why = "  ← UID 0 = второй root!" if uid == 0 else ""
        print(f"{mark} новый пользователь {fmt_ts(ts)}: {name} uid={uid} shell={shell}{why}")
    for ts, txt in groups:
        grp = txt.rsplit(" ", 1)[-1]
        print(f"{'[!]' if grp in PRIV_GROUPS else '   '} группы {fmt_ts(ts)}: {txt}")
    for ts, msg in pw:
        print(f"[!] учётки {fmt_ts(ts)}: {msg[:200]}")
    if cron:
        uniq = {}
        for ts, user, cmd in cron:
            uniq.setdefault((user, cmd), ts)
        print(f"[+] cron: {len(cron)} запусков, уникальных команд {len(uniq)}")
        for (user, cmd), ts in list(uniq.items())[:a.top]:
            tags = adminlib.analyze_command(cmd)[0]
            print(f"{'[!]' if tags else '   '} cron ({user}) {cmd[:200]}"
                  + (f"   [{', '.join(tags)}]" if tags else ""))
    for ts, msg in kern[:a.top]:
        print(f"[!] kernel {fmt_ts(ts)}: {msg[:200]}")
    if execs:
        uniq = list(dict.fromkeys(c for _t, c, _g in execs))
        print(f"[+] выполненные команды (auditd): {len(execs)}, уникальных {len(uniq)}")
        tags_of = {c: g for _t, c, g in execs}
        for c in uniq[:a.top * 3]:
            g = tags_of[c]
            print(f"{'[!]' if g else '   '} exec {c[:220]}" + (f"   [{', '.join(g)}]" if g else ""))
    if other_susp:
        print("[!] подозрительные команды/сообщения:")
        for ts, prog, msg, tags in other_susp[:a.top * 2]:
            print(f"    {fmt_ts(ts)} {prog}: {msg[:200]}   [{', '.join(tags)}]")


def _cluster_sizes(items):
    """Размер ответа → номер кластера (true/false у слепой SQLi), по наибольшему разрыву."""
    sizes = sorted({s for s in items})
    if len(sizes) <= 2:
        return {s: i for i, s in enumerate(sizes)}
    gaps = [(sizes[i + 1] - sizes[i], i) for i in range(len(sizes) - 1)]
    _g, cut = max(gaps)
    return {s: (0 if i <= cut else 1) for i, s in enumerate(sizes)}


def blind_sqli(reqs):
    """[(выражение, восстановленная строка)] из ASCII(SUBSTRING(expr,N,1))>X и т.п."""
    groups = defaultdict(list)
    for dec, status, size in reqs:
        for m in BLIND_NUM.finditer(dec):
            groups[re.sub(r"\s+", " ", m.group("expr").strip())].append(
                (int(m.group("pos")), m.group("op"), int(m.group("val")), status, size))
        for m in BLIND_CHR.finditer(dec):
            if m.group("ch") is not None:
                v = ord(m.group("ch")[0])
            elif m.group("hx"):
                v = int(m.group("hx"), 16)
            else:
                v = int(m.group("cv"))
            groups[re.sub(r"\s+", " ", m.group("expr").strip())].append(
                (int(m.group("pos")), m.group("op"), v, status, size))
    out = []
    for expr, items in groups.items():
        cl = _cluster_sizes([s for *_x, s in items])
        sigs = sorted({(st, cl[s]) for *_x, st, s in items})
        best = None
        for true_sig in sigs:
            chars = {}
            for pos in sorted({p for p, *_r in items}):
                lo, hi, eq, ne = 0, 255, None, set()
                for p, op, v, st, s in items:
                    if p != pos:
                        continue
                    t = (st, cl[s]) == true_sig
                    if op == ">":
                        lo, hi = (max(lo, v + 1), hi) if t else (lo, min(hi, v))
                    elif op == ">=":
                        lo, hi = (max(lo, v), hi) if t else (lo, min(hi, v - 1))
                    elif op == "<":
                        lo, hi = (lo, min(hi, v - 1)) if t else (max(lo, v), hi)
                    elif op == "<=":
                        lo, hi = (lo, min(hi, v)) if t else (max(lo, v + 1), hi)
                    elif op == "=":
                        if t:
                            eq = v
                        else:
                            ne.add(v)
                    elif op in ("!=", "<>"):
                        if t:
                            ne.add(v)
                        else:
                            eq = v
                if eq is not None:
                    chars[pos] = eq
                elif lo == hi or (hi - lo == 1 and hi in ne):
                    chars[pos] = lo
            if not chars:
                continue
            s = "".join(chr(chars[p]) if p in chars else "?" for p in range(1, max(chars) + 1))
            score = sum(32 <= ord(c) < 127 and c != "?" for c in s)
            if best is None or score > best[0]:
                best = (score, s)
        if best and best[0] >= 2:
            out.append((expr, best[1].rstrip("\x00")))
    return out


def analyze_access(lines, src, rep):
    a = rep.args
    n = 0
    ips, status, paths, uas, users = Counter(), Counter(), Counter(), Counter(), Counter()
    err_min = Counter()
    err_min_ip = defaultdict(Counter)
    attacks = defaultdict(list)
    scanners = Counter()
    notfound = defaultdict(set)
    blind = []
    params = defaultdict(list)       # (путь, параметр) → значения по порядку
    decoded_params = []
    burst = defaultdict(lambda: [0, None])
    for i, ln in enumerate(lines, 1):
        m = ACCESS_LINE.match(ln)
        if not m:
            continue
        n += 1
        ip, st = m.group("ip"), int(m.group("status"))
        size = 0 if m.group("size") == "-" else int(m.group("size"))
        ts = parse_ts_access(m.group("ts"))
        req, ua, ref = unesc(m.group("req")), unesc(m.group("ua")), unesc(m.group("ref"))
        parts = req.split(" ")
        method = parts[0] if len(parts) >= 2 else "?"
        target = parts[1] if len(parts) >= 2 else req
        dec = adminlib.url_unquote_all(target)
        ips[ip] += 1
        status[st] += 1
        paths[urllib.parse.urlsplit(target).path] += 1
        if ua:
            uas[ua] += 1
        if m.group("user") not in ("-", ""):
            users[m.group("user")] += 1
        if st >= 400 and ts:
            k = ts.replace(second=0)
            err_min[k] += 1
            err_min_ip[k][ip] += 1
        if st == 404:
            notfound[ip].add(target)
        if ua and SCANNER_UA.search(ua):
            scanners[(ip, SCANNER_UA.search(ua).group(0).lower())] += 1
        hit = False
        for tag, rx in WEB_ATTACKS_RX:
            if rx.search(dec) or (tag in ("log4shell", "shellshock", "xss", "sqli")
                                  and (rx.search(ua) or rx.search(ref))):
                if tag == "sensitive-file" and st >= 400:
                    continue
                attacks[tag].append((ts, ip, st, size, f"{method} {dec}"[:240]))
                hit = True
        if BLIND_NUM.search(dec) or BLIND_CHR.search(dec):
            blind.append((dec, st, size))
        if hit:
            key = (ip, tuple(t for t, rx in WEB_ATTACKS_RX if rx.search(dec)))
            burst[key][0] += 1
            burst[key][1] = ts
            if burst[key][0] <= 3:   # в таймлайн — первые 3, остальное сводкой
                rep.event(ts, src, "web-attack", f"{ip} {st} {method} {dec[:160]}")
        rep.add_flags(adminlib.flags_in(ln, dec, ua, ref), f"{src}:{i}")
        for kind, val in adminlib.find_credentials(dec):
            if kind in ("kv-secret", "url-userinfo", "basic-auth"):
                rep.add_cred(f"{src}:{i}", kind, val)
        query = urllib.parse.urlsplit(target).query
        for k, v in urllib.parse.parse_qsl(query, keep_blank_values=True):
            v2 = adminlib.url_unquote_all(v)
            params[(urllib.parse.urlsplit(target).path, k)].append(v2)
            raw = adminlib.try_b64(v2)
            txt = adminlib.readable(raw) if raw and len(v2) >= 8 else None
            if not txt and re.fullmatch(r"(?:[0-9a-fA-F]{2}){4,}", v2):
                txt = adminlib.readable(bytes.fromhex(v2))
            if txt:
                decoded_params.append((ip, k, v2, txt))
                rep.add_decoded(f"{src}:{i}", f"параметр {k}", txt)
        for how, text in adminlib.decode_inline(dec):
            rep.add_decoded(f"{src}:{i}", how, text)

    for (ip, tags), (cnt, last) in burst.items():
        if cnt > 3:
            rep.event(last, src, "web-attack",
                      f"{ip}: ещё {cnt - 3} запросов [{','.join(tags)}] до {fmt_ts(last)}")
    print(f"\n[+] web {src}: запросов {n}, IP {len(ips)}, статусы: "
          + ", ".join(f"{k}={v}" for k, v in sorted(status.items())))
    print("    топ IP: " + ", ".join(f"{ip}={c}" for ip, c in ips.most_common(a.top)))
    print("    топ путей: " + ", ".join(f"{p}={c}" for p, c in paths.most_common(min(a.top, 10))))
    if users:
        print("    HTTP-auth юзеры: " + ", ".join(f"{u}={c}" for u, c in users.most_common(a.top)))
    if err_min:
        vals = list(err_min.values())
        mean = statistics.mean(vals)
        sd = statistics.pstdev(vals) if len(vals) > 1 else 0
        thr = max(10, mean + 3 * sd)
        spikes = [(k, c) for k, c in err_min.items() if c >= thr]
        for k, c in sorted(spikes, key=lambda kc: -kc[1])[:5]:
            ip, ic = err_min_ip[k].most_common(1)[0]
            print(f"[!] всплеск 4xx/5xx: {fmt_ts(k)} — {c} ошибок/мин (основной {ip}: {ic})")
            rep.event(k, src, "error-spike", f"{c} ошибок/мин, {ip}")
    for ip, miss in sorted(notfound.items(), key=lambda kv: -len(kv[1])):
        if len(miss) >= 20:
            print(f"[!] перебор путей: {ip} — {len(miss)} разных 404")
    if scanners:
        print("[!] сканеры по User-Agent: "
              + ", ".join(f"{ip} ({tool})={c}" for (ip, tool), c in scanners.most_common(a.top)))
    for tag, items in sorted(attacks.items(), key=lambda kv: -len(kv[1])):
        ok = sum(1 for _t, _ip, st, _s, _r in items if 200 <= st < 400)
        print(f"[!] атака {tag}: {len(items)} запросов (успешных 2xx/3xx: {ok}), "
              f"IP: {', '.join(sorted({ip for _t, ip, *_r in items})[:5])}")
        for ts, ip, st, size, r in items[:a.examples]:
            print(f"      {fmt_ts(ts)} {ip} {st} {size}b  {r}")
    for expr, s in blind_sqli(blind):
        print(f"[!!] слепая SQLi восстановлена: {s!r}")
        print(f"      выражение: {expr[:160]}")
        rep.add_decoded(src, "слепая SQLi", s)
    seen_dp = set()
    shown = 0
    for ip, k, v, txt in decoded_params:
        if (k, txt) in seen_dp:
            continue
        seen_dp.add((k, txt))
        if shown == 0:
            print("[+] раскодированные параметры (base64/hex):")
        if shown < a.top:
            print(f"      {ip} {k}={v[:60]} → {txt[:160]!r}")
        shown += 1
    # склейка параметра: по одному символу за запрос
    for (path, k), vals in params.items():
        if len(vals) >= 6 and all(len(v) <= 3 for v in vals):
            joined = "".join(vals)
            if adminlib.flags_in(joined) or common.printable_ratio(joined) > 0.95:
                print(f"[+] склейка {path}?{k}= по порядку: {joined[:200]!r}")
                rep.add_decoded(src, f"склейка {k}", joined)


def analyze_history(hist, src, rep, kind):
    a = rep.args
    print(f"\n[+] история {kind} {src}: команд {len(hist)}")
    cnt = Counter()
    for ts, cmd, ln in hist:
        tags, creds, decoded = analyze_command_into(rep, src, ts, cmd, "hist")
        if not tags and ts and a.timeline:
            rep.event(ts, src, "hist", cmd[:200])
        for t in tags:
            cnt[t] += 1
        if tags or creds or decoded or a.all:
            mark = "[!]" if tags or creds else "   "
            print(f"{mark} {ln:5d} {fmt_ts(ts) if ts else '':19s} {cmd[:240]}"
                  + (f"   [{', '.join(tags)}]" if tags else ""))
            for how, text in decoded:
                print(f"          {how} → {text[:240]!r}")
            for k, v in creds:
                print(f"          кред ({k}): {v}")
    if cnt:
        print("    теги: " + ", ".join(f"{t}={c}" for t, c in cnt.most_common()))


def analyze_generic(lines, src, rep, fmt):
    """Неизвестный текст/ошибки nginx: подозрительное, креды, флаги, раскодирование."""
    shown = 0
    seen = set()
    for i, ln in enumerate(lines, 1):
        ts = None
        m = NGINX_ERR.match(ln)
        if m:
            try:
                ts = dt.datetime.strptime(m.group("ts"), "%Y/%m/%d %H:%M:%S")
            except ValueError:
                ts = None
        dec = adminlib.url_unquote_all(ln)
        rep.add_flags(adminlib.flags_in(ln, dec), f"{src}:{i}")
        tags, creds, decoded = adminlib.analyze_command(dec)
        for k, v in creds:
            rep.add_cred(f"{src}:{i}", k, v)
        for how, text in decoded:
            rep.add_decoded(f"{src}:{i}", how, text)
        web = [t for t, rx in WEB_ATTACKS_RX if rx.search(dec)]
        strong = [t for t in tags if t != "recon"] + web
        body = NGINX_ERR.sub(r"\g<lvl> \g<msg>", dec)
        if strong and body not in seen:
            seen.add(body)
            if shown == 0:
                print(f"\n[+] {fmt} {src}: подозрительные строки")
            if shown < rep.args.top * 2:
                print(f"[!] {i:5d} {dec[:220]}   [{', '.join(strong)}]")
            shown += 1
            rep.event(ts, src, "susp", dec[:160])


def analyze_file(path, rep, forced=None):
    head = adminlib.read_head(path, 16)
    if head[:8] == b"ElfFile\x00":
        print(f"\n[i] {path}: EVTX (бинарный журнал Windows) — "
              "python forensic/windows_triage.py / evtx_dump.py / Get-WinEvent")
        return
    lines = load_lines(path)
    if not lines:
        return
    src = os.path.basename(path)
    kind = forced or adminlib.log_kind(lines)
    if not kind:
        hk = adminlib.history_kind(path, lines)
        if hk:
            kind = "ps_history" if hk == "PSHISTORY" else "shell_history"
    if not kind:
        kind = "nginx_error" if sum(bool(NGINX_ERR.match(x)) for x in lines[:200]) > 5 else "text"
    print(f"\n=== {path}: формат {kind} ===")
    if kind == "syslog":
        analyze_auth(syslog_records(lines, rep.args.year), src, rep)
    elif kind in ("journal_json", "journal_export"):
        analyze_auth(journal_records(lines, kind), src, rep)
    elif kind == "audit":
        analyze_auth(audit_records(lines), src, rep)
    elif kind == "access":
        analyze_access(lines, src, rep)
    elif kind in ("shell_history", "ps_history"):
        analyze_history(history_records(lines), src, rep,
                        "PowerShell" if kind == "ps_history" else "shell")
    else:
        analyze_generic(lines, src, rep, kind)


LOG_NAME = re.compile(r"(?i)(auth|secure|syslog|messages|kern|daemon|access|error|audit|journal|"
                      r"history|\.log|ConsoleHost)")


def collect(paths, max_mb):
    out = []
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = [d for d in dirs if d not in (".git", "__pycache__", "node_modules")]
                for fn in sorted(files):
                    fp = os.path.join(root, fn)
                    try:
                        if os.path.getsize(fp) > max_mb * 1024 * 1024 or os.path.getsize(fp) == 0:
                            continue
                    except OSError:
                        continue
                    kind, _d = adminlib.detect(fp)
                    if kind in ("LOG", "PSHISTORY", "SHELLHISTORY") or (
                            LOG_NAME.search(fn) and adminlib.text_lines(fp)):
                        out.append(fp)
        else:
            out.append(p)
    return out


def main():
    ap = argparse.ArgumentParser(description="анализ логов: auth/web/journald/auditd/history")
    ap.add_argument("paths", nargs="+", help="файлы логов или папки (var/log, дамп)")
    ap.add_argument("--timeline", action="store_true", help="общая хронология событий")
    ap.add_argument("--format", choices=["syslog", "access", "journal_json", "journal_export",
                                         "audit", "shell_history", "ps_history", "text"],
                    help="не определять формат, а взять этот")
    ap.add_argument("--year", type=int, default=YEAR, help="год для syslog-дат без года")
    ap.add_argument("--brute", type=int, default=5, help="порог неудач для брутфорса")
    ap.add_argument("--window", type=int, default=60, help="окно брутфорса, сек")
    ap.add_argument("--top", type=int, default=10)
    ap.add_argument("--examples", type=int, default=3, help="примеров на тип атаки")
    ap.add_argument("--all", action="store_true", help="история: печатать все команды")
    ap.add_argument("--limit", type=int, default=400, help="строк таймлайна")
    ap.add_argument("--max-mb", type=float, default=512, help="предел размера файла в папке")
    common.add_flag_args(ap)
    args = ap.parse_args()
    common.apply_flag_args(args)

    files = []
    for p in args.paths:
        if not os.path.exists(p):
            print(f"[-] нет такого пути: {p}")
            continue
        if os.path.isfile(p):
            err = adminlib.open_error(p)
            if err:
                print(f"[-] {err}")
                continue
        files.append(p)
    files = collect(files, args.max_mb)
    if not files:
        print("[-] логов не найдено")
        sys.exit(2)
    rep = Report(args)
    for fp in files:
        try:
            analyze_file(fp, rep, args.format)
        except (OSError, ValueError) as e:
            print(f"[-] {fp}: {e}")

    if rep.decoded:
        print("\n[+] раскодировано:")
        for src, how, text in rep.decoded[:args.top * 3]:
            print(f"    {src}: {how} → {text[:240]!r}")
    if rep.creds:
        print("\n[!] креды/секреты:")
        for src, kind, val in rep.creds[:args.top * 3]:
            print(f"    {src}: {kind}: {val}")
    if args.timeline:
        tl = sorted((e for e in rep.timeline if e[0]), key=lambda e: e[0])
        print(f"\n=== таймлайн: {len(tl)} событий ===")
        for ts, src, tag, text in tl[:args.limit]:
            print(f"{fmt_ts(ts)}  {src:18.18s} [{tag}] {text}")
        if len(tl) > args.limit:
            print(f"    ... ещё {len(tl) - args.limit} (--limit)")
    if rep.flags:
        print()
        for f, where in rep.flags:
            adminlib.print_flags([f], where)


if __name__ == "__main__":
    main()
