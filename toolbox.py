#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
toolbox.py — единая точка входа.

  python toolbox.py index                 # список всех инструментов
  python toolbox.py auto <файл|строка>    # определить, что это, и что делать
  python toolbox.py <инструмент> ...      # запустить инструмент

Примеры:
  python toolbox.py auto "Q1RGe2ZsYWd9"
  python toolbox.py auto capture.pcap
  python toolbox.py lsb pic.png --channel r
  python toolbox.py rsa shared --moduli mods.txt --target t --cipher 0x1234
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import common  # noqa: E402

# Windows: свой вывод и вывод дочерних скриптов — всегда UTF-8, даже в pipe/файл.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
os.environ["PYTHONIOENCODING"] = "utf-8"

# (категория, имя, путь, описание)
REGISTRY = [
    ("", "triage", "triage.py", "первый прогон по файлу/папке"),
    ("", "text", "doctext.py", "вытащить текст из DOCX/PDF/ZIP"),
    ("", "enc", "enc.py", "декодировать строку во все стороны"),
    ("", "all", "megaall.py", "универсальный перебор: всё, что есть"),
    ("", "solve", "solve.py", "автопилот: прогнать всё подходящее до флага"),
    ("", "hint", "toolbox.py", "разбор с объяснением: что вижу и почему"),
    ("", "auto", "", "определить тип и предложить действия"),

    ("stego", "lsb", "stego/lsb.py", "LSB одного канала / diff двух картинок"),
    ("stego", "alpha", "stego/alpha.py", "значения канала как ASCII"),
    ("stego", "jpeg_tail", "stego/jpeg_tail.py", "хвост после JPEG → ZIP/PNG"),
    ("stego", "carve", "stego/carve.py", "вырезать вложенные файлы по сигнатурам"),
    ("stego", "ooxml", "stego/ooxml.py", "DOCX/XLSX как ZIP"),
    ("stego", "gif_frames", "stego/gif_frames.py", "пиксель с каждого кадра GIF"),
    ("stego", "runs", "stego/runs.py", "серии символов → ASCII"),
    ("stego", "png_chunks", "stego/png_chunks.py", "чанки PNG и хвост после IEND"),
    ("stego", "bitmap_font", "stego/bitmap_font.py", "точки → картинка → глифы"),
    ("stego", "ws", "stego/whitespace.py", "Whitespace и невидимые символы"),
    ("stego", "esolang", "stego/esolang.py", "Brainfuck/Ook/Cow/Befunge/Deadfish"),
    ("stego", "audio", "stego/audio_spectrum.py", "спектрограмма WAV"),
    ("stego", "audiotools", "stego/audio_tools.py", "DTMF и морзе из WAV"),
    ("stego", "qr", "stego/qr_scan.py", "найти и прочитать QR"),

    ("forensic", "zipmeta", "forensic/zipmeta.py", "комментарии/extra ZIP"),
    ("forensic", "exif", "forensic/exif.py", "метаданные файла"),
    ("forensic", "disk", "forensic/disk_triage.sh", "образ диска: mount/photorec/LUKS"),
    ("forensic", "hunt", "forensic/artifact_hunt.py", "поиск ключей/секретов/флагов"),
    ("forensic", "android", "forensic/android_backup.py", "XML/SQLite/логи Android"),
    ("forensic", "vol", "forensic/volatility_text.py", "разбор pstree/envars"),
    ("forensic", "apk", "forensic/apk_info.py", "APK: файлы, manifest, строки"),
    ("forensic", "ipa", "forensic/ipa_info.py", "iOS IPA: Info.plist, строки, флаги"),
    ("forensic", "geo", "forensic/geo_photo.py", "геолокация по фото: EXIF/GPS + ссылки"),
    ("forensic", "docker", "forensic/docker_image.py", "Docker-образ: слои, whiteouts, секреты"),
    ("forensic", "git", "forensic/git_hunt.py", "git: история, секреты, удалённые файлы"),
    ("forensic", "browser", "forensic/browser_artifacts.py", "история/куки/логины браузера"),
    ("forensic", "win", "forensic/windows_triage.py", "Windows-артефакты: Run/URL/пути"),
    ("forensic", "office", "forensic/office_docs.py", "Office/PDF: макросы, JS, вложенное"),
    ("forensic", "cloud", "forensic/cloud_creds.py", "AWS/GCP/Azure ключи и metadata"),
    ("forensic", "flaghunt", "forensic/flag_hunt.py", "файлы-флаги по имени и содержимому"),

    ("network", "pcap", "network/pcap_report.py", "сводка по PCAP"),
    ("network", "reasm", "network/tcp_reassemble.py", "сборка TCP по seq"),
    ("network", "mc", "network/mc_decrypt.py", "Minecraft AES-CFB8 + пакеты"),
    ("network", "mcblocks", "network/mc_blocks.py", "блоки → CSV точек"),
    ("network", "udp", "network/udp_payloads.py", "UDP payload и протоколы"),
    ("network", "icmp", "network/icmp_payloads.py",
     "ICMP payload, поля заголовка, тайминги"),
    ("network", "dns", "network/dns_tunnel.py",
     "DNS-канал: индексы, авто-ключи из артефактов, XOR→zlib"),
    ("network", "http", "network/pcap_http.py", "HTTP-объекты из PCAP"),
    ("network", "creds", "network/pcap_creds.py", "креды из трафика"),
    ("network", "dockerapi", "network/docker_api.py", "открытый Docker API"),
    ("network", "k8sapi", "network/k8s_api.py", "Kubernetes API по токену"),
    ("network", "serve", "network/serve.py", "HTTP-сервер для раздачи/приёма файлов"),

    ("crypto", "autocrack", "crypto/autocrack.py", "перебрать кодировки, шифры, XOR, хеши"),
    ("crypto", "mega", "crypto/megacrack.py", "шифротекст + материалы → ключи и шифры"),
    ("crypto", "obscure", "crypto/obscure.py", "Bacon/ADFGX/Bifid/base58/…"),
    ("crypto", "classical", "crypto/classical.py", "классические шифры"),
    ("crypto", "genetic", "crypto/genetic.py", "триплеты → аминокислоты"),
    ("crypto", "xorknown", "crypto/xor_known.py", "XOR с known plaintext"),
    ("crypto", "prng", "crypto/prng_seed.py", "random по seed-timestamp"),
    ("crypto", "aes", "crypto/aes_file.py", "AES-CBC из бинарника"),
    ("crypto", "ecb", "crypto/aes_ecb.py", "детект/расшифровка ECB"),
    ("crypto", "hash_id", "crypto/hash_id.py", "тип хеша + режим hashcat"),
    ("crypto", "hashcat", "crypto/hashcat_run.py", "запуск hashcat по режиму"),
    ("crypto", "rsa", "crypto/rsa_tool.py",
     "RSA: gcd/Ферма/малая e/Винер/Coppersmith/Boneh-Durfee"),
    ("crypto", "oracles", "crypto/block_oracles.py",
     "ECB/padding oracle, CBC flip, детект ECB"),
    ("crypto", "hashext", "crypto/hash_ext.py",
     "length extension MD5/SHA1/SHA256, GCM nonce reuse"),
    ("crypto", "otp", "crypto/otp_reuse.py", "two-time pad"),
    ("crypto", "stream", "crypto/stream_sha256.py", "SHA256-поток XOR"),

    ("linux", "privesc", "linux/privesc.sh", "разведка прав"),
    ("linux", "gtfo", "linux/gtfobins.py", "GTFObins оффлайн"),
    ("linux", "audit", "linux/script_audit.py", "что source-ит root-скрипт"),
    ("linux", "docker", "linux/docker_audit.sh", "аудит контейнера/Docker-хоста"),
    ("linux", "k8s", "linux/k8s_audit.sh", "аудит пода Kubernetes"),
    ("linux", "flaghunt", "linux/flag_hunt.sh", "поиск flag/flag.txt/flag_* и CTF{...}"),
    ("linux", "wsl", "linux/wsl.py",
     "запуск ELF в Arch WSL: копирует в Linux, +x, gdb/pwntools"),

    ("web", "recon", "web/recon.py", "разведка страницы: ссылки/формы/JS/куки/robots"),
    ("web", "jwt", "web/jwt_tool.py", "JWT decode/forge"),
    ("web", "jwtbrute", "web/jwt_brute.py", "подбор секрета JWT"),
    ("web", "ssti", "web/ssti_probe.py", "поиск SSTI"),
    ("web", "param", "web/param_probe.py", "payload'ы по параметрам"),
    ("web", "dirfuzz", "web/dir_fuzz.py", "перебор директорий"),

    ("pwn", "checksec", "pwn/checksec.py", "защиты ELF/PE"),
    ("pwn", "ret2win", "pwn/ret2win.py", "паттерн/оффсет/payload"),
    ("pwn", "fmtstr", "pwn/fmtstr.py", "format string helper"),
    ("pwn", "oracle", "pwn/oracle.py", "TCP-оракул: вопрос → формула → ответ, N раундов"),
    ("pwn", "ppc", "pwn/ppc_solvers.py", "какие ответы видит движок для PPC-вопроса"),

    ("reverse", "strings", "reverse/strings_filter.py", "строки с фильтрами"),
    ("reverse", "disasm", "reverse/disasm.py", "дизасм x86/x64/arm64 (capstone): cmp/lea/строки"),
    ("reverse", "ghidra", "reverse/ghidra_decomp.py", "декомпиляция Ghidra headless в C-подобный код"),
    ("reverse", "megarev", "reverse/megarev.py", "мега-реверс: тип/строки/ключи/перебор"),
    ("reverse", "lang", "reverse/lang_info.py", ".NET/Java/Go/Rust/Electron"),
    ("reverse", "xorscan", "reverse/xor_scan.py", "поиск XOR-ключа по файлу"),
    ("reverse", "pypack", "reverse/py_pack.py", "PyInstaller/pyarmor/Nuitka"),

    ("blockchain", "evm", "blockchain/evm_decode.py",
     "EVM calldata: селектор, аргументы, события"),
    ("ai", "pickle", "ai/pickle_scan.py",
     "pickle/модели: опасные глобалы и строки"),
    ("misc", "time", "misc/timeconv.py", "unix ↔ дата"),    ("misc", "game", "misc/game_bot.py", "универсальный бот: вопрос/слово/поле/клавиши + флаг"),
    ("misc", "wordle", "misc/wordle_bot.py", "Wordle: фильтр кандидатов + энтропия"),
    ("misc", "formats", "misc/formats.py", "кэш разметок ответа: спросил один раз"),
    ("misc", "ocr", "misc/ocr.py", "текст с картинки (капча/скриншот/кадр)"),
    ("misc", "video", "misc/video.py", "кадры видео/GIF: OCR, отличия"),
    ("misc", "nearlines", "misc/nearlines.py",
     "почти одинаковые строки: уникальные и отличия"),
]

DESC = {name: desc for _, name, _, desc in REGISTRY if name}


def path_of(name: str):
    for _, n, p, _ in REGISTRY:
        if n == name:
            return os.path.join(HERE, p)
    return None


def cmd_index(args):
    cat = None
    for c, name, _, desc in REGISTRY:
        if not name:
            continue
        if c != cat:
            cat = c
            print(f"\n[{cat or 'base'}]")
        print(f"  {name:12s} {desc}")


EXT_TYPE = {
    ".zip": "ZIP", ".docx": "ZIP", ".xlsx": "ZIP", ".pptx": "ZIP", ".jar": "ZIP", ".apk": "ZIP",
    ".png": "PNG", ".jpg": "JPEG", ".jpeg": "JPEG", ".gif": "GIF", ".pdf": "PDF",
    ".pcap": "PCAP", ".pcapng": "PCAPNG", ".wav": "RIFF", ".mp3": "MP3", ".ogg": "OGG",
    ".exe": "PE", ".dll": "PE", ".so": "ELF", ".7z": "7Z", ".rar": "RAR",
    ".gz": "GZIP", ".tar": "TAR", ".db": "SQLite", ".sqlite": "SQLite",
}

TEXT_MAGIC_HINT = {
    "whitespace-only": ("ws", "текст из одних пробелов/табов"),
    "trailing-whitespace": ("ws", "в конце строк спрятаны пробелы/табы"),
    "encoded-blob": ("enc", "в тексте длинный base64/hex"),
}


def _scan_embedded(data, limit=64_000_000):
    """{имя сигнатуры: [смещения]} для вложенных файлов."""
    scan = data[:limit]
    found = {}
    for sig, name in common.SIGS:
        if len(sig) < 4:
            continue
        off = scan.find(sig)
        while off != -1 and len(found.get(name, [])) < 8:
            found.setdefault(name, []).append(off)
            off = scan.find(sig, off + 1)
    return found


def _zip_report(data, label):
    """Показать содержимое ZIP и вернуть (флаги, заметки)."""
    import io
    import zipfile

    flags, notes = [], []
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except Exception as e:
        return flags, [f"ZIP не открылся: {e}"]
    infos = z.infolist()
    notes.append(f"ZIP: {len(infos)} файл(ов), comment={z.comment!r}")
    for i in infos[:15]:
        notes.append(f"  - {i.filename} ({i.file_size} b)")
        if i.is_dir() or i.file_size > 200_000:
            continue
        try:
            body = z.read(i)
        except Exception:
            continue
        flags += common.find_flags(body)
        if len(body) < 4000 and common.is_text(body, 0.85):
            try:
                txt = body.decode("utf-8").strip()
            except UnicodeDecodeError:
                txt = body.decode("cp1251", "replace").strip()
            if txt:
                notes.append(f"    текст: {txt[:300]!r}")
    return flags, notes


def _wav_report(path):
    import wave

    import numpy as np  # noqa: F401  (нужен audio_tools)
    sys.path.insert(0, os.path.join(HERE, "stego"))
    import audio_tools

    try:
        data, rate = audio_tools.read_wav(path)
    except Exception as e:
        return [f"WAV не читается: {e}"], []
    notes = [f"WAV: rate={rate}, {len(data)/rate:.1f}s"]
    found = []
    m = audio_tools.decode_morse(data, rate)
    if m:
        notes.append(f"морзе: {m[:200]}")
        found.append(("morse", m))
    d = audio_tools.decode_dtmf(data, rate)
    if d and len(d) >= 4 and len(set(d)) >= 3:
        notes.append(f"DTMF: {d[:60]}")
        found.append(("dtmf", d))
    return notes, found


def _pcap_report(path):
    notes = []
    try:
        from scapy.all import DNS, DNSQR, PcapReader, TCP, UDP, IP
    except Exception as e:
        return [f"scapy недоступен: {e}"], []
    protos, dns_labels = {}, []
    try:
        with PcapReader(path) as pr:
            for i, p in enumerate(pr):
                if i > 20000:
                    notes.append("(остановился после 20k пакетов)")
                    break
                if IP in p:
                    for lname, layer in (("TCP", TCP), ("UDP", UDP)):
                        if layer in p:
                            protos[lname] = protos.get(lname, 0) + 1
                            break
                    else:
                        protos["IP"] = protos.get("IP", 0) + 1
                if DNS in p and p[DNS].qd is not None:
                    try:
                        dns_labels.append(p[DNS].qd.qname.decode("utf-8", "replace").rstrip("."))
                    except Exception:
                        pass
    except Exception as e:
        return [f"PCAP не читается: {e}"], []
    notes.append("протоколы: " + ", ".join(f"{k}={v}" for k, v in protos.items()))
    if dns_labels:
        notes.append(f"DNS-запросов: {len(dns_labels)}")
        try:
            sys.path.insert(0, os.path.join(HERE, "network"))
            import dns_tunnel
            groups = dns_tunnel.group_labels(dns_labels)
            flags_in_dns = []
            structs = dns_tunnel.structured_channels(dns_labels)
            for s in structs[:3]:
                notes.append(f"структурный DNS-канал {s['base']} "
                             f"({s['session']}): кусков={s['count']}, "
                             f"{len(s['data'])} B — запусти dns")
            for base, labels in groups.items():
                sc, k2 = dns_tunnel.score_group(labels)
                if sc >= 0.35:
                    notes.append(f"канал в домене {base} ({k2}, score={sc:.2f})")
                    for how, txt in dns_tunnel.try_decode("".join(labels)):
                        if common.find_flags(txt.encode()):
                            flags_in_dns += common.find_flags(txt.encode())
                            notes.append(f"  {how}: {txt[:120]}")
            return notes, flags_in_dns
        except Exception as e:
            notes.append(f"(DNS-декод не сработал: {e})")
    return notes, []


def _plan_file(path):
    full = common.read_bytes(path)
    size = len(full)
    kind = common.sniff(full[:4096])
    ext = os.path.splitext(path)[1].lower()
    print(f"=== {path} ({common.human(size)}) ===")
    print(f"[+] реальный тип: {kind}" + (f"   расширение: {ext or '—'}" if ext else ""))

    denial = common.api_denial_note(full)
    if denial:
        print("[!]", denial)
        print("[i] пока файл не перекачан, анализировать нечего")
        return

    actions = []

    def act(prio, tool, why):
        actions.append((prio, tool, why))

    flags = common.find_flags(full)
    stubs = [f for f in flags if any(w in f.lower() for w in ("missing", "placeholder", "dummy", "fake"))]
    real = [f for f in flags if f not in stubs]
    if real:
        print("[!!!] ФЛАГИ:", " | ".join(real))
        act(0, None, "флаг уже лежит в файле — можно сдавать")
    if stubs:
        print("[!] заглушка, не флаг:", " | ".join(stubs),
              "— настоящий обычно приходит из окружения/сервера")

    emb = _scan_embedded(full)

    # расширение врёт
    expected = EXT_TYPE.get(ext)
    if expected and kind != "unknown" and kind != expected:
        print(f"[!] расширение {ext} не совпадает с содержимым ({kind})")
        act(1, None, f"это {kind}, а не {expected}")

    # вложенные архивы/картинки не с начала файла
    for name, offs in emb.items():
        if name in ("ZIP", "PNG", "JPEG", "PDF", "GIF") and offs and offs[0] > 16 and kind != name:
            print(f"[!] внутри {name} по смещению {offs[0]} — файл обрезан или склеен")
            act(1, "carve", f"вырезать {name} из смещения {offs[0]}")
            break

    tags = set()
    notes = []

    zip_off = None
    if full[:4] == b"PK\x03\x04":
        zip_off = 0
    elif "ZIP" in emb:
        zip_off = emb["ZIP"][0]
    if zip_off is not None:
        if zip_off:
            print(f"[!] файл не начинается с ZIP: архив лежит с {zip_off} "
                  "(архиватор откроет и так, киту нужен carve)")
        f2, notes = _zip_report(full[zip_off:], os.path.basename(path))
        if f2:
            print("[!!!] ФЛАГИ в архиве:", " | ".join(dict.fromkeys(f2)))
            act(0, None, "флаг внутри архива")
        act(2 if zip_off else 3, "zipmeta", "метаданные, комментарии, скрытые записи")
        if ext in (".docx", ".xlsx", ".pptx"):
            try:
                for _, t in common.document_text(path)[:6]:
                    tags.update(common.classify_text(t))
            except Exception:
                pass
            if tags:
                print("[+] теги текста:", ", ".join(sorted(tags)))
                if any(x in tags for x in ("whitespace-only", "trailing-whitespace")) or \
                        any(x.startswith(("zero-width", "variation", "braille")) for x in tags):
                    act(1, "ws", "внутри документа пробелы/zero-width — это и есть данные")
                if "encoded-blob" in tags:
                    act(2, "enc", "внутри документа base64/hex")
            act(3, "text", "вытащить текст из документа")

    if kind in ("PCAP", "PCAPNG"):
        notes2, findings = _pcap_report(path)
        notes += notes2
        if findings:
            print("[!!!] ФЛАГИ из DNS-канала:", " | ".join(dict.fromkeys(findings)))
            act(0, None, "флаг собран из DNS")
        act(2, "dns", "посмотреть все домены и кодировки")
        act(3, "creds", "пароли/куки/токены в трафике")
        act(4, "http", "вытащить тела HTTP-ответов")

    if kind == "RIFF":
        notes3, findings = _wav_report(path)
        notes += notes3
        if any(k == "morse" for k, _ in findings):
            act(1, "audiotools", "в звуке морзе/DTMF")
        act(3, "audio", "спектрограмма: текст/картинка в спектре")

    if kind in ("ELF", "PE"):
        try:
            sys.path.insert(0, os.path.join(HERE, "pwn"))
            import checksec
            info = checksec.elf_info(full) if kind == "ELF" else checksec.pe_info(full)
            if info:
                print("[+] защиты:", info)
                arch = info.get("arch", "")
                if arch and arch not in ("x86", "x86_64", "x64", "AMD64", "i386"):
                    print(f"[i] {arch}: локально не запустить — только статика/эмулятор")
        except Exception:
            pass
        act(2, "strings", "строки с ключевыми словами")
        act(3, "checksec", "PIE/NX/canary — от этого зависит эксплойт")
        act(4, "megarev", "упаковщики, энтропия, вложенные файлы")

    if kind == "PNG":
        notes.append(f"PNG: {size} b")
        act(2, "png_chunks", "нестандартные чанки/текст в метаданных")
        act(3, "lsb", "младшие биты каналов")
        act(4, "alpha", "данные в альфа-канале")
        act(5, "qr", "если на картинке QR")
    elif kind == "JPEG":
        act(2, "jpeg_tail", "данные после EOI")
        act(3, "exif", "EXIF/GPS/комментарии")
    elif kind == "GIF":
        act(2, "gif_frames", "кадры и палитра")

    if kind in ("PDF",):
        act(2, "text", "текст и вложения из PDF")
        act(3, "hunt", "строки/секреты")

    # текст
    text = None
    if size < 8_000_000:
        for enc in ("utf-8", "cp1251"):
            try:
                t = full.decode(enc)
            except UnicodeDecodeError:
                continue
            if common.printable_ratio(t) >= 0.85:
                text = t
                break
    if text is not None and text.strip():
        tags = set(common.classify_text(text))
        if tags:
            print("[+] теги текста:", ", ".join(sorted(tags)))
        for tag, (tool, why) in TEXT_MAGIC_HINT.items():
            if tag in tags:
                act(2, tool, why)
        if re.fullmatch(r"\s*[.\-–—_/|]{10,}\s*", text):
            act(4, None, "похоже на азбуку Морзе текстом: расшифруй через audiotools/enc")
        if len(text) < 4000:
            cands = common.decode_auto(text.strip())
            if cands:
                print("[+] декодируется как:")
                for how, val in cands[:4]:
                    print(f"    {how}: {val[:120]}")

    if kind == "SQLite":
        act(2, "android", "SQLite: таблицы, чаты, токены")
        act(3, "hunt", "строки из базы")

    if kind == "MP3" or kind == "OGG":
        act(2, "audio", "спектрограмма")

    if kind == "unknown" and not real and not emb and text is None:
        if size <= 8192 and common.printable_ratio(full) < 0.75:
            pre = (common.prefixes() or ["CTF"])[0]
            print(f"[i] короткий бинарный блоб без сигнатур. Если это XOR:"
                  f' python toolbox.py xorknown "{path}" --known "{pre}{{"')
        act(5, "triage", "полный отчёт: строки, архивные сигнатуры, содержимое")

    if notes:
        print("[+] подробности:")
        for n in notes[:20]:
            print("   ", n)

    # план
    actions = [a for a in actions if a[1] or a[0] == 0]
    print("\n[i] план (по приоритету):")
    seen = set()
    for prio, tool, why in actions:
        if tool in seen:
            continue
        seen.add(tool)
        if tool is None:
            continue
        print(f"    python toolbox.py {tool} {path}")
        print(f"        ^ {why}")
    if not any(a[1] for a in actions):
        print("    python toolbox.py triage", path)
        print("        ^ базовый отчёт")
    print("\n[i] или пусть кит сам: python toolbox.py solve", path)
    print("[i] тяжёлый перебор: python toolbox.py all", path)


def _pick_files(root, limit=12, max_size=50_000_000):
    """Файлы в папке, отсортированные по «интересности» типа."""
    prio = {"ZIP": 0, "PCAP": 0, "PCAPNG": 0, "PNG": 1, "JPEG": 1, "GIF": 1,
            "ELF": 1, "PE": 1, "PDF": 1, "SQLite": 1, "RIFF": 1, "MP3": 1, "OGG": 1,
            "7Z": 2, "RAR": 2, "GZIP": 2, "TAR": 2, "unknown": 3}
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ("__pycache__", ".git", "node_modules")]
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            try:
                if os.path.getsize(p) > max_size:
                    continue
                with open(p, "rb") as f:
                    kind = common.sniff(f.read(4096))
            except OSError:
                continue
            out.append((prio.get(kind, 4), os.path.getsize(p), p, kind))
    out.sort()
    return [(p, kind) for _, _, p, kind in out[:limit]]


def _plan_dir(path):
    from collections import Counter

    print(f"=== {path} (папка) ===")
    kinds = Counter()
    flags = []
    checked = 0
    for dirpath, dirnames, filenames in os.walk(path):
        dirnames[:] = [d for d in dirnames if d not in ("__pycache__", ".git", "node_modules")]
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            try:
                size = os.path.getsize(p)
            except OSError:
                continue
            checked += 1
            if checked > 5000:
                break
            try:
                with open(p, "rb") as f:
                    head = f.read(4096)
                    kind = common.sniff(head)
                    kinds[kind] += 1
                    if size < 5_000_000:
                        found = common.find_flags(head + f.read(5_000_000))
                        if found:
                            flags.append((p, found))
            except OSError:
                continue

    print(f"[+] файлов: {checked}")
    print("[+] типы: " + ", ".join(f"{k}={v}" for k, v in kinds.most_common(8)))
    if flags:
        print("[!!!] флаги по файлам:")
        for p, found in flags[:20]:
            print(f"    {p}: {' | '.join(dict.fromkeys(found))}")
    else:
        print("[-] в открытом виде флагов нет")

    picked = _pick_files(path)
    if picked:
        print("[i] что смотреть первым:")
        for p, kind in picked[:6]:
            print(f"    {kind:8s} {p}")
    print("\n[i] план:")
    print(f"    python toolbox.py solve {path}          # перебрать всё до флага")
    print(f"    python toolbox.py solve {path} --deep")
    print(f"    python toolbox.py flaghunt {path}       # файлы flag/user/root")
    print(f"    python toolbox.py triage {path}         # отчёт по каждому")


def cmd_auto(args):
    target = args.target
    if os.path.isdir(target):
        _plan_dir(target)
        return
    if os.path.exists(target):
        _plan_file(target)
        return

    text = target.strip()
    print("[+] не путь к файлу — разбираю как строку")
    direct = common.find_flags(text.encode())
    if direct:
        print("[+] строка уже является флагом:")
        for f in direct:
            print("[!!!] ФЛАГ:", f)
        return
    if text.lower().startswith(("http://", "https://")):
        print("[i] это URL: python toolbox.py param <url>  |  jwt  |  ssti  |  dirfuzz")
        return
    cands = common.decode_auto(text)
    for how, val in cands:
        print(f"[{how}] {val[:300]}")
        for f in common.find_flags(val.encode()):
            print("[!!!] ФЛАГ:", f)
    if not cands:
        print("[-] не похоже на base64/hex/url/бит/числа")
        print("[i] попробуй: python toolbox.py enc <строка>   или   autocrack --text <строка>")


TEACH = {
    "ZIP": "Архив — это контейнер. Смотри имена, комментарии, даты, лишние байты "
           "до/после, а не только содержимое. Если «пусто» — ищи второй архив внутри.",
    "PNG": "Картинка почти всегда несёт данные в: LSB каналов, альфа-канале, "
           "нестандартных чанках (tEXt/zTXt), хвосте после IEND. Если пиксели "
           "выглядят шумом — смотри битовые плоскости и порядок каналов.",
    "JPEG": "JPEG не любит LSB: чаще это EXIF/комментарий или данные после EOI.",
    "GIF": "Кадры и палитра: сравни кадры, смотри задержки и комментарии.",
    "RIFF": "Звук: морзе/DTMF по огибающей, текст/картинка в спектрограмме, "
            "данные в младших битах сэмплов.",
    "PCAP": "Сначала протоколы и разговоры, потом: DNS-метки, HTTP-тела, "
            "нестандартные порты, ICMP/UDP-полезная нагрузка, TLS без шифрования.",
    "ELF": "Бинарник: защиты (checksec), строки, импорты, сравнение/константы. "
           "Динамику — в отладчике/эмуляторе, не «на глаз».",
    "PE": "Бинарник Windows: секции, импорты, строки (UTF-16 тоже), ресурсы.",
    "PDF": "Текст/вложения/потоки: ищи FlateDecode, JavaScript, аннотации, "
           "скрытый текст белым по белому.",
    "SQLite": "База: таблицы, чаты, токены, время. Начни со схемы и имён таблиц.",
    "unknown": "Сигнатур нет: либо текст, либо сырые байты. Текст — кодировки/"
               "шифры/эзотерика; байты — энтропия, XOR с известным префиксом, "
               "вложенные сигнатуры по оффсетам. Если видишь «Ð¡Ð¾Ð¾Ð±Ñ‰» — это "
               "текст в чужой кодировке, а не шифр: enc --file его починит.",
}


def cmd_hint(args):
    target = args.target
    if os.path.isdir(target):
        _plan_dir(target)
        print("\n[как это понимать] Папка — это набор артефактов. Сначала типы и "
              "флаги в открытом виде, потом по одному самые «богатые» файлы.")
        return
    if not os.path.exists(target):
        print("[+] это не файл, а строка")
        direct = common.find_flags(target.strip().encode())
        if direct:
            print("[+] похоже, флаг уже перед тобой:")
            for f in direct:
                print("[!!!] ФЛАГ:", f)
            return
        cands = common.decode_auto(target.strip())
        for how, val in cands[:5]:
            print(f"    {how}: {val[:120]}")
        print("\n[как это понимать] Строка без контекста: сначала декодируй "
              "(base64/hex/url), потом смотри, читается ли результат. Если нет — "
              "это шифр, и нужен признак: длина, алфавит, повторяемость.")
        return

    data = common.read_bytes(target)[:4096]
    kind = common.sniff(data)
    _plan_file(target)
    print("\n[как это понимать]")
    print("  " + TEACH.get(kind, TEACH["unknown"]))
    print("\n[если шаги не дали флага]")
    print("  - перечитай условие: там часто есть подсказка про формат/алгоритм;")
    print("  - сравни с похожими задачами: EXAMPLES.md ищется по признаку;")
    print("  - если данные «шум» — проверь другой слой (биты, каналы, оффсеты);")
    print("  - если сервис — сначала oracle --peek, потом формула.")


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        print(__doc__)
        print("Инструменты: python toolbox.py index")
        return

    name = sys.argv[1]
    if name == "index":
        cmd_index(sys.argv[2:])
        return
    if name == "auto":
        sys.path.insert(0, HERE)
        import argparse
        import common
        ap = argparse.ArgumentParser(prog="toolbox.py auto")
        ap.add_argument("target")
        common.add_flag_args(ap)
        a = ap.parse_args(sys.argv[2:])
        common.apply_flag_args(a)
        cmd_auto(a)
        return
    if name == "hint":
        sys.path.insert(0, HERE)
        import argparse
        import common
        ap = argparse.ArgumentParser(prog="toolbox.py hint")
        ap.add_argument("target")
        common.add_flag_args(ap)
        a = ap.parse_args(sys.argv[2:])
        common.apply_flag_args(a)
        cmd_hint(a)
        return

    if name == "plugins":
        sys.path.insert(0, HERE)
        import common
        found = common.discover_plugins()
        if not found:
            print("[i] плагинов нет: шаблон plugins/_template.py, API plugins/README.md")
        for path, meta in found:
            if meta.get("error"):
                print(f"  [!] {os.path.basename(path)}: {meta['error']}")
                continue
            print(f"  {meta['name']:20} {meta.get('kind', '?'):12} {os.path.basename(path)}")
        return
    path = path_of(name)
    if not path:
        # алиас по имени файла: megacrack -> crypto/megacrack.py, megaall -> megaall.py
        low = name.lower()
        for _, _, p, _ in REGISTRY:
            stem = os.path.splitext(os.path.basename(p))[0].lower()
            if stem == low:
                path = os.path.join(HERE, p)
                print(f"[i] {name} = {os.path.basename(p)}")
                break
    if not path:
        import difflib
        near = difflib.get_close_matches(name, [n for _, n, _, _ in REGISTRY if n], n=3, cutoff=0.5)
        print(f"[-] неизвестный инструмент: {name}")
        if near:
            print("    может, ты имел в виду:", ", ".join(near))
        print("    python toolbox.py index")
        sys.exit(2)
    if not os.path.exists(path):
        print(f"[-] нет файла: {path}")
        sys.exit(2)

    cmd = [sys.executable, path] if path.endswith(".py") else ["bash", path]
    sys.exit(subprocess.call(cmd + sys.argv[2:]))


if __name__ == "__main__":
    main()
