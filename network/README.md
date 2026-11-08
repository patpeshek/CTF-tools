# network

- `pcap_report.py` — сводка: протоколы, разговоры, DNS, HTTP, ICMP, base64, флаги.
- `tcp_reassemble.py` — сборка TCP по sequence numbers, отдельно по направлениям.
- `mc_decrypt.py` — Minecraft: находит границу AES/CFB8, перебирает ключи и смещения,
  парсит пакеты с zlib, ищет флаги.
- `mc_blocks.py` — из пакетов установки блоков делает CSV координат.
- `udp_payloads.py` — UDP-payload, разбор полей по разделителю, hex/base64/raw.
- `pcap_creds.py` — HTTP Basic/формы, FTP, IRC, SMTP AUTH, Telnet.
- `dns_tunnel.py` — данные в DNS-запросах: простая склейка меток и структурный
  канал `<session>.<index>.<hex>.<домен>` (сортировка по индексу, дедуп
  ретрансмитов). Сам берёт `SEED`/`HOST`/`KEY` из артефактов рядом с pcap,
  пробует XOR → zlib/gzip/bz2/lzma и показывает флаг. Флаги: `--domain`,
  `--seed/--host`, `--xor-key`, `--no-auto-keys`, `--out`.
- `pcap_http.py` — HTTP-запросы и тела ответов, выгрузка объектов.

Если в PCAP несколько сессий на одном 4-tuple — режь по времени (`editcap -c` или
фильтр по времени), иначе потоки склеятся.
