# forensic

- `zipmeta.py` — комментарии архива и файлов, extra-поля, hex/base64/reverse;
  с `--decode` читает имена как байты (hex-имена, флаг разрезан по индексам).
- `exif.py` — метаданные: exiftool, если установлен, иначе PIL.
- `disk_triage.sh` — образ диска: `file`, mount read-only, photorec, LUKS, strings.
- `artifact_hunt.py` — рекурсивный поиск флагов, `KEY=VALUE`, секретов, base64 и hex;
  умеет заглядывать в zip, PDF (все ревизии) и снимать слой «base64 + XOR ключом
  из файла».
- `pdf_revisions.py` — текст из всех потоков PDF, включая перекрытые
  инкрементальными обновлениями (старая ревизия с «замазанным» текстом).
- `volatility_text.py` — разбор текстовых выгрузок `pstree`/`envars`: найти процесс,
  показать окружение, вытащить ключи.
- `android_backup.py` — XML/SQLite/логи Android-выгрузки: `android_id`, `seed`,
  `nonce`, таблицы и строки БД.
- `apk_info.py` — APK как zip: файлы, manifest (UTF-16/AXSL), dex-строки, URL, флаги.

Для Windows-образов команды из `disk_triage.sh` повторяй в WSL/Kali.
