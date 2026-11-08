# forensic

- `zipmeta.py` — комментарии архива и файлов, extra-поля, hex/base64/reverse.
- `exif.py` — метаданные: exiftool, если установлен, иначе PIL.
- `disk_triage.sh` — образ диска: `file`, mount read-only, photorec, LUKS, strings.
- `artifact_hunt.py` — рекурсивный поиск флагов, `KEY=VALUE`, секретов, base64 и hex;
  умеет заглядывать в zip.
- `volatility_text.py` — разбор текстовых выгрузок `pstree`/`envars`: найти процесс,
  показать окружение, вытащить ключи.
- `android_backup.py` — XML/SQLite/логи Android-выгрузки: `android_id`, `seed`,
  `nonce`, таблицы и строки БД.
- `apk_info.py` — APK как zip: файлы, manifest (UTF-16/AXSL), dex-строки, URL, флаги.

Для Windows-образов команды из `disk_triage.sh` повторяй в WSL/Kali.
