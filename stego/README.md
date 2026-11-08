# stego

Скрипты для стего-задач.

- `lsb.py` — LSB одного канала/нескольких бит и режим `--diff` для двух картинок.
- `alpha.py` — значения канала как ASCII.
- `jpeg_tail.py` — конец JPEG (FFD9), хвост, распаковка ZIP.
- `carve.py` — binwalk-lite: PNG/JPEG/ZIP/GZIP/PDF/ELF/SQLite по сигнатурам.
- `ooxml.py` — DOCX/XLSX/PPTX как ZIP: список файлов, media, strings.
- `gif_frames.py` — один пиксель с каждого кадра.
- `runs.py` — длина серии одинаковых символов → ASCII.
- `png_chunks.py` — чанки PNG: `tEXt`/`zTXt`/`iTXt`, IHDR, проверка CRC,
  `--fix` (пересчитать CRC), незнакомые критичные чанки, хвост после `IEND`.
- `audio_spectrum.py` — спектрограмма WAV (numpy+PIL) и доминирующие частоты.
- `qr_scan.py` — поиск и чтение QR (OpenCV), с несколькими попытками.
- `bitmap_font.py` — CSV точек → холст, нарезка на глифы, автодекод 5×5,
  `--legend` для ручного сопоставления.

Порядок: `carve` → `ooxml`/`jpeg_tail` → `lsb`/`alpha` → `runs`/`gif_frames`.
