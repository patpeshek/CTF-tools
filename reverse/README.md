# reverse

- `strings_filter.py` — строки из бинарника с offset, фильтры по regex, флагам,
  URL и путям, плюс UTF-16LE.
- `xor_scan.py` — одиночный байт (топ кандидатов), повторяющийся ключ, known plaintext.
- `py_pack.py` — определить PyInstaller / pyarmor / Nuitka / py2exe / zipapp и
  получить подсказку, что делать дальше.
- `disasm.py` — дизасм x86/x64/arm64 на capstone (без запуска): `--interesting`,
  `--strings` (RIP-ссылки → строки), `--around`, `--grep`.
- `ghidra_decomp.py` — headless-декомпиляция Ghidra в C-текст; гайд по Ghidra —
  [GHIDRA.md](GHIDRA.md).

Порядок: `strings_filter` → `checksec` (в pwn) → `py_pack`, если Python →
`xor_scan`, если данные выглядят «сдвинутыми».
