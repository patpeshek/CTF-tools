"""data_audit.py — можно ли верить синтетическому датасету.

Синтетика из gen_tasks.py / gen_artifacts.py — единственный источник обучения,
поэтому проверять надо её отдельно от модели: битые артефакты, дубликаты
(утечка test в train), перепутанные метки, мёртвые признаки. Скрипт ничего не
чинит и всегда возвращает 0 — он только печатает отчёт и ставит `[!]` там, где
реально плохо (`[i]` — «так и задумано», например NOVEL-классы).

  python ml/data_audit.py
  python ml/data_audit.py --data F:\\AIproject\\ml-runs\\data_v2_100k.npz

Важно про `x_bytes`: это НЕ исходные байты. gen_tasks.byte_ids() пишет
`байт + 1`, чтобы 0 оставался padding-ом, и режет всё до 256 байт. Поэтому
проверка магии сначала вычитает 1 и обрезает хвост из нулей — иначе PNG/zip
заведомо «не сойдутся». Из-за обрезки до 256 байт структуру видно только в
начале файла, так что единичные проценты «нарушений» на длинных контейнерах —
это норма, а не битые данные; поэтому же совпадение первых 256 байт ещё не
значит, что это один и тот же артефакт (у pdf и sqlite шапка статическая).
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import os
import sys
from collections import Counter, defaultdict

import numpy as np

# запускают и из корня репо (`python ml/data_audit.py`), и изнутри ml/ —
# поэтому ml/ всегда добавляем в sys.path сами, как это делает train_hf.py
HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from features import FEATURE_NAMES, MAGICS  # noqa: E402
from gen_tasks import FAMILIES, NOVEL  # noqa: E402

DEFAULT_DATA = r"F:\AIproject\ml-runs\data_v2_100k.npz"
SPLITS = ("train", "val", "test", "extra", "novel")
MIN_TRAIN = 200          # меньше — класс нечему учить
# индекс первой magic-колонки. Считать «len(FEATURE_NAMES) - len(MAGICS)» нельзя:
# последняя колонка — mbr, и формула съезжает на единицу (проверка магии тогда
# смотрит на соседние признаки и «согласована» вообще со всем).
MAGIC_OFFSET = FEATURE_NAMES.index(f"magic_{MAGICS[0][1]}")

PROBLEMS: list[str] = []
EXPECTED: list[str] = []


def warn(msg: str) -> None:
    PROBLEMS.append(msg)
    print(f"  [!] {msg}")


def note(msg: str) -> None:
    """Ожидаемое поведение — не проблема, но сказать надо."""
    EXPECTED.append(msg)
    print(f"  [i] {msg}")


def section(title: str) -> None:
    print(f"\n== {title} ==")


# ------------------------------------------------------------------ bytes ----
def row_bytes(row: np.ndarray) -> bytes:
    """Строка x_bytes -> исходные байты.

    byte_ids() пишет `байт + 1` в uint8, поэтому 0xFF переполняется в 0 — тем же
    кодом, что и padding. Внутри данных нулей быть не может (настоящий 0x00 лежит
    как 0x01), значит нули — это только 0xFF: отрезаем хвостовые (padding) и
    восстанавливаем остальные обратно. Без этого mp3, начинавшийся с кадра
    FF FB, выглядел пустым файлом, и проверка ругалась на 36% строк.
    """
    nonzero = np.flatnonzero(row)
    n = int(nonzero[-1]) + 1 if nonzero.size else 0
    return ((row[:n].astype(np.int16) - 1) & 0xFF).astype(np.uint8).tobytes()


PCAP_MAGICS = (
    b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",   # классический pcap, LE/BE
    b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",   # pcap с наносекундами
    b"\x0a\x0d\x0d\x0a",                          # pcapng
)

# magic-имя -> семейство, если они не совпадают буквально
MAGIC_SIBLINGS = {"mp3raw": "mp3"}


def _ok_b64(b: bytes) -> bool:
    s = b.strip()
    if not s:
        return False
    try:
        base64.b64decode(s + b"=" * ((-len(s)) % 4), validate=True)
        return True
    except (binascii.Error, ValueError):
        return False


def _ok_hex(b: bytes) -> bool:
    s = b.strip()
    if not s or len(s) % 2:
        return False
    try:
        bytes.fromhex(s.decode("ascii"))
        return True
    except (ValueError, UnicodeDecodeError):
        return False


def _ok_b32(b: bytes) -> bool:
    s = b.strip()
    if not s:
        return False
    try:
        base64.b32decode(s + b"=" * ((-len(s)) % 8))
        return True
    except (binascii.Error, ValueError):
        return False


def _ok_mp3(b: bytes) -> bool:
    """ID3v2-тег или сразу MPEG-кадр: синк 11 бит (0xFF + 0xE0) — оба варианта норма."""
    if b.startswith(b"ID3"):
        return True
    return len(b) > 1 and b[0] == 0xFF and (b[1] & 0xE0) == 0xE0


# семейство -> предикат «так и должно начинаться»
CHECKS = {
    "png": lambda b: b.startswith(b"\x89PNG\r\n\x1a\n"),
    "gif": lambda b: b.startswith(b"GIF8"),
    "zip": lambda b: b.startswith(b"PK\x03\x04"),
    "pdf": lambda b: b.startswith(b"%PDF"),
    "sqlite": lambda b: b.startswith(b"SQLite format 3\x00"),
    "pcap": lambda b: b.startswith(PCAP_MAGICS),
    "pcapng": lambda b: b.startswith(b"\x0a\x0d\x0d\x0a"),
    "mp3": _ok_mp3,
    "jpeg": lambda b: b.startswith(b"\xff\xd8\xff"),
    "elf": lambda b: b.startswith(b"\x7fELF"),
    "pe": lambda b: b.startswith(b"MZ"),
    "wav": lambda b: b.startswith(b"RIFF") and b[8:12] == b"WAVE",
    "b64": _ok_b64,
    "hex": _ok_hex,
    # ниже не просили, но проверить дешево и полезно
    "b32": _ok_b32,
    "gzip": lambda b: b.startswith(b"\x1f\x8b"),
    "zlib": lambda b: len(b) > 1 and b[0] == 0x78 and (b[0] << 8 | b[1]) % 31 == 0,
    # форматы из расширенного MAGICS: подпись должна быть на месте
    "rtf": lambda b: b.startswith(b"{\\rtf"),
    "xz": lambda b: b.startswith(b"\xfd7zXZ\x00"),
    "bz2": lambda b: b.startswith(b"BZh"),
    "tiff": lambda b: b.startswith((b"II*\x00", b"MM\x00*")),
    "aiff": lambda b: b.startswith(b"FORM"),
    "caf": lambda b: b.startswith(b"caff"),
    "ogg": lambda b: b.startswith(b"OggS"),
    "flac": lambda b: b.startswith(b"fLaC"),
    "7z": lambda b: b.startswith(b"7z\xbc\xaf\x27\x1c"),
    "rar": lambda b: b.startswith(b"Rar!\x1a\x07"),
    "mkv": lambda b: b.startswith(b"\x1aE\xdf\xa3"),
    "wasm": lambda b: b.startswith(b"\x00asm"),
    "psd": lambda b: b.startswith(b"8BPS"),
    "ico": lambda b: b.startswith(b"\x00\x00\x01\x00"),
}


# ------------------------------------------------------------------- main ----
def main() -> None:
    ap = argparse.ArgumentParser(description="аудит синтетического датасета роутера")
    ap.add_argument("--data", default=DEFAULT_DATA, help="путь к *.npz из gen_tasks.py")
    args = ap.parse_args()

    path = os.path.abspath(args.data)
    print("=== аудит датасета ===")
    print(f"  файл: {path}")
    if not os.path.exists(path):
        warn(f"нет файла {path} — проверять нечего")
        print("\n[=] проблем: 1\n")
        return

    z = np.load(path, allow_pickle=True)
    need = ("x_bytes", "x_hand", "x_hist", "y", "family", "split")
    missing = [k for k in need if k not in z.files]
    if missing:
        warn(f"в npz нет ключей: {missing} (есть: {list(z.files)})")
        print("\n[=] проблем: 1\n")
        return

    xb = z["x_bytes"]
    xh = z["x_hand"].astype(np.float32, copy=False)
    y = z["y"]
    fam = np.asarray([str(f) for f in z["family"]])
    split = np.asarray([str(s) for s in z["split"]])
    n = len(fam)
    print(f"  примеров: {n}, x_bytes {xb.shape}, x_hand {xh.shape}, y {y.dtype}")

    counts = Counter(split.tolist())
    print("  сплиты: " + ", ".join(f"{s}={counts.get(s, 0)}" for s in SPLITS))

    # ---------------------------------------------------------- 1. раскладка --
    section("1. сколько примеров на семейство по сплитам")
    fams = sorted(set(fam.tolist()))
    cells = Counter(zip(fam.tolist(), split.tolist()))
    fw = max(12, max(len(f) for f in fams) + 2)
    print("  " + "family".ljust(fw) + "".join(s.rjust(8) for s in SPLITS) + "total".rjust(7))
    for f in fams:
        cnt = [cells.get((f, s), 0) for s in SPLITS]
        line = "  " + f.ljust(fw) + "".join(str(c).rjust(8) for c in cnt) + str(sum(cnt)).rjust(7)
        marks = []
        if cnt[0] < MIN_TRAIN:
            marks.append(f"мало train (<{MIN_TRAIN})")
        if cnt[2] == 0:
            marks.append("нет в test")
        if marks:
            if f in NOVEL:
                line += "  [i] " + ", ".join(marks) + " (NOVEL по дизайну)"
                note(f"{f}: train={cnt[0]}, test={cnt[2]} — это NOVEL, так и задумано")
            else:
                line += "  [!] " + ", ".join(marks)
                warn(f"{f}: train={cnt[0]}, test={cnt[2]}")
        print(line)

    absent = [f for f in FAMILIES if f not in fams]
    extra = [f for f in fams if f not in FAMILIES]
    if absent:
        print(f"  классы FAMILIES, которых нет в датасете: {absent}")
        warn(f"в датасете нет классов {absent} — npz собран другой версией gen_artifacts.py")
    if extra:
        warn(f"в датасете есть семейства вне FAMILIES: {extra}")

    # --------------------------------------------------------- 2. структура ---
    section("2. структура байтов (x_bytes = байт+1, хвост обрезан до 256 Б)")
    print("  family".ljust(14) + "проверено".rjust(11) + "нарушений".rjust(11) + "доля".rjust(8))
    total_bad = 0
    for f, check in CHECKS.items():
        idx = np.flatnonzero(fam == f)
        if idx.size == 0:
            continue
        bad = sum(0 if check(row_bytes(xb[i])) else 1 for i in idx)
        total_bad += bad
        share = bad / idx.size
        print(f"  {f:<13}{idx.size:>11}{bad:>11}{share * 100:>7.2f}%")
        if share > 0.02:
            warn(f"{f}: {bad}/{idx.size} строк не проходят структурную проверку")
    print("  сноска: x_bytes обрезан до 256 байт, видно только начало файла;")
    print("  единичные проценты нарушений — норма, а не битые данные.")
    if total_bad == 0:
        print("  итог: нарушений нет — генераторы пишут честные заголовки и алфавиты.")

    # --------------------------------------------------------- 3. дубликаты ---
    section("3. дубликаты и утечка train -> test")
    print(f"  строк: {n}")
    hist = z["x_hist"]

    # (a) настоящий дубль: у двух строк одинаковый ВХОД модели (x_hand + x_hist).
    # x_hand в одиночку отпечатком не является — float32 квантует энтропию так,
    # что у разных файлов регулярно выходит один и тот же вектор.
    by_hand = defaultdict(int)
    for i in range(n):
        by_hand[xh[i].tobytes()] += 1
    hand_dup = sum(1 for c in by_hand.values() if c > 1)
    hand_rows = sum(c for c in by_hand.values() if c > 1)

    same_input = defaultdict(list)
    for i in range(n):
        digest = hashlib.blake2b(xh[i].tobytes() + hist[i].tobytes(), digest_size=16).digest()
        same_input[digest].append(i)
    dups = [(k, v) for k, v in same_input.items() if len(v) > 1]
    print(f"  (a) одинаковый вход модели (x_hand + x_hist): "
          f"{len(dups)} групп, {sum(len(v) for _k, v in dups)} строк")
    if dups:
        fams_dup = Counter(fam[i] for _k, rows in dups for i in rows)
        print("      семейства: " + ", ".join(f"{f}={c}" for f, c in fams_dup.most_common()))
        by_split = Counter()
        for _k, rows in dups:
            for s, c in Counter(str(split[i]) for i in rows).items():
                if c > 1:
                    by_split[s] += c - 1
        print("      внутри сплитов (лишние строки): "
              + ", ".join(f"{s}={c}" for s, c in sorted(by_split.items())))
        leak = [r for _k, r in dups
                if "train" in set(split[i] for i in r) and "test" in set(split[i] for i in r)]
        seen = sum(1 for r in leak for i in r if split[i] == "test")
        if leak:
            warn(f"утечка: {len(leak)} групп(ы) одинакового входа есть и в train, и в test "
                 f"(test-строк с близнецом в train: {seen})")
        else:
            print("      между train и test одинакового входа нет.")
        for _k, rows in sorted(dups, key=lambda kv: -len(kv[1]))[:3]:
            f0 = fam[rows[0]]
            txt = ""
            if "text" in z.files:
                txt = "".join(ch if 32 <= ord(ch) < 127 else "." for ch in str(z["text"][rows[0]])[:48])
            print(f"      {len(rows):>5d} строк  {f0:<10s} "
                  f"splits={sorted(set(str(split[i]) for i in rows))}  "
                  f"нач. байтов: {row_bytes(xb[rows[0]])[:12].hex()}")
            if txt:
                print(f"            text[..48]: {txt}")
    else:
        print("      полных дублей нет.")

    # (b) совпал только 256-байтовый префикс — то, что видит byte-модель
    groups = defaultdict(list)
    for i in range(n):
        groups[xb[i].tobytes()].append(i)
    pref = [(k, v) for k, v in groups.items() if len(v) > 1]
    lost = sum(len(v) - 1 for _k, v in pref)
    print(f"  (b) одинаковый префикс 256 Б: {len(pref)} групп, {lost} «лишних» строк, "
          f"уникальных префиксов {len(groups)}/{n}")
    if pref:
        fams_pref = Counter(fam[i] for _k, rows in pref for i in rows)
        print("      семейства: " + ", ".join(f"{f}={c}" for f, c in fams_pref.most_common()))
        top = max(pref, key=lambda kv: len(kv[1]))
        print(f"      самая большая: {len(top[1])} строк, family={fam[top[1][0]]}, "
              f"splits={sorted(set(str(split[i]) for i in top[1]))}")
        # где именно слепое пятно: сколько уникальных префиксов внутри семейства
        blind = []
        for f in fams:
            idx = np.flatnonzero(fam == f)
            uniq = len({xb[i].tobytes() for i in idx})
            if uniq < idx.size:
                blind.append((f, idx.size, uniq))
        blind.sort(key=lambda t: t[2] / t[1])
        print("      слепое пятно по семействам (уникальных префиксов / строк):")
        for f, total_f, uniq in blind:
            print(f"        {f:<12} {uniq:>4}/{total_f:<4}  ({uniq / total_f * 100:.1f}%)")
        print("      это статические шапки контейнеров: у таких семейств первые 256 Б")
        print("      одинаковы у всех примеров, поэтому byte-модель их не различает —")
        print("      но сами артефакты разные, так что это не утечка, а слепое пятно.")
    print(f"  сноска: x_hand в одиночку — плохой отпечаток ({hand_dup} групп, {hand_rows} строк "
          f"совпадают случайно из-за float32), поэтому дубли считаются по x_hand+x_hist.")

    # ------------------------------------------------------------- 4. метки ---
    section("4. согласованность y и family")
    fam2idx = {f: i for i, f in enumerate(FAMILIES)}
    expected = np.array([fam2idx.get(f, -1) for f in fam.tolist()], dtype=np.int64)
    unknown = int((expected < 0).sum())
    if unknown:
        warn(f"{unknown} строк с семейством вне FAMILIES — y для них сравнить не с чем")
    mask = expected >= 0
    wrong = mask & (y.astype(np.int64) != expected)
    bad = int(wrong.sum())
    print(f"  проверено строк: {int(mask.sum())}, несовпадений y != FAMILIES.index(family): {bad}")
    if bad:
        pairs = Counter((fam[i], int(y[i]), int(expected[i])) for i in np.flatnonzero(wrong))
        warn(f"перепутанные метки: {bad} строк")
        for (f, got, want), c in pairs.most_common(5):
            print(f"    {f}: y={got}, должно быть {want} ({c} строк)")

    # --------------------------------------------------------- 5. признаки ---
    section("5. признаки x_hand")
    finite = np.isfinite(xh)
    print(f"  NaN/inf: {int((~finite).sum())}")
    if not finite.all():
        cols = np.flatnonzero(~finite.all(axis=0))
        warn(f"в x_hand есть NaN/inf в колонках {cols.tolist()} "
             f"(строк затронуто: {int((~finite.all(axis=1)).sum())})")
    dead = np.flatnonzero(xh.std(axis=0) == 0)
    if dead.size:
        names = [FEATURE_NAMES[i] if i < len(FEATURE_NAMES) else f"col{i}" for i in dead]
        print(f"  константные колонки по всему датасету: {len(dead)} — "
              f"{', '.join(names[:10])}{' ...' if len(names) > 10 else ''}")
        note(f"мёртвые признаки: {', '.join(names[:10])} (всегда одно значение — "
             f"модель по ним ничего не различает)")
    else:
        print("  константных колонок нет.")

    frozen = [f for f in fams if xh[fam == f].std(axis=0).max() == 0]
    if frozen:
        warn(f"классы с полностью одинаковым вектором признаков (баг генератора): {frozen}")
    else:
        print("  ни один класс не вырожден в один и тот же вектор признаков.")

    # magic-флаг в x_hand должен стоять ровно у своего семейства
    # magic-флаг в x_hand должен стоять ровно у своего семейства.
    # mp3raw — это тот же mp3, только без ID3-тега, поэтому его колонка
    # приписывается семейству mp3 (иначе 40% mp3 «не согласованы»).
    by_family = defaultdict(list)
    for i, name in enumerate(FEATURE_NAMES):
        if i >= MAGIC_OFFSET:
            magic_name = name[len("magic_"):]
            by_family[MAGIC_SIBLINGS.get(magic_name, magic_name)].append(i)
    mism = []
    for family, cols in by_family.items():
        if family not in fams:
            continue
        vec = xh[:, cols].max(axis=1)   # у pcap/tiff/mp3 несколько подписей
        inside, outside = vec[fam == family], vec[fam != family]
        hit = float((inside > 0.5).mean()) if inside.size else 0.0
        fp = float((outside > 0.5).mean()) if outside.size else 0.0
        if hit < 0.99 or fp > 0.01:
            mism.append((family, hit))
    if mism:
        for family, hit in mism:
            warn(f"magic_{family}: стоит у {hit * 100:.1f}% «своих» строк — "
                 f"признак не согласован с меткой")
    else:
        print("  magic-признаки согласованы с метками: свои -> 100%, чужие -> 0%.")

    # -------------------------------------------------------------- итог -----
    section("итог")
    if not PROBLEMS:
        print("  проблем не найдено.")
    else:
        print(f"  проблем: {len(PROBLEMS)}")
        for msg in PROBLEMS:
            print(f"    - {msg}")
    if EXPECTED:
        print(f"  ожидаемо (не проблема): {len(EXPECTED)}")
        for msg in EXPECTED:
            print(f"    - {msg}")
    print(f"\n[=] вердикт: {'данные в порядке' if not PROBLEMS else 'есть проблемы, см. [!] выше'}\n")


if __name__ == "__main__":
    setup = getattr(sys.stdout, "reconfigure", None)
    if setup:  # кириллица в консоли Windows: utf-8 + не падать на редких символах
        try:
            if os.name == "nt":
                import ctypes
                ctypes.windll.kernel32.SetConsoleOutputCP(65001)
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    main()
