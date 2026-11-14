"""eval_real.py — честная проверка роутера на живых задачах, а не на синтетике.

Синтетический датасет доказывает, что пайплайн работает, но ничего не говорит
о реальности. Здесь берутся 19 самодельных задач из `custom_tasks` (crypto,
stego, forensics, reverse), для каждой вручную прописан ответ: какой файл в
папке — «тот самый» артефакт и к какому семейству он относится.

  python ml/eval_real.py --model F:\\AIproject\\_scratch\\inno\\smoke_mlp.pt
  python ml/eval_real.py --model F:\\AIproject\\ml-runs\\hf_deberta --dir ...

Модель — любой чекпоинт, который понимает `eval_dir.load()`: либо `*.pt` из
train.py (MLP/трансформер), либо папка с HF config.json. Загрузчик общий,
чтобы сравнивать модели одним и тем же ключом ответов.

Ключ ответов писался вручную по task.md и `_answers/*.txt`, правило такое:
семейство = тот инструмент кита, который должен взяться за файл. Если такого
семейства в списке модели нет (например, виженер или zero-width — их в
FAMILIES просто не существует), файл помечается `-` и в точность не идёт.
`doc_text` (task.md) и `py_src` (solve_ref.py) размечены как вспомогательные:
если класса нет у модели, строки честно уходят в «нет класса».
"""
from __future__ import annotations

import argparse
import os
import sys
from collections import Counter, defaultdict

import numpy as np

# работает и из корня репо, и из ml/ — ml/ добавляем в sys.path сами
HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from eval_dir import load  # noqa: E402
from features import hand_features  # noqa: E402

N_HAND = len(hand_features(b""))

DEFAULT_DIR = r"F:\AIproject\_scratch\custom_tasks"

# папка (по номеру) -> (главный артефакт, семейство | None)
#   None = семейства в списке модели нет, файл в точность не идёт
PRIMARY = {
    "01": ("cipher.txt", "rsa"),                    # RSA e=3, m^3 < n
    "02": ("cipher.txt", "rsa"),                    # общий простой делитель
    "03": ("cipher.txt", "rsa"),                    # близкие p,q (Ферма)
    "04": ("cipher.txt", "rsa"),                    # маленькое d (Винер)
    "05": ("traffic.log", "raw_text"),              # лог с base64 и одним nonce
    "06": ("message.txt", None),                    # виженер — семейства нет
    "07": ("photo.png", "png"),                     # LSB, порядок R,B,G
    "08": ("track.mp3", "mp3"),                     # ID3v2.3 TXXX, UTF-16
    "09": ("message.txt", "raw_text"),              # zero-width поверх письма
    "10": ("logo.gif", "gif"),                      # палитра XOR 0x80
    "11": ("photos.zip", "zip"),                    # ZipCrypto, пароль из письма
    "12": ("report.pdf", "pdf"),                    # белый текст на белом
    "13": ("notes.db", "sqlite"),                   # удалённая строка + WAL
    "14": ("capture.pcap", "pcap"),                 # DNS-метки по номерам
    "15": ("license_check.py", "py_src"),           # base64+XOR по кускам
    "16": ("pack.zip", "zip"),                      # hex-имена внутри
    "17": ("recipient1.txt", "rsa"),                # Håstad broadcast
    "18": ("wall.png", "png"),                      # LSB по PRNG-позициям
    "19": ("contract.pdf", "pdf"),                  # инкрементальная редакция
}

# остальные файлы, у которых семейство очевидно (в точность идут, но помечены 'a')
AUX = {
    "01": {"pubkey.txt": "rsa"},
    "02": {"key_alice.txt": "rsa", "key_bob.txt": "rsa"},
    "03": {"pubkey.txt": "rsa"},
    "04": {"pubkey.txt": "rsa"},
    "05": {"known_plaintext.txt": "raw_text"},
    "06": {"poem.txt": "raw_text"},
    "11": {"letter.txt": "raw_text"},
    "13": {"notes.db-wal": "sqlite", "README.txt": "raw_text"},
    "15": {"README.txt": "raw_text"},
    "17": {"note.txt": "raw_text", "recipient2.txt": "rsa", "recipient3.txt": "rsa"},
    "19": {"note.txt": "raw_text"},
}

# правило для любого файла с таким именем во всех папках
COMMON = {"task.md": "doc_text", "solve_ref.py": "py_src"}


def expected_for(folder: str, name: str):
    """-> (семейство | None, пометка 'P' главный / 'a' вспомогательный / '-')."""
    num = folder.split("_", 1)[0]
    prim = PRIMARY.get(num)
    if prim and prim[0] == name:
        return prim[1], "P"
    aux = AUX.get(num, {})
    if name in aux:
        return aux[name], "a"
    if name in COMMON:
        return COMMON[name], "a"
    return None, "-"


def collect(root: str):
    """Все файлы задач; служебные папки (_answers, _build) и report.md не трогаем."""
    out = []
    for cur, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if not d.startswith("_"))
        for name in sorted(names):
            if os.path.dirname(os.path.abspath(os.path.join(cur, name))) == os.path.abspath(root) \
                    and name == "report.md":
                continue
            out.append(os.path.join(cur, name))
    return sorted(out)


def main() -> int:
    ap = argparse.ArgumentParser(description="проверка роутера на реальных задачах")
    ap.add_argument("--model", required=True, help="*.pt из train.py или папка с HF config.json")
    ap.add_argument("--dir", default=DEFAULT_DIR, help="корень custom_tasks")
    ap.add_argument("--top", type=int, default=3, help="сколько вариантов печатать")
    ap.add_argument("--threshold", type=float, default=0.5, help="порог «не уверен»")
    ap.add_argument("--max-files", type=int, default=0, help="0 = все файлы")
    args = ap.parse_args()

    kind, predict, families = load(args.model)
    fam_names = [str(f) for f in families]
    fam2idx = {f: i for i, f in enumerate(fam_names)}
    print(f"[+] модель: {kind}, классов: {len(fam_names)}, чекпоинт: {args.model}")
    if all(f.isdigit() for f in fam_names):
        print("[!] у чекпоинта нет metrics.json с families — вместо имён классов числа,")
        print("    сопоставить их с ключом ответов нечем: точность будет нулевой по смыслу")
    print(f"[+] корень: {args.dir}")

    # пробный прогон: часть старых чекпоинтов обучена на другом наборе признаков
    try:
        predict(b"probe")
    except Exception as exc:  # noqa: BLE001 — нужен любой сбой совместимости
        print(f"[!] чекпоинт не применяется к текущим признакам: {type(exc).__name__}: {exc}")
        print(f"    похоже, он обучен на другой версии features.py (сейчас {N_HAND} признаков).")
        print("    для сравнения берите чекпоинты, собранные на data_v2_100k.npz.")
        return 1

    files = collect(args.dir)
    if args.max_files:
        files = files[:args.max_files]
    rows = []
    for p in files:
        try:
            data = open(p, "rb").read()
        except OSError as exc:
            print(f"  ... не открылся {p}: {exc}")
            continue
        rel = os.path.relpath(p, args.dir)
        folder = rel.split(os.sep)[0]
        exp, tag = expected_for(folder, os.path.basename(p))
        try:
            probs = np.asarray(predict(data), dtype=np.float64)
        except Exception as exc:  # noqa: BLE001 — один битый файл не должен ронять прогон
            print(f"  ... модель упала на {rel}: {type(exc).__name__}: {exc}")
            continue
        order = np.argsort(-probs)[:args.top]
        best = fam_names[int(order[0])]
        rows.append(dict(rel=rel, exp=exp, tag=tag, size=len(data),
                         best=best, best_p=float(probs[order[0]]), order=order, probs=probs))

    print(f"[+] файлов: {len(rows)}, из них с меткой: {sum(r['tag'] != '-' for r in rows)}")

    print("\n== по файлам ==")
    correct = scored = unsure = 0
    prim_ok = prim_all = 0
    blocked: Counter = Counter()
    confusion = Counter()
    per_exp: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for r in rows:
        top = " | ".join(f"{fam_names[int(i)]} {r['probs'][int(i)]:.2f}" for i in r["order"])
        if r["exp"] is None:
            verdict, exp_s, tail = "-", "-", ""
        elif r["exp"] not in fam2idx:
            verdict, exp_s = "-", r["exp"]
            tail = "  [класса нет в модели]"
            blocked[r["exp"]] += 1
        else:
            scored += 1
            ok = r["best"] == r["exp"]
            correct += int(ok)
            verdict = "OK" if ok else "WRONG"
            exp_s, tail = r["exp"], ""
            per_exp[r["exp"]][1] += 1
            per_exp[r["exp"]][0] += int(ok)
            if not ok:
                confusion[(r["exp"], r["best"])] += 1
            if r["tag"] == "P":
                prim_all += 1
                prim_ok += int(ok)
            if r["best_p"] < args.threshold:
                unsure += 1
        print(f"  {verdict:<6}[{r['tag']}] {r['rel']:<50s} {r['size']:>8d}B  "
              f"exp={exp_s:<12s} {top}{tail}")

    print("\n== итог по размеченным ==")
    if scored:
        print(f"  точность: {correct}/{scored} = {correct / scored * 100:.1f}%")
    else:
        print("  нечего считать: ни одна метка не попала в классы модели")
    if prim_all:
        print(f"  только главные артефакты: {prim_ok}/{prim_all} = {prim_ok / prim_all * 100:.1f}%")
    print(f"  «не уверен» (max prob < {args.threshold}): {unsure}/{scored}")
    if blocked:
        total_blocked = sum(blocked.values())
        pairs = ", ".join(f"{k} x{v}" for k, v in blocked.most_common())
        print(f"  меток вне словаря модели: {total_blocked} ({pairs}) — исключены")

    print("\n== confusion: ожидали -> что ответила модель ==")
    if not confusion:
        print("  ошибок нет.")
    for (exp, got), c in confusion.most_common():
        print(f"  {exp:<10s} -> {got:<12s} {c}")

    print("\n== точность по ожидаемым семействам ==")
    for exp in sorted(per_exp):
        ok, tot = per_exp[exp]
        bar = "#" * round(10 * ok / tot) if tot else ""
        print(f"  {exp:<10s} {ok}/{tot} {bar}")

    print()
    return 0


if __name__ == "__main__":
    if getattr(sys.stdout, "reconfigure", None):  # кириллица: utf-8 в консоли Windows
        try:
            if os.name == "nt":
                import ctypes
                ctypes.windll.kernel32.SetConsoleOutputCP(65001)
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    sys.exit(main())
