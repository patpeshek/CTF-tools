"""realdata.py — превратить настоящие файлы в датасет той же формы.

Синтетика учит правилам, но реальные файлы живут в другом распределении
(размеры, энтропия, паддинги). Здесь мы собираем настоящие артефакты,
размечаем их **детерминированно** по сигнатурам и текстовым эвристикам
(`eval_true.expected`) и сохраняем npz с тем же набором ключей, что у
`gen_tasks.py`, но со `split = "real"`.

Что с этим делать:
  * держать как честный тест (`eval_true.py --npz`), не подмешивая в train;
  * или подмешать в обучение (`train.py --add-real`) и посмотреть, не падает
    ли точность на синтетике — это проверяемый эксперимент, а не вера.

  python ml/realdata.py --out F:\\AIproject\\ml-runs\\real_v1.npz ^
      --roots F:\\AIproject\\ctf-files\\таски F:\\AIproject\\ctf-files\\BCACTF ^
              F:\\AIproject\\ctf-files\\corpus ^
              F:\\AIproject\\_scratch\\custom_tasks
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import numpy as np

from eval_true import expected
from features import byte_hist, byte_ids, hand_features

MAX_BYTES = 8 * 1024 * 1024
SKIP_DIRS = {"_answers", "_build", ".git", "__pycache__"}


def walk(roots):
    for root in roots:
        for dirpath, dirs, names in os.walk(root):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for n in sorted(names):
                p = os.path.join(dirpath, n)
                try:
                    if 0 < os.path.getsize(p) <= MAX_BYTES:
                        yield p
                except OSError:
                    continue


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--roots", nargs="+", required=True)
    ap.add_argument("--include-unknown", action="store_true",
                    help="оставить и файлы без уверенной метки (family='-')")
    args = ap.parse_args()

    hand, hist, ids, fam, paths, hashes = [], [], [], [], [], []
    seen = set()
    skipped = 0
    for p in walk(args.roots):
        try:
            with open(p, "rb") as fh:
                data = fh.read(MAX_BYTES)
        except OSError:
            skipped += 1
            continue
        digest = hashlib.sha256(data).hexdigest()[:16]
        if digest in seen:          # один и тот же файл в разных папках
            skipped += 1
            continue
        seen.add(digest)
        label = expected(data, p)
        if label == "-" and not args.include_unknown:
            skipped += 1
            continue
        hand.append(hand_features(data))
        hist.append(byte_hist(data))
        ids.append(byte_ids(data))
        fam.append(label)
        paths.append(os.path.abspath(p))
        hashes.append(digest)

    if not fam:
        print("[-] ничего не собралось")
        return 1

    np.savez(args.out,
             x_hand=np.stack(hand).astype(np.float32),
             x_hist=np.stack(hist).astype(np.float32),
             x_bytes=np.stack(ids).astype(np.uint8),
             family=np.array(fam),
             path=np.array(paths),
             digest=np.array(hashes),
             split=np.array(["real"] * len(fam)))
    counts = {}
    for f in fam:
        counts[f] = counts.get(f, 0) + 1
    print(f"[+] файлов: {len(fam)}, пропущено: {skipped} → {args.out}")
    print("[+] по семействам:")
    for name, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"    {name:12s} {n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
