"""suggest.py — что модель советует делать с файлом (без torch, без сети).

Читает экспортированный роутер (`export_numpy.py`) и печатает не только
вероятности семейств, но и **с чего начать**: первые инструменты кита для
самого вероятного типа. Это прикладной смысл decision model: не «что это»,
а «куда кинуть».

  python ml/suggest.py F:\\AIproject\\ml-runs\\router_v10.npz chall.bin
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import numpy as np

from np_router import Router

# первый шаг для семейства: чем реально начинать в ките
FIRST_STEPS = {
    "png": ["png_chunks", "lsb", "ocr", "alpha"],
    "gif": ["gif_frames", "video"],
    "jpeg": ["jpeg_tail", "exif", "lsb"],
    "pdf": ["text", "hunt", "pdf_revisions"],
    "zip": ["zipmeta --decode", "ziptricks info", "carve"],
    "sqlite": ["android", "hunt"],
    "pcap": ["dns", "creds", "http", "icmp"],
    "pcapng": ["dns", "creds", "http"],
    "mp3": ["audio", "audiotools --raw", "chain"],
    "wav": ["audiotools --raw", "audio"],
    "elf": ["strings", "disasm --interesting", "megarev"],
    "pe": ["strings", "disasm --interesting", "megarev"],
    "disk_img": ["disk_image scan --find-flags"],
    "b64": ["chain", "enc"],
    "b32": ["chain", "enc"],
    "hex": ["chain", "enc"],
    "rot13": ["chain", "enc"],
    "caesar": ["chain", "enc"],
    "xor1": ["chain", "xorknown"],
    "gzip": ["carve", "chain"],
    "zlib": ["carve", "chain"],
    "xz": ["carve", "chain"],
    "bz2": ["carve", "chain"],
    "utf16": ["chain", "strings --utf16"],
    "rsa": ["rsa auto", "factordb"],
    "py_src": ["hunt", "deobf", "strings"],
    "config_text": ["admin", "hunt"],
    "plain_log": ["logs", "hunt"],
    "json_log": ["hunt", "ws"],
    "doc_text": ["— (это условие задачи, декодировать нечего)"],
    "raw_text": ["ws (zero-width)", "enc", "chain"],
    "reverse": ["chain", "enc"],
    "random_bin": ["entropy/binwalk", "carve"],
    "git_object": ["chain", "strings"],
    "git_index": ["strings", "hunt"],
    "git_pack": ["strings", "carve"],
    "git_ref": ["hunt", "facts"],
    "git_config": ["hunt", "admin"],
}


def _dir_report(router, path, top=5):
    """«Куча файлов»: усредняем мнение модели по папке."""
    files = []
    for dirpath, dirs, names in os.walk(path):
        dirs[:] = [d for d in dirs if d not in (".git", "__pycache__")]
        for n in sorted(names):
            p = os.path.join(dirpath, n)
            try:
                size = os.path.getsize(p)
            except OSError:
                continue
            if 0 < size <= 8 * 1024 * 1024:
                files.append(p)
        if len(files) >= 40:
            break
    if not files:
        print("[-] в папке нет файлов")
        return
    files = files[:40]
    acc = None
    votes = {}
    for p in files:
        try:
            with open(p, "rb") as fh:
                data = fh.read(8 * 1024 * 1024)
        except OSError:
            continue
        probs = router.probs(data)
        acc = probs if acc is None else acc + probs
        fam = router.families[int(probs.argmax())]
        votes[fam] = votes.get(fam, 0) + 1
    if acc is None:
        print("[-] не удалось прочитать файлы")
        return
    acc /= len(files)
    order = np.argsort(-acc)[:top]
    print(f"[+] папка {os.path.basename(path) or path}: {len(files)} файлов")
    print("    по отдельным файлам: " + ", ".join(
        f"{k}×{v}" for k, v in sorted(votes.items(), key=lambda kv: -kv[1])[:6]))
    print("    усреднённое мнение:")
    for i in order:
        print(f"      {router.families[i]:12s} {acc[i]:5.3f}  {'█' * int(acc[i] * 25)}")
    best = router.families[int(order[0])]
    print(f"[>] начинать с: {', '.join(FIRST_STEPS.get(best, ['facts', 'chain']))}")


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: suggest.py <router.npz> <file> [--bare]")
        return 2
    router = Router(sys.argv[1])
    path = sys.argv[2]
    if os.path.isdir(path):
        _dir_report(router, path)
        return 0
    with open(path, "rb") as fh:
        data = fh.read()

    top = router.top(data, 4)
    best, prob = top[0]
    print(f"[+] {os.path.basename(path)}: {len(data)} байт")
    if prob < 0.5:
        print(f"[?] модель не уверена (max {prob:.2f}) — проверь вручную")
    for fam, p in top:
        print(f"    {fam:12s} {p:5.3f}  {'█' * int(p * 25)}")
    steps = FIRST_STEPS.get(best, ["facts", "chain"])
    print(f"[>] начинать с: {', '.join(steps)}")
    if len(top) > 1 and top[1][1] >= 0.25:
        alt = FIRST_STEPS.get(top[1][0], ["facts"])
        print(f"[>] если не сработает — {top[1][0]}: {', '.join(alt)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
