#!/usr/bin/env python
"""Сбор трасс решения «состояние -> действие -> результат» из реальных прогонов солвера.

Обходит папки задач, для каждой запускает `solve.py <dir> --time N --events - --json`
и превращает поток событий в одну строку JSONL:

    {"task", "dir", "files", "seconds", "flag_found", "flag", "status",
     "steps": [{"n", "tool", "args", "why", "t_start", "t_end", "seconds",
                "status", "flags", "leads", "error"}]}

Использование:
    python ml/collect.py --limit 60 --time 20 --out F:\\AIproject\\ml-runs\\traces.jsonl
    python ml/collect.py --roots F:\\...\\custom_tasks --limit 3 --time 10
"""
import argparse
import json
import os
import re
import statistics
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SOLVE = os.path.join(os.path.dirname(HERE), "solve.py")

DEFAULT_ROOTS = [r"F:\AIproject\_scratch\custom_tasks",
                 r"F:\AIproject\ctf-files\archive"]

# флаг, который похож на приманку/заглушку: так помечаем трассу, но не правим её
SUSPECT = re.compile(r"redact|not_the_flag|your_flag|placeholder|example|dummy|"
                     r"this_may_look_like|fake|xxx+|test_flag|lorem", re.I)

# папки-контейнеры, которые не являются задачей, даже если в них есть файлы
BLOCK = {
    "src", "source", "sources", "bin", "binary", "binaries", "build", "dist",
    "out", "output", "static", "css", "js", "assets", "public", "templates",
    "views", "node_modules", "venv", "env", "__pycache__", "docs", "doc",
    "images", "img", "files", "stuff", "data", "lib", "libs", "include",
    "web", "pwn", "crypto", "cryptography", "reverse", "rev", "forensic",
    "forensics", "misc", "stego", "osint", "hardware", "ppc", "network",
    "blockchain", "web3", "jail", "sandbox", "docker", "deploy", "tests",
}
MAX_DEPTH = 4          # глубина задачи от корня (archive/event/year/cat/task)
MAX_FILES = 60         # больше файлов — слишком тяжёлая папка для 20 сек
MAX_BYTES = 80 << 20


def _junk(name):
    low = name.lower()
    return (low.startswith(".") or low.startswith("_") or low.startswith("readme")
            or low in ("license", "licence", "changelog"))


def discover(root):
    """Список папок-задач: есть файлы, имя не контейнер, нет предка-кандидата."""
    if not os.path.isdir(root):
        return []
    found = {}
    keep = set()

    def scan(path, depth):
        try:
            entries = list(os.scandir(path))
        except OSError:
            return
        files = [e for e in entries if e.is_file() and not _junk(e.name)]
        if depth >= 1 and files and os.path.basename(path).lower() not in BLOCK:
            keep.add(path)
        if depth >= MAX_DEPTH:
            return
        for e in entries:
            if e.is_dir() and not _junk(e.name) and not e.is_symlink():
                scan(e.path, depth + 1)

    scan(root, 0)
    for path in keep:
        parent = os.path.dirname(path)
        buried = False
        while len(os.path.normpath(path)) > len(os.path.normpath(root)):
            if parent in keep and parent != path:
                buried = True
                break
            nxt = os.path.dirname(parent)
            if nxt == parent:
                break
            parent = nxt
        if not buried:
            nfiles, nbytes = 0, 0
            for dirpath, _dirs, fnames in os.walk(path):
                for f in fnames:
                    fp = os.path.join(dirpath, f)
                    try:
                        nbytes += os.path.getsize(fp)
                    except OSError:
                        continue
                    nfiles += 1
            if nfiles <= MAX_FILES and nbytes <= MAX_BYTES:
                found[path] = (nfiles, nbytes)
    # лёгкие задачи первыми: успеваем больше за отведённое время
    return [p for p, _ in sorted(found.items(), key=lambda kv: (kv[1][0], kv[1][1]))]


def _read_stream(pipe, sink):
    try:
        for line in pipe:
            sink.append(line)
    except Exception:
        pass


def run_task(task_dir, budget, idle_k, python):
    """Один прогон solve.py. Возвращает (trace, raw_events)."""
    cmd = [python, SOLVE, task_dir, "--time", str(int(budget)),
           "--events", "-", "--json", "--flag-set", "extended", "--any-prefix"]
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    t0 = time.time()
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                cwd=os.path.dirname(SOLVE), env=env,
                                encoding="utf-8", errors="replace", bufsize=1)
    except OSError as e:
        return _err_trace(task_dir, f"не запустился: {e}"), []
    err_lines = []
    threading.Thread(target=_read_stream, args=(proc.stderr, err_lines), daemon=True).start()

    idle_limit = max(90.0, idle_k * budget)
    last = [time.time()]
    killed = [None]

    def watchdog():
        while proc.poll() is None:
            time.sleep(1.0)
            if time.time() - last[0] > idle_limit:
                killed[0] = "нет вывода дольше %.0f c" % idle_limit
                try:
                    proc.kill()
                except Exception:
                    pass
                return

    t = threading.Thread(target=watchdog, daemon=True)
    t.start()

    events, result = [], None
    try:
        for line in proc.stdout:
            last[0] = time.time()
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if not isinstance(obj, dict):
                continue
            now = time.time()
            obj["_t"] = now
            if obj.get("event"):
                events.append(obj)
            elif obj.get("version"):
                result = obj
    finally:
        try:
            proc.stdout.close()
        except Exception:
            pass
    try:
        proc.wait(timeout=30)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    elapsed = round(time.time() - t0, 2)

    trace = build_trace(task_dir, events, result, elapsed, t0)
    if killed[0]:
        trace["error"] = killed[0]
        trace["flag_found"] = False
    elif proc.returncode not in (0, None) and not result:
        trace["error"] = "rc=%s: %s" % (proc.returncode, "".join(err_lines)[-300:].strip())
    return trace, events


def _err_trace(task_dir, msg):
    return {"task": os.path.basename(task_dir.rstrip("\\/")), "dir": task_dir,
            "files": [], "seconds": 0.0, "flag_found": False, "flag": None,
            "status": "error", "error": msg, "steps": []}


def build_trace(task_dir, events, result, elapsed, t0):
    steps = {}
    order = []
    flag_step = None
    flag = None
    status = None
    flg_total = None
    for ev in events:
        kind = ev.get("event")
        n = ev.get("n")
        if kind == "step_start":
            steps[n] = {"n": n, "tool": ev.get("tool"), "args": ev.get("args") or [],
                        "why": ev.get("why"), "t_start": round(ev["_t"] - t0, 2),
                        "t_end": None, "seconds": None, "status": None,
                        "flags": [], "leads": [], "error": None}
            order.append(n)
        elif kind == "step_end":
            rec = steps.setdefault(n, {"n": n, "tool": ev.get("tool"),
                                       "args": ev.get("args") or [],
                                       "why": ev.get("why"), "t_start": None,
                                       "flags": [], "leads": []})
            rec["t_end"] = round(ev["_t"] - t0, 2)
            rec["seconds"] = ev.get("seconds")
            rec["status"] = ev.get("status")
            rec["flags"] = ev.get("flags") or []
            rec["leads"] = ev.get("leads") or []
            st = ev.get("status")
            if st in ("timeout", "killed", "fail", "skipped"):
                reason = ev.get("reason") or (("rc=%s" % ev.get("rc"))
                                              if ev.get("rc") not in (None, 0) else st)
                rec["error"] = "%s: %s" % (st, reason)
            if n not in order:
                order.append(n)
        elif kind == "lead":
            if n in steps:
                txt = ev.get("text")
                if txt and txt not in steps[n]["leads"]:
                    steps[n]["leads"].append(txt)
        elif kind == "flag":
            flag = ev.get("flag")
            if flag_step is None:
                flag_step = n
            if n in steps:
                steps[n]["flags"] = ev.get("flags") or steps[n]["flags"]
        elif kind == "done":
            status = ev.get("status")
            flg_total = ev.get("elapsed")
            if ev.get("flag"):
                flag = ev.get("flag")

    if result:
        status = status or result.get("status")
        flag = flag or result.get("flag")
        # точные записи шагов (status/seconds/args) — из результата
        by_n = {r.get("n"): r for r in (result.get("steps") or [])}
        for n, rec in steps.items():
            src = by_n.get(n)
            if not src:
                continue
            rec["tool"] = src.get("tool") or rec["tool"]
            rec["args"] = src.get("args") or rec["args"]
            rec["why"] = src.get("why") or rec["why"]
            rec["status"] = src.get("status") or rec["status"]
            if src.get("seconds") is not None:
                rec["seconds"] = src.get("seconds")
            if src.get("flags"):
                rec["flags"] = src["flags"]
            if src.get("leads"):
                rec["leads"] = src["leads"]
            st = src.get("status")
            if st in ("timeout", "killed", "fail", "skipped") and not rec["error"]:
                reason = src.get("reason") or (("rc=%s" % src.get("rc"))
                                               if src.get("rc") not in (None, 0) else st)
                rec["error"] = "%s: %s" % (st, reason)
        for n, src in by_n.items():
            if n is None:
                continue
            if n not in steps:
                steps[n] = {"n": n, "tool": src.get("tool"),
                            "args": src.get("args") or [], "why": src.get("why"),
                            "t_start": None, "t_end": None,
                            "seconds": src.get("seconds"), "status": src.get("status"),
                            "flags": src.get("flags") or [], "leads": src.get("leads") or [],
                            "error": None}
                order.append(n)
        if flag and flag_step is None:
            for n, rec in steps.items():
                if flag in (rec.get("flags") or []):
                    flag_step = n
                    break

    ordered = []
    for n in order:
        rec = steps.get(n)
        if not rec:
            continue
        if rec.get("t_end") is None and rec.get("t_start") is not None \
                and rec.get("seconds") is not None:
            rec["t_end"] = round(rec["t_start"] + rec["seconds"], 2)
        if rec.get("t_start") is None and rec.get("t_end") is not None:
            rec["t_start"] = round(rec["t_end"] - (rec.get("seconds") or 0), 2)
        ordered.append(rec)

    try:
        files = sorted(f for f in os.listdir(task_dir) if not _junk(f))[:40]
    except OSError:
        files = []
    suspect = bool(flag and SUSPECT.search(flag))
    return {"task": os.path.basename(task_dir.rstrip("\\/")), "dir": task_dir,
            "files": files, "seconds": flg_total or elapsed,
            "flag_found": bool(flag), "flag": flag, "flag_suspect": suspect,
            "flag_step": flag_step, "steps": ordered,
            "status": status, "error": None}


def median(vals):
    return statistics.median(vals) if vals else 0


def summarize(traces, out_path):
    n = len(traces)
    solved = [t for t in traces if t["flag_found"]]
    clean = [t for t in solved if not t.get("flag_suspect")]
    errs = [t for t in traces if t.get("error")]
    print("\n===== СВОДКА =====")
    print("задач: %d | решено: %d (%.0f%%) | из них не-приманка: %d | ошибок запуска: %d"
          % (n, len(solved), 100.0 * len(solved) / n if n else 0, len(clean), len(errs)))
    if not traces:
        return
    secs = [t["seconds"] or 0 for t in traces]
    print("секунд на задачу: медиана %.1f, среднее %.1f, всего %.0f"
          % (median(secs), sum(secs) / n, sum(secs)))
    all_steps = [s for t in traces for s in t["steps"]]
    print("шагов на задачу: медиана %.1f, всего %d" % (median([len(t["steps"]) for t in traces]),
                                                       len(all_steps)))

    if solved:
        first = {}
        for t in solved:
            st = None
            for s in t["steps"]:
                if t["flag"] and t["flag"] in (s.get("flags") or []):
                    st = s
                    break
            key = st["tool"] if st else "(нет шага)"
            first[key] = first.get(key, 0) + 1
        print("первый успешный шаг:", ", ".join("%s=%d" % kv for kv in
                                                sorted(first.items(), key=lambda kv: -kv[1])))
        nsteps = []
        for t in solved:
            idx = [i for i, s in enumerate(t["steps"], 1)
                   if t["flag"] and t["flag"] in (s.get("flags") or [])]
            nsteps.append(idx[0] if idx else len(t["steps"]))
        print("шагов до флага: медиана %.1f, минимум %d, максимум %d"
              % (median(nsteps), min(nsteps), max(nsteps)))
        tflag = []
        for t in solved:
            hits = [s for s in t["steps"] if t["flag"] and t["flag"] in (s.get("flags") or [])]
            tflag.append(hits[0].get("t_end") or t["seconds"] or 0)
        print("секунд до флага: медиана %.1f" % median(tflag))

    got, waste, fails = {}, {}, {}
    for s in all_steps:
        tool = s.get("tool") or "?"
        sec = s.get("seconds") or 0
        if s.get("flags"):
            got[tool] = got.get(tool, 0) + 1
        elif s.get("error") or not (s.get("leads")):
            waste[tool] = waste.get(tool, 0) + sec
        if s.get("error"):
            fails[tool] = fails.get(tool, 0) + 1
    print("дали флаг: " + ", ".join("%s=%d" % kv for kv in
                                    sorted(got.items(), key=lambda kv: -kv[1])[:5]))
    print("съели время впустую (сек): " + ", ".join(
        "%s=%.0f" % kv for kv in sorted(waste.items(), key=lambda kv: -kv[1])[:5]))
    print("чаще падают/таймаут: " + ", ".join("%s=%d" % kv for kv in
                                              sorted(fails.items(), key=lambda kv: -kv[1])[:5]))
    if os.path.exists(out_path):
        print("размер %s: %.1f КБ, строк %d"
              % (out_path, os.path.getsize(out_path) / 1024.0, sum(
                  1 for _ in open(out_path, "r", encoding="utf-8"))))


def main():
    ap = argparse.ArgumentParser(description="Трассы решения из прогонов solve.py")
    ap.add_argument("--roots", nargs="+", default=DEFAULT_ROOTS,
                    help="папки с задачами (обход рекурсивный)")
    ap.add_argument("--out", default=r"F:\AIproject\ml-runs\traces.jsonl")
    ap.add_argument("--time", type=float, default=20, help="бюджет на задачу, сек")
    ap.add_argument("--limit", type=int, default=0, help="сколько задач брать (0 = все)")
    ap.add_argument("--idle", type=float, default=3.0,
                    help="убить задачу, если нет вывода > idle*time (мин. 90 c)")
    ap.add_argument("--append", action="store_true", help="дописывать в --out")
    ap.add_argument("--summary", action="store_true",
                    help="только пересчитать сводку по готовому --out")
    args = ap.parse_args()

    if args.summary:
        with open(args.out, "r", encoding="utf-8") as fh:
            summarize([json.loads(line) for line in fh if line.strip()], args.out)
        return 0

    tasks = []
    for root in args.roots:
        got = discover(root)
        print("[i] %s: %d задач" % (root, len(got)))
        tasks.extend(got)
    if args.limit:
        tasks = tasks[:args.limit]
    if not tasks:
        print("[-] задач не нашлось")
        return 2

    out_dir = os.path.dirname(os.path.abspath(args.out))
    if out_dir and not os.path.isdir(out_dir):
        os.makedirs(out_dir, exist_ok=True)
    python = sys.executable or "python"

    traces = []
    t_start = time.time()
    mode = "a" if args.append else "w"
    with open(args.out, mode, encoding="utf-8") as fh:
        for i, d in enumerate(tasks, 1):
            left = time.time() - t_start
            trace, _events = run_task(d, args.time, args.idle, python)
            fh.write(json.dumps(trace, ensure_ascii=False) + "\n")
            fh.flush()
            traces.append(trace)
            mark = "OK " if trace["flag_found"] else ".. "
            print("[%3d/%3d] %s %-42s %5.1fs %2d шагов  +%.0f c  %s"
                  % (i, len(tasks), mark, trace["task"][:42], trace["seconds"] or 0,
                     len(trace["steps"]), left, trace["flag"] or trace.get("error") or ""),
                  flush=True)
    summarize(traces, args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
