#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
app.py — тонкий прототип сайта (тикеты #143 + #147 + #146).

Цепочка: страница -> загрузка файла -> запуск `solve --events -` ->
живой поток событий в браузер по SSE -> лог шагов и флаг.

Только стандартная библиотека, запуск без установки зависимостей:

    python site/app.py            # http://127.0.0.1:8770

Два режима запуска движка:
  * есть Docker -> изолированная песочница (site/sandbox/runner.py, #142);
  * нет Docker  -> прямой ЛОКАЛЬНЫЙ запуск solve (без изоляции). Годится для
    проверки «решает/нет» на своей машине; для чужих файлов нужна песочница.

Это прототип: без логина, очереди, истории и защиты сайта (см. docs/SITE.md).
"""
from __future__ import annotations

import json
import os
import queue
import re
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
STATIC = os.path.join(HERE, "static")
sys.path.insert(0, os.path.join(HERE, "sandbox"))

try:
    import runner as sandbox  # site/sandbox/runner.py (#142)
except Exception:  # pragma: no cover
    sandbox = None

sys.path.insert(0, os.path.join(HERE, "ai"))
try:
    import deepseek  # site/ai/deepseek.py (#186)
except Exception:  # pragma: no cover
    deepseek = None

AI_FLAG = re.compile(r"[A-Za-z][A-Za-z0-9_]{1,15}\{[^{}\r\n]{2,120}\}")

MAX_UPLOAD = 64 * 1024 * 1024
JOB_ROOT = os.path.join(tempfile.gettempdir(), "ctf_site_jobs")
os.makedirs(JOB_ROOT, exist_ok=True)

_jobs: dict[str, dict] = {}
_lock = threading.Lock()


def docker_on() -> bool:
    return bool(sandbox and sandbox.docker_available(probe=True))


def _safe_name(name: str) -> str:
    name = os.path.basename((name or "").replace("\\", "/")) or "upload.bin"
    return "".join(c for c in name if c.isalnum() or c in "._-")[:120] or "upload.bin"


def engine_events(path: str, budget: float, flag_prefix: str | None):
    """Генератор dict-событий от движка. Через песочницу или напрямую."""
    if docker_on():
        yield from sandbox.run(path, mode="offline", engine_budget=budget,
                               flag_format=flag_prefix or None, want_summary=True)
        return
    # Прямой локальный режим (без изоляции).
    cmd = [sys.executable, os.path.join(ROOT, "solve.py"), path,
           "--events", "-", "--time", str(budget)]
    if flag_prefix:
        cmd += ["--flag-prefix", flag_prefix]
    yield {"event": "runner_note", "t": 0.0,
           "note": "ПЕСОЧНИЦА ВЫКЛЮЧЕНА (нет Docker): локальный запуск без изоляции"}
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            env=env, bufsize=1, text=True, encoding="utf-8",
                            errors="replace")
    deadline = time.time() + budget + 30
    try:
        for line in proc.stdout:
            ev = sandbox.parse_event_line(line) if sandbox else _parse(line)
            if ev and ev.get("event"):
                yield ev
            if time.time() > deadline:
                proc.kill()
                yield {"event": "runner_note", "t": 0.0, "note": "таймаут, процесс снят"}
                break
    finally:
        try:
            proc.stdout.close()
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


def _parse(line: str):
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
        return obj if isinstance(obj, dict) and "event" in obj else None
    except Exception:
        return None


def _ai_agent(job, q):
    """Агент-цикл: ИИ пишет решатель, он запускается, при неудаче правится и
    пробует снова. Наружу — только статус (runner_note) и РЕЗУЛЬТАТ (флаг или
    одна строка-ответ), без рассуждений («скрытый пул»). Запуск кода модели —
    через agent.run: без Docker локально с таймаутом (для чужих файлов нужна
    песочница #142)."""
    if not (deepseek and os.environ.get("DEEPSEEK_API_KEY")):
        q.put({"event": "runner_note", "t": 0.0,
               "note": "ИИ выключен: нет DEEPSEEK_API_KEY в окружении сервера"})
        return
    try:
        import agent
    except Exception as e:  # pragma: no cover
        q.put({"event": "runner_note", "t": 0.0, "note": f"агент недоступен: {e}"})
        return
    try:
        data = open(job["path"], "rb").read(40000)
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("latin-1", "replace")
    except OSError as e:
        q.put({"event": "runner_note", "t": 0.0, "note": f"файл не прочитан: {e}"})
        return
    for ev in agent.run(text, filename=os.path.basename(job["path"]),
                        file_path=job["path"]):
        k = ev.get("event")
        if k == "ai_status":
            q.put({"event": "runner_note", "t": 0.0, "note": ev["note"]})
        elif k == "flag":
            job["flag"] = ev["flag"]
            q.put({"event": "flag", "t": 0.0, "tool": "ИИ", "flag": ev["flag"]})
        elif k == "ai_answer":
            q.put({"event": "lead", "t": 0.0, "tool": "ИИ", "text": ev["text"]})


def _worker(job_id: str):
    job = _jobs[job_id]
    q: queue.Queue = job["q"]
    tried = []
    try:
        for ev in engine_events(job["path"], job["budget"], job["prefix"]):
            if ev.get("event") == "done":
                # НЕ пробрасываем done от solve: страница закрывает поток на нём,
                # а ИИ отрабатывает ПОЗЖЕ. Терминал потока — наш runner_end.
                if ev.get("flag"):
                    job["flag"] = ev["flag"]
                continue
            q.put(ev)
            if ev.get("event") == "step_end":
                tried.append(f"{ev.get('tool')}:{ev.get('status')}")
            if ev.get("event") == "flag" and ev.get("flag"):
                job["flag"] = ev["flag"]
    except Exception as e:  # pragma: no cover
        q.put({"event": "runner_note", "t": 0.0, "note": f"ошибка запуска: {e}"})
    try:
        if not job.get("flag"):
            _ai_agent(job, q)
    except Exception as e:  # pragma: no cover
        q.put({"event": "runner_note", "t": 0.0, "note": f"ИИ сбой: {e}"})
    q.put({"event": "runner_end", "t": 0.0, "flag": job.get("flag")})
    q.put(None)


class Handler(BaseHTTPRequestHandler):
    server_version = "ctf-site-proto"

    def log_message(self, *a):  # тише в консоли
        pass

    def _send(self, code, ctype, body: bytes, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            try:
                with open(os.path.join(STATIC, "index.html"), "rb") as f:
                    self._send(200, "text/html; charset=utf-8", f.read())
            except OSError:
                self._send(500, "text/plain; charset=utf-8", b"index.html not found")
            return
        if path == "/health":
            self._send(200, "application/json",
                       json.dumps({"ok": True, "docker": docker_on()}).encode())
            return
        if path.startswith("/events/"):
            self._events(path.rsplit("/", 1)[-1])
            return
        self._send(404, "text/plain; charset=utf-8", b"not found")

    def do_POST(self):
        if self.path.split("?", 1)[0] != "/solve":
            self._send(404, "text/plain; charset=utf-8", b"not found")
            return
        length = int(self.headers.get("Content-Length", 0))
        if length <= 0 or length > MAX_UPLOAD:
            self._send(400, "application/json", b'{"error":"bad size"}')
            return
        data = self.rfile.read(length)
        name = _safe_name(self.headers.get("X-Filename", "upload.bin"))
        try:
            budget = float(self.headers.get("X-Budget", "90"))
        except ValueError:
            budget = 90.0
        budget = max(5.0, min(budget, 600.0))
        prefix = (self.headers.get("X-Flag-Prefix", "") or "").strip()[:40] or None
        job_id = uuid.uuid4().hex
        job_dir = os.path.join(JOB_ROOT, job_id)
        os.makedirs(job_dir, exist_ok=True)
        path = os.path.join(job_dir, name)
        with open(path, "wb") as f:
            f.write(data)
        with _lock:
            _jobs[job_id] = {"path": path, "budget": budget, "prefix": prefix,
                             "q": queue.Queue(), "flag": None, "started": False}
        self._send(200, "application/json",
                   json.dumps({"job_id": job_id}).encode())

    def _events(self, job_id: str):
        job = _jobs.get(job_id)
        if not job:
            self._send(404, "text/plain; charset=utf-8", b"no such job")
            return
        with _lock:
            if not job["started"]:
                job["started"] = True
                threading.Thread(target=_worker, args=(job_id,), daemon=True).start()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        q: queue.Queue = job["q"]
        try:
            while True:
                try:
                    ev = q.get(timeout=15)
                except queue.Empty:
                    self.wfile.write(b": keep-alive\n\n")
                    self.wfile.flush()
                    continue
                if ev is None:
                    break
                payload = json.dumps(ev, ensure_ascii=False).encode("utf-8")
                self.wfile.write(b"data: " + payload + b"\n\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass


def main():
    port = int(os.environ.get("PORT", "8770"))
    bind = os.environ.get("BIND", "127.0.0.1")
    httpd = ThreadingHTTPServer((bind, port), Handler)
    mode = "ПЕСОЧНИЦА (Docker)" if docker_on() else "ЛОКАЛЬНО без изоляции (Docker нет)"
    print(f"[+] http://{bind}:{port}/   движок: {mode}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] стоп")


if __name__ == "__main__":
    main()
