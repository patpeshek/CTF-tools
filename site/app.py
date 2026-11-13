#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""app.py — сервер сайта: задача -> прогон кита -> при необходимости агент.

Эндпоинты (JSON):
  POST /api/task            {task, files:[{name,b64}], inputs:[{role,value}],
                             deep, budget, prefix}
  GET  /api/events/<id>     SSE-поток событий (запускает работу)
  POST /api/terminal        {id, cmd} — команда в папке задачи
  GET  /api/files/<id>      список файлов задачи
  GET  /api/file/<id>?path= содержимое файла
  POST /api/stop/<id>       остановить
  GET  /health              {ok, sandbox, model}
  GET  /                    index.html

Только стандартная библиотека.
"""
from __future__ import annotations

import base64
import json
import os
import queue
import re
import shutil
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
ENGINE = os.path.join(HERE, "engine")
sys.path.insert(0, ENGINE)
sys.path.insert(0, os.path.join(HERE, "sandbox"))

try:
    import client as model  # site/engine/client.py
except Exception:  # pragma: no cover
    model = None
try:
    import agent as engine  # site/engine/agent.py
except Exception:  # pragma: no cover
    engine = None
try:
    import runner as sandbox  # site/sandbox/runner.py
except Exception:  # pragma: no cover
    sandbox = None

MAX_FILES = 200
MAX_TOTAL = 128 * 1024 * 1024
JOB_ROOT = os.path.join(tempfile.gettempdir(), "cf_site_jobs")
os.makedirs(JOB_ROOT, exist_ok=True)

_jobs: dict[str, dict] = {}
_lock = threading.Lock()


def safe_name(name: str) -> str:
    name = os.path.basename((name or "").replace("\\", "/")) or "file.bin"
    return "".join(c for c in name if c.isalnum() or c in "._-")[:120] or "file.bin"


def docker_on() -> bool:
    try:
        return bool(sandbox and sandbox.docker_available(probe=True))
    except Exception:
        return False


def model_ready() -> bool:
    try:
        return bool(model and model.ready())
    except Exception:
        return False


# ------------------------------------------------------------------ движок кита

def toolkit_events(path: str, budget: float, deep: bool, prefix: str | None):
    cmd = [sys.executable, os.path.join(ROOT, "solve.py"), path,
           "--events", "-", "--time", str(int(budget))]
    if deep:
        cmd.append("--deep")
    if prefix:
        cmd += ["--flag-prefix", prefix]
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
    yield {"event": "runner_note", "note": "прогон инструментов кита"}
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, env=env,
                                bufsize=1, text=True, encoding="utf-8",
                                errors="replace")
    except OSError as exc:
        yield {"event": "runner_note", "note": f"не запустился кит: {exc}"}
        return
    deadline = time.time() + budget + 30
    try:
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(ev, dict) and ev.get("event"):
                if ev["event"] == "done":
                    continue
                yield ev
            if time.time() > deadline:
                proc.kill()
                yield {"event": "runner_note", "note": "кит: таймаут"}
                break
    finally:
        try:
            proc.stdout.close()
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


def _agent_events(job: dict):
    if not (engine and model_ready()):
        return
    ws = engine.Workspace(job["dir"])
    task = job["task"] or ""
    if job["inputs"]:
        lines = [f"[{i.get('role') or 'данные'}] {i.get('value', '')}"
                 for i in job["inputs"] if str(i.get("value", "")).strip()]
        if lines:
            task += "\n\nДанные из условия:\n" + "\n".join(lines)
    yield from engine.run(ws, task, max_steps=16,
                          deadline=time.time() + max(120, job["budget"] * 3))


# ---------------------------------------------------------------------- worker

def worker(job_id: str):
    """Кит и доработка идут ОДНОВРЕМЕННО; что первое нашло — то и ответ."""
    job = _jobs[job_id]
    q: queue.Queue = job["q"]
    target = job["dir"]
    files = [f for f in os.listdir(target)]
    single = os.path.join(target, files[0]) if len(files) == 1 else target
    out: queue.Queue = queue.Queue()

    def stage_kit():
        try:
            for ev in toolkit_events(single, job["budget"], job["deep"],
                                     job["prefix"]):
                out.put(("kit", ev))
        except Exception as exc:  # pragma: no cover
            out.put(("kit", {"event": "runner_note",
                             "note": f"ошибка кита: {exc}"}))
        finally:
            out.put(("kit", None))

    def stage_second():
        try:
            for ev in _agent_events(job):
                out.put(("second", ev))
        except Exception as exc:  # pragma: no cover
            out.put(("second", {"event": "runner_note",
                                "note": f"ошибка доработки: {exc}"}))
        finally:
            out.put(("second", None))

    threads = [threading.Thread(target=stage_kit, daemon=True),
               threading.Thread(target=stage_second, daemon=True)]
    for th in threads:
        th.start()

    alive = {"kit": True, "second": True}
    flag = None
    while any(alive.values()) and not job.get("stop"):
        try:
            src, ev = out.get(timeout=1.0)
        except queue.Empty:
            continue
        if ev is None:
            alive[src] = False
            continue
        ev = dict(ev)
        ev.setdefault("stage", src)
        q.put(ev)
        if ev.get("event") == "flag" and ev.get("flag"):
            flag = ev["flag"]
            break

    job["flag"] = flag
    q.put({"event": "runner_end", "flag": flag})
    q.put(None)


# ---------------------------------------------------------------------- HTTP

class Handler(BaseHTTPRequestHandler):
    server_version = "ctf-site"
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, ctype, body: bytes):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, "application/json; charset=utf-8",
                   json.dumps(obj, ensure_ascii=False).encode("utf-8"))

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length <= 0 or length > MAX_TOTAL:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    # ---------------- GET

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            try:
                with open(os.path.join(STATIC, "index.html"), "rb") as fh:
                    self._send(200, "text/html; charset=utf-8", fh.read())
            except OSError:
                self._send(500, "text/plain; charset=utf-8", b"no index.html")
            return
        if path == "/health":
            self._json(200, {"ok": True, "sandbox": docker_on(),
                             "model": model_ready()})
            return
        if path.startswith("/api/events/"):
            self._events(path.rsplit("/", 1)[-1])
            return
        if path.startswith("/api/files/"):
            job = _jobs.get(path.rsplit("/", 1)[-1])
            if not job:
                self._json(404, {"error": "no job"})
                return
            self._json(200, {"files": list_files(job["dir"])})
            return
        if path.startswith("/api/file/"):
            job_id = path.rsplit("/", 1)[-1]
            job = _jobs.get(job_id)
            query = self.path.split("?", 1)[1] if "?" in self.path else ""
            rel = ""
            for part in query.split("&"):
                if part.startswith("path="):
                    rel = part[5:].replace("%2F", "/").replace("%20", " ")
            if not job:
                self._json(404, {"error": "no job"})
                return
            try:
                full = os.path.abspath(os.path.join(job["dir"], rel))
                if os.path.commonpath([full, job["dir"]]) != job["dir"]:
                    raise ValueError
                with open(full, "rb") as fh:
                    data = fh.read(200000)
                self._json(200, {"path": rel, "text":
                                 data.decode("utf-8", "replace")})
            except (OSError, ValueError) as exc:
                self._json(400, {"error": str(exc)})
            return
        self._json(404, {"error": "not found"})

    # ---------------- POST

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path == "/api/task":
            self._task()
            return
        if path == "/api/terminal":
            self._terminal()
            return
        if path.startswith("/api/stop/"):
            job = _jobs.get(path.rsplit("/", 1)[-1])
            if job:
                job["stop"] = True
            self._json(200, {"ok": bool(job)})
            return
        self._json(404, {"error": "not found"})

    def _task(self):
        data = self._body()
        files = data.get("files") or []
        if not files:
            self._json(400, {"error": "нужен хотя бы один файл"})
            return
        job_id = uuid.uuid4().hex
        job_dir = os.path.join(JOB_ROOT, job_id)
        os.makedirs(job_dir, exist_ok=True)
        saved = 0
        for item in files[:MAX_FILES]:
            name = safe_name(item.get("name", "file.bin"))
            try:
                blob = base64.b64decode(item.get("b64", ""))
            except Exception:
                continue
            if saved + len(blob) > MAX_TOTAL:
                break
            with open(os.path.join(job_dir, name), "wb") as fh:
                fh.write(blob)
            saved += len(blob)
        try:
            budget = float(data.get("budget", 90))
        except (TypeError, ValueError):
            budget = 90.0
        with _lock:
            _jobs[job_id] = {
                "dir": job_dir,
                "task": str(data.get("task", ""))[:20000],
                "inputs": [i for i in (data.get("inputs") or [])
                           if isinstance(i, dict)][:20],
                "budget": max(10.0, min(budget, 900.0)),
                "deep": bool(data.get("deep")),
                "prefix": (data.get("prefix") or "").strip()[:40] or None,
                "q": queue.Queue(), "flag": None, "started": False,
                "stop": False,
            }
        self._json(200, {"id": job_id, "files": list_files(job_dir)})

    def _terminal(self):
        data = self._body()
        job = _jobs.get(data.get("id", ""))
        if not job:
            self._json(404, {"error": "no job"})
            return
        cmd = str(data.get("cmd", ""))[:2000]
        if not cmd.strip():
            self._json(400, {"error": "пустая команда"})
            return
        started = time.time()
        try:
            proc = subprocess.run(cmd, cwd=job["dir"], shell=True,
                                  capture_output=True, text=True,
                                  encoding="utf-8", errors="replace",
                                  timeout=60)
            out = ((proc.stdout or "") + (proc.stderr or ""))[:20000]
            self._json(200, {"rc": proc.returncode, "out": out,
                             "seconds": round(time.time() - started, 2)})
        except subprocess.TimeoutExpired:
            self._json(200, {"rc": -1, "out": "TIMEOUT 60s",
                             "seconds": round(time.time() - started, 2)})

    def _events(self, job_id: str):
        job = _jobs.get(job_id)
        if not job:
            self._json(404, {"error": "no job"})
            return
        with _lock:
            if not job["started"]:
                job["started"] = True
                threading.Thread(target=worker, args=(job_id,),
                                 daemon=True).start()
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
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
                    continue
                if ev is None:
                    break
                payload = json.dumps(ev, ensure_ascii=False).encode("utf-8")
                self.wfile.write(b"data: " + payload + b"\n\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass


def list_files(root: str):
    rows = []
    for base, _dirs, files in os.walk(root):
        for name in sorted(files):
            full = os.path.join(base, name)
            rel = os.path.relpath(full, root).replace("\\", "/")
            rows.append({"path": rel, "size": os.path.getsize(full)})
    return rows[:500]


def main():
    port = int(os.environ.get("PORT", "8770"))
    bind = os.environ.get("BIND", "127.0.0.1")
    httpd = ThreadingHTTPServer((bind, port), Handler)
    mode = "песочница" if docker_on() else "локально (без Docker)"
    print(f"[+] http://{bind}:{port}/  режим: {mode}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] стоп")


if __name__ == "__main__":
    main()
