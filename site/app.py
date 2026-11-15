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
  GET  /health              {ok, sandbox}
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
CACHE_ROOT = os.path.join(tempfile.gettempdir(), "cf_site_cache")
BLOB_DIR = os.path.join(CACHE_ROOT, "blobs")
ART_DIR = os.path.join(CACHE_ROOT, "artifacts")
HISTORY = os.path.join(JOB_ROOT, "history.json")
for _d in (JOB_ROOT, BLOB_DIR, ART_DIR):
    os.makedirs(_d, exist_ok=True)

_jobs: dict[str, dict] = {}
_lock = threading.Lock()

# Сайт — только для этого компьютера: и по bind, и по заголовку Host/Origin.
# Иначе чужой сайт в браузере мог бы дёргать локальный API (терминал, задачи).
LOOPBACK = {"127.0.0.1", "localhost", "::1", "0:0:0:0:0:0:0:1"}


def host_only(value: str) -> str:
    v = (value or "").strip().lower()
    if v.startswith("["):
        return v[1:].split("]", 1)[0]
    if v.count(":") == 1:
        return v.rsplit(":", 1)[0]
    return v


def sha256_bytes(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


def child_env(**extra) -> dict:
    """Окружение для дочерних процессов: без ключей доступа."""
    env = dict(os.environ, **extra)
    for key in ("SOLVER_API_KEY", "SOLVER_API_URL"):
        env.pop(key, None)
    return env


def load_history() -> list:
    try:
        with open(HISTORY, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return []


def save_history(rows: list) -> None:
    tmp = HISTORY + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(rows[-200:], fh, ensure_ascii=False, indent=1)
    os.replace(tmp, HISTORY)


def safe_rel(name: str) -> str:
    """Относительный путь внутри папки задачи: подпапки сохраняются,
    '..' и мусор выкидываются (иначе файлы из разных подпапок затирают друг друга)."""
    parts = [p for p in (name or "").replace("\\", "/").split("/")
             if p and p not in (".", "..")]
    clean = []
    for p in parts:
        c = "".join(ch for ch in p if ch.isalnum() or ch in "._- ")[:80].strip()
        if c:
            clean.append(c)
    return "/".join(clean[-6:]) or "file.bin"


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

def flag_prefixes(prefix: str | None) -> list[str]:
    """Набор префиксов для кита: дефолтные + введённый (почищенный) префикс."""
    try:
        if ROOT not in sys.path:
            sys.path.append(ROOT)
        import common
        out = list(common.DEFAULT_PREFIXES)
    except Exception:
        out = ["ctf", "flag"]
    clean = re.sub(r"[^A-Za-z0-9_]", "", str(prefix or ""))[:40]
    if clean and clean.lower() not in {p.lower() for p in out}:
        out.append(clean)
    return out


def toolkit_events(path: str, budget: float, deep: bool, prefix: str | None,
                   stop_check=None, desc_file: str | None = None):
    cmd = [sys.executable, os.path.join(ROOT, "solve.py"), path,
           "--events", "-", "--time", str(int(budget))]
    if deep:
        cmd.append("--deep")
    if desc_file:
        cmd += ["--desc-file", desc_file]
    for p in flag_prefixes(prefix):
        cmd += ["--flag-prefix", p]
    env = child_env(PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
    yield {"event": "runner_note", "note": "прогон инструментов кита"}
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, env=env,
                                bufsize=1, text=True, encoding="utf-8",
                                errors="replace")
    except OSError as exc:
        yield {"event": "runner_note", "note": f"не запустился кит: {exc}"}
        return
    lines: queue.Queue = queue.Queue()

    def reader():
        try:
            for line in proc.stdout:
                lines.put(line)
        finally:
            lines.put(None)

    threading.Thread(target=reader, daemon=True).start()
    deadline = time.time() + budget + 30
    try:
        while True:
            if stop_check and stop_check():
                proc.kill()
                yield {"event": "runner_note", "note": "остановлено пользователем"}
                break
            try:
                line = lines.get(timeout=0.5)
            except queue.Empty:
                if time.time() > deadline:
                    proc.kill()
                    yield {"event": "runner_note", "note": "кит: таймаут"}
                    break
                continue
            if line is None:
                break
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
    finally:
        try:
            proc.stdout.close()
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


def _agent_events(job: dict):
    if not (engine and model_ready()):
        return
    ws = engine.Workspace(job["work"],
                          cancel=lambda: job.get("stop", False)
                          or job.get("finished", False),
                          env={"FLAG_PREFIXES":
                               ",".join(flag_prefixes(job.get("prefix")))})
    task = job["task"] or ""
    if job["inputs"]:
        lines = [f"[{i.get('role') or 'данные'}] {i.get('value', '')}"
                 for i in job["inputs"] if str(i.get("value", "")).strip()]
        if lines:
            task += "\n\nДанные из условия:\n" + "\n".join(lines)
    yield from engine.run(ws, task, max_steps=16,
                          deadline=time.time() + max(120, job["budget"] * 3),
                          reasoning=job.get("reasoning", False),
                          show_thoughts=job.get("thoughts", False),
                          cancel=lambda: job.get("stop", False)
                          or job.get("finished", False))


# ---------------------------------------------------------------------- worker

FLAG_OK = re.compile(r"^[A-Za-z][A-Za-z0-9_]{1,15}\{[ -~]{1,200}\}$")


# локальные приманки: настоящий флаг в задачах с инстансом отдаёт сервер
FAKE_FLAG_RX = re.compile(
    r"(?i)(fake|not[_-]?solve|not[_-]?solved|not[_-]?real|not[_-]?the[_-]?real|"
    r"placeholder|example|dummy|decoy|sample[_-]?flag|test[_-]?flag|"
    r"local[_-]?only|need[_-]?server|replace[_-]?me|insert[_-]?flag)")


def valid_flag(text: str) -> bool:
    """Флаг — одна строка без переводов строк, кавычек, слэшей и скобок внутри."""
    text = (text or "").strip()
    if not FLAG_OK.match(text):
        return False
    inner = text[text.index("{") + 1:-1]
    if not any(c.isalnum() for c in inner):
        return False
    if set(inner) <= set(".… []{}"):
        return False
    return not any(c in inner for c in '\n\r\t"\\[]{}')


def _emit(job: dict, ev: dict) -> None:
    """Кладём событие в очередь и в файл <job>/events.jsonl (для разбора потом)."""
    job["q"].put(ev)
    try:
        with open(os.path.join(job["meta"], "events.jsonl"), "a",
                  encoding="utf-8") as fh:
            fh.write(json.dumps(ev, ensure_ascii=False) + "\n")
    except OSError:
        pass


def _cache_artifacts(job: dict) -> list:
    """Сохранить файлы, которые создал движок (не загруженные), по хешу входа."""
    if not job.get("input_hash"):
        return []
    uploaded = {u["name"] for u in job.get("uploaded", [])}
    art_dir = os.path.join(ART_DIR, job["input_hash"])
    os.makedirs(art_dir, exist_ok=True)
    saved = []
    for base, _dirs, files in os.walk(job["work"]):
        for name in files:
            if name in uploaded or name.endswith(".pyc"):
                continue
            src = os.path.join(base, name)
            rel = os.path.relpath(src, job["work"])
            if rel.startswith("__pycache__"):
                continue
            dst = os.path.join(art_dir, rel.replace("/", "__"))
            try:
                if os.path.getsize(src) <= 5 * 1024 * 1024:
                    shutil.copyfile(src, dst)
                    saved.append(rel)
            except OSError:
                pass
    return saved[:100]


def worker(job_id: str):
    """Кит и доработка идут ОДНОВРЕМЕННО; что первое нашло — то и ответ."""
    job = _jobs[job_id]
    job["status"] = "running"
    q: queue.Queue = job["q"]
    if job.get("reused"):
        _emit(job, {"event": "runner_note",
                    "note": "подхватил прошлые наработки: "
                            + ", ".join(job["reused"][:5])})
    target = job["in"]
    files = [f for f in os.listdir(target)]
    single = os.path.join(target, files[0]) if len(files) == 1 else target
    out: queue.Queue = queue.Queue()
    desc_path = os.path.join(job["meta"], "task.txt")
    desc = job["task"].strip()
    extra = []
    for item in job.get("inputs") or []:
        value = str(item.get("value", "")).strip()
        if not value:
            continue
        role = str(item.get("role") or "").lower()
        if role in ("пароль", "password", "pass"):
            extra.append(f"password: {value}")
        elif role in ("url", "ссылка", "сайт"):
            extra.append(f"url: {value}")
        elif role in ("логин", "login", "user"):
            extra.append(f"login: {value}")
        else:
            extra.append(f"[{item.get('role') or 'данные'}] {value}")
    # сервис для pwn: отдельная строка, чтобы разбор условия точно увидел host:port
    hosts = [i.get("value", "") for i in job.get("inputs") or []
             if (i.get("role") or "").lower() in ("адрес", "host", "ip")
             and str(i.get("value", "")).strip()]
    if hosts:
        extra.append("сервис: " + " ".join(str(h) for h in hosts))
    if desc or extra:
        try:
            with open(desc_path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(desc + ("\n\nДанные из условия:\n" + "\n".join(extra)
                                 if extra else ""))
        except OSError:
            desc_path = None
    else:
        desc_path = None

    def stage_kit():
        try:
            if not files:
                out.put(("kit", {"event": "runner_note",
                                 "note": "файлов нет — кит пропущен, работаю по тексту"}))
                return
            for ev in toolkit_events(single, job["budget"], job["deep"],
                                     job["prefix"], desc_file=desc_path,
                                     stop_check=lambda: job.get("stop")
                                     or job.get("finished")):
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
        if ev.get("event") == "flag":
            candidate = str(ev.get("flag") or "")
            if valid_flag(candidate) and FAKE_FLAG_RX.search(candidate):
                _emit(job, {"event": "runner_note",
                            "note": "приманка из файла (нужен инстанс), "
                                    "не считаю решением: " + candidate[:80]})
                continue
            if not valid_flag(candidate):
                _emit(job, {"event": "runner_note",
                            "note": "движок вернул не флаг, отбросил: "
                                    + repr(candidate)[:160]})
                continue
        _emit(job, ev)
        if ev.get("event") == "flag" and ev.get("flag"):
            flag = ev["flag"]
            job["finished"] = True
            break

    job["flag"] = flag
    job["status"] = ("stopped" if job.get("stop")
                     else ("done" if flag else "no_flag"))
    saved = _cache_artifacts(job)
    _emit(job, {"event": "runner_end", "flag": flag, "cached": saved[:10]})
    with _lock:
        rows = load_history()
        for row in rows:
            if row.get("id") == job_id:
                row.update({"status": job["status"], "flag": flag})
        save_history(rows)
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

    def _local_only(self) -> bool:
        if os.environ.get("ALLOW_REMOTE") == "1":
            return True
        host = host_only(self.headers.get("Host", ""))
        if host and host not in LOOPBACK:
            return False
        origin = self.headers.get("Origin")
        if origin:
            from urllib.parse import urlsplit
            try:
                ohost = (urlsplit(origin).hostname or "").lower()
            except ValueError:
                return False
            if ohost not in LOOPBACK:
                return False
        return True

    # ---------------- GET

    def do_GET(self):
        if not self._local_only():
            self._json(403, {"error": "только с этого компьютера"})
            return
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            try:
                with open(os.path.join(STATIC, "index.html"), "rb") as fh:
                    self._send(200, "text/html; charset=utf-8", fh.read())
            except OSError:
                self._send(500, "text/plain; charset=utf-8", b"no index.html")
            return
        if path == "/health":
            self._json(200, {"ok": True, "sandbox": docker_on()})
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
        if path.startswith("/api/status/"):
            job = _jobs.get(path.rsplit("/", 1)[-1])
            if not job:
                self._json(404, {"error": "no job"})
                return
            self._json(200, {"id": path.rsplit("/", 1)[-1],
                             "status": job.get("status"),
                             "started": job.get("started"),
                             "flag": job.get("flag"),
                             "reused": job.get("reused", [])})
            return
        if path == "/api/history":
            self._json(200, {"jobs": load_history()[-50:]})
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
                if os.path.relpath(full, job["dir"]).split(os.sep)[0] == "meta":
                    raise ValueError("служебная папка")
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
        if not self._local_only():
            self._json(403, {"error": "только с этого компьютера"})
            return
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
        if not data and int(self.headers.get("Content-Length", 0) or 0) > MAX_TOTAL:
            self._json(413, {"error": "слишком большой запрос (лимит 128 МБ): "
                                      "загрузи файлы по одному или архивом"})
            return
        # адрес сервиса без порта — задача не запускается (нечего подключать)
        for item in data.get("inputs") or []:
            role = str(item.get("role") or "").lower()
            value = str(item.get("value") or "").strip()
            if role in ("адрес", "host", "ip") and value and ":" not in value:
                self._json(400, {"error": "адрес сервиса без порта: укажи host:port "
                                          "(поле «порт»)"})
                return
        files = data.get("files") or []
        if not files and not str(data.get("task") or "").strip():
            self._json(400, {"error": "нужна задача или хотя бы один файл"})
            return
        job_id = uuid.uuid4().hex
        job_dir = os.path.join(JOB_ROOT, job_id)
        in_dir = os.path.join(job_dir, "in")
        work_dir = os.path.join(job_dir, "work")
        meta_dir = os.path.join(job_dir, "meta")
        for d in (in_dir, work_dir, meta_dir):
            os.makedirs(d, exist_ok=True)
        saved = 0
        uploaded = []
        for item in files[:MAX_FILES]:
            name = safe_rel(item.get("name", "file.bin"))
            dst_in = os.path.join(in_dir, name.replace("/", os.sep))
            dst_work = os.path.join(work_dir, name.replace("/", os.sep))
            try:
                blob = base64.b64decode(item.get("b64", ""))
            except Exception:
                continue
            if saved + len(blob) > MAX_TOTAL:
                break
            digest = sha256_bytes(blob)
            cached = os.path.join(BLOB_DIR, digest)
            if not os.path.exists(cached):
                with open(cached, "wb") as fh:
                    fh.write(blob)
            os.makedirs(os.path.dirname(dst_in), exist_ok=True)
            os.makedirs(os.path.dirname(dst_work), exist_ok=True)
            shutil.copyfile(cached, dst_in)
            shutil.copyfile(cached, dst_work)
            uploaded.append({"name": name, "size": len(blob), "sha": digest})
            saved += len(blob)
        input_hash = sha256_bytes(
            json.dumps(sorted((u["name"], u["sha"]) for u in uploaded),
                       ensure_ascii=False).encode())
        if not uploaded:
            # задача без файлов: ключ кеша — текст и поля условия, иначе
            # наработки разных текстовых задач смешаются
            seed = str(data.get("task", "")) + json.dumps(
                data.get("inputs") or [], ensure_ascii=False, sort_keys=True)
            input_hash = sha256_bytes(("text:" + seed).encode())
        # артефакты прошлой попытки с теми же входными файлами
        reused = []
        art_dir = os.path.join(ART_DIR, input_hash)
        if os.path.isdir(art_dir):
            for fname in os.listdir(art_dir):
                if fname in {u["name"] for u in uploaded}:
                    continue
                try:
                    shutil.copyfile(os.path.join(art_dir, fname),
                                    os.path.join(work_dir, fname))
                    reused.append(fname)
                except OSError:
                    pass
        try:
            budget = float(data.get("budget", 90))
        except (TypeError, ValueError):
            budget = 90.0
        with _lock:
            _jobs[job_id] = {
                "dir": job_dir,
                "in": in_dir,
                "work": work_dir,
                "meta": meta_dir,
                "task": str(data.get("task", ""))[:20000],
                "inputs": [i for i in (data.get("inputs") or [])
                           if isinstance(i, dict)][:20],
                "budget": max(10.0, min(budget, 900.0)),
                "deep": bool(data.get("deep")),
                "reasoning": bool(data.get("reasoning")),
                "thoughts": bool(data.get("thoughts")),
                "prefix": (data.get("prefix") or "").strip()[:40] or None,
                "q": queue.Queue(), "flag": None, "started": True,
                "finished": False,
                "stop": False, "status": "new", "created": time.time(),
                "uploaded": uploaded, "input_hash": input_hash,
                "reused": reused,
            }
            rows = load_history()
            rows.append({"id": job_id, "created": time.time(),
                         "files": [u["name"] for u in uploaded],
                         "input_hash": input_hash, "status": "new",
                         "flag": None})
            save_history(rows)
        self._json(200, {"id": job_id, "files": list_files(job_dir),
                         "reused": reused})
        threading.Thread(target=worker, args=(job_id,), daemon=True).start()

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
            proc = subprocess.run(cmd, cwd=job["work"], shell=True,
                                  capture_output=True, text=True,
                                  encoding="utf-8", errors="replace",
                                  timeout=60, env=child_env())
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
            if rel.split("/")[0] == "meta":
                continue
            rows.append({"path": rel, "size": os.path.getsize(full)})
    return rows[:500]


class QuietServer(ThreadingHTTPServer):
    """Не печатает трейсбеки, когда браузер/health закрыл соединение."""
    daemon_threads = True

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionResetError, ConnectionAbortedError,
                            BrokenPipeError)):
            return
        super().handle_error(request, client_address)


def main():
    port = int(os.environ.get("PORT", "8771"))
    bind = (os.environ.get("BIND") or "127.0.0.1").strip()
    if bind not in LOOPBACK and os.environ.get("ALLOW_REMOTE") != "1":
        print(f"[!] BIND={bind}: наружу не отдаю. Нужно осознанно — ALLOW_REMOTE=1")
        sys.exit(2)
    httpd = QuietServer((bind, port), Handler)
    mode = "песочница" if docker_on() else "локально (без Docker)"
    print(f"[+] http://{bind}:{port}/  режим: {mode}", flush=True)
    print("[+] доступ только с этого компьютера (127.0.0.1)", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] стоп")


if __name__ == "__main__":
    main()
