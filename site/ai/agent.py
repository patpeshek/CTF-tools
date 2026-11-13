#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
agent.py — агент-цикл решения.

Модель думает «в скрытом пуле»: наружу не выводятся её рассуждения, только
статус и РЕЗУЛЬТАТ. Цикл: ИИ пишет решатель → он запускается → если флага нет,
вывод возвращается модели, она правит → снова запуск (до max_rounds). Итог —
флаг или одна строка-ответ (напр. «нужен адрес сервиса»).

ВНИМАНИЕ: запускает код, сгенерированный моделью. Для чужих/недоверенных задач
это должно идти через песочницу (site/sandbox/runner.py, #142). Прямой локальный
запуск — только на своей машине (как и весь прототип без Docker).

    DEEPSEEK_API_KEY=... python site/ai/agent.py <файл>
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import deepseek  # noqa: E402

IMAGE = os.environ.get("AGENT_IMAGE", "ctf-agent-solver")
_DOCKER_CANDIDATES = ("docker",
                      r"C:\Program Files\Docker\Docker\resources\bin\docker.exe")


def _docker_bin():
    for c in _DOCKER_CANDIDATES:
        if shutil.which(c) or os.path.isfile(c):
            return c
    return None


DOCKER = _docker_bin()


def docker_ready() -> bool:
    """Доступен ли движок Docker и собран ли образ решателя."""
    if not DOCKER:
        return False
    try:
        if subprocess.run([DOCKER, "info"], capture_output=True, timeout=12).returncode != 0:
            return False
        r = subprocess.run([DOCKER, "image", "inspect", IMAGE],
                           capture_output=True, timeout=12)
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _run_solver(work: str, timeout: int, sandboxed: bool) -> str:
    """Запустить work/sol.py: в контейнере (изоляция) или локально (fallback)."""
    if sandboxed:
        name = "ctfagent_" + uuid.uuid4().hex[:12]
        cmd = [DOCKER, "run", "--rm", "--name", name,
               "--network", "none",
               "--read-only", "--tmpfs", "/tmp:rw,size=256m,nosuid,nodev",
               "-v", f"{work}:/work", "-w", "/work",
               "--memory", "2g", "--memory-swap", "2g", "--cpus", "2",
               "--pids-limit", "256", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges",
               IMAGE, "python", "-I", "sol.py"]
    else:
        cmd = [sys.executable, "-I", os.path.join(work, "sol.py")]
    try:
        r = subprocess.run(cmd, capture_output=True, cwd=work, timeout=timeout,
                           text=True, encoding="utf-8", errors="replace")
        return ((r.stdout or "") + "\n" + (r.stderr or "")).strip()
    except subprocess.TimeoutExpired:
        if sandboxed and DOCKER:
            try:
                subprocess.run([DOCKER, "kill", name], capture_output=True, timeout=15)
            except (OSError, subprocess.SubprocessError):
                pass
        return "TIMEOUT: решатель не уложился во время"

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

CODE_RE = re.compile(r"```(?:python)?\s*(.*?)```", re.S)
FLAG_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{1,15}\{[^{}\r\n]{1,160}\}")

SYSTEM = (
    "Ты автоматический CTF-решатель. Тебе дают артефакт или исходник задачи и, "
    "если есть, файл задачи в текущей папке. Цель — НАПЕЧАТАТЬ ФЛАГ в stdout.\n"
    "Отвечай ТОЛЬКО одним блоком ```python ...``` с полным самодостаточным "
    "решателем, который в конце делает print(флаг). Без объяснений вокруг кода.\n"
    "Файл задачи, если он есть, лежит в текущей папке под своим именем — "
    "открывай его по имени.\n"
    "Если для решения ОБЯЗАТЕЛЬНО нужен запущенный сервис host:port, которого "
    "нет, верни ровно одну строку: NEED_SERVICE: <что нужно подключить>.\n"
    "Если нужна внешняя программа (steghide, sage), вызывай её через subprocess; "
    "если её может не быть — всё равно попробуй.\n"
    "Доступно: pycryptodome, sympy, numpy, pwntools, PIL, requests."
)


def _extract_code(text: str):
    m = CODE_RE.search(text)
    return m.group(1).strip() if m else None


def run(challenge_text: str, *, filename: str = "", file_path: str | None = None,
        pyexe: str | None = None, max_rounds: int = 3, per_run_timeout: int = 60,
        model=None):
    """Генератор событий: ai_status / flag / ai_answer. Рассуждения не выводит."""
    pyexe = pyexe or sys.executable
    work = tempfile.mkdtemp(prefix="ctf_agent_")
    try:
        if file_path and filename and os.path.isfile(file_path):
            try:
                shutil.copyfile(file_path, os.path.join(work, filename))
            except OSError:
                pass
        sandboxed = docker_ready()
        yield {"event": "ai_status",
               "note": ("песочница Docker включена — решатель запускается изолированно"
                        if sandboxed else
                        "ПЕСОЧНИЦА ВЫКЛЮЧЕНА (нет Docker/образа): решатель локально")}
        msgs = [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content":
             f"Имя файла: {filename}\n\nСодержимое задачи:\n```\n{challenge_text[:20000]}\n```"},
        ]
        last_out = ""
        for rnd in range(1, max_rounds + 1):
            yield {"event": "ai_status", "note": f"ИИ пишет решатель (попытка {rnd}/{max_rounds})…"}
            try:
                resp = deepseek.chat(msgs, model=model, max_tokens=2600, temperature=0.1)
            except Exception as e:
                yield {"event": "ai_answer", "text": f"ИИ недоступен: {e}"}
                return
            head = resp.strip().splitlines()[0] if resp.strip() else ""
            if head.upper().startswith(("NEED_SERVICE", "NEED_TOOL")):
                yield {"event": "ai_answer", "text": head[:200]}
                return
            code = _extract_code(resp)
            if not code:
                yield {"event": "ai_answer", "text": (head or "ИИ не дал код решателя")[:200]}
                return
            yield {"event": "ai_status", "note": f"запуск решателя (попытка {rnd})…"}
            with open(os.path.join(work, "sol.py"), "w", encoding="utf-8") as f:
                f.write(code)
            last_out = _run_solver(work, per_run_timeout, sandboxed)
            flags = FLAG_RE.findall(last_out)
            if flags:
                yield {"event": "flag", "flag": flags[-1]}
                return
            if rnd < max_rounds:
                msgs.append({"role": "assistant", "content": resp})
                msgs.append({"role": "user", "content":
                             f"Запуск дал (stdout+stderr):\n```\n{last_out[:3000]}\n```\n"
                             "Флага нет. Исправь решатель и верни ТОЛЬКО ```python```. "
                             "Если без запущенного сервиса/внешней тулзы нельзя — "
                             "одна строка NEED_SERVICE/NEED_TOOL."})
                yield {"event": "ai_status", "note": f"попытка {rnd}: флага нет, правлю…"}
        yield {"event": "ai_answer",
               "text": f"не решил за {max_rounds} попыток; последний вывод: {last_out[:160]}"}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    path = argv[0]
    try:
        data = open(path, "rb").read(40000)
    except OSError as e:
        print(f"[-] {e}")
        return 2
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("latin-1", "replace")
    for ev in run(text, filename=os.path.basename(path), file_path=path):
        k = ev["event"]
        if k == "flag":
            print("ФЛАГ:", ev["flag"])
        elif k == "ai_answer":
            print("ОТВЕТ:", ev["text"])
        else:
            print("[", ev["note"], "]")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
