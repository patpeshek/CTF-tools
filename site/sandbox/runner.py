#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
runner.py — песочница для запуска движка ``solve`` на недоверенном задании.

Тикет #142. Первый кусок песочницы: собрать команду запуска одного эфемерного
контейнера (``docker run --rm``) с жёстким профилем изоляции, запустить внутри
него ``solve`` на входном файле и построчно отдать поток JSON-событий движка
наружу генератором. Контейнер — по одному на задание; настенный таймаут снимает
контейнер через ``docker kill`` независимо от того, что происходит внутри.

Движок остаётся за границей доверия: сам входной файл runner НЕ разбирает, он
только строит команду, стримит stdout контейнера и парсит строки.

Контракт движка (stdout, по строке на событие, flush после каждой) — docs/SITE.md §4::

    {"event": <plan|step_start|step_end|lead|flag|done>, "t": <сек>, ...поля}

Про флаги движка. Дизайн-документ (SITE.md §3/§4) называет машинный поток
``solve --json -``. В самом движке это два разных флага:

* ``--events -`` — построчный поток событий (plan/step_start/step_end/lead/flag/
  done) в stdout; человеческий лог уходит в stderr. Это и есть контракт §4.
* ``--json``     — одна финальная сводка-объект (version/status/flag/steps/...)
  в stdout в конце прогона.

Поэтому поток событий мы снимаем через ``--events -`` (ровно таблица §4), а
финальную сводку подключаем опцией ``want_summary=True`` (добавляет ``--json``).

Запуск без docker. Если docker недоступен (не установлен или демон не отвечает),
runner не падает: ``run()`` отдаёт одно событие ``runner_note`` с собранной
командой и понятным сообщением (dry-run). Сборка команды и парсинг потока —
чистые функции (``build_command`` / ``parse_event_stream``), тестируются без
docker (см. test_runner.py).
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import threading
import uuid
from typing import Iterable, Iterator, List, Optional

# --- значения по умолчанию ---------------------------------------------------

DEFAULT_IMAGE = "ctf-sandbox:latest"
#: Настенный таймаут в секундах: через столько контейнер снимается docker kill.
#: Это НЕ то же, что бюджет движка ``--time`` (SITE.md §5: «--time этому не
#: замена»). По умолчанию 120 — заметно больше дефолтного бюджета движка (90),
#: чтобы движок успевал завершиться сам, а kill оставался жёстким бэкапом.
DEFAULT_TIMEOUT = 120.0

#: Каталог с кодом движка внутри образа (куда Dockerfile кладёт solve.py и пр.).
ENGINE_DIR = "/engine"

#: События, которые эмитит сам runner (а не движок), — чтобы их было видно
#: отдельно от plan/step_start/step_end/lead/flag/done.
RUNNER_EVENTS = ("runner_note", "runner_end")


# --- сборка команды (чистая функция, тестируется без docker) ------------------


def build_command(
    input_path,
    *,
    image: str = DEFAULT_IMAGE,
    mode: str = "offline",
    flag_format: Optional[str] = None,
    engine_budget: Optional[float] = None,
    network: Optional[str] = None,
    container_name: Optional[str] = None,
    want_summary: bool = False,
    docker: str = "docker",
    engine_dir: str = ENGINE_DIR,
    memory: str = "1g",
    cpus: str = "2",
    pids_limit: int = 256,
    tmpfs_size: str = "512m",
    nofile: int = 1024,
    fsize_bytes: Optional[int] = None,
    extra_docker_args: Optional[Iterable[str]] = None,
    extra_engine_args: Optional[Iterable[str]] = None,
) -> List[str]:
    """Собрать argv для ``docker run`` по профилю изоляции песочницы (#142).

    Профиль (SITE.md §5): сети нет, корень только на чтение, запись лишь в
    tmpfs-скретч, вход смонтирован ``:ro``, жёсткие лимиты памяти/CPU/процессов,
    запуск не-root, все capabilities сняты, no-new-privileges, без docker.sock.

    input_path монтируется только на чтение:

    * файл  -> ``<abs>:/in/<basename>:ro``, цель движка ``/in/<basename>``;
    * папка -> ``<abs>:/in:ro``,            цель движка ``/in``.

    mode:
        ``offline`` (по умолчанию) — ``--network none``, полная изоляция сети.
        ``web``                    — требует явного ``network=<имя>`` (сеть с
        egress-allowlist на хост цели поднимает оркестратор; сам контейнер
        ограничить исходящий трафик не может — SITE.md §7). Это осознанный
        выбор пользователя на форме, не поведение по умолчанию.

    Возвращает список аргументов (argv). Строкой — ``command_to_str``.
    """
    src = os.path.abspath(str(input_path))
    base = os.path.basename(src.rstrip("/\\")) or "input"
    # Контейнерный путь всегда POSIX, вне зависимости от ОС хоста.
    if os.path.isdir(src):
        mount = f"{src}:/in:ro"
        target = "/in"
    else:
        mount = f"{src}:/in/{base}:ro"
        target = f"/in/{base}"

    if mode == "offline":
        net = "none" if network is None else network
    elif mode == "web":
        if not network:
            raise ValueError(
                "mode='web' требует явной сети с egress-allowlist "
                "(network=<имя>), которую поднимает оркестратор: сам контейнер "
                "ограничить исходящий трафик только хостом цели не может "
                "(SITE.md §7)."
            )
        net = network
    else:
        raise ValueError(
            f"неизвестный режим {mode!r}: ожидается 'offline' или 'web'"
        )

    mem_swap = memory  # --memory-swap == --memory => swap выключен

    cmd: List[str] = [
        docker, "run", "--rm",
        "--network", net,
        "--read-only",
        "--tmpfs", f"/work:rw,size={tmpfs_size},nosuid,nodev,noexec",
        "-v", mount,
        "-w", "/work",
        "-e", "TMPDIR=/work",
        "-e", "HOME=/work",
        "--memory", memory,
        "--memory-swap", mem_swap,
        "--cpus", str(cpus),
        "--pids-limit", str(pids_limit),
        "--ulimit", f"nofile={nofile}:{nofile}",
        "-u", "10000:10000",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
    ]
    if fsize_bytes is not None:
        # лимит на размер создаваемого файла — против бомб на диск (SITE.md §5)
        cmd += ["--ulimit", f"fsize={int(fsize_bytes)}:{int(fsize_bytes)}"]
    if container_name:
        cmd += ["--name", container_name]
    if extra_docker_args:
        cmd += list(extra_docker_args)

    cmd.append(image)

    engine: List[str] = [
        "python", f"{engine_dir.rstrip('/')}/solve.py", target, "--events", "-",
    ]
    if want_summary:
        engine.append("--json")
    if engine_budget is not None:
        engine += ["--time", str(engine_budget)]
    if flag_format:
        engine += ["--flag-prefix", str(flag_format)]
    if extra_engine_args:
        engine += list(extra_engine_args)
    cmd += engine
    return cmd


def command_to_str(cmd: Iterable[str]) -> str:
    """argv -> строка, пригодная для копирования в shell."""
    return shlex.join(cmd)


# --- парсинг потока событий (чистая функция, тестируется без docker) -----------


def parse_event_line(line: str) -> Optional[dict]:
    """Одна строка stdout -> dict-событие, или None если это не JSON-объект."""
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except (ValueError, TypeError):
        return None
    return obj if isinstance(obj, dict) else None


def parse_event_stream(lines: Iterable[str]) -> Iterator[dict]:
    """Поток строк -> поток dict-событий; мусор и пустые строки пропускаются."""
    for line in lines:
        obj = parse_event_line(line)
        if obj is not None:
            yield obj


# --- доступность docker и снятие контейнера -----------------------------------


def docker_available(docker: str = "docker", probe: bool = True) -> bool:
    """Есть ли рабочий docker: бинарь в PATH и (опц.) отвечающий демон."""
    if shutil.which(docker) is None:
        return False
    if not probe:
        return True
    try:
        res = subprocess.run(
            [docker, "version", "--format", "{{.Server.Version}}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10,
        )
        return res.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _kill_container(docker: str, name: str) -> None:
    try:
        subprocess.run(
            [docker, "kill", name],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        pass


def _new_name() -> str:
    return f"ctf-sandbox-{uuid.uuid4().hex[:12]}"


def _dry_run_note(cmd: List[str], docker: str) -> dict:
    return {
        "event": "runner_note",
        "level": "warn",
        "phase": "dry_run",
        "docker_available": False,
        "message": (
            f"docker ('{docker}') недоступен — dry-run: команда собрана, "
            f"контейнер не запущен"
        ),
        "command": cmd,
        "command_str": command_to_str(cmd),
    }


# --- запуск ------------------------------------------------------------------


def run(
    input_path,
    *,
    image: str = DEFAULT_IMAGE,
    mode: str = "offline",
    timeout: float = DEFAULT_TIMEOUT,
    flag_format: Optional[str] = None,
    engine_budget: Optional[float] = None,
    network: Optional[str] = None,
    want_summary: bool = False,
    container_name: Optional[str] = None,
    docker: str = "docker",
    probe: bool = True,
    **build_kwargs,
) -> Iterator[dict]:
    """Запустить задание в песочнице и отдать поток событий генератором.

    Отдаёт dict-события движка (plan/step_start/step_end/lead/flag/done) по мере
    поступления. В конце — служебное ``runner_end`` с кодом возврата и флагом
    ``timed_out``. Если docker недоступен — одно ``runner_note`` (dry-run) с
    собранной командой, без запуска.

    timeout — настенный таймаут (сек): через столько контейнер снимается
    ``docker kill`` независимо от состояния движка.
    """
    name = container_name or _new_name()
    cmd = build_command(
        input_path,
        image=image, mode=mode, flag_format=flag_format,
        engine_budget=engine_budget, network=network,
        want_summary=want_summary, container_name=name, docker=docker,
        **build_kwargs,
    )

    if not docker_available(docker, probe=probe):
        yield _dry_run_note(cmd, docker)
        return

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
    except FileNotFoundError:
        # docker исчез между проверкой и запуском — ведём себя как dry-run.
        yield _dry_run_note(cmd, docker)
        return

    fired = threading.Event()

    def _on_timeout() -> None:
        fired.set()
        _kill_container(docker, name)

    timer = threading.Timer(timeout, _on_timeout)
    timer.daemon = True
    timer.start()

    rc: Optional[int] = None
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            obj = parse_event_line(line)
            if obj is not None:
                yield obj
    finally:
        timer.cancel()
        if proc.stdout is not None:
            try:
                proc.stdout.close()
            except OSError:
                pass
        rc = proc.wait()

    yield {
        "event": "runner_end",
        "docker_available": True,
        "returncode": rc,
        "timed_out": fired.is_set(),
        "container": name,
    }


# --- CLI ---------------------------------------------------------------------


def _main(argv: Optional[List[str]] = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(
        description=(
            "Запуск движка solve в изолированном контейнере (песочница #142). "
            "Печатает поток JSON-событий построчно."
        )
    )
    ap.add_argument("input", help="путь к входному файлу или папке задания")
    ap.add_argument("--mode", choices=["offline", "web"], default="offline",
                    help="offline (по умолчанию, без сети) или web (egress-allowlist)")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                    help="настенный таймаут, сек (docker kill); по умолчанию 120")
    ap.add_argument("--engine-budget", type=float, default=None,
                    help="бюджет движка solve --time, сек (по умолчанию дефолт движка)")
    ap.add_argument("--flag-format", default=None,
                    help="префикс флага, напр. picoCTF -> solve --flag-prefix picoCTF")
    ap.add_argument("--image", default=DEFAULT_IMAGE, help="образ песочницы")
    ap.add_argument("--network", default=None,
                    help="сеть для web-режима (egress-allowlist оркестратора)")
    ap.add_argument("--summary", action="store_true",
                    help="добавить финальную сводку движка (--json)")
    ap.add_argument("--print-command", action="store_true",
                    help="только собрать и напечатать команду, не запускать")
    args = ap.parse_args(argv)

    try:
        if args.print_command:
            cmd = build_command(
                args.input, image=args.image, mode=args.mode,
                flag_format=args.flag_format, engine_budget=args.engine_budget,
                network=args.network, want_summary=args.summary,
            )
            print(command_to_str(cmd))
            return 0

        for ev in run(
            args.input, image=args.image, mode=args.mode, timeout=args.timeout,
            flag_format=args.flag_format, engine_budget=args.engine_budget,
            network=args.network, want_summary=args.summary,
        ):
            print(json.dumps(ev, ensure_ascii=False))
    except ValueError as e:
        print(f"ошибка: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
