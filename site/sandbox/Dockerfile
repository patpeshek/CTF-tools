# Минимальный образ движка solve для песочницы (#142).
#
# Контекст сборки — КОРЕНЬ репозитория (а не site/sandbox/), потому что код
# движка (solve.py, common.py, toolbox.py, flags.json, пакеты категорий) лежит
# в корне. Собирать так, из корня репозитория:
#
#     docker build -f site/sandbox/Dockerfile -t ctf-sandbox:latest .
#
# Базовый профиль НЕ включает тяжёлые/опасные инструменты (Ghidra, hashcat):
# по дизайну они подключаются отдельной опцией в «толстый» образ, а не в базу
# (SITE.md §5, открытый вопрос №3). Здесь — только slim-Python + requirements.
#
# Жёсткая изоляция (сеть/ФС/права/лимиты) задаётся не образом, а флагами
# `docker run`, которые собирает runner.build_command (см. runner.py и README).

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /engine

# Системные библиотеки, без которых не импортируются Python-зависимости
# (opencv-python-headless -> libGL/glib). Держим список минимальным.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libgl1 \
        libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Зависимости движка ставим отдельным слоем (кешируется, пока requirements.txt
# не меняется). requirements.txt берётся из корня репозитория (контекст сборки).
COPY requirements.txt /engine/requirements.txt
RUN pip install --no-cache-dir -r /engine/requirements.txt

# Код движка. Рекомендуется завести корневой .dockerignore (вне этого тикета),
# чтобы не тащить .git, тесты и артефакты в образ.
COPY . /engine

# Точки монтирования: /in — вход задания (bind :ro из runner), /work — скретч
# (tmpfs из runner). /work отдаём непривилегированному uid, под которым идёт
# запуск (`docker run -u 10000:10000`); сам tmpfs монтируется rw поверх.
RUN mkdir -p /in /work && chown 10000:10000 /work

# Не-root по умолчанию (runner дополнительно передаёт -u 10000:10000).
USER 10000:10000

# ENTRYPOINT намеренно НЕ задаём: runner передаёт полную команду
# `python /engine/solve.py <target> --events -` как аргументы docker run.
# cwd внутри — /work (задаёт `docker run -w /work`), чтобы любые записи
# попадали в tmpfs, а не в read-only корень. flags.json и plugins/ движок
# находит относительно своего файла (/engine), поэтому cwd роли не играет.
