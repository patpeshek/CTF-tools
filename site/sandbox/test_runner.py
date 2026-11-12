#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Тесты песочницы (#142) БЕЗ docker: сборка команды и парсинг потока событий.

Проверяется чистая логика runner.py — профиль изоляции в argv, маппинг входа
на bind-mount :ro, режимы offline/web, построчный парсинг JSON-событий движка и
dry-run (когда docker недоступен). Ничего не запускается в контейнере, docker не
нужен.

Запуск:  python site/sandbox/test_runner.py        (или: -m unittest)
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import runner  # noqa: E402


def _flag_value(cmd, flag):
    """Значение, идущее сразу за `flag` в argv (или None)."""
    for i, a in enumerate(cmd):
        if a == flag and i + 1 < len(cmd):
            return cmd[i + 1]
    return None


def _flag_values(cmd, flag):
    """Все значения, идущие за каждым вхождением `flag` в argv."""
    out = []
    for i, a in enumerate(cmd):
        if a == flag and i + 1 < len(cmd):
            out.append(cmd[i + 1])
    return out


class BuildCommandTest(unittest.TestCase):
    def setUp(self):
        # реальный файл, чтобы ветка «файл, а не папка» сработала детерминированно
        self.tmp = tempfile.NamedTemporaryFile(
            prefix="chal_", suffix=".bin", delete=False
        )
        self.tmp.write(b"\x00hostile\x00")
        self.tmp.close()
        self.path = self.tmp.name
        self.base = os.path.basename(self.path)

    def tearDown(self):
        try:
            os.unlink(self.path)
        except OSError:
            pass

    def test_isolation_profile(self):
        """В команде есть весь профиль изоляции из тикета/SITE.md §5."""
        cmd = runner.build_command(self.path, image="ctf-sandbox:test")

        self.assertEqual(cmd[:3], ["docker", "run", "--rm"])
        # сеть выключена
        self.assertEqual(_flag_value(cmd, "--network"), "none")
        # корень только на чтение + запись лишь в tmpfs-скретч
        self.assertIn("--read-only", cmd)
        tmpfs = _flag_value(cmd, "--tmpfs")
        self.assertIsNotNone(tmpfs)
        self.assertTrue(tmpfs.startswith("/work:rw"))
        for token in ("size=512m", "nosuid", "nodev", "noexec"):
            self.assertIn(token, tmpfs)
        # вход смонтирован :ro на /in/<basename>, цель движка — тот же путь
        mount = _flag_value(cmd, "-v")
        self.assertTrue(mount.endswith(f":/in/{self.base}:ro"), mount)
        self.assertIn(f"/in/{self.base}", cmd)
        # лимиты
        self.assertEqual(_flag_value(cmd, "--memory"), "1g")
        self.assertEqual(_flag_value(cmd, "--memory-swap"), "1g")
        self.assertEqual(_flag_value(cmd, "--cpus"), "2")
        self.assertEqual(_flag_value(cmd, "--pids-limit"), "256")
        self.assertIn("nofile=1024:1024", _flag_values(cmd, "--ulimit"))
        # права
        self.assertEqual(_flag_value(cmd, "-u"), "10000:10000")
        self.assertEqual(_flag_value(cmd, "--cap-drop"), "ALL")
        self.assertIn("no-new-privileges", _flag_values(cmd, "--security-opt"))
        # cwd — writable tmpfs, записи уводятся в /work
        self.assertEqual(_flag_value(cmd, "-w"), "/work")
        self.assertIn("TMPDIR=/work", _flag_values(cmd, "-e"))
        # без docker.sock
        self.assertNotIn(
            "/var/run/docker.sock",
            " ".join(cmd),
            "docker.sock не должен пробрасываться в песочницу",
        )

    def test_engine_invocation(self):
        """Команда движка — поток событий --events - (контракт §4)."""
        cmd = runner.build_command(self.path, image="ctf-sandbox:test")
        # образ идёт перед командой движка
        self.assertIn("ctf-sandbox:test", cmd)
        img = cmd.index("ctf-sandbox:test")
        engine = cmd[img + 1:]
        self.assertEqual(engine[0], "python")
        self.assertTrue(engine[1].endswith("/solve.py"), engine[1])
        self.assertEqual(engine[2], f"/in/{self.base}")
        self.assertIn("--events", engine)
        self.assertEqual(engine[engine.index("--events") + 1], "-")
        # по умолчанию без финальной сводки --json
        self.assertNotIn("--json", engine)

    def test_summary_and_flag_and_budget(self):
        cmd = runner.build_command(
            self.path, flag_format="picoCTF", engine_budget=42, want_summary=True
        )
        img = len(cmd) - 1
        while cmd[img] != runner.DEFAULT_IMAGE:
            img -= 1
        engine = cmd[img + 1:]
        self.assertIn("--json", engine)
        self.assertEqual(engine[engine.index("--time") + 1], "42")
        self.assertEqual(engine[engine.index("--flag-prefix") + 1], "picoCTF")

    def test_directory_input_mounts_whole_dir(self):
        d = tempfile.mkdtemp(prefix="chaldir_")
        try:
            cmd = runner.build_command(d)
            self.assertTrue(_flag_value(cmd, "-v").endswith(":/in:ro"))
            self.assertIn("/in", cmd[cmd.index(runner.DEFAULT_IMAGE) + 1:])
        finally:
            os.rmdir(d)

    def test_web_mode_requires_network(self):
        with self.assertRaises(ValueError):
            runner.build_command(self.path, mode="web")
        cmd = runner.build_command(self.path, mode="web", network="ctf-egress")
        self.assertEqual(_flag_value(cmd, "--network"), "ctf-egress")
        self.assertNotIn("none", _flag_values(cmd, "--network"))

    def test_bad_mode(self):
        with self.assertRaises(ValueError):
            runner.build_command(self.path, mode="nope")

    def test_container_name_and_fsize(self):
        cmd = runner.build_command(
            self.path, container_name="job-7", fsize_bytes=1048576
        )
        self.assertEqual(_flag_value(cmd, "--name"), "job-7")
        self.assertIn("fsize=1048576:1048576", _flag_values(cmd, "--ulimit"))

    def test_command_to_str_roundtrip(self):
        cmd = runner.build_command(self.path)
        s = runner.command_to_str(cmd)
        self.assertIn("docker", s)
        self.assertIn("--network", s)


class ParseEventStreamTest(unittest.TestCase):
    SAMPLE = [
        '{"event": "plan", "t": 0.01, "kind": "stego", "steps": [{"tool": "zsteg"}]}',
        '',  # пустая строка — пропустить
        '{"event": "step_start", "t": 0.2, "n": 1, "tool": "zsteg"}',
        'не-JSON строка из stderr просочилась — пропустить',
        '{"event": "step_end", "t": 1.5, "n": 1, "status": "ok", "flags": []}',
        '{"event": "lead", "t": 1.6, "n": 1, "text": "found base64 blob"}',
        '{"event": "flag", "t": 2.0, "n": 2, "flag": "picoCTF{x}", "flags": ["picoCTF{x}"]}',
        '{"event": "done", "t": 2.1, "status": "solved", "flag": "picoCTF{x}"}',
        '[1, 2, 3]',  # валидный JSON, но не объект — пропустить
    ]

    def test_parses_only_json_objects_in_order(self):
        events = list(runner.parse_event_stream(self.SAMPLE))
        kinds = [e["event"] for e in events]
        self.assertEqual(
            kinds,
            ["plan", "step_start", "step_end", "lead", "flag", "done"],
        )

    def test_fields_passthrough(self):
        events = list(runner.parse_event_stream(self.SAMPLE))
        flag_ev = next(e for e in events if e["event"] == "flag")
        self.assertEqual(flag_ev["flag"], "picoCTF{x}")
        self.assertEqual(flag_ev["t"], 2.0)

    def test_parse_single_line(self):
        self.assertIsNone(runner.parse_event_line(""))
        self.assertIsNone(runner.parse_event_line("plain text"))
        self.assertIsNone(runner.parse_event_line("[1,2]"))
        self.assertEqual(
            runner.parse_event_line('{"event":"flag","flag":"f"}')["flag"], "f"
        )


class DryRunTest(unittest.TestCase):
    """Когда docker недоступен — не падаем, отдаём команду и сообщение."""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(prefix="chal_", delete=False)
        self.tmp.close()

    def tearDown(self):
        try:
            os.unlink(self.tmp.name)
        except OSError:
            pass

    def test_run_yields_dry_run_note_without_docker(self):
        # заведомо несуществующий бинарь docker -> docker_available() == False
        events = list(
            runner.run(self.tmp.name, docker="definitely-no-such-docker-xyz")
        )
        self.assertEqual(len(events), 1)
        note = events[0]
        self.assertEqual(note["event"], "runner_note")
        self.assertEqual(note["phase"], "dry_run")
        self.assertFalse(note["docker_available"])
        # собранная команда есть и машинно, и строкой
        self.assertIsInstance(note["command"], list)
        self.assertIn("run", note["command"])
        self.assertIn("solve.py", note["command_str"])
        self.assertIn("--events", note["command_str"])
        # сообщение понятное и содержит имя бинаря
        self.assertIn("docker", note["message"].lower())

    def test_docker_available_false_for_missing_binary(self):
        self.assertFalse(
            runner.docker_available("definitely-no-such-docker-xyz", probe=False)
        )

    def test_dry_run_command_is_valid_json_serialisable(self):
        note = list(
            runner.run(self.tmp.name, docker="definitely-no-such-docker-xyz")
        )[0]
        # событие целиком сериализуемо (бэкенд перешлёт его как есть)
        json.dumps(note, ensure_ascii=False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
