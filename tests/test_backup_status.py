"""Локальная проверка строк бэкапа в штатной команде infra status."""

import datetime
import os
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parent.parent
STATUS_PREFIXES = ("Бэкап: ", "Частые снимки (")


class BackupStatus(unittest.TestCase):
    def setUp(self):
        stand = tempfile.TemporaryDirectory(prefix="infra-backup-status-")
        self.addCleanup(stand.cleanup)
        self.stand = pathlib.Path(stand.name)

        # Запускаем весь CLI из копии. Пути сервера ведут в рабочий каталог стенда.
        infra = (ROOT / "infra").read_text(encoding="utf-8")
        for path in ("/etc/", "/proc/", "/var/lib/", "/var/log/", "/usr/local/"):
            infra = infra.replace(path, path.lstrip("/"))
        # Пустой массив в обработчике EXIT и set -u несовместимы в Bash 3.2 на macOS.
        infra = infra.replace('"${CLEANUP[@]}"', '${CLEANUP[@]+"${CLEANUP[@]}"}')
        self.write("engine/infra", infra)
        self.write("etc/infra/secrets.yml", "")
        self.write("etc/os-release", "PRETTY_NAME=stand\n")
        self.write("etc/restic/projects.json", '[{"name": "shop", "hourly": "db", "every": 5}]\n')
        self.write("proc/meminfo", "MemTotal: 2097152 kB\nMemAvailable: 1048576 kB\n")
        self.write("proc/loadavg", "0.00 0.00 0.00 1/1 1\n")

        stubs = {
            "engine/.venv/bin/ansible-playbook": "exit 1",  # нужен только исполняемый файл
            "bin/id": "echo 0",
            "bin/ss": "exit 1",
            "bin/df": "printf 'Use%%\\n97%%\\n'",
            "bin/uptime": "echo '2026-11-22 00:00:00'",
            "bin/nproc": "echo 1",
            "bin/docker": "exit 1",
            "bin/systemctl": "exit 1",
        }
        for path, command in stubs.items():
            self.write(path, f"#!/bin/sh\n{command}\n").chmod(0o755)

    def write(self, name, contents):
        path = self.stand / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")
        return path

    def status(self, repository):
        self.write("etc/infra/server.yml", f'server_name: stand\nrestic_s3_repository_base: "{repository}"\n')
        env = {**os.environ, "PATH": f"{self.stand / 'bin'}:{os.environ['PATH']}", "TZ": "UTC"}
        return subprocess.run(
            ["bash", "engine/infra", "status"], cwd=self.stand, env=env,
            capture_output=True, encoding="utf-8", timeout=10,
        )

    def assert_status(self, nightly, hourly):
        for repository, setting, hourly_setting in (
            ("s3:https://example.com/backups", "S3 указан в server.yml", ". S3 указан в server.yml"),
            ("", "S3 не указан в server.yml", ""),
        ):
            with self.subTest(repository=repository):
                run = self.status(repository)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(run.stderr, "")
                self.assertEqual([line for line in run.stdout.splitlines() if line.startswith(STATUS_PREFIXES)], [
                    f"Бэкап: {nightly}. {setting}",
                    f"Частые снимки (shop — база, каждые 5 мин): {hourly}{hourly_setting}",
                ])

    def test_no_attempts(self):
        self.assert_status("ещё не было (ночью, около 03:00)", "ещё не было")

    def test_failed_attempts(self):
        self.write("var/log/infra.log", "2026-11-23 03:01:05 система бэкап: не выполнен — диск заполнен на 97%\n")
        self.write("var/lib/backup-hourly/failed", "2026-11-23 03:05 shop\n")
        self.assert_status(
            "2026-11-23 03:01 — не выполнен — диск заполнен на 97%",
            "ошибка 2026-11-23 03:05 shop — journalctl -u backup-hourly",
        )

    def test_successful_attempts(self):
        self.write("var/log/infra.log", "2026-11-23 03:12:34 система бэкап: готово\n")
        marker = self.write("var/lib/backup-hourly/last-ok", "")
        timestamp = datetime.datetime(2026, 11, 23, 3, 15, tzinfo=datetime.timezone.utc).timestamp()
        os.utime(marker, (timestamp, timestamp))
        self.assert_status("2026-11-23 03:12 — готово", "последний 2026-11-23 03:15")
