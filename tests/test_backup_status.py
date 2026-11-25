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

    def mark_update_reminder(self, day):
        marker = self.write("var/lib/update-last-run", "")
        timestamp = datetime.datetime(2026, 11, day, 7, tzinfo=datetime.timezone.utc).timestamp()
        os.utime(marker, (timestamp, timestamp))

    def assert_update_status(self, result, reminder=None):
        run = self.status("s3:https://example.com/backups")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stderr, "")
        lines = run.stdout.splitlines()
        prefixes = ("Последний завершённый update: ", "Отметка напоминания: ")
        reminder_text = f"{reminder} (sudo infra update — раз в неделю)" if reminder else "отсутствует"
        self.assertEqual([line for line in lines if line.startswith(prefixes)], [
            prefixes[0] + result, prefixes[1] + reminder_text,
        ])
        return lines

    def test_update_first_install(self):
        missing = "записи нет в infra.log и infra.log.1"
        self.assert_update_status(missing)

        self.mark_update_reminder(24)
        self.write("var/log/infra.log", "2026-11-24 07:10:00 система apply: готово, изменений 89\n")
        self.assert_update_status(missing, "2026-11-24")

    def test_update_completed_successfully(self):
        self.mark_update_reminder(24)
        self.write("var/log/infra.log", "2026-11-24 07:20:05 система update: готово, изменений 3\n")
        self.assert_update_status("2026-11-24 07:20 — готово, изменений 3", "2026-11-24")

    def test_update_failed_after_reminder_mark(self):
        self.mark_update_reminder(24)
        self.write(
            "var/log/infra.log",
            "2026-11-24 08:10:15 система update: ошибка (код 2) — "
            "journalctl -u infra-apply --since '2026-11-24 08:00:00'\n",
        )
        self.assert_update_status(
            "2026-11-24 08:10 — ошибка (код 2) — journalctl -u infra-apply --since '2026-11-24 08:00:00'",
            "2026-11-24",
        )

    def test_update_failure_in_rotated_log_after_apply(self):
        self.mark_update_reminder(23)
        self.write(
            "var/log/infra.log.1",
            "2026-11-24 02:00:00 система apply: ошибка (код 1)\n"
            "2026-11-24 03:05:00 система бэкап: не выполнен — диск заполнен на 97%\n"
            "2026-11-24 08:10:00 система update: ошибка (код 2)\n",
        )
        self.write(
            "var/log/infra.log",
            "2026-11-25 03:05:00 система бэкап: готово\n"
            "2026-11-25 10:45:00 система apply: готово, изменений 1\n",
        )
        lines = self.assert_update_status("2026-11-24 08:10 — ошибка (код 2)", "2026-11-23")
        self.assertIn("Последний apply: 2026-11-25 10:45 — готово, изменений 1", lines)
        self.assertIn("Бэкап: 2026-11-25 03:05 — готово. S3 указан в server.yml", lines)

    def test_update_start_keeps_previous_result(self):
        self.mark_update_reminder(24)
        self.write(
            "var/log/infra.log",
            "2026-11-23 08:10:00 система update: готово, изменений 5\n"
            "2026-11-24 08:00:00 система update: начат\n",
        )
        self.assert_update_status("2026-11-23 08:10 — готово, изменений 5", "2026-11-24")

    def test_update_prefers_last_result_in_current_log(self):
        self.write("var/log/infra.log.1", "2026-11-25 09:15:00 система update: ошибка (код 2)\n")
        self.write(
            "var/log/infra.log",
            "2026-11-24 08:00:00 система update: готово, изменений 1\n"
            "2026-11-24 09:15:00 admin@192.0.2.10 update: готово, изменений 4\n"
            "2026-11-24 10:30:00 система apply: готово, изменений 2\n",
        )
        self.assert_update_status("2026-11-24 09:15 — готово, изменений 4 (admin@192.0.2.10)")

    def test_update_rotation_after_first_open(self):
        previous = "2026-11-23 08:10:00 система update: ошибка (код 2)\n"
        current = "2026-11-24 09:15:00 система update: готово, изменений 4\n"
        current_path = self.write("var/log/infra.log", current)
        previous_path = self.write("var/log/infra.log.1", previous)
        # Переименовываем обычные файлы после первого открытия при чтении итогов update.
        self.write("bin/grep", """#!/bin/sh
set -eu
case "$#:${2-}" in
    '3:'*'update: '*)
        exec 3<"$3"
        mv var/log/infra.log.1 var/log/infra.log.2
        mv var/log/infra.log var/log/infra.log.1
        : > var/log/infra.log
        exec /usr/bin/grep "$1" "$2" <&3
        ;;
esac
exec /usr/bin/grep "$@"
""").chmod(0o755)
        self.assert_update_status("2026-11-24 09:15 — готово, изменений 4")
        self.assertEqual(current_path.read_text(encoding="utf-8"), "")
        self.assertEqual(previous_path.read_text(encoding="utf-8"), current)
        self.assertEqual(previous_path.with_suffix(".2").read_text(encoding="utf-8"), previous)
