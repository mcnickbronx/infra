"""Проверки ночного бэкапа на отрендеренном health-check.sh с двумя журналами и часами UTC."""
from datetime import datetime, timezone
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).parent / "golden/full/monitoring/health-check.sh"
OLD_OK = "2026-11-30 03:10:00 система бэкап: готово\n"
NEW_OK = "2026-12-01 03:20:00 система бэкап: готово\n"
FAILED = "2026-11-30 03:10:00 система бэкап: не выполнен — диск заполнен на 97%\n"
OTHER = "2026-12-01 07:55:00 система apply: готово\n"
EMBEDDED = "2026-12-01 07:55:00 система apply: готово, бэкап: без изменений\n"
STALE_PROBLEM = "Ночной бэкап не делался с 2026-11-30 03:10"
STALE_DETAILS = "sudo systemctl status backup.timer; sudo journalctl -u backup -n 30"


def timestamp(when):
    return int(datetime.fromisoformat(when).replace(tzinfo=timezone.utc).timestamp())


class BackupMonitoring(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.dir = Path(temp.name)
        self.current = self.dir / "infra.log"
        self.previous = self.dir / "infra.log.1"
        self.state = self.dir / "state/problems"
        (self.dir / "loadavg").write_text("0.00 0.00 0.00 1/100 1\n")
        (self.dir / "meminfo").write_text("MemTotal: 2097152 kB\nMemAvailable: 1048576 kB\n")

        # Как в тестах контейнеров: из эталона берём функции. Запускаем только нужную
        # проверку и тот же выбор режима, что на сервере. Внешние команды сводки заменены.
        functions, marker, calls = SCRIPT.read_text().partition("# ---------- Все проверки ----------\n")
        _, dispatch, modes = calls.rpartition("\ncase $MODE in\n")
        self.assertTrue(marker and dispatch)
        functions = functions.replace("/proc/loadavg", '"$STUB_ROOT/loadavg"')
        functions = functions.replace("/proc/meminfo", '"$STUB_ROOT/meminfo"')
        self.script = functions + r"""
EVENTS="$STUB_ROOT/infra.log"
HC_URL=""
df() { printf 'Mounted on Use%%\n/ 10%%\n'; }
nproc() { echo 2; }
site_errors() { return 1; }
crowdsec_bans() { return 1; }
infra-notify() {
  [ "$#" -eq 1 ] || { echo 'Ожидается серверное уведомление' >&2; return 1; }
  printf '%s\n' "$1"
}
date() {
  case $1 in
    +%s) echo "$STUB_NOW" ;;
    -d) "$STUB_PYTHON" -c 'from datetime import datetime, timezone
import sys
print(int(datetime.fromisoformat(sys.argv[1]).replace(tzinfo=timezone.utc).timestamp()))' "$2" ;;
    -u) echo 20261201080000 ;;    # границы для заглушки site_errors
    *) return 1 ;;
  esac
}
check_backup
""" + dispatch + modes

    def logs(self, previous=None, current=None):
        for path, content in ((self.previous, previous), (self.current, current)):
            if content is None:
                path.unlink(missing_ok=True)
            else:
                path.write_text(content)

    def run_check(self, mode="", now="2026-12-01 08:00"):
        env = {**os.environ, "STUB_ROOT": str(self.dir), "STUB_NOW": str(timestamp(now)),
               "STUB_PYTHON": sys.executable, "HEALTH_STATE_DIR": str(self.state.parent)}
        env.pop("HEALTH_RESOLVE_MINUTES", None)   # проверяем штатную задержку
        result = subprocess.run(["bash", "-c", self.script, "health-check.sh", mode],
                                env=env, capture_output=True, text=True, timeout=10, check=True)
        self.assertEqual(result.stderr, "")
        return result.stdout

    def assert_report(self, backup, problem="", details="", now="2026-12-01 08:00"):
        expected_problem = f"• {problem}\n  {details}\n" if problem else ""
        self.assertEqual(self.run_check(now=now), expected_problem)
        summary = self.run_check("--summary", now)
        heading = "⚠️ full: проблемы" if problem else "✅ full: всё в порядке"
        self.assertEqual(summary.splitlines()[0], heading)
        self.assertEqual(summary.partition(f"\nБэкап: {backup}\n")[1:],
                         (f"\nБэкап: {backup}\n", expected_problem))

    def test_rotated_success_with_no_new_event(self):
        backup = "бэкап: готово (2026-11-30 03:10)"
        for current in (None, "", OTHER):
            with self.subTest(current=current):
                self.logs(previous=OLD_OK, current=current)
                self.assert_report(backup, STALE_PROBLEM, STALE_DETAILS)
        self.assert_report(backup, now="2026-12-01 04:00")
        self.assert_report(backup, now="2026-12-01 05:10")   # ровно 26 часов
        self.assert_report(backup, STALE_PROBLEM, STALE_DETAILS, now="2026-12-01 05:10:01")

    def test_rotated_failure(self):
        self.logs(previous=FAILED, current=OTHER)
        self.assert_report("бэкап: не выполнен — диск заполнен на 97% (2026-11-30 03:10)",
                           "Ночной бэкап: не выполнен — диск заполнен на 97%",
                           "2026-11-30 03:10; sudo journalctl -u backup -n 50")

    def test_current_success_supersedes_rotated_failure(self):
        for previous in (FAILED, None):
            with self.subTest(previous=previous):
                self.logs(previous=previous, current=NEW_OK + EMBEDDED)
                self.assert_report("бэкап: готово (2026-12-01 03:20)")

    def test_no_events_yet(self):
        for previous, current in ((None, None), ("", ""), (None, OTHER)):
            with self.subTest(previous=previous, current=current):
                self.logs(previous, current)
                self.assert_report("записей ещё нет")
                self.assertEqual(self.run_check("--notify"), "")

    def test_rotation_keeps_active_alert_until_real_recovery(self):
        self.logs(current=OLD_OK)
        first = self.run_check("--notify")
        self.assertIn(f"⚠️ full — новое:\n• {STALE_PROBLEM}\n", first)
        key = "Ночной бэкап не делался с -- :"
        self.assertEqual(self.state.read_text(), f"{key}\t{STALE_PROBLEM}\t{timestamp('2026-12-01 08:00')}\n")

        self.current.rename(self.previous)
        self.current.write_text(OTHER)
        self.assertEqual(self.run_check("--notify", "2026-12-01 08:40"), "")
        self.assertEqual(self.state.read_text(), f"{key}\t{STALE_PROBLEM}\t{timestamp('2026-12-01 08:40')}\n")

        self.current.write_text("2026-12-01 08:45:00 система бэкап: готово\n")
        self.assertEqual(self.run_check("--notify", "2026-12-01 09:09"), "")
        self.assertIn(f"✅ full — прошло:\n• {STALE_PROBLEM}\n", self.run_check("--notify", "2026-12-01 09:10"))
        self.assertEqual(self.state.read_text(), "")
