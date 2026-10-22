"""Проверки Python-кода репозитория без сервера: python3 -m unittest discover -s tests
(запускает tools/check.sh). Нужен только стандартный Python; для проверки подписи — git и ssh-keygen."""
import hashlib
import importlib.machinery
import importlib.util
import os
import pathlib
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(ROOT / path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


wl = load("ufw_sync_whitelist", "roles/base/files/ufw-sync-whitelist")


class SecretSums(unittest.TestCase):
    """infra: отпечатки паролей (secret_sums) и их сравнение (sums_diff) — какие пароли появились, сменились,
    удалены. Файл отпечатков пишет то админ (его локаль), то служба infra-apply (локаль C): порядок строк
    в нём не должен влиять на итог."""

    def setUp(self):
        # из infra — две функции целиком, как есть
        text = (ROOT / "infra").read_text()
        parts = []
        for name in ("secret_sums", "sums_diff"):
            start = text.find(f"\n{name}() {{\n")
            end = text.find("\n}\n", start)
            self.assertTrue(0 <= start < end, f"в infra нет функции {name}")
            parts.append(text[start:end + len("\n}\n")])
        self.functions = "set -euo pipefail\n" + "".join(parts)

    def run_bash(self, call, locale="C", **env):
        env = {**os.environ, "LC_ALL": locale, **env}
        run = subprocess.run(["bash", "-c", self.functions + call + "\n"], env=env, capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        return run.stdout

    def diff(self, old, new):
        return self.run_bash('sums_diff "$OLD" "$NEW"', OLD=old, NEW=new)

    def test_changed_when_old_file_sorted_in_other_locale(self):
        # старый файл записан в локали, где «_» не в счёт (dbpass выше db_password_shop), новый — в C
        old = "dbpass 1111aaaa1111aaaa\ndb_password_shop 2222bbbb2222bbbb\nrestic_password 3333cccc3333cccc"
        new = "db_password_shop 4444dddd4444dddd\ndbpass 1111aaaa1111aaaa\nrestic_password 3333cccc3333cccc"
        self.assertEqual(self.diff(old, new), "сменились db_password_shop\n")

    def test_added_and_removed_in_other_order(self):
        old = "s3_secret_key 1111aaaa1111aaaa\ndbpass 2222bbbb2222bbbb\ndb_password_shop 3333cccc3333cccc"
        new = "db_password_lab 4444dddd4444dddd\ndb_password_shop 3333cccc3333cccc\ndbpass 2222bbbb2222bbbb"
        self.assertEqual(self.diff(old, new), "появились db_password_lab\nудалены s3_secret_key\n")
        self.assertEqual(self.diff(new, new), "")

    def test_sums_in_c_order_without_blanks(self):
        secrets = pathlib.Path(tempfile.mkdtemp()) / "secrets.yml"
        self.addCleanup(shutil.rmtree, secrets.parent)
        secrets.write_text('# пароли сервера\ndbpass: one-fake\ns3_secret_key: ""  # вписать\n'
                           "db_password_shop: two-fake\ntelegram_token: ''\nrestic_password: # потом\n")
        expected = "".join(f"{key} {hashlib.sha256(value.encode()).hexdigest()[:16]}\n"
                           for key, value in (("db_password_shop", "two-fake"), ("dbpass", "one-fake")))
        # тот же порядок, кто бы ни запустил: в en_US.UTF-8 на Linux «_» при сортировке не в счёт
        for locale in ("C", "en_US.UTF-8"):
            with self.subTest(locale=locale):
                self.assertEqual(self.run_bash('secret_sums "$SECRETS"', locale, SECRETS=str(secrets)), expected)


class UfwWhitelist(unittest.TestCase):
    """roles/base/files/ufw-sync-whitelist: белый список SSH в ufw."""

    ADDED = """Added user rules (see 'ufw status' for running firewall):
ufw allow 80/tcp
ufw allow from 198.51.100.7 to any port 22 proto tcp
ufw allow from 203.0.113.5 to any port 22 proto tcp comment 'ansible-wl'
ufw allow from 203.0.113.0/29 to any port 22 proto tcp comment 'ansible-wl'
ufw allow from 2001:db8::10 to any port 22 proto tcp comment 'ansible-wl'
"""

    def test_norm(self):
        self.assertEqual(wl.norm("203.0.113.5"), "203.0.113.5")
        self.assertEqual(wl.norm("203.0.113.5/32"), "203.0.113.5")
        self.assertEqual(wl.norm("203.0.113.5/29"), "203.0.113.0/29")
        self.assertEqual(wl.norm("2001:db8::10/128"), "2001:db8::10")

    def test_only_tagged_rules_are_ours(self):
        # правило без пометки (добавленное руками) скрипт не видит и не удаляет
        self.assertEqual(wl.existing_rules(self.ADDED), {
            ("203.0.113.5", "22"), ("203.0.113.0/29", "22"), ("2001:db8::10", "22")})

    def test_nothing_to_do_when_in_sync(self):
        desired = wl.desired_rules([
            "203.0.113.5/32",       # тот же адрес, записанный иначе
            "203.0.113.6/29",       # биты хоста в подсети
            "2001:db8::10"])
        self.assertEqual(wl.plan(desired, wl.existing_rules(self.ADDED)), ([], []))

    def test_add_and_delete(self):
        desired = wl.desired_rules(["203.0.113.5", "192.0.2.1"])
        to_add, to_delete = wl.plan(desired, wl.existing_rules(self.ADDED))
        self.assertEqual(to_add, [("192.0.2.1", "22")])
        self.assertEqual(to_delete, [("2001:db8::10", "22"), ("203.0.113.0/29", "22")])

    def test_rule_for_other_port_is_removed(self):
        # остаток прежних правил (доступ к базе по IP): наш, но не SSH — удаляется
        added = self.ADDED + "ufw allow from 203.0.113.5 to any port 5432 proto tcp comment 'ansible-wl'\n"
        desired = wl.desired_rules(["203.0.113.5", "203.0.113.0/29", "2001:db8::10"])
        self.assertEqual(wl.plan(desired, wl.existing_rules(added)), ([], [("203.0.113.5", "5432")]))

    def test_empty_whitelist_removes_all_ours(self):
        _, to_delete = wl.plan(set(), wl.existing_rules(self.ADDED))
        self.assertEqual(len(to_delete), 3)


acc = load("infra_access", "roles/access/files/infra-access")
web = load("infra_access_web", "roles/access/files/infra-access-web")


class AccessLink(unittest.TestCase):
    """roles/access: ссылка доступа — страница (infra-access-web) и правила ufw (infra-access)."""

    ADDED = """Added user rules (see 'ufw status' for running firewall):
ufw allow 80/tcp
ufw allow from 203.0.113.5 to any port 22 proto tcp comment 'ansible-wl'
ufw allow from 1.1.1.1 to any port 22 proto tcp comment 'infra-access 1760000000'
ufw allow from 1.0.0.1 to any port 22 proto tcp comment 'infra-access 1760003600'
ufw allow from 9.9.9.9 to any port 22 proto tcp comment 'infra-access manual'
"""
    SHA = "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92"   # sha256("123456")

    def test_token(self):
        self.assertTrue(web.token_ok("/access/123456", self.SHA))
        self.assertTrue(web.token_ok("/access/123456/?utm=1", self.SHA))
        self.assertFalse(web.token_ok("/access/1234567", self.SHA))
        self.assertFalse(web.token_ok("/access/", self.SHA))
        self.assertFalse(web.token_ok("/other/123456", self.SHA))
        self.assertFalse(web.token_ok("/access/" + "1" * 200, self.SHA))

    def test_only_public_ip(self):
        # своя сеть, localhost и адреса для документации — не открываются
        for bad in ("", "10.0.0.5", "127.0.0.1", "192.168.1.2", "198.51.100.7", "1.1.1.1, 2.2.2.2", "x"):
            self.assertIsNone(web.public_ip(bad), bad)
            self.assertIsNone(acc.public_ip(bad), bad)
        self.assertEqual(web.public_ip(" 1.1.1.1 "), "1.1.1.1")
        self.assertEqual(acc.public_ip("2606:4700:4700::1111"), "2606:4700:4700::1111")

    def test_rules_ours_only(self):
        # белый список и правило с чужой пометкой — не наши
        self.assertEqual(acc.open_rules(self.ADDED), {"1.1.1.1": 1760000000, "1.0.0.1": 1760003600})

    def test_whitelisted_exact_only(self):
        self.assertTrue(acc.whitelisted("203.0.113.5", ["203.0.113.5/32"]))
        # подсеть с этим IP — другое правило ufw: временное рядом не мешает
        self.assertFalse(acc.whitelisted("203.0.113.5", ["203.0.113.0/29"]))

    def test_reopen_extends_and_limit_drops_oldest(self):
        rules = acc.open_rules(self.ADDED)
        self.assertEqual(acc.plan_open(rules, "1.1.1.1", 1760090000, 10), ["1.1.1.1"])
        self.assertEqual(acc.plan_open(rules, "8.8.8.8", 1760090000, 10), [])
        self.assertEqual(acc.plan_open(rules, "8.8.8.8", 1760090000, 2), ["1.1.1.1"])
        self.assertEqual(acc.plan_open(rules, "8.8.8.8", 1760090000, 1), ["1.1.1.1", "1.0.0.1"])

    def test_expired(self):
        rules = acc.open_rules(self.ADDED)
        self.assertEqual(acc.expired(rules, 1759999999), [])
        self.assertEqual(acc.expired(rules, 1760000000), ["1.1.1.1"])
        self.assertEqual(acc.expired(rules, 1760100000), ["1.0.0.1", "1.1.1.1"])

    def test_queue_not_followed_by_root(self):
        # папки очереди и ответов пишет страница (не root): ссылки и FIFO root не читает и не пишет
        d = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        target = d / "target"
        target.write_text("чужой файл\n")
        (d / "ok").write_text("1.1.1.1\n")
        (d / "link").symlink_to(target)
        os.mkfifo(d / "fifo")
        self.assertEqual(acc.read_request(str(d / "ok")), "1.1.1.1\n")
        with self.assertRaises(OSError):
            acc.read_request(str(d / "link"))
        self.assertEqual(acc.read_request(str(d / "fifo")), "")
        with mock.patch.object(acc, "DONE", str(d)):
            (d / ("a" * 16)).symlink_to(target)
            acc.write_answer("a" * 16, "x")
            acc.write_answer("b" * 16, "готово")
        self.assertEqual(target.read_text(), "чужой файл\n")
        self.assertEqual((d / ("b" * 16)).read_text(), "готово\n")


pt = load("project_traefik", "roles/rootless/files/project-traefik")


class RootlessTraefik(unittest.TestCase):
    """roles/rootless/files/project-traefik: labels контейнеров без root → файл маршрутов Traefik."""

    def container(self, labels, ports=None, health=None, running=True):
        state = {"Running": running}
        if health:
            state["Health"] = {"Status": health}
        return {"Name": "/lab-app-1", "Config": {"Labels": labels}, "State": state,
                "NetworkSettings": {"Ports": ports if ports is not None else
                                     {"8000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "40600"}]}}}

    LABELS = {
        "traefik.enable": "true",
        "traefik.http.services.lab-app.loadbalancer.server.port": "8000",
        "traefik.http.routers.lab-app.rule": "Host(`lab.example.org`)",
        "traefik.http.routers.lab-app.entrypoints": "websecure",
        "traefik.http.routers.lab-app.service": "lab-app",
        "traefik.http.routers.lab-www.rule": "Host(`www.lab.example.org`)",
        "traefik.http.routers.lab-www.middlewares": "lab-www,login-ratelimit@file",
        "traefik.http.routers.lab-www.priority": "100",
        "traefik.http.middlewares.lab-www.redirectregex.regex": "^https://www\\.(.+)",
        "traefik.http.middlewares.lab-www.redirectregex.permanent": "true",
        "com.docker.compose.project": "lab",
    }

    def test_labels_to_routes(self):
        http = pt.build([self.container(self.LABELS)])["http"]
        self.assertEqual(http["services"]["lab-app"], {"loadbalancer": {"servers": [{"url": "http://127.0.0.1:40600"}]}})
        self.assertEqual(http["routers"]["lab-app"], {"rule": "Host(`lab.example.org`)", "entrypoints": ["websecure"],
                                                      "service": "lab-app"})
        # маршрут без service — к единственному сервису контейнера; списки, числа, true/false
        self.assertEqual(http["routers"]["lab-www"]["service"], "lab-app")
        self.assertEqual(http["routers"]["lab-www"]["middlewares"], ["lab-www", "login-ratelimit@file"])
        self.assertEqual(http["routers"]["lab-www"]["priority"], 100)
        self.assertEqual(http["middlewares"]["lab-www"]["redirectregex"],
                         {"regex": "^https://www\\.(.+)", "permanent": True})

    def test_only_ready_containers(self):
        # Traefik с labels тоже не ведёт к нездоровому и запускающемуся контейнеру
        for c in (self.container(self.LABELS, health="starting"), self.container(self.LABELS, health="unhealthy"),
                  self.container(self.LABELS, running=False), self.container({**self.LABELS, "traefik.enable": "false"})):
            self.assertIsNone(pt.build([c]))
        self.assertIsNotNone(pt.build([self.container(self.LABELS, health="healthy")]))

    def test_port_not_on_localhost(self):
        # порт не открыт на 127.0.0.1 (контейнер запущен не через project-compose) — маршрута нет
        for ports in ({}, {"8000/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8000"}]}):
            self.assertIsNone(pt.build([self.container(self.LABELS, ports=ports)]))


prf = load("project_rootless_files", "roles/rootless/files/project-rootless-files")


class RootlessFiles(unittest.TestCase):
    """roles/rootless/files/project-rootless-files: владельцы файлов при смене Docker проекта."""

    def test_both_ways(self):
        own, sub = 1004, 231072                  # <проект>-run и начало его subuid
        to_rl, to_rf = prf.mapper("to-rootless", own, sub), prf.mapper("to-rootful", own, sub)
        self.assertEqual(to_rl(100000), own)     # root контейнера
        self.assertEqual(to_rl(101000), sub + 999)   # uid 1000 контейнера
        for person in (0, 1000, 99999, 165536, 300000):   # люди, root сервера, чужие диапазоны
            self.assertEqual(to_rl(person), person)
            self.assertEqual(to_rf(person), person)
        for n in (0, 33, 1000, 65535):           # туда и обратно — как было
            self.assertEqual(to_rf(to_rl(100000 + n)), 100000 + n)


class HealthCheckContainers(unittest.TestCase):
    """roles/monitoring: health-check.sh (эталон tests/golden) — проверки контейнеров по заглушке docker
    и уведомления: о новом — один раз, о прошедшем — один раз."""

    SCRIPT = ROOT / "tests/golden/full/monitoring/health-check.sh"
    # Заглушка отвечает на запросы нездоровых, перезапускающихся и labels; остальные проверки видят
    # пустой Docker. Labels с фильтром сайтов — только здоровых, без фильтра — и больных (STUB_SICK_LABELS)
    DOCKER = """#!/bin/bash
case "$*" in
  "ps --filter health=unhealthy --filter status=running --format {{.Names}}")
    [ -z "$STUB_UNHEALTHY" ] || printf '%s\\n' $STUB_UNHEALTHY ;;
  "ps --filter status=restarting --format {{.Names}}")
    [ -z "$STUB_RESTARTING" ] || printf '%s\\n' $STUB_RESTARTING ;;
  "ps --filter status=running --filter health=healthy --filter health=none --format {{.Labels}}")
    printf '%s' "$STUB_LABELS" ;;
  *"--format {{.Labels}}"*)
    printf '%s' "$STUB_LABELS$STUB_SICK_LABELS" ;;
esac
"""
    NOTIFY = '#!/bin/bash\nprintf "%s\\n---\\n" "$1" >> "$STUB_SENT"\n'
    # curl: код по домену из STUB_SITES («домен=502» или «домен=502,200» — по попыткам), иначе 200;
    # 000 — как настоящий при таймауте, с кодом 28, через STUB_HANG секунд. Аргументы — в STUB_CURL_LOG
    CURL = """#!/bin/bash
printf '%s\\n' "$*" >> "$STUB_CURL_LOG"
url=${!#}; host=${url#https://}; host=${host%%/*}
n=$(grep -cF -- "https://$host/" "$STUB_CURL_LOG")
codes=$(printf '%s\\n' $STUB_SITES | awk -F= -v h="$host" '$1 == h { print $2 }')
code=$(awk -F, -v n="$n" '{ print (n <= NF ? $n : $NF) }' <<<"${codes:-200}")
[ "$code" != 000 ] || /bin/sleep "${STUB_HANG:-0}"
printf '%s' "$code"
[ "$code" != 000 ] || exit 28
"""
    SLEEP = '#!/bin/bash\nprintf "%s\\n" "$*" >> "$STUB_SLEPT"\n'

    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        for name, text in (("docker", self.DOCKER), ("infra-notify", self.NOTIFY), ("curl", self.CURL),
                           ("sleep", self.SLEEP)):
            (self.dir / name).write_text(text)
            (self.dir / name).chmod(0o755)
        # из эталона — функции (до «Все проверки») и цикл проверок контейнеров, как на сервере;
        # остальные проверки читают /proc, ufw, systemd
        head, sep, tail = self.SCRIPT.read_text().partition("# ---------- Все проверки ----------")
        start, end = tail.find("\nfor DOCKER_HOST in "), tail.find("\ndone\n")
        self.assertTrue(sep and 0 <= start < end, "в health-check.sh нет «Все проверки» и цикла по Docker")
        self.checks = head + tail[start:end + len("\ndone\n")]
        self.sent = self.dir / "sent"

    def run_checks(self, unhealthy, *calls, resolve=30, **stubs):
        env = {**os.environ, "PATH": f"{self.dir}:{os.environ['PATH']}", "STUB_UNHEALTHY": unhealthy,
               "STUB_SENT": str(self.sent), "HEALTH_STATE_DIR": str(self.dir / "state"),
               "HEALTH_RESOLVE_MINUTES": str(resolve), "STUB_CURL_LOG": str(self.dir / "curl.log"),
               "STUB_SLEPT": str(self.dir / "sleep.log"), "STUB_RESTARTING": "", "STUB_LABELS": "",
               "STUB_SICK_LABELS": "", "STUB_SITES": "", **stubs}
        script = self.checks + "\n".join(calls) + "\n"
        return subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, check=True).stdout

    def messages(self):
        return self.sent.read_text().split("---\n")[:-1] if self.sent.exists() else []

    def test_unhealthy_is_a_problem(self):
        out = self.run_checks("shop-back-1 lab-app-1", 'render "$PROBLEMS"')
        self.assertIn("Контейнеры нездоровы (не проходят свой healthcheck): shop-back-1 lab-app-1", out)
        self.assertIn("project-compose <проект> logs", out)
        self.assertEqual(self.run_checks("", 'render "$PROBLEMS"'), "")

    def test_notified_once_then_resolved_once(self):
        self.run_checks("shop-back-1", "notify_changes")
        self.run_checks("shop-back-1", "notify_changes")           # через 10 минут — то же: молчит
        self.run_checks("", "notify_changes")                      # поправили — «прошло» не сразу
        self.assertEqual(len(self.messages()), 1)
        self.assertIn("— новое:", self.messages()[0])
        self.assertIn("shop-back-1", self.messages()[0])
        self.run_checks("", "notify_changes", resolve=0)            # нет дольше HEALTH_RESOLVE_MINUTES
        self.assertEqual(len(self.messages()), 2)
        self.assertIn("— прошло:", self.messages()[1])
        self.assertIn("shop-back-1", self.messages()[1])

    # labels трёх работающих контейнеров: два имени через ||, условие с путём, Host с двумя именами
    LABELS = ("com.docker.compose.project=shop,traefik.enable=true,"
              "traefik.http.routers.shop.rule=Host(`shop.example.com`) || Host(`www.shop.example.com`)\n"
              "traefik.http.routers.lab.rule=Host(`lab.example.com`) && PathPrefix(`/`),traefik.enable=true\n"
              "traefik.http.routers.api.rule=Host(`api.example.com`, `api2.example.com`)\n")
    SITES = ["shop.example.com", "www.shop.example.com", "lab.example.com", "api.example.com", "api2.example.com"]

    def curls(self):
        log = self.dir / "curl.log"
        return log.read_text().splitlines() if log.exists() else []

    def test_sites_answering_are_fine(self):
        out = self.run_checks("", "check_sites", 'render "$PROBLEMS"', STUB_LABELS=self.LABELS,
                              STUB_SITES="shop.example.com=200 www.shop.example.com=301 lab.example.com=404 "
                                         "api.example.com=403 api2.example.com=200")
        self.assertEqual(out, "")
        self.assertEqual(len(self.curls()), len(self.SITES))   # каждый домен — один раз, без повтора
        self.assertFalse((self.dir / "sleep.log").exists())
        for site in self.SITES:
            calls = [c for c in self.curls() if c.endswith(f" https://{site}/")]
            self.assertEqual(len(calls), 1, site)
            self.assertIn(f"--resolve {site}:443:192.0.2.1 ", calls[0])   # публичный IPv4 сервера
            self.assertNotIn("-L", calls[0].split())

    def test_5xx_and_no_answer_after_retry(self):
        out = self.run_checks("", "check_sites", 'render "$PROBLEMS"', STUB_LABELS=self.LABELS,
                              STUB_SITES="shop.example.com=502 lab.example.com=000 api.example.com=503,200")
        self.assertIn("Сайты не отвечают (проверка с самого сервера): lab.example.com shop.example.com\n", out)
        self.assertEqual(out.count("Сайты не отвечают"), 1)
        self.assertIn("shop.example.com — 502", out)
        self.assertIn("lab.example.com — нет ответа", out)
        self.assertIn("--resolve <домен>:443:192.0.2.1", out)
        self.assertIn("project-compose <проект> logs --tail 50", out)
        self.assertNotIn("api.example.com", out)               # 503, через 10 с — 200: выкладка, не сбой
        self.assertEqual((self.dir / "sleep.log").read_text(), "10\n")   # одна пауза на все повторы
        self.assertEqual(len(self.curls()), len(self.SITES) + 3)

    # бэкенды сайтов web-start (back.<домен>) — по /api/health, сбой — любой ответ, кроме 200
    BACKS = ["back.shop.example.com", "back.lab.example.com", "back.api.example.com"]
    BACK_LABELS = "traefik.http.routers.shop.rule=Host(`shop.example.com`)\n" + "".join(
        f"traefik.http.routers.b{i}.rule=Host(`{b}`)\n" for i, b in enumerate(BACKS))

    def test_backend_checked_by_api_health(self):
        out = self.run_checks("", "check_sites", 'render "$PROBLEMS"', STUB_LABELS=self.BACK_LABELS,
                              STUB_SITES="shop.example.com=404 " + " ".join(f"{b}=200" for b in self.BACKS))
        self.assertEqual(out, "")
        self.assertEqual(sorted(c.split()[-1] for c in self.curls()),
                         sorted([f"https://{b}/api/health" for b in self.BACKS] + ["https://shop.example.com/"]))
        for back in self.BACKS:
            calls = [c for c in self.curls() if c.endswith(f" https://{back}/api/health")]
            self.assertIn(f"--resolve {back}:443:192.0.2.1 ", calls[0])

    def test_backend_not_200_after_retry(self):
        out = self.run_checks("", "check_sites", 'render "$PROBLEMS"', STUB_LABELS=self.BACK_LABELS,
                              STUB_SITES="shop.example.com=200 back.shop.example.com=404 back.lab.example.com=000 "
                                         "back.api.example.com=301,200")
        self.assertIn("Сайты не отвечают (проверка с самого сервера): back.lab.example.com back.shop.example.com\n", out)
        self.assertEqual(out.count("Сайты не отвечают"), 1)
        self.assertIn("back.shop.example.com/api/health — 404", out)
        self.assertIn("back.lab.example.com/api/health — нет ответа", out)
        self.assertIn("https://<домен>/api/health", out)
        self.assertNotIn("back.api.example.com", out)          # 301, через 10 с — 200: выкладка, не сбой
        self.assertEqual((self.dir / "sleep.log").read_text(), "10\n")
        self.assertEqual(len(self.curls()), 4 + 3)

    def test_sick_containers_not_checked(self):
        sick = ("traefik.http.routers.bad.rule=Host(`bad.example.com`)\n"
                "traefik.http.routers.loop.rule=Host(`loop.example.com`)\n")
        out = self.run_checks("shop-bad-1", "check_sites", 'render "$PROBLEMS"', STUB_RESTARTING="shop-loop-1",
                              STUB_LABELS="traefik.http.routers.ok.rule=Host(`ok.example.com`)\n",
                              STUB_SICK_LABELS=sick, STUB_SITES="bad.example.com=502 loop.example.com=000")
        self.assertIn("Контейнеры нездоровы (не проходят свой healthcheck): shop-bad-1", out)
        self.assertIn("Контейнеры перезапускаются по кругу: shop-loop-1", out)
        self.assertNotIn("Сайты не отвечают", out)
        self.assertEqual([c.split()[-1] for c in self.curls()], ["https://ok.example.com/"])

    def test_odd_labels_and_no_docker(self):
        labels = ("traefik.http.routers.a.rule=Host(`a.example.com`) && PathPrefix(`/api`),"
                  "note=it's \"quoted\" $(echo pwned >> \"$STUB_CURL_LOG\") * ; `x`,"
                  "traefik.http.routers.b.rule=HostRegexp(`^.+\\.example\\.com$`),"
                  "traefik.http.routers.c.rule=Host(`user@evil.example.com`) || Host(`-o.example.com/x`) || Host(`--config`)\n"
                  "traefik.http.routers.a2.rule=Host(`a.example.com`)\n")
        self.assertEqual(self.run_checks("", "check_sites", 'render "$PROBLEMS"', STUB_LABELS=labels), "")
        self.assertEqual([c.split()[-1] for c in self.curls()], ["https://a.example.com/"])
        (self.dir / "curl.log").unlink()
        self.assertEqual(self.run_checks("", "check_sites", 'render "$PROBLEMS"'), "")    # Docker пуст или не отвечает
        self.assertEqual(self.curls(), [])

    def test_sites_notified_once(self):
        self.run_checks("", "check_sites", "notify_changes", STUB_LABELS=self.LABELS,
                        STUB_SITES="shop.example.com=502")
        self.run_checks("", "check_sites", "notify_changes", STUB_LABELS=self.LABELS,
                        STUB_SITES="shop.example.com=504")
        self.assertEqual(len(self.messages()), 1)                # 502 → 504 — та же проблема
        self.assertIn("— новое:", self.messages()[0])
        self.assertIn("Сайты не отвечают (проверка с самого сервера): shop.example.com", self.messages()[0])
        self.run_checks("", "check_sites", "notify_changes", resolve=0, STUB_LABELS=self.LABELS)
        self.assertEqual(len(self.messages()), 2)
        self.assertIn("— прошло:", self.messages()[1])
        self.assertIn("shop.example.com", self.messages()[1])

    def test_hanging_sites_time_is_bounded(self):
        # 35 доменов, 10 «висят» (заглушка curl ждёт 1 с, потом 000): по одному — 20 с и больше
        names = [f"s{i:02}.example.com" for i in range(35)]
        labels = "".join(f"traefik.http.routers.r{i}.rule=Host(`{n}`)\n" for i, n in enumerate(names))
        start = time.monotonic()
        out = self.run_checks("", "check_sites", 'render "$PROBLEMS"', STUB_LABELS=labels, STUB_HANG="1",
                              STUB_SITES=" ".join(f"{n}=000" for n in names[:10]))
        self.assertLess(time.monotonic() - start, 10)
        self.assertIn("Сайты не отвечают (проверка с самого сервера): " + " ".join(names[:10]) + "\n", out)
        self.assertIn("не проверены: 5", out)                    # больше 30 доменов — проверяются первые 30
        self.assertEqual(sorted({c.split()[-1] for c in self.curls()}), [f"https://{n}/" for n in names[:30]])
        self.assertIn("\ndone\nunset DOCKER_HOST\ncheck_sites\n", self.SCRIPT.read_text())   # после цикла по Docker


@unittest.skipUnless(shutil.which("git") and shutil.which("ssh-keygen"), "нужны git и ssh-keygen")
class SignedUpgrade(unittest.TestCase):
    """infra tag-signed: infra upgrade ставит только тег, подписанный ключом из SIGNERS текущей версии."""

    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.repo = self.dir / "engine"
        self.repo.mkdir()
        self.keys = {}
        for who in ("author", "stranger"):
            key = self.dir / who
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", who, "-f", key], check=True)
            self.keys[who] = key
        self.git("init", "-q")
        shutil.copy(ROOT / "infra", self.repo / "infra")
        self.signers("author")
        self.git("add", ".")
        self.git("commit", "-q", "-m", "v1")

    def git(self, *args):
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.org", "-c", "gpg.format=ssh",
                        *args], cwd=self.repo, check=True, capture_output=True)

    def signers(self, who):
        public = pathlib.Path(f"{self.keys[who]}.pub").read_text().split()
        (self.repo / "SIGNERS").write_text(f'# ключи\n{who} namespaces="git" {public[0]} {public[1]}\n')

    def tag(self, name, who=None):
        if who:
            self.git("-c", f"user.signingkey={self.keys[who]}", "tag", "-s", name, "-m", name)
        else:
            self.git("tag", "-a", name, "-m", name)

    def signed(self, name):
        return subprocess.run(["bash", str(self.repo / "infra"), "tag-signed", name],
                              capture_output=True).returncode == 0

    def test_only_author_signature(self):
        self.tag("v1.0.1", "author")
        self.tag("v1.0.2", "stranger")
        self.tag("v1.0.3")
        self.git("tag", "v1.0.4")                       # лёгкий тег — без подписи
        self.assertTrue(self.signed("v1.0.1"))
        self.assertFalse(self.signed("v1.0.2"))
        self.assertFalse(self.signed("v1.0.3"))
        self.assertFalse(self.signed("v1.0.4"))
        self.assertFalse(self.signed("v9.9.9"))         # такой версии нет
        # подписанная старая версия под новым номером: имя внутри тега другое
        obj = subprocess.run(["git", "rev-parse", "refs/tags/v1.0.1"], cwd=self.repo, check=True,
                             capture_output=True, text=True).stdout.strip()
        self.git("update-ref", "refs/tags/v3.0.0", obj)
        self.assertFalse(self.signed("v3.0.0"))
        self.assertFalse(self.signed("v1.0.*"))         # шаблон, а не имя

    def test_new_version_does_not_vouch_for_itself(self):
        # чужая версия со своим ключом в SIGNERS — проверяется по SIGNERS той, что стоит
        self.git("checkout", "-q", "-b", "evil")
        self.signers("stranger")
        self.git("commit", "-q", "-am", "evil")
        self.tag("v2.0.0", "stranger")
        self.git("checkout", "-q", "-")
        self.assertFalse(self.signed("v2.0.0"))
        # и правка SIGNERS в рабочей папке без коммита не помогает
        self.signers("stranger")
        self.assertFalse(self.signed("v2.0.0"))


@unittest.skipUnless(shutil.which("git") and shutil.which("ssh-keygen"), "нужны git и ssh-keygen")
class ReleaseScript(unittest.TestCase):
    """tools/release.sh: проверки до изменений, CHANGELOG с пустым «Не выпущено» сверху, коммит и подписанный тег."""

    CHANGELOG = "# Изменения движка\n\n## Не выпущено\n\n- новое раз\n- новое два\n\n## v1.0.0 — 2026-01-01 — первая\n\n- было\n"

    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.repo = self.dir / "engine"
        (self.repo / "tools").mkdir(parents=True)
        key = self.dir / "author"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "author", "-f", key], check=True)
        public = pathlib.Path(f"{key}.pub").read_text().split()
        (self.repo / "SIGNERS").write_text(f'author namespaces="git" {public[0]} {public[1]}\n')
        shutil.copy(ROOT / "infra", self.repo / "infra")
        if (ROOT / "tools/release.sh").exists():
            shutil.copy(ROOT / "tools/release.sh", self.repo / "tools/release.sh")
        (self.repo / "CHANGELOG.md").write_text(self.CHANGELOG)
        self.env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", "RELEASE_CHECK": "true"}
        self.git("init", "-q", "-b", "main")
        for k, v in (("user.name", "t"), ("user.email", "t@example.org"), ("gpg.format", "ssh"),
                     ("user.signingkey", str(key))):
            self.git("config", k, v)
        self.git("add", ".")
        self.git("commit", "-q", "-m", "v1.0.0")
        self.git("tag", "-s", "v1.0.0", "-m", "v1.0.0")

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.repo, env=self.env, check=True,
                              capture_output=True, text=True).stdout.strip()

    def release(self, *args):
        return subprocess.run(["bash", str(self.repo / "tools/release.sh"), *args], cwd=self.dir, env=self.env,
                              capture_output=True, text=True)

    def assertRefused(self, *args):
        head = self.git("rev-parse", "HEAD")
        changelog = (self.repo / "CHANGELOG.md").read_text()
        result = self.release(*args)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.git("rev-parse", "HEAD"), head)
        self.assertEqual((self.repo / "CHANGELOG.md").read_text(), changelog)
        self.assertEqual(self.git("tag", "-l"), "v1.0.0")
        return result.stderr

    def test_release(self):
        result = self.release("1.0.1", "заголовок")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("git push origin main v1.0.1", result.stdout)
        today = time.strftime("%Y-%m-%d")
        self.assertEqual((self.repo / "CHANGELOG.md").read_text(), self.CHANGELOG.replace(
            "## Не выпущено\n", f"## Не выпущено\n\n## v1.0.1 — {today} — заголовок\n"))
        self.assertEqual(self.git("log", "--format=%s", "v1.0.0..HEAD"), "v1.0.1: заголовок")
        self.assertEqual(self.git("diff", "--name-only", "v1.0.0", "HEAD"), "CHANGELOG.md")
        self.assertEqual(self.git("rev-parse", "v1.0.1^{commit}"), self.git("rev-parse", "HEAD"))
        signed = subprocess.run(["bash", str(self.repo / "infra"), "tag-signed", "v1.0.1"], env=self.env)
        self.assertEqual(signed.returncode, 0)
        self.assertEqual(self.git("status", "--porcelain"), "")

    def test_nothing_unreleased(self):
        (self.repo / "CHANGELOG.md").write_text("## Не выпущено\n\n## v1.0.0 — 2026-01-01 — первая\n\n- было\n")
        self.git("commit", "-q", "-am", "пусто")
        self.assertIn("пусто", self.assertRefused("1.0.1", "заголовок"))

    def test_dirty_tree(self):
        (self.repo / "infra").write_text("правка")
        self.assertIn("несохранённое", self.assertRefused("1.0.1", "заголовок"))

    def test_version_not_newer(self):
        self.assertIn("не новее", self.assertRefused("0.9.9", "заголовок"))
        self.assertIn("уже есть", self.assertRefused("1.0.0", "заголовок"))
        self.assertIn("использование", self.assertRefused("1.0", "заголовок"))

    def test_only_from_main(self):
        self.git("switch", "-q", "-c", "other")
        self.assertIn("main", self.assertRefused("1.0.1", "заголовок"))


@unittest.skipUnless(shutil.which("git") and shutil.which("ssh-keygen"), "нужны git и ssh-keygen")
class UpgradePreview(unittest.TestCase):
    """infra upgrade: сервер не менялся (--check, «нет», предпросмотр не прошёл, Ctrl+C) — движок прежней версии;
    «изменений нет» и «да» — новой. Стенд: «origin» с подписанными v1.0.0 и v1.1.0, движок — его клон на v1.0.0,
    /etc/infra и /var/lib/infra — во временной папке; Ansible, install.sh, infra-log, id, systemd — заглушки,
    пишут строку в журнал стенда."""

    PLAYBOOK = """#!/bin/sh
echo "ansible-playbook $*" >> "$STUB_LOG"
[ -z "$STUB_INT" ] || kill -INT 0          # Ctrl+C в терминале — сигнал всей группе процессов
echo "PLAY RECAP"
echo "srv : ok=40 changed=$STUB_CHANGED failed=0"
exit "$STUB_RC"
"""
    STUBS = {
        "id": '#!/bin/sh\n[ "$1" = -u ] && echo 0 || exec /usr/bin/id "$@"\n',
        "systemctl": "#!/bin/sh\nexit 3\n",                                  # infra-apply не идёт
        "systemd-run": '#!/bin/sh\necho "systemd-run $*" >> "$STUB_LOG"\nexit "$STUB_APPLY_RC"\n',  # прогон «да»
        "stat": '#!/bin/sh\n[ "$1" = -c ] && [ "$2" = %s ] && wc -c < "$3" | tr -d " "\n',  # stat -c на Mac нет
    }

    @classmethod
    def setUpClass(cls):
        cls.dir = pathlib.Path(tempfile.mkdtemp())
        cls.addClassCleanup(shutil.rmtree, cls.dir)
        cls.bin, cls.etc, origin = cls.dir / "bin", cls.dir / "etc", cls.dir / "origin"
        for d in (cls.bin, cls.etc, origin / "roles/base/files"):
            d.mkdir(parents=True)
        for name, text in cls.STUBS.items():
            (cls.bin / name).write_text(text)
            (cls.bin / name).chmod(0o755)
        (cls.etc / "server.yml").write_text("server_name: srv\n")
        (cls.etc / "secrets.yml").write_text("")
        key = cls.dir / "author"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "author", "-f", key], check=True)
        public = pathlib.Path(f"{key}.pub").read_text().split()
        (origin / "SIGNERS").write_text(f'author namespaces="git" {public[0]} {public[1]}\n')
        # infra из репозитория, только пути и массивы: bash 3.2 на Mac под set -u не знает пустой "${A[@]}",
        # ${A[@]+"${A[@]}"} — то же на любом bash
        infra = (ROOT / "infra").read_text()
        for old, new in (("\nCONF=/etc/infra\n", f'\nCONF="{cls.etc}"\n'),
                         ("\nSTATE=/var/lib/infra ", f'\nSTATE="{cls.dir / "state"}" '),
                         ('"${ARGS[@]}"', '${ARGS[@]+"${ARGS[@]}"}'),
                         ('"${CLEANUP[@]}"', '${CLEANUP[@]+"${CLEANUP[@]}"}')):
            if old not in infra:
                raise AssertionError(f"в infra нет «{old.strip()}» — стенду нечего подменить")
            infra = infra.replace(old, new)
        for path, text in (("infra", infra),
                           ("install.sh", '#!/bin/sh\necho "install $(cat "$(dirname "$0")/VERSION")" >> "$STUB_LOG"\n'),
                           ("roles/base/files/infra-log", '#!/bin/sh\necho "infra-log $*" >> "$STUB_LOG"\n'),
                           (".gitignore", ".venv/\n")):
            (origin / path).write_text(text)
            (origin / path).chmod(0o755 if text.startswith("#!") else 0o644)

        def git(*args):
            subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.org", "-c", "gpg.format=ssh",
                            "-c", f"user.signingkey={key}", *args], cwd=origin, check=True, capture_output=True)
        git("init", "-q")
        for version in ("1.0.0", "1.1.0"):
            (origin / "VERSION").write_text(f"{version}\n")
            git("add", ".")
            git("commit", "-q", "-m", f"v{version}")
            git("tag", "-s", f"v{version}", "-m", f"v{version}")
        cls.origin = origin

    def setUp(self):
        self.engine = self.dir / "engine"
        shutil.rmtree(self.engine, ignore_errors=True)
        subprocess.run(["git", "clone", "-q", self.origin, self.engine], check=True)
        subprocess.run(["git", "-c", "advice.detachedHead=false", "checkout", "-q", "v1.0.0"], cwd=self.engine,
                       check=True)
        (self.engine / ".venv/bin").mkdir(parents=True)
        (self.engine / ".venv/bin/ansible-playbook").write_text(self.PLAYBOOK)
        (self.engine / ".venv/bin/ansible-playbook").chmod(0o755)
        self.log = self.dir / "stand.log"
        self.log.write_text("")

    def upgrade(self, *args, answer="", changed=2, rc=0, interrupt=False, apply_rc=0):
        env = {**os.environ, "PATH": f"{self.bin}:{os.environ['PATH']}", "STUB_LOG": str(self.log),
               "STUB_CHANGED": str(changed), "STUB_RC": str(rc), "STUB_INT": "1" if interrupt else "",
               "STUB_APPLY_RC": str(apply_rc)}
        run = subprocess.run(["bash", str(self.engine / "infra"), "upgrade", "v1.1.0", *args], input=answer,
                             env=env, capture_output=True, text=True, timeout=60, start_new_session=True)
        engine = subprocess.run(["git", "describe", "--tags"], cwd=self.engine, check=True, capture_output=True,
                                text=True).stdout.strip()
        return run, engine, self.log.read_text().splitlines()

    def assertReturned(self, lines):
        self.assertEqual([x for x in lines if x.startswith("install ")][-1], "install 1.0.0")
        self.assertIn("infra-log upgrade v1.1.0: только просмотр — движок возвращён на v1.0.0", lines)

    def test_check(self):
        run, engine, lines = self.upgrade("--check")
        self.assertEqual((run.returncode, engine), (0, "v1.0.0"), run.stderr)
        self.assertReturned(lines)
        self.assertIn("== Движок возвращён: v1.0.0", run.stdout)

    def test_answer_no(self):
        run, engine, lines = self.upgrade(answer="n\n")
        self.assertEqual((run.returncode, engine), (1, "v1.0.0"), run.stderr)
        self.assertReturned(lines)

    def test_preview_failed(self):
        run, engine, lines = self.upgrade(rc=2)
        self.assertNotEqual(run.returncode, 0)
        self.assertEqual(engine, "v1.0.0", run.stderr)
        self.assertReturned(lines)

    def test_interrupted_preview(self):
        run, engine, lines = self.upgrade(interrupt=True)
        self.assertEqual((run.returncode, engine), (130, "v1.0.0"), run.stderr)
        self.assertReturned(lines)

    def test_nothing_to_change_keeps_new(self):
        run, engine, lines = self.upgrade(changed=0)
        self.assertEqual((run.returncode, engine), (0, "v1.1.0"), run.stderr)
        self.assertIn("infra-log upgrade: движок v1.0.0 → v1.1.0", lines)
        self.assertEqual([x for x in lines if x.startswith("install ")], ["install 1.1.0"])
        self.assertFalse([x for x in lines if "только просмотр" in x])

    def test_answer_yes_keeps_new(self):
        run, engine, lines = self.upgrade(answer="y\n")
        self.assertEqual((run.returncode, engine), (0, "v1.1.0"), run.stderr)
        self.assertIn("infra-log upgrade: движок v1.0.0 → v1.1.0", lines)
        self.assertTrue(lines[-1].startswith("systemd-run "), lines)
        self.assertEqual([x for x in lines if x.startswith("install ")], ["install 1.1.0"])

    def test_failed_apply_keeps_new(self):
        # прогон начат — сервер мог уже измениться новой версией, назад её не отмотать
        run, engine, lines = self.upgrade(answer="y\n", apply_rc=1)
        self.assertEqual((run.returncode, engine), (1, "v1.1.0"), run.stderr)
        self.assertTrue(lines[-1].startswith("systemd-run "), lines)



@unittest.skipUnless(shutil.which("jq"), "нужен jq")
class ProjectDeployTo(unittest.TestCase):
    """project-deploy <проект> to <тег>: образа нет — .env побайтно тот же; есть — выкладка, и в .env заменена одна
    строка DEPLOY_IMAGE, владелец и права прежние; .env-ссылка — отказ; сбой выкладки — прежние версия и .env.
    Стенд: скрипт с папками проекта и состояния во временной папке; docker, project-compose, flock, infra-log —
    заглушки, пишут строку в журнал стенда; chown, chmod, stat, mv, dd, getfacl и setfacl — на Python (их ключей
    и ACL на Mac нет), пишут строку в журнал файловых команд. Папка проекта (/srv/projects/<проект>) — proj,
    web/ — внутри."""

    REPO = "ghcr.io/example/shop"
    HASH = "bb168cfcfece1b663da0141574e4994eed9eea20"
    OLD, NEW = "sha256:" + "1" * 64, "sha256:" + "2" * 64
    ENV = ('DEBUG=False\n#DEPLOY_IMAGE=ghcr.io/example/shop:v0\nDEPLOY_IMAGE="ghcr.io/example/shop:main"\n'
           "SITE_NAME=Магазин\n")
    # docker: в реестре — только теги из STUB_TAGS («образ:тег=дайджест») и любые @sha256
    DOCKER = """#!/bin/bash
echo "docker $*" >> "$STUB_LOG"
ref=${!#}
digest=$(printf '%s\\n' $STUB_TAGS | awk -F= -v r="$ref" '$1 == r { print $2 }')
case $1 in
  pull) [ -n "$digest" ] || [[ $ref == *@sha256:* ]] || { echo "Error response from daemon: manifest unknown" >&2; exit 1; } ;;
  image) [ -z "$digest" ] || echo "${ref%:*}@$digest" ;;
  run) printf 'services:\\n  api:\\n    image: ${DEPLOY_IMAGE}\\n' ;;
esac
"""
    # project-compose: STUB_FAIL_UP — первый up не проходит (возврат прежней версии — проходит)
    COMPOSE = """#!/bin/bash
echo "project-compose $*" >> "$STUB_LOG"
case "$*" in
  *"config --format json") echo '{"services":{}}' ;;
  *"config --services") echo api ;;
  *" up "*) [ -z "$STUB_FAIL_UP" ] || [ "$(grep -c ' up ' "$STUB_LOG")" -gt 1 ] || exit 1 ;;
esac
"""
    PYTHON = ("#!/usr/bin/env python3\nimport os, stat, sys\nargs = [a for a in sys.argv[1:] if a not in ('-f', '-T', '-fT', '--')]\n"
              "open(os.environ.get('STUB_FSLOG', os.devnull), 'a').write(' '.join([os.path.basename(sys.argv[0])] + args) + '\\n')\n")
    STUBS = {
        "docker": DOCKER,
        "project-compose": COMPOSE,
        "project-docker-host": "#!/bin/sh\n",
        "flock": "#!/bin/sh\n",
        "infra-log": '#!/bin/sh\necho "infra-log $*" >> "$STUB_LOG"\n',
        # chown --reference=<файл> | <uid>:<gid> и chmod --reference=<файл> | <восьмеричные>: по ссылке идут, как GNU без -h
        "chown": PYTHON + "who, path = args\n"
                 "if who.startswith('--reference='): ref = os.stat(who.split('=', 1)[1]); who = f'{ref.st_uid}:{ref.st_gid}'\n"
                 "os.chown(path, *map(int, who.split(':')))\n"
                 # STUB_RESTORE_ENV — крючок «после чтения, до сверки stat»: участник возвращает прежний .env (тот же inode)
                 # с <.env>.held на место ссылки — сверка stat подмены не видит, защищает только nofollow у dd
                 "if os.environ.get('STUB_RESTORE_ENV'):\n"
                 "    os.replace(os.environ['STUB_RESTORE_ENV'] + '.held', os.environ['STUB_RESTORE_ENV'])\n",
        "chmod": PYTHON + "how, path = args\n"
                 "os.chmod(path, stat.S_IMODE(os.stat(how.split('=', 1)[1]).st_mode) if how.startswith('--reference=') else int(how, 8))\n",
        # stat -c <формат> <файл>: %i %u %g %a %F, по ссылке не идёт (lstat), как GNU stat и uutils без -L
        "stat": PYTHON + "fmt, path = args[1:]\nst = os.lstat(path)\n"
                "kind = {stat.S_IFREG: 'regular empty file' if not st.st_size else 'regular file', stat.S_IFLNK: 'symbolic link',\n"
                "        stat.S_IFDIR: 'directory'}.get(stat.S_IFMT(st.st_mode), 'other')\n"
                "for k, v in (('%i', st.st_ino), ('%u', st.st_uid), ('%g', st.st_gid), ('%a', f'{stat.S_IMODE(st.st_mode):o}'), ('%F', kind)):\n"
                "    fmt = fmt.replace(k, str(v))\nprint(fmt)\n",
        # getfacl -n -p <файл>: по ссылке идёт, как GNU getfacl; ACL на Mac нет — только строка «# file:» и права
        "getfacl": PYTHON + "os.stat(args[-1])\nprint(f'# file: {args[-1]}\\nuser::rw-\\ngroup::r--\\nother::---')\n",
        # setfacl --set-file=- <файл>: файла не меняет, «# file:» с stdin — в журнал. STUB_SWAP_ENV — крючок «после чтения,
        # до mv»: этот .env участник подменяет ссылкой на STUB_SWAP_TO
        "setfacl": PYTHON + "acl = sys.stdin.read().splitlines()\nos.stat(args[-1])\n"
                   "open(os.environ.get('STUB_FSLOG', os.devnull), 'a').write(f'acl {acl[0]}\\n')\n"
                   "if os.environ.get('STUB_SWAP_ENV'):\n"
                   "    os.remove(os.environ['STUB_SWAP_ENV']); os.symlink(os.environ['STUB_SWAP_TO'], os.environ['STUB_SWAP_ENV'])\n",
        "mv": PYTHON + "os.replace(args[0], args[1])\n",
        # dd if=<файл> [iflag=nofollow]: с nofollow ссылку не открывает (O_NOFOLLOW), как GNU dd и uutils
        "dd": PYTHON + "opts = dict(a.split('=', 1) for a in args)\n"
              "flags = os.O_RDONLY | (os.O_NOFOLLOW if 'nofollow' in opts.get('iflag', '').split(',') else 0)\n"
              "sys.stdout.buffer.write(os.fdopen(os.open(opts['if'], flags), 'rb').read())\n",
    }

    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.bin, self.proj, self.states = self.dir / "bin", self.dir / "proj", self.dir / "state"
        self.web = self.proj / "web"
        for d in (self.bin, self.proj, self.web, self.states):
            d.mkdir()
        for name, text in self.STUBS.items():
            (self.bin / name).write_text(text)
            (self.bin / name).chmod(0o755)
        script = (ROOT / "roles/project/files/project-deploy").read_text()
        for old, new in (("/srv/projects/$NAME", f'"{self.proj}"'), ("/var/lib/project-deploy", f'"{self.states}"')):
            if old not in script:
                raise AssertionError(f"в project-deploy нет «{old}» — стенду нечего подменить")
            script = script.replace(old, new)
        (self.dir / "project-deploy").write_text(script)
        self.env = self.web / ".env"
        self.env.write_text(self.ENV)
        self.env.chmod(0o640)
        (self.states / "shop.current").write_text(f"{self.REPO}@{self.OLD}\n")
        self.log, self.fslog = self.dir / "log", self.dir / "fslog"

    def deploy(self, *args, **stubs):
        env = {**os.environ, "PATH": f"{self.bin}:{os.environ['PATH']}", "STUB_LOG": str(self.log), "STUB_FAIL_UP": "",
               "STUB_FSLOG": str(self.fslog),
               "STUB_TAGS": f"{self.REPO}:main={self.OLD} {self.REPO}:v1={self.OLD} {self.REPO}:{self.HASH}={self.NEW}",
               **stubs}
        run = subprocess.run(["bash", str(self.dir / "project-deploy"), "shop", *args], env=env,
                             capture_output=True, text=True)
        return run, self.log.read_text().splitlines() if self.log.exists() else []

    def state(self, name):
        path = self.states / f"shop.{name}"
        return path.read_text().strip() if path.exists() else None

    def leftovers(self):
        return sorted([p.name for p in self.web.iterdir() if p.name != ".env"] +
                      [f"../{p.name}" for p in self.proj.iterdir() if p.name != "web"])

    def test_unknown_tag_keeps_env(self):
        before = self.env.read_bytes()
        run, lines = self.deploy("to", "bb168cf")                   # опечатка: короткий хеш
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertIn("ничего не менял", run.stderr)
        self.assertEqual(self.env.read_bytes(), before)
        self.assertEqual(self.leftovers(), [])
        self.assertEqual(self.state("current"), f"{self.REPO}@{self.OLD}")
        self.assertFalse([x for x in lines if not x.startswith("docker ")], lines)

    def test_known_tag_rolls_out_and_replaces_one_line(self):
        # версия, которая уже не удалась, — решение администратора: выкладывается
        (self.states / "shop.failed-ref").write_text(f"{self.REPO}@{self.NEW}\n")
        (self.states / "shop.failed").write_text("2026-10-20 03:00 запуск: работает прежняя версия\n")
        before = self.env.read_text().splitlines()
        run, lines = self.deploy("to", self.HASH)
        self.assertEqual(run.returncode, 0, run.stderr)
        after = self.env.read_text().splitlines()
        self.assertEqual(len(after), len(before))
        changed = [(a, b) for a, b in zip(before, after) if a != b]
        self.assertEqual(changed, [('DEPLOY_IMAGE="ghcr.io/example/shop:main"', f"DEPLOY_IMAGE={self.REPO}:{self.HASH}")])
        self.assertEqual(self.env.stat().st_mode & 0o777, 0o640)
        self.assertEqual(self.leftovers(), ["compose.yml"])
        self.assertEqual((self.state("current"), self.state("previous")),
                         (f"{self.REPO}@{self.NEW}", f"{self.REPO}@{self.OLD}"))
        self.assertIsNone(self.state("failed-ref"))
        self.assertIsNone(self.state("failed"))
        self.assertTrue([x for x in lines if x.startswith("project-compose shop up ")], lines)
        self.assertIn(f"infra-log выкладка shop: DEPLOY_IMAGE shop:main → shop:{self.HASH}", lines)

    def test_env_link_refused(self):
        target = self.dir / "target.env"
        target.write_text(self.ENV)
        self.env.unlink()
        self.env.symlink_to(target)
        run, lines = self.deploy("to", self.HASH)
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertIn("ссылка", run.stderr)
        self.assertTrue(self.env.is_symlink())
        self.assertEqual(target.read_text(), self.ENV)
        self.assertEqual(self.leftovers(), [])
        self.assertEqual(lines, [])

    def test_bad_tag_refused_before_docker(self):
        for tag in ("main;id", "../x", "a/b", "-x", ".x", "", "a" * 129):
            with self.subTest(tag=tag):
                run, lines = self.deploy("to", tag)
                self.assertEqual(run.returncode, 1, run.stderr)
                self.assertIn("Тег образа", run.stderr)
                self.assertEqual(lines, [])
        self.assertEqual(self.env.read_text(), self.ENV)

    def test_failed_rollout_keeps_env_and_version(self):
        before = self.env.read_bytes()
        run, lines = self.deploy("to", self.HASH, STUB_FAIL_UP="1")
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertIn("не удалось на шаге «запуск»", run.stderr)
        self.assertEqual(self.env.read_bytes(), before)
        self.assertEqual(self.state("current"), f"{self.REPO}@{self.OLD}")
        self.assertEqual(self.state("failed-ref"), f"{self.REPO}@{self.NEW}")
        self.assertIn(f"docker tag {self.REPO}@{self.OLD} {self.REPO}:main", lines)   # прежний образ — на место
        self.assertFalse([x for x in lines if "DEPLOY_IMAGE" in x], lines)

    def test_same_version_only_env(self):
        before = self.env.read_bytes()
        run, lines = self.deploy("to", "main")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("эта версия уже работает", run.stdout)
        self.assertEqual(self.env.read_bytes(), before)
        run, lines = self.deploy("to", "v1")                        # другой тег того же образа
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn(f"DEPLOY_IMAGE={self.REPO}:v1\n", self.env.read_text())
        self.assertFalse([x for x in lines if " up " in x], lines)

    def test_image_forms(self):
        cases = (
            ("DEPLOY_IMAGE=ghcr.io/example/shop@sha256:" + "1" * 64, "не дайджест", None),
            ("DEPLOY_IMAGE=ghcr.io/example/shop:main\nDEPLOY_IMAGE=ghcr.io/example/shop:dev", "несколько строк", None),
            ("DEBUG=False", "нет DEPLOY_IMAGE", None),
            # без тега и реестр с портом: «:» в имени — не тег
            ("DEPLOY_IMAGE=registry.example.com:5000/shop", "не скачать",
             f"docker pull -q registry.example.com:5000/shop:{self.HASH}"),
        )
        for text, error, pulled in cases:
            with self.subTest(env=text):
                self.log.unlink(missing_ok=True)
                self.env.write_text(text + "\n")
                run, lines = self.deploy("to", self.HASH)
                self.assertEqual(run.returncode, 1, run.stderr)
                self.assertIn(error, run.stderr)
                self.assertEqual(self.env.read_text(), text + "\n")
                self.assertEqual(lines, [pulled] if pulled else [])

    def swap_env(self, stub, when, then):
        """Заглушка stub при аргументах when (шаблон case) подменяет .env ссылкой на .env чужого проекта (папка 0700),
        как участник проекта, у которого web/ открыта на запись, и запускает then. Затем to <хеш>"""
        other = self.dir / "other"
        other.mkdir(mode=0o700)
        (other / ".env").write_text("DEPLOY_IMAGE=ghcr.io/example/other:main\ndb_password_other=s3cret\n")
        (self.bin / stub).write_text(f'#!/bin/bash\ncase "$*" in {when}) rm -f .env && ln -s "{other}/.env" .env ;; esac\n'
                                     f'exec {then} "$@"\n')
        (self.bin / stub).chmod(0o755)
        run, lines = self.deploy("to", self.HASH)
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertIn(f"работает {self.REPO}:{self.HASH}, но .env не записан", run.stderr)
        self.assertEqual(self.state("current"), f"{self.REPO}@{self.NEW}")
        self.assertTrue(self.env.is_symlink())                    # root по ссылке не писал
        self.assertEqual(self.leftovers(), ["compose.yml"])       # временного .env.* нет
        self.assertFalse([p.name for p in self.web.iterdir()
                          if not p.is_symlink() and p.is_file() and "s3cret" in p.read_text()])
        self.assertFalse([x for x in lines if "DEPLOY_IMAGE" in x], lines)
        return run

    def test_env_swapped_during_rollout(self):
        # подменили, пока шёл запуск, — повторная проверка перед чтением
        (self.bin / "project-compose").rename(self.bin / "project-compose.real")
        run = self.swap_env("project-compose", '*" up "*', f'"{self.bin}/project-compose.real"')
        self.assertIn("ссылка или не файл", run.stderr)

    def test_env_swapped_after_check(self):
        # подменили уже после проверки, перед чтением, — dd с nofollow ссылку не открывает
        self.swap_env("mktemp", "*", shutil.which("mktemp"))

    def test_env_swapped_after_check_and_back_refused(self):
        # подменили ссылкой на чужой файл перед чтением, а прежний .env вернули до сверки stat (тот же inode —
        # сверка не ловит): отказ даёт только dd с nofollow, текст чужого файла не попал ни в один файл
        victim = victim_file(self.dir)
        participant_mktemp(self.bin, self.web, victim, swap="env-back")
        run, _ = self.deploy("to", self.HASH, STUB_RESTORE_ENV=str(self.env))
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertIn(f"работает {self.REPO}:{self.HASH}, но .env не записан", run.stderr)
        self.assertEqual((victim.read_text(), victim.stat().st_mode & 0o777), ("victim\n", 0o600))
        self.assertEqual(files_with(self.proj, "victim"), [])
        self.assertEqual(self.fs("mv"), ["mv compose.yml.new compose.yml"])     # .env не трогали
        self.assertFalse([p.name for p in self.proj.iterdir() if p.name.startswith(".env")])
        held = self.web / ".env.held"
        self.assertEqual((self.env if not self.env.is_symlink() else held).read_text(), self.ENV)

    def test_failed_to_keeps_failed_head_banned(self):
        # голова ветки уже не удалась, администратор переходит на хорошую версию — и to тоже не удался:
        # отметка остаётся, таймер упавшую голову снова не выкладывает
        bad = "sha256:" + "3" * 64
        tags = f"{self.REPO}:main={bad} {self.REPO}:{self.HASH}={self.NEW}"
        (self.states / "shop.failed-ref").write_text(f"{self.REPO}@{bad}\n")
        run, _ = self.deploy("to", self.HASH, STUB_FAIL_UP="1", STUB_TAGS=tags)
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertIn("не удалось на шаге «запуск»", run.stderr)
        self.assertEqual(self.state("failed-ref"), f"{self.REPO}@{bad}")
        self.log.unlink()
        run, lines = self.deploy(STUB_TAGS=tags)                   # таймер, через 15 секунд
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(self.state("current"), f"{self.REPO}@{self.OLD}")
        self.assertFalse([x for x in lines if not x.startswith("docker ") or x.startswith("docker run")], lines)

    def fs(self, *names):
        """Журнал файловых команд: строки этих команд по порядку"""
        return [x for x in self.fslog.read_text().splitlines() if x.split()[0] in names]

    def test_tmp_swapped_for_link_leaves_victim(self):
        # временный .env, созданный в web/, участник подменяет ссылкой на чужой файл: root не пишет в него
        # и не ставит ему владельца и права .env — временный файл в папке проекта, участнику туда не писать
        victim = victim_file(self.dir)
        participant_mktemp(self.bin, self.web, victim, swap="tmp")
        run, _ = self.deploy("to", self.HASH)
        self.assertEqual((victim.read_text(), victim.stat().st_mode & 0o777), ("victim\n", 0o600))
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertFalse(self.env.is_symlink())
        self.assertIn(f"\nDEPLOY_IMAGE={self.REPO}:{self.HASH}\n", self.env.read_text())
        self.assertEqual(self.env.stat().st_mode & 0o777, 0o640)
        self.assertEqual(self.leftovers(), ["compose.yml"])
        tmp = self.fs("mktemp")[0].split()[1]
        self.assertEqual(os.path.dirname(tmp), str(self.proj))
        # владелец, ACL и права — с .env на временный файл, затем ещё раз stat .env и mv
        st = self.env.stat()
        self.assertEqual(self.fs("chown", "setfacl", "chmod", "stat", "mv", "acl")[-6:],
                         [f"chown {st.st_uid}:{st.st_gid} {tmp}", f"setfacl --set-file=- {tmp}", "acl # file: .env",
                          f"chmod 640 {tmp}", "stat -c %i %u %g %a %F .env", f"mv {tmp} .env"])

    def test_env_swapped_before_mv_refused(self):
        # .env подменили ссылкой после чтения, до mv (крючок в setfacl): stat перед mv видит другой файл — отказ
        victim = victim_file(self.dir)
        run, _ = self.deploy("to", self.HASH, STUB_SWAP_ENV=str(self.env), STUB_SWAP_TO=str(victim))
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertIn(f"работает {self.REPO}:{self.HASH}, но .env не записан", run.stderr)
        self.assertEqual((victim.read_text(), victim.stat().st_mode & 0o777), ("victim\n", 0o600))
        self.assertTrue(self.env.is_symlink())
        self.assertEqual(self.leftovers(), ["compose.yml"])
        self.assertEqual(files_with(self.proj, "victim"), [])
        self.assertEqual(self.fs("mv"), ["mv compose.yml.new compose.yml"])     # .env не трогали

    def test_open_project_dir_refused(self):
        # в папку проекта пишет группа: временный .env туда не кладётся — отказ до выкладки, ничего не менял
        before = self.env.read_bytes()
        self.proj.chmod(0o770)
        run, lines = self.deploy("to", self.HASH)
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertIn("пишет не только root", run.stderr)
        self.assertIn("ничего не менял", run.stderr)
        self.assertEqual(self.env.read_bytes(), before)
        self.assertEqual(self.leftovers(), [])
        self.assertEqual(lines, [])

    def test_failed_to_marked_manual(self):
        # сбой ручного to — с пометкой в .failed (по ней health-check не отсылает к журналу таймера), сбой таймера — без
        self.deploy("to", self.HASH, STUB_FAIL_UP="1")
        self.assertRegex(self.state("failed"), rf"^\d{{4}}-\d\d-\d\d \d\d:\d\d вручную \(to {self.HASH}\), запуск: работает прежняя версия$")
        self.log.unlink()
        self.deploy(STUB_FAIL_UP="1", STUB_TAGS=f"{self.REPO}:main=sha256:{'3' * 64}")
        self.assertRegex(self.state("failed"), r"^\d{4}-\d\d-\d\d \d\d:\d\d запуск: работает прежняя версия$")


def victim_file(root):
    """Чужой файл (.env другого проекта, /etc/shadow): в папке 0700, права 0600, текст victim"""
    other = root / "other"
    other.mkdir(mode=0o700)
    victim = other / "secret"
    victim.write_text("victim\n")
    victim.chmod(0o600)
    return victim


def participant_mktemp(bin_dir, web, victim, swap):
    """mktemp с участником проекта, которому web/ открыта на запись: настоящий mktemp, путь — в журнал файловых
    команд; затем участник подменяет ссылкой на victim временный файл, если он создан в web/ (swap="tmp"),
    или сам .env (swap="env"); swap="env-back" — .env откладывает в .env.held, на его место ссылку (вернуть прежний
    файл до сверки stat — крючок STUB_RESTORE_ENV в chown)"""
    real = os.path.realpath(web)
    (bin_dir / "mktemp").write_text(f"""#!/bin/bash
f=$({shutil.which("mktemp")} "$@") || exit
echo "mktemp $f" >> "$STUB_FSLOG"
case {swap} in
  tmp) [ "$(cd "$(dirname "$f")" && pwd -P)" != "{real}" ] || {{ rm -f "$f" && ln -s "{victim}" "$f"; }} ;;
  env) rm -f "{web}/.env" && ln -s "{victim}" "{web}/.env" ;;
  env-back) {shutil.which("mv")} "{web}/.env" "{web}/.env.held" && ln -s "{victim}" "{web}/.env" ;;
esac
echo "$f"
""")
    (bin_dir / "mktemp").chmod(0o755)


def files_with(root, text):
    """Обычные файлы (не ссылки) под root, в которых есть text"""
    return [str(p) for p in root.rglob("*") if p.is_file() and not p.is_symlink() and text in p.read_text()]


class ProjectDbEnv(unittest.TestCase):
    """project-db-env <проект> [приставка]: строки DB_* в .env заменены, остальные на месте, владелец и права прежние;
    временный файл — в папке проекта, не в web/: подменённые ссылкой временный файл или .env не меняют чужой файл
    и не приносят его текст в .env. Стенд: скрипт с папкой проекта и secrets.yml во временной папке (пароль
    тестовый); docker и project-docker-host — заглушки, файловые команды — те же, что у ProjectDeployTo."""

    ENV = "DEBUG=False\nDB_HOST=192.0.2.1\nDB_PASSWORD=old\nDEV_DB_HOST=keep\nSITE_NAME=Магазин\n"
    DB = "DB_HOST=172.20.5.1\nDB_PORT=5432\nDB_NAME=shop\nDB_USER=shop\nDB_PASSWORD=pw-test\n"
    FILES = ("chown", "chmod", "stat", "dd", "mv", "getfacl", "setfacl")

    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.bin, self.proj = self.dir / "bin", self.dir / "proj"
        self.web = self.proj / "web"
        for d in (self.bin, self.proj, self.web):
            d.mkdir()
        stubs = {"project-docker-host": "#!/bin/sh\n", "docker": "#!/bin/sh\necho 172.20.5.1\n",
                 **{name: ProjectDeployTo.STUBS[name] for name in self.FILES}}
        for name, text in stubs.items():
            (self.bin / name).write_text(text)
            (self.bin / name).chmod(0o755)
        secrets = self.dir / "secrets.yml"
        secrets.write_text('db_password_shop: "pw-test"\n')
        script = (ROOT / "roles/project/files/project-db-env").read_text()
        for old, new in (("/srv/projects/$NAME", f'"{self.proj}"'), ("/etc/infra/secrets.yml", f'"{secrets}"')):
            if old not in script:
                raise AssertionError(f"в project-db-env нет «{old}» — стенду нечего подменить")
            script = script.replace(old, new)
        self.script = self.dir / "project-db-env"
        self.script.write_text(script)
        self.env = self.web / ".env"
        self.env.write_text(self.ENV)
        self.env.chmod(0o640)
        self.fslog = self.dir / "fslog"

    def db_env(self, *args, **stubs):
        env = {**os.environ, "PATH": f"{self.bin}:{os.environ['PATH']}", "STUB_FSLOG": str(self.fslog), **stubs}
        return subprocess.run(["bash", str(self.script), "shop", *args], env=env, capture_output=True, text=True)

    def leftovers(self):
        return sorted([p.name for p in self.web.iterdir() if p.name != ".env"] +
                      [f"../{p.name}" for p in self.proj.iterdir() if p.name != "web"])

    def assertVictimIntact(self, victim):
        self.assertEqual((victim.read_text(), victim.stat().st_mode & 0o777), ("victim\n", 0o600))
        self.assertEqual(files_with(self.proj, "victim"), [])

    def test_db_lines_replaced(self):
        run = self.db_env()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(self.env.read_text(), "DEBUG=False\nDEV_DB_HOST=keep\nSITE_NAME=Магазин\n" + self.DB)
        self.assertEqual(self.env.stat().st_mode & 0o777, 0o640)
        self.assertNotIn("pw-test", run.stdout + run.stderr)
        self.assertEqual(self.leftovers(), [])
        # ACL — с .env на временный файл в папке проекта, до chmod
        setfacl = self.fs("setfacl")
        self.assertEqual(len(setfacl), 1, setfacl)
        self.assertEqual(os.path.dirname(setfacl[0].split()[-1]), str(self.proj))
        self.assertEqual([x.split()[0] for x in self.fs("chown", "setfacl", "chmod", "mv")], ["chown", "setfacl", "chmod", "mv"])
        self.assertIn(f"acl # file: {self.env}", self.fslog.read_text().splitlines())
        run = self.db_env("DEV_")                                   # dev-проект: DEV_DB_*, DB_* не тронуты
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(self.env.read_text(), "DEBUG=False\nSITE_NAME=Магазин\n" + self.DB +
                         self.DB.replace("DB_", "DEV_DB_"))

    def fs(self, *names):
        return [x for x in self.fslog.read_text().splitlines() if x.split()[0] in names]

    def test_env_link_refused(self):
        victim = victim_file(self.dir)
        self.env.unlink()
        self.env.symlink_to(victim)
        run = self.db_env()
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertIn("ссылка", run.stderr)
        self.assertTrue(self.env.is_symlink())
        self.assertVictimIntact(victim)
        self.assertEqual(self.leftovers(), [])

    def test_tmp_swapped_for_link_leaves_victim(self):
        # временный файл, созданный в web/, участник подменяет ссылкой: root не пишет в чужой файл
        victim = victim_file(self.dir)
        participant_mktemp(self.bin, self.web, victim, swap="tmp")
        run = self.db_env()
        self.assertVictimIntact(victim)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertFalse(self.env.is_symlink())
        self.assertEqual(self.env.read_text(), "DEBUG=False\nDEV_DB_HOST=keep\nSITE_NAME=Магазин\n" + self.DB)
        self.assertEqual(self.leftovers(), [])

    def test_env_swapped_after_check_refused(self):
        # .env подменили ссылкой после проверки, перед чтением: dd с nofollow её не открывает — отказ,
        # текст чужого файла не попал ни в один файл
        victim = victim_file(self.dir)
        participant_mktemp(self.bin, self.web, victim, swap="env")
        run = self.db_env()
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertIn("меняли, пока root его переписывал", run.stderr)
        self.assertVictimIntact(victim)
        self.assertEqual(self.leftovers(), [])
        self.assertFalse(self.fs("mv"))

    def test_env_swapped_after_check_and_back_refused(self):
        # подменили ссылкой перед чтением, а прежний .env вернули до сверки stat (тот же inode — сверка не ловит):
        # отказ даёт только dd с nofollow; сбой dd не глотается — .env не остаётся с одними строками DB_*
        victim = victim_file(self.dir)
        participant_mktemp(self.bin, self.web, victim, swap="env-back")
        run = self.db_env(STUB_RESTORE_ENV=str(self.env))
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertIn("меняли, пока root его переписывал", run.stderr)
        self.assertVictimIntact(victim)
        self.assertFalse(self.fs("mv"))
        self.assertEqual([p.name for p in self.proj.iterdir() if p.name != "web"], [])    # временного .env.* нет
        held = self.web / ".env.held"
        self.assertEqual((self.env if not self.env.is_symlink() else held).read_text(), self.ENV)

    def test_env_swapped_before_mv_refused(self):
        # .env подменили ссылкой после чтения, до mv (крючок в setfacl): stat перед mv видит другой файл — отказ
        victim = victim_file(self.dir)
        run = self.db_env(STUB_SWAP_ENV=str(self.env), STUB_SWAP_TO=str(victim))
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertIn("меняли, пока root его переписывал", run.stderr)
        self.assertTrue(self.env.is_symlink())
        self.assertVictimIntact(victim)
        self.assertEqual(self.leftovers(), [])

    def test_open_project_dir_refused(self):
        self.proj.chmod(0o770)
        run = self.db_env()
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertIn("пишет не только root", run.stderr)
        self.assertEqual(self.env.read_text(), self.ENV)
        self.assertEqual(self.leftovers(), [])


if __name__ == "__main__":
    unittest.main()
