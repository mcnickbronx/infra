"""Проверки Python-кода репозитория без сервера: python3 -m unittest discover -s tests
(запускает tools/check.sh). Нужен только стандартный Python; для проверки подписи — git и ssh-keygen."""
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading
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


class CrowdsecAllowlist(unittest.TestCase):
    """roles/crowdsec/files/crowdsec-sync-allowlist: allowlist CrowdSec infra. Стенд — заглушка cscli с базой
    в JSON: вывод -o raw и поведение create/add/remove — как в cscli v1.8.1 (cmd/crowdsec-cli/cliallowlists/
    allowlists.go), флаги до «--» разбирает как cobra: неизвестный — ошибка, «-d» — описание."""

    DESC = "infra: admin_ips, people ips, server ips (roles/crowdsec)"
    INSPECT = ("name,description,value,comment,expiration,created_at,console_managed\n"
               f"infra,\"{DESC}\",203.0.113.5,,never,2026-10-24T03:00:00Z,false\n"
               f"infra,\"{DESC}\",198.51.100.0/29,,never,2026-10-24T03:00:00Z,false\n"
               f"infra,\"{DESC}\",203.0.113.9/32,руками,never,2026-10-24T03:00:00Z,false\n")
    CSCLI = """#!/usr/bin/env python3
import csv, json, os, sys
args = sys.argv[1:]
with open(os.environ["STUB_LOG"], "a") as f:
    f.write(json.dumps(args) + "\\n")
state = json.load(open(os.environ["STUB_STATE"]))
known = {"create": ("-o", "-d"), "add": ("-o", "-d", "-e")}.get(args[1] if len(args) > 1 else "", ("-o",))
pos, flags, rest = [], {}, iter(args)
for a in rest:
    if a == "--":
        pos += list(rest)
    elif a.startswith("-") and len(a) > 1:
        if a not in known:
            sys.exit(f"Error: unknown shorthand flag: {a!r}")
        flags[a] = next(rest, "")
    else:
        pos.append(a)
assert pos[0] == "allowlists", pos
cmd, name, values = pos[1], (pos[2:3] or [None])[0], pos[3:]
if cmd == os.environ.get("STUB_FAIL"):
    sys.exit("Error: LAPI is not reachable")
out = csv.writer(sys.stdout, lineterminator="\\n")
if cmd == "list":
    out.writerow(["name", "description", "created_at", "updated_at", "console_managed", "size"])
    for n, a in state.items():
        out.writerow([n, a["description"], "2026-10-24T03:00:00Z", "2026-10-24T03:00:00Z", "false", len(a["items"])])
elif name not in state and cmd != "create":
    sys.exit(f"Error: allowlist {name} not found")
elif cmd == "inspect":
    out.writerow(["name", "description", "value", "comment", "expiration", "created_at", "console_managed"])
    for v in state[name]["items"]:
        out.writerow([name, state[name]["description"], v, "", "never", "2026-10-24T03:00:00Z", "false"])
elif cmd == "create":
    if name in state or "-d" not in flags:
        sys.exit("Error: create")
    state[name] = {"description": flags["-d"], "items": []}
elif cmd in ("add", "remove"):
    if not values:
        sys.exit("Error: requires at least 2 arg(s)")
    items = state[name]["items"]
    if cmd == "add":
        new = [v for v in values if v not in items]
        items += new
        print(f"added {len(new)} values to allowlist {name}" if new else "no new values for allowlist")
    else:
        state[name]["items"] = [v for v in items if v not in values]
else:
    sys.exit(f"Error: {cmd}")
json.dump(state, open(os.environ["STUB_STATE"], "w"))
"""

    @classmethod
    def setUpClass(cls):
        # здесь, а не на уровне файла: нет скрипта — падает только этот класс
        cls.m = load("crowdsec_sync_allowlist", "roles/crowdsec/files/crowdsec-sync-allowlist")

    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        (self.dir / "bin").mkdir()
        stub = self.dir / "bin/cscli"
        stub.write_text(self.CSCLI)
        stub.chmod(0o755)
        self.log, self.state_file, self.json = self.dir / "log", self.dir / "state.json", self.dir / "allowlist.json"
        self.mark = self.dir / "executed"
        self.env = {**os.environ, "PATH": f"{self.dir / 'bin'}:{os.environ['PATH']}",
                    "STUB_LOG": str(self.log), "STUB_STATE": str(self.state_file)}

    def sync(self, ips, state, *opts):
        self.json.write_text(json.dumps(ips))
        if state is not None:
            self.state_file.write_text(json.dumps(state))
        self.log.unlink(missing_ok=True)
        run = subprocess.run([sys.executable, "-I", str(ROOT / "roles/crowdsec/files/crowdsec-sync-allowlist"),
                              *opts, str(self.json)], env=self.env, cwd=self.dir, capture_output=True, text=True)
        calls = [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []
        return run, calls, json.loads(self.state_file.read_text())

    def test_norm(self):
        self.assertEqual(self.m.norm("203.0.113.5/32"), "203.0.113.5")
        self.assertEqual(self.m.norm("198.51.100.7/29"), "198.51.100.0/29")
        self.assertEqual(self.m.norm("2001:DB8::10/128"), "2001:db8::10")

    def test_existing_keeps_stored_value(self):
        # remove в cscli ищет запись точным совпадением строки — удалять надо тем, что хранится
        self.assertEqual(self.m.existing(self.INSPECT), [
            ("203.0.113.5", "203.0.113.5"), ("198.51.100.0/29", "198.51.100.0/29"), ("203.0.113.9", "203.0.113.9/32")])
        self.assertEqual(self.m.lists("name,description,created_at,updated_at,console_managed,size\n"
                                      "infra,x,2026-10-24T03:00:00Z,2026-10-24T03:00:00Z,false,3\n"), {"infra"})

    def test_plan(self):
        found = self.m.existing(self.INSPECT)
        desired = {self.m.norm(a) for a in ["203.0.113.5/32", "198.51.100.7/29", "203.0.113.9"]}
        self.assertEqual(self.m.plan(desired, found), ([], []))
        desired = {"203.0.113.5", "192.0.2.1"}
        self.assertEqual(self.m.plan(desired, found), (["192.0.2.1"], ["198.51.100.0/29", "203.0.113.9/32"]))
        # тот же адрес второй записью — лишний; значение с запятой и переводом строки CSV не ломает
        self.assertEqual(self.m.existing('name,description,value,comment,expiration,created_at,console_managed\n'
                                         'infra,"a, b","x\ny",,never,2026-10-24T03:00:00Z,false\n'), [("x\ny", "x\ny")])
        self.assertEqual(self.m.plan({"203.0.113.5"}, found + [("203.0.113.5", "203.0.113.5/32")]),
                         ([], ["198.51.100.0/29", "203.0.113.5/32", "203.0.113.9/32"]))

    def test_creates_then_nothing_to_do_and_own_allowlist_untouched(self):
        mine = {"description": "своё", "items": ["192.0.2.200", "203.0.113.5"]}
        ips = ["192.0.2.10", "198.51.100.7/29", "2001:db8::10", "192.0.2.1"]
        run, calls, state = self.sync(ips, {"mine": mine})
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout.splitlines()[-1], "CHANGED")
        self.assertEqual(calls, [["allowlists", "list", "-o", "raw"],
                                 ["allowlists", "create", "infra", "-d", self.DESC],
                                 ["allowlists", "add", "infra", "--",
                                  "192.0.2.1", "192.0.2.10", "198.51.100.0/29", "2001:db8::10"]])
        run, calls, state2 = self.sync(ips, None)
        self.assertEqual((run.returncode, run.stdout), (0, "OK\n"), run.stderr)
        self.assertEqual([c[1] for c in calls], ["list", "inspect"])
        self.assertEqual(state2, state)
        self.assertEqual(state["mine"], mine)

    def test_extra_removed_by_stored_value_missing_added(self):
        state = {"infra": {"description": self.DESC, "items": ["203.0.113.5", "203.0.113.9/32", "198.51.100.0/29"]},
                 "mine": {"description": "своё", "items": ["203.0.113.9"]}}
        run, calls, state = self.sync(["203.0.113.5", "192.0.2.1", "198.51.100.0/29"], state)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout, "+ 192.0.2.1\n- 203.0.113.9/32\nCHANGED\n")
        self.assertEqual(calls[2:], [["allowlists", "add", "infra", "--", "192.0.2.1"],
                                     ["allowlists", "remove", "infra", "--", "203.0.113.9/32"]])
        self.assertEqual(state["infra"]["items"], ["203.0.113.5", "198.51.100.0/29", "192.0.2.1"])
        self.assertEqual(state["mine"]["items"], ["203.0.113.9"])

    def test_check_changes_nothing(self):
        before = {"infra": {"description": self.DESC, "items": ["203.0.113.5", "203.0.113.9"]}}
        run, calls, state = self.sync(["203.0.113.5", "192.0.2.1"], before, "--check")
        self.assertEqual((run.returncode, run.stdout), (1, "+ 192.0.2.1\n- 203.0.113.9\nCHANGED\n"), run.stderr)
        self.assertEqual([c[1] for c in calls], ["list", "inspect"])
        self.assertEqual(state, before)
        run, calls, state = self.sync(["203.0.113.5"], {}, "--check")       # списка нет — не создаёт
        self.assertEqual((run.returncode, run.stdout), (1, "+ allowlist infra\n+ 203.0.113.5\nCHANGED\n"))
        self.assertEqual((calls, state), ([["allowlists", "list", "-o", "raw"]], {}))

    def test_cscli_error_stops_with_its_message(self):
        # LAPI ещё не поднялся (inspect и list идут через него) — код 1 и сообщение cscli, ничего не меняется
        before = {"infra": {"description": self.DESC, "items": ["203.0.113.9"]}}
        self.env["STUB_FAIL"] = "inspect"
        run, calls, state = self.sync(["203.0.113.5"], before)
        self.assertEqual(run.returncode, 1)
        self.assertIn("cscli allowlists inspect: код 1: Error: LAPI is not reachable", run.stderr)
        self.assertEqual(([c[1] for c in calls], state), (["list", "inspect"], before))

    def test_hostile_address_in_json_never_reaches_cscli(self):
        # адреса из server.yml идут в команды root: не адрес — ошибка до первого вызова cscli
        for bad in (f"192.0.2.1; touch {self.mark}", f"$(touch {self.mark})", "192.0.2.1 192.0.2.2",
                    f"192.0.2.1\ntouch {self.mark}", "-d", "--help", "192.0.2.1/33"):
            with self.subTest(bad=bad):
                before = {"infra": {"description": self.DESC, "items": ["203.0.113.5"]}}
                run, calls, state = self.sync(["203.0.113.5", bad], before)
                self.assertNotEqual(run.returncode, 0)
                self.assertIn("ValueError", run.stderr)
                self.assertEqual((calls, state), ([], before))
                self.assertFalse(self.mark.exists())

    def test_hostile_value_in_allowlist_removed_as_value(self):
        # запись, добавленная в infra руками, с «-флагом», $(…), «;» и переводом строки — значение, а не флаг
        # и не команда: без «--» заглушка, как cobra, приняла бы «-e» за флаг
        bad = ["-e", f"$(touch {self.mark})", "203.0.113.7;id", "x\ny"]
        self.state_file.write_text(json.dumps({"infra": {"description": self.DESC, "items": ["203.0.113.5", *bad]}}))
        no_dash = subprocess.run([str(self.dir / "bin/cscli"), "allowlists", "remove", "infra", "-e"],
                                 env=self.env, capture_output=True, text=True)
        self.assertIn("unknown shorthand flag: '-e'", no_dash.stderr)
        run, calls, state = self.sync(["203.0.113.5"], None)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(calls[-1], ["allowlists", "remove", "infra", "--", *sorted(bad)])
        self.assertEqual(state["infra"]["items"], ["203.0.113.5"])
        self.assertIn("- 'x\\ny'\n", run.stdout)
        self.assertFalse(self.mark.exists())
        run, _, _ = self.sync(["203.0.113.5"], None)
        self.assertEqual(run.stdout, "OK\n")


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


class TraefikAccessLog(unittest.TestCase):
    """roles/traefik: traefik.yml (эталон tests/golden) — журнал запросов, по которому банит CrowdSec."""

    def test_client_username_dropped(self):
        # Имя пользователя из адреса Traefik пишет как есть, %0a в нём — перевод строки: без drop запрос
        # GET http://a%0a<строка журнала>%0ab@сайт/ дописывает в access.log строку с любым IP, кодом и роутером
        lines = (ROOT / "tests/golden/full/traefik/traefik.yml").read_text().split("\n")
        block = []
        for line in lines[lines.index("accessLog:") + 1:]:
            if line and not line.startswith(" "):
                break
            if line.strip() and not line.lstrip().startswith("#"):
                block.append(line)
        self.assertIn("  fields:\n    names:\n      ClientUsername: drop", "\n".join(block))


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

    # DNS сервера (check_dns): getent разрешает только имена из STUB_DNS_OK (остальные — код 2, как настоящий),
    # timeout — без ожидания; оба пишут вызовы в журнал
    DNS_NAMES = ["acme-v02.api.letsencrypt.org", "registry-1.docker.io", "api.telegram.org"]
    TIMEOUT = '#!/bin/bash\nprintf "timeout %s\\n" "$*" >> "$STUB_DNS_LOG"\nshift\nexec "$@"\n'
    GETENT = """#!/bin/bash
printf 'getent %s\\n' "$*" >> "$STUB_DNS_LOG"
case " $STUB_DNS_OK " in *" $2 "*) exit 0 ;; esac
exit 2
"""

    def check_dns(self, ok):
        for name, text in (("timeout", self.TIMEOUT), ("getent", self.GETENT)):
            (self.dir / name).write_text(text)
            (self.dir / name).chmod(0o755)
        log = self.dir / "dns.log"
        out = self.run_checks("", "check_dns", 'render "$PROBLEMS"', STUB_DNS_OK=ok, STUB_DNS_LOG=str(log))
        return out, log.read_text().splitlines()

    def test_dns_down_is_one_problem(self):
        out, calls = self.check_dns("")
        self.assertEqual(out.count("• "), 1)
        self.assertIn("• DNS сервера не отвечает: не разрешается ни одно из имён", out)
        self.assertIn("dns_servers в server.yml", out)
        self.assertEqual([c for c in calls if c.startswith("getent ")], [f"getent ahosts {n}" for n in self.DNS_NAMES])
        self.assertEqual([c for c in calls if c.startswith("timeout ")], [f"timeout 5 getent ahosts {n}" for n in self.DNS_NAMES])
        self.assertIn("\ncheck_failed_units\ncheck_dns\n", self.SCRIPT.read_text())     # в списке проверок

    def test_dns_one_name_is_enough(self):
        out, calls = self.check_dns(self.DNS_NAMES[-1])
        self.assertEqual(out, "")
        self.assertEqual(len([c for c in calls if c.startswith("getent ")]), 3)

    def test_dns_stops_at_first_resolved(self):
        out, calls = self.check_dns(self.DNS_NAMES[0])
        self.assertEqual(out, "")
        self.assertEqual([c for c in calls if c.startswith("getent ")], [f"getent ahosts {self.DNS_NAMES[0]}"])

    # Страницы другого сервера (watch_sites, check_watch_sites): в эталоне — из tests/inventory/host_vars/full.yml
    WATCHED = ["https://shop.other.test/", "https://back.shop.other.test/api/health"]

    def watch(self, *calls, **stubs):
        return self.run_checks("", *calls, **stubs)

    def test_watch_answering_is_fine(self):
        # 404 и 301 — сервер отвечает: это проверка сервера, а не приложения
        out = self.watch("check_watch_sites", 'render "$PROBLEMS"',
                         STUB_SITES="shop.other.test=404 back.shop.other.test=301")
        self.assertEqual(out, "")
        self.assertFalse((self.dir / "sleep.log").exists())
        self.assertEqual(sorted(c.split()[-1] for c in self.curls()), sorted(self.WATCHED))   # по разу, ровно эти адреса
        for call in self.curls():
            self.assertNotIn("--resolve", call)            # обычный DNS, как у посетителя: не на свой IP
            self.assertIn("--noproxy * ", call)
            self.assertIn(" -m 15 ", call)
            self.assertNotIn("-L", call.split())

    def test_watch_down_twice_is_one_problem(self):
        out = self.watch("check_watch_sites", 'render "$PROBLEMS"',
                         STUB_SITES="shop.other.test=503 back.shop.other.test=000")
        self.assertEqual(out.count("• "), 1)
        self.assertIn("• Сайты другого сервера не отвечают (проверка с full): "
                      "https://back.shop.other.test/api/health https://shop.other.test/\n", out)
        self.assertIn("https://back.shop.other.test/api/health — нет ответа за 15 с", out)
        self.assertIn("https://shop.other.test/ — 503", out)
        self.assertIn("его сводка не придёт", out)
        self.assertEqual((self.dir / "sleep.log").read_text(), "30\n")   # одна пауза на все повторы
        self.assertEqual(len(self.curls()), 4)

    def test_watch_retry_brings_up(self):
        # упал один раз, через 30 с ответил — мигание сети, не тревога; повторяется только упавший
        out = self.watch("check_watch_sites", 'render "$PROBLEMS"', STUB_SITES="back.shop.other.test=502,200")
        self.assertEqual(out, "")
        self.assertEqual((self.dir / "sleep.log").read_text(), "30\n")
        self.assertEqual(sorted(c.split()[-1] for c in self.curls()), sorted(self.WATCHED + [self.WATCHED[1]]))

    def test_watch_notified_once_then_resolved_once(self):
        self.watch("check_watch_sites", "notify_changes", STUB_SITES="shop.other.test=000")
        self.watch("check_watch_sites", "notify_changes", STUB_SITES="shop.other.test=000")   # через 10 минут — молчит
        self.assertEqual(len(self.messages()), 1)
        self.assertIn("— новое:", self.messages()[0])
        self.assertIn("Сайты другого сервера не отвечают (проверка с full): https://shop.other.test/", self.messages()[0])
        self.watch("check_watch_sites", "notify_changes")                  # ответил — «прошло» не сразу
        self.assertEqual(len(self.messages()), 1)
        self.watch("check_watch_sites", "notify_changes", resolve=0)
        self.assertEqual(len(self.messages()), 2)
        self.assertIn("— прошло:", self.messages()[1])
        self.assertIn("Сайты другого сервера не отвечают", self.messages()[1])

    def test_watch_empty_list_no_requests(self):
        self.assertEqual(self.watch("WATCH_SITES=()", "check_watch_sites", 'render "$PROBLEMS"',
                                    STUB_SITES="shop.other.test=000"), "")
        self.assertEqual(self.curls(), [])
        self.assertFalse((self.dir / "sleep.log").exists())

    def test_watch_skipped_when_own_dns_down(self):
        # свой DNS не отвечает (настоящий check_dns) — тревога о чужом сервере была бы ложной
        for name, text in (("timeout", self.TIMEOUT), ("getent", self.GETENT)):
            (self.dir / name).write_text(text)
            (self.dir / name).chmod(0o755)
        out = self.watch("check_dns", "check_watch_sites", 'render "$PROBLEMS"', STUB_DNS_OK="",
                         STUB_DNS_LOG=str(self.dir / "dns.log"), STUB_SITES="shop.other.test=000")
        self.assertEqual(out.count("• "), 1)
        self.assertIn("• DNS сервера не отвечает", out)
        self.assertEqual(self.curls(), [])

    def test_watch_time_is_bounded(self):
        # 10 адресов «висят» (заглушка curl ждёт 1 с): все разом, а не по одному — 20 с и больше
        urls = [f"https://w{i}.other.test/" for i in range(10)]
        start = time.monotonic()
        out = self.watch(f"WATCH_SITES=({' '.join(urls)})", "check_watch_sites", 'render "$PROBLEMS"', STUB_HANG="1",
                         STUB_SITES=" ".join(f"w{i}.other.test=000" for i in range(10)))
        self.assertLess(time.monotonic() - start, 8)
        self.assertIn("Сайты другого сервера не отвечают (проверка с full): " + " ".join(sorted(urls)) + "\n", out)
        self.assertEqual(len(self.curls()), 20)
        self.assertIn("\ncheck_sites\ncheck_watch_sites\n", self.SCRIPT.read_text())   # в списке проверок, после check_dns

    # ---------- Ошибки сайтов за сутки (--summary): журнал запросов Traefik ----------
    # Роутеры сервера — из labels: luk-app и med-www у здоровых контейнеров, med-api — у больного (его ошибки тоже видны)
    ROUTER_LABELS = ("traefik.enable=true,traefik.http.routers.luk-app.rule=Host(`luk.example.com`),"
                     "traefik.http.routers.luk-app.entrypoints=websecure\n"
                     "traefik.http.routers.med-www.rule=Host(`med.example.com`)\n")
    SICK_ROUTER_LABELS = "traefik.http.routers.med-api.rule=Host(`back.med.example.com`)\n"
    T = "24/Oct/2026:08:00:00"
    # summary на Маке: GNU date -d, df --output и nproc — заглушки; остальные date — настоящие
    DATE = """#!/bin/bash
if [ "$*" = "-u -d 24 hours ago +%Y%m%d%H%M%S" ]; then echo 20261024000000; else exec /bin/date "$@"; fi
"""

    @staticmethod
    def access(when, code, router, request="GET /a HTTP/1.1"):
        """Строка журнала, как пишет Traefik 3.7.15 (общий формат без fields: Referer и User-Agent — "-")."""
        return f'192.0.2.7 - - [{when} +0000] "{request}" {code} 11 "-" "-" 7 "{router}" "http://172.18.0.5:80" 0ms\n'

    def site_errors(self, old=None, new=None, call="site_errors 20261024000000 || echo absent", **stubs):
        """access.log.1 (old) и access.log (new) — в новой папке журнала; None — файла нет."""
        logs = pathlib.Path(tempfile.mkdtemp(dir=self.dir))
        for name, text in (("access.log.1", old), ("access.log", new)):
            if text is not None:
                (logs / name).write_bytes(text if isinstance(text, bytes) else text.encode())
        for name, text in (("date", self.DATE), ("df", "#!/bin/bash\necho Mounted Use%; echo / 42%\n"),
                           ("nproc", "#!/bin/bash\necho 2\n")):
            (self.dir / name).write_text(text)
            (self.dir / name).chmod(0o755)
        stubs = {"STUB_LABELS": self.ROUTER_LABELS, "STUB_SICK_LABELS": self.SICK_ROUTER_LABELS, **stubs}
        return self.run_checks("", call, HEALTH_TRAEFIK_LOGS=str(logs), **stubs)

    def test_site_errors_counted_by_own_router(self):
        a = self.access
        old = (a("23/Oct/2026:23:59:59", 502, "luk-app@docker")              # раньше отсечки — мимо
               + a("24/Oct/2026:00:00:00", 502, "luk-app@docker")
               + a("24/Oct/2026:01:10:00", 500, "med-api@file")               # больной контейнер, проект без root
               + a("24/Oct/2026:01:10:01", 200, "med-www@docker"))
        new = (a("24/Oct/2026:08:00:00", 502, "luk-app@docker")
               + a("24/Oct/2026:08:00:01", 504, "luk-app@docker")
               + a("24/Oct/2026:08:00:02", 500, "med-api@file")
               + a("24/Oct/2026:08:00:03", 404, "med-www@docker")
               + a("24/Oct/2026:08:00:04", 404, "-")                          # запрос без роутера
               # путь от посетителя (HTTP/2 — с пробелами): подделка кода и роутера в нём — мимо, хвост Traefik — luk-app 502
               + a("24/Oct/2026:08:00:05", 502, "luk-app@docker", 'GET /a?q=" 503 1 "-" "-" 1 "evil@docker" "x" 0ms HTTP/2.0')
               + a("24/Oct/2026:08:00:06", 500, "ghost@docker")               # роутера нет в labels сервера — мимо
               + '192.0.2.7 - - [24/Oct/2026:08:00:07 +0000] "GET /x HTTP/1.1" 502 11 "-" "-" 9 "luk-a')   # обрезана
        self.assertEqual(self.site_errors(old, new), "luk-app: 502 — 3, 504 — 1; med-api: 500 — 2\n")
        self.assertEqual(self.site_errors(old), "luk-app: 502 — 1; med-api: 500 — 1\n")      # только вчерашний файл

    def test_site_errors_none_absent_or_unknown_format(self):
        ok = self.access(self.T, 200, "luk-app@docker") + self.access(self.T, 404, "med-www@docker")
        self.assertEqual(self.site_errors(new=ok), "нет\n")
        self.assertEqual(self.site_errors("", ""), "нет\n")                                 # пустые файлы
        self.assertEqual(self.site_errors(), "absent\n")                                    # журнала нет: пусто и код 1
        self.assertEqual(self.site_errors(new=self.access(self.T, 502, "luk-app@docker"), STUB_LABELS="",
                                          STUB_SICK_LABELS=""), "нет\n")                    # Docker пуст: своих роутеров нет
        json = '{"RouterName":"luk-app@docker","DownstreamStatus":502,"StartUTC":"2026-10-24T08:00:00Z"}\n'
        self.assertRegex(self.site_errors(new=json * 3), r"^журнал не разобран \(сменился формат Traefik\?\) — "
                                                         r"sudo tail .*/access\.log\n$")

    def test_site_errors_top_five(self):
        labels = "".join(f"traefik.http.routers.r{i}.rule=Host(`r{i}.example.com`)\n" for i in range(1, 7))
        new = "".join(self.access(self.T, 500 + i % 2 * 3, f"r{i}@docker") * i for i in range(1, 7))
        self.assertEqual(self.site_errors(new=new, STUB_LABELS=labels),
                         "r6: 500 — 6; r5: 503 — 5; r4: 500 — 4; r3: 503 — 3; r2: 500 — 2\n")

    def test_site_errors_future_lines_skipped(self):
        # Строка со временем из будущего (своя или чужая) считалась бы в каждой сводке, пока файл не уйдёт ротацией:
        # до верхней границы — в счёт, позже — мимо; сводка ставит границу «сейчас + 5 минут»
        a = self.access
        new = (a("24/Oct/2026:09:05:00", 502, "luk-app@docker")              # ровно граница — в счёт
               + a("24/Oct/2026:09:05:01", 504, "luk-app@docker")            # на секунду позже — мимо
               + a("01/Jan/2099:00:00:00", 500, "med-www@docker") * 3)
        self.assertEqual(self.site_errors(new=new, call="site_errors 20261024000000 20261024090500"),
                         "luk-app: 502 — 1\n")
        self.DATE = """#!/bin/bash
case "$*" in
  "-u -d 24 hours ago +%Y%m%d%H%M%S") echo 20261024000000 ;;
  "-u -d 5 minutes +%Y%m%d%H%M%S") echo 20261024090500 ;;
  *) exec /bin/date "$@" ;;
esac
"""
        self.site_errors(new=new, call="summary")
        [msg] = self.messages()
        self.assertIn("\nОшибки сайтов за сутки (5xx): luk-app: 502 — 1\nБэкап: ", msg)

    def test_site_errors_hostile_journal(self):
        # Журнал пишет Traefik по запросам посетителей: кавычки, $(…), обратные кавычки, перевод строки, огромная строка,
        # байты не UTF-8 и битый JSON не исполняются и не ломают счёт; в сообщение — только имена своих роутеров и числа
        a, mark = self.access, self.dir / "pwned"
        cmd = f"$(touch {mark})`touch {mark}`;touch {mark}"
        journal = (a(self.T, 502, "luk-app@docker", f'GET /{cmd}"\'$IFS HTTP/1.1').encode()     # свой роутер — в счёт
                   + a(self.T, 502, f"{cmd}@docker").encode()                                  # не свой — мимо
                   + a(self.T, 500, "evil.example.com@docker").encode()
                   + b'garbage "quoted" [24/Oct/2026:08:00:00 +0000] "\n'
                   + b'{"RouterName":"luk-app@docker","DownstreamStatus":502,\n'                 # битый JSON
                   + a(self.T, 502, "luk-app@docker", "GET /" + "A" * 3_000_000 + " HTTP/1.1").encode()   # 3 МБ
                   + b'192.0.2.7 - - [24/Oct/2026:08:00:00 +0000] "GET /a\n'                     # строка, разорванная
                   + b'b HTTP/1.1" 502 11 "-" "-" 7 "luk-app@docker" "http://172.18.0.5:80" 0ms\n'   # переводом строки
                   + b"\xff\xfe\x00\x1b[31m" + a(self.T, 502, "med-www@docker").encode()       # мусор в начале — мимо
                   + a(self.T, 503, "med-www@docker", "GET /\xff\xfe‮ HTTP/1.1").encode("utf-8", "surrogateescape")
                   + b"\x00" * 1000 + b"\n")
        start = time.monotonic()
        self.assertEqual(self.site_errors(new=journal), "luk-app: 502 — 2; med-www: 503 — 1\n")
        self.site_errors(new=journal, call="summary")
        self.assertLess(time.monotonic() - start, 20)
        self.assertFalse(mark.exists())
        [msg] = self.messages()
        self.assertIn("\nНагрузка: ", msg)
        self.assertRegex(msg, r"\nНагрузка: [^\n]*\nОшибки сайтов за сутки \(5xx\): luk-app: 502 — 2; med-www: 503 — 1\n"
                              r"Бэкап: ")
        for bad in ("touch", "pwned", "evil", "192.0.2.7", "AAAA", "GET", "/a", "http", "@", '"', "$", "`"):
            self.assertNotIn(bad, msg)

    def test_summary_without_journal_has_no_errors_line(self):
        self.site_errors(call="summary")
        [msg] = self.messages()
        self.assertNotIn("Ошибки сайтов", msg)
        self.assertRegex(msg, r"\nНагрузка: [^\n]*\nБэкап: ")
        self.assertIn("\n  collect_sites\n  collect_routers\ndone\n", self.SCRIPT.read_text())   # роутеры — с каждого Docker

    # ---------- Баны CrowdSec за сутки (--summary): cscli alerts list -o json ----------
    # cscli: аргументы — в STUB_CSCLI_LOG, ответ — файл STUB_ALERTS, код — STUB_CSCLI_RC; timeout (GNU timeout на Маке нет) —
    # аргументы в STUB_TIMEOUT_LOG и команда без ограничения
    CSCLI = '#!/bin/bash\nprintf "%s\\n" "$*" >> "$STUB_CSCLI_LOG"\ncat "$STUB_ALERTS"\nexit "$STUB_CSCLI_RC"\n'
    CSCLI_TIMEOUT = '#!/bin/bash\nprintf "%s\\n" "$*" >> "$STUB_TIMEOUT_LOG"\nshift\nexec "$@"\n'
    MANUAL = "manual 'ban' from 'localhost'"        # имя сценария у ручного бана: cscli decisions add --ip …

    @staticmethod
    def alert(ip, scenario="crowdsecurity/http-probing", decision="ban", simulated=False, events=1):
        """Тревога, как в cscli alerts list -o json (CrowdSec v1.8.1, pkg/models/alert.go); decision=None — без решения."""
        return {"id": 1, "scenario": scenario, "message": f"Ip {ip} performed '{scenario}'", "events_count": events,
                "capacity": 5, "source": {"scope": "Ip", "value": ip, "ip": ip, "cn": "NL", "as_name": "EXAMPLE"},
                "decisions": [] if decision is None else [
                    {"duration": "3h59m", "origin": "crowdsec", "scenario": scenario, "scope": "Ip", "type": decision,
                     "value": ip}],
                "simulated": simulated, "created_at": "2026-10-24T06:00:00Z",
                "events": [{"meta": [{"key": "http_path", "value": "/.env"}]}] * events}

    def bans(self, alerts, rc=0, cscli=True, call="summary", journal=None):
        """Сводка с заглушкой cscli: alerts — список тревог (в JSON) или ответ как есть; cscli=False — cscli нет.
        Вернёт сообщение сводки (для другого call — его вывод)."""
        answer = self.dir / "alerts.json"
        answer.write_text(alerts if isinstance(alerts, str) else json.dumps(alerts))
        for name, text in (("timeout", self.CSCLI_TIMEOUT), ("cscli", self.CSCLI)):
            (self.dir / name).write_text(text)
            (self.dir / name).chmod(0o755)
        if not cscli:
            (self.dir / "cscli").unlink()
        self.sent.unlink(missing_ok=True)
        out = self.site_errors(new=journal, call=call, STUB_ALERTS=str(answer), STUB_CSCLI_RC=str(rc),
                               STUB_CSCLI_LOG=str(self.dir / "cscli.log"), STUB_TIMEOUT_LOG=str(self.dir / "timeout.log"))
        if call != "summary":
            return out
        [msg] = self.messages()
        return msg

    def test_crowdsec_bans_counted_by_scenario(self):
        a = self.alert
        alerts = [a("198.51.100.10"), a("198.51.100.10"),                   # один адрес — две тревоги: один адрес
                  a("198.51.100.11"),
                  a("198.51.100.12", "crowdsecurity/http-sensitive-files", simulated=True),   # simulated — мимо
                  a("198.51.100.13", "crowdsecurity/http-bad-user-agent", decision="captcha"),  # не бан — мимо
                  a("198.51.100.14", self.MANUAL)]                          # ручной бан — «другие»
        line = "Баны CrowdSec за сутки: 3 адреса — http-probing 2, другие 1"
        msg = self.bans(alerts)
        self.assertRegex(msg, r"\nНагрузка: [^\n]*\n" + line + "\nБэкап: ")
        msg = self.bans(alerts, journal=self.access(self.T, 502, "luk-app@docker"))
        self.assertIn("\nОшибки сайтов за сутки (5xx): luk-app: 502 — 1\n" + line + "\nБэкап: ", msg)
        for bad in ("198.51.100", "crowdsecurity", "manual", "localhost", "'", "sensitive", "bad-user-agent"):
            self.assertNotIn(bad, msg)

    def test_crowdsec_no_bans(self):
        self.assertIn("\nБаны CrowdSec за сутки: нет\nБэкап: ", self.bans([]))
        only_skipped = [self.alert("198.51.100.1", simulated=True), self.alert("198.51.100.2", decision="captcha"),
                        self.alert("198.51.100.3", decision=None)]
        self.assertIn("\nБаны CrowdSec за сутки: нет\nБэкап: ", self.bans(only_skipped))

    def test_crowdsec_failed_no_line(self):
        def rest(msg):          # сводка без строки «Нагрузка» (память и нагрузка меняются между прогонами)
            return "\n".join(s for s in msg.split("\n") if not s.startswith("Нагрузка: "))
        journal = self.access(self.T, 502, "luk-app@docker")
        good = self.bans([self.alert("198.51.100.1")], journal=journal)
        self.assertIn("\nБаны CrowdSec за сутки: 1 адрес — http-probing 1\n", good)
        expected = rest(good).replace("\nБаны CrowdSec за сутки: 1 адрес — http-probing 1", "")
        for case, kwargs in (("код 1", {"alerts": [self.alert("198.51.100.1")], "rc": 1}),
                             ("не JSON", {"alerts": "level=fatal msg=\"unable to list alerts\"\n"}),
                             ("пустой ответ", {"alerts": ""}),
                             ("не список", {"alerts": '{"message": "no alerts"}'}),
                             ("нет cscli", {"alerts": [], "cscli": False})):    # заглушки нет: на Маке и в CI cscli нет
            with self.subTest(case):
                msg = self.bans(journal=journal, **kwargs)
                self.assertNotIn("CrowdSec", msg)
                self.assertEqual(rest(msg), expected)

    def test_crowdsec_bans_call(self):
        self.bans([])
        self.assertEqual((self.dir / "timeout.log").read_text(), "20 cscli alerts list --since 24h -l 0 -o json\n")
        self.assertEqual((self.dir / "cscli.log").read_text(), "alerts list --since 24h -l 0 -o json\n")   # без -a
        # каждые 10 минут (--notify) cscli не зовётся: crowdsec_bans — только объявлена и вызвана в summary
        script = self.SCRIPT.read_text()
        self.assertEqual(script.count("crowdsec_bans"), 2)
        self.assertIn("\ncrowdsec_bans() {\n", script)
        self.assertIn("\n  bans=$(crowdsec_bans) && ", script.partition("\nsummary() {")[2].partition("\n}\n")[0])

    def test_crowdsec_top_four_and_crawl(self):
        a, n, mark = self.alert, iter(range(1, 255)), self.dir / "pwned"
        def many(scenario, count):
            return [a(f"198.51.100.{next(n)}", f"crowdsecurity/{scenario}") for _ in range(count)]
        alerts = (many("http-probing", 6) + many("http-sensitive-files", 5) + many("http-bad-user-agent", 4)
                  + many("ssh-bf", 3) + many("ssh-slow-bf", 2) + many("http-crawl-non_statics", 1)
                  + [a("198.51.100.1", "crowdsecurity/ssh-bf")])       # адрес из http-probing: в общем числе — один раз
        self.assertIn("\nБаны CrowdSec за сутки: 21 адрес — http-probing 6, http-sensitive-files 5, http-bad-user-agent 4, "
                      "ssh-bf 4, http-crawl-non_statics 1\n", self.bans(alerts))    # ssh-slow-bf 2 — шестой, не виден
        # http-crawl-non_statics среди четырёх — не повторяется; разные ручные причины, имя с $(…) и переводом строки, имени нет —
        # одни «другие»; адрес с $(…) — один из адресов, не исполняется
        alerts = (many("http-crawl-non_statics", 3) + many("http-probing", 2) + many("ssh-bf", 1)
                  + [a("203.0.113.1", self.MANUAL), a("203.0.113.2", "manual 'ban' from 'admin'"),
                     a("203.0.113.3", f"crowdsecurity/x\n$(touch {mark})`touch {mark}`;"), a(f"$(touch {mark})", None),
                     a("203.0.113.5", "LePresidente/http-generic-401-bf")])          # чужой автор — с его именем
        self.assertEqual(self.bans(alerts, call="crowdsec_bans"),
                         "11 адресов — другие 4, http-crawl-non_statics 3, http-probing 2, LePresidente/http-generic-401-bf 1\n")
        self.assertFalse(mark.exists())
        for count, word in ((1, "адрес"), (2, "адреса"), (5, "адресов"), (11, "адресов"), (12, "адресов"), (21, "адрес"),
                            (22, "адреса")):
            with self.subTest(count):
                self.assertEqual(self.bans([a(f"192.0.2.{i}") for i in range(count)], call="crowdsec_bans"),
                                 f"{count} {word} — http-probing {count}\n")

    def test_crowdsec_300_alerts_fast(self):
        # по образцу ответа на 300 тревог (CrowdSec v1.8.1): у каждой 10 событий, каждая 50-я — simulated без решения
        names = ["http-probing", "http-sensitive-files", "http-bad-user-agent", "http-crawl-non_statics", "ssh-bf"]
        alerts = [self.alert(f"198.51.100.{i % 120}", f"crowdsecurity/{names[i % 5]}", events=10,
                             **({"decision": None, "simulated": True} if i % 50 == 0 else {})) for i in range(300)]
        total = len({x["source"]["value"] for x in alerts if not x["simulated"]})
        start = time.monotonic()
        msg = self.bans(alerts)
        self.assertLess(time.monotonic() - start, 5)
        self.assertIn(f"\nБаны CrowdSec за сутки: {total} адресов — ", msg)


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

    def test_next_step_upgrade_on_test(self):
        # после выпуска тестовый идёт тем же upgrade, что рабочие, а не копией
        result = self.release("1.0.1", "заголовок")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("tools/rollout.sh admin@<тестовый> --upgrade v1.0.1", result.stdout)


@unittest.skipUnless(shutil.which("git") and shutil.which("ssh-keygen"), "нужны git и ssh-keygen")
class RolloutUpgrade(unittest.TestCase):
    """tools/rollout.sh --upgrade: новая версия на тестовом сервере тем же infra upgrade, что на рабочих, — только
    при test_server: true, версии проверены до первого ssh, прежняя — только подписанная, на сервере — тот же коммит;
    шаги U0–U3 без копии rsync; обычная раскатка на тестовом убирает .git. Стенд: репозиторий с подписанными тегами
    во временной папке, ssh и rsync — заглушки, пишут команду в журнал."""

    SSH = r"""#!/bin/sh
shift                                             # адрес сервера
input=$(cat)
echo "ssh $*" >> "$STUB_LOG"
case "$*" in
  "sudo /opt/infra/.venv/bin/python -")           # тестовый ли сервер
    [ -n "${STUB_SERVER_YML:-}" ] || exit "$STUB_TEST_SERVER"
    printf '%s\n' "$input" | sed "s#/etc/infra/server.yml#$STUB_SERVER_YML#" | "$STUB_PYTHON" -
    exit ;;
  "sudo test -d /opt/infra/.git") exit "${STUB_GIT:-1}" ;;
  "sudo bash -s -- "*) [ "${STUB_U0_RC:-0}" = 0 ] || { echo "infra: тег на GitHub подменён"; exit 1; } ;;
  "sudo infra upgrade "*) [ "${STUB_UPGRADE_RC:-0}" = 0 ] || { echo "fatal: сбой upgrade"; exit 1; }
                        printf '%b' "${STUB_HEALTH:-}" ;;          # вывод задачи health-check, если задан
esac
case " $* " in
  *" infra apply "*|*" infra upgrade "*) echo "PLAY RECAP"; echo "srv : ok=1 changed=${STUB_CHANGED:-0} failed=0" ;;
esac
exit 0
"""
    UPGRADE = ["ssh sudo /opt/infra/.venv/bin/python -", "ssh sudo bash -s -- v1.0.0 v1.1.0 {from_commit}",
               "ssh sudo /opt/infra/install.sh", "ssh sudo infra apply -y", "ssh sudo infra upgrade v1.1.0 -y",
               "ssh sudo infra apply -y"]

    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.repo, stubs = self.dir / "repo", self.dir / "bin"
        (self.repo / "tools").mkdir(parents=True)
        stubs.mkdir()
        shutil.copy(ROOT / "tools/rollout.sh", self.repo / "tools/rollout.sh")
        shutil.copy(ROOT / "infra", self.repo / "infra")          # infra tag-signed — проверка подписи прежней
        self.keys = {}
        for who in ("author", "stranger"):
            self.keys[who] = self.dir / who
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", who, "-f", self.keys[who]], check=True)
        public = pathlib.Path(f"{self.keys['author']}.pub").read_text().split()
        (self.repo / "SIGNERS").write_text(f'author namespaces="git" {public[0]} {public[1]}\n')
        for name, text in (("ssh", self.SSH), ("rsync", '#!/bin/sh\necho "rsync $*" >> "$STUB_LOG"\n')):
            (stubs / name).write_text(text)
            (stubs / name).chmod(0o755)
        self.log = self.dir / "stub.log"
        self.env = {**os.environ, "PATH": f"{stubs}:{os.environ['PATH']}", "TMPDIR": str(self.dir),
                    "STUB_LOG": str(self.log), "STUB_PYTHON": sys.executable, "STUB_TEST_SERVER": "0",
                    "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
        self.git(self.repo, "init", "-q")
        for tag in ("v1.0.0", "note", "v1.1.0"):          # note — не версия: --from его пропускает
            (self.repo / "VERSION").write_text(tag)
            self.git(self.repo, "add", ".")
            self.git(self.repo, "commit", "-q", "-m", tag)
            self.git(self.repo, "tag", *(["-s", "-m", tag] if tag.startswith("v") else []), tag)
        self.from_commit = self.git(self.repo, "rev-parse", "v1.0.0^{commit}")
        self.UPGRADE = [c.format(from_commit=self.from_commit) for c in self.UPGRADE]

    def git(self, cwd, *args):
        return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.org", "-c", "gpg.format=ssh",
                               "-c", f"user.signingkey={self.keys['author']}", *args], cwd=cwd,
                              env=self.env, check=True, capture_output=True, text=True).stdout.strip()

    def rollout(self, *args, **env):
        self.log.unlink(missing_ok=True)
        result = subprocess.run(["bash", str(self.repo / "tools/rollout.sh"), "admin@test", *args],
                                env={**self.env, **env}, stdin=subprocess.DEVNULL, capture_output=True, text=True)
        return result, self.log.read_text().splitlines() if self.log.exists() else []

    def test_only_on_test_server(self):
        for rc, why in (("3", "на рабочем это откат"), ("1", "test_server не узнать"), ("255", "не узнать")):
            with self.subTest(rc=rc):
                result, calls = self.rollout("--upgrade", "v1.1.0", "--from", "v1.0.0", STUB_TEST_SERVER=rc)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn(why, result.stderr)
                self.assertEqual(calls, self.UPGRADE[:1])         # после проверки — ни ssh, ни rsync

    def test_upgrade_steps(self):
        result, calls = self.rollout("--upgrade", "v1.1.0", "--from", "v1.0.0")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(calls, self.UPGRADE)                     # rsync нет: движок — с GitHub
        self.assertIn("v1.0.0 → v1.1.0", result.stdout)

    def test_upgrade_shows_health_check(self):
        # вывод Ansible — YAML (ansible.cfg): строки списка health-check — в выводе раскатки, без кавычек YAML
        health = ("TASK [Что сейчас сообщает health-check] ****\\nok: [srv] => \\n    msg:\\n    - 'Диск: 91% занято'\\n"
                  "    - 'Сервис web''s: упал'\\n    - 'DNS сервера не отвечает: не разрешается ни одно из имён Let''s Encrypt, Docker\\n"
                  "        Hub, Telegram — встанут apt'\\n    - без кавычек тоже переносится на следующую строку при ширине больше\\n"
                  "        восьмидесяти знаков\\n\\nTASK [infra status] ****\\nok: [srv] => \\n    msg: не отсюда\\n")
        result, _ = self.rollout("--upgrade", "v1.1.0", "--from", "v1.0.0", STUB_HEALTH=health)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        lines = [line.strip() for line in result.stdout.splitlines() if "health-check:" in line]
        self.assertEqual(lines, ["health-check: Диск: 91% занято", "health-check: Сервис web's: упал",          # длинные — целиком
                                 "health-check: DNS сервера не отвечает: не разрешается ни одно из имён Let's Encrypt, Docker Hub, Telegram — встанут apt",
                                 "health-check: без кавычек тоже переносится на следующую строку при ширине больше восьмидесяти знаков"])
        result, _ = self.rollout("--upgrade", "v1.1.0", "--from", "v1.0.0",
                                 STUB_HEALTH="TASK [Что сейчас сообщает health-check] ****\\nok: [srv] => \\n    msg: проблем нет\\n")
        self.assertIn("   health-check: проблем нет", result.stdout)

    def test_upgrade_failure_stops(self):
        # U0 отказал (тег прежней на GitHub подменён) — ни install.sh, ни apply
        result, calls = self.rollout("--upgrade", "v1.1.0", "--from", "v1.0.0", STUB_U0_RC="1")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(calls, self.UPGRADE[:2])
        self.assertIn("подменён", result.stdout)
        result, calls = self.rollout("--upgrade", "v1.1.0", "--from", "v1.0.0", STUB_UPGRADE_RC="1")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(calls, self.UPGRADE[:-1])
        self.assertIn("fatal: сбой upgrade", result.stdout)
        result, calls = self.rollout("--upgrade", "v1.1.0", "--from", "v1.0.0", STUB_CHANGED="2")
        self.assertEqual(result.returncode, 1)
        self.assertIn("не идемпотентны", result.stdout)

    def test_bad_arguments_before_ssh(self):
        for args, why in ((["--upgrade", "v1.1.0", "--scenarios"], "по отдельности"),
                          (["--scenarios", "--upgrade", "v1.1.0"], "по отдельности"),
                          (["--upgrade", "1.1.0"], "vX.Y.Z"), (["--upgrade", "v1.1"], "vX.Y.Z"),
                          (["--upgrade", "v1.1.0;id"], "vX.Y.Z"), (["--upgrade", "v1.1.0\nid"], "vX.Y.Z"),
                          (["--upgrade", "$(id)"], "vX.Y.Z"), (["--upgrade", "v1.1.0 v1.0.0"], "vX.Y.Z"),
                          (["--upgrade", "v1.1.0", "--from", "v1.0"], "vX.Y.Z"),
                          (["--upgrade", "v1.1.0", "--from", "--scenarios"], "vX.Y.Z"),
                          (["--from", "v1.0.0"], "вместе с --upgrade"),
                          (["--upgrade"], "без версии"), (["--upgrade", "v1.1.0", "--from"], "без версии"),
                          (["--upgrade", "v7.7.7"], "--from"),       # такого тега здесь нет
                          (["--upgrade", "v1.0.0"], "--from")):      # до первой версии тегов нет
            with self.subTest(args=args):
                result, calls = self.rollout(*args)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn(why, result.stderr)
                self.assertEqual(calls, [])

    def test_from_signed_here(self):
        # прежняя ставится от root — только подписанная ключом из SIGNERS; иначе — до первого ssh
        for name, cmd in (("без подписи", ["tag", "-f", "-a", "-m", "v1.0.0"]), ("лёгкий", ["tag", "-f"]),
                          ("чужой ключ", ["-c", f"user.signingkey={self.keys['stranger']}", "tag", "-f", "-s", "-m",
                                          "v1.0.0"])):
            with self.subTest(name):
                self.git(self.repo, *cmd, "v1.0.0", "v1.0.0^{commit}")
                result, calls = self.rollout("--upgrade", "v1.1.0", "--from", "v1.0.0")
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("не подписан", result.stderr)
                self.assertEqual(calls, [])
        result, calls = self.rollout("--upgrade", "v1.1.0", "--from", "v1.0.5")      # такого тега здесь нет
        self.assertEqual((result.returncode, calls), (2, []), result.stderr)

    def test_from_default(self):
        result, calls = self.rollout("--upgrade", "v1.1.0")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(calls, self.UPGRADE)                     # прежняя — v1.0.0, «note» не версия

    def test_copy_rollout_removes_git_only_on_test(self):
        copy = ["rsync", "ssh sudo /opt/infra/install.sh", "ssh sudo infra apply --check", "ssh sudo infra apply -y",
                "ssh sudo infra apply -y", "ssh sudo infra run tests/verify.yml"]
        check, has_git, remove = self.UPGRADE[0], "ssh sudo test -d /opt/infra/.git", "ssh sudo rm -rf /opt/infra/.git"
        for test, git, before in (("0", "0", [check, has_git, remove]),     # тестовый после --upgrade
                                  ("0", "1", [check, has_git]),             # тестовый, движок — копия
                                  ("3", "0", [check]),                      # рабочий — git не трогается
                                  ("1", "0", [check])):                     # не узнать — тоже
            with self.subTest(test_server=test, git=git):
                result, calls = self.rollout(STUB_TEST_SERVER=test, STUB_GIT=git)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual([c.split(" ")[0] if c.startswith("rsync") else c for c in calls], before + copy)

    @unittest.skipUnless(importlib.util.find_spec("yaml"), "нужен PyYAML (есть в .venv движка)")
    def test_test_server_from_server_yml(self):
        yml = self.dir / "server.yml"
        for text, rc, why in (("server_name: srv\ntest_server: true\n", 0, "→ v1.1.0"),
                              ("test_server: false\n", 1, "откат"), ("server_name: srv\n", 1, "откат"),
                              ('test_server: "true"\n', 1, "откат"), ("test_server: 1\n", 1, "откат"),
                              ("- test_server: true\n", 1, "откат"), ("", 1, "откат"),
                              ("test_server: [\n", 1, "не узнать"), (None, 1, "не узнать")):
            with self.subTest(text=text):
                yml.unlink(missing_ok=True)
                if text is not None:
                    yml.write_text(text)
                result, _ = self.rollout("--upgrade", "v1.1.0", "--from", "v1.0.0", STUB_SERVER_YML=str(yml))
                self.assertEqual(result.returncode, rc, result.stdout + result.stderr)
                self.assertIn(why, result.stdout + result.stderr)

    def test_engine_script(self):
        # U0 — скрипт для сервера из rollout.sh: на копии движка (rsync поверх) и на грязном git — чистый git
        # на прежней версии, .venv и коллекции целы; новой версии на GitHub нет — движок не тронут
        text = (ROOT / "tools/rollout.sh").read_text()
        script = text.split("<<'SH'\n", 1)[1].split("\nSH\n", 1)[0]
        origin, engine = self.dir / "origin", self.dir / "engine"
        for old, new in (("chown -R root:root /opt/infra", ": chown"), ("/opt/infra", str(engine)),
                         ("https://github.com/mcnickbronx/infra.git", str(origin))):
            self.assertIn(old, script, "стенду нечего подменить")
            script = script.replace(old, new)
        origin.mkdir()
        self.git(origin, "init", "-q")
        (origin / ".gitignore").write_text(".venv/\ncollections/\n")
        for version, files in (("v1.0.0", {"infra": "1.0.0", "gone": "был"}), ("v1.1.0", {"infra": "1.1.0", "new": "н"})):
            for name in ("infra", "gone", "new"):
                (origin / name).unlink(missing_ok=True)
            for name, body in files.items():
                (origin / name).write_text(body)
            self.git(origin, "add", "-A")
            self.git(origin, "commit", "-q", "-m", version)
            self.git(origin, "tag", "-a", version, "-m", version)
        # копия рабочей версии поверх (как rsync): новее v1.1.0, свой файл, Ansible сервера
        shutil.copytree(origin, engine, ignore=shutil.ignore_patterns(".git"))
        (engine / "infra").write_text("рабочая копия")
        (engine / "local").write_text("не из git")
        for kept in (".venv/bin/python", "collections/x"):
            (engine / kept).parent.mkdir(parents=True)
            (engine / kept).write_text("сервер")

        good = self.git(origin, "rev-parse", "v1.0.0^{commit}")      # коммит подписанного тега там, откуда раскатка

        def u0(new):
            return subprocess.run(["bash", "-s", "--", "v1.0.0", new, good], input=script, env=self.env,
                                  capture_output=True, text=True)
        # тег прежней на GitHub подменили, .git на сервере нет — fetch возьмёт любой: стоп до checkout и install.sh
        evil = self.git(origin, "commit-tree", "-p", good, "-m", "evil", self.git(origin, "rev-parse", "v1.1.0^{tree}"))
        self.git(origin, "tag", "-f", "-a", "-m", "v1.0.0", "v1.0.0", evil)
        result = u0("v1.1.0")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("v1.0.0 на GitHub — не тот коммит", result.stdout)
        self.assertEqual((engine / "infra").read_text(), "рабочая копия")   # до checkout не дошло
        self.git(origin, "tag", "-f", "-a", "-m", "v1.0.0", "v1.0.0", good)  # тег вернули, движок — снова копия
        shutil.rmtree(engine / ".git")
        result = u0("v9.9.9")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("на GitHub нет v9.9.9", result.stdout)
        self.assertEqual((engine / "infra").read_text(), "рабочая копия")   # до checkout не дошло
        for dirty in ("копия поверх", "грязный git"):
            with self.subTest(dirty):
                result = u0("v1.1.0")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.git(engine, "status", "--porcelain"), "")   # upgrade не откажет
                self.assertEqual(self.git(engine, "describe", "--tags"), "v1.0.0")
                self.assertEqual((engine / "infra").read_text(), "1.0.0")
                self.assertEqual(sorted(p.name for p in engine.iterdir()),
                                 [".git", ".gitignore", ".venv", "collections", "gone", "infra"])
                self.assertEqual((engine / ".venv/bin/python").read_text(), "сервер")
                self.assertIn("v1.1.0", self.git(engine, "tag"))               # upgrade найдёт её локально
                (engine / "infra").write_text("правка")
                (engine / "local").write_text("ещё")


@unittest.skipUnless(shutil.which("git") and shutil.which("ssh-keygen"), "нужны git и ssh-keygen")
class UpgradePreview(unittest.TestCase):
    """infra upgrade: сервер не менялся (--check, «нет», предпросмотр не прошёл, Ctrl+C) — движок прежней версии;
    «изменений нет» и «да» — новой, затем проверка сервера tests/verify.yml. Стенд: «origin» с подписанными v1.0.0
    и v1.1.0, движок — его клон на v1.0.0, /etc/infra и /var/lib/infra — во временной папке; Ansible, install.sh,
    infra-log, id, systemd — заглушки, пишут строку в журнал стенда."""

    PLAYBOOK = """#!/bin/sh
echo "ansible-playbook $*" >> "$STUB_LOG"
case " $* " in *" tests/verify.yml "*) exit "${STUB_VERIFY_RC:-0}" ;; esac   # проверка после upgrade
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

    def upgrade(self, *args, answer="", changed=2, rc=0, interrupt=False, apply_rc=0, verify_rc=0):
        env = {**os.environ, "PATH": f"{self.bin}:{os.environ['PATH']}", "STUB_LOG": str(self.log),
               "STUB_CHANGED": str(changed), "STUB_RC": str(rc), "STUB_INT": "1" if interrupt else "",
               "STUB_APPLY_RC": str(apply_rc), "STUB_VERIFY_RC": str(verify_rc)}
        run = subprocess.run(["bash", str(self.engine / "infra"), "upgrade", "v1.1.0", *args], input=answer,
                             env=env, capture_output=True, text=True, timeout=60, start_new_session=True)
        engine = subprocess.run(["git", "describe", "--tags"], cwd=self.engine, check=True, capture_output=True,
                                text=True).stdout.strip()
        return run, engine, self.log.read_text().splitlines()

    @staticmethod
    def verify_calls(lines):
        """Номера строк журнала стенда — вызовы Ansible с tests/verify.yml"""
        return [i for i, x in enumerate(lines) if x.startswith("ansible-playbook ") and " tests/verify.yml" in x]

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
        applied = [i for i, x in enumerate(lines) if x.startswith("systemd-run ")]
        self.assertTrue(applied, lines)
        self.assertTrue([i for i in self.verify_calls(lines) if i > applied[-1]], lines)   # после прогона — проверка
        self.assertEqual([x for x in lines if x.startswith("install ")], ["install 1.1.0"])

    def test_failed_apply_keeps_new(self):
        # прогон начат — сервер мог уже измениться новой версией, назад её не отмотать
        run, engine, lines = self.upgrade(answer="y\n", apply_rc=1)
        self.assertEqual((run.returncode, engine), (1, "v1.1.0"), run.stderr)
        self.assertTrue(lines[-1].startswith("systemd-run "), lines)

    def test_answer_yes_verifies_server(self):
        # после прогона — tests/verify.yml через infra run: с записью в журнал событий
        run, engine, lines = self.upgrade(answer="y\n")
        self.assertEqual((run.returncode, engine), (0, "v1.1.0"), run.stderr)
        self.assertIn("== Проверка сервера: tests/verify.yml (только чтение)", run.stdout)
        self.assertEqual(lines[-3], "infra-log run: tests/verify.yml", lines)
        self.assertEqual(self.verify_calls(lines), [len(lines) - 2], lines)
        self.assertEqual(lines[-1], "infra-log run tests/verify.yml: готово", lines)

    def test_nothing_to_change_verifies_server(self):
        run, engine, lines = self.upgrade(changed=0)
        self.assertEqual((run.returncode, engine), (0, "v1.1.0"), run.stderr)
        self.assertEqual(len(self.verify_calls(lines)), 1, lines)

    def test_partial_upgrade_verifies_whole_server(self):
        # --tags — частичный прогон, но проверяется весь сервер: параметры apply в verify не идут
        run, engine, lines = self.upgrade("--tags", "project", answer="y\n")
        self.assertEqual((run.returncode, engine), (0, "v1.1.0"), run.stderr)
        self.assertIn("--tags project", [x for x in lines if x.startswith("systemd-run ")][-1])
        verify = [lines[i] for i in self.verify_calls(lines)]
        self.assertEqual(len(verify), 1, lines)
        self.assertNotIn("--tags", verify[0])

    def test_no_verify_without_new_engine_applied(self):
        # движок вернулся (--check, «нет», предпросмотр не прошёл, Ctrl+C) или прогон упал — проверки нет
        for name, kwargs in (("--check", {"args": ("--check",)}), ("нет", {"answer": "n\n"}),
                             ("предпросмотр не прошёл", {"rc": 2}), ("Ctrl+C", {"interrupt": True}),
                             ("прогон упал", {"answer": "y\n", "apply_rc": 1})):
            with self.subTest(name):
                self.setUp()
                run, engine, lines = self.upgrade(*kwargs.pop("args", ()), **kwargs)
                self.assertEqual(self.verify_calls(lines), [], lines)
                self.assertFalse([x for x in lines if "infra-log run" in x], lines)

    def test_failed_verify(self):
        # проверка не прошла — код 1, но движок новый: сервер уже приведён к нему
        run, engine, lines = self.upgrade(answer="y\n", verify_rc=2)
        self.assertEqual((run.returncode, engine), (1, "v1.1.0"), run.stderr)
        self.assertIn("проверка после upgrade не прошла", run.stderr)
        self.assertIn("движок остаётся v1.1.0 (был v1.0.0)", run.stderr)
        self.assertIn("infra-log run tests/verify.yml: ошибка (код 2)", lines)
        self.assertFalse([x for x in lines if "только просмотр" in x], lines)
        self.assertEqual([x for x in lines if x.startswith("install ")], ["install 1.1.0"])



@unittest.skipUnless(shutil.which("jq"), "нужен jq")
class ProjectDeployTo(unittest.TestCase):
    """project-deploy <проект> to <тег>: образа нет — .env побайтно тот же; есть — выкладка, и в .env заменена одна
    строка DEPLOY_IMAGE, владелец и права прежние; .env-ссылка — отказ; сбой выкладки — прежние версия и .env.
    Стенд: скрипт с папками проекта и состояния во временной папке; docker, project-compose, flock, infra-log,
    infra-notify, timeout — заглушки, пишут строку в журнал стенда; chown, chmod, stat, mv, dd, getfacl и setfacl —
    на Python (их ключей и ACL на Mac нет), пишут строку в журнал файловых команд. Папка проекта
    (/srv/projects/<проект>) — proj, web/ — внутри; /etc/infra/server.yml — server.yml стенда."""

    REPO = "ghcr.io/example/shop"
    HASH = "bb168cfcfece1b663da0141574e4994eed9eea20"
    OLD, NEW = "sha256:" + "1" * 64, "sha256:" + "2" * 64
    ENV = ('DEBUG=False\n#DEPLOY_IMAGE=ghcr.io/example/shop:v0\nDEPLOY_IMAGE="ghcr.io/example/shop:main"\n'
           "SITE_NAME=Магазин\n")
    # docker: в реестре — только теги из STUB_TAGS («образ:тег=дайджест») и любые @sha256; ярлык коммита образа
    # (org.opencontainers.image.revision) — STUB_REV, ярлык версии (org.opencontainers.image.version) — STUB_VER. STUB_TAG_AFTER «образ:тег=N» — этот тег скачивается только с N-й
    # попытки pull (CI ещё собирает; счёт — по журналу стенда)
    DOCKER = """#!/bin/bash
echo "docker $*" >> "$STUB_LOG"
ref=${!#}
[[ "$*" != *image.revision* ]] || { echo "${STUB_REV:-}"; exit 0; }
[[ "$*" != *image.version* ]] || { echo "${STUB_VER:-}"; exit 0; }
digest=$(printf '%s\\n' $STUB_TAGS | awk -F= -v r="$ref" '$1 == r { print $2 }')
case $1 in
  pull) [ "$ref" != "${STUB_TAG_AFTER%=*}" ] || [ "$(grep -cxF "docker $*" "$STUB_LOG")" -ge "${STUB_TAG_AFTER##*=}" ] || digest=
        [ -n "$digest" ] || [[ $ref == *@sha256:* ]] || { echo "Error response from daemon: manifest unknown" >&2; exit 1; } ;;
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
        # sleep — строка в журнал, без сна (ожидание образа у to --wait)
        "sleep": '#!/bin/sh\necho "sleep $*" >> "$STUB_LOG"\n',
        "infra-log": '#!/bin/sh\necho "infra-log $*" >> "$STUB_LOG"\n',
        # infra-notify: код — STUB_NOTIFY_RC (1 — Telegram не ответил)
        "infra-notify": '#!/bin/sh\necho "infra-notify $*" >> "$STUB_LOG"\nexit ${STUB_NOTIFY_RC:-0}\n',
        # timeout <секунды> <команда>: строка в журнал, «(с замком)» — команде достался дескриптор 9 (замок выкладки);
        # затем команда — без ограничения времени
        "timeout": '#!/bin/bash\n[ -e /dev/fd/9 ] && lock=" (с замком)" || lock=\n'
                   'echo "timeout $*$lock" >> "$STUB_LOG"\nshift\nexec "$@"\n',
        # chown --reference=<файл> | <uid>:<gid> и chmod --reference=<файл> | <восьмеричные>: по ссылке идут, как GNU без -h
        "chown": PYTHON + "who, path = args\n"
                 "if who.startswith('--reference='): ref = os.stat(who.split('=', 1)[1]); who = f'{ref.st_uid}:{ref.st_gid}'\n"
                 "os.chown(path, *map(int, who.split(':')))\n"
                 # STUB_RESTORE_ENV — крючок «после чтения, до сверки stat» (chown временного .env, не compose.yml): участник
                 # возвращает прежний .env (тот же inode) с <.env>.held на место ссылки — сверка stat подмены не видит,
                 # защищает только nofollow у dd
                 "if os.environ.get('STUB_RESTORE_ENV') and '/.env.' in path:\n"
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
        # mv [-f] [-T] <откуда> <куда>: без -T цель-папка (или ссылка на папку) — «положить внутрь неё», как GNU и uutils
        "mv": PYTHON + "src, dst = args\n"
              "if not {'-T', '-fT'} & set(sys.argv[1:]) and os.path.isdir(dst): dst = os.path.join(dst, os.path.basename(src))\n"
              "os.replace(src, dst)\n",
        # ln -P[T] <файл> <имя> — жёсткая ссылка, как GNU и uutils (у ln Мака нет -T): -P — не по ссылке-источнику; без -T
        # имя-папка (или ссылка на папку) — «внутрь неё»; имя занято — отказ; ln -s — символьная (крючки участника).
        # В журнал не пишет
        "ln": "#!/usr/bin/env python3\nimport os, sys\nopts = ''.join(a for a in sys.argv[1:] if a.startswith('-'))\n"
              "src, dst = [a for a in sys.argv[1:] if not a.startswith('-')]\n"
              "if 's' in opts: os.symlink(src, dst); sys.exit()\n"
              "if 'T' not in opts and os.path.isdir(dst):\n"
              "    dst = os.path.join(dst, os.path.basename(src))\n"
              "if os.path.lexists(dst): sys.exit(f'ln: {dst}: File exists')\n"
              "os.link(src, dst, follow_symlinks=False)\n",
        # dd if=<файл> [iflag=nofollow[,nonblock]]: с nofollow ссылку не открывает (O_NOFOLLOW), с nonblock FIFO без
        # писателя не ждёт (O_NONBLOCK: пустое чтение), как GNU dd и uutils
        "dd": PYTHON + "opts = dict(a.split('=', 1) for a in args)\n"
              "iflag = opts.get('iflag', '').split(',')\n"
              "flags = os.O_RDONLY | (os.O_NOFOLLOW if 'nofollow' in iflag else 0) | (os.O_NONBLOCK if 'nonblock' in iflag else 0)\n"
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
        conf = self.dir / "server.yml"                       # server_name — в уведомлении о выкладке
        conf.write_text('server_name: "vds-x"   # имя сервера\nadmin_ips: []\n')
        script = (ROOT / "roles/project/files/project-deploy").read_text()
        for old, new in (("/srv/projects/$NAME", f'"{self.proj}"'), ("/var/lib/project-deploy", f'"{self.states}"'),
                         ("/etc/infra/server.yml", f'"{conf}"')):
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

    # Уведомление о выкладке: таймер выложил новую версию — строка в Telegram с коротким коммитом, в журнале событий —
    # полный; to, откат, сбой и «нового нет» — без сообщения
    NOTE = "infra-notify 🚀 vds-x: shop — выложена новая версия"

    def timer(self, digest=None, **stubs):
        return self.deploy(STUB_TAGS=f"{self.REPO}:main={digest or self.NEW}", **stubs)

    def notes(self, lines):
        return [x for x in lines if x.startswith("infra-notify")]

    def test_timer_notifies_with_commit(self):
        run, lines = self.timer(STUB_REV=self.HASH)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(self.notes(lines), [f"{self.NOTE}, коммит bb168cf"])
        self.assertIn(f"infra-log выкладка shop: готово, {self.REPO}@sha256:{'2' * 12}, коммит {self.HASH}", lines)

    def test_timer_notifies_without_label(self):
        # образ без ярлыка (у front.yml web-start его нет) — сообщение и журнал без коммита
        run, lines = self.timer()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(self.notes(lines), [self.NOTE])
        self.assertIn(f"infra-log выкладка shop: готово, {self.REPO}@sha256:{'2' * 12}", lines)

    def test_timer_bad_label_dropped(self):
        # ярлык задаёт тот, кто собирает образ: не хеш — отброшен, в сообщение и журнал не идёт
        for rev in ("abc; rm -rf /", "$(id)", "<no value>", "BB168CF", "abc123", f"{self.HASH}\nx", "a" * 65):
            with self.subTest(rev=rev):
                self.log.unlink(missing_ok=True)
                (self.states / "shop.current").write_text(f"{self.REPO}@{self.OLD}\n")
                run, lines = self.timer(STUB_REV=rev)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(self.notes(lines), [self.NOTE])
                self.assertFalse([x for x in lines if "коммит" in x], lines)

    def test_timer_notifies_with_version(self):
        # ярлык версии (CI web-start, git describe --tags): между выпусками — версия, сколько коммитов после неё и коммит;
        # на теге — одна версия. В журнале событий — как в ярлыке, и полный коммит
        run, lines = self.timer(STUB_REV=self.HASH, STUB_VER="v2.4.0-64-gbb168cfcfe")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(self.notes(lines), ["infra-notify 🚀 vds-x: shop — выложена v2.4.0 +64, коммит bb168cf"])
        self.assertIn(f"infra-log выкладка shop: готово, {self.REPO}@sha256:{'2' * 12}, версия v2.4.0-64-gbb168cfcfe, "
                      f"коммит {self.HASH}", lines)
        self.log.unlink()
        run, lines = self.timer(digest=f"sha256:{'3' * 64}", STUB_REV=self.HASH, STUB_VER="v3.0.0")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(self.notes(lines), ["infra-notify 🚀 vds-x: shop — выложена v3.0.0"])
        self.assertIn(f"infra-log выкладка shop: готово, {self.REPO}@sha256:{'3' * 12}, версия v3.0.0, коммит {self.HASH}",
                      lines)

    def test_timer_bad_version_dropped(self):
        # ярлык версии тоже задаёт тот, кто собирает образ: не по образцу — отброшен, сообщение — как без него, с коммитом
        for ver in ("v3.0.0; rm -rf /", "$(id)", "<no value>", "3.0.0", "v3.0", "v3.0.0-rc1", "v3.0.0-64-gBB168CF",
                    "v3.0.0-64-gabc123", "v3.0.0\nx", f"v{'9' * 10}.0.0", "v3.0.0-64-g" + "a" * 41, " v3.0.0"):
            with self.subTest(ver=ver):
                self.log.unlink(missing_ok=True)
                (self.states / "shop.current").write_text(f"{self.REPO}@{self.OLD}\n")
                run, lines = self.timer(STUB_REV=self.HASH, STUB_VER=ver)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(self.notes(lines), [f"{self.NOTE}, коммит bb168cf"])
                self.assertFalse([x for x in lines if "версия v" in x], lines)

    def test_version_from_image_tag(self):
        # ярлыка версии нет (образ собран до него), а тег образа — версия: она. Таймер — тег из DEPLOY_IMAGE,
        # to — тег, который дали; тег не версия (main, хеш) — без версии
        self.env.write_text(f"DEPLOY_IMAGE={self.REPO}:v3.0.0\n")
        run, lines = self.deploy(STUB_TAGS=f"{self.REPO}:v3.0.0={self.NEW}")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(self.notes(lines), ["infra-notify 🚀 vds-x: shop — выложена v3.0.0"])
        self.log.unlink()
        run, lines = self.deploy("to", "v3.1.0", STUB_TAGS=f"{self.REPO}:v3.1.0=sha256:{'3' * 64}")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn(f"infra-log выкладка shop: готово, {self.REPO}@sha256:{'3' * 12}, версия v3.1.0", lines)
        self.log.unlink()
        run, lines = self.deploy("to", self.HASH)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertFalse([x for x in lines if "версия v" in x], lines)

    def test_timer_telegram_down_deploy_ok(self):
        run, lines = self.timer(STUB_REV=self.HASH, STUB_NOTIFY_RC="1")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(len(self.notes(lines)), 1)                 # пробовали один раз — и не повторяем
        self.assertEqual((self.state("current"), self.state("previous")),
                         (f"{self.REPO}@{self.NEW}", f"{self.REPO}@{self.OLD}"))
        self.assertIsNone(self.state("failed"))

    def test_timer_failed_rollout_no_notify(self):
        run, lines = self.timer(STUB_FAIL_UP="1")
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertEqual(self.notes(lines), [])
        self.log.unlink()
        run, lines = self.timer(digest=f"sha256:{'3' * 64}")        # следующая версия удалась — сообщение есть
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(self.notes(lines), [self.NOTE])

    def test_timer_nothing_new_no_repeat(self):
        # таймер проверяет каждые 15 секунд: сообщение — одно на версию, не на каждую проверку
        self.timer()
        run, lines = self.timer()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(self.notes(lines), [self.NOTE])

    def test_manual_to_and_rollback_no_notify(self):
        # to и откат запускает человек и видит вывод; у to коммит — в журнале событий
        run, lines = self.deploy("to", self.HASH, STUB_REV=self.HASH)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn(f"infra-log выкладка shop: готово, {self.REPO}@sha256:{'2' * 12}, коммит {self.HASH}", lines)
        run, lines = self.deploy("rollback", STUB_REV=self.HASH)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("откат выполнен", run.stdout)
        self.assertEqual(self.notes(lines), [])

    def test_timer_notify_limited_and_without_lock(self):
        # Telegram закрыт — infra-notify ждёт минуту и дольше, а rollback и to ждут замок 30 с: отправка — через
        # timeout 15 и без дескриптора замка
        run, lines = self.timer(STUB_REV=self.HASH)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual([x for x in lines if x.startswith("timeout")], [f"timeout 15 {self.NOTE}, коммит bb168cf"])

    def test_timer_notify_without_server_name(self):
        # в server.yml нет server_name — имя хоста
        (self.dir / "server.yml").write_text("admin_ips: []\n")
        host = subprocess.run(["hostname"], capture_output=True, text=True, check=True).stdout.strip()
        run, lines = self.timer()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(self.notes(lines), [f"infra-notify 🚀 {host}: shop — выложена новая версия"])

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
        self.swap_env("mktemp", "*/.env.*", shutil.which("mktemp"))       # временный .env, не compose.yml

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
        self.assertEqual([x.split()[-1] for x in self.fs("mv")], ["compose.yml"])   # .env не трогали
        self.assertFalse([p.name for p in self.proj.iterdir() if p.name.startswith(".env")])
        held = self.web / ".env.held"
        self.assertEqual((self.env if not self.env.is_symlink() else held).read_text(), self.ENV)

    # --- .env подменили после проверки «не ссылка» (tag_ref), перед подсчётом строк DEPLOY_IMAGE ---
    # Крючок — первый stat прав папки проекта: он в proj_root_only из tag_ref, ровно между [ ! -L .env ] и подсчётом
    # (второй такой stat — в switch_to, его не трогаем)
    UNREAD = "shop: web/.env не прочитан без перехода по ссылке или в нём нет строки DEPLOY_IMAGE — ничего не менял"

    def env_after_check(self, action):
        participant_hook(self.bin, self.dir, "stat", f'"-c %a -- {self.proj}"', action)

    def test_env_link_after_check_no_bit(self):
        # ссылка на чужой файл: root его не читает — ни выкладки (одна строка DEPLOY_IMAGE), ни «несколько строк» (две):
        # исход один и тот же, о чужом файле не узнать ничего. Так и у to --wait (tag_ref до замка)
        victim = victim_file(self.dir)
        self.env_after_check(f'rm -f "{self.env}" && ln -s "{victim}" "{self.env}"')
        for text in ("DEPLOY_IMAGE=ghcr.io/example/other:main\n", "DEPLOY_IMAGE=a\nDEPLOY_IMAGE=b\n"):
            for args in (("to", self.HASH), ("to", self.HASH, "--wait")):
                with self.subTest(lines=text.count("\n"), args=args):
                    self.log.unlink(missing_ok=True)
                    (self.dir / "stat.hooked").unlink(missing_ok=True)
                    self.env.unlink()
                    self.env.write_text(self.ENV)
                    victim.write_text(text + "db_password_other=s3cret\n")
                    victim.chmod(0o600)
                    run, lines = self.deploy(*args)
                    self.assertEqual(run.returncode, 1, run.stderr)
                    self.assertNotIn("несколько строк", run.stderr)
                    self.assertEqual(run.stderr.splitlines()[-1:], [self.UNREAD])
                    self.assertFalse([x for x in lines if x.startswith("docker pull") or " up " in x], lines)
                    self.assertEqual((victim.read_text(), victim.stat().st_mode & 0o777),
                                     (text + "db_password_other=s3cret\n", 0o600))
                    self.assertEqual(self.state("current"), f"{self.REPO}@{self.OLD}")

    def test_env_fifo_link_after_check_no_hang(self):
        # ссылка на FIFO и сам FIFO на месте .env: подсчёт не ждёт писателя — отказ за секунды (под замком выкладки
        # таймер всё это время молча выходил бы). Страховка стенда — писатель FIFO через 10 с
        other = self.dir / "other"
        other.mkdir(mode=0o700)
        fifo = other / "fifo"
        os.mkfifo(fifo)
        for name, action, path in (("ссылка на FIFO", f'rm -f "{self.env}" && ln -s "{fifo}" "{self.env}"', fifo),
                                   ("FIFO", f'rm -f "{self.env}" && mkfifo "{self.env}"', self.env)):
            with self.subTest(name):
                self.log.unlink(missing_ok=True)
                (self.dir / "stat.hooked").unlink(missing_ok=True)
                self.env.unlink()
                self.env.write_text(self.ENV)
                self.env_after_check(action)
                guard = threading.Timer(10, open_fifo_writer, [path])
                guard.start()
                self.addCleanup(guard.cancel)
                start = time.monotonic()
                run, lines = self.deploy("to", self.HASH)
                self.assertLess(time.monotonic() - start, 5, "project-deploy ждал писателя FIFO")
                guard.cancel()
                self.assertEqual(run.returncode, 1, run.stderr)
                self.assertEqual(run.stderr.splitlines()[-1:], [self.UNREAD])
                self.assertFalse([x for x in lines if x.startswith("docker pull")], lines)

    def test_env_fifo_before_read_no_hang(self):
        # FIFO на месте .env после проверки перед чтением в to (крючок — mktemp временного .env): чтение не ждёт
        # писателя — пустое, сверка stat видит другой файл: отказ за секунды, .env не заменён, временного файла нет
        participant_hook(self.bin, self.dir, "mktemp", "*/.env.*", f'rm -f "{self.env}" && mkfifo "{self.env}"')
        guard = threading.Timer(10, open_fifo_writer, [self.env])
        guard.start()
        self.addCleanup(guard.cancel)
        start = time.monotonic()
        run, _ = self.deploy("to", self.HASH)
        self.assertLess(time.monotonic() - start, 5, "project-deploy ждал писателя FIFO")
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertIn(f"работает {self.REPO}:{self.HASH}, но .env не записан", run.stderr)
        self.assertTrue(self.env.is_fifo())
        self.assertEqual(self.leftovers(), ["compose.yml"])

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
        [tmp] = [x.split()[1] for x in self.fs("mktemp") if "/.env." in x]
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
        self.assertEqual([x.split()[-1] for x in self.fs("mv")], ["compose.yml"])   # .env не трогали

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

    # --- compose.yml из образа (switch_to): во временный файл в папке проекта и на место одним mv ---
    def plant_compose_new(self, target):
        """Пока root скачивает образ (крючок в docker pull), участник кладёт в web/ ссылку compose.yml.new на target:
        это имя root открывал на запись с noclobber, а bash с noclobber отказывает только обычному файлу"""
        (self.bin / "docker").rename(self.bin / "docker.real")
        (self.bin / "docker").write_text(f'#!/bin/bash\ncase "$*" in pull*) rm -f compose.yml.new && '
                                         f'ln -s "{target}" compose.yml.new ;; esac\nexec "{self.bin}/docker.real" "$@"\n')
        (self.bin / "docker").chmod(0o755)

    def test_compose_new_fifo_link_not_written(self):
        # ссылка на FIFO — как на устройство (/dev/vda: compose лёг бы в начало диска): читатель FIFO ничего не получает,
        # compose.yml — обычный файл с compose из образа
        other = self.dir / "other"
        other.mkdir(mode=0o700)
        fifo = other / "fifo"
        os.mkfifo(fifo)
        got = []
        reader = threading.Thread(target=lambda: got.append(fifo.read_bytes()), daemon=True)
        reader.start()
        self.plant_compose_new(fifo)
        run, _ = self.timer()
        open_fifo_writer(fifo)                                     # никто не писал — читатель получает конец файла
        reader.join(5)
        self.assertEqual(b"".join(got), b"", "root записал compose по ссылке compose.yml.new")
        self.assertEqual(run.returncode, 0, run.stderr)
        compose = self.web / "compose.yml"
        self.assertFalse(compose.is_symlink())
        self.assertIn("image: ${DEPLOY_IMAGE}", compose.read_text())
        self.assertTrue((self.web / "compose.yml.new").is_symlink())   # ссылку участника root не трогал

    def test_compose_new_link_to_file_untouched(self):
        # ссылка на чужой обычный файл: его root не переписывал и с noclobber — страховка, чтобы так и осталось
        victim = victim_file(self.dir)
        self.plant_compose_new(victim)
        self.timer()
        self.assertEqual((victim.read_text(), victim.stat().st_mode & 0o777), ("victim\n", 0o600))
        self.assertFalse((self.web / "compose.yml").is_symlink())

    def log_mktemp(self):
        """mktemp — настоящий, в журнал файловых команд: аргументы и созданный файл"""
        (self.bin / "mktemp").write_text(f'#!/bin/bash\nf=$({shutil.which("mktemp")} "$@") || exit\n'
                                         'echo "mktemp $* $f" >> "$STUB_FSLOG"\necho "$f"\n')
        (self.bin / "mktemp").chmod(0o755)

    def test_compose_tmp_in_project_dir(self):
        # временный файл — mktemp <папка проекта>/compose.yml.XXXXXX, без ключей (так же у .env; mktemp в Ubuntu 26.04 —
        # uutils); группа — как у web/, права 660 (читают участники и пользователь проекта без root), на место — mv
        self.log_mktemp()
        run, _ = self.timer()
        self.assertEqual(run.returncode, 0, run.stderr)
        [(_, template, tmp)] = [x.split() for x in self.fs("mktemp")]
        self.assertEqual(template, f"{self.proj}/compose.yml.XXXXXX")
        st = self.web.stat()
        self.assertEqual(self.fs("chown", "chmod", "mv"),
                         [f"chown {st.st_uid}:{st.st_gid} {tmp}", f"chmod 660 {tmp}", f"mv {tmp} compose.yml"])
        self.assertEqual((self.web / "compose.yml").stat().st_mode & 0o777, 0o660)
        self.assertEqual(self.leftovers(), ["compose.yml"])

    def test_compose_tmp_removed_on_failure(self):
        # docker run не отдал compose (нет /deploy/compose.yml в образе): отказ на шаге «compose.yml из образа»,
        # временного файла в папке проекта нет, compose.yml прежний
        (self.web / "compose.yml").write_text("services: {}\n")
        self.log_mktemp()
        (self.bin / "docker").write_text(self.DOCKER.replace("  run) printf", "  run) exit 1; printf"))
        run, _ = self.timer()
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertIn("не удалось на шаге «compose.yml из образа»", run.stderr)
        [(_, _, tmp)] = [x.split() for x in self.fs("mktemp")]
        self.assertFalse(os.path.exists(tmp))
        self.assertEqual(sorted(p.name for p in self.proj.iterdir()), ["web"])
        self.assertEqual((self.web / "compose.yml").read_text(), "services: {}\n")

    def test_compose_tmp_removed_when_killed(self):
        # выкладку остановили (systemctl stop, Ctrl+C) между mktemp и mv: временного compose.yml.XXXXXX в папке проекта
        # не остаётся — его убирает trap EXIT, как временный .env у to
        (self.web / "compose.yml").write_text("services: {}\n")
        (self.bin / "docker").write_text(self.DOCKER.replace("  run) printf", "  run) kill -TERM $PPID; printf"))
        run, _ = self.timer()
        self.assertNotEqual(run.returncode, 0, run.stderr)
        self.assertEqual(sorted(p.name for p in self.proj.iterdir()), ["web"])
        self.assertEqual((self.web / "compose.yml").read_text(), "services: {}\n")

    def test_failed_start_restores_previous_compose(self):
        # обычный откат: запуск не прошёл — compose.yml прежний побайтно (restore возвращает жёсткую ссылку
        # compose.yml.prev), compose.yml.prev не остаётся; web/compose.yml.new — остаток версий до v2.1.0 — убран
        before = b"services:\n  api:\n    image: ${DEPLOY_IMAGE}\n    command: old\n"
        (self.web / "compose.yml").write_bytes(before)
        (self.web / "compose.yml.new").write_text("services: {stale: {}}\n")
        run, _ = self.timer(STUB_FAIL_UP="1")
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertIn("не удалось на шаге «запуск»", run.stderr)
        self.assertEqual((self.web / "compose.yml").read_bytes(), before)
        self.assertEqual(self.leftovers(), ["compose.yml"])

    def test_open_project_dir_refused_on_deploy(self):
        # таймер: в папку проекта пишет группа — временный compose.yml туда не кладётся: отказ на шаге
        # «compose.yml из образа» до скачивания версии, работает прежняя
        self.proj.chmod(0o770)
        run, lines = self.timer()
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertIn(f"в папку {self.proj} пишет не только root — временный compose.yml туда не кладу", run.stderr)
        self.assertIn("не удалось на шаге «compose.yml из образа»", run.stderr)
        self.assertNotIn(f"docker pull -q {self.REPO}@{self.NEW}", lines)
        self.assertEqual(self.leftovers(), [])
        self.assertEqual(self.state("current"), f"{self.REPO}@{self.OLD}")

    def test_open_project_dir_other_compose_new_kept(self):
        # папка проекта открыта группе, участник сделал web ссылкой на web/ другого проекта (у shop не задан image):
        # таймер отказывает на шаге «compose.yml из образа», а compose.yml.new соседа цел — остаток версий до v2.1.0
        # root удаляет только после proj_root_only (rm берёт имя в папке, куда ведёт web)
        other = self.dir / "other-proj" / "web"
        other.mkdir(parents=True)
        (other / ".env").write_text("DEPLOY_IMAGE=ghcr.io/example/other:main\n")
        (other / "compose.yml").write_text("services: {other: {}}\n")
        (other / "compose.yml.new").write_text("other new\n")
        shutil.rmtree(self.web)
        self.web.symlink_to(other)
        self.proj.chmod(0o770)
        run, _ = self.deploy(STUB_TAGS=f"ghcr.io/example/other:main={self.NEW}")
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertIn("пишет не только root — временный compose.yml туда не кладу", run.stderr)
        self.assertTrue((other / "compose.yml.new").is_file(), "root удалил compose.yml.new в чужой папке")
        self.assertEqual((other / "compose.yml.new").read_text(), "other new\n")

    def test_restore_not_into_linked_dir(self):
        # откат: участник к запуску (up) ставит на место compose.yml ссылку на чужую папку и свой compose.yml.prev,
        # запуск не проходит — restore возвращает compose.yml.prev на место ссылки (mv -T), а не кладёт его в ту папку
        target = self.dir / "rootonly"
        target.mkdir(mode=0o700)
        (self.bin / "project-compose").write_text(self.COMPOSE.replace(
            '  *" up "*)', '  *" up "*) [ "$(grep -c " up " "$STUB_LOG")" -gt 1 ] || { rm -f compose.yml compose.yml.prev; '
            f'ln -s "{target}" compose.yml; echo planted > compose.yml.prev; }};'))
        (self.web / "compose.yml").write_text("services: {}\n")
        run, _ = self.timer(STUB_FAIL_UP="1")
        self.assertEqual(os.listdir(target), [], "root перенёс файл участника в чужую папку")
        self.assertFalse((self.web / "compose.yml").is_symlink())
        self.assertEqual((self.web / "compose.yml").read_text(), "planted\n")

    def test_prev_link_not_into_linked_dir(self):
        # участник выиграл гонку «rm -f compose.yml.prev → ln»: на месте compose.yml.prev — ссылка на папку соседа;
        # ln -PT отказывает (имя занято), жёсткой ссылки на compose.yml в чужой папке нет, выкладка идёт
        other = self.dir / "otherweb"
        other.mkdir(mode=0o700)
        (self.bin / "rm").write_text(f'#!/bin/bash\n{shutil.which("rm")} "$@"; rc=$?\n'
                                     f'[ "$*" != "-f compose.yml.prev" ] || ln -s "{other}" compose.yml.prev\nexit $rc\n')
        (self.bin / "rm").chmod(0o755)
        (self.web / "compose.yml").write_text("services: {evil: {}}\n")
        run, _ = self.timer()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(os.listdir(other), [], "root положил жёсткую ссылку на compose.yml в чужую папку")

    def test_failed_to_marked_manual(self):
        # сбой ручного to — с пометкой в .failed (по ней health-check не отсылает к журналу таймера), сбой таймера — без
        self.deploy("to", self.HASH, STUB_FAIL_UP="1")
        self.assertRegex(self.state("failed"), rf"^\d{{4}}-\d\d-\d\d \d\d:\d\d вручную \(to {self.HASH}\), запуск: работает прежняя версия$")
        self.log.unlink()
        self.deploy(STUB_FAIL_UP="1", STUB_TAGS=f"{self.REPO}:main=sha256:{'3' * 64}")
        self.assertRegex(self.state("failed"), r"^\d{4}-\d\d-\d\d \d\d:\d\d запуск: работает прежняя версия$")

    def test_timer_env_link_refused(self):
        # таймер: участник заменил web/.env ссылкой на .env другого проекта — root по ней не читает: отказ, образ соседа
        # не скачан своим входом в ghcr и не выложен, версия прежняя
        other = self.dir / "other"
        other.mkdir(mode=0o700)
        (other / ".env").write_text("DEPLOY_IMAGE=ghcr.io/example/other:main\ndb_password_other=s3cret\n")
        self.env.unlink()
        self.env.symlink_to(other / ".env")
        run, lines = self.deploy(STUB_TAGS=f"ghcr.io/example/other:main={self.NEW} {self.REPO}:main={self.OLD}")
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertIn("web/.env — ссылка", run.stderr)
        self.assertEqual(lines, [])                                 # ни pull, ни up
        self.assertEqual(self.state("current"), f"{self.REPO}@{self.OLD}")
        self.assertTrue(self.env.is_symlink())
        self.assertEqual(self.leftovers(), [])

    def test_timer_env_fifo_does_not_hang(self):
        # FIFO без писателя на месте web/.env: таймер не ждёт писателя — отказ за секунды, без pull. Страховка стенда:
        # через 10 с FIFO открывается на запись и закрывается — ждущий его читатель получает конец файла
        self.env.unlink()
        os.mkfifo(self.env)
        guard = threading.Timer(10, open_fifo_writer, [self.env])
        guard.start()
        self.addCleanup(guard.cancel)
        start = time.monotonic()
        run, lines = self.deploy()
        self.assertLess(time.monotonic() - start, 5, "project-deploy ждал писателя FIFO")
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertIn("нет DEPLOY_IMAGE", run.stderr)
        self.assertEqual(lines, [])
        self.assertEqual(self.state("current"), f"{self.REPO}@{self.OLD}")

    # image у проекта (роль project пишет его в <проект>.image): образ из .env — только из этого репозитория.
    # Участник вписал в свой .env образ соседа — root не скачивает его своим входом в ghcr
    def pin(self, repo=REPO):
        (self.states / "shop.image").write_text(repo + "\n")

    def test_image_pin_own_image_rolls_out(self):
        self.pin()
        run, lines = self.deploy(STUB_TAGS=f"{self.REPO}:main={self.NEW}")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn(f"docker pull -q {self.REPO}:main", lines)
        self.assertEqual(self.state("current"), f"{self.REPO}@{self.NEW}")

    def test_image_pin_foreign_image_not_pulled(self):
        self.pin()
        before = self.env.read_bytes().replace(b"shop:main", b"other:main")
        self.env.write_bytes(before)
        for args in ((), ("to", self.HASH), ("rollback",)):
            with self.subTest(args=args):
                (self.states / "shop.previous").write_text(f"{self.REPO}@{self.NEW}\n")
                run, lines = self.deploy(*args, STUB_TAGS=f"ghcr.io/example/other:main={self.NEW} "
                                                          f"ghcr.io/example/other:{self.HASH}={self.NEW}")
                self.assertEqual(run.returncode, 1, run.stderr)
                self.assertIn("DEPLOY_IMAGE=ghcr.io/example/other:main — образ не этого проекта "
                              f"(image в server.yml: {self.REPO}); не скачиваю", run.stderr)
                self.assertEqual(lines, [])                         # ни pull, ни tag, ни up
                self.assertEqual(self.env.read_bytes(), before)
                self.assertEqual(self.state("current"), f"{self.REPO}@{self.OLD}")
                self.assertEqual(self.leftovers(), [])

    def test_image_pin_is_whole_repository(self):
        # похожее имя — не тот репозиторий: сравнение строкой целиком, не по началу и не по концу
        self.pin()
        for image in ("ghcr.io/example/shop-evil:main", "ghcr.io/example/shop/x:main", "ghcr.io/example/sho:main",
                      "ghcr.io/example/shopx", "evil.io/ghcr.io/example/shop:main", "ghcr.io/example/shop:main/x",
                      "ghcr.io/example/shop.evil@sha256:" + "2" * 64, "GHCR.IO/example/shop:main"):
            with self.subTest(image=image):
                self.log.unlink(missing_ok=True)
                self.env.write_text(f"DEPLOY_IMAGE={image}\n")
                run, lines = self.deploy(STUB_TAGS=f"{image}={self.NEW}")
                self.assertEqual(run.returncode, 1, run.stderr)
                self.assertIn("образ не этого проекта", run.stderr)
                self.assertEqual(lines, [])

    def test_image_pin_tag_and_digest_forms(self):
        # тег, дайджест, тег с дайджестом, без тега; «:» в адресе реестра — порт, а не тег
        digest = "sha256:" + "2" * 64
        for repo, image in ((self.REPO, f"{self.REPO}@{digest}"), (self.REPO, f"{self.REPO}:main@{digest}"),
                            (self.REPO, self.REPO), ("registry.example.com:5000/shop", "registry.example.com:5000/shop:v1"),
                            ("registry.example.com:5000/shop", "registry.example.com:5000/shop")):
            with self.subTest(image=image):
                self.log.unlink(missing_ok=True)
                self.pin(repo)
                self.env.write_text(f"DEPLOY_IMAGE={image}\n")
                run, lines = self.deploy(STUB_TAGS=f"{image}={self.OLD}")
                self.assertNotIn("не этого проекта", run.stderr)
                self.assertIn(f"docker pull -q {image}", lines)
        self.log.unlink()
        self.env.write_text("DEPLOY_IMAGE=registry.example.com:5001/shop:v1\n")    # другой порт — другой реестр
        run, lines = self.deploy()
        self.assertIn("образ не этого проекта", run.stderr)
        self.assertEqual(lines, [])

    def test_no_image_pin_pulls_as_before(self):
        # image не задан — как раньше: образ из .env скачивается, какой бы ни был (README, «Проекты без root»)
        self.env.write_text("DEPLOY_IMAGE=ghcr.io/example/other:main\n")
        run, lines = self.deploy(STUB_TAGS=f"ghcr.io/example/other:main={self.NEW}")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("docker pull -q ghcr.io/example/other:main", lines)

    def test_image_pin_compose_gets_checked_image(self):
        # compose читает .env шире скрипта: строку export DEPLOY_IMAGE=<чужой> скрипт не берёт, compose — взял бы и скачал
        # от root. Проверенный образ — в окружении вызова compose (оно у compose сильнее .env): заглушка пишет, что получила
        (self.bin / "project-compose").write_text(
            self.COMPOSE.replace("#!/bin/bash\n", '#!/bin/bash\necho "${DEPLOY_IMAGE-нет}" >> "$STUB_LOG.image"\n', 1))
        self.pin()
        own, foreign = f"{self.REPO}:main", "ghcr.io/example/other:main"
        for args in ((), ("to", self.HASH), ("rollback",)):
            with self.subTest(args=args):
                for f in (self.log, self.dir / "log.image"):
                    f.unlink(missing_ok=True)
                (self.states / "shop.current").write_text(f"{self.REPO}@{self.OLD}\n")
                (self.states / "shop.previous").write_text(f"{self.REPO}@{self.NEW}\n")
                self.env.write_text(f"DEPLOY_IMAGE={own}\nexport DEPLOY_IMAGE={foreign}\n")
                run, lines = self.deploy(*args, STUB_TAGS=f"{own}={self.NEW} {self.REPO}:{self.HASH}={self.NEW} {foreign}={self.NEW}")
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertTrue(any(" up " in line for line in lines), lines)
                self.assertNotIn("other", "\n".join(lines))
                self.assertEqual(set((self.dir / "log.image").read_text().splitlines()), {own})

    def test_image_pin_rollback_checks_previous(self):
        # чужой образ, выложенный до image, откат не возвращает: прежняя версия сверяется с image, как образ из .env
        self.pin()
        for prev in (f"ghcr.io/example/other@{self.NEW}", f"ghcr.io/example/shop-evil@{self.NEW}"):
            with self.subTest(prev=prev):
                (self.states / "shop.previous").write_text(prev + "\n")
                run, lines = self.deploy("rollback")
                self.assertEqual(run.returncode, 1, run.stderr)
                self.assertIn(f"прежняя версия {prev} — образ не этого проекта (image в server.yml: {self.REPO}); "
                              "не скачиваю", run.stderr)
                self.assertEqual(lines, [])                         # ни pull, ни tag, ни up
                self.assertEqual(self.state("current"), f"{self.REPO}@{self.OLD}")
                self.assertEqual(self.state("previous"), prev)
        (self.states / "shop.previous").write_text(f"{self.REPO}@{self.NEW}\n")     # своя — откат идёт
        run, lines = self.deploy("rollback")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn(f"docker pull -q {self.REPO}@{self.NEW}", lines)
        self.assertEqual(self.state("current"), f"{self.REPO}@{self.NEW}")

    # --- Папки томов (make_dirs): root не создаёт их по ссылке в web/ (web/ пишут участники) ---
    def volume_source(self, source):
        """project-compose config --format json отдаёт один bind-том с источником source — так его
        видит make_dirs; current стираем, чтобы выкладка новой версии дошла до roll_out → make_dirs"""
        (self.bin / "project-compose").write_text(
            '#!/bin/bash\necho "project-compose $*" >> "$STUB_LOG"\n'
            'case "$*" in\n'
            f'  *"config --format json") printf \'{{"services":{{"a":{{"volumes":[{{"type":"bind","source":"%s"}}]}}}}}}\' "{source}" ;;\n'
            '  *"config --services") echo api ;;\n'
            'esac\n')
        (self.bin / "project-compose").chmod(0o755)
        (self.states / "shop.current").unlink()

    def test_volume_dir_through_link_not_created(self):
        # Участник кладёт в web/ ссылку web/a на чужую папку, в compose — том ./a/b. make_dirs не
        # должен создать b в чужой папке: промежуточная часть пути тома — ссылка. На main install -d
        # идёт по ней и создаёт foreign/b (красный); с заплаткой — отказ и выкладка не идёт
        foreign = self.dir / "foreign"
        foreign.mkdir()
        (self.web / "a").symlink_to(foreign)
        self.volume_source(f"{self.web}/a/b")
        run, lines = self.deploy()
        self.assertFalse((foreign / "b").exists(), "root создал папку в чужой папке через ссылку web/a")
        self.assertTrue((self.web / "a").is_symlink())            # ссылку не тронул
        self.assertEqual(run.returncode, 1, run.stderr)           # выкладка остановлена
        self.assertIn("идёт через ссылку", run.stderr)

    def test_volume_dirs_created_normally(self):
        # Обычный вложенный том ./media/cache (без ссылок) создаётся как прежде, выкладка идёт
        self.volume_source(f"{self.web}/media/cache")
        run, lines = self.deploy()
        self.assertEqual(run.returncode, 0, run.stderr)
        cache = self.web / "media" / "cache"
        self.assertTrue(cache.is_dir() and not cache.is_symlink())
        self.assertEqual(os.stat(cache).st_mode & 0o770, 0o770)   # запись для группы (setgid стенд Mac снимает)
        self.assertEqual(os.stat(cache).st_mode & 0o5000, 0)       # без setuid и sticky (uutils 0.8 — v1.7.2)

    def test_volume_dir_through_deeper_link_not_created(self):
        # Ссылка не первой частью пути: web/x — папка, web/x/y — ссылка на чужую, том ./x/y/z/w
        foreign = self.dir / "foreign"
        foreign.mkdir()
        (self.web / "x").mkdir()
        (self.web / "x" / "y").symlink_to(foreign)
        self.volume_source(f"{self.web}/x/y/z/w")
        run, lines = self.deploy()
        self.assertEqual(list(foreign.iterdir()), [], "root создал папку в чужой папке через ссылку web/x/y")
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertIn("идёт через ссылку", run.stderr)

    def test_volume_dir_swapped_after_mkdir_untouched(self):
        # Гонка: участник успел сразу после mkdir web/media подменить её ссылкой на чужую папку. chmod — на
        # папку, в которой стоим после cd -P и сверки пути, а не по имени: режим чужой папки тот же, отказ
        foreign = self.dir / "foreign"
        foreign.mkdir()
        foreign.chmod(0o755)
        (self.bin / "mkdir").write_text(
            '#!/bin/bash\n/bin/mkdir "$@" || exit\n'
            f'if [ "${{!#}}" = media ]; then rmdir media && ln -s "{foreign}" media; fi\n')
        (self.bin / "mkdir").chmod(0o755)
        self.volume_source(f"{self.web}/media")
        run, lines = self.deploy()
        self.assertEqual(os.stat(foreign).st_mode & 0o7777, 0o755, "root сменил режим чужой папки по подменённой ссылке")
        self.assertEqual(run.returncode, 1, run.stderr)

    def test_volume_link_to_existing_dir_kept(self):
        # Папка тома уже есть, пусть и ссылкой (web/media → store/media): создавать нечего — выкладка идёт,
        # как прежде, ссылка и режим папки не меняются
        store = self.dir / "store" / "media"
        store.mkdir(parents=True)
        store.chmod(0o750)
        (self.web / "media").symlink_to(store)
        self.volume_source(f"{self.web}/media")
        run, lines = self.deploy()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertTrue((self.web / "media").is_symlink())
        self.assertEqual(os.stat(store).st_mode & 0o7777, 0o750)

    # --- to <тег> --wait: ждать, пока CI соберёт образ, — до 45 попыток pull раз в 20 с, без замка выкладки ---
    def loud_flock(self):
        """flock — строкой в журнал стенда, в порядке с docker и sleep (общая заглушка молчит: старые тесты сверяют журнал
        целиком, а замок берут все действия)"""
        (self.bin / "flock").write_text('#!/bin/sh\necho "flock $*" >> "$STUB_LOG"\n')

    def test_wait_tag_appears_then_rolls_out(self):
        # образ появился к 3-й попытке: две неудачи и два sleep 20 — до замка, затем обычный to под замком
        self.loud_flock()
        pull = f"docker pull -q {self.REPO}:{self.HASH}"
        run, lines = self.deploy("to", self.HASH, "--wait", STUB_TAG_AFTER=f"{self.REPO}:{self.HASH}=3")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual([x for x in lines if x in (pull, "sleep 20") or x.startswith("flock")],
                         [pull, "sleep 20", pull, "sleep 20", pull, "flock -w 30 9", pull])
        self.assertIn("жду", run.stdout)
        self.assertIn(f"образ {self.REPO}:{self.HASH} есть — выкладываю", run.stdout)
        self.assertIn(f"\nDEPLOY_IMAGE={self.REPO}:{self.HASH}\n", self.env.read_text())
        self.assertEqual((self.state("current"), self.state("previous")),
                         (f"{self.REPO}@{self.NEW}", f"{self.REPO}@{self.OLD}"))
        self.assertIn(f"infra-log выкладка shop: DEPLOY_IMAGE shop:main → shop:{self.HASH}", lines)

    def test_wait_timeout_changes_nothing(self):
        # образ так и не появился (CI упал, опечатка в теге): 45 попыток — отказ; замок не брали, .env и состояние те же
        self.loud_flock()
        before = self.env.read_bytes()
        run, lines = self.deploy("to", "v9", "--wait")
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertIn("за 15 минут", run.stderr)
        self.assertIn("ничего не менял", run.stderr)
        self.assertIn("manifest unknown", run.stderr)               # последняя строка ошибки docker pull
        self.assertEqual(lines.count(f"docker pull -q {self.REPO}:v9"), 45)
        self.assertEqual(lines.count("sleep 20"), 44)
        self.assertFalse([x for x in lines if not x.startswith(("docker pull ", "sleep "))], lines)   # ни flock, ни up, ни infra-log
        self.assertEqual(self.env.read_bytes(), before)
        self.assertEqual(sorted(p.name for p in self.states.iterdir()), ["shop.current"])        # ни замка, ни отметок
        self.assertEqual(self.state("current"), f"{self.REPO}@{self.OLD}")
        self.assertEqual(self.leftovers(), [])

    def test_wait_only_exact_and_only_for_to(self):
        # --wait — только у to и только так: опечатка или --wait у rollback — отказ до docker, а не выкладка без ожидания
        (self.states / "shop.previous").write_text(f"{self.REPO}@{self.NEW}\n")
        for args in (("rollback", "--wait"), ("deploy", "--wait"), ("rollback", "x", "--wait"),
                     ("to", self.HASH, "--wiat"), ("to", self.HASH, "wait"), ("to", self.HASH, "--wait", "--wait")):
            with self.subTest(args=args):
                self.log.unlink(missing_ok=True)
                run, lines = self.deploy(*args)
                self.assertEqual(run.returncode, 1, run.stderr)
                self.assertIn("project-deploy <проект> [rollback | to <тег> [--wait]]", run.stderr)
                self.assertEqual(lines, [])
        self.assertEqual(self.env.read_text(), self.ENV)
        self.assertEqual((self.state("current"), self.state("previous")),
                         (f"{self.REPO}@{self.OLD}", f"{self.REPO}@{self.NEW}"))

    def test_wait_foreign_image_refused_before_pull(self):
        # в .env — образ соседа: ожидание не скачивает его от root своим входом в ghcr — отказ до первого pull
        self.pin()
        before = self.env.read_bytes().replace(b"shop:main", b"other:main")
        self.env.write_bytes(before)
        run, lines = self.deploy("to", self.HASH, "--wait", STUB_TAGS=f"ghcr.io/example/other:{self.HASH}={self.NEW}")
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertIn("образ не этого проекта", run.stderr)
        self.assertEqual(lines, [])
        self.assertEqual(self.env.read_bytes(), before)

    def test_wait_env_link_refused_before_pull(self):
        # web/.env — ссылка на .env соседа: ожидание по ней не читает — отказ до первого pull
        other = self.dir / "other"
        other.mkdir(mode=0o700)
        (other / ".env").write_text("DEPLOY_IMAGE=ghcr.io/example/other:main\ndb_password_other=s3cret\n")
        self.env.unlink()
        self.env.symlink_to(other / ".env")
        run, lines = self.deploy("to", self.HASH, "--wait",
                                 STUB_TAGS=f"ghcr.io/example/other:{self.HASH}={self.NEW} {self.REPO}:{self.HASH}={self.NEW}")
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertIn("web/.env — ссылка", run.stderr)
        self.assertEqual(lines, [])
        self.assertTrue(self.env.is_symlink())
        self.assertEqual(self.leftovers(), [])

    def test_wait_refusals_without_registry_come_first(self):
        # отказы to, которым реестр не нужен, — сразу, а не после 15 минут ожидания
        for text, mode, error in (
                ("DEPLOY_IMAGE=ghcr.io/example/shop:main\nDEPLOY_IMAGE=ghcr.io/example/shop:dev", 0o750, "несколько строк"),
                ("DEPLOY_IMAGE=ghcr.io/example/shop@sha256:" + "1" * 64, 0o750, "не дайджест"),
                ("DEPLOY_IMAGE=ghcr.io/example/shop:main", 0o770, "пишет не только root")):
            with self.subTest(error=error):
                self.log.unlink(missing_ok=True)
                self.env.write_text(text + "\n")
                self.proj.chmod(mode)
                run, lines = self.deploy("to", self.HASH, "--wait")
                self.assertEqual(run.returncode, 1, run.stderr)
                self.assertIn(error, run.stderr)
                self.assertEqual(lines, [])
                self.assertEqual(self.env.read_text(), text + "\n")


def open_fifo_writer(path):
    """Открыть FIFO на запись без ожидания и закрыть: читатель, который ждёт писателя, получает конец файла.
    Читателя нет — открыть нельзя (ENXIO), ждать некому"""
    try:
        os.close(os.open(path, os.O_WRONLY | os.O_NONBLOCK))
    except OSError:
        pass


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
    команд; затем, если это временный .env (.env.XXXXXX; у compose.yml из образа — свой), участник подменяет ссылкой
    на victim временный файл, если он создан в web/ (swap="tmp"), или сам .env (swap="env"); swap="env-back" — .env
    откладывает в .env.held, на его место ссылку (вернуть прежний файл до сверки stat — крючок STUB_RESTORE_ENV в chown)"""
    real = os.path.realpath(web)
    (bin_dir / "mktemp").write_text(f"""#!/bin/bash
f=$({shutil.which("mktemp")} "$@") || exit
echo "mktemp $f" >> "$STUB_FSLOG"
case $f in */.env.*)
  case {swap} in
    tmp) [ "$(cd "$(dirname "$f")" && pwd -P)" != "{real}" ] || {{ rm -f "$f" && ln -s "{victim}" "$f"; }} ;;
    env) rm -f "{web}/.env" && ln -s "{victim}" "{web}/.env" ;;
    env-back) {shutil.which("mv")} "{web}/.env" "{web}/.env.held" && ln -s "{victim}" "{web}/.env" ;;
  esac ;;
esac
echo "$f"
""")
    (bin_dir / "mktemp").chmod(0o755)


def files_with(root, text):
    """Обычные файлы (не ссылки) под root, в которых есть text"""
    return [str(p) for p in root.rglob("*") if p.is_file() and not p.is_symlink() and text in p.read_text()]


def participant_hook(bin_dir, flag_dir, stub, when, action):
    """Участник проекта, которому web/ открыта на запись, вмешивается посреди команды root: команда stub (заглушка стенда
    или системная) при аргументах when (шаблон case) — только в первый раз за прогон (флаг <stub>.hooked в flag_dir) —
    сначала выполняет action, затем — как была. Повторный вызов меняет только action"""
    hook, real = bin_dir / stub, bin_dir / f"{stub}.real"
    if hook.exists() and not real.exists():
        hook.rename(real)
    elif not real.exists():
        real.symlink_to(shutil.which(stub))
    flag = flag_dir / f"{stub}.hooked"
    hook.write_text(f'#!/bin/bash\ncase "$*" in {when}) [ -e "{flag}" ] || {{ : > "{flag}"; {action}; }} ;; esac\n'
                    f'exec "{real}" "$@"\n')
    hook.chmod(0o755)


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

    def test_env_fifo_before_read_no_hang(self):
        # FIFO на месте .env после снятия stat «до» (крючок — mktemp временного файла): чтение не ждёт писателя — пустое,
        # сверка stat видит другой файл: отказ «меняли» за секунды, .env не заменён. Страховка стенда — писатель через 10 с
        participant_hook(self.bin, self.dir, "mktemp", "*/.env.*", f'rm -f "{self.env}" && mkfifo "{self.env}"')
        guard = threading.Timer(10, open_fifo_writer, [self.env])
        guard.start()
        self.addCleanup(guard.cancel)
        start = time.monotonic()
        run = self.db_env()
        self.assertLess(time.monotonic() - start, 5, "project-db-env ждал писателя FIFO")
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertIn("меняли, пока root его переписывал", run.stderr)
        self.assertTrue(self.env.is_fifo())
        self.assertEqual(self.leftovers(), [])
        self.assertFalse(self.fs("mv"))

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


@unittest.skipUnless(shutil.which("jq"), "нужен jq")
class ProjectRestoreGuard(unittest.TestCase):
    """project-restore не идёт поверх запущенного проекта и не пересекается с автовыкладкой: сначала замок выкладки
    (/var/lib/project-deploy/<проект>.lock, ждёт до 30 с), потом контейнеры проекта в его Docker; замок не дождался,
    контейнеры запущены, Docker не ответил — отказ до restic. Стенд: скрипт со списком проектов и папкой замков
    во временной папке, env restic — пустой файл стенда; flock, docker, project-docker-host, infra-log, restic —
    заглушки, пишут строку в журнал стенда. restic отдаёт пустой список снимков: дальше скрипт останавливается
    сам («Снимок не найден»; в bash 3.2 на Mac — раньше, на mapfile) — это уже не проверка остановки."""

    STUBS = {
        # flock <ключи> <дескриптор>: код — STUB_LOCK_RC (1 — замок не дождались)
        "flock": '#!/bin/sh\necho "flock $*" >> "$STUB_LOG"\nexit "${STUB_LOCK_RC:-0}"\n',
        # docker ps …: печатает STUB_RUNNING (контейнеры проекта), код — STUB_DOCKER_RC (1 — Docker не ответил);
        # в журнал — и DOCKER_HOST, с которым его позвали (unset — не задан)
        "docker": '#!/bin/sh\necho "docker $* DOCKER_HOST=${DOCKER_HOST-unset}" >> "$STUB_LOG"\n'
                  '[ -z "${STUB_RUNNING:-}" ] || printf "%s\\n" "$STUB_RUNNING"\nexit "${STUB_DOCKER_RC:-0}"\n',
        # Docker проекта: STUB_SOCK — сокет Docker проекта без root, пусто — общий
        "project-docker-host": '#!/bin/sh\necho "${STUB_SOCK:-}"\n',
        "infra-log": '#!/bin/sh\necho "infra-log $*" >> "$STUB_LOG"\n',
        "restic": '#!/bin/sh\necho "restic $*" >> "$STUB_LOG"\necho "[]"\n',
    }
    PS = "docker ps -q --filter label=com.docker.compose.project=shop"

    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.bin, self.locks = self.dir / "bin", self.dir / "locks"
        for d in (self.bin, self.locks):
            d.mkdir()
        for name, text in self.STUBS.items():
            (self.bin / name).write_text(text)
            (self.bin / name).chmod(0o755)
        projects = self.dir / "projects.json"
        projects.write_text('[{"name":"shop","db":"postgres"}]\n')
        script = (ROOT / "roles/backup/files/project-restore").read_text()
        for old, new in (("/etc/restic/projects.json", f'"{projects}"'), ("/var/lib/project-deploy", f'"{self.locks}"')):
            if old not in script:
                raise AssertionError(f"в project-restore нет «{old}» — стенду нечего подменить")
            script = script.replace(old, new)
        self.script = self.dir / "project-restore"
        self.script.write_text(script)
        self.restic_env = self.dir / "env"
        self.restic_env.write_text("")
        self.log = self.dir / "log"

    def restore(self, name="shop", **stubs):
        env = {k: v for k, v in os.environ.items() if k != "DOCKER_HOST"}
        env.update(PATH=f"{self.bin}:{os.environ['PATH']}", STUB_LOG=str(self.log), **stubs)
        run = subprocess.run(["bash", str(self.script), name, str(self.restic_env)], env=env, cwd=self.dir,
                             capture_output=True, text=True)
        lines = self.log.read_text().splitlines() if self.log.exists() else []
        return run, [x for x in lines if not x.startswith("infra-log ")], lines

    def assertRefused(self, run, lines, text):
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertIn(text, run.stderr)
        self.assertIn("ничего не менял", run.stderr)
        self.assertFalse([x for x in lines if x.startswith("restic ")], lines)

    def test_running_project_refused(self):
        run, calls, lines = self.restore(STUB_RUNNING="abc123")
        self.assertRefused(run, calls, "Проект shop запущен — остановите: sudo project-compose shop down")
        self.assertEqual(calls, ["flock -w 30 9", f"{self.PS} DOCKER_HOST=unset"])   # замок — первым, Docker — общий
        self.assertFalse([x for x in lines if "начато" in x], lines)
        self.assertTrue((self.locks / "shop.lock").exists())

    def test_deploy_lock_busy_refused_before_docker(self):
        run, calls, _ = self.restore(STUB_LOCK_RC="1")
        self.assertRefused(run, calls, "shop: идёт выкладка")
        self.assertEqual(calls, ["flock -w 30 9"])

    def test_rootless_project_checked_in_its_docker(self):
        sock = "unix:///run/user/1001/docker.sock"
        run, calls, _ = self.restore(STUB_SOCK=sock, STUB_RUNNING="abc123")
        self.assertRefused(run, calls, "project-compose shop down")
        self.assertIn(f"{self.PS} DOCKER_HOST={sock}", calls)
        # Docker проекта без root ведёт его пользователь — ответ для root только данные: ничего не исполняется
        run, calls, _ = self.restore(STUB_SOCK=sock, STUB_RUNNING="$(touch pwned)\n`touch pwned`\n../../etc/passwd")
        self.assertRefused(run, calls, "project-compose shop down")
        self.assertFalse((self.dir / "pwned").exists())

    def test_docker_silent_refused(self):
        run, calls, _ = self.restore(STUB_DOCKER_RC="1")
        self.assertRefused(run, calls, "Docker не ответил — не могу проверить, что проект shop остановлен")

    def test_stopped_project_goes_on_under_lock(self):
        run, calls, _ = self.restore()
        self.assertNotIn("ничего не менял", run.stderr)
        self.assertEqual(calls[:2], ["flock -w 30 9", f"{self.PS} DOCKER_HOST=unset"])
        self.assertTrue(calls[2].startswith("restic snapshots --json --tag project:shop"), calls)
        self.assertTrue((self.locks / "shop.lock").exists())

    def test_no_deploy_dir_no_lock(self):
        self.locks.rmdir()                                        # нет автовыкладки на сервере — нет и замка
        run, calls, _ = self.restore(STUB_RUNNING="abc123")
        self.assertRefused(run, calls, "project-compose shop down")
        self.assertEqual(calls, [f"{self.PS} DOCKER_HOST=unset"])
        self.assertFalse(self.locks.exists())

    def test_unknown_project_refused_before_lock(self):
        run, calls, _ = self.restore("../x")                      # имя — путь: замок по нему не создаётся
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertIn("не описан на этом сервере", run.stderr)
        self.assertEqual(calls, [])
        self.assertEqual(list(self.locks.iterdir()), [])
        self.assertFalse((self.dir / "x.lock").exists())


class SettingsDiffMasked(unittest.TestCase):
    """infra: diff server.yml в журнале событий — полный apply (log_settings_change в run-unit) и infra edit
    (changes: экран и журнал). Значения ключей с token, password, secret… — ***, остальное и открытые ключи
    людей — как есть. Стенд: infra из репозитория, /etc/infra и /var/lib/infra — во временной папке; Ansible,
    Python (проверка YAML), infra-log, id, flock, редактор — заглушки; mktemp --suffix (на Mac нет) — тоже."""

    OLD = ("server_name: srv\n"
           "ghcr_token: oldtok777\n"
           "people:\n"
           "  ivan:\n"
           '    key: "ssh-ed25519 AAAAold ivan@laptop"\n'
           "projects:\n"
           "  shop:\n"
           "    net: 11\n"
           "    memory: 1g\n")
    NEW = ("server_name: srv\n"
           "ghcr_token: abc123secret\n"
           "people:\n"
           "  ivan:\n"
           '    key: "ssh-ed25519 AAAAnew ivan@laptop"\n'
           "projects:\n"
           "  shop:\n"
           "    net: 11\n"
           "    memory: 2g\n"
           '    db_password: "p4ss"\n')
    STUBS = {
        "id": '#!/bin/sh\n[ "$1" = -u ] && echo 0 || exec /usr/bin/id "$@"\n',
        "flock": "#!/bin/sh\nexit 0\n",
        "mktemp": ('#!/bin/sh\ncase $1 in --suffix=*) s=${1#--suffix=}; shift\n'
                   '  f=$(/usr/bin/mktemp "$@") && mv "$f" "$f$s" && echo "$f$s"; exit ;; esac\n'
                   'exec /usr/bin/mktemp "$@"\n'),
        "editor": '#!/bin/sh\ncp "$STUB_NEW" "$1"\n',                              # правка — новый server.yml
    }

    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.bin, self.etc, self.state, engine = (self.dir / x for x in ("bin", "etc", "state", "engine"))
        for d in (self.bin, self.etc, self.state, engine / "roles/base/files", engine / ".venv/bin"):
            d.mkdir(parents=True)
        infra = (ROOT / "infra").read_text()
        for old, new in (("\nCONF=/etc/infra\n", f'\nCONF="{self.etc}"\n'),
                         ("\nSTATE=/var/lib/infra ", f'\nSTATE="{self.state}" '),
                         ('"${ARGS[@]}"', '${ARGS[@]+"${ARGS[@]}"}'),
                         ('"${CLEANUP[@]}"', '${CLEANUP[@]+"${CLEANUP[@]}"}')):
            if old not in infra:
                raise AssertionError(f"в infra нет «{old.strip()}» — стенду нечего подменить")
            infra = infra.replace(old, new)
        files = {**{self.bin / name: text for name, text in self.STUBS.items()},
                 engine / "infra": infra,
                 engine / "roles/base/files/infra-log":
                     '#!/bin/sh\necho "infra-log $*" >> "$STUB_LOG"\n[ "$1" != - ] || cat >> "$STUB_LOG"\n',
                 engine / ".venv/bin/ansible-playbook": "#!/bin/sh\necho PLAY RECAP\necho 'srv : ok=40 changed=0'\n",
                 engine / ".venv/bin/python": "#!/bin/sh\ncat >/dev/null\n"}                # YAML в порядке
        for path, text in files.items():
            path.write_text(text)
            path.chmod(0o755)
        (self.etc / "server.yml").write_text(self.OLD)
        (self.etc / "secrets.yml").write_text("")
        self.new = self.dir / "new.yml"
        self.new.write_text(self.NEW)
        self.log = self.dir / "stand.log"
        self.log.write_text("")
        self.infra = engine / "infra"

    def infra_run(self, *args):
        env = {**os.environ, "PATH": f"{self.bin}:{os.environ['PATH']}", "STUB_LOG": str(self.log),
               "STUB_NEW": str(self.new), "SUDO_EDITOR": str(self.bin / "editor")}
        run = subprocess.run(["bash", str(self.infra), *args], input="", env=env, capture_output=True, text=True,
                             timeout=60)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        return run

    def assertMasked(self, text):
        self.assertIn("+ghcr_token: ***", text)
        self.assertIn("-ghcr_token: ***", text)
        self.assertIn("+    db_password: ***", text)
        for secret in ("oldtok777", "abc123secret", "p4ss"):
            self.assertNotIn(secret, text)
        self.assertIn("-    memory: 1g", text)                                   # остальное — как есть
        self.assertIn("+    memory: 2g", text)
        self.assertIn('+    key: "ssh-ed25519 AAAAnew ivan@laptop"', text)       # открытый ключ — не секрет

    def test_full_apply(self):
        # служба infra-apply: копия server.yml прошлого полного apply — старая, в /etc/infra — новая
        shutil.copy(self.etc / "server.yml", self.state / "server.yml")
        (self.etc / "server.yml").write_text(self.NEW)
        self.infra_run("run-unit", "site.yml")
        log = self.log.read_text()
        self.assertIn("infra-log настройки (server.yml) изменены с прошлого полного apply:", log)
        self.assertMasked(log)

    def test_edit(self):
        run = self.infra_run("edit")
        self.assertEqual((self.etc / "server.yml").read_text(), self.NEW)
        log = self.log.read_text()
        self.assertIn("infra-log edit: server.yml изменён", log)
        self.assertMasked(log)
        self.assertMasked(run.stdout)                                             # и на экране


if __name__ == "__main__":
    unittest.main()
