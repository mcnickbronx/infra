"""Активные настройки опубликованного образца проходят настоящий localhost-preflight."""
import copy
import json
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from ansible.parsing.dataloader import DataLoader

ROOT = pathlib.Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "server.yml.example"
PLACEHOLDER = "AAAA...замените..."
# Синтетический payload: только формат, который проверяет preflight, не настоящий ключ.
PAYLOAD = "A" * 64
KEY_FIELDS = {
    ("admin_keys",): "ssh-ed25519 AAAA...замените... you@laptop\n",
    ("people", "ivan", "key"): "ssh-ed25519 AAAA...замените... ivan@laptop",
    ("people", "olga", "key"): ("ssh-ed25519 AAAA...замените... olga@laptop\n"
                                 "ssh-ed25519 AAAA...замените... olga@desktop\n"),
    ("people", "anna", "key"): "ssh-ed25519 AAAA...замените... anna@laptop",
}


class ExamplesPreflight(unittest.TestCase):
    def setUp(self):
        loader = DataLoader()
        try:
            self.settings = loader.load_from_file(str(EXAMPLE))
        except Exception as exc:
            self.fail(f"server.yml.example: не удалось прочитать YAML: {exc}")
        finally:
            loader.cleanup_all_tmp_files()
        self.assertIsInstance(self.settings, dict, "server.yml.example: нужен YAML-словарь")

    def prepared(self, *, email=False):
        settings = copy.deepcopy(self.settings)
        for path, expected in KEY_FIELDS.items():
            owner = settings
            for part in path[:-1]:
                self.assertIsInstance(owner, dict, f"server.yml.example: {'.'.join(path)}")
                self.assertIn(part, owner, f"server.yml.example: {'.'.join(path)} отсутствует")
                owner = owner[part]
            self.assertIsInstance(owner, dict, f"server.yml.example: {'.'.join(path)}")
            self.assertEqual(owner.get(path[-1]), expected,
                             f"server.yml.example: неожиданная SSH-заготовка {'.'.join(path)}")
            # Сохраняем тип ключа, комментарии, все строки и завершающий перевод строки.
            owner[path[-1]] = expected.replace(PLACEHOLDER, PAYLOAD)
        if email:
            self.assertEqual(settings.get("acme_email"), "you@example.org",
                             "server.yml.example: неожиданная email-заготовка")
            settings["acme_email"] = "admin@fixture.test"
        return settings

    def run_preflight(self, settings):
        with tempfile.TemporaryDirectory(prefix="infra-example-") as temporary:
            work = pathlib.Path(temporary)
            (work / "settings.json").write_text(json.dumps(settings), encoding="utf-8")
            inventory = {"all": {"hosts": {"localhost": {
                "ansible_connection": "local",
                "ansible_python_interpreter": "{{ ansible_playbook_python }}",
            }}}}
            (work / "inventory.json").write_text(json.dumps(inventory), encoding="utf-8")
            # Extra vars важнее vars_files: даже одноимённый ключ образца не должен
            # подменить проверяемый словарь, пустые secrets или локальный исполнитель.
            controls = {"server_settings": settings, "secrets_file": {},
                        "ansible_connection": "local", "ansible_host": "localhost",
                        "ansible_become": False, "ansible_python_interpreter": sys.executable}
            (work / "controls.json").write_text(json.dumps(controls), encoding="utf-8")
            playbook = [{
                "name": "server.yml.example — только preflight",
                "hosts": "localhost", "connection": "local",
                "gather_facts": False, "become": False,
                # Последний vars_file важнее defaults: проверяем именно активный образец.
                "vars_files": [str(ROOT / "group_vars/all/main.yml"),
                               str(ROOT / "group_vars/all/derived.yml"),
                               str(work / "settings.json")],
                "tasks": [
                    {"name": "Факты тестового сервера",
                     "ansible.builtin.import_tasks": str(ROOT / "tests/facts.yml")},
                    {"name": "Настоящий preflight",
                     "ansible.builtin.import_role": {"name": str(ROOT / "roles/preflight")}},
                ],
            }]
            (work / "playbook.json").write_text(json.dumps(playbook), encoding="utf-8")
            try:
                process = subprocess.Popen(
                    ["ansible-playbook", "-i", str(work / "inventory.json"),
                     "--extra-vars", "@" + str(work / "controls.json"),
                     str(work / "playbook.json")],
                    cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, start_new_session=True,
                )
            except OSError as exc:
                self.fail(f"server.yml.example: не удалось запустить ansible-playbook: {exc}")
            try:
                output, _ = process.communicate(timeout=90)
            except subprocess.TimeoutExpired:
                self.fail("server.yml.example: preflight превысил 90 секунд")
            finally:
                # Лидер мог уже выйти, пока потомок держит stdout открытым.
                # Группа принадлежит только этому запуску (start_new_session=True).
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.communicate()
            return process.returncode, output

    def test_unfilled_ssh_placeholder_is_rejected(self):
        code, output = self.run_preflight(self.settings)
        self.assertEqual(code, 2, f"server.yml.example: ожидался отказ SSH-preflight\n{output}")
        self.assertIn("admin_keys: незаполненный или испорченный SSH-ключ", output,
                      f"server.yml.example: отказ не по SSH-заготовке\n{output}")

    def test_unfilled_email_placeholder_is_rejected(self):
        code, output = self.run_preflight(self.prepared())
        self.assertEqual(code, 2, f"server.yml.example: ожидался отказ email-preflight\n{output}")
        self.assertIn("Заполните (сейчас там заготовка): acme_email", output,
                      f"server.yml.example: отказ не по email-заготовке\n{output}")

    def test_filled_example_passes_preflight(self):
        code, output = self.run_preflight(self.prepared(email=True))
        self.assertEqual(code, 0, f"server.yml.example: preflight отклонил заполненный образец\n{output}")


class PreflightProcessCleanup(unittest.TestCase):
    def test_timeout_cleans_descendant_after_leader_exit(self):
        real_popen = subprocess.Popen
        launched = []
        with tempfile.TemporaryDirectory(prefix="infra-example-cleanup-") as temporary:
            pidfile = pathlib.Path(temporary) / "child.pid"
            code = ("import os,pathlib,time\n"
                    "child = os.fork()\n"
                    "if child:\n"
                    f"    pathlib.Path({str(pidfile)!r}).write_text(str(child))\n"
                    "else:\n"
                    "    time.sleep(60)\n")

            def launch(arguments, **kwargs):
                process = real_popen([sys.executable, "-c", code], **kwargs)
                launched.append(process)
                # Доказанный порядок: лидер вышел, потомок ещё держит pipe.
                self.assertEqual(process.wait(timeout=5), 0)
                proxy = mock.Mock(wraps=process, pid=process.pid)
                # Ускоряем только этот воспроизводитель, рабочий timeout остаётся 90.
                proxy.communicate.side_effect = lambda timeout=None: process.communicate(
                    timeout=0.2 if timeout is not None else None)
                return proxy

            try:
                with mock.patch.object(subprocess, "Popen", launch):
                    with self.assertRaisesRegex(AssertionError, "preflight превысил 90 секунд"):
                        ExamplesPreflight().run_preflight({})
                child = int(pidfile.read_text())
                state = subprocess.run(["ps", "-p", str(child), "-o", "stat="],
                                       capture_output=True, text=True, timeout=5)
                self.assertTrue(state.returncode != 0 or state.stdout.strip().startswith("Z"),
                                f"после timeout остался живой потомок {child}: {state.stdout}")
            finally:
                # Регрессия должна убирать свой стенд и при сломанном helper.
                for process in launched:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.communicate(timeout=5)
