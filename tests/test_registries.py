"""Настоящие preflight и docker_login; локальная action-заглушка вместо Docker/сети."""
import copy
import json
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import unittest

import test_scripts

ROOT = pathlib.Path(__file__).resolve().parent.parent
HOSTS = ["ghcr.io", "registry.gitlab.com", "registry.example.com:5050"]
REGISTRIES = [dict(host=h, user_key=f"registry_user_{i}", token_key=f"registry_token_{i}")
              for i, h in enumerate(HOSTS)]
MARKERS = {key: f"SYNTHETIC_REGISTRY_MARKER_{key}" for key in
           ["ghcr_user", "ghcr_token"] + [r[k] for r in REGISTRIES for k in ("user_key", "token_key")]}

# Запускается в процессе Ansible; наружу только host и результат сравнения пар credentials.
# Значения не попадают ни в argv, ни в результат модуля, ни в протокол вызовов.
ACTION = '''from ansible.plugins.action import ActionBase
import json
from pathlib import Path
class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        args = self._task.args
        host = args['registry_url']
        expected = task_vars['expected_credentials'].get(host)
        matched = expected == [args['username'], args['password']]
        path = Path(task_vars['probe_dir']) / (task_vars['inventory_hostname'] + '.login')
        with path.open('a') as stream:
            stream.write(json.dumps(dict(host=host, matched=matched)) + '\\n')
        return dict(changed=False, failed=not matched, matched=matched)
'''


def matrix():
    settings = dict(server_name="registry-fixture", admin_keys="ssh-ed25519 " + "A" * 64,
                    admin_ips=["192.0.2.10"], acme_email="admin@fixture.test",
                    projects={"shop": dict(net=42, rootless=True, autodeploy=True,
                                           image="registry.gitlab.com/group/subgroup/shop")})
    cases = {}

    def add(name, regs=REGISTRIES, *, ok=True, reason="", secrets=None, changes=None, project=None):
        config = copy.deepcopy(settings)
        if regs is not ...:
            config["container_registries"] = copy.deepcopy(regs)
        if project:
            config["projects"]["shop"].update(project)
        config.update(changes or {})
        credentials = dict(MARKERS if secrets is None else secrets)
        selected = regs if isinstance(regs, list) else []
        if regs is ...:
            selected = [dict(host="ghcr.io", user_key="ghcr_user", token_key="ghcr_token")]
        expected = {r["host"]: [credentials.get(r["user_key"]), credentials.get(r["token_key"])]
                    for r in selected if isinstance(r, dict) and set(r) == {"host", "user_key", "token_key"}
                    and isinstance(r["host"], str) and isinstance(r["user_key"], str)
                    and isinstance(r["token_key"], str)}
        active = config["projects"].get("shop", {}).get("autodeploy", False)
        cases[name] = dict(settings=config, secrets_file=credentials, expected_ok=ok,
                           expected_credentials=expected, expected_hosts=list(expected) if ok and active else [],
                           reason=reason)

    add("legacy", ..., secrets={k: MARKERS[k] for k in ("ghcr_user", "ghcr_token")},
        project={"image": "ghcr.io/example/shop"})
    add("legacy-public-port", ..., project={"image": "registry.example.com:5050/group/shop"})
    add("gitlab", [REGISTRIES[1]], secrets={k: MARKERS[k] for k in ("registry_user_1", "registry_token_1")})
    add("selfhost", [REGISTRIES[2]], project={"image": "registry.example.com:5050/group/shop"})
    add("mixed")
    add("disabled-empty-secrets", secrets={}, project={"autodeploy": False})
    add("disabled-empty-list", [], secrets={}, changes={"projects": {}})
    add("legacy-no-image", ..., changes={"projects": {"shop": dict(net=42, autodeploy=True)}})
    add("explicit-no-image", changes={"projects": {"shop": dict(net=42, autodeploy=True)}})
    for name, value in [("null", None), ("string", "bad"), ("mapping", {}), ("empty", []),
                        ("entry-string", ["bad"]), ("entry-null", [None]),
                        ("missing", [dict(host="ghcr.io", user_key="ghcr_user")]),
                        ("extra", [{**REGISTRIES[1], "password": MARKERS["ghcr_token"]}]),
                        ("host-type", [{**REGISTRIES[1], "host": 12}]),
                        ("key-type", [{**REGISTRIES[1], "token_key": []}])]:
        add("bad-" + name, value, ok=False, reason="container_registries — список")
    for i, host in enumerate(["https://registry.gitlab.com", "registry.gitlab.com/path", "user@registry.gitlab.com",
                              "registry.gitlab.com ", "registry.gitlab.com\n", "registry.gitlab.com\t", "-registry.test",
                              "registry..test", "Registry.gitlab.com", "registry.test:0", "registry.test:65536",
                              "[2001:db8::1]:5050", "256.2.3.4", "registry.test:-1", "registry.test:"]):
        add(f"bad-host-{i}", [{**REGISTRIES[1], "host": host}], ok=False, reason="host — DNS")
    add("bad-duplicate", [REGISTRIES[1], REGISTRIES[1]], ok=False, reason="host — DNS")
    add("bad-host-secret", [{**REGISTRIES[1], "host": "https://" + MARKERS["ghcr_token"] + "@registry.test"}],
        ok=False, reason="host — DNS")
    for i, key in enumerate(["{{ lookup('env', 'TOKEN') }}", "x/path", "x-token", "x\n", "", "0token"]):
        add(f"bad-key-{i}", [{**REGISTRIES[1], "token_key": key}], ok=False, reason="user_key/token_key")
    add("bad-same-key", [{**REGISTRIES[1], "token_key": "registry_user_1"}], ok=False, reason="user_key/token_key")
    add("bad-key-secret", [{**REGISTRIES[1], "token_key": MARKERS["ghcr_token"]}],
        ok=False, reason="user_key/token_key")
    for i, value in enumerate(["", "  ", None, 42, False, ["bad"]]):
        add(f"bad-credential-{i}", [REGISTRIES[1]], ok=False, reason="непустые строковые",
            secrets={"registry_user_1": MARKERS["registry_user_1"], "registry_token_1": value})
    add("bad-missing-user", [REGISTRIES[1]], ok=False, reason="непустые строковые",
        secrets={"registry_token_1": MARKERS["registry_token_1"]})
    add("bad-user-type", [REGISTRIES[1]], ok=False, reason="непустые строковые",
        secrets={"registry_user_1": 42, "registry_token_1": MARKERS["registry_token_1"]})
    add("bad-empty-user", [REGISTRIES[1]], ok=False, reason="непустые строковые",
        secrets={"registry_user_1": "", "registry_token_1": MARKERS["registry_token_1"]})
    add("bad-unknown-key", [{**REGISTRIES[1], "token_key": "absent_token"}], ok=False, reason="непустые строковые")
    add("bad-server-credential", ..., ok=False, reason="только в secrets.yml",
        changes={"ghcr_token": MARKERS["ghcr_token"]})
    add("bad-foreign-image", [REGISTRIES[1]], ok=False, reason="host image отсутствует",
        project={"image": "registry.example.com:5050/group/shop"})
    add("ipv4-port", [{**REGISTRIES[1], "host": "192.0.2.8:65535"}],
        project={"image": "192.0.2.8:65535/group/shop"})
    return cases


class Registries(unittest.TestCase):
    def test_preflight_and_real_login_loop(self):
        cases = matrix()
        with tempfile.TemporaryDirectory(prefix="infra-registries-", dir=os.environ.get("REGISTRY_TEST_TMP")) as temp:
            work = pathlib.Path(temp)
            probe = work / "probe"
            probe.mkdir()
            collection = work / "collections/ansible_collections/community/docker/plugins"
            (collection / "action").mkdir(parents=True)
            (collection / "modules").mkdir()
            (collection / "action/docker_login.py").write_text(ACTION)
            (collection / "modules/docker_login.py").write_text("# Локальная заглушка action, модуль не исполняется.\n")
            inventory = {"all": {"hosts": {}}}
            for name, case in cases.items():
                settings_file = work / (name + ".json")
                settings_file.write_text(json.dumps(case["settings"]))
                inventory["all"]["hosts"][name] = {
                    "server_settings": case["settings"], "settings_file": str(settings_file),
                    "secrets_file": case["secrets_file"], "expected_ok": case["expected_ok"],
                    "expected_reason": case["reason"], "expected_credentials": case["expected_credentials"],
                }
            (work / "inventory.json").write_text(json.dumps(inventory))
            play = [dict(name="Реестры без Docker и серверов", hosts="all", gather_facts=False, become=False,
                         vars_files=[str(ROOT / "group_vars/all/main.yml"), str(ROOT / "group_vars/all/derived.yml")],
                         vars=dict(probe_dir=str(probe), ansible_connection="local", ansible_host="localhost",
                                   ansible_python_interpreter=sys.executable), tasks=[
                             {"name": "Синтетические настройки", "ansible.builtin.include_vars": "{{ settings_file }}", "no_log": True},
                             {"name": "Факты", "ansible.builtin.import_tasks": str(ROOT / "tests/facts.yml")},
                             {"name": "Ожидаемый результат", "ansible.builtin.set_fact": {"preflight_ok": True, "reason_ok": True}},
                             {"name": "Настоящий preflight", "block": [
                                 {"name": "Вся роль preflight", "ansible.builtin.import_role": {"name": str(ROOT / "roles/preflight")}}],
                              "rescue": [{"name": "Безопасный исход", "ansible.builtin.set_fact": {
                                  "preflight_ok": False,
                                  "reason_ok": "{{ expected_reason in (ansible_failed_result.msg ~ ' ' ~ (ansible_failed_result.results | default([]) | map(attribute='msg') | join(' '))) }}"}}]},
                             {"name": "Настоящий цикл входа", "ansible.builtin.include_tasks": str(ROOT / "roles/project/tasks/registries.yml"),
                              "when": "preflight_ok"},
                             {"name": "Итог матрицы", "ansible.builtin.assert": {
                                 "that": ["preflight_ok == expected_ok", "reason_ok"], "quiet": True}},
                         ])]
            (work / "playbook.json").write_text(json.dumps(play))
            # Настройки изолированы папкой опыта, глобальная среда Ansible не меняется.
            env = {**os.environ, "ANSIBLE_COLLECTIONS_PATH": str(work / "collections"),
                   "ANSIBLE_LOCAL_TEMP": str(work / "ansible-local"),
                   "ANSIBLE_REMOTE_TEMP": str(work / "ansible-remote"), "ANSIBLE_NOCOLOR": "1"}
            args = ["ansible-playbook", "-i", str(work / "inventory.json"), str(work / "playbook.json")]
            process = subprocess.Popen(args, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       text=True, start_new_session=True)
            try:
                output, _ = process.communicate(timeout=180)
            finally:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.communicate()
            protocols = output + json.dumps(args) + "".join(p.read_text() for p in probe.iterdir())
            for marker in MARKERS.values():
                self.assertNotIn(marker, protocols, "синтетический credential попал в протокол")
            evidence = os.environ.get("REGISTRY_EVIDENCE_DIR")
            if evidence:
                pathlib.Path(evidence).mkdir(parents=True, exist_ok=True)
                pathlib.Path(evidence, "registries-ansible.log").write_text(output)
            self.assertEqual(process.returncode, 0, output)
            summary = {}
            for name, case in cases.items():
                with self.subTest(case=name):
                    log = probe / (name + ".login")
                    calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
                    self.assertEqual([c["host"] for c in calls], case["expected_hosts"])
                    self.assertTrue(all(c["matched"] for c in calls))
                    summary[name] = dict(preflight=case["expected_ok"], calls=calls)
            if evidence:
                pathlib.Path(evidence, "registries-results.json").write_text(json.dumps(summary, indent=2))


class RegistrySecretChanges(test_scripts.SecretSums):
    def test_registry_token_changes_only_name(self):
        text = (ROOT / "infra").read_text()
        start = text.index("\nchanges() {\n")
        self.functions += text[start:text.index("\n}\n", start) + 3]
        with tempfile.TemporaryDirectory(dir=os.environ.get("REGISTRY_TEST_TMP")) as temp:
            old, new = pathlib.Path(temp) / "old.yml", pathlib.Path(temp) / "new.yml"
            old.write_text('registry_token_gitlab: "SYNTHETIC_OLD_TOKEN"\n')
            new.write_text('registry_token_gitlab: "SYNTHETIC_NEW_TOKEN"\n')
            output = self.run_bash('changes secrets.yml "$BEFORE" "$AFTER"', BEFORE=str(old), AFTER=str(new))
            self.assertEqual(output, "сменились registry_token_gitlab\n")


class GitLabCIExample(unittest.TestCase):
    def test_yaml_and_commands_with_local_docker_stub(self):
        import yaml
        pipeline = yaml.safe_load((ROOT / "docs/gitlab-ci.yml.example").read_text())
        job = pipeline["build_image"]
        self.assertEqual(pipeline["stages"], ["build"])
        self.assertNotIn("needs", job)
        self.assertEqual(job["variables"]["DOCKER_TLS_VERIFY"], "1")
        self.assertEqual(job["variables"]["DOCKER_HOST"], "tcp://docker:2376")
        script = "\n".join(job["script"])
        with tempfile.TemporaryDirectory(dir=os.environ.get("REGISTRY_TEST_TMP")) as temp:
            work = pathlib.Path(temp)
            docker = work / "docker"
            docker.write_text('''#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
if args[0] == 'login':
    assert args == ['login', os.environ['CI_REGISTRY'], '--username', os.environ['CI_REGISTRY_USER'], '--password-stdin']
    assert sys.stdin.read() == os.environ['CI_REGISTRY_PASSWORD']
    args = ['login', os.environ['CI_REGISTRY'], 'credentials_matched=true']
with open(os.environ['CI_STUB_LOG'], 'a') as stream:
    stream.write(json.dumps(args) + '\\n')
''')
            docker.chmod(0o755)
            sha = "b" * 40
            for host in ("registry.gitlab.com", "registry.example.com:5050"):
                with self.subTest(host=host):
                    log = work / "calls"
                    log.unlink(missing_ok=True)
                    image = host + "/group/subgroup/shop"
                    env = {**os.environ, "PATH": str(work) + ":" + os.environ["PATH"],
                           "CI_REGISTRY": host, "CI_REGISTRY_IMAGE": image, "CI_COMMIT_SHA": sha,
                           "CI_COMMIT_REF_SLUG": "main", "CI_REGISTRY_USER": "SYNTHETIC_CI_USER",
                           "CI_REGISTRY_PASSWORD": "SYNTHETIC_CI_PASSWORD", "CI_STUB_LOG": str(log)}
                    run = subprocess.run(["bash", "-eu", "-c", script], env=env, cwd=work,
                                         capture_output=True, text=True, timeout=15)
                    self.assertEqual(run.returncode, 0, run.stderr)
                    output = run.stdout + run.stderr + log.read_text()
                    self.assertNotIn(env["CI_REGISTRY_PASSWORD"], output)
                    self.assertNotIn(env["CI_REGISTRY_USER"], output)
                    calls = [json.loads(line) for line in log.read_text().splitlines()]
                    self.assertEqual([c[0] for c in calls], ["login", "build", "push", "tag", "push"])
                    self.assertIn("org.opencontainers.image.revision=" + sha, calls[1])
                    self.assertIn("org.opencontainers.image.version=", calls[1])
                    self.assertEqual(calls[2], ["push", image + ":" + sha])
                    self.assertEqual(calls[3], ["tag", image + ":" + sha, image + ":main"])
                    self.assertEqual(calls[4], ["push", image + ":main"])
