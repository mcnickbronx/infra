"""А2: целая команда, синтетический restic, настоящие временные PostgreSQL/restore.

Без установки: RESTORE_CHECK_PG_BIN=/path/to/postgresql/bin python3 -m unittest
discover -s tests -p test_restore_check.py -v. Без server binaries SQL-класс явно
пропускается; это не подтверждение SQL-безопасности. Тест никогда не использует
существующий кластер: отдельные datadir/socket/случайный порт, SYNTHETIC данные.
"""
from datetime import datetime, timezone
import fcntl
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "roles/backup/files/project-restore-check"
STUB = r'''
import json, os, pathlib, signal, subprocess, sys, time
root = pathlib.Path(os.environ['STAND'])
name, args = pathlib.Path(sys.argv[0]).name, sys.argv[1:]
config = json.loads((root / 'config').read_text())
def record(action):
    with (root / 'calls').open('a') as f:
        f.write(json.dumps(dict(command=name, args=args, action=action,
                               user=os.environ.get('PGUSER'), db=os.environ.get('PGDATABASE'),
                               pid=int(os.environ.get('CHECK_PID',os.getppid())))) + '\n')
def after(action):
    if config.get('signal') == action:
        os.kill(int(os.environ.get('CHECK_PID', os.getppid())), config.get('signal-number', signal.SIGTERM))
        time.sleep(.1)
def failed(action):
    if config.get('fail') == action:
        record('failure:' + action); sys.exit(1)
if name == 'runuser':
    assert args[:3] == ['-u','postgres','--']
    env = dict(os.environ, PGHOST=os.environ['SQL_SOCKET'], PGPORT=os.environ['SQL_PORT'],
               PGUSER='probe_admin', CHECK_PID=str(os.getppid()))
    cmd = [str(root / 'bin' / args[3]), *args[4:]]
    sys.exit(subprocess.run(cmd, input=sys.stdin.buffer.read(), env=env).returncode)
elif name == 'project-docker-host':
    assert args == ['shop','user']; record('docker-user'); print('shop-run')
elif name == 'restic':
    assert args.pop(0) == '--no-cache'
    repository = os.environ['RESTIC_REPOSITORY']
    assert repository.startswith('s3:https://s3.example.org/bucket/synthetic/')
    period = repository.rsplit('/',1)[1]
    action = args[0]; record(action); failed(action)
    if action == 'snapshots':
        assert args == ['snapshots','--json','--tag','project:shop']
        if config.get('oversized-metadata'):
            sys.stdout.buffer.write(b'x' * (17*1024**2)); sys.stdout.buffer.flush()
            (root/'metadata-complete').touch(); sys.exit(0)
        if period not in config['periods']: sys.exit(10)
        print(json.dumps(config['periods'][period]))
    elif action == 'ls':
        assert args == ['ls','--json',config['id'],'/var/backups/db/shop/shop.pgdump']
        print(json.dumps(dict(struct_type='snapshot',id=config['id'])))
        print(json.dumps(config['node']))
    elif action == 'dump':
        assert args == ['dump',config['id'],'/var/backups/db/shop/shop.pgdump']
        if config.get('pause'):
            (root / 'paused').touch()
            while not (root / 'release').exists(): time.sleep(.02)
        sys.stdout.buffer.write((root / 'dump').read_bytes()); sys.stdout.buffer.flush()
        after('download')
    else: raise AssertionError(args)
elif name in ('psql','pg_restore'):
    raw = sys.stdin.buffer.read()
    sql = raw.decode() if name == 'psql' else ''
    action = 'connect' if '-c' in args else 'sql'
    for match, label in [('CREATE ROLE ', 'create-role'), ('CREATE DATABASE ', 'create-db'),
                         ('DROP DATABASE ', 'drop-db'), ('DROP ROLE ', 'drop-role'),
                         ('BEGIN ISOLATION LEVEL', 'query'), ('has_database_privilege(', 'acl'),
                         ("SELECT current_user || ':' || session_user", 'identity')]:
        if match in sql: action = label; break
    if name == 'pg_restore': action = 'toc' if '--list' in args else 'restore'
    record(action); failed(action)
    cmd = [str(pathlib.Path(os.environ['SQL_BIN']) / name), *args]
    result = subprocess.run(cmd, input=raw, capture_output=True)
    if action == 'toc' and config.get('recreate-plpgsql'):
        env=dict(os.environ, PGHOST=os.environ['SQL_SOCKET'], PGPORT=os.environ['SQL_PORT'], PGUSER='probe_admin')
        psql=str(pathlib.Path(os.environ['SQL_BIN'])/'psql')
        database=subprocess.check_output([psql,'-X','-tA','-d','postgres','-c',
                                         "SELECT datname FROM pg_database WHERE datname LIKE 'infra_check_%';"],env=env,text=True).strip()
        subprocess.run([psql,'-X','-d',database,'-c','DROP EXTENSION plpgsql;'],env=env,check=True,capture_output=True)
    if action == 'restore' and config.get('recreate-plpgsql') and result.returncode == 0:
        psql=str(pathlib.Path(os.environ['SQL_BIN'])/'psql')
        actual=subprocess.check_output([psql,'-X','-tA','-d',os.environ['PGUSER'],'-c',
                                       "SELECT pg_get_userbyid(extowner)=current_user FROM pg_extension WHERE extname='plpgsql';"],text=True).strip()
        assert actual == 't', 'trusted extension was not created by restricted LOGIN'
    pid=int(os.environ.get('CHECK_PID',os.getppid()))
    acl_calls = sum(entry['action'] == 'acl' and entry['pid'] == pid
                    for entry in map(json.loads,(root/'calls').read_text().splitlines()))
    if action == 'acl' and config.get('acl-drift-after') == acl_calls:
        env=dict(os.environ, PGHOST=os.environ['SQL_SOCKET'], PGPORT=os.environ['SQL_PORT'], PGUSER='probe_admin')
        subprocess.run([str(pathlib.Path(os.environ['SQL_BIN'])/'psql'),'-X','-d','postgres','-c',
                        'GRANT CONNECT ON DATABASE neighbor TO PUBLIC;'], env=env, check=True, capture_output=True)
    sys.stdout.buffer.write(result.stdout); sys.stdout.buffer.flush()
    sys.stderr.buffer.write(result.stderr)
    if result.returncode == 0: after(action)
    sys.exit(result.returncode)
elif name == 'bash':
    record('source')
    result = subprocess.run(['/bin/bash',*args], input=sys.stdin.buffer.read(), capture_output=True)
    sys.stdout.buffer.write(result.stdout); sys.stdout.buffer.flush()
    after('stage'); sys.exit(result.returncode)
else: raise AssertionError(name)
'''
RUNNER = r'''
import importlib.machinery, importlib.util, json, os, pathlib, shutil, sys
root = pathlib.Path(os.environ['STAND'])
loader = importlib.machinery.SourceFileLoader('check', str(root / 'command'))
spec = importlib.util.spec_from_loader(loader.name, loader)
mod = importlib.util.module_from_spec(spec); loader.exec_module(mod)
mod.OWNER_UID = os.geteuid(); mod.PG_PORT = os.environ['SQL_PORT']
mod.S3_ENV=root/'s3-env'; mod.PROJECTS=root/'projects.json'; mod.STAGE_ROOT=root/'stage'
mod.LOCK_ROOT=root/'locks'; mod.DEPLOY_ROOT=root/'deploy'
config=json.loads((root/'config').read_text())
if config.get('fixed'): mod.secrets.token_hex=lambda n: 'c' * (n*2)
if config.get('now'): mod.time.time=lambda: config['now']
if config.get('no-space'):
    mod.shutil.disk_usage=lambda path: shutil._ntuple_diskusage(1,1,0)
if config.get('cleanup-stage'):
    def failure(path): raise OSError('synthetic cleanup failure')
    mod.shutil.rmtree=failure
sys.exit(mod.main())
'''


def load_script():
    loader = importlib.machinery.SourceFileLoader("restore_check", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class PureContract(unittest.TestCase):
    def test_quoting(self):
        module = load_script()
        self.assertEqual(module.literal("a'b\\c"), "'a''b\\c'")
        self.assertEqual(module.identifier('a"b'), '"a""b"')

    def test_installation(self):
        tasks = SCRIPT.parents[1] / "tasks/main.yml"
        self.assertIn("project-restore-check", tasks.read_text())


class RestoreCheckSQL(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        candidates = [Path(os.environ["RESTORE_CHECK_PG_BIN"])] if os.environ.get("RESTORE_CHECK_PG_BIN") else []
        if not os.environ.get("RESTORE_CHECK_PG_BIN"):
            if shutil.which("initdb"):
                candidates.append(Path(shutil.which("initdb")).resolve().parent)
            candidates.extend(Path("/usr/lib/postgresql").glob("*/bin"))
        cls.pg = next((p.resolve() for p in candidates if (p / "postgres").is_file()
                       and all((p / tool).is_file() for tool in ("initdb", "pg_ctl", "psql", "pg_dump", "pg_restore"))), None)
        if cls.pg is None:
            if os.environ.get("RESTORE_CHECK_PG_BIN"):
                raise AssertionError("Указанный RESTORE_CHECK_PG_BIN не содержит PostgreSQL server binaries")
            raise unittest.SkipTest("Нет PostgreSQL server binaries; SQL-судья не выполнен (RESTORE_CHECK_PG_BIN)")
        if os.geteuid() == 0:
            if os.environ.get("RESTORE_CHECK_PG_BIN"):
                raise AssertionError("Явный SQL-прогон требует обычного пользователя, не root")
            raise unittest.SkipTest("initdb не запускается от root; SQL-судья требует обычного локального пользователя")
        cls.cluster = Path(tempfile.mkdtemp(prefix="infra-a2-pg-", dir="/tmp")).resolve()
        cls.data = cls.cluster / "data"
        while True:
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0)); cls.port = sock.getsockname()[1]
            if cls.port != 55433:
                break
        cls.sqlenv = {k: v for k, v in os.environ.items() if not k.startswith("PG")}
        cls.sqlenv.update(PGHOST=str(cls.cluster), PGPORT=str(cls.port), PGUSER="probe_admin", PGDATABASE="postgres")
        try:
            cls.tool("initdb", "-D", cls.data, "-U", "probe_admin", "--auth-local=trust",
                     "--auth-host=scram-sha-256", "--no-locale", "--encoding=UTF8")
            with (cls.data / "postgresql.conf").open("a") as f:
                f.write(f"\nlisten_addresses='127.0.0.1'\nport={cls.port}\n"
                        f"unix_socket_directories='{cls.cluster}'\nshared_buffers='16MB'\n"
                        "max_connections=20\nfsync=off\n")
            cls.tool("pg_ctl", "-D", cls.data, "-l", cls.cluster / "server.log", "-t", "10", "-w", "start")
            for name in ("shop", "neighbor"):
                cls.query(f"CREATE ROLE {name} LOGIN PASSWORD 'synthetic-only' NOCREATEDB NOCREATEROLE;")
                cls.query(f"CREATE DATABASE {name} OWNER {name};")
                cls.query(f"REVOKE CONNECT ON DATABASE {name} FROM PUBLIC;")
        except BaseException:
            if (cls.data / "postmaster.pid").exists():
                cls.tool("pg_ctl", "-D", cls.data, "-m", "fast", "-w", "stop")
            shutil.rmtree(cls.cluster)
            raise

    @classmethod
    def tearDownClass(cls):
        cls.tool("pg_ctl", "-D", cls.data, "-m", "fast", "-w", "stop")
        shutil.rmtree(cls.cluster)

    @classmethod
    def tool(cls, name, *args, sql=None, env=None):
        result = subprocess.run([str(cls.pg / name), *map(str, args)], input=sql, text=True,
                                capture_output=True, env=env or cls.sqlenv, timeout=30)
        if result.returncode:
            raise AssertionError((name, result.returncode, result.stderr))
        return result.stdout.strip()

    @classmethod
    def query(cls, sql, db="postgres"):
        return cls.tool("psql", "-X", "-q", "-tA", "-v", "ON_ERROR_STOP=1", "-d", db, "-c", sql)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="infra-a2-case-")
        self.root = Path(self.tmp.name).resolve()
        for folder in ("bin", "stage", "locks", "deploy"):
            (self.root / folder).mkdir()
        for name in ("runuser", "psql", "pg_restore", "restic", "project-docker-host", "bash"):
            path = self.root / "bin" / name
            path.write_text("#!/usr/bin/env python3\n" + STUB); path.chmod(0o700)
        (self.root / "command").write_text(SCRIPT.read_text())
        (self.root / "runner.py").write_text(RUNNER)
        (self.root / "projects.json").write_text('[{"name":"shop","db":"postgres"}]')
        (self.root / "s3-env").write_text("RESTIC_REPOSITORY=s3:https://s3.example.org/bucket/synthetic\n"
                                           "RESTIC_PASSWORD=synthetic-only\nMARKER=s3\n")
        (self.root / "s3-env").chmod(0o600)
        (self.root / "env").write_text(f'touch "{self.root / "local-read"}"\nRESTIC_REPOSITORY=local\n')
        for db in ("shop", "neighbor"):
            self.query("DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION " + db + "; "
                       "CREATE TABLE public.example(id int PRIMARY KEY, value text NOT NULL); "
                       "INSERT INTO public.example VALUES (1,'before'),(2,'unchanged'); "
                       "ALTER TABLE public.example OWNER TO " + db + ";", db)
        self.query("CREATE FUNCTION public.restore_guard() RETURNS boolean LANGUAGE plpgsql AS $$ BEGIN "
                   "IF current_database() LIKE 'infra_check_%' AND "
                   "(session_user NOT LIKE 'infra_check_%' OR session_user <> current_user) THEN "
                   "RAISE EXCEPTION 'restore requires separate restricted LOGIN'; END IF; RETURN true; END $$; "
                   "ALTER TABLE public.example ADD CONSTRAINT restricted_login CHECK(public.restore_guard());", "shop")
        self.tool("pg_dump", "-Fc", "-d", "shop", "-f", self.root / "dump")
        now = time.time()
        self.current = datetime.fromtimestamp(int(now) // (14 * 86400) * 14 * 86400, timezone.utc).strftime("%F")
        self.previous = datetime.fromtimestamp(int(now) // (14 * 86400) * 14 * 86400 - 14 * 86400, timezone.utc).strftime("%F")
        self.snapshot = dict(id="a" * 64, time=datetime.fromtimestamp(now - 10, timezone.utc).isoformat(),
                             tags=["project:shop", "db-only"], paths=["/var/backups/db/shop"])
        self.config = dict(id="a" * 64, periods={self.current: [self.snapshot]},
                           node=dict(path="/var/backups/db/shop/shop.pgdump", type="file",
                                     size=(self.root / "dump").stat().st_size,
                                     mtime=datetime.fromtimestamp(now - 10, timezone.utc).isoformat()))
        self.expected = self.state()
        self.env = dict(os.environ, STAND=str(self.root), SQL_BIN=str(self.pg), SQL_SOCKET=str(self.cluster),
                        SQL_PORT=str(self.port), PATH=str(self.root / "bin") + os.pathsep + os.environ["PATH"],
                        PGUSER="should-not-leak", RESTIC_REPOSITORY="local-should-not-leak")
        self.active = []

    def tearDown(self):
        for proc in self.active:
            if proc.poll() is None:
                proc.kill(); proc.wait()
        try:
            self.assertEqual(self.state(), self.expected, "prod/neighbor data or ACL changed")
            self.assertFalse((self.root / "local-read").exists(), "read local source")
        finally:
            for db in self.query("SELECT datname FROM pg_database WHERE datname LIKE 'infra_check_%';").splitlines():
                self.query('DROP DATABASE "' + db.replace('"', '""') + '" WITH (FORCE);')
            for role in self.query("SELECT rolname FROM pg_roles WHERE rolname LIKE 'infra_check_%';").splitlines():
                self.query('DROP ROLE "' + role.replace('"', '""') + '";')
            self.tmp.cleanup()

    def state(self):
        return dict(data={db: self.query("SELECT md5(string_agg(row_to_json(t)::text, ',' ORDER BY id)) "
                                         "FROM public.example t;", db) for db in ("shop", "neighbor")},
                    structure={db: hashlib.sha256("\n".join(line for line in self.tool("pg_dump", "--schema-only", "-d", db).splitlines()
                                                           if not line.startswith(("\\restrict ", "\\unrestrict "))).encode()).hexdigest()
                               for db in ("shop", "neighbor")},
                    acl=self.query("SELECT datname,datacl FROM pg_database WHERE datname IN ('shop','neighbor') ORDER BY datname;"))

    def start(self, *args):
        (self.root / "config").write_text(json.dumps(self.config))
        proc = subprocess.Popen([sys.executable, str(self.root / "runner.py"), *(args or ("shop",))],
                                env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.active.append(proc)
        return proc

    def execute(self, expected=0, *args, clean=True):
        proc = self.start(*args)
        out, err = proc.communicate(timeout=30)
        self.assertEqual(proc.returncode, expected, out + err)
        if clean:
            self.assertEqual(list((self.root / "stage").iterdir()), [], "stage remains")
            self.assertEqual(self.query("SELECT count(*) FROM pg_database WHERE datname LIKE 'infra_check_%';"), "0")
            self.assertEqual(self.query("SELECT count(*) FROM pg_roles WHERE rolname LIKE 'infra_check_%';"), "0")
        return json.loads(out) if out else err

    def calls(self, action=None):
        path = self.root / "calls"
        calls = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
        return calls if action is None else [call for call in calls if call["action"] == action]

    def wait_paused(self):
        end = time.monotonic() + 10
        while not (self.root / "paused").exists() and time.monotonic() < end:
            time.sleep(.02)
        self.assertTrue((self.root / "paused").exists(), "command never reached pause")

    def test_success_real_login_metrics_and_cleanup(self):
        result = self.execute()
        self.assertEqual(result["comparison"], "equal")
        self.assertEqual(result["isolation"]["denied_connect"], ["neighbor", "shop"])
        self.assertEqual(result["cleanup"], "done")
        self.assertEqual(result["migrations"], "not-checked")
        self.assertEqual(result["restored"][1]["value"], 2)
        self.assertEqual(len(self.calls("connect")), 4)
        restore = self.calls("restore")[0]
        self.assertTrue(restore["user"].startswith("infra_check_"))
        self.assertNotIn("--role", " ".join(restore["args"]))
        self.assertEqual(self.calls("query")[0]["user"], restore["user"])

    def test_cli_rejected_before_source(self):
        for args in (("../shop",), ("shop;SELECT1",), ("shop", "extra")):
            self.execute(2, *args)
        self.assertEqual(self.calls(), [])

    def test_source_missing_or_not_s3(self):
        source = self.root / "s3-env"
        source.unlink(); self.execute(1)
        source.write_text("RESTIC_REPOSITORY=local\n"); source.chmod(0o600)
        self.execute(1)
        self.assertEqual(self.calls("snapshots"), [])

    def test_inherited_bash_env_cannot_read_local_source(self):
        self.env["BASH_ENV"] = str(self.root / "env")
        self.execute()
        self.assertFalse((self.root / "local-read").exists(), "BASH_ENV прочитал посторонний env до s3-env")
        del self.env["BASH_ENV"]
        self.env["BASH_FUNC_source%%"] = '() { touch "' + str(self.root / "local-read") + '"; builtin source "$@"; }'
        self.execute()
        self.assertFalse((self.root / "local-read").exists(), "Экспортированная функция подменила source")

    def test_source_permissions_and_symlink(self):
        source = self.root / "s3-env"
        source.chmod(0o644); self.execute(1)
        source.unlink(); source.symlink_to(self.root / "env"); self.execute(1)
        self.assertEqual(self.calls("snapshots"), [])

    def test_missing_old_future_snapshot(self):
        self.config["periods"] = {}; self.execute(1)
        for age in (86401, -60):
            self.snapshot["time"] = datetime.fromtimestamp(time.time() - age, timezone.utc).isoformat()
            self.config["periods"] = {self.current: [self.snapshot]}; self.execute(1)
        self.assertEqual(self.calls("dump"), [])

    def test_timestamp_requires_explicit_timezone(self):
        self.snapshot["time"] = "2026-11-01T23:00:00"
        self.execute(1)
        self.assertEqual(self.calls("dump"), [])

    def test_previous_period_and_newest_across_rollover(self):
        self.config["periods"] = {self.previous: [self.snapshot]}
        self.assertEqual(self.execute()["period"], self.previous)
        older = dict(self.snapshot, time=datetime.fromtimestamp(time.time() - 3600, timezone.utc).isoformat())
        self.config["periods"][self.current] = [older]
        self.assertEqual(self.execute()["period"], self.previous)

    def test_utc_period_boundary_and_exact_24_hours(self):
        boundary = (int(time.time()) // (14 * 86400) + 1) * 14 * 86400
        self.config["now"] = boundary
        folder = datetime.fromtimestamp(boundary, timezone.utc).strftime("%F")
        previous = datetime.fromtimestamp(boundary - 14 * 86400, timezone.utc).strftime("%F")
        self.snapshot["time"] = datetime.fromtimestamp(boundary - 86400, timezone.utc).isoformat()
        self.config["node"]["mtime"] = self.snapshot["time"]
        self.config["periods"] = {previous: [self.snapshot]}
        self.assertEqual(self.execute()["period"], previous)
        self.config["now"] = boundary + .01
        self.execute(1)
        self.assertNotEqual(folder, previous)

    def test_bad_paths_symlink_size_and_old_dump(self):
        for path in ("/var/backups/db", "/var/backups/db/neighbor", "/srv/projects/shop/../neighbor",
                     "/srv//projects/shop", "/srv/projects/shop/."):
            self.snapshot["paths"] = ["/var/backups/db/shop", path]; self.execute(1)
        self.snapshot["paths"] = ["/var/backups/db/shop"]
        for key, value in (("type", "symlink"), ("size", 0), ("size", 513 * 1024**2),
                           ("mtime", datetime.fromtimestamp(time.time() - 86401, timezone.utc).isoformat())):
            node = dict(self.config["node"]); self.config["node"][key] = value
            self.execute(1); self.config["node"] = node
        self.assertEqual(self.calls("dump"), [])

    def test_full_snapshot_only_exact_dump_downloaded(self):
        self.snapshot["paths"] += ["/srv/projects/shop", "/var/lib/docker/volumes/shop_data",
                                    "/home/shop-run/.local/share/docker/volumes/shop_media"]
        self.snapshot["tags"] = ["project:shop"]
        self.execute()
        self.assertEqual(self.calls("dump")[0]["args"][-1], "/var/backups/db/shop/shop.pgdump")

    def test_space_and_metadata_failures_before_download(self):
        self.config["no-space"] = True; self.execute(1)
        self.assertEqual(self.calls("create-role"), [])
        self.assertEqual(self.calls("dump"), [])
        del self.config["no-space"]
        for action in ("snapshots", "ls"):
            self.config["fail"] = action; self.execute(1)
        self.assertEqual(self.calls("dump"), [])

    def test_metadata_output_is_bounded_before_reading(self):
        self.config['oversized-metadata'] = True
        self.assertIn('restic:', self.execute(1))
        self.assertFalse((self.root/'metadata-complete').exists())
        self.assertEqual(self.calls('create-role'), [])

    def test_useful_dump_larger_than_metadata_limit(self):
        self.query("CREATE TABLE public.payload(id int PRIMARY KEY, value text); "
                   "INSERT INTO public.payload SELECT i,repeat(chr(64+i),1024*1024) FROM generate_series(1,20) i;", "shop")
        self.expected = self.state()
        self.tool("pg_dump", "-Fc", "-Z0", "-d", "shop", "-f", self.root / "dump")
        self.config["node"]["size"] = (self.root / "dump").stat().st_size
        self.assertGreater(self.config["node"]["size"], 16 * 1024**2)
        result = self.execute()
        payload = [item for item in result["restored"] if item.get("name") == "payload"]
        self.assertEqual(payload[0]["value"], 20)

    def test_all_stage_failures_clean_resources(self):
        for action in ("create-role", "create-db", "identity", "acl", "dump", "toc", "restore", "query"):
            with self.subTest(action=action):
                self.config["fail"] = action
                self.execute(1)

    def test_actual_connect_preflight_refuses_acl_drift(self):
        self.query("GRANT CONNECT ON DATABASE neighbor TO PUBLIC;")
        self.expected = self.state()
        self.execute(1)
        self.assertEqual(self.calls("dump"), [])
        self.query("REVOKE CONNECT ON DATABASE neighbor FROM PUBLIC;")
        self.expected = self.state()

    def test_neighbor_name_is_not_a_connection_string(self):
        for database in ("dbname=postgres", "host=127.0.0.2 port=1 user=probe_admin dbname=postgres"):
            self.query(f'CREATE DATABASE "{database}" OWNER neighbor;')
            try:
                self.query(f'REVOKE CONNECT ON DATABASE "{database}" FROM PUBLIC;')
                owner_env = dict(self.sqlenv, PGHOST="127.0.0.1", PGPORT=str(self.port),
                                 PGDATABASE=database, PGUSER="neighbor", PGPASSWORD="synthetic-only")
                actual = json.loads(self.tool("psql", "-X", "-q", "-tA", "-c",
                                              "SELECT json_build_array(current_database(),current_user,session_user,"
                                              "host(inet_server_addr()),inet_server_port());", env=owner_env))
                self.assertEqual(actual, [database, "neighbor", "neighbor", "127.0.0.1", self.port])
                print("CONNINFO opaque database:", json.dumps(actual), flush=True)
                calls = self.root / "calls"
                if calls.exists():
                    calls.unlink()
                result = self.execute()
                self.assertIn(database, result["isolation"]["denied_connect"])
                attempts = self.calls("connect")
                self.assertEqual(len(attempts), 6)
                self.assertEqual({call["db"] for call in attempts}, {database, "neighbor", "shop"})
                self.assertEqual({call["user"] for call in attempts}, {result["isolation"]["login"]})
                self.assertTrue(all("-d" not in call["args"] for call in attempts))
            finally:
                self.query(f'DROP DATABASE "{database}";')

    def test_rechecks_rights_before_restore_and_requires_real_connect_refusal(self):
        self.config["acl-drift-after"] = 2
        try:
            self.execute(1)
            self.assertEqual(self.calls("restore"), [])
        finally:
            self.query("REVOKE CONNECT ON DATABASE neighbor FROM PUBLIC;")

    def test_live_change_reported_as_difference(self):
        self.config["pause"] = True
        proc = self.start(); self.wait_paused()
        self.query("INSERT INTO public.example VALUES(3,'new live value');", "shop")
        self.expected = self.state()
        (self.root / "release").touch()
        out, err = proc.communicate(timeout=30)
        self.assertEqual(proc.returncode, 3, out + err)
        self.assertEqual(json.loads(out)["comparison"], "different")
        self.assertEqual(list((self.root / "stage").iterdir()), [])

    def test_django_latest_per_app_and_difference(self):
        self.query("CREATE TABLE public.django_migrations(id int, app text, name text, applied timestamptz); "
                   "INSERT INTO public.django_migrations VALUES(1,'catalog','0001','2026-10-01T00:00:00Z');", "shop")
        self.tool("pg_dump", "-Fc", "-d", "shop", "-f", self.root / "dump")
        self.config["node"]["size"] = (self.root / "dump").stat().st_size
        result = self.execute()
        self.assertEqual(result["migrations"], "checked")
        self.assertEqual(result["restored"][-1]["value"][0]["name"], "0001")
        self.query("INSERT INTO public.django_migrations VALUES(2,'catalog','0002','2026-10-02T00:00:00Z');", "shop")
        self.execute(3)
        self.query("DROP TABLE public.django_migrations;", "shop")
        self.assertEqual(self.execute(3)["migrations"], "not-checked")

    def test_structure_difference_is_not_hidden(self):
        self.query("ALTER TABLE public.example ADD COLUMN another text;", "shop")
        self.expected = self.state()
        result = self.execute(3)
        self.assertEqual(len(result["restored"][0]["value"][0]["columns"]), 2)
        self.assertEqual(len(result["current"][0]["value"][0]["columns"]), 3)

    def test_trusted_extension_and_untrusted_refusal(self):
        if self.query("SELECT count(*) FROM pg_available_extensions WHERE name='pg_trgm';") != "1":
            self.skipTest("В этом локальном PostgreSQL нет pg_trgm")
        self.query("CREATE EXTENSION pg_trgm; CREATE INDEX example_trgm ON public.example USING gin(value gin_trgm_ops);", "shop")
        self.expected = self.state()
        self.tool("pg_dump", "-Fc", "-d", "shop", "-f", self.root / "dump")
        self.config["node"]["size"] = (self.root / "dump").stat().st_size
        self.execute()
        if self.query("SELECT count(*) FROM pg_available_extensions WHERE name='dblink';") == "1":
            self.query("CREATE EXTENSION dblink;", "shop")
            self.expected = self.state()
            self.tool("pg_dump", "-Fc", "-d", "shop", "-f", self.root / "dump")
            self.config["node"]["size"] = (self.root / "dump").stat().st_size
            self.assertIn("не доверенное", self.execute(1))

    def test_real_creation_of_trusted_extension_by_login(self):
        # Пересоздать исходный extension: initdb-прикреплённый plpgsql pg_dump
        # пропускает даже с -e. Это только синтетическая source-база стенда.
        self.query("DROP EXTENSION plpgsql CASCADE; CREATE EXTENSION plpgsql;", "shop")
        self.expected = self.state()
        self.tool("pg_dump", "-Fc", "-d", "shop", "-f", self.root / "dump")
        self.config["node"]["size"] = (self.root / "dump").stat().st_size
        self.config["recreate-plpgsql"] = True
        self.execute()

    def test_untrusted_extension_refused_with_real_dump(self):
        available = self.query("SELECT name FROM pg_available_extensions WHERE name IN ('vector','dblink') ORDER BY name LIMIT 1;")
        if not available:
            self.skipTest("В локальном наборе нет vector/dblink для отрицательного dump-case")
        self.query("CREATE EXTENSION " + available + ";", "shop")
        self.expected = self.state()
        self.tool("pg_dump", "-Fc", "-d", "shop", "-f", self.root / "dump")
        self.config["node"]["size"] = (self.root / "dump").stat().st_size
        self.assertIn("не доверенное", self.execute(1))

    def test_collision_never_deleted(self):
        self.config["fixed"] = True
        name = "infra_check_" + "c" * 24
        self.query(f"CREATE ROLE {name} LOGIN;")
        self.execute(1, clean=False)
        self.assertEqual(self.query(f"SELECT count(*) FROM pg_roles WHERE rolname='{name}';"), "1")
        self.query(f"DROP ROLE {name};")
        self.query(f"CREATE DATABASE {name} OWNER neighbor;")
        self.execute(1, clean=False)
        self.assertEqual(self.query(f"SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='{name}';"), "neighbor")

    def test_signals_after_each_resource(self):
        for action in ("stage", "create-role", "create-db", "download", "restore", "query"):
            for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
                with self.subTest(action=action, signum=signum):
                    self.config["signal"] = action
                    self.config["signal-number"] = signum
                    self.execute(1)

    def test_cleanup_failure_visible_and_owned_residue(self):
        for action in ("drop-db", "drop-role"):
            with self.subTest(action=action):
                self.config["fail"] = action
                error = self.execute(1, clean=False)
                self.assertIn("Ошибка уборки", error)
                self.assertEqual(list((self.root / "stage").iterdir()), [])
                for db in self.query("SELECT datname FROM pg_database WHERE datname LIKE 'infra_check_%';").splitlines():
                    self.query(f"DROP DATABASE {db} WITH (FORCE);")
                for role in self.query("SELECT rolname FROM pg_roles WHERE rolname LIKE 'infra_check_%';").splitlines():
                    self.query(f"DROP ROLE {role};")
        del self.config["fail"]
        self.config["cleanup-stage"] = True
        self.assertIn("Ошибка уборки", self.execute(1, clean=False))
        self.assertEqual(len(list((self.root / "stage").iterdir())), 1)

    def test_parallel_and_shared_locks(self):
        self.config["pause"] = True
        first = self.start(); self.wait_paused()
        second = self.start()
        out, err = second.communicate(timeout=10)
        self.assertEqual(second.returncode, 1, out + err)
        (self.root / "release").touch()
        out, err = first.communicate(timeout=30)
        self.assertEqual(first.returncode, 0, out + err)
        del self.config["pause"]
        for path in (self.root / "locks/restic-backup.lock", self.root / "deploy/shop.lock"):
            with path.open("a") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.execute(1)

    def test_sql_judge_catches_mutations(self):
        original = SCRIPT.read_text()
        mutations = {
            "temp-to-prod": ('"-d", self.temp, str(dump)', '"-d", self.name, str(dump)'),
            "s3-to-local": ('info = S3_ENV.lstat()', 'global S3_ENV; S3_ENV = PROJECTS.parent / "env"; info = S3_ENV.lstat()'),
            "remove-age": ('require(0 <= now - stamp <= 86400,', 'require(True,'),
            "remove-space": ('require(shutil.disk_usage(path).free >= amount + RESERVE,', 'require(True,'),
            "remove-cleanup": ('check.cleanup()', 'None'),
            "extra-rights": ('LOGIN NOSUPERUSER NOCREATEDB', 'LOGIN SUPERUSER NOCREATEDB'),
            "privileged-restore": ('self.command(["pg_restore", "--no-owner"',
                                    'self.command(["runuser", "-u", "postgres", "--", "pg_restore", "--role=" + self.temp, "--no-owner"'),
            "skip-connect-probe": ('require(rc != 0, "Настоящий CONNECT', 'require(True, "Настоящий CONNECT'),
        }
        for name, (before, after) in mutations.items():
            with self.subTest(mutation=name):
                self.assertIn(before, original)
                self.config.pop('no-space', None)
                self.config.pop('acl-drift-after', None)
                self.snapshot['time'] = datetime.fromtimestamp(time.time() - 10, timezone.utc).isoformat()
                (self.root / 'command').write_text(original.replace(before, after))
                if name == 'remove-age':
                    self.snapshot['time'] = datetime.fromtimestamp(time.time() - 86401, timezone.utc).isoformat()
                if name == 'remove-space':
                    self.config['no-space'] = True
                if name == 's3-to-local':
                    (self.root / 'env').chmod(0o600)
                if name == 'skip-connect-probe':
                    self.config['acl-drift-after'] = 2
                proc = self.start()
                out, err = proc.communicate(timeout=30)
                if name in ('temp-to-prod', 's3-to-local', 'extra-rights', 'privileged-restore'):
                    self.assertNotEqual(proc.returncode, 0, (name, out, err))
                    if name == 's3-to-local':
                        self.assertTrue((self.root / 'local-read').exists())
                        (self.root / 'local-read').unlink()
                elif name in ('remove-age', 'remove-space', 'skip-connect-probe'):
                    self.assertEqual(proc.returncode, 0, (name, out, err))
                    # Отрицательный судья базовой команды требует 1; мутант дал 0.
                    self.assertTrue(json.loads(out)['comparison'] == 'equal')
                elif name == 'remove-cleanup':
                    self.assertEqual(proc.returncode, 0, out + err)
                    self.assertNotEqual(self.query("SELECT count(*) FROM pg_roles WHERE rolname LIKE 'infra_check_%';"), '0')
                    self.assertTrue(list((self.root / 'stage').iterdir()))
                    for db in self.query("SELECT datname FROM pg_database WHERE datname LIKE 'infra_check_%';").splitlines():
                        self.query(f'DROP DATABASE {db} WITH (FORCE);')
                    for role in self.query("SELECT rolname FROM pg_roles WHERE rolname LIKE 'infra_check_%';").splitlines():
                        self.query(f'DROP ROLE {role};')
                    for stage in (self.root / 'stage').iterdir(): shutil.rmtree(stage)
                if name == 'skip-connect-probe':
                    self.query('REVOKE CONNECT ON DATABASE neighbor FROM PUBLIC;')
                print(f'MUTATION {name}: caught, actual_rc={proc.returncode}', flush=True)
        (self.root / 'command').write_text(original)


if __name__ == "__main__":
    unittest.main()
