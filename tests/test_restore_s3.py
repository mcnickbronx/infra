"""Офлайн-судья существующего project-restore: S3 env, снимки, пути и уборка.

Запускается копия целого скрипта; заменены только абсолютные пути и внешние
команды. SQL, S3 и пригодность настоящего бэкапа этот стенд не проверяет.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "roles/backup/files/project-restore"
REPO = "s3:https://s3.example.invalid/bucket/server/2026-10-22"
# Системный macOS Bash 3.2: только используемый вызов builtin, без eval/выбора снимка.
MAPFILE = r'''
if ! type -t mapfile >/dev/null; then
  mapfile() {
    [ "$#" = 2 ] && [ "$1" = -t ] && [ "$2" = SNAP ] || return 2
    SNAP=(); local line
    while IFS= read -r line || [ -n "$line" ]; do SNAP[${#SNAP[@]}]=$line; done
  }
fi
source "$1" "${@:2}"
'''
STUB = r'''
import json, os, pathlib, shutil, subprocess, sys, tempfile
root = pathlib.Path(os.environ['STAND'])
name, args = pathlib.Path(sys.argv[0]).name, sys.argv[1:]
def record(value):
    with (root / 'calls').open('a') as f: f.write(json.dumps(value) + '\n')
def inside(value):
    p = pathlib.Path(value).resolve()
    assert p.is_relative_to(root), ('выход из стенда', value)
    return p
record([name, args, os.environ.get('RESTIC_REPOSITORY'), os.environ.get('MARKER')])
project, dumps = root / 'srv/projects/shop', root / 'var/backups/db/shop'
if name == 'restic':
    assert os.environ['RESTIC_REPOSITORY'] == os.environ['EXPECTED_REPO'], 'не S3'
    assert os.environ['MARKER'] == 's3', 'прочитан local env'
    snapshots = json.loads((root / 'snapshots').read_text())
    if args[0] == 'snapshots':
        assert args[:3] == ['snapshots', '--json', '--tag']
        assert args[3] in ('project:shop', 'project:shop,db-only')
        print(json.dumps([s for s in snapshots if args[3] != 'project:shop,db-only'
                          or 'db-only' in s['tags']]))
    else:
        assert args[0] == 'restore' and args[2] == '--target' and len(args) == 4
        stage = inside(args[3])
        for p in next(s['paths'] for s in snapshots if s['id'] == args[1]):
            target = inside(str(stage) + p)
            assert p in (str(project), str(dumps)), ('чужой путь до restore', p)
            target.mkdir(parents=True)
            if p == str(dumps): (target / 'shop.pgdump').write_text('synthetic dump')
        sys.exit(1 if os.environ.get('FAIL') == 'restic' else 0)
elif name == 'mktemp':
    if args:
        assert args[0] == '-d' and len(args) == 2
        template = inside(args[1])
        result = tempfile.mkdtemp(prefix=template.name.removesuffix('XXXXXX'), dir=template.parent)
    else:
        fd, result = tempfile.mkstemp(dir=inside(os.environ['TMPDIR']))
        os.close(fd)
    record(['temp', result]); print(result)
elif name == 'rsync':
    assert args[:3] == ['-aHAX', '--numeric-ids', '--delete'] and len(args) == 5
    src, dst = inside(args[-2]), inside(args[-1])
    assert dst in (project, dumps), ('чужой путь до rsync', dst)
    assert str(src).endswith(str(dst)), (src, dst)
    shutil.copytree(src, dst, dirs_exist_ok=True)
elif name == 'project-db-empty':
    assert args == ['shop']
elif name == 'runuser':
    assert args[:3] == ['-u', 'postgres', '--'] and args[3] in ('pg_restore', 'psql')
    sys.exit(subprocess.run(args[3:], input=sys.stdin.buffer.read()).returncode)
elif name == 'pg_restore':
    if args[0] == '-l':
        assert args == ['-l', str(dumps / 'shop.pgdump')]
        print('1; 0 0 EXTENSION - pg_trgm\n2; 0 0 TABLE public example shop')
    elif '-f' in args:
        assert len(args) == 5 and args[0] == '-L' and args[2:4] == ['-f', '-']
        inside(args[1]); assert args[4] == str(dumps / 'shop.pgdump')
        print('CREATE EXTENSION pg_trgm;')
    else:
        assert args[:5] == ['--clean', '--if-exists', '--no-owner', '--role=shop', '-L']
        assert len(args) == 8 and args[6:] == ['-d', 'shop']
        assert inside(args[5]).read_text() == '2; 0 0 TABLE public example shop\n'
        assert sys.stdin.read() == 'synthetic dump'
        sys.exit(1 if os.environ.get('FAIL') == 'pg_restore' else 0)
elif name == 'psql':
    assert args == ['-X', '-q', '-v', 'ON_ERROR_STOP=1', '-d', 'shop']
    assert sys.stdin.read() == 'CREATE EXTENSION pg_trgm;\n'
elif name == 'chown':
    assert len(args) == 2 and args[0] == 'postgres'
    assert inside(args[1]).is_file()
elif name == 'stat':
    assert len(args) == 3 and args[:2] == ['-c', '%g']
    assert str(inside(args[2])).endswith(str(project))
    print(0)
elif name == 'getent':
    assert args == ['group', 'shop-dev']; print('shop-dev:x:0:')
elif name == 'project-docker-host':
    assert args in (['shop'], ['shop', 'user'])
    if len(args) == 2: print('shop-run')
elif name == 'docker':
    assert args == ['ps', '-q', '--filter', 'label=com.docker.compose.project=shop']
elif name == 'flock':
    assert args == ['-w', '30', '9']
elif name != 'infra-log':
    raise AssertionError(('неизвестная команда', name, args))
'''


class RestoreS3(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        for folder in ('bin', 'tmp', 'etc/restic', 'var/tmp', 'var/lib/project-deploy'):
            (self.root / folder).mkdir(parents=True)
        for name in ('restic', 'mktemp', 'rsync', 'project-db-empty', 'runuser', 'pg_restore',
                     'psql', 'chown', 'stat', 'getent', 'project-docker-host', 'docker', 'flock', 'infra-log'):
            path = self.root / 'bin' / name
            path.write_text('#!/usr/bin/env python3\n' + STUB)
            path.chmod(0o755)
        (self.root / 'etc/restic/projects.json').write_text('[{"name":"shop","db":"postgres"}]')
        (self.root / 'etc/restic/env').write_text(
            f'MARKER=local\nRESTIC_REPOSITORY=local\ntouch "{self.root / "local-read"}"\n')
        self.s3 = self.root / 'etc/restic/s3-env'
        self.s3.write_text(f'MARKER=s3\nRESTIC_REPOSITORY={REPO}\n')
        script = SCRIPT.read_text()
        # Только системные абсолютные пути, включая те же пути в metadata снимков.
        for prefix in ('/etc/restic', '/var/lib/project-deploy', '/var/tmp',
                       '/srv/projects', '/var/backups/db', '/var/lib/docker', '/home'):
            script = script.replace(prefix, str(self.root) + prefix)
        self.script = self.root / 'project-restore'
        self.script.write_text(script)
        paths = [str(self.root / p) for p in ('srv/projects/shop', 'var/backups/db/shop')]
        self.snapshots = [dict(id=i * 64, short_id=i * 8, time=f'2026-10-{day}T00:00:00Z',
                               paths=paths if i != 'c' else paths[1:],
                               tags=['project:shop'] + (['db-only'] if i == 'c' else []))
                          for i, day in [('c', '24'), ('a', '22'), ('b', '23')]]

    def restore(self, snapshot='latest', fail=''):
        (self.root / 'snapshots').write_text(json.dumps(self.snapshots))
        env = {'PATH': f"{self.root / 'bin'}:{os.environ['PATH']}",
               'STAND': str(self.root), 'TMPDIR': str(self.root / 'tmp'),
               'EXPECTED_REPO': REPO, 'FAIL': fail}
        run = subprocess.run(['bash', '-c', MAPFILE, 'restore-test', str(self.script),
                              'shop', str(self.s3), snapshot], cwd=self.root, env=env,
                             text=True, capture_output=True, timeout=20)
        self.calls = [json.loads(line) for line in (self.root / 'calls').read_text().splitlines()]
        self.assertNotIn('Traceback', run.stderr, run.stderr)
        self.assertFalse((self.root / 'local-read').exists(), 'прочитан local env')
        self.assertEqual(list((self.root / 'tmp').iterdir()), [], run.stderr)
        self.assertEqual(list((self.root / 'var/tmp').iterdir()), [], run.stderr)
        for call in self.calls:
            if call[0] == 'temp':
                self.assertFalse(Path(call[1]).exists(), f'не убран временный объект {call[1]}')
        return run

    def commands(self, name):
        return [call[1] for call in self.calls if call[0] == name]

    def test_latest_full_reaches_database_using_explicit_s3(self):
        run = self.restore()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(self.commands('restic')[-1][1], 'b' * 64)
        self.assertEqual(self.commands('project-db-empty'), [['shop']])
        self.assertEqual(len(self.commands('rsync')), 2)
        self.assertEqual(len(self.commands('runuser')), 2)
        self.assertIn('--role=shop', self.commands('pg_restore')[-1])
        self.assertEqual(len([c for c in self.calls if c[0] == 'temp']), 2)
        for call in self.calls:
            if call[0] == 'restic': self.assertEqual(call[2:], [REPO, 's3'])

    def test_explicit_old_snapshot(self):
        run = self.restore('a' * 8)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(self.commands('restic')[-1][1], 'a' * 64)

    def test_explicit_db_only_snapshot(self):
        run = self.restore('c' * 64)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(self.commands('restic')[-1][1], 'c' * 64)
        self.assertEqual(len(self.commands('rsync')), 1)
        self.assertFalse((self.root / 'srv/projects/shop').exists())

    def test_restore_failure_cleans_stage(self):
        run = self.restore(fail='restic')
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertEqual(self.commands('rsync'), [])
        self.assertEqual(self.commands('project-db-empty'), [])
        self.assertEqual(len([c for c in self.calls if c[0] == 'temp']), 1)

    def test_database_failure_cleans_stage_and_pglist(self):
        run = self.restore(fail='pg_restore')
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertIn('--role=shop', self.commands('pg_restore')[-1])
        self.assertEqual(len([c for c in self.calls if c[0] == 'temp']), 2)

    def test_foreign_path_refused_before_restore(self):
        self.snapshots[2]['paths'] = [str(self.root / 'srv/projects/other')]
        self.assert_refused('неожиданный путь')

    def test_parent_component_refused_before_restore(self):
        self.snapshots[2]['paths'] = [str(self.root / 'srv/projects/shop/../other')]
        self.assert_refused('некорректный путь')

    def assert_refused(self, message):
        run = self.restore()
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertIn(message, run.stderr)
        self.assertFalse([args for args in self.commands('restic') if args[0] == 'restore'])
        for name in ('rsync', 'project-db-empty', 'runuser', 'pg_restore', 'mktemp'):
            self.assertEqual(self.commands(name), [])
