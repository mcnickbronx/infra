"""Настоящий project-db-copy на стенде; база/backup/rsync заглушены, права — настоящие.

install моделирует переход по ссылке GNU (режим и группа); это не опыт GNU на сервере.
Крючки в mkdir/install/chmod/find синхронные: без потоков, пауз и случайных гонок.
"""
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
STUB = r'''#!/usr/bin/env python3
import json, os, pathlib, stat, subprocess, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
base = pathlib.Path(os.environ['STAND'])
dst = base / 'projects/shop_dev/web/media'
foreign = base / 'foreign'
hook = os.environ.get('HOOK', '')
def swap(path):
    if path.is_symlink():
        return
    if path.exists():
        path.rename(path.with_name(path.name + '.saved'))
    path.symlink_to(foreign, target_is_directory=True)
def log(targets=()):
    with (base / 'calls').open('a') as out:
        out.write(json.dumps([name, args, [str(pathlib.Path(p).resolve()) for p in targets]]) + '\n')
if name == 'jq':
    pass
elif name == 'project-backup':
    print('snapshot abc123 saved')
elif name in ('project-compose', 'project-db-empty', 'infra-log', 'runuser', 'pg_restore', 'chown', 'flock'):
    pass
elif name == 'stat':
    p = pathlib.Path(args[-1])
    s = p.stat()
    if args[1] == '%u':
        print(0 if os.environ.get('OWNER', 'root') == 'root' else 12345)
    elif args[1] == '%a':
        print(format(stat.S_IMODE(s.st_mode), 'o'))
    else:
        raise RuntimeError(args)
elif name in ('mkdir', 'install'):
    p = pathlib.Path(args[-1])
    if p.name == 'media' and hook == 'before-create':
        swap(p)
    log([p])
    if name == 'install':
        # GNU install -d suit: существует ссылка на каталог — меняет её цель.
        p.mkdir(parents=True, exist_ok=True)
        os.chown(p, -1, int(os.environ['TARGET_GID']))
        p.chmod(0o2770)
    else:
        p.mkdir()
    if p.name == 'media' and hook == 'after-mkdir':
        swap(p)
elif name == 'chmod':
    if hook == 'before-chmod' and args[0] == '02770':
        swap(dst)
    log(args[1:])
    subprocess.run(['/bin/chmod', *args], check=True)
elif name == 'chgrp':
    # Реальный chgrp ОС; имя серверной группы заменено доступной группой стенда.
    mapped = [os.environ['TARGET_GID'] if a == 'shop_dev-dev' else a for a in args]
    index = args.index('shop_dev-dev')
    log(args[index + 1:])
    subprocess.run(['/usr/bin/chgrp', *mapped], check=True)
elif name == 'find':
    if hook == 'before-find':
        swap(dst)
    if hook == 'nested-before-find':
        # find уже выбрал настоящий каталог, но до cd/chmod участник заменил его.
        p = pathlib.Path('nested')
        swap(p)
        if '-exec' in args:
            start = args.index('-exec') + 1
            command = [('./nested' if a == '{}' else a) for a in args[start:-1]]
            result = subprocess.run(command)
            sys.exit(result.returncode)
    log()
    subprocess.run(['/usr/bin/find', *args], check=True)
elif name == 'rsync':
    log()
    if hook == 'after-rsync':
        swap(dst)
else:
    raise RuntimeError(name)
'''


class DbCopyDirs(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='db-copy-dirs-')
        self.addCleanup(self.tmp.cleanup)
        # Физический путь нужен cd -P (на macOS /var — ссылка).
        self.base = Path(self.tmp.name).resolve()
        self.bin = self.base / 'bin'
        self.bin.mkdir()
        self.web = self.base / 'projects/shop_dev/web'
        self.web.mkdir(parents=True)
        self.web.parent.chmod(0o750)
        src = self.base / 'projects/shop/web/media'
        src.mkdir(parents=True)
        (src / 'source').write_bytes(b'source\0data')
        self.dst = self.web / 'media'
        self.foreign = self.base / 'foreign'
        self.foreign.mkdir(mode=0o700)
        (self.foreign / 'valuable').write_bytes(b'foreign\0data\xff')
        gids = os.getgroups()
        self.gid = next((g for g in gids if g != os.getgid()), os.getgid())
        self.env = dict(os.environ, PATH=f'{self.bin}:{os.environ["PATH"]}',
                        STAND=str(self.base), TARGET_GID=str(self.gid))
        for name in ('jq', 'project-backup', 'project-compose', 'project-db-empty', 'infra-log',
                     'runuser', 'pg_restore', 'chown', 'flock', 'stat', 'mkdir', 'install',
                     'chmod', 'chgrp', 'find', 'rsync'):
            path = self.bin / name
            path.write_text(STUB)
            path.chmod(0o755)
        self.before = self.foreign_state()
        self.script = self.base / 'project-db-copy'
        self.write_script((ROOT / 'roles/backup/files/project-db-copy').read_text())

    def write_script(self, text):
        # Только серверные пути, не логика: запускается весь настоящий скрипт.
        text = text.replace('/srv/projects', str(self.base / 'projects'))
        text = text.replace('/var/tmp/db-copy.', str(self.base / 'stage.'))
        text = text.replace('/var/lib/project-deploy', str(self.base / 'locks'))
        text = text.replace('/etc/restic/projects.json', str(self.base / 'projects.json'))
        self.script.write_text(text)

    def foreign_state(self):
        return [(str(p.relative_to(self.foreign)), stat.S_IMODE(p.stat().st_mode), p.stat().st_gid,
                 p.read_bytes() if p.is_file() else None)
                for p in [self.foreign, *sorted(self.foreign.rglob('*'))]]

    def run_copy(self, hook='', **env):
        result = subprocess.run(['bash', str(self.script), '--files', '-y', 'shop', 'shop_dev'],
                                env=dict(self.env, HOOK=hook, **env), capture_output=True,
                                text=True, timeout=15)
        calls = self.base / 'calls'
        self.calls = [json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []
        return result

    def assert_foreign_untouched(self):
        self.assertEqual(self.foreign_state(), self.before, 'изменены данные, режим или группа foreign')
        for name, args, targets in self.calls:
            if name in ('chmod', 'chgrp'):
                self.assertFalse(any(p == str(self.foreign) or p.startswith(str(self.foreign) + '/')
                                     for p in targets), (name, args, targets))

    def test_link_appearing_before_create(self):
        run = self.run_copy('before-create')
        self.assert_foreign_untouched()
        self.assertNotEqual(run.returncode, 0, run.stderr)

    def test_link_after_mkdir(self):
        run = self.run_copy('after-mkdir')
        self.assert_foreign_untouched()
        self.assertNotEqual(run.returncode, 0, run.stderr)

    def test_name_replaced_after_cd_before_chmod(self):
        run = self.run_copy('before-chmod')
        self.assert_foreign_untouched()
        self.assertEqual(stat.S_IMODE((self.web / 'media.saved').stat().st_mode) & 0o777, 0o770)
        self.assertNotEqual(run.returncode, 0, run.stderr)

    def test_name_replaced_before_recursive_group(self):
        run = self.run_copy('after-rsync')
        self.assert_foreign_untouched()
        self.assertNotEqual(run.returncode, 0, run.stderr)

    def test_name_replaced_before_recursive_permissions(self):
        self.dst.mkdir()
        run = self.run_copy('before-find')
        self.assert_foreign_untouched()
        self.assertNotEqual(run.returncode, 0, run.stderr)

    def test_nested_directory_replaced_before_chmod(self):
        (self.dst / 'nested').mkdir(parents=True)
        run = self.run_copy('nested-before-find')
        self.assert_foreign_untouched()
        self.assertNotEqual(run.returncode, 0, run.stderr)

    def test_missing_directory_created(self):
        (self.base / 'projects/shop/web/private').mkdir()
        run = self.run_copy()
        self.assertEqual(run.returncode, 0, run.stderr)
        for p in (self.dst, self.web / 'private'):
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o2770)
            self.assertEqual(p.stat().st_gid, self.gid)
        self.assert_foreign_untouched()

    def test_existing_directory(self):
        (self.dst / 'nested').mkdir(parents=True)
        run = self.run_copy()
        self.assertEqual(run.returncode, 0, run.stderr)
        for p in (self.dst, self.dst / 'nested'):
            self.assertEqual(p.stat().st_mode & 0o2070, 0o2070)
            self.assertEqual(p.stat().st_gid, self.gid)
        self.assert_foreign_untouched()

    def test_initial_link_skipped(self):
        self.dst.symlink_to(self.foreign, target_is_directory=True)
        run = self.run_copy()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn('пропуск', run.stderr)
        self.assert_foreign_untouched()
        self.assertFalse(any(c[0] == 'rsync' for c in self.calls))

    def test_nested_link_not_followed_recursively(self):
        self.dst.mkdir()
        (self.dst / 'nested').symlink_to(self.foreign, target_is_directory=True)
        run = self.run_copy()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assert_foreign_untouched()

    def test_project_parent_group_writable_refused(self):
        self.web.parent.chmod(0o770)
        run = self.run_copy()
        self.assertNotEqual(run.returncode, 0, run.stderr)
        self.assertFalse(self.dst.exists())
        self.assert_foreign_untouched()

    def test_project_parent_wrong_owner_refused(self):
        run = self.run_copy(OWNER='other')
        self.assertNotEqual(run.returncode, 0, run.stderr)
        self.assertFalse(self.dst.exists())
        self.assert_foreign_untouched()

    def test_web_link_outside_project_refused(self):
        self.web.rmdir()
        self.web.symlink_to(self.foreign, target_is_directory=True)
        run = self.run_copy()
        self.assertNotEqual(run.returncode, 0, run.stderr)
        self.assert_foreign_untouched()
