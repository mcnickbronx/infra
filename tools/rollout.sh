#!/usr/bin/env bash
# Проверка движка на сервере — рабочая копия отсюда, без git. Запуск из любой папки:
#   tools/rollout.sh admin@<тестовый> --scenarios     # тестовый сервер: всё (make test-vds)
#   tools/rollout.sh admin@<сервер>                    # раскатка и проверка без сценариев
#   tools/rollout.sh admin@<тестовый> --upgrade vX.Y.Z [--from vA.B.C]   # выпуск — как на рабочих
# Шаги, любой сбой — остановка:
#   0. копия движка на сервер в /opt/infra (rsync без того, что в .gitignore: .vault_pass и прочее
#      локальное не уезжает; .venv и коллекции сервера не трогает) и install.sh — Ansible тех версий,
#      что в копии; на тестовом после --upgrade движок — git, его .git убирается: копия поверх git
#      для upgrade — «ручные правки», а меню показало бы тег, которого нет;
#   1. infra apply --check — ошибки, видные без изменений;
#   2. infra apply -y;
#   3. infra apply -y ещё раз — изменений быть не должно (иначе какая-то задача не идемпотентна:
#      каждый прогон что-то меняет, и настоящие изменения в предпросмотре не видны);
#   4. tests/verify.yml — сервер в том состоянии, которое обещано (только чтение);
#   5. --scenarios: tests/scenarios.yml — бэкап и восстановление, удаление людей и т.п.
#      по-настоящему (только на сервере с test_server: true в server.yml).
# Рабочие серверы обновляются не так, а из git: sudo infra upgrade <версия> (ADMIN.md).
#
# --upgrade — новая версия сначала на тестовом тем же sudo infra upgrade, что на рабочих, а не копией.
# Только на сервере с test_server: true — иначе ни одной команды: режим ставит движок на прежнюю
# версию, на рабочем это откат. Версии берутся с GitHub, как у рабочих: новая уже должна быть там
# (git push origin main vX.Y.Z), копия отсюда не едет. Шаги:
#   U0. движок тестового — git на прежней версии (--from; по умолчанию — тег перед новой в этом
#       репозитории): тег с GitHub, checkout -f и clean (без -x: .venv и коллекции целы), install.sh;
#   U1. infra apply -y — тестовый как рабочий до выпуска;
#   U2. infra upgrade vX.Y.Z -y — подпись по SIGNERS прежней, install.sh, apply, tests/verify.yml;
#   U3. infra apply -y ещё раз — изменений быть не должно.
# Сценарии — обычной раскаткой (--scenarios): она снова делает движок копией.
set -euo pipefail
cd "$(dirname "$0")/.." || exit 1
USAGE="Использование: tools/rollout.sh <ssh-адрес> [--scenarios | --upgrade vX.Y.Z [--from vA.B.C]]"
DEST=${1:?$USAGE}
shift
SCENARIOS="" NEW="" FROM=""
while [ $# -gt 0 ]; do
  case $1 in
    --scenarios) SCENARIOS=1 ;;
    --upgrade|--from)
      [ $# -ge 2 ] || { echo "$1 — без версии. $USAGE" >&2; exit 2; }
      if [ "$1" = --upgrade ]; then NEW=$2; else FROM=$2; fi
      shift ;;
    *) echo "Неизвестный параметр: $1" >&2; exit 2 ;;
  esac
  shift
done

# Версии — до первого ssh: они идут в команду на сервере
version_ok() {
  [[ $1 =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Версия — vX.Y.Z, а не «$1»" >&2; exit 2; }
}
if [ -n "$NEW$FROM" ]; then
  [ -n "$NEW" ] || { echo "--from — только вместе с --upgrade" >&2; exit 2; }
  [ -z "$SCENARIOS" ] || { echo "--upgrade и --scenarios — по отдельности: сценарии ждут движок-копию, их — обычной раскаткой" >&2; exit 2; }
  version_ok "$NEW"
  [ -n "$FROM" ] || FROM=$(git describe --tags --abbrev=0 --match 'v[0-9]*' "$NEW^" 2>/dev/null) ||
    { echo "Версию перед $NEW по тегам здесь не найти — задайте её: --from vA.B.C" >&2; exit 2; }
  version_ok "$FROM"
fi

LOGS=$(mktemp -d "${TMPDIR:-/tmp}/rollout.XXXXXX")
recap() { sed -n '/PLAY RECAP/,$p' "$1" | grep -E 'ok=' || true; }

# run <шаг> <лог> <команда на сервере...>
run() {
  local name=$1 log=$LOGS/$2; shift 2
  echo "== $name"
  if ! ssh "$DEST" "$@" > "$log" 2>&1; then
    grep -E 'fatal:|FAILED!|ERROR|Ждали|msg|infra:' "$log" | tail -20
    recap "$log"
    echo "!! $name — не прошло. Полный вывод: $log"
    exit 1
  fi
  recap "$log"
}

# Повторный прогон <лог> ничего не изменил — иначе остановка
unchanged() {
  if recap "$1" | grep -qE 'changed=[1-9]'; then
    echo "!! Повторный прогон снова что-то изменил — эти задачи не идемпотентны:"
    awk '/^TASK \[/ { task = $0 } /^changed:/ { print "   " task " — " $2 }' "$1" | sort -u
    echo "   Полный вывод: $1"
    exit 1
  fi
}
health() { grep -A3 'Что сейчас сообщает health-check' "$1" | grep -E '^\s+"' | sed 's/^/   health-check: /' || true; }

# Тестовый ли сервер: test_server: true в /etc/infra/server.yml (только код возврата, файл
# не выводится). 0 — да, 3 — нет, другое — не узнать (связь, нет движка или server.yml)
test_server() {
  ssh "$DEST" sudo /opt/infra/.venv/bin/python - 2>/dev/null <<'PY'
import sys

import yaml

try:
    with open("/etc/infra/server.yml") as f:
        conf = yaml.safe_load(f)
except Exception:
    sys.exit(2)
sys.exit(0 if isinstance(conf, dict) and conf.get("test_server") is True else 3)
PY
}

if [ -n "$NEW" ]; then
  rc=0
  test_server || rc=$?
  case $rc in
    0) ;;
    3) echo "!! --upgrade — только на сервере с test_server: true в /etc/infra/server.yml: режим ставит движок на прежнюю $FROM, на рабочем это откат" >&2
       exit 1 ;;
    *) echo "!! $DEST: test_server не узнать (связь, /opt/infra/.venv, /etc/infra/server.yml) — --upgrade только на тестовом" >&2
       exit 1 ;;
  esac
  run "U0. Движок $DEST — git на прежней $FROM, с GitHub" engine.log sudo bash -s -- "$FROM" "$NEW" <<'SH'
set -euo pipefail
# Копия с Мака (rsync -a) оставляет владельцем пользователя Мака, а git от root в чужой папке
# не работает («dubious ownership»); движок рабочих — клон от root
chown -R root:root /opt/infra
cd /opt/infra
if [ ! -d .git ]; then
  git init -q
  git remote add origin https://github.com/mcnickbronx/infra.git
fi
git fetch -q --tags origin
git rev-parse -q --verify "refs/tags/$2" >/dev/null ||
  { echo "infra: на GitHub нет $2 — сначала git push origin main $2"; exit 1; }
git -c advice.detachedHead=false checkout -q -f "refs/tags/$1"
git clean -q -fd
SH
  ssh "$DEST" sudo /opt/infra/install.sh
  run "U1. infra apply — прежняя $FROM, как на рабочих до выпуска" apply.log sudo infra apply -y
  run "U2. infra upgrade $NEW — та же команда, что на рабочих" upgrade.log sudo infra upgrade "$NEW" -y
  health "$LOGS/upgrade.log"
  run "U3. infra apply ещё раз — изменений быть не должно" again.log sudo infra apply -y
  unchanged "$LOGS/again.log"
  echo "Всё прошло: $FROM → $NEW тем же upgrade. Логи: $LOGS"
  exit 0
fi

echo "== 0. Копия движка на $DEST"
if test_server && ssh "$DEST" sudo test -d /opt/infra/.git; then
  echo "   движок тестового — снова копия: git после --upgrade убран"
  ssh "$DEST" sudo rm -rf /opt/infra/.git
fi
# .gitignore — чтобы не уехало локальное (.vault_pass и т.п.). .venv и коллекции сервера — ещё и
# явно: rsync в macOS (openrsync) исключённое через .gitignore на сервере при --delete удаляет
rsync -a --delete --rsync-path="sudo rsync" \
  --exclude=/.git --exclude=/tests/golden --exclude=/.venv --exclude=/collections \
  --filter=':- .gitignore' ./ "$DEST:/opt/infra/"
ssh "$DEST" sudo /opt/infra/install.sh

run "1. infra apply --check" check.log sudo infra apply --check
run "2. infra apply" apply.log sudo infra apply -y
run "3. infra apply ещё раз — изменений быть не должно" again.log sudo infra apply -y
unchanged "$LOGS/again.log"
run "4. tests/verify.yml" verify.log sudo infra run tests/verify.yml
health "$LOGS/verify.log"
[ -z "$SCENARIOS" ] || run "5. tests/scenarios.yml" scenarios.log sudo infra run tests/scenarios.yml
echo "Всё прошло. Логи: $LOGS"
