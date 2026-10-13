#!/usr/bin/env bash
# Проверка движка на сервере — рабочая копия отсюда, без git. Запуск из любой папки:
#   tools/rollout.sh admin@<тестовый> --scenarios     # тестовый сервер: всё (make test-vds)
#   tools/rollout.sh admin@<сервер>                    # раскатка и проверка без сценариев
# Шаги, любой сбой — остановка:
#   0. копия движка на сервер в /opt/infra (rsync без того, что в .gitignore: .vault_pass и прочее
#      локальное не уезжает; .venv и коллекции сервера не трогает) и install.sh — Ansible тех версий,
#      что в копии;
#   1. infra apply --check — ошибки, видные без изменений;
#   2. infra apply -y;
#   3. infra apply -y ещё раз — изменений быть не должно (иначе какая-то задача не идемпотентна:
#      каждый прогон что-то меняет, и настоящие изменения в предпросмотре не видны);
#   4. tests/verify.yml — сервер в том состоянии, которое обещано (только чтение);
#   5. --scenarios: tests/scenarios.yml — бэкап и восстановление, удаление людей и т.п.
#      по-настоящему (только на сервере с test_server: true в server.yml).
# Рабочие серверы обновляются не так, а из git: sudo infra upgrade <версия> (ADMIN.md).
set -euo pipefail
cd "$(dirname "$0")/.." || exit 1
DEST=${1:?Использование: tools/rollout.sh <ssh-адрес> [--scenarios]}
shift
SCENARIOS=""
for a in "$@"; do
  case $a in
    --scenarios) SCENARIOS=1 ;;
    *) echo "Неизвестный параметр: $a" >&2; exit 2 ;;
  esac
done

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

echo "== 0. Копия движка на $DEST"
# .gitignore — чтобы не уехало локальное (.vault_pass и т.п.). .venv и коллекции сервера — ещё и
# явно: rsync в macOS (openrsync) исключённое через .gitignore на сервере при --delete удаляет
rsync -a --delete --rsync-path="sudo rsync" \
  --exclude=/.git --exclude=/tests/golden --exclude=/.venv --exclude=/collections \
  --filter=':- .gitignore' ./ "$DEST:/opt/infra/"
ssh "$DEST" sudo /opt/infra/install.sh

run "1. infra apply --check" check.log sudo infra apply --check
run "2. infra apply" apply.log sudo infra apply -y
run "3. infra apply ещё раз — изменений быть не должно" again.log sudo infra apply -y
if recap "$LOGS/again.log" | grep -qE 'changed=[1-9]'; then
  echo "!! Повторный прогон снова что-то изменил — эти задачи не идемпотентны:"
  awk '/^TASK \[/ { task = $0 } /^changed:/ { print "   " task " — " $2 }' "$LOGS/again.log" | sort -u
  echo "   Полный вывод: $LOGS/again.log"
  exit 1
fi
run "4. tests/verify.yml" verify.log sudo infra run tests/verify.yml
grep -A3 'Что сейчас сообщает health-check' "$LOGS/verify.log" | grep -E '^\s+"' | sed 's/^/   health-check: /' || true
[ -z "$SCENARIOS" ] || run "5. tests/scenarios.yml" scenarios.log sudo infra run tests/scenarios.yml
echo "Всё прошло. Логи: $LOGS"
