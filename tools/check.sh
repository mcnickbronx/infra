#!/usr/bin/env bash
# Все проверки без серверов — те же, что в CI (.github/workflows/lint.yml).
# Запуск из любой папки: tools/check.sh (или make check). Минута-две.
#
# Инструменты — тех же версий, что в CI, в .venv репозитория (один раз: make venv).
# Без .venv берутся из PATH; чего нет (nft, docker) — шаг пропускается с пометкой.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
[ -x .venv/bin/ansible-lint ] && PATH="$PWD/.venv/bin:$PATH"
export PYTHONDONTWRITEBYTECODE=1 ANSIBLE_FORCE_COLOR=0 ANSIBLE_NOCOLOR=1

FAILED=()
LOG=$(mktemp)
trap 'rm -f "$LOG"' EXIT

# Название шага с выравниванием (printf считает байты, а не буквы)
label() { printf '%s%*s' "$1" $((56 - ${#1})) ''; }

# step <название> <команда...>: вывод показывается, только если шаг не прошёл
step() {
  local name=$1; shift
  label "$name"
  if "$@" >"$LOG" 2>&1; then
    echo "ok"
  else
    echo "ОШИБКА"
    sed 's/^/    /' "$LOG" | tail -60
    FAILED+=("$name")
  fi
}
skip() { label "$1"; echo "пропущено: $2"; }
have() { command -v "$1" >/dev/null 2>&1; }

# Плейбуки движка читают /etc/infra/server.yml сервера — здесь его нет, синтаксис проверяется
# на тестовом инвентаре
syntax() {
  ansible-playbook -i tests/inventory site.yml update.yml --syntax-check &&
  ansible-playbook -i tests/inventory tests/render.yml tests/invalid.yml tests/verify.yml tests/scenarios.yml --syntax-check
}

# Скрипты на bash/sh в ролях, tools/, сам движок (infra, infra-menu, install.sh) — все, а не список:
# новый не забудется
scripts() {
  find roles/*/files tools infra infra-menu install.sh -type f -exec grep -lE '^#!(/usr/bin/env (bash|sh)|/bin/(ba)?sh)' {} + || true
}
shellcheck_files() { scripts | xargs shellcheck -S warning -e SC1090,SC1091; }

# Шаблоны рендерятся на тестовом инвентаре и сравниваются с эталоном в git.
# Изменение ожидаемое — посмотрите git diff tests/golden и добавьте: git add tests/golden
golden() {
  ansible-playbook -i tests/inventory tests/render.yml >/dev/null || {
    ansible-playbook -i tests/inventory tests/render.yml | grep -E 'fatal|msg' | head -20; return 1; }
  local new
  new=$(git ls-files --others --exclude-standard -- tests/golden)
  if ! git diff --quiet -- tests/golden || [ -n "$new" ]; then
    echo "Результат шаблонов отличается от эталона (tests/golden):"
    git --no-pager diff --stat -- tests/golden
    [ -z "$new" ] || printf 'новые файлы:\n%s\n' "$new"
    echo "Посмотрите: git diff tests/golden. Так и задумано — git add tests/golden"
    return 1
  fi
}
shellcheck_rendered() {
  find tests/golden -name '*.sh' -print0 | xargs -0 shellcheck -s bash -S warning -e SC1090,SC1091
}
invalid() {
  ansible-playbook -i tests/inventory tests/invalid.yml > "$LOG.inv" 2>&1 && return 0
  grep -E 'Ждали|ERROR' "$LOG.inv" | grep -v 'Task failed: Action failed: Ждали' | head -20
  rm -f "$LOG.inv"; return 1
}
python_tests() { python3 -m unittest discover -s tests -q; }

# compose-шаблон — настоящим docker compose (в CI он есть)
compose_check() {
  local d f
  d=$(mktemp -d)
  for f in tests/golden/*/docker/base.yml; do
    cp "$f" "$d/base.yml"
    printf 'services:\n  a: {extends: {file: base.yml, service: hardened}, image: alpine}\n  b: {extends: {file: base.yml, service: hardened-strict}, image: alpine}\n' > "$d/compose.yml"
    (cd "$d" && COMPOSE_PROJECT_NAME=check docker compose config -q) || { rm -rf "$d"; return 1; }
  done
  rm -rf "$d"
}

step "Синтаксис плейбуков" syntax
step "ansible-lint (профиль production)" ansible-lint --offline -q
step "shellcheck скриптов" shellcheck_files
step "Шаблоны совпадают с эталоном (tests/golden)" golden
step "shellcheck скриптов из шаблонов" shellcheck_rendered
step "Проверки инвентаря ловят ошибки (tests/invalid.yml)" invalid
step "Python (tests/test_scripts.py)" python_tests
if have docker && docker compose version >/dev/null 2>&1; then
  step "base.yml для compose (docker compose config)" compose_check
else
  skip "base.yml для compose (docker compose config)" "нет docker (проверяется в CI)"
fi

echo
if [ ${#FAILED[@]} -gt 0 ]; then
  printf 'Не прошло: %s\n' "${FAILED[@]}"
  exit 1
fi
echo "Все проверки прошли"
