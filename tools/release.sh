#!/usr/bin/env bash
# Выпуск версии движка одной командой — на машине автора, не на сервере. Запуск из любой папки:
#   tools/release.sh 1.11.0 "заголовок версии"
# Шаги, любой сбой — остановка, ничего не отправляется:
#   1. ветка main, дерево чистое, тега ещё нет, версия новее последнего тега, в «Не выпущено» есть записи;
#   2. make check;
#   3. CHANGELOG: под «## Не выпущено» — «## vX.Y.Z — дата — заголовок», записи остаются под ним, а
#      «Не выпущено» — пустым над ним (без него ветки создают раздел каждая сама и конфликтуют);
#      заголовок — тот, что меню показывает при выборе версии;
#   4. коммит «vX.Y.Z: заголовок» (только CHANGELOG.md) и подписанный тег; подпись проверяет
#      тот же infra tag-signed, что и на сервере;
#   5. печатает, что дальше: push — руками.
set -euo pipefail
cd "$(dirname "$0")/.." || exit 1

die() { echo "release: $*" >&2; exit 1; }

V=${1:-}; TITLE=${2:-}
[[ $V =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && -n $TITLE ]] || die 'использование: tools/release.sh X.Y.Z "заголовок"'
T=v$V

# ---------- Проверки до любых изменений ----------
[ "$(git rev-parse --abbrev-ref HEAD)" = main ] || die "выпуск — с ветки main"
[ -z "$(git status --porcelain)" ] || die "в дереве есть несохранённое — закоммитьте или уберите"
! git rev-parse -q --verify "refs/tags/$T" >/dev/null || die "тег $T уже есть"
last=$(git tag -l 'v[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname | head -n 1)
if [ -n "$last" ]; then
  IFS=. read -r a1 a2 a3 <<<"${last#v}"; IFS=. read -r b1 b2 b3 <<<"$V"
  (( 10#$b1 > 10#$a1 || (10#$b1 == 10#$a1 && (10#$b2 > 10#$a2 || (10#$b2 == 10#$a2 && 10#$b3 > 10#$a3))) )) \
    || die "$T не новее последней версии $last"
fi
n=$(awk '/^## Не выпущено$/ { on = 1; next } /^## / { on = 0 } on && /^- /' CHANGELOG.md | wc -l | tr -d ' ')
[ "$n" -gt 0 ] || die "в «Не выпущено» пусто — выпускать нечего"

# RELEASE_CHECK — только для тестов этого скрипта
${RELEASE_CHECK:-make check}

# ---------- Выпуск ----------
awk -v h="## $T — $(date +%F) — $TITLE" \
  '!done && /^## Не выпущено$/ { print; print ""; print h; done = 1; next } 1' CHANGELOG.md > CHANGELOG.md.new
mv CHANGELOG.md.new CHANGELOG.md
git commit -q -m "$T: $TITLE" -- CHANGELOG.md

# Сбой дальше — коммит уже есть: сами не откатываем, говорим как
undo() { die "$1. Убрать выпуск: git tag -d $T; git reset --hard HEAD~1"; }
git tag -s "$T" -m "$T" || undo "тег $T не создан (ключ: git config gpg.format ssh, user.signingkey — README)"
./infra tag-signed "$T" || undo "тег $T не подписан ключом из SIGNERS"

cat <<NEXT
$T готов: коммит $(git rev-parse --short HEAD), тег подписан, записей — $n.
Дальше:
  git push origin main $T
  tools/rollout.sh admin@<тестовый> --scenarios        # или на тестовом: sudo infra upgrade $T
  на каждом рабочем: sudo infra upgrade $T --check, затем без --check
NEXT
