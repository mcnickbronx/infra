#!/usr/bin/env bash
# Управляется Ansible. Частые снимки — проектам с backup_hourly в server.yml, тем же project-backup,
# что и ночью, в локальный репозиторий (уровень 1): backup_hourly: all — база и папки проекта, как
# ночной снимок; db — только база (project-backup --db-only). Как часто — backup_every, минут
# (по умолчанию 60): первый снимок часа в :05, дальше через каждые backup_every минут (15 — в :05,
# :20, :35, :50). Таймер срабатывает с шагом самого частого проекта, остальные ждут своей минуты.
# Сразу после снимков — копия в S3 (backup-s3-copy): с потерей сервера теряется не больше
# backup_every минут. На сервере хранятся 48 часов, по одному в час (restic forget ночного бэкапа).
# Неудача — в $STATE/failed, о ней сообщает health-check. В журнал событий — только когда снимки
# перестали получаться и когда снова получились: десятки строк в сутки там не нужны.
#   backup-hourly.sh        — проекты, чья минута настала (так запускает таймер)
#   backup-hourly.sh --all  — все проекты с backup_hourly, сейчас
set -Eeuo pipefail

ALL=""
[ "${1:-}" != --all ] || ALL=1

STATE=/var/lib/backup-hourly
install -d -m 0700 "$STATE"

# Ночной бэкап снимает все проекты сам — пока он идёт, частые снимки пропускаются.
# Ночной, наоборот, дожидается конца частых (та же блокировка в backup.sh)
exec 9>/run/restic-backup.lock
flock -n 9 || { echo "идёт другой бэкап — пропуск"; exit 0; }

set -a; source /etc/restic/env; set +a

# Диск почти полон — не дописываем (о диске сообщает health-check, ночной бэкап тоже остановится)
USED=$(df --output=pcent "$RESTIC_REPOSITORY" | tail -1 | tr -dc 0-9)
if [ "$USED" -ge 90 ]; then
  echo "диск с $RESTIC_REPOSITORY заполнен на $USED% — снимки пропущены"
  exit 0
fi

# Проект снимается, если от :05 прошло кратное его backup_every число минут. Запуск мог опоздать
# (прошлый ещё шёл) — пока не дольше шага таймера, это та же минута. Шаг делит любой backup_every
# (1, 5, 15, 30, 60), поэтому минута каждого проекта попадает на срабатывание таймера.
# BACKUP_HOURLY_MINUTE — задать минуту вместо текущей (сценарии тестов)
STEP=5
MINUTE=$((10#${BACKUP_HOURLY_MINUTE:-$(date +%M)}))

failed=()
taken=0
while read -r name mode every; do
  [ -n "$ALL" ] || [ $(( (MINUTE + 55) % every )) -lt "$STEP" ] || continue
  echo "=== $name ($mode, каждые $every мин)"
  if [ "$mode" = db ]; then
    /usr/local/bin/project-backup --db-only "$name" || failed+=("$name")
  else
    /usr/local/bin/project-backup "$name" || failed+=("$name")
  fi
  taken=$((taken + 1))
done < <(jq -r '.[] | select(.hourly) | "\(.name) \(.hourly) \(.every)"' /etc/restic/projects.json)

# Сразу в S3 — всё, чего там ещё нет; не удалось — следующий запуск доложит пропущенное
if [ "$taken" -gt 0 ]; then
  /usr/local/bin/backup-s3-copy || failed+=("S3")
fi

if [ -n "${failed[*]}" ]; then
  [ -s "$STATE/failed" ] || infra-log "частые снимки: ошибка — ${failed[*]} (journalctl -u backup-hourly)"
  echo "$(date '+%F %H:%M') ${failed[*]}" > "$STATE/failed"
  exit 1
fi
if [ -s "$STATE/failed" ]; then
  infra-log "частые снимки: снова получаются"
  rm -f "$STATE/failed"
fi
[ "$taken" -eq 0 ] || touch "$STATE/last-ok"
