#!/usr/bin/env bash
# Управляется Ansible. Ночной бэкап в локальный репозиторий (уровень 1):
#   • по снимку на каждый проект (тег project:<имя>) — чтобы можно было
#     восстановить или перенести один проект, не трогая остальные;
#   • один снимок системы (тег system): /etc, /srv/infra, общие настройки баз.
# Затем, если настроен S3 (/etc/restic/s3-env), — копия новых снимков туда (уровень 3).
set -Eeuo pipefail

set -a; source /etc/restic/env; set +a

# Частые снимки (backup-hourly.sh) и ночной бэкап — по очереди: идёт частый — ждём его конца
exec 9>/run/restic-backup.lock
flock 9

LOG=$(mktemp)
FAILED=0
# notify /start | /fail | "" (успех) — пинг healthchecks с журналом бэкапа; без HC_URL — ничего
notify() { [ -n "${HC_URL:-}" ] && curl -fsS -m 10 --retry 3 -o /dev/null --data-binary @"$LOG" "${HC_URL}$1" || true; }
# Итог — и в журнал событий сервера (/var/log/infra.log)
trap 'notify /fail; infra-log "бэкап: ошибка — journalctl -u backup"' ERR
notify /start

# Бэкап не должен заполнить диск: сайты и базы важнее. Выше порога локальный снимок
# не пишется, приходит уведомление — освободите место или увеличьте диск.
USED=$(df --output=pcent "$RESTIC_REPOSITORY" | tail -1 | tr -dc 0-9)
if [ "$USED" -ge 90 ]; then
  echo "!!! Диск с $RESTIC_REPOSITORY заполнен на $USED% (порог 90%): бэкап не выполнен" | tee -a "$LOG"
  notify /fail
  infra-log "бэкап: не выполнен — диск заполнен на $USED%"
  exit 1
fi

restic cat config >/dev/null 2>&1 || restic init

# 1. Проекты — каждый своим снимком
for name in $(jq -r '.[].name' /etc/restic/projects.json); do
  echo "=== $name" | tee -a "$LOG"
  /usr/local/bin/project-backup "$name" >>"$LOG" 2>&1 || { FAILED=1; echo "!!! $name: ошибка" >>"$LOG"; }
done

# 2. Система: настройки сервера и инфраструктуры + глобальные роли Postgres.
#    Слева от || set -e не действует, поэтому сбой дампа ролей отмечается сам; в снимок тогда
#    идёт прошлый дамп (новый пишется рядом и заменяет его, только если удался).
#    Журнал событий — чтобы история «что, когда и кто» пережила сервер
echo "=== system" | tee -a "$LOG"
{
  install -d -m 0700 /var/backups/db
  if runuser -u postgres -- pg_dumpall --globals-only > /var/backups/db/pg-globals.sql.new; then
    mv /var/backups/db/pg-globals.sql.new /var/backups/db/pg-globals.sql
  else
    FAILED=1; echo "!!! pg_dumpall --globals-only: ошибка"
  fi
  restic backup --tag system /etc /srv/infra /var/backups/db/pg-globals.sql /var/log/infra.log \
    --exclude /srv/infra/traefik/logs
} >>"$LOG" 2>&1 || { FAILED=1; echo "!!! system: ошибка" >>"$LOG"; }

# 3. Хранение: 7 дневных, 4 недельных, 6 месячных — отдельно для каждого тега; у проектов
#    с частыми снимками (backup_hourly) ещё и по одному в час за последние 48 часов. Именно
#    --keep-within-hourly, а не --keep-hourly 48: тот оставил бы 48 последних снимков любого
#    проекта, то есть 48 ночных — полтора месяца вместо недели
restic forget --prune --group-by tags \
  --keep-within-hourly 48h --keep-daily 7 --keep-weekly 4 --keep-monthly 6 >>"$LOG" 2>&1 || FAILED=1

# 4. По воскресеньям проверяем часть данных в локальном репозитории
if [ "$(date +%u)" = 7 ]; then
  restic check --read-data-subset=5% >>"$LOG" 2>&1 || FAILED=1
fi

# 5. Копия в S3 — новые снимки дописываются, там сервер ничего не удаляет (backup-s3-copy;
#    без S3 ничего не делает)
/usr/local/bin/backup-s3-copy >>"$LOG" 2>&1 || FAILED=1

cat "$LOG"
if [ "$FAILED" = 1 ]; then
  notify /fail
  infra-log "бэкап: с ошибками — journalctl -u backup"
else
  notify ""
  infra-log "бэкап: готово"
fi
rm -f "$LOG"
