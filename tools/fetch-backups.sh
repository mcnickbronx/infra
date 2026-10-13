#!/usr/bin/env bash
# Уровень 2 бэкапов: копия у вас на компьютере. Запускайте раз в неделю:
#   tools/fetch-backups.sh admin@<сервер> [папка]    # по умолчанию ~/backups/<адрес сервера>
#
# Забирает с сервера только НОВЫЕ файлы локального репозитория restic и ничего не удаляет
# и не перезаписывает у вас. Файлы restic после записи не меняются (имя файла — хеш
# содержимого), поэтому, даже если репозиторий на сервере испортят или удалят, уже
# скачанное останется целым. Забирает ваш компьютер: у сервера доступа к нему нет.
#
# Копия — обычный репозиторий restic, пароль — restic_password сервера (менеджер паролей):
#   restic -r ~/backups/<сервер> snapshots
#   restic -r ~/backups/<сервер> check        # раз в пару месяцев
# Копия только растёт (удалённое на сервере у вас остаётся); чистить у себя:
#   restic -r ~/backups/<сервер> forget --prune --keep-monthly 12
set -euo pipefail
DEST=${1:?Использование: tools/fetch-backups.sh <ssh-адрес> [папка]}
DIR=${2:-$HOME/backups/${DEST#*@}}

# Во время ночного бэкапа можно забрать недописанный файл, а --ignore-existing его потом не исправит
if ssh "$DEST" systemctl is-active -q backup.service; then
  echo "На $DEST идёт ночной бэкап — запустите позже" >&2
  exit 1
fi
mkdir -p "$DIR"
chmod 700 "$DIR"
rsync -a --ignore-existing --exclude=/locks/ --rsync-path="sudo rsync" "$DEST:/var/backups/restic/" "$DIR/"
echo "Копия: $DIR"
