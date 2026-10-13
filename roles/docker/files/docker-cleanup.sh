#!/usr/bin/env bash
# Управляется Ansible. Раз в неделю удаляет образы и кеш сборки,
# которые не используются ни одним контейнером и старше 7 дней.
# Volumes (данные) НЕ трогает.
set -euo pipefail
docker image prune -af --filter "until=168h"
docker builder prune -af --filter "until=168h"
