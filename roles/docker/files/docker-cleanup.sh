#!/usr/bin/env bash
# Управляется Ansible. Раз в неделю удаляет образы и кеш сборки,
# которые не используются ни одним контейнером и старше 7 дней.
# Volumes (данные) НЕ трогает.
set -euo pipefail
# И в Docker каждого проекта без root (rootless: true) — у него свои образы
for host in "" $(jq -r '.[].sock' /usr/local/etc/infra-rootless.json 2>/dev/null); do
  env ${host:+DOCKER_HOST="$host"} docker image prune -af --filter "until=168h"
  env ${host:+DOCKER_HOST="$host"} docker builder prune -af --filter "until=168h"
done
