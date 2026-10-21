#!/usr/bin/env bash
# Установка движка на сервер — как установка панели.
#
# Когда: на новом сервере с Ubuntu 26.04, от root — клон в /opt/infra, последняя подписанная
# версия и этот файл (команды — ADMIN.md, «Новый сервер»). Повторный запуск ничего не ломает:
# так же после infra upgrade обновляются Ansible и коллекции.
#
# Что ставит:
#   - Ansible в /opt/infra/.venv (версии — requirements-server.txt и requirements.yml);
#   - команду infra;
#   - папку /etc/infra с secrets.yml из образца: пустые строки под ключи, которые вписываете вы,
#     пароли допишет первый sudo infra apply. server.yml создаёт sudo infra init.
#
# Не трогает: существующие server.yml и secrets.yml.
set -euo pipefail
ENGINE=$(cd "$(dirname "$(readlink -f "$0")")" && pwd)
CONF=/etc/infra
[ "$(id -u)" = 0 ] || { echo "нужен root: sudo $0" >&2; exit 1; }

# На свежем сервере apt может держать unattended-upgrades — ждём до 15 минут
if ! dpkg -s python3-venv git >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get -o DPkg::Lock::Timeout=900 update -qq
  apt-get -o DPkg::Lock::Timeout=900 install -yqq python3-venv git >/dev/null
fi

[ -x "$ENGINE/.venv/bin/python" ] || python3 -m venv "$ENGINE/.venv"
"$ENGINE/.venv/bin/pip" install -q --upgrade pip
"$ENGINE/.venv/bin/pip" install -q -r "$ENGINE/requirements-server.txt"
ANSIBLE_CONFIG=$ENGINE/ansible.cfg \
  "$ENGINE/.venv/bin/ansible-galaxy" collection install -r "$ENGINE/requirements.yml" -p "$ENGINE/collections" >/dev/null
ln -sfn "$ENGINE/infra" /usr/local/sbin/infra

install -d -m 0700 "$CONF"
if [ ! -f "$CONF/secrets.yml" ]; then
  install -m 0600 "$ENGINE/secrets.yml.example" "$CONF/secrets.yml"
fi

echo "Движок: $ENGINE ($(git -C "$ENGINE" describe --tags --always 2>/dev/null || echo 'копия, не git'))"
if [ ! -f "$CONF/server.yml" ]; then
  echo "Дальше: sudo infra init — четыре вопроса, и сервер настроится"
fi
