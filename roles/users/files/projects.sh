# shellcheck shell=bash
# Управляется Ansible (роль users). Для входа по SSH.
# go [проект] — в папку проекта /srv/projects/<проект>/web, Tab дополняет имя. Без имени —
# единственный проект; проектов несколько — их список. Проекты — группы <проект>-dev.
# Переход по настоящему пути, не через ссылку: compose запоминает путь, с которого его запустили.
[ -n "${BASH_VERSION:-}" ] || return 0
command -v go >/dev/null 2>&1 && return 0     # стоит язык Go — его команду не заменяем

_go_projects() {
  local g
  for g in $(id -nG); do
    [[ $g == *-dev ]] && echo "${g%-dev}"
  done
}

go() {
  local list
  list=$(_go_projects)
  if [[ -z ${1:-} ]]; then
    case $(grep -c . <<<"$list") in
      0) echo "У вас нет проектов на этом сервере"; return 1 ;;
      1) set -- "$list" ;;
      *) echo "Проекты: $(tr '\n' ' ' <<<"$list")— go <проект>"; return 0 ;;
    esac
  fi
  cd "/srv/projects/$1/web" || return 1
  echo "→ $PWD"
  [ -f VERSION ] && echo "  версия: $(cat VERSION)"
  return 0
}

complete -W "$(_go_projects)" go
