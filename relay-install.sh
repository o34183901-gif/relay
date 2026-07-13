#!/usr/bin/env bash
#
# Установка релея «Лично» ОДНИМ файлом на арендованный сервер (Ubuntu/Debian).
#
# ПОЛНОСТЬЮ автономно: скрипт САМ ставит все зависимости (Docker + compose, git,
# curl), скачивает код релея, генерирует все секреты и поднимает весь стек
# (релей + Caddy авто-TLS + coturn для звонков). Адрес релея ВСЕГДА берётся
# автоматически как <публичный-IP>.sslip.io — домен не нужен.
#
# Запуск — просто:
#   sudo bash relay-install.sh
#
# Дальше скрипт САМ спросит АДРЕС ПИРА (единственный ввод):
#   • нажмите Enter — пропустить (релей поднимется сам по себе), ЛИБО
#   • введите адрес по образцу wss://хост.
# Другого способа задать пир нет — только этот диалог.
#   • где взять адрес: приложение «Лично» → «Профиль» → «Сеть» → адрес сервера.
#
# Клиентам ничего вводить не нужно — ключ подлинности релея они закрепляют сами (TOFU).
set -euo pipefail

REPO_URL="${RELAY_REPO_URL:-https://github.com/o34183901-gif/relay.git}"
APP_DIR="${RELAY_APP_DIR:-/opt/licno-relay}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || echo /tmp)"

log() { echo -e "\n\033[1;34m==>\033[0m $*"; }
if [[ $EUID -ne 0 ]]; then
  echo "Запустите через sudo/root." >&2
  exit 1
fi

log "Базовые пакеты (curl, git)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y || true
apt-get install -y curl git ca-certificates || true

log "Docker (установим, если ещё нет)"
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | sh
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "Нужен Docker Compose v2 (входит в свежий Docker). Обновите Docker." >&2
  exit 1
fi

# Код + деплой-комплект. Если этот скрипт запущен ИЗ уже скачанного репозитория
# (рядом лежит docker-compose.yml) — используем его на месте; иначе скачиваем
# (git clone) в ${APP_DIR}. Так один файл работает и «соло», и внутри репозитория.
if [[ -f "$SCRIPT_DIR/docker-compose.yml" ]]; then
  WORK="$SCRIPT_DIR"
  log "Использую комплект рядом со скриптом: $WORK"
else
  log "Скачивание кода релея из $REPO_URL"
  if [[ -d "$APP_DIR/.git" ]]; then
    git -C "$APP_DIR" pull --ff-only || true
  else
    git clone --depth 1 "$REPO_URL" "$APP_DIR"
  fi
  WORK="$APP_DIR"
fi
cd "$WORK"

PUBIP="$(curl -fsSL https://api.ipify.org || echo '')"
if [[ -z "$PUBIP" ]]; then
  echo "Не удалось определить публичный IP сервера (нет сети?)." >&2
  exit 1
fi
# Адрес релея — ВСЕГДА <публичный-IP>.sslip.io (бесплатный TLS без домена).
HOST="${PUBIP}.sslip.io"
# Адрес пира задаётся ТОЛЬКО в диалоге ниже (никаких аргументов/переменных).
PEERS=""

# Интерактивный запрос пира. Если терминала нет (установка через «curl | sudo
# bash») — диалог невозможен, релей просто поднимется сам по себе (пир — Enter).
if [[ -t 0 ]]; then
  echo
  echo "──────────────────────────────────────────────────────────────────────"
  echo " Адрес пира — другого уже работающего релея, чтобы этот сервер вошёл в"
  echo " общую сеть (обмен каталогом релеев). Можно оставить пустым — сервер"
  echo " будет работать сам по себе, а другие узнают о нём позже."
  echo
  echo " Где взять: в приложении «Лично» → «Профиль» → раздел «Сеть» → там"
  echo " показан адрес сервера (строка вида wss://…). Это и есть адрес пира."
  echo
  echo " Формат (по образцу):  wss://<IP>.sslip.io"
  echo "              напр.:   wss://203.0.113.7.sslip.io"
  echo " Несколько пиров — через запятую."
  echo "──────────────────────────────────────────────────────────────────────"
  read -r -p " Адрес пира [Enter — пропустить]: " PEERS || PEERS=""
fi

# Лёгкая валидация введённого: каждый адрес должен быть ws:// или wss://.
if [[ -n "$PEERS" ]]; then
  _clean=""
  IFS=',' read -ra _parts <<< "$PEERS"
  for _p in "${_parts[@]}"; do
    _p="$(echo "$_p" | tr -d '[:space:]')"
    [[ -z "$_p" ]] && continue
    if [[ "$_p" =~ ^wss?://[^[:space:]]+$ ]]; then
      _clean="${_clean:+$_clean,}$_p"
    else
      log "Пропускаю некорректный адрес пира: '$_p' (нужен формат wss://хост)"
    fi
  done
  PEERS="$_clean"
fi

log "Конфигурация (.env)"
if [[ ! -f .env ]]; then
  cp .env.example .env
  gen() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }
  set_kv() { sed -i "s|^$1=.*|$1=$2|" .env; }
  set_kv RELAY_HOST "$HOST"
  set_kv RELAY_SELF_URL "wss://${HOST}"
  set_kv TURN_HOST "$PUBIP"
  set_kv TURN_SECRET "$(gen 32)"
  set_kv RELAY_GOSSIP_TOKEN "$(gen 24)"
  set_kv RELAY_METRICS_TOKEN "$(gen 16)"
  [[ -n "$PEERS" ]] && set_kv RELAY_PEERS "$PEERS"
  log "Сгенерированы секреты TURN/gossip/metrics; host=${HOST}${PEERS:+; пиры=${PEERS}}"
else
  log ".env уже есть — использую существующий (секреты не трогаю)"
  [[ -n "$PEERS" ]] && sed -i "s|^RELAY_PEERS=.*|RELAY_PEERS=$PEERS|" .env && log "Обновил RELAY_PEERS=${PEERS}"
fi

log "Firewall (ufw, если установлен)"
if command -v ufw >/dev/null 2>&1; then
  ufw allow 22/tcp || true
  ufw allow 80/tcp || true
  ufw allow 443/tcp || true
  ufw allow 3478/tcp || true
  ufw allow 3478/udp || true
  ufw allow 49160:49200/udp || true
fi

log "Сборка и запуск (docker compose up -d --build)"
docker compose up -d --build

# FCM (необязательно): если рядом лежит service-account.json — кладём в том данных,
# чтобы релей будил закрытые приложения пушами.
if [[ -f service-account.json ]]; then
  log "FCM: копирую service-account.json в контейнер релея"
  docker compose cp service-account.json relay:/data/service-account.json
  docker compose restart relay
else
  log "service-account.json не найден — пуши при закрытом приложении выключены (релей работает)"
fi

log "Готово"
echo "Релей:    wss://${HOST}"
echo "Проверка: curl https://${HOST}/health"
echo "Логи:     cd ${WORK} && docker compose logs -f relay"
# Ключ подлинности релея — для информации; клиенты закрепляют его сами (TOFU).
sleep 6
KEY="$(docker compose logs relay 2>/dev/null | grep -o 'RELAY_SIGN_PUBLIC=[A-Za-z0-9+/=]*' | tail -1 || true)"
[[ -n "$KEY" ]] && echo "Ключ релея (TOFU, вводить не нужно): ${KEY}"
