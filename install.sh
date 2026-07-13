#!/usr/bin/env bash
#
# Установщик релея «Лично» для Ubuntu 22.04 / 24.04.
#
# Использование (от root или через sudo):
#
#   # Вариант A — с настоящим TLS через бесплатный sslip.io (РЕКОМЕНДУЕТСЯ):
#   #   HOST = <IP-с-точками>.sslip.io, напр. 203.0.113.7.sslip.io
#   sudo bash install.sh 203.0.113.7.sslip.io
#
#   # Вариант B — свой домен (A-запись уже указывает на сервер):
#   sudo bash install.sh relay.example.com
#
#   # Вариант C — без TLS, чистый ws:// на порту 8787 (быстрый тест):
#   sudo bash install.sh --plain
#
# В приложении «Лично» затем указываете адрес сервера:
#   Вариант A/B ->  wss://<HOST>
#   Вариант C   ->  ws://<IP>:8787
#
set -euo pipefail

MODE="tls"
HOST="${1:-}"
if [[ "$HOST" == "--plain" || "$HOST" == "" ]]; then
  MODE="plain"
fi

APP_DIR="/opt/licno-relay"
SERVICE="licno-relay"

log() { echo -e "\n\033[1;34m==>\033[0m $*"; }

if [[ $EUID -ne 0 ]]; then
  echo "Запустите через sudo/root." >&2
  exit 1
fi

log "Обновление пакетов и базовые утилиты"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y curl ca-certificates gnupg ufw

log "Установка Node.js 20 (если нужно)"
if ! command -v node >/dev/null || [[ "$(node -v | cut -c2-3)" -lt 18 ]]; then
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt-get install -y nodejs
fi
node -v

log "Копирование релея в ${APP_DIR}"
mkdir -p "$APP_DIR"
# скрипт лежит рядом с relay.js/package.json — копируем их
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cp "$SRC_DIR/relay.js" "$SRC_DIR/relays.js" "$SRC_DIR/store.js" "$SRC_DIR/push.js" "$SRC_DIR/package.json" "$APP_DIR/"
cd "$APP_DIR"
# build-tools нужны для нативного модуля better-sqlite3 (встроенное хранилище)
apt-get install -y --no-install-recommends python3 make g++ || true
npm install --omit=dev

# Optional FCM push: if a Firebase service-account JSON is present next to the
# installer, wire it in so offline users get wake-up notifications. Project id
# is read from the file itself.
FCM_ENV=""
if [[ -f "$SRC_DIR/service-account.json" ]]; then
  cp "$SRC_DIR/service-account.json" "$APP_DIR/service-account.json"
  chmod 600 "$APP_DIR/service-account.json"
  FCM_PROJECT_ID="$(node -e "console.log(require('$APP_DIR/service-account.json').project_id)")"
  FCM_ENV="Environment=GOOGLE_APPLICATION_CREDENTIALS=${APP_DIR}/service-account.json
Environment=FCM_PROJECT_ID=${FCM_PROJECT_ID}"
  log "FCM настроен для проекта ${FCM_PROJECT_ID}"
else
  log "service-account.json не найден — пуши при закрытом приложении отключены (релей работает)"
fi

log "Установка и настройка TURN-сервера (coturn) для звонков"
apt-get install -y coturn
PUBIP="$(curl -fsSL https://api.ipify.org || echo '')"
TURN_SECRET_FILE="${APP_DIR}/turn-secret"
if [[ -f "$TURN_SECRET_FILE" ]]; then
  TURN_SECRET="$(cat "$TURN_SECRET_FILE")"
else
  TURN_SECRET="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  echo -n "$TURN_SECRET" > "$TURN_SECRET_FILE"
  chmod 600 "$TURN_SECRET_FILE"
fi

cat >/etc/turnserver.conf <<TURN
listening-port=3478
fingerprint
use-auth-secret
static-auth-secret=${TURN_SECRET}
realm=licno
no-tls
no-dtls
no-cli
min-port=49160
max-port=49200
external-ip=${PUBIP}
simple-log
# M-4: не ретранслировать во внутренние сети/облачные метаданные/loopback/multicast
# (иначе coturn становится open-relay и SSRF-плацдармом во внутреннюю сеть).
no-multicast-peers
denied-peer-ip=0.0.0.0-0.255.255.255
denied-peer-ip=10.0.0.0-10.255.255.255
denied-peer-ip=100.64.0.0-100.127.255.255
denied-peer-ip=127.0.0.0-127.255.255.255
denied-peer-ip=169.254.0.0-169.254.255.255
denied-peer-ip=172.16.0.0-172.31.255.255
denied-peer-ip=192.168.0.0-192.168.255.255
TURN

# enable the coturn systemd service
sed -i 's/#TURNSERVER_ENABLED=1/TURNSERVER_ENABLED=1/' /etc/default/coturn 2>/dev/null || true
grep -q '^TURNSERVER_ENABLED=1' /etc/default/coturn 2>/dev/null || echo 'TURNSERVER_ENABLED=1' >> /etc/default/coturn
systemctl enable coturn || true
systemctl restart coturn || true
ufw allow 3478 || true
ufw allow 3478/udp || true
ufw allow 49160:49200/udp || true
log "TURN готов на ${PUBIP}:3478"

TURN_ENV="Environment=TURN_SECRET=${TURN_SECRET}
Environment=TURN_HOST=${PUBIP}"

# --- каталог релеев (gossip): анонсируем себя и стартовых соседей ------------
# RELAY_SELF_URL — публичный адрес ЭТОГО релея, кладётся в общий каталог, чтобы
# другие узнали о нём. RELAY_PEERS — стартовые соседи (через запятую), из чьих
# каталогов мы подтянем остальную сеть. Задать соседей можно так:
#   sudo RELAY_PEERS="wss://relay-a.example.com,wss://relay-b.example.com" bash install.sh <HOST>
if [[ "$MODE" == "tls" ]]; then
  SELF_URL="wss://${HOST}"
else
  SELF_URL="ws://${PUBIP:-$(curl -fsSL https://api.ipify.org || echo 127.0.0.1)}:8787"
fi
# L-8: RELAY_DIR удалён — relay.js его не читает (мёртвая настройка). Каталог
# релеев живёт в SQLite-БД (RELAY_DB), отдельный путь не нужен.
DIR_ENV="Environment=RELAY_SELF_URL=${SELF_URL}"
if [[ -n "${RELAY_PEERS:-}" ]]; then
  DIR_ENV="${DIR_ENV}
Environment=RELAY_PEERS=${RELAY_PEERS}"
  log "Стартовые соседи (peers): ${RELAY_PEERS}"
fi
log "Этот релей анонсирует себя как: ${SELF_URL}"

log "Создание systemd-сервиса ${SERVICE}"
# M-2: за Caddy (TLS-режим) реальный IP клиента приходит в X-Forwarded-For —
# доверяем одному прокси, чтобы per-IP лимиты считались по клиенту, а не по адресу
# Caddy. В plain-режиме прокси нет, поэтому XFF НЕ доверяем (его можно подделать).
if [[ "$MODE" == "tls" ]]; then
  PROXY_ENV="Environment=RELAY_TRUST_PROXY=1"
else
  PROXY_ENV=""
fi

cat >/etc/systemd/system/${SERVICE}.service <<UNIT
[Unit]
Description=Licno relay (encrypted store-and-forward)
After=network.target

[Service]
Type=simple
WorkingDirectory=${APP_DIR}
ExecStart=/usr/bin/node ${APP_DIR}/relay.js
Environment=PORT=8787
Environment=RELAY_DB=${APP_DIR}/relay.db
${DIR_ENV}
${FCM_ENV}
${TURN_ENV}
${PROXY_ENV}
Restart=always
RestartSec=3
User=root
# M-3: базовый харденинг systemd — RCE в релее не должен давать доступ ко всей ФС.
# ProtectSystem=full делает /usr,/boot,/etc только для чтения (релей пишет лишь в
# APP_DIR); NoNewPrivileges запрещает повышение прав.
NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable ${SERVICE}
# restart (not just --now) so an already-running service picks up new code
systemctl restart ${SERVICE}

log "Настройка firewall (ufw)"
ufw allow 22/tcp || true
if [[ "$MODE" == "tls" ]]; then
  ufw allow 80/tcp || true
  ufw allow 443/tcp || true
else
  ufw allow 8787/tcp || true
fi
yes | ufw enable || true

if [[ "$MODE" == "tls" ]]; then
  log "Установка Caddy (авто-TLS, проксирование WebSocket)"
  apt-get install -y debian-keyring debian-archive-keyring apt-transport-https
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' >/etc/apt/sources.list.d/caddy-stable.list
  apt-get update -y
  apt-get install -y caddy

  log "Caddyfile для ${HOST} -> localhost:8787"
  cat >/etc/caddy/Caddyfile <<CADDY
${HOST} {
    reverse_proxy localhost:8787
}
CADDY
  systemctl restart caddy

  echo -e "\n\033[1;32mГотово!\033[0m Релей доступен по:  wss://${HOST}"
  echo "Проверка:  curl https://${HOST}/health"
else
  PUBIP="$(curl -fsSL https://api.ipify.org || echo '<IP-сервера>')"
  echo -e "\n\033[1;32mГотово!\033[0m Релей (без TLS) доступен по:  ws://${PUBIP}:8787"
  echo "Проверка:  curl http://${PUBIP}:8787/health"
fi

echo
echo "Статус:   systemctl status ${SERVICE} --no-pager"
echo "Логи:     journalctl -u ${SERVICE} -f"
