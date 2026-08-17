#!/usr/bin/env bash
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
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ ! -f "$SRC_DIR/relayModules.js" ]]; then
  echo "ОШИБКА: рядом с установщиком нет relayModules.js. Копируйте каталог server/ целиком." >&2
  exit 1
fi
if ! RELAY_MODULES="$(node "$SRC_DIR/relayModules.js" "$SRC_DIR")"; then
  echo "ОШИБКА: не удалось собрать список модулей релея. Копируйте каталог server/ целиком." >&2
  exit 1
fi
while IFS= read -r module; do
  [[ -n "$module" ]] || continue
  if [[ ! -f "$SRC_DIR/$module" ]]; then
    echo "ОШИБКА: рядом с установщиком нет ${module}. Копируйте каталог server/ целиком." >&2
    exit 1
  fi
  cp "$SRC_DIR/$module" "$APP_DIR/"
done <<< "$RELAY_MODULES"
[[ -f "$SRC_DIR/package-lock.json" ]] && cp "$SRC_DIR/package-lock.json" "$APP_DIR/"

missing=""
for file in "$APP_DIR"/*.js; do
  while read -r dep; do
    [[ -f "$APP_DIR/${dep}.js" || -f "$APP_DIR/${dep}.json" || -f "$APP_DIR/${dep}" ]] || missing="${missing} ${dep}"
  done < <(grep -oE "require\('\./[a-zA-Z0-9_.-]+'\)" "$file" | sed "s/require('\.\///; s/')//")
done
if [[ -n "$missing" ]]; then
  echo "ОШИБКА: не скопированы модули релея:${missing}" >&2
  echo "Это расхождение relayModules.js со стражем — почините сбор списка." >&2
  exit 1
fi

cd "$APP_DIR"
if [[ -f "$APP_DIR/package-lock.json" ]]; then
  npm ci --omit=dev
else
  npm install --omit=dev
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
fi
chmod 600 "$TURN_SECRET_FILE"

cat >/etc/turnserver.conf <<TURN
listening-port=3478
fingerprint
use-auth-secret
static-auth-secret=${TURN_SECRET}
realm=licno
no-tls
no-dtls
no-cli
no-multicast-peers
min-port=49160
max-port=49200
external-ip=${PUBIP}
simple-log
denied-peer-ip=0.0.0.0-0.255.255.255
denied-peer-ip=10.0.0.0-10.255.255.255
denied-peer-ip=100.64.0.0-100.127.255.255
denied-peer-ip=127.0.0.0-127.255.255.255
denied-peer-ip=169.254.0.0-169.254.255.255
denied-peer-ip=172.16.0.0-172.31.255.255
denied-peer-ip=192.168.0.0-192.168.255.255
denied-peer-ip=::1
denied-peer-ip=fc00::-fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
denied-peer-ip=fe80::-febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff
TURN
chmod 640 /etc/turnserver.conf
chown root:turnserver /etc/turnserver.conf 2>/dev/null || true

sed -i 's/#TURNSERVER_ENABLED=1/TURNSERVER_ENABLED=1/' /etc/default/coturn 2>/dev/null || true
grep -q '^TURNSERVER_ENABLED=1' /etc/default/coturn 2>/dev/null || echo 'TURNSERVER_ENABLED=1' >> /etc/default/coturn
systemctl enable coturn || true
systemctl restart coturn || true
ufw allow 3478 || true
ufw allow 3478/udp || true
ufw allow 49160:49200/udp || true
log "TURN готов на ${PUBIP}:3478"

RELAY_ENV_FILE="${APP_DIR}/relay.env"
cat > "$RELAY_ENV_FILE" <<ENVFILE
TURN_SECRET=${TURN_SECRET}
TURN_HOST=${PUBIP}
ENVFILE
chmod 600 "$RELAY_ENV_FILE"
TURN_ENV="EnvironmentFile=${RELAY_ENV_FILE}"

if [[ "$MODE" == "tls" ]]; then
  SELF_URL="wss://${HOST}"
else
  SELF_URL="ws://${PUBIP:-$(curl -fsSL https://api.ipify.org || echo 127.0.0.1)}:8787"
fi
DIR_ENV="Environment=RELAY_SELF_URL=${SELF_URL}"
if [[ -n "${RELAY_PEERS:-}" ]]; then
  DIR_ENV="${DIR_ENV}
Environment=RELAY_PEERS=${RELAY_PEERS}"
  log "Стартовые соседи (peers): ${RELAY_PEERS}"
fi
log "Этот релей анонсирует себя как: ${SELF_URL}"

RELAY_USER="licno"
if ! id -u "$RELAY_USER" >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin "$RELAY_USER"
fi
mkdir -p "$APP_DIR/blobs"
chown -R "$RELAY_USER":"$RELAY_USER" "$APP_DIR"

TRUST_ENV=""
if [[ "$MODE" == "tls" ]]; then
  TRUST_ENV="Environment=RELAY_TRUST_PROXY=1"
fi

log "Создание systemd-сервиса ${SERVICE}"
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
Environment=RELAY_BLOB_DIR=${APP_DIR}/blobs
${TRUST_ENV}
${DIR_ENV}
${TURN_ENV}
Restart=always
RestartSec=3
User=${RELAY_USER}
Group=${RELAY_USER}
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=${APP_DIR}

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable ${SERVICE}
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
