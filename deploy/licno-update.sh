#!/usr/bin/env bash
#
# licno-update.sh — верифицированный авто-апдейтер релея (замена watchtower, H-1).
#
# Что делает раз в интервал (systemd-таймер):
#   1) тянет образ канала (:stable по умолчанию) — слои лишь скачиваются, код НЕ
#      исполняется;
#   2) ПРОВЕРЯЕТ cosign-подпись ИМЕННО скачанного digest (keyless: подпись должна
#      исходить от workflow image.yml репозитория relay на ветке main);
#   3) только при валидной подписи применяет `docker compose up -d` (idempotent —
#      пересоздаёт relay лишь если digest сменился).
#
# Не проходит проверку -> обновление НЕ применяется, релей продолжает работать на
# прежнем (проверенном) образе. Никакого контейнера с docker.sock: скрипт крутит
# docker на хосте под systemd (доверие уровня хоста, а не подтягиваемого образа).
set -euo pipefail

IMAGE="${LICNO_IMAGE:-ghcr.io/o34183901-gif/relay}"
COMPOSE_DIR="${LICNO_COMPOSE_DIR:-/opt/licno-relay}"   # где лежит docker-compose.yml
IDENTITY="${LICNO_COSIGN_IDENTITY:-https://github.com/o34183901-gif/relay/.github/workflows/image.yml@refs/heads/main}"
ISSUER="${LICNO_COSIGN_ISSUER:-https://token.actions.githubusercontent.com}"

log() { echo "[licno-update] $*"; }

command -v cosign >/dev/null 2>&1 || { log "cosign не установлен — см. deploy/install-updater.sh"; exit 1; }
cd "$COMPOSE_DIR"

# Реальный образ канала берём из compose (с учётом .env: :stable по умолчанию,
# :canary если в .env задан LICNO_CHANNEL). Апдейтер и compose всегда согласованы.
IMG_REF="$(docker compose config --images 2>/dev/null | grep "${IMAGE}[:@]" | head -1 || true)"
[ -n "$IMG_REF" ] || { log "не нашёл образ ${IMAGE} в docker-compose.yml"; exit 1; }

# 1) Скачать образ канала (только загрузка слоёв, без запуска).
docker compose pull relay

# 2) Digest того, что скачали.
DIGEST="$(docker image inspect "$IMG_REF" --format '{{index .RepoDigests 0}}' 2>/dev/null | sed 's/.*@//' || true)"
[ -n "$DIGEST" ] || { log "не удалось определить digest для $IMG_REF"; exit 1; }

# 3) Проверить подпись ИМЕННО этого digest (то, что и запустим).
if ! cosign verify \
      --certificate-identity "$IDENTITY" \
      --certificate-oidc-issuer "$ISSUER" \
      "${IMAGE}@${DIGEST}" >/dev/null 2>&1; then
  log "ОТКАЗ: подпись ${IMAGE}@${DIGEST} не прошла проверку — обновление НЕ применяю"
  exit 1
fi

# 4) Применить (compose пересоздаст relay только если digest реально сменился).
log "подпись OK — применяю ${IMAGE}@${DIGEST}"
docker compose up -d --remove-orphans
