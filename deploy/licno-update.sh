#!/usr/bin/env bash
set -euo pipefail

IMAGE="${LICNO_IMAGE:-ghcr.io/o34183901-gif/relay}"
COMPOSE_DIR="${LICNO_COMPOSE_DIR:-/opt/licno-relay}"
IDENTITY="${LICNO_COSIGN_IDENTITY:-https://github.com/o34183901-gif/relay/.github/workflows/image.yml@refs/heads/main}"
ISSUER="${LICNO_COSIGN_ISSUER:-https://token.actions.githubusercontent.com}"

log() { echo "[licno-update] $*"; }

command -v cosign >/dev/null 2>&1 || { log "cosign не установлен — см. deploy/install-updater.sh"; exit 1; }
cd "$COMPOSE_DIR"

IMG_REF="$(docker compose config --images 2>/dev/null | grep "${IMAGE}[:@]" | head -1 || true)"
[ -n "$IMG_REF" ] || { log "не нашёл образ ${IMAGE} в docker-compose.yml"; exit 1; }

docker compose pull relay

DIGEST="$(docker image inspect "$IMG_REF" --format '{{index .RepoDigests 0}}' 2>/dev/null | sed 's/.*@//' || true)"
[ -n "$DIGEST" ] || { log "не удалось определить digest для $IMG_REF"; exit 1; }

if ! cosign verify \
      --certificate-identity "$IDENTITY" \
      --certificate-oidc-issuer "$ISSUER" \
      "${IMAGE}@${DIGEST}" >/dev/null 2>&1; then
  log "ОТКАЗ: подпись ${IMAGE}@${DIGEST} не прошла проверку — обновление НЕ применяю"
  exit 1
fi

log "подпись OK — применяю ${IMAGE}@${DIGEST}"
docker compose up -d --remove-orphans
