#!/usr/bin/env bash
set -euo pipefail

IMAGE="${LICNO_IMAGE:-ghcr.io/o34183901-gif/relay}"
COMPOSE_DIR="${LICNO_COMPOSE_DIR:-/opt/licno-relay}"
IDENTITY="${LICNO_COSIGN_IDENTITY:-https://github.com/o34183901-gif/relay/.github/workflows/image.yml@refs/heads/main}"
ISSUER="${LICNO_COSIGN_ISSUER:-https://token.actions.githubusercontent.com}"
HEALTH_TIMEOUT=90

log() { echo "[licno-update] $*"; }

command -v cosign >/dev/null 2>&1 || { log "cosign не установлен — см. deploy/install-updater.sh"; exit 1; }
cd "$COMPOSE_DIR"

IMG_REF="$(docker compose config --images relay 2>/dev/null | grep -F "$IMAGE" | head -1 || true)"
[ -n "$IMG_REF" ] || { log "не нашёл образ ${IMAGE} в docker-compose.yml"; exit 1; }

digest_of() { docker image inspect "$1" --format '{{if .RepoDigests}}{{index .RepoDigests 0}}{{end}}' 2>/dev/null | sed 's/.*@//' || true; }
created_of() { docker image inspect "$1" --format '{{.Created}}' 2>/dev/null || true; }
restore_prev() { [ -n "$PREV_DIGEST" ] && docker tag "${IMAGE}@${PREV_DIGEST}" "$IMG_REF" >/dev/null 2>&1 || true; }

PREV_DIGEST="$(digest_of "$IMG_REF")"
PREV_CREATED="$(created_of "$IMG_REF")"

docker compose pull relay

NEW_DIGEST="$(digest_of "$IMG_REF")"
[ -n "$NEW_DIGEST" ] || { log "не удалось определить digest для $IMG_REF"; exit 1; }

if ! COSIGN_OUT="$(cosign verify \
      --certificate-identity "$IDENTITY" \
      --certificate-oidc-issuer "$ISSUER" \
      "${IMAGE}@${NEW_DIGEST}" 2>&1)"; then
  log "ОТКАЗ: подпись ${IMAGE}@${NEW_DIGEST} не прошла проверку — обновление НЕ применяю"
  log "cosign: ${COSIGN_OUT}"
  restore_prev
  exit 1
fi

if [ -n "$PREV_DIGEST" ] && [ "$PREV_DIGEST" = "$NEW_DIGEST" ]; then
  log "образ не изменился (${NEW_DIGEST}) — применять нечего"
  exit 0
fi

NEW_CREATED="$(created_of "${IMAGE}@${NEW_DIGEST}")"
if [ -n "$PREV_CREATED" ] && [ -n "$NEW_CREATED" ] && [[ "$NEW_CREATED" < "$PREV_CREATED" ]]; then
  log "ОТКАЗ: предложенный образ собран ${NEW_CREATED}, старше установленного ${PREV_CREATED} — похоже на подмену тега старым подписанным образом (откат), НЕ применяю"
  restore_prev
  exit 1
fi

log "подпись OK, образ не старше текущего — применяю ${IMAGE}@${NEW_DIGEST}"
docker compose up -d --remove-orphans --pull never

CID="$(docker compose ps -q relay 2>/dev/null || true)"
healthy=0
if [ -n "$CID" ]; then
  deadline=$(( $(date +%s) + HEALTH_TIMEOUT ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    st="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$CID" 2>/dev/null || echo unknown)"
    case "$st" in
      healthy|none) healthy=1; break ;;
      *) sleep 3 ;;
    esac
  done
fi

if [ "$healthy" -ne 1 ]; then
  log "ОТКАЗ: ${IMAGE}@${NEW_DIGEST} не стал healthy за ${HEALTH_TIMEOUT}s — откатываю на ${PREV_DIGEST:-<нет предыдущего>}"
  if [ -n "$PREV_DIGEST" ]; then
    restore_prev
    docker compose up -d --remove-orphans --pull never
  fi
  exit 1
fi

log "обновление применено и подтверждено healthy: ${IMAGE}@${NEW_DIGEST}"
docker image prune -f >/dev/null 2>&1 || true
