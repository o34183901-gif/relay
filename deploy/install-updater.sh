#!/usr/bin/env bash
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "Запустите через sudo/root." >&2; exit 1; }

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_DIR="${1:-$(dirname "$SRC")}"
COSIGN_VERSION="${COSIGN_VERSION:-v2.4.1}"

echo "==> Каталог compose: $COMPOSE_DIR"
[ -f "$COMPOSE_DIR/docker-compose.yml" ] || { echo "В $COMPOSE_DIR нет docker-compose.yml"; exit 1; }

if ! command -v cosign >/dev/null 2>&1; then
  echo "==> Ставлю cosign $COSIGN_VERSION"
  case "$(uname -m)" in
    x86_64) A=amd64 ;;
    aarch64|arm64) A=arm64 ;;
    *) A=amd64 ;;
  esac
  base="https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}"
  tmp="$(mktemp -d)"
  curl -fsSL "${base}/cosign-linux-${A}" -o "${tmp}/cosign"
  curl -fsSL "${base}/cosign_checksums.txt" -o "${tmp}/sums.txt"
  expected="$(awk -v f="cosign-linux-${A}" '$2==f {print $1}' "${tmp}/sums.txt")"
  actual="$(sha256sum "${tmp}/cosign" | awk '{print $1}')"
  if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
    echo "ОШИБКА: контрольная сумма cosign не совпала (ожидалось '$expected', получено '$actual') — прерываю." >&2
    rm -rf "$tmp"; exit 1
  fi
  install -m 0755 "${tmp}/cosign" /usr/local/bin/cosign
  rm -rf "$tmp"
fi
cosign version >/dev/null 2>&1 || { echo "cosign не работает"; exit 1; }

echo "==> Ставлю апдейтер и таймер"
install -m 0755 "$SRC/licno-update.sh" /usr/local/bin/licno-update.sh
install -m 0644 "$SRC/licno-update.service" /etc/systemd/system/licno-update.service
install -m 0644 "$SRC/licno-update.timer" /etc/systemd/system/licno-update.timer
sed -i "s#^Environment=LICNO_COMPOSE_DIR=.*#Environment=LICNO_COMPOSE_DIR=${COMPOSE_DIR}#" /etc/systemd/system/licno-update.service

systemctl daemon-reload
systemctl enable --now licno-update.timer

echo "==> Готово. Первый прогон запускаю сейчас:"
systemctl start licno-update.service || true
echo
echo "Проверка:   systemctl list-timers licno-update.timer"
echo "Логи:       journalctl -u licno-update.service -n 50 --no-pager"
