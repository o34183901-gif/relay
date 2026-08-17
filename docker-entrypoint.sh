#!/bin/sh
set -e
if [ "$(id -u)" = "0" ]; then
  chown -R licno:licno /data 2>/dev/null || true
  exec gosu licno "$@"
fi
exec "$@"
