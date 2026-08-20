#!/bin/sh
set -e
if [ "$(id -u)" = "0" ]; then
  if [ "$(stat -c '%U' /data 2>/dev/null || echo '?')" != "licno" ]; then
    chown -R licno:licno /data
  fi
  exec gosu licno "$@"
fi
exec "$@"
