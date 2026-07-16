# Самодостаточный образ релея «Лично». Оператору НЕ нужен весь репозиторий и
# исходники приложения — только этот образ и пара переменных окружения.
#
#   docker run -d --name licno-relay -p 8787:8787 \
#     -e RELAY_SELF_URL=wss://<ВАШ_HOST> \
#     -e RELAY_PEERS=wss://89.108.83.230.sslip.io \
#     -v licno-data:/data \
#     ghcr.io/o34183901-gif/relay:stable
#
# node:20-slim (glibc) + build-tools: better-sqlite3 ставит нативный модуль
# (prebuild или сборка из исходников) для встроенного хранилища.
FROM node:20-slim
WORKDIR /app

# python3/make/g++ — сборка нативного better-sqlite3; coturn — встроенный TURN
# (RELAY_EMBED_COTURN, дочерний процесс релея); gosu — безопасный дроп привилегий
# в entrypoint (ДПЛ-5). Создаём непривилегированного пользователя licno.
RUN apt-get update \
  && apt-get install -y --no-install-recommends python3 make g++ coturn gosu \
  && rm -rf /var/lib/apt/lists/* \
  && groupadd -r licno && useradd -r -g licno -s /usr/sbin/nologin licno

# ДПЛ-5: манифест + lock и `npm ci` — воспроизводимая установка ровно по локу
# (не «резолвим заново» на каждой сборке). Кешируется между сборками.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

# Затем код релея (без клиентских исходников).
COPY relay.js relays.js store.js push.js ./
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh

# Рантайм-данные (SQLite-БД релея + крупные вложения в /data/blobs) — в томе,
# чтобы переживали рестарт.
ENV RELAY_DB=/data/relay.db \
    PORT=8787
VOLUME ["/data"]
EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8787)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

# ДПЛ-5: entrypoint приводит владение /data и запускает релей под licno (non-root).
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["node", "relay.js"]
