# Релей «Лично» в контейнере. Видит только шифртекст; хранит очередь/ключи в
# томе /data. Собирается автономно (docker compose up -d --build).
FROM node:20-bookworm-slim
WORKDIR /app

# better-sqlite3 — нативный модуль; на slim-образе может собираться из исходников,
# поэтому кладём тулчейн (для платформ без готового prebuild).
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 make g++ ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund && npm cache clean --force

# Код релея (данные — в томе /data, сюда не копируются).
COPY relay.js store.js relays.js push.js ./

ENV NODE_ENV=production
ENV PORT=8787
ENV RELAY_DB=/data/relay.db
ENV RELAY_BLOB_DIR=/data/blobs
ENV RELAY_SIGN_KEY_FILE=/data/relay-sign.key
EXPOSE 8787

CMD ["node", "relay.js"]
