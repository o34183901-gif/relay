# Самодостаточный образ релея «Лично». Оператору НЕ нужен весь репозиторий и
# исходники приложения — только этот образ и пара переменных окружения.
#
#   docker run -d --name licno-relay -p 8787:8787 \
#     -e RELAY_SELF_URL=wss://<ВАШ_HOST> \
#     -e RELAY_PEERS=wss://89.108.83.230.sslip.io \
#     -v licno-data:/data \
#     ghcr.io/o34183901-gif/relay:latest
#
# node:20-slim (glibc) + build-tools: better-sqlite3 ставит нативный модуль
# (prebuild или сборка из исходников) для встроенного хранилища.
FROM node:20-slim
WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends python3 make g++ \
  && rm -rf /var/lib/apt/lists/*

# Сначала только манифест — кешируем npm install между сборками.
COPY package.json ./
RUN npm install --omit=dev && npm cache clean --force

# Затем код релея (без клиентских исходников).
COPY relay.js relays.js store.js push.js ./

# Рантайм-данные (SQLite-БД релея) — в томе, чтобы переживали рестарт.
ENV RELAY_DB=/data/relay.db \
    PORT=8787
VOLUME ["/data"]
EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8787)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "relay.js"]
