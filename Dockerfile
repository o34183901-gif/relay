# Самодостаточный образ релея «Лично». Оператору НЕ нужен весь репозиторий и
# исходники приложения — только этот образ и пара переменных окружения.
#
#   docker run -d --name licno-relay -p 8787:8787 \
#     -e RELAY_SELF_URL=wss://<ВАШ_HOST> \
#     -e RELAY_PEERS=wss://89.108.83.230.sslip.io \
#     -v licno-data:/data \
#     ghcr.io/o34183901-gif/licno-relay:latest
#
FROM node:20-alpine
WORKDIR /app

# Сначала только манифест — кешируем npm install между сборками.
COPY package.json ./
RUN npm install --omit=dev && npm cache clean --force

# Затем код релея (без клиентских исходников).
COPY relay.js relays.js push.js ./

# Рантайм-данные (очередь/каталог/токены) — в томе, чтобы переживали рестарт.
ENV RELAY_DATA=/data/queue.json \
    RELAY_DIR=/data/relays.json \
    RELAY_PUSH=/data/push-tokens.json \
    RELAY_IDENT=/data/identities.json \
    PORT=8787
VOLUME ["/data"]
EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8787)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "relay.js"]
