FROM node:20-slim
WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends python3 make g++ coturn gosu curl ca-certificates \
  && rm -rf /var/lib/apt/lists/* \
  && groupadd -r licno && useradd -r -g licno -s /usr/sbin/nologin licno

ARG NTFY_VERSION=2.27.0
ARG NTFY_SHA256=4b7220cb0e7673a66ace8e1368573c0df89888aafde6860ae3a48ae1174c8cee
RUN set -eux; \
  case "$(dpkg --print-architecture)" in \
    amd64) NTFY_ARCH=linux_amd64 ;; \
    *) echo "ntfy: неподдержанная архитектура $(dpkg --print-architecture)" >&2; exit 1 ;; \
  esac; \
  curl -fsSL -o /tmp/ntfy.tar.gz \
    "https://github.com/binwiederhier/ntfy/releases/download/v${NTFY_VERSION}/ntfy_${NTFY_VERSION}_${NTFY_ARCH}.tar.gz"; \
  echo "${NTFY_SHA256}  /tmp/ntfy.tar.gz" | sha256sum -c -; \
  tar -xzf /tmp/ntfy.tar.gz -C /tmp "ntfy_${NTFY_VERSION}_${NTFY_ARCH}/ntfy"; \
  install -m 0755 "/tmp/ntfy_${NTFY_VERSION}_${NTFY_ARCH}/ntfy" /usr/local/bin/ntfy; \
  rm -rf /tmp/ntfy.tar.gz "/tmp/ntfy_${NTFY_VERSION}_${NTFY_ARCH}"; \
  ntfy --version

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY binary-frame.js ed25519.js envelopeFrame.js gateway-ticket.js httpRateLimit.js landing.js \
  linked-devices.js mailboxEvict.js mailboxGcs.js mbx.js nativeEd25519.js nativeX25519.js notifications.js \
  ntfy.js push.js queueAdmission.js relay.js relays.js releaseKey.js reports.js store.js updateFeed.js \
  updateManifest.js updateMirror.js vapid-fleet.js vapid-fleet.json vapid-identity.js \
  webApp.js x25519.js ./
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh

ENV RELAY_DB=/data/relay.db \
    PORT=8787 \
    RELAY_EMBED_NTFY=1
VOLUME ["/data"]
EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8787)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["node", "relay.js"]
