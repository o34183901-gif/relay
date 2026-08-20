const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const dns = require('dns').promises;
const nacl = require('tweetnacl');
const naclUtil = require('tweetnacl-util');
const { WebSocketServer } = require('ws');
const {
  sendPush,
  sendCallPush,
  sendTestPush,
  setVapidKeys,
  vapidPublicKey,
  vapidPublicKeyFor,
  generateVapidKeys,
} = require('./push');
const { mergeRelays, isValidRelayUrl, normalizeRelayUrl, isPrivateHost, coturnConfigText, rateGate, byteGate, buildIceServers, parsePublicStun, MAX_RELAYS } = require('./relays');
const { chatNotificationTag, createPushGate } = require('./notifications');
const { createStore } = require('./store');
const mbx = require('./mbx');
const { createHttpRateLimit } = require('./httpRateLimit');

const updateFeed = require('./updateFeed');
const updateManifestRule = require('./updateManifest');
const ntfy = require('./ntfy');
const updateMirror = require('./updateMirror');
const webApp = require('./webApp');
const landing = require('./landing');
const { RELEASE_PUBLIC_KEY } = require('./releaseKey');
const ed25519 = require('./ed25519');
const gatewayTicketRule = require('./gateway-ticket');
const reportsRule = require('./reports');
const REPORTS_OWNER_KEY = process.env.RELAY_REPORTS_KEY || '';
const { resolveNativeEd25519 } = require('./nativeEd25519');
const nativeEd25519 = resolveNativeEd25519(() => crypto);
if (nativeEd25519.implementation) ed25519.setNative(nativeEd25519.implementation);
const x25519 = require('./x25519');
const { resolveNativeX25519 } = require('./nativeX25519');
const nativeX25519 = resolveNativeX25519(() => crypto);
if (nativeX25519.implementation) x25519.setNative(nativeX25519.implementation);
const { unpackBinaryFrame, packBinaryFrame } = require('./binary-frame');
const envelopeFrame = require('./envelopeFrame');
const { encode: encodeMessagePack, decode: decodeMessagePack } = require('@msgpack/msgpack');
const {
  assertDeviceCertificate,
  assertSignedRoster,
  rosterWriteGate,
  stableStringify,
  MAX_ACTIVE_DEVICES,
} = require('./linked-devices');
const {
  loadFleetConfig,
  memberFor,
  memberAcceptsKey,
  validVapidPair,
  signVapidBundle,
  verifyVapidBundle,
  createVapidRequest,
  verifyVapidRequest,
  createVapidResponse,
  openVapidResponse,
  sourceMatchesResolved,
  readJsonFile,
  writeJsonAtomic,
} = require('./vapid-fleet');
const TURN_HOST = process.env.TURN_HOST;
let turnSecret = null;
const PUBLIC_STUN = parsePublicStun(process.env.RELAY_PUBLIC_STUN);
function turnIceServers() {
  return buildIceServers({
    turnSecret,
    turnHost: TURN_HOST,
    publicStun: PUBLIC_STUN,
    now: Date.now(),
    hmac: (username) => crypto.createHmac('sha1', turnSecret).update(username).digest('base64'),
  });
}

const PORT = process.env.PORT || 8787;
const RELAY_PROTOCOL = 6;
const RELAY_CAPABILITIES = Object.freeze([
  'linked-devices-v2',
  'device-queues',
  'signed-rosters',
  'binary-attachments-v1',
  'push-test-v1',
  'frame-batch-v1',
  envelopeFrame.BINARY_ENVELOPE_CAPABILITY,
  'prekeys-count-v1',
  'mbx-v1',
  'cover-traffic-v1',
  gatewayTicketRule.PULL_CAPABILITY,
  'reports-v1',
]);
const DB_FILE = process.env.RELAY_DB || path.join(__dirname, 'relay.db');
const MAX_QUEUE_PER_USER = 500;
const MAX_TOTAL_MESSAGES = Number(process.env.RELAY_MAX_TOTAL_MESSAGES) || 200000;
const MAX_QUEUE_BYTES = Number(process.env.RELAY_MAX_QUEUE_BYTES) || 8 * 1024 * 1024 * 1024;
const MAX_QUEUE_PER_SENDER = Number(process.env.RELAY_MAX_QUEUE_PER_SENDER) || 100;
const QUEUE_RESERVE_SLOTS = Number(process.env.RELAY_QUEUE_RESERVE) || 100;
const QUEUE_TTL_MS = Number(process.env.RELAY_TTL_MS) || 14 * 24 * 3600 * 1000;
const MBX_MAX_RECORDS = Number(process.env.RELAY_MBX_MAX_RECORDS) || mbx.MAX_RECORDS;
const MBX_PUT_MAX = Number(process.env.RELAY_MBX_PUT_MAX) || 64;
const MBX_PUT_WINDOW_MS = 60 * 1000;
const MAX_IDENTITIES = Number(process.env.RELAY_MAX_IDENTITIES) || 500000;
const BLOB_DIR = process.env.RELAY_BLOB_DIR || path.join(path.dirname(DB_FILE), 'blobs');
const BLOB_THRESHOLD = Number(process.env.RELAY_BLOB_THRESHOLD) || 64 * 1024;
const store = createStore(DB_FILE, { blobDir: BLOB_DIR, blobThreshold: BLOB_THRESHOLD });
function mbxValueHash(record) {
  return crypto
    .createHash('sha256')
    .update(Buffer.from(record.value))
    .update(Buffer.from(record.mac))
    .digest();
}

const mbxDigest = mbx.createDigestCache();
function mbxTrim(now = Date.now()) {
  const removed = store.mbxExpire(mbx.slotOf(now - mbx.TTL_MS));
  return removed + store.mbxTrimTo(MBX_MAX_RECORDS);
}

const MBX_DIGEST_MIN_INTERVAL_MS = Number(process.env.RELAY_MBX_DIGEST_MS) || 1000;
function mbxRefreshDigest(now = Date.now()) {
  return mbxDigest.refreshIfDue(store.mbxRevision(), () => store.mbxKeys(), {
    now,
    minIntervalMs: MBX_DIGEST_MIN_INTERVAL_MS,
  });
}
{
  const orphans = store.cleanupOrphanBlobs();
  if (orphans) console.log(`[blobs] removed ${orphans} orphan attachment file(s)`);
}


const SELF_URL = normalizeRelayUrl(process.env.RELAY_SELF_URL || '') || null;
const REPORTS_SELF_HOST = (() => {
  if (!SELF_URL) return '';
  try {
    return new URL(SELF_URL).host;
  } catch (e) {
    return '';
  }
})();
const PEER_SEED = (process.env.RELAY_PEERS || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);
const GOSSIP_INTERVAL_MS = Number(process.env.RELAY_GOSSIP_MS) || 60000;
const GOSSIP_TOKEN = process.env.RELAY_GOSSIP_TOKEN || null;
let relayDir = mergeRelays([], [SELF_URL, ...PEER_SEED, ...store.directory()].filter(Boolean));
store.addRelays(relayDir, Date.now());
function learnRelays(urls) {
  const before = relayDir.length;
  const seen = mergeRelays([], urls);
  relayDir = mergeRelays(relayDir, urls);
  if (seen.length) store.addRelays(seen, Date.now());
  return relayDir.length !== before;
}
function sweepRelayDirectory(now = Date.now()) {
  store.addRelays([], now);
  relayDir = mergeRelays([], [SELF_URL, ...PEER_SEED, ...store.directory()].filter(Boolean));
}
const MAX_ENVELOPE_BYTES = 32 * 1024 * 1024;
const MAX_SEALED_PAYLOAD_BYTES = envelopeFrame.maxSealedBytes(MAX_ENVELOPE_BYTES);
const MAX_BINARY_CHUNK_BYTES = 300 * 1024;
const MAX_BINARY_CHUNKS = 4096;
const JSON_FRAME_OVERHEAD_BYTES = 128 * 1024;
const MAX_JSON_FRAME_BYTES = MAX_ENVELOPE_BYTES + JSON_FRAME_OVERHEAD_BYTES;
const MAX_PREAUTH_FRAME_BYTES = 64 * 1024;
const AUTH_TIMEOUT_MS = 10000;
const RATE_WINDOW_MS = 1000;
const RATE_MAX_FRAMES = 80;
const RATE_MAX_BYTES = Number(process.env.RELAY_MAX_BYTES_PER_SEC) || 12 * 1024 * 1024;
const RATE_ABUSE_WINDOWS = Number(process.env.RELAY_ABUSE_WINDOWS) || 15;
const COSTLY_WINDOW_MS = 60 * 1000;
const MBX_DIGEST_MAX_PER_MIN = Number(process.env.RELAY_MBX_DIGEST_PER_MIN) || 10;
const TURN_MAX_PER_MIN = 30;
const PUSH_TEST_MAX_PER_MIN = 12;
const MBX_FETCH_MAX_PER_MIN = Number(process.env.RELAY_MBX_FETCH_PER_MIN) || 30;
const MBX_HTTP_MAX_PER_MIN = Number(process.env.RELAY_MBX_HTTP_PER_MIN) || 12;
const MBX_HTTP_PAGE = Math.min(mbx.SYNC_LIMIT, Number(process.env.RELAY_MBX_HTTP_PAGE) || 512);
const mbxHttpRate = createHttpRateLimit({ max: MBX_HTTP_MAX_PER_MIN, windowMs: COSTLY_WINDOW_MS });
const reportHttpRate = createHttpRateLimit({
  max: reportsRule.PER_IP_PER_DAY,
  windowMs: reportsRule.DAY_MS,
});
const REPORT_ADMIN_MAX_PER_MIN = 30;
const reportAdminRate = createHttpRateLimit({ max: REPORT_ADMIN_MAX_PER_MIN, windowMs: COSTLY_WINDOW_MS });
const REPORT_FETCH_MAX_BYTES = 4 * 1024 * 1024;
const reportOwnerReplay = new Map();
function reportRequestFresh(domain, signature, now) {
  if (typeof signature !== 'string' || !signature) return false;
  const key = domain + '|' + signature;
  for (const [seen, until] of reportOwnerReplay) {
    if (until <= now) reportOwnerReplay.delete(seen);
  }
  if (reportOwnerReplay.has(key)) return false;
  reportOwnerReplay.set(key, now + reportsRule.REQUEST_TTL_MS + reportsRule.REQUEST_SKEW_MS);
  return true;
}
const ROSTER_PUT_MAX_PER_MIN = Number(process.env.RELAY_ROSTER_PUT_PER_MIN) || 10;
const UPDATE_DIR = process.env.RELAY_UPDATE_DIR || path.join(path.dirname(DB_FILE), 'releases');
const UPDATE_MIRROR_OFF = String(process.env.RELAY_UPDATE_MIRROR || '').trim().toLowerCase() === 'off';
const UPDATE_SOURCE = String(process.env.RELAY_UPDATE_SOURCE || updateMirror.DEFAULT_SOURCE).trim();
const UPDATE_MIRROR_MS = Number(process.env.RELAY_UPDATE_MIRROR_MS) || updateMirror.DEFAULT_INTERVAL_MS;
const WEB_DIR = path.join(UPDATE_DIR, 'web');
const UPDATE_MANIFEST_MAX_PER_MIN = Number(process.env.RELAY_UPDATE_MANIFEST_PER_MIN) || 12;
const UPDATE_FILE_MAX_PER_MIN = Number(process.env.RELAY_UPDATE_FILE_PER_MIN) || 3;
const updateManifestRate = createHttpRateLimit({
  max: UPDATE_MANIFEST_MAX_PER_MIN,
  windowMs: COSTLY_WINDOW_MS,
});
const updateFileRate = createHttpRateLimit({ max: UPDATE_FILE_MAX_PER_MIN, windowMs: COSTLY_WINDOW_MS });
const healthHttpRate = createHttpRateLimit({ max: 60, windowMs: COSTLY_WINDOW_MS });
const helloSigRate = createHttpRateLimit({ max: 60, windowMs: COSTLY_WINDOW_MS });
const NTFY_MAX_PER_MIN = 60;
const ntfyHttpRate = createHttpRateLimit({ max: NTFY_MAX_PER_MIN, windowMs: COSTLY_WINDOW_MS });
let healthStatsCache = null;
let healthStatsAt = 0;
function healthStats(now) {
  if (healthStatsCache && now - healthStatsAt < 1000) return healthStatsCache;
  healthStatsCache = store.stats();
  healthStatsAt = now;
  return healthStatsCache;
}
const MAX_CONN_PER_IP = Number(process.env.RELAY_MAX_CONN_PER_IP) || 1000;
const MAX_BUFFERED_BYTES = Number(process.env.RELAY_MAX_BUFFERED) || 64 * 1024 * 1024;
const METRICS_TOKEN = process.env.RELAY_METRICS_TOKEN || null;
const START_TS = Date.now();
const counters = {
  msgsIn: 0,
  deliveredOnline: 0,
  queuedOffline: 0,
  acked: 0,
  pushes: 0,
  authOk: 0,
  dropped: 0,
  throttled: 0,
  abusive: 0,
  oversized: 0,
  overloaded: 0,
  costlyRefused: 0,
  rosterDeniedEarly: 0,
  cover: 0,
  mbxHttpLimited: 0,
  reportsIn: 0,
  reportsRefused: 0,
  updateManifestServed: 0,
  updateFileServed: 0,
  updateHttpLimited: 0,
  ntfyProxied: 0,
  ntfyProxyErrors: 0,
};
const EVENT_LOOP_PROBE_MS = 500;
const LAG_WINDOW = 120;
const LAG_ALERT_MS = Number(process.env.RELAY_LAG_ALERT_MS) || 250;
const LAG_ALERT_STREAK = Number(process.env.RELAY_LAG_ALERT_STREAK) || 3;
const LAG_LOG_INTERVAL_MS = 60000;
const eventLoopLag = { last: 0, max: 0, samples: [], streak: 0, overloaded: false, loggedAt: 0 };
let eventLoopProbeAt = Date.now();
function eventLoopLagP99() {
  const list = eventLoopLag.samples;
  if (!list.length) return 0;
  const sorted = [...list].sort((left, right) => left - right);
  return sorted[Math.min(sorted.length - 1, Math.max(0, Math.ceil(sorted.length * 0.99) - 1))];
}
function relayOverloaded() {
  return eventLoopLag.overloaded;
}
function sampleEventLoopLag(now = Date.now()) {
  const lag = Math.max(0, now - eventLoopProbeAt - EVENT_LOOP_PROBE_MS);
  eventLoopProbeAt = now;
  eventLoopLag.last = lag;
  if (lag > eventLoopLag.max) eventLoopLag.max = lag;
  eventLoopLag.samples.push(lag);
  if (eventLoopLag.samples.length > LAG_WINDOW) eventLoopLag.samples.shift();
  eventLoopLag.streak =
    lag >= LAG_ALERT_MS
      ? eventLoopLag.streak + Math.max(1, Math.floor(lag / EVENT_LOOP_PROBE_MS))
      : 0;
  const overloaded = eventLoopLag.streak >= LAG_ALERT_STREAK;
  if (overloaded && !eventLoopLag.overloaded) {
    console.warn(
      `[lag] узел перегружен: задержка цикла ${lag} мс ${eventLoopLag.streak} проб подряд ` +
        `(порог ${LAG_ALERT_MS} мс, p99 ${eventLoopLagP99()} мс). Клиентам сообщено.`
    );
    eventLoopLag.loggedAt = now;
  } else if (overloaded && now - eventLoopLag.loggedAt >= LAG_LOG_INTERVAL_MS) {
    console.warn(`[lag] перегрузка продолжается: p99 ${eventLoopLagP99()} мс`);
    eventLoopLag.loggedAt = now;
  } else if (!overloaded && eventLoopLag.overloaded) {
    console.warn(`[lag] перегрузка снята: p99 ${eventLoopLagP99()} мс`);
  }
  eventLoopLag.overloaded = overloaded;
}
const eventLoopTimer = setInterval(sampleEventLoopLag, EVENT_LOOP_PROBE_MS);
if (typeof eventLoopTimer.unref === 'function') eventLoopTimer.unref();
function renderMetrics() {
  const st = store.stats();
  const mem = process.memoryUsage();
  const lines = [];
  const metric = (name, type, help, value, labels) => {
    lines.push(`# HELP ${name} ${help}`);
    lines.push(`# TYPE ${name} ${type}`);
    lines.push(`${name}${labels || ''} ${value}`);
  };
  metric('licno_up', 'gauge', 'Relay process is up.', 1);
  metric('licno_uptime_seconds', 'gauge', 'Seconds since process start.', Math.round((Date.now() - START_TS) / 1000));
  lines.push('# HELP licno_connections WebSocket connections.');
  lines.push('# TYPE licno_connections gauge');
  lines.push(`licno_connections{state="open"} ${wss.clients.size}`);
  lines.push(`licno_connections{state="authed"} ${online.size}`);
  metric('licno_known_relays', 'gauge', 'Relays known to this node (gossip directory).', relayDir.length);
  metric('licno_queue_users', 'gauge', 'Users with pending (undelivered) envelopes.', st.usersQueued);
  metric('licno_queue_messages', 'gauge', 'Pending envelopes in the store-and-forward queue.', st.totalQueued);
  metric('licno_queue_bytes', 'gauge', 'Bytes held by the queue (DB rows + attachment blobs on disk).', store.queueBytes());
  metric('licno_messages_in_total', 'counter', 'Envelopes accepted from senders since start.', counters.msgsIn);
  metric('licno_messages_delivered_online_total', 'counter', 'Envelopes pushed to an online recipient since start.', counters.deliveredOnline);
  metric('licno_messages_queued_offline_total', 'counter', 'Envelopes queued for an offline recipient since start.', counters.queuedOffline);
  metric('licno_messages_dropped_total', 'counter', 'Envelopes dropped (recipient queue full, no own slots) since start.', counters.dropped);
  metric('licno_throttled_total', 'counter', 'Times a connection was paused for exceeding the byte budget.', counters.throttled);
  metric('licno_abusive_closed_total', 'counter', 'Connections closed for sustained byte-budget abuse.', counters.abusive);
  metric(
    'licno_costly_refused_total',
    'counter',
    'Expensive frames refused by the per-minute budget (mailbox digest/fetch, roster writes).',
    counters.costlyRefused
  );
  metric(
    'licno_roster_denied_early_total',
    'counter',
    'Device-roster writes rejected on permissions before any signature was verified.',
    counters.rosterDeniedEarly
  );
  metric('licno_messages_acked_total', 'counter', 'Envelopes confirmed received by recipients since start.', counters.acked);
  metric('licno_push_sent_total', 'counter', 'Wake-up pushes sent since start.', counters.pushes);
  metric('licno_auth_success_total', 'counter', 'Successful client authentications since start.', counters.authOk);
  metric('process_resident_memory_bytes', 'gauge', 'Resident set size of the relay process.', mem.rss);
  metric('nodejs_heap_used_bytes', 'gauge', 'V8 heap used by the relay process.', mem.heapUsed);
  metric(
    'licno_event_loop_lag_ms',
    'gauge',
    'Задержка event-loop за последний интервал: время, которое цикл был занят и никого не обслуживал.',
    eventLoopLag.last
  );
  metric(
    'licno_event_loop_lag_max_ms',
    'gauge',
    'Максимальная задержка event-loop с момента старта процесса.',
    eventLoopLag.max
  );
  metric(
    'licno_event_loop_lag_p99_ms',
    'gauge',
    'p99 задержки event-loop по скользящему окну. Порог для алерта: см. licno_overloaded.',
    eventLoopLagP99()
  );
  metric(
    'licno_overloaded',
    'gauge',
    'Узел считает себя перегруженным (задержка цикла держится выше порога). Клиентам сообщается, чтобы они ушли на соседний релей.',
    relayOverloaded() ? 1 : 0
  );
  metric(
    'licno_overload_notices_total',
    'counter',
    'Сколько раз узел сообщил клиенту о перегрузке.',
    counters.overloaded
  );
  metric(
    'licno_oversized_frames_total',
    'counter',
    'Кадров отвергнуто по размеру ДО разбора (АУД-06): их содержимое узел даже не читал.',
    counters.oversized
  );
  metric(
    'licno_cover_frames_total',
    'counter',
    'Кадров-пустышек принято и выброшено (СРЕД-03). Это полоса, но не сообщения: в очередь они не встают и никого не будят.',
    counters.cover
  );
  metric(
    'licno_mbx_http_limited_total',
    'counter',
    'Отказов HTTP-репликации ящика по частоте (ВЫС-19). Рост — узел дёргают как усилитель, а не реплицируют.',
    counters.mbxHttpLimited
  );
  metric(
    'licno_update_manifest_served_total',
    'counter',
    'Манифестов выпуска отдано (ОБН-2). Байты; растёт вместе с числом устройств, которым этот релей известен.',
    counters.updateManifestServed
  );
  metric(
    'licno_update_file_served_total',
    'counter',
    'Файлов выпуска отдано (ОБН-2). Десятки мегабайт за штуку — это и есть цена включённой раздачи.',
    counters.updateFileServed
  );
  metric(
    'licno_update_http_limited_total',
    'counter',
    'Отказов раздачи обновлений по частоте (ОБН-2). Рост — узел качают как файлопомойку.',
    counters.updateHttpLimited
  );
  metric(
    'licno_ntfy_proxied_total',
    'counter',
    'Запросов, переданных встроенному серверу уведомлений (УВД-4). Ноль при живом флоте — уведомления не доходят.',
    counters.ntfyProxied
  );
  metric(
    'licno_ntfy_proxy_errors_total',
    'counter',
    'Сбоев передачи встроенному серверу уведомлений (УВД-4). Рост — процесс ntfy упал или не слушает порт.',
    counters.ntfyProxyErrors
  );
  return lines.join('\n') + '\n';
}
function safeEqual(a, b) {
  const ab = Buffer.from(String(a == null ? '' : a));
  const bb = Buffer.from(String(b == null ? '' : b));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}
function metricsAuthorized(req) {
  if (!METRICS_TOKEN) return isPrivateHost((req && req.socket && req.socket.remoteAddress) || '');
  const url = new URL(req.url, 'http://x');
  if (safeEqual(url.searchParams.get('token'), METRICS_TOKEN)) return true;
  const auth = (req.headers && req.headers.authorization) || '';
  return safeEqual(auth, `Bearer ${METRICS_TOKEN}`);
}
const vapidRequestRate = new Map();
const vapidRequestNonces = new Map();
let vapidGlobalRate = null;
function readJsonRequest(req, maxBytes = 32 * 1024) {
  return new Promise((resolve) => {
    let body = '';
    let done = false;
    const finish = (value) => {
      if (done) return;
      done = true;
      resolve(value);
    };
    req.on('error', () => finish(null));
    req.on('aborted', () => finish(null));
    req.on('data', (chunk) => {
      body += chunk;
      if (Buffer.byteLength(body) > maxBytes) {
        finish(null);
        req.destroy();
      }
    });
    req.on('end', () => {
      if (done) return;
      try {
        finish(JSON.parse(body));
      } catch (e) {
        finish(null);
      }
    });
  });
}
function vapidRequestRateAllowed(ip) {
  const now = Date.now();
  let gate = rateGate(vapidGlobalRate, now, 60000, 120);
  vapidGlobalRate = gate.state;
  if (!gate.allow) return false;
  vapidGlobalRate.count += 1;
  const key = String(ip || 'unknown');
  gate = rateGate(vapidRequestRate.get(key), now, 60000, 12);
  vapidRequestRate.set(key, gate.state);
  if (!gate.allow) return false;
  gate.state.count += 1;
  if (vapidRequestRate.size > 10000) vapidRequestRate.clear();
  return true;
}
function rememberVapidRequest(request) {
  const now = Date.now();
  const key = `${request.relayPub}|${request.nonce}`;
  if (vapidRequestNonces.has(key)) return false;
  vapidRequestNonces.set(key, now);
  if (vapidRequestNonces.size > 5000) {
    const cutoff = now - 10 * 60 * 1000;
    for (const [nonce, timestamp] of vapidRequestNonces) {
      if (timestamp < cutoff) vapidRequestNonces.delete(nonce);
    }
    while (vapidRequestNonces.size > 5000) {
      const oldest = vapidRequestNonces.keys().next().value;
      vapidRequestNonces.delete(oldest);
    }
  }
  return true;
}
async function handleVapidFleetHttpWith(req, res, options = {}) {
  const fleet = options.fleet === undefined ? VAPID_FLEET : options.fleet;
  const member = options.member === undefined ? VAPID_MEMBER : options.member;
  const bundle = options.bundle === undefined ? vapidFleetBundle : options.bundle;
  const allowPrivate = options.allowPrivate === undefined ? VAPID_FLEET_ALLOW_PRIVATE : options.allowPrivate;
  const selfUrl = options.selfUrl === undefined ? SELF_URL : options.selfUrl;
  const relayPublicKey = options.relayPublicKey || RELAY_KEYS.pub;
  const relaySecretKey = options.relaySecretKey || RELAY_KEYS.sec;
  const rateAllowed = options.rateAllowed || vapidRequestRateAllowed;
  const readRequest = options.readRequest || readJsonRequest;
  const verifyRequest = options.verifyRequest || verifyVapidRequest;
  const rememberRequest = options.rememberRequest || rememberVapidRequest;
  const resolvePeer = options.resolvePeer || safePeerAddrs;
  const sourceMatches = options.sourceMatches || sourceMatchesResolved;
  const makeResponse = options.makeResponse || createVapidResponse;
  const logger = options.logger || console;
  const ip = clientIp(req);
  if (!fleet || !member || !bundle || !rateAllowed(ip)) {
    res.writeHead(bundle ? 429 : 503, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: false }));
    return;
  }
  const request = await readRequest(req);
  const requestMember = verifyRequest(request, fleet);
  if (!requestMember || !rememberRequest(request)) {
    res.writeHead(403, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: false }));
    return;
  }
  const resolved = await resolvePeer(requestMember.url, { allowPrivate });
  if (!resolved || !sourceMatches(ip, resolved)) {
    res.writeHead(403, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: false }));
    return;
  }
  try {
    const response = makeResponse({
      config: fleet,
      request,
      bundle,
      senderUrl: selfUrl,
      senderRelayPub: relayPublicKey,
      senderRelaySecret: relaySecretKey,
    });
    res.writeHead(200, {
      'content-type': 'application/json',
      'cache-control': 'no-store',
    });
    res.end(JSON.stringify(response));
  } catch (e) {
    logger.warn('[vapid-fleet] не удалось сформировать ответ:', e && e.message);
    res.writeHead(500, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: false }));
  }
}
async function handleVapidFleetHttp(req, res) {
  return handleVapidFleetHttpWith(req, res);
}
const online = new Map();
const accountOnline = new Map();
function unindexAccountSocket(ws) {
  if (!ws || !ws.accountPubkey || !ws.deviceId) return;
  const devices = accountOnline.get(ws.accountPubkey);
  if (!devices) return;
  if (devices.get(ws.deviceId) === ws) devices.delete(ws.deviceId);
  if (!devices.size) accountOnline.delete(ws.accountPubkey);
  ws.accountPubkey = null;
  ws.deviceId = null;
  ws.deviceCertificate = null;
}
function indexAccountSocket(ws, record) {
  unindexAccountSocket(ws);
  let devices = accountOnline.get(record.accountPublicKey);
  if (!devices) {
    devices = new Map();
    accountOnline.set(record.accountPublicKey, devices);
  }
  const previous = devices.get(record.deviceId);
  if (previous && previous !== ws) {
    try {
      previous.terminate();
    } catch (e) {
    }
  }
  ws.accountPubkey = record.accountPublicKey;
  ws.deviceId = record.deviceId;
  ws.deviceCertificate = record.certificate;
  devices.set(record.deviceId, ws);
  store.touchDevice(record.devicePublicKey, Date.now());
}
function broadcastAccount(accountPk, frame) {
  const devices = accountOnline.get(accountPk);
  if (!devices) return 0;
  let sent = 0;
  for (const ws of devices.values()) if (send(ws, frame)) sent += 1;
  return sent;
}
const ipConns = new Map();
const PUSH_MIN_INTERVAL_MS = Number(process.env.RELAY_PUSH_INTERVAL_MS) || 20000;
const messagePushGate = createPushGate({
  windowMs: PUSH_MIN_INTERVAL_MS,
  maxPerRecipient: Number(process.env.RELAY_PUSH_MAX_PER_WINDOW) || undefined,
});
const CALL_PUSH_MIN_INTERVAL_MS = Number(process.env.RELAY_CALL_PUSH_INTERVAL_MS) || 5000;
const lastCallPushAt = new Map();
function sweepPushGates(now = Date.now()) {
  messagePushGate.sweep(now);
  const ccut = now - 10 * CALL_PUSH_MIN_INTERVAL_MS;
  for (const [pk, t] of lastCallPushAt) if (t < ccut) lastCallPushAt.delete(pk);
}
setInterval(sweepPushGates, 60000).unref();
const MAX_ADDR_LEN = 64;
const TRUST_PROXY_HOPS = Math.max(0, Number(process.env.RELAY_TRUST_PROXY) || 0);
function clientIp(req) {
  const remote = (req && req.socket && req.socket.remoteAddress) || 'unknown';
  if (TRUST_PROXY_HOPS > 0) {
    const xff = req && req.headers && req.headers['x-forwarded-for'];
    if (xff) {
      const parts = String(xff)
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      const idx = parts.length - TRUST_PROXY_HOPS;
      if (idx >= 0 && parts[idx]) return parts[idx];
    }
  }
  return remote;
}
function readJsonBody(req, maxBytes, onBody) {
  let body = '';
  let aborted = false;
  req.on('error', () => {
    aborted = true;
  });
  req.on('data', (chunk) => {
    if (aborted) return;
    body += chunk;
    if (body.length > maxBytes) {
      aborted = true;
      req.destroy();
    }
  });
  req.on('end', () => {
    if (aborted) return;
    let parsed = null;
    try {
      parsed = JSON.parse(body);
    } catch (e) {
      parsed = null;
    }
    onBody(parsed, Buffer.byteLength(body));
  });
}
let seq = 0;
function nextId() {
  seq = (seq + 1) % Number.MAX_SAFE_INTEGER;
  return Date.now().toString(36) + '-' + seq.toString(36) + '-' + crypto.randomBytes(3).toString('hex');
}
const CHALLENGE_SIG_PREFIX = 'licno-relay-challenge-v1|';
function verifySignature(nonceB64, signatureB64, signPublicKeyB64) {
  try {
    const sig = naclUtil.decodeBase64(signatureB64);
    const pk = naclUtil.decodeBase64(signPublicKeyB64);
    if (ed25519.verify(naclUtil.decodeUTF8(CHALLENGE_SIG_PREFIX + nonceB64), sig, pk)) {
      return true;
    }
    return ed25519.verify(naclUtil.decodeBase64(nonceB64), sig, pk);
  } catch (e) {
    return false;
  }
}
const BOX_PROOF_PREFIX = 'licno-box-proof-v1|';
function hmacSha512(key, data) {
  const B = 128;
  let k = key;
  if (k.length > B) k = nacl.hash(k);
  if (k.length < B) {
    const t = new Uint8Array(B);
    t.set(k);
    k = t;
  }
  const ipad = new Uint8Array(B);
  const opad = new Uint8Array(B);
  for (let i = 0; i < B; i++) {
    ipad[i] = k[i] ^ 0x36;
    opad[i] = k[i] ^ 0x5c;
  }
  const inner = nacl.hash(concatU8(ipad, data));
  return nacl.hash(concatU8(opad, inner));
}
function concatU8(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}
function verifyBoxProof(nonceB64, proofB64, boxPubB64, ephSecB64) {
  try {
    const shared = x25519.sharedSecret(
      naclUtil.decodeBase64(ephSecB64),
      naclUtil.decodeBase64(boxPubB64)
    );
    const data = concatU8(naclUtil.decodeUTF8(BOX_PROOF_PREFIX), naclUtil.decodeBase64(nonceB64));
    const expected = hmacSha512(shared, data).slice(0, 32);
    const got = naclUtil.decodeBase64(proofB64);
    if (got.length !== expected.length) return false;
    return nacl.verify(got, expected);
  } catch (e) {
    return false;
  }
}
const RELAY_AUTH_PREFIX = 'licno-relay-auth-v1|';
const RELAY_SIGN_KEY_FILE = process.env.RELAY_SIGN_KEY_FILE || path.join(path.dirname(DB_FILE), 'relay-sign.key');
function loadOrCreateRelaySignKeys({
  fileSystem = fs,
  exit = (code) => process.exit(code),
} = {}) {
  let secB64 = process.env.RELAY_SIGN_SECRET || null;
  if (!secB64) {
    try {
      secB64 = fileSystem.readFileSync(RELAY_SIGN_KEY_FILE, 'utf8').trim();
    } catch (e) {
      if (!e || e.code !== 'ENOENT') {
        console.error(
          `[relay-key] ключ ${RELAY_SIGN_KEY_FILE} существует, но не читается (${(e && e.code) || 'ошибка'}). ` +
            'Новый НЕ генерирую: клиенты пинят публичную половину, и подмена ключа отрезала бы их всех. ' +
            'Проверьте права и том, затем запустите снова.'
        );
        exit(1);
        return null;
      }
    }
  }
  try {
    if (secB64) {
      const kp = nacl.sign.keyPair.fromSecretKey(naclUtil.decodeBase64(secB64));
      return { pub: naclUtil.encodeBase64(kp.publicKey), sec: kp.secretKey };
    }
  } catch (e) {
    console.error('[relay-key] RELAY_SIGN_SECRET некорректен — генерирую новый');
  }
  const kp = nacl.sign.keyPair();
  try {
    fileSystem.writeFileSync(RELAY_SIGN_KEY_FILE, naclUtil.encodeBase64(kp.secretKey), { mode: 0o600 });
  } catch (e) {
    console.error(
      `[relay-key] не удалось сохранить ключ в ${RELAY_SIGN_KEY_FILE} (${(e && e.code) || 'ошибка'}). ` +
        'Без этого следующий запуск сменит личность релея и отрежет запинивших клиентов. ' +
        'Дайте процессу право записи либо задайте RELAY_SIGN_SECRET.'
    );
    exit(1);
    return null;
  }
  return { pub: naclUtil.encodeBase64(kp.publicKey), sec: kp.secretKey };
}
const RELAY_KEYS = loadOrCreateRelaySignKeys();
const CHAT_TAG_SALT = RELAY_KEYS
  ? crypto.createHash('sha256').update(Buffer.from(RELAY_KEYS.sec)).update('licno-chat-tag-salt-v1').digest()
  : Buffer.alloc(0);
function signRelayAuth(cnonce) {
  return naclUtil.encodeBase64(ed25519.sign(naclUtil.decodeUTF8(RELAY_AUTH_PREFIX + cnonce), RELAY_KEYS.sec));
}
const RELAY_VAPID_KEY_FILE = process.env.RELAY_VAPID_KEY_FILE || path.join(path.dirname(DB_FILE), 'vapid.json');
const RELAY_VAPID_FLEET_FILE =
  process.env.RELAY_VAPID_FLEET_FILE || path.join(__dirname, 'vapid-fleet.json');
const VAPID_FLEET_ALLOW_PRIVATE = process.env.RELAY_VAPID_FLEET_ALLOW_PRIVATE === '1';
const VAPID_STANDALONE = process.env.RELAY_VAPID_STANDALONE === '1';
const VAPID_SYNC_INTERVAL_MS = Math.max(10000, Number(process.env.RELAY_VAPID_SYNC_MS) || 60000);
let VAPID_FLEET = null;
try {
  VAPID_FLEET = loadFleetConfig(RELAY_VAPID_FLEET_FILE, { allowPrivate: VAPID_FLEET_ALLOW_PRIVATE });
} catch (e) {
  if (fs.existsSync(RELAY_VAPID_FLEET_FILE)) {
    console.error('[vapid-fleet] конфигурация некорректна:', e && e.message);
  }
}
const VAPID_MEMBER = VAPID_FLEET && SELF_URL ? memberFor(VAPID_FLEET, SELF_URL) : null;
let vapidFleetBundle = null;
let vapidKeySource = 'disabled';
let onVapidActivated = null;
function activateVapid(publicKey, privateKey, source, bundle) {
  if (!validVapidPair(publicKey, privateKey)) return false;
  const before = vapidPublicKey();
  if (!setVapidKeys(publicKey, privateKey, process.env.RELAY_VAPID_SUBJECT, SELF_URL)) return false;
  vapidFleetBundle = bundle || null;
  vapidKeySource = source;
  if (before !== publicKey && onVapidActivated) onVapidActivated();
  return true;
}
function resolveVapidKeysWith(options = {}) {
  const fleet = options.fleet === undefined ? VAPID_FLEET : options.fleet;
  const selfUrl = options.selfUrl === undefined ? SELF_URL : options.selfUrl;
  const member = options.member === undefined ? VAPID_MEMBER : options.member;
  const standalone = options.standalone === undefined ? VAPID_STANDALONE : options.standalone;
  const relayPublicKey = options.relayPublicKey || RELAY_KEYS.pub;
  const relaySecretKey = options.relaySecretKey || RELAY_KEYS.sec;
  const keyFile = options.keyFile || RELAY_VAPID_KEY_FILE;
  const fromEnv = options.fromEnv || {
    publicKey: process.env.RELAY_VAPID_PUBLIC || null,
    privateKey: process.env.RELAY_VAPID_PRIVATE || null,
  };
  const fromFile = options.fromFile === undefined ? readJsonFile(keyFile) : options.fromFile;
  const verifyBundle = options.verifyBundle || verifyVapidBundle;
  const acceptsKey = options.acceptsKey || memberAcceptsKey;
  const validPair = options.validPair || validVapidPair;
  const activate = options.activate || activateVapid;
  const generate = options.generate || generateVapidKeys;
  const signBundle = options.signBundle || signVapidBundle;
  const writeFile = options.writeFile || writeJsonAtomic;
  const logger = options.logger || console;
  if (fleet && selfUrl) {
    if (!member) {
      if (!standalone) {
        logger.warn(`[vapid-fleet] ${selfUrl} не входит в разрешённый флот — web-push выключен`);
        return null;
      }
    } else if (!acceptsKey(member, relayPublicKey)) {
      logger.error(
        `[vapid-fleet] relay-sign.key не совпадает с разрешённым ключом для ${selfUrl} — web-push выключен`
      );
      return null;
    } else {
      if (verifyBundle(fromFile, fleet)) {
        activate(fromFile.publicKey, fromFile.privateKey, 'fleet-file', fromFile);
        return 'fleet-file';
      }
      if (selfUrl.toLowerCase() !== fleet.genesis.toLowerCase()) {
        logger.log('[vapid-fleet] общий VAPID ещё не получен — ожидаю разрешённый peer');
        return null;
      }
      let pair = validPair(fromEnv.publicKey, fromEnv.privateKey) ? fromEnv : null;
      if (!pair && fromFile && validPair(fromFile.publicKey, fromFile.privateKey)) {
        pair = { publicKey: fromFile.publicKey, privateKey: fromFile.privateKey };
      }
      if (!pair) pair = generate();
      try {
        const bundle = signBundle(pair, fleet, relaySecretKey);
        writeFile(keyFile, bundle);
        activate(bundle.publicKey, bundle.privateKey, 'fleet-genesis', bundle);
        logger.log(`[vapid-fleet] genesis создал/подписал общий VAPID epoch=${bundle.epoch}`);
        return 'fleet-genesis';
      } catch (e) {
        logger.warn('[vapid-fleet] не удалось создать/сохранить общий VAPID:', e && e.message);
        return null;
      }
    }
  }
  let pair = validPair(fromEnv.publicKey, fromEnv.privateKey) ? fromEnv : null;
  if (!pair && fromFile && validPair(fromFile.publicKey, fromFile.privateKey)) {
    pair = { publicKey: fromFile.publicKey, privateKey: fromFile.privateKey };
  }
  if (!pair) pair = generate();
  try {
    if (!fromFile || fromFile.publicKey !== pair.publicKey || fromFile.privateKey !== pair.privateKey) {
      writeFile(keyFile, pair);
    }
    activate(pair.publicKey, pair.privateKey, 'standalone', null);
    return 'standalone';
  } catch (e) {
    logger.warn('[push] не удалось создать/сохранить VAPID:', e && e.message);
    return null;
  }
}
function resolveVapidKeys() {
  return resolveVapidKeysWith();
}
resolveVapidKeys();
const TURN_SECRET_FILE = process.env.TURN_SECRET_FILE || path.join(path.dirname(DB_FILE), 'turn-secret');
const COTURN_CONF_FILE = process.env.RELAY_COTURN_CONF || path.join(path.dirname(DB_FILE), 'turnserver.conf');
function resolveTurnSecret({ fileSystem = fs } = {}) {
  if (process.env.TURN_SECRET) return process.env.TURN_SECRET;
  let mayPersist = true;
  try {
    const f = fileSystem.readFileSync(TURN_SECRET_FILE, 'utf8').trim();
    if (f) return f;
  } catch (e) {
    if (!e || e.code !== 'ENOENT') {
      console.error(
        `[turn] секрет ${TURN_SECRET_FILE} существует, но не читается (${(e && e.code) || 'ошибка'}). ` +
          'Этот запуск работает на временном секрете, поверх файла НЕ пишу. ' +
          'После рестарта выданные TURN-учётки протухнут — проверьте права.'
      );
      mayPersist = false;
    }
  }
  const gen = crypto.randomBytes(32).toString('hex');
  if (mayPersist) {
    try {
      fileSystem.writeFileSync(TURN_SECRET_FILE, gen, { mode: 0o600 });
    } catch (e) {
      console.error(
        `[turn] не удалось сохранить секрет в ${TURN_SECRET_FILE} (${(e && e.code) || 'ошибка'}). ` +
          'Секрет остаётся только в памяти: после рестарта он сменится, и выданные клиентам ' +
          'учётки перестанут работать примерно на час. Дайте процессу право записи.'
      );
    }
  }
  return gen;
}
let coturnChild = null;
let coturnStopped = false;
function startEmbeddedCoturn() {
  if (coturnChild || coturnStopped) return;
  const { spawn } = require('child_process');
  try {
    coturnChild = spawn('turnserver', ['-c', COTURN_CONF_FILE], { stdio: ['ignore', 'inherit', 'inherit'] });
  } catch (e) {
    console.warn('[turn] встроенный coturn не запустился:', e && e.message);
    coturnChild = null;
    return;
  }
  coturnChild.on('error', (e) => console.warn('[turn] coturn:', e && e.message));
  coturnChild.on('exit', (code, sig) => {
    coturnChild = null;
    if (coturnStopped) return;
    console.warn(`[turn] coturn завершился (code=${code} sig=${sig}) — перезапуск через 3с`);
    setTimeout(startEmbeddedCoturn, 3000).unref();
  });
  console.log(`[turn] встроенный coturn запущен: turnserver -c ${COTURN_CONF_FILE}`);
}
function stopEmbeddedCoturn() {
  coturnStopped = true;
  if (coturnChild) {
    try {
      coturnChild.kill('SIGTERM');
    } catch (e) {
    }
    coturnChild = null;
  }
}
const NTFY_ON = ntfy.ntfyEnabled(process.env);
const NTFY_PORT = ntfy.ntfyPort(process.env);
const NTFY_DIR = process.env.RELAY_NTFY_DIR || path.join(path.dirname(DB_FILE), 'ntfy');
const NTFY_CONF_FILE = path.join(NTFY_DIR, 'server.yml');
const NTFY_BIN = process.env.RELAY_NTFY_BIN || 'ntfy';
let ntfyChild = null;
let ntfyStopped = false;
function writeNtfyConfig() {
  fs.mkdirSync(NTFY_DIR, { recursive: true });
  fs.writeFileSync(
    NTFY_CONF_FILE,
    ntfy.ntfyConfigText({
      baseUrl: ntfy.ntfyBaseUrl(SELF_URL),
      port: NTFY_PORT,
      cacheFile: path.join(NTFY_DIR, 'cache.db'),
    }),
    { mode: 0o600 }
  );
}
function startEmbeddedNtfy() {
  if (ntfyChild || ntfyStopped) return;
  const { spawn } = require('child_process');
  try {
    ntfyChild = spawn(NTFY_BIN, ['serve', '--config', NTFY_CONF_FILE], {
      stdio: ['ignore', 'inherit', 'inherit'],
    });
  } catch (e) {
    console.warn('[ntfy] встроенный сервер уведомлений не запустился:', e && e.message);
    ntfyChild = null;
    return;
  }
  ntfyChild.on('error', (e) => console.warn('[ntfy]', e && e.message));
  ntfyChild.on('exit', (code, sig) => {
    ntfyChild = null;
    if (ntfyStopped) return;
    console.warn(`[ntfy] сервер уведомлений завершился (code=${code} sig=${sig}) — перезапуск через 3с`);
    setTimeout(startEmbeddedNtfy, 3000).unref();
  });
  console.log(`[ntfy] встроенный сервер уведомлений запущен на 127.0.0.1:${NTFY_PORT}, путь ${ntfy.NTFY_PREFIX}`);
}
function stopEmbeddedNtfy() {
  ntfyStopped = true;
  if (ntfyChild) {
    try {
      ntfyChild.kill('SIGTERM');
    } catch (e) {
    }
    ntfyChild = null;
  }
}
function ntfyStatus() {
  if (!NTFY_ON) return 'off';
  return ntfyChild ? 'running' : 'starting';
}
function proxyToNtfy(req, res) {
  const target = ntfy.ntfyTarget(req.url);
  if (!target) {
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('not found');
    return;
  }
  if (!NTFY_ON) {
    res.writeHead(503, { 'content-type': 'text/plain' });
    res.end('ntfy disabled');
    return;
  }
  if (!ntfyHttpRate.allow(clientIp(req), Date.now())) {
    counters.ntfyProxyErrors += 1;
    res.writeHead(429, { 'content-type': 'text/plain', 'retry-after': '60' });
    res.end('rate');
    return;
  }
  const upstream = http.request(
    {
      host: '127.0.0.1',
      port: NTFY_PORT,
      method: req.method,
      path: target,
      headers: ntfy.ntfyProxyHeaders(req.headers, {
        host: (req.headers && req.headers.host) || '',
        clientIp: clientIp(req),
      }),
    },
    (answer) => {
      res.writeHead(answer.statusCode || 502, answer.headers);
      answer.pipe(res);
    }
  );
  upstream.on('error', () => {
    counters.ntfyProxyErrors += 1;
    if (!res.headersSent) {
      res.writeHead(502, { 'content-type': 'text/plain' });
      res.end('ntfy unavailable');
      return;
    }
    res.destroy();
  });
  res.on('close', () => upstream.destroy());
  req.pipe(upstream);
}
function proxyNtfyUpgrade(req, socket, head) {
  const target = ntfy.ntfyTarget(req.url);
  if (!target || !NTFY_ON) {
    socket.destroy();
    return;
  }
  if (!ntfyHttpRate.allow(clientIp(req), Date.now())) {
    counters.ntfyProxyErrors += 1;
    socket.destroy();
    return;
  }
  const upstream = http.request({
    host: '127.0.0.1',
    port: NTFY_PORT,
    method: req.method,
    path: target,
    headers: {
      ...ntfy.ntfyProxyHeaders(req.headers, {
        host: (req.headers && req.headers.host) || '',
        clientIp: clientIp(req),
      }),
      connection: 'Upgrade',
      upgrade: (req.headers && req.headers.upgrade) || 'websocket',
    },
  });
  upstream.on('upgrade', (answer, upstreamSocket, upstreamHead) => {
    const lines = [`HTTP/1.1 ${answer.statusCode} ${answer.statusMessage || 'Switching Protocols'}`];
    for (const [name, value] of Object.entries(answer.headers || {})) {
      if (Array.isArray(value)) {
        for (const item of value) lines.push(`${name}: ${item}`);
      } else {
        lines.push(`${name}: ${value}`);
      }
    }
    socket.write(`${lines.join('\r\n')}\r\n\r\n`);
    if (upstreamHead && upstreamHead.length) socket.write(upstreamHead);
    if (head && head.length) upstreamSocket.write(head);
    const drop = () => {
      upstreamSocket.destroy();
      socket.destroy();
    };
    upstreamSocket.on('error', drop);
    socket.on('error', drop);
    upstreamSocket.pipe(socket);
    socket.pipe(upstreamSocket);
  });
  upstream.on('response', (answer) => {
    answer.resume();
    socket.destroy();
  });
  upstream.on('error', () => {
    counters.ntfyProxyErrors += 1;
    socket.destroy();
  });
  upstream.end();
}
if (TURN_HOST) {
  turnSecret = resolveTurnSecret();
  try {
    fs.writeFileSync(
      COTURN_CONF_FILE,
      coturnConfigText(turnSecret, {
        turnHost: TURN_HOST,
        pidfile: path.join(path.dirname(COTURN_CONF_FILE), 'turnserver.pid'),
        userdb: path.join(path.dirname(COTURN_CONF_FILE), 'turndb'),
      }),
      { mode: 0o600 }
    );
    console.log(`[turn] coturn config -> ${COTURN_CONF_FILE} (секрет во владении релея, 0600)`);
  } catch (e) {
    console.warn('[turn] не удалось записать конфиг coturn:', e && e.message);
  }
  if (process.env.RELAY_EMBED_COTURN) startEmbeddedCoturn();
} else {
  turnSecret = process.env.TURN_SECRET || null;
  if (!PUBLIC_STUN.length) {
    console.warn(
      '[turn] TURN_HOST не задан: релей не выдаёт ни STUN, ни TURN. Звонки за NAT не соберутся.\n' +
        '       Поднимите coturn на этом узле (TURN_HOST=<адрес> + RELAY_EMBED_COTURN=1) —\n' +
        '       он же раздаёт STUN на порту 3478. Внешний STUN, если он вам осознанно нужен,\n' +
        '       задаётся явно: RELAY_PUBLIC_STUN=stun:stun.example.org:3478'
    );
  }
}
if (NTFY_ON) {
  try {
    writeNtfyConfig();
    console.log(`[ntfy] config -> ${NTFY_CONF_FILE}`);
  } catch (e) {
    console.warn('[ntfy] не удалось записать конфиг:', e && e.message);
  }
  startEmbeddedNtfy();
} else {
  console.log('[ntfy] встроенный сервер уведомлений выключен (RELAY_EMBED_NTFY не задан)');
}
const SPK_SIG_PREFIX = 'licno-spk-v1|';
const SPK_PQ_SIG_PREFIX = 'licno-spk-v2|';
const MAX_SPK_PQ_B64 = 2048;
const MAX_OTPS_PER_USER = 100;
const PREKEY_GET_WINDOW_MS = 60000;
const PREKEY_GET_MAX = 60;
const PREKEY_TARGET_WINDOW_MS = Number(process.env.RELAY_PREKEY_TARGET_MS) || 60000;
const PREKEY_TARGET_MAX = Number(process.env.RELAY_PREKEY_TARGET_MAX) || 30;
const otpDrain = new Map();
function sweepOtpDrain(now = Date.now()) {
  const cutoff = now - PREKEY_TARGET_WINDOW_MS;
  for (const [pk, d] of otpDrain) if (d.start < cutoff) otpDrain.delete(pk);
}
setInterval(sweepOtpDrain, PREKEY_TARGET_WINDOW_MS).unref();
const isB64Field = (s, max = 128) => typeof s === 'string' && s.length > 0 && s.length <= max;
function verifySpkSignature(spkObj, signPublicKeyB64) {
  try {
    const message = spkObj.pq
      ? SPK_PQ_SIG_PREFIX + spkObj.id + '|' + spkObj.pub + '|' + spkObj.pq
      : SPK_SIG_PREFIX + spkObj.id + '|' + spkObj.pub;
    return ed25519.verify(
      naclUtil.decodeUTF8(message),
      naclUtil.decodeBase64(spkObj.sig),
      naclUtil.decodeBase64(signPublicKeyB64)
    );
  } catch (e) {
    return false;
  }
}
const server = http.createServer((req, res) => {
  if (req.url === '/health') {
    const nowHealth = Date.now();
    const trustedHealth =
      !!GOSSIP_TOKEN && safeEqual((req.headers && req.headers['x-gossip-token']) || '', GOSSIP_TOKEN);
    if (!trustedHealth && !healthHttpRate.allow(clientIp(req), nowHealth)) {
      res.writeHead(429, { 'content-type': 'text/plain', 'retry-after': '60' });
      res.end('rate');
      return;
    }
    const st = healthStats(nowHealth);
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(
      JSON.stringify({
        ok: true,
        protocol: RELAY_PROTOCOL,
        capabilities: RELAY_CAPABILITIES,
        maxLinkedDevices: MAX_ACTIVE_DEVICES,
        online: online.size,
        queued: st.usersQueued,
        messages: st.totalQueued,
        relays: relayDir.length,
        vapid: !!vapidPublicKey(),
        vapidPublicKey: vapidPublicKey(),
        vapidSource: vapidKeySource,
        vapidFleetMember: !!VAPID_MEMBER,
        ntfy: ntfyStatus(),
      })
    );
    return;
  }
  if (ntfy.ntfyTarget(req.url)) {
    counters.ntfyProxied += 1;
    proxyToNtfy(req, res);
    return;
  }
  if (req.method === 'POST' && req.url === '/vapid-fleet') {
    handleVapidFleetHttp(req, res).catch((e) => {
      console.warn('[vapid-fleet] HTTP handler failed:', e && e.message);
      if (!res.headersSent) res.writeHead(500, { 'content-type': 'application/json' });
      if (!res.writableEnded) res.end(JSON.stringify({ ok: false }));
    });
    return;
  }
  if (req.url === '/i' || req.url.startsWith('/i?') || req.url.startsWith('/i#')) {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { 'content-type': 'text/plain' });
      res.end('method');
      return;
    }
    const html = landing.landingHtml({
      userAgent: (req.headers && req.headers['user-agent']) || '',
      downloadUrl: `${updateFeed.RELEASE_FILE_PATH}?platform=android`,
      webUrl: webApp.WEB_APP_PREFIX,
    });
    const body = Buffer.from(html, 'utf8');
    res.writeHead(200, {
      'content-type': 'text/html; charset=utf-8',
      'content-length': String(body.length),
      'x-content-type-options': 'nosniff',
      'cache-control': 'no-cache',
    });
    if (req.method === 'HEAD') return res.end();
    res.end(body);
    return;
  }
  {
    const relative = webApp.webAppPath(req.url);
    if (relative !== null) {
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        res.writeHead(405, { 'content-type': 'text/plain' });
        res.end('method');
        return;
      }
      const full = relative ? webApp.resolveWebFile(WEB_DIR, relative) : '';
      let stat = null;
      try {
        stat = full ? fs.statSync(full) : null;
      } catch (e) {
        stat = null;
      }
      if (!stat || !stat.isFile()) {
        const page = webApp.resolveWebFile(WEB_DIR, 'index.html');
        let pageStat = null;
        try {
          pageStat = page ? fs.statSync(page) : null;
        } catch (e) {
          pageStat = null;
        }
        if (!pageStat || !pageStat.isFile()) {
          res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
          res.end('веб-версия на этом узле ещё не разложена');
          return;
        }
        res.writeHead(200, webApp.webAppHeaders('index.html', pageStat.size));
        if (req.method === 'HEAD') return res.end();
        const pageStream = fs.createReadStream(page);
        pageStream.on('error', () => res.destroy());
        pageStream.pipe(res);
        return;
      }
      res.writeHead(200, webApp.webAppHeaders(relative, stat.size));
      if (req.method === 'HEAD') return res.end();
      const fileStream = fs.createReadStream(full);
      fileStream.on('error', () => res.destroy());
      fileStream.pipe(res);
      return;
    }
  }
  if (req.url === '/update' || req.url.startsWith('/update?') || req.url.startsWith('/update/')) {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { 'content-type': 'text/plain' });
      res.end('method');
      return;
    }
    const parsed = new URL(req.url, 'http://x');
    const platform = parsed.searchParams.get('platform');
    const wantsFile = parsed.pathname === '/update/file';
    if (!wantsFile && parsed.pathname !== '/update') {
      res.writeHead(404, { 'content-type': 'text/plain' });
      res.end('not found');
      return;
    }
    const limiter = wantsFile ? updateFileRate : updateManifestRate;
    if (!limiter.allow(clientIp(req), Date.now())) {
      counters.updateHttpLimited += 1;
      res.writeHead(429, { 'content-type': 'text/plain', 'retry-after': '60' });
      res.end('rate');
      return;
    }
    const channel = parsed.searchParams.get('channel') || '';
    if (wantsFile) {
      const manifestVerdict = updateFeed.manifestResponse({
        dir: UPDATE_DIR,
        platform,
        channel,
        read: (target) => fs.readFileSync(target, 'utf8'),
        verify: verifyManifestSignature,
      });
      if (manifestVerdict.status !== 200) {
        res.writeHead(404, { 'content-type': 'text/plain' });
        res.end(manifestVerdict.reason || 'not found');
        return;
      }
      const verdict = updateFeed.fileResponse({
        dir: UPDATE_DIR,
        platform,
        channel,
        stat: (target) => fs.statSync(target),
        expect: {
          size: Number(manifestVerdict.manifest.size),
          sha256: String(manifestVerdict.manifest.sha256 || ''),
        },
        hash: (target) => releaseFileHash(target),
      });
      if (verdict.status !== 200) {
        res.writeHead(404, { 'content-type': 'text/plain' });
        res.end(verdict.reason || 'not found');
        return;
      }
      counters.updateFileServed += 1;
      res.writeHead(200, {
        'content-type': verdict.type,
        'content-length': String(verdict.size),
        'content-disposition': `attachment; filename="${verdict.filename}"`,
        'access-control-allow-origin': '*',
      });
      if (req.method === 'HEAD') {
        res.end();
        return;
      }
      const stream = fs.createReadStream(verdict.path);
      stream.on('error', () => {
        res.destroy();
      });
      stream.pipe(res);
      return;
    }
    const verdict = updateFeed.manifestResponse({
      dir: UPDATE_DIR,
      platform,
      channel,
      read: (target) => fs.readFileSync(target, 'utf8'),
      verify: verifyManifestSignature,
    });
    if (verdict.status !== 200) {
      res.writeHead(404, { 'content-type': 'text/plain' });
      res.end(verdict.reason || 'not found');
      return;
    }
    counters.updateManifestServed += 1;
    res.writeHead(200, {
      'content-type': 'application/json',
      'access-control-allow-origin': '*',
      'cache-control': 'no-store',
    });
    res.end(req.method === 'HEAD' ? undefined : verdict.body);
    return;
  }
  if (req.url === '/metrics' || req.url.startsWith('/metrics?')) {
    if (!metricsAuthorized(req)) {
      res.writeHead(403, { 'content-type': 'text/plain' });
      res.end('forbidden');
      return;
    }
    res.writeHead(200, { 'content-type': 'text/plain; version=0.0.4; charset=utf-8' });
    res.end(renderMetrics());
    return;
  }
  if (req.url === '/mbx' || req.url.startsWith('/mbx?')) {
    const trustedPeer =
      !!GOSSIP_TOKEN && safeEqual((req.headers && req.headers['x-gossip-token']) || '', GOSSIP_TOKEN);
    if (!trustedPeer && !mbxHttpRate.allow(clientIp(req), Date.now())) {
      counters.mbxHttpLimited += 1;
      res.writeHead(429, { 'content-type': 'text/plain', 'retry-after': '60' });
      res.end('rate');
      return;
    }
    const after = Number(new URL(req.url, 'http://x').searchParams.get('after')) || 0;
    const rows = store.mbxAfter(after, trustedPeer ? mbx.SYNC_LIMIT : MBX_HTTP_PAGE);
    const last = rows.length ? rows[rows.length - 1].seq : after;
    res.writeHead(200, { 'content-type': 'application/json', 'access-control-allow-origin': '*' });
    res.end(
      JSON.stringify({
        seq: last,
        slot: mbx.slotOf(Date.now()),
        records: mbx
          .packRecords(rows.map((row) => ({ key: row.key, value: row.val, mac: row.mac })))
          .toString('base64'),
        slots: rows.map((row) => row.slot),
      })
    );
    return;
  }
  if (req.url === '/report' || req.url.startsWith('/report?')) {
    if (req.method !== 'POST') {
      res.writeHead(405, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: false, reason: 'method' }));
      return;
    }
    if (!reportHttpRate.allow(clientIp(req), Date.now())) {
      counters.reportsRefused += 1;
      res.writeHead(429, { 'content-type': 'application/json', 'retry-after': '3600' });
      res.end(JSON.stringify({ ok: false, reason: 'rate' }));
      return;
    }
    readJsonBody(req, reportsRule.MAX_REPORT_BYTES, (body, bytes) => {
      const verdict = reportsRule.validReport(body, bytes);
      if (!verdict.ok) {
        counters.reportsRefused += 1;
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ ok: false, reason: verdict.reason }));
        return;
      }
      const id = crypto
        .createHash('sha256')
        .update(String(body.ek) + '|' + String(body.nonce) + '|' + String(body.cipher))
        .digest('hex')
        .slice(0, 32);
      try {
        store.addReport(id, Date.now(), JSON.stringify({ v: 1, ek: body.ek, nonce: body.nonce, cipher: body.cipher }));
        counters.reportsIn += 1;
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ ok: true, id }));
      } catch (e) {
        counters.reportsRefused += 1;
        res.writeHead(500, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ ok: false, reason: 'store' }));
      }
    });
    return;
  }
  if (req.url === '/reports' || req.url.startsWith('/reports?')) {
    const parsed = new URL(req.url, 'http://x');
    if (req.method === 'GET') {
      const nowReports = Date.now();
      if (!reportAdminRate.allow(clientIp(req), nowReports)) {
        res.writeHead(429, { 'content-type': 'application/json', 'retry-after': '60' });
        res.end(JSON.stringify({ ok: false, reason: 'rate' }));
        return;
      }
      const signature = parsed.searchParams.get('sig');
      const verdict = reportsRule.verifyOwnerRequest({
        domain: reportsRule.FETCH_DOMAIN,
        ts: parsed.searchParams.get('ts'),
        host: REPORTS_SELF_HOST,
        signature,
        publicKey: REPORTS_OWNER_KEY,
        now: nowReports,
      });
      if (!verdict.ok) {
        res.writeHead(403, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ ok: false, reason: verdict.reason }));
        return;
      }
      if (!reportRequestFresh(reportsRule.FETCH_DOMAIN, signature, nowReports)) {
        res.writeHead(403, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ ok: false, reason: 'replay' }));
        return;
      }
      const rows = store.reportsPage(reportsRule.FETCH_PAGE);
      const page = [];
      let budget = 0;
      for (const row of rows) {
        const item = { id: row.id, at: row.at, body: row.body };
        budget += Buffer.byteLength(typeof row.body === 'string' ? row.body : '');
        if (page.length && budget > REPORT_FETCH_MAX_BYTES) break;
        page.push(item);
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(
        JSON.stringify({
          ok: true,
          left: store.reportsCount(),
          reports: page,
        })
      );
      return;
    }
    res.writeHead(405, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: false, reason: 'method' }));
    return;
  }
  if (req.url === '/reports/ack') {
    if (req.method !== 'POST') {
      res.writeHead(405, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: false, reason: 'method' }));
      return;
    }
    const nowAck = Date.now();
    if (!reportAdminRate.allow(clientIp(req), nowAck)) {
      res.writeHead(429, { 'content-type': 'application/json', 'retry-after': '60' });
      res.end(JSON.stringify({ ok: false, reason: 'rate' }));
      return;
    }
    readJsonBody(req, 256 * 1024, (body) => {
      const signature = body && body.sig;
      const verdict = reportsRule.verifyOwnerRequest({
        domain: reportsRule.DELETE_DOMAIN,
        ts: body && body.ts,
        host: REPORTS_SELF_HOST,
        signature,
        publicKey: REPORTS_OWNER_KEY,
        now: Date.now(),
      });
      if (!verdict.ok) {
        res.writeHead(403, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ ok: false, reason: verdict.reason }));
        return;
      }
      if (!reportRequestFresh(reportsRule.DELETE_DOMAIN, signature, Date.now())) {
        res.writeHead(403, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ ok: false, reason: 'replay' }));
        return;
      }
      const ids = Array.isArray(body.ids) ? body.ids.slice(0, reportsRule.FETCH_PAGE) : [];
      const removed = store.deleteReports(ids);
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, removed, left: store.reportsCount() }));
    });
    return;
  }
  if (req.url === '/relays') {
    if (req.method === 'POST') {
      const gossipOk =
        !!GOSSIP_TOKEN && safeEqual((req.headers && req.headers['x-gossip-token']) || '', GOSSIP_TOKEN);
      let body = '';
      let aborted = false;
      req.on('error', () => {
        aborted = true;
      });
      req.on('data', (c) => {
        body += c;
        if (body.length > 200000) {
          aborted = true;
          req.destroy();
        }
      });
      req.on('end', () => {
        if (aborted) return;
        try {
          const j = JSON.parse(body);
          if (gossipOk && Array.isArray(j.relays)) learnRelays(j.relays.filter(isValidRelayUrl));
        } catch (e) {
        }
        res.writeHead(200, { 'content-type': 'application/json', 'access-control-allow-origin': '*' });
        res.end(JSON.stringify({ relays: relayDir }));
      });
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json', 'access-control-allow-origin': '*' });
    res.end(JSON.stringify({ relays: relayDir }));
    return;
  }
  res.writeHead(426);
  res.end('Upgrade Required: connect via WebSocket');
});
const wss = new WebSocketServer({ noServer: true, maxPayload: MAX_ENVELOPE_BYTES + 1024 * 1024 });
server.on('upgrade', (req, socket, head) => {
  if (ntfy.ntfyTarget(req.url)) {
    counters.ntfyProxied += 1;
    proxyNtfyUpgrade(req, socket, head);
    return;
  }
  wss.handleUpgrade(req, socket, head, (ws) => {
    wss.emit('connection', ws, req);
  });
});
const BATCHABLE_SERVER_FRAMES = new Set([
  'message',
  'ack',
  'delivered',
  'binary-ack',
  'binary-delivered',
]);
function flushFrameBatch(ws) {
  clearTimeout(ws.frameBatchTimer);
  ws.frameBatchTimer = null;
  const frames = ws.frameBatchQueue || [];
  ws.frameBatchQueue = [];
  ws.frameBatchBytes = 0;
  if (!frames.length || ws.readyState !== ws.OPEN) return false;
  try {
    const payload = encodeMessagePack(frames);
    ws.send(
      packBinaryFrame(
        { type: 'frame-batch-v1', version: 1, count: frames.length },
        payload
      ),
      { binary: true }
    );
    return true;
  } catch (error) {
    return false;
  }
}
function sendImmediate(ws, obj) {
  if (!ws || ws.readyState !== ws.OPEN) return false;
  try {
    ws.send(JSON.stringify(obj));
    return true;
  } catch (error) {
    return false;
  }
}
const RECEIPT_FRAMES = new Set(['ack', 'delivered', 'binary-ack', 'binary-delivered']);
const RECEIPT_FRAME_BYTES = 512;
function frameBatchBytes(obj, sizeHint) {
  if (Number.isFinite(sizeHint) && sizeHint >= 0) return sizeHint;
  if (RECEIPT_FRAMES.has(obj.type)) return RECEIPT_FRAME_BYTES;
  return JSON.stringify(obj).length;
}
function send(ws, obj, sizeHint) {
  if (ws && ws.readyState === ws.OPEN) {
    if (
      ws.frameBatchV1 &&
      ws.authed &&
      obj &&
      typeof obj === 'object' &&
      BATCHABLE_SERVER_FRAMES.has(obj.type)
    ) {
      const encodedLength = frameBatchBytes(obj, sizeHint);
      if (encodedLength <= 64 * 1024) {
        if (
          ws.frameBatchQueue.length &&
          (ws.frameBatchQueue.length >= 24 || ws.frameBatchBytes + encodedLength > 192 * 1024)
        ) {
          flushFrameBatch(ws);
        }
        ws.frameBatchQueue.push(obj);
        ws.frameBatchBytes += encodedLength;
        if (ws.frameBatchQueue.length >= 24 || ws.frameBatchBytes >= 192 * 1024) {
          flushFrameBatch(ws);
        } else if (!ws.frameBatchTimer) {
          ws.frameBatchTimer = setTimeout(() => flushFrameBatch(ws), 10);
        }
        return true;
      }
    }
    return sendImmediate(ws, obj);
  }
  return false;
}
function sendBinary(ws, header, payload) {
  if (ws.readyState !== ws.OPEN) return false;
  try {
    ws.send(packBinaryFrame(header, payload), { binary: true });
    return true;
  } catch (error) {
    return false;
  }
}
function queuedMessageFrame(item) {
  const frame = { type: 'message', id: item.id, envelope: item.envelope };
  if (item.from) frame.from = item.from;
  if (item.fromAccount) frame.fromAccount = item.fromAccount;
  if (item.fromDeviceId) frame.fromDeviceId = item.fromDeviceId;
  if (item.deviceCertificate) frame.deviceCertificate = item.deviceCertificate;
  if (item.deviceRoster) frame.deviceRoster = item.deviceRoster;
  return frame;
}
function sendMessageFrame(ws, frame, sizeHint, { immediate = false } = {}) {
  if (ws && ws.binaryEnvelopeV1 && ws.readyState === ws.OPEN) {
    const bytes = envelopeFrame.sealedBytes(frame.envelope);
    if (bytes) {
      try {
        const header = envelopeFrame.buildMessageHeader(frame);
        if (ws.frameBatchQueue && ws.frameBatchQueue.length) flushFrameBatch(ws);
        return sendBinary(ws, header, bytes);
      } catch (error) {
      }
    }
  }
  return immediate ? sendImmediate(ws, frame) : send(ws, frame, sizeHint);
}
function queuedBinaryHeader(item) {
  const header = {
    type: 'attachment-chunk',
    version: 1,
    id: item.id,
    from: item.from,
    transferId: item.transferId,
    index: item.index,
    total: item.total,
  };
  if (item.metadata && item.metadata.fromAccount) header.fromAccount = item.metadata.fromAccount;
  if (item.metadata && item.metadata.fromDeviceId) header.fromDeviceId = item.metadata.fromDeviceId;
  return header;
}
function senderMetadata(ws) {
  if (!ws || !ws.pubkey) return {};
  return {
    fromAccount: ws.accountPubkey || ws.pubkey,
    fromDeviceId: ws.deviceId || undefined,
    deviceCertificate: ws.deviceCertificate || undefined,
    deviceRoster: ws.accountPubkey ? store.getAccountRoster(ws.accountPubkey) || undefined : undefined,
  };
}
onVapidActivated = () => {
  for (const ws of wss.clients) {
    if (ws.authed) send(ws, { type: 'vapid-key', vapidPublicKey: vapidPublicKeyFor(ws.pubkey) });
  }
};
const FLUSH_HIGH_WATER = 4 * 1024 * 1024;
const FLUSH_RESUME_MS = 25;
function flushQueue(pubkey, ws, onComplete) {
  const ids = store.queueIdsFor(pubkey);
  let i = 0;
  async function pump() {
    if (ws.readyState !== ws.OPEN) return;
    while (i < ids.length) {
      if (typeof ws.bufferedAmount === 'number' && ws.bufferedAmount > FLUSH_HIGH_WATER) {
        setTimeout(start, FLUSH_RESUME_MS);
        return;
      }
      const item = await store.getItemAsync(ids[i]);
      i += 1;
      if (ws.readyState !== ws.OPEN) return;
      if (item) sendMessageFrame(ws, queuedMessageFrame(item), item.bytes);
    }
    if (onComplete) onComplete();
  }
  function start() {
    pump().catch((error) => console.warn('[queue] выгрузка прервана:', (error && error.message) || error));
  }
  start();
  return ids.length;
}
const GW_PULL_MAX_ITEMS = 50;
const GW_PULL_RATE = 6;
const GW_PULL_WINDOW_MS = 60 * 1000;
const GW_PULL_MAX_KEYS = 10000;
const gatewayTickets = gatewayTicketRule.createTicketLedger();
const gatewayPullRate = new Map();
function gatewayPullAllowed(pubkey) {
  const at = Date.now();
  const entry = gatewayPullRate.get(pubkey);
  if (!entry || at - entry.startedAt > GW_PULL_WINDOW_MS) {
    gatewayPullRate.set(pubkey, { startedAt: at, count: 1 });
    if (gatewayPullRate.size > GW_PULL_MAX_KEYS) {
      sweepGatewayPullRate(at);
      while (gatewayPullRate.size > GW_PULL_MAX_KEYS) {
        const oldest = gatewayPullRate.keys().next().value;
        gatewayPullRate.delete(oldest);
      }
    }
    return true;
  }
  entry.count += 1;
  return entry.count <= GW_PULL_RATE;
}
function sweepGatewayPullRate(now = Date.now()) {
  for (const [pubkey, entry] of gatewayPullRate) {
    if (now - entry.startedAt > GW_PULL_WINDOW_MS) gatewayPullRate.delete(pubkey);
  }
}
function sweepRateBudgets(now = Date.now()) {
  sweepCostlyBudgets(now);
  sweepGatewayPullRate(now);
}
setInterval(sweepRateBudgets, COSTLY_WINDOW_MS).unref();
setInterval(() => mbxRefreshDigest(), COSTLY_WINDOW_MS).unref();
function handleGatewayPull(ws, msg) {
  if (!ws.authed || !ws.pubkey) return send(ws, { type: 'gw-pull-result', ok: false });
  if (!ws.proven) return send(ws, { type: 'gw-pull-result', ok: false });
  if (!gatewayPullAllowed(ws.pubkey)) return send(ws, { type: 'gw-pull-result', ok: false });
  const owner = msg && msg.ticket && typeof msg.ticket.addr === 'string' ? msg.ticket.addr : '';
  const bound = owner ? store.getIdentity(owner) : null;
  const verdict = gatewayTicketRule.checkTicket({
    candidate: msg && msg.ticket,
    ownerSignKey: bound && bound.proven ? bound.signPk : null,
    presenter: { addr: ws.pubkey, signKey: ws.signPk },
    now: Date.now(),
    verify: (bytes, sig, publicKey) =>
      ed25519.verify(bytes, naclUtil.decodeBase64(sig), naclUtil.decodeBase64(publicKey)),
    used: (nonce) => gatewayTickets.used(nonce),
  });
  if (!verdict.ok) {
    console.warn('[gw] жетон отклонён:', verdict.reason);
    return send(ws, { type: 'gw-pull-result', ok: false });
  }
  gatewayTickets.remember(verdict.ticket);
  return flushQueueToAgent(verdict.ticket.addr, ws);
}
function flushQueueToAgent(owner, ws) {
  const ids = store.queueIdsFor(owner).slice(0, GW_PULL_MAX_ITEMS);
  let index = 0;
  async function pump() {
    if (ws.readyState !== ws.OPEN) return;
    while (index < ids.length) {
      if (typeof ws.bufferedAmount === 'number' && ws.bufferedAmount > FLUSH_HIGH_WATER) {
        setTimeout(start, FLUSH_RESUME_MS);
        return;
      }
      const item = await store.getItemAsync(ids[index]);
      index += 1;
      if (ws.readyState !== ws.OPEN) return;
      if (item) send(ws, { type: 'gw-mail', addr: owner, id: item.id, envelope: item.envelope });
    }
    if (ws.readyState === ws.OPEN) {
      send(ws, { type: 'gw-pull-result', ok: true, addr: owner, count: ids.length });
    }
  }
  function start() {
    pump().catch((error) =>
      console.warn('[gw] выгрузка по жетону прервана:', (error && error.message) || error)
    );
  }
  start();
  return ids.length;
}
function flushBinaryQueue(pubkey, ws) {
  const ids = store.binaryQueueIdsFor(pubkey);
  let index = 0;
  async function pump() {
    if (ws.readyState !== ws.OPEN) return;
    while (index < ids.length) {
      if (typeof ws.bufferedAmount === 'number' && ws.bufferedAmount > FLUSH_HIGH_WATER) {
        setTimeout(start, FLUSH_RESUME_MS);
        return;
      }
      const item = await store.getBinaryItemAsync(ids[index]);
      index += 1;
      if (ws.readyState !== ws.OPEN) return;
      if (item) sendBinary(ws, queuedBinaryHeader(item), item.payload);
    }
  }
  function start() {
    pump().catch((error) =>
      console.warn('[queue] выгрузка вложений прервана:', (error && error.message) || error)
    );
  }
  start();
  return ids.length;
}
function deliver(from, to, envelope, silent, callPush, metadata = {}) {
  const id = nextId();
  const stored = store.enqueue({
    id,
    to,
    from,
    fromAccount: metadata.fromAccount,
    fromDeviceId: metadata.fromDeviceId,
    deviceCertificate: metadata.deviceCertificate,
    deviceRoster: metadata.deviceRoster,
    envelope,
    envelopeJson: metadata.envelopeJson,
    silent,
    callPush,
    ts: Date.now(),
    maxPerUser: MAX_QUEUE_PER_USER,
    maxPerSender: MAX_QUEUE_PER_SENDER,
    maxTotal: MAX_TOTAL_MESSAGES,
    maxTotalBytes: MAX_QUEUE_BYTES,
    reserve: QUEUE_RESERVE_SLOTS,
    reciprocityTtlMs: QUEUE_TTL_MS,
  });
  const ws = online.get(to);
  const liveFrame = queuedMessageFrame({ id, from, envelope, ...metadata });
  if (ws && sendMessageFrame(ws, liveFrame, metadata.envelopeBytes, { immediate: !stored })) {
    counters.deliveredOnline += 1;
    return { queued: true, id };
  }
  if (!stored) {
    counters.dropped += 1;
    return { queued: false, dropped: true, id };
  }
  counters.queuedOffline += 1;
  const token = store.getToken(to);
  const onInvalid = (r) => {
    if (r === 'invalid') store.delToken(to);
  };
  if (callPush) {
    if (token && Date.now() - (lastCallPushAt.get(to) || 0) >= CALL_PUSH_MIN_INTERVAL_MS) {
      lastCallPushAt.set(to, Date.now());
      counters.pushes += 1;
      sendCallPush(token, to).then(onInvalid);
    }
    return { queued: true, id };
  }
  if (silent) return { queued: true, id };
  const chatTag = chatNotificationTag(metadata.fromAccount || from, CHAT_TAG_SALT);
  if (token && messagePushGate.allow(to, chatTag, Date.now())) {
    counters.pushes += 1;
    sendPush(token, metadata.notificationId || id, chatTag, to).then(onInvalid);
  }
  return { queued: true, id };
}
function isRecipientAddress(addr) {
  if (typeof addr !== 'string' || addr.length !== 44) return false;
  let bytes;
  try {
    bytes = naclUtil.decodeBase64(addr);
  } catch (error) {
    return false;
  }
  return bytes.length === nacl.box.publicKeyLength && naclUtil.encodeBase64(bytes) === addr;
}
function acceptEnvelope(ws, { to, envelope, silent, callPush, ref, envelopeJson, noMeta }) {
  if (!ws.proven) {
    return send(ws, { type: 'error', error: 'box ownership proof required' });
  }
  if (!isRecipientAddress(to)) {
    return send(ws, { type: 'error', error: 'invalid recipient' });
  }
  let json = envelopeJson;
  if (json === undefined) {
    try {
      json = JSON.stringify(envelope);
    } catch (e) {
      return send(ws, { type: 'error', error: 'invalid envelope' });
    }
  }
  const size = Buffer.byteLength(json);
  if (size > MAX_ENVELOPE_BYTES) {
    return send(ws, { type: 'error', error: 'envelope too large' });
  }
  counters.msgsIn += 1;
  const r = deliver(ws.pubkey, to, envelope, silent, callPush, {
    ...(noMeta ? {} : senderMetadata(ws)),
    notificationId: typeof ref === 'string' ? ref.slice(0, 160) : undefined,
    envelopeJson: json,
    envelopeBytes: size,
  });
  return send(ws, { type: 'ack', ref, id: r.id, queued: r.queued, dropped: !!r.dropped });
}
function deliverBinary(from, header, payload, metadata = {}) {
  const id = nextId();
  const stored = store.enqueueBinary({
    id,
    to: header.to,
    from,
    ref: header.ref,
    transferId: header.transferId,
    index: header.index,
    total: header.total,
    metadata,
    payload,
    ts: Date.now(),
    maxPerUser: MAX_QUEUE_PER_USER,
    maxPerSender: MAX_QUEUE_PER_SENDER,
    maxTotal: MAX_TOTAL_MESSAGES,
    maxTotalBytes: MAX_QUEUE_BYTES,
    reserve: QUEUE_RESERVE_SLOTS,
    reciprocityTtlMs: QUEUE_TTL_MS,
  });
  const recipient = online.get(header.to);
  if (recipient && recipient.frameBatchQueue && recipient.frameBatchQueue.length) flushFrameBatch(recipient);
  if (recipient && sendBinary(recipient, queuedBinaryHeader({
    id,
    from,
    transferId: header.transferId,
    index: header.index,
    total: header.total,
    metadata,
  }), payload)) {
    counters.deliveredOnline += 1;
    return { id, queued: true, dropped: false };
  }
  if (!stored) {
    counters.dropped += 1;
    return { id, queued: false, dropped: true };
  }
  counters.queuedOffline += 1;
  return { id, queued: true, dropped: false };
}
function ackReceived(recipientPubkey, id) {
  const from = store.ack(recipientPubkey, id);
  if (from) {
    counters.acked += 1;
    const senderWs = online.get(from);
    if (senderWs) send(senderWs, { type: 'delivered', id });
  }
}
function ackBinaryReceived(recipientPubkey, id) {
  const accepted = store.ackBinary(recipientPubkey, id);
  if (!accepted) return;
  counters.acked += 1;
  const sender = online.get(accepted.from);
  if (sender) {
    send(sender, {
      type: 'binary-delivered',
      id,
      ref: accepted.ref,
      transferId: accepted.transferId,
      index: accepted.index,
    });
  }
}
function rateLimited(ws) {
  const now = Date.now();
  if (now - ws.rateStart > RATE_WINDOW_MS) {
    ws.rateStart = now;
    ws.rateCount = 0;
  }
  ws.rateCount += 1;
  return ws.rateCount > RATE_MAX_FRAMES;
}
const costlyBudgets = new Map();
function costlyIdentity(ws) {
  return (ws && ws.pubkey) || (ws && ws.ip) || 'anon';
}
function costlyLimited(ws, kind, max, now = Date.now()) {
  const identity = costlyIdentity(ws);
  let byKind = costlyBudgets.get(identity);
  if (!byKind) {
    byKind = new Map();
    costlyBudgets.set(identity, byKind);
  }
  const state = byKind.get(kind);
  let over;
  if (!state || now - state.start > COSTLY_WINDOW_MS) {
    byKind.set(kind, { start: now, count: 1 });
    over = 1 > max;
  } else {
    state.count += 1;
    over = state.count > max;
  }
  if (over) counters.costlyRefused += 1;
  return over;
}
function sweepCostlyBudgets(now = Date.now()) {
  for (const [identity, byKind] of costlyBudgets) {
    for (const [kind, state] of byKind) {
      if (now - state.start > COSTLY_WINDOW_MS) byKind.delete(kind);
    }
    if (!byKind.size) costlyBudgets.delete(identity);
  }
}
function byteLimited(ws, bytes) {
  const gate = byteGate(ws.byteState, Date.now(), bytes, RATE_WINDOW_MS, RATE_MAX_BYTES, RATE_ABUSE_WINDOWS);
  ws.byteState = gate.state;
  if (gate.abusive) {
    counters.abusive += 1;
    return true;
  }
  if (gate.pauseMs > 0 && !ws.throttledUntil) {
    counters.throttled += 1;
    ws.throttledUntil = Date.now() + gate.pauseMs;
    try {
      ws.pause();
    } catch (e) {
    }
    const timer = setTimeout(() => {
      ws.throttledUntil = 0;
      try {
        ws.resume();
      } catch (e) {
      }
    }, gate.pauseMs);
    if (typeof timer.unref === 'function') timer.unref();
  }
  return false;
}
function closeRevokedDevice(devicePk, accountPk) {
  store.purgeDeviceTransport(devicePk);
  const target = online.get(devicePk);
  if (!target) return;
  if (target.accountPubkey === accountPk) {
    send(target, { type: 'device-revoked', accountPublicKey: accountPk });
    try {
      target.close(4003, 'device revoked');
    } catch (e) {
      try {
        target.terminate();
      } catch (e2) {
      }
    }
  }
}
function rosterSession(ws, accountPublicKey) {
  const known =
    typeof accountPublicKey === 'string' && accountPublicKey ? store.getAccount(accountPublicKey) : null;
  return {
    proven: !!ws.proven,
    sessionPublicKey: ws.pubkey,
    knownAccountSignPublicKey: known ? known.accountSignPublicKey : null,
    boundRootSignPublicKey:
      typeof accountPublicKey === 'string' && accountPublicKey ? store.getSignKey(accountPublicKey) : null,
  };
}
function acceptSignedRoster(ws, candidate) {
  const claimed = candidate && typeof candidate === 'object' ? candidate : {};
  const early = rosterWriteGate(claimed, rosterSession(ws, claimed.accountPublicKey));
  if (!early.ok) {
    counters.rosterDeniedEarly += 1;
    return { ok: false, reason: early.reason };
  }
  let roster;
  try {
    roster = assertSignedRoster(candidate);
  } catch (error) {
    return { ok: false, reason: 'invalid-roster' };
  }
  const allowed = rosterWriteGate(roster, rosterSession(ws, roster.accountPublicKey));
  if (!allowed.ok) return { ok: false, reason: allowed.reason };
  const result = store.putAccountRoster(roster);
  if (!result.ok) return result;
  for (const devicePk of result.revokedDeviceKeys || []) closeRevokedDevice(devicePk, roster.accountPublicKey);
  return { ...result, roster };
}
function bindSocketToCertifiedDevice(ws, candidate) {
  if (!ws.proven) return { ok: false, reason: 'box-ownership-proof-required' };
  let certificate;
  try {
    certificate = assertDeviceCertificate(candidate);
  } catch (error) {
    return { ok: false, reason: 'invalid-device-certificate' };
  }
  if (
    certificate.devicePublicKey !== ws.pubkey ||
    certificate.deviceSignPublicKey !== store.getSignKey(ws.pubkey)
  ) {
    return { ok: false, reason: 'certificate-does-not-match-session' };
  }
  const account = store.getAccount(certificate.accountPublicKey);
  if (!account || account.accountSignPublicKey !== certificate.accountSignPublicKey) {
    return { ok: false, reason: 'unknown-account' };
  }
  const record = store.getAccountDevice(certificate.accountPublicKey, certificate.deviceId);
  if (!record) return { ok: false, reason: 'device-unknown' };
  if (record.revokedAt != null) return { ok: false, reason: 'device-revoked' };
  if (
    record.devicePublicKey !== certificate.devicePublicKey ||
    record.deviceSignPublicKey !== certificate.deviceSignPublicKey ||
    stableStringify(record.certificate) !== stableStringify(certificate)
  ) {
    return { ok: false, reason: 'certificate-not-in-roster' };
  }
  indexAccountSocket(ws, record);
  return { ok: true, record, roster: store.getAccountRoster(certificate.accountPublicKey) };
}
function enforceAuthTimeout(ws) {
  if (ws.authed) return false;
  send(ws, { type: 'error', error: 'auth timeout' });
  try {
    ws.close(4008, 'auth timeout');
  } catch (e) {
    try {
      ws.terminate();
    } catch (e2) {
    }
  }
  return true;
}
function handleSocketMessage(ws, raw, isBinary, options = {}) {
  const handleBinary = options.handleBinary || handleBinaryFrameSafely;
  const handleJson = options.handleJson || handleFrameSafely;
  const topLevel = options.topLevel || handleTopLevelError;
  const logger = options.logger || console;
  if (rateLimited(ws)) {
    send(ws, { type: 'error', error: 'rate limit' });
    ws.terminate();
    return;
  }
  if (byteLimited(ws, raw.length || 0)) {
    send(ws, { type: 'error', error: 'byte rate limit' });
    ws.terminate();
    return;
  }
  if (isBinary) {
    if (!ws.authed && (raw.length || 0) > MAX_PREAUTH_FRAME_BYTES) {
      counters.oversized += 1;
      send(ws, { type: 'binary-error', error: 'frame too large' });
      return ws.terminate();
    }
    try {
      handleBinary(ws, raw);
    } catch (error) {
      if (isFatalDbError(error)) {
        topLevel('binary-frame-fatal-db', error);
        return;
      }
      send(ws, { type: 'binary-error', error: 'invalid binary frame' });
    }
    return;
  }
  const frameLimit = ws.authed ? MAX_JSON_FRAME_BYTES : MAX_PREAUTH_FRAME_BYTES;
  if (raw.length > frameLimit) {
    counters.oversized += 1;
    send(ws, { type: 'error', error: 'frame too large' });
    if (!ws.authed) return ws.terminate();
    return;
  }
  let msg;
  try {
    msg = JSON.parse(raw.toString());
  } catch (e) {
    return send(ws, { type: 'error', error: 'bad json' });
  }
  try {
    handleJson(ws, msg);
  } catch (e) {
    if (isFatalDbError(e)) {
      topLevel('frame-fatal-db', e);
      return;
    }
    logger.error('[frame]', e && e.stack ? e.stack : e);
    try {
      send(ws, { type: 'error', error: 'server error' });
    } catch (e2) {
    }
  }
}
wss.on('connection', (ws, req) => {
  const ip = clientIp(req);
  const nConn = (ipConns.get(ip) || 0) + 1;
  if (nConn > MAX_CONN_PER_IP) {
    try {
      send(ws, { type: 'error', error: 'too many connections' });
    } catch (e) {
    }
    return ws.terminate();
  }
  ipConns.set(ip, nConn);
  ws.ip = ip;
  ws.isAlive = true;
  ws.authed = false;
  ws.pubkey = null;
  ws.pendingPubkey = null;
  ws.pendingSpk = null;
  ws.nonce = null;
  ws.ephSec = null;
  ws.accountPubkey = null;
  ws.deviceId = null;
  ws.deviceCertificate = null;
  ws.frameBatchV1 = false;
  ws.binaryEnvelopeV1 = false;
  ws.frameBatchQueue = [];
  ws.frameBatchBytes = 0;
  ws.frameBatchTimer = null;
  ws.rateStart = Date.now();
  ws.rateCount = 0;
  ws.byteState = null;
  ws.throttledUntil = 0;
  ws.on('pong', () => (ws.isAlive = true));
  ws.on('error', () => {
    try {
      ws.terminate();
    } catch (e) {
    }
  });
  ws.authTimer = setTimeout(() => enforceAuthTimeout(ws), AUTH_TIMEOUT_MS);
  ws.on('message', (raw, isBinary) => handleSocketMessage(ws, raw, isBinary));
  ws.on('close', () => {
    clearTimeout(ws.frameBatchTimer);
    ws.frameBatchQueue = [];
    clearTimeout(ws.authTimer);
    if (ws.ip) {
      const c = (ipConns.get(ws.ip) || 1) - 1;
      if (c <= 0) ipConns.delete(ws.ip);
      else ipConns.set(ws.ip, c);
    }
    unindexAccountSocket(ws);
    if (ws.pubkey && online.get(ws.pubkey) === ws) online.delete(ws.pubkey);
  });
});
function handleBinaryFrameSafely(ws, raw) {
  if (!ws.authed) return send(ws, { type: 'binary-error', error: 'not authenticated' });
  const { header, payload } = unpackBinaryFrame(raw);
  if (header.type === 'cover-v1' && header.version === 1) {
    counters.cover += 1;
    return true;
  }
  if (header.type === 'frame-batch-v1' && header.version === 1) {
    if (!ws.frameBatchV1 || payload.length > 256 * 1024) {
      return send(ws, { type: 'binary-error', error: 'frame batch not negotiated' });
    }
    const frames = decodeMessagePack(payload);
    if (
      !Array.isArray(frames) ||
      frames.length < 1 ||
      frames.length > 64 ||
      frames.length !== header.count
    ) {
      return send(ws, { type: 'binary-error', error: 'invalid frame batch' });
    }
    for (const frame of frames) {
      if (!frame || typeof frame !== 'object' || Array.isArray(frame)) {
        return send(ws, { type: 'binary-error', error: 'invalid frame in batch' });
      }
      handleFrameSafely(ws, frame);
    }
    return true;
  }
  if (header.type === envelopeFrame.SEND_FRAME_TYPE && header.version === 1) {
    if (
      typeof header.to !== 'string' ||
      !header.to ||
      header.to.length > MAX_ADDR_LEN ||
      (header.ref != null && (typeof header.ref !== 'string' || header.ref.length > 160)) ||
      !payload.length ||
      payload.length > MAX_SEALED_PAYLOAD_BYTES
    ) {
      return send(ws, { type: 'error', error: 'invalid envelope frame' });
    }
    const envelope = envelopeFrame.sealedEnvelope(header.sv, payload);
    if (!envelope) return send(ws, { type: 'error', error: 'invalid envelope frame' });
    const flags = envelopeFrame.sendHeaderFlags(header);
    return acceptEnvelope(ws, {
      to: header.to,
      envelope,
      envelopeJson: JSON.stringify(envelope),
      silent: flags.silent,
      callPush: flags.callPush,
      noMeta: flags.noMeta,
      ref: header.ref == null ? undefined : header.ref,
    });
  }
  if (
    header.type !== 'attachment-chunk' ||
    header.version !== 1 ||
    typeof header.to !== 'string' ||
    !header.to ||
    header.to.length > MAX_ADDR_LEN ||
    typeof header.transferId !== 'string' ||
    !/^[A-Za-z0-9_-]{12,64}$/.test(header.transferId) ||
    !Number.isInteger(header.index) ||
    !Number.isInteger(header.total) ||
    header.total < 1 ||
    header.total > MAX_BINARY_CHUNKS ||
    header.index < 0 ||
    header.index >= header.total ||
    payload.length < 40 ||
    payload.length > MAX_BINARY_CHUNK_BYTES ||
    (header.ref != null && (typeof header.ref !== 'string' || header.ref.length > 160))
  ) {
    return send(ws, { type: 'binary-error', ref: header.ref, error: 'invalid attachment chunk' });
  }
  if (!ws.proven) {
    return send(ws, { type: 'error', error: 'box ownership proof required' });
  }
  counters.msgsIn += 1;
  const result = deliverBinary(ws.pubkey, header, payload, senderMetadata(ws));
  return send(ws, {
    type: 'binary-ack',
    ref: header.ref,
    id: result.id,
    transferId: header.transferId,
    index: header.index,
    queued: result.queued,
    dropped: result.dropped,
  });
}
function sendPushTestResult(ws, token, testId, channel, provider = sendTestPush, tokenStore = store) {
  return provider(token, testId, channel, ws.pubkey)
    .then((result) => {
      if (result === 'invalid') tokenStore.delToken(ws.pubkey);
      send(ws, {
        type: 'push-test-result',
        testId,
        channel,
        accepted: result === true,
        error: result === 'invalid' ? 'invalid-subscription' : result === true ? undefined : 'provider-unavailable',
      });
    })
    .catch(() => {
      send(ws, { type: 'push-test-result', testId, channel, accepted: false, error: 'provider-error' });
    });
}
function handleFrameSafely(ws, msg) {
    if (!msg || typeof msg !== 'object' || Array.isArray(msg)) {
      return send(ws, { type: 'error', error: 'bad frame' });
    }
    if (msg.type === 'hello') {
      if (ws.authed) {
        return send(ws, { type: 'error', error: 'already authenticated' });
      }
      ws.helloCount = (ws.helloCount || 0) + 1;
      if (ws.helloCount > 20) {
        send(ws, { type: 'error', error: 'too many hellos' });
        return ws.terminate();
      }
      if (typeof msg.pubkey !== 'string' || !msg.pubkey) {
        return send(ws, { type: 'error', error: 'hello requires pubkey' });
      }
      if (typeof msg.signPublicKey !== 'string' || !msg.signPublicKey) {
        return send(ws, { type: 'error', error: 'hello requires signPublicKey' });
      }
      if (msg.pubkey.length > MAX_ADDR_LEN || msg.signPublicKey.length > MAX_ADDR_LEN) {
        return send(ws, { type: 'error', error: 'invalid key' });
      }
      ws.frameBatchV1 =
        Array.isArray(msg.capabilities) && msg.capabilities.includes('frame-batch-v1');
      ws.binaryEnvelopeV1 =
        Array.isArray(msg.capabilities) &&
        msg.capabilities.includes(envelopeFrame.BINARY_ENVELOPE_CAPABILITY);
      ws.pendingPubkey = msg.pubkey;
      ws.pendingSpk = msg.signPublicKey;
      ws.nonce = naclUtil.encodeBase64(crypto.randomBytes(32));
      const eph = nacl.box.keyPair();
      ws.ephSec = naclUtil.encodeBase64(eph.secretKey);
      const reply = { type: 'challenge', nonce: ws.nonce, eph: naclUtil.encodeBase64(eph.publicKey) };
      if (
        typeof msg.cnonce === 'string' &&
        msg.cnonce &&
        msg.cnonce.length <= MAX_ADDR_LEN &&
        helloSigRate.allow(ws.ip || 'anon', Date.now())
      ) {
        reply.relayPub = RELAY_KEYS.pub;
        reply.relaySig = signRelayAuth(msg.cnonce);
      }
      return send(ws, reply);
    }
    if (msg.type === 'auth') {
      if (!ws.pendingPubkey || !ws.nonce) {
        return send(ws, { type: 'error', error: 'say hello first' });
      }
      if (typeof msg.signature !== 'string') {
        return send(ws, { type: 'error', error: 'auth requires signature' });
      }
      ws.authCount = (ws.authCount || 0) + 1;
      if (ws.authCount > 20) {
        send(ws, { type: 'error', error: 'too many auth attempts' });
        return ws.terminate();
      }
      if (!verifySignature(ws.nonce, msg.signature, ws.pendingSpk)) {
        return send(ws, { type: 'error', error: 'bad signature' });
      }
      const boxProven =
        typeof msg.boxProof === 'string' &&
        ws.ephSec &&
        verifyBoxProof(ws.nonce, msg.boxProof, ws.pendingPubkey, ws.ephSec);
      const bound = store.getIdentity(ws.pendingPubkey);
      if (bound && bound.proven) {
        if (!boxProven) {
          return send(ws, { type: 'error', error: 'box ownership proof required' });
        }
        if (bound.signPk !== ws.pendingSpk) store.rebindSignKey(ws.pendingPubkey, ws.pendingSpk, Date.now());
      } else if (bound && !bound.proven) {
        if (boxProven) {
          store.rebindSignKey(ws.pendingPubkey, ws.pendingSpk, Date.now());
        } else if (bound.signPk !== ws.pendingSpk) {
          return send(ws, { type: 'error', error: 'pubkey bound to a different key' });
        }
      } else {
        store.bindSignKey(ws.pendingPubkey, ws.pendingSpk, boxProven, Date.now());
      }
      counters.authOk += 1;
      ws.authed = true;
      ws.pubkey = ws.pendingPubkey;
      ws.proven = !!boxProven;
      ws.signPk = ws.pendingSpk;
      ws.nonce = null;
      ws.ephSec = null;
      clearTimeout(ws.authTimer);
      if (!ws.proven) {
        counters.unprovenReceive = (counters.unprovenReceive || 0) + 1;
        const evictedUnproven = store.evictColdIdentities(MAX_IDENTITIES);
        if (evictedUnproven) console.log(`[identities] evicted ${evictedUnproven} cold identity(ies) over cap`);
        return send(ws, {
          type: 'ready',
          queued: 0,
          prekeys: 0,
          vapidPublicKey: vapidPublicKeyFor(ws.pubkey),
          protocol: RELAY_PROTOCOL,
          capabilities: RELAY_CAPABILITIES,
          maxLinkedDevices: MAX_ACTIVE_DEVICES,
          overloaded: relayOverloaded(),
          receiveBlocked: 'box-proof-required',
        });
      }
      const prev = online.get(ws.pubkey);
      if (prev && prev !== ws) {
        try {
          prev.terminate();
        } catch (e) {
        }
      }
      online.set(ws.pubkey, ws);
      store.touchIdentity(ws.pubkey, Date.now());
      const evicted = store.evictColdIdentities(MAX_IDENTITIES);
      if (evicted) console.log(`[identities] evicted ${evicted} cold identity(ies) over cap`);
      const flushedBinary = store.binaryQueueIdsFor(ws.pubkey).length;
      const flushed = flushQueue(ws.pubkey, ws, () => flushBinaryQueue(ws.pubkey, ws));
      if (relayOverloaded()) counters.overloaded += 1;
      return send(ws, {
        type: 'ready',
        queued: flushed + flushedBinary,
        prekeys: store.countOtps(ws.pubkey),
        vapidPublicKey: vapidPublicKeyFor(ws.pubkey),
        protocol: RELAY_PROTOCOL,
        capabilities: RELAY_CAPABILITIES,
        maxLinkedDevices: MAX_ACTIVE_DEVICES,
        overloaded: relayOverloaded(),
      });
    }
    if (msg.type === 'ping') {
      if (ws.deviceId) store.touchDevice(ws.pubkey, Date.now());
      const busy = relayOverloaded();
      if (busy) counters.overloaded += 1;
      return send(ws, busy ? { type: 'pong', overloaded: true } : { type: 'pong' });
    }
    if (!ws.authed) return send(ws, { type: 'error', error: 'not authenticated' });
    if (msg.type === 'relays') {
      return send(ws, { type: 'relays', relays: relayDir });
    }
    if (msg.type === 'device-roster-put') {
      if (costlyLimited(ws, 'rosterPut', ROSTER_PUT_MAX_PER_MIN)) {
        return send(ws, { type: 'device-roster-error', error: 'rate' });
      }
      const accepted = acceptSignedRoster(ws, msg.roster);
      if (!accepted.ok) {
        return send(ws, { type: 'device-roster-error', error: accepted.reason || 'invalid-roster' });
      }
      send(ws, {
        type: 'device-roster-ok',
        accountPublicKey: accepted.roster.accountPublicKey,
        version: accepted.roster.version,
        unchanged: !!accepted.unchanged,
      });
      broadcastAccount(accepted.roster.accountPublicKey, {
        type: 'device-roster',
        roster: accepted.roster,
      });
      return;
    }
    if (msg.type === 'device-bind') {
      const bound = bindSocketToCertifiedDevice(ws, msg.certificate);
      if (!bound.ok) {
        return send(ws, { type: 'device-bind-error', error: bound.reason || 'device-bind-failed' });
      }
      return send(ws, {
        type: 'device-bound',
        accountPublicKey: bound.record.accountPublicKey,
        deviceId: bound.record.deviceId,
        roster: bound.roster,
      });
    }
    if (msg.type === 'device-roster-get') {
      const requested =
        typeof msg.accountPublicKey === 'string' && msg.accountPublicKey
          ? msg.accountPublicKey
          : ws.accountPubkey || ws.pubkey;
      const ownsRequested =
        requested === ws.accountPubkey ||
        (requested === ws.pubkey && !!store.getAccount(requested));
      if (!ownsRequested) return send(ws, { type: 'device-roster-error', error: 'forbidden' });
      return send(ws, { type: 'device-roster', roster: store.getAccountRoster(requested) });
    }
    if (msg.type === 'relay-advertise') {
      ws.advCount = (ws.advCount || 0) + 1;
      if (ws.advCount > 30) {
        return send(ws, { type: 'relays', relays: relayDir });
      }
      const urls = Array.isArray(msg.relays) ? msg.relays : [msg.url];
      const clean = urls.slice(0, MAX_RELAYS).filter((u) => isValidRelayUrl(u));
      if (ws.proven && clean.length) learnRelays(clean);
      return send(ws, { type: 'relays', relays: relayDir });
    }
    if (msg.type === 'turn') {
      if (!ws.proven) {
        return send(ws, { type: 'error', error: 'box ownership proof required' });
      }
      if (costlyLimited(ws, 'turn', TURN_MAX_PER_MIN)) {
        return send(ws, { type: 'error', error: 'rate' });
      }
      return send(ws, { type: 'turn', iceServers: turnIceServers() });
    }
    if (msg.type === 'prekeys-put') {
      if (!ws.proven) {
        return send(ws, { type: 'error', error: 'box ownership proof required' });
      }
      const b = msg.bundle || {};
      const spkObj = b.spk;
      if (!spkObj || !isB64Field(spkObj.id, 32) || !isB64Field(spkObj.pub) || !isB64Field(spkObj.sig)) {
        return send(ws, { type: 'error', error: 'prekeys-put requires bundle.spk {id,pub,sig}' });
      }
      if (spkObj.pq !== undefined && !isB64Field(spkObj.pq, MAX_SPK_PQ_B64)) {
        return send(ws, { type: 'error', error: 'bad bundle.spk.pq' });
      }
      const boundSpkKey = store.getSignKey(ws.pubkey);
      if (!boundSpkKey || !verifySpkSignature(spkObj, boundSpkKey)) {
        return send(ws, { type: 'error', error: 'bad prekey signature' });
      }
      const opks = (Array.isArray(b.opks) ? b.opks : [])
        .filter((k) => k && isB64Field(k.id, 32) && isB64Field(k.pub))
        .slice(0, MAX_OTPS_PER_USER)
        .map((k) => ({ id: k.id, pub: k.pub }));
      store.setSpk(ws.pubkey, { id: spkObj.id, pub: spkObj.pub, sig: spkObj.sig, pq: spkObj.pq });
      store.replaceOtps(ws.pubkey, opks);
      return send(ws, { type: 'prekeys-ok', otps: store.countOtps(ws.pubkey) });
    }
    if (msg.type === 'mbx-put') {
      if (typeof msg.records !== 'string' || msg.records.length > 4 * mbx.RECORD_BYTES * mbx.MAX_PUT_RECORDS + 8) {
        return send(ws, { type: 'mbx-error', error: 'bad records' });
      }
      const nowPut = Date.now();
      if (nowPut - (ws.mbxPutStart || 0) > MBX_PUT_WINDOW_MS) {
        ws.mbxPutStart = nowPut;
        ws.mbxPutCount = 0;
      }
      ws.mbxPutCount = (ws.mbxPutCount || 0) + 1;
      if (ws.mbxPutCount > MBX_PUT_MAX) {
        return send(ws, { type: 'mbx-error', error: 'rate' });
      }
      let raw = null;
      try {
        raw = Buffer.from(msg.records, 'base64');
      } catch (e) {
        return send(ws, { type: 'mbx-error', error: 'bad records' });
      }
      const parsed = mbx.parsePut(raw, { now: nowPut, slot: msg.slot });
      if (!parsed) return send(ws, { type: 'mbx-error', error: 'bad records' });
      const added = store.mbxPut(parsed, mbxValueHash);
      mbxTrim();
      mbxRefreshDigest();
      return send(ws, { type: 'mbx-ok', added });
    }
    if (msg.type === 'mbx-digest') {
      if (costlyLimited(ws, 'mbxDigest', MBX_DIGEST_MAX_PER_MIN)) {
        return send(ws, { type: 'mbx-error', error: 'rate' });
      }
      const size = store.mbxCount();
      const digest = mbxDigest.get(store.mbxRevision(), () => store.mbxKeys());
      return send(ws, {
        type: 'mbx-digest',
        size,
        depth: mbx.bucketDepth(size),
        p: digest.p,
        n: digest.n,
        bits: digest.bitsBase64,
      });
    }
    if (msg.type === 'mbx-fetch') {
      if (costlyLimited(ws, 'mbxFetch', MBX_FETCH_MAX_PER_MIN)) {
        return send(ws, { type: 'mbx-error', error: 'rate' });
      }
      const size = store.mbxCount();
      if (!mbx.depthAllowed(msg.depth, size)) {
        return send(ws, { type: 'mbx-error', error: 'depth' });
      }
      const range = mbx.bucketRange(msg.bucket, msg.depth);
      if (!range) return send(ws, { type: 'mbx-error', error: 'bucket' });
      const rows = store.mbxBucket(range.low, range.high, mbx.SYNC_LIMIT);
      return send(ws, {
        type: 'mbx-bucket',
        depth: msg.depth,
        bucket: msg.bucket,
        count: rows.length,
        records: mbx.packRecords(rows.map((row) => ({ key: row.key, value: row.val, mac: row.mac }))).toString('base64'),
      });
    }
    if (msg.type === 'prekeys-count') {
      return send(ws, { type: 'prekeys-count', otps: store.countOtps(ws.pubkey) });
    }
    if (msg.type === 'prekeys-get') {
      if (typeof msg.pubkey !== 'string' || !msg.pubkey) {
        return send(ws, { type: 'error', error: 'prekeys-get requires pubkey' });
      }
      const nowPk = Date.now();
      if (nowPk - (ws.pkGetStart || 0) > PREKEY_GET_WINDOW_MS) {
        ws.pkGetStart = nowPk;
        ws.pkGetCount = 0;
      }
      ws.pkGetCount = (ws.pkGetCount || 0) + 1;
      if (ws.pkGetCount > PREKEY_GET_MAX) {
        return send(ws, { type: 'prekeys', pubkey: msg.pubkey, bundle: null });
      }
      const spkRec = store.getSpk(msg.pubkey);
      if (!spkRec) return send(ws, { type: 'prekeys', pubkey: msg.pubkey, bundle: null });
      const nowT = Date.now();
      const gate = rateGate(otpDrain.get(msg.pubkey), nowT, PREKEY_TARGET_WINDOW_MS, PREKEY_TARGET_MAX);
      otpDrain.set(msg.pubkey, gate.state);
      let opk = null;
      if (gate.allow) {
        opk = store.takeOtp(msg.pubkey);
        if (opk) gate.state.count += 1;
      }
      return send(ws, { type: 'prekeys', pubkey: msg.pubkey, bundle: { spk: spkRec, opk } });
    }
    if (msg.type === 'register') {
      if (!ws.proven) {
        return send(ws, { type: 'error', error: 'box ownership proof required' });
      }
      if (typeof msg.pushToken === 'string' && msg.pushToken && msg.pushToken.length <= 1024) {
        store.setToken(ws.pubkey, msg.pushToken);
      }
      return send(ws, { type: 'registered' });
    }
    if (msg.type === 'push-test') {
      const testId = typeof msg.testId === 'string' ? msg.testId : '';
      const channel = msg.channel === 'call' ? 'call' : 'message';
      if (!/^[A-Za-z0-9_-]{8,96}$/.test(testId)) {
        return send(ws, { type: 'push-test-result', testId, accepted: false, error: 'invalid-test-id' });
      }
      if (costlyLimited(ws, 'pushTest', PUSH_TEST_MAX_PER_MIN)) {
        return send(ws, { type: 'push-test-result', testId, accepted: false, error: 'rate-limited' });
      }
      const token = store.getToken(ws.pubkey);
      if (!token) {
        return send(ws, { type: 'push-test-result', testId, accepted: false, error: 'not-registered' });
      }
      sendPushTestResult(ws, token, testId, channel);
      return;
    }
    if (msg.type === 'received') {
      if (typeof msg.id === 'string' && ws.proven) ackReceived(ws.pubkey, msg.id);
      return;
    }
    if (msg.type === 'gw-pull') {
      handleGatewayPull(ws, msg);
      return;
    }
    if (msg.type === 'binary-received') {
      if (typeof msg.id === 'string' && ws.proven) ackBinaryReceived(ws.pubkey, msg.id);
      return;
    }
    if (msg.type === 'send') {
      if (typeof msg.to !== 'string' || !msg.to || !msg.envelope) {
        return send(ws, { type: 'error', error: 'send requires to + envelope' });
      }
      return acceptEnvelope(ws, {
        to: msg.to,
        envelope: msg.envelope,
        silent: !!msg.silent,
        callPush: !!msg.callPush,
        noMeta: !!msg.noMeta,
        ref: msg.ref,
      });
    }
    send(ws, { type: 'error', error: 'unknown type' });
}
function relayHttpBase(wsUrl) {
  return wsUrl.replace(/^ws:\/\//i, 'http://').replace(/^wss:\/\//i, 'https://');
}
function hostOf(wsUrl) {
  return String(wsUrl)
    .replace(/^wss?:\/\//i, '')
    .replace(/[/?#].*$/, '')
    .replace(/:\d+$/, '')
    .replace(/^\[|\]$/g, '');
}
async function safePeerAddrs(wsUrl, { allowPrivate = false } = {}) {
  const host = hostOf(wsUrl);
  if (!host || (!allowPrivate && isPrivateHost(host))) return null;
  try {
    const addrs = await dns.lookup(host, { all: true });
    if (!addrs.length) return null;
    if (!allowPrivate) {
      for (const a of addrs) if (isPrivateHost(a.address)) return null;
    }
    return addrs.map((a) => ({ address: a.address, family: a.family }));
  } catch (e) {
    return null;
  }
}
function pinnedLookup(pinned) {
  return (hostname, options, cb) => {
    if (options && options.all) return cb(null, pinned);
    cb(null, pinned[0].address, pinned[0].family);
  };
}
function httpJson(urlStr, { method = 'GET', headers = {}, body = null, pinned, timeoutMs = 5000 }) {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (v) => {
      if (settled) return;
      settled = true;
      resolve(v);
    };
    let mod;
    try {
      mod = new URL(urlStr).protocol === 'https:' ? https : http;
    } catch (e) {
      return finish(null);
    }
    const req = mod.request(urlStr, { method, headers, lookup: pinnedLookup(pinned) }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        return finish(null);
      }
      let buf = '';
      res.on('data', (c) => {
        buf += c;
        if (buf.length > 1000000) {
          req.destroy();
          finish(null);
        }
      });
      res.on('end', () => {
        try {
          finish(JSON.parse(buf));
        } catch (e) {
          finish(null);
        }
      });
      res.on('error', () => finish(null));
    });
    req.on('error', () => finish(null));
    req.on('close', () => finish(null));
    req.setTimeout(timeoutMs, () => req.destroy());
    if (body) req.write(body);
    req.end();
  });
}
async function fetchPeerRelays(wsUrl) {
  const pinned = await safePeerAddrs(wsUrl);
  if (!pinned) return null;
  const body = await httpJson(relayHttpBase(wsUrl) + '/relays', { pinned });
  return body && Array.isArray(body.relays) ? body.relays : null;
}
async function pushSelfTo(wsUrl) {
  const pinned = await safePeerAddrs(wsUrl);
  if (!pinned) return;
  await httpJson(relayHttpBase(wsUrl) + '/relays', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(GOSSIP_TOKEN ? { 'x-gossip-token': GOSSIP_TOKEN } : {}),
    },
    body: JSON.stringify({ relays: relayDir }),
    pinned,
  });
}
const vapidSyncState = { running: false };
async function vapidSyncWith(options = {}) {
  const state = options.state || vapidSyncState;
  const bundle = options.bundle === undefined ? vapidFleetBundle : options.bundle;
  const fleet = options.fleet === undefined ? VAPID_FLEET : options.fleet;
  const member = options.member === undefined ? VAPID_MEMBER : options.member;
  const selfUrl = options.selfUrl === undefined ? SELF_URL : options.selfUrl;
  const relayPublicKey = options.relayPublicKey || RELAY_KEYS.pub;
  const relaySecretKey = options.relaySecretKey || RELAY_KEYS.sec;
  const allowPrivate = options.allowPrivate === undefined ? VAPID_FLEET_ALLOW_PRIVATE : options.allowPrivate;
  const acceptsKey = options.acceptsKey || memberAcceptsKey;
  const resolvePeer = options.resolvePeer || safePeerAddrs;
  const createRequest = options.createRequest || createVapidRequest;
  const requestJson = options.requestJson || httpJson;
  const httpBase = options.httpBase || relayHttpBase;
  const openResponse = options.openResponse || openVapidResponse;
  const writeFile = options.writeFile || writeJsonAtomic;
  const keyFile = options.keyFile || RELAY_VAPID_KEY_FILE;
  const activate = options.activate || activateVapid;
  const logger = options.logger || console;
  if (
    state.running ||
    bundle ||
    !fleet ||
    !member ||
    !selfUrl ||
    !acceptsKey(member, relayPublicKey)
  ) {
    return false;
  }
  state.running = true;
  try {
    const peers = [...fleet.relays]
      .filter((entry) => entry.url.toLowerCase() !== selfUrl.toLowerCase())
      .sort((a, b) => Number(b.url === fleet.genesis) - Number(a.url === fleet.genesis));
    for (const peer of peers) {
      const pinned = await resolvePeer(peer.url, { allowPrivate });
      if (!pinned) continue;
      let pending;
      try {
        pending = createRequest({
          config: fleet,
          relayUrl: selfUrl,
          relayPub: relayPublicKey,
          relaySecret: relaySecretKey,
        });
      } catch (e) {
        logger.warn('[vapid-fleet] локальная идентичность не разрешена:', e && e.message);
        return false;
      }
      const response = await requestJson(httpBase(peer.url) + '/vapid-fleet', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(pending.request),
        pinned,
        timeoutMs: 8000,
      });
      if (
        !response ||
        typeof response.senderUrl !== 'string' ||
        response.senderUrl.toLowerCase() !== peer.url.toLowerCase()
      ) {
        continue;
      }
      const receivedBundle = openResponse({
        config: fleet,
        request: pending.request,
        response,
        boxSecret: pending.boxSecret,
      });
      if (!receivedBundle) continue;
      try {
        writeFile(keyFile, receivedBundle);
        if (!activate(receivedBundle.publicKey, receivedBundle.privateKey, `fleet-peer:${peer.url}`, receivedBundle)) {
          throw new Error('web-push rejected the verified VAPID pair');
        }
        logger.log(`[vapid-fleet] общий VAPID epoch=${receivedBundle.epoch} получен от ${peer.url}`);
        return true;
      } catch (e) {
        logger.warn('[vapid-fleet] не удалось сохранить полученный VAPID:', e && e.message);
      }
    }
    return false;
  } finally {
    state.running = false;
  }
}
async function vapidSyncOnce() {
  return vapidSyncWith();
}
const mbxCursors = new Map();
async function fetchPeerNotes(wsUrl) {
  const after = mbxCursors.get(wsUrl) || 0;
  const pinned = await safePeerAddrs(wsUrl);
  if (!pinned) return 0;
  const body = await httpJson(relayHttpBase(wsUrl) + '/mbx?after=' + after, { pinned });
  if (!body || typeof body.records !== 'string') return 0;
  if (!Array.isArray(body.slots)) return 0;
  let raw = null;
  try {
    raw = Buffer.from(body.records, 'base64');
  } catch (e) {
    return 0;
  }
  if (!raw.length || raw.length % mbx.RECORD_BYTES !== 0) return 0;
  const count = raw.length / mbx.RECORD_BYTES;
  if (count !== body.slots.length || count > mbx.SYNC_LIMIT) return 0;
  const now = Date.now();
  const here = mbx.slotOf(now);
  const records = [];
  for (let i = 0; i < count; i += 1) {
    const slot = body.slots[i];
    if (!Number.isInteger(slot) || Math.abs(slot - here) > mbx.SLOT_TOLERANCE) continue;
    const at = i * mbx.RECORD_BYTES;
    records.push({
      key: raw.subarray(at, at + mbx.KEY_BYTES),
      value: raw.subarray(at + mbx.KEY_BYTES, at + mbx.KEY_BYTES + mbx.VALUE_BYTES),
      mac: raw.subarray(at + mbx.KEY_BYTES + mbx.VALUE_BYTES, at + mbx.RECORD_BYTES),
      slot,
    });
  }
  if (Number.isInteger(body.seq) && body.seq > after) mbxCursors.set(wsUrl, body.seq);
  if (!records.length) return 0;
  const added = store.mbxPut(records, mbxValueHash);
  if (added) mbxTrim(now);
  return added;
}
let gossipRunning = false;
async function gossipOnce() {
  if (gossipRunning) return;
  gossipRunning = true;
  try {
    const peers = relayDir.filter((u) => !SELF_URL || u.toLowerCase() !== SELF_URL.toLowerCase());
    let learned = false;
    for (const peer of peers) {
      const list = await fetchPeerRelays(peer);
      if (list && learnRelays(list)) learned = true;
      await pushSelfTo(peer);
      await fetchPeerNotes(peer);
    }
    mbxTrim();
    if (learned) console.log(`[gossip] directory now ${relayDir.length} relays`);
  } finally {
    gossipRunning = false;
  }
}
function scheduleFederation(options = {}) {
  const selfUrl = options.selfUrl === undefined ? SELF_URL : options.selfUrl;
  const seeds = options.seeds || PEER_SEED;
  const fleet = options.fleet === undefined ? VAPID_FLEET : options.fleet;
  const member = options.member === undefined ? VAPID_MEMBER : options.member;
  const bundle = options.bundle === undefined ? vapidFleetBundle : options.bundle;
  const runGossip = options.runGossip || gossipOnce;
  const runVapidSync = options.runVapidSync || vapidSyncOnce;
  const setEvery = options.setEvery || setInterval;
  const setLater = options.setLater || setTimeout;
  const timers = [];
  if (selfUrl || seeds.length) {
    const timer = setEvery(() => runGossip().catch(() => {}), GOSSIP_INTERVAL_MS);
    if (timer && typeof timer.unref === 'function') timer.unref();
    timers.push(timer);
  }
  if (fleet && member && !bundle) {
    const initial = setLater(() => runVapidSync().catch(() => {}), 2000);
    const repeat = setEvery(() => runVapidSync().catch(() => {}), VAPID_SYNC_INTERVAL_MS);
    if (initial && typeof initial.unref === 'function') initial.unref();
    if (repeat && typeof repeat.unref === 'function') repeat.unref();
    timers.push(initial, repeat);
  }
  return timers;
}
scheduleFederation();
function heartbeatConnections(clients = wss.clients) {
  for (const ws of clients) {
    if (ws.bufferedAmount > MAX_BUFFERED_BYTES) {
      ws.terminate();
      continue;
    }
    if (!ws.isAlive) {
      ws.terminate();
      continue;
    }
    ws.isAlive = false;
    ws.ping();
  }
}
setInterval(heartbeatConnections, 30000).unref();
function expireQueuedEnvelopes(now = Date.now(), queueStore = store, { onFatal = handleTopLevelError } = {}) {
  try {
    const removed = queueStore.expireOlderThan(now - QUEUE_TTL_MS);
    if (removed) console.log(`[ttl] expired ${removed} stale envelope(s)`);
    const redacted = store.redactRevokedDevices(Date.now());
    if (redacted) console.log(`[ttl] redacted ${redacted} revoked device record(s)`);
    const staleReports = store.sweepReports(now - reportsRule.REPORT_TTL_MS);
    if (staleReports) console.log(`[ttl] dropped ${staleReports} stale report(s)`);
    sweepRelayDirectory(now);
    return removed;
  } catch (e) {
    if (isFatalDbError(e)) {
      onFatal('ttl', e);
      return 0;
    }
    console.warn('[ttl] проход уборки не выполнен:', (e && e.message) || e);
  }
  return 0;
}
setInterval(expireQueuedEnvelopes, 3600 * 1000).unref();
let mirrorRunning = false;
function mirroredRelease(platform) {
  try {
    const file = path.join(UPDATE_DIR, updateFeed.RELEASES[platform].manifest);
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    return { version: String(parsed.version || ''), sha256: String(parsed.sha256 || '') };
  } catch (e) {
    return null;
  }
}
function verifyReleaseSignature(payload, signature, key) {
  try {
    return ed25519.verify(
      naclUtil.decodeUTF8(payload),
      naclUtil.decodeBase64(signature),
      naclUtil.decodeBase64(key)
    );
  } catch (e) {
    return false;
  }
}
function verifyManifestSignature(manifest) {
  try {
    return (
      verifyReleaseSignature(
        updateManifestRule.signedPayload(manifest),
        manifest && manifest.signature,
        RELEASE_PUBLIC_KEY
      ) === true
    );
  } catch (e) {
    return false;
  }
}
const updateHashCache = new Map();
function releaseFileHash(target) {
  let info = null;
  try {
    info = fs.statSync(target);
  } catch (e) {
    return '';
  }
  const cached = updateHashCache.get(target);
  if (cached && cached.size === info.size && cached.mtimeMs === info.mtimeMs) return cached.sha;
  const hash = crypto.createHash('sha256');
  let fd = null;
  try {
    fd = fs.openSync(target, 'r');
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let read = 0;
    while ((read = fs.readSync(fd, buffer, 0, buffer.length, null)) > 0) {
      hash.update(buffer.subarray(0, read));
    }
  } catch (e) {
    return '';
  } finally {
    if (fd !== null) {
      try {
        fs.closeSync(fd);
      } catch (e) {}
    }
  }
  const sha = hash.digest('hex');
  updateHashCache.set(target, { size: info.size, mtimeMs: info.mtimeMs, sha });
  if (updateHashCache.size > 32) {
    const oldest = updateHashCache.keys().next().value;
    updateHashCache.delete(oldest);
  }
  return sha;
}
async function fetchText(url, limit) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 20000);
  try {
    const response = await fetch(url, { signal: controller.signal, redirect: 'follow' });
    if (!response.ok) return null;
    const text = await response.text();
    return text.length > limit ? null : text;
  } catch (e) {
    return null;
  } finally {
    clearTimeout(timer);
  }
}
async function mirrorPlatform(platform) {
  const url = updateMirror.manifestUrl(UPDATE_SOURCE, platform);
  if (!url) return;
  const body = await fetchText(url, updateMirror.MAX_MANIFEST_BYTES);
  if (!body) return;
  const have = mirroredRelease(platform);
  const checked = updateMirror.checkedManifest({
    body,
    platform,
    publicKey: RELEASE_PUBLIC_KEY,
    verifySignature: verifyReleaseSignature,
    currentVersion: '0.0.0',
  });
  if (!checked.ok) {
    console.warn(`[update] манифест ${platform} отвергнут: ${checked.reason}`);
    return;
  }
  if (!updateMirror.needsFetch({ have, release: checked.release })) return;
  const fileUrl = updateMirror.usableFileUrl(checked.release.url);
  if (!fileUrl) {
    console.warn(`[update] адрес файла ${platform} не годится: нужен https`);
    return;
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 300000);
  let bytes = null;
  try {
    const response = await fetch(fileUrl, { signal: controller.signal, redirect: 'follow' });
    if (!response.ok) return;
    bytes = Buffer.from(await response.arrayBuffer());
  } catch (e) {
    console.warn(`[update] файл ${platform} не скачался:`, (e && e.message) || e);
    return;
  } finally {
    clearTimeout(timer);
  }
  const sha256 = crypto.createHash('sha256').update(bytes).digest('hex');
  const verdict = updateMirror.fileVerdict({ size: bytes.length, sha256, release: checked.release });
  if (!verdict.ok) {
    console.warn(`[update] файл ${platform} не сошёлся с подписанным манифестом: ${verdict.reason}`);
    return;
  }
  fs.mkdirSync(UPDATE_DIR, { recursive: true });
  const names = updateFeed.RELEASES[platform];
  const filePath = path.join(UPDATE_DIR, names.file);
  const tmpPath = `${filePath}.part`;
  fs.writeFileSync(tmpPath, bytes);
  fs.renameSync(tmpPath, filePath);
  fs.writeFileSync(path.join(UPDATE_DIR, names.manifest), body, 'utf8');
  console.warn(`[update] ${platform}: раздаём ${checked.release.version} (${bytes.length} байт)`);
}
function mirroredCanaryRelease() {
  try {
    const name = updateFeed.RELEASES.android.canaryManifest;
    const parsed = JSON.parse(fs.readFileSync(path.join(UPDATE_DIR, name), 'utf8'));
    const version = String(parsed.version || '');
    if (!version) return null;
    return { version, sha256: String(parsed.sha256 || '') };
  } catch (e) {
    return null;
  }
}
async function mirrorCanary() {
  const url = updateMirror.manifestUrl(UPDATE_SOURCE, 'android', 'canary');
  if (!url) return;
  const body = await fetchText(url, updateMirror.MAX_MANIFEST_BYTES);
  if (!body) return;
  const checked = updateMirror.checkedManifest({
    body,
    platform: 'android',
    publicKey: RELEASE_PUBLIC_KEY,
    verifySignature: verifyReleaseSignature,
    currentVersion: '0.0.0',
    channel: 'canary',
  });
  if (!checked.ok) {
    console.warn(`[update] тестовый манифест отвергнут: ${checked.reason}`);
    return;
  }
  const names = updateFeed.RELEASES.android;
  const filePath = path.join(UPDATE_DIR, names.canaryFile);
  const have = mirroredCanaryRelease();
  if (have && !updateMirror.needsFetch({ have, release: checked.release }) && fs.existsSync(filePath)) {
    return;
  }
  const fileUrl = updateMirror.usableFileUrl(checked.release.url);
  if (!fileUrl) {
    console.warn('[update] адрес тестового файла не годится: нужен https');
    return;
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 300000);
  let bytes = null;
  try {
    const response = await fetch(fileUrl, { signal: controller.signal, redirect: 'follow' });
    if (!response.ok) return;
    bytes = Buffer.from(await response.arrayBuffer());
  } catch (e) {
    console.warn('[update] тестовый файл не скачался:', (e && e.message) || e);
    return;
  } finally {
    clearTimeout(timer);
  }
  const sha256 = crypto.createHash('sha256').update(bytes).digest('hex');
  const verdict = updateMirror.fileVerdict({ size: bytes.length, sha256, release: checked.release });
  if (!verdict.ok) {
    console.warn(`[update] тестовый файл не сошёлся с подписанным манифестом: ${verdict.reason}`);
    return;
  }
  fs.mkdirSync(UPDATE_DIR, { recursive: true });
  const tmpPath = `${filePath}.part`;
  fs.writeFileSync(tmpPath, bytes);
  fs.renameSync(tmpPath, filePath);
  fs.writeFileSync(path.join(UPDATE_DIR, names.canaryManifest), body, 'utf8');
  console.warn(`[update] тестовый канал: раздаём ${checked.release.version} (${bytes.length} байт)`);
}
function mirroredTreeVersion(manifestName) {
  try {
    const parsed = JSON.parse(fs.readFileSync(path.join(UPDATE_DIR, manifestName), 'utf8'));
    return String(parsed.version || '');
  } catch (e) {
    return '';
  }
}
async function mirrorTree(platform, manifestName, targetDir, replaceDir) {
  const url = updateMirror.manifestUrl(UPDATE_SOURCE, platform);
  if (!url) return;
  const body = await fetchText(url, updateMirror.MAX_MANIFEST_BYTES);
  if (!body) return;
  const checked = updateMirror.checkedManifest({
    body,
    platform,
    publicKey: RELEASE_PUBLIC_KEY,
    verifySignature: verifyReleaseSignature,
    currentVersion: '0.0.0',
  });
  if (!checked.ok) {
    console.warn(`[update] манифест ${platform} отвергнут: ${checked.reason}`);
    return;
  }
  const have = mirroredTreeVersion(manifestName);
  if (
    have &&
    !updateMirror.needsFetch({
      have: { version: have, sha256: '' },
      release: { version: checked.release.version, sha256: '' },
    })
  ) {
    return;
  }
  let list = [];
  try {
    list = JSON.parse(body).files;
  } catch (e) {
    return;
  }
  const verdict = updateMirror.webFilesVerdict({ files: list, filesHash: checked.release.filesHash });
  if (!verdict.ok) {
    console.warn(`[update] список файлов ${platform} отвергнут: ${verdict.reason}`);
    return;
  }
  const stageDir = replaceDir ? `${replaceDir}.new` : path.join(targetDir, `.${platform}.new`);
  fs.rmSync(stageDir, { recursive: true, force: true });
  fs.mkdirSync(stageDir, { recursive: true });
  for (const item of list) {
    const safe = updateMirror.safeWebPath(item.path);
    const fileUrl = updateMirror.treeFileUrl(UPDATE_SOURCE, platform, safe);
    if (!safe || !fileUrl) {
      fs.rmSync(stageDir, { recursive: true, force: true });
      return;
    }
    let bytes = null;
    const itemController = new AbortController();
    const itemTimer = setTimeout(() => itemController.abort(), 300000);
    try {
      const response = await fetch(fileUrl, { redirect: 'follow', signal: itemController.signal });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      bytes = Buffer.from(await response.arrayBuffer());
    } catch (e) {
      console.warn(`[update] файл ${platform} ${safe} не скачался:`, (e && e.message) || e);
      fs.rmSync(stageDir, { recursive: true, force: true });
      return;
    } finally {
      clearTimeout(itemTimer);
    }
    const digest = crypto.createHash('sha256').update(bytes).digest('hex');
    if (bytes.length !== Number(item.size) || digest !== String(item.sha256).toLowerCase()) {
      console.warn(`[update] файл ${platform} ${safe} не сошёлся с подписанным списком`);
      fs.rmSync(stageDir, { recursive: true, force: true });
      return;
    }
    const target = path.join(stageDir, safe);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, bytes);
  }
  if (replaceDir) {
    const oldDir = `${replaceDir}.old`;
    fs.rmSync(oldDir, { recursive: true, force: true });
    if (fs.existsSync(replaceDir)) fs.renameSync(replaceDir, oldDir);
    fs.renameSync(stageDir, replaceDir);
    fs.rmSync(oldDir, { recursive: true, force: true });
  } else {
    for (const item of list) {
      const safe = updateMirror.safeWebPath(item.path);
      const from = path.join(stageDir, safe);
      const to = path.join(targetDir, safe);
      fs.mkdirSync(path.dirname(to), { recursive: true });
      fs.renameSync(from, to);
    }
    fs.rmSync(stageDir, { recursive: true, force: true });
  }
  const mainName = (updateFeed.RELEASES[platform] || {}).file || '';
  const inList = list.some((item) => updateMirror.safeWebPath(item.path) === mainName);
  if (mainName && !inList) {
    const fileUrl = updateMirror.usableFileUrl(checked.release.url);
    if (!fileUrl) {
      console.warn(`[update] адрес файла ${platform} не годится: нужен https`);
      return;
    }
    let bytes = null;
    const mainController = new AbortController();
    const mainTimer = setTimeout(() => mainController.abort(), 300000);
    try {
      const response = await fetch(fileUrl, { redirect: 'follow', signal: mainController.signal });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      bytes = Buffer.from(await response.arrayBuffer());
    } catch (e) {
      console.warn(`[update] файл ${platform} не скачался:`, (e && e.message) || e);
      return;
    } finally {
      clearTimeout(mainTimer);
    }
    const digest = crypto.createHash('sha256').update(bytes).digest('hex');
    const fileOk = updateMirror.fileVerdict({ size: bytes.length, sha256: digest, release: checked.release });
    if (!fileOk.ok) {
      console.warn(`[update] файл ${platform} не сошёлся с подписанным манифестом: ${fileOk.reason}`);
      return;
    }
    const target = path.join(targetDir, mainName);
    const tmp = `${target}.part`;
    fs.writeFileSync(tmp, bytes);
    fs.renameSync(tmp, target);
  }
  fs.writeFileSync(path.join(UPDATE_DIR, manifestName), body, 'utf8');
  console.warn(`[update] ${platform}: раздаём ${checked.release.version} (${list.length} файлов)`);
}
async function maintainUpdateMirror() {
  if (UPDATE_MIRROR_OFF || mirrorRunning) return;
  mirrorRunning = true;
  try {
    for (const [platform, names] of Object.entries(updateFeed.RELEASES)) {
      if (names.kind !== 'licno') continue;
      await mirrorPlatform(platform);
    }
    await mirrorCanary();
    await mirrorTree('web', 'web-version.json', WEB_DIR, WEB_DIR);
  } catch (e) {
    console.warn('[update] обход зеркала не выполнен:', (e && e.message) || e);
  } finally {
    mirrorRunning = false;
  }
}
if (!UPDATE_MIRROR_OFF) {
  setTimeout(() => {
    maintainUpdateMirror();
  }, 60000).unref();
  setInterval(maintainUpdateMirror, UPDATE_MIRROR_MS).unref();
}
const SHUTDOWN_FLUSH_MS = 9000;
function performShutdown({
  queueStore = store,
  exit = (code) => process.exit(code),
  timeoutMs = SHUTDOWN_FLUSH_MS,
  setTimer = setTimeout,
  clearTimer = clearTimeout,
} = {}) {
  let finished = false;
  const finish = () => {
    if (finished) return;
    finished = true;
    try {
      queueStore.close();
    } catch (e) {
    }
    exit(0);
  };
  const flush = typeof queueStore.flushPendingBlobs === 'function' ? queueStore.flushPendingBlobs() : null;
  if (!flush) {
    finish();
    return Promise.resolve();
  }
  let resolveDone;
  const done = new Promise((resolve) => { resolveDone = resolve; });
  const settle = () => {
    clearTimer(timer);
    finish();
    resolveDone();
  };
  const timer = setTimer(() => {
    console.warn(`[shutdown] флаш не завершился за ${timeoutMs} мс — доводим остановку принудительно`);
    finish();
    resolveDone();
  }, timeoutMs);
  if (typeof timer.unref === 'function') timer.unref();
  Promise.resolve(flush).then(settle, settle);
  return done;
}
function stopEmbeddedChildren() {
  stopEmbeddedCoturn();
  stopEmbeddedNtfy();
}
function createShutdownHandler({ stop = stopEmbeddedChildren, perform = performShutdown } = {}) {
  let shuttingDown = false;
  return function shutdown() {
    if (shuttingDown) return;
    shuttingDown = true;
    stop();
    return perform();
  };
}
const shutdown = createShutdownHandler();
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
function isFatalDbError(err) {
  const code = (err && err.code && String(err.code)) || '';
  const msg = (err && err.message && String(err.message)) || '';
  return (
    /^SQLITE_(CORRUPT|NOTADB|CANTOPEN|IOERR|FULL|READONLY)/.test(code) ||
    /malformed|not a database|disk image is malformed|disk I\/O error/i.test(msg)
  );
}
function handleTopLevelError(tag, err, {
  queueStore = store,
  exit = (code) => process.exit(code),
} = {}) {
  console.error(`[${tag}]`, err && err.stack ? err.stack : err);
  if (isFatalDbError(err)) {
    console.error('[fatal] сбой/повреждение БД — управляемый выход для рестарта под systemd');
    try {
      queueStore.close();
    } catch (e) {
    }
    exit(1);
  }
}
process.on('uncaughtException', (err) => handleTopLevelError('uncaughtException', err));
process.on('unhandledRejection', (err) => handleTopLevelError('unhandledRejection', err));
function handleServerError(err, {
  queueStore = store,
  exit = (code) => process.exit(code),
} = {}) {
  console.error('[server] listen/HTTP error:', err && err.stack ? err.stack : err);
  if (err && (err.code === 'EADDRINUSE' || err.code === 'EACCES')) {
    try {
      queueStore.close();
    } catch (e) {
    }
    exit(1);
  }
}
server.on('error', handleServerError);
wss.on('error', (err) => {
  console.error('[wss] error:', err && err.message ? err.message : err);
});
function logMetricsAccess(metricsToken = METRICS_TOKEN, logger = console) {
  if (metricsToken) return false;
  logger.log('[metrics] /metrics доступен только из приватной сети/localhost (задайте RELAY_METRICS_TOKEN для внешнего доступа)');
  return true;
}
server.listen(PORT, () => {
  console.log(`Лично relay listening on :${PORT} (health: /health, directory: /relays)`);
  console.log(`[dir] ${relayDir.length} relay(s) known${SELF_URL ? `, self=${SELF_URL}` : ' (set RELAY_SELF_URL to advertise self)'}`);
  console.log(`[relay-key] RELAY_SIGN_PUBLIC=${RELAY_KEYS.pub}${SELF_URL ? `  (для ${SELF_URL})` : ''}`);
  console.log(
    '[sign]',
    ed25519.nativeAvailable()
      ? 'подпись через OpenSSL (×13 к JavaScript)'
      : `подпись через JavaScript — OpenSSL не включён: ${nativeEd25519.reason}`
  );
  console.log(
    '[dh]',
    x25519.nativeAvailable()
      ? 'общий секрет через OpenSSL (×18 к JavaScript)'
      : `общий секрет через JavaScript — OpenSSL не включён: ${nativeX25519.reason}`
  );
  console.log(
    '[push]',
    vapidPublicKey()
      ? 'UnifiedPush web-push (VAPID) enabled'
      : 'UnifiedPush web-push (VAPID) NOT configured'
  );
  logMetricsAccess();
});
module.exports.runtime = {
  server,
  wss,
  store,
  online,
  accountOnline,
  counters,
  eventLoopLag,
  sampleEventLoopLag,
  sweepPushGates,
  sweepOtpDrain,
  heartbeatConnections,
  expireQueuedEnvelopes,
  turnIceServers,
  learnRelays,
  eventLoopLagP99,
  relayOverloaded,
  renderMetrics,
  safeEqual,
  metricsAuthorized,
  readJsonRequest,
  vapidRequestRateAllowed,
  rememberVapidRequest,
  handleVapidFleetHttpWith,
  handleVapidFleetHttp,
  unindexAccountSocket,
  indexAccountSocket,
  broadcastAccount,
  clientIp,
  nextId,
  verifySignature,
  hmacSha512,
  concatU8,
  verifyBoxProof,
  loadOrCreateRelaySignKeys,
  signRelayAuth,
  activateVapid,
  resolveVapidKeysWith,
  resolveVapidKeys,
  resolveTurnSecret,
  startEmbeddedCoturn,
  stopEmbeddedCoturn,
  stopEmbeddedNtfy,
  stopEmbeddedChildren,
  startEmbeddedNtfy,
  ntfyStatus,
  proxyToNtfy,
  proxyNtfyUpgrade,
  writeNtfyConfig,
  verifySpkSignature,
  flushFrameBatch,
  sendImmediate,
  frameBatchBytes,
  send,
  sendBinary,
  queuedMessageFrame,
  queuedBinaryHeader,
  senderMetadata,
  flushQueue,
  flushBinaryQueue,
  deliver,
  deliverBinary,
  ackReceived,
  ackBinaryReceived,
  rateLimited,
  costlyLimited,
  sweepCostlyBudgets,
  sweepGatewayPullRate,
  sweepRateBudgets,
  gatewayPullAllowed,
  byteLimited,
  closeRevokedDevice,
  acceptSignedRoster,
  bindSocketToCertifiedDevice,
  enforceAuthTimeout,
  handleSocketMessage,
  handleBinaryFrameSafely,
  sendPushTestResult,
  handleFrameSafely,
  relayHttpBase,
  hostOf,
  safePeerAddrs,
  pinnedLookup,
  httpJson,
  fetchPeerRelays,
  pushSelfTo, mirroredRelease, verifyReleaseSignature, fetchText, mirrorPlatform, mirrorCanary, mirroredCanaryRelease, mirroredTreeVersion, mirrorTree, maintainUpdateMirror,
  vapidSyncWith,
  vapidSyncOnce,
  gossipOnce,
  scheduleFederation,
  performShutdown,
  createShutdownHandler,
  shutdown,
  isFatalDbError,
  handleTopLevelError,
  handleServerError,
  logMetricsAccess,
};