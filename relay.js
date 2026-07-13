/**
 * relay.js — store-and-forward ретранслятор для мессенджера «Лично».
 *
 * Задача: доставлять зашифрованные конверты между телефонами. Сервер НЕ знает
 * секретных ключей и НЕ может прочитать сообщения — он видит только шифртекст и
 * адрес получателя (его публичный ключ).
 *
 * Протокол (JSON, по одному сообщению на кадр):
 *   client -> server  {"type":"hello","pubkey":"<b64>","signPublicKey":"<b64>"}
 *       сервер отвечает challenge с одноразовым nonce
 *   server -> client  {"type":"challenge","nonce":"<b64>"}
 *   client -> server  {"type":"auth","signature":"<b64>"}
 *       подпись nonce ключом Ed25519 — доказательство владения pubkey
 *   server -> client  {"type":"ready","queued":N}       — после успешной auth
 *   client -> server  {"type":"prekeys-put","bundle":{spk:{id,pub,sig},opks:[{id,pub}]}}
 *       выгрузка СВОИХ публичных X3DH-prekey (sig сверяется с TOFU-ключом)
 *   server -> client  {"type":"prekeys-ok","otps":N}
 *   client -> server  {"type":"prekeys-get","pubkey":"<b64>"}
 *   server -> client  {"type":"prekeys","pubkey":"...","bundle":{spk,opk}|null}
 *       одноразовый prekey выдаётся ровно один раз и вычёркивается
 *   client -> server  {"type":"send","to":"<b64>","envelope":{...},"ref":"..."}
 *   server -> client  {"type":"ack","ref":"...","id":"...","queued":bool}
 *   server -> client  {"type":"message","id":"...","envelope":{...}}
 *   client -> server  {"type":"received","id":"..."}    — квитанция о приёме
 *       ТОЛЬКО после неё сервер удаляет конверт из очереди (надёжная доставка)
 *   server -> client  {"type":"delivered","id":"..."}   — отправителю, когда
 *       получатель подтвердил приём
 *   ping/pong          — проверка живости соединения
 *
 * НАДЁЖНОСТЬ: конверт лежит в очереди, пока получатель не пришлёт `received`.
 * Онлайн-доставка тоже держит копию в очереди до квитанции, поэтому обрыв связи
 * в момент доставки не теряет сообщение — при переподключении оно шлётся снова.
 * Клиент дедуплицирует по `id`.
 *
 * АУТЕНТИФИКАЦИЯ (TOFU): при первом hello связка pubkey→signPublicKey
 * запоминается; далее подключиться под этим pubkey можно, только подписав nonce
 * тем же ключом. Это закрывает захват чужого адреса после первой регистрации.
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const dns = require('dns').promises;
const nacl = require('tweetnacl');
const naclUtil = require('tweetnacl-util');
const { WebSocketServer } = require('ws');
const { sendPush, sendCallPush, pushReady } = require('./push');
const { mergeRelays, isValidRelayUrl, normalizeRelayUrl, isPrivateHost, coturnConfigText, rateGate } = require('./relays');
const { createStore } = require('./store');

const TURN_HOST = process.env.TURN_HOST;
// H-2: секрет TURN больше НЕ передаётся открытым аргументом coturn или отдельной
// переменной окружения на каждый сервер (виден в ps/`docker inspect`/world-
// readable файлах). Источник разрешается при старте (resolveTurnSecret ниже,
// после определения DB_FILE) в turnSecret; сам релей владеет секретом и пишет
// конфиг coturn в data-том. Всё это едет в образе через watchtower, поэтому фикс
// автономен: серверы подхватывают его сами.
let turnSecret = null;

// Ephemeral coturn REST credentials (valid ~1h), so no long-lived TURN
// password ships in the app.
function turnIceServers() {
  const base = [{ urls: 'stun:stun.l.google.com:19302' }];
  if (!turnSecret || !TURN_HOST) return base;
  const username = `${Math.floor(Date.now() / 1000) + 3600}:licno`;
  const credential = crypto.createHmac('sha1', turnSecret).update(username).digest('base64');
  return [
    { urls: `stun:${TURN_HOST}:3478` },
    {
      urls: [`turn:${TURN_HOST}:3478?transport=udp`, `turn:${TURN_HOST}:3478?transport=tcp`],
      username,
      credential,
    },
  ];
}

const PORT = process.env.PORT || 8787;
// Встроенное хранилище на SQLite (queue/identities/tokens/directory) — вместо
// in-memory Map + перезаписи JSON. Файл лежит в volume контейнера.
const DB_FILE = process.env.RELAY_DB || path.join(__dirname, 'relay.db');
const MAX_QUEUE_PER_USER = 500;
// H-3: глобальный потолок числа недоставленных конвертов во ВСЕЙ очереди (по всем
// получателям). Защита диска от абуза «рассылка на миллионы адресов». При
// превышении вытесняется самый старый конверт целиком. Оператор меняет через env.
const MAX_TOTAL_MESSAGES = Number(process.env.RELAY_MAX_TOTAL_MESSAGES) || 200000;
// S4: глобальный потолок ОЧЕРЕДИ В БАЙТАХ (тела в БД + файлы-blob). Конверт
// разрешён до 32 МБ, поэтому count-лимита мало: 200000×32 МБ ≈ 6.4 ТБ. Байтовый
// лимит защищает диск volume от переполнения одним клиентом. Дефолт 8 ГБ —
// оператор поднимает под свой диск через RELAY_MAX_QUEUE_BYTES.
const MAX_QUEUE_BYTES = Number(process.env.RELAY_MAX_QUEUE_BYTES) || 8 * 1024 * 1024 * 1024;
// S5: сколько конвертов ОДИН отправитель может держать в очереди ОДНОГО
// получателя. При превышении вытесняется его же старейший (self-eviction) —
// флудер не выдавливает чужие (реальные) сообщения жертвы. < MAX_QUEUE_PER_USER.
const MAX_QUEUE_PER_SENDER = Number(process.env.RELAY_MAX_QUEUE_PER_SENDER) || 100;
const QUEUE_TTL_MS = Number(process.env.RELAY_TTL_MS) || 14 * 24 * 3600 * 1000; // 14 дней
// Тела конвертов крупнее порога (вложения) лежат файлами рядом с БД (тот же
// volume), в очереди — только ссылка: БД остаётся маленькой и быстрой при
// потоке фото/видео офлайн-получателям.
const BLOB_DIR = process.env.RELAY_BLOB_DIR || path.join(path.dirname(DB_FILE), 'blobs');
const BLOB_THRESHOLD = Number(process.env.RELAY_BLOB_THRESHOLD) || 64 * 1024;

const store = createStore(DB_FILE, { blobDir: BLOB_DIR, blobThreshold: BLOB_THRESHOLD });
{
  const orphans = store.cleanupOrphanBlobs();
  if (orphans) console.log(`[blobs] removed ${orphans} orphan attachment file(s)`);
}

// --- Реплицированный каталог релеев (gossip) ------------------------------
// SELF_URL — публичный wss-адрес ЭТОГО релея; RELAY_PEERS — стартовые соседи
// (через запятую). Каталог = self ∪ peers ∪ выученные, хранится в БД и
// периодически синхронизируется с пирами. Клиент может забрать его у любого
// релея (GET /relays или WS {type:'relays'}), поэтому падение одного не критично.
const SELF_URL = normalizeRelayUrl(process.env.RELAY_SELF_URL || '') || null;
const PEER_SEED = (process.env.RELAY_PEERS || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);
const GOSSIP_INTERVAL_MS = Number(process.env.RELAY_GOSSIP_MS) || 60000;
// M1: анонимный POST /relays раньше позволял кому угодно из интернета залить
// записи в каталог (обход намеренно закрытого WS relay-advertise). Теперь
// пополнение каталога через HTTP требует общего токена (RELAY_GOSSIP_TOKEN),
// который операторы федерации задают на своих узлах. Без токена HTTP-push-gossip
// ВЫКЛЮЧЕН (безопасно по умолчанию): каталог по-прежнему читается через GET, а
// узлы находят друг друга pull-gossip'ом (fetchPeerRelays) и WS relay-advertise.
const GOSSIP_TOKEN = process.env.RELAY_GOSSIP_TOKEN || null;

let relayDir = mergeRelays([], [SELF_URL, ...PEER_SEED, ...store.directory()].filter(Boolean));
store.addRelays(relayDir, Date.now());
/** Добавить URL(ы) в каталог; вернуть true, если что-то реально добавилось. */
function learnRelays(urls) {
  const before = relayDir.length;
  relayDir = mergeRelays(relayDir, urls);
  if (relayDir.length !== before) {
    store.addRelays(relayDir, Date.now());
    return true;
  }
  return false;
}
const MAX_ENVELOPE_BYTES = 32 * 1024 * 1024; // 32 MB envelope (~24 MB video/file)

// Rate limiting (per connection).
const AUTH_TIMEOUT_MS = 10000; // must authenticate within this window
const RATE_WINDOW_MS = 1000;
const RATE_MAX_FRAMES = 80; // frames per RATE_WINDOW_MS before we drop the socket

// Resource limits (H4): защита узла от исчерпания ресурсов при абузе/DoS.
// ВАЖНО: мобильные операторы прячут тысячи абонентов за одним IP (CGNAT),
// поэтому per-IP лимит — грубый предохранитель от одиночного хоста, а не от
// «многих пользователей». Держим его высоким, чтобы не рубить легитимных
// пользователей за общим NAT; тонкую защиту дают auth-timeout, rate-limit на
// соединение и квота очереди на pubkey. Оператор может поднять/опустить через env.
const MAX_CONN_PER_IP = Number(process.env.RELAY_MAX_CONN_PER_IP) || 1000; // одновременных соединений с одного IP
const MAX_BUFFERED_BYTES = Number(process.env.RELAY_MAX_BUFFERED) || 64 * 1024 * 1024; // если клиент не читает и буфер сокета раздулся — рвём

// --- /metrics (п.4): счётчики с момента старта процесса ---------------------
// Формат Prometheus, чтобы оператор мог повесить Grafana/alerting без плясок.
// Если endpoint нужно закрыть от посторонних — env RELAY_METRICS_TOKEN, тогда
// требуется ?token=... или заголовок Authorization: Bearer ...
const METRICS_TOKEN = process.env.RELAY_METRICS_TOKEN || null;
const START_TS = Date.now();
const counters = {
  msgsIn: 0, // принятых 'send' от клиентов
  deliveredOnline: 0, // доставлено получателю онлайн (сокет открыт)
  queuedOffline: 0, // получатель офлайн — легло в очередь
  acked: 0, // квитанций received (сообщение реально дошло)
  pushes: 0, // отправлено wake-up пушей
  authOk: 0, // успешных аутентификаций
};

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
  metric('licno_messages_acked_total', 'counter', 'Envelopes confirmed received by recipients since start.', counters.acked);
  metric('licno_push_sent_total', 'counter', 'Wake-up pushes sent since start.', counters.pushes);
  metric('licno_auth_success_total', 'counter', 'Successful client authentications since start.', counters.authOk);
  metric('process_resident_memory_bytes', 'gauge', 'Resident set size of the relay process.', mem.rss);
  metric('nodejs_heap_used_bytes', 'gauge', 'V8 heap used by the relay process.', mem.heapUsed);
  return lines.join('\n') + '\n';
}

// M11: сравнение токена — константное по времени (timingSafeEqual), чтобы по
// времени ответа нельзя было побайтово подобрать токен.
function safeEqual(a, b) {
  const ab = Buffer.from(String(a == null ? '' : a));
  const bb = Buffer.from(String(b == null ? '' : b));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}
function metricsAuthorized(req) {
  // M-1: без заданного токена /metrics больше НЕ открыт всему интернету. Разрешаем
  // только приватный/loopback источник (внутренняя сеть/localhost/Docker) — публичный
  // скрейп через Caddy (реальный клиент виден по X-Forwarded-For) отвергается. Задан
  // токен — как раньше: пускаем по ?token=/Bearer с любого адреса.
  if (!METRICS_TOKEN) return isPrivateHost(clientIp(req));
  const url = new URL(req.url, 'http://x');
  if (safeEqual(url.searchParams.get('token'), METRICS_TOKEN)) return true;
  const auth = (req.headers && req.headers.authorization) || '';
  return safeEqual(auth, `Bearer ${METRICS_TOKEN}`);
}

// pubkey -> live WebSocket (in-memory: живые сокеты место в RAM, не в БД)
const online = new Map();
// ip -> число активных соединений (за Caddy берём X-Forwarded-For)
const ipConns = new Map();
// pubkey -> время последнего message-пуша (троттлинг уведомлений)
const PUSH_MIN_INTERVAL_MS = Number(process.env.RELAY_PUSH_INTERVAL_MS) || 20000;
const lastPushAt = new Map();
setInterval(() => {
  const cutoff = Date.now() - 10 * PUSH_MIN_INTERVAL_MS;
  for (const [pk, t] of lastPushAt) if (t < cutoff) lastPushAt.delete(pk);
}, 60000).unref();

// H4: сколько доверенных обратных прокси перед релеем. X-Forwarded-For клиент
// может подделать в НАЧАЛЕ списка; честный прокси (Caddy) ДОПИСЫВАЕТ реальный IP
// в КОНЕЦ. Поэтому доверяем XFF только за известным числом прокси и берём
// hops-й элемент С КОНЦА. По умолчанию 0 — XFF игнорируется (безопасно для
// прямого режима); за Caddy оператор ставит RELAY_TRUST_PROXY=1.
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

let seq = 0;
function nextId() {
  seq = (seq + 1) % Number.MAX_SAFE_INTEGER;
  return Date.now().toString(36) + '-' + seq.toString(36);
}

// --- ownership proof helpers ---------------------------------------------
function verifySignature(nonceB64, signatureB64, signPublicKeyB64) {
  try {
    return nacl.sign.detached.verify(
      naclUtil.decodeBase64(nonceB64),
      naclUtil.decodeBase64(signatureB64),
      naclUtil.decodeBase64(signPublicKeyB64)
    );
  } catch (e) {
    return false;
  }
}

// H5/H6: доказательство владения box-ключом адреса. Должно совпадать с клиентским
// crypto.proveBoxOwnership: HMAC-SHA512(ECDH(eph, boxPub), "licno-box-proof-v1|"||nonce).
// Держим примитивы локально, чтобы релей оставался самодостаточным (server/).
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
/** true, если boxProof доказывает владение box-секреткой адреса boxPubB64. */
function verifyBoxProof(nonceB64, proofB64, boxPubB64, ephSecB64) {
  try {
    const shared = nacl.scalarMult(naclUtil.decodeBase64(ephSecB64), naclUtil.decodeBase64(boxPubB64));
    const data = concatU8(naclUtil.decodeUTF8(BOX_PROOF_PREFIX), naclUtil.decodeBase64(nonceB64));
    const expected = hmacSha512(shared, data).slice(0, 32);
    const got = naclUtil.decodeBase64(proofB64);
    if (got.length !== expected.length) return false;
    return nacl.verify(got, expected); // constant-time
  } catch (e) {
    return false;
  }
}

// --- Подлинность релея (S6) ------------------------------------------------
// Релей подписывает клиентский cnonce своим долговременным Ed25519-ключом; его
// публичную половину клиент пинит (config.SEED_RELAY_KEYS) и отвергает релей без
// валидной подписи. Ключ берём из RELAY_SIGN_SECRET (base64) либо персистим в
// файле рядом с БД (стабильность пина между рестартами) и печатаем публичную
// половину в лог, чтобы оператор внёс её клиентам.
const RELAY_AUTH_PREFIX = 'licno-relay-auth-v1|';
const RELAY_SIGN_KEY_FILE = process.env.RELAY_SIGN_KEY_FILE || path.join(path.dirname(DB_FILE), 'relay-sign.key');
function loadOrCreateRelaySignKeys() {
  let secB64 = process.env.RELAY_SIGN_SECRET || null;
  if (!secB64) {
    try {
      secB64 = fs.readFileSync(RELAY_SIGN_KEY_FILE, 'utf8').trim();
    } catch (e) {}
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
    fs.writeFileSync(RELAY_SIGN_KEY_FILE, naclUtil.encodeBase64(kp.secretKey), { mode: 0o600 });
  } catch (e) {}
  return { pub: naclUtil.encodeBase64(kp.publicKey), sec: kp.secretKey };
}
const RELAY_KEYS = loadOrCreateRelaySignKeys();
function signRelayAuth(cnonce) {
  return naclUtil.encodeBase64(nacl.sign.detached(naclUtil.decodeUTF8(RELAY_AUTH_PREFIX + cnonce), RELAY_KEYS.sec));
}

// --- TURN: секрет и конфиг coturn во владении релея (H-2/M-4) --------------
// Автономность: релей сам владеет секретом TURN и пишет конфиг coturn в data-том
// (0600). coturn стартует с `-c <data>/turnserver.conf` и читает секрет ОТТУДА —
// секрета больше нет в аргументах процесса, env и world-readable файлах. Приоритет
// источника: TURN_SECRET (совместимость/override) -> TURN_SECRET_FILE -> само-
// генерация + персист (как relay-sign.key). Всё это едет в образе через watchtower.
const TURN_SECRET_FILE = process.env.TURN_SECRET_FILE || path.join(path.dirname(DB_FILE), 'turn-secret');
const COTURN_CONF_FILE = process.env.RELAY_COTURN_CONF || path.join(path.dirname(DB_FILE), 'turnserver.conf');
function resolveTurnSecret() {
  if (process.env.TURN_SECRET) return process.env.TURN_SECRET; // явный override оператора
  try {
    const f = fs.readFileSync(TURN_SECRET_FILE, 'utf8').trim();
    if (f) return f;
  } catch (e) {}
  const gen = crypto.randomBytes(32).toString('hex');
  try {
    fs.writeFileSync(TURN_SECRET_FILE, gen, { mode: 0o600 });
  } catch (e) {}
  return gen;
}

// Встроенный coturn (флаг RELAY_EMBED_COTURN): в Docker-образе релей сам запускает
// turnserver дочерним процессом — отдельного контейнера coturn НЕТ, весь TURN
// (секрет+конфиг+процесс) живёт в образе, который watchtower обновляет → будущие
// правки TURN автономны. Флаг ставит ТОЛЬКО compose образа; bare-metal (системный
// coturn под systemd) его не ставит, поэтому второго coturn не поднимается.
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
    } catch (e) {}
    coturnChild = null;
  }
}

if (TURN_HOST) {
  turnSecret = resolveTurnSecret();
  try {
    fs.writeFileSync(COTURN_CONF_FILE, coturnConfigText(turnSecret, { turnHost: TURN_HOST }), { mode: 0o600 });
    console.log(`[turn] coturn config -> ${COTURN_CONF_FILE} (секрет во владении релея, 0600)`);
  } catch (e) {
    console.warn('[turn] не удалось записать конфиг coturn:', e && e.message);
  }
  // Встроенный coturn стартуем только по флагу (Docker-образ) — bare-metal нет.
  if (process.env.RELAY_EMBED_COTURN) startEmbeddedCoturn();
} else {
  // Без TURN_HOST TURN не анонсируется (только STUN) — поведение как раньше.
  turnSecret = process.env.TURN_SECRET || null;
}

// --- X3DH prekeys ----------------------------------------------------------
// Формат подписи SPK должен совпадать с клиентским (src/crypto.js).
const SPK_SIG_PREFIX = 'licno-spk-v1|';
const MAX_OTPS_PER_USER = 100;
// M2: троттлинг выдачи prekey на СОЕДИНЕНИЕ. Без него авторизованный клиент за
// пару секунд (rate-limit 80 кадров/с) высасывал все OTP жертвы по её адресу,
// деградируя forward secrecy её будущих собеседников. Легитимному клиенту
// prekeys-get нужен изредка (новый контакт), поэтому 60/мин с запасом хватает;
// при превышении отвечаем bundle:null (X3DH-фолбэк), OTP при этом НЕ тратится.
const PREKEY_GET_WINDOW_MS = 60000;
const PREKEY_GET_MAX = 60;
// H-4: троттлинг ВЫДАЧИ одноразовых prekey по ЦЕЛЕВОМУ адресу — ГЛОБАЛЬНО по всем
// соединениям. M2 (выше) считал на соединение и обходился числом соединений:
// атакующий открывал много сессий и высасывал OTP жертвы, деградируя forward
// secrecy её первых сообщений. Теперь на адрес выдаётся не больше PREKEY_TARGET_MAX
// OTP за окно; сверх лимита отдаём SPK без OTP (opk:null) — X3DH всё равно работает
// (SPK forward-secret), но одноразовые ключи не расходуются. Порог щедрый:
// легитимно OTP жертвы запрашивают редко (новый контакт).
const PREKEY_TARGET_WINDOW_MS = Number(process.env.RELAY_PREKEY_TARGET_MS) || 60000;
const PREKEY_TARGET_MAX = Number(process.env.RELAY_PREKEY_TARGET_MAX) || 30;
const otpDrain = new Map(); // targetPubkey -> { start, count } (реально выданные OTP в окне)
setInterval(() => {
  const cutoff = Date.now() - PREKEY_TARGET_WINDOW_MS;
  for (const [pk, d] of otpDrain) if (d.start < cutoff) otpDrain.delete(pk);
}, PREKEY_TARGET_WINDOW_MS).unref();
const isB64Field = (s, max = 128) => typeof s === 'string' && s.length > 0 && s.length <= max;

function verifySpkSignature(spkObj, signPublicKeyB64) {
  try {
    return nacl.sign.detached.verify(
      naclUtil.decodeUTF8(SPK_SIG_PREFIX + spkObj.id + '|' + spkObj.pub),
      naclUtil.decodeBase64(spkObj.sig),
      naclUtil.decodeBase64(signPublicKeyB64)
    );
  } catch (e) {
    return false;
  }
}

const server = http.createServer((req, res) => {
  if (req.url === '/health') {
    const st = store.stats();
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(
      JSON.stringify({
        ok: true,
        online: online.size,
        queued: st.usersQueued,
        messages: st.totalQueued,
        relays: relayDir.length,
      })
    );
    return;
  }
  // Метрики для мониторинга (Prometheus text format). Закрывается токеном
  // через RELAY_METRICS_TOKEN (см. metricsAuthorized).
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
  // Публичный каталог релеев — любой (клиент или другой релей) может забрать его
  // отсюда. Это и есть точка, из которой список реплицируется по сети.
  if (req.url === '/relays') {
    // POST — другой релей сообщает о себе/своём каталоге (push-gossip): так
    // сосед, у которого мы в peers, узнаёт про нас без ручной настройки.
    if (req.method === 'POST') {
      // M1: учимся из POST только при совпадении общего токена. Аноним не может
      // отравить каталог/подсунуть вредоносные релеи; при этом GET-каталог открыт.
      const gossipOk =
        !!GOSSIP_TOKEN && safeEqual((req.headers && req.headers['x-gossip-token']) || '', GOSSIP_TOKEN);
      let body = '';
      let aborted = false;
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
        } catch (e) {}
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

const wss = new WebSocketServer({ server, maxPayload: MAX_ENVELOPE_BYTES + 1024 * 1024 });

function send(ws, obj) {
  if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(obj));
}

// Re-send everything still queued for pubkey (nothing is deleted until the
// recipient acks each id with `received`). Safe to call on every (re)connect.
function flushQueue(pubkey, ws) {
  const q = store.queueFor(pubkey);
  for (const item of q) send(ws, { type: 'message', id: item.id, envelope: item.envelope });
  return q.length;
}

function deliver(from, to, envelope, silent, callPush) {
  const id = nextId();
  // Always enqueue; the copy is removed only when the recipient acks (received).
  store.enqueue({
    id,
    to,
    from,
    envelope,
    silent,
    callPush,
    ts: Date.now(),
    maxPerUser: MAX_QUEUE_PER_USER,
    maxPerSender: MAX_QUEUE_PER_SENDER,
    maxTotal: MAX_TOTAL_MESSAGES,
    maxTotalBytes: MAX_QUEUE_BYTES,
  });

  const ws = online.get(to);
  if (ws) {
    send(ws, { type: 'message', id, envelope });
    counters.deliveredOnline += 1;
    return { queued: false, id };
  }

  // recipient offline -> maybe wake them
  counters.queuedOffline += 1;
  const token = store.getToken(to);
  const onInvalid = (r) => {
    if (r === 'invalid') store.delToken(to);
  };

  if (callPush) {
    if (token) {
      counters.pushes += 1;
      sendCallPush(token).then(onInvalid);
    }
    return { queued: true, id };
  }
  if (silent) return { queued: true, id }; // control message: deliver, no push
  // Троттлинг: не чаще одного message-пуша получателю за PUSH_MIN_INTERVAL_MS.
  // Дубли одного сообщения (веер по релеям от старых клиентов) и бурсты
  // сообщений не превращаются в очередь уведомлений; на устройстве они и так
  // схлопываются по tag (см. push.js), это экономит и запросы к FCM.
  if (token && Date.now() - (lastPushAt.get(to) || 0) >= PUSH_MIN_INTERVAL_MS) {
    lastPushAt.set(to, Date.now());
    counters.pushes += 1;
    sendPush(token).then(onInvalid);
  }
  return { queued: true, id };
}

// Recipient confirmed receipt of `id`: drop it from their queue and tell the
// original sender (if online) that it was delivered.
function ackReceived(recipientPubkey, id) {
  const from = store.ack(recipientPubkey, id); // from_pk, либо null если нет/не его
  if (from) {
    counters.acked += 1;
    const senderWs = online.get(from);
    if (senderWs) send(senderWs, { type: 'delivered', id });
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

wss.on('connection', (ws, req) => {
  // H4: per-IP лимит одновременных соединений (защита от коннект-флуда).
  const ip = clientIp(req);
  const nConn = (ipConns.get(ip) || 0) + 1;
  if (nConn > MAX_CONN_PER_IP) {
    try {
      send(ws, { type: 'error', error: 'too many connections' });
    } catch (e) {}
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
  ws.rateStart = Date.now();
  ws.rateCount = 0;
  ws.on('pong', () => (ws.isAlive = true));

  // Drop connections that never authenticate.
  ws.authTimer = setTimeout(() => {
    if (!ws.authed) {
      send(ws, { type: 'error', error: 'auth timeout' });
      ws.terminate();
    }
  }, AUTH_TIMEOUT_MS);

  ws.on('message', (raw) => {
    if (rateLimited(ws)) {
      send(ws, { type: 'error', error: 'rate limit' });
      ws.terminate();
      return;
    }

    let msg;
    try {
      msg = JSON.parse(raw.toString());
    } catch (e) {
      return send(ws, { type: 'error', error: 'bad json' });
    }
    try {
      handleFrameSafely(ws, msg);
    } catch (e) {
      console.error('[frame]', e && e.stack ? e.stack : e);
      try { send(ws, { type: 'error', error: 'server error' }); } catch (e2) {}
    }
  });

  ws.on('close', () => {
    clearTimeout(ws.authTimer);
    if (ws.ip) {
      const c = (ipConns.get(ws.ip) || 1) - 1;
      if (c <= 0) ipConns.delete(ws.ip);
      else ipConns.set(ws.ip, c);
    }
    if (ws.pubkey && online.get(ws.pubkey) === ws) online.delete(ws.pubkey);
  });
});

// Обработка одного разобранного кадра. Вынесено в отдельную функцию, чтобы
// вызывающий мог обернуть её в try/catch (C-1: одна ошибка не роняет процесс).
function handleFrameSafely(ws, msg) {
    // C-1: JSON.parse принимает не только объекты — "null", "true", "1", "[...]"
    // это валидный JSON. Обращение msg.type к такому значению роняло обработчик
    // (напр. null.type -> TypeError), а глобального перехватчика нет — падал ВЕСЬ
    // процесс от одного кадра неаутентифицированного клиента. Требуем объект.
    if (!msg || typeof msg !== 'object' || Array.isArray(msg)) {
      return send(ws, { type: 'error', error: 'bad frame' });
    }

    // --- handshake: hello -> challenge -> auth ---
    if (msg.type === 'hello') {
      if (typeof msg.pubkey !== 'string' || !msg.pubkey) {
        return send(ws, { type: 'error', error: 'hello requires pubkey' });
      }
      if (typeof msg.signPublicKey !== 'string' || !msg.signPublicKey) {
        return send(ws, { type: 'error', error: 'hello requires signPublicKey' });
      }
      ws.pendingPubkey = msg.pubkey;
      ws.pendingSpk = msg.signPublicKey;
      ws.nonce = naclUtil.encodeBase64(crypto.randomBytes(32));
      // H5/H6: эфемерная X25519-пара для доказательства владения box-ключом.
      // Публичную половинку кладём в challenge; секретку держим до auth.
      const eph = nacl.box.keyPair();
      ws.ephSec = naclUtil.encodeBase64(eph.secretKey);
      const reply = { type: 'challenge', nonce: ws.nonce, eph: naclUtil.encodeBase64(eph.publicKey) };
      // S6: если клиент прислал cnonce — подписываем его ключом релея (клиент
      // сверит с закреплённым ключом). Старый клиент без cnonce — просто без подписи.
      if (typeof msg.cnonce === 'string' && msg.cnonce) {
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
      // Шаг 1 (всегда, первым): подпись challenge доказывает владение ЗАЯВЛЕННЫМ
      // Ed25519-ключом. Проверяем против предъявленного spk — если не сходится,
      // это 'bad signature' независимо от состояния привязки.
      if (!verifySignature(ws.nonce, msg.signature, ws.pendingSpk)) {
        return send(ws, { type: 'error', error: 'bad signature' });
      }
      // Шаг 2 (H5/H6): доказательство владения BOX-ключом адреса. Новые клиенты
      // всегда присылают boxProof; старые — нет (легаси-путь, ниже).
      const boxProven =
        typeof msg.boxProof === 'string' &&
        ws.ephSec &&
        verifyBoxProof(ws.nonce, msg.boxProof, ws.pendingPubkey, ws.ephSec);

      const bound = store.getIdentity(ws.pendingPubkey); // { signPk, proven } | null
      if (bound && bound.proven) {
        // Адрес доказанно принадлежит владельцу box-ключа: подтвердить/сменить
        // связку можно ТОЛЬКО снова доказав владение box-ключом. Это закрывает
        // и oracle подписи (H5: перехваченной подписи мало), и захват (H6).
        if (!boxProven) {
          return send(ws, { type: 'error', error: 'box ownership proof required' });
        }
        if (bound.signPk !== ws.pendingSpk) store.rebindSignKey(ws.pendingPubkey, ws.pendingSpk);
      } else if (bound && !bound.proven) {
        if (boxProven) {
          // Владелец box-ключа перебивает прежнюю (возможно сквоттерскую) связку
          // и закрепляет её как доказанную — сквоттер потом уже не отберёт.
          store.rebindSignKey(ws.pendingPubkey, ws.pendingSpk);
        } else if (bound.signPk !== ws.pendingSpk) {
          // Легаси-путь (TOFU): сменить незакреплённый sign-ключ нельзя.
          return send(ws, { type: 'error', error: 'pubkey bound to a different key' });
        }
      } else {
        // Первая регистрация: закрепляем; proven только при доказанном владении.
        store.bindSignKey(ws.pendingPubkey, ws.pendingSpk, boxProven);
      }
      // authenticated: take ownership of this pubkey
      counters.authOk += 1;
      ws.authed = true;
      ws.pubkey = ws.pendingPubkey;
      ws.nonce = null;
      ws.ephSec = null;
      clearTimeout(ws.authTimer);
      // If a stale socket still claims this pubkey, replace it.
      const prev = online.get(ws.pubkey);
      if (prev && prev !== ws) try { prev.terminate(); } catch (e) {}
      online.set(ws.pubkey, ws);
      const flushed = flushQueue(ws.pubkey, ws);
      // prekeys: сколько одноразовых prekey клиента осталось у этого релея —
      // клиент по этому числу решает, пора ли выгрузить свежую пачку.
      return send(ws, { type: 'ready', queued: flushed, prekeys: store.countOtps(ws.pubkey) });
    }

    // --- relay directory (public READ allowed before auth for bootstrap) ---
    if (msg.type === 'relays') {
      return send(ws, { type: 'relays', relays: relayDir });
    }

    // App-level liveness: клиент шлёт ping, чтобы отличить живое соединение от
    // «тихо зависшего» при смене сети (WS-фреймы ping ему не видны из JS).
    if (msg.type === 'ping') {
      return send(ws, { type: 'pong' });
    }

    // --- everything past here requires authentication ---
    if (!ws.authed) return send(ws, { type: 'error', error: 'not authenticated' });

    if (msg.type === 'relay-advertise') {
      // M-1: учить каталог может ТОЛЬКО аутентифицированный клиент/релей — иначе
      // аноним отравлял бы список мусором и подсовывал вредоносные релеи (в т.ч.
      // как вектор SSRF через gossip). Плюс валидация URL (без приватных адресов).
      const urls = Array.isArray(msg.relays) ? msg.relays : [msg.url];
      const clean = urls.filter((u) => isValidRelayUrl(u));
      if (clean.length) learnRelays(clean);
      return send(ws, { type: 'relays', relays: relayDir });
    }

    if (msg.type === 'turn') {
      return send(ws, { type: 'turn', iceServers: turnIceServers() });
    }

    if (msg.type === 'prekeys-put') {
      // Выгрузка СВОИХ публичных X3DH-prekey. Подпись SPK сверяется с TOFU-ключом
      // этого соединения — чужие/битые бандлы не сохраняются.
      const b = msg.bundle || {};
      const spkObj = b.spk;
      if (!spkObj || !isB64Field(spkObj.id, 32) || !isB64Field(spkObj.pub) || !isB64Field(spkObj.sig)) {
        return send(ws, { type: 'error', error: 'prekeys-put requires bundle.spk {id,pub,sig}' });
      }
      const boundSpkKey = store.getSignKey(ws.pubkey);
      if (!boundSpkKey || !verifySpkSignature(spkObj, boundSpkKey)) {
        return send(ws, { type: 'error', error: 'bad prekey signature' });
      }
      const opks = (Array.isArray(b.opks) ? b.opks : [])
        .filter((k) => k && isB64Field(k.id, 32) && isB64Field(k.pub))
        .slice(0, MAX_OTPS_PER_USER)
        .map((k) => ({ id: k.id, pub: k.pub }));
      store.setSpk(ws.pubkey, { id: spkObj.id, pub: spkObj.pub, sig: spkObj.sig });
      store.replaceOtps(ws.pubkey, opks);
      return send(ws, { type: 'prekeys-ok', otps: store.countOtps(ws.pubkey) });
    }

    if (msg.type === 'prekeys-get') {
      // Бандл prekey получателя для X3DH: SPK + один одноразовый (выдаётся
      // РОВНО один раз). Публичные данные; подпись клиент сверяет сам с ключом,
      // закреплённым при QR-знакомстве, — релею верить не обязан.
      if (typeof msg.pubkey !== 'string' || !msg.pubkey) {
        return send(ws, { type: 'error', error: 'prekeys-get requires pubkey' });
      }
      // M2: троттлинг на соединение — при превышении отвечаем как «prekey нет»
      // (bundle:null), OTP не расходуется (клиент откатится на static/SPK-only).
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
      // H-4: глобальный лимит выдачи OTP на целевой адрес. Сверх лимита — SPK без OTP
      // (opk:null): X3DH работает через SPK, одноразовые ключи жертвы не сливаются.
      const nowT = Date.now();
      const gate = rateGate(otpDrain.get(msg.pubkey), nowT, PREKEY_TARGET_WINDOW_MS, PREKEY_TARGET_MAX);
      otpDrain.set(msg.pubkey, gate.state);
      let opk = null;
      if (gate.allow) {
        opk = store.takeOtp(msg.pubkey);
        if (opk) gate.state.count += 1; // считаем только реально выданные
      }
      return send(ws, { type: 'prekeys', pubkey: msg.pubkey, bundle: { spk: spkRec, opk } });
    }

    if (msg.type === 'register') {
      if (typeof msg.pushToken === 'string' && msg.pushToken) {
        store.setToken(ws.pubkey, msg.pushToken);
      }
      return send(ws, { type: 'registered' });
    }

    if (msg.type === 'received') {
      if (typeof msg.id === 'string') ackReceived(ws.pubkey, msg.id);
      return;
    }

    if (msg.type === 'send') {
      if (typeof msg.to !== 'string' || !msg.envelope) {
        return send(ws, { type: 'error', error: 'send requires to + envelope' });
      }
      const size = Buffer.byteLength(JSON.stringify(msg.envelope));
      if (size > MAX_ENVELOPE_BYTES) {
        return send(ws, { type: 'error', error: 'envelope too large' });
      }
      counters.msgsIn += 1;
      const r = deliver(ws.pubkey, msg.to, msg.envelope, !!msg.silent, !!msg.callPush);
      return send(ws, { type: 'ack', ref: msg.ref, id: r.id, queued: r.queued });
    }

    send(ws, { type: 'error', error: 'unknown type' });
}

// --- gossip: периодически синхронизируем каталог с известными релеями --------
// Каждый релей тянет /relays у пиров и сливает списки — так новый узел за
// несколько раундов становится известен почти всем, без центрального реестра.
function relayHttpBase(wsUrl) {
  return wsUrl.replace(/^ws:\/\//i, 'http://').replace(/^wss:\/\//i, 'https://');
}
// M-1 (SSRF): перед исходящим запросом к пиру резолвим его хост и отказываемся,
// если он указывает на приватный/loopback/link-local адрес. isValidRelayUrl уже
// блокирует ЛИТЕРАЛЬНЫЕ приватные IP; здесь ловим ХОСТНЕЙМЫ, которые резолвятся
// внутрь сети (DNS-rebinding-подобный вектор через отравленный каталог).
function hostOf(wsUrl) {
  return String(wsUrl)
    .replace(/^wss?:\/\//i, '')
    .replace(/[/?#].*$/, '')
    .replace(/:\d+$/, '')
    .replace(/^\[|\]$/g, '');
}
// L7 (TOCTOU/DNS-rebinding): резолвим хост ОДИН раз, проверяем ВСЕ адреса и
// возвращаем их для ПИННИНГА соединения. Раньше проверка (dns.lookup) и запрос
// (fetch со своим резолвингом) были разными разрешениями имени — вредоносный DNS
// мог отдать публичный IP на проверке и приватный на самом запросе. Теперь
// соединение идёт ровно на проверенные IP (кастомный lookup), а имя хоста
// сохраняется для SNI/валидации TLS-сертификата — сертификат по-прежнему сверяется.
async function safePeerAddrs(wsUrl) {
  const host = hostOf(wsUrl);
  if (!host || isPrivateHost(host)) return null;
  try {
    const addrs = await dns.lookup(host, { all: true });
    if (!addrs.length) return null;
    for (const a of addrs) if (isPrivateHost(a.address)) return null;
    return addrs.map((a) => ({ address: a.address, family: a.family }));
  } catch (e) {
    return null; // не резолвится — не ходим
  }
}
// Кастомный lookup для http/https: игнорирует реальный DNS и отдаёт ТОЛЬКО
// заранее проверенные адреса (пиннинг) — между проверкой и коннектом имя уже не
// переразрешается, окно DNS-rebinding закрыто.
function pinnedLookup(pinned) {
  return (hostname, options, cb) => {
    if (options && options.all) return cb(null, pinned);
    cb(null, pinned[0].address, pinned[0].family);
  };
}
/** GET/POST JSON к пиру по проверенным IP. Возвращает распарсенный ответ или null. */
function httpJson(urlStr, { method = 'GET', headers = {}, body = null, pinned, timeoutMs = 5000 }) {
  return new Promise((resolve) => {
    let mod;
    try {
      mod = new URL(urlStr).protocol === 'https:' ? https : http;
    } catch (e) {
      return resolve(null);
    }
    const req = mod.request(urlStr, { method, headers, lookup: pinnedLookup(pinned) }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        return resolve(null);
      }
      let buf = '';
      res.on('data', (c) => {
        buf += c;
        if (buf.length > 1000000) req.destroy(); // защита от гигантского ответа
      });
      res.on('end', () => {
        try {
          resolve(JSON.parse(buf));
        } catch (e) {
          resolve(null);
        }
      });
    });
    req.on('error', () => resolve(null));
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
// Push-gossip: сообщить peer'у наш каталог (включая себя). Благодаря этому
// сосед, который сам нас в peers не прописывал (напр. самый первый релей),
// узнаёт про нас — распространение становится двунаправленным.
async function pushSelfTo(wsUrl) {
  const pinned = await safePeerAddrs(wsUrl);
  if (!pinned) return;
  await httpJson(relayHttpBase(wsUrl) + '/relays', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      // M1: свой токен федерации — чтобы пир с тем же токеном принял наш каталог.
      ...(GOSSIP_TOKEN ? { 'x-gossip-token': GOSSIP_TOKEN } : {}),
    },
    body: JSON.stringify({ relays: relayDir }),
    pinned,
  });
}
async function gossipOnce() {
  const peers = relayDir.filter((u) => !SELF_URL || u.toLowerCase() !== SELF_URL.toLowerCase());
  let learned = false;
  for (const peer of peers) {
    const list = await fetchPeerRelays(peer);
    if (list && learnRelays(list)) learned = true;
    await pushSelfTo(peer); // рассказываем peer'у про себя (двунаправленно)
  }
  if (learned) console.log(`[gossip] directory now ${relayDir.length} relays`);
}
if (SELF_URL || PEER_SEED.length) {
  setInterval(() => {
    gossipOnce().catch(() => {});
  }, GOSSIP_INTERVAL_MS).unref();
}

// drop dead connections + backpressure (H4): рвём сокеты, чей буфер отправки
// раздулся (клиент не вычитывает) — иначе они держат память узла.
setInterval(() => {
  for (const ws of wss.clients) {
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
}, 30000).unref();

// TTL: периодически чистим протухшие конверты (не забрали за QUEUE_TTL_MS).
setInterval(() => {
  try {
    const removed = store.expireOlderThan(Date.now() - QUEUE_TTL_MS);
    if (removed) console.log(`[ttl] expired ${removed} stale envelope(s)`);
  } catch (e) {}
}, 3600 * 1000).unref();

function shutdown() {
  stopEmbeddedCoturn();
  try {
    store.close();
  } catch (e) {}
  process.exit(0);
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

// C-1 (backstop): узел store-and-forward не должен умирать от одного битого
// кадра/промиса. Обычную необработанную ошибку логируем и продолжаем работу — это
// многократно безопаснее падения всего процесса (перманентный DoS всей ноды).
//
// L4: ИСКЛЮЧЕНИЕ — повреждение/сбой БД. Продолжать работу с битой SQLite опасно:
// узел будет тихо деградировать (терять/недоставлять конверты) вместо честного
// рестарта. Такие ошибки → управляемый выход, systemd (Restart=always) поднимет
// процесс заново, при старте WAL восстановится/подчистится.
function isFatalDbError(err) {
  const code = (err && err.code && String(err.code)) || '';
  const msg = (err && err.message && String(err.message)) || '';
  return (
    /^SQLITE_(CORRUPT|NOTADB|CANTOPEN|IOERR|FULL|READONLY)/.test(code) ||
    /malformed|not a database|disk image is malformed|disk I\/O error/i.test(msg)
  );
}
function handleTopLevelError(tag, err) {
  console.error(`[${tag}]`, err && err.stack ? err.stack : err);
  if (isFatalDbError(err)) {
    console.error('[fatal] сбой/повреждение БД — управляемый выход для рестарта под systemd');
    try {
      store.close();
    } catch (e) {}
    process.exit(1);
  }
}
process.on('uncaughtException', (err) => handleTopLevelError('uncaughtException', err));
process.on('unhandledRejection', (err) => handleTopLevelError('unhandledRejection', err));

server.listen(PORT, () => {
  console.log(`Лично relay listening on :${PORT} (health: /health, directory: /relays)`);
  console.log(`[dir] ${relayDir.length} relay(s) known${SELF_URL ? `, self=${SELF_URL}` : ' (set RELAY_SELF_URL to advertise self)'}`);
  // S6: публичный ключ подлинности этого релея — впишите его клиентам в
  // config.SEED_RELAY_KEYS для пиннинга (иначе релей не проверяется).
  console.log(`[relay-key] RELAY_SIGN_PUBLIC=${RELAY_KEYS.pub}${SELF_URL ? `  (для ${SELF_URL})` : ''}`);
  console.log(
    '[push]',
    pushReady()
      ? 'FCM configured — wake-up pushes enabled'
      : 'FCM NOT configured — closed-app notifications will NOT be sent (add service-account.json)'
  );
  // M-1: без токена /metrics доступен ТОЛЬКО из приватной сети/localhost (публичный
  // скрейп отвергается). Для внешнего мониторинга задайте RELAY_METRICS_TOKEN.
  if (!METRICS_TOKEN) {
    console.log('[metrics] /metrics доступен только из приватной сети/localhost (задайте RELAY_METRICS_TOKEN для внешнего доступа)');
  }
});
