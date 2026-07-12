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
const path = require('path');
const crypto = require('crypto');
const nacl = require('tweetnacl');
const naclUtil = require('tweetnacl-util');
const { WebSocketServer } = require('ws');
const { sendPush, sendCallPush, pushReady } = require('./push');
const { mergeRelays, isValidRelayUrl, normalizeRelayUrl } = require('./relays');
const { createStore } = require('./store');

const TURN_SECRET = process.env.TURN_SECRET;
const TURN_HOST = process.env.TURN_HOST;

// Ephemeral coturn REST credentials (valid ~1h), so no long-lived TURN
// password ships in the app.
function turnIceServers() {
  const base = [{ urls: 'stun:stun.l.google.com:19302' }];
  if (!TURN_SECRET || !TURN_HOST) return base;
  const username = `${Math.floor(Date.now() / 1000) + 3600}:licno`;
  const credential = crypto.createHmac('sha1', TURN_SECRET).update(username).digest('base64');
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

// pubkey -> live WebSocket (in-memory: живые сокеты место в RAM, не в БД)
const online = new Map();
// ip -> число активных соединений (за Caddy берём X-Forwarded-For)
const ipConns = new Map();

function clientIp(req) {
  const xff = req && req.headers && req.headers['x-forwarded-for'];
  if (xff) return String(xff).split(',')[0].trim();
  return (req && req.socket && req.socket.remoteAddress) || 'unknown';
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
  // Публичный каталог релеев — любой (клиент или другой релей) может забрать его
  // отсюда. Это и есть точка, из которой список реплицируется по сети.
  if (req.url === '/relays') {
    // POST — другой релей сообщает о себе/своём каталоге (push-gossip): так
    // сосед, у которого мы в peers, узнаёт про нас без ручной настройки.
    if (req.method === 'POST') {
      let body = '';
      req.on('data', (c) => {
        body += c;
        if (body.length > 200000) req.destroy();
      });
      req.on('end', () => {
        try {
          const j = JSON.parse(body);
          if (Array.isArray(j.relays)) learnRelays(j.relays.filter(isValidRelayUrl));
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
  store.enqueue({ id, to, from, envelope, silent, callPush, ts: Date.now(), maxPerUser: MAX_QUEUE_PER_USER });

  const ws = online.get(to);
  if (ws) {
    send(ws, { type: 'message', id, envelope });
    return { queued: false, id };
  }

  // recipient offline -> maybe wake them
  const token = store.getToken(to);
  const onInvalid = (r) => {
    if (r === 'invalid') store.delToken(to);
  };

  if (callPush) {
    if (token) sendCallPush(token).then(onInvalid);
    return { queued: true, id };
  }
  if (silent) return { queued: true, id }; // control message: deliver, no push
  if (token) sendPush(token).then(onInvalid);
  return { queued: true, id };
}

// Recipient confirmed receipt of `id`: drop it from their queue and tell the
// original sender (if online) that it was delivered.
function ackReceived(recipientPubkey, id) {
  const from = store.ack(recipientPubkey, id); // from_pk, либо null если нет/не его
  if (from) {
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
      return send(ws, { type: 'challenge', nonce: ws.nonce });
    }

    if (msg.type === 'auth') {
      if (!ws.pendingPubkey || !ws.nonce) {
        return send(ws, { type: 'error', error: 'say hello first' });
      }
      if (typeof msg.signature !== 'string') {
        return send(ws, { type: 'error', error: 'auth requires signature' });
      }
      // TOFU: the signPublicKey bound to this pubkey must not change.
      const boundSpk = store.getSignKey(ws.pendingPubkey);
      const spk = boundSpk || ws.pendingSpk;
      if (boundSpk && boundSpk !== ws.pendingSpk) {
        return send(ws, { type: 'error', error: 'pubkey bound to a different key' });
      }
      if (!verifySignature(ws.nonce, msg.signature, spk)) {
        return send(ws, { type: 'error', error: 'bad signature' });
      }
      if (!boundSpk) store.bindSignKey(ws.pendingPubkey, ws.pendingSpk);
      // authenticated: take ownership of this pubkey
      ws.authed = true;
      ws.pubkey = ws.pendingPubkey;
      ws.nonce = null;
      clearTimeout(ws.authTimer);
      // If a stale socket still claims this pubkey, replace it.
      const prev = online.get(ws.pubkey);
      if (prev && prev !== ws) try { prev.terminate(); } catch (e) {}
      online.set(ws.pubkey, ws);
      const flushed = flushQueue(ws.pubkey, ws);
      return send(ws, { type: 'ready', queued: flushed });
    }

    // --- relay directory (public: allowed before auth for bootstrap) ---
    if (msg.type === 'relays') {
      return send(ws, { type: 'relays', relays: relayDir });
    }
    if (msg.type === 'relay-advertise') {
      // кто-то (клиент/релей) сообщает об известном релее — валидируем и учим
      const urls = Array.isArray(msg.relays) ? msg.relays : [msg.url];
      const clean = urls.filter((u) => isValidRelayUrl(u));
      if (clean.length) learnRelays(clean);
      return send(ws, { type: 'relays', relays: relayDir });
    }

    // App-level liveness: клиент шлёт ping, чтобы отличить живое соединение от
    // «тихо зависшего» при смене сети (WS-фреймы ping ему не видны из JS).
    if (msg.type === 'ping') {
      return send(ws, { type: 'pong' });
    }

    // --- everything past here requires authentication ---
    if (!ws.authed) return send(ws, { type: 'error', error: 'not authenticated' });

    if (msg.type === 'turn') {
      return send(ws, { type: 'turn', iceServers: turnIceServers() });
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
      const r = deliver(ws.pubkey, msg.to, msg.envelope, !!msg.silent, !!msg.callPush);
      return send(ws, { type: 'ack', ref: msg.ref, id: r.id, queued: r.queued });
    }

    send(ws, { type: 'error', error: 'unknown type' });
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

// --- gossip: периодически синхронизируем каталог с известными релеями --------
// Каждый релей тянет /relays у пиров и сливает списки — так новый узел за
// несколько раундов становится известен почти всем, без центрального реестра.
function relayHttpBase(wsUrl) {
  return wsUrl.replace(/^ws:\/\//i, 'http://').replace(/^wss:\/\//i, 'https://');
}
async function fetchPeerRelays(wsUrl) {
  if (typeof fetch !== 'function') return null; // Node < 18
  const url = relayHttpBase(wsUrl) + '/relays';
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 5000);
  try {
    const res = await fetch(url, { signal: ctrl.signal });
    if (!res.ok) return null;
    const body = await res.json();
    return Array.isArray(body.relays) ? body.relays : null;
  } catch (e) {
    return null;
  } finally {
    clearTimeout(t);
  }
}
// Push-gossip: сообщить peer'у наш каталог (включая себя). Благодаря этому
// сосед, который сам нас в peers не прописывал (напр. самый первый релей),
// узнаёт про нас — распространение становится двунаправленным.
async function pushSelfTo(wsUrl) {
  if (typeof fetch !== 'function') return;
  const url = relayHttpBase(wsUrl) + '/relays';
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 5000);
  try {
    await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ relays: relayDir }),
      signal: ctrl.signal,
    });
  } catch (e) {
  } finally {
    clearTimeout(t);
  }
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
  try {
    store.close();
  } catch (e) {}
  process.exit(0);
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

server.listen(PORT, () => {
  console.log(`Лично relay listening on :${PORT} (health: /health, directory: /relays)`);
  console.log(`[dir] ${relayDir.length} relay(s) known${SELF_URL ? `, self=${SELF_URL}` : ' (set RELAY_SELF_URL to advertise self)'}`);
  console.log(
    '[push]',
    pushReady()
      ? 'FCM configured — wake-up pushes enabled'
      : 'FCM NOT configured — closed-app notifications will NOT be sent (add service-account.json)'
  );
});
