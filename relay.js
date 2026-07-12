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
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const nacl = require('tweetnacl');
const naclUtil = require('tweetnacl-util');
const { WebSocketServer } = require('ws');
const { sendPush, sendCallPush, pushReady } = require('./push');
const { mergeRelays, isValidRelayUrl, normalizeRelayUrl } = require('./relays');

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
const DATA_FILE = process.env.RELAY_DATA || path.join(__dirname, 'queue.json');
const PUSH_FILE = process.env.RELAY_PUSH || path.join(__dirname, 'push-tokens.json');
const IDENT_FILE = process.env.RELAY_IDENT || path.join(__dirname, 'identities.json');
const DIR_FILE = process.env.RELAY_DIR || path.join(__dirname, 'relays.json');
const MAX_QUEUE_PER_USER = 500;

// --- Реплицированный каталог релеев (gossip) ------------------------------
// SELF_URL — публичный wss-адрес ЭТОГО релея; RELAY_PEERS — стартовые соседи
// (через запятую). Каталог = self ∪ peers ∪ выученные, сохраняется в relays.json
// и периодически синхронизируется с пирами. Клиент может забрать его у любого
// релея (GET /relays или WS {type:'relays'}), поэтому падение одного не критично.
const SELF_URL = normalizeRelayUrl(process.env.RELAY_SELF_URL || '') || null;
const PEER_SEED = (process.env.RELAY_PEERS || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);
const GOSSIP_INTERVAL_MS = Number(process.env.RELAY_GOSSIP_MS) || 60000;

function loadRelayDir() {
  let stored = [];
  try {
    stored = JSON.parse(fs.readFileSync(DIR_FILE, 'utf8'));
  } catch (e) {
    stored = [];
  }
  return mergeRelays([], [SELF_URL, ...PEER_SEED, ...stored].filter(Boolean));
}
let relayDir = loadRelayDir();
function persistRelayDir() {
  try {
    fs.writeFileSync(DIR_FILE, JSON.stringify(relayDir));
  } catch (e) {
    console.error('relay-dir persist failed:', e.message);
  }
}
/** Добавить URL(ы) в каталог; вернуть true, если что-то реально добавилось. */
function learnRelays(urls) {
  const before = relayDir.length;
  relayDir = mergeRelays(relayDir, urls);
  if (relayDir.length !== before) {
    persistRelayDir();
    return true;
  }
  return false;
}
const MAX_ENVELOPE_BYTES = 32 * 1024 * 1024; // 32 MB envelope (~24 MB video/file)

// Rate limiting (per connection).
const AUTH_TIMEOUT_MS = 10000; // must authenticate within this window
const RATE_WINDOW_MS = 1000;
const RATE_MAX_FRAMES = 80; // frames per RATE_WINDOW_MS before we drop the socket

// pubkey -> live WebSocket
const online = new Map();
// pubkey -> array of pending {id, from, envelope, silent, callPush}
const queues = loadMap(DATA_FILE);
// pubkey -> FCM device token (for wake-up pushes when offline)
const pushTokens = loadMap(PUSH_FILE);
// pubkey -> signPublicKey (trust-on-first-use ownership binding)
const identities = loadMap(IDENT_FILE);

function loadMap(file) {
  try {
    return new Map(Object.entries(JSON.parse(fs.readFileSync(file, 'utf8'))));
  } catch (e) {
    return new Map();
  }
}

function persistFile(file, map, label) {
  try {
    fs.writeFileSync(file, JSON.stringify(Object.fromEntries(map)));
  } catch (e) {
    console.error(`${label} persist failed:`, e.message);
  }
}
const persist = () => persistFile(DATA_FILE, queues, 'queue');
const persistTokens = () => persistFile(PUSH_FILE, pushTokens, 'token');
const persistIdentities = () => persistFile(IDENT_FILE, identities, 'identity');

setInterval(persist, 10000).unref();

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
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true, online: online.size, queued: queues.size, relays: relayDir.length }));
    return;
  }
  // Публичный каталог релеев — любой (клиент или другой релей) может забрать его
  // отсюда. Это и есть точка, из которой список реплицируется по сети.
  if (req.url === '/relays') {
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
  const q = queues.get(pubkey) || [];
  for (const item of q) send(ws, { type: 'message', id: item.id, envelope: item.envelope });
  return q.length;
}

function deliver(from, to, envelope, silent, callPush) {
  const id = nextId();
  // Always enqueue; the copy is removed only when the recipient acks (received).
  const q = queues.get(to) || [];
  if (q.length >= MAX_QUEUE_PER_USER) q.shift();
  q.push({ id, from, envelope, silent, callPush });
  queues.set(to, q);
  persist();

  const ws = online.get(to);
  if (ws) {
    send(ws, { type: 'message', id, envelope });
    return { queued: false, id };
  }

  // recipient offline -> maybe wake them
  const token = pushTokens.get(to);
  const onInvalid = (r) => {
    if (r === 'invalid') {
      pushTokens.delete(to);
      persistTokens();
    }
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
  const q = queues.get(recipientPubkey);
  if (!q) return;
  const idx = q.findIndex((item) => item.id === id);
  if (idx < 0) return;
  const [item] = q.splice(idx, 1);
  if (q.length === 0) queues.delete(recipientPubkey);
  else queues.set(recipientPubkey, q);
  persist();
  const senderWs = item.from && online.get(item.from);
  if (senderWs) send(senderWs, { type: 'delivered', id });
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

wss.on('connection', (ws) => {
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
      const boundSpk = identities.get(ws.pendingPubkey);
      const spk = boundSpk || ws.pendingSpk;
      if (boundSpk && boundSpk !== ws.pendingSpk) {
        return send(ws, { type: 'error', error: 'pubkey bound to a different key' });
      }
      if (!verifySignature(ws.nonce, msg.signature, spk)) {
        return send(ws, { type: 'error', error: 'bad signature' });
      }
      if (!boundSpk) {
        identities.set(ws.pendingPubkey, ws.pendingSpk);
        persistIdentities();
      }
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

    // --- everything past here requires authentication ---
    if (!ws.authed) return send(ws, { type: 'error', error: 'not authenticated' });

    if (msg.type === 'turn') {
      return send(ws, { type: 'turn', iceServers: turnIceServers() });
    }

    if (msg.type === 'register') {
      if (typeof msg.pushToken === 'string' && msg.pushToken) {
        pushTokens.set(ws.pubkey, msg.pushToken);
        persistTokens();
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
async function gossipOnce() {
  const peers = relayDir.filter((u) => !SELF_URL || u.toLowerCase() !== SELF_URL.toLowerCase());
  let learned = false;
  for (const peer of peers) {
    const list = await fetchPeerRelays(peer);
    if (list && learnRelays(list)) learned = true;
  }
  if (learned) console.log(`[gossip] directory now ${relayDir.length} relays`);
}
if (SELF_URL || PEER_SEED.length) {
  setInterval(() => {
    gossipOnce().catch(() => {});
  }, GOSSIP_INTERVAL_MS).unref();
}

// drop dead connections
setInterval(() => {
  for (const ws of wss.clients) {
    if (!ws.isAlive) {
      ws.terminate();
      continue;
    }
    ws.isAlive = false;
    ws.ping();
  }
}, 30000).unref();

process.on('SIGTERM', () => { persist(); persistRelayDir(); process.exit(0); });
process.on('SIGINT', () => { persist(); persistRelayDir(); process.exit(0); });

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
