/**
 * push.js — send FCM (Firebase Cloud Messaging) pushes so a recipient gets a
 * notification even when the app is fully closed.
 *
 * Privacy: the push carries NO message content and NO contact name — the server
 * only knows public keys. It just says "new encrypted message". The real text
 * is pulled from the queue (still E2E-encrypted) when the app opens.
 *
 * Config — ЛЮБОЙ из способов:
 *   1. Просто положить service-account.json в каталог данных (/data в Docker,
 *      рядом с relay.js на bare-metal) — файл найдётся сам, project_id
 *      прочитается из него. Ничего настраивать не нужно.
 *   2. Классически через env: FCM_PROJECT_ID + GOOGLE_APPLICATION_CREDENTIALS.
 * If unset, pushes are silently skipped (relay still works, just no wake-ups).
 */
const fs = require('fs');
const path = require('path');
const dns = require('dns').promises;
const webpush = require('web-push');
const { isPrivateHost } = require('./relays');

let GoogleAuth;
try {
  ({ GoogleAuth } = require('google-auth-library'));
} catch (e) {
  GoogleAuth = null;
}

// Автопоиск service-account.json: env → каталог данных (volume) → рядом с кодом.
function autoDetectCredentials() {
  const candidates = [
    process.env.GOOGLE_APPLICATION_CREDENTIALS,
    path.join(path.dirname(process.env.RELAY_DB || path.join(__dirname, 'relay.db')), 'service-account.json'),
    path.join(__dirname, 'service-account.json'),
  ].filter(Boolean);
  for (const p of candidates) {
    try {
      if (fs.existsSync(p)) return p;
    } catch (e) {}
  }
  return null;
}

const CREDENTIALS_FILE = autoDetectCredentials();
if (CREDENTIALS_FILE && !process.env.GOOGLE_APPLICATION_CREDENTIALS) {
  // google-auth-library читает путь из этой переменной
  process.env.GOOGLE_APPLICATION_CREDENTIALS = CREDENTIALS_FILE;
}

function detectProjectId() {
  if (process.env.FCM_PROJECT_ID) return process.env.FCM_PROJECT_ID;
  if (!CREDENTIALS_FILE) return null;
  try {
    return JSON.parse(fs.readFileSync(CREDENTIALS_FILE, 'utf8')).project_id || null;
  } catch (e) {
    return null;
  }
}

const PROJECT_ID = detectProjectId();
let auth = null;
let warned = false;

function ready() {
  if (PROJECT_ID && process.env.GOOGLE_APPLICATION_CREDENTIALS && GoogleAuth) return true;
  if (!warned) {
    console.log('[push] FCM not configured — skipping wake-up pushes');
    warned = true;
  }
  return false;
}

async function accessToken() {
  if (!auth) {
    auth = new GoogleAuth({ scopes: ['https://www.googleapis.com/auth/firebase.messaging'] });
  }
  const client = await auth.getClient();
  const t = await client.getAccessToken();
  return t.token;
}

async function fcmSend(message) {
  if (!ready()) return false;
  try {
    const at = await accessToken();
    const res = await fetch(`https://fcm.googleapis.com/v1/projects/${PROJECT_ID}/messages:send`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${at}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ message }),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      console.log('[push] FCM error', res.status, text.slice(0, 200));
      if (res.status === 404 || res.status === 400) return 'invalid';
      return false;
    }
    return true;
  } catch (e) {
    console.log('[push] send failed:', e.message);
    return false;
  }
}

// ---------------------------------------------------------------------------
// UnifiedPush (web-push / VAPID) — открытый push БЕЗ Google (F-Droid / de-Googled).
// ---------------------------------------------------------------------------
//
// Клиент (expo-unified-push) регистрируется у дистрибьютора (ntfy) и получает
// web-push ПОДПИСКУ: { endpoint, keys:{ p256dh, auth } }. Она передаётся релею
// кадром register (JSON-строкой в поле pushToken). Релей шлёт ЗАШИФРОВАННЫЙ
// web-push (VAPID + RFC 8291); expo-unified-push расшифровывает и РИСУЕТ
// уведомление НАТИВНО из формы Notification { id, title?, body? } — контента
// сообщения в пуше нет (как и в FCM), только обобщённый текст.
//
// VAPID-пара релея: env RELAY_VAPID_PUBLIC/PRIVATE или персист в файле рядом с БД
// (relay.js resolveVapidKeys → setVapidKeys). Клиент забирает публичный ключ из
// кадра ready и передаёт в registerDevice. Во ФЕДЕРАЦИИ пуш шлёт лишь релей, у
// которого есть VAPID-приватный ключ подписки — как и с FCM service-account
// (доверенный релей). Оператор флота ставит ОДНУ VAPID-пару на свои релеи.

const UP_MAX_ENDPOINT_LEN = 512;
const UP_MAX_SUB_LEN = 1024; // подписка (endpoint + ключи) длиннее FCM-токена

let vapidConfigured = false;
let vapidPub = null;
/** Задать VAPID-пару релея (зовётся из relay.js после resolveVapidKeys). */
function setVapidKeys(publicKey, privateKey, subject) {
  try {
    webpush.setVapidDetails(subject || 'mailto:relay@licno.invalid', publicKey, privateKey);
    vapidPub = publicKey;
    vapidConfigured = true;
    return true;
  } catch (e) {
    console.warn('[push] VAPID некорректен:', e && e.message);
    vapidConfigured = false;
    return false;
  }
}
/** Публичный VAPID-ключ для кадра ready клиенту (null — web-push не настроен). */
function vapidPublicKey() {
  return vapidConfigured ? vapidPub : null;
}

/** Литеральная (без DNS) валидация endpoint: http(s), длина, хост не приватный. */
function validUnifiedPushEndpoint(endpoint) {
  if (typeof endpoint !== 'string' || !endpoint || endpoint.length > UP_MAX_ENDPOINT_LEN) return false;
  let u;
  try {
    u = new URL(endpoint);
  } catch (e) {
    return false;
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return false;
  if (isPrivateHost(u.hostname)) return false;
  return true;
}

/**
 * Разобрать сохранённый токен как web-push подписку. Возвращает { endpoint, keys }
 * либо null (тогда это обычный FCM-токен). Валидирует форму, endpoint и SSRF
 * (литерально). Экспортируется для тестов.
 */
function parseSubscription(token) {
  if (typeof token !== 'string' || !token || token.length > UP_MAX_SUB_LEN) return null;
  if (token[0] !== '{') return null; // FCM-токен — не JSON
  let s;
  try {
    s = JSON.parse(token);
  } catch (e) {
    return null;
  }
  if (!s || typeof s.endpoint !== 'string' || !validUnifiedPushEndpoint(s.endpoint)) return null;
  const k = s.keys || {};
  if (typeof k.p256dh !== 'string' || !k.p256dh || typeof k.auth !== 'string' || !k.auth) return null;
  return { endpoint: s.endpoint, keys: { p256dh: k.p256dh, auth: k.auth } };
}

/** Это web-push подписка (UnifiedPush), а не FCM-токен? */
function isUnifiedPushEndpoint(token) {
  return parseSubscription(token) !== null;
}

let notifSeq = 0;

/**
 * Отправить зашифрованный web-push на подписку. notification — форма expo-unified-
 * push { title, body } (id проставляем сами). SSRF: endpoint приходит от клиента,
 * поэтому резолвим и отвергаем приватные адреса ПЕРЕД отправкой (web-push-
 * библиотека ходит сама, без кастомного lookup; литеральный + резолв-чек закрывают
 * основной вектор). Возвращает true | false | 'invalid' (подписка отозвана).
 */
async function unifiedPushSend(sub, notification) {
  if (!vapidConfigured) return false; // VAPID не задан — web-push не шлём
  const parsed = typeof sub === 'string' ? parseSubscription(sub) : sub;
  if (!parsed) return 'invalid';
  try {
    const host = new URL(parsed.endpoint).hostname;
    if (isPrivateHost(host)) return 'invalid';
    const addrs = await dns.lookup(host, { all: true });
    if (!addrs.length) return false;
    for (const a of addrs) if (isPrivateHost(a.address)) return 'invalid';
  } catch (e) {
    return false; // не резолвится — не ходим
  }
  try {
    notifSeq = (notifSeq + 1) % 1e9;
    const body = JSON.stringify({ id: notifSeq, ...notification });
    const res = await webpush.sendNotification(parsed, body, { TTL: 3600 });
    return !!res && res.statusCode >= 200 && res.statusCode < 300;
  } catch (e) {
    const code = e && e.statusCode;
    if (code === 404 || code === 410) return 'invalid'; // подписка отозвана
    console.log('[push] web-push send failed:', (e && e.message) || e);
    return false;
  }
}

/** Content-free wake-up push for a new message. FCM или web-push (UnifiedPush). */
async function sendPush(token) {
  if (!token) return false;
  const sub = parseSubscription(token);
  if (sub) return unifiedPushSend(sub, { title: 'Лично', body: 'Новое зашифрованное сообщение' });
  return fcmSend({
    token,
    notification: { title: 'Лично', body: 'Новое зашифрованное сообщение' },
    // tag: одинаковый у всех message-пушей — новое уведомление ЗАМЕНЯЕТ
    // предыдущее на устройстве, а не добавляется рядом. Даже если дубли
    // придут с нескольких релеев, пользователь увидит одно уведомление.
    android: { priority: 'HIGH', notification: { channel_id: 'messages', tag: 'new-message' } },
    data: { type: 'message' },
  });
}

/** High-priority ring push for an incoming call. FCM или web-push (UnifiedPush). */
async function sendCallPush(token) {
  if (!token) return false;
  const sub = parseSubscription(token);
  if (sub) return unifiedPushSend(sub, { title: 'Входящий звонок', body: 'Нажмите, чтобы ответить' });
  return fcmSend({
    token,
    notification: { title: 'Входящий звонок', body: 'Нажмите, чтобы ответить' },
    android: {
      priority: 'HIGH',
      notification: { channel_id: 'calls', sound: 'default', tag: 'incoming-call' },
    },
    data: { type: 'call' },
  });
}

/** Сгенерировать новую VAPID-пару (для персиста в relay.js). */
function generateVapidKeys() {
  return webpush.generateVAPIDKeys();
}

module.exports = {
  sendPush,
  sendCallPush,
  pushReady: ready,
  setVapidKeys,
  vapidPublicKey,
  generateVapidKeys,
  isUnifiedPushEndpoint,
  validUnifiedPushEndpoint,
  parseSubscription,
};
