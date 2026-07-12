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

/** Content-free wake-up push for a new message. */
async function sendPush(token) {
  if (!token) return false;
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

/** High-priority ring push for an incoming call. */
async function sendCallPush(token) {
  if (!token) return false;
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

module.exports = { sendPush, sendCallPush, pushReady: ready };
