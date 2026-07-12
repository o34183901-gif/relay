/**
 * push.js — send FCM (Firebase Cloud Messaging) pushes so a recipient gets a
 * notification even when the app is fully closed.
 *
 * Privacy: the push carries NO message content and NO contact name — the server
 * only knows public keys. It just says "new encrypted message". The real text
 * is pulled from the queue (still E2E-encrypted) when the app opens.
 *
 * Config via env (set by install.sh):
 *   FCM_PROJECT_ID                 - Firebase project id
 *   GOOGLE_APPLICATION_CREDENTIALS - path to the service-account JSON
 * If unset, pushes are silently skipped (relay still works, just no wake-ups).
 */
let GoogleAuth;
try {
  ({ GoogleAuth } = require('google-auth-library'));
} catch (e) {
  GoogleAuth = null;
}

const PROJECT_ID = process.env.FCM_PROJECT_ID;
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
    android: { priority: 'HIGH', notification: { channel_id: 'messages' } },
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
