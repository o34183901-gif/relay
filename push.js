const dns = require('dns').promises;
const https = require('https');
const webpush = require('web-push');
const { isPrivateHost } = require('./relays');
const { deviceVapidKeys, vapidSubject } = require('./vapid-identity');
function pinnedLookup(pinned) {
  return (hostname, options, cb) => {
    if (options && options.all) return cb(null, pinned);
    cb(null, pinned[0].address, pinned[0].family);
  };
}
const UP_MAX_ENDPOINT_LEN = 512;
const UP_MAX_SUB_LEN = 1024;
const VAPID_REJECTED = new Set([400, 401, 403]);
let vapidConfigured = false;
let vapidBase = null;
let vapidContact = null;
function setVapidKeys(publicKey, privateKey, subject, selfUrl) {
  try {
    const contact = vapidSubject(selfUrl, subject);
    webpush.setVapidDetails(contact, publicKey, privateKey);
    vapidBase = { publicKey, privateKey };
    vapidContact = contact;
    vapidConfigured = true;
    return true;
  } catch (e) {
    console.warn('[push] VAPID некорректен:', e && e.message);
    vapidConfigured = false;
    return false;
  }
}
function vapidPublicKey() {
  return vapidConfigured && vapidBase ? vapidBase.publicKey : null;
}
function vapidKeysFor(address) {
  if (!vapidConfigured || !vapidBase) return null;
  return deviceVapidKeys(vapidBase.privateKey, address) || vapidBase;
}
function vapidPublicKeyFor(address) {
  const keys = vapidKeysFor(address);
  return keys ? keys.publicKey : null;
}
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
function parseSubscription(token) {
  if (typeof token !== 'string' || !token || token.length > UP_MAX_SUB_LEN) return null;
  if (token[0] !== '{') return null;
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
function isUnifiedPushEndpoint(token) {
  return parseSubscription(token) !== null;
}
let notifSeq = 0;
const MESSAGE_NOTIFICATION_ID = 1279877966;
const CALL_NOTIFICATION_ID = 1279877967;
async function unifiedPushSend(sub, notification, address) {
  if (!vapidConfigured) return false;
  const parsed = typeof sub === 'string' ? parseSubscription(sub) : sub;
  if (!parsed) return 'invalid';
  let pinned;
  try {
    const host = new URL(parsed.endpoint).hostname;
    if (isPrivateHost(host)) return 'invalid';
    const addrs = await dns.lookup(host, { all: true });
    if (!addrs.length) return false;
    for (const a of addrs) if (isPrivateHost(a.address)) return 'invalid';
    pinned = addrs.map((a) => ({ address: a.address, family: a.family }));
  } catch (e) {
    return false;
  }
  try {
    notifSeq = (notifSeq + 1) % 1e9;
    const body = JSON.stringify({ id: notification.id || notifSeq, ...notification });
    const agent = new https.Agent({ lookup: pinnedLookup(pinned), keepAlive: false });
    const deliver = (keys) =>
      webpush.sendNotification(parsed, body, {
        TTL: 3600,
        agent,
        vapidDetails: { subject: vapidContact, publicKey: keys.publicKey, privateKey: keys.privateKey },
      });
    const keys = vapidKeysFor(address);
    let res;
    try {
      res = await deliver(keys);
    } catch (e) {
      if (keys === vapidBase || !VAPID_REJECTED.has(e && e.statusCode)) throw e;
      res = await deliver(vapidBase);
    }
    return !!res && res.statusCode >= 200 && res.statusCode < 300;
  } catch (e) {
    const code = e && e.statusCode;
    if (code === 404 || code === 410) return 'invalid';
    console.log('[push] web-push send failed:', (e && e.message) || e);
    return false;
  }
}
async function sendPush(token, messageId, chatTag, address) {
  if (!token) return false;
  const sub = parseSubscription(token);
  if (!sub) return 'invalid';
  const safeMessageId = typeof messageId === 'string' ? messageId.slice(0, 160) : '';
  const safeChatTag =
    typeof chatTag === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(chatTag) ? chatTag : '';
  return unifiedPushSend(
    sub,
    {
      id: MESSAGE_NOTIFICATION_ID,
      title: 'Лично',
      body: 'Новое зашифрованное сообщение',
      type: 'message',
      messageId: safeMessageId,
      chatTag: safeChatTag,
      data: { type: 'message', messageId: safeMessageId, chatTag: safeChatTag },
    },
    address
  );
}
async function sendCallPush(token, address) {
  if (!token) return false;
  const sub = parseSubscription(token);
  if (!sub) return 'invalid';
  return unifiedPushSend(
    sub,
    {
      id: CALL_NOTIFICATION_ID,
      title: 'Входящий звонок',
      body: 'Нажмите, чтобы ответить',
      type: 'call',
      data: { type: 'call' },
    },
    address
  );
}
async function sendTestPush(token, testId, channel = 'message', address) {
  if (!token || typeof testId !== 'string' || !testId) return false;
  const sub = parseSubscription(token);
  if (!sub) return 'invalid';
  const isCall = channel === 'call';
  return unifiedPushSend(
    sub,
    {
      title: 'Лично · проверка уведомлений',
      body: isCall ? 'Проверка канала аудио- и видеозвонков' : 'Проверка канала сообщений',
      type: 'push-test',
      testId,
      channel: isCall ? 'call' : 'message',
    },
    address
  );
}
function generateVapidKeys() {
  return webpush.generateVAPIDKeys();
}
module.exports = {
  sendPush,
  sendCallPush,
  sendTestPush,
  setVapidKeys,
  vapidPublicKey,
  vapidPublicKeyFor,
  generateVapidKeys,
  isUnifiedPushEndpoint,
  validUnifiedPushEndpoint,
  parseSubscription,
};
