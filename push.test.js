/**
 * push.test.js — юнит-тесты web-push (UnifiedPush) маршрутизации, разбора подписки,
 * VAPID и SSRF-отбраковки (node server/push.test.js).
 *
 * Сеть не дёргаем: проверяем чистую логику. Реальная доставка web-push на push-
 * сервис (ntfy) проверяется на боевом стенде с телефоном.
 */
const assert = require('assert');
const {
  isUnifiedPushEndpoint,
  validUnifiedPushEndpoint,
  parseSubscription,
  setVapidKeys,
  vapidPublicKey,
  generateVapidKeys,
} = require('./push');

let passed = 0;
function test(name, fn) {
  fn();
  passed++;
  console.log('  ✓ ' + name);
}
console.log('push (web-push/UnifiedPush routing + VAPID + SSRF)');

const goodSub = (endpoint = 'https://ntfy.example.com/upABC?up=1') =>
  JSON.stringify({ endpoint, keys: { p256dh: 'BFxxYYzz_publicKeyBase64Url', auth: 'authSecretBase64Url' } });

test('parseSubscription: валидная web-push подписка разбирается', () => {
  const s = parseSubscription(goodSub());
  assert.ok(s && s.endpoint === 'https://ntfy.example.com/upABC?up=1');
  assert.strictEqual(s.keys.p256dh, 'BFxxYYzz_publicKeyBase64Url');
  assert.strictEqual(s.keys.auth, 'authSecretBase64Url');
});

test('parseSubscription: FCM-токен (не JSON) → null', () => {
  assert.strictEqual(parseSubscription('fMEP0vJqRk:APA91bH...'), null);
  assert.strictEqual(parseSubscription(''), null);
  assert.strictEqual(parseSubscription(null), null);
});

test('parseSubscription: без ключей / битая форма → null', () => {
  assert.strictEqual(parseSubscription(JSON.stringify({ endpoint: 'https://x.example.com/a' })), null);
  assert.strictEqual(parseSubscription(JSON.stringify({ endpoint: 'https://x.example.com/a', keys: {} })), null);
  assert.strictEqual(parseSubscription('{not json'), null);
});

test('parseSubscription: SSRF — приватный/loopback/метаданные endpoint → null', () => {
  assert.strictEqual(parseSubscription(goodSub('http://127.0.0.1/up')), null);
  assert.strictEqual(parseSubscription(goodSub('http://169.254.169.254/latest')), null);
  assert.strictEqual(parseSubscription(goodSub('http://192.168.1.10/up')), null);
  assert.strictEqual(parseSubscription(goodSub('http://[::1]/up')), null);
  assert.strictEqual(parseSubscription(goodSub('ftp://example.com/up')), null); // не http(s)
});

test('parseSubscription: гигантская подписка → null (потолок длины)', () => {
  assert.strictEqual(parseSubscription(goodSub('https://example.com/' + 'a'.repeat(1200))), null);
});

test('isUnifiedPushEndpoint: подписка → true, FCM-токен → false', () => {
  assert.strictEqual(isUnifiedPushEndpoint(goodSub()), true);
  assert.strictEqual(isUnifiedPushEndpoint('fMEP0vJqRk:APA91bH...'), false);
});

test('validUnifiedPushEndpoint: публичный http(s) — ок; приватный/мусор — нет', () => {
  assert.strictEqual(validUnifiedPushEndpoint('https://ntfy.example.com/up'), true);
  assert.strictEqual(validUnifiedPushEndpoint('http://127.0.0.1/up'), false);
  assert.strictEqual(validUnifiedPushEndpoint('http://2130706433/up'), false); // decimal 127.0.0.1
  assert.strictEqual(validUnifiedPushEndpoint('ws://example.com/up'), false);
});

test('VAPID: до setVapidKeys — не настроен; после — публичный ключ доступен', () => {
  assert.strictEqual(vapidPublicKey(), null);
  const kp = generateVapidKeys();
  assert.ok(kp.publicKey && kp.privateKey);
  assert.strictEqual(setVapidKeys(kp.publicKey, kp.privateKey), true);
  assert.strictEqual(vapidPublicKey(), kp.publicKey);
});

console.log(`\npush: ${passed} passed`);
