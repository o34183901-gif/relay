const assert = require('assert');
const push = require('./push');
const fs = require('fs');
const path = require('path');
const {
  isUnifiedPushEndpoint,
  validUnifiedPushEndpoint,
  parseSubscription,
  setVapidKeys,
  vapidPublicKey,
  vapidPublicKeyFor,
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
  assert.strictEqual(parseSubscription(goodSub('ftp://example.com/up')), null);
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
  assert.strictEqual(validUnifiedPushEndpoint('http://ntfy.example.com/up'), false);
  assert.strictEqual(validUnifiedPushEndpoint('http://127.0.0.1/up'), false);
  assert.strictEqual(validUnifiedPushEndpoint('http://2130706433/up'), false);
  assert.strictEqual(validUnifiedPushEndpoint('ws://example.com/up'), false);
});

test('VAPID: до setVapidKeys — не настроен; после — публичный ключ доступен', () => {
  assert.strictEqual(vapidPublicKey(), null);
  assert.strictEqual(vapidPublicKeyFor('АДРЕС-УСТРОЙСТВА'), null, 'без пары выводить нечего');
  const kp = generateVapidKeys();
  assert.ok(kp.publicKey && kp.privateKey);
  assert.strictEqual(setVapidKeys(kp.publicKey, kp.privateKey), true);
  assert.strictEqual(vapidPublicKey(), kp.publicKey);
});
test('ВЫС-51: клиенту уходит пара УСТРОЙСТВА, а не общая пара флота', () => {
  const kp = generateVapidKeys();
  setVapidKeys(kp.publicKey, kp.privateKey);
  const alice = vapidPublicKeyFor('adres-alisy-AAAAAAAAAAAAAAAAAAAAAAAAAAAA=');
  const bob = vapidPublicKeyFor('adres-borisa-BBBBBBBBBBBBBBBBBBBBBBBBBB=');
  assert.notStrictEqual(alice, kp.publicKey, 'общий ключ флота клиенту больше не выдаётся');
  assert.notStrictEqual(alice, bob, 'два устройства — два разных ключа, склеить подписки нечем');
  assert.strictEqual(
    vapidPublicKeyFor('adres-alisy-AAAAAAAAAAAAAAAAAAAAAAAAAAAA='),
    alice,
    'вывод обязан быть повторяемым: иначе подписку, выпущенную вчера, сегодня нечем подписать'
  );
});
test('ВЫС-51: без адреса (диагностика, старый вызов) остаётся базовая пара', () => {
  const kp = generateVapidKeys();
  setVapidKeys(kp.publicKey, kp.privateKey);
  assert.strictEqual(vapidPublicKeyFor(null), kp.publicKey);
  assert.strictEqual(vapidPublicKeyFor(''), kp.publicKey);
});
test('УВД-7: FCM вырезан — токен, который не разбирается как подписка, отвергается', () => {
  assert.strictEqual(typeof push.sendPush, 'function');
  assert.strictEqual(push.messageFcmPayload, undefined, 'вернулась сборка FCM-сообщения');
  assert.strictEqual(push.pushReady, undefined, 'вернулась проверка настроенности FCM');
  assert.strictEqual(push.loadGoogleAuth, undefined, 'вернулась загрузка google-auth-library');
  assert.strictEqual(push.detectProjectId, undefined, 'вернулось определение проекта Firebase');
  assert.strictEqual(push.applyCredentialsFile, undefined, 'вернулась подстановка ключа сервисного аккаунта');
  const source = fs.readFileSync(path.join(__dirname, 'push.js'), 'utf8');
  for (const trace of ['fcm', 'FCM', 'googleapis', 'google-auth', 'service-account', 'firebase']) {
    assert.ok(!source.includes(trace), `в push.js остался след Google: ${trace}`);
  }
});
test('УВД-7: без подписи UnifiedPush отправка не выдумывает запасной путь', async () => {
  assert.strictEqual(await push.sendPush('НЕ-JSON-ТОКЕН', 'mid', 'tag', 'addr'), 'invalid');
  assert.strictEqual(await push.sendCallPush('НЕ-JSON-ТОКЕН', 'addr'), 'invalid');
  assert.strictEqual(await push.sendTestPush('НЕ-JSON-ТОКЕН', 'pt_1', 'message', 'addr'), 'invalid');
  assert.strictEqual(await push.sendPush('', 'mid', 'tag', 'addr'), false);
  assert.strictEqual(await push.sendCallPush(null, 'addr'), false);
  assert.strictEqual(await push.sendTestPush('{}', '', 'message', 'addr'), false);
});
console.log(`\npush: ${passed} passed`);