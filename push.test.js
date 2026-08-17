const assert = require('assert');
const {
  isUnifiedPushEndpoint,
  validUnifiedPushEndpoint,
  parseSubscription,
  setVapidKeys,
  vapidPublicKey,
  vapidPublicKeyFor,
  generateVapidKeys,
  messageFcmPayload,
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
test('FCM-уведомление о сообщении не несёт ничего, кроме типа', () => {
  const payload = messageFcmPayload('ТОКЕН-УСТРОЙСТВА');
  assert.deepStrictEqual(payload.data, { type: 'message' }, 'в data не должно быть ни идентификаторов, ни ключей');
  assert.deepStrictEqual(
    Object.keys(payload).sort(),
    ['android', 'data', 'notification', 'token'],
    'состав полей FCM-сообщения изменился — проверьте, что новое поле не раскрывает метаданные'
  );
  assert.strictEqual(payload.notification.body, 'Новое зашифрованное сообщение', 'текст не зависит от содержимого');
  assert.strictEqual(payload.android.notification.tag, 'new-message');
});
test('публичный ключ из клиентской метки не попадает в FCM ни при каких условиях', () => {
  const serialized = JSON.stringify(messageFcmPayload('ТОКЕН'));
  assert.ok(!serialized.includes('messageId'), 'поле идентификатора удалено');
  assert.ok(!serialized.includes('chatTag'), 'признак чата в FCM не передаётся (ПРФ-4)');
});
console.log(`\npush: ${passed} passed`);