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
  assert.strictEqual(vapidPublicKeyFor('АДРЕС-УСТРОЙСТВА'), null, 'без пары выводить нечего');
  const kp = generateVapidKeys();
  assert.ok(kp.publicKey && kp.privateKey);
  assert.strictEqual(setVapidKeys(kp.publicKey, kp.privateKey), true);
  assert.strictEqual(vapidPublicKey(), kp.publicKey);
});

// ВЫС-51. Одна VAPID-пара на весь флот означала, что push-провайдер видит все
// подписки «Лично» одной группой: по общему ключу отправителя он в любой момент
// отвечает, сколько у мессенджера устройств и когда их будят. Клиенту теперь
// уходит пара, выведенная из адреса устройства, — проверяем именно это, а не то,
// что «функция что-то вернула».
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
  // Потерять уведомление хуже, чем отдать провайдеру один ключ: путь без адреса
  // обязан работать, а не отказывать.
  assert.strictEqual(vapidPublicKeyFor(null), kp.publicKey);
  assert.strictEqual(vapidPublicKeyFor(''), kp.publicKey);
});

// АУД-Э1. Тело FCM-уведомления читает Google. Раньше сюда попадал клиентский
// идентификатор сообщения, а клиент кладёт в него публичный ключ участника
// (src/groups.js формирует метку как «mid:публичный ключ»). То есть адрес
// получателя уезжал Google рядом с токеном его устройства, а общий идентификатор
// у копий одного группового сообщения позволял связать токены между собой.
//
// Проверяем состав полей целиком, а не отсутствие одного поля: любое новое поле
// здесь — это новые метаданные у Google, и такое изменение обязано быть
// осознанным, а не проехать в общем потоке правок.
test('FCM-уведомление о сообщении не несёт ничего, кроме типа', () => {
  const payload = messageFcmPayload('ТОКЕН-УСТРОЙСТВА');
  assert.deepStrictEqual(payload.data, { type: 'message' }, 'в data не должно быть ни идентификаторов, ни ключей');
  assert.deepStrictEqual(
    Object.keys(payload).sort(),
    ['android', 'data', 'notification', 'token'],
    'состав полей FCM-сообщения изменился — проверьте, что новое поле не раскрывает метаданные'
  );
  assert.strictEqual(payload.notification.body, 'Новое зашифрованное сообщение', 'текст не зависит от содержимого');
  // Схлопывание уведомлений держится на теге, а не на идентификаторе, — поэтому
  // удаление идентификатора его не ломает.
  assert.strictEqual(payload.android.notification.tag, 'new-message');
});

// Ключ участника из реальной клиентской метки не должен находиться нигде в теле.
test('публичный ключ из клиентской метки не попадает в FCM ни при каких условиях', () => {
  const serialized = JSON.stringify(messageFcmPayload('ТОКЕН'));
  assert.ok(!serialized.includes('messageId'), 'поле идентификатора удалено');
  assert.ok(!serialized.includes('chatTag'), 'признак чата в FCM не передаётся (ПРФ-4)');
});

console.log(`\npush: ${passed} passed`);
