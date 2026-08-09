/**
 * vapid-identity.test.js — вывод VAPID-пары на устройство и контакт RFC 8292
 * (ВЫС-51). Сети и диска нет: правило чистое (node server/vapid-identity.test.js).
 *
 * Главное свойство, ради которого набор существует: у двух устройств РАЗНЫЕ
 * ключи отправителя. Совпади они — push-провайдер снова склеивает подписки в
 * одну группу и отвечает на вопрос «покажи все устройства этого мессенджера»,
 * а по коду это выглядит как работающая доставка, потому что пуши при общем
 * ключе доходят прекрасно.
 *
 * Второе свойство не менее тихое: выведенная пара обязана быть НАСТОЯЩЕЙ парой
 * P-256 в форме web-push. Кривая половина не даёт красной строки нигде — она
 * даёт 403 от push-сервиса на боевом стенде и «уведомления не приходят» у
 * человека. Поэтому пара сверяется той же проверкой, что и пара флота
 * (vapid-fleet.validVapidPair), и отдельно скармливается настоящей библиотеке.
 */
const assert = require('assert');
const crypto = require('crypto');
const webpush = require('web-push');
const { validVapidPair } = require('./vapid-fleet');
const {
  P256_ORDER,
  SCALAR_BYTES,
  PUBLIC_BYTES,
  MAX_DERIVE_ATTEMPTS,
  FALLBACK_SUBJECT,
  scalarFromBytes,
  keyPairFromScalar,
  deviceVapidKeys,
  validSubject,
  vapidSubject,
} = require('./vapid-identity');

let passed = 0;
function test(name, fn) {
  fn();
  passed++;
  console.log('  ✓ ' + name);
}

console.log('vapid identity (пара на устройство + контакт RFC 8292)');

// Базовая пара берётся у настоящей библиотеки: именно её приватную половину
// раздаёт по флоту vapid-fleet.js, и именно из неё выводятся ключи устройств.
const base = webpush.generateVAPIDKeys();
const other = webpush.generateVAPIDKeys();
const ALICE = 'YWxpY2UtZGV2aWNlLWFkZHJlc3MtaW4tYmFzZTY0AAAAAAA=';
const BOB = 'Ym9iLWRldmljZS1hZGRyZXNzLWluLWJhc2U2NAAAAAAAAAA=';

test('выведенная пара — настоящая пара P-256 в форме web-push', () => {
  const pair = deviceVapidKeys(base.privateKey, ALICE);
  assert.ok(pair, 'вывод обязан дать пару: без неё релей уйдёт на общий ключ флота');
  assert.strictEqual(validVapidPair(pair.publicKey, pair.privateKey), true, 'публичная половина обязана сходиться с приватной');
  const pub = Buffer.from(pair.publicKey, 'base64url');
  const priv = Buffer.from(pair.privateKey, 'base64url');
  assert.strictEqual(pub.length, PUBLIC_BYTES, 'точка обязана быть НЕСЖАТОЙ — сжатую не примет ни браузер, ни push-сервис');
  assert.strictEqual(pub[0], 4, 'первый байт несжатой точки — 0x04');
  assert.strictEqual(priv.length, SCALAR_BYTES);
});

test('настоящая библиотека web-push принимает выведенную пару', () => {
  const pair = deviceVapidKeys(base.privateKey, ALICE);
  // Библиотека сама проверяет длину и форму обеих половин; отказ здесь означал
  // бы, что подписать пуш этой парой не выйдет вовсе.
  assert.doesNotThrow(() => webpush.setVapidDetails('https://relay.example.com/', pair.publicKey, pair.privateKey));
});

test('у двух устройств ключи РАЗНЫЕ — провайдеру больше нечем склеить подписки', () => {
  const alice = deviceVapidKeys(base.privateKey, ALICE);
  const bob = deviceVapidKeys(base.privateKey, BOB);
  assert.notStrictEqual(alice.publicKey, bob.publicKey, 'общий ключ у двух устройств — это ровно та беда, ради которой всё сделано');
  assert.notStrictEqual(alice.privateKey, bob.privateKey);
  // И ни один из них не равен общей паре флота: иначе группа сохранится, просто
  // станет меньше.
  assert.notStrictEqual(alice.publicKey, base.publicKey, 'ключ устройства не должен совпадать с общим ключом флота');
  assert.notStrictEqual(bob.publicKey, base.publicKey);
});

test('вывод детерминирован: тот же адрес у другого релея флота даёт ту же пару', () => {
  // Это и есть условие доставки: подписку клиент выпустил под ключ ОДНОГО релея,
  // а разбудить его может любой, у кого осела очередь. Разойдись вывод — пуш
  // уйдёт с чужим ключом и push-сервис его отвергнет.
  const first = deviceVapidKeys(base.privateKey, ALICE);
  const second = deviceVapidKeys(base.privateKey, ALICE);
  assert.deepStrictEqual(second, first);
});

test('другой базовый секрет даёт другую пару для того же адреса', () => {
  // Одиночный релей (не член флота) не должен случайно выдать ключ, который
  // подписывает чужие подписки.
  const mine = deviceVapidKeys(base.privateKey, ALICE);
  const theirs = deviceVapidKeys(other.privateKey, ALICE);
  assert.notStrictEqual(mine.publicKey, theirs.publicKey);
});

test('негодный вход — null, а не кривая пара', () => {
  assert.strictEqual(deviceVapidKeys(base.privateKey, ''), null, 'пустой адрес');
  assert.strictEqual(deviceVapidKeys(base.privateKey, null), null, 'адреса нет');
  assert.strictEqual(deviceVapidKeys(base.privateKey, 42), null, 'адрес не строка');
  assert.strictEqual(deviceVapidKeys(null, ALICE), null, 'секрета нет');
  assert.strictEqual(deviceVapidKeys('короткий', ALICE), null, 'секрет не 32 байта');
  assert.strictEqual(deviceVapidKeys(base.publicKey, ALICE), null, 'публичная половина вместо приватной — 65 байт');
});

test('скаляр вне [1, n-1] отвергается', () => {
  const zero = Buffer.alloc(SCALAR_BYTES, 0);
  const order = Buffer.from(P256_ORDER.toString(16), 'hex');
  const belowOrder = Buffer.from((P256_ORDER - 1n).toString(16), 'hex');
  const one = Buffer.alloc(SCALAR_BYTES, 0);
  one[SCALAR_BYTES - 1] = 1;
  assert.strictEqual(scalarFromBytes(zero), null, 'ноль не задаёт точки');
  assert.strictEqual(scalarFromBytes(order), null, 'значение порядка группы недопустимо');
  assert.ok(scalarFromBytes(belowOrder), 'n-1 — крайнее допустимое значение');
  assert.ok(scalarFromBytes(one), 'единица допустима');
  assert.strictEqual(scalarFromBytes(Buffer.alloc(16, 7)), null, 'короткий вывод');
  assert.strictEqual(scalarFromBytes(null), null);
});

test('негодный скаляр пропускается, следующая попытка идёт в дело', () => {
  // Промах имеет вероятность порядка 2^-32 и живьём не случается никогда —
  // поэтому источник вывода подменяется. Без этой проверки ветка «попробовать
  // ещё раз» существовала бы только на бумаге.
  const outputs = [Buffer.alloc(SCALAR_BYTES, 0), crypto.hkdfSync('sha256', Buffer.alloc(SCALAR_BYTES, 9), Buffer.alloc(1), Buffer.alloc(1), SCALAR_BYTES)];
  let calls = 0;
  const pair = deviceVapidKeys(base.privateKey, ALICE, {
    hkdf: () => outputs[calls++] || outputs[1],
  });
  assert.strictEqual(calls, 2, 'первая попытка дала ноль — обязана быть вторая');
  assert.ok(pair && validVapidPair(pair.publicKey, pair.privateKey));
});

test('вывод, который не даёт годного скаляра, честно возвращает null', () => {
  let calls = 0;
  const pair = deviceVapidKeys(base.privateKey, ALICE, {
    hkdf: () => {
      calls += 1;
      return Buffer.alloc(SCALAR_BYTES, 0);
    },
  });
  assert.strictEqual(pair, null, 'кривой ключ хуже общего: пуш уйдёт и будет отвергнут');
  assert.strictEqual(calls, MAX_DERIVE_ATTEMPTS, 'попытки обязаны кончаться, а не крутиться вечно');
});

test('пара из скаляра: сжатая точка парой web-push не считается', () => {
  const one = Buffer.alloc(SCALAR_BYTES, 0);
  one[SCALAR_BYTES - 1] = 1;
  const pair = keyPairFromScalar(one);
  // Скаляр 1 даёт базовую точку кривой — публичная половина обязана совпасть с
  // независимо вычисленной.
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.setPrivateKey(one);
  assert.strictEqual(pair.publicKey, ecdh.getPublicKey(null, 'uncompressed').toString('base64url'));
  assert.strictEqual(pair.privateKey, one.toString('base64url'));
});

test('контакт: явная настройка оператора важнее всего', () => {
  assert.strictEqual(vapidSubject('wss://relay.example.com', 'mailto:abuse@example.org'), 'mailto:abuse@example.org');
  assert.strictEqual(vapidSubject('wss://relay.example.com', 'https://example.org/abuse'), 'https://example.org/abuse');
});

test('контакт по умолчанию — СВОЙ адрес релея, а не общая константа', () => {
  // Ключ на устройство ничего не даёт, если рядом едет фирменная константа: по
  // ней подписки склеиваются обратно в одну группу.
  const subject = vapidSubject('wss://relay.example.com:8443', null);
  assert.strictEqual(subject, 'https://relay.example.com:8443/');
  assert.notStrictEqual(subject, FALLBACK_SUBJECT, 'узел, знающий свой адрес, не должен представляться общей константой');
  assert.strictEqual(vapidSubject('https://relay.example.com', null), 'https://relay.example.com/');
});

test('контакт: мусорная настройка не проходит, а без своего адреса берётся запасной', () => {
  assert.strictEqual(vapidSubject('', null), FALLBACK_SUBJECT, 'без адреса узла и без настройки — запасной контакт');
  assert.strictEqual(vapidSubject('не адрес вовсе', null), FALLBACK_SUBJECT);
  assert.strictEqual(vapidSubject('ws://relay.example.com', null), FALLBACK_SUBJECT, 'без TLS обещать https-контакт нельзя');
  assert.strictEqual(vapidSubject('wss://relay.example.com', 'http://example.org/'), 'https://relay.example.com/', 'http-контакт RFC 8292 не разрешает');
  assert.strictEqual(vapidSubject('wss://relay.example.com', 'абы что'), 'https://relay.example.com/');
});

test('годность контакта проверяется отдельно и по протоколу', () => {
  assert.strictEqual(validSubject('https://example.org/'), 'https://example.org/');
  assert.strictEqual(validSubject('mailto:a@example.org'), 'mailto:a@example.org');
  assert.strictEqual(validSubject('ftp://example.org/'), null);
  assert.strictEqual(validSubject('https:///'), null, 'https без хоста — не контакт');
  assert.strictEqual(validSubject(''), null);
  assert.strictEqual(validSubject(null), null);
  assert.strictEqual(validSubject('https://example.org/' + 'a'.repeat(300)), null, 'потолок длины');
});

console.log(`\nvapid identity: ${passed} passed`);
