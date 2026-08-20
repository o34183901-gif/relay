const assert = require('assert');
const { chatNotificationTag, createPushGate } = require('./notifications');
let passed = 0;
function test(name, fn) {
  fn();
  passed++;
  console.log('  ✓ ' + name);
}
console.log('уведомления (ПРФ-4)');
const NOW = 1_800_000_000_000;
const ALICE = 'YWxpY2UtcHVibGljLWtleQ==';
const BOB = 'Ym9iLXB1YmxpYy1rZXk=';
test('признак чата не содержит адреса отправителя', () => {
  const tag = chatNotificationTag(ALICE);
  assert.ok(tag.length > 0);
  assert.ok(!tag.includes(ALICE), 'адрес не должен утекать в тело уведомления');
});

test('признак стабилен для одного отправителя и различается у разных', () => {
  assert.strictEqual(chatNotificationTag(ALICE), chatNotificationTag(ALICE));
  assert.notStrictEqual(chatNotificationTag(ALICE), chatNotificationTag(BOB));
});

test('REL-30: метка солится — без соли не воспроизводится, разные соли различны', () => {
  const crypto = require('crypto');
  const saltA = crypto.createHash('sha256').update('соль-узла-A').digest();
  const saltB = crypto.createHash('sha256').update('соль-узла-B').digest();
  assert.notStrictEqual(chatNotificationTag(ALICE, saltA), chatNotificationTag(ALICE), 'соль меняет метку');
  assert.notStrictEqual(chatNotificationTag(ALICE, saltA), chatNotificationTag(ALICE, saltB), 'разные соли — разные метки');
  assert.strictEqual(chatNotificationTag(ALICE, saltA), chatNotificationTag(ALICE, saltA), 'стабильна при одной соли');
});
test('признак безопасен как тег уведомления (base64url, ограниченная длина)', () => {
  const tag = chatNotificationTag(ALICE);
  assert.ok(/^[A-Za-z0-9_-]{1,64}$/.test(tag), 'тег: ' + tag);
});

test('пустой адрес даёт пустой признак (старый путь без веера устройств)', () => {
  assert.strictEqual(chatNotificationTag(''), '');
  assert.strictEqual(chatNotificationTag(null), '');
});

test('второе сообщение из ТОГО ЖЕ чата в окне не будит повторно', () => {
  const gate = createPushGate({ windowMs: 20000 });
  assert.strictEqual(gate.allow('вова', 'чат-А', NOW), true);
  assert.strictEqual(gate.allow('вова', 'чат-А', NOW + 5000), false);
});

test('сообщение из ДРУГОГО чата в том же окне будит — это и было сломано', () => {
  const gate = createPushGate({ windowMs: 20000 });
  assert.strictEqual(gate.allow('вова', 'чат-А', NOW), true);
  assert.strictEqual(gate.allow('вова', 'чат-Б', NOW + 1000), true);
  assert.strictEqual(gate.allow('вова', 'чат-В', NOW + 2000), true);
});
test('после окна тот же чат снова будит', () => {
  const gate = createPushGate({ windowMs: 20000 });
  gate.allow('вова', 'чат-А', NOW);
  assert.strictEqual(gate.allow('вова', 'чат-А', NOW + 20000), true);
});
test('потолок на получателя не даёт превратить это в усилитель флуда', () => {
  const gate = createPushGate({ windowMs: 20000, maxPerRecipient: 3 });
  assert.strictEqual(gate.allow('жертва', 'спам-1', NOW), true);
  assert.strictEqual(gate.allow('жертва', 'спам-2', NOW + 100), true);
  assert.strictEqual(gate.allow('жертва', 'спам-3', NOW + 200), true);
  assert.strictEqual(gate.allow('жертва', 'спам-4', NOW + 300), false);
});
test('потолок считается на получателя, а не глобально', () => {
  const gate = createPushGate({ windowMs: 20000, maxPerRecipient: 1 });
  assert.strictEqual(gate.allow('первый', 'чат-А', NOW), true);
  assert.strictEqual(gate.allow('второй', 'чат-А', NOW), true);
  assert.strictEqual(gate.allow('первый', 'чат-Б', NOW), false);
});
test('окно потолка сдвигается вместе со временем', () => {
  const gate = createPushGate({ windowMs: 20000, maxPerRecipient: 1 });
  assert.strictEqual(gate.allow('вова', 'чат-А', NOW), true);
  assert.strictEqual(gate.allow('вова', 'чат-Б', NOW + 100), false);
  assert.strictEqual(gate.allow('вова', 'чат-Б', NOW + 20000), true);
});
test('пустой получатель не будит и состояние не копит', () => {
  const gate = createPushGate();
  assert.strictEqual(gate.allow('', 'чат-А', NOW), false);
  assert.strictEqual(gate.size(), 0);
});
test('чистка убирает протухшие окна', () => {
  const gate = createPushGate({ windowMs: 20000 });
  gate.allow('вова', 'чат-А', NOW);
  assert.ok(gate.size() > 0);
  gate.sweep(NOW + 10 * 20000 + 1);
  assert.strictEqual(gate.size(), 0);
});
console.log('\nуведомления: ' + passed + ' passed');