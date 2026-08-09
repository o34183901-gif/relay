/**
 * httpRateLimit.test.js — счётчик обращений в окне (ВЫС-19).
 *
 * HTTP /mbx — усилитель ×30000 без ограничения частоты. Здесь проверяется
 * правило, которое частоту ограничивает.
 *
 * Запуск: node server/httpRateLimit.test.js
 */

'use strict';

const assert = require('assert');
const { createHttpRateLimit } = require('./httpRateLimit');

let passed = 0;
function test(name, fn) {
  fn();
  passed += 1;
  console.log('  ✓ ' + name);
}
console.log('счётчик обращений в окне (ВЫС-19)');

test('в пределах окна пропускает max, дальше отказывает', () => {
  const rl = createHttpRateLimit({ max: 3, windowMs: 1000 });
  assert.strictEqual(rl.allow('ip', 0), true);
  assert.strictEqual(rl.allow('ip', 100), true);
  assert.strictEqual(rl.allow('ip', 200), true);
  assert.strictEqual(rl.allow('ip', 300), false, 'четвёртое обращение в окне — отказ');
});

test('окно закрывается — счёт начинается заново', () => {
  const rl = createHttpRateLimit({ max: 2, windowMs: 1000 });
  assert.strictEqual(rl.allow('ip', 0), true);
  assert.strictEqual(rl.allow('ip', 1), true);
  assert.strictEqual(rl.allow('ip', 2), false);
  assert.strictEqual(rl.allow('ip', 1001), true, 'за границей окна лимит сброшен');
});

test('ключи считаются раздельно: один флудер не блокирует других', () => {
  const rl = createHttpRateLimit({ max: 1, windowMs: 1000 });
  assert.strictEqual(rl.allow('флудер', 0), true);
  assert.strictEqual(rl.allow('флудер', 1), false);
  assert.strictEqual(rl.allow('честный', 1), true, 'у другого адреса своё окно');
});

test('пустой и отсутствующий ключ не роняют счёт', () => {
  const rl = createHttpRateLimit({ max: 1, windowMs: 1000 });
  assert.strictEqual(rl.allow(undefined, 0), true);
  assert.strictEqual(rl.allow(null, 1), false, 'null и undefined — один и тот же ключ');
  assert.strictEqual(rl.allow('', 2), false, 'и пустая строка тоже');
});

test('карта окон не растёт без предела', () => {
  const rl = createHttpRateLimit({ max: 5, windowMs: 1000 });
  // Много уникальных адресов в одном окне — карта растёт; следующее окно за
  // порогом уборки их выметает.
  for (let i = 0; i < 5000; i += 1) rl.allow('ip-' + i, 0);
  const peak = rl.size();
  assert.ok(peak >= 4096, 'до уборки карта отражает поток адресов');
  // Обращение сильно позже — старые окна протухли, уборка их снимет.
  rl.allow('новый', 10000);
  assert.ok(rl.size() < peak, 'протухшие окна выметены');
});

console.log(`\nсчётчик обращений в окне: ${passed} проверок пройдено`);
