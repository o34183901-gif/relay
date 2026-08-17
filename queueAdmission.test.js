'use strict';
const assert = require('assert');
const { QUEUE_RESERVE, admitEnvelope } = require('./queueAdmission');
let passed = 0;
function test(name, fn) {
  fn();
  passed += 1;
  console.log('  ✓ ' + name);
}
console.log('приём в очередь получателя (ВЫС-15)');
const LIMITS = { maxPerUser: 500, maxPerSender: 100, reserve: 100 };
test('первое сообщение незнакомца проходит как раньше', () => {
  assert.deepStrictEqual(
    admitEnvelope({ ...LIMITS, recipientCount: 0, strangerCount: 0, senderCount: 0 }),
    { admit: true, evict: null }
  );
  assert.deepStrictEqual(
    admitEnvelope({ ...LIMITS, recipientCount: 399, strangerCount: 399, senderCount: 99 }),
    { admit: true, evict: null }
  );
});

test('сценарий аудита: пять личностей больше не закрывают ящик', () => {
  assert.deepStrictEqual(
    admitEnvelope({ ...LIMITS, recipientCount: 400, strangerCount: 400, senderCount: 0 }),
    { admit: false, evict: null },
    'пятая личность упирается в резерв, а не в потолок очереди'
  );
  assert.deepStrictEqual(
    admitEnvelope({
      ...LIMITS,
      recipientCount: 400,
      strangerCount: 400,
      senderCount: 0,
      correspondent: true,
    }),
    { admit: true, evict: null },
    'резерв существует ровно для него'
  );
});
test('корреспондент у полной очереди вытесняет чужой спам, а не отбрасывается', () => {
  assert.deepStrictEqual(
    admitEnvelope({
      ...LIMITS,
      recipientCount: 500,
      strangerCount: 400,
      senderCount: 0,
      correspondent: true,
    }),
    { admit: true, evict: 'stranger' }
  );
});
test('очередь, полная письмами корреспондентов, — честная загрузка, а не абуз', () => {
  assert.deepStrictEqual(
    admitEnvelope({
      ...LIMITS,
      recipientCount: 500,
      strangerCount: 0,
      senderCount: 0,
      correspondent: true,
    }),
    { admit: false, evict: null }
  );
});
test('свой потолок пары ротирует свои конверты — и у корреспондента тоже', () => {
  for (const correspondent of [false, true]) {
    assert.deepStrictEqual(
      admitEnvelope({ ...LIMITS, recipientCount: 250, strangerCount: 0, senderCount: 100, correspondent }),
      { admit: true, evict: 'own' },
      'квота пары одна на всех: и корреспондент не занимает чужую очередь целиком'
    );
  }
});
test('полная очередь со своими конвертами — ротация своих, чужие неприкосновенны', () => {
  assert.deepStrictEqual(
    admitEnvelope({ ...LIMITS, recipientCount: 500, strangerCount: 100, senderCount: 5 }),
    { admit: true, evict: 'own' }
  );
});
test('незнакомец у полной очереди получает drop-new, как раньше', () => {
  assert.deepStrictEqual(
    admitEnvelope({ ...LIMITS, recipientCount: 500, strangerCount: 400, senderCount: 0 }),
    { admit: false, evict: null }
  );
});
test('легаси-кадр без отправителя ведёт себя по-старому', () => {
  assert.deepStrictEqual(
    admitEnvelope({ ...LIMITS, recipientCount: 500, strangerCount: 0, senderKnown: false }),
    { admit: true, evict: 'oldest' }
  );
  assert.deepStrictEqual(
    admitEnvelope({ ...LIMITS, recipientCount: 10, strangerCount: 10, senderKnown: false }),
    { admit: true, evict: null },
    'и резерв на него не распространяется — незнакомцем он не считается'
  );
});
test('резерв можно выключить нулём — остаются прежние правила', () => {
  assert.deepStrictEqual(
    admitEnvelope({ ...LIMITS, reserve: 0, recipientCount: 499, strangerCount: 499, senderCount: 0 }),
    { admit: true, evict: null }
  );
});
test('резерв не шире очереди: перекос настроек не запирает её целиком', () => {
  assert.deepStrictEqual(
    admitEnvelope({ maxPerUser: 50, maxPerSender: 10, reserve: 500, recipientCount: 0, strangerCount: 0 }),
    { admit: false, evict: null },
    'формально это отказ — но только когда оператор сам так настроил'
  );
  assert.ok(QUEUE_RESERVE < 500, 'штатный резерв заведомо уже штатной очереди');
});
test('без потолков всё проходит — потолки задаёт вызывающий', () => {
  assert.deepStrictEqual(admitEnvelope(), { admit: true, evict: null });
  assert.deepStrictEqual(
    admitEnvelope({ recipientCount: 10000, strangerCount: 10000, senderCount: 10000 }),
    { admit: true, evict: null }
  );
});
console.log(`\nприём в очередь получателя: ${passed} проверок пройдено`);