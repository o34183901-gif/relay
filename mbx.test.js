const assert = require('assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const mbx = require('./mbx');
const gcs = require('./mailboxGcs');
const { createStore } = require('./store');
let passed = 0;
const ok = (name) => {
  console.log('  ✓ ' + name);
  passed += 1;
};
const NOW = 1_800_000_000_000;
const SLOT = mbx.slotOf(NOW);
const valueHash = (record) =>
  crypto
    .createHash('sha256')
    .update(Buffer.from(record.value))
    .update(Buffer.from(record.mac))
    .digest();
function record({ key = crypto.randomBytes(mbx.KEY_BYTES), slot = SLOT } = {}) {
  return {
    key: Buffer.from(key),
    value: crypto.randomBytes(mbx.VALUE_BYTES),
    mac: crypto.randomBytes(mbx.MAC_BYTES),
    slot,
  };
}

console.log('\nПЯЩ-1: общий ящик на релее\n');
{
  const two = Buffer.concat([
    mbx.packRecords([record()]),
    mbx.packRecords([record()]),
  ]);
  const parsed = mbx.parsePut(two, { now: NOW, slot: SLOT });
  assert.ok(parsed, 'годная пачка обязана разбираться');
  assert.strictEqual(parsed.length, 2);
  assert.strictEqual(parsed[0].key.length, mbx.KEY_BYTES);
  assert.strictEqual(parsed[0].value.length, mbx.VALUE_BYTES);
  for (const [what, bytes, opts] of [
    ['не байты', 'строка', {}],
    ['пусто', Buffer.alloc(0), {}],
    ['длина не кратна записи', Buffer.alloc(mbx.RECORD_BYTES + 1), {}],
    ['на одну больше предела', Buffer.alloc(mbx.RECORD_BYTES * (mbx.MAX_PUT_RECORDS + 1)), {}],
    ['мегабайт', Buffer.alloc(1024 * 1024), {}],
    ['отрезок из прошлого', mbx.packRecords([record()]), { slot: SLOT - 5 }],
    ['отрезок из будущего', mbx.packRecords([record()]), { slot: SLOT + 5 }],
    ['отрезок не число', mbx.packRecords([record()]), { slot: 'вчера' }],
  ]) {
    assert.strictEqual(
      mbx.parsePut(bytes, { now: NOW, slot: SLOT, ...opts }),
      null,
      `обязано отвергаться: ${what}`
    );
  }
  assert.ok(mbx.parsePut(mbx.packRecords([record()]), { now: NOW, slot: SLOT - 1 }));
  ok('кадр разбирается строго: длина, число записок и отрезок');
}

{
  const keys = [];
  for (let i = 0; i < 500; i += 1) keys.push(crypto.randomBytes(mbx.KEY_BYTES));
  const first = mbx.buildDigest(keys);
  const second = mbx.buildDigest([...keys].reverse());
  assert.deepStrictEqual(
    first.bits.toString('hex'),
    second.bits.toString('hex'),
    'сводка обязана зависеть только от содержимого ящика'
  );
  const decoded = gcs.decode({ p: first.p, n: first.n, bits: Uint8Array.from(first.bits) });
  assert.ok(decoded, 'телефон обязан разобрать сводку релея');
  for (const key of keys) {
    assert.strictEqual(gcs.probablyHas(decoded, Uint8Array.from(key)), true, 'ключ потерялся');
  }
  ok('сводка одинакова для всех и разбирается тем же кодом, что на телефоне');
}
{
  let built = 0;
  const cache = mbx.createDigestCache({
    build: (keys) => {
      built += 1;
      return mbx.buildDigest(keys);
    },
  });
  const keys = [crypto.randomBytes(mbx.KEY_BYTES)];
  for (let i = 0; i < 10; i += 1) cache.get(7, keys);
  assert.strictEqual(built, 1, 'десять просьб — один пересчёт');
  cache.get(8, keys);
  assert.strictEqual(built, 2, 'ящик изменился — пересчёт обязателен');
  ok('сводка пересчитывается только когда ящик изменился');
}
{
  const size = 32000;
  const honest = mbx.bucketDepth(size);
  assert.ok(size / 2 ** honest >= mbx.BUCKET_MIN, 'честная глубина оставляет сотню в корзине');
  assert.strictEqual(mbx.depthAllowed(honest, size), true);
  assert.strictEqual(mbx.depthAllowed(honest + 1, size), true, 'на один шаг уже — терпимо');
  assert.strictEqual(mbx.depthAllowed(honest + 2, size), false, 'а дальше — отказ');
  assert.strictEqual(mbx.depthAllowed(mbx.MAX_DEPTH + 1, size), false);
  assert.strictEqual(mbx.depthAllowed(-1, size), false);
  assert.strictEqual(mbx.depthAllowed(1.5, size), false);
  ok('слишком узкая корзина не отдаётся даже по просьбе');
}
{
  const depth = 6;
  const key = Buffer.from('4200000000000000000000000000000000000000000000000000000000000000', 'hex');
  const bucket = mbx.bucketOf(key, depth);
  const { low, high } = mbx.bucketRange(bucket, depth);
  assert.ok(Buffer.compare(low, key) <= 0 && Buffer.compare(high, key) >= 0, 'ключ внутри границ');
  const other = mbx.bucketRange(bucket + 1, depth);
  assert.ok(Buffer.compare(other.low, high) > 0, 'корзины не пересекаются');
  assert.strictEqual(mbx.bucketOf(key, 0), 0, 'на нулевой глубине корзина одна');
  assert.strictEqual(mbx.bucketRange(2 ** depth, depth), null, 'за пределом глубины — отказ');
  assert.strictEqual(mbx.bucketRange(-1, depth), null);
  assert.strictEqual(mbx.bucketRange(1.5, depth), null);
  assert.strictEqual(mbx.bucketRange(1, 0), null, 'на нулевой глубине второй корзины нет');
  assert.ok(mbx.bucketRange(0, 0), 'а нулевая — есть');
  ok('границы корзины не пересекаются, а несуществующая корзина даёт отказ');
}
{
  const store = createStore(':memory:');
  const real = record();
  const forged = { ...real, value: crypto.randomBytes(mbx.VALUE_BYTES) };
  assert.strictEqual(store.mbxPut([real], valueHash), 1, 'первая записка ложится');
  assert.strictEqual(store.mbxPut([real], valueHash), 0, 'та же вторым путём — не новая');
  assert.strictEqual(store.mbxCount(), 1);
  assert.strictEqual(store.mbxPut([forged], valueHash), 1, 'подделка ложится ОТДЕЛЬНОЙ строкой');
  assert.strictEqual(store.mbxCount(), 2, 'настоящая обязана остаться рядом с подделкой');
  const { low, high } = mbx.bucketRange(0, 0);
  const bucket = store.mbxBucket(low, high, 100);
  assert.strictEqual(bucket.length, 2, 'адресат получит обе и сам разберётся по метке');
  ok('повтор не плодит строк, а подделка не вытесняет настоящую записку');
}
{
  const store = createStore(':memory:');
  const first = [record(), record()];
  store.mbxPut(first, valueHash);
  const seen = store.mbxVersion();
  store.mbxPut([record()], valueHash);
  const fresh = store.mbxAfter(seen, mbx.SYNC_LIMIT);
  assert.strictEqual(fresh.length, 1, 'сосед обязан получить только появившееся после его курсора');
  assert.strictEqual(store.mbxAfter(store.mbxVersion(), 10).length, 0, 'нового нет — ничего');
  assert.strictEqual(store.mbxAfter(0, 10).length, 3, 'с нуля — всё');
  ok('репликация отдаёт только то, чего сосед ещё не видел');
}
{
  const store = createStore(':memory:');
  store.mbxPut([record({ slot: SLOT - 3 }), record({ slot: SLOT - 3 })], valueHash);
  store.mbxPut([record({ slot: SLOT })], valueHash);
  assert.strictEqual(store.mbxCount(), 3);
  assert.strictEqual(store.mbxExpire(SLOT - 1), 2, 'старые отрезки обязаны уйти');
  assert.strictEqual(store.mbxCount(), 1, 'а сегодняшний — остаться');
  store.mbxPut([record({ slot: SLOT - 1 }), record({ slot: SLOT - 1 })], valueHash);
  assert.strictEqual(store.mbxSlotCount(SLOT - 1), 2, 'в старом отрезке две записки');
  assert.strictEqual(store.mbxEvictSome(1), 1, 'убирается ровно запрошенное, а не весь отрезок');
  assert.strictEqual(store.mbxSlotCount(SLOT - 1), 1, 'вторая записка того же отрезка обязана остаться');
  assert.strictEqual(store.mbxCount(), 2);
  assert.strictEqual(store.mbxEvictSome(0), 0, 'нулевая порция ничего не трогает');
  assert.strictEqual(store.mbxEvictSome(50), 1, 'порция больше отрезка выносит его, но не соседние');
  assert.strictEqual(store.mbxCount(), 1, 'сегодняшняя записка не тронута');
  assert.strictEqual(store.mbxOldestSlot(), SLOT, 'старейшим стал сегодняшний отрезок');
  ok('протухшее уходит по сроку, а переполнение режет порцией, а не шестью часами разом');
}
{
  let honestLost = 0;
  const ROUNDS = 40;
  for (let round = 0; round < ROUNDS; round += 1) {
    const store = createStore(':memory:');
    const honest = record({ slot: SLOT });
    store.mbxPut([honest], valueHash);
    const flood = [];
    for (let i = 0; i < 9; i += 1) flood.push(record({ slot: SLOT }));
    store.mbxPut(flood, valueHash);
    store.mbxEvictSome(5);
    const left = store.mbxBucket(Buffer.alloc(32), Buffer.alloc(32, 0xff), 100);
    const survived = left.some((row) => Buffer.compare(row.key, Buffer.from(honest.key)) === 0);
    if (!survived) honestLost += 1;
  }
  assert.ok(
    honestLost > 0 && honestLost < ROUNDS,
    `выбор внутри отрезка обязан быть равномерным: положенная первой потерялась ${honestLost} раз из ${ROUNDS}, ` +
      'а при вытеснении по времени вставки это было бы всегда'
  );
  ok('ВЫС-31: внутри отрезка выбор равномерен, и заливка бьёт прежде всего по заливающему');
}
{
  const store = createStore(':memory:');
  const old = [];
  for (let i = 0; i < 40; i += 1) old.push(record({ slot: SLOT - 1 }));
  store.mbxPut(old, valueHash);
  const flood = [];
  for (let i = 0; i < 60; i += 1) flood.push(record({ slot: SLOT }));
  store.mbxPut(flood, valueHash);
  assert.strictEqual(store.mbxCount(), 100);
  const removed = store.mbxTrimTo(90);
  assert.ok(removed > 0, 'переполненный ящик обязан сводиться к потолку');
  assert.ok(store.mbxCount() <= 90, 'после уборки ящик обязан быть под потолком');
  assert.ok(
    store.mbxSlotCount(SLOT - 1) > 0,
    'вчерашний отрезок не имеет права исчезнуть целиком: это ровно те записки, за которыми придут'
  );
  assert.ok(
    store.mbxSlotCount(SLOT - 1) >= 25,
    `вынесено слишком много вчерашнего: осталось ${store.mbxSlotCount(SLOT - 1)} из 40 при превышении в 10`
  );
  assert.strictEqual(store.mbxSlotCount(SLOT), 60, 'сегодняшний отрезок уборка не трогает, пока есть старее');
  assert.strictEqual(store.mbxTrimTo(1000), 0, 'непереполненный ящик трогать не за чем');
  ok('ВЫС-31: сведение к потолку убирает лишнее, а не выносит старейший отрезок');
}
{
  const at = SLOT * mbx.SLOT_MS;
  assert.strictEqual(mbx.isExpired({ slot: SLOT }, at), false, 'свежая жива');
  assert.strictEqual(mbx.isExpired({ slot: SLOT }, at + mbx.TTL_MS - 1), false);
  assert.strictEqual(mbx.isExpired({ slot: SLOT }, at + mbx.TTL_MS), true, 'по сроку — мертва');
  assert.strictEqual(mbx.isExpired(null, at), true, 'ничего — тоже мертво');
  assert.ok(mbx.TTL_MS > 2 * mbx.SLOT_MS, 'срок обязан покрывать два отрезка и запас на часы');
  ok(`записка живёт ${(mbx.TTL_MS / 3600000).toFixed(0)} ч — два отрезка и запас на часы`);
}
{
  let reads = 0;
  const cache = mbx.createDigestCache();
  const keys = [crypto.randomBytes(mbx.KEY_BYTES)];
  const loadKeys = () => {
    reads += 1;
    return keys;
  };
  for (let i = 0; i < 50; i += 1) cache.get(3, loadKeys);
  assert.strictEqual(reads, 1, 'пятьдесят просьб — одно чтение ящика, а не пятьдесят');
  cache.get(4, loadKeys);
  assert.strictEqual(reads, 2, 'ящик изменился — читаем заново');
  ok('КРИТ-04: чтение ящика происходит при изменении, а не при просьбе');
}
{
  const cache = mbx.createDigestCache();
  const keys = [crypto.randomBytes(mbx.KEY_BYTES), crypto.randomBytes(mbx.KEY_BYTES)];
  const first = cache.get(1, () => keys);
  const again = cache.get(1, () => keys);
  assert.ok(typeof first.bitsBase64 === 'string' && first.bitsBase64, 'строка ответа посчитана заранее');
  assert.strictEqual(
    first.bitsBase64,
    Buffer.from(first.bits).toString('base64'),
    'и она обязана быть той же самой, что и раньше кодировалась на лету'
  );
  assert.strictEqual(again, first, 'повторная просьба получает ТОТ ЖЕ объект — работы не делается вовсе');
  ok('КРИТ-04: строка ответа считается один раз вместе со сводкой');
}
{
  let builds = 0;
  const cache = mbx.createDigestCache({
    build: (keys) => {
      builds += 1;
      return mbx.buildDigest(keys);
    },
  });
  const keys = [crypto.randomBytes(mbx.KEY_BYTES)];
  assert.strictEqual(cache.refresh(1, () => keys), true, 'первое изменение — пересчёт нужен');
  assert.strictEqual(builds, 1);
  assert.strictEqual(cache.refresh(1, () => keys), false, 'ящик не менялся — пересчитывать нечего');
  assert.strictEqual(builds, 1, 'повторное событие не должно стоить пересчёта');
  let reads = 0;
  cache.get(1, () => {
    reads += 1;
    return keys;
  });
  assert.strictEqual(reads, 0, 'просьба после пересчёта не делает вообще ничего');
  ok('КРИТ-04: сводка готовится по событию изменения, а не по просьбе');
}
{
  const store = createStore(':memory:');
  const oldSlot = SLOT - 8;
  store.mbxPut([record({ slot: oldSlot }), record({ slot: oldSlot })], valueHash);
  store.mbxPut([record({ slot: SLOT })], valueHash);
  const seqBefore = store.mbxVersion();
  const revBefore = store.mbxRevision();
  assert.strictEqual(store.mbxCount(), 3);
  const removed = store.mbxExpire(oldSlot);
  assert.strictEqual(removed, 2, 'старый отрезок вычищен');
  assert.strictEqual(store.mbxVersion(), seqBefore, 'курсор репликации удаления НЕ заметил');
  assert.notStrictEqual(store.mbxRevision(), revBefore, 'а ревизия обязана заметить');
  assert.strictEqual(store.mbxCount(), 1, 'и счётчик записок обязан обновиться вместе с ней');
  ok('КРИТ-04: версия сводки замечает чистку ящика, а не только пополнение');
}
{
  const store = createStore(':memory:');
  const one = record();
  store.mbxPut([one], valueHash);
  const rev = store.mbxRevision();
  store.mbxPut([one], valueHash);
  assert.strictEqual(store.mbxRevision(), rev, 'повтор ничего не изменил — и ревизия та же');
  assert.strictEqual(store.mbxEvictSome(1), 1);
  assert.notStrictEqual(store.mbxRevision(), rev, 'вытеснение — изменение');
  ok('КРИТ-04: ревизия растёт от изменений, а не от обращений');
}
{
  const keys = [];
  for (let i = 0; i < 50; i += 1) keys.push(crypto.randomBytes(mbx.KEY_BYTES));
  let builds = 0;
  const cache = mbx.createDigestCache({
    build: (list) => {
      builds += 1;
      return { n: list.length, p: 8, bits: new Uint8Array(4) };
    },
  });
  const at = 1_700_000_000_000;
  assert.strictEqual(cache.refreshIfDue(1, () => keys, { now: at, minIntervalMs: 1000 }), true);
  assert.strictEqual(builds, 1, 'первый пересчёт обязан пройти сразу');
  for (let i = 1; i <= 10; i += 1) {
    keys.push(crypto.randomBytes(mbx.KEY_BYTES));
    cache.refreshIfDue(1 + i, () => keys, { now: at + i * 50, minIntervalMs: 1000 });
  }
  assert.strictEqual(builds, 1, `внутри окна пересчётов ${builds} вместо одного — узел встанет на каждой укладке`);
  const answer = cache.get(11, () => keys);
  assert.strictEqual(builds, 2, 'просьба о сводке обязана пересчитать её, если пересчёт был отложен');
  assert.strictEqual(answer.n, keys.length, 'ответ обязан быть по текущему содержимому ящика, а не по вчерашнему');
  assert.strictEqual(cache.version(), 11);
  keys.push(crypto.randomBytes(mbx.KEY_BYTES));
  assert.strictEqual(
    cache.refreshIfDue(12, () => keys, { now: at + 5000, minIntervalMs: 1000 }),
    true,
    'после окна пересчёт обязан идти заранее — иначе первая же просьба оплатит обход целиком'
  );
  const before = builds;
  assert.strictEqual(cache.refreshIfDue(12, () => keys, { now: at + 99999, minIntervalMs: 0 }), false);
  assert.strictEqual(builds, before, 'без изменений считать нечего');
  const relaySource = fs.readFileSync(path.join(__dirname, 'relay.js'), 'utf8');
  const start = relaySource.indexOf('function mbxRefreshDigest(');
  assert.ok(start > 0, 'пересчёт сводки не найден — проверка смотрит не туда');
  const body = relaySource.slice(start, start + 700);
  assert.ok(
    body.includes('mbxDigest.refreshIfDue('),
    'пересчёт снова идёт на каждую укладку — узел встаёт почти на секунду на каждой из них'
  );
  assert.ok(
    body.includes('minIntervalMs: MBX_DIGEST_MIN_INTERVAL_MS'),
    'окно объединения не передаётся — правило есть, а работы не делает'
  );
  ok('ПРФ-21: пересчёт сводки объединяется по времени, но ответ не отстаёт');
}
console.log(`\nПЯЩ-1 (релей): ${passed} проверок пройдено`);