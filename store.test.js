const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const Database = require('better-sqlite3');
const { createStore } = require('./store');
let passed = 0;
let chain = Promise.resolve();
function test(name, fn) {
  chain = chain.then(async () => {
    await fn();
    passed++;
    console.log('  ✓ ' + name);
  });
}
console.log('relay store (sqlite)');
function fresh() {
  return createStore(':memory:');
}

test('enqueue + queueFor: порядок по времени, распаковка конверта', () => {
  const s = fresh();
  s.enqueue({ id: 'a', to: 'bob', from: 'alice', envelope: { cipher: '1' }, ts: 1 });
  s.enqueue({ id: 'b', to: 'bob', from: 'alice', envelope: { cipher: '2' }, ts: 2 });
  const q = s.queueFor('bob');
  assert.strictEqual(q.length, 2);
  assert.deepStrictEqual(q.map((x) => x.id), ['a', 'b']);
  assert.deepStrictEqual(q[0].envelope, { cipher: '1' });
  assert.strictEqual(q[0].from, 'alice');
  s.close();
});

test('ack: удаляет по id и возвращает адрес отправителя; чужой to игнорируется', () => {
  const s = fresh();
  s.enqueue({ id: 'a', to: 'bob', from: 'alice', envelope: {}, ts: 1 });
  assert.strictEqual(s.ack('carol', 'a'), null, 'нельзя ack чужой очереди');
  assert.strictEqual(s.ack('bob', 'a'), 'alice');
  assert.strictEqual(s.queueFor('bob').length, 0);
  assert.strictEqual(s.ack('bob', 'a'), null, 'повторный ack — уже нет');
  s.close();
});

test('maxPerUser: вытесняется самый старый', () => {
  const s = fresh();
  for (let i = 0; i < 5; i++) s.enqueue({ id: 'm' + i, to: 'bob', envelope: {}, ts: i, maxPerUser: 3 });
  const q = s.queueFor('bob');
  assert.strictEqual(q.length, 3);
  assert.deepStrictEqual(q.map((x) => x.id), ['m2', 'm3', 'm4']);
  s.close();
});

test('maxTotal (H-03): глобальный потолок ОТКЛОНЯЕТ новый, чужое старьё не вытесняет', () => {
  const s = fresh();
  for (let i = 0; i < 3; i++) {
    const ok = s.enqueue({ id: 'g' + i, to: 'u' + i, envelope: {}, ts: i, maxPerUser: 500, maxTotal: 3 });
    assert.strictEqual(ok, true, 'до потолка конверты принимаются');
  }
  const stored = s.enqueue({ id: 'g3', to: 'u3', envelope: {}, ts: 3, maxPerUser: 500, maxTotal: 3 });
  assert.strictEqual(stored, false, 'при полной глобальной очереди новый конверт отклонён');
  assert.strictEqual(s.stats().totalQueued, 3, 'всего не больше глобального потолка');
  assert.ok(s.getItem('g0'), 'старейший чужой конверт НЕ вытеснен');
  assert.strictEqual(s.getItem('g3'), null, 'отклонённый конверт не сохранён');
  s.close();
});

test('S5 maxPerSender: флудер вытесняет ТОЛЬКО свои сообщения, чужие целы', () => {
  const s = fresh();
  s.enqueue({ id: 'real', to: 'bob', from: 'carol', envelope: {}, ts: 1, maxPerUser: 500, maxPerSender: 2 });
  for (let i = 0; i < 5; i++) {
    s.enqueue({ id: 'spam' + i, to: 'bob', from: 'mallory', envelope: {}, ts: 10 + i, maxPerUser: 500, maxPerSender: 2 });
  }
  const ids = s.queueFor('bob').map((x) => x.id);
  assert.ok(ids.includes('real'), 'сообщение честного контакта НЕ вытеснено флудером');
  const spam = ids.filter((x) => x.startsWith('spam'));
  assert.strictEqual(spam.length, 2, 'у флудера не больше его квоты (self-eviction)');
  s.close();
});

test('СРВ-2: Sybil-флудер (свежие identity) не вытесняет чужое из полной очереди', () => {
  const s = fresh();
  for (let i = 0; i < 3; i++) {
    s.enqueue({ id: 'real' + i, to: 'bob', from: 'carol', envelope: {}, ts: i, maxPerUser: 3 });
  }
  for (let i = 0; i < 5; i++) {
    const stored = s.enqueue({ id: 'sybil' + i, to: 'bob', from: 'att' + i, envelope: {}, ts: 100 + i, maxPerUser: 3 });
    assert.strictEqual(stored, false, 'свежий отправитель при полной очереди отклонён');
  }
  assert.deepStrictEqual(
    s.queueFor('bob').map((x) => x.id),
    ['real0', 'real1', 'real2'],
    'реальные сообщения жертвы не вытеснены Sybil-флудом'
  );
  s.close();
});

test('ВЫС-15: пять личностей не закрывают ящик — резерв достаётся корреспонденту', () => {
  const s = fresh();
  const limits = { maxPerUser: 10, maxPerSender: 4, reserve: 4, reciprocityTtlMs: 1000 };
  s.enqueue({ id: 'из-дома', to: 'carol', from: 'bob', envelope: {}, ts: 1, ...limits });
  let admitted = 0;
  for (let i = 0; i < 12; i++) {
    if (s.enqueue({ id: 'спам' + i, to: 'bob', from: 'личность' + (i % 3), envelope: {}, ts: 10 + i, ...limits })) {
      admitted += 1;
    }
  }
  assert.strictEqual(admitted, 6, 'незнакомцам достаётся очередь без резерва, сколько бы личностей ни было');
  for (let i = 0; i < 4; i++) {
    assert.strictEqual(
      s.enqueue({ id: 'письмо' + i, to: 'bob', from: 'carol', envelope: {}, ts: 100 + i, ...limits }),
      true,
      'письмо корреспондента проходит в резерв'
    );
  }
  const ids = s.queueFor('bob').map((x) => x.id);
  assert.strictEqual(ids.filter((x) => x.startsWith('письмо')).length, 4, 'все письма на месте');
  s.close();
});

test('ВЫС-15: корреспондент у полной очереди вытесняет спам незнакомца, а не отбрасывается', () => {
  const s = fresh();
  const limits = { maxPerUser: 6, maxPerSender: 6, reserve: 2, reciprocityTtlMs: 1000 };
  s.enqueue({ id: 'из-дома', to: 'carol', from: 'bob', envelope: {}, ts: 1, ...limits });
  s.enqueue({ id: 'письмо0', to: 'bob', from: 'carol', envelope: {}, ts: 5, ...limits });
  s.enqueue({ id: 'письмо1', to: 'bob', from: 'carol', envelope: {}, ts: 6, ...limits });
  for (let i = 0; i < 4; i++) {
    s.enqueue({ id: 'спам' + i, to: 'bob', from: 'личность' + i, envelope: {}, ts: 10 + i, ...limits });
  }
  assert.strictEqual(s.queueFor('bob').length, 6, 'очередь полна');
  s.enqueue({ id: 'из-дома-2', to: 'dave', from: 'bob', envelope: {}, ts: 30, ...limits });
  assert.strictEqual(
    s.enqueue({ id: 'письмо-дейва', to: 'bob', from: 'dave', envelope: {}, ts: 40, ...limits }),
    true,
    'письмо корреспондента у полной очереди принимается'
  );
  const ids = s.queueFor('bob').map((x) => x.id);
  assert.ok(ids.includes('письмо-дейва'), 'письмо в очереди');
  assert.ok(!ids.includes('спам0'), 'старейший спам незнакомца вытеснен');
  assert.ok(ids.includes('письмо0') && ids.includes('письмо1'), 'письма других корреспондентов целы');
  assert.strictEqual(
    s.enqueue({ id: 'спам-новый', to: 'bob', from: 'свежая-личность', envelope: {}, ts: 50, ...limits }),
    false,
    'незнакомцу чужие конверты не жертвуются'
  );
  s.close();
});
test('ВЫС-15: память о корреспондентах стареет — «писал когда-то» не открывает резерв', () => {
  const s = fresh();
  const limits = { maxPerUser: 4, maxPerSender: 4, reserve: 2, reciprocityTtlMs: 100 };
  s.enqueue({ id: 'давно', to: 'carol', from: 'bob', envelope: {}, ts: 1, ...limits });
  s.enqueue({ id: 'спам0', to: 'bob', from: 'х0', envelope: {}, ts: 1000, ...limits });
  s.enqueue({ id: 'спам1', to: 'bob', from: 'х1', envelope: {}, ts: 1001, ...limits });
  assert.strictEqual(
    s.enqueue({ id: 'письмо', to: 'bob', from: 'carol', envelope: {}, ts: 5000, ...limits }),
    false,
    'память истекла — carol снова незнакомка, и резерв ей не достаётся'
  );
  s.expireOlderThan(2000);
  s.close();
});
test('S4/H-03 maxTotalBytes: байтовый потолок ОТКЛОНЯЕТ новый, чужое не вытесняет', () => {
  const s = fresh();
  const big = { cipher: 'x'.repeat(1000) };
  for (let i = 0; i < 5; i++) {
    s.enqueue({ id: 'b' + i, to: 'u' + i, envelope: big, ts: i, maxPerUser: 500, maxTotalBytes: 2500 });
  }
  assert.ok(s.queueBytes() <= 2500, 'вес очереди под байтовым потолком');
  assert.ok(s.getItem('b0'), 'старейший чужой конверт НЕ вытеснен по байтам');
  assert.strictEqual(s.getItem('b4'), null, 'новейший сверх потолка отклонён');
  s.close();
});
test('queueBytes (O(1)): точен при вставке/ack/вытеснении', () => {
  const s = fresh();
  assert.strictEqual(s.queueBytes(), 0);
  s.enqueue({ id: 'a', to: 'bob', envelope: { cipher: 'hello' }, ts: 1 });
  const after = s.queueBytes();
  assert.ok(after > 0);
  s.ack('bob', 'a');
  assert.strictEqual(s.queueBytes(), 0, 'после ack вес обнулился');
  s.close();
});
test('TTL: expireOlderThan удаляет старьё', () => {
  const s = fresh();
  s.enqueue({ id: 'old', to: 'bob', envelope: {}, ts: 100 });
  s.enqueue({ id: 'new', to: 'bob', envelope: {}, ts: 1000 });
  const removed = s.expireOlderThan(500);
  assert.strictEqual(removed, 1);
  assert.deepStrictEqual(s.queueFor('bob').map((x) => x.id), ['new']);
  s.close();
});
test('identities TOFU: первый ключ закрепляется, второй игнорируется', () => {
  const s = fresh();
  assert.strictEqual(s.getSignKey('bob'), null);
  s.bindSignKey('bob', 'KEY_A');
  s.bindSignKey('bob', 'KEY_EVIL');
  assert.strictEqual(s.getSignKey('bob'), 'KEY_A');
  s.close();
});
test('identities proven (H-6): доказанную связку легаси не перебивает, владелец box-ключа — да', () => {
  const s = fresh();
  s.bindSignKey('bob', 'KEY_A', true);
  s.touchIdentity('bob', 1234);
  assert.deepStrictEqual(s.getIdentity('bob'), { signPk: 'KEY_A', proven: true });
  s.bindSignKey('bob', 'KEY_EVIL', false);
  assert.strictEqual(s.getSignKey('bob'), 'KEY_A');
  s.rebindSignKey('bob', 'KEY_B');
  assert.deepStrictEqual(s.getIdentity('bob'), { signPk: 'KEY_B', proven: true });
  s.close();
});
test('identities proven (H-6): незакреплённую (сквоттерскую) связку владелец перебивает', () => {
  const s = fresh();
  s.bindSignKey('bob', 'SQUAT', false);
  assert.deepStrictEqual(s.getIdentity('bob'), { signPk: 'SQUAT', proven: false });
  s.rebindSignKey('bob', 'OWNER');
  assert.deepStrictEqual(s.getIdentity('bob'), { signPk: 'OWNER', proven: true });
  s.close();
});
test('M-02: evictColdIdentities вытесняет холодные БЕЗ очереди, каскадно чистит prekey/токен', () => {
  const s = fresh();
  s.bindSignKey('cold', 'K1', true, 100);
  s.bindSignKey('warm', 'K2', true, 300);
  s.bindSignKey('busy', 'K3', true, 50);
  s.setSpk('cold', { id: 'c', pub: 'p', sig: 'g' });
  s.setToken('cold', 'tok-cold');
  s.enqueue({ id: 'm1', to: 'busy', envelope: {}, ts: 1 });
  assert.strictEqual(s.identityCount(), 3);
  const evicted = s.evictColdIdentities(2);
  assert.strictEqual(evicted, 1, 'вытеснена одна identity');
  assert.strictEqual(s.getIdentity('cold'), null, 'холодная без очереди вытеснена');
  assert.strictEqual(s.getSpk('cold'), null, 'её SPK удалён каскадно');
  assert.strictEqual(s.getToken('cold'), null, 'её push-токен удалён каскадно');
  assert.ok(s.getIdentity('busy'), 'identity с ожидающей очередью НЕ вытеснена, хоть и холоднее');
  assert.ok(s.getIdentity('warm'), 'тёплая identity на месте');
  assert.strictEqual(s.evictColdIdentities(5), 0, 'под потолком вытеснения нет');
  s.close();
});
test('push tokens: set/get/del', () => {
  const s = fresh();
  s.setToken('bob', 'tok1');
  assert.strictEqual(s.getToken('bob'), 'tok1');
  s.setToken('bob', 'tok2');
  assert.strictEqual(s.getToken('bob'), 'tok2');
  s.delToken('bob');
  assert.strictEqual(s.getToken('bob'), null);
  s.close();
});
test('directory: addRelays + dedupe', () => {
  const s = fresh();
  s.addRelays(['wss://a', 'wss://b'], 1);
  s.addRelays(['wss://a', 'wss://c'], 2);
  const d = s.directory();
  assert.strictEqual(d.length, 3);
  assert.ok(d.includes('wss://a') && d.includes('wss://b') && d.includes('wss://c'));
  s.close();
});
test('stats отражает состояние', () => {
  const s = fresh();
  s.enqueue({ id: 'a', to: 'bob', envelope: {}, ts: 1 });
  s.enqueue({ id: 'b', to: 'carol', envelope: {}, ts: 1 });
  s.addRelays(['wss://a'], 1);
  const st = s.stats();
  assert.strictEqual(st.usersQueued, 2);
  assert.strictEqual(st.totalQueued, 2);
  assert.strictEqual(st.relays, 1);
  s.close();
});
test('prekeys: SPK сохраняется и заменяется', () => {
  const s = fresh();
  assert.strictEqual(s.getSpk('bob'), null);
  s.setSpk('bob', { id: 'a', pub: 'PUB_A', sig: 'SIG_A' });
  assert.deepStrictEqual(s.getSpk('bob'), { id: 'a', pub: 'PUB_A', sig: 'SIG_A' });
  s.setSpk('bob', { id: 'b', pub: 'PUB_B', sig: 'SIG_B' });
  assert.strictEqual(s.getSpk('bob').id, 'b');
  s.close();
});
test('prekeys: одноразовый выдаётся РОВНО один раз, пачка заменяется целиком', () => {
  const s = fresh();
  s.replaceOtps('bob', [
    { id: 'k1', pub: 'P1' },
    { id: 'k2', pub: 'P2' },
  ]);
  assert.strictEqual(s.countOtps('bob'), 2);
  const first = s.takeOtp('bob');
  assert.ok(['k1', 'k2'].includes(first.id));
  const second = s.takeOtp('bob');
  assert.notStrictEqual(first.id, second.id, 'один и тот же ключ дважды не выдаётся');
  assert.strictEqual(s.takeOtp('bob'), null, 'запас исчерпан');
  s.replaceOtps('bob', [{ id: 'k3', pub: 'P3' }]);
  assert.strictEqual(s.countOtps('bob'), 1, 'replace: старых нет, новая пачка на месте');
  s.close();
});
function freshBlobs(threshold = 100) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'licno-blobs-'));
  return { s: createStore(':memory:', { blobDir: dir, blobThreshold: threshold }), dir };
}
const bigEnvelope = () => ({ cipher: 'x'.repeat(500) });
const blobFiles = (dir) => fs.readdirSync(dir).filter((f) => f.endsWith('.json'));
test('АУД-06: тело читается ДО того, как доехало до диска', async () => {
  const { s, dir } = freshBlobs();
  s.enqueue({ id: 'big', to: 'bob', from: 'alice', envelope: bigEnvelope(), ts: 1 });
  const item = s.getItem('big');
  assert.deepStrictEqual(item.envelope, bigEnvelope(), '...но конверт уже отдаётся');
  await s.flushPendingBlobs();
  assert.deepStrictEqual(blobFiles(dir), ['big.json'], 'а затем тело оказывается на диске');
  assert.deepStrictEqual(s.getItem('big').envelope, bigEnvelope(), 'и читается уже оттуда');
  s.close();
});
test('blob: крупный конверт уходит файлом, мелкий остаётся в БД', async () => {
  const { s, dir } = freshBlobs();
  s.enqueue({ id: 'big', to: 'bob', from: 'alice', envelope: bigEnvelope(), ts: 1 });
  s.enqueue({ id: 'small', to: 'bob', from: 'alice', envelope: { cipher: 'hi' }, ts: 2 });
  await s.flushPendingBlobs();
  assert.deepStrictEqual(blobFiles(dir), ['big.json']);
  const q = s.queueFor('bob');
  assert.deepStrictEqual(q.map((x) => x.id), ['big', 'small']);
  assert.deepStrictEqual(q[0].envelope, bigEnvelope());
  assert.strictEqual(q[0].from, 'alice');
  s.close();
});
test('blob: ack удаляет и строку, и файл', async () => {
  const { s, dir } = freshBlobs();
  s.enqueue({ id: 'big', to: 'bob', from: 'alice', envelope: bigEnvelope(), ts: 1 });
  await s.flushPendingBlobs();
  assert.strictEqual(s.ack('bob', 'big'), 'alice');
  assert.strictEqual(blobFiles(dir).length, 0);
  s.close();
});
test('АУД-06: удаление до окончания записи не оставляет файл-сироту', async () => {
  const { s, dir } = freshBlobs();
  s.enqueue({ id: 'big', to: 'bob', from: 'alice', envelope: bigEnvelope(), ts: 1 });
  assert.strictEqual(s.ack('bob', 'big'), 'alice');
  await s.flushPendingBlobs();
  assert.strictEqual(blobFiles(dir).length, 0, 'отменённая запись не должна дописаться на диск');
  s.close();
});
test('blob: вытеснение по maxPerUser удаляет файл старейшего', async () => {
  const { s, dir } = freshBlobs();
  for (let i = 0; i < 3; i++) s.enqueue({ id: 'm' + i, to: 'bob', envelope: bigEnvelope(), ts: i, maxPerUser: 2 });
  await s.flushPendingBlobs();
  assert.deepStrictEqual(s.queueFor('bob').map((x) => x.id), ['m1', 'm2']);
  assert.deepStrictEqual(blobFiles(dir).sort(), ['m1.json', 'm2.json']);
  s.close();
});
test('blob: TTL удаляет протухшие файлы', async () => {
  const { s, dir } = freshBlobs();
  s.enqueue({ id: 'old', to: 'bob', envelope: bigEnvelope(), ts: 100 });
  s.enqueue({ id: 'new', to: 'bob', envelope: bigEnvelope(), ts: 1000 });
  await s.flushPendingBlobs();
  assert.strictEqual(s.expireOlderThan(500), 1);
  assert.deepStrictEqual(blobFiles(dir), ['new.json']);
  s.close();
});
test('blob: пропавший файл — строка подчищается, очередь не ломается', async () => {
  const { s, dir } = freshBlobs();
  s.enqueue({ id: 'big', to: 'bob', envelope: bigEnvelope(), ts: 1 });
  s.enqueue({ id: 'small', to: 'bob', envelope: { cipher: 'hi' }, ts: 2 });
  await s.flushPendingBlobs();
  fs.unlinkSync(path.join(dir, 'big.json'));
  assert.deepStrictEqual(s.queueFor('bob').map((x) => x.id), ['small']);
  assert.strictEqual(s.getItem('big'), null);
  s.close();
});
test('blob: cleanupOrphanBlobs убирает сирот и tmp, живые не трогает', async () => {
  const { s, dir } = freshBlobs();
  s.enqueue({ id: 'live', to: 'bob', envelope: bigEnvelope(), ts: 1 });
  await s.flushPendingBlobs();
  fs.writeFileSync(path.join(dir, 'orphan.json'), '{}');
  fs.writeFileSync(path.join(dir, 'half.json.tmp'), '{');
  fs.writeFileSync(path.join(dir, 'unrelated.txt'), 'keep');
  assert.strictEqual(s.cleanupOrphanBlobs(), 2);
  assert.deepStrictEqual(fs.readdirSync(dir).sort(), ['live.json', 'unrelated.txt']);
  s.close();
});
test('queueBytes: считает и строки БД, и blob-файлы', () => {
  const { s } = freshBlobs(100);
  assert.strictEqual(s.queueBytes(), 0);
  s.enqueue({ id: 'small', to: 'bob', envelope: { cipher: 'hi' }, ts: 1 });
  s.enqueue({ id: 'big', to: 'bob', envelope: bigEnvelope(), ts: 2 });
  const bytes = s.queueBytes();
  assert.ok(bytes > 500, 'учтён blob-файл (тело ~500 байт)');
  s.ack('bob', 'big');
  assert.ok(s.queueBytes() < bytes, 'после ack вес очереди уменьшился');
  s.close();
});
test('blob: без blobDir всё в БД (обратная совместимость)', () => {
  const s = createStore(':memory:');
  s.enqueue({ id: 'big', to: 'bob', envelope: bigEnvelope(), ts: 1 });
  assert.deepStrictEqual(s.queueFor('bob')[0].envelope, bigEnvelope());
  assert.strictEqual(s.cleanupOrphanBlobs(), 0);
  s.close();
});
test('АУД-06: getItemAsync отдаёт то же тело — и из памяти, и с диска', async () => {
  const { s } = freshBlobs();
  s.enqueue({ id: 'big', to: 'bob', from: 'alice', envelope: bigEnvelope(), ts: 1 });
  const fromMemory = await s.getItemAsync('big');
  assert.deepStrictEqual(fromMemory.envelope, bigEnvelope());
  await s.flushPendingBlobs();
  const fromDisk = await s.getItemAsync('big');
  assert.deepStrictEqual(fromDisk.envelope, bigEnvelope());
  assert.strictEqual(fromDisk.from, 'alice');
  assert.strictEqual(await s.getItemAsync('нет-такого'), null);
  s.close();
});
const binFiles = (dir) => fs.readdirSync(dir).filter((f) => f.endsWith('.bin'));
const chunk = (byte = 1, size = 4096) => Buffer.alloc(size, byte);
function putChunk(s, id, extra = {}) {
  return s.enqueueBinary({
    id,
    to: 'bob',
    from: 'alice',
    ref: 'msg-1',
    transferId: 't1',
    index: 0,
    total: 1,
    metadata: { name: 'видео.mp4' },
    payload: chunk(),
    ts: 1,
    ...extra,
  });
}
test('binary: чанк ставится в очередь, читается целиком и снимается ackBinary', async () => {
  const { s, dir } = freshBlobs();
  assert.strictEqual(putChunk(s, 'c1'), true);
  await s.flushPendingBlobs();
  assert.deepStrictEqual(s.binaryQueueIdsFor('bob'), ['c1']);
  const item = s.getBinaryItem('c1');
  assert.strictEqual(item.to, 'bob');
  assert.strictEqual(item.from, 'alice');
  assert.strictEqual(item.ref, 'msg-1');
  assert.strictEqual(item.transferId, 't1');
  assert.deepStrictEqual(item.metadata, { name: 'видео.mp4' });
  assert.ok(item.payload.equals(chunk()), 'тело чанка не искажено');
  const ack = s.ackBinary('bob', 'c1');
  assert.strictEqual(ack.from, 'alice');
  assert.strictEqual(ack.transferId, 't1');
  assert.strictEqual(binFiles(dir).length, 0, 'ack удаляет и строку, и файл');
  s.close();
});
test('АУД-06: чанк читается ДО того, как доехал до диска', async () => {
  const { s, dir } = freshBlobs();
  putChunk(s, 'c1');
  const item = s.getBinaryItem('c1');
  assert.ok(item && item.payload.equals(chunk()), '...но чанк уже отдаётся');
  await s.flushPendingBlobs();
  assert.deepStrictEqual(binFiles(dir), ['c1.bin'], 'а затем тело оказывается на диске');
  assert.ok(s.getBinaryItem('c1').payload.equals(chunk()), 'и читается уже оттуда');
  s.close();
});
test('АУД-06: getBinaryItemAsync отдаёт то же — и из памяти, и с диска', async () => {
  const { s } = freshBlobs();
  putChunk(s, 'c1');
  const fromMemory = await s.getBinaryItemAsync('c1');
  assert.ok(fromMemory.payload.equals(chunk()));
  await s.flushPendingBlobs();
  const fromDisk = await s.getBinaryItemAsync('c1');
  assert.ok(fromDisk.payload.equals(chunk()));
  assert.strictEqual(fromDisk.from, 'alice');
  assert.strictEqual(await s.getBinaryItemAsync('нет-такого'), null);
  s.close();
});
test('АУД-06: ackBinary до окончания записи не оставляет файл-сироту', async () => {
  const { s, dir } = freshBlobs();
  putChunk(s, 'c1');
  assert.ok(s.ackBinary('bob', 'c1'), 'ack пришёл раньше, чем запись закончилась');
  await s.flushPendingBlobs();
  assert.strictEqual(fs.readdirSync(dir).length, 0, 'отменённая запись не должна дописаться на диск');
  s.close();
});
test('binary: пропавший файл — строка подчищается, очередь не ломается', async () => {
  const { s, dir } = freshBlobs();
  putChunk(s, 'c1');
  putChunk(s, 'c2', { ts: 2 });
  await s.flushPendingBlobs();
  fs.unlinkSync(path.join(dir, 'c1.bin'));
  assert.strictEqual(s.getBinaryItem('c1'), null, 'мёртвая строка удалена');
  assert.deepStrictEqual(s.binaryQueueIdsFor('bob'), ['c2'], 'остальная очередь цела');
  assert.strictEqual(s.queueBytes(), 4096, 'вес очереди пересчитан ровно на один чанк');
  s.close();
});
test('АУД-06: строка, снятая во время асинхронного чтения, не вычитается дважды', async () => {
  const { s, dir } = freshBlobs();
  putChunk(s, 'c1');
  putChunk(s, 'c2', { ts: 2 });
  await s.flushPendingBlobs();
  assert.strictEqual(s.queueBytes(), 8192);
  fs.unlinkSync(path.join(dir, 'c1.bin'));
  const reading = s.getBinaryItemAsync('c1');
  assert.ok(s.ackBinary('bob', 'c1'));
  assert.strictEqual(await reading, null);
  assert.strictEqual(s.queueBytes(), 4096, 'вес уменьшился ровно на один чанк, а не на два');
  assert.strictEqual(s.stats().totalQueued, 1, 'в очереди действительно осталась одна строка');
  s.close();
});
test('binary: TTL удаляет протухшие чанки вместе с файлами', async () => {
  const { s, dir } = freshBlobs();
  putChunk(s, 'old', { ts: 100 });
  putChunk(s, 'new', { ts: 1000 });
  await s.flushPendingBlobs();
  assert.strictEqual(s.expireOlderThan(500), 1);
  assert.deepStrictEqual(binFiles(dir), ['new.bin']);
  assert.strictEqual(s.queueBytes(), 4096);
  s.close();
});
test('binary: cleanupOrphanBlobs убирает .bin-сирот, но не трогает идущую запись', async () => {
  const { s, dir } = freshBlobs();
  putChunk(s, 'live');
  assert.strictEqual(s.cleanupOrphanBlobs(), 0);
  await s.flushPendingBlobs();
  assert.ok(s.getBinaryItem('live').payload.equals(chunk()), 'чанк уцелел');
  fs.writeFileSync(path.join(dir, 'orphan.bin'), 'x');
  fs.writeFileSync(path.join(dir, 'half.bin.tmp'), 'x');
  assert.strictEqual(s.cleanupOrphanBlobs(), 2);
  assert.deepStrictEqual(fs.readdirSync(dir).sort(), ['live.bin']);
  s.close();
});
test('binary: потолки очереди считают чанки вместе с конвертами', () => {
  const { s } = freshBlobs();
  assert.strictEqual(putChunk(s, 'c1', { maxPerUser: 2 }), true);
  assert.strictEqual(putChunk(s, 'c2', { ts: 2, maxPerUser: 2 }), true);
  assert.strictEqual(putChunk(s, 'c3', { ts: 3, maxPerUser: 2 }), false, 'потолок получателя');
  assert.strictEqual(putChunk(s, 'c4', { ts: 4, maxTotalBytes: 100 }), false, 'байтовый потолок');
  assert.deepStrictEqual(s.binaryQueueIdsFor('bob'), ['c1', 'c2']);
  s.close();
});
test('blob: ошибка фоновой записи подчищает недоступное тело', async () => {
  const { s } = freshBlobs();
  const originalWriteFile = fs.promises.writeFile;
  fs.promises.writeFile = async () => { throw new Error('disk unavailable'); };
  try {
    s.enqueue({ id: 'write-failed', to: 'bob', envelope: bigEnvelope(), ts: 1 });
    await s.flushPendingBlobs();
    assert.strictEqual(s.getItem('write-failed'), null);
  } finally {
    fs.promises.writeFile = originalWriteFile;
    s.close();
  }
});
test('binary: raw-чанк читается, учитывается и подтверждается без base64', () => {
  const { s, dir } = freshBlobs();
  const payload = Buffer.from([0, 1, 2, 255]);
  assert.strictEqual(s.enqueueBinary({
    id: 'binary-1', to: 'bob', from: 'alice', ref: 'message-1', transferId: 'transfer-1',
    index: 0, total: 1, metadata: { mime: 'image/png' }, payload, ts: 10,
  }), true);
  assert.deepStrictEqual(s.binaryQueueIdsFor('bob'), ['binary-1']);
  const item = s.getBinaryItem('binary-1');
  assert.deepStrictEqual(item.payload, payload);
  assert.deepStrictEqual(item.metadata, { mime: 'image/png' });
  assert.strictEqual(s.ackBinary('mallory', 'binary-1'), null);
  assert.deepStrictEqual(s.ackBinary('bob', 'binary-1'), {
    from: 'alice', ref: 'message-1', transferId: 'transfer-1', index: 0,
  });
  assert.strictEqual(s.getBinaryItem('binary-1'), null);
  assert.strictEqual(fs.existsSync(path.join(dir, 'binary-1.bin')), false);
  s.close();
});
test('binary: лимиты учитывают общую и парную очередь', () => {
  const { s } = freshBlobs();
  const payload = Buffer.from([1, 2, 3]);
  assert.strictEqual(s.enqueueBinary({ id: 'b-limit', to: 'bob', from: 'alice', transferId: 't', index: 0, total: 1, payload, ts: 1 }), true);
  assert.strictEqual(s.enqueue({ id: 'json-pair', to: 'bob', from: 'alice', envelope: {}, ts: 2, maxPerSender: 1 }), false);
  assert.strictEqual(s.enqueueBinary({ id: 'b-count', to: 'carol', from: 'alice', transferId: 't2', index: 0, total: 1, payload, ts: 2, maxTotal: 1 }), false);
  assert.strictEqual(s.enqueueBinary({ id: 'b-bytes', to: 'carol', from: 'alice', transferId: 't3', index: 0, total: 1, payload, ts: 3, maxTotalBytes: s.queueBytes() }), false);
  s.close();
});
test('binary: ошибка метаданных и дубликат не оставляют сирот и не портят принятое тело', () => {
  const { s, dir } = freshBlobs();
  const circular = {};
  circular.self = circular;
  assert.throws(() => s.enqueueBinary({
    id: 'bad-meta', to: 'bob', from: 'alice', transferId: 't', index: 0, total: 1,
    metadata: circular, payload: Buffer.from('bad'), ts: 1,
  }));
  assert.strictEqual(fs.existsSync(path.join(dir, 'bad-meta.bin')), false);
  const original = Buffer.from('original');
  s.enqueueBinary({ id: 'duplicate', to: 'bob', from: 'alice', transferId: 't', index: 0, total: 1, payload: original, ts: 2 });
  assert.throws(() => s.enqueueBinary({ id: 'duplicate', to: 'bob', from: 'alice', transferId: 't', index: 0, total: 1, payload: Buffer.from('replacement'), ts: 3 }));
  assert.deepStrictEqual(s.getBinaryItem('duplicate').payload, original, 'дубликат не уничтожает уже принятое тело');
  s.close();
});
test('binary: пропавший raw-файл удаляет мёртвую строку', async () => {
  const { s, dir } = freshBlobs();
  s.enqueueBinary({ id: 'missing-bin', to: 'bob', from: 'alice', transferId: 't', index: 0, total: 1, payload: Buffer.from('x'), ts: 1 });
  await s.flushPendingBlobs();
  fs.unlinkSync(path.join(dir, 'missing-bin.bin'));
  assert.strictEqual(s.getBinaryItem('missing-bin'), null);
  assert.deepStrictEqual(s.binaryQueueIdsFor('bob'), []);
  s.close();
});
test('перезапуск: backfill восстанавливает bytes, повреждённые JSON изолируются', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'licno-store-db-'));
  const dbPath = path.join(root, 'relay.sqlite');
  const blobDir = path.join(root, 'blobs');
  let s = createStore(dbPath, { blobDir, blobThreshold: 100 });
  s.enqueue({ id: 'legacy-inline', to: 'bob', from: 'alice', envelope: { text: 'inline' }, ts: 1 });
  s.enqueue({
    id: 'legacy-blob', to: 'bob', from: 'alice', envelope: bigEnvelope(), ts: 2,
    deviceCertificate: { id: 'device' }, deviceRoster: { version: 1 },
  });
  s.enqueue({ id: 'legacy-missing', to: 'bob', from: 'alice', envelope: bigEnvelope(), ts: 3 });
  return s.flushPendingBlobs().then(() => {
    s.close();
    const raw = new Database(dbPath);
    raw.prepare('UPDATE queue SET bytes=0').run();
    raw.close();
    fs.unlinkSync(path.join(blobDir, 'legacy-missing.json'));
    s = createStore(dbPath, { blobDir, blobThreshold: 100 });
    assert.ok(s.queueBytes() > 500, 'размеры строк прежней версии восстановлены');
    assert.deepStrictEqual(s.queueIdsFor('bob'), ['legacy-inline', 'legacy-blob', 'legacy-missing']);
    const mutate = new Database(dbPath);
    mutate.prepare("UPDATE queue SET envelope='{broken' WHERE id='legacy-inline'").run();
    mutate.prepare("UPDATE queue SET sender_meta=x'00' WHERE id='legacy-blob'").run();
    mutate.close();
    assert.strictEqual(s.getItem('legacy-inline'), null);
    const blob = s.getItem('legacy-blob');
    assert.strictEqual(blob.deviceCertificate, undefined);
    assert.strictEqual(blob.deviceRoster, undefined);
    assert.strictEqual(blob.from, undefined, 'из нечитаемого блоба не берётся и отправитель');
    s.close();
  });
});
function deviceCertificate(accountPk, rootSignPk, id, pk, signPk, issuedAt = 1000) {
  return {
    v: 2,
    type: 'licno-device-certificate',
    accountPublicKey: accountPk,
    accountSignPublicKey: rootSignPk,
    deviceId: id,
    devicePublicKey: pk,
    deviceSignPublicKey: signPk,
    name: id === 'phone' ? 'Телефон Android' : 'Второе устройство',
    platform: id === 'phone' ? 'android' : 'windows',
    issuedAt,
    capabilities: ['files', 'history-sync', 'messages', 'notifications', 'voice'],
    rootSignature: 'signed-' + id,
  };
}
function roster(version, devices, updatedAt = version * 1000) {
  return {
    v: 2,
    type: 'licno-device-roster',
    accountPublicKey: 'account-pk',
    accountSignPublicKey: 'root-sign-pk',
    version,
    updatedAt,
    devices,
    rootSignature: 'roster-signature-' + version,
  };
}
test('linked devices: roster монотонен, читается по account и device key', () => {
  const s = fresh();
  const phone = deviceCertificate('account-pk', 'root-sign-pk', 'phone', 'account-pk', 'root-sign-pk');
  const second = deviceCertificate('account-pk', 'root-sign-pk', 'second', 'second-pk', 'second-sign-pk', 2000);
  const v1 = roster(1, [{ certificate: phone, revokedAt: null }]);
  const first = s.putAccountRoster(v1);
  assert.strictEqual(first.ok, true);
  assert.strictEqual(s.getAccount('account-pk').rosterVersion, 1);
  assert.deepStrictEqual(s.getAccountRoster('account-pk'), v1);
  assert.strictEqual(s.getDevice('account-pk').deviceId, 'phone');
  const v2 = roster(2, [
    { certificate: phone, revokedAt: null },
    { certificate: second, revokedAt: null },
  ]);
  assert.strictEqual(s.putAccountRoster(v2).ok, true);
  assert.strictEqual(s.devicesForAccount('account-pk').length, 2);
  assert.strictEqual(s.getDevice('second-pk').revokedAt, null);
  assert.strictEqual(s.getAccountDevice('account-pk', 'second').devicePublicKey, 'second-pk');
  s.touchDevice('second-pk', 3000);
  assert.strictEqual(s.putAccountRoster(v2).unchanged, true, 'повтор идемпотентен');
  assert.strictEqual(s.putAccountRoster(v1).reason, 'stale-roster');
  assert.strictEqual(s.putAccountRoster({ ...v2, rootSignature: 'other' }).reason, 'roster-version-conflict');
  s.close();
});
test('linked devices: отзыв необратим тем же сертификатом и чистит транспорт', () => {
  const s = fresh();
  const phone = deviceCertificate('account-pk', 'root-sign-pk', 'phone', 'account-pk', 'root-sign-pk');
  const second = deviceCertificate('account-pk', 'root-sign-pk', 'second', 'second-pk', 'second-sign-pk', 2000);
  s.putAccountRoster(
    roster(1, [
      { certificate: phone, revokedAt: null },
      { certificate: second, revokedAt: null },
    ])
  );
  s.enqueue({ id: 'for-second', to: 'second-pk', from: 'sender', envelope: { cipher: 'x' }, ts: 1 });
  s.setToken('second-pk', 'push-token');
  s.setSpk('second-pk', { id: 'spk', pub: 'pub', sig: 'sig' });
  s.replaceOtps('second-pk', [{ id: 'otp', pub: 'pub' }]);
  const revoked = s.putAccountRoster(
    roster(2, [
      { certificate: phone, revokedAt: null },
      { certificate: second, revokedAt: 2500 },
    ], 2500)
  );
  assert.deepStrictEqual(revoked.revokedDeviceKeys, ['second-pk']);
  assert.strictEqual(s.getDevice('second-pk').revokedAt, 2500);
  assert.strictEqual(s.purgeDeviceTransport('second-pk'), 1);
  assert.strictEqual(s.queueFor('second-pk').length, 0);
  assert.strictEqual(s.getToken('second-pk'), null);
  assert.strictEqual(s.getSpk('second-pk'), null);
  assert.strictEqual(s.countOtps('second-pk'), 0);
  const replay = s.putAccountRoster(
    roster(3, [
      { certificate: phone, revokedAt: null },
      { certificate: second, revokedAt: null },
    ], 3000)
  );
  assert.strictEqual(replay.reason, 'device-revoked');
  s.close();
});
test('ГРФ-1: в базе нет ни колонки, ни индекса «кто кому»', () => {
  const s = fresh();
  s.enqueue({ id: 'a', to: 'bob', from: 'alice', envelope: {}, ts: 1 });
  const columns = (table) => s.tableColumnsForTest(table);
  for (const table of ['queue', 'binary_queue']) {
    for (const gone of ['from_pk', 'from_account', 'from_device', 'device_cert', 'device_roster', 'meta_json']) {
      assert.ok(!columns(table).includes(gone), `${table}.${gone} не должен существовать`);
    }
    assert.ok(columns(table).includes('sender_meta'), `${table}.sender_meta есть`);
    assert.ok(columns(table).includes('pair_tag'), `${table}.pair_tag есть`);
  }
  const indexes = s.indexNamesForTest();
  assert.ok(!indexes.includes('idx_queue_from_to'), 'индекс графа снесён');
  assert.ok(!indexes.includes('idx_binary_queue_from_to'), 'индекс графа снесён (бинарный)');
  assert.ok(indexes.includes('idx_queue_pair'), 'квота ходит по индексу метки пары');
  assert.ok(indexes.includes('idx_binary_queue_pair'), 'квота ходит по индексу метки пары (бинарный)');
  s.close();
});
test('ГРФ-1: доставка получателю сохраняет ВСЕ метаданные отправителя', () => {
  const s = fresh();
  const cert = { deviceId: 'second-1', devicePublicKey: 'alice-dev' };
  const roster = { version: 7, devices: [{ certificate: cert, revokedAt: null }] };
  s.enqueue({
    id: 'a',
    to: 'bob',
    from: 'alice-dev',
    fromAccount: 'alice-acc',
    fromDeviceId: 'second-1',
    deviceCertificate: cert,
    deviceRoster: roster,
    envelope: { cipher: 'x' },
    ts: 1,
  });
  const item = s.getItem('a');
  assert.strictEqual(item.from, 'alice-dev');
  assert.strictEqual(item.fromAccount, 'alice-acc');
  assert.strictEqual(item.fromDeviceId, 'second-1');
  assert.deepStrictEqual(item.deviceCertificate, cert);
  assert.deepStrictEqual(item.deviceRoster, roster);
  assert.strictEqual(s.ack('bob', 'a'), 'alice-dev');
  s.close();
});
test('ГРФ-1: без fromAccount он равен from (легаси-путь одноустройственного отправителя)', () => {
  const s = fresh();
  s.enqueue({ id: 'a', to: 'bob', from: 'alice', envelope: {}, ts: 1 });
  const item = s.getItem('a');
  assert.strictEqual(item.from, 'alice');
  assert.strictEqual(item.fromAccount, 'alice');
  assert.strictEqual(item.fromDeviceId, undefined);
  s.close();
});
test('ГРФ-1: квота на пару считается по метке — разные отправители не мешают друг другу', () => {
  const s = fresh();
  s.enqueue({ id: 'real', to: 'bob', from: 'carol', envelope: {}, ts: 1, maxPerUser: 500, maxPerSender: 2 });
  for (let i = 0; i < 4; i++) {
    s.enqueue({ id: 's' + i, to: 'bob', from: 'mallory', envelope: {}, ts: 10 + i, maxPerUser: 500, maxPerSender: 2 });
  }
  for (let i = 0; i < 4; i++) {
    s.enqueue({ id: 'd' + i, to: 'dave', from: 'mallory', envelope: {}, ts: 20 + i, maxPerUser: 500, maxPerSender: 2 });
  }
  assert.ok(s.queueFor('bob').map((x) => x.id).includes('real'), 'чужое не вытеснено');
  assert.strictEqual(s.queueFor('bob').filter((x) => x.id.startsWith('s')).length, 2);
  assert.strictEqual(s.queueFor('dave').length, 2, 'квота пары считается на пару, а не на отправителя');
  s.close();
});
test('ГРФ-1: файл базы не содержит адресов отправителей, метаданные переживают перезапуск', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'grf-'));
  const dbPath = path.join(dir, 'relay.db');
  const cert = { deviceId: 'd1', devicePublicKey: 'SENDER-DEVICE-KEY' };
  const first = createStore(dbPath, { blobDir: path.join(dir, 'blobs') });
  first.enqueue({
    id: 'a',
    to: 'RECIPIENT-KEY',
    from: 'SENDER-DEVICE-KEY',
    fromAccount: 'SENDER-ACCOUNT-KEY',
    fromDeviceId: 'd1',
    deviceCertificate: cert,
    envelope: { cipher: 'x' },
    ts: 1,
  });
  first.close();
  for (const file of fs.readdirSync(dir).filter((f) => f.startsWith('relay.db'))) {
    const raw = fs.readFileSync(path.join(dir, file));
    assert.ok(!raw.includes(Buffer.from('SENDER-DEVICE-KEY')), file + ' не должен содержать адрес отправителя');
    assert.ok(!raw.includes(Buffer.from('SENDER-ACCOUNT-KEY')), file + ' не должен содержать аккаунт отправителя');
  }
  assert.ok(fs.readFileSync(dbPath).includes(Buffer.from('RECIPIENT-KEY')));
  const again = createStore(dbPath, { blobDir: path.join(dir, 'blobs') });
  const item = again.getItem('a');
  assert.strictEqual(item.from, 'SENDER-DEVICE-KEY', 'ключ подхватился из файла рядом с базой');
  assert.strictEqual(item.fromAccount, 'SENDER-ACCOUNT-KEY');
  assert.deepStrictEqual(item.deviceCertificate, cert);
  again.close();
  fs.unlinkSync(dbPath + '.metakey');
  const orphaned = createStore(dbPath, { blobDir: path.join(dir, 'blobs') });
  const blind = orphaned.getItem('a');
  assert.deepStrictEqual(blind.envelope, { cipher: 'x' }, 'конверт не потерян');
  assert.strictEqual(blind.from, undefined, 'отправитель без ключа не восстанавливается');
  assert.strictEqual(orphaned.ack('RECIPIENT-KEY', 'a'), null, 'квитанцию слать некому');
  orphaned.close();
  fs.rmSync(dir, { recursive: true, force: true });
});
test('ГРФ-1: миграция старой базы переносит метаданные и сносит открытый текст', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'grf-mig-'));
  const dbPath = path.join(dir, 'relay.db');
  const legacy = new Database(dbPath);
  legacy.pragma('journal_mode = WAL');
  legacy.exec(`
    CREATE TABLE queue (
      id TEXT PRIMARY KEY, to_pk TEXT NOT NULL, from_pk TEXT, envelope TEXT NOT NULL,
      silent INTEGER DEFAULT 0, call_push INTEGER DEFAULT 0, ts INTEGER NOT NULL,
      blob INTEGER DEFAULT 0, bytes INTEGER DEFAULT 0,
      from_account TEXT, from_device TEXT, device_cert TEXT, device_roster TEXT
    );
    CREATE INDEX idx_queue_to ON queue(to_pk, ts);
    CREATE INDEX idx_queue_from_to ON queue(from_pk, to_pk, ts);
    CREATE TABLE binary_queue (
      id TEXT PRIMARY KEY, to_pk TEXT NOT NULL, from_pk TEXT NOT NULL, ref TEXT,
      transfer_id TEXT NOT NULL, chunk_index INTEGER NOT NULL, total_chunks INTEGER NOT NULL,
      meta_json TEXT, bytes INTEGER NOT NULL, ts INTEGER NOT NULL
    );
    CREATE INDEX idx_binary_queue_from_to ON binary_queue(from_pk, to_pk, ts);
  `);
  legacy
    .prepare(
      'INSERT INTO queue (id,to_pk,from_pk,envelope,silent,call_push,ts,blob,bytes,from_account,from_device,device_cert,device_roster) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)'
    )
    .run('m1', 'bob', 'OLD-SENDER', '{"cipher":"x"}', 0, 0, 100, 0, 14, 'OLD-ACCOUNT', 'dev-7', '{"deviceId":"dev-7"}', '{"version":3}');
  legacy
    .prepare(
      'INSERT INTO binary_queue (id,to_pk,from_pk,ref,transfer_id,chunk_index,total_chunks,meta_json,bytes,ts) VALUES (?,?,?,?,?,?,?,?,?,?)'
    )
    .run('b1', 'bob', 'OLD-SENDER', 'r1', 't1', 0, 2, '{"fromAccount":"OLD-ACCOUNT"}', 10, 102);
  legacy.close();
  const s = createStore(dbPath, { blobDir: path.join(dir, 'blobs') });
  const item = s.getItem('m1');
  assert.strictEqual(item.from, 'OLD-SENDER', 'накопленная очередь не потеряла отправителя');
  assert.strictEqual(item.fromAccount, 'OLD-ACCOUNT');
  assert.strictEqual(item.fromDeviceId, 'dev-7');
  assert.deepStrictEqual(item.deviceRoster, { version: 3 });
  assert.ok(!s.indexNamesForTest().includes('idx_queue_from_to'), 'индекс графа снесён миграцией');
  assert.ok(!s.tableColumnsForTest('queue').includes('from_pk'));
  assert.ok(!s.tableColumnsForTest('binary_queue').includes('meta_json'));
  const stored = s.enqueue({ id: 'm2', to: 'bob', from: 'OLD-SENDER', envelope: {}, ts: 200, maxPerUser: 500, maxPerSender: 1 });
  assert.strictEqual(stored, true);
  assert.deepStrictEqual(s.queueFor('bob').map((x) => x.id), ['m2'], 'вытеснен свой же старейший');
  s.close();
  for (const file of fs.readdirSync(dir).filter((f) => f.startsWith('relay.db'))) {
    const raw = fs.readFileSync(path.join(dir, file));
    assert.ok(!raw.includes(Buffer.from('OLD-SENDER')), file + ': открытый текст вычищен VACUUM+checkpoint');
    assert.ok(!raw.includes(Buffer.from('OLD-ACCOUNT')), file + ': открытый текст вычищен VACUUM+checkpoint');
  }
  fs.rmSync(dir, { recursive: true, force: true });
});
test('ГРФ-3: имя давно отозванного устройства стирается, ключи и запрет оживления остаются', () => {
  const s = fresh();
  const phone = deviceCertificate('account-pk', 'root-sign-pk', 'phone', 'account-pk', 'root-sign-pk');
  const second = deviceCertificate('account-pk', 'root-sign-pk', 'second', 'second-pk', 'second-sign-pk', 2000);
  second.name = 'Второе устройство Виктора';
  s.putAccountRoster(roster(1, [{ certificate: phone, revokedAt: null }, { certificate: second, revokedAt: null }]));
  s.putAccountRoster(
    roster(2, [{ certificate: phone, revokedAt: null }, { certificate: second, revokedAt: 2500 }], 2500)
  );
  assert.strictEqual(s.getDevice('second-pk').name, 'Второе устройство Виктора');
  assert.strictEqual(s.redactRevokedDevices(2500 + 1000, 30 * 24 * 3600 * 1000), 0);
  assert.strictEqual(s.getDevice('second-pk').name, 'Второе устройство Виктора');
  const redacted = s.redactRevokedDevices(2500 + 40 * 24 * 3600 * 1000);
  assert.strictEqual(redacted, 1);
  const row = s.getDevice('second-pk');
  assert.strictEqual(row.name, '', 'имя стёрто');
  assert.strictEqual(row.certificate, null, 'сертификат стёрт');
  assert.strictEqual(row.devicePublicKey, 'second-pk', 'ключ остался — на нём держится запрет переприсвоения');
  assert.strictEqual(row.revokedAt, 2500, 'отметка отзыва осталась');
  assert.ok(row.redactedAt > 0);
  assert.strictEqual(s.redactRevokedDevices(2500 + 50 * 24 * 3600 * 1000), 0, 'повтор ничего не меняет');
  const replay = s.putAccountRoster(
    roster(3, [{ certificate: phone, revokedAt: null }, { certificate: second, revokedAt: 2500 }], 3000)
  );
  assert.strictEqual(replay.ok, true);
  assert.strictEqual(s.getDevice('second-pk').name, '', 'roster не оживил имя');
  assert.strictEqual(
    s.putAccountRoster(
      roster(4, [{ certificate: phone, revokedAt: null }, { certificate: second, revokedAt: null }], 4000)
    ).reason,
    'device-revoked',
    'вычищенная запись по-прежнему запрещает оживление'
  );
  s.close();
});
test('linked devices: ключ устройства не переносится между аккаунтами', () => {
  const s = fresh();
  const first = deviceCertificate('account-pk', 'root-sign-pk', 'phone', 'shared-device-pk', 'device-sign');
  assert.strictEqual(s.putAccountRoster(roster(1, [{ certificate: first, revokedAt: null }])).ok, true);
  const second = deviceCertificate('other-account', 'other-root', 'other-phone', 'shared-device-pk', 'other-sign');
  const otherRoster = {
    ...roster(1, [{ certificate: second, revokedAt: null }]),
    accountPublicKey: 'other-account',
    accountSignPublicKey: 'other-root',
  };
  assert.strictEqual(s.putAccountRoster(otherRoster).reason, 'device-key-conflict');
  s.close();
});
test('linked devices: отсутствие устройства в новом полном roster отзывает его', () => {
  const s = fresh();
  const phone = deviceCertificate('account-pk', 'root-sign-pk', 'phone', 'account-pk', 'root-sign-pk');
  const second = deviceCertificate('account-pk', 'root-sign-pk', 'second', 'second-pk', 'second-sign-pk', 2000);
  s.putAccountRoster(roster(1, [
    { certificate: phone, revokedAt: null },
    { certificate: second, revokedAt: null },
  ]));
  const result = s.putAccountRoster(roster(2, [{ certificate: phone, revokedAt: null }], 3000));
  assert.deepStrictEqual(result.revokedDeviceKeys, ['second-pk']);
  assert.strictEqual(s.getDevice('second-pk').revokedAt, 3000);
  s.close();
});
test('linked devices: повреждённый roster в БД не выходит наружу', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'licno-roster-db-'));
  const dbPath = path.join(root, 'relay.sqlite');
  const s = createStore(dbPath);
  const phone = deviceCertificate('account-pk', 'root-sign-pk', 'phone', 'account-pk', 'root-sign-pk');
  s.putAccountRoster(roster(1, [{ certificate: phone, revokedAt: null }]));
  const raw = new Database(dbPath);
  raw.prepare("UPDATE accounts SET roster_json='{broken'").run();
  raw.close();
  assert.strictEqual(s.getAccountRoster('account-pk'), null);
  s.close();
});
test('отчёты: повтор той же посылки не создаёт вторую запись', () => {
  const s = fresh();
  s.addReport('id-1', 1000, '{"v":1}');
  s.addReport('id-1', 2000, '{"v":1}');
  assert.strictEqual(s.reportsCount(), 1, 'повтор доставки — не второй отчёт');
  const page = s.reportsPage(10);
  assert.strictEqual(page.length, 1);
  assert.strictEqual(page[0].at, 1000, 'осталась первая запись, время не переписано');
  s.close();
});
test('отчёты: страница отдаёт самые старые вперёд и не больше запрошенного', () => {
  const s = fresh();
  s.addReport('c', 3000, '{"v":1,"n":3}');
  s.addReport('a', 1000, '{"v":1,"n":1}');
  s.addReport('b', 2000, '{"v":1,"n":2}');
  assert.deepStrictEqual(s.reportsPage(2).map((r) => r.id), ['a', 'b']);
  s.close();
});
test('отчёты: подтверждённые удаляются, остальные остаются', () => {
  const s = fresh();
  s.addReport('a', 1000, '{}');
  s.addReport('b', 2000, '{}');
  assert.strictEqual(s.deleteReports(['a', 'нет-такого']), 1, 'считаются только реально удалённые');
  assert.deepStrictEqual(s.reportsPage(10).map((r) => r.id), ['b']);
  assert.strictEqual(s.deleteReports([]), 0);
  s.close();
});
test('отчёты: невостребованные уходят по сроку', () => {
  const s = fresh();
  s.addReport('старый', 1000, '{}');
  s.addReport('свежий', 9000, '{}');
  assert.strictEqual(s.sweepReports(5000), 1);
  assert.deepStrictEqual(s.reportsPage(10).map((r) => r.id), ['свежий']);
  s.close();
});
chain
  .then(() => {
    console.log('\n' + passed + ' passed');
  })
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });