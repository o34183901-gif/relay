/**
 * store.js — тесты встроенного хранилища (node server/store.test.js).
 */
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { createStore } = require('./store');

let passed = 0;
function test(name, fn) {
  fn();
  passed++;
  console.log('  ✓ ' + name);
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

test('ack: удаляет по id и возвращает from_pk; чужой to игнорируется', () => {
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
  assert.deepStrictEqual(q.map((x) => x.id), ['m2', 'm3', 'm4']); // старые вытеснены
  s.close();
});

test('maxTotal (H-03): глобальный потолок ОТКЛОНЯЕТ новый, чужое старьё не вытесняет', () => {
  const s = fresh();
  // разные получатели — per-user не помогает, срабатывает только глобальный лимит
  for (let i = 0; i < 3; i++) {
    const ok = s.enqueue({ id: 'g' + i, to: 'u' + i, envelope: {}, ts: i, maxPerUser: 500, maxTotal: 3 });
    assert.strictEqual(ok, true, 'до потолка конверты принимаются');
  }
  // H-03: очередь заполнена глобально — новый конверт ОТКЛОНЯЕТСЯ (drop-new), а
  // уже принятые сообщения ДРУГИХ получателей НЕ удаляются (раньше вытеснялся
  // глобально старейший — молчаливая цензура/потеря чужих сообщений).
  const stored = s.enqueue({ id: 'g3', to: 'u3', envelope: {}, ts: 3, maxPerUser: 500, maxTotal: 3 });
  assert.strictEqual(stored, false, 'при полной глобальной очереди новый конверт отклонён');
  assert.strictEqual(s.stats().totalQueued, 3, 'всего не больше глобального потолка');
  assert.ok(s.getItem('g0'), 'старейший чужой конверт НЕ вытеснен');
  assert.strictEqual(s.getItem('g3'), null, 'отклонённый конверт не сохранён');
  s.close();
});

test('S5 maxPerSender: флудер вытесняет ТОЛЬКО свои сообщения, чужие целы', () => {
  const s = fresh();
  // жертва bob получила настоящее сообщение от честного carol
  s.enqueue({ id: 'real', to: 'bob', from: 'carol', envelope: {}, ts: 1, maxPerUser: 500, maxPerSender: 2 });
  // злоумышленник mallory флудит bob сверх своей квоты (2)
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
  // очередь bob заполнена настоящими сообщениями честного carol (потолок 3)
  for (let i = 0; i < 3; i++) {
    s.enqueue({ id: 'real' + i, to: 'bob', from: 'carol', envelope: {}, ts: i, maxPerUser: 3 });
  }
  // атакующий шлёт с ПАЧКИ одноразовых identity (по 1 конверту) — очередь полна,
  // своих слотов у свежего отправителя нет → новый конверт отклоняется, чужое цело.
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

test('S4/H-03 maxTotalBytes: байтовый потолок ОТКЛОНЯЕТ новый, чужое не вытесняет', () => {
  const s = fresh();
  const big = { cipher: 'x'.repeat(1000) };
  // каждый конверт ~>1000 байт; лимит ~2500 байт вмещает ~2 таких
  for (let i = 0; i < 5; i++) {
    s.enqueue({ id: 'b' + i, to: 'u' + i, envelope: big, ts: i, maxPerUser: 500, maxTotalBytes: 2500 });
  }
  assert.ok(s.queueBytes() <= 2500, 'вес очереди под байтовым потолком');
  // H-03: первые (старейшие) остаются, новые сверх потолка отклоняются.
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
  s.bindSignKey('bob', 'KEY_EVIL'); // INSERT OR IGNORE — не перезаписывает
  assert.strictEqual(s.getSignKey('bob'), 'KEY_A');
  s.close();
});

test('identities proven (H-6): доказанную связку легаси не перебивает, владелец box-ключа — да', () => {
  const s = fresh();
  s.bindSignKey('bob', 'KEY_A', true); // доказано владение box-ключом -> proven
  assert.deepStrictEqual(s.getIdentity('bob'), { signPk: 'KEY_A', proven: true });
  s.bindSignKey('bob', 'KEY_EVIL', false); // INSERT OR IGNORE — не трогает
  assert.strictEqual(s.getSignKey('bob'), 'KEY_A');
  s.rebindSignKey('bob', 'KEY_B'); // владелец снова доказал box-ключ — перепривязка
  assert.deepStrictEqual(s.getIdentity('bob'), { signPk: 'KEY_B', proven: true });
  s.close();
});

test('identities proven (H-6): незакреплённую (сквоттерскую) связку владелец перебивает', () => {
  const s = fresh();
  s.bindSignKey('bob', 'SQUAT', false); // сквоттер занял легаси-путём (proven=0)
  assert.deepStrictEqual(s.getIdentity('bob'), { signPk: 'SQUAT', proven: false });
  s.rebindSignKey('bob', 'OWNER'); // владелец доказал владение box-ключом — перебивает
  assert.deepStrictEqual(s.getIdentity('bob'), { signPk: 'OWNER', proven: true });
  s.close();
});

test('M-02: evictColdIdentities вытесняет холодные БЕЗ очереди, каскадно чистит prekey/токен', () => {
  const s = fresh();
  // три identity с разной «свежестью» (last_seen) и своими prekey/токенами
  s.bindSignKey('cold', 'K1', true, 100);
  s.bindSignKey('warm', 'K2', true, 300);
  s.bindSignKey('busy', 'K3', true, 50); // самый холодный, НО с очередью — не трогаем
  s.setSpk('cold', { id: 'c', pub: 'p', sig: 'g' });
  s.setToken('cold', 'tok-cold');
  s.enqueue({ id: 'm1', to: 'busy', envelope: {}, ts: 1 }); // у busy есть ожидающий конверт
  assert.strictEqual(s.identityCount(), 3);

  // потолок 2 → вытесняется 1 самый холодный БЕЗ очереди = 'cold'
  const evicted = s.evictColdIdentities(2);
  assert.strictEqual(evicted, 1, 'вытеснена одна identity');
  assert.strictEqual(s.getIdentity('cold'), null, 'холодная без очереди вытеснена');
  assert.strictEqual(s.getSpk('cold'), null, 'её SPK удалён каскадно');
  assert.strictEqual(s.getToken('cold'), null, 'её push-токен удалён каскадно');
  assert.ok(s.getIdentity('busy'), 'identity с ожидающей очередью НЕ вытеснена, хоть и холоднее');
  assert.ok(s.getIdentity('warm'), 'тёплая identity на месте');

  // под потолком — ничего не вытесняется
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

// --- X3DH prekeys ------------------------------------------------------------

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

// --- вложения на диск (blob-хранилище) --------------------------------------
function freshBlobs(threshold = 100) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'licno-blobs-'));
  return { s: createStore(':memory:', { blobDir: dir, blobThreshold: threshold }), dir };
}
const bigEnvelope = () => ({ cipher: 'x'.repeat(500) });
const blobFiles = (dir) => fs.readdirSync(dir).filter((f) => f.endsWith('.json'));

test('blob: крупный конверт уходит файлом, мелкий остаётся в БД', () => {
  const { s, dir } = freshBlobs();
  s.enqueue({ id: 'big', to: 'bob', from: 'alice', envelope: bigEnvelope(), ts: 1 });
  s.enqueue({ id: 'small', to: 'bob', from: 'alice', envelope: { cipher: 'hi' }, ts: 2 });
  assert.deepStrictEqual(blobFiles(dir), ['big.json']);
  const q = s.queueFor('bob');
  assert.deepStrictEqual(q.map((x) => x.id), ['big', 'small']);
  assert.deepStrictEqual(q[0].envelope, bigEnvelope()); // тело читается из файла
  assert.strictEqual(q[0].from, 'alice');
  s.close();
});

test('blob: ack удаляет и строку, и файл', () => {
  const { s, dir } = freshBlobs();
  s.enqueue({ id: 'big', to: 'bob', from: 'alice', envelope: bigEnvelope(), ts: 1 });
  assert.strictEqual(s.ack('bob', 'big'), 'alice');
  assert.strictEqual(blobFiles(dir).length, 0);
  s.close();
});

test('blob: вытеснение по maxPerUser удаляет файл старейшего', () => {
  const { s, dir } = freshBlobs();
  for (let i = 0; i < 3; i++) s.enqueue({ id: 'm' + i, to: 'bob', envelope: bigEnvelope(), ts: i, maxPerUser: 2 });
  assert.deepStrictEqual(s.queueFor('bob').map((x) => x.id), ['m1', 'm2']);
  assert.deepStrictEqual(blobFiles(dir).sort(), ['m1.json', 'm2.json']);
  s.close();
});

test('blob: TTL удаляет протухшие файлы', () => {
  const { s, dir } = freshBlobs();
  s.enqueue({ id: 'old', to: 'bob', envelope: bigEnvelope(), ts: 100 });
  s.enqueue({ id: 'new', to: 'bob', envelope: bigEnvelope(), ts: 1000 });
  assert.strictEqual(s.expireOlderThan(500), 1);
  assert.deepStrictEqual(blobFiles(dir), ['new.json']);
  s.close();
});

test('blob: пропавший файл — строка подчищается, очередь не ломается', () => {
  const { s, dir } = freshBlobs();
  s.enqueue({ id: 'big', to: 'bob', envelope: bigEnvelope(), ts: 1 });
  s.enqueue({ id: 'small', to: 'bob', envelope: { cipher: 'hi' }, ts: 2 });
  fs.unlinkSync(path.join(dir, 'big.json')); // volume почистили руками
  assert.deepStrictEqual(s.queueFor('bob').map((x) => x.id), ['small']);
  assert.strictEqual(s.getItem('big'), null); // мёртвая строка удалена
  s.close();
});

test('blob: cleanupOrphanBlobs убирает сирот и tmp, живые не трогает', () => {
  const { s, dir } = freshBlobs();
  s.enqueue({ id: 'live', to: 'bob', envelope: bigEnvelope(), ts: 1 });
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
  s.enqueue({ id: 'small', to: 'bob', envelope: { cipher: 'hi' }, ts: 1 }); // в БД
  s.enqueue({ id: 'big', to: 'bob', envelope: bigEnvelope(), ts: 2 }); // файлом
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

function deviceCertificate(accountPk, rootSignPk, id, pk, signPk, issuedAt = 1000) {
  return {
    v: 2,
    type: 'licno-device-certificate',
    accountPublicKey: accountPk,
    accountSignPublicKey: rootSignPk,
    deviceId: id,
    devicePublicKey: pk,
    deviceSignPublicKey: signPk,
    name: id === 'phone' ? 'Телефон Android' : 'Домашний компьютер',
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
  const desktop = deviceCertificate('account-pk', 'root-sign-pk', 'desktop', 'desktop-pk', 'desktop-sign-pk', 2000);
  const v1 = roster(1, [{ certificate: phone, revokedAt: null }]);
  const first = s.putAccountRoster(v1);
  assert.strictEqual(first.ok, true);
  assert.strictEqual(s.getAccount('account-pk').rosterVersion, 1);
  assert.deepStrictEqual(s.getAccountRoster('account-pk'), v1);
  assert.strictEqual(s.getDevice('account-pk').deviceId, 'phone');

  const v2 = roster(2, [
    { certificate: phone, revokedAt: null },
    { certificate: desktop, revokedAt: null },
  ]);
  assert.strictEqual(s.putAccountRoster(v2).ok, true);
  assert.strictEqual(s.devicesForAccount('account-pk').length, 2);
  assert.strictEqual(s.getDevice('desktop-pk').revokedAt, null);
  assert.strictEqual(s.putAccountRoster(v2).unchanged, true, 'повтор идемпотентен');
  assert.strictEqual(s.putAccountRoster(v1).reason, 'stale-roster');
  assert.strictEqual(s.putAccountRoster({ ...v2, rootSignature: 'other' }).reason, 'roster-version-conflict');
  s.close();
});

test('linked devices: отзыв необратим тем же сертификатом и чистит транспорт', () => {
  const s = fresh();
  const phone = deviceCertificate('account-pk', 'root-sign-pk', 'phone', 'account-pk', 'root-sign-pk');
  const desktop = deviceCertificate('account-pk', 'root-sign-pk', 'desktop', 'desktop-pk', 'desktop-sign-pk', 2000);
  s.putAccountRoster(
    roster(1, [
      { certificate: phone, revokedAt: null },
      { certificate: desktop, revokedAt: null },
    ])
  );
  s.enqueue({ id: 'for-desktop', to: 'desktop-pk', from: 'sender', envelope: { cipher: 'x' }, ts: 1 });
  s.setToken('desktop-pk', 'push-token');
  s.setSpk('desktop-pk', { id: 'spk', pub: 'pub', sig: 'sig' });
  s.replaceOtps('desktop-pk', [{ id: 'otp', pub: 'pub' }]);

  const revoked = s.putAccountRoster(
    roster(2, [
      { certificate: phone, revokedAt: null },
      { certificate: desktop, revokedAt: 2500 },
    ], 2500)
  );
  assert.deepStrictEqual(revoked.revokedDeviceKeys, ['desktop-pk']);
  assert.strictEqual(s.getDevice('desktop-pk').revokedAt, 2500);
  assert.strictEqual(s.purgeDeviceTransport('desktop-pk'), 1);
  assert.strictEqual(s.queueFor('desktop-pk').length, 0);
  assert.strictEqual(s.getToken('desktop-pk'), null);
  assert.strictEqual(s.getSpk('desktop-pk'), null);
  assert.strictEqual(s.countOtps('desktop-pk'), 0);

  const replay = s.putAccountRoster(
    roster(3, [
      { certificate: phone, revokedAt: null },
      { certificate: desktop, revokedAt: null },
    ], 3000)
  );
  assert.strictEqual(replay.reason, 'device-revoked');
  s.close();
});

console.log('\n' + passed + ' passed');
