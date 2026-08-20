const assert = require('assert');
const nacl = require('tweetnacl');
const naclUtil = require('tweetnacl-util');
const reports = require('./reports');
let passed = 0;
function test(name, fn) {
  fn();
  console.log('  ✓ ' + name);
  passed++;
}
const owner = nacl.sign.keyPair();
const OWNER_PUB = naclUtil.encodeBase64(owner.publicKey);
const OWNER_SEC = naclUtil.encodeBase64(owner.secretKey);
const HOST = 'relay-a.example';
const goodBody = { v: 1, ek: 'ZWs=', nonce: 'bm9uY2U=', cipher: 'Y2lwaGVy' };
test('годная посылка принимается', () => {
  assert.deepStrictEqual(reports.validReport(goodBody, 128), { ok: true });
});

test('мусор вместо посылки не принимается', () => {
  assert.strictEqual(reports.validReport(null).ok, false);
  assert.strictEqual(reports.validReport('строка').ok, false);
  assert.strictEqual(reports.validReport({ ...goodBody, v: 2 }).reason, 'version');
  assert.strictEqual(reports.validReport({ ...goodBody, cipher: '' }).reason, 'field:cipher');
  assert.strictEqual(reports.validReport({ v: 1, ek: 'a', nonce: 'b' }).reason, 'field:cipher');
});

test('посылка сверх потолка не принимается', () => {
  const verdict = reports.validReport(goodBody, reports.MAX_REPORT_BYTES + 1);
  assert.strictEqual(verdict.ok, false);
  assert.strictEqual(verdict.reason, 'size');
});

test('подпись владельца открывает выдачу', () => {
  const ts = 1770000000000;
  const sig = reports.signOwnerRequest({ domain: reports.FETCH_DOMAIN, ts, host: HOST, secretKey: OWNER_SEC });
  const verdict = reports.verifyOwnerRequest({
    domain: reports.FETCH_DOMAIN,
    ts,
    host: HOST,
    signature: sig,
    publicKey: OWNER_PUB,
    now: ts + 1000,
  });
  assert.deepStrictEqual(verdict, { ok: true });
});

test('INF-01: подпись одного релея не открывает выдачу на другом', () => {
  const ts = 1770000000000;
  const sig = reports.signOwnerRequest({ domain: reports.FETCH_DOMAIN, ts, host: HOST, secretKey: OWNER_SEC });
  const other = reports.verifyOwnerRequest({
    domain: reports.FETCH_DOMAIN,
    ts,
    host: 'relay-b.example',
    signature: sig,
    publicKey: OWNER_PUB,
    now: ts + 1000,
  });
  assert.strictEqual(other.ok, false, 'подпись хоста A прокатилась на хост B — флот воспроизводим');
  assert.strictEqual(other.reason, 'signature');
  const noHost = reports.verifyOwnerRequest({
    domain: reports.FETCH_DOMAIN,
    ts,
    signature: sig,
    publicKey: OWNER_PUB,
    now: ts + 1000,
  });
  assert.strictEqual(noHost.reason, 'host', 'запрос без привязки к хосту обязан отвергаться');
  assert.throws(
    () => reports.signOwnerRequest({ domain: reports.FETCH_DOMAIN, ts, secretKey: OWNER_SEC }),
    /host/,
    'подпись без хоста не должна выпускаться'
  );
});

test('чужая подпись не открывает ничего', () => {
  const ts = 1770000000000;
  const stranger = nacl.sign.keyPair();
  const sig = reports.signOwnerRequest({
    domain: reports.FETCH_DOMAIN,
    ts,
    host: HOST,
    secretKey: naclUtil.encodeBase64(stranger.secretKey),
  });
  const verdict = reports.verifyOwnerRequest({
    domain: reports.FETCH_DOMAIN,
    ts,
    host: HOST,
    signature: sig,
    publicKey: OWNER_PUB,
    now: ts,
  });
  assert.strictEqual(verdict.ok, false);
  assert.strictEqual(verdict.reason, 'signature');
});
test('подпись на ЧТЕНИЕ не стирает отчёты', () => {
  const ts = 1770000000000;
  const fetchSig = reports.signOwnerRequest({ domain: reports.FETCH_DOMAIN, ts, host: HOST, secretKey: OWNER_SEC });
  const verdict = reports.verifyOwnerRequest({
    domain: reports.DELETE_DOMAIN,
    ts,
    host: HOST,
    signature: fetchSig,
    publicKey: OWNER_PUB,
    now: ts,
  });
  assert.strictEqual(verdict.ok, false, 'подпись чтения на удалении не годится');
});
test('просроченная подпись не работает — и из будущего тоже', () => {
  const ts = 1770000000000;
  const sig = reports.signOwnerRequest({ domain: reports.FETCH_DOMAIN, ts, host: HOST, secretKey: OWNER_SEC });
  const stale = reports.verifyOwnerRequest({
    domain: reports.FETCH_DOMAIN,
    ts,
    host: HOST,
    signature: sig,
    publicKey: OWNER_PUB,
    now: ts + reports.REQUEST_TTL_MS + 1,
  });
  assert.strictEqual(stale.reason, 'stale', 'подсмотренная ссылка перестаёт работать');
  const future = reports.verifyOwnerRequest({
    domain: reports.FETCH_DOMAIN,
    ts,
    host: HOST,
    signature: sig,
    publicKey: OWNER_PUB,
    now: ts - reports.REQUEST_TTL_MS - 1,
  });
  assert.strictEqual(future.reason, 'stale', 'окно двустороннее — часы узлов расходятся');
});
test('REL-08: свежая по формату подпись из будущего (в пределах TTL) отвергается', () => {
  const ts = 1770000000000;
  const sig = reports.signOwnerRequest({ domain: reports.FETCH_DOMAIN, ts, host: HOST, secretKey: OWNER_SEC });
  const nearFuture = reports.verifyOwnerRequest({
    domain: reports.FETCH_DOMAIN,
    ts,
    host: HOST,
    signature: sig,
    publicKey: OWNER_PUB,
    now: ts - Math.floor(reports.REQUEST_TTL_MS / 2),
  });
  assert.strictEqual(nearFuture.reason, 'stale', 'будущее время в пределах TTL больше не проходит');
});
test('битые входные данные не роняют проверку', () => {
  assert.strictEqual(reports.verifyOwnerRequest({ domain: 'x', ts: 'вчера', host: HOST, now: 1 }).reason, 'ts');
  assert.strictEqual(
    reports.verifyOwnerRequest({ domain: 'x', ts: 1, host: HOST, signature: 'не base64!!!', publicKey: OWNER_PUB, now: 1 }).ok,
    false
  );
  assert.strictEqual(
    reports.verifyOwnerRequest({ domain: 'x', ts: 1, host: HOST, signature: 'YQ==', publicKey: '', now: 1 }).reason,
    'key'
  );
});
console.log(`\nreports (ОТЧ-1): ${passed} passed`);