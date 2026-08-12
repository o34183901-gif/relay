/**
 * reports.test.js — правила приёма и выдачи отчётов о неполадках (ОТЧ-1).
 *
 * ЧТО ЗДЕСЬ ВАЖНО
 *
 * Узел принимает отчёты БЕЗ аутентификации — иначе их не пришлёт как раз тот, у
 * кого сломалась аутентификация. Значит вся защита держится на трёх правилах:
 * форма посылки, потолок размера и доказанное право владельца забрать
 * накопленное. Ошибка в третьем означает, что отчёты пользователей может
 * скачать кто угодно; ошибка в первых двух — что диск узла заливают чем попало.
 */
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
  const sig = reports.signOwnerRequest({ domain: reports.FETCH_DOMAIN, ts, secretKey: OWNER_SEC });
  const verdict = reports.verifyOwnerRequest({
    domain: reports.FETCH_DOMAIN,
    ts,
    signature: sig,
    publicKey: OWNER_PUB,
    now: ts + 1000,
  });
  assert.deepStrictEqual(verdict, { ok: true });
});

test('чужая подпись не открывает ничего', () => {
  const ts = 1770000000000;
  const stranger = nacl.sign.keyPair();
  const sig = reports.signOwnerRequest({
    domain: reports.FETCH_DOMAIN,
    ts,
    secretKey: naclUtil.encodeBase64(stranger.secretKey),
  });
  const verdict = reports.verifyOwnerRequest({
    domain: reports.FETCH_DOMAIN,
    ts,
    signature: sig,
    publicKey: OWNER_PUB,
    now: ts,
  });
  assert.strictEqual(verdict.ok, false);
  assert.strictEqual(verdict.reason, 'signature');
});

test('подпись на ЧТЕНИЕ не стирает отчёты', () => {
  // Домены разные намеренно: подсмотренная ссылка выдачи не должна работать
  // как удаление, даже если её повторить слово в слово.
  const ts = 1770000000000;
  const fetchSig = reports.signOwnerRequest({ domain: reports.FETCH_DOMAIN, ts, secretKey: OWNER_SEC });
  const verdict = reports.verifyOwnerRequest({
    domain: reports.DELETE_DOMAIN,
    ts,
    signature: fetchSig,
    publicKey: OWNER_PUB,
    now: ts,
  });
  assert.strictEqual(verdict.ok, false, 'подпись чтения на удалении не годится');
});

test('просроченная подпись не работает — и из будущего тоже', () => {
  const ts = 1770000000000;
  const sig = reports.signOwnerRequest({ domain: reports.FETCH_DOMAIN, ts, secretKey: OWNER_SEC });
  const stale = reports.verifyOwnerRequest({
    domain: reports.FETCH_DOMAIN,
    ts,
    signature: sig,
    publicKey: OWNER_PUB,
    now: ts + reports.REQUEST_TTL_MS + 1,
  });
  assert.strictEqual(stale.reason, 'stale', 'подсмотренная ссылка перестаёт работать');
  const future = reports.verifyOwnerRequest({
    domain: reports.FETCH_DOMAIN,
    ts,
    signature: sig,
    publicKey: OWNER_PUB,
    now: ts - reports.REQUEST_TTL_MS - 1,
  });
  assert.strictEqual(future.reason, 'stale', 'окно двустороннее — часы узлов расходятся');
});

test('битые входные данные не роняют проверку', () => {
  assert.strictEqual(reports.verifyOwnerRequest({ domain: 'x', ts: 'вчера', now: 1 }).reason, 'ts');
  assert.strictEqual(
    reports.verifyOwnerRequest({ domain: 'x', ts: 1, signature: 'не base64!!!', publicKey: OWNER_PUB, now: 1 }).ok,
    false
  );
  assert.strictEqual(
    reports.verifyOwnerRequest({ domain: 'x', ts: 1, signature: 'YQ==', publicKey: '', now: 1 }).reason,
    'key'
  );
});

console.log(`\nreports (ОТЧ-1): ${passed} passed`);
