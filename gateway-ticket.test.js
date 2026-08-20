'use strict';
const assert = require('assert');
const nacl = require('tweetnacl');
const ticketRule = require('./gateway-ticket');
let passed = 0;
function test(name, fn) {
  fn();
  passed += 1;
  console.log('  ✓ ' + name);
}

function b64(bytes) {
  return Buffer.from(bytes).toString('base64');
}
function unb64(value) {
  return new Uint8Array(Buffer.from(value, 'base64'));
}

const owner = nacl.sign.keyPair();
const agent = nacl.sign.keyPair();
const OWNER_SIGN = b64(owner.publicKey);
const AGENT_SIGN = b64(agent.publicKey);
const OWNER_ADDR = b64(nacl.box.keyPair().publicKey);
const AGENT_ADDR = b64(nacl.box.keyPair().publicKey);
const NOW = 1_700_000_000_000;

function sign(bytes) {
  return b64(nacl.sign.detached(bytes, owner.secretKey));
}
function verify(bytes, sig, publicKey) {
  return nacl.sign.detached.verify(bytes, unb64(sig), unb64(publicKey));
}
function issue(overrides = {}) {
  return ticketRule.buildTicket({
    addr: OWNER_ADDR,
    agent: AGENT_ADDR,
    agentSign: AGENT_SIGN,
    now: NOW,
    nonce: 'н-' + Math.random().toString(36).slice(2, 10),
    sign,
    ...overrides,
  });
}
const PRESENTER = { addr: AGENT_ADDR, signKey: AGENT_SIGN };
function check(candidate, extra = {}) {
  return ticketRule.checkTicket({
    candidate,
    ownerSignKey: OWNER_SIGN,
    presenter: PRESENTER,
    now: NOW,
    verify,
    ...extra,
  });
}
console.log('жетон доступа к своей очереди (ЭТП5-4)');
test('годный жетон проходит', () => {
  const result = check(issue());
  assert.strictEqual(result.ok, true, result.reason);
  assert.strictEqual(result.ticket.addr, OWNER_ADDR, 'жетон обязан называть ровно одну очередь');
});
test('перехваченный жетон бесполезен другому предъявителю', () => {
  const ticket = issue();
  const other = { addr: b64(nacl.box.keyPair().publicKey), signKey: b64(nacl.sign.keyPair().publicKey) };
  assert.strictEqual(check(ticket, { presenter: other }).reason, 'не тот предъявитель');
  assert.strictEqual(
    check(ticket, { presenter: { addr: AGENT_ADDR, signKey: other.signKey } }).reason,
    'не тот предъявитель'
  );
  assert.strictEqual(
    check(ticket, { presenter: { addr: other.addr, signKey: AGENT_SIGN } }).reason,
    'не тот предъявитель'
  );
  assert.strictEqual(check(ticket, { presenter: null }).reason, 'не тот предъявитель');
});
test('срок работает в обе стороны', () => {
  const ticket = issue();
  assert.strictEqual(check(ticket, { now: NOW + ticketRule.TICKET_TTL_MS + ticketRule.CLOCK_SKEW_MS + 1 }).reason, 'срок');
  assert.strictEqual(check(ticket, { now: NOW - ticketRule.CLOCK_SKEW_MS - 1 }).reason, 'срок');
  assert.strictEqual(check(ticket, { now: NOW - ticketRule.CLOCK_SKEW_MS + 1000 }).ok, true);
});
test('использованный жетон второй раз не проходит', () => {
  const ledger = ticketRule.createTicketLedger({ now: () => NOW });
  const ticket = issue();
  const first = check(ticket, { used: (nonce) => ledger.used(nonce) });
  assert.strictEqual(first.ok, true, first.reason);
  ledger.remember(first.ticket);
  assert.strictEqual(check(ticket, { used: (nonce) => ledger.used(nonce) }).reason, 'повтор');
  assert.strictEqual(check(issue(), { used: (nonce) => ledger.used(nonce) }).ok, true);
});
test('память о жетонах не растёт вечно', () => {
  const clock = { at: NOW };
  const ledger = ticketRule.createTicketLedger({ now: () => clock.at });
  ledger.remember(issue({ nonce: 'первый' }));
  ledger.remember(issue({ nonce: 'второй' }));
  assert.strictEqual(ledger.size(), 2);
  clock.at = NOW + ticketRule.TICKET_TTL_MS + ticketRule.CLOCK_SKEW_MS + 1;
  assert.strictEqual(ledger.size(), 0, 'просроченные жетоны обязаны выметаться');
});
test('REL-23: реестр вытесняет по сроку, а не FIFO — использованный жетон помнится до expiry', () => {
  const AT = 1_000_000_000_000;
  const ledger = ticketRule.createTicketLedger({ now: () => AT, limit: 4 });
  const late = AT + 9 * 60 * 1000;
  const early = AT + 60 * 1000;
  ledger.remember({ nonce: 'использован-поздний', expiresAt: late });
  for (let i = 0; i < 4; i += 1) ledger.remember({ nonce: 'flood-' + i, expiresAt: early });
  assert.strictEqual(ledger.used('использован-поздний'), true, 'поздний жетон не вытеснен наплывом ранних');
  assert.ok(ledger.size() <= 4, 'реестр по-прежнему ограничен');
});
test('подделка любого поля ломает подпись', () => {
  const ticket = issue();
  const swaps = {
    addr: b64(nacl.box.keyPair().publicKey),
    agent: b64(nacl.box.keyPair().publicKey),
    agentSign: b64(nacl.sign.keyPair().publicKey),
    issuedAt: ticket.issuedAt + 1000,
    expiresAt: ticket.expiresAt - 1000,
    nonce: 'подменённый',
  };
  for (const [field, value] of Object.entries(swaps)) {
    const forged = { ...ticket, [field]: value };
    const verdict = ticketRule.checkTicket({
      candidate: forged,
      ownerSignKey: OWNER_SIGN,
      presenter: {
        addr: field === 'agent' ? value : AGENT_ADDR,
        signKey: field === 'agentSign' ? value : AGENT_SIGN,
      },
      now: NOW,
      verify,
    });
    assert.strictEqual(verdict.ok, false, `подмена ${field} обязана отвергаться`);
    assert.strictEqual(verdict.reason, 'подпись', `подмена ${field}: отказ обязан быть по подписи`);
  }
});
test('чужая подпись не проходит', () => {
  const stranger = nacl.sign.keyPair();
  const forged = ticketRule.buildTicket({
    addr: OWNER_ADDR,
    agent: AGENT_ADDR,
    agentSign: AGENT_SIGN,
    now: NOW,
    nonce: 'чужой',
    sign: (bytes) => b64(nacl.sign.detached(bytes, stranger.secretKey)),
  });
  assert.strictEqual(check(forged).reason, 'подпись');
});
test('без закреплённого ключа владельца жетон не проверяется', () => {
  assert.strictEqual(check(issue(), { ownerSignKey: null }).reason, 'владелец не закреплён');
  assert.strictEqual(check(issue(), { ownerSignKey: '' }).reason, 'владелец не закреплён');
});
test('жетон на долгий срок не принимается', () => {
  const long = issue();
  long.expiresAt = long.issuedAt + 365 * 24 * 60 * 60 * 1000;
  assert.strictEqual(check(long).reason, 'форма');
  assert.strictEqual(ticketRule.parseTicket(long), null);
});
test('негодная форма отбрасывается до всякой работы', () => {
  assert.strictEqual(ticketRule.parseTicket(null), null);
  assert.strictEqual(ticketRule.parseTicket('строка'), null);
  assert.strictEqual(ticketRule.parseTicket([]), null);
  assert.strictEqual(ticketRule.parseTicket({ ...issue(), v: 2 }), null, 'чужая версия');
  assert.strictEqual(ticketRule.parseTicket({ ...issue(), sig: '' }), null, 'без подписи');
  assert.strictEqual(ticketRule.parseTicket({ ...issue(), addr: 'x'.repeat(200) }), null, 'слишком длинный адрес');
  assert.strictEqual(ticketRule.parseTicket({ ...issue(), issuedAt: 0 }), null);
  assert.strictEqual(
    ticketRule.parseTicket({ ...issue(), expiresAt: NOW - 1 }),
    null,
    'срок раньше выпуска'
  );
});
test('жетон не собирается без обязательного', () => {
  const full = {
    addr: OWNER_ADDR,
    agent: AGENT_ADDR,
    agentSign: AGENT_SIGN,
    now: NOW,
    nonce: 'н',
    sign,
  };
  for (const missing of Object.keys(full)) {
    const opts = { ...full };
    delete opts[missing];
    assert.throws(() => ticketRule.buildTicket(opts), Error, `без ${missing} жетон не должен собираться`);
  }
});
test('байты подписи одинаковы у обеих сторон', () => {
  const body = {
    addr: OWNER_ADDR,
    agent: AGENT_ADDR,
    agentSign: AGENT_SIGN,
    issuedAt: NOW,
    expiresAt: NOW + 1000,
    nonce: 'жетон-№1',
  };
  const mine = ticketRule.ticketBytes(body);
  const line =
    ticketRule.TICKET_PREFIX +
    `${OWNER_ADDR}|${AGENT_ADDR}|${AGENT_SIGN}|${NOW}|${NOW + 1000}|жетон-№1`;
  assert.deepStrictEqual(Buffer.from(mine), Buffer.from(line, 'utf8'), 'кодировка обязана быть UTF-8');
  assert.ok(Buffer.from(mine).toString('utf8').startsWith('licno-gw-ticket-v1|'));
});
console.log(`\nжетон доступа: ${passed} проверок пройдено`);