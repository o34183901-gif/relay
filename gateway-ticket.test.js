/**
 * gateway-ticket.test.js — жетон доступа к своей очереди (ЭТП5-4).
 *
 * ЧТО ЗДЕСЬ ЗАЩИЩАЕТСЯ
 *
 * Жетон — это подписанное разрешение отдать НАШУ очередь чужому устройству.
 * Ошибка здесь стоит не «медленно», а «переписку читает посторонний», поэтому
 * проверяется каждая граница по отдельности:
 *
 *   • перехваченный жетон бесполезен другому предъявителю;
 *   • просроченный не работает, и «из будущего» тоже;
 *   • использованный второй раз не работает;
 *   • подделанное поле ломает подпись — какое бы поле ни поменяли;
 *   • жетон на год не выпускается даже своей же сборкой.
 *
 * Запуск: node server/gateway-ticket.test.js
 */

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
  // Именно эта проверка и делает жетон безопасным для передачи по сети
  // знакомств: он едет открыто, но годен ровно одному.
  const other = { addr: b64(nacl.box.keyPair().publicKey), signKey: b64(nacl.sign.keyPair().publicKey) };
  assert.strictEqual(check(ticket, { presenter: other }).reason, 'не тот предъявитель');
  // И половины совпадения мало: подменить можно любую.
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
  // «Из будущего» отвергаем не из педантизма: без этого владелец с
  // переведёнными вперёд часами выпускал бы жетоны, годные много дольше.
  assert.strictEqual(check(ticket, { now: NOW - ticketRule.CLOCK_SKEW_MS - 1 }).reason, 'срок');
  // А запас на расхождение часов обязан быть: иначе минута разницы между двумя
  // телефонами выглядела бы как «связь через соседа не работает».
  assert.strictEqual(check(ticket, { now: NOW - ticketRule.CLOCK_SKEW_MS + 1000 }).ok, true);
});

test('использованный жетон второй раз не проходит', () => {
  const ledger = ticketRule.createTicketLedger({ now: () => NOW });
  const ticket = issue();
  const first = check(ticket, { used: (nonce) => ledger.used(nonce) });
  assert.strictEqual(first.ok, true, first.reason);
  ledger.remember(first.ticket);
  assert.strictEqual(check(ticket, { used: (nonce) => ledger.used(nonce) }).reason, 'повтор');
  // Другой жетон того же владельца при этом проходит: одноразовость про жетон,
  // а не про владельца.
  assert.strictEqual(check(issue(), { used: (nonce) => ledger.used(nonce) }).ok, true);
});

test('память о жетонах не растёт вечно', () => {
  const clock = { at: NOW };
  const ledger = ticketRule.createTicketLedger({ now: () => clock.at });
  ledger.remember(issue({ nonce: 'первый' }));
  ledger.remember(issue({ nonce: 'второй' }));
  assert.strictEqual(ledger.size(), 2);
  // После истечения срока помнить нечего: жетон не годится и без памяти.
  clock.at = NOW + ticketRule.TICKET_TTL_MS + ticketRule.CLOCK_SKEW_MS + 1;
  assert.strictEqual(ledger.size(), 0, 'просроченные жетоны обязаны выметаться');
});

test('подделка любого поля ломает подпись', () => {
  const ticket = issue();
  // Каждое поле, оставленное за подписью, — это то, что можно поменять по
  // дороге. Поэтому проверяем ВСЕ, а не выборочно.
  const swaps = {
    addr: b64(nacl.box.keyPair().publicKey),
    agent: b64(nacl.box.keyPair().publicKey),
    agentSign: b64(nacl.sign.keyPair().publicKey),
    // Сдвигаем ВНУТРЬ допустимого срока: иначе отказ пришёл бы по форме, и
    // проверка подписи осталась бы непроверенной.
    issuedAt: ticket.issuedAt + 1000,
    expiresAt: ticket.expiresAt - 1000,
    nonce: 'подменённый',
  };
  for (const [field, value] of Object.entries(swaps)) {
    const forged = { ...ticket, [field]: value };
    const verdict = ticketRule.checkTicket({
      candidate: forged,
      ownerSignKey: OWNER_SIGN,
      // Предъявителя подстраиваем под подделку, чтобы отказ был именно из-за
      // подписи, а не из-за несовпадения предъявителя.
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
  // Подписать «разрешение на чужую очередь» может кто угодно — значение имеет
  // только то, чей ключ ЗАКРЕПЛЁН за адресом на этом релее.
  assert.strictEqual(check(forged).reason, 'подпись');
});

test('без закреплённого ключа владельца жетон не проверяется', () => {
  // Адрес, за которым ещё никто не закрепился, — это не повод отдать очередь.
  // Ровно наоборот: закрепиться мог бы и сам предъявитель.
  assert.strictEqual(check(issue(), { ownerSignKey: null }).reason, 'владелец не закреплён');
  assert.strictEqual(check(issue(), { ownerSignKey: '' }).reason, 'владелец не закреплён');
});

test('жетон на долгий срок не принимается', () => {
  const long = issue();
  long.expiresAt = long.issuedAt + 365 * 24 * 60 * 60 * 1000;
  // Даже за подписью владельца: своя сборка могла быть подменена, а один
  // потерянный телефон соседа не должен оставаться ключом к очереди на год.
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
  // Модуль общий для сервера (Node) и телефона (React Native). Разойдись
  // кодировка — телефон подписывал бы одни байты, релей проверял бы другие, и
  // связь через соседа не работала бы вовсе, без единого объяснения.
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
  // И домен обязан входить: без него подпись жетона можно было бы предъявить
  // как подпись чего-то другого, что подписывается тем же ключом.
  assert.ok(Buffer.from(mine).toString('utf8').startsWith('licno-gw-ticket-v1|'));
});

console.log(`\nжетон доступа: ${passed} проверок пройдено`);
