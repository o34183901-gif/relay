'use strict';

const VERSION = 1;
const PULL_CAPABILITY = 'gateway-pull-v1';
const TICKET_PREFIX = 'licno-gw-ticket-v1|';
const TICKET_TTL_MS = 10 * 60 * 1000;
const CLOCK_SKEW_MS = 2 * 60 * 1000;
const NONCE_BYTES = 12;
function text(value, max = 128) {
  return typeof value === 'string' ? value.slice(0, max) : '';
}

function ticketBytes({ addr, agent, agentSign, issuedAt, expiresAt, nonce }) {
  const line =
    TICKET_PREFIX +
    text(addr) +
    '|' +
    text(agent) +
    '|' +
    text(agentSign) +
    '|' +
    (Number.isFinite(issuedAt) ? Math.floor(issuedAt) : 0) +
    '|' +
    (Number.isFinite(expiresAt) ? Math.floor(expiresAt) : 0) +
    '|' +
    text(nonce, 32);
  return utf8Bytes(line);
}
function utf8Bytes(line) {
  const out = [];
  for (let i = 0; i < line.length; i += 1) {
    let code = line.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff && i + 1 < line.length) {
      const next = line.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        code = 0x10000 + ((code - 0xd800) << 10) + (next - 0xdc00);
        i += 1;
      }
    }
    if (code < 0x80) out.push(code);
    else if (code < 0x800) out.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
    else if (code < 0x10000)
      out.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
    else
      out.push(
        0xf0 | (code >> 18),
        0x80 | ((code >> 12) & 0x3f),
        0x80 | ((code >> 6) & 0x3f),
        0x80 | (code & 0x3f)
      );
  }
  return Uint8Array.from(out);
}
function buildTicket({ addr, agent, agentSign, now, ttlMs = TICKET_TTL_MS, nonce, sign }) {
  if (typeof addr !== 'string' || !addr) throw new Error('Нет адреса очереди');
  if (typeof agent !== 'string' || !agent) throw new Error('Неизвестно, кому выдан жетон');
  if (typeof agentSign !== 'string' || !agentSign) throw new Error('Нет ключа подписи соседа');
  if (typeof nonce !== 'string' || !nonce) throw new Error('Нет одноразового номера');
  if (typeof sign !== 'function') throw new Error('Нечем подписать жетон');
  if (!Number.isFinite(now) || now <= 0) throw new Error('Некорректное время выпуска');
  const issuedAt = Math.floor(now);
  const expiresAt = issuedAt + Math.max(1, Math.floor(ttlMs));
  const body = { v: VERSION, addr, agent, agentSign, issuedAt, expiresAt, nonce };
  return { ...body, sig: sign(ticketBytes(body)) };
}
function parseTicket(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  if (value.v !== VERSION) return null;
  for (const field of ['addr', 'agent', 'agentSign', 'sig']) {
    const item = value[field];
    if (typeof item !== 'string' || !item || item.length > 128) return null;
  }
  if (typeof value.nonce !== 'string' || !value.nonce || value.nonce.length > 32) return null;
  if (!Number.isFinite(value.issuedAt) || value.issuedAt <= 0) return null;
  if (!Number.isFinite(value.expiresAt) || value.expiresAt <= value.issuedAt) return null;
  if (value.expiresAt - value.issuedAt > TICKET_TTL_MS) return null;
  return {
    v: VERSION,
    addr: value.addr,
    agent: value.agent,
    agentSign: value.agentSign,
    issuedAt: Math.floor(value.issuedAt),
    expiresAt: Math.floor(value.expiresAt),
    nonce: value.nonce,
    sig: value.sig,
  };
}
function checkTicket({ candidate, ownerSignKey, presenter, now, verify, used = () => false }) {
  const ticket = parseTicket(candidate);
  if (!ticket) return { ok: false, reason: 'форма' };
  const at = Number.isFinite(now) ? now : 0;
  if (at > ticket.expiresAt + CLOCK_SKEW_MS) return { ok: false, reason: 'срок' };
  if (at + CLOCK_SKEW_MS < ticket.issuedAt) return { ok: false, reason: 'срок' };
  if (!presenter || ticket.agent !== presenter.addr) return { ok: false, reason: 'не тот предъявитель' };
  if (ticket.agentSign !== presenter.signKey) return { ok: false, reason: 'не тот предъявитель' };
  if (!ownerSignKey) return { ok: false, reason: 'владелец не закреплён' };
  if (used(ticket.nonce)) return { ok: false, reason: 'повтор' };
  let signed = false;
  try {
    signed = verify(ticketBytes(ticket), ticket.sig, ownerSignKey);
  } catch (error) {
    signed = false;
  }
  if (!signed) return { ok: false, reason: 'подпись' };
  return { ok: true, ticket };
}
function createTicketLedger({ now = () => Date.now(), limit = 4096 } = {}) {
  const seen = new Map();
  function sweep(at) {
    for (const [nonce, until] of seen) {
      if (until <= at) seen.delete(nonce);
    }
    while (seen.size > limit) {
      let victim = null;
      let soonest = Infinity;
      for (const [nonce, until] of seen) {
        if (until < soonest) {
          soonest = until;
          victim = nonce;
        }
      }
      if (victim === null) break;
      seen.delete(victim);
    }
  }
  return {
    used(nonce) {
      const at = now();
      sweep(at);
      const until = seen.get(nonce);
      return !!until && until > at;
    },
    remember(ticket) {
      if (!ticket || typeof ticket.nonce !== 'string') return false;
      const at = now();
      sweep(at);
      seen.set(ticket.nonce, ticket.expiresAt + CLOCK_SKEW_MS);
      return true;
    },
    size() {
      sweep(now());
      return seen.size;
    },
  };
}
module.exports = {
  VERSION,
  PULL_CAPABILITY,
  TICKET_PREFIX,
  TICKET_TTL_MS,
  CLOCK_SKEW_MS,
  NONCE_BYTES,
  ticketBytes,
  buildTicket,
  parseTicket,
  checkTicket,
  createTicketLedger,
};