const net = require('net');

const MAX_RELAYS = 500;
function normalizeRelayUrl(url) {
  if (typeof url !== 'string') return null;
  const u = url.trim().replace(/\/+$/, '');
  if (!u) return null;
  return u;
}

function isPrivateIPv4(a, b, c, d) {
  if ([a, b, c, d].some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a >= 224) return true;
  return false;
}

function ipv6Groups(h) {
  if (!net.isIPv6(h)) return null;
  let s = h;
  const m = s.match(/^(.*:)((?:\d{1,3}\.){3}\d{1,3})$/);
  if (m) {
    const p = m[2].split('.').map((x) => parseInt(x, 10));
    if (p.some((n) => n > 255)) return null;
    s = m[1] + (((p[0] << 8) | p[1]) & 0xffff).toString(16) + ':' + (((p[2] << 8) | p[3]) & 0xffff).toString(16);
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  let groups;
  if (halves.length === 2) {
    const fill = 8 - head.length - tail.length;
    if (fill < 0) return null;
    groups = [...head, ...Array(fill).fill('0'), ...tail];
  } else {
    groups = head;
  }
  if (groups.length !== 8) return null;
  return groups.map((x) => parseInt(x || '0', 16));
}
function isPrivateHost(host) {
  let h = String(host == null ? '' : host).trim().toLowerCase();
  const br = h.match(/^\[([^\]]+)\](?::\d+)?$/);
  if (br) h = br[1];
  else if (!net.isIP(h)) h = h.replace(/:\d+$/, '');
  if (!h) return true;
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local')) return true;
  const m4 = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m4) return isPrivateIPv4(Number(m4[1]), Number(m4[2]), Number(m4[3]), Number(m4[4]));
  if (/^\d+$/.test(h)) {
    const n = Number(h);
    if (Number.isFinite(n) && n >= 0 && n <= 0xffffffff) {
      return isPrivateIPv4((n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
    }
    return true;
  }
  const g = ipv6Groups(h);
  if (g) {
    if (g.every((x) => x === 0)) return true;
    if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0 && g[6] === 0 && g[7] === 1)
      return true;
    if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0 && (g[5] === 0xffff || g[5] === 0)) {
      return isPrivateIPv4((g[6] >> 8) & 255, g[6] & 255, (g[7] >> 8) & 255, g[7] & 255);
    }
    if ((g[0] & 0xfe00) === 0xfc00) return true;
    if ((g[0] & 0xffc0) === 0xfe80) return true;
    return false;
  }
  return false;
}
function isValidRelayUrl(url) {
  const u = normalizeRelayUrl(url);
  if (!u || u.length > 256) return false;
  if (!/^wss?:\/\//i.test(u)) return false;
  const host = u.replace(/^wss?:\/\//i, '').replace(/[/?#].*$/, '');
  if (!host || /\s/.test(host)) return false;
  if (isPrivateHost(host)) return false;
  return true;
}
function mergeRelays(current, incoming) {
  const seen = new Set();
  const out = [];
  const add = (raw) => {
    if (!isValidRelayUrl(raw)) return;
    const u = normalizeRelayUrl(raw);
    const key = u.toLowerCase();
    if (seen.has(key)) return;
    seen.add(key);
    out.push(u);
  };
  for (const u of Array.isArray(current) ? current : []) add(u);
  for (const u of Array.isArray(incoming) ? incoming : []) add(u);
  return out.slice(0, MAX_RELAYS);
}
const COTURN_DENIED_RANGES = [
  '0.0.0.0-0.255.255.255',
  '10.0.0.0-10.255.255.255',
  '100.64.0.0-100.127.255.255',
  '127.0.0.0-127.255.255.255',
  '169.254.0.0-169.254.255.255',
  '172.16.0.0-172.31.255.255',
  '192.168.0.0-192.168.255.255',
  '::1',
  'fc00::-fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
  'fe80::-febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
];
function coturnConfigText(secret, { turnHost, pidfile, userdb } = {}) {
  const lines = [
    'listening-port=3478',
    'fingerprint',
    'use-auth-secret',
    `static-auth-secret=${secret}`,
    'realm=licno',
    'no-tls',
    'no-dtls',
    'no-cli',
    'no-multicast-peers',
    'min-port=49152',
    'max-port=65535',
    'log-file=stdout',
  ];
  if (pidfile) lines.push(`pidfile=${pidfile}`);
  if (userdb) lines.push(`userdb=${userdb}`);
  if (turnHost) lines.push(`external-ip=${turnHost}`);
  for (const r of COTURN_DENIED_RANGES) lines.push(`denied-peer-ip=${r}`);
  lines.push('');
  return lines.join('\n');
}
function rateGate(state, now, windowMs, max) {
  const s = !state || now - state.start > windowMs ? { start: now, count: 0 } : state;
  return { allow: s.count < max, state: s };
}
function byteGate(state, now, bytes, windowMs, maxBytes, maxStrikes) {
  let s = state;
  if (!s || now - s.start >= windowMs) {
    s = { start: now, bytes: 0, strikes: s && s.bytes > maxBytes ? s.strikes : 0 };
  }
  const wasOver = s.bytes > maxBytes;
  const nextBytes = s.bytes + (bytes > 0 ? bytes : 0);
  const nowOver = nextBytes > maxBytes;
  const strikes = nowOver && !wasOver ? s.strikes + 1 : s.strikes;
  return {
    state: { start: s.start, bytes: nextBytes, strikes },
    pauseMs: nowOver ? Math.max(0, windowMs - (now - s.start)) : 0,
    abusive: nowOver && strikes >= maxStrikes,
  };
}
const TURN_PORT = 3478;
const TURN_TTL_SEC = 3600;
function buildIceServers(opts) {
  const o = opts || {};
  const turnHost = o.turnHost;
  const turnSecret = o.turnSecret;
  const port = o.port || TURN_PORT;
  if (turnSecret && turnHost) {
    const username = `${Math.floor((o.now || 0) / 1000) + (o.ttlSec || TURN_TTL_SEC)}:licno`;
    return [
      { urls: `stun:${turnHost}:${port}` },
      {
        urls: [`turn:${turnHost}:${port}?transport=udp`, `turn:${turnHost}:${port}?transport=tcp`],
        username,
        credential: o.hmac(username),
      },
    ];
  }
  return (Array.isArray(o.publicStun) ? o.publicStun : []).map((urls) => ({ urls }));
}
function parsePublicStun(value) {
  return String(value || '')
    .split(',')
    .map((item) => item.trim())
    .filter((item) => /^stuns?:/i.test(item));
}
module.exports = {
  MAX_RELAYS,
  normalizeRelayUrl,
  isValidRelayUrl,
  isPrivateHost,
  mergeRelays,
  coturnConfigText,
  COTURN_DENIED_RANGES,
  rateGate,
  byteGate,
  buildIceServers,
  parsePublicStun,
  TURN_PORT,
  TURN_TTL_SEC,
};