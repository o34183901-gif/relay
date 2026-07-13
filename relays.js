/**
 * relays.js — ЧИСТАЯ логика реплицированного каталога релеев (gossip).
 *
 * Каталог держит не один «главный» релей, а КАЖДЫЙ: список известных релеев
 * реплицируется между узлами эпидемически (каждый периодически тянет /relays у
 * пиров и сливает). Клиент может спросить список у любого релея — падение одного
 * ничего не ломает. Здесь только чистые функции (нормализация/валидация/слияние),
 * чтобы их можно было тестировать без сети (см. server/test.js).
 */

const net = require('net');

const MAX_RELAYS = 500; // потолок каталога: защита от «отравления» списка мусором

/** Привести URL релея к канону: обрезать пробелы и хвостовые слэши. */
function normalizeRelayUrl(url) {
  if (typeof url !== 'string') return null;
  const u = url.trim().replace(/\/+$/, '');
  if (!u) return null;
  return u;
}

// M-1 (SSRF, defence-in-depth): литеральные приватные/loopback/link-local и
// метаданные-адреса в каталоге недопустимы — иначе анонсированный релей
// вида ws://169.254.169.254 или ws://127.0.0.1 заставлял бы узел ходить к
// внутренним сервисам (gossip делает исходящие запросы к адресам каталога).
// Хостнеймы, резолвящиеся в приватные IP, дополнительно отсекаются перед
// самим запросом (см. relay.js: SSRF-guard в fetchPeerRelays/pushSelfTo).
// Приватен ли IPv4-октет-квартет: loopback / private / link-local (+ метаданные
// 169.254.169.254) / CGNAT / multicast+reserved. Fail-closed: любой невалидный
// или зарезервированный октет считаем приватным (не ходим).
function isPrivateIPv4(a, b, c, d) {
  if ([a, b, c, d].some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  if (a === 0 || a === 10 || a === 127) return true; // this-network / private / loopback
  if (a === 169 && b === 254) return true; // link-local + метаданные облака 169.254.169.254
  if (a === 172 && b >= 16 && b <= 31) return true; // private
  if (a === 192 && b === 168) return true; // private
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  if (a >= 224) return true; // multicast / зарезервировано
  return false;
}

// Развернуть IPv6-строку в 8 групп (числа). Поддерживает сжатие "::" и встроенный
// IPv4 в хвосте (mapped/compat). null — если это не валидный IPv6. C-3: раньше
// IPv6 проверялся хрупкими регэкспами, из-за чего IPv4-mapped (`::ffff:127.0.0.1`,
// `::ffff:169.254.169.254`) и развёрнутый loopback (`0:0:0:0:0:0:0:1`) считались
// «публичными» и обходили SSRF-фильтр. Теперь адрес нормализуется целиком.
function ipv6Groups(h) {
  if (!net.isIPv6(h)) return null;
  let s = h;
  // Встроенный точечный IPv4 в хвосте -> две hex-группы.
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
  // Снять скобки IPv6 и хвостовой :port БЕЗОПАСНО — не откусывая часть самого
  // IPv6-адреса (напр. завершающую группу у `0:0:...:1`).
  const br = h.match(/^\[([^\]]+)\](?::\d+)?$/);
  if (br) h = br[1];
  else if (!net.isIP(h)) h = h.replace(/:\d+$/, ''); // hostname / IPv4 с портом
  if (!h) return true;

  // Имена
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local')) return true;

  // IPv4-литерал (точечный)
  const m4 = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m4) return isPrivateIPv4(Number(m4[1]), Number(m4[2]), Number(m4[3]), Number(m4[4]));

  // IPv4 одним десятичным числом (классический обход: `ws://2130706433`).
  if (/^\d+$/.test(h)) {
    const n = Number(h);
    if (Number.isFinite(n) && n >= 0 && n <= 0xffffffff) {
      return isPrivateIPv4((n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
    }
    return true; // подозрительный число-хост — не ходим
  }

  // IPv6 (сжатый/развёрнутый, IPv4-mapped/compat)
  const g = ipv6Groups(h);
  if (g) {
    if (g.every((x) => x === 0)) return true; // :: (unspecified)
    // ::1 loopback
    if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0 && g[6] === 0 && g[7] === 1)
      return true;
    // IPv4-mapped ::ffff:a.b.c.d и IPv4-compat ::a.b.c.d -> проверить вложенный IPv4
    if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0 && (g[5] === 0xffff || g[5] === 0)) {
      return isPrivateIPv4((g[6] >> 8) & 255, g[6] & 255, (g[7] >> 8) & 255, g[7] & 255);
    }
    if ((g[0] & 0xfe00) === 0xfc00) return true; // ULA fc00::/7
    if ((g[0] & 0xffc0) === 0xfe80) return true; // link-local fe80::/10
    return false;
  }
  return false;
}

/** Валиден ли URL релея: только ws:// или wss://, разумной длины, публичный хост. */
function isValidRelayUrl(url) {
  const u = normalizeRelayUrl(url);
  if (!u || u.length > 256) return false;
  if (!/^wss?:\/\//i.test(u)) return false;
  const host = u.replace(/^wss?:\/\//i, '').replace(/[/?#].*$/, '');
  // хост непустой и без пробельных символов (переносы/табы/пробелы = инъекция).
  // Дефисы и точки в хостах допустимы.
  if (!host || /\s/.test(host)) return false;
  if (isPrivateHost(host)) return false;
  return true;
}

/**
 * Слить входящий список в текущий каталог. Возвращает НОВЫЙ массив уникальных
 * валидных URL (нормализованных), с сохранением порядка «сначала старые», и
 * усечением до MAX_RELAYS. Невалидные записи молча отбрасываются.
 */
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

// H-2/M-4: конфиг coturn генерирует САМ релей (он владелец секрета) и пишет его в
// data-том с правами 0600 — секрета больше нет ни в аргументах процесса
// (ps/`docker inspect`), ни в переменных окружения, ни в world-readable файлах.
// Здесь — чистый билдер строки конфига (запись файла — в relay.js). Диапазоны
// denied-peer-ip закрывают ретрансляцию TURN во внутреннюю сеть и к облачным
// метаданным (open-relay / SSRF-плацдарм — M-4).
const COTURN_DENIED_RANGES = [
  '0.0.0.0-0.255.255.255',
  '10.0.0.0-10.255.255.255',
  '100.64.0.0-100.127.255.255', // CGNAT
  '127.0.0.0-127.255.255.255',
  '169.254.0.0-169.254.255.255', // link-local + метаданые облака
  '172.16.0.0-172.31.255.255',
  '192.168.0.0-192.168.255.255',
  '::1',
  'fc00::-fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', // ULA
  'fe80::-febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff', // link-local
];

function coturnConfigText(secret, { turnHost } = {}) {
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
    'min-port=49160',
    'max-port=49200',
  ];
  if (turnHost) lines.push(`external-ip=${turnHost}`);
  for (const r of COTURN_DENIED_RANGES) lines.push(`denied-peer-ip=${r}`);
  lines.push('');
  return lines.join('\n');
}

module.exports = {
  MAX_RELAYS,
  normalizeRelayUrl,
  isValidRelayUrl,
  isPrivateHost,
  mergeRelays,
  coturnConfigText,
  COTURN_DENIED_RANGES,
};
