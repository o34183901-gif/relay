/**
 * relays.js — ЧИСТАЯ логика реплицированного каталога релеев (gossip).
 *
 * Каталог держит не один «главный» релей, а КАЖДЫЙ: список известных релеев
 * реплицируется между узлами эпидемически (каждый периодически тянет /relays у
 * пиров и сливает). Клиент может спросить список у любого релея — падение одного
 * ничего не ломает. Здесь только чистые функции (нормализация/валидация/слияние),
 * чтобы их можно было тестировать без сети (см. server/test.js).
 */

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
function isPrivateHost(host) {
  const h = String(host).toLowerCase().replace(/:\d+$/, '').replace(/^\[|\]$/g, '');
  if (!h) return true;
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local')) return true;
  if (h === '0.0.0.0' || h === '::' || h === '::1') return true;
  // IPv4-литералы: loopback / private / link-local / CGNAT / metadata
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const [a, b] = [Number(m[1]), Number(m[2])];
    if (a === 127 || a === 10 || a === 0) return true;
    if (a === 169 && b === 254) return true; // link-local + 169.254.169.254
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  }
  // IPv6 unique-local (fc00::/7) и link-local (fe80::/10)
  if (/^f[cd][0-9a-f]{2}:/.test(h) || /^fe[89ab][0-9a-f]:/.test(h)) return true;
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

module.exports = { MAX_RELAYS, normalizeRelayUrl, isValidRelayUrl, isPrivateHost, mergeRelays };
