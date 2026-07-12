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

/** Валиден ли URL релея: только ws:// или wss://, разумной длины, с хостом. */
function isValidRelayUrl(url) {
  const u = normalizeRelayUrl(url);
  if (!u || u.length > 256) return false;
  if (!/^wss?:\/\//i.test(u)) return false;
  const host = u.replace(/^wss?:\/\//i, '');
  // хост непустой и без пробельных символов (переносы/табы/пробелы = инъекция).
  // Дефисы и точки в хостах допустимы.
  if (!host || /\s/.test(host)) return false;
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

module.exports = { MAX_RELAYS, normalizeRelayUrl, isValidRelayUrl, mergeRelays };
