/**
 * mbx.js — общий ящик записок на релее (ПЯЩ-1). Правило, без базы и без сети.
 *
 * ЧТО ЗДЕСЬ ЛЕЖИТ И ПОЧЕМУ ОПЕРАТОРУ ЭТО ВАЖНО ЗНАТЬ
 *
 * Записка — 224 байта, которые кладёт один человек, чтобы другой смог его найти
 * после переезда на другой узел. Узел не знает о ней НИЧЕГО: ни кто положил, ни
 * кому, ни что внутри. Ключ записки — 32 байта, выведенные из секрета, который
 * есть только у двоих; значение — шифртекст; метка — код, который узел проверить
 * не может, потому что секрета у него нет.
 *
 * Это отличается от очереди конвертов, где у строки есть адрес получателя.
 * Здесь адреса нет вовсе, и оператор при всём желании не может сказать, чьё
 * лежит у него на диске. Ответ на вопрос «что у вас хранится» звучит так:
 * несколько сотен тысяч блобов по 224 байта без опознавательных признаков,
 * протухающих за тринадцать часов.
 *
 * ГЛАВНОЕ ПРАВИЛО: УЗЕЛ НЕ ОТВЕЧАЕТ НА ВОПРОС «ЕСТЬ ЛИ КЛЮЧ K»
 *
 * Такого кадра в протоколе нет и быть не должно. Ответив на него, узел связал бы
 * того, кто положил, с тем, кто спросил, — то есть выдал бы ребро графа
 * знакомств, ради сокрытия которого весь замысел и существует.
 *
 * Вместо вопроса узел отдаёт СВОДКУ обо всём, что у него лежит: она одинакова
 * для всех и не зависит от спросившего ни одним битом. Сверка идёт на телефоне.
 * При попадании телефон забирает КОРЗИНУ — сотню чужих записок, среди которых
 * его. Узел видит только номер корзины, а в корзине всегда достаточно чужого.
 *
 * ЧЕГО ЗДЕСЬ НЕТ
 *
 * Базы, сокетов и часов: записи, время и пределы приходят параметрами. Поэтому
 * весь порядок проверяется в Node без SQLite и без сети (server/mbx.test.js).
 */
const gcs = require('./mailboxGcs');

const VERSION = 1;

/** Длины — те же, что в src/mailbox.js. Расходиться им нельзя. */
const KEY_BYTES = 32;
const VALUE_BYTES = 176;
const MAC_BYTES = 16;
const RECORD_BYTES = KEY_BYTES + VALUE_BYTES + MAC_BYTES;

/** Сколько записок принимаем одним кадром. Столько же кладёт клиент за отрезок. */
const MAX_PUT_RECORDS = 8;

/** Отрезок и срок жизни. Те же шесть часов, что у ключа записки. */
const SLOT_MS = 6 * 60 * 60 * 1000;
const SLOT_TOLERANCE = 1;
const TTL_MS = 2 * SLOT_MS + 60 * 60 * 1000;

/**
 * Сколько записок обязано лежать в корзине.
 *
 * То же число, что у клиента. Узел не может проверить, честную ли глубину у него
 * попросили, — но может отказать в слишком узкой: корзина из десятка записок
 * почти называет ключ, и отдавать такую нельзя, даже если попросили.
 */
const BUCKET_MIN = 96;
const MAX_DEPTH = 16;

/** Потолок хранилища. Сверх него вытесняется самый старый отрезок целиком. */
const MAX_RECORDS = 400000;

/** Сколько записок отдаём соседнему узлу за один заход репликации. */
const SYNC_LIMIT = 4096;

function slotOf(now) {
  return Math.floor(now / SLOT_MS);
}

/**
 * Разобрать пачку записок из кадра.
 *
 * Возвращает массив записей либо null. Разбор строгий и ДО любых выделений
 * памяти: кадр приходит от кого угодно, а нестрогая проверка длины здесь — это
 * приглашение прислать мегабайт вместо восьми записок.
 */
function parsePut(bytes, { now = Date.now(), slot } = {}) {
  if (!(bytes instanceof Uint8Array) && !Buffer.isBuffer(bytes)) return null;
  if (!bytes.length || bytes.length % RECORD_BYTES !== 0) return null;
  const count = bytes.length / RECORD_BYTES;
  if (count > MAX_PUT_RECORDS) return null;
  if (!Number.isInteger(slot)) return null;
  // Отрезок обязан быть нашим: записка позавчерашнего отрезка либо просрочена,
  // либо это попытка занять место под ключ, который уже никто не спросит.
  if (Math.abs(slot - slotOf(now)) > SLOT_TOLERANCE) return null;

  const out = [];
  for (let i = 0; i < count; i += 1) {
    const at = i * RECORD_BYTES;
    out.push({
      key: Buffer.from(bytes.subarray(at, at + KEY_BYTES)),
      value: Buffer.from(bytes.subarray(at + KEY_BYTES, at + KEY_BYTES + VALUE_BYTES)),
      mac: Buffer.from(bytes.subarray(at + KEY_BYTES + VALUE_BYTES, at + RECORD_BYTES)),
      slot,
    });
  }
  return out;
}

/** Собрать записи обратно в пачку — для ответа корзиной и для репликации. */
function packRecords(records) {
  const list = Array.isArray(records) ? records : [];
  const out = Buffer.alloc(list.length * RECORD_BYTES);
  for (let i = 0; i < list.length; i += 1) {
    const at = i * RECORD_BYTES;
    Buffer.from(list[i].key).copy(out, at);
    Buffer.from(list[i].value).copy(out, at + KEY_BYTES);
    Buffer.from(list[i].mac).copy(out, at + KEY_BYTES + VALUE_BYTES);
  }
  return out;
}

/**
 * На какой глубине резать корзины при таком размере хранилища.
 *
 * То же правило, что у клиента, и считается независимо: клиент зажимает глубину
 * сверху сам, а узел — снизу. Так ни одна сторона не может заставить другую
 * работать с корзиной, из которой читается ключ.
 */
function bucketDepth(size) {
  if (!Number.isFinite(size) || size <= BUCKET_MIN) return 0;
  return Math.max(0, Math.min(MAX_DEPTH, Math.floor(Math.log2(size / BUCKET_MIN))));
}

/** Номер корзины ключа: старшие `depth` бит первых четырёх байт. */
function bucketOf(key, depth) {
  if (depth <= 0) return 0;
  const head = (key[0] << 24) >>> 0;
  const value = head + (key[1] << 16) + (key[2] << 8) + key[3];
  return Math.floor(value / 2 ** (32 - depth));
}

/**
 * Границы ключей корзины — для выборки диапазоном, без отдельного индекса.
 *
 * null — такой корзины на этой глубине не существует. Проверка обязательна:
 * номер приходит от клиента, а `writeUInt32BE` сворачивает всё, что не влезло в
 * четыре байта, по модулю. Без неё просьба о несуществующей корзине молча
 * отдавала бы нулевую — то есть чужие записки вместо отказа.
 */
function bucketRange(bucket, depth) {
  const low = Buffer.alloc(KEY_BYTES);
  const high = Buffer.alloc(KEY_BYTES, 0xff);
  if (!Number.isInteger(bucket) || bucket < 0) return null;
  if (depth <= 0) return bucket === 0 ? { low, high } : null;
  if (bucket >= 2 ** depth) return null;
  const shift = 2 ** (32 - depth);
  const start = bucket * shift;
  const end = (bucket + 1) * shift - 1;
  low.writeUInt32BE(start, 0);
  high.writeUInt32BE(end, 0);
  return { low, high };
}

/**
 * Можно ли отдать корзину такой глубины.
 *
 * Слишком узкую не отдаём даже по просьбе: попросивший корзину из одной записки
 * тем самым почти назвал ключ, и ответ на такую просьбу — это ответ на вопрос
 * «есть ли ключ K», которого в протоколе нет.
 */
function depthAllowed(depth, size) {
  if (!Number.isInteger(depth) || depth < 0 || depth > MAX_DEPTH) return false;
  return depth <= bucketDepth(size) + 1;
}

/**
 * Построить сводку.
 *
 * Считается РАЗ в отрезок и отдаётся всем одинаковой. Пересчитывать её на каждую
 * просьбу было бы и дорого (тридцать тысяч ключей), и опасно: сводка,
 * посчитанная в момент просьбы, отличалась бы у двоих спросивших подряд, и по
 * разнице читалось бы, что легло между ними.
 */
function buildDigest(keys) {
  const list = (Array.isArray(keys) ? keys : []).map((key) => Uint8Array.from(key));
  const digest = gcs.encode(list);
  return { v: VERSION, p: digest.p, n: digest.n, bits: Buffer.from(digest.bits) };
}

/**
 * Кэш сводки: пересчитывать не чаще раза в отрезок и не чаще, чем меняется ящик.
 *
 * `version` — любое значение, меняющееся при изменении хранилища. Совпало с
 * прошлым — отдаём готовые байты.
 *
 * КРИТ-04: ключи берутся ФУНКЦИЕЙ, а не значением.
 *
 * Прежняя подпись была `get(version, keys)`, и вызывающая сторона считала
 * `store.mbxKeys()` ДО обращения к кэшу — то есть на каждую просьбу, независимо
 * от попадания. А `mbxKeys()` — это выборка всех ключей ящика из базы, до
 * тридцати тысяч буферов. Кэш при этом честно возвращал готовую сводку и
 * выглядел работающим: экономил он ровно то, что стоит дёшево (кодирование
 * GCS), и не экономил то, что стоит дорого. Просьбы о сводке шли на общий
 * лимит кадров — восемьдесят в секунду, — и одно соединение выгребало базу
 * восемьдесят раз в секунду, не превысив ни одного порога.
 *
 * Ленивое чтение — половина лечения. Вторая в том, что здесь же кэшируется
 * ГОТОВАЯ строка base64: без неё каждая просьба заново кодировала килобайты
 * битового поля, и «отдать готовое» означало бы отдать готовое наполовину.
 */
function createDigestCache({ build = buildDigest } = {}) {
  let cached = null;
  let atVersion = null;
  // ПРФ-21: когда сводку считали в последний раз — для объединения пересчётов.
  let lastBuiltAt = null;
  return {
    /**
     * loadKeys — функция, отдающая ключи. Вызывается ТОЛЬКО при промахе.
     * Значение (массив) тоже принимается: так удобнее тестам и вызывающим,
     * у которых ключи уже на руках.
     */
    get(version, loadKeys) {
      if (cached && atVersion === version) return cached;
      const keys = typeof loadKeys === 'function' ? loadKeys() : loadKeys;
      const digest = build(keys);
      // Строка считается один раз вместе со сводкой: она едет в каждом ответе,
      // а меняется ровно тогда же, когда и сама сводка.
      cached = { ...digest, bitsBase64: Buffer.from(digest.bits).toString('base64') };
      atVersion = version;
      return cached;
    },
    /**
     * Пересчитать заранее, по событию изменения ящика.
     *
     * Смысл в том, чтобы к моменту просьбы работа была уже сделана: иначе
     * первая же просьба после изменения оплачивает и выборку, и кодирование —
     * и делает это в обработчике кадра, между приёмами других соединений.
     * Возвращает true, если пересчёт действительно понадобился.
     */
    refresh(version, loadKeys) {
      if (cached && atVersion === version) return false;
      this.get(version, loadKeys);
      lastBuiltAt = null; // считали прямо сейчас — окно объединения начнём заново
      return true;
    },

    /**
     * ПРФ-21: пересчитать, но не чаще, чем раз в окно.
     *
     * ЧТО БЫЛО НЕ ТАК. Пересчёт шёл на КАЖДОЕ изменение ящика, а изменение —
     * это каждая укладка записок. Пересчёт — полный обход ключей: замер на
     * двухстах тысячах записок даёт 982 мс, десять укладок подряд — 9,4
     * секунды. Всё это время однопоточный узел не обслуживает никого: ни
     * приёма конвертов, ни выдачи очереди, ни чужих сводок.
     *
     * Отложить его можно без потерь. Записка живёт тринадцать часов, а тот,
     * кто спросит сводку раньше срока пересчёта, получит её посчитанной по
     * требованию (get ниже) — то есть отставшего ответа не бывает.
     *
     * Возвращает true, если пересчёт действительно сделан.
     */
    refreshIfDue(version, loadKeys, { now = Date.now(), minIntervalMs = 0 } = {}) {
      if (cached && atVersion === version) return false;
      if (lastBuiltAt !== null && now - lastBuiltAt < minIntervalMs) return false;
      this.get(version, loadKeys);
      lastBuiltAt = now;
      return true;
    },
    version() {
      return atVersion;
    },
    size() {
      return cached ? cached.n : 0;
    },
    reset() {
      cached = null;
      atVersion = null;
      lastBuiltAt = null;
    },
  };
}

/** До какого времени записка живёт. */
function expiresAt(slot) {
  return slot * SLOT_MS + TTL_MS;
}

/** Протухла ли. */
function isExpired(record, now) {
  return !record || expiresAt(record.slot) <= now;
}

module.exports = {
  VERSION,
  KEY_BYTES,
  VALUE_BYTES,
  MAC_BYTES,
  RECORD_BYTES,
  MAX_PUT_RECORDS,
  SLOT_MS,
  SLOT_TOLERANCE,
  TTL_MS,
  BUCKET_MIN,
  MAX_DEPTH,
  MAX_RECORDS,
  SYNC_LIMIT,
  slotOf,
  parsePut,
  packRecords,
  bucketDepth,
  bucketOf,
  bucketRange,
  depthAllowed,
  buildDigest,
  createDigestCache,
  expiresAt,
  isExpired,
};
