/**
 * gateway-ticket.js — жетон доступа к своей очереди (ЭТП5-4).
 *
 * ОБЩИЙ КОНТРАКТ, КАК И linked-devices.js. Жетон выпускает телефон владельца,
 * а проверяет релей — на разных платформах и в разных процессах. Две копии
 * одного правила разошлись бы молча и в худшую сторону: телефон выпускал бы
 * жетон, который релей отвергает, либо — что гораздо хуже — релей принимал бы
 * жетон, которого владелец не выпускал.
 *
 * ЗАЧЕМ ЖЕТОН
 *
 * Выход в интернет через соседа (ШЛЗ-1) работал В ОДНУ СТОРОНУ: сосед мог
 * положить наш конверт в релей, но забрать НАШУ очередь не мог. Причина
 * законная: релей отдаёт очередь только тому, кто доказал владение box-ключом
 * адреса, а такого ключа у соседа нет и быть не должно.
 *
 * Из-за этого человек без интернета мог писать, но не мог получать. Половина
 * связи — это не связь: ответа он не увидит, пока сеть не появится лично у
 * него.
 *
 * Жетон закрывает вторую половину: владелец подписывает разрешение «этому
 * соседу, до этого времени, один раз — забрать мою очередь». Релей проверяет
 * подпись тем же ключом, которым владелец аутентифицируется сам.
 *
 * ЧТО ЖЕТОН НЕ ДАЁТ, И ЭТО ГЛАВНОЕ
 *
 *   • Читать содержимое. Конверты запечатаны на получателя (sealedSender), и
 *     сосед везёт непрозрачные блобы — ровно как в сети знакомств (МШ-1).
 *   • Удалять очередь. Квитанция о приёме принимается релеем только от
 *     доказанного владельца box-ключа; предъявитель жетона её дать не может.
 *     Значит потерять сообщения по чужой воле нельзя: худшее, что сделает
 *     недобросовестный сосед, — не довезёт, и конверты останутся в очереди.
 *   • Отправлять от имени владельца, менять привязку ключа, читать чужие
 *     очереди. Жетон называет РОВНО ОДИН адрес и разрешает РОВНО ОДНО действие.
 *   • Пользоваться дважды. У жетона есть одноразовый номер, и релей помнит
 *     предъявленные до истечения срока.
 *   • Достаться другому. Жетон выдан конкретному соседу — и по адресу, и по
 *     ключу подписи. Перехвативший его предъявить не сможет: релей сверяет
 *     обоих с тем, кем предъявитель уже доказал себя.
 *
 * ЧТО СОСЕД ВСЁ-ТАКИ УЗНАЁТ, ЧЕСТНО
 *
 * Сколько конвертов лежит в очереди владельца, каких они размеров и когда
 * пришли. Скрыть это, не отказавшись от самой затеи, нельзя: чтобы довезти
 * конверты, их надо получить. Это меньше, чем знает релей, но больше нуля, —
 * поэтому жетон и выдаётся вручную, конкретному соседу и на минуты.
 */
'use strict';

const VERSION = 1;

/**
 * Имя возможности: этот узел принимает кадр `gw-pull` и отвечает на него.
 *
 * Здесь, а не отдельными строками у каждой стороны, — по той же причине, что и
 * всё остальное в этом файле: разойдись они, шлюз предъявлял бы жетон узлу,
 * который о нём не знает, и ждал бы ответа, которого не будет.
 *
 * Проверять объявление ОБЯЗАТЕЛЬНО. Узел прежней версии на `gw-pull` не отвечает
 * НИЧЕГО — ни отказа, ни ошибки, — а по молчанию отличить «не умеет» от «ещё
 * выгружает» нечем. Шлюз в этом случае держал бы поездку до срока, а владелец
 * впустую ждал бы конверты, которые никто не поехал забирать.
 */
const PULL_CAPABILITY = 'gateway-pull-v1';

/**
 * Домен подписи. Версия внутри домена: смена формата обязана делать прежние
 * жетоны НЕДЕЙСТВИТЕЛЬНЫМИ, а не «почти подходящими».
 */
const TICKET_PREFIX = 'licno-gw-ticket-v1|';

/**
 * Сколько живёт жетон.
 *
 * Десять минут. Сосед забирает очередь сразу — он для того и просит, — а
 * длинный срок означал бы, что потерянный телефон соседа остаётся ключом к
 * нашей очереди на всё это время.
 */
const TICKET_TTL_MS = 10 * 60 * 1000;

/**
 * Запас на расхождение часов двух устройств.
 *
 * Без него жетон, выпущенный телефоном, чьи часы отстают на минуту, релей
 * счёл бы «из будущего» и отверг — а человек увидел бы, что связь через соседа
 * просто не работает, без единого объяснения.
 */
const CLOCK_SKEW_MS = 2 * 60 * 1000;

/** Длина одноразового номера в байтах (в жетоне — base64). */
const NONCE_BYTES = 12;

function text(value, max = 128) {
  return typeof value === 'string' ? value.slice(0, max) : '';
}

/**
 * Байты, которые подписываются.
 *
 * Входит ВСЁ, чем жетон ограничен: адрес очереди, кому выдан (и адрес соседа, и
 * его ключ подписи), когда выпущен, до какого времени годен и одноразовый
 * номер. Оставь мы за подписью хоть одно из этих полей — его можно было бы
 * поменять по дороге, а подпись осталась бы верной.
 *
 * Ключ подписи соседа входит по той же причине, что и в полномочиях группы:
 * иначе владелец разрешал бы «вот этому адресу», а проверяющему пришлось бы
 * откуда-то узнать, какой подписью тот подписывается, — то есть спросить у него
 * же. С обоими полями удостоверение замкнуто: из него одного видно и кому
 * выдано, и чем предъявитель себя доказывает.
 */
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
  // Своя кодировка, а не Buffer и не TextEncoder: модуль общий для сервера
  // (Node) и клиента (React Native), и оба должны получить ОДНИ И ТЕ ЖЕ байты.
  return utf8Bytes(line);
}

/** UTF-8 в байты. Без зависимостей: модуль обязан грузиться и там, и там. */
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

/**
 * Собрать жетон.
 *
 * `sign(bytes)` — подпись байтов ключом ВЛАДЕЛЬЦА; тем самым, которым он
 * аутентифицируется на релее. Подпись вносится функцией, а не ключом: секретный
 * ключ не должен попадать в модуль, который грузится и на сервере.
 */
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

/**
 * Разобрать жетон. null — это не жетон либо он негодный по форме.
 *
 * Разбор строгий и БЕЗ проверки подписи: подпись проверяет тот, кто знает
 * закреплённый ключ владельца, — то есть релей. Разделение намеренное: форма
 * проверяется одинаково везде, а ключ есть только у одной стороны.
 */
function parseTicket(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  if (value.v !== VERSION) return null;
  for (const field of ['addr', 'agent', 'agentSign', 'nonce', 'sig']) {
    const item = value[field];
    if (typeof item !== 'string' || !item || item.length > 128) return null;
  }
  if (!Number.isFinite(value.issuedAt) || value.issuedAt <= 0) return null;
  if (!Number.isFinite(value.expiresAt) || value.expiresAt <= value.issuedAt) return null;
  // Срок в самом жетоне тоже ограничен: иначе владелец мог бы (по ошибке в
  // своей сборке или по чужой подсказке) выпустить жетон на год, и один
  // потерянный телефон соседа оставался бы ключом к очереди всё это время.
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

/**
 * Проверить жетон целиком.
 *
 * Возвращает `{ ok: true, ticket }` либо `{ ok: false, reason }`. Причина
 * короткая и без подробностей: предъявителю незачем знать, чем именно его
 * жетон не подошёл, — по этому легко подбирать.
 *
 *   verify(bytes, sig, signPublicKey) → boolean — проверка подписи владельца;
 *   ownerSignKey  — ключ подписи, ЗАКРЕПЛЁННЫЙ за адресом на этом релее;
 *   presenter     — кем предъявитель уже доказал себя: { addr, signKey };
 *   used(nonce)   — предъявлялся ли этот жетон раньше.
 */
function checkTicket({ candidate, ownerSignKey, presenter, now, verify, used = () => false }) {
  const ticket = parseTicket(candidate);
  if (!ticket) return { ok: false, reason: 'форма' };
  const at = Number.isFinite(now) ? now : 0;
  // Срок в обе стороны. «Из будущего» отвергаем не из педантизма: без этого
  // владелец с переведёнными вперёд часами (своими или подсунутыми) выпускал бы
  // жетоны, годные много дольше положенного.
  if (at > ticket.expiresAt + CLOCK_SKEW_MS) return { ok: false, reason: 'срок' };
  if (at + CLOCK_SKEW_MS < ticket.issuedAt) return { ok: false, reason: 'срок' };
  // Кому выдан — сверяется с тем, кем предъявитель УЖЕ доказал себя релею.
  // Именно это и делает перехваченный жетон бесполезным.
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

/**
 * Память о предъявленных жетонах.
 *
 * Одноразовость невозможна без памяти, а память без уборки — это утечка,
 * которую наполняет кто угодно. Поэтому забываем по сроку самого жетона: после
 * него он не годится и без всякой памяти.
 */
function createTicketLedger({ now = () => Date.now(), limit = 4096 } = {}) {
  const seen = new Map();

  function sweep(at) {
    for (const [nonce, until] of seen) {
      if (until <= at) seen.delete(nonce);
    }
    // Потолок на случай потока свежих жетонов: вытесняем самое старое. Это не
    // ослабляет одноразовость сверх необходимого — вытесненный жетон к тому
    // моменту либо уже просрочен, либо его вытеснил поток от того же владельца.
    while (seen.size > limit) {
      const oldest = seen.keys().next().value;
      seen.delete(oldest);
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
