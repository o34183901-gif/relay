/* ЭТОТ ФАЙЛ СГЕНЕРИРОВАН — НЕ РЕДАКТИРУЙТЕ ЕГО.
 * Источник: src/mailboxGcs.js
 * Перегенерировать: node scripts/sync-core.js
 *
 * Правки вносятся ТОЛЬКО в источник. Ручная правка этой копии будет затёрта,
 * а CI (`node scripts/sync-core.js --check`) не пропустит расхождение: именно
 * оно однажды стоило потерянных сообщений на компьютере (НАД-1).
 */
/**
 * mailboxGcs.js — сжатое множество ключей (ПЯЩ-1). Правило, без сети.
 *
 * ЗАЧЕМ ЭТО СУЩЕСТВУЕТ
 *
 * Мы хотим узнать, лежит ли на релее записка под НАШИМ ключом, и при этом не
 * назвать релею этот ключ. Спросить «есть ли у тебя ключ K» нельзя: спросив, мы
 * сообщаем ровно то, что скрываем. Релей увидит, что ключ K кто-то положил и
 * кто-то спросил, — и свяжет двоих, а связь двоих и есть граф общения, который
 * весь этот продукт отказывается отдавать.
 *
 * Поэтому спрашивать нельзя ВООБЩЕ. Вместо вопроса релей отдаёт СВОДКУ обо всём,
 * что у него лежит, а сверка идёт дома. Сводка одинакова для всех и не зависит
 * от того, кто её попросил, ни одним битом.
 *
 * ПОЧЕМУ НЕ ПРОСТО СПИСОК КЛЮЧЕЙ
 *
 * Список из тридцати двух тысяч ключей по 32 байта — это мегабайт на каждую
 * сверку. Здесь ключи сжаты до примерно двух байтов на штуку: сводка той же сети
 * весит 64 КБ. Это разница между «раз в сутки на мобильном тарифе» и «никогда».
 *
 * КАК СЖАТИЕ РАБОТАЕТ
 *
 * Ключ сводится к числу в диапазоне 0..(N·M), где N — число ключей, а M —
 * параметр (у нас 16384). Числа сортируются, и записываются не сами числа, а
 * РАЗНОСТИ между соседними. Разности при таком выборе диапазона распределены
 * геометрически, а для геометрического распределения оптимален код Голомба—Райса:
 * частное от деления на M — в унарном виде, остаток — в двоичном.
 *
 * ЦЕНА ЭТОГО СЖАТИЯ — ЛОЖНЫЕ СРАБАТЫВАНИЯ
 *
 * Разные ключи иногда дают одно и то же число: примерно один раз на M. Тогда
 * сводка ответит «похоже, есть», а записки не окажется. Это не беда: за сводкой
 * следует выемка, и она либо принесёт нашу записку, либо нет. Беда была бы в
 * обратном — если бы сводка теряла настоящие ключи, — а этого код не допускает
 * никогда: всё, что положено, найдётся.
 *
 * ЧЕГО ЗДЕСЬ НЕТ
 *
 * Сети, времени, хранилища и знания о том, что такое записка. Только числа и
 * биты, поэтому весь порядок проверяется в Node без единого сокета.
 */

/**
 * Параметр кода: 2^14.
 *
 * Ложных срабатываний примерно одно на 16384, цена — около 16,5 бит на ключ.
 * Меньше — сводка дешевле, но выемок впустую больше; больше — наоборот. При
 * тридцати двух тысячах записок это 66 КБ сводки и одна лишняя выемка на две
 * сотни сверок.
 */
const P_BITS = 14;
const M = 1 << P_BITS;

/** Потолок на разбор чужой сводки: она приходит от релея, а он нам не судья. */
const MAX_KEYS = 1 << 21;

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

/** Запись битов подряд. Отдельный класс не нужен — нужен только порядок. */
function createWriter() {
  const bytes = [];
  let current = 0;
  let filled = 0;
  return {
    bit(value) {
      current = (current << 1) | (value ? 1 : 0);
      filled += 1;
      if (filled === 8) {
        bytes.push(current);
        current = 0;
        filled = 0;
      }
    },
    /** Число в `width` битах, старший бит первым. */
    number(value, width) {
      for (let i = width - 1; i >= 0; i -= 1) this.bit((value / 2 ** i) & 1);
    },
    done() {
      // Хвост добивается нулями. Разбор его не заметит: он читает ровно столько
      // ключей, сколько объявлено числом.
      while (filled) this.bit(0);
      return Uint8Array.from(bytes);
    },
  };
}

function createReader(bytes) {
  let at = 0;
  return {
    bit() {
      const index = at >> 3;
      if (index >= bytes.length) return null;
      const value = (bytes[index] >> (7 - (at & 7))) & 1;
      at += 1;
      return value;
    },
    number(width) {
      let value = 0;
      for (let i = 0; i < width; i += 1) {
        const bit = this.bit();
        if (bit === null) return null;
        value = value * 2 + bit;
      }
      return value;
    },
  };
}

/**
 * Число, к которому сводится ключ.
 *
 * Берутся первые шесть байт — этого хватает: диапазон N·M при нашем масштабе не
 * превышает 2^35, а число из шести байт даёт 2^48, то есть остаток по модулю
 * распределён ровно.
 *
 * Ключ приходит сырыми байтами, а не строкой: сводка считается и на телефоне, и
 * на релее, и одна лишняя перекодировка на каждый из тридцати двух тысяч ключей
 * — это заметное время на дешёвом узле.
 */
function valueOf(key, range) {
  invariant(key instanceof Uint8Array && key.length >= 6, 'Ключ слишком короткий');
  let value = 0;
  for (let i = 0; i < 6; i += 1) value = value * 256 + key[i];
  return value % range;
}

/**
 * Собрать сводку.
 *
 * `keys` — сырые ключи (Uint8Array по 32 байта). Порядок не важен: он всё равно
 * определяется значениями, а не тем, как ключи пришли.
 */
function encode(keys, { pBits = P_BITS } = {}) {
  invariant(Array.isArray(keys) || keys instanceof Set, 'Нечего сжимать');
  const list = [...keys];
  invariant(list.length <= MAX_KEYS, 'Слишком много ключей');
  const m = 1 << pBits;
  const range = Math.max(1, list.length) * m;
  const values = list.map((key) => valueOf(key, range)).sort((a, b) => a - b);

  const writer = createWriter();
  let previous = -1;
  for (const value of values) {
    // Разности, а не сами числа: именно они распределены геометрически, и
    // именно на них код Голомба даёт свой выигрыш.
    const delta = value - previous;
    previous = value;
    const quotient = Math.floor(delta / m);
    const remainder = delta % m;
    // Частное — в унарном виде: столько единиц, сколько само частное, и ноль в
    // конце. При правильно выбранном диапазоне частное почти всегда ноль или
    // единица, поэтому унарная запись здесь дешевле любой другой.
    for (let i = 0; i < quotient; i += 1) writer.bit(1);
    writer.bit(0);
    writer.number(remainder, pBits);
  }
  return { p: pBits, n: list.length, bits: writer.done() };
}

/**
 * Разобрать сводку в множество чисел.
 *
 * Возвращает null на любой негодный ввод. Сводка приходит от релея, а он не
 * обязан быть исправным и не обязан быть честным: испорченный или намеренно
 * оборванный поток обязан кончиться пустым ответом, а не исключением посреди
 * приёма и не бесконечным циклом.
 */
function decode(digest) {
  if (!digest || typeof digest !== 'object') return null;
  const { p, n, bits } = digest;
  if (!Number.isInteger(p) || p < 1 || p > 24) return null;
  if (!Number.isInteger(n) || n < 0 || n > MAX_KEYS) return null;
  if (!(bits instanceof Uint8Array)) return null;
  const m = 1 << p;
  const range = Math.max(1, n) * m;
  const reader = createReader(bits);
  const out = new Set();
  let previous = -1;
  for (let i = 0; i < n; i += 1) {
    let quotient = 0;
    for (;;) {
      const bit = reader.bit();
      // Поток кончился раньше объявленного числа ключей — сводка оборвана.
      if (bit === null) return null;
      if (!bit) break;
      quotient += 1;
      // Потолок на унарную часть: без него объявленные «сто ключей» и поток из
      // одних единиц заставили бы нас крутиться, пока не кончатся байты, — а
      // байтов может быть шестьдесят четыре тысячи.
      if (quotient > range / m + 2) return null;
    }
    const remainder = reader.number(p);
    if (remainder === null) return null;
    const value = previous + quotient * m + remainder;
    if (value > range) return null;
    previous = value;
    out.add(value);
  }
  return { p, n, range, values: out };
}

/**
 * Есть ли этот ключ в разобранной сводке.
 *
 * «Да» означает «скорее всего есть»: примерно один ответ на 16384 будет ложным
 * (см. шапку). «Нет» означает «точно нет» — и вот на это можно опираться.
 */
function probablyHas(decoded, key) {
  if (!decoded || !(key instanceof Uint8Array)) return false;
  return decoded.values.has(valueOf(key, decoded.range));
}

module.exports = {
  P_BITS,
  M,
  MAX_KEYS,
  valueOf,
  encode,
  decode,
  probablyHas,
};
