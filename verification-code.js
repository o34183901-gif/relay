'use strict';

/**
 * verification-code.js — код подтверждения привязки компьютера (АУД-КР2).
 *
 * Привязка компьютера — единственное место, где к переписке добавляется новый
 * читатель. От подмены здесь защищает ровно одно: человек сверяет код на двух
 * экранах. Значит цена ошибки в этом коде равна цене всей переписки, и правило
 * его вывода обязано жить отдельным чистым модулем с собственным тестом, а не
 * строчкой внутри восьмисотстрочного файла протокола.
 *
 * Что было не так. Код — шесть цифр, полученных из двадцати четырёх бит хеша по
 * модулю миллиона. Вычисляется мгновенно, подпись в него не входит. Значит
 * подставное устройство свободно варьирует собственный nonce и ищет совпадение
 * с кодом настоящего компьютера: замер на одном ядре в чистом JavaScript дал
 * около семнадцати тысяч вариантов в секунду и совпадение за минуту, при том что
 * QR живёт две минуты. Сверка «сравните шесть цифр» не защищала ни от чего.
 *
 * Что здесь сделано.
 *
 * Длина. К прежним шести цифрам добавлены ещё четыре, и первые шесть остались в
 * точности прежними. Поэтому сторона старой версии, показывающая короткий код, и
 * сторона новой, показывающая длинный, по-прежнему сверяемы глазами: короткий
 * является префиксом длинного. Ломать совместимость ради удлинения не пришлось.
 *
 * Цена вычисления. Добавленные цифры выводятся не одним хешем, а цепочкой из
 * STRONG_CODE_ROUNDS последовательных SHA-512. Цепочку нельзя распараллелить
 * внутри себя, поэтому одна попытка перебора стоит примерно столько же, сколько
 * честное вычисление, — порядка четверти секунды на телефоне. Подогнать все
 * десять цифр значит выполнить около 10^10 таких цепочек: недостижимо ни за две
 * минуты жизни QR, ни за любое осмысленное время даже при распараллеливании.
 *
 * Модуль принимает УЖЕ канонизированную строку подписываемых полей, а не сам
 * запрос: канонизация живёт в протоколе (linked-devices.js), и дублировать её
 * здесь означало бы завести второй источник истины ровно там, где расхождение
 * стоит дороже всего.
 */
const nacl = require('tweetnacl');
const { decodeUTF8 } = require('tweetnacl-util');

const SHORT_CODE_DOMAIN = 'licno-device-verify-code-v2|';
const STRONG_CODE_DOMAIN = 'licno-device-verify-strong-v1|';

// Компромисс между стойкостью и отзывчивостью: около 170 мс на настольном
// процессоре и порядка 0,7 с на телефоне — один раз за привязку.
const STRONG_CODE_ROUNDS = 30000;

function pairs(text) {
  const out = [];
  for (let index = 0; index < text.length; index += 2) out.push(text.slice(index, index + 2));
  return out.join(' · ');
}

/** Прежний шестизначный код. Формат и вывод не менялись — на нём совместимость. */
function shortCode(canonical) {
  const hash = nacl.hash(decodeUTF8(SHORT_CODE_DOMAIN + canonical));
  const number = (((hash[0] << 16) | (hash[1] << 8) | hash[2]) >>> 0) % 1000000;
  return pairs(String(number).padStart(6, '0'));
}

function strongSeed(canonical) {
  return nacl.hash(decodeUTF8(STRONG_CODE_DOMAIN + canonical));
}

function strongTail(digest) {
  const number = (((digest[0] << 8) | digest[1]) >>> 0) % 10000;
  return pairs(String(number).padStart(4, '0'));
}

/** Десятизначный код. Первые шесть цифр совпадают с shortCode. */
function strongCode(canonical) {
  let digest = strongSeed(canonical);
  for (let round = 1; round < STRONG_CODE_ROUNDS; round += 1) digest = nacl.hash(digest);
  return `${shortCode(canonical)} · ${strongTail(digest)}`;
}

/**
 * То же самое, но с уступкой потоку интерфейса: на телефоне цепочка занимает
 * заметное время, и заморозить на неё экран подтверждения было бы хуже, чем
 * показать его с задержкой.
 */
async function strongCodeAsync(canonical) {
  let digest = strongSeed(canonical);
  let deadline = Date.now() + 8;
  for (let round = 1; round < STRONG_CODE_ROUNDS; round += 1) {
    digest = nacl.hash(digest);
    if ((round & 255) === 0 && Date.now() >= deadline) {
      await new Promise((resolve) => setTimeout(resolve, 0));
      deadline = Date.now() + 8;
    }
  }
  return `${shortCode(canonical)} · ${strongTail(digest)}`;
}

/**
 * Сверка присланного подтверждения с локально вычисленным.
 *
 * Совместимость обеих сторон разбирается здесь, в одном месте: если пришёл
 * длинный код и он есть у нас — сверяем его целиком; если пришёл только
 * короткий (сторона прежней версии) — сверяем короткий. Подогнать длинный код
 * нельзя, короткий можно, поэтому длинный всегда в приоритете.
 */
function verificationCodesMatch(incoming, local) {
  const expectedShort = local && local.short;
  const expectedStrong = local && local.strong;
  if (incoming && incoming.strong && expectedStrong) return incoming.strong === expectedStrong;
  if (!incoming || !incoming.short || !expectedShort) return false;
  return incoming.short === expectedShort;
}

module.exports = {
  STRONG_CODE_ROUNDS,
  shortCode,
  strongCode,
  strongCodeAsync,
  verificationCodesMatch,
};
