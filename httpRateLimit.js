/**
 * httpRateLimit.js — счётчик обращений по ключу в скользящем окне (ВЫС-19).
 * Чистое правило, без сети и без часов внутри.
 *
 * ЗАЧЕМ
 *
 * HTTP-эндпойнт /mbx отдаёт до полутора мегабайт на запрос в сорок байт — то
 * есть усилитель в тридцать тысяч раз, и без ограничения частоты его можно
 * дёргать сколько угодно. WebSocket-кадры ящика (mbx-digest/mbx-fetch) уже за
 * аутентификацией и под costlyLimited; у HTTP-пути такой защиты не было вовсе.
 *
 * Окно фиксированное, а не «токенное ведро»: код релея уже считает так же
 * (costlyLimited, prekey-троттлинг), и заводить второй вид лимитера ради того
 * же результата незачем. Ключ — IP клиента (за Caddy — реальный, из
 * X-Forwarded-For; см. ВЫС-17, доверять ему можно только за прокси).
 *
 * Проверяется в server/httpRateLimit.test.js.
 */

'use strict';

/**
 * `max` обращений за `windowMs` на ключ. Возвращает { allow(key, now) } —
 * true, если обращение в пределах окна; false, если пора отказать.
 *
 * Карта окон подметается лениво, при обращении: держать таймер ради счётчика
 * запросов незачем, а без уборки карта росла бы числом уникальных IP.
 */
function createHttpRateLimit({ max, windowMs }) {
  const windows = new Map(); // key -> { start, count }

  function allow(key, now) {
    const k = key == null ? '' : String(key);
    const w = windows.get(k);
    if (!w || now - w.start >= windowMs) {
      windows.set(k, { start: now, count: 1 });
      sweep(now);
      return true;
    }
    w.count += 1;
    return w.count <= max;
  }

  // Лениво выкидываем окна, чей срок вышел: иначе поток уникальных адресов
  // растил бы карту без предела. Дёшево — проход только при заведении окна.
  function sweep(now) {
    if (windows.size < 4096) return;
    for (const [k, w] of windows) {
      if (now - w.start >= windowMs) windows.delete(k);
    }
  }

  function size() {
    return windows.size;
  }

  return { allow, size };
}

module.exports = { createHttpRateLimit };
