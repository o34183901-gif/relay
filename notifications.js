/**
 * notifications.js — ЧИСТЫЕ правила wake-up уведомлений (ПРФ-4).
 *
 * Раньше троттлинг считался на ПОЛУЧАТЕЛЯ целиком: не чаще одного пуша в 20
 * секунд, независимо от того, из скольких чатов пришли сообщения. Пять сообщений
 * из трёх разных чатов давали ОДИН пуш — остальные чаты устройство не будили
 * вовсе, и это читалось пользователем как потерянные сообщения.
 *
 * Теперь окно считается на пару «получатель + чат». Чтобы это не превратилось в
 * усилитель флуда (много отправителей → много пушей), сверху стоит потолок на
 * число пушей одному получателю за то же окно.
 *
 * Здесь только арифметика окон и вычисление признака чата — ни сети, ни БД,
 * поэтому модуль тестируется в Node (server/notifications.test.js).
 */
const crypto = require('crypto');

const DEFAULT_WINDOW_MS = 20000;
const DEFAULT_MAX_PER_RECIPIENT = 5;

/**
 * Непрозрачный признак чата для уведомления: хэш адреса отправителя, а не сам
 * адрес.
 *
 * Едет он ТОЛЬКО в web-push, тело которого зашифровано ключами подписки, — то
 * есть провайдер пуша его не видит. Но и внутри зашифрованного тела возить
 * адрес открытым текстом незачем: устройству достаточно любого стабильного
 * признака, чтобы не схлопывать уведомления разных чатов в одно.
 *
 * Считать нужно от АККАУНТА отправителя, а не от адреса устройства: иначе два
 * устройства одного собеседника дали бы две ветки уведомлений для одного чата.
 */
function chatNotificationTag(address) {
  if (!address) return '';
  return crypto
    .createHash('sha256')
    .update('licno-chat-tag|' + String(address))
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .slice(0, 22);
}

/**
 * Ворота уведомлений. Состояние держится внутри (две карты), время передаётся
 * снаружи — так модуль тестируется без таймеров.
 */
function createPushGate({ windowMs = DEFAULT_WINDOW_MS, maxPerRecipient = DEFAULT_MAX_PER_RECIPIENT } = {}) {
  const lastByPair = new Map(); // "получатель|чат" -> время последнего пуша
  const burstByRecipient = new Map(); // получатель -> { start, count }

  return {
    /**
     * Будить ли получателя уведомлением из этого чата прямо сейчас.
     * Побочный эффект есть только при ответе true (окна сдвигаются).
     */
    allow(to, chatTag, now) {
      if (!to) return false;
      const pairKey = to + '|' + (chatTag || '');
      if (now - (lastByPair.get(pairKey) || 0) < windowMs) return false;
      const burst = burstByRecipient.get(to);
      if (!burst || now - burst.start >= windowMs) {
        burstByRecipient.set(to, { start: now, count: 1 });
      } else {
        // Потолок на получателя: пачка одноразовых отправителей не должна
        // превращаться в шквал уведомлений.
        if (burst.count >= maxPerRecipient) return false;
        burst.count += 1;
      }
      lastByPair.set(pairKey, now);
      return true;
    },

    /** Убрать записи старше десяти окон (зовётся по таймеру). */
    sweep(now) {
      const cutoff = now - 10 * windowMs;
      for (const [key, at] of lastByPair) if (at < cutoff) lastByPair.delete(key);
      for (const [key, burst] of burstByRecipient) if (burst.start < cutoff) burstByRecipient.delete(key);
    },

    size() {
      return lastByPair.size + burstByRecipient.size;
    },
  };
}

module.exports = {
  DEFAULT_WINDOW_MS,
  DEFAULT_MAX_PER_RECIPIENT,
  chatNotificationTag,
  createPushGate,
};
