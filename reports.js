/**
 * reports.js — отчёты о неполадках: правила приёма и выдачи (ОТЧ-1).
 *
 * ЗАЧЕМ ЭТО ВООБЩЕ ЕСТЬ
 *
 * Приложение измеряет себя само (src/diagnostics.js), но всё измеренное живёт в
 * памяти телефона до перезапуска и никуда не уходит. Пока пользователь один и
 * он же владелец — это работает: он смотрит экран диагностики и рассказывает,
 * что видит. Дальше не работает совсем: «у меня сообщения не доходят» без цифр
 * не отличить от «у меня плохой интернет», а попросить человека переписать
 * четырнадцать чисел с экрана — не путь.
 *
 * ЧТО ЗДЕСЬ, А ЧЕГО ЗДЕСЬ НЕТ
 *
 * Узел принимает ЗАПЕЧАТАННЫЙ отчёт и не может его прочитать: тело зашифровано
 * на публичный ключ владельца приложения (nacl.box с одноразовой парой
 * отправителя, src/reportUpload.js), а секретная половина живёт только в
 * секретах сборки. Для узла отчёт — непрозрачные байты с временем приёма.
 *
 * Поэтому здесь всего три правила:
 *   • что считать годной посылкой (форма и потолок размера);
 *   • сколько отчётов пускать с одного адреса и как долго их хранить;
 *   • чем доказывается право ЗАБРАТЬ и УДАЛИТЬ накопленное.
 *
 * ПРАВО ЗАБРАТЬ. Подписью ключа выпуска — того же Ed25519, которым подписан
 * манифест обновлений (server/releaseKey.js). Открытая половина уже вшита в
 * каждый узел и в каждое приложение, секретная лежит в секретах сборки. Второго
 * ключа заводить незачем: владелец у них один, а лишний секрет — лишнее место,
 * откуда он утекает.
 *
 * Подписывается строка `<домен>|<время>` со сроком годности: без времени
 * подпись становится вечным пропуском, который достаточно подсмотреть однажды в
 * логе прокси. Запрос старше REQUEST_TTL_MS не принимается, из будущего — тоже
 * (часы узлов расходятся, поэтому окно двустороннее).
 *
 * Модуль чистый: ни сети, ни базы, ни часов внутри (тест server/reports.test.js).
 */

'use strict';

const naclUtil = require('tweetnacl-util');
// В-2: подпись и её проверка — через единую обёртку (внутри @noble/curves либо
// OpenSSL, формат прежний побайтно). Прямой вызов tweetnacl здесь размывал бы
// единую точку смены криптографического основания.
const ed25519 = require('./ed25519');

/** Потолок одной посылки. Отчёт — это числа и метки мест, ему хватает с избытком. */
const MAX_REPORT_BYTES = 64 * 1024;

/** Сколько отчётов принимаем с одного адреса за сутки. */
const PER_IP_PER_DAY = 2;
const DAY_MS = 24 * 60 * 60 * 1000;

/** Сколько отчёт лежит на узле, если владелец за ним не пришёл. */
const REPORT_TTL_MS = 14 * DAY_MS;

/** Сколько отчётов отдаём за один запрос: выгрузка идёт страницами. */
const FETCH_PAGE = 200;

/** Домены подписи. Разные у чтения и удаления: подпись на чтение не должна стирать. */
const FETCH_DOMAIN = 'licno-reports-fetch-v1';
const DELETE_DOMAIN = 'licno-reports-delete-v1';

/** Насколько подпись остаётся годной. Окно двустороннее — часы узлов расходятся. */
const REQUEST_TTL_MS = 5 * 60 * 1000;

/**
 * Годная ли посылка. Отчёт приходит в виде { v, ek, nonce, cipher } — ровно то,
 * что собирает клиент; ничего сверх этого узел не хранит и не пересылает.
 *
 * Проверяется ФОРМА, а не содержимое: содержимое узлу и не прочитать.
 */
function validReport(body, bytes) {
  if (!body || typeof body !== 'object') return { ok: false, reason: 'shape' };
  if (Number.isFinite(bytes) && bytes > MAX_REPORT_BYTES) return { ok: false, reason: 'size' };
  if (body.v !== 1) return { ok: false, reason: 'version' };
  for (const field of ['ek', 'nonce', 'cipher']) {
    const value = body[field];
    if (typeof value !== 'string' || !value || value.length > MAX_REPORT_BYTES) {
      return { ok: false, reason: 'field:' + field };
    }
  }
  return { ok: true };
}

/** Строка, которую подписывает владелец. Домен внутри — чтобы подписи не путались. */
function requestChallenge(domain, ts) {
  return `${domain}|${ts}`;
}

/**
 * Доказано ли право владельца на этот запрос.
 *
 * `publicKey` — открытая половина ключа выпуска (у узла она вшита).
 * Возвращает { ok, reason } — причина нужна ответу и разбору жалоб.
 */
function verifyOwnerRequest({ domain, ts, signature, publicKey, now }) {
  const stamp = Number(ts);
  if (!Number.isFinite(stamp)) return { ok: false, reason: 'ts' };
  if (Math.abs(now - stamp) > REQUEST_TTL_MS) return { ok: false, reason: 'stale' };
  if (typeof signature !== 'string' || !signature) return { ok: false, reason: 'signature' };
  if (typeof publicKey !== 'string' || !publicKey) return { ok: false, reason: 'key' };
  try {
    const ok = ed25519.verify(
      naclUtil.decodeUTF8(requestChallenge(domain, stamp)),
      naclUtil.decodeBase64(signature),
      naclUtil.decodeBase64(publicKey)
    );
    return ok ? { ok: true } : { ok: false, reason: 'signature' };
  } catch (e) {
    // Битая base64 в подписи или ключе — то же самое «не доказано».
    return { ok: false, reason: 'signature' };
  }
}

/** Подписать запрос своей половиной ключа выпуска (скрипт выгрузки и тесты). */
function signOwnerRequest({ domain, ts, secretKey }) {
  return naclUtil.encodeBase64(
    ed25519.sign(
      naclUtil.decodeUTF8(requestChallenge(domain, Number(ts))),
      naclUtil.decodeBase64(secretKey)
    )
  );
}

module.exports = {
  MAX_REPORT_BYTES,
  PER_IP_PER_DAY,
  REPORT_TTL_MS,
  FETCH_PAGE,
  FETCH_DOMAIN,
  DELETE_DOMAIN,
  REQUEST_TTL_MS,
  DAY_MS,
  validReport,
  requestChallenge,
  verifyOwnerRequest,
  signOwnerRequest,
};
