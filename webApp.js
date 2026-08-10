'use strict';

/**
 * webApp.js — узел раздаёт веб-версию приложения (ВЫП-9).
 *
 * КОМУ ЭТО НУЖНО
 *
 * Тому, у кого приложение не поставить. На iPhone магазина у проекта нет, а APK
 * туда не ставится вовсе — для этих людей веб-версия не запасной путь, а
 * единственный. Раньше её раздавал сайт; сайта нет, и раздавать её больше
 * некому, кроме релеев.
 *
 * ЧТО ЗДЕСЬ
 *
 * Только правила: какой путь запроса какому файлу соответствует, какой у него
 * тип и как его кэшировать. Ни диска, ни HTTP — они приходят снаружи, — поэтому
 * проверяется целиком, без поднятия сервера.
 *
 * ГЛАВНОЕ ПРАВИЛО — НЕ ВЫПУСТИТЬ ЗАПРОС ЗА ПРЕДЕЛЫ КАТАЛОГА
 *
 * Путь приходит из сети, то есть от кого угодно. Ошибка здесь означает выдачу
 * любого файла с диска узла: ключа подписи релея, базы с очередью конвертов,
 * /etc/shadow. Поэтому путь не «очищается», а СОБИРАЕТСЯ заново из безопасных
 * кусков, и результат ещё раз сверяется с корнем каталога.
 */

const path = require('path');

/** Адрес, по которому узел отдаёт веб-версию. */
const WEB_APP_PREFIX = '/app';

/**
 * Тип содержимого по расширению.
 *
 * Список закрытый: неизвестное расширение отдаётся как поток байтов, а не
 * «угадывается». Угаданный text/html на чужом файле — это исполнение чужого
 * кода на нашем происхождении.
 */
const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.gif': 'image/gif',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf',
  '.txt': 'text/plain; charset=utf-8',
  '.webmanifest': 'application/manifest+json',
};

function contentType(filePath) {
  return TYPES[path.extname(String(filePath || '')).toLowerCase()] || 'application/octet-stream';
}

/**
 * Разобрать путь запроса в относительный путь файла.
 *
 * Возвращает пустую строку, если запрос не наш или ведёт наружу. `''` вместо
 * `null` — чтобы забытая проверка давала пустую строку и не находила файл, а не
 * превращалась в `undefined` где-нибудь в path.join.
 */
function webAppPath(requestUrl) {
  const raw = String(requestUrl || '');
  if (raw !== WEB_APP_PREFIX && !raw.startsWith(`${WEB_APP_PREFIX}/`) && !raw.startsWith(`${WEB_APP_PREFIX}?`)) {
    return null; // не наш запрос вовсе
  }
  let pathname;
  try {
    pathname = new URL(raw, 'http://x').pathname;
  } catch (error) {
    return '';
  }
  // ПРЕФИКС ПРОВЕРЯЕТСЯ ПОСЛЕ НОРМАЛИЗАЦИИ, И ЭТО НЕ ПРИДИРКА.
  //
  // URL схлопывает «..» сам, ДО нашего разбора: «/app/../relay.js» приходит сюда
  // уже как «/relay.js». Проверь мы префикс только на сырой строке и отрежь
  // четыре символа вслепую — получили бы «ay.js», то есть имя файла, собранное
  // из чужого пути. Так и было: тест это и поймал.
  if (pathname !== WEB_APP_PREFIX && !pathname.startsWith(`${WEB_APP_PREFIX}/`)) return '';

  // Проценты раскрываем ПОСЛЕ отсечения префикса: «%2e%2e» — это те же две
  // точки, URL их не схлопывает, и проверка по сырой строке их не увидела бы.
  let decoded;
  try {
    decoded = decodeURIComponent(pathname);
  } catch (error) {
    return ''; // битая процентная последовательность
  }
  if (decoded !== WEB_APP_PREFIX && !decoded.startsWith(`${WEB_APP_PREFIX}/`)) return '';
  const rest = decoded.slice(WEB_APP_PREFIX.length).replace(/^\/+/, '');
  if (!rest) return 'index.html'; // сам /app — это страница приложения

  if (rest.includes('\0')) return '';
  const parts = [];
  for (const part of rest.split('/')) {
    if (!part || part === '.') continue;
    if (part === '..') return ''; // наружу не выпускаем и не «схлопываем»
    if (part.includes('\\')) return '';
    parts.push(part);
  }
  if (!parts.length) return 'index.html';
  if (parts.join('/').length > 200) return '';
  return parts.join('/');
}

/**
 * Собрать полный путь файла и убедиться, что он ВНУТРИ корня.
 *
 * Вторая проверка после webAppPath не лишняя: та работает со строкой, а эта — с
 * тем, что получилось после соединения путей. Символьная ссылка внутри каталога
 * сюда не относится (её раскрывает уже файловая система), но опечатка в правиле
 * выше ловится именно здесь.
 */
function resolveWebFile(root, relative) {
  if (!root || !relative) return '';
  const full = path.resolve(root, relative);
  const base = path.resolve(root);
  if (full !== base && !full.startsWith(base + path.sep)) return '';
  return full;
}

/**
 * Заголовки ответа.
 *
 * Страница — без кэша: иначе браузер держал бы старую разметку, которая тянет
 * несуществующий бандл, и человек видел бы белый экран до очистки кэша. Всё
 * остальное у веб-сборки именовано с отпечатком, поэтому кэшируется надолго.
 *
 * nosniff обязателен: без него браузер вправе «угадать» тип и выполнить как
 * скрипт то, что мы отдали потоком байтов.
 */
function webAppHeaders(relative, size) {
  const type = contentType(relative);
  const isPage = relative === 'index.html' || relative.endsWith('.html');
  const isServiceWorker = relative === 'sw.js';
  return {
    'content-type': type,
    'content-length': String(size),
    'x-content-type-options': 'nosniff',
    // Service worker управляет обновлением всей веб-версии: закэшируй его
    // браузер надолго — и человек остался бы на старой сборке навсегда.
    'cache-control': isPage || isServiceWorker ? 'no-cache' : 'public, max-age=3600',
  };
}

module.exports = {
  WEB_APP_PREFIX,
  TYPES,
  contentType,
  webAppPath,
  resolveWebFile,
  webAppHeaders,
};
