'use strict';

/**
 * updateMirror.js — релей сам забирает актуальный выпуск (ВЫП-8).
 *
 * ЧТО БЫЛО НЕ ТАК
 *
 * Раздача выпуска существовала, но включал её оператор вручную: задать
 * RELAY_UPDATE_DIR, скачать пару «манифест + файл», положить в каталог. На
 * каждый выпуск. На каждом узле.
 *
 * Значит на практике не раздавал никто. А раздачи через релеи — единственный
 * путь, которым обновление доезжает до установленного приложения: ни сайта, ни
 * магазина у проекта нет. Выпустить исправление дыры и не доставить его — это
 * то же самое, что не выпустить.
 *
 * ЧТО ЗДЕСЬ
 *
 * Правила зеркала: откуда брать, когда качать заново, что считать пригодным
 * файлом. Ни сети, ни диска — они приходят снаружи, — поэтому проверяется
 * целиком, без поднятия сервера и без похода в интернет.
 *
 * ПОРЯДОК ДЕЙСТВИЙ И ПОЧЕМУ ОН ИМЕННО ТАКОЙ
 *
 * 1. Скачали манифест.
 * 2. ПРОВЕРИЛИ ПОДПИСЬ — до всего остального. Внутри манифеста лежит адрес, по
 *    которому предстоит идти за файлом; рассуждать о непроверенном адресе, а тем
 *    более ходить по нему, значит позволить любому желающему отправить узел
 *    куда угодно и занять ему диск.
 * 3. Сравнили версию с тем, что уже лежит. Та же или старее — не качаем ничего:
 *    файл весит десятки мегабайт, а выпуск случается раз в недели.
 * 4. Скачали файл, сверили длину и отпечаток с ПОДПИСАННЫМ манифестом.
 * 5. Записали. Сначала файл, потом манифест: манифест — это объявление «файл
 *    готов», и появись оно раньше файла, приложение пришло бы за файлом, а его
 *    ещё нет.
 *
 * ЧЕГО ЗДЕСЬ НЕТ НАМЕРЕННО
 *
 * Репликации выпусков МЕЖДУ релеями. Каталог узлов и записки ящика расходятся по
 * федерации сами, но там килобайты, а здесь десятки мегабайт: узел, случайно
 * оказавшийся быстрым, оплатил бы раздачу всей сети. Каждый релей берёт выпуск
 * из репозитория раздачи сам — это один поход на выпуск.
 */

const crypto = require('crypto');

const { verifyUpdateManifest, isNewerVersion, filesPayload } = require('./updateManifest');

/** Откуда берётся выпуск. Открытый репозиторий раздачи — он доступен всем. */
const DEFAULT_SOURCE = 'https://raw.githubusercontent.com/o34183901-gif/relay/main';

/**
 * Насколько часто узел спрашивает «нет ли нового».
 *
 * Полчаса — это 48 запросов к маленькому JSON в сутки с узла. Чаще незачем:
 * выпуск случается раз в недели, а обновление, опоздавшее на полчаса, ничем не
 * хуже пришедшего сразу.
 */
const DEFAULT_INTERVAL_MS = 30 * 60 * 1000;

/** Потолок на файл выпуска: APK порядка 60 МБ, вдвое — с запасом на рост. */
const MAX_FILE_BYTES = 200 * 1024 * 1024;

/** Потолок на манифест: он маленький, всё крупнее — не наше. */
const MAX_MANIFEST_BYTES = 64 * 1024;

/** Адрес манифеста платформы в репозитории раздачи. */
function manifestUrl(source, platform, channel) {
  const base = String(source || '').trim().replace(/\/+$/, '');
  if (!base) return '';
  // КАН-1: тестовый канал есть только у android — второй манифест рядом со
  // стабильным. Файл выпуска для него узел не зеркалит (см. relay.js).
  if (platform === 'android' && channel === 'canary') return `${base}/android-canary-version.json`;
  if (channel === 'canary') return '';
  if (platform === 'android') return `${base}/android-version.json`;
  // ВЫП-11: для настольного клиента у нас ДВА манифеста, и это не дублирование.
  //
  // `desktop-latest.json` — формат Tauri, его ждёт сам обновлятор приложения;
  // нашей подписи он не несёт, потому что подпись minisign стоит на установщике.
  // Узлу этого мало: по манифесту он решает, ЧТО КАЧАТЬ, и доверять такой выбор
  // непроверенному документу нельзя. Поэтому для транспорта заведён
  // `desktop-version.json` в нашем формате — по нему узел и ходит.
  if (platform === 'desktop') return `${base}/desktop-version.json`;
  if (platform === 'web') return `${base}/web-version.json`;
  return '';
}

/**
 * Разобрать и ПРОВЕРИТЬ манифест. Всё, что ниже по течению, работает уже с
 * проверенными данными.
 */
function checkedManifest({ body, platform, publicKey, verifySignature, currentVersion, channel }) {
  if (typeof body !== 'string' || !body || body.length > MAX_MANIFEST_BYTES) {
    return { ok: false, reason: 'манифест не получен или неправдоподобно велик' };
  }
  let manifest;
  try {
    manifest = JSON.parse(body);
  } catch (error) {
    return { ok: false, reason: 'манифест не разбирается как JSON' };
  }
  // currentVersion здесь — версия, которую узел УЖЕ раздаёт. Пусто — ещё ничего
  // не раздаёт, и годится любая: сравнение версий делает сам verifyUpdateManifest.
  const verdict = verifyUpdateManifest({
    manifest,
    currentVersion: currentVersion || '0.0.0',
    platform,
    publicKey,
    verifySignature,
    // КАН-1: манифест тестового канала проверяется правилом тестового клиента —
    // иначе он падал бы здесь как «обновление другого канала».
    channel: channel === 'canary' ? 'canary' : 'stable',
  });
  if (!verdict.ok) return { ok: false, reason: verdict.reason };
  return { ok: true, reason: '', release: verdict.release };
}

/**
 * Стоит ли качать файл.
 *
 * `have` — что узел раздаёт сейчас (версия и отпечаток из лежащего манифеста).
 * Отпечаток сверяется тоже: та же версия с другим содержимым означает, что на
 * диске лежит не то, что объявлено, — и это надо чинить, а не оставлять.
 */
function needsFetch({ have, release }) {
  if (!release || typeof release !== 'object') return false;
  if (!have || typeof have !== 'object' || !have.version) return true;
  // Порядок аргументов: isNewerVersion(candidate, current) — «строго ли первое
  // новее второго». Перепутай их местами, и узел тянул бы СТАРЫЕ выпуски поверх
  // новых, ничем себя не выдав: файл скачивается, отпечаток сходится, версия
  // откатывается назад.
  if (isNewerVersion(release.version, have.version)) return true;
  if (String(have.version) !== String(release.version)) return false; // на диске новее — не трогаем
  return String(have.sha256 || '').toLowerCase() !== String(release.sha256 || '').toLowerCase();
}

/**
 * Годится ли скачанный файл. Сверяется с ПОДПИСАННЫМ манифестом: длина и
 * отпечаток. Не сошлось — выбрасываем, ничего не записав.
 */
function fileVerdict({ size, sha256, release }) {
  if (!release || typeof release !== 'object') return { ok: false, reason: 'нечего сверять' };
  const actual = Number(size);
  if (!Number.isFinite(actual) || actual <= 0) return { ok: false, reason: 'файл пуст или не скачался' };
  if (actual > MAX_FILE_BYTES) return { ok: false, reason: 'файл больше потолка' };
  if (actual !== Number(release.size)) return { ok: false, reason: 'длина файла не совпала с подписанной' };
  if (typeof sha256 !== 'string' || sha256.toLowerCase() !== String(release.sha256).toLowerCase()) {
    return { ok: false, reason: 'отпечаток файла не совпал с подписанным' };
  }
  return { ok: true, reason: '' };
}

/**
 * Адрес файла годится, только если он https.
 *
 * Подпись уже проверена, то есть адрес выбрал тот, у кого секретная половина
 * ключа. Но http означал бы, что содержимое можно подменить по дороге: подмену
 * поймает сверка отпечатка, однако узел успеет скачать десятки мегабайт мусора,
 * и повторять это будет каждые полчаса.
 */
function usableFileUrl(url) {
  const value = String(url || '').trim();
  if (!/^https:\/\//i.test(value)) return '';
  try {
    return new URL(value).toString();
  } catch (error) {
    return '';
  }
}


// --- ВЫП-9: веб-версия — дерево файлов --------------------------------------
//
// Её открывают на iPhone, где приложения нет и не будет: магазина у проекта нет,
// а поставить APK туда нельзя. Значит для этих людей веб-версия — не запасной
// путь, а единственный.

/** Сколько файлов и сколько всего байт готовы принять. Веб-сборка — единицы МБ. */
const MAX_WEB_FILES = 400;
const MAX_WEB_BYTES = 64 * 1024 * 1024;
const MAX_WEB_FILE_BYTES = 16 * 1024 * 1024;

/**
 * Сверить список файлов с ПОДПИСАННОЙ свёрткой.
 *
 * Список едет рядом с манифестом и в подпись не входит — в неё входит его
 * свёртка. Без этой сверки список можно было бы переписать целиком, не тронув
 * подписи: подсунуть свой путь, свой отпечаток, и узел разложил бы чужие файлы.
 */
function webFilesVerdict({ files, filesHash }) {
  if (!Array.isArray(files) || !files.length) return { ok: false, reason: 'в манифесте нет списка файлов' };
  if (files.length > MAX_WEB_FILES) return { ok: false, reason: 'файлов больше, чем бывает у веб-сборки' };
  let total = 0;
  for (const item of files) {
    if (!item || typeof item !== 'object') return { ok: false, reason: 'запись списка не объект' };
    if (!safeWebPath(item.path)) return { ok: false, reason: `негодный путь: ${String(item && item.path)}` };
    const size = Number(item.size);
    if (!Number.isFinite(size) || size < 0) return { ok: false, reason: 'у файла нет длины' };
    if (size > MAX_WEB_FILE_BYTES) return { ok: false, reason: 'файл веб-сборки неправдоподобно велик' };
    if (!/^[0-9a-f]{64}$/i.test(String(item.sha256 || ''))) return { ok: false, reason: 'у файла нет отпечатка' };
    total += size;
    if (total > MAX_WEB_BYTES) return { ok: false, reason: 'веб-сборка целиком больше потолка' };
  }
  const digest = crypto.createHash('sha256').update(filesPayload(files), 'utf8').digest('hex');
  if (digest !== String(filesHash || '').toLowerCase()) {
    return { ok: false, reason: 'список файлов не сходится с подписанной свёрткой' };
  }
  return { ok: true, reason: '' };
}

/**
 * Годится ли путь файла веб-сборки.
 *
 * Путь приходит из манифеста, то есть снаружи. Подпись его прикрывает, но
 * полагаться на одну подпись здесь нельзя: ошибка в этом месте означает запись
 * файла КУДА УГОДНО на диск узла — `../../etc/`, абсолютный путь, символьная
 * ссылка. Проверка стоит отдельно от подписи именно поэтому.
 */
function safeWebPath(value) {
  const raw = String(value || '');
  if (!raw || raw.length > 200) return '';
  if (raw.startsWith('/') || raw.startsWith('\\')) return '';
  if (/^[a-zA-Z]:/.test(raw)) return ''; // C:\… — абсолютный путь Windows
  if (raw.includes('\\')) return ''; // разделитель только прямой
  if (raw.includes('\0')) return '';
  const parts = raw.split('/');
  for (const part of parts) {
    if (!part || part === '.' || part === '..') return '';
  }
  return parts.join('/');
}

/**
 * Адрес файла многофайлового выпуска в репозитории раздачи.
 *
 * Каждая платформа лежит в своём подкаталоге: имена файлов у веб-версии и
 * настольного клиента разные, но общий каталог рано или поздно свёл бы их в
 * одно место, и один выпуск затирал бы другой.
 */
function treeFileUrl(source, platform, relativePath) {
  const base = String(source || '').trim().replace(/\/+$/, '');
  const safe = safeWebPath(relativePath);
  const dir = platform === 'web' ? 'web' : platform === 'desktop' ? 'desktop' : '';
  if (!base || !safe || !dir) return '';
  return `${base}/${dir}/${safe.split('/').map(encodeURIComponent).join('/')}`;
}

/** Прежнее имя — веб-версия. Оставлено, чтобы не переписывать проверки разом. */
function webFileUrl(source, relativePath) {
  return treeFileUrl(source, 'web', relativePath);
}

module.exports = {
  DEFAULT_SOURCE,
  DEFAULT_INTERVAL_MS,
  MAX_FILE_BYTES,
  MAX_MANIFEST_BYTES,
  manifestUrl,
  checkedManifest,
  needsFetch,
  fileVerdict,
  usableFileUrl,
  webFilesVerdict,
  safeWebPath,
  webFileUrl,
  treeFileUrl,
  MAX_WEB_FILES,
  MAX_WEB_BYTES,
  MAX_WEB_FILE_BYTES,
};
