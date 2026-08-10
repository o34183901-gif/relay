'use strict';

/**
 * updateFeed.js — раздача обновлений с релея (ОБН-2).
 *
 * ЗАЧЕМ РЕЛЕЮ ЭТИМ ЗАНИМАТЬСЯ
 *
 * Обновление приложения жило по одному адресу — `https://lichno.pro/download/…`.
 * Один домен — одна точка отказа, и отказ этот чаще не технический: домен
 * блокируют, разделегируют, за него забывают заплатить. Обновления перестают
 * приходить у всех разом и ровно тогда, когда они нужнее всего: после находки
 * дыры в предыдущей сборке.
 *
 * Релеев три в сборке и сколько угодно в федерации, приложение к ним и так
 * подключено, а файл выпуска публичный. Раздать его — самая дешёвая из
 * возможных мер.
 *
 * ПОЧЕМУ РЕЛЕЙ НЕ ПРОВЕРЯЕТ ПОДПИСЬ, И ЭТО НЕ УПУЩЕНИЕ
 *
 * Потому что доверия к релею нет по замыслу. Манифест подписан ключом выпуска,
 * ключ вшит в приложение, файл сверяется с отпечатком из подписанного
 * манифеста. Проверь релей подпись — приложение всё равно проверит её заново,
 * и итог не изменится ни в одном случае: подделку отвергнет клиент.
 *
 * Зато проверка на релее потребовала бы держать здесь ключ выпуска и повторять
 * подписываемое представление — то есть завести ВТОРОЕ место, где формат
 * подписи может разойтись сам с собой. Разойдись оно — обновления встали бы у
 * всех, и понять почему было бы нечем.
 *
 * Оператор релея, подложивший чужой файл, добьётся ровно одного: его релей
 * будет отдавать то, что не проходит проверку, и клиент пойдёт к следующему.
 *
 * ЧТО ЗДЕСЬ ЕСТЬ
 *
 * Только правила: какой платформе какие файлы соответствуют, что отдавать и
 * чего не отдавать никогда. Ни чтения диска (оно приходит параметрами), ни
 * HTTP — и потому это проверяется целиком, без поднятия сервера.
 *
 * ЧЕГО ЗДЕСЬ НЕТ НАМЕРЕННО
 *
 * Репликации выпусков между релеями. Соблазн большой — каталог релеев и записки
 * ящика уже разъезжаются по федерации сами, — но там разъезжаются килобайты, а
 * здесь десятки мегабайт, и оплатит их оператор, который ни о чём не просил.
 * Выпуск кладёт тот, кто держит релей и хочет его раздавать.
 */

const path = require('path');

/**
 * Что раздаём. Имена фиксированы таблицей, а не собираются из запроса: любая
 * склейка пути с тем, что пришло из сети, — это разговор о выходе за каталог,
 * которого здесь просто не будет.
 *
 * ANDROID И DESKTOP. ВЕБА ЗДЕСЬ НЕТ, И ЭТО НЕ НЕДОДЕЛКА: страница обновляется
 * service worker'ом при загрузке, ей нечего раздавать.
 *
 * У десктопа формат манифеста СВОЙ — его читает Tauri updater, а не наше
 * приложение (ОБН-5). Различие принципиальное: подпись у Tauri стоит на самом
 * установщике (minisign, ключ вшит в desktop/src-tauri/tauri.conf.json), а не
 * на манифесте. Поэтому адрес файла внутри манифеста НЕ подписан — и его можно
 * безопасно заменить на адрес того релея, который отдаёт манифест: подмену
 * самого файла Tauri поймает проверкой подписи.
 */
const RELEASES = {
  android: {
    manifest: 'android-version.json',
    file: 'licno-android.apk',
    type: 'application/vnd.android.package-archive',
    kind: 'licno',
  },
  desktop: {
    manifest: 'desktop-latest.json',
    file: 'licno-windows-x64-setup.exe',
    type: 'application/octet-stream',
    kind: 'tauri',
  },
};

/** Потолок манифеста. Он меньше килобайта; всё, что больше, — не манифест. */
const MAX_MANIFEST_BYTES = 64 * 1024;

/** Путь, по которому этот же релей отдаёт файл выпуска. */
const RELEASE_FILE_PATH = '/update/file';

/**
 * Какую платформу спрашивают.
 *
 * Умолчание — android, и это не лень: сегодня самообновлением пользуется только
 * он, а старые сборки спросят без параметра вовсе. Неизвестное значение — это
 * `null`, а не «отдам android»: отдать чужой платформе чужой файл значит
 * заставить человека скачать десятки мегабайт впустую.
 */
function askedPlatform(value) {
  if (value === undefined || value === null || value === '') return 'android';
  if (typeof value !== 'string') return null;
  return Object.prototype.hasOwnProperty.call(RELEASES, value) ? value : null;
}

/**
 * Полный путь к файлу выпуска внутри каталога раздачи.
 *
 * `null` — каталог не настроен либо платформа неизвестна. Проверка на выход за
 * каталог здесь избыточна (имена берутся из таблицы), но оставлена: она стоит
 * одно сравнение, а цена ошибки — отдача произвольного файла с релея, на
 * котором лежат ключи.
 */
function releasePath(dir, platform, kind) {
  if (!dir || typeof dir !== 'string') return null;
  const release = RELEASES[platform];
  if (!release) return null;
  const name = kind === 'file' ? release.file : release.manifest;
  const full = path.resolve(dir, name);
  const root = path.resolve(dir);
  if (full !== path.join(root, name)) return null;
  return full;
}

/**
 * Что ответить на запрос манифеста.
 *
 * `read(path) → string|null` приходит параметром: правило не читает диск само,
 * и потому проверяется без него.
 *
 * Разбираем JSON ЗДЕСЬ, а не отдаём как есть: файл на диске мог быть записан
 * наполовину (выпуск идёт во время работы релея), и отдать половину значит
 * заставить клиента считать источник негодным и уйти к следующему — при том что
 * через секунду здесь будет целый манифест.
 */
function manifestResponse(input) {
  const { dir, platform, read } = input && typeof input === 'object' ? input : {};
  const asked = askedPlatform(platform);
  if (!asked) return { status: 404, reason: 'неизвестная платформа' };
  const target = releasePath(dir, asked, 'manifest');
  if (!target) return { status: 404, reason: 'раздача обновлений не настроена' };
  let text = null;
  try {
    text = read(target);
  } catch (error) {
    return { status: 404, reason: 'выпуска нет' };
  }
  if (typeof text !== 'string' || !text) return { status: 404, reason: 'выпуска нет' };
  if (text.length > MAX_MANIFEST_BYTES) return { status: 404, reason: 'это не манифест' };
  let manifest = null;
  try {
    manifest = JSON.parse(text);
  } catch (error) {
    return { status: 404, reason: 'манифест не разобран' };
  }
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
    return { status: 404, reason: 'манифест не разобран' };
  }
  // НЕПОДПИСАННОЕ НЕ РАЗДАЁМ.
  //
  // Подпись мы не проверяем — нечем и незачем, это дело клиента, — но её
  // ОТСУТСТВИЕ видно и отсюда. Раздача заведомо негодного манифеста тратит
  // трафик всех, кто его скачает, и заканчивается отказом на каждом устройстве.
  // Пусть лучше оператор увидит 404 и положит подписанный файл.
  if (RELEASES[asked].kind === 'tauri') {
    return tauriResponse({ manifest, platform: asked, selfUrl: input.selfUrl });
  }
  if (typeof manifest.signature !== 'string' || !manifest.signature) {
    return { status: 404, reason: 'выпуск не подписан' };
  }
  return { status: 200, platform: asked, manifest, body: JSON.stringify(manifest) };
}

/**
 * Манифест для Tauri updater (ОБН-5) — и подстановка своего адреса.
 *
 * ФОРМАТ ЧУЖОЙ, И МЕНЯТЬ ЕГО НЕЛЬЗЯ: `{ version, notes, pub_date, platforms:
 * { "windows-x86_64": { signature, url } } }`. Читает его не наше приложение, а
 * плагин обновления Tauri.
 *
 * ПОЧЕМУ АДРЕС МОЖНО ПОДМЕНЯТЬ, И ПОЧЕМУ ЭТО НЕ ДЫРА.
 *
 * У Tauri подпись стоит на САМОМ УСТАНОВЩИКЕ (minisign; рядом с файлом лежит
 * `.sig`, его содержимое и попадает в поле signature). Манифест не подписан
 * вовсе — значит `url` в нём не защищён ничем, и подменить его может кто угодно
 * по дороге. Но подменить сам файл нельзя: ключ проверки вшит в приложение, и
 * установщик с чужой подписью до установки не доходит.
 *
 * Отсюда и решение. Адрес в манифесте указывает на выпуск в репозитории, а этот
 * релей заменяет его на СВОЙ — иначе получилось бы так: манифест приехал от
 * релея (значит до репозитория не достучались), а за файлом клиента отправляют
 * туда же. Запасной путь довёл бы до половины и бросил.
 *
 * `selfUrl` — адрес этого узла, каким его назвал сам клиент. Подделать его
 * может только тот, кто делает запрос, и навредит он этим лишь себе.
 */
function tauriResponse(input) {
  const { manifest, platform, selfUrl } = input && typeof input === 'object' ? input : {};
  const platforms = manifest && manifest.platforms;
  if (!platforms || typeof platforms !== 'object' || Array.isArray(platforms)) {
    return { status: 404, reason: 'в манифесте нет платформ' };
  }
  const names = Object.keys(platforms);
  if (!names.length) return { status: 404, reason: 'в манифесте нет платформ' };

  const patched = {};
  for (const name of names) {
    const entry = platforms[name];
    if (!entry || typeof entry !== 'object') return { status: 404, reason: 'платформа не разобрана' };
    // Подпись обязана быть: без неё Tauri всё равно откажет, а мы успеем отдать
    // человеку десятки мегабайт впустую.
    if (typeof entry.signature !== 'string' || !entry.signature) {
      return { status: 404, reason: 'выпуск не подписан' };
    }
    patched[name] = {
      ...entry,
      url: selfUrl ? `${selfUrl}${RELEASE_FILE_PATH}?platform=${platform}` : entry.url,
    };
  }
  if (typeof manifest.version !== 'string' || !manifest.version) {
    return { status: 404, reason: 'в манифесте нет версии' };
  }
  const out = { ...manifest, platforms: patched };
  return { status: 200, platform, manifest: out, body: JSON.stringify(out) };
}

/**
 * Что ответить на запрос самого файла.
 *
 * `stat(path) → {size}|null` приходит параметром по той же причине.
 *
 * Возвращает путь и заголовки; отдавать поток — дело проводки. Здесь только
 * решение «есть ли что отдавать и под каким видом».
 */
function fileResponse(input) {
  const { dir, platform, stat } = input && typeof input === 'object' ? input : {};
  const asked = askedPlatform(platform);
  if (!asked) return { status: 404, reason: 'неизвестная платформа' };
  const target = releasePath(dir, asked, 'file');
  if (!target) return { status: 404, reason: 'раздача обновлений не настроена' };
  let info = null;
  try {
    info = stat(target);
  } catch (error) {
    return { status: 404, reason: 'файла выпуска нет' };
  }
  const size = info && Number(info.size);
  if (!Number.isFinite(size) || size <= 0) return { status: 404, reason: 'файла выпуска нет' };
  return {
    status: 200,
    platform: asked,
    path: target,
    size,
    type: RELEASES[asked].type,
    // Имя для сохранения. Без него браузер предложит сохранить «file» без
    // расширения, а Android-загрузчик — угадать тип по адресу.
    filename: RELEASES[asked].file,
  };
}

module.exports = {
  RELEASES,
  MAX_MANIFEST_BYTES,
  RELEASE_FILE_PATH,
  askedPlatform,
  releasePath,
  manifestResponse,
  fileResponse,
};
