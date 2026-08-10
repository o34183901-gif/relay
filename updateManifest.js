/* ЭТОТ ФАЙЛ СГЕНЕРИРОВАН — НЕ РЕДАКТИРУЙТЕ ЕГО.
 * Источник: src/updateManifest.js
 * Перегенерировать: node scripts/sync-core.js
 *
 * Правки вносятся ТОЛЬКО в источник. Ручная правка этой копии будет затёрта,
 * а CI (`node scripts/sync-core.js --check`) не пропустит расхождение: именно
 * оно однажды стоило потерянных сообщений на компьютере (НАД-1).
 */
/**
 * updateManifest.js — можно ли верить этому обновлению (ОБН-1).
 *
 * ЧТО БЫЛО НЕ ТАК
 *
 * Обновление на Android скачивалось так: сходить за манифестом по адресу
 * `https://lichno.pro/download/android-version.json`, взять оттуда версию и
 * ссылку, скачать файл, передать его системе на установку. Ни подписи манифеста,
 * ни сверки скачанного файла — вообще ничего. Единственной защитой была
 * связность «TLS + один известный домен».
 *
 * Этого мало уже сегодня: сервер раздачи может быть подменён, а файл на нём —
 * заменён, и приложение установит чужой APK, не заметив разницы. Речь не о
 * повреждённом обновлении, а о полном захвате устройства: установщик Android
 * поставит то, что ему дали.
 *
 * И этого становится СОВСЕМ мало, как только раздача идёт через релеи (о чём и
 * просили). Федерация открытая — свой релей поднимает кто угодно, это прямо
 * записано в разборе квитанций. Релей, раздающий обновления без проверки
 * подписи, — это раздача произвольного кода на все устройства, которые к нему
 * подключились.
 *
 * ПРАВИЛО
 *
 * Доверяем не источнику, а подписи. Манифест подписан ключом выпуска, ключ
 * вшит в сборку, и проверка идёт ДО скачивания. Файл сверяется с длиной и
 * SHA-256 из подписанного манифеста — иначе подписанным оказался бы только
 * рассказ о файле, а сам файл любым.
 *
 * Тогда источник перестаёт иметь значение: манифест может приехать с сайта, от
 * релея, из соседнего телефона по Bluetooth или с флешки. Подпись либо сходится,
 * либо нет.
 *
 * ЧЕГО ЭТИМ НЕ ЗАКРЫТО
 *
 * Откат на старую подписанную версию. Подпись у неё настоящая, и правило её
 * примет, если номер версии выше установленной, — а понизить версию правило и
 * не даёт. Но злоумышленник, придержавший подписанный манифест месячной
 * давности, может держать человека на старой сборке, не давая увидеть новую.
 * Лечится сроком годности манифеста; сегодня его нет, и выдумывать его в
 * одиночку здесь нельзя — он должен появиться вместе с выпуском.
 *
 * Модуль чистый: проверка подписи и хеша приходят параметрами, поэтому его
 * можно проверить целиком (тест test/updateManifest.test.js).
 */

'use strict';

/** Поля, из которых собирается подписываемое представление. */
// ВЫП-9: `filesHash` — свёртка списка файлов веб-сборки.
//
// Сам список (`files`) в подпись не входит и войти не может: значения здесь
// сводятся к строке, и `String(массив)` дал бы одинаковый результат для разных
// списков. Поэтому подписывается КОРОТКАЯ СВЁРТКА списка, а список едет рядом и
// сверяется с ней. Новое поле в конце — прежние манифесты (у них его нет)
// подписываются ровно как раньше: отсутствующие поля пропускаются.
const SIGNED_FIELDS = ['version', 'url', 'size', 'sha256', 'platform', 'notes', 'filesHash'];

/** Разбор номера версии: «1.2.3», «v1.2.3», «1.2.3-4» — всё это числа по точкам. */
function versionParts(value) {
  return String(value || '')
    .replace(/^v/i, '')
    .split(/[.-]/)
    .map((part) => Number.parseInt(part, 10))
    .map((part) => (Number.isFinite(part) ? part : 0));
}

/** Строго ли `candidate` новее `current`. */
function isNewerVersion(candidate, current) {
  const next = versionParts(candidate);
  const installed = versionParts(current);
  const length = Math.max(next.length, installed.length);
  for (let index = 0; index < length; index += 1) {
    const left = next[index] || 0;
    const right = installed[index] || 0;
    if (left !== right) return left > right;
  }
  return false;
}

/**
 * Каноническое представление списка файлов веб-сборки (ВЫП-9).
 *
 * Веб-версия — это не один файл, а дерево: страница, бандл, service worker,
 * значки. Каждый из них узел скачивает отдельно, и каждый обязан быть сверен —
 * иначе подменить можно было бы ровно один файл, тот самый, который исполняется.
 *
 * Здесь строка, а не хеш: считать хеш модуль не может — на телефоне для него нет
 * ни crypto, ни зависимости, которую стоило бы туда тащить. Обе стороны берут
 * sha256 от ЭТОЙ строки своим способом, а совпадать обязано её содержимое.
 *
 * Порядок фиксирован сортировкой по пути: обход каталога отдаёт файлы в порядке
 * файловой системы, и на другой машине он другой — свёртка не сошлась бы, хотя
 * сборка та же.
 */
function filesPayload(files) {
  const list = Array.isArray(files) ? files : [];
  return list
    .map((item) => ({
      path: String((item && item.path) || ''),
      size: Number((item && item.size) || 0),
      sha256: String((item && item.sha256) || '').toLowerCase(),
    }))
    .sort((left, right) => (left.path < right.path ? -1 : left.path > right.path ? 1 : 0))
    .map((item) => `${item.path}\n${item.size}\n${item.sha256}`)
    .join('\n');
}

/**
 * Что именно подписывается.
 *
 * Порядок полей задан списком, а не обходом объекта: обход зависит от порядка
 * ключей в JSON, и подпись, собранная отправителем, не сошлась бы с нашей из-за
 * перестановки. Отсутствующие поля пропускаются — иначе добавление нового поля
 * в манифест ломало бы проверку у всех прежних сборок.
 */
function signedPayload(manifest) {
  const source = manifest && typeof manifest === 'object' ? manifest : {};
  const parts = [];
  for (const field of SIGNED_FIELDS) {
    const value = source[field];
    if (value === undefined || value === null) continue;
    parts.push(`${field}=${String(value)}`);
  }
  return parts.join('\n');
}

/**
 * Проверить манифест обновления.
 *
 * `verifySignature(payload, signature, key)` — проверка подписи, приходит
 * параметром: сам модуль не должен знать, чем она считается, и только так его
 * можно проверить без криптографии.
 *
 * Возвращает `{ ok, reason, release }`. Причина отказа названа всегда: «не
 * обновилось молча» — это то же самое, что «не обновилось», только без
 * возможности разобраться.
 */
function verifyUpdateManifest(input) {
  const {
    manifest,
    currentVersion,
    platform,
    publicKey,
    verifySignature,
  } = input && typeof input === 'object' ? input : {};

  if (!manifest || typeof manifest !== 'object') return { ok: false, reason: 'манифест не разобран' };
  if (typeof verifySignature !== 'function') return { ok: false, reason: 'проверять подпись нечем' };
  if (!publicKey) return { ok: false, reason: 'ключ выпуска не задан в сборке' };

  const signature = manifest.signature;
  if (typeof signature !== 'string' || !signature) return { ok: false, reason: 'манифест не подписан' };

  // ПОДПИСЬ ПРОВЕРЯЕТСЯ ПЕРВОЙ. Всё, что ниже, — данные из манифеста, и
  // рассуждать о них до проверки значит доверять неподписанному.
  let signatureOk = false;
  try {
    signatureOk = verifySignature(signedPayload(manifest), signature, publicKey) === true;
  } catch (error) {
    signatureOk = false;
  }
  if (!signatureOk) return { ok: false, reason: 'подпись обновления не сходится' };

  if (platform && manifest.platform && manifest.platform !== platform) {
    return { ok: false, reason: 'обновление для другой платформы' };
  }
  if (typeof manifest.version !== 'string' || !manifest.version) {
    return { ok: false, reason: 'в манифесте нет версии' };
  }
  if (!isNewerVersion(manifest.version, currentVersion)) {
    return { ok: false, reason: 'установленная версия не старее' };
  }
  // БЕЗ ХЕША ПОДПИСЬ ЗАЩИЩАЕТ ТОЛЬКО РАССКАЗ О ФАЙЛЕ.
  //
  // Подписанный манифест без sha256 означает: «эту версию выпустил я, а файл
  // берите любой». Ровно то, от чего проверка и заводится.
  if (typeof manifest.sha256 !== 'string' || !/^[0-9a-f]{64}$/i.test(manifest.sha256)) {
    return { ok: false, reason: 'в манифесте нет отпечатка файла' };
  }
  const size = Number(manifest.size);
  if (!Number.isFinite(size) || size <= 0) return { ok: false, reason: 'в манифесте нет размера файла' };
  // Многофайловые web/desktop-выпуски подписывают не весь список, а его
  // SHA-256. Поле нужно не только проверить подписью выше, но и передать дальше
  // зеркалу: без него список неизбежно сравнивается с пустой свёрткой и каждый
  // настоящий выпуск отвергается. Для старых однофайловых манифестов поле
  // по-прежнему необязательно.
  const filesHash = manifest.filesHash;
  if (
    filesHash !== undefined &&
    filesHash !== null &&
    (typeof filesHash !== 'string' || !/^[0-9a-f]{64}$/i.test(filesHash))
  ) {
    return { ok: false, reason: 'в манифесте нет свёртки списка файлов' };
  }

  return {
    ok: true,
    reason: 'подпись сходится',
    release: {
      version: manifest.version,
      url: typeof manifest.url === 'string' ? manifest.url : '',
      size,
      sha256: manifest.sha256.toLowerCase(),
      notes: typeof manifest.notes === 'string' ? manifest.notes : '',
      filesHash: typeof filesHash === 'string' ? filesHash.toLowerCase() : '',
    },
  };
}

/**
 * Совпадает ли скачанный файл с тем, что обещал подписанный манифест.
 *
 * Сверяются оба признака. Длина — дешёвая проверка, которая ловит обрыв
 * скачивания раньше, чем считается хеш целого файла; хеш — единственное, что
 * ловит подмену.
 */
function fileMatchesRelease(release, actual) {
  // Значение по умолчанию у разбора аргумента срабатывает только на undefined:
  // на null он бросает. Сюда приходит результат чтения файла, а он может не
  // получиться вовсе.
  const { size, sha256 } = actual && typeof actual === 'object' ? actual : {};
  if (!release || typeof release !== 'object') return { ok: false, reason: 'нечего сверять' };
  const actualSize = Number(size);
  if (!Number.isFinite(actualSize) || actualSize !== Number(release.size)) {
    return { ok: false, reason: 'размер файла не совпал с обещанным' };
  }
  if (typeof sha256 !== 'string' || sha256.toLowerCase() !== String(release.sha256).toLowerCase()) {
    return { ok: false, reason: 'отпечаток файла не совпал — это не то обновление' };
  }
  return { ok: true, reason: 'файл тот самый' };
}

module.exports = {
  SIGNED_FIELDS,
  signedPayload,
  filesPayload,
  isNewerVersion,
  verifyUpdateManifest,
  fileMatchesRelease,
};
