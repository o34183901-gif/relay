/**
 * updateFeed.test.js — раздача обновлений с релея (ОБН-2).
 *
 * Обновление жило по одному адресу, и отказ этого адреса — обычно не
 * технический: домен блокируют, разделегируют, за него забывают заплатить.
 * Обновления встают у всех разом и ровно тогда, когда нужнее всего.
 *
 * Релей раздаёт файл, который и так публичный. Подпись он не проверяет — это
 * дело клиента, и проверка здесь означала бы второе место, где формат подписи
 * может разойтись сам с собой. Поэтому проверяется другое: что релей не отдаст
 * ничего, кроме выпуска, и не станет складывать путь из того, что пришло из
 * сети.
 *
 * Запуск: node server/updateFeed.test.js
 */

'use strict';

const assert = require('assert');
const path = require('path');
const {
  RELEASES,
  MAX_MANIFEST_BYTES,
  askedPlatform,
  releasePath,
  manifestResponse,
  fileResponse,
} = require('./updateFeed');

let passed = 0;
function test(name, fn) {
  fn();
  passed += 1;
  console.log('  ✓ ' + name);
}
console.log('раздача обновлений с релея (ОБН-2)');

// Абсолютный путь нужен именно текущей платформы: releasePath намеренно
// нормализует каталог через path.resolve, и Unix-путь на Windows превращался в
// другой ключ карты, отчего тест сообщал «выпуска нет» до первой проверки.
const DIR = path.resolve('srv/licno/releases');
const SIGNED = JSON.stringify({
  version: '2.0.0',
  url: 'https://lichno.pro/download/licno-android.apk',
  size: 1000,
  sha256: 'a'.repeat(64),
  platform: 'android',
  signature: 'подпись',
});

const readOf = (map) => (target) => {
  if (!Object.prototype.hasOwnProperty.call(map, target)) throw new Error('нет такого файла');
  return map[target];
};
const statOf = (map) => (target) => {
  if (!Object.prototype.hasOwnProperty.call(map, target)) throw new Error('нет такого файла');
  return map[target];
};

test('ГЛАВНОЕ: подписанный выпуск отдаётся', () => {
  const verdict = manifestResponse({
    dir: DIR,
    platform: 'android',
    read: readOf({ [path.join(DIR, 'android-version.json')]: SIGNED }),
  });
  assert.strictEqual(verdict.status, 200, verdict.reason);
  assert.strictEqual(verdict.manifest.version, '2.0.0');
  assert.strictEqual(verdict.platform, 'android');
  // Тело — то же самое, что разобрали: клиент проверит подпись по нему.
  assert.deepStrictEqual(JSON.parse(verdict.body), JSON.parse(SIGNED));
});

test('файл выпуска отдаётся под своим именем и типом', () => {
  const verdict = fileResponse({
    dir: DIR,
    platform: 'android',
    stat: statOf({ [path.join(DIR, 'licno-android.apk')]: { size: 42 * 1024 * 1024 } }),
  });
  assert.strictEqual(verdict.status, 200, verdict.reason);
  assert.strictEqual(verdict.size, 42 * 1024 * 1024);
  assert.strictEqual(verdict.filename, 'licno-android.apk');
  assert.strictEqual(verdict.type, 'application/vnd.android.package-archive');
  assert.strictEqual(verdict.path, path.join(DIR, 'licno-android.apk'));
});

test('НЕПОДПИСАННЫЙ ВЫПУСК НЕ РАЗДАЁТСЯ', () => {
  // Подпись мы не проверяем, но её отсутствие видно и отсюда. Раздача заведомо
  // негодного манифеста тратит трафик всех, кто его скачает, и заканчивается
  // отказом на каждом устройстве.
  const unsigned = JSON.stringify({ version: '2.0.0', url: '/x.apk', size: 1, sha256: 'a'.repeat(64) });
  for (const body of [unsigned, JSON.stringify({ version: '2.0.0', signature: '' }), JSON.stringify({ signature: 42 })]) {
    const verdict = manifestResponse({
      dir: DIR,
      platform: 'android',
      read: readOf({ [path.join(DIR, 'android-version.json')]: body }),
    });
    assert.strictEqual(verdict.status, 404, `отдан неподписанный выпуск: ${body}`);
    assert.ok(verdict.reason);
  }
});

test('чужая платформа не получает чужой файл', () => {
  // Отдать android-сборку десктопу значит заставить человека скачать десятки
  // мегабайт впустую и решить, что обновление сломано.
  // web и desktop сюда не ходят: веб обновляется service worker'ом, настольный
  // клиент — своим механизмом с собственной подписью. Отвечать им «вот выпуск»
  // значило бы обещать раздачу, которой нет.
  for (const bad of ['web', 'symbian', 'ANDROID', '../android', 'android ', 42, {}, []]) {
    assert.strictEqual(askedPlatform(bad), null, `принята платформа ${JSON.stringify(bad)}`);
    assert.strictEqual(
      manifestResponse({ dir: DIR, platform: bad, read: () => SIGNED }).status,
      404,
      `выпуск отдан платформе ${JSON.stringify(bad)}`
    );
  }
  // А объявленные — получают своё, и у каждой свои имена файлов.
  const names = new Set();
  for (const platform of Object.keys(RELEASES)) {
    assert.strictEqual(askedPlatform(platform), platform);
    const verdict = fileResponse({
      dir: DIR,
      platform,
      stat: statOf({ [path.join(DIR, RELEASES[platform].file)]: { size: 10 } }),
    });
    assert.strictEqual(verdict.status, 200, `${platform}: ${verdict.reason}`);
    assert.ok(!names.has(verdict.filename), `имя файла повторяется: ${verdict.filename}`);
    names.add(verdict.filename);
  }
});

test('старые сборки спрашивают без платформы и получают android', () => {
  // Параметра у них нет вовсе, и отказ означал бы, что запасной путь появился
  // только для тех, кто уже обновился.
  for (const empty of [undefined, null, '']) {
    assert.strictEqual(askedPlatform(empty), 'android');
  }
  const verdict = manifestResponse({
    dir: DIR,
    read: readOf({ [path.join(DIR, 'android-version.json')]: SIGNED }),
  });
  assert.strictEqual(verdict.status, 200, verdict.reason);
});

test('путь не складывается из того, что пришло из сети', () => {
  // Имена берутся из таблицы, поэтому выход за каталог невозможен по строению.
  // Проверка всё равно есть: цена ошибки — отдача произвольного файла с релея,
  // на котором лежат ключи.
  for (const bad of ['../../etc/passwd', '/etc/passwd', '..', 'android/../../..']) {
    assert.strictEqual(releasePath(DIR, bad, 'file'), null, `сложился путь для ${bad}`);
    assert.strictEqual(releasePath(DIR, bad, 'manifest'), null);
  }
  // И ни один настоящий путь не выходит за каталог раздачи.
  for (const platform of Object.keys(RELEASES)) {
    for (const kind of ['manifest', 'file']) {
      const full = releasePath(DIR, platform, kind);
      assert.ok(full.startsWith(path.resolve(DIR) + path.sep), `${platform}/${kind}: ${full}`);
    }
  }
});

test('раздача выключена, пока оператор её не настроил', () => {
  // Релей без каталога выпусков обязан честно отвечать «нет», а не пытаться
  // читать неизвестно что.
  for (const dir of [undefined, null, '', 42, {}]) {
    assert.strictEqual(
      manifestResponse({ dir, platform: 'android', read: () => SIGNED }).status,
      404,
      `раздача заработала при каталоге ${JSON.stringify(dir)}`
    );
    assert.strictEqual(fileResponse({ dir, platform: 'android', stat: () => ({ size: 1 }) }).status, 404);
  }
});

test('половина файла и мусор не отдаются', () => {
  // Выпуск идёт во время работы релея: файл на диске мог быть записан наполовину.
  const cases = {
    'обрезанный json': '{"version":"2.0.0","sign',
    'пустой файл': '',
    'не json вовсе': 'это не манифест',
    'json-массив': '[]',
    'json-строка': '"строка"',
    'json-null': 'null',
    'слишком длинное': `{"signature":"${'a'.repeat(MAX_MANIFEST_BYTES)}"}`,
  };
  for (const [name, body] of Object.entries(cases)) {
    const verdict = manifestResponse({
      dir: DIR,
      platform: 'android',
      read: readOf({ [path.join(DIR, 'android-version.json')]: body }),
    });
    assert.strictEqual(verdict.status, 404, `отдано «${name}»`);
    assert.ok(verdict.reason, `отказ без причины на «${name}»`);
  }
});

test('пустой файл выпуска — это отсутствие выпуска', () => {
  // Нулевой файл возникает от прерванного копирования. Отдай мы его — человек
  // скачал бы ноль байт и получил отказ сверки вместо понятного «пока нечего».
  for (const info of [{ size: 0 }, { size: -1 }, { size: 'много' }, {}, null]) {
    assert.strictEqual(
      fileResponse({ dir: DIR, platform: 'android', stat: () => info }).status,
      404,
      `отдан файл ${JSON.stringify(info)}`
    );
  }
});

test('мусор на входе не роняет релей', () => {
  // Обработчик стоит на публичном порту: сюда придёт что угодно.
  for (const bad of [null, undefined, 42, 'строка', [], {}]) {
    assert.strictEqual(manifestResponse(bad).status, 404);
    assert.strictEqual(fileResponse(bad).status, 404);
  }
  assert.strictEqual(manifestResponse().status, 404);
  assert.strictEqual(fileResponse().status, 404);
  // Чтение, которое бросает, — это «нет выпуска», а не падение процесса.
  assert.strictEqual(
    manifestResponse({
      dir: DIR,
      platform: 'android',
      read: () => {
        throw new Error('диск отвалился');
      },
    }).status,
    404
  );
  assert.strictEqual(
    fileResponse({
      dir: DIR,
      platform: 'android',
      stat: () => {
        throw new Error('диск отвалился');
      },
    }).status,
    404
  );
});

// ---------------------------------------------------------------------------
// ОБН-5: десктоп. Формат чужой (его читает Tauri updater), правила свои.
// ---------------------------------------------------------------------------

const TAURI = JSON.stringify({
  version: '1.4.0',
  notes: 'починили кружки',
  pub_date: '2026-01-01T00:00:00Z',
  platforms: {
    'windows-x86_64': {
      signature: 'подпись-minisign',
      url: 'https://github.com/o34183901-gif/messege/releases/download/desktop-v1.4.0/licno-setup.exe',
    },
  },
});
const DESKTOP_MANIFEST = path.join(DIR, 'desktop-latest.json');

test('ГЛАВНОЕ ОБН-5: адрес файла подменяется на СВОЙ, а подпись не трогается', () => {
  // Манифест приехал от релея — значит до репозитория могли и не достучаться.
  // Оставь мы адрес как есть, клиента отправили бы за файлом туда же, и
  // запасной путь довёл бы до половины и бросил.
  //
  // Подменить этим ничего нельзя: подпись Tauri стоит на самом установщике, а
  // не на манифесте. Установщик с чужой подписью до установки не доходит.
  const verdict = manifestResponse({
    dir: DIR,
    platform: 'desktop',
    selfUrl: 'https://relay.example',
    read: readOf({ [DESKTOP_MANIFEST]: TAURI }),
  });
  assert.strictEqual(verdict.status, 200, verdict.reason);
  const entry = verdict.manifest.platforms['windows-x86_64'];
  assert.strictEqual(entry.url, 'https://relay.example/update/file?platform=desktop');
  assert.strictEqual(entry.signature, 'подпись-minisign', 'подпись обязана дойти нетронутой');
  // Остальное — как было: версию и заметки Tauri читает сам.
  assert.strictEqual(verdict.manifest.version, '1.4.0');
  assert.strictEqual(verdict.manifest.notes, 'починили кружки');
  assert.strictEqual(verdict.manifest.pub_date, '2026-01-01T00:00:00Z');
  // И тело ответа — то же самое, что разобрали.
  assert.deepStrictEqual(JSON.parse(verdict.body), verdict.manifest);
});

test('ОБН-5: не знаем своего адреса — оставляем тот, что в манифесте', () => {
  // Заголовок Host мог не дойти (кривой прокси). Выдуманный адрес был бы хуже
  // прежнего: по нему точно никто не ответит.
  const verdict = manifestResponse({
    dir: DIR,
    platform: 'desktop',
    read: readOf({ [DESKTOP_MANIFEST]: TAURI }),
  });
  assert.strictEqual(verdict.status, 200, verdict.reason);
  assert.ok(
    verdict.manifest.platforms['windows-x86_64'].url.startsWith('https://github.com/'),
    'адрес из манифеста потерян, а своего нет'
  );
});

test('ОБН-5: манифест десктопа без подписи не раздаётся', () => {
  // Tauri всё равно откажет, но мы успеем отдать десятки мегабайт впустую.
  const cases = {
    'без подписи': JSON.stringify({ version: '1.0.0', platforms: { 'windows-x86_64': { url: 'https://x/y' } } }),
    'подпись пустая': JSON.stringify({ version: '1.0.0', platforms: { 'windows-x86_64': { signature: '', url: 'https://x/y' } } }),
    'подпись не строка': JSON.stringify({ version: '1.0.0', platforms: { 'windows-x86_64': { signature: 42 } } }),
    'платформ нет': JSON.stringify({ version: '1.0.0', platforms: {} }),
    'платформы не объект': JSON.stringify({ version: '1.0.0', platforms: [] }),
    'платформ вовсе нет': JSON.stringify({ version: '1.0.0' }),
    'платформа не разобрана': JSON.stringify({ version: '1.0.0', platforms: { 'windows-x86_64': null } }),
    'без версии': JSON.stringify({ platforms: { 'windows-x86_64': { signature: 'да', url: 'https://x/y' } } }),
  };
  for (const [name, body] of Object.entries(cases)) {
    const verdict = manifestResponse({
      dir: DIR,
      platform: 'desktop',
      selfUrl: 'https://relay.example',
      read: readOf({ [DESKTOP_MANIFEST]: body }),
    });
    assert.strictEqual(verdict.status, 404, `отдано «${name}»`);
    assert.ok(verdict.reason, `отказ без причины на «${name}»`);
  }
});

test('ОБН-5: у десктопа свой файл и своё имя, чужой манифест ему не подходит', () => {
  const verdict = fileResponse({
    dir: DIR,
    platform: 'desktop',
    stat: statOf({ [path.join(DIR, 'licno-windows-x64-setup.exe')]: { size: 90 * 1024 * 1024 } }),
  });
  assert.strictEqual(verdict.status, 200, verdict.reason);
  assert.strictEqual(verdict.filename, 'licno-windows-x64-setup.exe');
  assert.notStrictEqual(verdict.filename, RELEASES.android.file, 'десктопу отдают android-файл');
  // Манифест android по правилам десктопа не разбирается и наоборот: у них
  // разные форматы, и перепутать их значит отдать мусор обеим платформам.
  const wrong = manifestResponse({
    dir: DIR,
    platform: 'desktop',
    selfUrl: 'https://relay.example',
    read: readOf({ [DESKTOP_MANIFEST]: SIGNED }),
  });
  assert.strictEqual(wrong.status, 404, 'манифест android отдан как десктопный');
});

console.log(`раздача обновлений: ${passed} проверок пройдено`);
