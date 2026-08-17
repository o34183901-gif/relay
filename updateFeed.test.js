'use strict';
const assert = require('assert');
const path = require('path');
const {
  RELEASES,
  MAX_MANIFEST_BYTES,
  askedPlatform,
  askedChannel,
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
  for (const bad of ['web', 'symbian', 'ANDROID', '../android', 'android ', 42, {}, []]) {
    assert.strictEqual(askedPlatform(bad), null, `принята платформа ${JSON.stringify(bad)}`);
    assert.strictEqual(
      manifestResponse({ dir: DIR, platform: bad, read: () => SIGNED }).status,
      404,
      `выпуск отдан платформе ${JSON.stringify(bad)}`
    );
  }
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
  for (const bad of ['../../etc/passwd', '/etc/passwd', '..', 'android/../../..']) {
    assert.strictEqual(releasePath(DIR, bad, 'file'), null, `сложился путь для ${bad}`);
    assert.strictEqual(releasePath(DIR, bad, 'manifest'), null);
  }
  for (const platform of Object.keys(RELEASES)) {
    for (const kind of ['manifest', 'file']) {
      const full = releasePath(DIR, platform, kind);
      assert.ok(full.startsWith(path.resolve(DIR) + path.sep), `${platform}/${kind}: ${full}`);
    }
  }
});
test('раздача выключена, пока оператор её не настроил', () => {
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
  for (const info of [{ size: 0 }, { size: -1 }, { size: 'много' }, {}, null]) {
    assert.strictEqual(
      fileResponse({ dir: DIR, platform: 'android', stat: () => info }).status,
      404,
      `отдан файл ${JSON.stringify(info)}`
    );
  }
});
test('мусор на входе не роняет релей', () => {
  for (const bad of [null, undefined, 42, 'строка', [], {}]) {
    assert.strictEqual(manifestResponse(bad).status, 404);
    assert.strictEqual(fileResponse(bad).status, 404);
  }
  assert.strictEqual(manifestResponse().status, 404);
  assert.strictEqual(fileResponse().status, 404);
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
test('КАН-1: тестовый канал отдаёт свой манифест, не трогая проверенный', () => {
  const CANARY = JSON.stringify({
    version: '2.1.0',
    url: 'https://github.com/o34183901-gif/relay/releases/download/app-v2.1.0/licno-android.apk',
    size: 1000,
    sha256: 'b'.repeat(64),
    platform: 'android',
    channel: 'canary',
    signature: 'подпись',
  });
  const read = readOf({
    [path.join(DIR, 'android-version.json')]: SIGNED,
    [path.join(DIR, 'android-canary-version.json')]: CANARY,
  });
  const canary = manifestResponse({ dir: DIR, platform: 'android', channel: 'canary', read });
  assert.strictEqual(canary.status, 200, canary.reason);
  assert.strictEqual(canary.manifest.version, '2.1.0');
  assert.strictEqual(canary.manifest.channel, 'canary');
  const stable = manifestResponse({ dir: DIR, platform: 'android', read });
  assert.strictEqual(stable.status, 200, stable.reason);
  assert.strictEqual(stable.manifest.version, '2.0.0');
  assert.strictEqual(stable.manifest.channel, undefined, 'в проверенный манифест пролез канал');
});
test('КАН-1: незнакомый канал и платформа без тестового канала — отказ, а не «отдам проверенный»', () => {
  assert.strictEqual(askedChannel(''), 'stable');
  assert.strictEqual(askedChannel(undefined), 'stable');
  assert.strictEqual(askedChannel('canary'), 'canary');
  assert.strictEqual(askedChannel('nightly'), null);
  assert.strictEqual(askedChannel(42), null);
  const read = readOf({
    [path.join(DIR, 'android-version.json')]: SIGNED,
    [path.join(DIR, 'android-canary-version.json')]: SIGNED,
  });
  const unknown = manifestResponse({ dir: DIR, platform: 'android', channel: 'nightly', read });
  assert.strictEqual(unknown.status, 404, 'незнакомый канал получил ответ');
  const unknownOs = manifestResponse({ dir: DIR, platform: 'unknown-os', channel: 'canary', read });
  assert.strictEqual(unknownOs.status, 404, 'неизвестной платформе не отдан 404');
});
test('КАН-1: тестового манифеста нет на диске — 404, проверенный при этом жив', () => {
  const read = readOf({ [path.join(DIR, 'android-version.json')]: SIGNED });
  const canary = manifestResponse({ dir: DIR, platform: 'android', channel: 'canary', read });
  assert.strictEqual(canary.status, 404, 'отдан манифест, которого нет');
  const stable = manifestResponse({ dir: DIR, platform: 'android', channel: 'stable', read });
  assert.strictEqual(stable.status, 200, stable.reason);
});
console.log(`раздача обновлений: ${passed} проверок пройдено`);