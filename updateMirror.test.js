'use strict';

const assert = require('assert');
const nacl = require('tweetnacl');
const {
  treeFileUrl,
  manifestUrl,
  checkedManifest,
  needsFetch,
  fileVerdict,
  usableFileUrl,
  safeWebPath,
  webFilesVerdict,
  webFileUrl,
  MAX_FILE_BYTES,
  DEFAULT_SOURCE,
} = require('./updateMirror');
const crypto = require('crypto');
const { filesPayload } = require('./updateManifest');
let passed = 0;
const ok = (name) => {
  console.log('  ✓ ' + name);
  passed += 1;
};
console.log('\nВЫП-8: узел сам забирает выпуск\n');
const pair = nacl.sign.keyPair();
const OPEN = Buffer.from(pair.publicKey).toString('base64');
const verifySignature = (payload, signature, key) =>
  nacl.sign.detached.verify(
    Buffer.from(payload, 'utf8'),
    new Uint8Array(Buffer.from(signature, 'base64')),
    new Uint8Array(Buffer.from(key, 'base64'))
  );
const { signedPayload } = require('./updateManifest');
const signManifest = (fields, key = pair.secretKey) => ({
  ...fields,
  signature: Buffer.from(
    nacl.sign.detached(Buffer.from(signedPayload(fields), 'utf8'), key)
  ).toString('base64'),
});
const release = (over = {}) =>
  signManifest({
    version: '1.4.0',
    url: 'https://github.com/o34183901-gif/relay/releases/download/app-v1.4.0/licno-android.apk',
    size: 60 * 1024 * 1024,
    sha256: 'c'.repeat(64),
    platform: 'android',
    ...over,
  });
const check = (manifest, over = {}) =>
  checkedManifest({
    body: JSON.stringify(manifest),
    platform: 'android',
    publicKey: OPEN,
    verifySignature,
    ...over,
  });
{
  const verdict = check(release());
  assert.strictEqual(verdict.ok, true, `свой же выпуск отвергнут: ${verdict.reason}`);
  assert.strictEqual(verdict.release.version, '1.4.0');
  ok('подписанный манифест принимается');
}

{
  const alien = nacl.sign.keyPair();
  const verdict = check(release({}), {});
  assert.strictEqual(verdict.ok, true);
  const forged = signManifest(
    {
      version: '9.9.9',
      url: 'https://злоумышленник.example/licno.apk',
      size: 10,
      sha256: 'd'.repeat(64),
      platform: 'android',
    },
    alien.secretKey
  );
  assert.strictEqual(check(forged).ok, false, 'манифест с чужой подписью принят — узел пойдёт по чужому адресу');
  ok('чужая подпись отвергается до того, как адрес будет прочитан');
}

{
  const swapped = { ...release(), url: 'https://злоумышленник.example/licno.apk' };
  assert.strictEqual(check(swapped).ok, false, 'подменённый адрес принят');
  ok('подменённый адрес ломает подпись');
}

{
  assert.strictEqual(check(release({ platform: 'web' })).ok, false);
  ok('чужая платформа отвергается');
}
{
  for (const body of ['', 'не json', '{', null, undefined, 'x'.repeat(70 * 1024)]) {
    const verdict = checkedManifest({ body, platform: 'android', publicKey: OPEN, verifySignature });
    assert.strictEqual(verdict.ok, false, `мусор ${JSON.stringify(String(body).slice(0, 12))} принят`);
    assert.ok(verdict.reason, 'отказ без объяснения');
  }
  ok('мусор вместо манифеста отвергается с объяснением');
}
{
  const rel = { version: '1.4.0', sha256: 'c'.repeat(64) };
  assert.strictEqual(needsFetch({ have: null, release: rel }), true, 'первый выпуск обязан скачаться');
  assert.strictEqual(needsFetch({ have: { version: '1.3.9', sha256: 'a' }, release: rel }), true);
  assert.strictEqual(
    needsFetch({ have: { version: '1.4.0', sha256: 'c'.repeat(64) }, release: rel }),
    false,
    'тот же выпуск качается заново — это десятки мегабайт на ровном месте'
  );
  assert.strictEqual(
    needsFetch({ have: { version: '1.5.0', sha256: 'e' }, release: rel }),
    false,
    'на диске новее — старое подтягивать незачем'
  );
  assert.strictEqual(
    needsFetch({ have: { version: '1.4.0', sha256: 'f'.repeat(64) }, release: rel }),
    true,
    'версия та же, а файл другой — узел раздаёт не то, что объявляет'
  );
  ok('лишний раз не качаем, а расхождение с диском чиним');
}
{
  const rel = { size: 1000, sha256: 'ab'.repeat(32) };
  assert.strictEqual(fileVerdict({ size: 1000, sha256: 'ab'.repeat(32), release: rel }).ok, true);
  assert.strictEqual(fileVerdict({ size: 1000, sha256: 'AB'.repeat(32), release: rel }).ok, true, 'регистр отпечатка');
  assert.strictEqual(fileVerdict({ size: 999, sha256: 'ab'.repeat(32), release: rel }).ok, false);
  assert.strictEqual(fileVerdict({ size: 1000, sha256: 'cd'.repeat(32), release: rel }).ok, false);
  assert.strictEqual(fileVerdict({ size: 0, sha256: 'ab'.repeat(32), release: rel }).ok, false);
  assert.strictEqual(
    fileVerdict({ size: MAX_FILE_BYTES + 1, sha256: 'ab'.repeat(32), release: { size: MAX_FILE_BYTES + 1, sha256: 'ab'.repeat(32) } }).ok,
    false,
    'файл больше потолка обязан отсеиваться до записи на диск'
  );
  ok('скачанный файл сверяется с подписанным манифестом');
}
{
  assert.ok(usableFileUrl('https://example.org/a.apk'));
  assert.strictEqual(usableFileUrl('http://example.org/a.apk'), '', 'http принят — узел скачает мусор по дороге');
  assert.strictEqual(usableFileUrl('file:///etc/passwd'), '');
  assert.strictEqual(usableFileUrl(''), '');
  assert.strictEqual(usableFileUrl(null), '');
  ok('за файлом узел ходит только по https');
}
{
  assert.strictEqual(manifestUrl(DEFAULT_SOURCE, 'android'), `${DEFAULT_SOURCE}/android-version.json`);
  assert.strictEqual(manifestUrl(`${DEFAULT_SOURCE}/`, 'android'), `${DEFAULT_SOURCE}/android-version.json`);
  assert.strictEqual(manifestUrl(DEFAULT_SOURCE, 'выдумка'), '', 'неизвестная платформа не должна давать адрес');
  assert.strictEqual(manifestUrl('', 'android'), '');
  assert.ok(/^https:\/\//.test(DEFAULT_SOURCE), 'источник по умолчанию обязан быть https');
  ok('адрес источника собирается предсказуемо');
}
{
  assert.strictEqual(treeFileUrl(DEFAULT_SOURCE, 'web', 'index.html'), `${DEFAULT_SOURCE}/web/index.html`);
  assert.strictEqual(treeFileUrl(DEFAULT_SOURCE, 'android', 'x'), '', 'у android дерева файлов нет');
  assert.strictEqual(treeFileUrl(DEFAULT_SOURCE, 'выдумка', 'x'), '');
  assert.strictEqual(treeFileUrl(DEFAULT_SOURCE, 'web', '../../secret'), '');
  assert.strictEqual(treeFileUrl(DEFAULT_SOURCE, 'web', '/etc/passwd'), '');
  assert.strictEqual(treeFileUrl('', 'web', 'a'), '');
  ok('у каждой платформы свой подкаталог, и наружу путь не выпускает');
}
{
  const files = [
    { path: 'index.html', size: 5, sha256: 'a'.repeat(64) },
    { path: 'assets/app.js', size: 7, sha256: 'b'.repeat(64) },
  ];
  const filesHash = crypto.createHash('sha256').update(filesPayload(files), 'utf8').digest('hex');
  assert.strictEqual(webFilesVerdict({ files, filesHash }).ok, true);
  assert.strictEqual(webFilesVerdict({ files: null, filesHash }).ok, false);
  assert.strictEqual(webFilesVerdict({ files: new Array(401).fill(files[0]), filesHash }).ok, false);
  assert.strictEqual(webFilesVerdict({ files: [null], filesHash }).ok, false);
  assert.strictEqual(webFilesVerdict({ files: [{ ...files[0], path: '../secret' }], filesHash }).ok, false);
  assert.strictEqual(webFilesVerdict({ files: [{ ...files[0], size: -1 }], filesHash }).ok, false);
  assert.strictEqual(webFilesVerdict({ files: [{ ...files[0], size: 17 * 1024 * 1024 }], filesHash }).ok, false);
  assert.strictEqual(webFilesVerdict({ files: [{ ...files[0], sha256: 'bad' }], filesHash }).ok, false);
  assert.strictEqual(
    webFilesVerdict({ files: new Array(5).fill({ ...files[0], size: 15 * 1024 * 1024 }), filesHash }).ok,
    false
  );
  assert.strictEqual(webFilesVerdict({ files, filesHash: 'c'.repeat(64) }).ok, false);
  assert.strictEqual(safeWebPath('assets/app.js'), 'assets/app.js');
  for (const bad of ['', '/etc/passwd', '\\server\\share', 'C:/secret', 'a\\b', 'a\0b', 'a//b', 'a/./b', 'a/../b', 'x'.repeat(201)]) {
    assert.strictEqual(safeWebPath(bad), '', `принят путь ${JSON.stringify(bad)}`);
  }
  assert.strictEqual(webFileUrl(DEFAULT_SOURCE, 'assets/app.js'), `${DEFAULT_SOURCE}/web/assets/app.js`);
  ok('список дерева сверяется со свёрткой, размерами и безопасными путями');
}
{
  const files = [
    { path: 'index.html', size: 814, sha256: 'a'.repeat(64) },
    { path: 'assets/app.js', size: 420, sha256: 'b'.repeat(64) },
  ];
  const filesHash = crypto.createHash('sha256').update(filesPayload(files), 'utf8').digest('hex');
  const checked = check(release({ platform: 'web', filesHash }), { platform: 'web' });
  assert.strictEqual(checked.ok, true, `web-манифест отвергнут: ${checked.reason}`);
  assert.strictEqual(checked.release.filesHash, filesHash, 'filesHash потерян после проверки подписи');
  assert.strictEqual(
    webFilesVerdict({ files, filesHash: checked.release.filesHash }).ok,
    true,
    'mirrorTree не принимает список настоящего подписанного веб-выпуска'
  );
  assert.strictEqual(
    check(release({ platform: 'web', filesHash: 'не-sha256' }), { platform: 'web' }).ok,
    false,
    'зеркало приняло подписанную, но негодную свёртку списка'
  );
  ok('подписанная свёртка дерева проходит полный путь до проверки списка');
}
console.log(`\nВЫП-8: ${passed} проверок пройдено`);