'use strict';

const assert = require('assert');
const path = require('path');
const { webAppPath, resolveWebFile, webAppHeaders, contentType, WEB_APP_PREFIX } = require('./webApp');

let passed = 0;
const ok = (name) => {
  console.log('  ✓ ' + name);
  passed += 1;
};
console.log('\nВЫП-9: раздача веб-версии\n');
{
  for (const url of ['/health', '/relays', '/update', '/', '/apple', '/appx/y']) {
    assert.strictEqual(webAppPath(url), null, `${url} перехвачен раздачей веб-версии`);
  }
  assert.notStrictEqual(webAppPath(WEB_APP_PREFIX), null);
  assert.notStrictEqual(webAppPath(`${WEB_APP_PREFIX}/x.js`), null);
  ok('чужие адреса не перехватываются');
}

{
  assert.strictEqual(webAppPath('/app'), 'index.html');
  assert.strictEqual(webAppPath('/app/'), 'index.html');
  assert.strictEqual(webAppPath('/app?utm=1'), 'index.html');
  assert.strictEqual(webAppPath('/app/index.html'), 'index.html');
  assert.strictEqual(webAppPath('/app/static/js/bundle.js'), 'static/js/bundle.js');
  assert.strictEqual(webAppPath('/app/sw.js?v=2'), 'sw.js');
  assert.strictEqual(webAppPath('/app//static//a.js'), 'static/a.js');
  ok('обычные запросы разбираются в путь файла');
}

{
  const outside = [
    '/app/../relay.js',
    '/app/../../etc/passwd',
    '/app/%2e%2e/relay.js',
    '/app/%2E%2E%2Frelay.js',
    '/app/static/../../relay.js',
    '/app/..%2Frelay.js',
    '/app/%00.js',
    `/app/${'x'.repeat(250)}`,
    '/app/%',
  ];
  for (const url of outside) {
    assert.strictEqual(webAppPath(url), '', `${url} НЕ отсечён — узел отдаст файл за пределами каталога`);
  }
  const backslash = String.fromCharCode(92);
  assert.strictEqual(
    webAppPath(`/app/..${backslash}..${backslash}relay.js`),
    '',
    'обратными слэшами удалось выйти за каталог'
  );
  assert.strictEqual(
    webAppPath(`/app/a${backslash}b.js`),
    'a/b.js',
    'обратный слэш обязан стать разделителем пути, а не остаться в имени файла'
  );
  ok('попытки выйти за каталог отсекаются, включая процентные и обратные слэши');
}
{
  const root = '/srv/licno/releases/web';
  assert.strictEqual(resolveWebFile(root, 'index.html'), path.resolve(root, 'index.html'));
  assert.strictEqual(resolveWebFile(root, 'static/a.js'), path.resolve(root, 'static/a.js'));
  assert.strictEqual(resolveWebFile(root, '../relay.js'), '', 'выход за корень не пойман на собранном пути');
  assert.strictEqual(resolveWebFile(root, '/etc/passwd'), '', 'абсолютный путь принят');
  assert.strictEqual(resolveWebFile(root, ''), '');
  assert.strictEqual(resolveWebFile('', 'index.html'), '');
  assert.strictEqual(resolveWebFile('/srv/web', '../web-secret/key'), '');
  ok('собранный путь ещё раз сверяется с корнем');
}
{
  assert.strictEqual(contentType('index.html'), 'text/html; charset=utf-8');
  assert.strictEqual(contentType('a/b.js'), 'text/javascript; charset=utf-8');
  assert.strictEqual(contentType('style.CSS'), 'text/css; charset=utf-8');
  assert.strictEqual(contentType('icon.png'), 'image/png');
  assert.strictEqual(contentType('site.webmanifest'), 'application/manifest+json');
  assert.strictEqual(contentType('чужое.exe'), 'application/octet-stream');
  assert.strictEqual(contentType('без-расширения'), 'application/octet-stream');
  assert.strictEqual(contentType(''), 'application/octet-stream');
  ok('тип берётся из закрытого списка, а не угадывается');
}
{
  const page = webAppHeaders('index.html', 100);
  assert.strictEqual(page['cache-control'], 'no-cache', 'страница закэширована — человек увидит белый экран после выпуска');
  assert.strictEqual(webAppHeaders('sw.js', 10)['cache-control'], 'no-cache', 'service worker закэширован — обновления встанут навсегда');
  assert.strictEqual(webAppHeaders('static/a.9f8e.js', 10)['cache-control'], 'public, max-age=3600');
  assert.strictEqual(page['x-content-type-options'], 'nosniff', 'без nosniff браузер вправе угадать тип и выполнить как скрипт');
  assert.strictEqual(page['content-length'], '100');
  ok('заголовки: страница и service worker не кэшируются, тип не угадывается');
}
console.log(`\nВЫП-9: ${passed} проверок пройдено`);