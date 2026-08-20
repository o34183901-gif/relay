'use strict';

const assert = require('assert');
const {
  NTFY_PREFIX,
  NTFY_DEFAULT_PORT,
  ntfyEnabled,
  ntfyPort,
  ntfyTarget,
  ntfyBaseUrl,
  ntfyConfigText,
  ntfyProxyHeaders,
} = require('./ntfy');

let passed = 0;
function test(name, fn) {
  fn();
  passed += 1;
  console.log(`  ✓ ${name}`);
}

console.log('УВД-4: встроенный сервер уведомлений');

test('включается переменной образа, а не догадками', () => {
  assert.strictEqual(ntfyEnabled({ RELAY_EMBED_NTFY: '1' }), true);
  assert.strictEqual(ntfyEnabled({ RELAY_EMBED_NTFY: 'yes' }), true);
  assert.strictEqual(ntfyEnabled({ RELAY_EMBED_NTFY: 'true' }), true);
  assert.strictEqual(ntfyEnabled({}), false, 'без переменной процесс поднимать нельзя — в тестах ntfy нет');
  assert.strictEqual(ntfyEnabled({ RELAY_EMBED_NTFY: '' }), false);
  assert.strictEqual(ntfyEnabled({ RELAY_EMBED_NTFY: '0' }), false);
  assert.strictEqual(ntfyEnabled({ RELAY_EMBED_NTFY: 'off' }), false);
  assert.strictEqual(ntfyEnabled({ RELAY_EMBED_NTFY: 'false' }), false);
  assert.strictEqual(ntfyEnabled(null), false);
  assert.strictEqual(ntfyEnabled(42), false);
});

test('порт берётся из окружения только осмысленный', () => {
  assert.strictEqual(ntfyPort({}), NTFY_DEFAULT_PORT);
  assert.strictEqual(ntfyPort({ RELAY_NTFY_PORT: '9999' }), 9999);
  assert.strictEqual(ntfyPort({ RELAY_NTFY_PORT: '0' }), NTFY_DEFAULT_PORT);
  assert.strictEqual(ntfyPort({ RELAY_NTFY_PORT: '70000' }), NTFY_DEFAULT_PORT);
  assert.strictEqual(ntfyPort({ RELAY_NTFY_PORT: 'мусор' }), NTFY_DEFAULT_PORT);
  assert.strictEqual(ntfyPort({ RELAY_NTFY_PORT: '8.5' }), NTFY_DEFAULT_PORT);
  assert.strictEqual(ntfyPort(null), NTFY_DEFAULT_PORT);
});

test('путь /ntfy срезается, а чужие пути не проксируются', () => {
  assert.strictEqual(ntfyTarget('/ntfy'), '/');
  assert.strictEqual(ntfyTarget('/ntfy/'), '/');
  assert.strictEqual(ntfyTarget('/ntfy/upAbC123?up=1'), '/upAbC123?up=1');
  assert.strictEqual(ntfyTarget('/ntfy/upAbC123/ws'), '/upAbC123/ws');
  assert.strictEqual(ntfyTarget('/ntfy?poll=1'), '/?poll=1');
  assert.strictEqual(ntfyTarget('/ntfyx/topic'), null, 'префикс обязан быть отдельным сегментом');
  assert.strictEqual(ntfyTarget('/ntfyx'), null);
  assert.strictEqual(ntfyTarget('/update/file'), null);
  assert.strictEqual(ntfyTarget('/health'), null);
  assert.strictEqual(ntfyTarget('/'), null);
  assert.strictEqual(ntfyTarget('ntfy/topic'), null, 'адрес без ведущей косой — не наш');
  assert.strictEqual(ntfyTarget(''), null);
  assert.strictEqual(ntfyTarget(null), null);
  assert.strictEqual(ntfyTarget(42), null);
  assert.strictEqual(ntfyTarget(`/ntfy/${'a'.repeat(4096)}`), null, 'неправдоподобно длинный адрес');
  assert.strictEqual(ntfyTarget('/ntfy/x\u0000y'), null, 'нулевой байт в адресе');
});

test('адрес сервера уведомлений выводится из адреса релея', () => {
  assert.strictEqual(ntfyBaseUrl('wss://relay.example'), 'https://relay.example');
  assert.strictEqual(ntfyBaseUrl('wss://relay.example:8443'), 'https://relay.example:8443');
  assert.strictEqual(ntfyBaseUrl('https://relay.example'), 'https://relay.example');
  assert.ok(
    !ntfyBaseUrl('wss://relay.example').includes(NTFY_PREFIX),
    'ntfy отказывается стартовать, если base-url содержит путь: sub-path он не поддерживает'
  );
  assert.strictEqual(ntfyBaseUrl('ws://relay.example'), '', 'открытый канал адресом не становится');
  assert.strictEqual(ntfyBaseUrl('мусор'), '');
  assert.strictEqual(ntfyBaseUrl(''), '');
  assert.strictEqual(ntfyBaseUrl(null), '');
});

test('конфиг слушает только петлю и не пересылает уведомления наружу', () => {
  const text = ntfyConfigText({
    baseUrl: 'https://relay.example/ntfy',
    port: 2586,
    cacheFile: '/data/ntfy/cache.db',
  });
  assert.ok(text.includes('listen-http: "127.0.0.1:2586"'), 'сервер уведомлений слушает не только петлю');
  assert.ok(text.includes('base-url: "https://relay.example/ntfy"'));
  assert.ok(text.includes('cache-file: "/data/ntfy/cache.db"'));
  assert.ok(text.includes('behind-proxy: true'), 'без этого ntfy считает всех клиентов одним адресом');
  assert.ok(text.includes('upstream-base-url: ""'), 'пересылка на ntfy.sh обязана быть выключена');
  assert.ok(text.includes('enable-signup: false'));
  assert.ok(text.includes('enable-login: false'));
  assert.ok(text.includes('auth-default-access: "deny-all"'), 'аноним не должен читать и публиковать в топики');
  assert.ok(text.includes('auth-file: "/data/ntfy/auth.db"'), 'без файла учёток политика доступа не применяется');
  assert.ok(
    !text.split('\n').some((line) => /^auth-default-access:\s*"?(read-write|read-only|write-only)"?/.test(line)),
    'умолчание ntfy read-write обязано быть закрыто'
  );
  assert.ok(text.endsWith('\n'));
  const withAuth = ntfyConfigText({ cacheFile: '/data/ntfy/cache.db', authFile: '/etc/ntfy/user.db' });
  assert.ok(withAuth.includes('auth-file: "/etc/ntfy/user.db"'), 'явный файл учёток обязан побеждать вычисленный');
  const bare = ntfyConfigText();
  assert.ok(bare.includes(`listen-http: "127.0.0.1:${NTFY_DEFAULT_PORT}"`));
  assert.ok(bare.includes('auth-default-access: "deny-all"'), 'закрытый доступ обязан быть и без адреса релея');
  assert.ok(
    !bare.split('\n').some((line) => line.startsWith('base-url:')),
    'без адреса релея строка base-url не выдумывается'
  );
  const odd = ntfyConfigText({ port: 70000 });
  assert.ok(odd.includes(`127.0.0.1:${NTFY_DEFAULT_PORT}`), 'негодный порт обязан падать на дефолт');
});

test('заголовки для ntfy: свои хопы срезаются, адрес клиента подставляется явно', () => {
  const headers = ntfyProxyHeaders(
    {
      Host: 'relay.example',
      Connection: 'keep-alive',
      Upgrade: 'websocket',
      'X-Forwarded-For': '10.0.0.1, 203.0.113.9',
      'X-Forwarded-Proto': 'http',
      'X-Forwarded-Host': 'подделка',
      'Transfer-Encoding': 'chunked',
      'Content-Type': 'application/octet-stream',
      Authorization: 'Bearer vapid',
    },
    { host: 'relay.example', clientIp: '203.0.113.9' }
  );
  assert.strictEqual(headers['x-forwarded-for'], '203.0.113.9', 'ntfy обязан видеть клиента, а не чужую цепочку');
  assert.strictEqual(headers['x-forwarded-proto'], 'https');
  assert.strictEqual(headers['x-forwarded-host'], 'relay.example');
  assert.strictEqual(headers['Content-Type'], 'application/octet-stream');
  assert.strictEqual(headers.Authorization, 'Bearer vapid', 'подпись VAPID обязана доехать до подписчика');
  assert.strictEqual(headers.Host, undefined);
  assert.strictEqual(headers.Connection, undefined);
  assert.strictEqual(headers.Upgrade, undefined);
  assert.strictEqual(headers['Transfer-Encoding'], undefined);
  assert.strictEqual(headers['X-Forwarded-For'], undefined, 'чужая цепочка пролезла нетронутой');
  const bare = ntfyProxyHeaders(null, null);
  assert.strictEqual(bare['x-forwarded-proto'], 'https');
  assert.strictEqual(bare['x-forwarded-for'], undefined);
  assert.strictEqual(bare['x-forwarded-host'], undefined);
});

console.log(`встроенный сервер уведомлений: ${passed} проверок пройдено`);
