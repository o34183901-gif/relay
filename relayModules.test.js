'use strict';
const assert = require('assert');
const path = require('path');
const {
  EXTRA_RUNTIME,
  localRequires,
  resolveDependency,
  moduleClosure,
  relayFileList,
} = require('./relayModules');
let passed = 0;
function test(name, fn) {
  fn();
  passed += 1;
  console.log('  ✓ ' + name);
}
console.log('список файлов релея (ВЫС-16)');

test('локальные require вычитываются, чужие и закомментированные — нет', () => {
  const req = (name) => "require('" + './' + name + "')";
  const source = [
    'const a = ' + req('store') + ';',
    "const b = require('better-sqlite3');",
    '// поминание в комментарии: ' + req('ghost'),
    ' * и в звёздочном тоже: ' + req('ghost-2'),
    'const c = ' + req('relays') + '; const d = ' + req('push') + ';',
  ].join('\n');
  assert.deepStrictEqual(localRequires(source).sort(), ['push', 'relays', 'store']);
});

test('зависимость разрешается в файл: .js, .json или как есть', () => {
  const exists = (name) => ['store.js', 'fleet.json', 'сырое-имя'].includes(name);
  assert.strictEqual(resolveDependency('store', exists), 'store.js');
  assert.strictEqual(resolveDependency('fleet.json', exists), 'fleet.json');
  assert.strictEqual(resolveDependency('сырое-имя', exists), 'сырое-имя');
  assert.strictEqual(resolveDependency('нет-такого', exists), null);
});

test('замыкание идёт вглубь: зависимость зависимости тоже в списке', () => {
  const req = (name) => "require('" + './' + name + "')";
  const files = {
    'relay.js': req('store'),
    'store.js': req('queueAdmission'),
    'queueAdmission.js': '',
  };
  const io = { readFile: (n) => files[n], exists: (n) => n in files };
  assert.deepStrictEqual(moduleClosure(['relay.js'], io), [
    'queueAdmission.js',
    'relay.js',
    'store.js',
  ]);
});
test('недостижимая зависимость — ошибка с именем виновника, а не молчание', () => {
  const req = (name) => "require('" + './' + name + "')";
  const io = { readFile: () => req('lost-module'), exists: (n) => n === 'relay.js' };
  assert.throws(() => moduleClosure(['relay.js'], io), /relay\.js требует \.\/lost-module/);
});
test('цикл require не зацикливает замыкание', () => {
  const req = (name) => "require('" + './' + name + "')";
  const files = { 'a.js': req('b'), 'b.js': req('a') };
  const io = { readFile: (n) => files[n], exists: (n) => n in files };
  assert.deepStrictEqual(moduleClosure(['a.js'], io), ['a.js', 'b.js']);
});
test('главный анкер: недостававшие модули достижимы из настоящего relay.js', () => {
  const list = relayFileList(path.join(__dirname));
  for (const must of ['mbx.js', 'mailboxGcs.js', 'envelopeFrame.js', 'queueAdmission.js']) {
    assert.ok(list.includes(must), `${must} обязан быть в списке — relay.js без него не стартует`);
  }
  assert.ok(list.includes('relay.js'));
  for (const extra of ['package.json', 'vapid-fleet.json']) {
    assert.ok(list.includes(extra), `${extra} — ручное дополнение, но обязан быть в списке`);
  }
  assert.deepStrictEqual([...EXTRA_RUNTIME].sort(), ['package.json', 'vapid-fleet.json']);
  assert.ok(!list.some((name) => name.endsWith('.test.js')), 'тесты в запуск не входят');
});
test('со «--with-tests» приходят наборы и их помощники', () => {
  const list = relayFileList(path.join(__dirname), { withTests: true });
  for (const must of ['store.test.js', 'test.js', 'test-crypto.js', 'queueAdmission.test.js']) {
    assert.ok(list.includes(must), `${must} нужен прогону тестов в репозитории релея`);
  }
});
console.log(`\nсписок файлов релея: ${passed} проверок пройдено`);