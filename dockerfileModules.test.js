'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { relayFileList } = require('./relayModules');

const COPIED_SEPARATELY = ['package.json', 'package-lock.json'];

function dockerfilePath() {
  const candidates = [
    path.join(__dirname, 'Dockerfile'),
    path.join(__dirname, 'relay-infra', 'Dockerfile'),
  ];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return candidate;
  }
  assert.fail(`Dockerfile релея не найден ни как ${candidates.join(', ни как ')}`);
  return '';
}

function copiedIntoImage(source) {
  const joined = source.replace(/\\\s*\n\s*/g, ' ');
  const files = new Set();
  for (const raw of joined.split('\n')) {
    const line = raw.trim();
    const match = /^COPY\s+(.+?)\s+\.\/\s*$/.exec(line);
    if (!match) continue;
    for (const name of match[1].split(/\s+/)) files.add(name);
  }
  return files;
}

let passed = 0;
const ok = (name) => {
  console.log('  ✓ ' + name);
  passed += 1;
};

console.log('\nОбраз релея: в него попадает ровно то, что нужно релею\n');

const file = dockerfilePath();
const source = fs.readFileSync(file, 'utf8');
const copied = copiedIntoImage(source);
const runtime = relayFileList(__dirname).filter(
  (name) => !name.endsWith('.test.js') && !COPIED_SEPARATELY.includes(name)
);

assert.ok(runtime.length > 10, 'список модулей релея подозрительно короткий — сверять нечего');
ok(`список модулей релея получен: ${runtime.length} файлов`);

const forgotten = runtime.filter((name) => !copied.has(name));
assert.deepStrictEqual(
  forgotten,
  [],
  'модуль нужен релею, но в образ не копируется — контейнер упадёт при первом обращении: ' +
    forgotten.join(', ')
);
ok('каждый нужный релею модуль копируется в образ');

const extra = [...copied].filter(
  (name) => !runtime.includes(name) && !COPIED_SEPARATELY.includes(name)
);
assert.deepStrictEqual(
  extra,
  [],
  'в образ копируется файл, которого нет в списке синхронизации — сборка сломается, когда он исчезнет: ' +
    extra.join(', ')
);
ok('лишнего в образ не копируется');

for (const name of COPIED_SEPARATELY) {
  assert.ok(
    copied.has(name),
    `${name} обязан копироваться до npm ci, иначе слой зависимостей пересобирается на каждую правку кода`
  );
}
ok('манифест зависимостей копируется отдельным слоем до установки');

const npmCiAt = source.indexOf('npm ci');
const manifestAt = source.indexOf('COPY package.json');
assert.ok(manifestAt >= 0 && npmCiAt > manifestAt, 'npm ci идёт раньше копирования манифеста');
ok('порядок слоёв сохранён: сначала манифест, потом установка, потом код');

console.log(`\nОбраз релея: ${passed} проверок пройдено`);
