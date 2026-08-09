/**
 * relayModules.js — какие файлы образуют релей (ВЫС-16). Список СЧИТАЕТСЯ, а не
 * ведётся руками.
 *
 * ЧТО БЫЛО НЕ ТАК
 *
 * Список модулей релея жил в двух местах ручными перечислениями: RELAY_MODULES
 * в install.sh и cp-строка в sync-relay.yml. Оба отставали при каждом новом
 * модуле: install.sh не знал про mbx.js, mailboxGcs.js и envelopeFrame.js,
 * которые relay.js требует с момента их появления. Страж в установщике это
 * ловил — установка падала честно, с внятным сообщением, — но документированный
 * путь «на голое железо» не работал вовсе. Ровно та же судьба ждала каждый
 * следующий модуль: queueAdmission.js (ВЫС-15) в списках уже отсутствовал.
 *
 * ЧТО ЗДЕСЬ
 *
 * Замыкание локальных require, посчитанное от relay.js. Файл появился в графе —
 * он в списке; не появился — значит, он релею и не нужен. Руками остаются
 * только файлы, которых require не видит: package.json и конфиг флота — они
 * перечислены здесь ОДИН раз, а не в каждом потребителе списка.
 *
 * Скрипт двуликий: как модуль отдаёт чистые функции (тест —
 * server/relayModules.test.js), как CLI печатает список для install.sh и
 * sync-relay.yml:
 *
 *   node relayModules.js <каталог>              — файлы, нужные для ЗАПУСКА
 *   node relayModules.js <каталог> --with-tests — плюс тесты и их зависимости
 */

'use strict';

const fs = require('fs');
const path = require('path');

/** Файлы, которых require не видит. Единственное ручное место. */
const EXTRA_RUNTIME = ['package.json', 'vapid-fleet.json'];

/** Локальные require('./…') из исходника. Только простая форма — как в коде релея. */
function localRequires(source) {
  const out = new Set();
  const pattern = /require\('\.\/([a-zA-Z0-9_.-]+)'\)/g;
  for (const line of String(source).split('\n')) {
    const trimmed = line.trim();
    // Комментарии не тянут зависимостей: упоминание модуля — не требование.
    if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) continue;
    let match;
    while ((match = pattern.exec(line))) out.add(match[1]);
  }
  return [...out];
}

/** Имя зависимости -> имя файла: './store' может значить store.js или store.json. */
function resolveDependency(dep, exists) {
  for (const candidate of [dep, `${dep}.js`, `${dep}.json`]) {
    if (exists(candidate)) return candidate;
  }
  return null;
}

/**
 * Замыкание: файл-вход плюс всё, что достижимо по локальным require.
 *
 * `readFile(name)` — источник текста; `exists(name)` — есть ли файл. Обе
 * приходят снаружи, чтобы правило проверялось без диска. Недостижимая
 * зависимость — ошибка с именем того, кто её требует: молча пропущенный модуль
 * и был исходной поломкой.
 */
function moduleClosure(entries, { readFile, exists }) {
  const files = [];
  const seen = new Set();
  const queue = [...entries];
  while (queue.length) {
    const name = queue.shift();
    if (seen.has(name)) continue;
    seen.add(name);
    if (!exists(name)) throw new Error(`нет файла ${name}`);
    files.push(name);
    if (!name.endsWith('.js')) continue;
    for (const dep of localRequires(readFile(name))) {
      const resolved = resolveDependency(dep, exists);
      if (!resolved) throw new Error(`${name} требует ./${dep}, а такого файла нет рядом`);
      if (!seen.has(resolved)) queue.push(resolved);
    }
  }
  return files.sort();
}

/** Список файлов релея для каталога dir. withTests — плюс тесты и их зависимости. */
function relayFileList(dir, { withTests = false } = {}) {
  const io = {
    readFile: (name) => fs.readFileSync(path.join(dir, name), 'utf8'),
    exists: (name) => fs.existsSync(path.join(dir, name)),
  };
  const entries = ['relay.js', ...EXTRA_RUNTIME];
  if (withTests) {
    for (const file of fs.readdirSync(dir)) {
      if (file.endsWith('.test.js')) entries.push(file);
    }
    // Главный набор релея старше соглашения об именах: он test.js, не *.test.js.
    if (io.exists('test.js')) entries.push('test.js');
    if (io.exists('package-lock.json')) entries.push('package-lock.json');
  }
  return moduleClosure(entries, io);
}

module.exports = {
  EXTRA_RUNTIME,
  localRequires,
  resolveDependency,
  moduleClosure,
  relayFileList,
};

if (require.main === module) {
  const args = process.argv.slice(2);
  const withTests = args.includes('--with-tests');
  const dir = args.find((value) => !value.startsWith('--'));
  if (!dir) {
    process.stderr.write('использование: node relayModules.js <каталог> [--with-tests]\n');
    process.exit(2);
  }
  try {
    process.stdout.write(relayFileList(dir, { withTests }).join('\n') + '\n');
  } catch (error) {
    process.stderr.write(`ОШИБКА: ${error.message}\n`);
    process.exit(1);
  }
}
