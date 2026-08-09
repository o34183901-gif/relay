/**
 * Защита Docker-образа от рассинхронизации с графом runtime-зависимостей.
 *
 * relayModules.js вычисляет полный список файлов, нужных relay.js. Dockerfile
 * обязан копировать каждый из них: иначе локальные тесты проходят, а контейнер
 * завершается с MODULE_NOT_FOUND ещё до готовности /health.
 */

'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { relayFileList } = require('./relayModules');

function dockerCopySources(source) {
  const logicalLines = String(source).replace(/\\\r?\n\s*/g, ' ');
  const copied = new Set();
  for (const line of logicalLines.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!/^COPY\s+/i.test(trimmed)) continue;
    const args = trimmed.split(/\s+/).slice(1).filter((arg) => !arg.startsWith('--'));
    // Последний аргумент COPY — каталог назначения, все предыдущие — источники.
    args.pop();
    for (const file of args) copied.add(file);
  }
  return copied;
}

const dockerfile = fs.readFileSync(path.join(__dirname, 'Dockerfile'), 'utf8');
const copied = dockerCopySources(dockerfile);
const runtime = relayFileList(__dirname);
const missing = runtime.filter((file) => !copied.has(file));

assert.deepStrictEqual(
  missing,
  [],
  `Dockerfile не копирует runtime-файлы: ${missing.join(', ')}`,
);

console.log(`Dockerfile копирует все ${runtime.length} runtime-файла релея`);

module.exports = { dockerCopySources };
