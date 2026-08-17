'use strict';
const fs = require('fs');
const path = require('path');

const EXTRA_RUNTIME = ['package.json', 'vapid-fleet.json'];
function localRequires(source) {
  const out = new Set();
  const pattern = /require\('\.\/([a-zA-Z0-9_.-]+)'\)/g;
  for (const line of String(source).split('\n')) {
    const trimmed = line.trim();
    if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) continue;
    let match;
    while ((match = pattern.exec(line))) out.add(match[1]);
  }
  return [...out];
}

function resolveDependency(dep, exists) {
  for (const candidate of [dep, `${dep}.js`, `${dep}.json`]) {
    if (exists(candidate)) return candidate;
  }
  return null;
}

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