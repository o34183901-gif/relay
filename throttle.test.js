/**
 * throttle.test.js — БЕЗ-5: байтовый потолок на соединение, живой стенд.
 *
 * Чистая логика окна проверена юнит-тестами в test.js (byteGate). Здесь
 * проверяется то, что юнит-тестом не проверить: релей реально притормаживает
 * чтение сокета и — главное — реально его ВОЗОБНОВЛЯЕТ. Ошибка в resume()
 * оставила бы соединение висеть навсегда, то есть была бы хуже той проблемы,
 * ради которой всё затевалось.
 *
 * Ключевое утверждение теста: превышение потолка НИЧЕГО НЕ ТЕРЯЕТ. Отказ или
 * разрыв на превышении означал бы потерянный чанк вложения у легитимного
 * пользователя с быстрым каналом, поэтому реакция — только задержка.
 *
 * Стенд отдельный от test.js: там релей поднимается один на весь прогон, и
 * низкий потолок исказил бы остальные проверки.
 *
 * Запуск: node server/throttle.test.js
 */
const assert = require('assert');
const { spawn } = require('child_process');
const http = require('http');
const path = require('path');
const os = require('os');
const fs = require('fs');
const WebSocket = require('ws');
const crypto = require('./test-crypto');

const TMP = (name, port) => path.join(os.tmpdir(), `licno-thr-${name}-${port}-${process.pid}.json`);

// Потолок нарочно крошечный, чтобы тест упирался в него за доли секунды и не
// зависел от скорости машины.
const MAX_BYTES_PER_SEC = 64 * 1024;
const ENVELOPE_BYTES = 16 * 1024;
const ENVELOPES = 12; // ~192 КБ, то есть заведомо больше потолка за окно

/** Поднимает отдельный релей: два стенда отличаются только порогом абуза. */
function startRelay(port, abuseWindows) {
  const db = TMP('db', port);
  const vapid = TMP('vapid', port);
  const blobs = path.join(os.tmpdir(), `licno-thr-blobs-${port}-${process.pid}`);
  const srv = spawn('node', [path.join(__dirname, 'relay.js')], {
    env: {
      ...process.env,
      PORT: String(port),
      RELAY_DB: db,
      RELAY_VAPID_KEY_FILE: vapid,
      RELAY_BLOB_DIR: blobs,
      RELAY_MAX_BYTES_PER_SEC: String(MAX_BYTES_PER_SEC),
      RELAY_ABUSE_WINDOWS: String(abuseWindows),
    },
    stdio: 'ignore',
  });
  return {
    srv,
    url: `ws://127.0.0.1:${port}`,
    port,
    cleanup() {
      srv.kill();
      for (const file of [db, `${db}-wal`, `${db}-shm`, vapid]) {
        try {
          fs.unlinkSync(file);
        } catch (e) {}
      }
      try {
        fs.rmSync(blobs, { recursive: true, force: true });
      } catch (e) {}
    },
  };
}

function waitForServer(port, timeoutMs = 15000) {
  const started = Date.now();
  return new Promise((resolve, reject) => {
    const retry = () => {
      if (Date.now() - started > timeoutMs) return reject(new Error('сервер не поднялся'));
      setTimeout(tryOnce, 100);
    };
    const tryOnce = () => {
      const req = http.get({ host: '127.0.0.1', port, path: '/health', timeout: 1000 }, (res) => {
        res.resume();
        res.on('end', () => (res.statusCode === 200 ? resolve() : retry()));
      });
      req.on('error', retry);
      req.on('timeout', () => req.destroy());
    };
    tryOnce();
  });
}

function metrics(port) {
  return new Promise((resolve, reject) => {
    const req = http.get({ host: '127.0.0.1', port, path: '/metrics', timeout: 2000 }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => (body += chunk));
      res.on('end', () => resolve(body));
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy());
  });
}

function metricValue(text, name) {
  const match = new RegExp(`^${name} (\\d+)$`, 'm').exec(text);
  return match ? Number(match[1]) : null;
}

function client(URL, id, { autoAck = true } = {}) {
  const ws = new WebSocket(URL);
  const inbox = [];
  let closed = null;
  ws.on('error', () => {});
  ws.on('close', (code) => (closed = code));
  ws.on('message', (data) => {
    const m = JSON.parse(data.toString());
    inbox.push(m);
    if (m.type === 'challenge') {
      const frame = {
        type: 'auth',
        signature: crypto.signChallenge({ nonce: m.nonce, signSecretKey: id.signSecretKey }),
      };
      if (m.eph) {
        frame.boxProof = crypto.proveBoxOwnership({
          nonce: m.nonce,
          mySecretKey: id.secretKey,
          serverEphPublicKey: m.eph,
        });
      }
      ws.send(JSON.stringify(frame));
    }
    if (m.type === 'message' && autoAck) ws.send(JSON.stringify({ type: 'received', id: m.id }));
  });
  return new Promise((resolve, reject) => {
    ws.on('open', () => {
      ws.send(JSON.stringify({ type: 'hello', pubkey: id.publicKey, signPublicKey: id.signPublicKey }));
      resolve({ ws, inbox, id, isClosed: () => closed });
    });
    ws.on('error', reject);
  });
}

function waitFor(inbox, type, timeout = 5000) {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const tick = () => {
      const m = inbox.find((x) => x.type === type);
      if (m) return resolve(m);
      if (Date.now() - started > timeout) return reject(new Error('нет ' + type));
      setTimeout(tick, 20);
    };
    tick();
  });
}

function waitUntil(predicate, timeout, what) {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const tick = () => {
      if (predicate()) return resolve();
      if (Date.now() - started > timeout) return reject(new Error('не дождались: ' + what));
      setTimeout(tick, 25);
    };
    tick();
  });
}

let passed = 0;
const ok = (name) => {
  console.log('  ✓ ' + name);
  passed++;
};

/**
 * Стенд 1: порог абуза недостижимо высок. Проверяем, что обычное превышение —
 * это ТОЛЬКО задержка: ничего не потеряно, ничего не переставлено, связь жива.
 */
async function testThrottleKeepsEverything() {
  // Абузом считаем только очень долгое превышение: этот стенд обязан
  // притормаживаться, но НЕ быть разорванным.
  const relay = startRelay(8801, 1000);
  await waitForServer(relay.port);
  const URL = relay.url;

  try {
    const alice = crypto.generateIdentity();
    const bob = crypto.generateIdentity();
    const a = await client(URL, alice);
    const b = await client(URL, bob);
    await waitFor(a.inbox, 'ready');
    await waitFor(b.inbox, 'ready');

    const before = metricValue(await metrics(relay.port), 'licno_throttled_total');
    assert.strictEqual(typeof before, 'number', '/metrics отдаёт licno_throttled_total');
    ok('метрика licno_throttled_total публикуется');

    // Заливаем поток заведомо выше потолка одним махом.
    const body = 'x'.repeat(ENVELOPE_BYTES);
    const started = Date.now();
    for (let i = 0; i < ENVELOPES; i++) {
      a.ws.send(JSON.stringify({ type: 'send', to: bob.publicKey, envelope: `${i}|${body}` }));
    }

    // Главное свойство: дошли ВСЕ конверты. Ни один не отклонён и не потерян.
    await waitUntil(
      () => b.inbox.filter((m) => m.type === 'message').length >= ENVELOPES,
      20000,
      'доставка всех конвертов'
    );
    const elapsed = Date.now() - started;
    const got = b.inbox.filter((m) => m.type === 'message');
    assert.strictEqual(got.length, ENVELOPES);
    ok(`превышение потолка ничего не теряет (${ENVELOPES}/${ENVELOPES} конвертов)`);

    // И в правильном порядке — притормаживание не перемешивает поток.
    const order = got.map((m) => Number(String(m.envelope).split('|')[0]));
    assert.deepStrictEqual(order, Array.from({ length: ENVELOPES }, (_, i) => i));
    ok('порядок конвертов сохранён');

    // Соединение живо: притормаживание — это задержка, а не разрыв.
    assert.strictEqual(a.isClosed(), null, 'соединение отправителя не разорвано');
    assert.strictEqual(a.ws.readyState, WebSocket.OPEN);
    ok('соединение не разорвано (притормаживание ≠ разрыв)');

    // Релей действительно тормозил, а не пропустил всё мимо лимита.
    const after = metricValue(await metrics(relay.port), 'licno_throttled_total');
    assert.ok(after > before, `счётчик притормаживаний вырос (${before} -> ${after})`);
    ok(`чтение придерживалось: licno_throttled_total ${before} -> ${after}`);

    // Раз всё дошло, а тормозили — значит resume() отработал. Проверяем это ещё
    // и явно: сокет обязан принимать новые кадры ПОСЛЕ снятия паузы.
    const mark = b.inbox.length;
    a.ws.send(JSON.stringify({ type: 'send', to: bob.publicKey, envelope: 'после-паузы' }));
    await waitUntil(
      () => b.inbox.slice(mark).some((m) => m.type === 'message' && m.envelope === 'после-паузы'),
      10000,
      'кадр после снятия паузы'
    );
    ok('после паузы чтение возобновляется (сокет не завис)');

    // Задержка обязана быть, иначе потолок не работал бы: ~192 КБ при 64 КБ/с.
    assert.ok(elapsed >= 1000, `поток растянут во времени (${elapsed} мс)`);
    ok(`поток растянут потолком: ${elapsed} мс на ${ENVELOPES} × ${ENVELOPE_BYTES / 1024} КБ`);

    const text = await metrics(relay.port);
    assert.ok(/^licno_abusive_closed_total \d+$/m.test(text));
    ok('метрика licno_abusive_closed_total публикуется');
  } finally {
    relay.cleanup();
  }
}

/**
 * Стенд 2: порог абуза = 1, то есть первое же превышение считается абузом.
 * Проверяем, что защита от DoS вообще срабатывает — иначе всё вышеописанное
 * означало бы лишь бесконечное вежливое притормаживание флудера.
 */
async function testSustainedAbuseIsClosed() {
  const relay = startRelay(8802, 1);
  await waitForServer(relay.port);

  try {
    const alice = crypto.generateIdentity();
    const bob = crypto.generateIdentity();
    const a = await client(relay.url, alice);
    await waitFor(a.inbox, 'ready');

    const body = 'x'.repeat(ENVELOPE_BYTES);
    for (let i = 0; i < ENVELOPES; i++) {
      a.ws.send(JSON.stringify({ type: 'send', to: bob.publicKey, envelope: `${i}|${body}` }));
    }

    await waitUntil(() => a.isClosed() !== null, 15000, 'разрыв за абуз');
    ok('длительное превышение рвёт соединение (защита от DoS работает)');

    const closed = metricValue(await metrics(relay.port), 'licno_abusive_closed_total');
    assert.ok(closed >= 1, `разрывы за абуз посчитаны (${closed})`);
    ok(`разрыв учтён метрикой: licno_abusive_closed_total = ${closed}`);

    // Наказан флудер, а не адрес: переподключиться сразу можно.
    const again = await client(relay.url, alice);
    await waitFor(again.inbox, 'ready');
    ok('после разрыва клиент подключается снова (бана адреса нет)');
    again.ws.close();
  } finally {
    relay.cleanup();
  }
}

async function main() {
  await testThrottleKeepsEverything();
  await testSustainedAbuseIsClosed();
  console.log(`\nthrottle: ${passed} passed`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
