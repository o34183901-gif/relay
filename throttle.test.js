const assert = require('assert');
const { spawn } = require('child_process');
const http = require('http');
const path = require('path');
const os = require('os');
const fs = require('fs');
const net = require('net');
const WebSocket = require('ws');
const crypto = require('./test-crypto');
const TMP = (name, port) => path.join(os.tmpdir(), `licno-thr-${name}-${port}-${process.pid}.json`);
const MAX_BYTES_PER_SEC = 64 * 1024;
const ENVELOPE_BYTES = 16 * 1024;
const ENVELOPES = 12;
function freePort() {
  return new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.on('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });
}

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
  let exited = null;
  srv.on('exit', (code, signal) => {
    exited = signal ? `сигнал ${signal}` : `код ${code}`;
  });
  const relay = {
    srv,
    url: `ws://127.0.0.1:${port}`,
    port,
    exitReason: () => exited,
    cleanup() {
      process.off('exit', relay.cleanup);
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
  process.on('exit', relay.cleanup);
  return relay;
}

function waitForServer(relay, timeoutMs = 15000) {
  const port = relay.port;
  const started = Date.now();
  return new Promise((resolve, reject) => {
    const retry = () => {
      const gone = relay.exitReason();
      if (gone) return reject(new Error(`релей не запустился (${gone}) — порт ${port} занят?`));
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
async function testThrottleKeepsEverything() {
  const relay = startRelay(await freePort(), 1000);
  await waitForServer(relay);
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
    assert.strictEqual(before, 0, 'на порту отвечает свежий релей этого стенда, а не чей-то чужой');
    ok('метрика licno_throttled_total публикуется');
    const body = 'x'.repeat(ENVELOPE_BYTES);
    const started = Date.now();
    for (let i = 0; i < ENVELOPES; i++) {
      a.ws.send(JSON.stringify({ type: 'send', to: bob.publicKey, envelope: `${i}|${body}` }));
    }
    await waitUntil(
      () => b.inbox.filter((m) => m.type === 'message').length >= ENVELOPES,
      20000,
      'доставка всех конвертов'
    );
    const elapsed = Date.now() - started;
    const got = b.inbox.filter((m) => m.type === 'message');
    assert.strictEqual(got.length, ENVELOPES);
    ok(`превышение потолка ничего не теряет (${ENVELOPES}/${ENVELOPES} конвертов)`);
    const order = got.map((m) => Number(String(m.envelope).split('|')[0]));
    assert.deepStrictEqual(order, Array.from({ length: ENVELOPES }, (_, i) => i));
    ok('порядок конвертов сохранён');
    assert.strictEqual(a.isClosed(), null, 'соединение отправителя не разорвано');
    assert.strictEqual(a.ws.readyState, WebSocket.OPEN);
    ok('соединение не разорвано (притормаживание ≠ разрыв)');
    const after = metricValue(await metrics(relay.port), 'licno_throttled_total');
    assert.ok(after > before, `счётчик притормаживаний вырос (${before} -> ${after})`);
    ok(`чтение придерживалось: licno_throttled_total ${before} -> ${after}`);
    const mark = b.inbox.length;
    a.ws.send(JSON.stringify({ type: 'send', to: bob.publicKey, envelope: 'после-паузы' }));
    await waitUntil(
      () => b.inbox.slice(mark).some((m) => m.type === 'message' && m.envelope === 'после-паузы'),
      10000,
      'кадр после снятия паузы'
    );
    ok('после паузы чтение возобновляется (сокет не завис)');
    ok(`поток растянут потолком: ${elapsed} мс на ${ENVELOPES} × ${ENVELOPE_BYTES / 1024} КБ`);
    const text = await metrics(relay.port);
    assert.ok(/^licno_abusive_closed_total \d+$/m.test(text));
    ok('метрика licno_abusive_closed_total публикуется');
  } finally {
    relay.cleanup();
  }
}
async function testSustainedAbuseIsClosed() {
  const relay = startRelay(await freePort(), 1);
  await waitForServer(relay);
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