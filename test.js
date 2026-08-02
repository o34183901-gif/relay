/**
 * Интеграционный тест релея: поднимает сервер и проверяет доставку конвертов,
 * аутентификацию по challenge и надёжную (ack) доставку. Запуск: node server/test.js
 */
const assert = require('assert');
const { spawn } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');
const WebSocket = require('ws');
const crypto = require('./test-crypto');
const linked = require('./linked-devices');
const { packBinaryFrame, unpackBinaryFrame } = require('./binary-frame');

const PORT = 8799;
const URL = `ws://127.0.0.1:${PORT}`;
const TMP = (name) => path.join(os.tmpdir(), `licno-${name}-${process.pid}.json`);
const DB = TMP('db');
const VAPID_FILE = TMP('vapid');
const BLOB_DIR = path.join(os.tmpdir(), `licno-blobs-${process.pid}`);
const BLOB_THRESHOLD = 1024; // маленький порог, чтобы тестовое «вложение» ушло на диск

function wait(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// СРВ-14: ждём РЕАЛЬНОЙ готовности сервера (poll /health), а не фиксированные
// 600 мс. На нагруженной машине сервер мог не успеть подняться за это время →
// первые клиенты не подключались, тест падал в обход srv.kill() и оставлял
// осиротевший процесс (держал порт → следующие запуски падали с EADDRINUSE).
function waitForServer(timeoutMs = 15000) {
  const http = require('http');
  const started = Date.now();
  return new Promise((resolve, reject) => {
    const tryOnce = () => {
      const req = http.get({ host: '127.0.0.1', port: PORT, path: '/health', timeout: 1000 }, (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => {
          body += chunk;
        });
        res.on('end', () => {
          if (res.statusCode !== 200) return retry();
          try {
            resolve(JSON.parse(body));
          } catch (_) {
            retry();
          }
        });
      });
      req.on('error', retry);
      req.on('timeout', () => req.destroy());
    };
    const retry = () => {
      if (Date.now() - started > timeoutMs) return reject(new Error('server did not become ready'));
      setTimeout(tryOnce, 100);
    };
    tryOnce();
  });
}

function waitFor(inbox, type, timeout = 2000) {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const tick = () => {
      const m = inbox.find((x) => x.type === type);
      if (m) return resolve(m);
      if (Date.now() - started > timeout) return reject(new Error('timeout waiting for ' + type));
      setTimeout(tick, 20);
    };
    tick();
  });
}

function waitForAfter(inbox, type, startIndex, timeout = 2000) {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const tick = () => {
      const m = inbox.slice(startIndex).find((x) => x.type === type);
      if (m) return resolve(m);
      if (Date.now() - started > timeout) return reject(new Error('timeout waiting for new ' + type));
      setTimeout(tick, 20);
    };
    tick();
  });
}

function waitForBinaryAfter(inbox, startIndex, timeout = 2000) {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const tick = () => {
      const item = inbox.slice(startIndex)[0];
      if (item) return resolve(item);
      if (Date.now() - started > timeout) return reject(new Error('timeout waiting for binary frame'));
      setTimeout(tick, 20);
    };
    tick();
  });
}

/**
 * Connect and complete the ownership handshake. `autoAck` acks each incoming
 * message (needed for delivery); omit to test queue retention.
 * `signId` overrides which identity signs the challenge (to test rejection).
 */
// boxProof по умолчанию true: реальные клиенты ВСЕГДА доказывают владение
// box-ключом (см. src/relay.js). СРВ-1: квитанции `received` сервер принимает
// только от доказанного владельца, поэтому тестовый клиент должен вести себя как
// боевой. Легаси-путь (без boxProof) проверяется отдельными raw-соединениями ниже.
function client(id, { autoAck = true, signId, boxProof = true } = {}) {
  const ws = new WebSocket(URL);
  const inbox = [];
  const binaryInbox = [];
  const signer = signId || id;
  // СРВ-14: без слушателя 'error' сбой соединения роняет тест необработанным
  // событием; здесь он превращается в reject открывающего промиса (уходит в
  // main try/catch → finally срубает сервер).
  ws.on('error', () => {});
  ws.on('message', (d, isBinary) => {
    if (isBinary) {
      const frame = unpackBinaryFrame(d);
      binaryInbox.push(frame);
      if (autoAck && frame.header.id) {
        ws.send(JSON.stringify({ type: 'binary-received', id: frame.header.id }));
      }
      return;
    }
    const m = JSON.parse(d.toString());
    inbox.push(m);
    if (m.type === 'challenge') {
      const signature = crypto.signChallenge({ nonce: m.nonce, signSecretKey: signer.signSecretKey });
      const frame = { type: 'auth', signature };
      // H5/H6: новый клиент доказывает владение box-ключом адреса (ECDH-proof).
      if (boxProof && m.eph) {
        frame.boxProof = crypto.proveBoxOwnership({ nonce: m.nonce, mySecretKey: id.secretKey, serverEphPublicKey: m.eph });
      }
      ws.send(JSON.stringify(frame));
    }
    if (m.type === 'message' && autoAck) {
      ws.send(JSON.stringify({ type: 'received', id: m.id }));
    }
  });
  return new Promise((resolve, reject) => {
    ws.on('open', () => {
      ws.send(JSON.stringify({ type: 'hello', pubkey: id.publicKey, signPublicKey: id.signPublicKey }));
      resolve({ ws, inbox, binaryInbox, id });
    });
    ws.on('error', (e) => reject(e)); // соединение не открылось — не виснем
  });
}

async function main() {
  const srv = spawn('node', [path.join(__dirname, 'relay.js')], {
    env: {
      ...process.env,
      PORT: String(PORT),
      RELAY_DB: DB,
      RELAY_VAPID_KEY_FILE: VAPID_FILE,
      RELAY_BLOB_DIR: BLOB_DIR,
      RELAY_BLOB_THRESHOLD: String(BLOB_THRESHOLD),
    },
    stdio: 'ignore',
  });
  const health = await waitForServer(); // СРВ-14: ждём готовности (poll /health), а не фикс. паузу
  let passed = 0;
  const ok = (name) => {
    console.log('  ✓ ' + name);
    passed++;
  };

  try {
    assert.strictEqual(health.protocol, 4);
    assert.ok(Array.isArray(health.capabilities));
    assert.ok(health.capabilities.includes('linked-devices-v2'));
    assert.ok(health.capabilities.includes('binary-attachments-v1'));
    assert.ok(health.capabilities.includes('frame-batch-v1'));
    assert.strictEqual(health.maxLinkedDevices, linked.MAX_ACTIVE_DEVICES);
    ok('health reports linked-device protocol capabilities');

    const alice = crypto.generateIdentity();
    const bob = crypto.generateIdentity();

    // --- handshake + online delivery ---
    const a = await client(alice);
    const b = await client(bob);
    await waitFor(a.inbox, 'ready');
    await waitFor(b.inbox, 'ready');
    ok('challenge handshake authenticates both clients');

    const env1 = crypto.encryptMessage({
      plaintext: 'привет через сервер 👋',
      mySecretKey: alice.secretKey,
      myPublicKey: alice.publicKey,
      theirPublicKey: bob.publicKey,
    });
    a.ws.send(JSON.stringify({ type: 'send', to: bob.publicKey, envelope: env1, ref: 'r1' }));

    const delivered = await waitFor(b.inbox, 'message');
    const text1 = crypto.decryptMessage({
      envelope: delivered.envelope,
      mySecretKey: bob.secretKey,
      senderPublicKey: alice.publicKey,
    });
    assert.strictEqual(text1, 'привет через сервер 👋');
    ok('online delivery works and decrypts');

    // --- raw binary attachment chunks (v3) ---
    const binaryStart = b.binaryInbox.length;
    const ackStart = a.inbox.length;
    const rawChunk = crypto.randomBytes ? crypto.randomBytes(96) : require('crypto').randomBytes(96);
    a.ws.send(
      packBinaryFrame(
        {
          type: 'attachment-chunk',
          version: 1,
          to: bob.publicKey,
          transferId: 'binary-online-1',
          index: 0,
          total: 1,
          ref: 'binary-ref-online',
        },
        rawChunk
      )
    );
    const binaryAck = await waitForAfter(a.inbox, 'binary-ack', ackStart);
    const deliveredBinary = await waitForBinaryAfter(b.binaryInbox, binaryStart);
    assert.strictEqual(binaryAck.dropped, false);
    assert.strictEqual(deliveredBinary.header.transferId, 'binary-online-1');
    assert.deepStrictEqual(deliveredBinary.payload, rawChunk);
    await waitForAfter(a.inbox, 'binary-delivered', ackStart);
    ok('v3 raw binary attachment chunk is delivered and acknowledged without base64');

    // sender gets an ack (ref echoed) and a delivered receipt after bob acks
    const ack = await waitFor(a.inbox, 'ack');
    assert.strictEqual(ack.ref, 'r1');
    const dr = await waitFor(a.inbox, 'delivered');
    assert.strictEqual(dr.id, delivered.id);
    ok('sender receives ack + delivered receipt');

    // --- linked devices v2 + mixed legacy recipient -----------------------
    const desktop = crypto.generateIdentity();
    const issuedAt = Date.now();
    const capabilities = ['messages', 'files', 'voice', 'history-sync', 'notifications'];
    const phoneCert = linked.createDeviceCertificate(
      {
        accountPublicKey: alice.publicKey,
        accountSignPublicKey: alice.signPublicKey,
        deviceId: linked.deriveDeviceId(alice.publicKey),
        devicePublicKey: alice.publicKey,
        deviceSignPublicKey: alice.signPublicKey,
        name: 'Телефон Android',
        platform: 'android',
        issuedAt,
        capabilities,
      },
      alice.signSecretKey
    );
    const desktopCert = linked.createDeviceCertificate(
      {
        accountPublicKey: alice.publicKey,
        accountSignPublicKey: alice.signPublicKey,
        deviceId: linked.deriveDeviceId(desktop.publicKey),
        devicePublicKey: desktop.publicKey,
        deviceSignPublicKey: desktop.signPublicKey,
        name: 'Домашний компьютер',
        platform: 'windows',
        issuedAt: issuedAt + 1,
        capabilities,
      },
      alice.signSecretKey
    );
    const rosterV1 = linked.createSignedRoster(
      {
        accountPublicKey: alice.publicKey,
        accountSignPublicKey: alice.signPublicKey,
        version: 1,
        updatedAt: issuedAt + 2,
        devices: [
          { certificate: phoneCert, revokedAt: null },
          { certificate: desktopCert, revokedAt: null },
        ],
      },
      alice.signSecretKey
    );
    a.ws.send(JSON.stringify({ type: 'device-roster-put', roster: rosterV1 }));
    await waitFor(a.inbox, 'device-roster-ok');
    a.ws.send(JSON.stringify({ type: 'device-bind', certificate: phoneCert }));
    await waitFor(a.inbox, 'device-bound');

    const desktopClient = await client(desktop);
    await waitFor(desktopClient.inbox, 'ready');
    desktopClient.ws.send(JSON.stringify({ type: 'device-bind', certificate: desktopCert }));
    const desktopBound = await waitFor(desktopClient.inbox, 'device-bound');
    assert.strictEqual(desktopBound.accountPublicKey, alice.publicKey);
    assert.strictEqual(desktopBound.roster.version, 1);
    ok('signed roster binds root and independent desktop device');

    const bobStart = b.inbox.length;
    const desktopEnvelope = crypto.encryptMessage({
      plaintext: 'сообщение с компьютера',
      mySecretKey: desktop.secretKey,
      myPublicKey: desktop.publicKey,
      theirPublicKey: bob.publicKey,
    });
    desktopClient.ws.send(
      JSON.stringify({ type: 'send', to: bob.publicKey, envelope: desktopEnvelope, ref: 'desktop-r1' })
    );
    const fromDesktop = await waitForAfter(b.inbox, 'message', bobStart);
    assert.strictEqual(fromDesktop.from, desktop.publicKey);
    assert.strictEqual(fromDesktop.fromAccount, alice.publicKey);
    assert.strictEqual(fromDesktop.fromDeviceId, desktopCert.deviceId);
    assert.deepStrictEqual(fromDesktop.deviceCertificate, desktopCert);
    assert.strictEqual(fromDesktop.deviceRoster.version, 1);
    assert.strictEqual(
      crypto.decryptMessage({
        envelope: fromDesktop.envelope,
        mySecretKey: bob.secretKey,
        senderPublicKey: desktop.publicKey,
      }),
      'сообщение с компьютера'
    );
    ok('v2 device metadata reaches an unchanged legacy queue/delivery path');

    const rosterStart = desktopClient.inbox.length;
    desktopClient.ws.send(JSON.stringify({ type: 'device-roster-get' }));
    const rosterFrame = await waitForAfter(desktopClient.inbox, 'device-roster', rosterStart);
    assert.strictEqual(rosterFrame.roster.version, 1);

    const rosterV2 = linked.createSignedRoster(
      {
        accountPublicKey: alice.publicKey,
        accountSignPublicKey: alice.signPublicKey,
        version: 2,
        updatedAt: issuedAt + 3,
        devices: [
          { certificate: phoneCert, revokedAt: null },
          { certificate: desktopCert, revokedAt: issuedAt + 3 },
        ],
      },
      alice.signSecretKey
    );
    const revokeStart = desktopClient.inbox.length;
    const rosterAckStart = a.inbox.length;
    a.ws.send(JSON.stringify({ type: 'device-roster-put', roster: rosterV2 }));
    await waitForAfter(a.inbox, 'device-roster-ok', rosterAckStart);
    await waitForAfter(desktopClient.inbox, 'device-revoked', revokeStart);

    const desktopAgain = await client(desktop);
    await waitFor(desktopAgain.inbox, 'ready');
    desktopAgain.ws.send(JSON.stringify({ type: 'device-bind', certificate: desktopCert }));
    const revokedError = await waitFor(desktopAgain.inbox, 'device-bind-error');
    assert.match(revokedError.error, /revoked/);
    desktopAgain.ws.close();
    ok('signed roster revokes a device and prevents certificate replay');

    // --- offline queue: bob disconnects, alice sends, bob reconnects ---
    b.ws.close();
    await wait(200);
    const env2 = crypto.encryptMessage({
      plaintext: 'сообщение в оффлайне',
      mySecretKey: alice.secretKey,
      myPublicKey: alice.publicKey,
      theirPublicKey: bob.publicKey,
    });
    a.ws.send(JSON.stringify({ type: 'send', to: bob.publicKey, envelope: env2, ref: 'r2' }));
    await wait(200);

    const b2 = await client(bob);
    const queued = await waitFor(b2.inbox, 'message');
    const text2 = crypto.decryptMessage({
      envelope: queued.envelope,
      mySecretKey: bob.secretKey,
      senderPublicKey: alice.publicKey,
    });
    assert.strictEqual(text2, 'сообщение в оффлайне');
    ok('offline queue delivers on reconnect');

    // --- вложения на диск: крупный конверт офлайн-получателю лежит файлом ---
    const b2Closed = new Promise((resolve) => b2.ws.once('close', resolve));
    b2.ws.close();
    await b2Closed;
    await wait(100); // серверный close-handler успевает убрать сокет из online
    const bigText = 'видео '.repeat(40000); // ~ четверть мегабайта, много больше порога
    const envBig = crypto.encryptMessage({
      plaintext: bigText,
      mySecretKey: alice.secretKey,
      myPublicKey: alice.publicKey,
      theirPublicKey: bob.publicKey,
    });
    a.ws.send(JSON.stringify({ type: 'send', to: bob.publicKey, envelope: envBig, ref: 'rb' }));
    await wait(300);
    const blobsWhileQueued = fs.readdirSync(BLOB_DIR).filter((f) => f.endsWith('.json'));
    assert.ok(blobsWhileQueued.length >= 1, 'крупный конверт должен лечь файлом в blob-каталог');

    const b3 = await client(bob);
    const queuedBig = await waitFor(b3.inbox, 'message', 5000);
    assert.strictEqual(
      crypto.decryptMessage({
        envelope: queuedBig.envelope,
        mySecretKey: bob.secretKey,
        senderPublicKey: alice.publicKey,
      }),
      bigText
    );
    await wait(300); // ack ушёл — файл должен исчезнуть
    const blobsAfterAck = fs.readdirSync(BLOB_DIR).filter((f) => f.endsWith('.json'));
    assert.strictEqual(blobsAfterAck.length, 0, 'после квитанции blob-файл удаляется');
    ok('big envelope is stored as a blob file and cleaned up after ack');

    // --- reliable delivery: no ack -> message survives a reconnect ---
    const carol = crypto.generateIdentity();
    const dave = crypto.generateIdentity();
    const c = await client(carol);
    await waitFor(c.inbox, 'ready');
    const dNoAck = await client(dave, { autoAck: false });
    await waitFor(dNoAck.inbox, 'ready');
    const env3 = crypto.encryptMessage({
      plaintext: 'надёжная доставка',
      mySecretKey: carol.secretKey,
      myPublicKey: carol.publicKey,
      theirPublicKey: dave.publicKey,
    });
    c.ws.send(JSON.stringify({ type: 'send', to: dave.publicKey, envelope: env3, ref: 'r3' }));
    await waitFor(dNoAck.inbox, 'message'); // received but NOT acked
    dNoAck.ws.close();
    await wait(200);
    const dAck = await client(dave); // reconnect with auto-ack
    const redelivered = await waitFor(dAck.inbox, 'message');
    assert.strictEqual(
      crypto.decryptMessage({
        envelope: redelivered.envelope,
        mySecretKey: dave.secretKey,
        senderPublicKey: carol.publicKey,
      }),
      'надёжная доставка'
    );
    ok('unacked message is re-delivered after reconnect');

    // --- auth: a stranger signing with the wrong key is rejected ---
    const mallory = crypto.generateIdentity();
    const badWs = new WebSocket(URL);
    const badInbox = [];
    await new Promise((resolve) => {
      badWs.on('message', (d) => {
        const m = JSON.parse(d.toString());
        badInbox.push(m);
        if (m.type === 'challenge') {
          // claim alice's pubkey/spk but sign with mallory's secret -> invalid
          badWs.send(JSON.stringify({ type: 'auth', signature: crypto.signChallenge({ nonce: m.nonce, signSecretKey: mallory.signSecretKey }) }));
        }
      });
      badWs.on('open', () => {
        badWs.send(JSON.stringify({ type: 'hello', pubkey: alice.publicKey, signPublicKey: alice.signPublicKey }));
        resolve();
      });
    });
    const err = await waitFor(badInbox, 'error');
    assert.match(err.error, /signature/);
    assert.ok(!badInbox.find((m) => m.type === 'ready'), 'must not authenticate');
    ok('bad signature is rejected (cannot claim another pubkey)');
    badWs.close();

    // --- X3DH prekeys: выгрузка своих, выдача чужих (по одному) ---
    {
      const kp = crypto.generateIdentity();
      const kc = await client(kp);
      await waitFor(kc.inbox, 'ready');
      const spk = crypto.generateSignedPrekey({ signSecretKey: kp.signSecretKey });
      const opks = crypto.generateOneTimePrekeys(2);
      kc.ws.send(
        JSON.stringify({
          type: 'prekeys-put',
          bundle: {
            spk: { id: spk.id, pub: spk.pub, sig: spk.sig },
            opks: opks.map((k) => ({ id: k.id, pub: k.pub })),
          },
        })
      );
      const okMsg = await waitFor(kc.inbox, 'prekeys-ok');
      assert.strictEqual(okMsg.otps, 2);
      ok('prekeys-put stores a signed bundle');

      // подпись чужим ключом отвергается (релей не даст подсунуть фальшивку)
      const badSpk = crypto.generateSignedPrekey({ signSecretKey: alice.signSecretKey });
      kc.ws.send(
        JSON.stringify({
          type: 'prekeys-put',
          bundle: { spk: { id: badSpk.id, pub: badSpk.pub, sig: badSpk.sig }, opks: [] },
        })
      );
      const errMsg = await waitFor(kc.inbox, 'error');
      assert.match(errMsg.error, /prekey signature/);
      ok('prekeys-put rejects a bundle signed by another identity');

      // другой клиент забирает бандл: SPK + один одноразовый, ровно один раз
      const asker = await client(crypto.generateIdentity());
      await waitFor(asker.inbox, 'ready');
      asker.ws.send(JSON.stringify({ type: 'prekeys-get', pubkey: kp.publicKey }));
      const got1 = await waitFor(asker.inbox, 'prekeys');
      assert.strictEqual(got1.bundle.spk.pub, spk.pub);
      assert.ok(crypto.verifySignedPrekey({ spk: got1.bundle.spk, signPublicKey: kp.signPublicKey }));
      assert.ok(got1.bundle.opk && opks.some((k) => k.id === got1.bundle.opk.id));
      asker.inbox.length = 0;
      asker.ws.send(JSON.stringify({ type: 'prekeys-get', pubkey: kp.publicKey }));
      const got2 = await waitFor(asker.inbox, 'prekeys');
      assert.notStrictEqual(got2.bundle.opk.id, got1.bundle.opk.id, 'OPK не выдаётся дважды');
      asker.inbox.length = 0;
      asker.ws.send(JSON.stringify({ type: 'prekeys-get', pubkey: kp.publicKey }));
      const got3 = await waitFor(asker.inbox, 'prekeys');
      assert.strictEqual(got3.bundle.opk, null, 'запас OPK исчерпан — SPK остаётся');
      ok('prekeys-get hands out one-time prekeys exactly once');

      // у незнакомца prekey нет — bundle null (отправитель откатится на статику)
      asker.inbox.length = 0;
      asker.ws.send(JSON.stringify({ type: 'prekeys-get', pubkey: 'nobody' }));
      const none = await waitFor(asker.inbox, 'prekeys');
      assert.strictEqual(none.bundle, null);
      ok('prekeys-get for an unknown user returns null bundle');

      // ready сообщает остаток наших OPK на релее (клиент решает, когда пополнять)
      kc.ws.close();
      await wait(150);
      const kc2 = await client(kp);
      const ready2 = await waitFor(kc2.inbox, 'ready');
      assert.strictEqual(ready2.prekeys, 0, 'остаток OPK в ready (всё роздано)');
      ok('ready reports the remaining one-time prekey count');
      kc2.ws.close();
      asker.ws.close();
    }

    // --- heartbeat: клиентский app-level ping получает pong ---
    const pinger = await client(crypto.generateIdentity());
    pinger.ws.send(JSON.stringify({ type: 'ping' }));
    await waitFor(pinger.inbox, 'pong');
    ok('app-level ping is answered with pong (client heartbeat relies on it)');
    pinger.ws.close();

    // --- /metrics: Prometheus-формат с живыми значениями ---
    {
      const resp = await fetch(`http://127.0.0.1:${PORT}/metrics`);
      assert.strictEqual(resp.status, 200);
      assert.match(resp.headers.get('content-type'), /text\/plain/);
      const body = await resp.text();
      for (const name of [
        'licno_up 1',
        'licno_uptime_seconds',
        'licno_connections{state="open"}',
        'licno_connections{state="authed"}',
        'licno_queue_messages',
        'licno_queue_bytes',
        'licno_messages_in_total',
        'licno_messages_acked_total',
        'licno_auth_success_total',
        'process_resident_memory_bytes',
      ]) {
        assert.ok(body.includes(name), `metric ${name} present`);
      }
      const num = (n) => Number((body.match(new RegExp(`^${n} (\\d+)`, 'm')) || [])[1]);
      assert.ok(num('licno_messages_in_total') >= 3, 'входящие сообщения посчитаны');
      assert.ok(num('licno_messages_acked_total') >= 2, 'квитанции посчитаны');
      assert.ok(num('licno_auth_success_total') >= 4, 'аутентификации посчитаны');
      ok('/metrics exposes Prometheus counters and gauges');
    }

    // --- H5/H6: доказательство владения box-ключом (proven-привязка) ---
    {
      const owner = crypto.generateIdentity();
      // владелец аутентифицируется с доказательством владения box-ключом -> proven
      const o1 = await client(owner, { boxProof: true });
      await waitFor(o1.inbox, 'ready');
      ok('box-ownership proof authenticates (proven binding)');
      o1.ws.close();
      await wait(150);

      // сквоттер знает ПУБЛИЧНЫЙ pubkey владельца, но не его box-секретку: пытается
      // занять адрес своим sign-ключом легаси-путём (без boxProof) — отвергается.
      const squatter = crypto.generateIdentity();
      const sq = new WebSocket(URL);
      const sqInbox = [];
      await new Promise((resolve) => {
        sq.on('message', (d) => {
          const m = JSON.parse(d.toString());
          sqInbox.push(m);
          if (m.type === 'challenge') {
            sq.send(
              JSON.stringify({
                type: 'auth',
                signature: crypto.signChallenge({ nonce: m.nonce, signSecretKey: squatter.signSecretKey }),
              })
            );
          }
        });
        sq.on('open', () => {
          sq.send(JSON.stringify({ type: 'hello', pubkey: owner.publicKey, signPublicKey: squatter.signPublicKey }));
          resolve();
        });
      });
      const sqErr = await waitFor(sqInbox, 'error');
      assert.match(sqErr.error, /proof required|different key/);
      assert.ok(!sqInbox.find((m) => m.type === 'ready'), 'squatter must not take a proven address');
      ok('proven address cannot be squatted without the box secret (H5/H6)');
      sq.close();
      await wait(100);

      // M-6: валидная подпись СВОИМ sign-ключом, но ПОДДЕЛЬНЫЙ boxProof (мусор) —
      // доказательство владения не проходит проверку, proven-адрес не отдаётся.
      const forger = crypto.generateIdentity();
      const fg = new WebSocket(URL);
      const fgInbox = [];
      await new Promise((resolve) => {
        fg.on('message', (d) => {
          const m = JSON.parse(d.toString());
          fgInbox.push(m);
          if (m.type === 'challenge') {
            fg.send(
              JSON.stringify({
                type: 'auth',
                signature: crypto.signChallenge({ nonce: m.nonce, signSecretKey: forger.signSecretKey }),
                boxProof: Buffer.alloc(32).toString('base64'), // подделка: не сойдётся с ECDH
              })
            );
          }
        });
        fg.on('open', () => {
          fg.send(JSON.stringify({ type: 'hello', pubkey: owner.publicKey, signPublicKey: forger.signPublicKey }));
          resolve();
        });
      });
      const fgErr = await waitFor(fgInbox, 'error');
      assert.match(fgErr.error, /proof required|different key|bad/);
      assert.ok(!fgInbox.find((m) => m.type === 'ready'), 'forged box proof must be rejected');
      ok('forged box-ownership proof is rejected on a proven address (M-6)');
      fg.close();

      // владелец возвращается с доказательством — по-прежнему пускает
      const o2 = await client(owner, { boxProof: true });
      await waitFor(o2.inbox, 'ready');
      ok('owner reconnects to its proven address with box proof');
      o2.ws.close();
    }

    // --- СРВ-1: недоказанный держатель адреса НЕ вычёрпывает очередь ---
    {
      const victim = crypto.generateIdentity();
      const sender = crypto.generateIdentity();
      const s = await client(sender);
      await waitFor(s.inbox, 'ready');
      // конверт уходит в очередь (victim офлайн)
      const envV = crypto.encryptMessage({
        plaintext: 'секрет жертве',
        mySecretKey: sender.secretKey,
        myPublicKey: sender.publicKey,
        theirPublicKey: victim.publicKey,
      });
      s.ws.send(JSON.stringify({ type: 'send', to: victim.publicKey, envelope: envV, ref: 'rv' }));
      await waitFor(s.inbox, 'ack');

      // недоказанный держатель (boxProof:false) занимает ещё не занятый адрес,
      // получает конверт онлайн и автоматически шлёт `received` — квитанция должна
      // быть ПРОИГНОРИРОВАНА (иначе он вычерпал бы очередь и жертва не получила бы своё).
      const unproven = await client(victim, { boxProof: false });
      await waitFor(unproven.inbox, 'message'); // онлайн-доставка (шифртекст)
      await wait(200); // autoAck отправил received (должен игнорироваться)
      unproven.ws.close();
      await wait(150);

      // настоящий владелец приходит с доказательством — конверт ВСЁ ЕЩЁ в очереди.
      const real = await client(victim, { boxProof: true });
      const redeliv = await waitFor(real.inbox, 'message');
      const text = crypto.decryptMessage({
        envelope: redeliv.envelope,
        mySecretKey: victim.secretKey,
        senderPublicKey: sender.publicKey,
      });
      assert.strictEqual(text, 'секрет жертве', 'конверт не вычерпан недоказанной квитанцией');
      ok('СРВ-1: недоказанная квитанция `received` не удаляет конверт из очереди');
      real.ws.close();
      s.ws.close();
      await wait(100);
    }

    // --- relay directory: WS query + advertise ---
    const dirClient = await client(crypto.generateIdentity());
    await waitFor(dirClient.inbox, 'ready'); // advertise теперь требует auth (M-1)
    dirClient.ws.send(JSON.stringify({ type: 'relays' }));
    const dirMsg = await waitFor(dirClient.inbox, 'relays');
    assert.ok(Array.isArray(dirMsg.relays), 'server returns a relay directory');
    ok('relay directory is queryable over WS');

    dirClient.ws.send(JSON.stringify({ type: 'relay-advertise', url: 'wss://peer-relay.example.com' }));
    await wait(120);
    dirClient.ws.send(JSON.stringify({ type: 'relays' }));
    await wait(120);
    const dir2 = dirClient.inbox.filter((m) => m.type === 'relays').pop();
    assert.ok(dir2.relays.includes('wss://peer-relay.example.com'), 'advertised relay is learned');
    ok('advertised relay is added to the directory');

    // garbage advertise is rejected by validation
    dirClient.ws.send(JSON.stringify({ type: 'relay-advertise', url: 'http://not-a-ws.example' }));
    await wait(120);
    dirClient.ws.send(JSON.stringify({ type: 'relays' }));
    await wait(120);
    const dir3 = dirClient.inbox.filter((m) => m.type === 'relays').pop();
    assert.ok(!dir3.relays.some((u) => u.includes('not-a-ws')), 'invalid relay url is rejected');
    ok('invalid relay url is rejected by the directory');
    dirClient.ws.close();

    // --- S6: релей подписывает cnonce своим ключом (подлинность релея) ---
    {
      const rawInbox = [];
      const raw = new WebSocket(URL);
      await new Promise((resolve) => raw.on('open', resolve));
      raw.on('message', (d) => rawInbox.push(JSON.parse(d.toString())));
      const idr = crypto.generateIdentity();
      const cnonce = 'test-cnonce-' + Date.now();
      raw.send(JSON.stringify({ type: 'hello', pubkey: idr.publicKey, signPublicKey: idr.signPublicKey, cnonce }));
      const ch = await waitFor(rawInbox, 'challenge');
      assert.ok(ch.relayPub && ch.relaySig, 'challenge содержит подпись релея');
      assert.ok(
        crypto.verifyRelayAuth({ cnonce, relaySig: ch.relaySig, relayPublicKey: ch.relayPub }),
        'подпись релея валидна по его публичному ключу'
      );
      assert.ok(
        !crypto.verifyRelayAuth({ cnonce: 'other', relaySig: ch.relaySig, relayPublicKey: ch.relayPub }),
        'подпись не проходит для другого cnonce (анти-replay)'
      );
      ok('relay signs the client cnonce with its pinned key (S6)');
      raw.close();
    }

    a.ws.close();
    b3.ws.close();
    c.ws.close();
    dAck.ws.close();
    console.log(`\nrelay: ${passed} passed`);
  } finally {
    srv.kill();
    for (const f of [DB, DB + '-wal', DB + '-shm', VAPID_FILE]) try { fs.unlinkSync(f); } catch (e) {}
    try { fs.rmSync(BLOB_DIR, { recursive: true, force: true }); } catch (e) {}
  }
}

// --- unit tests for the pure directory logic (no server needed) ------------
function unitTests() {
  const dir = require('./relays');
  let n = 0;
  const u = (name, cond) => {
    assert.ok(cond, name);
    console.log('  ✓ ' + name);
    n++;
  };
  console.log('relay directory (pure)');
  u('valid wss accepted', dir.isValidRelayUrl('wss://a.example.com'));
  u('valid ws+port accepted', dir.isValidRelayUrl('ws://1.2.3.4:8787'));
  u('http rejected', !dir.isValidRelayUrl('http://a.com'));
  u('whitespace host rejected', !dir.isValidRelayUrl('wss://a b.com'));
  u('empty rejected', !dir.isValidRelayUrl(''));
  u('trailing slash normalized', dir.normalizeRelayUrl('wss://a.com//') === 'wss://a.com');
  const merged = dir.mergeRelays(['wss://a.com'], ['wss://A.com/', 'wss://b.com', 'junk']);
  u('merge dedups case-insensitively', merged.length === 2);
  u('merge keeps valid only', merged.includes('wss://a.com') && merged.includes('wss://b.com'));

  // C-3: SSRF-фильтр приватных адресов. Регрессия — обход через IPv6-формы.
  const priv = [
    '127.0.0.1',
    '169.254.169.254',
    '10.0.0.5',
    '192.168.1.1',
    '2130706433', // 127.0.0.1 одним числом
    '[::1]',
    '[::ffff:127.0.0.1]',
    '[::ffff:169.254.169.254]', // метаданные облака через IPv4-mapped
    '[0:0:0:0:0:0:0:1]', // развёрнутый loopback
    '[fc00::1]',
    '[fe80::1]',
  ];
  for (const h of priv) u(`isPrivateHost blocks ${h}`, dir.isPrivateHost(h) === true);
  const pub = ['example.com', '1.2.3.4', '93.184.216.34', '[2606:4700::1111]', '[::ffff:8.8.8.8]'];
  for (const h of pub) u(`isPrivateHost allows ${h}`, dir.isPrivateHost(h) === false);

  // те же обходы должны отвергаться на уровне URL-валидации каталога
  u('reject ws IPv4-mapped loopback URL', !dir.isValidRelayUrl('ws://[::ffff:127.0.0.1]:8787'));
  u('reject ws cloud-metadata via mapped IPv6', !dir.isValidRelayUrl('ws://[::ffff:169.254.169.254]'));
  u('reject ws expanded IPv6 loopback', !dir.isValidRelayUrl('ws://[0:0:0:0:0:0:0:1]:8787'));
  u('allow public IPv6 relay', dir.isValidRelayUrl('wss://[2606:4700::1111]'));

  // H-2/M-4: конфиг coturn генерируется релеем; секрет внутри, а не в CLI/env.
  const cfg = dir.coturnConfigText('SEKRET123', { turnHost: '203.0.113.7' });
  u('coturn: секрет попадает в конфиг', cfg.includes('static-auth-secret=SEKRET123'));
  u('coturn: use-auth-secret включён', cfg.includes('use-auth-secret'));
  u('coturn: external-ip проставлен', cfg.includes('external-ip=203.0.113.7'));
  u('coturn: НЕ содержит "-n" (конфиг из файла, не CLI)', !/(^|\n)-n(\n|$)/.test(cfg));
  u('coturn: закрыты метаданные облака (M-4)', cfg.includes('denied-peer-ip=169.254.0.0-169.254.255.255'));
  u('coturn: закрыт RFC1918 10/8', cfg.includes('denied-peer-ip=10.0.0.0-10.255.255.255'));
  u('coturn: закрыт loopback ::1', cfg.includes('denied-peer-ip=::1'));
  const cfgNoHost = dir.coturnConfigText('S', {});
  u('coturn: без host нет external-ip', !cfgNoHost.includes('external-ip='));
  // ДПЛ-5 (non-root): coturn не пишет в root-only /var/run и /var/log.
  u('coturn: лог в stdout (не /var/log)', cfg.includes('log-file=stdout'));
  const cfgPid = dir.coturnConfigText('S', { pidfile: '/data/turnserver.pid', userdb: '/data/turndb' });
  u('coturn: pidfile в writable-путь (не /var/run)', cfgPid.includes('pidfile=/data/turnserver.pid'));
  u('coturn: userdb в writable-путь (не /var/lib/turn)', cfgPid.includes('userdb=/data/turndb'));
  u('coturn: без опций строк pidfile/userdb нет', !cfgNoHost.includes('pidfile=') && !cfgNoHost.includes('userdb='));

  // H-4: rateGate — скользящее окно для троттлинга выдачи OTP по адресу.
  let st = null;
  const W = 1000, MAX = 3;
  // симулируем выдачу: инкремент только при allow (как в prekeys-get)
  let given = 0;
  for (let i = 0; i < 10; i++) {
    const g = dir.rateGate(st, 100, W, MAX); // одно и то же «now» — одно окно
    st = g.state;
    if (g.allow) { given += 1; st.count += 1; }
  }
  u('rateGate: в окне выдаётся не больше max', given === MAX);
  // окно истекло -> счётчик сбрасывается, снова можно
  const g2 = dir.rateGate(st, 100 + W + 1, W, MAX);
  u('rateGate: после окна снова allow', g2.allow === true && g2.state.count === 0);
  console.log(`\ndirectory-unit: ${n} passed`);
}

unitTests();
main().catch((e) => {
  console.error(e);
  process.exit(1);
});
