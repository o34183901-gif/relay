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
const BLOB_THRESHOLD = 1024;
const nacl = require('tweetnacl');
const naclUtil = require('tweetnacl-util');
const reportsRule = require('./reports');
const reportsOwner = nacl.sign.keyPair();
const REPORTS_OWNER_PUB = naclUtil.encodeBase64(reportsOwner.publicKey);
const REPORTS_OWNER_SEC = naclUtil.encodeBase64(reportsOwner.secretKey);
const signReports = (domain, ts) =>
  reportsRule.signOwnerRequest({ domain, ts, secretKey: REPORTS_OWNER_SEC });
function wait(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

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
async function metricValue(name) {
  const resp = await fetch(`http://127.0.0.1:${PORT}/metrics`);
  const body = await resp.text();
  return Number((body.match(new RegExp(`^${name} (\\d+)`, 'm')) || [])[1] || 0);
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
function waitForRef(inbox, type, ref, timeout = 2000) {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const tick = () => {
      const m = inbox.find((x) => x.type === type && x.ref === ref);
      if (m) return resolve(m);
      if (Date.now() - started > timeout) return reject(new Error(`нет ${type} с ref=${ref}`));
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
function client(id, { autoAck = true, signId, boxProof = true, capabilities = null } = {}) {
  const ws = new WebSocket(URL);
  const inbox = [];
  const binaryInbox = [];
  const signer = signId || id;
  ws.on('error', () => {});
  ws.on('message', (d, isBinary) => {
    if (isBinary) {
      const frame = unpackBinaryFrame(d);
      binaryInbox.push(frame);
      if (autoAck && frame.header.id) {
        const type = frame.header.type === 'message-v1' ? 'received' : 'binary-received';
        ws.send(JSON.stringify({ type, id: frame.header.id }));
      }
      return;
    }
    const m = JSON.parse(d.toString());
    inbox.push(m);
    if (m.type === 'challenge') {
      const signature = crypto.signChallenge({ nonce: m.nonce, signSecretKey: signer.signSecretKey });
      const frame = { type: 'auth', signature };
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
      const hello = { type: 'hello', pubkey: id.publicKey, signPublicKey: id.signPublicKey };
      if (capabilities) hello.capabilities = capabilities;
      ws.send(JSON.stringify(hello));
      resolve({ ws, inbox, binaryInbox, id });
    });
    ws.on('error', (e) => reject(e));
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
      RELAY_REPORTS_KEY: REPORTS_OWNER_PUB,
    },
    stdio: 'ignore',
  });
  const health = await waitForServer();
  let passed = 0;
  const ok = (name) => {
    console.log('  ✓ ' + name);
    passed++;
  };
  try {
    assert.strictEqual(health.protocol, 6);
    assert.ok(Array.isArray(health.capabilities));
    assert.ok(health.capabilities.includes('linked-devices-v2'));
    assert.ok(health.capabilities.includes('binary-attachments-v1'));
    assert.ok(health.capabilities.includes('frame-batch-v1'));
    assert.ok(health.capabilities.includes('binary-envelope-v1'));
    assert.ok(health.capabilities.includes('cover-traffic-v1'));
    assert.strictEqual(health.maxLinkedDevices, linked.MAX_ACTIVE_DEVICES);
    ok('health reports linked-device protocol capabilities');
    const alice = crypto.generateIdentity();
    const bob = crypto.generateIdentity();
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
    const ack = await waitFor(a.inbox, 'ack');
    assert.strictEqual(ack.ref, 'r1');
    const dr = await waitFor(a.inbox, 'delivered');
    assert.strictEqual(dr.id, delivered.id);
    ok('sender receives ack + delivered receipt');
    const ghost = crypto.generateIdentity();
    const probeEnv = crypto.encryptMessage({
      plaintext: 'зонд присутствия',
      mySecretKey: alice.secretKey,
      myPublicKey: alice.publicKey,
      theirPublicKey: bob.publicKey,
    });
    const probe = (ref, to) =>
      a.ws.send(JSON.stringify({ type: 'send', to, envelope: probeEnv, ref, silent: true }));
    probe('probe-online', bob.publicKey);
    probe('probe-offline', ghost.publicKey);
    const ackOnline = await waitForRef(a.inbox, 'ack', 'probe-online');
    const ackOffline = await waitForRef(a.inbox, 'ack', 'probe-offline');
    assert.strictEqual(ackOnline.queued, true, 'queued — константа, а не состояние получателя');
    assert.strictEqual(ackOnline.dropped, false, 'принятый конверт не помечается отказом');
    assert.deepStrictEqual(
      { ...ackOnline, ref: null, id: null },
      { ...ackOffline, ref: null, id: null },
      'ack онлайн-получателю обязан быть неотличим от ack офлайн-получателю'
    );
    ok('СРВ-11: ack не различает онлайн и офлайн получателя (оракула присутствия нет)');
    const probeChunk = require('crypto').randomBytes(64);
    const binaryProbe = (ref, to) =>
      a.ws.send(
        packBinaryFrame(
          { type: 'attachment-chunk', version: 1, to, transferId: 'presence-probe-1', index: 0, total: 1, ref },
          probeChunk
        )
      );
    binaryProbe('bprobe-online', bob.publicKey);
    binaryProbe('bprobe-offline', ghost.publicKey);
    const binOnline = await waitForRef(a.inbox, 'binary-ack', 'bprobe-online');
    const binOffline = await waitForRef(a.inbox, 'binary-ack', 'bprobe-offline');
    assert.strictEqual(binOnline.queued, true, 'binary-ack: queued — та же константа, что и в ack');
    assert.deepStrictEqual(
      { ...binOnline, ref: null, id: null },
      { ...binOffline, ref: null, id: null },
      'binary-ack онлайн-получателю обязан быть неотличим от офлайн'
    );
    ok('СРВ-11: binary-ack тоже не различает онлайн и офлайн (зонд не переезжает на вложения)');
    {
      const sealedOf = (bytes) => ({ v: 1, sealed: Buffer.from(bytes).toString('base64') });
      const blob = require('crypto').randomBytes(320);
      const outer = sealedOf(blob);
      const arrivedAs = async (peer, jsonStart, binaryStart, timeout = 3000) => {
        const started = Date.now();
        while (Date.now() - started < timeout) {
          if (peer.binaryInbox.length > binaryStart) return 'двоично';
          if (peer.inbox.slice(jsonStart).some((m) => m.type === 'message')) return 'JSON';
          await wait(20);
        }
        return 'не дошло';
      };
      const jsonStart = b.inbox.length;
      const bBinaryStart = b.binaryInbox.length;
      const ackStart2 = a.inbox.length;
      a.ws.send(
        packBinaryFrame(
          { type: 'send-v1', version: 1, to: bob.publicKey, sv: 1, ref: 'bin-r1' },
          blob
        )
      );
      assert.strictEqual(
        await arrivedAs(b, jsonStart, bBinaryStart),
        'JSON',
        'клиент, не объявивший возможность, обязан продолжать получать конверты JSON-ом'
      );
      const gotJson = await waitForAfter(b.inbox, 'message', jsonStart);
      assert.deepStrictEqual(gotJson.envelope, outer, 'конверт обязан доехать байт в байт');
      const binAck = await waitForRef(a.inbox, 'ack', 'bin-r1');
      assert.strictEqual(binAck.dropped, false);
      await waitForAfter(a.inbox, 'delivered', ackStart2);
      ok('ПРФ-14: конверт, отправленный двоичным кадром, доходит до клиента прежней версии как JSON');
      a.ws.send(JSON.stringify({ type: 'send', to: bob.publicKey, envelope: outer, ref: 'json-r1' }));
      const jsonAck = await waitForRef(a.inbox, 'ack', 'json-r1');
      assert.deepStrictEqual(
        { ...binAck, ref: null, id: null },
        { ...jsonAck, ref: null, id: null },
        'квитанция двоичного пути обязана быть неотличима от квитанции JSON-пути'
      );
      ok('ПРФ-14: квитанции двоичного и JSON-пути неразличимы');
      const carol = crypto.generateIdentity();
      const c = await client(carol, { capabilities: ['binary-envelope-v1'] });
      await waitFor(c.inbox, 'ready');
      const cBinaryStart = c.binaryInbox.length;
      const cJsonStart = c.inbox.length;
      const ackStart3 = a.inbox.length;
      a.ws.send(JSON.stringify({ type: 'send', to: carol.publicKey, envelope: outer, ref: 'to-carol' }));
      const gotBinary = await waitForBinaryAfter(c.binaryInbox, cBinaryStart);
      assert.strictEqual(gotBinary.header.type, 'message-v1');
      assert.strictEqual(gotBinary.header.sv, 1);
      assert.ok(typeof gotBinary.header.id === 'string' && gotBinary.header.id);
      assert.ok(Buffer.from(gotBinary.payload).equals(blob), 'тело обязано быть сырыми байтами конверта');
      assert.strictEqual(
        c.inbox.slice(cJsonStart).filter((m) => m.type === 'message').length,
        0,
        'тот же конверт не должен приехать ещё и JSON-ом'
      );
      await waitForAfter(a.inbox, 'delivered', ackStart3);
      ok('ПРФ-14: получатель, объявивший возможность, получает конверт двоичным кадром без base64');
      const plainEnvelope = {
        v: 1,
        dr: 1,
        from: alice.publicKey,
        header: { dh: 'ZWZlbWVybnlqLWtsanVjaA==', pn: 3, n: 11 },
        nonce: 'bm9uY2UtMjQtYmFqdGEtcm92bm8h',
        cipher: 'c2hpZnJvdGVrc3Q=',
      };
      const beforePlain = c.binaryInbox.length;
      const beforePlainJson = c.inbox.length;
      a.ws.send(
        JSON.stringify({ type: 'send', to: carol.publicKey, envelope: plainEnvelope, ref: 'plain-1' })
      );
      assert.strictEqual(
        await arrivedAs(c, beforePlainJson, beforePlain),
        'JSON',
        'незапечатанный конверт не имеет права уехать двоичным кадром'
      );
      const plainDelivered = await waitForAfter(c.inbox, 'message', beforePlainJson);
      assert.deepStrictEqual(plainDelivered.envelope, plainEnvelope);
      ok('ПРФ-14: незапечатанный конверт остаётся в JSON — его поля не выходят в открытый заголовок');
      const dave = crypto.generateIdentity();
      const queuedBlob = require('crypto').randomBytes(200);
      a.ws.send(
        packBinaryFrame(
          { type: 'send-v1', version: 1, to: dave.publicKey, sv: 1, ref: 'queued-1', silent: true },
          queuedBlob
        )
      );
      await waitForRef(a.inbox, 'ack', 'queued-1');
      const d = await client(dave, { capabilities: ['binary-envelope-v1'] });
      await waitFor(d.inbox, 'ready');
      const fromQueue = await waitForBinaryAfter(d.binaryInbox, 0);
      assert.strictEqual(fromQueue.header.type, 'message-v1');
      assert.ok(Buffer.from(fromQueue.payload).equals(queuedBlob), 'из очереди обязан прийти тот же конверт');
      const readyFrame = d.inbox.find((m) => m.type === 'ready');
      assert.ok(readyFrame.queued >= 1, 'релей обязан сообщить о непустой очереди');
      ok('ПРФ-14: конверт из ОЧЕРЕДИ выдаётся двоичным кадром и не теряется');
      const errStart = a.inbox.length;
      a.ws.send(packBinaryFrame({ type: 'send-v1', version: 1, to: bob.publicKey, sv: 7 }, blob));
      const badVersion = await waitForAfter(a.inbox, 'error', errStart);
      assert.ok(/envelope frame/.test(badVersion.error));
      const errStart2 = a.inbox.length;
      a.ws.send(packBinaryFrame({ type: 'send-v1', version: 1, to: '', sv: 1 }, blob));
      await waitForAfter(a.inbox, 'error', errStart2);
      a.ws.send(
        packBinaryFrame({ type: 'send-v1', version: 1, to: bob.publicKey, sv: 1, ref: 'after-err' }, blob)
      );
      await waitForRef(a.inbox, 'ack', 'after-err');
      ok('ПРФ-14: негодный двоичный кадр конверта отвергается, соединение переживает это');
      const coverStart = a.inbox.length;
      a.ws.send(
        packBinaryFrame(
          { type: 'cover-v1', version: 1, p: 'a'.repeat(51) },
          require('crypto').randomBytes(48 + 2048)
        )
      );
      a.ws.send(
        packBinaryFrame(
          { type: 'send-v1', version: 1, to: bob.publicKey, sv: 1, ref: 'after-cover' },
          blob
        )
      );
      await waitForRef(a.inbox, 'ack', 'after-cover');
      const afterCover = a.inbox.slice(coverStart);
      assert.ok(
        !afterCover.some((m) => m.type === 'error' || m.type === 'binary-error'),
        'СРЕД-03: на пустышку узел не отвечает ничем — ответ размечал бы её'
      );
      assert.strictEqual(
        afterCover.filter((m) => m.type === 'ack' || m.type === 'binary-ack').length,
        1,
        'СРЕД-03: пустышка не встаёт в очередь и не считается сообщением'
      );
      ok('СРЕД-03: пустышка принята, молча выброшена и сообщением не стала');
      c.ws.close();
      d.ws.close();
    }
    const second = crypto.generateIdentity();
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
    const secondCert = linked.createDeviceCertificate(
      {
        accountPublicKey: alice.publicKey,
        accountSignPublicKey: alice.signPublicKey,
        deviceId: linked.deriveDeviceId(second.publicKey),
        devicePublicKey: second.publicKey,
        deviceSignPublicKey: second.signPublicKey,
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
          { certificate: secondCert, revokedAt: null },
        ],
      },
      alice.signSecretKey
    );
    a.ws.send(JSON.stringify({ type: 'device-roster-put', roster: rosterV1 }));
    await waitFor(a.inbox, 'device-roster-ok');
    a.ws.send(JSON.stringify({ type: 'device-bind', certificate: phoneCert }));
    await waitFor(a.inbox, 'device-bound');
    const secondClient = await client(second);
    await waitFor(secondClient.inbox, 'ready');
    secondClient.ws.send(JSON.stringify({ type: 'device-bind', certificate: secondCert }));
    const secondBound = await waitFor(secondClient.inbox, 'device-bound');
    assert.strictEqual(secondBound.accountPublicKey, alice.publicKey);
    assert.strictEqual(secondBound.roster.version, 1);
    ok('signed roster binds root and independent second device');
    const bobStart = b.inbox.length;
    const secondEnvelope = crypto.encryptMessage({
      plaintext: 'сообщение с компьютера',
      mySecretKey: second.secretKey,
      myPublicKey: second.publicKey,
      theirPublicKey: bob.publicKey,
    });
    secondClient.ws.send(
      JSON.stringify({ type: 'send', to: bob.publicKey, envelope: secondEnvelope, ref: 'second-r1' })
    );
    const fromSecond = await waitForAfter(b.inbox, 'message', bobStart);
    assert.strictEqual(fromSecond.from, second.publicKey);
    assert.strictEqual(fromSecond.fromAccount, alice.publicKey);
    assert.strictEqual(fromSecond.fromDeviceId, secondCert.deviceId);
    assert.deepStrictEqual(fromSecond.deviceCertificate, secondCert);
    assert.strictEqual(fromSecond.deviceRoster.version, 1);
    assert.strictEqual(
      crypto.decryptMessage({
        envelope: fromSecond.envelope,
        mySecretKey: bob.secretKey,
        senderPublicKey: second.publicKey,
      }),
      'сообщение с компьютера'
    );
    ok('v2 device metadata reaches an unchanged legacy queue/delivery path');
    const noMetaStart = b.inbox.length;
    secondClient.ws.send(
      JSON.stringify({
        type: 'send',
        to: bob.publicKey,
        envelope: secondEnvelope,
        ref: 'second-r2',
        noMeta: true,
      })
    );
    const hidden = await waitForAfter(b.inbox, 'message', noMetaStart);
    assert.strictEqual(hidden.fromAccount, undefined, 'адрес аккаунта отправителя наружу не выходит');
    assert.strictEqual(hidden.fromDeviceId, undefined);
    assert.strictEqual(hidden.deviceCertificate, undefined);
    assert.strictEqual(hidden.deviceRoster, undefined, 'и весь список его устройств — тоже');
    assert.strictEqual(hidden.from, second.publicKey, 'адрес устройства остаётся: без него кадр некому доставить');
    assert.ok(hidden.envelope, 'сам конверт при этом доезжает как обычно');
    ok('ВЫС-41: по просьбе отправителя релей не подставляет его метаданные наружу');
    const rosterStart = secondClient.inbox.length;
    secondClient.ws.send(JSON.stringify({ type: 'device-roster-get' }));
    const rosterFrame = await waitForAfter(secondClient.inbox, 'device-roster', rosterStart);
    assert.strictEqual(rosterFrame.roster.version, 1);
    const rosterV2 = linked.createSignedRoster(
      {
        accountPublicKey: alice.publicKey,
        accountSignPublicKey: alice.signPublicKey,
        version: 2,
        updatedAt: issuedAt + 3,
        devices: [
          { certificate: phoneCert, revokedAt: null },
          { certificate: secondCert, revokedAt: issuedAt + 3 },
        ],
      },
      alice.signSecretKey
    );
    const revokeStart = secondClient.inbox.length;
    const rosterAckStart = a.inbox.length;
    a.ws.send(JSON.stringify({ type: 'device-roster-put', roster: rosterV2 }));
    await waitForAfter(a.inbox, 'device-roster-ok', rosterAckStart);
    await waitForAfter(secondClient.inbox, 'device-revoked', revokeStart);
    const secondAgain = await client(second);
    await waitFor(secondAgain.inbox, 'ready');
    secondAgain.ws.send(JSON.stringify({ type: 'device-bind', certificate: secondCert }));
    const revokedError = await waitFor(secondAgain.inbox, 'device-bind-error');
    assert.match(revokedError.error, /revoked/);
    secondAgain.ws.close();
    ok('signed roster revokes a device and prevents certificate replay');
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
    const b2Closed = new Promise((resolve) => b2.ws.once('close', resolve));
    b2.ws.close();
    await b2Closed;
    await wait(100);
    const bigText = 'видео '.repeat(40000);
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
    await wait(300);
    const blobsAfterAck = fs.readdirSync(BLOB_DIR).filter((f) => f.endsWith('.json'));
    assert.strictEqual(blobsAfterAck.length, 0, 'после квитанции blob-файл удаляется');
    ok('big envelope is stored as a blob file and cleaned up after ack');
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
    await waitFor(dNoAck.inbox, 'message');
    dNoAck.ws.close();
    await wait(200);
    const dAck = await client(dave);
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
    const mallory = crypto.generateIdentity();
    const badWs = new WebSocket(URL);
    const badInbox = [];
    await new Promise((resolve) => {
      badWs.on('message', (d) => {
        const m = JSON.parse(d.toString());
        badInbox.push(m);
        if (m.type === 'challenge') {
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
      asker.inbox.length = 0;
      asker.ws.send(JSON.stringify({ type: 'prekeys-get', pubkey: 'nobody' }));
      const none = await waitFor(asker.inbox, 'prekeys');
      assert.strictEqual(none.bundle, null);
      ok('prekeys-get for an unknown user returns null bundle');
      kc.ws.close();
      await wait(150);
      const kc2 = await client(kp);
      const ready2 = await waitFor(kc2.inbox, 'ready');
      assert.strictEqual(ready2.prekeys, 0, 'остаток OPK в ready (всё роздано)');
      ok('ready reports the remaining one-time prekey count');
      kc2.ws.close();
      asker.ws.close();
    }
    const pinger = await client(crypto.generateIdentity());
    pinger.ws.send(JSON.stringify({ type: 'ping' }));
    await waitFor(pinger.inbox, 'pong');
    ok('app-level ping is answered with pong (client heartbeat relies on it)');
    pinger.ws.close();
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
    {
      const owner = crypto.generateIdentity();
      const o1 = await client(owner, { boxProof: true });
      await waitFor(o1.inbox, 'ready');
      ok('box-ownership proof authenticates (proven binding)');
      o1.ws.close();
      await wait(150);
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
                boxProof: Buffer.alloc(32).toString('base64'),
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
      const o2 = await client(owner, { boxProof: true });
      await waitFor(o2.inbox, 'ready');
      ok('owner reconnects to its proven address with box proof');
      o2.ws.close();
    }
    {
      const victim = crypto.generateIdentity();
      const sender = crypto.generateIdentity();
      const s = await client(sender);
      await waitFor(s.inbox, 'ready');
      const envV = crypto.encryptMessage({
        plaintext: 'секрет жертве',
        mySecretKey: sender.secretKey,
        myPublicKey: sender.publicKey,
        theirPublicKey: victim.publicKey,
      });
      s.ws.send(JSON.stringify({ type: 'send', to: victim.publicKey, envelope: envV, ref: 'rv' }));
      await waitFor(s.inbox, 'ack');
      const unproven = await client(victim, { boxProof: false });
      const readyUnproven = await waitFor(unproven.inbox, 'ready');
      assert.strictEqual(
        readyUnproven.receiveBlocked,
        'box-proof-required',
        'релей обязан сказать, почему входящих не будет, а не молчать'
      );
      assert.strictEqual(readyUnproven.queued, 0, 'очередь недоказанному сеансу не выгружается');
      await wait(250);
      assert.strictEqual(
        unproven.inbox.filter((m) => m.type === 'message').length,
        0,
        'ни один конверт не уходит тому, кто не доказал владение адресом'
      );
      unproven.ws.send(JSON.stringify({ type: 'register', pushToken: 'ТОКЕН-ЗАХВАТЧИКА' }));
      const regErr = await waitFor(unproven.inbox, 'error');
      assert.strictEqual(regErr.error, 'box ownership proof required', 'push-токен не перебивается без доказательства');
      unproven.ws.close();
      await wait(150);
      const real = await client(victim, { boxProof: true });
      const redeliv = await waitFor(real.inbox, 'message');
      const text = crypto.decryptMessage({
        envelope: redeliv.envelope,
        mySecretKey: victim.secretKey,
        senderPublicKey: sender.publicKey,
      });
      assert.strictEqual(text, 'секрет жертве', 'конверт не вычерпан недоказанной квитанцией');
      ok('АУД-Э1: незакреплённый адрес нельзя занять — ни приём, ни очередь, ни push, ни prekey');
      real.ws.close();
      s.ws.close();
      await wait(100);
    }
    const dirClient = await client(crypto.generateIdentity());
    await waitFor(dirClient.inbox, 'ready');
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
    dirClient.ws.send(JSON.stringify({ type: 'relay-advertise', url: 'http://not-a-ws.example' }));
    await wait(120);
    dirClient.ws.send(JSON.stringify({ type: 'relays' }));
    await wait(120);
    const dir3 = dirClient.inbox.filter((m) => m.type === 'relays').pop();
    assert.ok(!dir3.relays.some((u) => u.includes('not-a-ws')), 'invalid relay url is rejected');
    ok('invalid relay url is rejected by the directory');
    dirClient.ws.close();
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
    {
      const crit = await client(crypto.generateIdentity());
      await waitFor(crit.inbox, 'ready');
      const victim = crypto.generateIdentity();
      const victimCert = linked.createDeviceCertificate(
        {
          accountPublicKey: victim.publicKey,
          accountSignPublicKey: victim.signPublicKey,
          deviceId: linked.deriveDeviceId(victim.publicKey),
          devicePublicKey: victim.publicKey,
          deviceSignPublicKey: victim.signPublicKey,
          name: 'Телефон',
          platform: 'android',
          issuedAt: Date.now(),
          capabilities: ['messages', 'files', 'voice', 'history-sync', 'notifications'],
        },
        victim.signSecretKey
      );
      const victimRoster = linked.createSignedRoster(
        {
          accountPublicKey: victim.publicKey,
          accountSignPublicKey: victim.signPublicKey,
          version: 1,
          updatedAt: Date.now(),
          devices: [{ certificate: victimCert, revokedAt: null }],
        },
        victim.signSecretKey
      );
      const earlyBefore = await metricValue('licno_roster_denied_early_total');
      const before = crit.inbox.length;
      crit.ws.send(JSON.stringify({ type: 'device-roster-put', roster: victimRoster }));
      const denied = await waitForAfter(crit.inbox, 'device-roster-error', before);
      assert.strictEqual(denied.error, 'invalid-roster', 'посторонний получает отказ и ничего не узнаёт');
      assert.strictEqual(
        await metricValue('licno_roster_denied_early_total'),
        earlyBefore + 1,
        'отказ обязан случиться ДО проверки подписей, а не после'
      );
      ok('КРИТ-04: чужой список устройств отвергается без проверки подписей');
      const firstAt = crit.inbox.length;
      crit.ws.send(JSON.stringify({ type: 'mbx-digest' }));
      const d1 = await waitForAfter(crit.inbox, 'mbx-digest', firstAt);
      const secondAt = crit.inbox.length;
      crit.ws.send(JSON.stringify({ type: 'mbx-digest' }));
      const d2 = await waitForAfter(crit.inbox, 'mbx-digest', secondAt);
      assert.strictEqual(d1.bits, d2.bits, 'ящик не менялся — байты сводки обязаны совпасть');
      assert.strictEqual(d1.size, d2.size);
      ok('КРИТ-04: сводка отдаётся готовой и не меняется между просьбами');
      const refusedBefore = await metricValue('licno_costly_refused_total');
      const floodAt = crit.inbox.length;
      for (let i = 0; i < 50; i += 1) crit.ws.send(JSON.stringify({ type: 'mbx-digest' }));
      const refused = await waitForAfter(crit.inbox, 'mbx-error', floodAt);
      assert.strictEqual(refused.error, 'rate', 'сверх минутной нормы узел отказывает');
      assert.ok(
        (await metricValue('licno_costly_refused_total')) > refusedBefore,
        'оператор обязан видеть обстрел дорогими кадрами, а не только рост задержек'
      );
      const served = crit.inbox.slice(floodAt).filter((m) => m.type === 'mbx-digest').length;
      assert.ok(served <= 10, `обслужено ${served} просьб — не больше минутной нормы`);
      assert.strictEqual(crit.ws.readyState, WebSocket.OPEN, 'соединение живо');
      crit.ws.send(JSON.stringify({ type: 'ping' }));
      await waitForAfter(crit.inbox, 'pong', crit.inbox.length - 1);
      ok('КРИТ-04: у дорогих кадров свой потолок, и превышение не рвёт связь');
      crit.ws.close();
      const limitedBefore = await metricValue('licno_mbx_http_limited_total');
      let served200 = 0;
      let refused429 = 0;
      for (let i = 0; i < 40; i += 1) {
        const resp = await fetch(`http://127.0.0.1:${PORT}/mbx?after=0`);
        if (resp.status === 429) refused429 += 1;
        else if (resp.status === 200) served200 += 1;
        await resp.arrayBuffer();
      }
      assert.ok(refused429 > 0, 'поток обращений обязан упереться в потолок частоты');
      assert.ok(served200 <= 12, `обслужено ${served200} обращений — не больше минутной нормы`);
      assert.ok(
        (await metricValue('licno_mbx_http_limited_total')) > limitedBefore,
        'оператор обязан видеть, что узел дёргают как усилитель'
      );
      const limitedResp = await fetch(`http://127.0.0.1:${PORT}/mbx?after=0`);
      assert.strictEqual(limitedResp.status, 429);
      assert.strictEqual(limitedResp.headers.get('retry-after'), '60');
      await limitedResp.arrayBuffer();
      ok('ВЫС-19: HTTP-репликация ящика ограничена по частоте и это видно оператору');
    }
    {
      const ticketRule = require('./gateway-ticket');
      const nacl = require('tweetnacl');
      const { decodeBase64, encodeBase64 } = require('tweetnacl-util');
      const serverEd25519 = require('./ed25519');
      const owner = crypto.generateIdentity();
      const agent = crypto.generateIdentity();
      const sender = crypto.generateIdentity();
      const ownerConn = await client(owner, { autoAck: false });
      await waitFor(ownerConn.inbox, 'ready');
      ownerConn.ws.close();
      await wait(120);
      const senderConn = await client(sender);
      await waitFor(senderConn.inbox, 'ready');
      senderConn.ws.send(
        JSON.stringify({ type: 'send', to: owner.publicKey, envelope: { sealed: 'через-соседа' } })
      );
      await wait(200);
      const agentConn = await client(agent, { autoAck: false });
      await waitFor(agentConn.inbox, 'ready');
      const issue = (overrides = {}) =>
        ticketRule.buildTicket({
          addr: owner.publicKey,
          agent: agent.publicKey,
          agentSign: agent.signPublicKey,
          now: Date.now(),
          nonce: encodeBase64(nacl.randomBytes(ticketRule.NONCE_BYTES)),
          sign: (bytes) => encodeBase64(serverEd25519.sign(bytes, decodeBase64(owner.signSecretKey))),
          ...overrides,
        });
      const ticket = issue();
      agentConn.ws.send(JSON.stringify({ type: 'gw-pull', ticket }));
      const result = await waitFor(agentConn.inbox, 'gw-pull-result');
      assert.strictEqual(result.ok, true, 'жетон владельца обязан приниматься');
      const mail = agentConn.inbox.filter((m) => m.type === 'gw-mail');
      assert.strictEqual(mail.length, 1, 'очередь владельца обязана уехать соседу');
      assert.strictEqual(mail[0].addr, owner.publicKey);
      assert.deepStrictEqual(mail[0].envelope, { sealed: 'через-соседа' }, 'конверт дошёл целым');
      assert.strictEqual(mail[0].from, undefined, 'соседу не отдаётся отправитель');
      assert.strictEqual(mail[0].deviceRoster, undefined, 'соседу не отдаётся список устройств');
      ok('ЭТП5-4: очередь уезжает соседу по жетону владельца');
      agentConn.inbox.length = 0;
      agentConn.ws.send(JSON.stringify({ type: 'gw-pull', ticket }));
      const again = await waitFor(agentConn.inbox, 'gw-pull-result');
      assert.strictEqual(again.ok, false, 'жетон обязан быть одноразовым');
      assert.strictEqual(
        agentConn.inbox.filter((m) => m.type === 'gw-mail').length,
        0,
        'по повторному жетону не должно уехать ни одного конверта'
      );
      ok('ЭТП5-4: жетон одноразовый');
      const stranger = crypto.generateIdentity();
      const strangerConn = await client(stranger, { autoAck: false });
      await waitFor(strangerConn.inbox, 'ready');
      strangerConn.ws.send(JSON.stringify({ type: 'gw-pull', ticket: issue() }));
      const stolen = await waitFor(strangerConn.inbox, 'gw-pull-result');
      assert.strictEqual(stolen.ok, false, 'перехваченный жетон обязан быть бесполезен');
      assert.strictEqual(strangerConn.inbox.filter((m) => m.type === 'gw-mail').length, 0);
      ok('ЭТП5-4: перехваченный жетон бесполезен другому предъявителю');
      agentConn.inbox.length = 0;
      agentConn.ws.send(
        JSON.stringify({
          type: 'gw-pull',
          ticket: issue({
            sign: (bytes) =>
              encodeBase64(serverEd25519.sign(bytes, decodeBase64(stranger.signSecretKey))),
          }),
        })
      );
      const forged = await waitFor(agentConn.inbox, 'gw-pull-result');
      assert.strictEqual(forged.ok, false, 'жетон с чужой подписью обязан отвергаться');
      ok('ЭТП5-4: жетон обязан быть подписан владельцем адреса');
      agentConn.ws.send(JSON.stringify({ type: 'received', id: mail[0].id }));
      await wait(150);
      const back = await client(owner);
      const delivered = await waitFor(back.inbox, 'message');
      assert.deepStrictEqual(
        delivered.envelope,
        { sealed: 'через-соседа' },
        'конверт обязан остаться в очереди: сосед не имеет права его стереть'
      );
      ok('ЭТП5-4: сосед не может стереть чужую очередь');
      agentConn.ws.close();
      strangerConn.ws.close();
      senderConn.ws.close();
      back.ws.close();
    }
    {
      const sealed = { v: 1, ek: 'ZWs=', nonce: 'bm9uY2U=', cipher: 'Y2lwaGVy' };
      const post = (path, body) =>
        fetch(`http://127.0.0.1:${PORT}${path}`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(body),
        });
      const accepted = await post('/report', sealed);
      assert.strictEqual(accepted.status, 200, 'отчёт принимается без аутентификации');
      const acceptedBody = await accepted.json();
      assert.strictEqual(acceptedBody.ok, true);
      ok('ОТЧ-1: узел принимает запечатанный отчёт');
      const junk = await post('/report', { v: 1, ek: '', nonce: '', cipher: '' });
      assert.strictEqual(junk.status, 400, 'посылка не той формы отвергается');
      await junk.arrayBuffer();
      const flooded = await post('/report', sealed);
      assert.strictEqual(flooded.status, 429, 'поток посылок упирается в суточный потолок');
      await flooded.arrayBuffer();
      ok('ОТЧ-1: диск узла нельзя залить отчётами с одного адреса');
      const anonymous = await fetch(`http://127.0.0.1:${PORT}/reports`);
      assert.strictEqual(anonymous.status, 403, 'без подписи выдачи нет');
      await anonymous.arrayBuffer();
      const ts = Date.now();
      const fetchSig = signReports(reportsRule.FETCH_DOMAIN, ts);
      const listed = await fetch(
        `http://127.0.0.1:${PORT}/reports?ts=${ts}&sig=${encodeURIComponent(fetchSig)}`
      );
      assert.strictEqual(listed.status, 200);
      const page = await listed.json();
      assert.strictEqual(page.reports.length, 1, 'принятый отчёт лежит и отдаётся владельцу');
      assert.deepStrictEqual(JSON.parse(page.reports[0].body), sealed, 'байты те же, что принесли');
      ok('ОТЧ-1: забрать отчёты может только владелец — по подписи');
      const wrongDomain = await post('/reports/ack', {
        ts,
        sig: fetchSig,
        ids: [page.reports[0].id],
      });
      assert.strictEqual(wrongDomain.status, 403, 'подпись чтения не стирает отчёты');
      await wrongDomain.arrayBuffer();
      const ackTs = Date.now();
      const removed = await post('/reports/ack', {
        ts: ackTs,
        sig: signReports(reportsRule.DELETE_DOMAIN, ackTs),
        ids: [page.reports[0].id],
      });
      assert.strictEqual(removed.status, 200);
      const removedBody = await removed.json();
      assert.strictEqual(removedBody.removed, 1);
      assert.strictEqual(removedBody.left, 0, 'забранное на узле не остаётся');
      ok('ОТЧ-1: подтверждение получения стирает отчёт с узла');
    }
    a.ws.close();
    b3.ws.close();
    c.ws.close();
    dAck.ws.close();
    console.log(`\nrelay: ${passed} passed`);
  } finally {
    const serverExited = new Promise((resolve) => srv.once('exit', resolve));
    srv.kill();
    await serverExited;
    for (const f of [DB, DB + '-wal', DB + '-shm', VAPID_FILE]) try { fs.unlinkSync(f); } catch (e) {}
    try { fs.rmSync(BLOB_DIR, { recursive: true, force: true }); } catch (e) {}
  }
}
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
  const priv = [
    '127.0.0.1',
    '169.254.169.254',
    '10.0.0.5',
    '192.168.1.1',
    '2130706433',
    '[::1]',
    '[::ffff:127.0.0.1]',
    '[::ffff:169.254.169.254]',
    '[0:0:0:0:0:0:0:1]',
    '[fc00::1]',
    '[fe80::1]',
  ];
  for (const h of priv) u(`isPrivateHost blocks ${h}`, dir.isPrivateHost(h) === true);
  const pub = ['example.com', '1.2.3.4', '93.184.216.34', '[2606:4700::1111]', '[::ffff:8.8.8.8]'];
  for (const h of pub) u(`isPrivateHost allows ${h}`, dir.isPrivateHost(h) === false);
  u('reject ws IPv4-mapped loopback URL', !dir.isValidRelayUrl('ws://[::ffff:127.0.0.1]:8787'));
  u('reject ws cloud-metadata via mapped IPv6', !dir.isValidRelayUrl('ws://[::ffff:169.254.169.254]'));
  u('reject ws expanded IPv6 loopback', !dir.isValidRelayUrl('ws://[0:0:0:0:0:0:0:1]:8787'));
  u('allow public IPv6 relay', dir.isValidRelayUrl('wss://[2606:4700::1111]'));
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
  u('coturn: лог в stdout (не /var/log)', cfg.includes('log-file=stdout'));
  const cfgPid = dir.coturnConfigText('S', { pidfile: '/data/turnserver.pid', userdb: '/data/turndb' });
  u('coturn: pidfile в writable-путь (не /var/run)', cfgPid.includes('pidfile=/data/turnserver.pid'));
  u('coturn: userdb в writable-путь (не /var/lib/turn)', cfgPid.includes('userdb=/data/turndb'));
  u('coturn: без опций строк pidfile/userdb нет', !cfgNoHost.includes('pidfile=') && !cfgNoHost.includes('userdb='));
  const W2 = 1000, MAXB = 1000, STRIKES = 3;
  const bg = (state, now, bytes) => dir.byteGate(state, now, bytes, W2, MAXB, STRIKES);
  let b = bg(null, 0, 400);
  u('byteGate: в бюджете паузы нет', b.pauseMs === 0 && b.abusive === false);
  b = bg(b.state, 100, 400);
  u('byteGate: байты накапливаются в окне', b.state.bytes === 800 && b.pauseMs === 0);
  b = bg(b.state, 200, 400);
  u('byteGate: превышение даёт паузу', b.pauseMs === 800);
  u('byteGate: одно превышение — не абуз', b.abusive === false);
  u('byteGate: страйк начислен', b.state.strikes === 1);
  b = bg(b.state, 300, 400);
  b = bg(b.state, 400, 400);
  b = bg(b.state, 500, 400);
  u('byteGate: страйк не растёт внутри одного окна', b.state.strikes === 1);
  u('byteGate: пачка кадров сверх лимита не рвёт связь', b.abusive === false);
  b = bg(b.state, 1000, 2000);
  u('byteGate: второе окно подряд — страйк 2', b.state.strikes === 2 && b.abusive === false);
  b = bg(b.state, 2000, 2000);
  u('byteGate: третье окно подряд — абуз', b.state.strikes === 3 && b.abusive === true);
  let calm = bg(null, 0, 2000);
  u('byteGate: всплеск даёт страйк', calm.state.strikes === 1);
  calm = bg(calm.state, 1000, 10);
  u('byteGate: серия переживает закрытие превышенного окна', calm.state.strikes === 1);
  calm = bg(calm.state, 2000, 10);
  u('byteGate: тихое окно обнуляет серию', calm.state.strikes === 0);
  const late = bg({ start: 0, bytes: 2000, strikes: 1 }, 999, 1);
  u('byteGate: пауза в пределах окна', late.pauseMs > 0 && late.pauseMs <= W2);
  const edge = bg({ start: 0, bytes: 2000, strikes: 1 }, 1000, 1);
  u('byteGate: на границе окно уже новое', edge.state.bytes === 1 && edge.pauseMs === 0);
  const neg = bg({ start: 0, bytes: 100, strikes: 0 }, 10, -5000);
  u('byteGate: отрицательный размер игнорируется', neg.state.bytes === 100);
  const exact = bg(null, 0, MAXB);
  u('byteGate: ровно потолок — не превышение', exact.pauseMs === 0 && exact.state.strikes === 0);
  u('byteGate: потолок + 1 байт — превышение', bg(exact.state, 1, 1).pauseMs > 0);
  const hmac = (username) => `sig(${username})`;
  const ice = dir.buildIceServers({
    turnSecret: 'SEKRET',
    turnHost: '203.0.113.7',
    publicStun: ['stun:stun.example.org:3478'],
    now: 1_700_000_000_000,
    hmac,
  });
  u('ICE: свой STUN первым', ice[0].urls === 'stun:203.0.113.7:3478');
  u('ICE: свой TURN по udp и tcp', ice[1].urls.length === 2 && ice[1].urls.every((x) => x.startsWith('turn:203.0.113.7:3478')));
  u('ICE: учётка эфемерная (срок в username)', /^\d+:licno$/.test(ice[1].username));
  u('ICE: срок = now + 1ч', ice[1].username === `${1_700_000_000 + 3600}:licno`);
  u('ICE: credential — HMAC от username', ice[1].credential === `sig(${ice[1].username})`);
  u('ICE: секрет TURN наружу не уходит', !JSON.stringify(ice).includes('SEKRET'));
  u('ICE: при своём TURN чужой STUN не добавляется', !JSON.stringify(ice).includes('stun.example.org'));
  const iceNoTurn = dir.buildIceServers({ publicStun: ['stun:stun.example.org:3478'], now: 0, hmac });
  u('ICE: без TURN отдаётся только явный STUN оператора', iceNoTurn.length === 1 && iceNoTurn[0].urls === 'stun:stun.example.org:3478');
  u('ICE: по умолчанию список пуст', dir.buildIceServers({ now: 0, hmac }).length === 0);
  u('ICE: секрет без хоста не включает TURN', dir.buildIceServers({ turnSecret: 'S', now: 0, hmac }).length === 0);
  u('ICE: хост без секрета не включает TURN', dir.buildIceServers({ turnHost: 'h', now: 0, hmac }).length === 0);
  for (const bad of [undefined, null, {}, { publicStun: null }, { publicStun: 'stun:x' }]) {
    u(`ICE: мусорный ввод ${JSON.stringify(bad)} -> пусто`, dir.buildIceServers(bad ? { ...bad, hmac } : bad).length === 0);
  }
  const allIce = JSON.stringify([ice, iceNoTurn, dir.buildIceServers({ now: 0, hmac })]);
  for (const forbidden of ['google', 'stun.l.', 'twilio', 'cloudflare']) {
    u(`ICE: нет зашитого ${forbidden}`, !allIce.includes(forbidden));
  }
  u('STUN-парсер: пусто по умолчанию', dir.parsePublicStun('').length === 0);
  u('STUN-парсер: пусто при undefined', dir.parsePublicStun(undefined).length === 0);
  u('STUN-парсер: разбирает список через запятую', dir.parsePublicStun('stun:a:3478, stuns:b:5349').length === 2);
  u('STUN-парсер: обрезает пробелы', dir.parsePublicStun('  stun:a:3478  ')[0] === 'stun:a:3478');
  u('STUN-парсер: отбрасывает не-STUN схемы', dir.parsePublicStun('turn:a,http://b,wss://c,a.b.c').length === 0);
  let st = null;
  const W = 1000, MAX = 3;
  let given = 0;
  for (let i = 0; i < 10; i++) {
    const g = dir.rateGate(st, 100, W, MAX);
    st = g.state;
    if (g.allow) { given += 1; st.count += 1; }
  }
  u('rateGate: в окне выдаётся не больше max', given === MAX);
  const g2 = dir.rateGate(st, 100 + W + 1, W, MAX);
  u('rateGate: после окна снова allow', g2.allow === true && g2.state.count === 0);
  console.log(`\ndirectory-unit: ${n} passed`);
}
unitTests();
main().catch((e) => {
  console.error(e);
  process.exit(1);
});