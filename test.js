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

// ОТЧ-1: пара владельца отчётов для проверок. Настоящая половина ключа выпуска
// живёт в секретах сборки, поэтому узел в тесте проверяет подписи этой.
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

/**
 * КРИТ-04: прочитать счётчик из /metrics.
 *
 * Часть свойств узла снаружи иначе не видна: отказ до проверки подписей и
 * отказ после неё выглядят для клиента одинаково — и это намеренно, иначе по
 * тексту ответа посторонний узнавал бы про чужие аккаунты. Метрика показывает
 * то же самое оператору, которому знать положено.
 */
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

// СРВ-11: квитанции надо сличать попарно, поэтому ждём КОНКРЕТНЫЙ ref, а не
// «первый кадр такого типа»: в inbox одновременно лежат ответы на оба зонда.
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

/**
 * Connect and complete the ownership handshake. `autoAck` acks each incoming
 * message (needed for delivery); omit to test queue retention.
 * `signId` overrides which identity signs the challenge (to test rejection).
 */
// boxProof по умолчанию true: реальные клиенты ВСЕГДА доказывают владение
// box-ключом (см. src/relay.js). СРВ-1: квитанции `received` сервер принимает
// только от доказанного владельца, поэтому тестовый клиент должен вести себя как
// боевой. Легаси-путь (без boxProof) проверяется отдельными raw-соединениями ниже.
function client(id, { autoAck = true, signId, boxProof = true, capabilities = null } = {}) {
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
        // ПРФ-14: у обычного сообщения квитанция СВОЯ (`received`), как и при
        // JSON-доставке. Подтверди мы его как чанк вложения — конверт остался бы
        // в очереди навсегда, а отправитель не получил бы `delivered`.
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
      const hello = { type: 'hello', pubkey: id.publicKey, signPublicKey: id.signPublicKey };
      // ПРФ-14: возможности объявляются В HELLO. Клиент, который их не назвал
      // (умолчание в тестах, как и у прежних версий приложения), обязан и дальше
      // получать конверты JSON-ом.
      if (capabilities) hello.capabilities = capabilities;
      ws.send(JSON.stringify(hello));
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
      // ОТЧ-1: чем узел проверяет право забрать отчёты. В бою это ключ выпуска,
      // секретной половины которого у проверок нет и быть не должно.
      RELAY_REPORTS_KEY: REPORTS_OWNER_PUB,
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
    // СРЕД-03: версия поднята с 5 до 6 — узел принимает кадр-пустышку и молча
    // её выбрасывает. Клиент включает прикрывающий трафик только при совпадении
    // И версии, И имени возможности, поэтому число здесь рабочее: занизив его,
    // мы бы молча выключили прикрытие у всех, кто ходит через этот узел.
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

    // --- СРВ-11: квитанция не выдаёт присутствия получателя ------------------
    //
    // Раньше `ack` отвечал `queued:false`, если кадр ушёл в живой сокет, и
    // `queued:true`, если лёг в очередь. Регистрация свободна, служебный
    // (`silent`) конверт получателя не будит и в его переписке не виден — то
    // есть любой желающий мог опрашивать ЧУЖОЙ адрес хоть каждую секунду и
    // строить профиль присутствия: сон, работа, поездки, «эти двое онлайн
    // одновременно». Ниже — прямая проверка того самого зонда: два конверта, у
    // одного получатель в сети, у другого адрес не подключался НИ РАЗУ. Ответы
    // обязаны совпасть во всём, кроме ref и идентификатора конверта.
    const ghost = crypto.generateIdentity(); // адрес, за которым никто не стоит
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

    // Тот же зонд на бинарном пути: `attachment-chunk` шлётся так же свободно,
    // и если бы `binary-ack` сохранил различие, опрос просто переехал бы на
    // вложения.
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

    // --- ПРФ-14: обычное сообщение двоичным кадром ---------------------------
    //
    // Проверяется не «принял ли релей кадр», а два свойства, от которых зависит,
    // дойдёт ли сообщение вообще.
    //
    // Первое: путь один. Квоты очереди, признак `dropped` и форма квитанции у
    // двоичного и JSON-кадра обязаны совпадать — иначе двоичный кадр стал бы
    // обходом ограничений очереди либо новым оракулом присутствия.
    //
    // Второе: согласование. Клиент, не объявивший возможность, обязан
    // ПРОДОЛЖАТЬ получать конверты JSON-ом, кем бы они ни были отправлены.
    // Конверт идёт от узла к узлу, поэтому отправитель о клиенте получателя
    // ничего не знает и решение принимается по соединению ПОЛУЧАТЕЛЯ.
    {
      const sealedOf = (bytes) => ({ v: 1, sealed: Buffer.from(bytes).toString('base64') });
      const blob = require('crypto').randomBytes(320);
      const outer = sealedOf(blob);

      /**
       * Каким кадром конверт доехал до получателя.
       *
       * Ждём ЛЮБОЙ реакции, а не кадра нужного вида: иначе «уехало не тем
       * форматом» было бы не отличить от «ещё не дошло», и поломка
       * совместимости выглядела бы как таймаут без объяснения.
       */
      const arrivedAs = async (peer, jsonStart, binaryStart, timeout = 3000) => {
        const started = Date.now();
        while (Date.now() - started < timeout) {
          if (peer.binaryInbox.length > binaryStart) return 'двоично';
          if (peer.inbox.slice(jsonStart).some((m) => m.type === 'message')) return 'JSON';
          await wait(20);
        }
        return 'не дошло';
      };

      // 1. Двоичный кадр от отправителя → получатель прежней версии (b) читает
      //    его прежним JSON-кадром. Именно так работает совместимость.
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

      // 2. Квитанции обоих путей неразличимы (кроме ref и id) — общий путь
      //    приёма, а не две расходящиеся ветки.
      a.ws.send(JSON.stringify({ type: 'send', to: bob.publicKey, envelope: outer, ref: 'json-r1' }));
      const jsonAck = await waitForRef(a.inbox, 'ack', 'json-r1');
      assert.deepStrictEqual(
        { ...binAck, ref: null, id: null },
        { ...jsonAck, ref: null, id: null },
        'квитанция двоичного пути обязана быть неотличима от квитанции JSON-пути'
      );
      ok('ПРФ-14: квитанции двоичного и JSON-пути неразличимы');

      // 3. Получатель, объявивший возможность, получает ДВОИЧНЫЙ кадр — и
      //    полезная нагрузка в нём сырая, без base64.
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
      // Квитанция `received` из двоичного кадра снимает конверт с очереди так же,
      // как из JSON: иначе он лежал бы до истечения срока и приезжал снова.
      await waitForAfter(a.inbox, 'delivered', ackStart3);
      ok('ПРФ-14: получатель, объявивший возможность, получает конверт двоичным кадром без base64');

      // 4. ГРАНИЦА ПРИВАТНОСТИ. Незапечатанный конверт двоично не отдаётся: его
      //    поля (отправитель, эфемерный ключ храповика, счётчики цепочки) иначе
      //    вышли бы в открытый заголовок кадра.
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

      // 5. Очередь не теряется. Отправляем на адрес, которого нет в сети, затем
      //    поднимаем его с объявленной возможностью — конверт обязан приехать
      //    двоично и сняться с очереди по квитанции.
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

      // 6. Негодный двоичный кадр отвергается внятной ошибкой, а соединение
      //    остаётся живым: разбор идёт над данными из сети.
      const errStart = a.inbox.length;
      a.ws.send(packBinaryFrame({ type: 'send-v1', version: 1, to: bob.publicKey, sv: 7 }, blob));
      const badVersion = await waitForAfter(a.inbox, 'error', errStart);
      assert.ok(/envelope frame/.test(badVersion.error));
      const errStart2 = a.inbox.length;
      a.ws.send(packBinaryFrame({ type: 'send-v1', version: 1, to: '', sv: 1 }, blob));
      await waitForAfter(a.inbox, 'error', errStart2);
      // Соединение живо: следующий нормальный кадр по-прежнему принимается.
      a.ws.send(
        packBinaryFrame({ type: 'send-v1', version: 1, to: bob.publicKey, sv: 1, ref: 'after-err' }, blob)
      );
      await waitForRef(a.inbox, 'ack', 'after-err');
      ok('ПРФ-14: негодный двоичный кадр конверта отвергается, соединение переживает это');

      // 7. СРЕД-03: кадр-пустышка. Узел обязан принять его и молча выбросить —
      //    ни ответа, ни квитанции, ни очереди, ни доставки.
      //
      //    Проверяется на настоящем узле, потому что цена ошибки здесь двойная.
      //    Ответь он хоть чем-нибудь — и в канале появится вторая запись,
      //    жёстко привязанная к первой: наблюдатель отличит пустышку от
      //    сообщения по одному наличию пары, и вся мера сведётся к самопометке.
      //    Прими он её за конверт — мусор пойдёт между людьми как сообщение и
      //    займёт место в очереди получателя.
      //
      //    Следующий обычный кадр служит меткой времени: дождавшись ЕГО
      //    квитанции, мы точно знаем, что узел успел обработать и пустышку.
      //    Каждый принятый конверт отвечает ровно одной `ack`, поэтому «одна
      //    квитанция на два отправленных кадра» и означает, что пустышка
      //    сообщением не стала.
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

    // ВЫС-41: отправитель просит НЕ подставлять его метаданные снаружи —
    // получатель читает их изнутри запечатанного конверта. Прежде адрес
    // аккаунта и весь список устройств ложились в очередь на диск открытым
    // текстом рядом с запечатанным конвертом: изъятая база релея прямо
    // говорила, какие ключи принадлежат одному человеку и кому он писал.
    const noMetaStart = b.inbox.length;
    desktopClient.ws.send(
      JSON.stringify({
        type: 'send',
        to: bob.publicKey,
        envelope: desktopEnvelope,
        ref: 'desktop-r2',
        noMeta: true,
      })
    );
    const hidden = await waitForAfter(b.inbox, 'message', noMetaStart);
    assert.strictEqual(hidden.fromAccount, undefined, 'адрес аккаунта отправителя наружу не выходит');
    assert.strictEqual(hidden.fromDeviceId, undefined);
    assert.strictEqual(hidden.deviceCertificate, undefined);
    assert.strictEqual(hidden.deviceRoster, undefined, 'и весь список его устройств — тоже');
    assert.strictEqual(hidden.from, desktop.publicKey, 'адрес устройства остаётся: без него кадр некому доставить');
    assert.ok(hidden.envelope, 'сам конверт при этом доезжает как обычно');
    ok('ВЫС-41: по просьбе отправителя релей не подставляет его метаданные наружу');

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

      // АУД-Э1: недоказанный держатель (boxProof:false) занимает ещё не занятый
      // адрес — и не получает НИЧЕГО.
      //
      // Раньше он получал конверт онлайн, и защищена была только квитанция: он
      // не мог вычерпать очередь, но читал и шифртекст, и метаданные каждого
      // отправителя (адрес, идентификатор и имя устройства, весь его список
      // устройств). Для продукта, который прячет социальный граф, это сводило
      // усилия на нет: адрес публичен, а закрепление живёт на каждом релее
      // отдельно, поэтому найти узел, где жертва ещё не входила, несложно.
      const unproven = await client(victim, { boxProof: false });
      const readyUnproven = await waitFor(unproven.inbox, 'ready');
      assert.strictEqual(
        readyUnproven.receiveBlocked,
        'box-proof-required',
        'релей обязан сказать, почему входящих не будет, а не молчать'
      );
      assert.strictEqual(readyUnproven.queued, 0, 'очередь недоказанному сеансу не выгружается');
      await wait(250); // за это время конверт НЕ должен приехать
      assert.strictEqual(
        unproven.inbox.filter((m) => m.type === 'message').length,
        0,
        'ни один конверт не уходит тому, кто не доказал владение адресом'
      );

      // Публикация prekey и перехват токена пробуждения тоже закрыты: иначе
      // захвативший адрес подменял бы бандл жертвы и забирал её уведомления.
      unproven.ws.send(JSON.stringify({ type: 'register', pushToken: 'ТОКЕН-ЗАХВАТЧИКА' }));
      const regErr = await waitFor(unproven.inbox, 'error');
      assert.strictEqual(regErr.error, 'box ownership proof required', 'push-токен не перебивается без доказательства');

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
      ok('АУД-Э1: незакреплённый адрес нельзя занять — ни приём, ни очередь, ни push, ни prekey');
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

    // --- КРИТ-04: цена дорогих кадров назначает узел, а не спрашивающий ---
    {
      const crit = await client(crypto.generateIdentity());
      await waitFor(crit.inbox, 'ready');

      // 1. Права на список устройств проверяются ДО криптографии.
      //
      // Отличить «отказали до разбора» от «отказали после» по ответу нельзя, и
      // это намеренно: постороннему причина не рассказывается, иначе он узнавал
      // бы, заводил ли на узле аккаунт конкретный человек. Наблюдаемым порядок
      // делает счётчик — он же и нужен оператору, чтобы отличать обстрел
      // дорогими кадрами от «узел стал медленным».
      //
      // Ростер здесь ВАЛИДНО ПОДПИСАН: проверяется именно порядок, а не то, что
      // мусор отвергается. Права на чужой аккаунт у соединения при этом нет.
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

      // 2. Сводка ящика отдаётся из готового, а не пересчитывается на просьбу.
      //
      // Проверяется наблюдаемое следствие: между двумя просьбами подряд, если
      // ящик не менялся, ответ обязан совпасть побайтно. Пересчёт на каждую
      // просьбу был бы не только дорог, но и опасен: сводки двух спросивших
      // подряд отличались бы, и по разнице читалось бы, что легло между ними.
      const firstAt = crit.inbox.length;
      crit.ws.send(JSON.stringify({ type: 'mbx-digest' }));
      const d1 = await waitForAfter(crit.inbox, 'mbx-digest', firstAt);
      const secondAt = crit.inbox.length;
      crit.ws.send(JSON.stringify({ type: 'mbx-digest' }));
      const d2 = await waitForAfter(crit.inbox, 'mbx-digest', secondAt);
      assert.strictEqual(d1.bits, d2.bits, 'ящик не менялся — байты сводки обязаны совпасть');
      assert.strictEqual(d1.size, d2.size);
      ok('КРИТ-04: сводка отдаётся готовой и не меняется между просьбами');

      // 3. Дорогие кадры живут по своему потолку, а не по общему.
      //
      // Общий лимит — восемьдесят кадров в секунду; в него укладываются и
      // просьбы, каждая из которых стоит выборки по всей базе. Здесь их идёт
      // полсотни — заведомо больше минутной нормы и заведомо меньше общего
      // лимита, поэтому отказ может прийти только от отдельного потолка.
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
      // Отказ, а не разрыв: легитимный клиент мог попасть сюда из-за повторов
      // при плохой связи, и рвать ему соединение дороже, чем отказать.
      assert.strictEqual(crit.ws.readyState, WebSocket.OPEN, 'соединение живо');
      crit.ws.send(JSON.stringify({ type: 'ping' }));
      await waitForAfter(crit.inbox, 'pong', crit.inbox.length - 1);
      ok('КРИТ-04: у дорогих кадров свой потолок, и превышение не рвёт связь');
      crit.ws.close();

      // 4. ВЫС-19: HTTP-репликация ящика — не бесплатный усилитель.
      //
      // GET /mbx отдавал до 1,2 МБ на запрос в сорок байт (усилитель ×30000)
      // без аутентификации и без ограничения частоты, при том что WS-кадры
      // ящика давно и за auth, и под своим потолком.
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
      // Отказ — обычный 429 с retry-after, а не разрыв: сосед мог упереться в
      // потолок из-за повторов, и молчание объяснило бы ему меньше.
      const limitedResp = await fetch(`http://127.0.0.1:${PORT}/mbx?after=0`);
      assert.strictEqual(limitedResp.status, 429);
      assert.strictEqual(limitedResp.headers.get('retry-after'), '60');
      await limitedResp.arrayBuffer();
      ok('ВЫС-19: HTTP-репликация ящика ограничена по частоте и это видно оператору');
    }

    // --- ЭТП5-4: приём через соседа по жетону доступа ------------------------
    //
    // Выход в интернет через соседа (ШЛЗ-1) работал В ОДНУ СТОРОНУ: сосед мог
    // положить наш конверт в релей, но забрать нашу очередь не мог — релей
    // отдаёт её только доказавшему владение box-ключом адреса. Человек без
    // интернета мог писать, но не получать.
    //
    // Здесь проверяется вторая половина: владелец подписывает жетон соседу, и
    // очередь уходит соседу — но ТОЛЬКО ему, ТОЛЬКО один раз и БЕЗ права
    // удалить её.
    {
      const ticketRule = require('./gateway-ticket');
      const nacl = require('tweetnacl');
      const { decodeBase64, encodeBase64 } = require('tweetnacl-util');
      // Подпись — через ту же обёртку, что и весь релей: единая точка смены
      // криптографического основания существует ровно затем, чтобы её не
      // обходили, и проверка ЕД-1 это стережёт.
      const serverEd25519 = require('./ed25519');

      const owner = crypto.generateIdentity(); // тот, кто без интернета
      const agent = crypto.generateIdentity(); // сосед-шлюз
      const sender = crypto.generateIdentity(); // кто ему написал

      // Владелец подключается один раз: адрес обязан быть ЗАКРЕПЛЁН за его
      // ключом, иначе жетон проверять нечем. Это не поблажка — ровно наоборот:
      // за незакреплённый адрес мог бы выдать жетон кто угодно.
      const ownerConn = await client(owner, { autoAck: false });
      await waitFor(ownerConn.inbox, 'ready');
      ownerConn.ws.close();
      await wait(120);

      // Пока владелец офлайн, ему пишут.
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
      // Ни отправителя, ни сертификата устройства, ни списка устройств: соседу
      // для доставки это не нужно, а вместе оно и есть социальный граф.
      assert.strictEqual(mail[0].from, undefined, 'соседу не отдаётся отправитель');
      assert.strictEqual(mail[0].deviceRoster, undefined, 'соседу не отдаётся список устройств');
      ok('ЭТП5-4: очередь уезжает соседу по жетону владельца');

      // Повтор того же жетона не проходит: иначе потерянный телефон соседа
      // оставался бы ключом к очереди до конца срока.
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

      // Жетон, выданный другому, не работает у перехватившего. Ровно это и
      // позволяет везти жетон открыто по сети знакомств.
      const stranger = crypto.generateIdentity();
      const strangerConn = await client(stranger, { autoAck: false });
      await waitFor(strangerConn.inbox, 'ready');
      strangerConn.ws.send(JSON.stringify({ type: 'gw-pull', ticket: issue() }));
      const stolen = await waitFor(strangerConn.inbox, 'gw-pull-result');
      assert.strictEqual(stolen.ok, false, 'перехваченный жетон обязан быть бесполезен');
      assert.strictEqual(strangerConn.inbox.filter((m) => m.type === 'gw-mail').length, 0);
      ok('ЭТП5-4: перехваченный жетон бесполезен другому предъявителю');

      // Подпись чужим ключом не проходит: подписать «разрешение на чужую
      // очередь» может кто угодно, значение имеет только закрепление на релее.
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

      // ГЛАВНОЕ: очередь на месте. Предъявитель жетона не может её удалить —
      // квитанцию принимает только доказанный владелец, — поэтому худшее, что
      // сделает недобросовестный сосед, это не довезёт.
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

    // --- ОТЧ-1: отчёты о неполадках -----------------------------------------
    //
    // Приём открыт намеренно: отчёт нужен ровно тогда, когда у человека
    // сломалось всё, включая аутентификацию. Поэтому проверяется, что открытым
    // остался ТОЛЬКО приём: забрать накопленное можно лишь подписью владельца,
    // стереть — лишь ОТДЕЛЬНОЙ подписью, а поток посылок упирается в потолок.
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

      // Третья посылка с того же адреса за сутки — уже за потолком.
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

      // Подпись ЧТЕНИЯ не должна ничего стирать, даже если её повторить слово
      // в слово: у выдачи и удаления разные домены подписи.
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

  // БЕЗ-5: byteGate — потолок ПОТОКА байт на соединение.
  const W2 = 1000, MAXB = 1000, STRIKES = 3;
  const bg = (state, now, bytes) => dir.byteGate(state, now, bytes, W2, MAXB, STRIKES);
  // В пределах бюджета — ни паузы, ни страйков.
  let b = bg(null, 0, 400);
  u('byteGate: в бюджете паузы нет', b.pauseMs === 0 && b.abusive === false);
  b = bg(b.state, 100, 400);
  u('byteGate: байты накапливаются в окне', b.state.bytes === 800 && b.pauseMs === 0);
  // Превышение -> пауза до конца окна, но НЕ разрыв.
  b = bg(b.state, 200, 400);
  u('byteGate: превышение даёт паузу', b.pauseMs === 800);
  u('byteGate: одно превышение — не абуз', b.abusive === false);
  u('byteGate: страйк начислен', b.state.strikes === 1);
  // Страйк — РАЗ ЗА ОКНО: пачка кадров сверх лимита не сжигает серию мгновенно.
  b = bg(b.state, 300, 400);
  b = bg(b.state, 400, 400);
  b = bg(b.state, 500, 400);
  u('byteGate: страйк не растёт внутри одного окна', b.state.strikes === 1);
  u('byteGate: пачка кадров сверх лимита не рвёт связь', b.abusive === false);
  // Непрерывное превышение окно за окном -> абуз.
  b = bg(b.state, 1000, 2000);
  u('byteGate: второе окно подряд — страйк 2', b.state.strikes === 2 && b.abusive === false);
  b = bg(b.state, 2000, 2000);
  u('byteGate: третье окно подряд — абуз', b.state.strikes === 3 && b.abusive === true);
  // Спокойное окно обнуляет серию: всплеск при отправке файла не копится вечно.
  let calm = bg(null, 0, 2000); // страйк 1
  u('byteGate: всплеск даёт страйк', calm.state.strikes === 1);
  calm = bg(calm.state, 1000, 10); // окно закрылось превышенным -> серия жива
  u('byteGate: серия переживает закрытие превышенного окна', calm.state.strikes === 1);
  calm = bg(calm.state, 2000, 10); // а это окно прошло тихо -> серия сброшена
  u('byteGate: тихое окно обнуляет серию', calm.state.strikes === 0);
  // Пауза не бывает отрицательной и не превышает окно.
  const late = bg({ start: 0, bytes: 2000, strikes: 1 }, 999, 1);
  u('byteGate: пауза в пределах окна', late.pauseMs > 0 && late.pauseMs <= W2);
  const edge = bg({ start: 0, bytes: 2000, strikes: 1 }, 1000, 1);
  u('byteGate: на границе окно уже новое', edge.state.bytes === 1 && edge.pauseMs === 0);
  // Мусорный размер кадра не должен уводить счётчик в минус.
  const neg = bg({ start: 0, bytes: 100, strikes: 0 }, 10, -5000);
  u('byteGate: отрицательный размер игнорируется', neg.state.bytes === 100);
  // Ровно на потолке — ещё не превышение (границу не рубим).
  const exact = bg(null, 0, MAXB);
  u('byteGate: ровно потолок — не превышение', exact.pauseMs === 0 && exact.state.strikes === 0);
  u('byteGate: потолок + 1 байт — превышение', bg(exact.state, 1, 1).pauseMs > 0);

  // БЕЗ-1: релей отдаёт клиенту СВОЙ STUN/TURN — и ничей больше.
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
  // Свой coturn настроен -> внешний STUN не подмешивается, даже если задан.
  u('ICE: при своём TURN чужой STUN не добавляется', !JSON.stringify(ice).includes('stun.example.org'));

  // Своего TURN нет -> только то, что оператор разрешил ЯВНО.
  const iceNoTurn = dir.buildIceServers({ publicStun: ['stun:stun.example.org:3478'], now: 0, hmac });
  u('ICE: без TURN отдаётся только явный STUN оператора', iceNoTurn.length === 1 && iceNoTurn[0].urls === 'stun:stun.example.org:3478');
  // Ключевая регрессия: по умолчанию не отдаётся НИЧЕГО. Раньше здесь был Google.
  u('ICE: по умолчанию список пуст', dir.buildIceServers({ now: 0, hmac }).length === 0);
  u('ICE: секрет без хоста не включает TURN', dir.buildIceServers({ turnSecret: 'S', now: 0, hmac }).length === 0);
  u('ICE: хост без секрета не включает TURN', dir.buildIceServers({ turnHost: 'h', now: 0, hmac }).length === 0);
  for (const bad of [undefined, null, {}, { publicStun: null }, { publicStun: 'stun:x' }]) {
    u(`ICE: мусорный ввод ${JSON.stringify(bad)} -> пусто`, dir.buildIceServers(bad ? { ...bad, hmac } : bad).length === 0);
  }
  // Ни при какой конфигурации в списке не должно оказаться зашитого чужого STUN.
  const allIce = JSON.stringify([ice, iceNoTurn, dir.buildIceServers({ now: 0, hmac })]);
  for (const forbidden of ['google', 'stun.l.', 'twilio', 'cloudflare']) {
    u(`ICE: нет зашитого ${forbidden}`, !allIce.includes(forbidden));
  }

  // parsePublicStun: пропускает только stun:/stuns:, мусор отбрасывает молча.
  u('STUN-парсер: пусто по умолчанию', dir.parsePublicStun('').length === 0);
  u('STUN-парсер: пусто при undefined', dir.parsePublicStun(undefined).length === 0);
  u('STUN-парсер: разбирает список через запятую', dir.parsePublicStun('stun:a:3478, stuns:b:5349').length === 2);
  u('STUN-парсер: обрезает пробелы', dir.parsePublicStun('  stun:a:3478  ')[0] === 'stun:a:3478');
  u('STUN-парсер: отбрасывает не-STUN схемы', dir.parsePublicStun('turn:a,http://b,wss://c,a.b.c').length === 0);

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
