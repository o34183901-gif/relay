'use strict';

const assert = require('assert');
const nacl = require('tweetnacl');
const { encodeBase64 } = require('tweetnacl-util');
const linked = require('./linked-devices');

const PAIRING_RELAYS = [
  'wss://89.108.83.230.sslip.io',
  'wss://46.226.162.166.sslip.io',
  'wss://77.221.137.215.sslip.io',
];

let passed = 0;
function test(name, fn) {
  try {
    fn();
    passed += 1;
    console.log('✓', name);
  } catch (error) {
    console.error('✗', name);
    throw error;
  }
}

function identity() {
  const box = nacl.box.keyPair();
  const sign = nacl.sign.keyPair();
  return {
    publicKey: encodeBase64(box.publicKey),
    secretKey: encodeBase64(box.secretKey),
    signPublicKey: encodeBase64(sign.publicKey),
    signSecretKey: encodeBase64(sign.secretKey),
  };
}

function certificate(account, device, overrides = {}) {
  return linked.createDeviceCertificate(
    {
      accountPublicKey: account.publicKey,
      accountSignPublicKey: account.signPublicKey,
      deviceId: linked.deriveDeviceId(device.publicKey),
      devicePublicKey: device.publicKey,
      deviceSignPublicKey: device.signPublicKey,
      name: 'Домашний компьютер',
      platform: 'windows',
      issuedAt: 1000,
      capabilities: ['messages', 'files', 'voice', 'history-sync', 'notifications'],
      ...overrides,
    },
    account.signSecretKey
  );
}

test('stableStringify сортирует ключи рекурсивно', () => {
  assert.strictEqual(linked.stableStringify({ z: 1, a: { y: 2, b: 3 } }), '{"a":{"b":3,"y":2},"z":1}');
});

test('deviceId детерминирован и привязан к box-ключу', () => {
  const device = identity();
  assert.strictEqual(linked.deriveDeviceId(device.publicKey), linked.deriveDeviceId(device.publicKey));
  assert.notStrictEqual(linked.deriveDeviceId(device.publicKey), linked.deriveDeviceId(identity().publicKey));
});

test('сертификат устройства проверяется корневым sign-ключом', () => {
  const account = identity();
  const cert = certificate(account, identity());
  assert.ok(linked.verifyDeviceCertificate(cert, { accountPublicKey: account.publicKey }));
  assert.ok(!linked.verifyDeviceCertificate({ ...cert, name: 'Подмена' }, { accountPublicKey: account.publicKey }));
});

test('roster требует активное основное устройство и не принимает подмену', () => {
  const account = identity();
  const desktop = identity();
  const primary = certificate(account, account, { name: 'Телефон Android', platform: 'android' });
  const secondary = certificate(account, desktop);
  const roster = linked.createSignedRoster(
    {
      accountPublicKey: account.publicKey,
      accountSignPublicKey: account.signPublicKey,
      version: 2,
      updatedAt: 2000,
      devices: [
        { certificate: primary, revokedAt: null },
        { certificate: secondary, revokedAt: null },
      ],
    },
    account.signSecretKey
  );
  assert.ok(linked.verifySignedRoster(roster, { accountPublicKey: account.publicKey, minVersion: 2 }));
  assert.ok(!linked.verifySignedRoster({ ...roster, version: 3 }, { accountPublicKey: account.publicKey }));
  assert.throws(
    () =>
      linked.createSignedRoster(
        {
          accountPublicKey: account.publicKey,
          accountSignPublicKey: account.signPublicKey,
          version: 3,
          updatedAt: 3000,
          devices: [{ certificate: primary, revokedAt: 2500 }],
        },
        account.signSecretKey
      ),
    /active device|active primary/
  );
});

test('web/iPhone может быть основным устройством для desktop', () => {
  const account = identity();
  const desktop = identity();
  const primary = certificate(account, account, { name: 'iPhone web', platform: 'web' });
  const secondary = certificate(account, desktop, { name: 'Рабочий ПК', platform: 'windows' });
  const roster = linked.createSignedRoster(
    {
      accountPublicKey: account.publicKey,
      accountSignPublicKey: account.signPublicKey,
      version: 1,
      updatedAt: 3000,
      devices: [
        { certificate: primary, revokedAt: null },
        { certificate: secondary, revokedAt: null },
      ],
    },
    account.signSecretKey
  );
  const checked = linked.assertSignedRoster(roster);
  const root = checked.devices.find((entry) => entry.certificate.devicePublicKey === account.publicKey);
  assert.strictEqual(root && root.certificate.platform, 'web');
});

test('pairing QR подписан устройством, имеет TTL и одинаковый шестизначный код', () => {
  const device = identity();
  const now = 10_000;
  const request = linked.createPairingRequest(
    {
      deviceId: linked.deriveDeviceId(device.publicKey),
      devicePublicKey: device.publicKey,
      deviceSignPublicKey: device.signPublicKey,
      name: 'Компьютер Windows',
      platform: 'windows',
      relays: PAIRING_RELAYS,
      capabilities: ['messages', 'files', 'voice', 'history-sync', 'notifications'],
      createdAt: now,
    },
    device.signSecretKey,
    (length) => new Uint8Array(length).fill(7)
  );
  const qr = linked.encodePairingQr(request);
  assert.ok(qr.startsWith(linked.PAIRING_QR_BINARY_PREFIX));
  assert.strictEqual(qr.length, 289, `binary pairing QR changed size: ${qr.length}`);
  const decoded = linked.decodePairingQr(qr, { now: now + 1 });
  assert.deepStrictEqual(decoded, request);
  const compatQr = linked.encodePairingQrCompat(request);
  assert.ok(compatQr.startsWith(linked.PAIRING_QR_COMPACT_PREFIX));
  assert.deepStrictEqual(linked.decodePairingQr(compatQr, { now: now + 1 }), request);
  const legacyQr = linked.PAIRING_QR_PREFIX + Buffer.from(linked.stableStringify(request), 'utf8').toString('base64url');
  assert.deepStrictEqual(linked.decodePairingQr(legacyQr, { now: now + 1 }), request);
  assert.match(linked.verificationCode(request), /^\d{2} · \d{2} · \d{2}$/);
  assert.strictEqual(linked.verificationCode(decoded), linked.verificationCode(request));
  assert.throws(() => linked.decodePairingQr(qr, { now: request.expiresAt + linked.PAIRING_CLOCK_SKEW_MS + 1 }), /expired/);
  const changed = `${qr.slice(0, -1)}${qr.endsWith('0') ? '1' : '0'}`;
  assert.throws(() => linked.decodePairingQr(changed, { now: now + 1 }), /signature|invalid/);
  assert.throws(() => linked.decodePairingQr(`${linked.PAIRING_QR_BINARY_PREFIX}0`), /invalid/);
});

test('pairing QR v4 сохраняет нестандартное имя, relay и сокращённый TTL', () => {
  const device = identity();
  const now = 30_000;
  const request = linked.createPairingRequest(
    {
      deviceId: linked.deriveDeviceId(device.publicKey),
      devicePublicKey: device.publicKey,
      deviceSignPublicKey: device.signPublicKey,
      name: 'Рабочая станция',
      platform: 'linux',
      relays: ['wss://relay.example', 'wss://backup.example/ws'],
      capabilities: ['messages', 'files', 'notifications'],
      createdAt: now,
      expiresAt: now + 60_000,
    },
    device.signSecretKey,
    (length) => new Uint8Array(length).fill(19)
  );
  const qr = linked.encodePairingQr(request);
  assert.deepStrictEqual(linked.decodePairingQr(qr, { now: now + 1 }), request);
});

/**
 * ПРВ-1: срок жизни QR входит в ПОДПИСАННЫЕ данные и в компактный формат.
 *
 * В v4 «срок по умолчанию» едет одним битом: декодер разворачивает его в
 * PAIRING_TTL_MS СВОЕЙ версии. Значит смена этой константы разводит версии —
 * подпись у них не сойдётся, и QR чужой версии просто не отсканируется. Это
 * намеренный размен (телефон прежней версии не умеет требовать код подключения),
 * но он обязан быть зафиксирован проверкой, а не остаться сюрпризом.
 */
test('ПРВ-1: срок жизни QR — 90 секунд, прежний двухминутный запрос не собирается', () => {
  const device = identity();
  const now = 40_000;
  const base = {
    deviceId: linked.deriveDeviceId(device.publicKey),
    devicePublicKey: device.publicKey,
    deviceSignPublicKey: device.signPublicKey,
    name: 'Компьютер Windows',
    platform: 'windows',
    relays: PAIRING_RELAYS,
    capabilities: ['messages', 'files'],
    createdAt: now,
  };
  assert.strictEqual(linked.PAIRING_TTL_MS, 90_000);
  const request = linked.createPairingRequest(base, device.signSecretKey, (length) => new Uint8Array(length).fill(5));
  assert.strictEqual(request.expiresAt - request.createdAt, 90_000, 'срок по умолчанию — полторы минуты');
  assert.throws(
    () => linked.createPairingRequest({ ...base, expiresAt: now + 120_000 }, device.signSecretKey),
    /pairing expiry is invalid/
  );
  // Бит «срок по умолчанию» действительно используется: QR не растёт от TTL.
  const decoded = linked.decodePairingQr(linked.encodePairingQr(request), { now: now + 1 });
  assert.deepStrictEqual(decoded, request);
});

/**
 * ПРВ-1: код подключения на уровне протокола.
 *
 * Здесь проверяется то, ради чего он появился: из одного лишь QR доказательство
 * не собирается. Всё остальное (пространство кода, нормализация ввода,
 * разделение направлений) — в test/devicePairing.test.js; проверка того, что без
 * доказательства привязка не начинается, — в test/deviceSyncHistory.test.js.
 */
test('ПРВ-1: доказательство кода подключения не выводится из содержимого QR', () => {
  const device = identity();
  const request = linked.createPairingRequest(
    {
      deviceId: linked.deriveDeviceId(device.publicKey),
      devicePublicKey: device.publicKey,
      deviceSignPublicKey: device.signPublicKey,
      name: 'Компьютер Windows',
      platform: 'windows',
      relays: PAIRING_RELAYS,
      capabilities: ['messages', 'files'],
      createdAt: 50_000,
    },
    device.signSecretKey
  );
  const challenge = encodeBase64(new Uint8Array(32).fill(3));
  const code = linked.generateLinkCode(nacl.randomBytes);
  const proof = linked.pairingLinkProof(request, challenge, code);

  // Всё, что есть у держателя QR: сам запрос, вызов телефона и любые коды, кроме
  // настоящего. Ни одна комбинация не даёт того же доказательства.
  for (let candidate = 0; candidate < 200; candidate += 1) {
    const guess = String(candidate).padStart(6, '0');
    if (guess === code) continue;
    assert.ok(!linked.linkProofsMatch(linked.pairingLinkProof(request, challenge, guess), proof));
  }
  assert.ok(linked.linkProofsMatch(linked.pairingLinkProof(request, challenge, code), proof));
  assert.notStrictEqual(linked.pairingLinkConfirmation(request, challenge, code), proof);
  assert.strictEqual(linked.LINK_CODE_DIGITS, 6);
  assert.strictEqual(linked.LINK_CODE_MAX_ATTEMPTS, 3);
});

test('pairing QR отвергает изменение имени после подписи', () => {
  const device = identity();
  const request = linked.createPairingRequest(
    {
      deviceId: linked.deriveDeviceId(device.publicKey),
      devicePublicKey: device.publicKey,
      deviceSignPublicKey: device.signPublicKey,
      name: 'Мой ПК',
      platform: 'linux',
      relays: ['wss://relay.example'],
      capabilities: ['messages', 'files', 'voice', 'history-sync', 'notifications'],
      createdAt: 20_000,
    },
    device.signSecretKey
  );
  assert.ok(!linked.verifyPairingRequest({ ...request, name: 'Чужой ПК' }, { now: 20_001 }));
});

// --- КРИТ-04: право переписать список устройств — до проверки подписей -------
//
// Правило вынесено отдельно ровно затем, чтобы его можно было прогнать по всей
// таблице входов. В самом релее до него не добраться: нужен поднятый узел,
// доказанное соединение и валидно подписанный ростер — а проверяются здесь как
// раз те случаи, где подписи заведомо нет.

test('КРИТ-04: владелец известного аккаунта с тем же корневым ключом — можно', () => {
  const account = identity();
  const gate = linked.rosterWriteGate(
    { accountPublicKey: account.publicKey, accountSignPublicKey: account.signPublicKey },
    { proven: true, sessionPublicKey: account.publicKey, knownAccountSignPublicKey: account.signPublicKey }
  );
  assert.deepStrictEqual(gate, { ok: true });
});

test('КРИТ-04: чужое устройство того же аккаунта тоже пишет ростер', () => {
  // Компьютер подключён своим адресом, а ростер аккаунта переписывает от имени
  // аккаунта. Требуй правило совпадения адресов — привязка второго устройства
  // перестала бы работать вовсе.
  const account = identity();
  const desktop = identity();
  const gate = linked.rosterWriteGate(
    { accountPublicKey: account.publicKey, accountSignPublicKey: account.signPublicKey },
    { proven: true, sessionPublicKey: desktop.publicKey, knownAccountSignPublicKey: account.signPublicKey }
  );
  assert.deepStrictEqual(gate, { ok: true });
});

test('КРИТ-04: первичное создание аккаунта — только из доказанного корневого сеанса', () => {
  const account = identity();
  const base = { accountPublicKey: account.publicKey, accountSignPublicKey: account.signPublicKey };
  const rootSession = {
    proven: true,
    sessionPublicKey: account.publicKey,
    knownAccountSignPublicKey: null,
    boundRootSignPublicKey: account.signPublicKey,
  };
  assert.deepStrictEqual(linked.rosterWriteGate(base, rootSession), { ok: true });
  // Без доказательства владения адресом — нельзя: иначе занявший незакреплённый
  // адрес заводил бы на нём аккаунт и получал все устройства жертвы.
  assert.strictEqual(linked.rosterWriteGate(base, { ...rootSession, proven: false }).ok, false);
  // С другого адреса — нельзя.
  assert.strictEqual(
    linked.rosterWriteGate(base, { ...rootSession, sessionPublicKey: identity().publicKey }).ok,
    false
  );
  // С чужим корневым ключом подписи — нельзя.
  assert.strictEqual(
    linked.rosterWriteGate(base, { ...rootSession, boundRootSignPublicKey: identity().signPublicKey }).ok,
    false
  );
});

test('КРИТ-04: корневой ключ известного аккаунта подменить нельзя', () => {
  const account = identity();
  const attacker = identity();
  const gate = linked.rosterWriteGate(
    { accountPublicKey: account.publicKey, accountSignPublicKey: attacker.signPublicKey },
    { proven: true, sessionPublicKey: account.publicKey, knownAccountSignPublicKey: account.signPublicKey }
  );
  assert.deepStrictEqual(gate, { ok: false, reason: 'root-key-conflict' });
});

test('КРИТ-04: причина отказа не рассказывает постороннему про чужой аккаунт', () => {
  // «Корневой ключ не тот» означает «аккаунт узлу известен», «нужен корневой
  // сеанс» — «неизвестен». Раньше добраться до этих ответов без валидной
  // подписи было нельзя: до них просто не доходило. Теперь проверка идёт
  // ПЕРВОЙ, и если отвечать точно всем, любой назвавшийся чужим адресом
  // спрашивал бы у релея, заводил ли там аккаунт конкретный человек.
  const account = identity();
  const stranger = identity();
  const outsider = { proven: true, sessionPublicKey: stranger.publicKey };

  const known = linked.rosterWriteGate(
    { accountPublicKey: account.publicKey, accountSignPublicKey: identity().signPublicKey },
    { ...outsider, knownAccountSignPublicKey: account.signPublicKey }
  );
  const unknown = linked.rosterWriteGate(
    { accountPublicKey: account.publicKey, accountSignPublicKey: identity().signPublicKey },
    { ...outsider, knownAccountSignPublicKey: null, boundRootSignPublicKey: null }
  );
  assert.strictEqual(known.ok, false);
  assert.strictEqual(unknown.ok, false);
  assert.strictEqual(
    known.reason,
    unknown.reason,
    'известный и неизвестный аккаунт обязаны быть неразличимы для постороннего'
  );
  assert.strictEqual(known.reason, 'invalid-roster', 'и выглядеть как обычный негодный ростер');

  // А сидящему на самом адресе аккаунта точная причина по-прежнему говорится:
  // он и так знает всё про свой аккаунт, а без неё не понял бы, почему его
  // ростер не приняли. Воспользоваться этим со стороны нельзя: чтобы сюда
  // попасть, надо занять сам адрес, а закреплённый адрес занять не выйдет.
  const owner = linked.rosterWriteGate(
    { accountPublicKey: account.publicKey, accountSignPublicKey: identity().signPublicKey },
    { proven: true, sessionPublicKey: account.publicKey, knownAccountSignPublicKey: account.signPublicKey }
  );
  assert.strictEqual(owner.reason, 'root-key-conflict');
});

test('КРИТ-04: владелец адреса без доказательства получает подсказку, а не «негодный ростер»', () => {
  // Это самый частый отказ у живого человека: клиент ещё не предъявил
  // доказательство владения адресом, а ростер уже шлёт. Строка
  // «нужен корневой сеанс» — единственное, что объясняет ему, что делать.
  // Спрятать её ради приватности здесь нечего: чтобы её увидеть, надо уже
  // сидеть на этом самом адресе.
  const account = identity();
  const gate = linked.rosterWriteGate(
    { accountPublicKey: account.publicKey, accountSignPublicKey: account.signPublicKey },
    {
      proven: false,
      sessionPublicKey: account.publicKey,
      knownAccountSignPublicKey: null,
      boundRootSignPublicKey: account.signPublicKey,
    }
  );
  assert.deepStrictEqual(gate, { ok: false, reason: 'account-bootstrap-requires-root' });
});

test('КРИТ-04: мусор отвергается без единой криптографической операции', () => {
  // Ни одно из этих значений не должно доходить до разбора сертификатов: там
  // тридцать две проверки подписи на кадр, и назначать их вправе только тот,
  // у кого есть права.
  for (const junk of [null, undefined, {}, { accountPublicKey: '' }, { accountPublicKey: 42 }]) {
    assert.strictEqual(linked.rosterWriteGate(junk, { proven: true }).ok, false, JSON.stringify(junk));
  }
  assert.strictEqual(
    linked.rosterWriteGate({ accountPublicKey: 'x', accountSignPublicKey: '' }, { proven: true }).ok,
    false
  );
});

console.log(`\nlinked-devices: ${passed} tests passed`);
