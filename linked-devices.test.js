'use strict';

const assert = require('assert');
const nacl = require('tweetnacl');
const { encodeBase64 } = require('tweetnacl-util');
const linked = require('./linked-devices');

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
      name: 'Windows 11',
      platform: 'windows',
      relays: ['wss://relay.example'],
      capabilities: ['messages', 'files', 'voice', 'history-sync', 'notifications'],
      createdAt: now,
    },
    device.signSecretKey,
    (length) => new Uint8Array(length).fill(7)
  );
  const qr = linked.encodePairingQr(request);
  const decoded = linked.decodePairingQr(qr, { now: now + 1 });
  assert.deepStrictEqual(decoded, request);
  assert.match(linked.verificationCode(request), /^\d{2} · \d{2} · \d{2}$/);
  assert.strictEqual(linked.verificationCode(decoded), linked.verificationCode(request));
  assert.throws(() => linked.decodePairingQr(qr, { now: request.expiresAt + linked.PAIRING_CLOCK_SKEW_MS + 1 }), /expired/);
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

console.log(`\nlinked-devices: ${passed} tests passed`);
