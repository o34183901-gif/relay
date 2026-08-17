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
      name: 'Устройство прежней сборки',
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
  const second = identity();
  const primary = certificate(account, account, { name: 'Телефон Android', platform: 'android' });
  const secondary = certificate(account, second);
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

test('web/iPhone может быть основным устройством при втором устройстве прежней сборки', () => {
  const account = identity();
  const second = identity();
  const primary = certificate(account, account, { name: 'iPhone web', platform: 'web' });
  const secondary = certificate(account, second, { name: 'Устройство прежней сборки', platform: 'windows' });
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

test('КРИТ-04: владелец известного аккаунта с тем же корневым ключом — можно', () => {
  const account = identity();
  const gate = linked.rosterWriteGate(
    { accountPublicKey: account.publicKey, accountSignPublicKey: account.signPublicKey },
    { proven: true, sessionPublicKey: account.publicKey, knownAccountSignPublicKey: account.signPublicKey }
  );
  assert.deepStrictEqual(gate, { ok: true });
});

test('КРИТ-04: чужое устройство того же аккаунта тоже пишет ростер', () => {
  const account = identity();
  const second = identity();
  const gate = linked.rosterWriteGate(
    { accountPublicKey: account.publicKey, accountSignPublicKey: account.signPublicKey },
    { proven: true, sessionPublicKey: second.publicKey, knownAccountSignPublicKey: account.signPublicKey }
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
  assert.strictEqual(linked.rosterWriteGate(base, { ...rootSession, proven: false }).ok, false);
  assert.strictEqual(
    linked.rosterWriteGate(base, { ...rootSession, sessionPublicKey: identity().publicKey }).ok,
    false
  );
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
  const owner = linked.rosterWriteGate(
    { accountPublicKey: account.publicKey, accountSignPublicKey: identity().signPublicKey },
    { proven: true, sessionPublicKey: account.publicKey, knownAccountSignPublicKey: account.signPublicKey }
  );
  assert.strictEqual(owner.reason, 'root-key-conflict');
});
test('КРИТ-04: владелец адреса без доказательства получает подсказку, а не «негодный ростер»', () => {
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
  for (const junk of [null, undefined, {}, { accountPublicKey: '' }, { accountPublicKey: 42 }]) {
    assert.strictEqual(linked.rosterWriteGate(junk, { proven: true }).ok, false, JSON.stringify(junk));
  }
  assert.strictEqual(
    linked.rosterWriteGate({ accountPublicKey: 'x', accountSignPublicKey: '' }, { proven: true }).ok,
    false
  );
});
console.log(`\nlinked-devices: ${passed} tests passed`);