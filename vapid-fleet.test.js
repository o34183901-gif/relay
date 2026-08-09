/**
 * Unit tests for the fleet VAPID protocol. No network calls: exercise the
 * signed bundle, member authorization and end-to-end NaCl-box exchange.
 */
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const nacl = require('tweetnacl');
const naclUtil = require('tweetnacl-util');
const { generateVapidKeys } = require('./push');
const {
  loadFleetConfig,
  memberFor,
  memberAcceptsKey,
  validVapidPair,
  signVapidBundle,
  verifyVapidBundle,
  createVapidRequest,
  verifyVapidRequest,
  createVapidResponse,
  openVapidResponse,
  sourceMatchesResolved,
  readJsonFile,
  writeJsonAtomic,
} = require('./vapid-fleet');

let passed = 0;
function test(name, fn) {
  fn();
  passed++;
  console.log('  ✓ ' + name);
}

console.log('vapid fleet (signed P2P bootstrap)');

const genesisKeys = nacl.sign.keyPair();
const followerKeys = nacl.sign.keyPair();
const dynamicKeys = nacl.sign.keyPair();
const b64 = (bytes) => naclUtil.encodeBase64(bytes);
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'licno-vapid-fleet-'));
const configPath = path.join(tmp, 'vapid-fleet.json');
const bundlePath = path.join(tmp, 'vapid.json');

fs.writeFileSync(
  configPath,
  JSON.stringify({
    version: 1,
    fleetId: 'test-fleet',
    epoch: 1,
    genesis: 'wss://genesis.example.com',
    relays: [
      { url: 'wss://genesis.example.com', relayPub: b64(genesisKeys.publicKey) },
      { url: 'wss://follower.example.com', relayPub: b64(followerKeys.publicKey) },
      { url: 'wss://new.example.com', allowDynamicKey: true },
    ],
  })
);
const config = loadFleetConfig(configPath);

function configFile(name, value) {
  const filename = path.join(tmp, name);
  fs.writeFileSync(filename, JSON.stringify(value));
  return filename;
}

try {
  test('fleet config loads pinned genesis and dynamic future member', () => {
    assert.strictEqual(config.genesis, 'wss://genesis.example.com');
    assert.strictEqual(memberFor(config, 'wss://FOLLOWER.example.com/').relayPub, b64(followerKeys.publicKey));
    assert.strictEqual(memberFor(config, 'wss://new.example.com').allowDynamicKey, true);
  });

  test('fleet config rejects every malformed trust boundary', () => {
    const base = {
      version: 1,
      fleetId: 'invalid-cases',
      epoch: 1,
      genesis: 'wss://genesis.example.com',
      relays: [{ url: 'wss://genesis.example.com', relayPub: b64(genesisKeys.publicKey) }],
    };
    const invalid = [
      { ...base, version: 2 },
      { ...base, relays: [] },
      { ...base, relays: [{ url: 'wss://%', relayPub: b64(genesisKeys.publicKey) }] },
      { ...base, relays: [{ url: 'wss://genesis.example.com', relayPub: 'broken' }] },
      { ...base, relays: [{ url: 'wss://genesis.example.com' }] },
      { ...base, genesis: 'wss://other.example.com' },
    ];
    invalid.forEach((value, index) => {
      assert.throws(() => loadFleetConfig(configFile(`invalid-${index}.json`, value)), /vapid-fleet/);
    });
    const throwingString = { toString() { throw new Error('bad base64 input'); } };
    assert.strictEqual(memberAcceptsKey({ relayPub: null }, throwingString), false);
    assert.strictEqual(validVapidPair(throwingString, 'x'), false);
  });

  const vapid = generateVapidKeys();
  let bundle;
  test('genesis signs a valid VAPID pair and tampering is rejected', () => {
    assert.strictEqual(validVapidPair(vapid.publicKey, vapid.privateKey), true);
    bundle = signVapidBundle(vapid, config, genesisKeys.secretKey, 1700000000000);
    assert.strictEqual(verifyVapidBundle(bundle, config), true);
    assert.strictEqual(verifyVapidBundle({ ...bundle, publicKey: bundle.publicKey.slice(1) }, config), false);
    assert.strictEqual(verifyVapidBundle({ ...bundle, epoch: 2 }, config), false);
    assert.strictEqual(verifyVapidBundle(bundle, { ...config, relays: [] }), false);
  });

  test('allowed follower performs signed request and decrypts the exact genesis bundle', () => {
    const pending = createVapidRequest({
      config,
      relayUrl: 'wss://follower.example.com',
      relayPub: b64(followerKeys.publicKey),
      relaySecret: followerKeys.secretKey,
      now: 1700000001000,
    });
    assert.ok(verifyVapidRequest(pending.request, config, 1700000002000));
    const response = createVapidResponse({
      config,
      request: pending.request,
      bundle,
      senderUrl: config.genesis,
      senderRelayPub: b64(genesisKeys.publicKey),
      senderRelaySecret: genesisKeys.secretKey,
    });
    const opened = openVapidResponse({
      config,
      request: pending.request,
      response,
      boxSecret: pending.boxSecret,
    });
    assert.deepStrictEqual(opened, bundle);
    const corrupted = { ...response, ciphertext: response.ciphertext.slice(0, -2) + 'AA' };
    assert.strictEqual(
      openVapidResponse({ config, request: pending.request, response: corrupted, boxSecret: pending.boxSecret }),
      null
    );
    assert.strictEqual(verifyVapidRequest(null, config), null);
    assert.strictEqual(
      verifyVapidRequest(new Proxy({}, { get() { throw new Error('request getter'); } }), config),
      null
    );
    assert.throws(() => createVapidResponse({
      config,
      request: { ...pending.request, boxPub: 'broken' },
      bundle,
      senderUrl: config.genesis,
      senderRelayPub: b64(genesisKeys.publicKey),
      senderRelaySecret: genesisKeys.secretKey,
    }), /response keys/);
    assert.strictEqual(openVapidResponse({ config, request: pending.request, response: null, boxSecret: pending.boxSecret }), null);
    assert.strictEqual(
      openVapidResponse({
        config,
        request: pending.request,
        response: new Proxy({}, { get() { throw new Error('response getter'); } }),
        boxSecret: pending.boxSecret,
      }),
      null
    );
  });

  test('unknown identity is rejected, pre-authorized dynamic server is accepted', () => {
    const stranger = nacl.sign.keyPair();
    assert.throws(() =>
      createVapidRequest({
        config,
        relayUrl: 'wss://follower.example.com',
        relayPub: b64(stranger.publicKey),
        relaySecret: stranger.secretKey,
      })
    );
    const dynamic = createVapidRequest({
      config,
      relayUrl: 'wss://new.example.com',
      relayPub: b64(dynamicKeys.publicKey),
      relaySecret: dynamicKeys.secretKey,
    });
    assert.ok(verifyVapidRequest(dynamic.request, config));
  });

  test('source IP comparison handles IPv4-mapped IPv6 and rejects another host', () => {
    assert.strictEqual(sourceMatchesResolved('::ffff:203.0.113.7', [{ address: '203.0.113.7' }]), true);
    assert.strictEqual(sourceMatchesResolved('203.0.113.8', [{ address: '203.0.113.7' }]), false);
  });

  test('bundle persistence is atomic and readable', () => {
    writeJsonAtomic(bundlePath, bundle);
    assert.deepStrictEqual(readJsonFile(bundlePath), bundle);
    assert.strictEqual(verifyVapidBundle(readJsonFile(bundlePath), config), true);
    assert.strictEqual(readJsonFile(path.join(tmp, 'missing.json')), null);
  });

  console.log(`\nvapid fleet: ${passed} passed`);
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}
