/**
 * Integration: start two real relay processes on loopback. Genesis creates the
 * bundle, follower obtains it through POST /vapid-fleet and persists the same
 * signed VAPID without any filesystem sharing.
 */
const assert = require('assert');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const nacl = require('tweetnacl');
const naclUtil = require('tweetnacl-util');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'licno-vapid-p2p-'));
const genesisPort = 8811 + (process.pid % 100);
const followerPort = genesisPort + 100;
const genesisUrl = `ws://127.0.0.1:${genesisPort}`;
const followerUrl = `ws://127.0.0.1:${followerPort}`;
const genesisKeys = nacl.sign.keyPair();
const followerKeys = nacl.sign.keyPair();
const b64 = (bytes) => naclUtil.encodeBase64(bytes);
const configPath = path.join(tmp, 'fleet.json');

fs.writeFileSync(
  configPath,
  JSON.stringify({
    version: 1,
    fleetId: 'integration-fleet',
    epoch: 1,
    genesis: genesisUrl,
    relays: [
      { url: genesisUrl, relayPub: b64(genesisKeys.publicKey) },
      { url: followerUrl, relayPub: b64(followerKeys.publicKey) },
    ],
  })
);

function startRelay(name, port, selfUrl, keys) {
  const dir = path.join(tmp, name);
  fs.mkdirSync(dir, { recursive: true });
  return spawn('node', [path.join(__dirname, 'relay.js')], {
    env: {
      ...process.env,
      PORT: String(port),
      RELAY_DB: path.join(dir, 'relay.db'),
      RELAY_BLOB_DIR: path.join(dir, 'blobs'),
      RELAY_VAPID_KEY_FILE: path.join(dir, 'vapid.json'),
      RELAY_VAPID_FLEET_FILE: configPath,
      RELAY_VAPID_FLEET_ALLOW_PRIVATE: '1',
      RELAY_VAPID_SYNC_MS: '10000',
      RELAY_SELF_URL: selfUrl,
      RELAY_SIGN_SECRET: b64(keys.secretKey),
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

function stopRelay(child) {
  return new Promise((resolve) => {
    if (!child || child.exitCode !== null) return resolve();
    const timer = setTimeout(() => {
      try {
        child.kill('SIGKILL');
      } catch (e) {}
      resolve();
    }, 3000);
    child.once('exit', () => {
      clearTimeout(timer);
      resolve();
    });
    try {
      child.kill();
    } catch (e) {
      clearTimeout(timer);
      resolve();
    }
  });
}

function health(port) {
  return new Promise((resolve) => {
    const req = http.get({ host: '127.0.0.1', port, path: '/health', timeout: 1000 }, (res) => {
      let body = '';
      res.on('data', (chunk) => (body += chunk));
      res.on('end', () => {
        try {
          resolve(res.statusCode === 200 ? JSON.parse(body) : null);
        } catch (e) {
          resolve(null);
        }
      });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => req.destroy());
  });
}

async function waitFor(check, timeoutMs = 20000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const value = await check();
    if (value) return value;
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error('timeout');
}

async function main() {
  const follower = startRelay('follower', followerPort, followerUrl, followerKeys);
  let genesis = null;
  let logs = '';
  follower.stdout.on('data', (x) => (logs += `[follower] ${x}`));
  follower.stderr.on('data', (x) => (logs += `[follower:err] ${x}`));

  try {
    const waiting = await waitFor(async () => health(followerPort));
    assert.strictEqual(waiting.vapid, false);
    assert.strictEqual(fs.existsSync(path.join(tmp, 'follower', 'vapid.json')), false);
    console.log('  ✓ follower waits without generating a conflicting local VAPID');

    genesis = startRelay('genesis', genesisPort, genesisUrl, genesisKeys);
    genesis.stdout.on('data', (x) => (logs += `[genesis] ${x}`));
    genesis.stderr.on('data', (x) => (logs += `[genesis:err] ${x}`));
    const g = await waitFor(async () => {
      const value = await health(genesisPort);
      return value && value.vapid ? value : null;
    });
    const f = await waitFor(async () => {
      const value = await health(followerPort);
      return value && value.vapid && value.vapidPublicKey === g.vapidPublicKey ? value : null;
    });
    assert.strictEqual(g.vapidSource, 'fleet-genesis');
    assert.ok(String(f.vapidSource).startsWith('fleet-peer:'));
    const genesisBundle = JSON.parse(fs.readFileSync(path.join(tmp, 'genesis', 'vapid.json'), 'utf8'));
    const followerBundle = JSON.parse(fs.readFileSync(path.join(tmp, 'follower', 'vapid.json'), 'utf8'));
    assert.deepStrictEqual(followerBundle, genesisBundle);
    console.log('  ✓ follower automatically received and persisted the genesis VAPID bundle');
  } catch (e) {
    console.error(logs);
    throw e;
  } finally {
    await Promise.all([stopRelay(genesis), stopRelay(follower)]);
    fs.rmSync(tmp, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
}

main().catch((e) => {
  console.error(e && e.stack ? e.stack : e);
  process.exitCode = 1;
});
