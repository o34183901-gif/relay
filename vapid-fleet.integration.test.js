const assert = require('assert');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const net = require('net');
const { spawn } = require('child_process');
const nacl = require('tweetnacl');
const naclUtil = require('tweetnacl-util');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'licno-vapid-p2p-'));
const genesisKeys = nacl.sign.keyPair();
const followerKeys = nacl.sign.keyPair();
const b64 = (bytes) => naclUtil.encodeBase64(bytes);
const configPath = path.join(tmp, 'fleet.json');
function freePorts(count) {
  const servers = [];
  const open = (index) =>
    new Promise((resolve, reject) => {
      const probe = net.createServer();
      probe.on('error', reject);
      probe.listen(0, '127.0.0.1', () => {
        servers[index] = probe;
        resolve(probe.address().port);
      });
    });
  return Promise.all(Array.from({ length: count }, (_, index) => open(index))).then(
    (ports) =>
      new Promise((resolve) => {
        let left = servers.length;
        for (const probe of servers) probe.close(() => (left -= 1) || resolve(ports));
      })
  );
}

function writeFleetConfig(genesisUrl, followerUrl) {
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
}

const running = new Set();
function startRelay(name, port, selfUrl, keys) {
  const dir = path.join(tmp, name);
  fs.mkdirSync(dir, { recursive: true });
  const child = spawn('node', [path.join(__dirname, 'relay.js')], {
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
  child.exitReason = null;
  child.on('exit', (code, signal) => {
    child.exitReason = signal ? `сигнал ${signal}` : `код ${code}`;
    running.delete(child);
  });
  running.add(child);
  return child;
}
process.on('exit', () => {
  for (const child of running) {
    try {
      child.kill('SIGKILL');
    } catch (e) {
    }
  }
});
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
async function waitFor(check, timeoutMs = 20000, describe = null) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const value = await check();
    if (value) return value;
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error(describe ? `timeout: ${describe()}` : 'timeout');
}
function waitForRelay(child, port, accept, what) {
  return waitFor(
    async () => {
      if (child.exitReason) {
        throw new Error(`${what}: релей не запустился (${child.exitReason}) — порт ${port} занят?`);
      }
      const value = await health(port);
      if (!value || !value.vapidFleetMember) return null;
      return accept(value) ? value : null;
    },
    20000,
    () => `${what} (порт ${port})`
  );
}
async function main() {
  const [genesisPort, followerPort] = await freePorts(2);
  const genesisUrl = `ws://127.0.0.1:${genesisPort}`;
  const followerUrl = `ws://127.0.0.1:${followerPort}`;
  writeFleetConfig(genesisUrl, followerUrl);
  const follower = startRelay('follower', followerPort, followerUrl, followerKeys);
  let genesis = null;
  let logs = '';
  follower.stdout.on('data', (x) => (logs += `[follower] ${x}`));
  follower.stderr.on('data', (x) => (logs += `[follower:err] ${x}`));
  try {
    const waiting = await waitForRelay(follower, followerPort, () => true, 'follower поднялся');
    assert.strictEqual(waiting.vapid, false);
    assert.strictEqual(fs.existsSync(path.join(tmp, 'follower', 'vapid.json')), false);
    console.log('  ✓ follower waits without generating a conflicting local VAPID');
    genesis = startRelay('genesis', genesisPort, genesisUrl, genesisKeys);
    genesis.stdout.on('data', (x) => (logs += `[genesis] ${x}`));
    genesis.stderr.on('data', (x) => (logs += `[genesis:err] ${x}`));
    const g = await waitForRelay(genesis, genesisPort, (value) => value.vapid, 'genesis собрал VAPID');
    const f = await waitForRelay(
      follower,
      followerPort,
      (value) => value.vapid && value.vapidPublicKey === g.vapidPublicKey,
      'follower получил VAPID от genesis'
    );
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
main()
  .then(() => {
    console.log('\nvapid fleet integration: 2 проверок пройдено');
  })
  .catch((e) => {
    console.error(e && e.stack ? e.stack : e);
    process.exitCode = 1;
  });