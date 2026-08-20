'use strict';

const nacl = require('tweetnacl');
const { encodeBase64, decodeBase64, decodeUTF8 } = require('tweetnacl-util');
const ed25519 = require('./ed25519');
const LINKED_DEVICE_VERSION = 2;
const DEVICE_CERT_TYPE = 'licno-device-certificate';
const DEVICE_ROSTER_TYPE = 'licno-device-roster';

const MAX_ACTIVE_DEVICES = 10;
const MAX_ROSTER_ENTRIES = 32;

const CERT_DOMAIN = 'licno-device-certificate-v2|';
const ROSTER_DOMAIN = 'licno-device-roster-v2|';
const DEVICE_ID_DOMAIN = 'licno-device-id-v2|';
const CAPABILITIES = new Set(['messages', 'files', 'voice', 'history-sync', 'notifications']);
const PLATFORMS = new Set(['android', 'web', 'windows', 'macos', 'linux']);
function fail(message) {
  const error = new Error(message);
  error.code = 'LINKED_DEVICE_INVALID';
  throw error;
}

function isPlainObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function stableStringify(value) {
  function normalize(input) {
    if (input === null || typeof input === 'string' || typeof input === 'boolean') return input;
    if (typeof input === 'number') {
      if (!Number.isFinite(input)) fail('non-finite number');
      return input;
    }
    if (Array.isArray(input)) return input.map((item) => normalize(item));
    if (!isPlainObject(input)) fail('unsupported signed value');
    const out = {};
    for (const key of Object.keys(input).sort()) {
      const item = input[key];
      if (typeof item === 'undefined' || typeof item === 'function' || typeof item === 'symbol') {
        fail('unsupported signed field');
      }
      out[key] = normalize(item);
    }
    return out;
  }
  return JSON.stringify(normalize(value));
}

function decodeExact(value, bytes, label) {
  if (typeof value !== 'string' || !value || value.length > 256) fail(`${label} is required`);
  let decoded;
  try {
    decoded = decodeBase64(value);
  } catch (error) {
    fail(`${label} is not base64`);
  }
  if (decoded.length !== bytes) fail(`${label} has invalid length`);
  return decoded;
}
function cleanText(value, label, max = 64) {
  if (typeof value !== 'string') fail(`${label} is required`);
  const clean = [...value]
    .filter((char) => {
      const code = char.charCodeAt(0);
      return code > 31 && code !== 127;
    })
    .join('')
    .trim();
  if (!clean || [...clean].length > max) fail(`${label} has invalid length`);
  if (clean !== value) fail(`${label} is not canonical`);
  return clean;
}
function cleanTimestamp(value, label) {
  if (!Number.isSafeInteger(value) || value < 1) fail(`${label} is invalid`);
  return value;
}
function toBase64Url(bytes) {
  return encodeBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
function signPayload(domain, payload, secretKey) {
  const sk = decodeExact(secretKey, nacl.sign.secretKeyLength, 'sign secret key');
  const bytes = decodeUTF8(domain + stableStringify(payload));
  return encodeBase64(ed25519.sign(bytes, sk));
}
function verifyPayload(domain, payload, signature, publicKey) {
  try {
    const sig = decodeExact(signature, nacl.sign.signatureLength, 'signature');
    const pk = decodeExact(publicKey, nacl.sign.publicKeyLength, 'sign public key');
    return ed25519.verify(decodeUTF8(domain + stableStringify(payload)), sig, pk);
  } catch (error) {
    return false;
  }
}
function deriveDeviceId(devicePublicKey) {
  decodeExact(devicePublicKey, nacl.box.publicKeyLength, 'device public key');
  const hash = nacl.hash(decodeUTF8(DEVICE_ID_DOMAIN + devicePublicKey));
  return toBase64Url(hash.slice(0, 16));
}
function normalizeCapabilities(value) {
  if (!Array.isArray(value)) fail('capabilities must be an array');
  const result = [...new Set(value.map((item) => cleanText(item, 'capability', 32)))].sort();
  if (!result.length || result.some((item) => !CAPABILITIES.has(item))) fail('unsupported capability');
  return result;
}
function certificatePayload(input) {
  if (!isPlainObject(input)) fail('certificate must be an object');
  const accountPublicKey = input.accountPublicKey;
  const accountSignPublicKey = input.accountSignPublicKey;
  const devicePublicKey = input.devicePublicKey;
  const deviceSignPublicKey = input.deviceSignPublicKey;
  decodeExact(accountPublicKey, nacl.box.publicKeyLength, 'account public key');
  decodeExact(accountSignPublicKey, nacl.sign.publicKeyLength, 'account sign public key');
  decodeExact(devicePublicKey, nacl.box.publicKeyLength, 'device public key');
  decodeExact(deviceSignPublicKey, nacl.sign.publicKeyLength, 'device sign public key');
  const deviceId = cleanText(input.deviceId, 'device id', 64);
  if (deviceId !== deriveDeviceId(devicePublicKey)) fail('device id does not match device key');
  const platform = cleanText(input.platform, 'platform', 16).toLowerCase();
  if (!PLATFORMS.has(platform)) fail('unsupported platform');
  return {
    v: LINKED_DEVICE_VERSION,
    type: DEVICE_CERT_TYPE,
    accountPublicKey,
    accountSignPublicKey,
    deviceId,
    devicePublicKey,
    deviceSignPublicKey,
    name: cleanText(input.name, 'device name'),
    platform,
    issuedAt: cleanTimestamp(input.issuedAt, 'issuedAt'),
    capabilities: normalizeCapabilities(input.capabilities),
  };
}
function createDeviceCertificate(input, accountSignSecretKey) {
  const payload = certificatePayload(input);
  return { ...payload, rootSignature: signPayload(CERT_DOMAIN, payload, accountSignSecretKey) };
}
function assertDeviceCertificate(certificate, options = {}) {
  const payload = certificatePayload(certificate);
  const expectedAccount = options.accountPublicKey;
  const expectedRootSign = options.accountSignPublicKey;
  if (expectedAccount && payload.accountPublicKey !== expectedAccount) fail('certificate belongs to another account');
  if (expectedRootSign && payload.accountSignPublicKey !== expectedRootSign) fail('certificate has another root key');
  if (!verifyPayload(CERT_DOMAIN, payload, certificate.rootSignature, payload.accountSignPublicKey)) {
    fail('bad device certificate signature');
  }
  return { ...payload, rootSignature: certificate.rootSignature };
}
function verifyDeviceCertificate(certificate, options = {}) {
  try {
    assertDeviceCertificate(certificate, options);
    return true;
  } catch (error) {
    return false;
  }
}
function normalizeRosterEntries(entries, accountPublicKey, accountSignPublicKey) {
  if (!Array.isArray(entries) || !entries.length || entries.length > MAX_ROSTER_ENTRIES) {
    fail('roster has invalid device count');
  }
  const seenIds = new Set();
  const seenKeys = new Set();
  const normalized = entries.map((entry) => {
    if (!isPlainObject(entry)) fail('invalid roster entry');
    const certificate = assertDeviceCertificate(entry.certificate, { accountPublicKey, accountSignPublicKey });
    if (seenIds.has(certificate.deviceId) || seenKeys.has(certificate.devicePublicKey)) fail('duplicate roster device');
    seenIds.add(certificate.deviceId);
    seenKeys.add(certificate.devicePublicKey);
    let revokedAt = null;
    if (entry.revokedAt !== null && typeof entry.revokedAt !== 'undefined') {
      revokedAt = cleanTimestamp(entry.revokedAt, 'revokedAt');
      if (revokedAt < certificate.issuedAt) fail('device revoked before it was issued');
    }
    return { certificate, revokedAt };
  });
  normalized.sort((a, b) => a.certificate.deviceId.localeCompare(b.certificate.deviceId));
  const active = normalized.filter((entry) => entry.revokedAt === null);
  if (!active.length || active.length > MAX_ACTIVE_DEVICES) fail('roster has invalid active device count');
  const primary = active.find(
    (entry) =>
      entry.certificate.devicePublicKey === accountPublicKey &&
      entry.certificate.deviceSignPublicKey === accountSignPublicKey
  );
  if (!primary) fail('active primary device is required');
  return normalized;
}
function rosterPayload(input) {
  if (!isPlainObject(input)) fail('roster must be an object');
  decodeExact(input.accountPublicKey, nacl.box.publicKeyLength, 'account public key');
  decodeExact(input.accountSignPublicKey, nacl.sign.publicKeyLength, 'account sign public key');
  const version = input.version;
  if (!Number.isSafeInteger(version) || version < 1) fail('roster version is invalid');
  const updatedAt = cleanTimestamp(input.updatedAt, 'updatedAt');
  return {
    v: LINKED_DEVICE_VERSION,
    type: DEVICE_ROSTER_TYPE,
    accountPublicKey: input.accountPublicKey,
    accountSignPublicKey: input.accountSignPublicKey,
    version,
    updatedAt,
    devices: normalizeRosterEntries(input.devices, input.accountPublicKey, input.accountSignPublicKey),
  };
}
function createSignedRoster(input, accountSignSecretKey) {
  const payload = rosterPayload(input);
  return { ...payload, rootSignature: signPayload(ROSTER_DOMAIN, payload, accountSignSecretKey) };
}
function assertSignedRoster(roster, options = {}) {
  const payload = rosterPayload(roster);
  if (options.accountPublicKey && payload.accountPublicKey !== options.accountPublicKey) fail('roster belongs to another account');
  if (options.accountSignPublicKey && payload.accountSignPublicKey !== options.accountSignPublicKey) fail('roster has another root key');
  if (Number.isSafeInteger(options.minVersion) && payload.version < options.minVersion) fail('stale roster');
  if (!verifyPayload(ROSTER_DOMAIN, payload, roster.rootSignature, payload.accountSignPublicKey)) {
    fail('bad roster signature');
  }
  return { ...payload, rootSignature: roster.rootSignature };
}
function rosterWriteGate(claimed, session = {}) {
  const accountPublicKey = claimed && claimed.accountPublicKey;
  const accountSignPublicKey = claimed && claimed.accountSignPublicKey;
  const onOwnAddress = !!accountPublicKey && session.sessionPublicKey === accountPublicKey;
  const deny = (reason) => ({ ok: false, reason: onOwnAddress ? reason : 'invalid-roster' });
  if (typeof accountPublicKey !== 'string' || !accountPublicKey) {
    return { ok: false, reason: 'invalid-roster' };
  }
  if (typeof accountSignPublicKey !== 'string' || !accountSignPublicKey) {
    return { ok: false, reason: 'invalid-roster' };
  }
  if (session.knownAccountSignPublicKey) {
    return session.knownAccountSignPublicKey === accountSignPublicKey
      ? { ok: true }
      : deny('root-key-conflict');
  }
  const bootstrap =
    !!session.proven && onOwnAddress && session.boundRootSignPublicKey === accountSignPublicKey;
  return bootstrap ? { ok: true } : deny('account-bootstrap-requires-root');
}
function verifySignedRoster(roster, options = {}) {
  try {
    assertSignedRoster(roster, options);
    return true;
  } catch (error) {
    return false;
  }
}
module.exports = {
  LINKED_DEVICE_VERSION,
  DEVICE_CERT_TYPE,
  DEVICE_ROSTER_TYPE,
  MAX_ACTIVE_DEVICES,
  MAX_ROSTER_ENTRIES,
  stableStringify,
  deriveDeviceId,
  createDeviceCertificate,
  assertDeviceCertificate,
  verifyDeviceCertificate,
  createSignedRoster,
  assertSignedRoster,
  verifySignedRoster,
  rosterWriteGate,
};