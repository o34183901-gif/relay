'use strict';

/**
 * Чистые криптографические контракты протокола связанных устройств v2.
 *
 * Модуль намеренно не зависит от сети, SQLite, React Native или Tauri. Один и тот
 * же файл используется релеем, Android-клиентом и desktop-клиентом, чтобы
 * канонизация подписываемых данных не расходилась между платформами.
 */
const nacl = require('tweetnacl');
const { encodeBase64, decodeBase64, encodeUTF8, decodeUTF8 } = require('tweetnacl-util');

const LINKED_DEVICE_VERSION = 2;
const DEVICE_CERT_TYPE = 'licno-device-certificate';
const DEVICE_ROSTER_TYPE = 'licno-device-roster';
const PAIRING_REQUEST_TYPE = 'licno-device-link-request';
const PAIRING_QR_PREFIX = 'licno://link-device/v2#';
const PAIRING_TTL_MS = 2 * 60 * 1000;
const PAIRING_CLOCK_SKEW_MS = 30 * 1000;
const MAX_ACTIVE_DEVICES = 10;
const MAX_ROSTER_ENTRIES = 32;

const CERT_DOMAIN = 'licno-device-certificate-v2|';
const ROSTER_DOMAIN = 'licno-device-roster-v2|';
const PAIRING_DOMAIN = 'licno-device-link-request-v2|';
const DEVICE_ID_DOMAIN = 'licno-device-id-v2|';
const VERIFY_CODE_DOMAIN = 'licno-device-verify-code-v2|';

const CAPABILITIES = new Set(['messages', 'files', 'voice', 'history-sync', 'notifications']);
const PLATFORMS = new Set(['android', 'web', 'windows', 'macos', 'linux']);
const DESKTOP_PLATFORMS = new Set(['windows', 'macos', 'linux']);

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

/** Стабильный JSON: ключи объектов сортируются, порядок массивов сохраняется. */
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
  return clean;
}

function cleanTimestamp(value, label) {
  if (!Number.isSafeInteger(value) || value < 1) fail(`${label} is invalid`);
  return value;
}

function toBase64Url(bytes) {
  return encodeBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function fromBase64Url(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) fail('invalid base64url');
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (value.length % 4)) % 4);
  try {
    return decodeBase64(padded);
  } catch (error) {
    fail('invalid base64url');
  }
}

function signPayload(domain, payload, secretKey) {
  const sk = decodeExact(secretKey, nacl.sign.secretKeyLength, 'sign secret key');
  const bytes = decodeUTF8(domain + stableStringify(payload));
  return encodeBase64(nacl.sign.detached(bytes, sk));
}

function verifyPayload(domain, payload, signature, publicKey) {
  try {
    const sig = decodeExact(signature, nacl.sign.signatureLength, 'signature');
    const pk = decodeExact(publicKey, nacl.sign.publicKeyLength, 'sign public key');
    return nacl.sign.detached.verify(decodeUTF8(domain + stableStringify(payload)), sig, pk);
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

function verifySignedRoster(roster, options = {}) {
  try {
    assertSignedRoster(roster, options);
    return true;
  } catch (error) {
    return false;
  }
}

function cleanRelays(relays) {
  if (!Array.isArray(relays) || !relays.length || relays.length > 8) fail('pairing relays are invalid');
  const out = [...new Set(relays.map((item) => cleanText(item, 'relay url', 256)))];
  for (const value of out) {
    let url;
    try {
      url = new URL(value);
    } catch (error) {
      fail('pairing relay URL is invalid');
    }
    if (url.protocol !== 'wss:' && url.protocol !== 'ws:') fail('pairing relay protocol is invalid');
    if (url.username || url.password || url.hash) fail('pairing relay URL is invalid');
  }
  return out;
}

function pairingPayload(input) {
  if (!isPlainObject(input)) fail('pairing request must be an object');
  decodeExact(input.devicePublicKey, nacl.box.publicKeyLength, 'device public key');
  decodeExact(input.deviceSignPublicKey, nacl.sign.publicKeyLength, 'device sign public key');
  const deviceId = cleanText(input.deviceId, 'device id', 64);
  if (deviceId !== deriveDeviceId(input.devicePublicKey)) fail('device id does not match device key');
  const platform = cleanText(input.platform, 'platform', 16).toLowerCase();
  if (!DESKTOP_PLATFORMS.has(platform)) fail('pairing platform is invalid');
  const createdAt = cleanTimestamp(input.createdAt, 'createdAt');
  const expiresAt = cleanTimestamp(input.expiresAt, 'expiresAt');
  if (expiresAt <= createdAt || expiresAt - createdAt > PAIRING_TTL_MS) fail('pairing expiry is invalid');
  decodeExact(input.nonce, 32, 'pairing nonce');
  decodeExact(input.pairingId, 18, 'pairing id');
  return {
    v: LINKED_DEVICE_VERSION,
    type: PAIRING_REQUEST_TYPE,
    pairingId: input.pairingId,
    deviceId,
    devicePublicKey: input.devicePublicKey,
    deviceSignPublicKey: input.deviceSignPublicKey,
    name: cleanText(input.name, 'device name'),
    platform,
    createdAt,
    expiresAt,
    nonce: input.nonce,
    relays: cleanRelays(input.relays),
    capabilities: normalizeCapabilities(input.capabilities),
  };
}

function createPairingRequest(input, deviceSignSecretKey, randomBytes = nacl.randomBytes) {
  const createdAt = input.createdAt || Date.now();
  const payload = pairingPayload({
    ...input,
    pairingId: input.pairingId || encodeBase64(randomBytes(18)),
    nonce: input.nonce || encodeBase64(randomBytes(32)),
    createdAt,
    expiresAt: input.expiresAt || createdAt + PAIRING_TTL_MS,
  });
  return { ...payload, requestSignature: signPayload(PAIRING_DOMAIN, payload, deviceSignSecretKey) };
}

function assertPairingRequest(request, options = {}) {
  const payload = pairingPayload(request);
  if (!verifyPayload(PAIRING_DOMAIN, payload, request.requestSignature, payload.deviceSignPublicKey)) {
    fail('bad pairing request signature');
  }
  const now = Number.isSafeInteger(options.now) ? options.now : Date.now();
  if (now < payload.createdAt - PAIRING_CLOCK_SKEW_MS) fail('pairing request is from the future');
  if (now > payload.expiresAt + PAIRING_CLOCK_SKEW_MS) fail('pairing request expired');
  return { ...payload, requestSignature: request.requestSignature };
}

function verifyPairingRequest(request, options = {}) {
  try {
    assertPairingRequest(request, options);
    return true;
  } catch (error) {
    return false;
  }
}

function encodePairingQr(request) {
  const valid = assertPairingRequest(request, { now: request.createdAt });
  return PAIRING_QR_PREFIX + toBase64Url(decodeUTF8(stableStringify(valid)));
}

function decodePairingQr(value, options = {}) {
  if (typeof value !== 'string' || !value.startsWith(PAIRING_QR_PREFIX)) fail('not a linked-device QR');
  const bytes = fromBase64Url(value.slice(PAIRING_QR_PREFIX.length));
  if (bytes.length > 8192) fail('pairing QR is too large');
  let parsed;
  try {
    parsed = JSON.parse(encodeUTF8(bytes));
  } catch (error) {
    fail('pairing QR is invalid');
  }
  return assertPairingRequest(parsed, options);
}

function verificationCode(request) {
  const payload = pairingPayload(request);
  const hash = nacl.hash(decodeUTF8(VERIFY_CODE_DOMAIN + stableStringify(payload)));
  const number = (((hash[0] << 16) | (hash[1] << 8) | hash[2]) >>> 0) % 1000000;
  const text = String(number).padStart(6, '0');
  return `${text.slice(0, 2)} · ${text.slice(2, 4)} · ${text.slice(4, 6)}`;
}

module.exports = {
  LINKED_DEVICE_VERSION,
  DEVICE_CERT_TYPE,
  DEVICE_ROSTER_TYPE,
  PAIRING_REQUEST_TYPE,
  PAIRING_QR_PREFIX,
  PAIRING_TTL_MS,
  PAIRING_CLOCK_SKEW_MS,
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
  createPairingRequest,
  assertPairingRequest,
  verifyPairingRequest,
  encodePairingQr,
  decodePairingQr,
  verificationCode,
};
