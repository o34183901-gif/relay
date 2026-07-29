/**
 * vapid-fleet.js — безопасная P2P-раздача одной VAPID-пары между релеями
 * оператора.
 *
 * В публичном образе лежит только список разрешённых URL и публичных Ed25519-
 * ключей релеев. Начальный (genesis) релей создаёт VAPID один раз, подписывает
 * весь bundle своим долговременным relay-sign.key и передаёт его остальным
 * разрешённым узлам в NaCl-box, зашифрованном на одноразовый ключ получателя.
 *
 * Приватный VAPID никогда не попадает в GitHub/образ/логи. Узел из открытого
 * gossip-каталога не получает ключ: URL должен быть в vapid-fleet.json, подпись
 * запроса должна сходиться, а сетевой источник — совпадать с публичным IP этого
 * URL. Для будущего сервера можно заранее добавить URL с allowDynamicKey=true:
 * его первый relay-sign.key привязывается к владению этим IP без входа по SSH.
 */

const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const path = require('path');
const nacl = require('tweetnacl');
const naclUtil = require('tweetnacl-util');
const { normalizeRelayUrl, isPrivateHost } = require('./relays');

const REQUEST_PREFIX = 'licno-vapid-fleet-request-v1|';
const RESPONSE_PREFIX = 'licno-vapid-fleet-response-v1|';
const BUNDLE_PREFIX = 'licno-vapid-fleet-bundle-v1|';
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
const MAX_JSON_BYTES = 32 * 1024;

function decodeB64(value, expectedLength) {
  try {
    const out = naclUtil.decodeBase64(String(value || ''));
    return !expectedLength || out.length === expectedLength ? out : null;
  } catch (e) {
    return null;
  }
}

function validRelayPublicKey(value) {
  return !!decodeB64(value, nacl.sign.publicKeyLength);
}

function validVapidPair(publicKey, privateKey) {
  try {
    const pub = Buffer.from(String(publicKey || ''), 'base64url');
    const priv = Buffer.from(String(privateKey || ''), 'base64url');
    if (pub.length !== 65 || pub[0] !== 4 || priv.length !== 32) return false;
    const ecdh = crypto.createECDH('prime256v1');
    ecdh.setPrivateKey(priv);
    const derived = ecdh.getPublicKey(null, 'uncompressed');
    return derived.length === pub.length && crypto.timingSafeEqual(derived, pub);
  } catch (e) {
    return false;
  }
}

function parseRelayUrl(raw, allowPrivate) {
  const normalized = normalizeRelayUrl(raw);
  if (!normalized || normalized.length > 256 || !/^wss?:\/\//i.test(normalized)) return null;
  let parsed;
  try {
    parsed = new URL(normalized);
  } catch (e) {
    return null;
  }
  if (!parsed.hostname || (!allowPrivate && isPrivateHost(parsed.hostname))) return null;
  return normalized;
}

function loadFleetConfig(filePath, { allowPrivate = false } = {}) {
  const raw = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  if (!raw || raw.version !== 1 || typeof raw.fleetId !== 'string' || !raw.fleetId || raw.fleetId.length > 80) {
    throw new Error('vapid-fleet.json: invalid version/fleetId');
  }
  const epoch = Number(raw.epoch);
  if (!Number.isSafeInteger(epoch) || epoch < 1) throw new Error('vapid-fleet.json: invalid epoch');
  if (!Array.isArray(raw.relays) || !raw.relays.length || raw.relays.length > 500) {
    throw new Error('vapid-fleet.json: invalid relays');
  }

  const seenUrls = new Set();
  const seenKeys = new Set();
  const relays = raw.relays.map((entry) => {
    const url = parseRelayUrl(entry && entry.url, allowPrivate);
    if (!url) throw new Error('vapid-fleet.json: invalid relay URL');
    const urlKey = url.toLowerCase();
    if (seenUrls.has(urlKey)) throw new Error(`vapid-fleet.json: duplicate URL ${url}`);
    seenUrls.add(urlKey);

    const relayPub = entry && typeof entry.relayPub === 'string' ? entry.relayPub : null;
    const allowDynamicKey = !!(entry && entry.allowDynamicKey);
    if (relayPub && !validRelayPublicKey(relayPub)) {
      throw new Error(`vapid-fleet.json: invalid relayPub for ${url}`);
    }
    if (!relayPub && !allowDynamicKey) {
      throw new Error(`vapid-fleet.json: relayPub or allowDynamicKey required for ${url}`);
    }
    if (relayPub) {
      if (seenKeys.has(relayPub)) throw new Error(`vapid-fleet.json: duplicate relayPub for ${url}`);
      seenKeys.add(relayPub);
    }
    return { url, relayPub, allowDynamicKey };
  });

  const genesis = parseRelayUrl(raw.genesis, allowPrivate);
  const genesisMember = relays.find((x) => x.url.toLowerCase() === String(genesis || '').toLowerCase());
  if (!genesisMember || !genesisMember.relayPub || genesisMember.allowDynamicKey) {
    throw new Error('vapid-fleet.json: genesis must have a pinned relayPub');
  }
  return {
    version: 1,
    fleetId: raw.fleetId,
    epoch,
    genesis: genesisMember.url,
    relays,
  };
}

function memberFor(config, rawUrl) {
  const url = normalizeRelayUrl(rawUrl);
  if (!config || !url) return null;
  return config.relays.find((x) => x.url.toLowerCase() === url.toLowerCase()) || null;
}

function memberAcceptsKey(member, relayPub) {
  return !!member && validRelayPublicKey(relayPub) && (!member.relayPub || member.relayPub === relayPub);
}

function bundlePayload(bundle) {
  return (
    BUNDLE_PREFIX +
    [
      bundle.fleetId,
      String(bundle.epoch),
      bundle.genesis,
      bundle.genesisRelayPub,
      String(bundle.issuedAt),
      bundle.publicKey,
      bundle.privateKey,
    ].join('|')
  );
}

function signVapidBundle({ publicKey, privateKey }, config, genesisRelaySecret, issuedAt = Date.now()) {
  if (!validVapidPair(publicKey, privateKey)) throw new Error('invalid VAPID pair');
  const secret = genesisRelaySecret instanceof Uint8Array ? genesisRelaySecret : decodeB64(genesisRelaySecret);
  if (!secret || secret.length !== nacl.sign.secretKeyLength) throw new Error('invalid genesis relay secret');
  const genesisMember = memberFor(config, config.genesis);
  const bundle = {
    version: 1,
    fleetId: config.fleetId,
    epoch: config.epoch,
    genesis: config.genesis,
    genesisRelayPub: genesisMember.relayPub,
    issuedAt,
    publicKey,
    privateKey,
  };
  bundle.signature = naclUtil.encodeBase64(
    nacl.sign.detached(naclUtil.decodeUTF8(bundlePayload(bundle)), secret)
  );
  return bundle;
}

function verifyVapidBundle(bundle, config) {
  try {
    if (!bundle || bundle.version !== 1 || bundle.fleetId !== config.fleetId || bundle.epoch !== config.epoch) {
      return false;
    }
    const genesisMember = memberFor(config, config.genesis);
    if (
      bundle.genesis !== config.genesis ||
      bundle.genesisRelayPub !== genesisMember.relayPub ||
      !Number.isSafeInteger(bundle.issuedAt) ||
      !validVapidPair(bundle.publicKey, bundle.privateKey)
    ) {
      return false;
    }
    const sig = decodeB64(bundle.signature, nacl.sign.signatureLength);
    const pub = decodeB64(genesisMember.relayPub, nacl.sign.publicKeyLength);
    return !!sig && nacl.sign.detached.verify(naclUtil.decodeUTF8(bundlePayload(bundle)), sig, pub);
  } catch (e) {
    return false;
  }
}

function requestPayload(request) {
  return (
    REQUEST_PREFIX +
    [
      request.fleetId,
      String(request.epoch),
      request.relayUrl,
      request.relayPub,
      String(request.timestamp),
      request.nonce,
      request.boxPub,
    ].join('|')
  );
}

function createVapidRequest({ config, relayUrl, relayPub, relaySecret, now = Date.now() }) {
  const member = memberFor(config, relayUrl);
  if (!memberAcceptsKey(member, relayPub)) throw new Error('relay is not an allowed fleet member');
  const secret = relaySecret instanceof Uint8Array ? relaySecret : decodeB64(relaySecret);
  if (!secret || secret.length !== nacl.sign.secretKeyLength) throw new Error('invalid relay secret');
  const box = nacl.box.keyPair();
  const request = {
    version: 1,
    fleetId: config.fleetId,
    epoch: config.epoch,
    relayUrl: member.url,
    relayPub,
    timestamp: now,
    nonce: naclUtil.encodeBase64(crypto.randomBytes(24)),
    boxPub: naclUtil.encodeBase64(box.publicKey),
  };
  request.signature = naclUtil.encodeBase64(
    nacl.sign.detached(naclUtil.decodeUTF8(requestPayload(request)), secret)
  );
  return { request, boxSecret: box.secretKey };
}

function verifyVapidRequest(request, config, now = Date.now()) {
  try {
    if (
      !request ||
      request.version !== 1 ||
      request.fleetId !== config.fleetId ||
      request.epoch !== config.epoch ||
      !Number.isSafeInteger(request.timestamp) ||
      Math.abs(now - request.timestamp) > MAX_CLOCK_SKEW_MS
    ) {
      return null;
    }
    const member = memberFor(config, request.relayUrl);
    if (!memberAcceptsKey(member, request.relayPub)) return null;
    if (!decodeB64(request.nonce, 24) || !decodeB64(request.boxPub, nacl.box.publicKeyLength)) return null;
    const sig = decodeB64(request.signature, nacl.sign.signatureLength);
    const pub = decodeB64(request.relayPub, nacl.sign.publicKeyLength);
    if (!sig || !pub) return null;
    if (!nacl.sign.detached.verify(naclUtil.decodeUTF8(requestPayload(request)), sig, pub)) return null;
    return member;
  } catch (e) {
    return null;
  }
}

function responsePayload(response) {
  return (
    RESPONSE_PREFIX +
    [
      response.fleetId,
      String(response.epoch),
      response.requestNonce,
      response.senderUrl,
      response.senderRelayPub,
      response.boxPub,
      response.nonce,
      response.ciphertext,
    ].join('|')
  );
}

function createVapidResponse({ config, request, bundle, senderUrl, senderRelayPub, senderRelaySecret }) {
  if (!verifyVapidBundle(bundle, config)) throw new Error('refusing to serve an invalid VAPID bundle');
  const sender = memberFor(config, senderUrl);
  if (!memberAcceptsKey(sender, senderRelayPub)) throw new Error('sender is not an allowed fleet member');
  const secret = senderRelaySecret instanceof Uint8Array ? senderRelaySecret : decodeB64(senderRelaySecret);
  const recipientBoxPub = decodeB64(request.boxPub, nacl.box.publicKeyLength);
  if (!secret || secret.length !== nacl.sign.secretKeyLength || !recipientBoxPub) {
    throw new Error('invalid response keys');
  }
  const ephemeral = nacl.box.keyPair();
  const nonce = crypto.randomBytes(nacl.box.nonceLength);
  const plaintext = naclUtil.decodeUTF8(JSON.stringify(bundle));
  if (plaintext.length > MAX_JSON_BYTES) throw new Error('VAPID bundle too large');
  const ciphertext = nacl.box(plaintext, nonce, recipientBoxPub, ephemeral.secretKey);
  const response = {
    version: 1,
    fleetId: config.fleetId,
    epoch: config.epoch,
    requestNonce: request.nonce,
    senderUrl: sender.url,
    senderRelayPub,
    boxPub: naclUtil.encodeBase64(ephemeral.publicKey),
    nonce: naclUtil.encodeBase64(nonce),
    ciphertext: naclUtil.encodeBase64(ciphertext),
  };
  response.signature = naclUtil.encodeBase64(
    nacl.sign.detached(naclUtil.decodeUTF8(responsePayload(response)), secret)
  );
  return response;
}

function openVapidResponse({ config, request, response, boxSecret }) {
  try {
    if (
      !response ||
      response.version !== 1 ||
      response.fleetId !== config.fleetId ||
      response.epoch !== config.epoch ||
      response.requestNonce !== request.nonce
    ) {
      return null;
    }
    const sender = memberFor(config, response.senderUrl);
    if (!memberAcceptsKey(sender, response.senderRelayPub)) return null;
    const senderPub = decodeB64(response.senderRelayPub, nacl.sign.publicKeyLength);
    const sig = decodeB64(response.signature, nacl.sign.signatureLength);
    if (
      !senderPub ||
      !sig ||
      !nacl.sign.detached.verify(naclUtil.decodeUTF8(responsePayload(response)), sig, senderPub)
    ) {
      return null;
    }
    const senderBoxPub = decodeB64(response.boxPub, nacl.box.publicKeyLength);
    const nonce = decodeB64(response.nonce, nacl.box.nonceLength);
    const ciphertext = decodeB64(response.ciphertext);
    if (!senderBoxPub || !nonce || !ciphertext || ciphertext.length > MAX_JSON_BYTES) return null;
    const plaintext = nacl.box.open(ciphertext, nonce, senderBoxPub, boxSecret);
    if (!plaintext || plaintext.length > MAX_JSON_BYTES) return null;
    const bundle = JSON.parse(naclUtil.encodeUTF8(plaintext));
    return verifyVapidBundle(bundle, config) ? bundle : null;
  } catch (e) {
    return null;
  }
}

function normalizeIp(value) {
  let ip = String(value || '').trim().toLowerCase();
  if (ip.startsWith('::ffff:') && net.isIPv4(ip.slice(7))) ip = ip.slice(7);
  const zone = ip.indexOf('%');
  if (zone !== -1) ip = ip.slice(0, zone);
  return net.isIP(ip) ? ip : null;
}

function sourceMatchesResolved(sourceIp, resolved) {
  const source = normalizeIp(sourceIp);
  if (!source || !Array.isArray(resolved)) return false;
  return resolved.some((entry) => normalizeIp(entry && entry.address) === source);
}

function readJsonFile(filePath) {
  try {
    const text = fs.readFileSync(filePath, 'utf8');
    if (Buffer.byteLength(text) > MAX_JSON_BYTES) return null;
    return JSON.parse(text);
  } catch (e) {
    return null;
  }
}

function writeJsonAtomic(filePath, value) {
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const temp = `${filePath}.tmp-${process.pid}-${crypto.randomBytes(4).toString('hex')}`;
  const data = JSON.stringify(value);
  if (Buffer.byteLength(data) > MAX_JSON_BYTES) throw new Error('JSON value too large');
  try {
    fs.writeFileSync(temp, data, { mode: 0o600, flag: 'wx' });
    fs.chmodSync(temp, 0o600);
    fs.renameSync(temp, filePath);
    try {
      fs.chmodSync(filePath, 0o600);
    } catch (e) {}
  } finally {
    try {
      fs.unlinkSync(temp);
    } catch (e) {}
  }
}

module.exports = {
  MAX_CLOCK_SKEW_MS,
  MAX_JSON_BYTES,
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
  normalizeIp,
  sourceMatchesResolved,
  readJsonFile,
  writeJsonAtomic,
};
