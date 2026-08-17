'use strict';

const nacl = require('tweetnacl');
const KEY_LENGTH = 32;
const LOW_ORDER_MESSAGE = 'low-order DH point';
const HSALSA20_SIGMA = Uint8Array.from([
  101, 120, 112, 97, 110, 100, 32, 51, 50, 45, 98, 121, 116, 101, 32, 107,
]);
const HSALSA20_ZERO = new Uint8Array(16);

function isZero(bytes) {
  let acc = 0;
  for (let i = 0; i < bytes.length; i += 1) acc |= bytes[i];
  return acc === 0;
}

const NO_PAIR_SECRET_MESSAGE = 'Нет общего секрета пары';
const DEGENERATE_SECRET_MESSAGE = 'Вырожденный общий секрет: публичный ключ контакта негоден';
function assertPairSecret(secret) {
  if (!(secret instanceof Uint8Array) || secret.length !== KEY_LENGTH) {
    throw new Error(NO_PAIR_SECRET_MESSAGE);
  }
  if (isZero(secret)) throw new Error(DEGENERATE_SECRET_MESSAGE);
  return secret;
}
function createX25519() {
  let native = null;
  function nativeAvailable() {
    return !!native;
  }
  function setNative(next) {
    if (next === null || next === undefined) {
      native = null;
      return false;
    }
    if (typeof next.sharedSecret !== 'function') {
      throw new Error('setNative: реализация обязана иметь sharedSecret');
    }
    native = next;
    return true;
  }
  function sharedSecret(secretKey, publicKey) {
    if (!secretKey || secretKey.length !== KEY_LENGTH) throw new Error(LOW_ORDER_MESSAGE);
    if (!publicKey || publicKey.length !== KEY_LENGTH) throw new Error(LOW_ORDER_MESSAGE);
    let out;
    if (native) {
      try {
        out = native.sharedSecret(secretKey, publicKey);
      } catch (error) {
        throw new Error(LOW_ORDER_MESSAGE);
      }
    } else {
      out = nacl.scalarMult(secretKey, publicKey);
    }
    if (!out || out.length !== KEY_LENGTH || isZero(out)) throw new Error(LOW_ORDER_MESSAGE);
    return out;
  }
  function assertUsableKey(publicKey) {
    sharedSecret(nacl.randomBytes(KEY_LENGTH), publicKey);
    return publicKey;
  }
  function boxSharedKey(secretKey, publicKey) {
    const secret = sharedSecret(secretKey, publicKey);
    const key = new Uint8Array(KEY_LENGTH);
    nacl.lowlevel.crypto_core_hsalsa20(key, HSALSA20_ZERO, secret, HSALSA20_SIGMA);
    return key;
  }
  return { sharedSecret, boxSharedKey, assertUsableKey, nativeAvailable, setNative };
}
const { sharedSecret, boxSharedKey, assertUsableKey, nativeAvailable, setNative } = createX25519();
module.exports = {
  KEY_LENGTH,
  LOW_ORDER_MESSAGE,
  NO_PAIR_SECRET_MESSAGE,
  DEGENERATE_SECRET_MESSAGE,
  assertPairSecret,
  assertUsableKey,
  boxSharedKey,
  sharedSecret,
  nativeAvailable,
  setNative,
  createX25519,
};