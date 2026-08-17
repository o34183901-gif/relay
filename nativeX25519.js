'use strict';
const PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);
const SPKI_PREFIX = Uint8Array.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
]);
const KEY_LENGTH = 32;
const VECTOR = {
  aliceSecret: '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a',
  alicePublic: '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a',
  bobSecret: '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb',
  bobPublic: 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f',
  shared: '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742',
};

const LOW_ORDER_POINT = '0100000000000000000000000000000000000000000000000000000000000000';
function fromHex(text) {
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(text.substr(i * 2, 2), 16);
  return out;
}
function toHex(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 1) out += bytes[i].toString(16).padStart(2, '0');
  return out;
}
function wrap(prefix, key) {
  const out = new Uint8Array(prefix.length + KEY_LENGTH);
  out.set(prefix, 0);
  out.set(key.subarray(0, KEY_LENGTH), prefix.length);
  return out;
}
function createNativeX25519(nodeCrypto) {
  if (
    !nodeCrypto ||
    typeof nodeCrypto.createPrivateKey !== 'function' ||
    typeof nodeCrypto.createPublicKey !== 'function' ||
    typeof nodeCrypto.diffieHellman !== 'function'
  ) {
    return null;
  }
  return {
    sharedSecret(secretKey, publicKey) {
      const privateKey = nodeCrypto.createPrivateKey({
        key: wrap(PKCS8_PREFIX, secretKey),
        format: 'der',
        type: 'pkcs8',
      });
      const theirs = nodeCrypto.createPublicKey({
        key: wrap(SPKI_PREFIX, publicKey),
        format: 'der',
        type: 'spki',
      });
      const out = nodeCrypto.diffieHellman({ privateKey, publicKey: theirs });
      const copy = new Uint8Array(out.length);
      copy.set(out, 0);
      return copy;
    },
  };
}
function selfTest(implementation) {
  if (!implementation) return 'нет реализации';
  const aliceSecret = fromHex(VECTOR.aliceSecret);
  const alicePublic = fromHex(VECTOR.alicePublic);
  const bobSecret = fromHex(VECTOR.bobSecret);
  const bobPublic = fromHex(VECTOR.bobPublic);
  const mine = implementation.sharedSecret(aliceSecret, bobPublic);
  if (!mine || mine.length !== KEY_LENGTH) return 'общий секрет не той длины';
  if (toHex(mine) !== VECTOR.shared) return 'общий секрет не совпал с вектором RFC 7748';
  const theirs = implementation.sharedSecret(bobSecret, alicePublic);
  if (toHex(theirs) !== VECTOR.shared) return 'обмен несимметричен — перепутаны аргументы';
  const other = new Uint8Array(aliceSecret);
  other[0] ^= 0xff;
  let different;
  try {
    different = implementation.sharedSecret(other, bobPublic);
  } catch (error) {
    return `другая секретка уронила реализацию: ${(error && error.message) || error}`;
  }
  if (toHex(different) === VECTOR.shared) return 'общий секрет не зависит от секретки';
  const lowOrder = fromHex(LOW_ORDER_POINT);
  let degenerate = null;
  try {
    degenerate = implementation.sharedSecret(aliceSecret, lowOrder);
  } catch (error) {
    degenerate = null;
  }
  if (degenerate) {
    let acc = 0;
    for (let i = 0; i < degenerate.length; i += 1) acc |= degenerate[i];
    if (acc !== 0) return 'точка малого порядка дала рабочий секрет';
  }
  return null;
}
function resolveNativeX25519(load) {
  let nodeCrypto = null;
  try {
    nodeCrypto = typeof load === 'function' ? load() : null;
  } catch (error) {
    return { implementation: null, reason: `модуль не загрузился: ${(error && error.message) || error}` };
  }
  const implementation = createNativeX25519(nodeCrypto);
  if (!implementation) return { implementation: null, reason: 'модуль без нужных методов' };
  let failure;
  try {
    failure = selfTest(implementation);
  } catch (error) {
    failure = `самопроверка бросила ошибку: ${(error && error.message) || error}`;
  }
  return failure ? { implementation: null, reason: failure } : { implementation, reason: null };
}
module.exports = {
  PKCS8_PREFIX,
  SPKI_PREFIX,
  KEY_LENGTH,
  VECTOR,
  LOW_ORDER_POINT,
  createNativeX25519,
  selfTest,
  resolveNativeX25519,
};