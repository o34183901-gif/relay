'use strict';
const PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);
const SPKI_PREFIX = Uint8Array.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);
const KEY_LENGTH = 32;
const SIGNATURE_LENGTH = 64;
const VECTOR = {
  seed: '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
  publicKey: '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
  message: '72',
  signature:
    '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da' +
    '085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00',
};

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
function copy(value) {
  const out = new Uint8Array(value.length);
  out.set(value, 0);
  return out;
}
function createNativeEd25519(nodeCrypto) {
  if (
    !nodeCrypto ||
    typeof nodeCrypto.createPrivateKey !== 'function' ||
    typeof nodeCrypto.createPublicKey !== 'function' ||
    typeof nodeCrypto.sign !== 'function' ||
    typeof nodeCrypto.verify !== 'function'
  ) {
    return null;
  }
  return {
    sign(message, secretKey) {
      const key = nodeCrypto.createPrivateKey({
        key: wrap(PKCS8_PREFIX, secretKey),
        format: 'der',
        type: 'pkcs8',
      });
      return copy(nodeCrypto.sign(null, message, key));
    },
    verify(message, signature, publicKey) {
      try {
        if (!publicKey || publicKey.length !== KEY_LENGTH) return false;
        const key = nodeCrypto.createPublicKey({
          key: wrap(SPKI_PREFIX, publicKey),
          format: 'der',
          type: 'spki',
        });
        return nodeCrypto.verify(null, message, key, signature) === true;
      } catch (error) {
        return false;
      }
    },
  };
}
function selfTest(implementation) {
  if (!implementation) return 'нет реализации';
  const seed = fromHex(VECTOR.seed);
  const publicKey = fromHex(VECTOR.publicKey);
  const message = fromHex(VECTOR.message);
  const expected = VECTOR.signature;
  const secretKey = new Uint8Array(64);
  secretKey.set(seed, 0);
  secretKey.set(publicKey, KEY_LENGTH);
  const signature = implementation.sign(message, secretKey);
  if (!signature || signature.length !== SIGNATURE_LENGTH) return 'подпись не той длины';
  if (toHex(signature) !== expected) return 'подпись не совпала с вектором RFC 8032';
  if (implementation.verify(message, signature, publicKey) !== true) {
    return 'собственная подпись не проверяется';
  }
  const damaged = copy(signature);
  damaged[damaged.length - 1] ^= 0xff;
  if (implementation.verify(message, damaged, publicKey) !== false) {
    return 'подделанная подпись принята';
  }
  const otherMessage = Uint8Array.from([...message, 0x00]);
  if (implementation.verify(otherMessage, signature, publicKey) !== false) {
    return 'подпись принята под другим сообщением';
  }
  const otherKey = copy(publicKey);
  otherKey[0] ^= 0xff;
  if (implementation.verify(message, signature, otherKey) !== false) {
    return 'подпись принята под чужим ключом';
  }
  return null;
}
function resolveNativeEd25519(load) {
  let nodeCrypto = null;
  try {
    nodeCrypto = typeof load === 'function' ? load() : null;
  } catch (error) {
    return { implementation: null, reason: `модуль не загрузился: ${(error && error.message) || error}` };
  }
  const implementation = createNativeEd25519(nodeCrypto);
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
  SIGNATURE_LENGTH,
  VECTOR,
  createNativeEd25519,
  selfTest,
  resolveNativeEd25519,
};