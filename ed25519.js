const nacl = require('tweetnacl');
let nobleCache;
function nobleEd25519() {
  if (nobleCache === undefined) {
    nobleCache = require('@noble/curves/ed25519.js').ed25519;
  }
  return nobleCache;
}
function usable(implementation) {
  return implementation &&
    typeof implementation.sign === 'function' &&
    typeof implementation.verify === 'function'
    ? implementation
    : null;
}
function createEd25519(implementation) {
  let fastCache = implementation === undefined ? undefined : usable(implementation);
  function fast() {
    if (fastCache === undefined) fastCache = usable(nobleEd25519());
    return fastCache;
  }
  let native = null;
  function fastAvailable() {
    return !!fast();
  }
  function nativeAvailable() {
    return !!native;
  }
  function setNative(next) {
    if (next === null || next === undefined) {
      native = null;
      return false;
    }
    if (typeof next.sign !== 'function' || typeof next.verify !== 'function') {
      throw new Error('setNative: реализация обязана иметь sign и verify');
    }
    native = next;
    return true;
  }
  function sign(message, secretKey) {
    if (native) return native.sign(message, secretKey);
    const quick = fast();
    if (quick) return quick.sign(message, secretKey.subarray(0, 32));
    return nacl.sign.detached(message, secretKey);
  }
  function verify(message, signature, publicKey) {
    try {
      if (native) return native.verify(message, signature, publicKey);
      const quick = fast();
      if (quick) return quick.verify(signature, message, publicKey);
      return nacl.sign.detached.verify(message, signature, publicKey);
    } catch (error) {
      return false;
    }
  }
  return { sign, verify, fastAvailable, nativeAvailable, setNative };
}
const { sign, verify, fastAvailable, nativeAvailable, setNative } = createEd25519();
module.exports = {
  sign,
  verify,
  fastAvailable,
  nativeAvailable,
  setNative,
  createEd25519,
};