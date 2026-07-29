/**
 * Minimal client-side crypto used only by server integration tests.
 *
 * The public relay repository intentionally has no ../src client tree. Keeping
 * these protocol primitives beside test.js makes `npm test` reproducible after
 * messege/server is synchronized into that standalone repository.
 */
const nacl = require('tweetnacl');
const util = require('tweetnacl-util');

const { encodeBase64, decodeBase64, encodeUTF8, decodeUTF8 } = util;
const CHALLENGE_SIG_PREFIX = 'licno-relay-challenge-v1|';
const BOX_PROOF_PREFIX = 'licno-box-proof-v1|';
const RELAY_AUTH_PREFIX = 'licno-relay-auth-v1|';
const SPK_SIG_PREFIX = 'licno-spk-v1|';

function concatBytes(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function hmacSha512(key, data) {
  const blockSize = 128;
  let k = key;
  if (k.length > blockSize) k = nacl.hash(k);
  if (k.length < blockSize) {
    const padded = new Uint8Array(blockSize);
    padded.set(k);
    k = padded;
  }
  const ipad = new Uint8Array(blockSize);
  const opad = new Uint8Array(blockSize);
  for (let i = 0; i < blockSize; i++) {
    ipad[i] = k[i] ^ 0x36;
    opad[i] = k[i] ^ 0x5c;
  }
  return nacl.hash(concatBytes(opad, nacl.hash(concatBytes(ipad, data))));
}

function generateIdentity() {
  const box = nacl.box.keyPair();
  const sign = nacl.sign.keyPair();
  return {
    publicKey: encodeBase64(box.publicKey),
    secretKey: encodeBase64(box.secretKey),
    signPublicKey: encodeBase64(sign.publicKey),
    signSecretKey: encodeBase64(sign.secretKey),
  };
}

function signChallenge({ nonce, signSecretKey }) {
  return encodeBase64(
    nacl.sign.detached(
      decodeUTF8(CHALLENGE_SIG_PREFIX + nonce),
      decodeBase64(signSecretKey)
    )
  );
}

function proveBoxOwnership({ nonce, mySecretKey, serverEphPublicKey }) {
  const shared = nacl.scalarMult(decodeBase64(mySecretKey), decodeBase64(serverEphPublicKey));
  const mac = hmacSha512(
    shared,
    concatBytes(decodeUTF8(BOX_PROOF_PREFIX), decodeBase64(nonce))
  );
  return encodeBase64(mac.slice(0, 32));
}

function verifyRelayAuth({ cnonce, relaySig, relayPublicKey }) {
  try {
    return nacl.sign.detached.verify(
      decodeUTF8(RELAY_AUTH_PREFIX + cnonce),
      decodeBase64(relaySig),
      decodeBase64(relayPublicKey)
    );
  } catch (e) {
    return false;
  }
}

function prekeyId() {
  return encodeBase64(nacl.randomBytes(9));
}

function spkMessage(id, pub) {
  return decodeUTF8(SPK_SIG_PREFIX + id + '|' + pub);
}

function generateSignedPrekey({ signSecretKey }) {
  const pair = nacl.box.keyPair();
  const id = prekeyId();
  const pub = encodeBase64(pair.publicKey);
  return {
    id,
    pub,
    sec: encodeBase64(pair.secretKey),
    sig: encodeBase64(
      nacl.sign.detached(spkMessage(id, pub), decodeBase64(signSecretKey))
    ),
    createdAt: Date.now(),
  };
}

function verifySignedPrekey({ spk, signPublicKey }) {
  try {
    return nacl.sign.detached.verify(
      spkMessage(spk.id, spk.pub),
      decodeBase64(spk.sig),
      decodeBase64(signPublicKey)
    );
  } catch (e) {
    return false;
  }
}

function generateOneTimePrekeys(count) {
  const out = [];
  for (let i = 0; i < count; i++) {
    const pair = nacl.box.keyPair();
    out.push({
      id: prekeyId(),
      pub: encodeBase64(pair.publicKey),
      sec: encodeBase64(pair.secretKey),
      createdAt: Date.now(),
    });
  }
  return out;
}

function encryptMessage({ plaintext, mySecretKey, theirPublicKey, myPublicKey }) {
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const content = decodeUTF8(JSON.stringify({ kind: 'text', text: plaintext }));
  const cipher = nacl.box(
    content,
    nonce,
    decodeBase64(theirPublicKey),
    decodeBase64(mySecretKey)
  );
  return {
    v: 1,
    from: myPublicKey,
    nonce: encodeBase64(nonce),
    cipher: encodeBase64(cipher),
  };
}

function decryptMessage({ envelope, mySecretKey, senderPublicKey }) {
  try {
    const opened = nacl.box.open(
      decodeBase64(envelope.cipher),
      decodeBase64(envelope.nonce),
      decodeBase64(senderPublicKey),
      decodeBase64(mySecretKey)
    );
    if (!opened) return null;
    const content = JSON.parse(encodeUTF8(opened));
    return content && content.kind === 'text' ? content.text : null;
  } catch (e) {
    return null;
  }
}

module.exports = {
  generateIdentity,
  signChallenge,
  proveBoxOwnership,
  verifyRelayAuth,
  generateSignedPrekey,
  verifySignedPrekey,
  generateOneTimePrekeys,
  encryptMessage,
  decryptMessage,
};
