'use strict';

const crypto = require('crypto');
const CURVE = 'prime256v1';
const P256_ORDER = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
const SCALAR_BYTES = 32;
const PUBLIC_BYTES = 65;
const DERIVE_LABEL = 'licno-vapid-device-v1';
const MAX_DERIVE_ATTEMPTS = 8;
const FALLBACK_SUBJECT = 'https://lichno.pro/';
function scalarFromBytes(bytes) {
  if (!bytes || bytes.length !== SCALAR_BYTES) return null;
  const buffer = Buffer.from(bytes);
  const value = BigInt(`0x${buffer.toString('hex')}`);
  if (value === 0n || value >= P256_ORDER) return null;
  return buffer;
}
function keyPairFromScalar(scalar) {
  const ecdh = crypto.createECDH(CURVE);
  ecdh.setPrivateKey(scalar);
  const publicKey = ecdh.getPublicKey(null, 'uncompressed');
  if (publicKey.length !== PUBLIC_BYTES) return null;
  return { publicKey: publicKey.toString('base64url'), privateKey: scalar.toString('base64url') };
}
function deviceVapidKeys(basePrivateKey, address, { hkdf = crypto.hkdfSync } = {}) {
  if (typeof address !== 'string' || !address) return null;
  const ikm = Buffer.from(String(basePrivateKey || ''), 'base64url');
  if (ikm.length !== SCALAR_BYTES) return null;
  for (let attempt = 0; attempt < MAX_DERIVE_ATTEMPTS; attempt += 1) {
    const bytes = hkdf(
      'sha256',
      ikm,
      Buffer.from(DERIVE_LABEL, 'utf8'),
      Buffer.from(`${DERIVE_LABEL}|${attempt}|${address}`, 'utf8'),
      SCALAR_BYTES
    );
    const scalar = scalarFromBytes(Buffer.from(bytes));
    if (!scalar) continue;
    return keyPairFromScalar(scalar);
  }
  return null;
}
function validSubject(value) {
  if (typeof value !== 'string' || !value || value.length > 256) return null;
  let parsed;
  try {
    parsed = new URL(value);
  } catch (error) {
    return null;
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'mailto:') return null;
  if (parsed.protocol === 'https:' && !parsed.hostname) return null;
  return value;
}
function vapidSubject(selfUrl, override) {
  const explicit = validSubject(override);
  if (explicit) return explicit;
  try {
    const parsed = new URL(String(selfUrl || ''));
    if ((parsed.protocol === 'wss:' || parsed.protocol === 'https:') && parsed.hostname) {
      return `https://${parsed.host}/`;
    }
  } catch (error) {
  }
  return FALLBACK_SUBJECT;
}
module.exports = {
  CURVE,
  P256_ORDER,
  SCALAR_BYTES,
  PUBLIC_BYTES,
  DERIVE_LABEL,
  MAX_DERIVE_ATTEMPTS,
  FALLBACK_SUBJECT,
  scalarFromBytes,
  keyPairFromScalar,
  deviceVapidKeys,
  validSubject,
  vapidSubject,
};