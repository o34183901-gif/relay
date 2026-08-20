const gcs = require('./mailboxGcs');

const VERSION = 1;
const KEY_BYTES = 32;
const VALUE_BYTES = 176;
const MAC_BYTES = 16;
const RECORD_BYTES = KEY_BYTES + VALUE_BYTES + MAC_BYTES;

const MAX_PUT_RECORDS = 8;
const SLOT_MS = 6 * 60 * 60 * 1000;
const SLOT_TOLERANCE = 1;
const TTL_MS = 2 * SLOT_MS + 60 * 60 * 1000;

const BUCKET_MIN = 96;
const MAX_DEPTH = 16;
const MAX_RECORDS = 400000;
const SYNC_LIMIT = 4096;
function slotOf(now) {
  return Math.floor(now / SLOT_MS);
}

function parsePut(bytes, { now = Date.now(), slot } = {}) {
  if (!(bytes instanceof Uint8Array) && !Buffer.isBuffer(bytes)) return null;
  if (!bytes.length || bytes.length % RECORD_BYTES !== 0) return null;
  const count = bytes.length / RECORD_BYTES;
  if (count > MAX_PUT_RECORDS) return null;
  if (!Number.isInteger(slot)) return null;
  if (Math.abs(slot - slotOf(now)) > SLOT_TOLERANCE) return null;
  const out = [];
  for (let i = 0; i < count; i += 1) {
    const at = i * RECORD_BYTES;
    out.push({
      key: Buffer.from(bytes.subarray(at, at + KEY_BYTES)),
      value: Buffer.from(bytes.subarray(at + KEY_BYTES, at + KEY_BYTES + VALUE_BYTES)),
      mac: Buffer.from(bytes.subarray(at + KEY_BYTES + VALUE_BYTES, at + RECORD_BYTES)),
      slot,
    });
  }
  return out;
}

function packRecords(records) {
  const list = Array.isArray(records) ? records : [];
  const out = Buffer.alloc(list.length * RECORD_BYTES);
  for (let i = 0; i < list.length; i += 1) {
    const at = i * RECORD_BYTES;
    Buffer.from(list[i].key).copy(out, at);
    Buffer.from(list[i].value).copy(out, at + KEY_BYTES);
    Buffer.from(list[i].mac).copy(out, at + KEY_BYTES + VALUE_BYTES);
  }
  return out;
}
function bucketDepth(size) {
  if (!Number.isFinite(size) || size <= BUCKET_MIN) return 0;
  return Math.max(0, Math.min(MAX_DEPTH, Math.floor(Math.log2(size / BUCKET_MIN))));
}
function bucketOf(key, depth) {
  if (depth <= 0) return 0;
  const head = key[0] * 0x1000000 + (key[1] << 16) + (key[2] << 8) + key[3];
  return Math.floor(head / 2 ** (32 - depth));
}
function bucketRange(bucket, depth) {
  const low = Buffer.alloc(KEY_BYTES);
  const high = Buffer.alloc(KEY_BYTES, 0xff);
  if (!Number.isInteger(bucket) || bucket < 0) return null;
  if (depth <= 0) return bucket === 0 ? { low, high } : null;
  if (bucket >= 2 ** depth) return null;
  const shift = 2 ** (32 - depth);
  const start = bucket * shift;
  const end = (bucket + 1) * shift - 1;
  low.writeUInt32BE(start, 0);
  high.writeUInt32BE(end, 0);
  return { low, high };
}
function depthAllowed(depth, size) {
  if (!Number.isInteger(depth) || depth < 0 || depth > MAX_DEPTH) return false;
  return depth <= bucketDepth(size) + 1;
}
function buildDigest(keys) {
  const list = (Array.isArray(keys) ? keys : []).map((key) => Uint8Array.from(key));
  const digest = gcs.encode(list);
  return { v: VERSION, p: digest.p, n: digest.n, bits: Buffer.from(digest.bits) };
}
function createDigestCache({ build = buildDigest } = {}) {
  let cached = null;
  let atVersion = null;
  let lastBuiltAt = null;
  return {
    get(version, loadKeys) {
      if (cached && atVersion === version) return cached;
      const keys = typeof loadKeys === 'function' ? loadKeys() : loadKeys;
      const digest = build(keys);
      cached = { ...digest, bitsBase64: Buffer.from(digest.bits).toString('base64') };
      atVersion = version;
      return cached;
    },
    refresh(version, loadKeys) {
      if (cached && atVersion === version) return false;
      this.get(version, loadKeys);
      lastBuiltAt = null;
      return true;
    },
    refreshIfDue(version, loadKeys, { now = Date.now(), minIntervalMs = 0 } = {}) {
      if (cached && atVersion === version) return false;
      if (lastBuiltAt !== null && now - lastBuiltAt < minIntervalMs) return false;
      this.get(version, loadKeys);
      lastBuiltAt = now;
      return true;
    },
    version() {
      return atVersion;
    },
    size() {
      return cached ? cached.n : 0;
    },
    reset() {
      cached = null;
      atVersion = null;
      lastBuiltAt = null;
    },
  };
}
function expiresAt(slot) {
  return slot * SLOT_MS + TTL_MS;
}
function isExpired(record, now) {
  return !record || expiresAt(record.slot) <= now;
}
module.exports = {
  VERSION,
  KEY_BYTES,
  VALUE_BYTES,
  MAC_BYTES,
  RECORD_BYTES,
  MAX_PUT_RECORDS,
  SLOT_MS,
  SLOT_TOLERANCE,
  TTL_MS,
  BUCKET_MIN,
  MAX_DEPTH,
  MAX_RECORDS,
  SYNC_LIMIT,
  slotOf,
  parsePut,
  packRecords,
  bucketDepth,
  bucketOf,
  bucketRange,
  depthAllowed,
  buildDigest,
  createDigestCache,
  expiresAt,
  isExpired,
};