const P_BITS = 14;
const M = 1 << P_BITS;
const MAX_KEYS = 1 << 21;
function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function createWriter() {
  const bytes = [];
  let current = 0;
  let filled = 0;
  return {
    bit(value) {
      current = (current << 1) | (value ? 1 : 0);
      filled += 1;
      if (filled === 8) {
        bytes.push(current);
        current = 0;
        filled = 0;
      }
    },
    number(value, width) {
      for (let i = width - 1; i >= 0; i -= 1) this.bit((value / 2 ** i) & 1);
    },
    done() {
      while (filled) this.bit(0);
      return Uint8Array.from(bytes);
    },
  };
}

function createReader(bytes) {
  let at = 0;
  return {
    bit() {
      const index = at >> 3;
      if (index >= bytes.length) return null;
      const value = (bytes[index] >> (7 - (at & 7))) & 1;
      at += 1;
      return value;
    },
    number(width) {
      let value = 0;
      for (let i = 0; i < width; i += 1) {
        const bit = this.bit();
        if (bit === null) return null;
        value = value * 2 + bit;
      }
      return value;
    },
  };
}
function valueOf(key, range) {
  invariant(key instanceof Uint8Array && key.length >= 6, 'Ключ слишком короткий');
  let value = 0;
  for (let i = 0; i < 6; i += 1) value = value * 256 + key[i];
  return value % range;
}
function encode(keys, { pBits = P_BITS } = {}) {
  invariant(Array.isArray(keys) || keys instanceof Set, 'Нечего сжимать');
  const list = [...keys];
  invariant(list.length <= MAX_KEYS, 'Слишком много ключей');
  const m = 1 << pBits;
  const range = Math.max(1, list.length) * m;
  const values = list.map((key) => valueOf(key, range)).sort((a, b) => a - b);
  const writer = createWriter();
  let previous = -1;
  for (const value of values) {
    const delta = value - previous;
    previous = value;
    const quotient = Math.floor(delta / m);
    const remainder = delta % m;
    for (let i = 0; i < quotient; i += 1) writer.bit(1);
    writer.bit(0);
    writer.number(remainder, pBits);
  }
  return { p: pBits, n: list.length, bits: writer.done() };
}
function decode(digest) {
  if (!digest || typeof digest !== 'object') return null;
  const { p, n, bits } = digest;
  if (!Number.isInteger(p) || p < 1 || p > 24) return null;
  if (!Number.isInteger(n) || n < 0 || n > MAX_KEYS) return null;
  if (!(bits instanceof Uint8Array)) return null;
  if (n > Math.floor((bits.length * 8) / (p + 1))) return null;
  const m = 1 << p;
  const range = Math.max(1, n) * m;
  const reader = createReader(bits);
  const out = new Set();
  let previous = -1;
  for (let i = 0; i < n; i += 1) {
    let quotient = 0;
    for (;;) {
      const bit = reader.bit();
      if (bit === null) return null;
      if (!bit) break;
      quotient += 1;
      if (quotient > range / m + 2) return null;
    }
    const remainder = reader.number(p);
    if (remainder === null) return null;
    const value = previous + quotient * m + remainder;
    if (value > range) return null;
    previous = value;
    out.add(value);
  }
  return { p, n, range, values: out };
}
function probablyHas(decoded, key) {
  if (!decoded || !(key instanceof Uint8Array)) return false;
  return decoded.values.has(valueOf(key, decoded.range));
}
module.exports = {
  P_BITS,
  M,
  MAX_KEYS,
  valueOf,
  encode,
  decode,
  probablyHas,
};