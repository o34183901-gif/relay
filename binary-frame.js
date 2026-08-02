'use strict';

const MAGIC = Buffer.from('LICNOBA1', 'ascii');
const MAX_HEADER = 16 * 1024;

function unpackBinaryFrame(input) {
  const frame = Buffer.isBuffer(input) ? input : Buffer.from(input);
  if (frame.length < MAGIC.length + 4 || !frame.subarray(0, MAGIC.length).equals(MAGIC)) {
    throw new Error('unknown binary frame');
  }
  const headerLength = frame.readUInt32BE(MAGIC.length);
  if (headerLength < 2 || headerLength > MAX_HEADER) throw new Error('invalid binary header');
  const bodyOffset = MAGIC.length + 4 + headerLength;
  if (bodyOffset > frame.length) throw new Error('truncated binary frame');
  const header = JSON.parse(frame.subarray(MAGIC.length + 4, bodyOffset).toString('utf8'));
  if (!header || typeof header !== 'object' || Array.isArray(header)) throw new Error('invalid binary header');
  return { header, payload: frame.subarray(bodyOffset) };
}

function packBinaryFrame(header, payload) {
  const headerBytes = Buffer.from(JSON.stringify(header), 'utf8');
  if (headerBytes.length > MAX_HEADER) throw new Error('binary header too large');
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  const length = Buffer.allocUnsafe(4);
  length.writeUInt32BE(headerBytes.length, 0);
  return Buffer.concat([MAGIC, length, headerBytes, body]);
}

module.exports = { unpackBinaryFrame, packBinaryFrame, MAX_HEADER };
