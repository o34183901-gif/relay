const { decodeBase64, encodeBase64 } = require('tweetnacl-util');
const BINARY_ENVELOPE_CAPABILITY = 'binary-envelope-v1';
const SEND_FRAME_TYPE = 'send-v1';
const MESSAGE_FRAME_TYPE = 'message-v1';
const SEALED_ENVELOPE_VERSION = 1;
const ENVELOPE_JSON_OVERHEAD = 32;
function maxSealedBytes(maxEnvelopeJsonBytes) {
  const room = maxEnvelopeJsonBytes - ENVELOPE_JSON_OVERHEAD;
  if (!(room > 0)) return 0;
  return Math.floor(room / 4) * 3;
}
function sealedBytes(envelope) {
  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) return null;
  const keys = Object.keys(envelope);
  if (keys.length !== 2 || !keys.includes('v') || !keys.includes('sealed')) return null;
  if (envelope.v !== SEALED_ENVELOPE_VERSION) return null;
  if (typeof envelope.sealed !== 'string' || !envelope.sealed) return null;
  let bytes;
  try {
    bytes = decodeBase64(envelope.sealed);
  } catch (error) {
    return null;
  }
  if (!bytes.length) return null;
  if (encodeBase64(bytes) !== envelope.sealed) return null;
  return bytes;
}
function sealedEnvelope(version, bytes) {
  if (version !== SEALED_ENVELOPE_VERSION) return null;
  if (!(bytes instanceof Uint8Array) || !bytes.length) return null;
  return { v: SEALED_ENVELOPE_VERSION, sealed: encodeBase64(bytes) };
}
function buildSendHeader({
  to,
  ref,
  silent,
  callPush,
  noMeta,
  sealedVersion = SEALED_ENVELOPE_VERSION,
}) {
  const header = { type: SEND_FRAME_TYPE, version: 1, to, sv: sealedVersion };
  if (ref !== undefined && ref !== null) header.ref = ref;
  header.silent = silent ? 1 : 0;
  header.callPush = callPush ? 1 : 0;
  header.noMeta = noMeta ? 1 : 0;
  return header;
}
function sendHeaderFlags(header) {
  return {
    silent: !!(header && header.silent),
    callPush: !!(header && header.callPush),
    noMeta: !!(header && header.noMeta),
  };
}
function buildMessageHeader(frame) {
  const header = {
    type: MESSAGE_FRAME_TYPE,
    version: 1,
    id: frame.id,
    sv: SEALED_ENVELOPE_VERSION,
  };
  if (frame.from) header.from = frame.from;
  if (frame.fromAccount) header.fromAccount = frame.fromAccount;
  if (frame.fromDeviceId) header.fromDeviceId = frame.fromDeviceId;
  if (frame.deviceCertificate) header.deviceCertificate = frame.deviceCertificate;
  if (frame.deviceRoster) header.deviceRoster = frame.deviceRoster;
  return header;
}
function messageFromHeader(header, payload) {
  if (!header || typeof header !== 'object') return null;
  if (header.type !== MESSAGE_FRAME_TYPE || header.version !== 1) return null;
  if (typeof header.id !== 'string' || !header.id) return null;
  const envelope = sealedEnvelope(header.sv, payload);
  if (!envelope) return null;
  const message = { type: 'message', id: header.id, envelope };
  if (typeof header.from === 'string') message.from = header.from;
  if (typeof header.fromAccount === 'string') message.fromAccount = header.fromAccount;
  if (typeof header.fromDeviceId === 'string') message.fromDeviceId = header.fromDeviceId;
  if (header.deviceCertificate) message.deviceCertificate = header.deviceCertificate;
  if (header.deviceRoster) message.deviceRoster = header.deviceRoster;
  return message;
}
module.exports = {
  BINARY_ENVELOPE_CAPABILITY,
  SEND_FRAME_TYPE,
  MESSAGE_FRAME_TYPE,
  SEALED_ENVELOPE_VERSION,
  maxSealedBytes,
  sealedBytes,
  sealedEnvelope,
  buildSendHeader,
  sendHeaderFlags,
  buildMessageHeader,
  messageFromHeader,
};