'use strict';
const naclUtil = require('tweetnacl-util');
const ed25519 = require('./ed25519');
const MAX_REPORT_BYTES = 64 * 1024;
const PER_IP_PER_DAY = 2;
const DAY_MS = 24 * 60 * 60 * 1000;
const REPORT_TTL_MS = 14 * DAY_MS;
const FETCH_PAGE = 200;
const FETCH_DOMAIN = 'licno-reports-fetch-v1';
const DELETE_DOMAIN = 'licno-reports-delete-v1';
const REQUEST_TTL_MS = 5 * 60 * 1000;
const REQUEST_SKEW_MS = 5 * 1000;
function validReport(body, bytes) {
  if (!body || typeof body !== 'object') return { ok: false, reason: 'shape' };
  let size = bytes;
  if (!Number.isFinite(size)) {
    try {
      size = Buffer.byteLength(JSON.stringify(body));
    } catch (e) {
      return { ok: false, reason: 'size' };
    }
  }
  if (size > MAX_REPORT_BYTES) return { ok: false, reason: 'size' };
  if (body.v !== 1) return { ok: false, reason: 'version' };
  for (const field of ['ek', 'nonce', 'cipher']) {
    const value = body[field];
    if (typeof value !== 'string' || !value || value.length > MAX_REPORT_BYTES) {
      return { ok: false, reason: 'field:' + field };
    }
  }
  return { ok: true };
}
function canonicalHost(host) {
  if (typeof host !== 'string') return '';
  return host.trim().toLowerCase();
}
function requestChallenge(domain, ts, host) {
  return `${domain}|${canonicalHost(host)}|${ts}`;
}
function verifyOwnerRequest({ domain, ts, host, signature, publicKey, now }) {
  if (typeof ts !== 'number' && typeof ts !== 'string') return { ok: false, reason: 'ts' };
  const stamp = Number(ts);
  if (!Number.isFinite(stamp)) return { ok: false, reason: 'ts' };
  const boundHost = canonicalHost(host);
  if (!boundHost) return { ok: false, reason: 'host' };
  if (stamp - now > REQUEST_SKEW_MS) return { ok: false, reason: 'stale' };
  if (now - stamp > REQUEST_TTL_MS) return { ok: false, reason: 'stale' };
  if (typeof signature !== 'string' || !signature) return { ok: false, reason: 'signature' };
  if (typeof publicKey !== 'string' || !publicKey) return { ok: false, reason: 'key' };
  try {
    const ok = ed25519.verify(
      naclUtil.decodeUTF8(requestChallenge(domain, stamp, boundHost)),
      naclUtil.decodeBase64(signature),
      naclUtil.decodeBase64(publicKey)
    );
    return ok ? { ok: true } : { ok: false, reason: 'signature' };
  } catch (e) {
    return { ok: false, reason: 'signature' };
  }
}
function signOwnerRequest({ domain, ts, host, secretKey }) {
  const boundHost = canonicalHost(host);
  if (!boundHost) throw new Error('report owner signature requires a host');
  return naclUtil.encodeBase64(
    ed25519.sign(
      naclUtil.decodeUTF8(requestChallenge(domain, Number(ts), boundHost)),
      naclUtil.decodeBase64(secretKey)
    )
  );
}
module.exports = {
  MAX_REPORT_BYTES,
  PER_IP_PER_DAY,
  REPORT_TTL_MS,
  FETCH_PAGE,
  FETCH_DOMAIN,
  DELETE_DOMAIN,
  REQUEST_TTL_MS,
  REQUEST_SKEW_MS,
  DAY_MS,
  validReport,
  requestChallenge,
  verifyOwnerRequest,
  signOwnerRequest,
};