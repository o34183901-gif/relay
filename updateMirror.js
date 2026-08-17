'use strict';

const crypto = require('crypto');

const { verifyUpdateManifest, isNewerVersion, filesPayload } = require('./updateManifest');
const DEFAULT_SOURCE = 'https://raw.githubusercontent.com/o34183901-gif/relay/main';
const DEFAULT_INTERVAL_MS = 30 * 60 * 1000;
const MAX_FILE_BYTES = 200 * 1024 * 1024;
const MAX_MANIFEST_BYTES = 64 * 1024;

function manifestUrl(source, platform, channel) {
  const base = String(source || '').trim().replace(/\/+$/, '');
  if (!base) return '';
  if (platform === 'android' && channel === 'canary') return `${base}/android-canary-version.json`;
  if (channel === 'canary') return '';
  if (platform === 'android') return `${base}/android-version.json`;
  if (platform === 'web') return `${base}/web-version.json`;
  return '';
}
function checkedManifest({ body, platform, publicKey, verifySignature, currentVersion, channel }) {
  if (typeof body !== 'string' || !body || body.length > MAX_MANIFEST_BYTES) {
    return { ok: false, reason: 'манифест не получен или неправдоподобно велик' };
  }
  let manifest;
  try {
    manifest = JSON.parse(body);
  } catch (error) {
    return { ok: false, reason: 'манифест не разбирается как JSON' };
  }
  const verdict = verifyUpdateManifest({
    manifest,
    currentVersion: currentVersion || '0.0.0',
    platform,
    publicKey,
    verifySignature,
    channel: channel === 'canary' ? 'canary' : 'stable',
  });
  if (!verdict.ok) return { ok: false, reason: verdict.reason };
  return { ok: true, reason: '', release: verdict.release };
}
function needsFetch({ have, release }) {
  if (!release || typeof release !== 'object') return false;
  if (!have || typeof have !== 'object' || !have.version) return true;
  if (isNewerVersion(release.version, have.version)) return true;
  if (String(have.version) !== String(release.version)) return false;
  return String(have.sha256 || '').toLowerCase() !== String(release.sha256 || '').toLowerCase();
}
function fileVerdict({ size, sha256, release }) {
  if (!release || typeof release !== 'object') return { ok: false, reason: 'нечего сверять' };
  const actual = Number(size);
  if (!Number.isFinite(actual) || actual <= 0) return { ok: false, reason: 'файл пуст или не скачался' };
  if (actual > MAX_FILE_BYTES) return { ok: false, reason: 'файл больше потолка' };
  if (actual !== Number(release.size)) return { ok: false, reason: 'длина файла не совпала с подписанной' };
  if (typeof sha256 !== 'string' || sha256.toLowerCase() !== String(release.sha256).toLowerCase()) {
    return { ok: false, reason: 'отпечаток файла не совпал с подписанным' };
  }
  return { ok: true, reason: '' };
}
function usableFileUrl(url) {
  const value = String(url || '').trim();
  if (!/^https:\/\//i.test(value)) return '';
  try {
    return new URL(value).toString();
  } catch (error) {
    return '';
  }
}
const MAX_WEB_FILES = 400;
const MAX_WEB_BYTES = 64 * 1024 * 1024;
const MAX_WEB_FILE_BYTES = 16 * 1024 * 1024;
function webFilesVerdict({ files, filesHash }) {
  if (!Array.isArray(files) || !files.length) return { ok: false, reason: 'в манифесте нет списка файлов' };
  if (files.length > MAX_WEB_FILES) return { ok: false, reason: 'файлов больше, чем бывает у веб-сборки' };
  let total = 0;
  for (const item of files) {
    if (!item || typeof item !== 'object') return { ok: false, reason: 'запись списка не объект' };
    if (!safeWebPath(item.path)) return { ok: false, reason: `негодный путь: ${String(item && item.path)}` };
    const size = Number(item.size);
    if (!Number.isFinite(size) || size < 0) return { ok: false, reason: 'у файла нет длины' };
    if (size > MAX_WEB_FILE_BYTES) return { ok: false, reason: 'файл веб-сборки неправдоподобно велик' };
    if (!/^[0-9a-f]{64}$/i.test(String(item.sha256 || ''))) return { ok: false, reason: 'у файла нет отпечатка' };
    total += size;
    if (total > MAX_WEB_BYTES) return { ok: false, reason: 'веб-сборка целиком больше потолка' };
  }
  const digest = crypto.createHash('sha256').update(filesPayload(files), 'utf8').digest('hex');
  if (digest !== String(filesHash || '').toLowerCase()) {
    return { ok: false, reason: 'список файлов не сходится с подписанной свёрткой' };
  }
  return { ok: true, reason: '' };
}
function safeWebPath(value) {
  const raw = String(value || '');
  if (!raw || raw.length > 200) return '';
  if (raw.startsWith('/') || raw.startsWith('\\')) return '';
  if (/^[a-zA-Z]:/.test(raw)) return '';
  if (raw.includes('\\')) return '';
  if (raw.includes('\0')) return '';
  const parts = raw.split('/');
  for (const part of parts) {
    if (!part || part === '.' || part === '..') return '';
  }
  return parts.join('/');
}
function treeFileUrl(source, platform, relativePath) {
  const base = String(source || '').trim().replace(/\/+$/, '');
  const safe = safeWebPath(relativePath);
  const dir = platform === 'web' ? 'web' : '';
  if (!base || !safe || !dir) return '';
  return `${base}/${dir}/${safe.split('/').map(encodeURIComponent).join('/')}`;
}
function webFileUrl(source, relativePath) {
  return treeFileUrl(source, 'web', relativePath);
}
module.exports = {
  DEFAULT_SOURCE,
  DEFAULT_INTERVAL_MS,
  MAX_FILE_BYTES,
  MAX_MANIFEST_BYTES,
  manifestUrl,
  checkedManifest,
  needsFetch,
  fileVerdict,
  usableFileUrl,
  webFilesVerdict,
  safeWebPath,
  webFileUrl,
  treeFileUrl,
  MAX_WEB_FILES,
  MAX_WEB_BYTES,
  MAX_WEB_FILE_BYTES,
};