'use strict';
const SIGNED_FIELDS = ['version', 'url', 'size', 'sha256', 'platform', 'channel', 'notes', 'filesHash'];
const MAX_RELEASE_BYTES = 4 * 1024 * 1024 * 1024;
function manifestChannel(manifest) {
  const value = manifest && manifest.channel;
  return typeof value === 'string' && value ? value : 'stable';
}
function channelAccepts(expected, actual) {
  if (expected === 'canary') return actual === 'canary' || actual === 'stable';
  return actual === 'stable';
}
function versionParts(value) {
  return String(value || '')
    .replace(/^v/i, '')
    .split(/[.-]/)
    .map((part) => Number.parseInt(part, 10))
    .map((part) => (Number.isFinite(part) ? part : 0));
}
function isNewerVersion(candidate, current) {
  const next = versionParts(candidate);
  const installed = versionParts(current);
  const length = Math.max(next.length, installed.length);
  for (let index = 0; index < length; index += 1) {
    const left = next[index] || 0;
    const right = installed[index] || 0;
    if (left !== right) return left > right;
  }
  return false;
}
function filesPayload(files) {
  const list = Array.isArray(files) ? files : [];
  return list
    .map((item) => ({
      path: String((item && item.path) || ''),
      size: Number((item && item.size) || 0),
      sha256: String((item && item.sha256) || '').toLowerCase(),
    }))
    .sort((left, right) => (left.path < right.path ? -1 : left.path > right.path ? 1 : 0))
    .map((item) => `${item.path}\n${item.size}\n${item.sha256}`)
    .join('\n');
}
function canonicalValue(value) {
  const type = typeof value;
  if (type === 'string') return { t: 's', v: value };
  if (type === 'number') return Number.isFinite(value) ? { t: 'n', v: value } : { t: 'x', v: String(value) };
  if (type === 'boolean') return { t: 'b', v: value };
  if (Array.isArray(value)) return { t: 'a', v: value.map(canonicalValue) };
  if (value && type === 'object') {
    const keys = Object.keys(value).sort();
    return { t: 'o', v: keys.map((key) => [key, canonicalValue(value[key])]) };
  }
  return { t: 'x', v: String(value) };
}
function signedPayloadCanonical(manifest) {
  const source = manifest && typeof manifest === 'object' ? manifest : {};
  const shape = [];
  for (const field of SIGNED_FIELDS) {
    const value = source[field];
    if (value === undefined || value === null) continue;
    shape.push([field, canonicalValue(value)]);
  }
  return JSON.stringify(shape);
}
function signedPayload(manifest) {
  const source = manifest && typeof manifest === 'object' ? manifest : {};
  const parts = [];
  for (const field of SIGNED_FIELDS) {
    const value = source[field];
    if (value === undefined || value === null) continue;
    parts.push(`${field}=${String(value)}`);
  }
  return parts.join('\n');
}
function verifyUpdateManifest(input) {
  const {
    manifest,
    currentVersion,
    platform,
    publicKey,
    verifySignature,
    channel = 'stable',
  } = input && typeof input === 'object' ? input : {};
  if (!manifest || typeof manifest !== 'object') return { ok: false, reason: 'манифест не разобран' };
  if (typeof verifySignature !== 'function') return { ok: false, reason: 'проверять подпись нечем' };
  if (!publicKey) return { ok: false, reason: 'ключ выпуска не задан в сборке' };
  const signature = manifest.signature;
  if (typeof signature !== 'string' || !signature) return { ok: false, reason: 'манифест не подписан' };
  let signatureOk = false;
  try {
    signatureOk =
      verifySignature(signedPayload(manifest), signature, publicKey) === true ||
      verifySignature(signedPayloadCanonical(manifest), signature, publicKey) === true;
  } catch (error) {
    signatureOk = false;
  }
  if (!signatureOk) return { ok: false, reason: 'подпись обновления не сходится' };
  if (platform && manifest.platform && manifest.platform !== platform) {
    return { ok: false, reason: 'обновление для другой платформы' };
  }
  if (!channelAccepts(channel, manifestChannel(manifest))) {
    return { ok: false, reason: 'обновление другого канала' };
  }
  if (typeof manifest.version !== 'string' || !manifest.version) {
    return { ok: false, reason: 'в манифесте нет версии' };
  }
  if (!isNewerVersion(manifest.version, currentVersion)) {
    return { ok: false, reason: 'установленная версия не старее' };
  }
  if (typeof manifest.sha256 !== 'string' || !/^[0-9a-f]{64}$/i.test(manifest.sha256)) {
    return { ok: false, reason: 'в манифесте нет отпечатка файла' };
  }
  const size = Number(manifest.size);
  if (!Number.isSafeInteger(size) || size <= 0 || size > MAX_RELEASE_BYTES) {
    return { ok: false, reason: 'в манифесте нет размера файла' };
  }
  const filesHash = manifest.filesHash;
  if (
    filesHash !== undefined &&
    filesHash !== null &&
    (typeof filesHash !== 'string' || !/^[0-9a-f]{64}$/i.test(filesHash))
  ) {
    return { ok: false, reason: 'в манифесте нет свёртки списка файлов' };
  }
  return {
    ok: true,
    reason: 'подпись сходится',
    release: {
      version: manifest.version,
      url: typeof manifest.url === 'string' ? manifest.url : '',
      size,
      sha256: manifest.sha256.toLowerCase(),
      notes: typeof manifest.notes === 'string' ? manifest.notes : '',
      filesHash: typeof filesHash === 'string' ? filesHash.toLowerCase() : '',
    },
  };
}
function fileMatchesRelease(release, actual) {
  const { size, sha256 } = actual && typeof actual === 'object' ? actual : {};
  if (!release || typeof release !== 'object') return { ok: false, reason: 'нечего сверять' };
  const actualSize = Number(size);
  if (!Number.isFinite(actualSize) || actualSize !== Number(release.size)) {
    return { ok: false, reason: 'размер файла не совпал с обещанным' };
  }
  if (typeof sha256 !== 'string' || sha256.toLowerCase() !== String(release.sha256).toLowerCase()) {
    return { ok: false, reason: 'отпечаток файла не совпал — это не то обновление' };
  }
  return { ok: true, reason: 'файл тот самый' };
}
module.exports = {
  SIGNED_FIELDS,
  signedPayload,
  filesPayload,
  isNewerVersion,
  verifyUpdateManifest,
  fileMatchesRelease,
  manifestChannel,
  channelAccepts,
};