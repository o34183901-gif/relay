'use strict';

const path = require('path');
const RELEASES = {
  android: {
    manifest: 'android-version.json',
    canaryManifest: 'android-canary-version.json',
    file: 'licno-android.apk',
    canaryFile: 'licno-android-canary.apk',
    type: 'application/vnd.android.package-archive',
    kind: 'licno',
  },
  distributor: {
    manifest: 'distributor-version.json',
    canaryManifest: '',
    file: 'licno-push.apk',
    canaryFile: '',
    type: 'application/vnd.android.package-archive',
    kind: 'licno',
  },
};

const MAX_MANIFEST_BYTES = 64 * 1024;
const RELEASE_FILE_PATH = '/update/file';
function askedPlatform(value) {
  if (value === undefined || value === null || value === '') return 'android';
  if (typeof value !== 'string') return null;
  return Object.prototype.hasOwnProperty.call(RELEASES, value) ? value : null;
}
function askedChannel(value) {
  if (value === undefined || value === null || value === '') return 'stable';
  if (value === 'stable' || value === 'canary') return value;
  return null;
}
function releasePath(dir, platform, kind) {
  if (!dir || typeof dir !== 'string') return null;
  const release = RELEASES[platform];
  if (!release) return null;
  const name =
    kind === 'file'
      ? release.file
      : kind === 'canaryFile'
        ? release.canaryFile
        : kind === 'canary'
          ? release.canaryManifest
          : release.manifest;
  if (!name) return null;
  const full = path.resolve(dir, name);
  const root = path.resolve(dir);
  if (full !== path.join(root, name)) return null;
  return full;
}
function manifestResponse(input) {
  const { dir, platform, read, channel, verify } = input && typeof input === 'object' ? input : {};
  const asked = askedPlatform(platform);
  if (!asked) return { status: 404, reason: 'неизвестная платформа' };
  const wantedChannel = askedChannel(channel);
  if (!wantedChannel) return { status: 404, reason: 'неизвестный канал' };
  if (wantedChannel === 'canary' && !RELEASES[asked].canaryManifest) {
    return { status: 404, reason: 'у платформы нет тестового канала' };
  }
  const target = releasePath(dir, asked, wantedChannel === 'canary' ? 'canary' : 'manifest');
  if (!target) return { status: 404, reason: 'раздача обновлений не настроена' };
  let text = null;
  try {
    text = read(target);
  } catch (error) {
    return { status: 404, reason: 'выпуска нет' };
  }
  if (typeof text !== 'string' || !text) return { status: 404, reason: 'выпуска нет' };
  if (text.length > MAX_MANIFEST_BYTES) return { status: 404, reason: 'это не манифест' };
  let manifest = null;
  try {
    manifest = JSON.parse(text);
  } catch (error) {
    return { status: 404, reason: 'манифест не разобран' };
  }
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
    return { status: 404, reason: 'манифест не разобран' };
  }
  if (typeof manifest.signature !== 'string' || !manifest.signature) {
    return { status: 404, reason: 'выпуск не подписан' };
  }
  if (typeof verify === 'function' && verify(manifest) !== true) {
    return { status: 404, reason: 'подпись выпуска не сходится' };
  }
  return { status: 200, platform: asked, manifest, body: JSON.stringify(manifest) };
}
function fileResponse(input) {
  const { dir, platform, stat, channel, expect, hash } = input && typeof input === 'object' ? input : {};
  const asked = askedPlatform(platform);
  if (!asked) return { status: 404, reason: 'неизвестная платформа' };
  const wantedChannel = askedChannel(channel);
  if (!wantedChannel) return { status: 404, reason: 'неизвестный канал' };
  const canary = wantedChannel === 'canary';
  if (canary && !RELEASES[asked].canaryFile) {
    return { status: 404, reason: 'у платформы нет тестового канала' };
  }
  const target = releasePath(dir, asked, canary ? 'canaryFile' : 'file');
  if (!target) return { status: 404, reason: 'раздача обновлений не настроена' };
  let info = null;
  try {
    info = stat(target);
  } catch (error) {
    return { status: 404, reason: 'файла выпуска нет' };
  }
  const size = info && Number(info.size);
  if (!Number.isFinite(size) || size <= 0) return { status: 404, reason: 'файла выпуска нет' };
  if (expect && typeof expect === 'object') {
    if (Number(expect.size) !== size) {
      return { status: 404, reason: 'размер файла не совпал с манифестом' };
    }
    if (typeof hash === 'function') {
      let digest = '';
      try {
        digest = hash(target);
      } catch (error) {
        digest = '';
      }
      const wanted = String(expect.sha256 || '').toLowerCase();
      if (!/^[0-9a-f]{64}$/.test(wanted) || String(digest).toLowerCase() !== wanted) {
        return { status: 404, reason: 'отпечаток файла не совпал с манифестом' };
      }
    }
  }
  return {
    status: 200,
    platform: asked,
    channel: wantedChannel,
    path: target,
    size,
    type: RELEASES[asked].type,
    filename: canary ? RELEASES[asked].canaryFile : RELEASES[asked].file,
  };
}
module.exports = {
  askedChannel,
  RELEASES,
  MAX_MANIFEST_BYTES,
  RELEASE_FILE_PATH,
  askedPlatform,
  releasePath,
  manifestResponse,
  fileResponse,
};