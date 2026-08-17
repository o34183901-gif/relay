'use strict';

const path = require('path');
const WEB_APP_PREFIX = '/app';
const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.gif': 'image/gif',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf',
  '.txt': 'text/plain; charset=utf-8',
  '.webmanifest': 'application/manifest+json',
};

function contentType(filePath) {
  return TYPES[path.extname(String(filePath || '')).toLowerCase()] || 'application/octet-stream';
}
function webAppPath(requestUrl) {
  const raw = String(requestUrl || '');
  if (raw !== WEB_APP_PREFIX && !raw.startsWith(`${WEB_APP_PREFIX}/`) && !raw.startsWith(`${WEB_APP_PREFIX}?`)) {
    return null;
  }
  let pathname;
  try {
    pathname = new URL(raw, 'http://x').pathname;
  } catch (error) {
    return '';
  }
  if (pathname !== WEB_APP_PREFIX && !pathname.startsWith(`${WEB_APP_PREFIX}/`)) return '';
  let decoded;
  try {
    decoded = decodeURIComponent(pathname);
  } catch (error) {
    return '';
  }
  if (decoded !== WEB_APP_PREFIX && !decoded.startsWith(`${WEB_APP_PREFIX}/`)) return '';
  const rest = decoded.slice(WEB_APP_PREFIX.length).replace(/^\/+/, '');
  if (!rest) return 'index.html';
  if (rest.includes('\0')) return '';
  const parts = [];
  for (const part of rest.split('/')) {
    if (!part || part === '.') continue;
    if (part === '..') return '';
    if (part.includes('\\')) return '';
    parts.push(part);
  }
  if (!parts.length) return 'index.html';
  if (parts.join('/').length > 200) return '';
  return parts.join('/');
}
function resolveWebFile(root, relative) {
  if (!root || !relative) return '';
  const full = path.resolve(root, relative);
  const base = path.resolve(root);
  if (full !== base && !full.startsWith(base + path.sep)) return '';
  return full;
}
function webAppHeaders(relative, size) {
  const type = contentType(relative);
  const isPage = relative === 'index.html' || relative.endsWith('.html');
  const isServiceWorker = relative === 'sw.js';
  return {
    'content-type': type,
    'content-length': String(size),
    'x-content-type-options': 'nosniff',
    'cache-control': isPage || isServiceWorker ? 'no-cache' : 'public, max-age=3600',
  };
}
module.exports = {
  WEB_APP_PREFIX,
  TYPES,
  contentType,
  webAppPath,
  resolveWebFile,
  webAppHeaders,
};