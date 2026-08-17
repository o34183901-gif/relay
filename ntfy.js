'use strict';

const NTFY_PREFIX = '/ntfy';
const NTFY_DEFAULT_PORT = 2586;
const NTFY_DEFAULT_CACHE = '12h';
const MAX_NTFY_URL = 2048;

function ntfyEnabled(env) {
  const source = env && typeof env === 'object' ? env : {};
  const raw = source.RELAY_EMBED_NTFY;
  if (raw === undefined || raw === null || raw === '') return false;
  const text = String(raw).trim().toLowerCase();
  return !(text === '0' || text === 'false' || text === 'no' || text === 'off');
}

function ntfyPort(env) {
  const source = env && typeof env === 'object' ? env : {};
  const raw = Number(source.RELAY_NTFY_PORT);
  if (!Number.isInteger(raw) || raw < 1 || raw > 65535) return NTFY_DEFAULT_PORT;
  return raw;
}

function ntfyTarget(url) {
  if (typeof url !== 'string' || !url || url.length > MAX_NTFY_URL) return null;
  if (url[0] !== '/') return null;
  if (url.includes('\0')) return null;
  if (url === NTFY_PREFIX) return '/';
  if (!url.startsWith(`${NTFY_PREFIX}/`) && !url.startsWith(`${NTFY_PREFIX}?`)) return null;
  const rest = url.slice(NTFY_PREFIX.length);
  if (rest.startsWith('?')) return `/${rest}`;
  return rest === '/' ? '/' : rest;
}

function ntfyBaseUrl(selfUrl) {
  const text = typeof selfUrl === 'string' ? selfUrl.trim() : '';
  if (!text) return '';
  let parsed = null;
  try {
    parsed = new URL(text);
  } catch (error) {
    return '';
  }
  if (parsed.protocol !== 'wss:' && parsed.protocol !== 'https:') return '';
  if (!parsed.hostname) return '';
  const port = parsed.port ? `:${parsed.port}` : '';
  return `https://${parsed.hostname}${port}${NTFY_PREFIX}`;
}

function yamlString(value) {
  return `"${String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

function ntfyConfigText(input) {
  const {
    baseUrl = '',
    port = NTFY_DEFAULT_PORT,
    cacheFile = '',
    cacheDuration = NTFY_DEFAULT_CACHE,
  } = input && typeof input === 'object' ? input : {};
  const safePort = Number.isInteger(port) && port >= 1 && port <= 65535 ? port : NTFY_DEFAULT_PORT;
  const lines = [];
  if (baseUrl) lines.push(`base-url: ${yamlString(baseUrl)}`);
  lines.push(`listen-http: ${yamlString(`127.0.0.1:${safePort}`)}`);
  lines.push('behind-proxy: true');
  if (cacheFile) lines.push(`cache-file: ${yamlString(cacheFile)}`);
  lines.push(`cache-duration: ${yamlString(cacheDuration)}`);
  lines.push('attachment-cache-dir: ""');
  lines.push('enable-signup: false');
  lines.push('enable-login: false');
  lines.push('upstream-base-url: ""');
  return `${lines.join('\n')}\n`;
}

function ntfyProxyHeaders(headers, input) {
  const source = headers && typeof headers === 'object' ? headers : {};
  const { host = '', clientIp = '' } = input && typeof input === 'object' ? input : {};
  const copy = {};
  for (const [name, value] of Object.entries(source)) {
    const key = String(name).toLowerCase();
    if (key === 'host' || key === 'connection' || key === 'upgrade') continue;
    if (key === 'x-forwarded-for' || key === 'x-forwarded-proto' || key === 'x-forwarded-host') continue;
    if (key === 'transfer-encoding' || key === 'keep-alive' || key === 'proxy-authorization') continue;
    copy[name] = value;
  }
  if (host) copy['x-forwarded-host'] = host;
  copy['x-forwarded-proto'] = 'https';
  if (clientIp) copy['x-forwarded-for'] = clientIp;
  return copy;
}

module.exports = {
  NTFY_PREFIX,
  NTFY_DEFAULT_PORT,
  NTFY_DEFAULT_CACHE,
  MAX_NTFY_URL,
  ntfyEnabled,
  ntfyPort,
  ntfyTarget,
  ntfyBaseUrl,
  ntfyConfigText,
  ntfyProxyHeaders,
};
