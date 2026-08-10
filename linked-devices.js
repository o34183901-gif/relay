'use strict';

/**
 * Чистые криптографические контракты протокола связанных устройств v2.
 *
 * Модуль намеренно не зависит от сети, SQLite, React Native или Tauri. Один и тот
 * же файл используется релеем, Android-клиентом и desktop-клиентом, чтобы
 * канонизация подписываемых данных не расходилась между платформами.
 */
const nacl = require('tweetnacl');
const { encodeBase64, decodeBase64, encodeUTF8, decodeUTF8 } = require('tweetnacl-util');
// АУД-КР2: правило вывода кода подтверждения живёт отдельным чистым модулем —
// от него зависит, можно ли подменить компьютер при привязке, и проверяться оно
// должно целиком, а не заодно с остальным протоколом.
const verifyCode = require('./verification-code');
const ed25519 = require('./ed25519');
// Пробрасываем как есть: правило сверки и цена вывода — часть контракта привязки,
// и вызывающим не должно быть дела до того, в каком файле они живут.
// ПРВ-1: код подключения выводится там же, где остальные коды привязки, — иначе
// появился бы второй файл, от которого зависит, можно ли привязать чужой ПК.
const {
  verificationCodesMatch,
  STRONG_CODE_ROUNDS,
  LINK_CODE_DIGITS,
  LINK_CODE_MAX_ATTEMPTS,
  generateLinkCode,
  normalizeLinkCode,
  formatLinkCode,
  linkProofsMatch,
} = verifyCode;

const LINKED_DEVICE_VERSION = 2;
const DEVICE_CERT_TYPE = 'licno-device-certificate';
const DEVICE_ROSTER_TYPE = 'licno-device-roster';
const PAIRING_REQUEST_TYPE = 'licno-device-link-request';
const PAIRING_QR_PREFIX = 'licno://link-device/v2#';
const PAIRING_QR_COMPACT_PREFIX = 'licno://ld/3#';
const PAIRING_QR_BINARY_PREFIX = 'LICNO:LD4:';
/**
 * ПРВ-1: срок жизни QR — полторы минуты вместо прежних двух.
 *
 * Две минуты выбирались под сценарий «взять телефон, открыть приложение, дойти
 * до сканера и СВЕРИТЬ КОД». Сверки глазами больше нет: телефон показывает код
 * подключения, и на его ввод отведено отдельное окно (PAIRING_APPROVAL_WINDOW_MS
 * в src/pairingFlow.js). Самому QR остаётся «поднести телефон к экрану», и
 * полутора минут хватает с запасом — истёкший QR обновляется автоматически.
 * Дыру сокращение не закрывает (переслать картинку успевают и за минуту), её
 * закрывает код подключения; но длинный срок после этого нечем оправдать.
 *
 * ВНИМАНИЕ, СОВМЕСТИМОСТЬ. Значение входит в компактный QR как флаг «срок по
 * умолчанию», и декодер разворачивает его в PAIRING_TTL_MS СВОЕЙ версии. Разные
 * версии получат разный expiresAt, подпись не сойдётся, и QR не отсканируется.
 * Это НАМЕРЕННО: телефон прежней версии не умеет требовать код подключения и
 * привязался бы по старому — уязвимому — пути. Отказ на сканировании лучше
 * тихой привязки без кода. Уже привязанных устройств это не касается: новых
 * запросов привязки они не создают.
 */
const PAIRING_TTL_MS = 90 * 1000;
const PAIRING_CLOCK_SKEW_MS = 30 * 1000;
const MAX_ACTIVE_DEVICES = 10;
const MAX_ROSTER_ENTRIES = 32;

const CERT_DOMAIN = 'licno-device-certificate-v2|';
const ROSTER_DOMAIN = 'licno-device-roster-v2|';
const PAIRING_DOMAIN = 'licno-device-link-request-v2|';
const DEVICE_ID_DOMAIN = 'licno-device-id-v2|';

const CAPABILITIES = new Set(['messages', 'files', 'voice', 'history-sync', 'notifications']);
const CAPABILITY_BITS = Object.freeze({ files: 1, 'history-sync': 2, messages: 4, notifications: 8, voice: 16 });
const PLATFORMS = new Set(['android', 'web', 'windows', 'macos', 'linux']);
const DESKTOP_PLATFORMS = new Set(['windows', 'macos', 'linux']);
const PLATFORM_CODES = Object.freeze({ windows: 'w', macos: 'm', linux: 'l' });
const CODE_PLATFORMS = Object.freeze({ w: 'windows', m: 'macos', l: 'linux' });
const BINARY_PLATFORM_CODES = Object.freeze({ windows: 0, macos: 1, linux: 2 });
const BINARY_CODE_PLATFORMS = Object.freeze({ 0: 'windows', 1: 'macos', 2: 'linux' });
const DEFAULT_DEVICE_NAMES = Object.freeze({
  windows: 'Компьютер Windows',
  macos: 'Mac',
  linux: 'Компьютер Linux',
});
const PAIRING_RELAY_PROFILES = Object.freeze([
  null,
  Object.freeze([
    'wss://89.108.83.230.sslip.io',
    'wss://46.226.162.166.sslip.io',
    'wss://77.221.137.215.sslip.io',
  ]),
]);
const BASE41_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$%*+-';
const BINARY_CANONICAL_NAME = 0x80;
const BINARY_DEFAULT_TTL = 0x80;

function fail(message) {
  const error = new Error(message);
  error.code = 'LINKED_DEVICE_INVALID';
  throw error;
}

function isPlainObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/** Стабильный JSON: ключи объектов сортируются, порядок массивов сохраняется. */
function stableStringify(value) {
  function normalize(input) {
    if (input === null || typeof input === 'string' || typeof input === 'boolean') return input;
    if (typeof input === 'number') {
      if (!Number.isFinite(input)) fail('non-finite number');
      return input;
    }
    if (Array.isArray(input)) return input.map((item) => normalize(item));
    if (!isPlainObject(input)) fail('unsupported signed value');
    const out = {};
    for (const key of Object.keys(input).sort()) {
      const item = input[key];
      if (typeof item === 'undefined' || typeof item === 'function' || typeof item === 'symbol') {
        fail('unsupported signed field');
      }
      out[key] = normalize(item);
    }
    return out;
  }
  return JSON.stringify(normalize(value));
}

function decodeExact(value, bytes, label) {
  if (typeof value !== 'string' || !value || value.length > 256) fail(`${label} is required`);
  let decoded;
  try {
    decoded = decodeBase64(value);
  } catch (error) {
    fail(`${label} is not base64`);
  }
  if (decoded.length !== bytes) fail(`${label} has invalid length`);
  return decoded;
}

function cleanText(value, label, max = 64) {
  if (typeof value !== 'string') fail(`${label} is required`);
  const clean = [...value]
    .filter((char) => {
      const code = char.charCodeAt(0);
      return code > 31 && code !== 127;
    })
    .join('')
    .trim();
  if (!clean || [...clean].length > max) fail(`${label} has invalid length`);
  return clean;
}

function cleanTimestamp(value, label) {
  if (!Number.isSafeInteger(value) || value < 1) fail(`${label} is invalid`);
  return value;
}

function toBase64Url(bytes) {
  return encodeBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function fromBase64Url(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) fail('invalid base64url');
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (value.length % 4)) % 4);
  try {
    return decodeBase64(padded);
  } catch (error) {
    fail('invalid base64url');
  }
}

function compactBase64(value, bytes, label) {
  return toBase64Url(decodeExact(value, bytes, label));
}

function expandBase64Url(value, bytes, label) {
  const decoded = fromBase64Url(value);
  if (decoded.length !== bytes) fail(`${label} has invalid length`);
  return encodeBase64(decoded);
}

function compactRelay(value) {
  if (value.startsWith('wss://')) return value.slice(6);
  if (value.startsWith('ws://')) return `~${value.slice(5)}`;
  return value;
}

function expandRelay(value) {
  if (typeof value !== 'string' || !value) fail('pairing relay URL is invalid');
  if (value.startsWith('~')) return `ws://${value.slice(1)}`;
  if (!value.includes('://')) return `wss://${value}`;
  return value;
}

function parseBase36(value, label) {
  if (typeof value !== 'string' || !/^[0-9a-z]{1,12}$/.test(value)) fail(`${label} is invalid`);
  const result = Number.parseInt(value, 36);
  if (!Number.isSafeInteger(result)) fail(`${label} is invalid`);
  return result;
}

function capabilityMask(capabilities) {
  return capabilities.reduce((mask, capability) => mask | CAPABILITY_BITS[capability], 0);
}

function capabilitiesFromMaskNumber(mask) {
  const knownMask = Object.values(CAPABILITY_BITS).reduce((result, bit) => result | bit, 0);
  if (!Number.isInteger(mask) || !mask || (mask & ~knownMask)) fail('unsupported capability');
  return Object.keys(CAPABILITY_BITS).filter((capability) => (mask & CAPABILITY_BITS[capability]) !== 0);
}

function capabilitiesFromMask(value) {
  return capabilitiesFromMaskNumber(parseBase36(value, 'capabilities'));
}

function encodeBase41(bytes) {
  if (!(bytes instanceof Uint8Array) || !bytes.length || bytes.length > 8192) {
    fail('pairing QR is invalid');
  }
  let output = '';
  let index = 0;
  for (; index + 1 < bytes.length; index += 2) {
    let value = bytes[index] * 256 + bytes[index + 1];
    output += BASE41_ALPHABET[value % 41];
    value = Math.floor(value / 41);
    output += BASE41_ALPHABET[value % 41];
    output += BASE41_ALPHABET[Math.floor(value / 41)];
  }
  if (index < bytes.length) {
    const value = bytes[index];
    output += BASE41_ALPHABET[value % 41];
    output += BASE41_ALPHABET[Math.floor(value / 41)];
  }
  return output;
}

function decodeBase41(value) {
  if (typeof value !== 'string' || !value || value.length > 12288 || value.length % 3 === 1) {
    fail('pairing QR is invalid');
  }
  const output = [];
  for (let index = 0; index < value.length; ) {
    const remaining = value.length - index;
    const count = remaining === 2 ? 2 : 3;
    const first = BASE41_ALPHABET.indexOf(value[index]);
    const second = BASE41_ALPHABET.indexOf(value[index + 1]);
    const third = count === 3 ? BASE41_ALPHABET.indexOf(value[index + 2]) : 0;
    if (first < 0 || second < 0 || third < 0) fail('pairing QR is invalid');
    const decoded = first + second * 41 + third * 41 * 41;
    if (count === 3) {
      if (decoded > 0xffff) fail('pairing QR is invalid');
      output.push(decoded >>> 8, decoded & 0xff);
    } else {
      if (decoded > 0xff) fail('pairing QR is invalid');
      output.push(decoded);
    }
    index += count;
  }
  return new Uint8Array(output);
}

function unsignedBytes(value, length, label) {
  if (!Number.isSafeInteger(value) || value < 0) fail(`${label} is invalid`);
  const output = new Uint8Array(length);
  let remaining = value;
  for (let index = length - 1; index >= 0; index -= 1) {
    output[index] = remaining % 256;
    remaining = Math.floor(remaining / 256);
  }
  if (remaining) fail(`${label} is invalid`);
  return output;
}

function concatBytes(parts) {
  const length = parts.reduce((total, part) => total + part.length, 0);
  if (!length || length > 8192) fail('pairing QR is too large');
  const output = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function equalList(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function signPayload(domain, payload, secretKey) {
  const sk = decodeExact(secretKey, nacl.sign.secretKeyLength, 'sign secret key');
  const bytes = decodeUTF8(domain + stableStringify(payload));
  return encodeBase64(ed25519.sign(bytes, sk));
}

// В-2: САМОЕ ГОРЯЧЕЕ МЕСТО ПРОВЕРКИ ПОДПИСИ ВО ВСЁМ ПРОЕКТЕ.
//
// Через verifyPayload проходят сертификат каждого устройства собеседника и
// подпись самого списка устройств, а список едет с КАЖДЫМ входящим конвертом.
// Проверка подписи здесь — не деталь, а то, сколько человек ждёт свои сообщения
// после возвращения в сеть.
//
// ЗАМЕР ПЕРЕСНЯТ (П1-0), И ПРЕЖНИЕ ЦИФРЫ БЫЛИ УСТАРЕВШИМИ.
//
// Здесь стояло «42 мс при одном устройстве и 200 мс при десяти». Эти числа сняты
// коммитом ВЫС-17, а быстрый уровень Ed25519 внесён СЛЕДУЮЩИМ за ним (НАТ-1), и
// с тех пор их никто не пересматривал. Замер того же пути сегодня, на настольной
// машине, через ту реализацию, которая работает в приложении на самом деле
// (ed25519.fastAvailable() === true):
//
//   1 устройство   5,1 мс      10 устройств (потолок)  21,6 мс
//
// То есть в восемь-девять раз дешевле написанного. На телефоне вчетверо больше —
// порядка 20 и 90 мс. Вывод от этого не меняется: девяносто миллисекунд одним
// куском это пять пропущенных кадров подряд, и разрезать этот кусок нечем, пока
// проверка синхронна. Но масштаб теперь честный, и решать по нему можно.
//
// Формат подписи не изменился: обёртка отдаёт те же байты, а подписи двух
// реализаций взаимно проверяемы (test/ed25519.test.js). Поэтому клиент и релей
// разных версий совместимы в обе стороны и обновляться могут порознь.
function verifyPayload(domain, payload, signature, publicKey) {
  try {
    const sig = decodeExact(signature, nacl.sign.signatureLength, 'signature');
    const pk = decodeExact(publicKey, nacl.sign.publicKeyLength, 'sign public key');
    return ed25519.verify(decodeUTF8(domain + stableStringify(payload)), sig, pk);
  } catch (error) {
    return false;
  }
}

function deriveDeviceId(devicePublicKey) {
  decodeExact(devicePublicKey, nacl.box.publicKeyLength, 'device public key');
  const hash = nacl.hash(decodeUTF8(DEVICE_ID_DOMAIN + devicePublicKey));
  return toBase64Url(hash.slice(0, 16));
}

function normalizeCapabilities(value) {
  if (!Array.isArray(value)) fail('capabilities must be an array');
  const result = [...new Set(value.map((item) => cleanText(item, 'capability', 32)))].sort();
  if (!result.length || result.some((item) => !CAPABILITIES.has(item))) fail('unsupported capability');
  return result;
}

function certificatePayload(input) {
  if (!isPlainObject(input)) fail('certificate must be an object');
  const accountPublicKey = input.accountPublicKey;
  const accountSignPublicKey = input.accountSignPublicKey;
  const devicePublicKey = input.devicePublicKey;
  const deviceSignPublicKey = input.deviceSignPublicKey;
  decodeExact(accountPublicKey, nacl.box.publicKeyLength, 'account public key');
  decodeExact(accountSignPublicKey, nacl.sign.publicKeyLength, 'account sign public key');
  decodeExact(devicePublicKey, nacl.box.publicKeyLength, 'device public key');
  decodeExact(deviceSignPublicKey, nacl.sign.publicKeyLength, 'device sign public key');
  const deviceId = cleanText(input.deviceId, 'device id', 64);
  if (deviceId !== deriveDeviceId(devicePublicKey)) fail('device id does not match device key');
  const platform = cleanText(input.platform, 'platform', 16).toLowerCase();
  if (!PLATFORMS.has(platform)) fail('unsupported platform');
  return {
    v: LINKED_DEVICE_VERSION,
    type: DEVICE_CERT_TYPE,
    accountPublicKey,
    accountSignPublicKey,
    deviceId,
    devicePublicKey,
    deviceSignPublicKey,
    name: cleanText(input.name, 'device name'),
    platform,
    issuedAt: cleanTimestamp(input.issuedAt, 'issuedAt'),
    capabilities: normalizeCapabilities(input.capabilities),
  };
}

function createDeviceCertificate(input, accountSignSecretKey) {
  const payload = certificatePayload(input);
  return { ...payload, rootSignature: signPayload(CERT_DOMAIN, payload, accountSignSecretKey) };
}

function assertDeviceCertificate(certificate, options = {}) {
  const payload = certificatePayload(certificate);
  const expectedAccount = options.accountPublicKey;
  const expectedRootSign = options.accountSignPublicKey;
  if (expectedAccount && payload.accountPublicKey !== expectedAccount) fail('certificate belongs to another account');
  if (expectedRootSign && payload.accountSignPublicKey !== expectedRootSign) fail('certificate has another root key');
  if (!verifyPayload(CERT_DOMAIN, payload, certificate.rootSignature, payload.accountSignPublicKey)) {
    fail('bad device certificate signature');
  }
  return { ...payload, rootSignature: certificate.rootSignature };
}

function verifyDeviceCertificate(certificate, options = {}) {
  try {
    assertDeviceCertificate(certificate, options);
    return true;
  } catch (error) {
    return false;
  }
}

function normalizeRosterEntries(entries, accountPublicKey, accountSignPublicKey) {
  if (!Array.isArray(entries) || !entries.length || entries.length > MAX_ROSTER_ENTRIES) {
    fail('roster has invalid device count');
  }
  const seenIds = new Set();
  const seenKeys = new Set();
  const normalized = entries.map((entry) => {
    if (!isPlainObject(entry)) fail('invalid roster entry');
    const certificate = assertDeviceCertificate(entry.certificate, { accountPublicKey, accountSignPublicKey });
    if (seenIds.has(certificate.deviceId) || seenKeys.has(certificate.devicePublicKey)) fail('duplicate roster device');
    seenIds.add(certificate.deviceId);
    seenKeys.add(certificate.devicePublicKey);
    let revokedAt = null;
    if (entry.revokedAt !== null && typeof entry.revokedAt !== 'undefined') {
      revokedAt = cleanTimestamp(entry.revokedAt, 'revokedAt');
      if (revokedAt < certificate.issuedAt) fail('device revoked before it was issued');
    }
    return { certificate, revokedAt };
  });
  normalized.sort((a, b) => a.certificate.deviceId.localeCompare(b.certificate.deviceId));
  const active = normalized.filter((entry) => entry.revokedAt === null);
  if (!active.length || active.length > MAX_ACTIVE_DEVICES) fail('roster has invalid active device count');
  const primary = active.find(
    (entry) =>
      entry.certificate.devicePublicKey === accountPublicKey &&
      entry.certificate.deviceSignPublicKey === accountSignPublicKey
  );
  if (!primary) fail('active primary device is required');
  return normalized;
}

function rosterPayload(input) {
  if (!isPlainObject(input)) fail('roster must be an object');
  decodeExact(input.accountPublicKey, nacl.box.publicKeyLength, 'account public key');
  decodeExact(input.accountSignPublicKey, nacl.sign.publicKeyLength, 'account sign public key');
  const version = input.version;
  if (!Number.isSafeInteger(version) || version < 1) fail('roster version is invalid');
  const updatedAt = cleanTimestamp(input.updatedAt, 'updatedAt');
  return {
    v: LINKED_DEVICE_VERSION,
    type: DEVICE_ROSTER_TYPE,
    accountPublicKey: input.accountPublicKey,
    accountSignPublicKey: input.accountSignPublicKey,
    version,
    updatedAt,
    devices: normalizeRosterEntries(input.devices, input.accountPublicKey, input.accountSignPublicKey),
  };
}

function createSignedRoster(input, accountSignSecretKey) {
  const payload = rosterPayload(input);
  return { ...payload, rootSignature: signPayload(ROSTER_DOMAIN, payload, accountSignSecretKey) };
}

function assertSignedRoster(roster, options = {}) {
  const payload = rosterPayload(roster);
  if (options.accountPublicKey && payload.accountPublicKey !== options.accountPublicKey) fail('roster belongs to another account');
  if (options.accountSignPublicKey && payload.accountSignPublicKey !== options.accountSignPublicKey) fail('roster has another root key');
  if (Number.isSafeInteger(options.minVersion) && payload.version < options.minVersion) fail('stale roster');
  if (!verifyPayload(ROSTER_DOMAIN, payload, roster.rootSignature, payload.accountSignPublicKey)) {
    fail('bad roster signature');
  }
  return { ...payload, rootSignature: roster.rootSignature };
}

/**
 * КРИТ-04: имеет ли эта сторона ПРАВО переписывать список устройств аккаунта.
 *
 * ПОЧЕМУ ОТДЕЛЬНО ОТ ПРОВЕРКИ ПОДПИСЕЙ
 *
 * Раньше порядок был обратным: сначала assertSignedRoster разбирал кандидата
 * целиком — а это проверка корневой подписи плюс отдельная проверка подписи
 * КАЖДОГО сертификата устройства, до тридцати двух штук в одном кадре, — и
 * только потом выяснялось, что прислал его вообще не владелец аккаунта.
 *
 * То есть работу назначал тот, у кого нет никаких прав: аноним слал кадр с
 * тридцатью двумя сертификатами, узел честно проверял тридцать три подписи
 * Ed25519 и отвечал «нельзя». Общий лимит — восемьдесят кадров в секунду, узел
 * однопоточный, и всё это время он не обслуживает никого.
 *
 * Здесь смотрят ровно на два ЗАЯВЛЕННЫХ поля и на состояние соединения. Этого
 * достаточно, чтобы отказать до единой криптографической операции. Заявленным
 * полям при этом ничего не доверяется: то же правило применяется второй раз,
 * уже к разобранному и проверенному объекту, — и авторитетно именно оно.
 * Первый вызов только экономит работу, второй решает.
 *
 * Правила ровно те же, что были:
 *   • аккаунт уже известен — корневой ключ обязан совпасть с закреплённым;
 *   • аккаунта ещё нет — создать его может только доказанный сеанс того самого
 *     адреса, к которому привязан этот же корневой ключ подписи.
 *
 * ПОЧЕМУ ПРИЧИНА ОТКАЗА ГОВОРИТСЯ НЕ ВСЕМ
 *
 * Отвечать точной причиной кому угодно нельзя, и это не мелочь. «Корневой ключ
 * не тот» означает «аккаунт X узлу известен», а «нужен корневой сеанс» —
 * «неизвестен». Раньше добраться до этих ответов без валидной подписи было
 * нельзя вовсе: до них просто не доходило. Пусти сюда всех — и любой,
 * назвавшийся чужим адресом, спрашивал бы у релея, заводил ли там аккаунт
 * конкретный человек, и с каким корневым ключом. Ускорение не стоит нового
 * способа узнавать про чужие аккаунты.
 *
 * Поэтому точная причина полагается только тому, кто сидит на САМОМ адресе
 * аккаунта. Воспользоваться этим, не заняв адрес, нельзя, а закреплённый адрес
 * занять нельзя без доказательства владения (АУД-Э1) — значит и спросить про
 * существующий чужой аккаунт таким способом не выйдет. Всем остальным отказ
 * выглядит так же, как негодный ростер, то есть ровно так, как выглядел раньше.
 *
 * Условие намеренно НЕ включает `proven`: владелец, ещё не предъявивший
 * доказательство, — самый частый получатель отказа «нужен корневой сеанс», и
 * именно эта строка объясняет ему, что делать дальше. Спрятать её значило бы
 * ради приватности, которой здесь не прибавится, сломать единственную подсказку.
 */
function rosterWriteGate(claimed, session = {}) {
  const accountPublicKey = claimed && claimed.accountPublicKey;
  const accountSignPublicKey = claimed && claimed.accountSignPublicKey;
  const onOwnAddress = !!accountPublicKey && session.sessionPublicKey === accountPublicKey;
  const deny = (reason) => ({ ok: false, reason: onOwnAddress ? reason : 'invalid-roster' });
  if (typeof accountPublicKey !== 'string' || !accountPublicKey) {
    return { ok: false, reason: 'invalid-roster' };
  }
  if (typeof accountSignPublicKey !== 'string' || !accountSignPublicKey) {
    return { ok: false, reason: 'invalid-roster' };
  }
  if (session.knownAccountSignPublicKey) {
    return session.knownAccountSignPublicKey === accountSignPublicKey
      ? { ok: true }
      : deny('root-key-conflict');
  }
  const bootstrap =
    !!session.proven && onOwnAddress && session.boundRootSignPublicKey === accountSignPublicKey;
  return bootstrap ? { ok: true } : deny('account-bootstrap-requires-root');
}

function verifySignedRoster(roster, options = {}) {
  try {
    assertSignedRoster(roster, options);
    return true;
  } catch (error) {
    return false;
  }
}

function cleanRelays(relays) {
  if (!Array.isArray(relays) || !relays.length || relays.length > 8) fail('pairing relays are invalid');
  const out = [...new Set(relays.map((item) => cleanText(item, 'relay url', 256)))];
  for (const value of out) {
    let url;
    try {
      url = new URL(value);
    } catch (error) {
      fail('pairing relay URL is invalid');
    }
    if (url.protocol !== 'wss:' && url.protocol !== 'ws:') fail('pairing relay protocol is invalid');
    if (url.username || url.password || url.hash) fail('pairing relay URL is invalid');
  }
  return out;
}

function pairingPayload(input) {
  if (!isPlainObject(input)) fail('pairing request must be an object');
  decodeExact(input.devicePublicKey, nacl.box.publicKeyLength, 'device public key');
  decodeExact(input.deviceSignPublicKey, nacl.sign.publicKeyLength, 'device sign public key');
  const deviceId = cleanText(input.deviceId, 'device id', 64);
  if (deviceId !== deriveDeviceId(input.devicePublicKey)) fail('device id does not match device key');
  const platform = cleanText(input.platform, 'platform', 16).toLowerCase();
  if (!DESKTOP_PLATFORMS.has(platform)) fail('pairing platform is invalid');
  const createdAt = cleanTimestamp(input.createdAt, 'createdAt');
  const expiresAt = cleanTimestamp(input.expiresAt, 'expiresAt');
  if (expiresAt <= createdAt || expiresAt - createdAt > PAIRING_TTL_MS) fail('pairing expiry is invalid');
  decodeExact(input.nonce, 32, 'pairing nonce');
  decodeExact(input.pairingId, 18, 'pairing id');
  return {
    v: LINKED_DEVICE_VERSION,
    type: PAIRING_REQUEST_TYPE,
    pairingId: input.pairingId,
    deviceId,
    devicePublicKey: input.devicePublicKey,
    deviceSignPublicKey: input.deviceSignPublicKey,
    name: cleanText(input.name, 'device name'),
    platform,
    createdAt,
    expiresAt,
    nonce: input.nonce,
    relays: cleanRelays(input.relays),
    capabilities: normalizeCapabilities(input.capabilities),
  };
}

function createPairingRequest(input, deviceSignSecretKey, randomBytes = nacl.randomBytes) {
  const createdAt = input.createdAt || Date.now();
  const payload = pairingPayload({
    ...input,
    pairingId: input.pairingId || encodeBase64(randomBytes(18)),
    nonce: input.nonce || encodeBase64(randomBytes(32)),
    createdAt,
    expiresAt: input.expiresAt || createdAt + PAIRING_TTL_MS,
  });
  return { ...payload, requestSignature: signPayload(PAIRING_DOMAIN, payload, deviceSignSecretKey) };
}

function assertPairingRequest(request, options = {}) {
  const payload = pairingPayload(request);
  if (!verifyPayload(PAIRING_DOMAIN, payload, request.requestSignature, payload.deviceSignPublicKey)) {
    fail('bad pairing request signature');
  }
  const now = Number.isSafeInteger(options.now) ? options.now : Date.now();
  if (now < payload.createdAt - PAIRING_CLOCK_SKEW_MS) fail('pairing request is from the future');
  if (now > payload.expiresAt + PAIRING_CLOCK_SKEW_MS) fail('pairing request expired');
  return { ...payload, requestSignature: request.requestSignature };
}

function verifyPairingRequest(request, options = {}) {
  try {
    assertPairingRequest(request, options);
    return true;
  } catch (error) {
    return false;
  }
}

/** Совместимый QR v3 для телефонов, которые ещё не получили декодер v4. */
function encodePairingQrCompat(request) {
  const valid = assertPairingRequest(request, { now: request.createdAt });
  const compact = {
    i: compactBase64(valid.pairingId, 18, 'pairing id'),
    b: compactBase64(valid.devicePublicKey, nacl.box.publicKeyLength, 'device public key'),
    s: compactBase64(valid.deviceSignPublicKey, nacl.sign.publicKeyLength, 'device sign public key'),
    n: valid.name,
    p: PLATFORM_CODES[valid.platform],
    t: valid.createdAt.toString(36),
    e: (valid.expiresAt - valid.createdAt).toString(36),
    x: compactBase64(valid.nonce, 32, 'pairing nonce'),
    r: valid.relays.map(compactRelay),
    c: capabilityMask(valid.capabilities).toString(36),
    g: compactBase64(valid.requestSignature, nacl.sign.signatureLength, 'signature'),
  };
  return PAIRING_QR_COMPACT_PREFIX + toBase64Url(decodeUTF8(stableStringify(compact)));
}

/**
 * QR v4 хранит те же подписанные поля без JSON/base64-обвязки. Ключи, nonce и
 * Ed25519-подпись остаются полной длины; сокращаются только повторяемые имена
 * полей, стандартное имя платформы и известный набор relay.
 */
function encodePairingQr(request) {
  const valid = assertPairingRequest(request, { now: request.createdAt });
  const platformCode = BINARY_PLATFORM_CODES[valid.platform];
  if (!Number.isInteger(platformCode)) fail('pairing platform is invalid');

  const canonicalName = valid.name === DEFAULT_DEVICE_NAMES[valid.platform];
  const header =
    (canonicalName ? BINARY_CANONICAL_NAME : 0) |
    (capabilityMask(valid.capabilities) << 2) |
    platformCode;
  const ttl = valid.expiresAt - valid.createdAt;
  const defaultTtl = ttl === PAIRING_TTL_MS;
  let relayProfile = 0;
  for (let index = 1; index < PAIRING_RELAY_PROFILES.length; index += 1) {
    if (equalList(valid.relays, PAIRING_RELAY_PROFILES[index])) {
      relayProfile = index;
      break;
    }
  }
  const routeFlags = (defaultTtl ? BINARY_DEFAULT_TTL : 0) | relayProfile;
  const parts = [
    new Uint8Array([header, routeFlags]),
    decodeExact(valid.pairingId, 18, 'pairing id'),
    decodeExact(valid.devicePublicKey, nacl.box.publicKeyLength, 'device public key'),
    decodeExact(valid.deviceSignPublicKey, nacl.sign.publicKeyLength, 'device sign public key'),
    unsignedBytes(valid.createdAt, 6, 'createdAt'),
    decodeExact(valid.nonce, 32, 'pairing nonce'),
  ];

  if (!defaultTtl) parts.push(unsignedBytes(ttl, 3, 'expiresAt'));
  if (!relayProfile) {
    parts.push(new Uint8Array([valid.relays.length]));
    for (const relay of valid.relays) {
      const bytes = decodeUTF8(relay);
      if (!bytes.length || bytes.length > 1024) fail('pairing relay URL is invalid');
      parts.push(unsignedBytes(bytes.length, 2, 'relay length'), bytes);
    }
  }
  if (!canonicalName) {
    const bytes = decodeUTF8(valid.name);
    if (!bytes.length || bytes.length > 1024) fail('device name has invalid length');
    parts.push(unsignedBytes(bytes.length, 2, 'device name length'), bytes);
  }
  parts.push(decodeExact(valid.requestSignature, nacl.sign.signatureLength, 'signature'));
  return PAIRING_QR_BINARY_PREFIX + encodeBase41(concatBytes(parts));
}

function decodePairingQrBinary(value, options) {
  const bytes = decodeBase41(value.slice(PAIRING_QR_BINARY_PREFIX.length));
  let offset = 0;
  const read = (length, label) => {
    if (!Number.isInteger(length) || length < 0 || offset + length > bytes.length) {
      fail(`${label} is invalid`);
    }
    const output = bytes.slice(offset, offset + length);
    offset += length;
    return output;
  };
  const readNumber = (length, label) => {
    let output = 0;
    for (const byte of read(length, label)) output = output * 256 + byte;
    if (!Number.isSafeInteger(output)) fail(`${label} is invalid`);
    return output;
  };

  const header = readNumber(1, 'pairing header');
  const platformCode = header & 0x03;
  const platform = BINARY_CODE_PLATFORMS[platformCode];
  if (!platform) fail('pairing platform is invalid');
  const capabilities = capabilitiesFromMaskNumber((header >>> 2) & 0x1f);
  const canonicalName = (header & BINARY_CANONICAL_NAME) !== 0;

  const routeFlags = readNumber(1, 'pairing route flags');
  if (routeFlags & 0x70) fail('pairing route flags are invalid');
  const relayProfile = routeFlags & 0x0f;
  if (relayProfile >= PAIRING_RELAY_PROFILES.length) fail('pairing relay profile is invalid');
  const defaultTtl = (routeFlags & BINARY_DEFAULT_TTL) !== 0;

  const pairingId = encodeBase64(read(18, 'pairing id'));
  const devicePublicKey = encodeBase64(read(nacl.box.publicKeyLength, 'device public key'));
  const deviceSignPublicKey = encodeBase64(read(nacl.sign.publicKeyLength, 'device sign public key'));
  const createdAt = readNumber(6, 'createdAt');
  const nonce = encodeBase64(read(32, 'pairing nonce'));
  const ttl = defaultTtl ? PAIRING_TTL_MS : readNumber(3, 'expiresAt');

  let relays;
  if (relayProfile) {
    relays = [...PAIRING_RELAY_PROFILES[relayProfile]];
  } else {
    const count = readNumber(1, 'relay count');
    if (!count || count > 8) fail('pairing relays are invalid');
    relays = [];
    for (let index = 0; index < count; index += 1) {
      const length = readNumber(2, 'relay length');
      if (!length || length > 1024) fail('pairing relay URL is invalid');
      relays.push(encodeUTF8(read(length, 'relay url')));
    }
  }

  let name = DEFAULT_DEVICE_NAMES[platform];
  if (!canonicalName) {
    const length = readNumber(2, 'device name length');
    if (!length || length > 1024) fail('device name has invalid length');
    name = encodeUTF8(read(length, 'device name'));
  }
  const requestSignature = encodeBase64(read(nacl.sign.signatureLength, 'signature'));
  if (offset !== bytes.length) fail('pairing QR has trailing data');

  return assertPairingRequest(
    {
      pairingId,
      deviceId: deriveDeviceId(devicePublicKey),
      devicePublicKey,
      deviceSignPublicKey,
      name,
      platform,
      createdAt,
      expiresAt: createdAt + ttl,
      nonce,
      relays,
      capabilities,
      requestSignature,
    },
    options
  );
}

function decodePairingQr(value, options = {}) {
  if (typeof value !== 'string') fail('not a linked-device QR');
  if (value.startsWith(PAIRING_QR_BINARY_PREFIX)) return decodePairingQrBinary(value, options);
  const compact = value.startsWith(PAIRING_QR_COMPACT_PREFIX);
  const legacy = value.startsWith(PAIRING_QR_PREFIX);
  if (!compact && !legacy) fail('not a linked-device QR');
  const prefix = compact ? PAIRING_QR_COMPACT_PREFIX : PAIRING_QR_PREFIX;
  const bytes = fromBase64Url(value.slice(prefix.length));
  if (bytes.length > 8192) fail('pairing QR is too large');
  let parsed;
  try {
    parsed = JSON.parse(encodeUTF8(bytes));
  } catch (error) {
    fail('pairing QR is invalid');
  }
  if (!compact) return assertPairingRequest(parsed, options);
  if (!isPlainObject(parsed) || !Array.isArray(parsed.r)) fail('pairing QR is invalid');
  const createdAt = parseBase36(parsed.t, 'createdAt');
  const devicePublicKey = expandBase64Url(parsed.b, nacl.box.publicKeyLength, 'device public key');
  return assertPairingRequest(
    {
      pairingId: expandBase64Url(parsed.i, 18, 'pairing id'),
      deviceId: deriveDeviceId(devicePublicKey),
      devicePublicKey,
      deviceSignPublicKey: expandBase64Url(parsed.s, nacl.sign.publicKeyLength, 'device sign public key'),
      name: parsed.n,
      platform: CODE_PLATFORMS[parsed.p],
      createdAt,
      expiresAt: createdAt + parseBase36(parsed.e, 'expiresAt'),
      nonce: expandBase64Url(parsed.x, 32, 'pairing nonce'),
      relays: parsed.r.map(expandRelay),
      capabilities: capabilitiesFromMask(parsed.c),
      requestSignature: expandBase64Url(parsed.g, nacl.sign.signatureLength, 'signature'),
    },
    options
  );
}

/** Канонизированные подписываемые поля запроса — вход для вывода кода. */
function pairingCanonical(request) {
  return stableStringify(pairingPayload(request));
}

function verificationCode(request) {
  return verifyCode.shortCode(pairingCanonical(request));
}

/** Десятизначный код: первые шесть цифр совпадают с verificationCode. */
function strongVerificationCode(request) {
  return verifyCode.strongCode(pairingCanonical(request));
}

/** То же, но без заморозки интерфейса на время вывода. */
function strongVerificationCodeAsync(request) {
  return verifyCode.strongCodeAsync(pairingCanonical(request));
}

/**
 * ПРВ-1: доказательство компьютера — «код с экрана телефона введён у меня».
 * Привязано к КАНОНИЗИРОВАННОМУ запросу, а не к одному pairingId: иначе
 * доказательство одной попытки годилось бы для другой с тем же идентификатором.
 */
function pairingLinkProof(request, challenge, code) {
  return verifyCode.linkCodeProof(pairingCanonical(request), challenge, code);
}

/** Встречное подтверждение телефона: едет вместе с сертификатом устройства. */
function pairingLinkConfirmation(request, challenge, code) {
  return verifyCode.linkCodeConfirmation(pairingCanonical(request), challenge, code);
}

module.exports = {
  LINKED_DEVICE_VERSION,
  DEVICE_CERT_TYPE,
  DEVICE_ROSTER_TYPE,
  PAIRING_REQUEST_TYPE,
  PAIRING_QR_PREFIX,
  PAIRING_QR_COMPACT_PREFIX,
  PAIRING_QR_BINARY_PREFIX,
  PAIRING_TTL_MS,
  PAIRING_CLOCK_SKEW_MS,
  MAX_ACTIVE_DEVICES,
  MAX_ROSTER_ENTRIES,
  stableStringify,
  deriveDeviceId,
  createDeviceCertificate,
  assertDeviceCertificate,
  verifyDeviceCertificate,
  createSignedRoster,
  assertSignedRoster,
  verifySignedRoster,
  rosterWriteGate,
  createPairingRequest,
  assertPairingRequest,
  verifyPairingRequest,
  encodePairingQr,
  encodePairingQrCompat,
  decodePairingQr,
  encodeBase41,
  verificationCode,
  strongVerificationCode,
  strongVerificationCodeAsync,
  verificationCodesMatch,
  STRONG_CODE_ROUNDS,
  LINK_CODE_DIGITS,
  LINK_CODE_MAX_ATTEMPTS,
  generateLinkCode,
  normalizeLinkCode,
  formatLinkCode,
  linkProofsMatch,
  pairingLinkProof,
  pairingLinkConfirmation,
};
