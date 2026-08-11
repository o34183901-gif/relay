/**
 * relay.js — store-and-forward ретранслятор для мессенджера «Лично».
 *
 * Задача: доставлять зашифрованные конверты между телефонами. Сервер НЕ знает
 * секретных ключей и НЕ может прочитать сообщения. Но не «только шифртекст и
 * адрес получателя», как тут стояло: см. server/README.md, что он видит и хранит.
 *
 * Протокол (JSON, по одному сообщению на кадр):
 *   client -> server  {"type":"hello","pubkey":"<b64>","signPublicKey":"<b64>"}
 *       сервер отвечает challenge с одноразовым nonce
 *   server -> client  {"type":"challenge","nonce":"<b64>"}
 *   client -> server  {"type":"auth","signature":"<b64>"}
 *       подпись nonce ключом Ed25519 — доказательство владения pubkey
 *   server -> client  {"type":"ready","queued":N}       — после успешной auth
 *   client -> server  {"type":"prekeys-put","bundle":{spk:{id,pub,sig},opks:[{id,pub}]}}
 *       выгрузка СВОИХ публичных X3DH-prekey (sig сверяется с TOFU-ключом)
 *   server -> client  {"type":"prekeys-ok","otps":N}
 *   client -> server  {"type":"prekeys-get","pubkey":"<b64>"}
 *   server -> client  {"type":"prekeys","pubkey":"...","bundle":{spk,opk}|null}
 *       одноразовый prekey выдаётся ровно один раз и вычёркивается
 *   client -> server  {"type":"send","to":"<b64>","envelope":{...},"ref":"..."}
 *   server -> client  {"type":"ack","ref":"...","id":"...","queued":true,"dropped":bool}
 *       СРВ-11: `queued` — КОНСТАНТА (всегда true), а не состояние получателя;
 *       раньше по нему читалось «адрес сейчас в сети» (см. ACK_QUEUED). Отказ
 *       принять конверт несёт `dropped`. Факт доставки — кадр `delivered` ниже.
 *   server -> client  {"type":"message","id":"...","envelope":{...}}
 *   client -> server  {"type":"received","id":"..."}    — квитанция о приёме
 *       ТОЛЬКО после неё сервер удаляет конверт из очереди (надёжная доставка)
 *   server -> client  {"type":"delivered","id":"..."}   — отправителю, когда
 *       получатель подтвердил приём
 *   ping/pong          — проверка живости соединения
 *
 * Связанные устройства v2 (полностью совместимо со старыми кадрами выше):
 *   client -> server  {"type":"device-roster-put","roster":{...rootSignature}}
 *   client -> server  {"type":"device-bind","certificate":{...rootSignature}}
 *   server -> client  {"type":"device-bound","roster":{...}}
 * После bind обычный `send` получает внешние поля fromAccount/fromDeviceId и
 * сертификат устройства; сам E2E-конверт релей по-прежнему не расшифровывает.
 *
 * НАДЁЖНОСТЬ: конверт лежит в очереди, пока получатель не пришлёт `received`.
 * Онлайн-доставка тоже держит копию в очереди до квитанции, поэтому обрыв связи
 * в момент доставки не теряет сообщение — при переподключении оно шлётся снова.
 * Клиент дедуплицирует по `id`.
 *
 * АУТЕНТИФИКАЦИЯ (TOFU): при первом hello связка pubkey→signPublicKey
 * запоминается; далее подключиться под этим pubkey можно, только подписав nonce
 * тем же ключом. Это закрывает захват чужого адреса после первой регистрации.
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const dns = require('dns').promises;
const nacl = require('tweetnacl');
const naclUtil = require('tweetnacl-util');
const { WebSocketServer } = require('ws');
const {
  sendPush,
  sendCallPush,
  sendTestPush,
  pushReady,
  setVapidKeys,
  vapidPublicKey,
  vapidPublicKeyFor,
  generateVapidKeys,
} = require('./push');
const { mergeRelays, isValidRelayUrl, normalizeRelayUrl, isPrivateHost, coturnConfigText, rateGate, byteGate, buildIceServers, parsePublicStun } = require('./relays');
const { chatNotificationTag, createPushGate } = require('./notifications');
const { createStore } = require('./store');
const mbx = require('./mbx');
// ВЫС-19: частота обращений к HTTP-репликации ящика на IP. Чистое правило,
// проверяется отдельно (server/httpRateLimit.test.js).
const { createHttpRateLimit } = require('./httpRateLimit');
// ОБН-2: раздача обновлений. Правила (какой платформе что и чего не отдавать
// никогда) — в server/updateFeed.js, здесь только проводка и отдача файла.
const updateFeed = require('./updateFeed');
const updateMirror = require('./updateMirror');
const webApp = require('./webApp');
const landing = require('./landing');
const { RELEASE_PUBLIC_KEY } = require('./releaseKey');
// В-2: подпись и её проверка — через единую обёртку (внутри @noble/curves,
// формат прежний побайтно). На релее это путь аутентификации КАЖДОГО
// подключения: challenge подписывает клиент, свою подпись ставит релей, и
// подпись подписанного prekey сверяется при каждой выгрузке бандла.
const ed25519 = require('./ed25519');
// НАТ-1: третий уровень той же обёртки — подпись через OpenSSL, который у Node
// уже есть. Замер с честным разбором ключа на каждый вызов: проверка подписи
// 1,61 мс через @noble/curves против 0,12 мс через OpenSSL — ×13. Для релея это
// прямой потолок: подпись проверяется на КАЖДОЕ подключение (challenge) и на
// подписанный список устройств в каждом конверте, а узел однопоточный.
//
// Включается только после самопроверки на векторе RFC 8032, и она же обязана
// ОТКАЗАТЬ на подделке. Не сошлось — работает прежний путь, и причина уходит в
// лог: молчаливый откат на медленное потом не разобрать.
const { resolveNativeEd25519 } = require('./nativeEd25519');
const nativeEd25519 = resolveNativeEd25519(() => crypto);
if (nativeEd25519.implementation) ed25519.setNative(nativeEd25519.implementation);
// НАТ-2: общий секрет — то же самое для X25519. Замер: 0,646 мс через tweetnacl
// против 0,035 мс через OpenSSL, ×18. На релее он считается на КАЖДОЕ
// подключение — доказательством владения адресом (verifyBoxProof ниже).
//
// Самопроверка здесь спрашивает не только «тот ли ответ», но и «отвергает ли
// точку малого порядка»: такая точка даёт секрет, не зависящий от секретки, и
// реализация, выдающая на ней рабочий на вид ответ, выглядит совершенно
// исправной (КЛТ-4).
const x25519 = require('./x25519');
const { resolveNativeX25519 } = require('./nativeX25519');
const nativeX25519 = resolveNativeX25519(() => crypto);
if (nativeX25519.implementation) x25519.setNative(nativeX25519.implementation);
const { unpackBinaryFrame, packBinaryFrame } = require('./binary-frame');
// ПРФ-14: правило двоичного кадра обычного сообщения. Файл ГЕНЕРИРУЕТСЯ из
// src/envelopeFrame.js (scripts/sync-core.js) — правится только источник,
// иначе клиент и релей однажды разойдутся в том, какой конверт можно упаковать.
const envelopeFrame = require('./envelopeFrame');
const { encode: encodeMessagePack, decode: decodeMessagePack } = require('@msgpack/msgpack');
const {
  assertDeviceCertificate,
  assertSignedRoster,
  // КРИТ-04: право переписать список устройств — отдельно от проверки подписей,
  // чтобы спрашивать его ДО неё.
  rosterWriteGate,
  stableStringify,
  MAX_ACTIVE_DEVICES,
} = require('./linked-devices');
const {
  loadFleetConfig,
  memberFor,
  memberAcceptsKey,
  validVapidPair,
  signVapidBundle,
  verifyVapidBundle,
  createVapidRequest,
  verifyVapidRequest,
  createVapidResponse,
  openVapidResponse,
  sourceMatchesResolved,
  readJsonFile,
  writeJsonAtomic,
} = require('./vapid-fleet');

const TURN_HOST = process.env.TURN_HOST;
// H-2: секрет TURN больше НЕ передаётся открытым аргументом coturn или отдельной
// переменной окружения на каждый сервер (виден в ps/`docker inspect`/world-
// readable файлах). Источник разрешается при старте (resolveTurnSecret ниже,
// после определения DB_FILE) в turnSecret; сам релей владеет секретом и пишет
// конфиг coturn в data-том. Всё это едет в образе через watchtower, поэтому фикс
// автономен: серверы подхватывают его сами.
let turnSecret = null;

// БЕЗ-1: публичный STUN — ТОЛЬКО по явному решению оператора.
//
// Раньше при ненастроенном TURN сюда подставлялся stun.l.google.com. Для
// мессенджера, чей заявленный тезис — «без слежки», это означало, что при каждом
// звонке обе стороны сообщают Google свой реальный IP и точное время. Содержимое
// звонка при этом защищено, но сам факт разговора, его время и география обеих
// сторон утекают третьей стороне мимо всей остальной защиты.
//
// Теперь по умолчанию публичного STUN нет вовсе: свой coturn на релее (он же
// отдаёт STUN на том же порту 3478) закрывает задачу без посредников. Оператор,
// который сознательно готов на внешний STUN, задаёт его сам:
//   RELAY_PUBLIC_STUN=stun:stun.example.org:3478,stun:stun2.example.org:3478
const PUBLIC_STUN = parsePublicStun(process.env.RELAY_PUBLIC_STUN);

// Эфемерные REST-учётки coturn (живут ~1 ч), чтобы долгоживущий пароль TURN
// не уезжал в приложение. Сама сборка списка — чистая, в relays.js.
function turnIceServers() {
  return buildIceServers({
    turnSecret,
    turnHost: TURN_HOST,
    publicStun: PUBLIC_STUN,
    now: Date.now(),
    hmac: (username) => crypto.createHmac('sha1', turnSecret).update(username).digest('base64'),
  });
}

const PORT = process.env.PORT || 8787;
const RELAY_PROTOCOL = 6;
const RELAY_CAPABILITIES = Object.freeze([
  'linked-devices-v2',
  'device-queues',
  'signed-rosters',
  'binary-attachments-v1',
  'push-test-v1',
  'frame-batch-v1',
  // ПРФ-14: обычное сообщение принимается и отдаётся двоичным кадром, без
  // base64 вокруг запечатанного конверта. Объявляется отдельно от
  // binary-attachments-v1: релей может уметь чанки вложений и не уметь этого.
  envelopeFrame.BINARY_ENVELOPE_CAPABILITY,
  // АУД-13: клиент может спросить остаток своих одноразовых prekey, не
  // переподключаясь. Без этого долгоживущее соединение не пополняло пул никогда.
  'prekeys-count-v1',
  // ПЯЩ-1: общий ящик записок «ищи меня вот здесь». Объявляется отдельно:
  // старый узел его не умеет, и клиент обязан это видеть, а не гадать.
  'mbx-v1',
  // СРЕД-03: узел принимает кадр-пустышку и молча его выбрасывает.
  //
  // Объявление здесь — не формальность, а условие работы меры. Прежний релей на
  // незнакомый двоичный кадр ОТВЕЧАЕТ (`binary-error`), и такой ответ уходил бы
  // в канал на каждую пустышку: прикрытие, которое само себя размечает, хуже
  // отсутствия прикрытия. Поэтому клиент шлёт пустышки только туда, где
  // возможность объявлена, а узел прежней версии их не видит вовсе.
  'cover-traffic-v1',
]);
// Встроенное хранилище на SQLite (queue/identities/tokens/directory) — вместо
// in-memory Map + перезаписи JSON. Файл лежит в volume контейнера.
const DB_FILE = process.env.RELAY_DB || path.join(__dirname, 'relay.db');
const MAX_QUEUE_PER_USER = 500;
// H-3: глобальный потолок числа недоставленных конвертов во ВСЕЙ очереди (по всем
// получателям). Защита диска от абуза «рассылка на миллионы адресов». При
// превышении вытесняется самый старый конверт целиком. Оператор меняет через env.
const MAX_TOTAL_MESSAGES = Number(process.env.RELAY_MAX_TOTAL_MESSAGES) || 200000;
// S4: глобальный потолок ОЧЕРЕДИ В БАЙТАХ (тела в БД + файлы-blob). Конверт
// разрешён до 32 МБ, поэтому count-лимита мало: 200000×32 МБ ≈ 6.4 ТБ. Байтовый
// лимит защищает диск volume от переполнения одним клиентом. Дефолт 8 ГБ —
// оператор поднимает под свой диск через RELAY_MAX_QUEUE_BYTES.
const MAX_QUEUE_BYTES = Number(process.env.RELAY_MAX_QUEUE_BYTES) || 8 * 1024 * 1024 * 1024;
// S5: сколько конвертов ОДИН отправитель может держать в очереди ОДНОГО
// получателя. При превышении вытесняется его же старейший (self-eviction) —
// флудер не выдавливает чужие (реальные) сообщения жертвы. < MAX_QUEUE_PER_USER.
const MAX_QUEUE_PER_SENDER = Number(process.env.RELAY_MAX_QUEUE_PER_SENDER) || 100;
// ВЫС-15: сколько слотов очереди получателя доступно только корреспондентам —
// отправителям, которым получатель сам недавно писал. Иначе пять бесплатных
// личностей по MAX_QUEUE_PER_SENDER конвертов выбирали очередь целиком, и
// честные отправители получали отказ на весь срок TTL. Память «кто кому писал»
// стареет вместе с очередью (см. store.expireOlderThan).
const QUEUE_RESERVE_SLOTS = Number(process.env.RELAY_QUEUE_RESERVE) || 100;
const QUEUE_TTL_MS = Number(process.env.RELAY_TTL_MS) || 14 * 24 * 3600 * 1000; // 14 дней
// ПЯЩ-1: потолок общего ящика записок. Записка 224 байта, срок жизни 13 часов;
// 400 000 штук — это около 90 МБ с индексами. Сверх потолка вытесняется самый
// старый ОТРЕЗОК целиком: резать по одной записке внутри отрезка нельзя — какая
// из них кому нужна, узел не знает и знать не может.
const MBX_MAX_RECORDS = Number(process.env.RELAY_MBX_MAX_RECORDS) || mbx.MAX_RECORDS;
// Сколько записок один сокет кладёт за окно. Восемь за отрезок — норма клиента;
// шестьдесят четыре в минуту с запасом покрывают её и отсекают поток.
const MBX_PUT_MAX = Number(process.env.RELAY_MBX_PUT_MAX) || 64;
const MBX_PUT_WINDOW_MS = 60 * 1000;
// M-02: глобальный потолок числа зарегистрированных identity. У таблиц identities/
// prekeys/push_tokens (в отличие от очереди) не было ни TTL, ни лимита, ни
// вытеснения — Sybil-регистрация (hello→auth→prekeys-put→register в цикле) могла
// неограниченно раздувать каталог и переполнить диск. При превышении вытесняем
// самые холодные identity БЕЗ ожидающих конвертов (см. store.evictColdIdentities).
const MAX_IDENTITIES = Number(process.env.RELAY_MAX_IDENTITIES) || 500000;
// Тела конвертов крупнее порога (вложения) лежат файлами рядом с БД (тот же
// volume), в очереди — только ссылка: БД остаётся маленькой и быстрой при
// потоке фото/видео офлайн-получателям.
const BLOB_DIR = process.env.RELAY_BLOB_DIR || path.join(path.dirname(DB_FILE), 'blobs');
const BLOB_THRESHOLD = Number(process.env.RELAY_BLOB_THRESHOLD) || 64 * 1024;

const store = createStore(DB_FILE, { blobDir: BLOB_DIR, blobThreshold: BLOB_THRESHOLD });

// ПЯЩ-1: как узел отличает повтор записки от подделки под тем же ключом.
//
// Хеш берётся от значения И метки вместе. Совпало всё — записка пришла вторым
// путём, новой строки не нужно. Совпал ключ, но не метка — это ДРУГАЯ запись, и
// она обязана лечь рядом: иначе подделкой вытесняли бы настоящую записку, а
// адресат, сверяя метку, молча не находил бы ничего.
function mbxValueHash(record) {
  return crypto
    .createHash('sha256')
    .update(Buffer.from(record.value))
    .update(Buffer.from(record.mac))
    .digest();
}

// Сводка считается раз на изменение ящика и отдаётся всем одинаковой.
const mbxDigest = mbx.createDigestCache();

/**
 * Убрать протухшее и, если ящик всё равно переполнен, лишнее из старейшего
 * отрезка.
 *
 * ВЫС-31: лишнее — это ровно столько записок, сколько нужно, чтобы вернуться
 * под потолок, а не отрезок целиком. Прежнее вычищало шесть часов записок одним
 * движением, и залив ящик, этим можно было выбивать чужие записки прицельно:
 * старейший отрезок — ровно тот, за которым адресат придёт в следующий раз, а
 * свои заливающий кладёт в текущий.
 *
 * Порядок внутри отрезка назначает узел при вставке, поэтому выбор равномерен:
 * доля выброшенного у каждого равна его доле в ящике.
 */
function mbxTrim(now = Date.now()) {
  const removed = store.mbxExpire(mbx.slotOf(now - mbx.TTL_MS));
  return removed + store.mbxTrimTo(MBX_MAX_RECORDS);
}

/**
 * КРИТ-04: пересчитать сводку ящика — по СОБЫТИЮ изменения, а не по просьбе.
 *
 * Просьба обслуживается в обработчике кадра, между приёмами других соединений,
 * и однопоточному узлу нечем её обогнать. Пока сводка считалась там, стоимость
 * выборки всех ключей ящика и кодирования GCS платил тот, кто спросил, — а
 * значит, её мог назначить кто угодно, просто спрашивая почаще.
 *
 * Теперь работа делается здесь, сразу после изменения, и к моменту просьбы уже
 * готова. Сверяемся с ревизией, а не с курсором репликации: курсор растёт только
 * при добавлении, поэтому чистка ящика для него невидима.
 */
/**
 * ПРФ-21: сколько ждать перед пересчётом сводки ящика.
 *
 * Секунда. Записка живёт тринадцать часов, поэтому сводка, отставшая на
 * секунду, не значит ничего; а тот, кто спросит её раньше, получит посчитанную
 * по требованию — отставшего ответа не бывает по построению.
 */
const MBX_DIGEST_MIN_INTERVAL_MS = Number(process.env.RELAY_MBX_DIGEST_MS) || 1000;

function mbxRefreshDigest(now = Date.now()) {
  // Пересчёт — полный обход ключей ящика: на двухстах тысячах записок это почти
  // секунда, и всё это время однопоточный узел не обслуживает никого. Раньше он
  // шёл на КАЖДУЮ укладку.
  return mbxDigest.refreshIfDue(store.mbxRevision(), () => store.mbxKeys(), {
    now,
    minIntervalMs: MBX_DIGEST_MIN_INTERVAL_MS,
  });
}
{
  const orphans = store.cleanupOrphanBlobs();
  if (orphans) console.log(`[blobs] removed ${orphans} orphan attachment file(s)`);
}

// --- Реплицированный каталог релеев (gossip) ------------------------------
// SELF_URL — публичный wss-адрес ЭТОГО релея; RELAY_PEERS — стартовые соседи
// (через запятую). Каталог = self ∪ peers ∪ выученные, хранится в БД и
// периодически синхронизируется с пирами. Клиент может забрать его у любого
// релея (GET /relays или WS {type:'relays'}), поэтому падение одного не критично.
const SELF_URL = normalizeRelayUrl(process.env.RELAY_SELF_URL || '') || null;
const PEER_SEED = (process.env.RELAY_PEERS || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);
const GOSSIP_INTERVAL_MS = Number(process.env.RELAY_GOSSIP_MS) || 60000;
// M1: анонимный POST /relays раньше позволял кому угодно из интернета залить
// записи в каталог (обход намеренно закрытого WS relay-advertise). Теперь
// пополнение каталога через HTTP требует общего токена (RELAY_GOSSIP_TOKEN),
// который операторы федерации задают на своих узлах. Без токена HTTP-push-gossip
// ВЫКЛЮЧЕН (безопасно по умолчанию): каталог по-прежнему читается через GET, а
// узлы находят друг друга pull-gossip'ом (fetchPeerRelays) и WS relay-advertise.
const GOSSIP_TOKEN = process.env.RELAY_GOSSIP_TOKEN || null;

let relayDir = mergeRelays([], [SELF_URL, ...PEER_SEED, ...store.directory()].filter(Boolean));
store.addRelays(relayDir, Date.now());
/** Добавить URL(ы) в каталог; вернуть true, если что-то реально добавилось. */
function learnRelays(urls) {
  const before = relayDir.length;
  relayDir = mergeRelays(relayDir, urls);
  if (relayDir.length !== before) {
    store.addRelays(relayDir, Date.now());
    return true;
  }
  return false;
}
const MAX_ENVELOPE_BYTES = 32 * 1024 * 1024; // 32 MB envelope (~24 MB video/file)
// ПРФ-14: потолок ТЕЛА двоичного кадра `send-v1`, посчитанный так, чтобы конверт
// после кодирования в base64 уложился в MAX_ENVELOPE_BYTES. Проверяется ДО
// кодирования: иначе тело в 33 МБ сначала превратилось бы в 44 МБ строки и лишь
// потом было отвергнуто — то есть отправка мусора стоила бы узлу столько же,
// сколько настоящая работа (та же беда, что чинил АУД-06).
const MAX_SEALED_PAYLOAD_BYTES = envelopeFrame.maxSealedBytes(MAX_ENVELOPE_BYTES);
const MAX_BINARY_CHUNK_BYTES = 300 * 1024;
const MAX_BINARY_CHUNKS = 4096;

// АУД-06: потолок JSON-кадра, проверяемый ДО разбора.
//
// Раньше кадр в 33 МБ (maxPayload) сначала превращался в строку (raw.toString()),
// затем полностью разбирался (JSON.parse) — и только потом отвергался проверкой
// размера конверта. Релей однопоточный: пока идут эти два прохода, НИ ОДИН
// пользователь узла не получает и не отправляет сообщений. То есть отправить
// мусор и заставить узел его разобрать стоило ровно столько же, сколько
// отправить настоящее сообщение, и никакой аутентификации для этого не
// требовалось.
//
// Длина кадра известна из самого буфера, до единой операции над содержимым.
// Конверт не может быть больше кадра, в котором приехал, поэтому кадр крупнее
// потолка конверта плюс служебные поля — заведомо негодный.
const JSON_FRAME_OVERHEAD_BYTES = 128 * 1024; // to/ref/метаданные устройства с запасом
const MAX_JSON_FRAME_BYTES = MAX_ENVELOPE_BYTES + JSON_FRAME_OVERHEAD_BYTES;
// До аутентификации валидны только hello и auth — это пара ключей и подпись,
// то есть сотни байт. Держать здесь 32 МБ значит разрешать неизвестно кому
// занимать процессор узла разбором мусора. Порог щедрый на два порядка.
const MAX_PREAUTH_FRAME_BYTES = 64 * 1024;

// Rate limiting (per connection).
const AUTH_TIMEOUT_MS = 10000; // must authenticate within this window
const RATE_WINDOW_MS = 1000;
const RATE_MAX_FRAMES = 80; // frames per RATE_WINDOW_MS before we drop the socket
// БЕЗ-5: потолок ПОТОКА с одного соединения. Кадровый лимит выше пропускал
// 80 × 300 КБ = 24 МБ/с, а при онлайн-получателе конверты минуют очередь, то
// есть и квоты хранения. Потолок щедрый: отправка вложения 24 МБ укладывается
// примерно в две секунды, легитимный быстрый клиент его почти не замечает —
// при превышении релей лишь притормаживает чтение, ничего не теряя.
const RATE_MAX_BYTES = Number(process.env.RELAY_MAX_BYTES_PER_SEC) || 12 * 1024 * 1024;
// Сколько окон подряд можно держать превышение, прежде чем это перестанет быть
// «быстрый канал» и станет абузом. 15 с непрерывного упора в потолок.
const RATE_ABUSE_WINDOWS = Number(process.env.RELAY_ABUSE_WINDOWS) || 15;

// КРИТ-04: отдельный потолок на ДОРОГИЕ кадры.
//
// Общий лимит меряет кадры, а не работу. Восемьдесят кадров в секунду — верная
// мерка для конвертов, каждый из которых стоит одну вставку в очередь, и
// негодная для просьб, каждая из которых стоит выборки по всей базе или пачки
// проверок подписи. Одно соединение, укладываясь в общий лимит с запасом,
// занимало однопоточный узел целиком, и страдали при этом все остальные.
//
// Числа взяты от того, как этими кадрами пользуются на самом деле:
//   • сводку ящика клиент спрашивает раз в отрезок, то есть раз в шесть часов;
//     десять в минуту — это триста шестьдесят суточных норм подряд;
//   • корзин за один поиск набирается единицы (сколько ключей совпало с
//     фильтром), тридцать в минуту покрывает поиск с большим запасом;
//   • список устройств переписывается при привязке или отзыве — событие,
//     которое у человека случается несколько раз в год.
//
// Превышение НЕ рвёт соединение: легитимный клиент мог попасть сюда из-за
// повторов при плохой связи, а разрыв обошёлся бы ему дороже отказа. Ответ —
// обычная ошибка, по которой клиент отступает.
const COSTLY_WINDOW_MS = 60 * 1000;
const MBX_DIGEST_MAX_PER_MIN = Number(process.env.RELAY_MBX_DIGEST_PER_MIN) || 10;
const MBX_FETCH_MAX_PER_MIN = Number(process.env.RELAY_MBX_FETCH_PER_MIN) || 30;
// ВЫС-19: HTTP-репликация ящика (GET /mbx) — усилитель ×30000. WS-кадры ящика
// уже за аутентификацией и под costlyLimited, а у HTTP-пути защиты не было.
// Частота на IP: репликация соседа — редкий фоновый опрос, десяток в минуту с
// запасом её покрывает и отсекает поток. Страница — сколько записок отдаём за
// один ответ: полный перенос всё равно идёт постранично по курсору after,
// поэтому маленькая страница лишь снижает разовое усиление, ничего не ломая.
const MBX_HTTP_MAX_PER_MIN = Number(process.env.RELAY_MBX_HTTP_PER_MIN) || 12;
const MBX_HTTP_PAGE = Math.min(mbx.SYNC_LIMIT, Number(process.env.RELAY_MBX_HTTP_PAGE) || 512);
const mbxHttpRate = createHttpRateLimit({ max: MBX_HTTP_MAX_PER_MIN, windowMs: COSTLY_WINDOW_MS });
const ROSTER_PUT_MAX_PER_MIN = Number(process.env.RELAY_ROSTER_PUT_PER_MIN) || 10;

// ОБН-2: раздача обновлений приложения.
//
// Пусто — раздачи нет вовсе, и это умолчание правильное: файл выпуска весит
// десятки мегабайт, а платит за них оператор. Включает тот, кто сам решил
// раздавать: RELAY_UPDATE_DIR=/srv/licno/releases, и туда кладутся подписанные
// android-version.json и licno-android.apk (см. scripts/release-manifest.js).
//
// Частота на IP: манифест спрашивают раз в полчаса на устройство, поэтому
// десяток в минуту с одного адреса — уже далеко за пределами обычного. Файл
// ограничен отдельно и жёстче: это десятки мегабайт за запрос, и качают его
// один раз на выпуск, а не по расписанию.
// ВЫП-8: РАЗДАЧА ВКЛЮЧЕНА ПО УМОЛЧАНИЮ, и выпуск узел забирает сам.
//
// Раньше здесь было пусто, и оператор включал раздачу вручную: задать каталог,
// скачать пару «манифест + файл», положить. На каждый выпуск, на каждом узле.
// На практике это означало, что не раздавал никто, — а через релеи обновление
// доезжает единственным путём: ни сайта, ни магазина у проекта нет. Выпустить
// исправление и не доставить его — то же самое, что не выпустить.
//
// Отказаться можно: RELAY_UPDATE_MIRROR=off выключает и загрузку, и раздачу.
const UPDATE_DIR = process.env.RELAY_UPDATE_DIR || path.join(path.dirname(DB_FILE), 'releases');
const UPDATE_MIRROR_OFF = String(process.env.RELAY_UPDATE_MIRROR || '').trim().toLowerCase() === 'off';
const UPDATE_SOURCE = String(process.env.RELAY_UPDATE_SOURCE || updateMirror.DEFAULT_SOURCE).trim();
const UPDATE_MIRROR_MS = Number(process.env.RELAY_UPDATE_MIRROR_MS) || updateMirror.DEFAULT_INTERVAL_MS;
// ВЫП-9: веб-версия лежит деревом внутри того же каталога раздачи.
const WEB_DIR = path.join(UPDATE_DIR, 'web');
const UPDATE_MANIFEST_MAX_PER_MIN = Number(process.env.RELAY_UPDATE_MANIFEST_PER_MIN) || 12;
const UPDATE_FILE_MAX_PER_MIN = Number(process.env.RELAY_UPDATE_FILE_PER_MIN) || 3;
const updateManifestRate = createHttpRateLimit({
  max: UPDATE_MANIFEST_MAX_PER_MIN,
  windowMs: COSTLY_WINDOW_MS,
});
const updateFileRate = createHttpRateLimit({ max: UPDATE_FILE_MAX_PER_MIN, windowMs: COSTLY_WINDOW_MS });

// Resource limits (H4): защита узла от исчерпания ресурсов при абузе/DoS.
// ВАЖНО: мобильные операторы прячут тысячи абонентов за одним IP (CGNAT),
// поэтому per-IP лимит — грубый предохранитель от одиночного хоста, а не от
// «многих пользователей». Держим его высоким, чтобы не рубить легитимных
// пользователей за общим NAT; тонкую защиту дают auth-timeout, rate-limit на
// соединение и квота очереди на pubkey. Оператор может поднять/опустить через env.
const MAX_CONN_PER_IP = Number(process.env.RELAY_MAX_CONN_PER_IP) || 1000; // одновременных соединений с одного IP
const MAX_BUFFERED_BYTES = Number(process.env.RELAY_MAX_BUFFERED) || 64 * 1024 * 1024; // если клиент не читает и буфер сокета раздулся — рвём

// --- /metrics (п.4): счётчики с момента старта процесса ---------------------
// Формат Prometheus, чтобы оператор мог повесить Grafana/alerting без плясок.
// Если endpoint нужно закрыть от посторонних — env RELAY_METRICS_TOKEN, тогда
// требуется ?token=... или заголовок Authorization: Bearer ...
const METRICS_TOKEN = process.env.RELAY_METRICS_TOKEN || null;
const START_TS = Date.now();
const counters = {
  msgsIn: 0, // принятых 'send' от клиентов
  deliveredOnline: 0, // доставлено получателю онлайн (сокет открыт)
  queuedOffline: 0, // получатель офлайн — легло в очередь
  acked: 0, // квитанций received (сообщение реально дошло)
  pushes: 0, // отправлено wake-up пушей
  authOk: 0, // успешных аутентификаций
  dropped: 0, // СРВ-2: конверт отброшен (очередь получателя полна, нет своих слотов)
  throttled: 0, // БЕЗ-5: сколько раз чтение сокета придерживали из-за потолка байт
  abusive: 0, // БЕЗ-5: сколько соединений разорвано за длительное превышение
  oversized: 0, // АУД-06: кадров отвергнуто по размеру ДО разбора
  overloaded: 0, // АУД-06: сколько раз узел сообщил клиенту о перегрузке
  // КРИТ-04: работа, которую пытались назначить узлу и которую он не сделал.
  // Оператору эти два числа говорят то, чего не скажет ни одно другое: узел
  // сейчас не «медленный», а обстреливаемый дорогими просьбами. Без них поток
  // мусорных ростеров и просьб о сводке выглядит просто ростом задержек.
  costlyRefused: 0, // отказов по отдельному потолку дорогих кадров
  rosterDeniedEarly: 0, // ростеров отвергнуто ДО проверки подписей
  // СРЕД-03: принятых и выброшенных пустышек. Оператору это единственный способ
  // увидеть, сколько полосы уходит на прикрывающий трафик: в счётчики сообщений
  // такие кадры не попадают намеренно — они не сообщения.
  cover: 0,
  // ВЫС-19: отказов HTTP-репликации ящика по частоте. Рост числа — узел дёргают
  // как усилитель, а не реплицируют.
  mbxHttpLimited: 0,
  // ОБН-2: раздача обновлений. Оператору это единственный способ увидеть, во
  // что ему обходится включённая раздача: манифест — байты, файл — десятки
  // мегабайт за штуку.
  updateManifestServed: 0,
  updateFileServed: 0,
  updateHttpLimited: 0,
};

// ПРФ-3: задержка event-loop. Релей однопоточный, а хранилище (better-sqlite3) и
// запись тел вложений на диск синхронны — то есть пока идёт одна тяжёлая
// операция, НИ ОДИН другой пользователь не получает и не отправляет сообщений:
// ни heartbeat, ни квитанции, ни доставку. Снаружи это выглядит как «мессенджер
// подтормаживает» ровно тогда, когда кто-то отправил видео.
//
// Померить это иначе нечем: счётчики сообщений при такой блокировке выглядят
// нормально. Ставим таймер на фиксированный интервал и смотрим, насколько он
// опоздал, — опоздание и есть время, которое цикл провёл занятым.
const EVENT_LOOP_PROBE_MS = 500;
// АУД-06: одной метрики мало. Число, на которое никто не смотрит, ничем не
// отличается от отсутствия числа: узел может неделями отвечать с секундными
// паузами, и снаружи это будет выглядеть просто как «мессенджер иногда
// подтормаживает». Поэтому держим ОКНО последних замеров (чтобы считать p99, а
// не только максимум с момента старта), пишем в лог при устойчивом превышении и
// отдаём наружу признак перегрузки, по которому клиент может уйти на соседний
// релей.
const LAG_WINDOW = 120; // минута наблюдений при пробе раз в 500 мс
// Порог взят от обещания продукта, а не от возможностей железа: задержка выше
// четверти секунды уже заметна человеку как «сообщение думает».
const LAG_ALERT_MS = Number(process.env.RELAY_LAG_ALERT_MS) || 250;
// Сколько подряд проб должно превысить порог, прежде чем считать это перегрузкой,
// а не одним тяжёлым кадром. Три пробы — полторы секунды.
const LAG_ALERT_STREAK = Number(process.env.RELAY_LAG_ALERT_STREAK) || 3;
const LAG_LOG_INTERVAL_MS = 60000; // не чаще раза в минуту, иначе лог сам станет нагрузкой

const eventLoopLag = { last: 0, max: 0, samples: [], streak: 0, overloaded: false, loggedAt: 0 };
let eventLoopProbeAt = Date.now();

/** p99 задержки по окну наблюдений. Ноль, если замеров ещё нет. */
function eventLoopLagP99() {
  const list = eventLoopLag.samples;
  if (!list.length) return 0;
  const sorted = [...list].sort((left, right) => left - right);
  return sorted[Math.min(sorted.length - 1, Math.max(0, Math.ceil(sorted.length * 0.99) - 1))];
}

/** Считает ли узел себя перегруженным прямо сейчас. */
function relayOverloaded() {
  return eventLoopLag.overloaded;
}

function sampleEventLoopLag(now = Date.now()) {
  const lag = Math.max(0, now - eventLoopProbeAt - EVENT_LOOP_PROBE_MS);
  eventLoopProbeAt = now;
  eventLoopLag.last = lag;
  if (lag > eventLoopLag.max) eventLoopLag.max = lag;
  eventLoopLag.samples.push(lag);
  if (eventLoopLag.samples.length > LAG_WINDOW) eventLoopLag.samples.shift();

  // Одна тяжёлая операция — это норма (кто-то отправил видео). Перегрузка — это
  // когда цикл не успевает разгрестись НЕСКОЛЬКО проб подряд.
  eventLoopLag.streak = lag >= LAG_ALERT_MS ? eventLoopLag.streak + 1 : 0;
  const overloaded = eventLoopLag.streak >= LAG_ALERT_STREAK;
  if (overloaded && !eventLoopLag.overloaded) {
    console.warn(
      `[lag] узел перегружен: задержка цикла ${lag} мс ${eventLoopLag.streak} проб подряд ` +
        `(порог ${LAG_ALERT_MS} мс, p99 ${eventLoopLagP99()} мс). Клиентам сообщено.`
    );
    eventLoopLag.loggedAt = now;
  } else if (overloaded && now - eventLoopLag.loggedAt >= LAG_LOG_INTERVAL_MS) {
    console.warn(`[lag] перегрузка продолжается: p99 ${eventLoopLagP99()} мс`);
    eventLoopLag.loggedAt = now;
  } else if (!overloaded && eventLoopLag.overloaded) {
    console.warn(`[lag] перегрузка снята: p99 ${eventLoopLagP99()} мс`);
  }
  eventLoopLag.overloaded = overloaded;
}
const eventLoopTimer = setInterval(sampleEventLoopLag, EVENT_LOOP_PROBE_MS);
// Метрика не должна удерживать процесс от штатного завершения.
if (typeof eventLoopTimer.unref === 'function') eventLoopTimer.unref();

function renderMetrics() {
  const st = store.stats();
  const mem = process.memoryUsage();
  const lines = [];
  const metric = (name, type, help, value, labels) => {
    lines.push(`# HELP ${name} ${help}`);
    lines.push(`# TYPE ${name} ${type}`);
    lines.push(`${name}${labels || ''} ${value}`);
  };
  metric('licno_up', 'gauge', 'Relay process is up.', 1);
  metric('licno_uptime_seconds', 'gauge', 'Seconds since process start.', Math.round((Date.now() - START_TS) / 1000));
  lines.push('# HELP licno_connections WebSocket connections.');
  lines.push('# TYPE licno_connections gauge');
  lines.push(`licno_connections{state="open"} ${wss.clients.size}`);
  lines.push(`licno_connections{state="authed"} ${online.size}`);
  metric('licno_known_relays', 'gauge', 'Relays known to this node (gossip directory).', relayDir.length);
  metric('licno_queue_users', 'gauge', 'Users with pending (undelivered) envelopes.', st.usersQueued);
  metric('licno_queue_messages', 'gauge', 'Pending envelopes in the store-and-forward queue.', st.totalQueued);
  metric('licno_queue_bytes', 'gauge', 'Bytes held by the queue (DB rows + attachment blobs on disk).', store.queueBytes());
  metric('licno_messages_in_total', 'counter', 'Envelopes accepted from senders since start.', counters.msgsIn);
  metric('licno_messages_delivered_online_total', 'counter', 'Envelopes pushed to an online recipient since start.', counters.deliveredOnline);
  metric('licno_messages_queued_offline_total', 'counter', 'Envelopes queued for an offline recipient since start.', counters.queuedOffline);
  metric('licno_messages_dropped_total', 'counter', 'Envelopes dropped (recipient queue full, no own slots) since start.', counters.dropped);
  metric('licno_throttled_total', 'counter', 'Times a connection was paused for exceeding the byte budget.', counters.throttled);
  metric('licno_abusive_closed_total', 'counter', 'Connections closed for sustained byte-budget abuse.', counters.abusive);
  metric(
    'licno_costly_refused_total',
    'counter',
    'Expensive frames refused by the per-minute budget (mailbox digest/fetch, roster writes).',
    counters.costlyRefused
  );
  metric(
    'licno_roster_denied_early_total',
    'counter',
    'Device-roster writes rejected on permissions before any signature was verified.',
    counters.rosterDeniedEarly
  );
  metric('licno_messages_acked_total', 'counter', 'Envelopes confirmed received by recipients since start.', counters.acked);
  metric('licno_push_sent_total', 'counter', 'Wake-up pushes sent since start.', counters.pushes);
  metric('licno_auth_success_total', 'counter', 'Successful client authentications since start.', counters.authOk);
  metric('process_resident_memory_bytes', 'gauge', 'Resident set size of the relay process.', mem.rss);
  metric('nodejs_heap_used_bytes', 'gauge', 'V8 heap used by the relay process.', mem.heapUsed);
  // ПРФ-3: пока цикл занят, узел не обслуживает НИКОГО. Рост max — прямой
  // признак того, что синхронная работа (крупный конверт на диск, тяжёлый
  // запрос) выросла до заметной для пользователей паузы.
  metric(
    'licno_event_loop_lag_ms',
    'gauge',
    'Задержка event-loop за последний интервал: время, которое цикл был занят и никого не обслуживал.',
    eventLoopLag.last
  );
  metric(
    'licno_event_loop_lag_max_ms',
    'gauge',
    'Максимальная задержка event-loop с момента старта процесса.',
    eventLoopLag.max
  );
  // АУД-06: максимум с момента старта не годится для алерта — один тяжёлый кадр
  // в прошлую пятницу навсегда делает его красным. p99 по скользящему окну
  // показывает, как узел живёт СЕЙЧАС, и именно на него вешается порог.
  metric(
    'licno_event_loop_lag_p99_ms',
    'gauge',
    'p99 задержки event-loop по скользящему окну. Порог для алерта: см. licno_overloaded.',
    eventLoopLagP99()
  );
  metric(
    'licno_overloaded',
    'gauge',
    'Узел считает себя перегруженным (задержка цикла держится выше порога). Клиентам сообщается, чтобы они ушли на соседний релей.',
    relayOverloaded() ? 1 : 0
  );
  metric(
    'licno_overload_notices_total',
    'counter',
    'Сколько раз узел сообщил клиенту о перегрузке.',
    counters.overloaded
  );
  metric(
    'licno_oversized_frames_total',
    'counter',
    'Кадров отвергнуто по размеру ДО разбора (АУД-06): их содержимое узел даже не читал.',
    counters.oversized
  );
  metric(
    'licno_cover_frames_total',
    'counter',
    'Кадров-пустышек принято и выброшено (СРЕД-03). Это полоса, но не сообщения: в очередь они не встают и никого не будят.',
    counters.cover
  );
  metric(
    'licno_mbx_http_limited_total',
    'counter',
    'Отказов HTTP-репликации ящика по частоте (ВЫС-19). Рост — узел дёргают как усилитель, а не реплицируют.',
    counters.mbxHttpLimited
  );
  metric(
    'licno_update_manifest_served_total',
    'counter',
    'Манифестов выпуска отдано (ОБН-2). Байты; растёт вместе с числом устройств, которым этот релей известен.',
    counters.updateManifestServed
  );
  metric(
    'licno_update_file_served_total',
    'counter',
    'Файлов выпуска отдано (ОБН-2). Десятки мегабайт за штуку — это и есть цена включённой раздачи.',
    counters.updateFileServed
  );
  metric(
    'licno_update_http_limited_total',
    'counter',
    'Отказов раздачи обновлений по частоте (ОБН-2). Рост — узел качают как файлопомойку.',
    counters.updateHttpLimited
  );
  return lines.join('\n') + '\n';
}

// M11: сравнение токена — константное по времени (timingSafeEqual), чтобы по
// времени ответа нельзя было побайтово подобрать токен.
function safeEqual(a, b) {
  const ab = Buffer.from(String(a == null ? '' : a));
  const bb = Buffer.from(String(b == null ? '' : b));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}
function metricsAuthorized(req) {
  // M-1: без заданного токена /metrics больше НЕ открыт всему интернету. Разрешаем
  // только приватный/loopback источник (внутренняя сеть/localhost/Docker) — публичный
  // скрейп через Caddy (реальный клиент виден по X-Forwarded-For) отвергается. Задан
  // токен — как раньше: пускаем по ?token=/Bearer с любого адреса.
  if (!METRICS_TOKEN) return isPrivateHost(clientIp(req));
  const url = new URL(req.url, 'http://x');
  if (safeEqual(url.searchParams.get('token'), METRICS_TOKEN)) return true;
  const auth = (req.headers && req.headers.authorization) || '';
  return safeEqual(auth, `Bearer ${METRICS_TOKEN}`);
}

// --- HTTP bootstrap общей VAPID-пары между разрешёнными релеями ------------
const vapidRequestRate = new Map(); // source IP -> {start,count}
const vapidRequestNonces = new Map(); // relayPub|nonce -> timestamp (anti-replay)
let vapidGlobalRate = null;

function readJsonRequest(req, maxBytes = 32 * 1024) {
  return new Promise((resolve) => {
    let body = '';
    let done = false;
    const finish = (value) => {
      if (done) return;
      done = true;
      resolve(value);
    };
    req.on('error', () => finish(null));
    req.on('aborted', () => finish(null));
    req.on('data', (chunk) => {
      body += chunk;
      if (Buffer.byteLength(body) > maxBytes) {
        finish(null);
        req.destroy();
      }
    });
    req.on('end', () => {
      if (done) return;
      try {
        finish(JSON.parse(body));
      } catch (e) {
        finish(null);
      }
    });
  });
}

function vapidRequestRateAllowed(ip) {
  const now = Date.now();
  let gate = rateGate(vapidGlobalRate, now, 60000, 120);
  vapidGlobalRate = gate.state;
  if (!gate.allow) return false;
  vapidGlobalRate.count += 1;

  const key = String(ip || 'unknown');
  gate = rateGate(vapidRequestRate.get(key), now, 60000, 12);
  vapidRequestRate.set(key, gate.state);
  if (!gate.allow) return false;
  gate.state.count += 1;
  if (vapidRequestRate.size > 10000) vapidRequestRate.clear();
  return true;
}

function rememberVapidRequest(request) {
  const now = Date.now();
  const key = `${request.relayPub}|${request.nonce}`;
  if (vapidRequestNonces.has(key)) return false;
  vapidRequestNonces.set(key, now);
  if (vapidRequestNonces.size > 5000) {
    const cutoff = now - 10 * 60 * 1000;
    for (const [nonce, timestamp] of vapidRequestNonces) {
      if (timestamp < cutoff) vapidRequestNonces.delete(nonce);
    }
    if (vapidRequestNonces.size > 5000) vapidRequestNonces.clear();
  }
  return true;
}

async function handleVapidFleetHttpWith(req, res, options = {}) {
  const fleet = options.fleet === undefined ? VAPID_FLEET : options.fleet;
  const member = options.member === undefined ? VAPID_MEMBER : options.member;
  const bundle = options.bundle === undefined ? vapidFleetBundle : options.bundle;
  const allowPrivate = options.allowPrivate === undefined ? VAPID_FLEET_ALLOW_PRIVATE : options.allowPrivate;
  const selfUrl = options.selfUrl === undefined ? SELF_URL : options.selfUrl;
  const relayPublicKey = options.relayPublicKey || RELAY_KEYS.pub;
  const relaySecretKey = options.relaySecretKey || RELAY_KEYS.sec;
  const rateAllowed = options.rateAllowed || vapidRequestRateAllowed;
  const readRequest = options.readRequest || readJsonRequest;
  const verifyRequest = options.verifyRequest || verifyVapidRequest;
  const rememberRequest = options.rememberRequest || rememberVapidRequest;
  const resolvePeer = options.resolvePeer || safePeerAddrs;
  const sourceMatches = options.sourceMatches || sourceMatchesResolved;
  const makeResponse = options.makeResponse || createVapidResponse;
  const logger = options.logger || console;
  const ip = clientIp(req);
  if (!fleet || !member || !bundle || !rateAllowed(ip)) {
    res.writeHead(bundle ? 429 : 503, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: false }));
    return;
  }
  const request = await readRequest(req);
  const requestMember = verifyRequest(request, fleet);
  if (!requestMember || !rememberRequest(request)) {
    res.writeHead(403, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: false }));
    return;
  }

  // Подпись доказывает владение relay-sign.key, а совпадение сетевого источника
  // с DNS/IP разрешённого URL не даёт скопировать публичный образ на чужой сервер
  // и запросить приватный VAPID под именем участника флота.
  const resolved = await resolvePeer(requestMember.url, { allowPrivate });
  if (!resolved || !sourceMatches(ip, resolved)) {
    res.writeHead(403, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: false }));
    return;
  }

  try {
    const response = makeResponse({
      config: fleet,
      request,
      bundle,
      senderUrl: selfUrl,
      senderRelayPub: relayPublicKey,
      senderRelaySecret: relaySecretKey,
    });
    res.writeHead(200, {
      'content-type': 'application/json',
      'cache-control': 'no-store',
    });
    res.end(JSON.stringify(response));
  } catch (e) {
    logger.warn('[vapid-fleet] не удалось сформировать ответ:', e && e.message);
    res.writeHead(500, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: false }));
  }
}
async function handleVapidFleetHttp(req, res) {
  return handleVapidFleetHttpWith(req, res);
}

// pubkey -> live WebSocket (in-memory: живые сокеты место в RAM, не в БД)
const online = new Map();
// account public key -> deviceId -> live WebSocket. Это дополнительный индекс:
// legacy online(pubkey) остаётся неизменным, поэтому старые APK не замечают v2.
const accountOnline = new Map();

function unindexAccountSocket(ws) {
  if (!ws || !ws.accountPubkey || !ws.deviceId) return;
  const devices = accountOnline.get(ws.accountPubkey);
  if (!devices) return;
  if (devices.get(ws.deviceId) === ws) devices.delete(ws.deviceId);
  if (!devices.size) accountOnline.delete(ws.accountPubkey);
  ws.accountPubkey = null;
  ws.deviceId = null;
  ws.deviceCertificate = null;
}

function indexAccountSocket(ws, record) {
  unindexAccountSocket(ws);
  let devices = accountOnline.get(record.accountPublicKey);
  if (!devices) {
    devices = new Map();
    accountOnline.set(record.accountPublicKey, devices);
  }
  const previous = devices.get(record.deviceId);
  if (previous && previous !== ws) {
    try {
      previous.terminate();
    } catch (e) {
      // Прежний сокет этого устройства всё равно вычёркивается из каталога.
      // Он мог оборваться сам — тогда terminate() уже нечего закрывать.
    }
  }
  ws.accountPubkey = record.accountPublicKey;
  ws.deviceId = record.deviceId;
  ws.deviceCertificate = record.certificate;
  devices.set(record.deviceId, ws);
  store.touchDevice(record.devicePublicKey, Date.now());
}

function broadcastAccount(accountPk, frame) {
  const devices = accountOnline.get(accountPk);
  if (!devices) return 0;
  let sent = 0;
  for (const ws of devices.values()) if (send(ws, frame)) sent += 1;
  return sent;
}
// ip -> число активных соединений (за Caddy берём X-Forwarded-For)
const ipConns = new Map();
// Окно троттлинга message-пушей (см. messagePushGate ниже).
const PUSH_MIN_INTERVAL_MS = Number(process.env.RELAY_PUSH_INTERVAL_MS) || 20000;
// ПРФ-4: троттлинг раньше был на ПОЛУЧАТЕЛЯ целиком — пять сообщений из трёх
// разных чатов за 20 секунд давали ОДИН пуш, и остальные чаты не будили
// устройство вовсе. Теперь окно считается на пару «получатель + чат», а от
// усиления флуда (много отправителей → много пушей) защищает потолок на
// получателя в том же окне. Логика — в чистом server/notifications.js.
const messagePushGate = createPushGate({
  windowMs: PUSH_MIN_INTERVAL_MS,
  maxPerRecipient: Number(process.env.RELAY_PUSH_MAX_PER_WINDOW) || undefined,
});
// СРВ-3: троттлинг ЗВОНКОВЫХ пушей. Раньше call-пуш (high-priority «Входящий
// звонок») не троттлился вообще — зная адрес жертвы, атакующий устраивал шквал
// звонковых уведомлений (спам/разряд батареи). Интервал мягче обычного (звонить
// повторно легитимно быстрее, чем слать сообщения), но флуд отсекает.
const CALL_PUSH_MIN_INTERVAL_MS = Number(process.env.RELAY_CALL_PUSH_INTERVAL_MS) || 5000;
const lastCallPushAt = new Map();
function sweepPushGates(now = Date.now()) {
  messagePushGate.sweep(now);
  const ccut = now - 10 * CALL_PUSH_MIN_INTERVAL_MS;
  for (const [pk, t] of lastCallPushAt) if (t < ccut) lastCallPushAt.delete(pk);
}
setInterval(sweepPushGates, 60000).unref();

// СРВ-4: потолок длины адреса получателя. box-pubkey в base64 = 44 символа; берём
// с запасом. Без этого `to` не ограничивался ничем, кроме maxPayload (~33 МБ) и в
// учёте байтов очереди не участвовал — крошечный envelope + гигантский `to`
// обходили байтовый потолок и раздували диск. Кап закрывает вектор в корне.
const MAX_ADDR_LEN = 64;

// H4: сколько доверенных обратных прокси перед релеем. X-Forwarded-For клиент
// может подделать в НАЧАЛЕ списка; честный прокси (Caddy) ДОПИСЫВАЕТ реальный IP
// в КОНЕЦ. Поэтому доверяем XFF только за известным числом прокси и берём
// hops-й элемент С КОНЦА. По умолчанию 0 — XFF игнорируется (безопасно для
// прямого режима); за Caddy оператор ставит RELAY_TRUST_PROXY=1.
const TRUST_PROXY_HOPS = Math.max(0, Number(process.env.RELAY_TRUST_PROXY) || 0);
function clientIp(req) {
  const remote = (req && req.socket && req.socket.remoteAddress) || 'unknown';
  if (TRUST_PROXY_HOPS > 0) {
    const xff = req && req.headers && req.headers['x-forwarded-for'];
    if (xff) {
      const parts = String(xff)
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      const idx = parts.length - TRUST_PROXY_HOPS;
      if (idx >= 0 && parts[idx]) return parts[idx];
    }
  }
  return remote;
}

let seq = 0;
function nextId() {
  seq = (seq + 1) % Number.MAX_SAFE_INTEGER;
  // СРВ-8: добавляем случайный суффикс. seq сбрасывается при рестарте, а Date.now()
  // может повториться — без энтропии теоретически возможна коллизия id, из-за
  // которой INSERT OR REPLACE затёр бы чужой конверт и оставил сиротский blob.
  return Date.now().toString(36) + '-' + seq.toString(36) + '-' + crypto.randomBytes(3).toString('hex');
}

// --- ownership proof helpers ---------------------------------------------
// КРП-1: доменно-разделённая подпись challenge («licno-relay-challenge-v1|»+nonce).
// Должна совпадать с клиентской crypto.signChallenge. Принимаем ОБА варианта:
// новый (с префиксом) и сырой nonce (легаси-клиент до КРП-1) — переходная
// совместимость. Оракул закрыт уже тем, что НОВЫЙ клиент сырой nonce не подписывает.
const CHALLENGE_SIG_PREFIX = 'licno-relay-challenge-v1|';
function verifySignature(nonceB64, signatureB64, signPublicKeyB64) {
  try {
    const sig = naclUtil.decodeBase64(signatureB64);
    const pk = naclUtil.decodeBase64(signPublicKeyB64);
    if (ed25519.verify(naclUtil.decodeUTF8(CHALLENGE_SIG_PREFIX + nonceB64), sig, pk)) {
      return true;
    }
    return ed25519.verify(naclUtil.decodeBase64(nonceB64), sig, pk);
  } catch (e) {
    return false;
  }
}

// H5/H6: доказательство владения box-ключом адреса. Должно совпадать с клиентским
// crypto.proveBoxOwnership: HMAC-SHA512(ECDH(eph, boxPub), "licno-box-proof-v1|"||nonce).
// Держим примитивы локально, чтобы релей оставался самодостаточным (server/).
const BOX_PROOF_PREFIX = 'licno-box-proof-v1|';
function hmacSha512(key, data) {
  const B = 128;
  let k = key;
  if (k.length > B) k = nacl.hash(k);
  if (k.length < B) {
    const t = new Uint8Array(B);
    t.set(k);
    k = t;
  }
  const ipad = new Uint8Array(B);
  const opad = new Uint8Array(B);
  for (let i = 0; i < B; i++) {
    ipad[i] = k[i] ^ 0x36;
    opad[i] = k[i] ^ 0x5c;
  }
  const inner = nacl.hash(concatU8(ipad, data));
  return nacl.hash(concatU8(opad, inner));
}
function concatU8(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}
/** true, если boxProof доказывает владение box-секреткой адреса boxPubB64. */
function verifyBoxProof(nonceB64, proofB64, boxPubB64, ephSecB64) {
  try {
    // НАТ-2: через единую точку. Она же отбраковывает точку малого порядка —
    // раньше здесь этой отбраковки не было вовсе: нулевой общий секрет прошёл
    // бы дальше и доказательство считалось бы от него.
    const shared = x25519.sharedSecret(
      naclUtil.decodeBase64(ephSecB64),
      naclUtil.decodeBase64(boxPubB64)
    );
    const data = concatU8(naclUtil.decodeUTF8(BOX_PROOF_PREFIX), naclUtil.decodeBase64(nonceB64));
    const expected = hmacSha512(shared, data).slice(0, 32);
    const got = naclUtil.decodeBase64(proofB64);
    if (got.length !== expected.length) return false;
    return nacl.verify(got, expected); // constant-time
  } catch (e) {
    return false;
  }
}

// --- Подлинность релея (S6) ------------------------------------------------
// Релей подписывает клиентский cnonce своим долговременным Ed25519-ключом; его
// публичную половину клиент пинит (config.SEED_RELAY_KEYS) и отвергает релей без
// валидной подписи. Ключ берём из RELAY_SIGN_SECRET (base64) либо персистим в
// файле рядом с БД (стабильность пина между рестартами) и печатаем публичную
// половину в лог, чтобы оператор внёс её клиентам.
const RELAY_AUTH_PREFIX = 'licno-relay-auth-v1|';
const RELAY_SIGN_KEY_FILE = process.env.RELAY_SIGN_KEY_FILE || path.join(path.dirname(DB_FILE), 'relay-sign.key');
/**
 * Т-4: новая личность релея создаётся только тогда, когда прежней ТОЧНО нет.
 *
 * ЧТО БЫЛО НЕ ТАК. Чтение файла с ключом не различало два случая: «файла нет»
 * (первый запуск, нормально) и «файл есть, но не читается» (права, сбой тома,
 * подмонтированный не туда volume). Оба вели в одну ветку — сгенерировать новую
 * пару. А публичную половину клиенты ПИНЯТ: смена ключа для них выглядит как
 * подмена релея, и они отказываются с ним разговаривать. Узел при этом считает,
 * что всё в порядке, и оператор узнаёт о случившемся по массовому «релей не
 * отвечает», не имея ни строчки в логе о причине.
 *
 * Теперь новая пара создаётся только на ENOENT. Любая другая ошибка чтения —
 * отказ старта: прежний ключ, скорее всего, цел и лежит рядом, и заменить его
 * молча значит потерять доверие всех клиентов ради обхода проблемы с правами.
 * Не стартовать громко лучше, чем стартовать чужим.
 *
 * `exit` и `fileSystem` параметризованы ради теста: проверить поведение при
 * нечитаемом ключе иначе нечем, а именно оно здесь и важно.
 */
function loadOrCreateRelaySignKeys({
  fileSystem = fs,
  exit = (code) => process.exit(code),
} = {}) {
  let secB64 = process.env.RELAY_SIGN_SECRET || null;
  if (!secB64) {
    try {
      secB64 = fileSystem.readFileSync(RELAY_SIGN_KEY_FILE, 'utf8').trim();
    } catch (e) {
      if (!e || e.code !== 'ENOENT') {
        console.error(
          `[relay-key] ключ ${RELAY_SIGN_KEY_FILE} существует, но не читается (${(e && e.code) || 'ошибка'}). ` +
            'Новый НЕ генерирую: клиенты пинят публичную половину, и подмена ключа отрезала бы их всех. ' +
            'Проверьте права и том, затем запустите снова.'
        );
        exit(1);
        return null;
      }
      // ENOENT — первый запуск, пару создаём ниже.
    }
  }
  try {
    if (secB64) {
      const kp = nacl.sign.keyPair.fromSecretKey(naclUtil.decodeBase64(secB64));
      return { pub: naclUtil.encodeBase64(kp.publicKey), sec: kp.secretKey };
    }
  } catch (e) {
    console.error('[relay-key] RELAY_SIGN_SECRET некорректен — генерирую новый');
  }
  const kp = nacl.sign.keyPair();
  try {
    fileSystem.writeFileSync(RELAY_SIGN_KEY_FILE, naclUtil.encodeBase64(kp.secretKey), { mode: 0o600 });
  } catch (e) {
    // Пара создана, но на диск не легла: следующий запуск возьмёт ДРУГУЮ, и
    // запинившие клиенты потеряют доверие к релею. Работать в таком состоянии —
    // значит копить отказы, которые проявятся при ближайшем рестарте и будут
    // выглядеть беспричинными. Отказываем в старте сразу и называем причину.
    console.error(
      `[relay-key] не удалось сохранить ключ в ${RELAY_SIGN_KEY_FILE} (${(e && e.code) || 'ошибка'}). ` +
        'Без этого следующий запуск сменит личность релея и отрежет запинивших клиентов. ' +
        'Дайте процессу право записи либо задайте RELAY_SIGN_SECRET.'
    );
    exit(1);
    return null;
  }
  return { pub: naclUtil.encodeBase64(kp.publicKey), sec: kp.secretKey };
}
const RELAY_KEYS = loadOrCreateRelaySignKeys();
function signRelayAuth(cnonce) {
  return naclUtil.encodeBase64(ed25519.sign(naclUtil.decodeUTF8(RELAY_AUTH_PREFIX + cnonce), RELAY_KEYS.sec));
}

// --- VAPID для web-push: общий БАЗОВЫЙ секрет, пара — на устройство ---------
// В публичном образе нет приватного VAPID. Genesis-релей из vapid-fleet.json
// создаёт/подписывает одну пару, остальные разрешённые узлы получают тот же
// подписанный bundle по NaCl-box через POST /vapid-fleet. Выдача разрешена только
// URL из списка флота, чей relay-sign.key совпал и чей публичный IP является
// источником запроса. Поэтому произвольный узел из открытого gossip ключ не получит.
//
// ВЫС-51: эта общая пара — БАЗОВЫЙ СЕКРЕТ, а не то, что видит push-провайдер.
// Клиенту (кадр `ready`, кадр `vapid-key`) и в подпись пуша идёт пара,
// выведенная из адреса устройства (server/vapid-identity.js). Общей она
// остаётся ровно затем, чтобы любой релей флота вывел ту же пару и мог
// разбудить устройство, чья очередь осела именно у него. Наружу (/health) по-
// прежнему отдаётся базовый публичный ключ — по нему операторы сверяют, что
// флот синхронен; ключевого материала он не раскрывает.
const RELAY_VAPID_KEY_FILE = process.env.RELAY_VAPID_KEY_FILE || path.join(path.dirname(DB_FILE), 'vapid.json');
const RELAY_VAPID_FLEET_FILE =
  process.env.RELAY_VAPID_FLEET_FILE || path.join(__dirname, 'vapid-fleet.json');
const VAPID_FLEET_ALLOW_PRIVATE = process.env.RELAY_VAPID_FLEET_ALLOW_PRIVATE === '1'; // только интеграционные тесты
const VAPID_STANDALONE = process.env.RELAY_VAPID_STANDALONE === '1';
const VAPID_SYNC_INTERVAL_MS = Math.max(10000, Number(process.env.RELAY_VAPID_SYNC_MS) || 60000);

let VAPID_FLEET = null;
try {
  VAPID_FLEET = loadFleetConfig(RELAY_VAPID_FLEET_FILE, { allowPrivate: VAPID_FLEET_ALLOW_PRIVATE });
} catch (e) {
  // Bare-metal/сторонний запуск без fleet-файла остаётся совместимым: ниже
  // сработает прежний standalone-путь. В официальном образе файл обязателен.
  if (fs.existsSync(RELAY_VAPID_FLEET_FILE)) {
    console.error('[vapid-fleet] конфигурация некорректна:', e && e.message);
  }
}
const VAPID_MEMBER = VAPID_FLEET && SELF_URL ? memberFor(VAPID_FLEET, SELF_URL) : null;
let vapidFleetBundle = null;
let vapidKeySource = 'disabled';
let onVapidActivated = null;

function activateVapid(publicKey, privateKey, source, bundle) {
  if (!validVapidPair(publicKey, privateKey)) return false;
  const before = vapidPublicKey();
  // SELF_URL идёт в contact URI (RFC 8292): контактом узла становится он сам, а
  // не общая для всего флота константа, по которой провайдер склеивал подписки.
  if (!setVapidKeys(publicKey, privateKey, process.env.RELAY_VAPID_SUBJECT, SELF_URL)) return false;
  vapidFleetBundle = bundle || null;
  vapidKeySource = source;
  if (before !== publicKey && onVapidActivated) onVapidActivated();
  return true;
}

function resolveVapidKeysWith(options = {}) {
  const fleet = options.fleet === undefined ? VAPID_FLEET : options.fleet;
  const selfUrl = options.selfUrl === undefined ? SELF_URL : options.selfUrl;
  const member = options.member === undefined ? VAPID_MEMBER : options.member;
  const standalone = options.standalone === undefined ? VAPID_STANDALONE : options.standalone;
  const relayPublicKey = options.relayPublicKey || RELAY_KEYS.pub;
  const relaySecretKey = options.relaySecretKey || RELAY_KEYS.sec;
  const keyFile = options.keyFile || RELAY_VAPID_KEY_FILE;
  const fromEnv = options.fromEnv || {
    publicKey: process.env.RELAY_VAPID_PUBLIC || null,
    privateKey: process.env.RELAY_VAPID_PRIVATE || null,
  };
  const fromFile = options.fromFile === undefined ? readJsonFile(keyFile) : options.fromFile;
  const verifyBundle = options.verifyBundle || verifyVapidBundle;
  const acceptsKey = options.acceptsKey || memberAcceptsKey;
  const validPair = options.validPair || validVapidPair;
  const activate = options.activate || activateVapid;
  const generate = options.generate || generateVapidKeys;
  const signBundle = options.signBundle || signVapidBundle;
  const writeFile = options.writeFile || writeJsonAtomic;
  const logger = options.logger || console;

  if (fleet && selfUrl) {
    if (!member) {
      // Ошибка/чужой узел не должен тихо создать четвёртую VAPID-пару и отдать её
      // PWA-клиентам. Явный standalone override оставлен для независимых операторов.
      if (!standalone) {
        logger.warn(`[vapid-fleet] ${selfUrl} не входит в разрешённый флот — web-push выключен`);
        return null;
      }
    } else if (!acceptsKey(member, relayPublicKey)) {
      logger.error(
        `[vapid-fleet] relay-sign.key не совпадает с разрешённым ключом для ${selfUrl} — web-push выключен`
      );
      return null;
    } else {
      if (verifyBundle(fromFile, fleet)) {
        activate(fromFile.publicKey, fromFile.privateKey, 'fleet-file', fromFile);
        return 'fleet-file';
      }

      if (selfUrl.toLowerCase() !== fleet.genesis.toLowerCase()) {
        // Не принимаем старый локально сгенерированный vapid.json: follower ждёт
        // подписанный genesis bundle и затем безопасно заменит файл атомарно.
        logger.log('[vapid-fleet] общий VAPID ещё не получен — ожидаю разрешённый peer');
        return null;
      }

      // Genesis может принять уже существующую пару (важно при миграции с живыми
      // подписками) или env override, затем подписывает её своим relay-sign.key.
      let pair = validPair(fromEnv.publicKey, fromEnv.privateKey) ? fromEnv : null;
      if (!pair && fromFile && validPair(fromFile.publicKey, fromFile.privateKey)) {
        pair = { publicKey: fromFile.publicKey, privateKey: fromFile.privateKey };
      }
      if (!pair) pair = generate();
      try {
        const bundle = signBundle(pair, fleet, relaySecretKey);
        writeFile(keyFile, bundle);
        activate(bundle.publicKey, bundle.privateKey, 'fleet-genesis', bundle);
        logger.log(`[vapid-fleet] genesis создал/подписал общий VAPID epoch=${bundle.epoch}`);
        return 'fleet-genesis';
      } catch (e) {
        logger.warn('[vapid-fleet] не удалось создать/сохранить общий VAPID:', e && e.message);
        return null;
      }
    }
  }

  // Совместимость для bare-metal/стороннего standalone-релея без fleet-конфига.
  let pair = validPair(fromEnv.publicKey, fromEnv.privateKey) ? fromEnv : null;
  if (!pair && fromFile && validPair(fromFile.publicKey, fromFile.privateKey)) {
    pair = { publicKey: fromFile.publicKey, privateKey: fromFile.privateKey };
  }
  if (!pair) pair = generate();
  try {
    if (!fromFile || fromFile.publicKey !== pair.publicKey || fromFile.privateKey !== pair.privateKey) {
      writeFile(keyFile, pair);
    }
    activate(pair.publicKey, pair.privateKey, 'standalone', null);
    return 'standalone';
  } catch (e) {
    logger.warn('[push] не удалось создать/сохранить VAPID:', e && e.message);
    return null;
  }
}
function resolveVapidKeys() {
  return resolveVapidKeysWith();
}
resolveVapidKeys();

// --- TURN: секрет и конфиг coturn во владении релея (H-2/M-4) --------------
// Автономность: релей сам владеет секретом TURN и пишет конфиг coturn в data-том
// (0600). coturn стартует с `-c <data>/turnserver.conf` и читает секрет ОТТУДА —
// секрета больше нет в аргументах процесса, env и world-readable файлах. Приоритет
// источника: TURN_SECRET (совместимость/override) -> TURN_SECRET_FILE -> само-
// генерация + персист (как relay-sign.key). Всё это едет в образе через watchtower.
const TURN_SECRET_FILE = process.env.TURN_SECRET_FILE || path.join(path.dirname(DB_FILE), 'turn-secret');
const COTURN_CONF_FILE = process.env.RELAY_COTURN_CONF || path.join(path.dirname(DB_FILE), 'turnserver.conf');
/**
 * Т-4: секрет TURN, и почему здесь НЕ отказ старта.
 *
 * Отличие от ключа подписи релея принципиальное. Тот пинят клиенты, и его смена
 * отрезает их навсегда — потому там отказ в старте. Секрет TURN не пинят: его
 * смена делает недействительными выданные часовые учётки, звонки перестают
 * соединяться примерно на час и чинятся сами. Ронять из-за этого весь узел —
 * лечение хуже болезни.
 *
 * Что здесь исправлено. Во-первых, нечитаемый СУЩЕСТВУЮЩИЙ файл больше не
 * приводит к записи поверх него: прежний секрет мог быть цел, и затереть его,
 * не сумев прочитать, значит превратить временную проблему с правами в
 * постоянную потерю. Во-вторых, обе неудачи теперь громко названы: раньше узел
 * молчал, а оператор видел только «звонки перестали соединяться после
 * обновления» и не имел ни одной зацепки.
 */
function resolveTurnSecret({ fileSystem = fs } = {}) {
  if (process.env.TURN_SECRET) return process.env.TURN_SECRET; // явный override оператора
  let mayPersist = true;
  try {
    const f = fileSystem.readFileSync(TURN_SECRET_FILE, 'utf8').trim();
    if (f) return f;
  } catch (e) {
    if (!e || e.code !== 'ENOENT') {
      // Файл есть, но не читается. Записывать поверх нельзя: под ним, скорее
      // всего, лежит рабочий секрет, а мы просто не смогли до него добраться.
      console.error(
        `[turn] секрет ${TURN_SECRET_FILE} существует, но не читается (${(e && e.code) || 'ошибка'}). ` +
          'Этот запуск работает на временном секрете, поверх файла НЕ пишу. ' +
          'После рестарта выданные TURN-учётки протухнут — проверьте права.'
      );
      mayPersist = false;
    }
    // ENOENT — первый запуск: секрет генерируется ниже, это штатный путь.
  }
  const gen = crypto.randomBytes(32).toString('hex');
  if (mayPersist) {
    try {
      fileSystem.writeFileSync(TURN_SECRET_FILE, gen, { mode: 0o600 });
    } catch (e) {
      console.error(
        `[turn] не удалось сохранить секрет в ${TURN_SECRET_FILE} (${(e && e.code) || 'ошибка'}). ` +
          'Секрет остаётся только в памяти: после рестарта он сменится, и выданные клиентам ' +
          'учётки перестанут работать примерно на час. Дайте процессу право записи.'
      );
    }
  }
  return gen;
}

// Встроенный coturn (флаг RELAY_EMBED_COTURN): в Docker-образе релей сам запускает
// turnserver дочерним процессом — отдельного контейнера coturn НЕТ, весь TURN
// (секрет+конфиг+процесс) живёт в образе, который watchtower обновляет → будущие
// правки TURN автономны. Флаг ставит ТОЛЬКО compose образа; bare-metal (системный
// coturn под systemd) его не ставит, поэтому второго coturn не поднимается.
let coturnChild = null;
let coturnStopped = false;
function startEmbeddedCoturn() {
  if (coturnChild || coturnStopped) return;
  const { spawn } = require('child_process');
  try {
    coturnChild = spawn('turnserver', ['-c', COTURN_CONF_FILE], { stdio: ['ignore', 'inherit', 'inherit'] });
  } catch (e) {
    console.warn('[turn] встроенный coturn не запустился:', e && e.message);
    coturnChild = null;
    return;
  }
  coturnChild.on('error', (e) => console.warn('[turn] coturn:', e && e.message));
  coturnChild.on('exit', (code, sig) => {
    coturnChild = null;
    if (coturnStopped) return;
    console.warn(`[turn] coturn завершился (code=${code} sig=${sig}) — перезапуск через 3с`);
    setTimeout(startEmbeddedCoturn, 3000).unref();
  });
  console.log(`[turn] встроенный coturn запущен: turnserver -c ${COTURN_CONF_FILE}`);
}
function stopEmbeddedCoturn() {
  coturnStopped = true;
  if (coturnChild) {
    try {
      coturnChild.kill('SIGTERM');
    } catch (e) {
      // Процесс мог завершиться сам между проверкой и сигналом; ссылку
      // обнуляем в любом случае, и перезапуск отключён флагом coturnStopped.
    }
    coturnChild = null;
  }
}

if (TURN_HOST) {
  turnSecret = resolveTurnSecret();
  try {
    fs.writeFileSync(
      COTURN_CONF_FILE,
      // ДПЛ-5: pid coturn — рядом с конфигом в data-томе (writable под non-root),
      // а не в root-only /var/run.
      coturnConfigText(turnSecret, {
        turnHost: TURN_HOST,
        pidfile: path.join(path.dirname(COTURN_CONF_FILE), 'turnserver.pid'),
        userdb: path.join(path.dirname(COTURN_CONF_FILE), 'turndb'),
      }),
      { mode: 0o600 }
    );
    console.log(`[turn] coturn config -> ${COTURN_CONF_FILE} (секрет во владении релея, 0600)`);
  } catch (e) {
    console.warn('[turn] не удалось записать конфиг coturn:', e && e.message);
  }
  // Встроенный coturn стартуем только по флагу (Docker-образ) — bare-metal нет.
  if (process.env.RELAY_EMBED_COTURN) startEmbeddedCoturn();
} else {
  turnSecret = process.env.TURN_SECRET || null;
  // БЕЗ-1: молчаливого отката на чужой STUN больше нет, поэтому оператор должен
  // узнать об этом при старте, а не по жалобам на несобирающиеся звонки.
  if (!PUBLIC_STUN.length) {
    console.warn(
      '[turn] TURN_HOST не задан: релей не выдаёт ни STUN, ни TURN. Звонки за NAT не соберутся.\n' +
        '       Поднимите coturn на этом узле (TURN_HOST=<адрес> + RELAY_EMBED_COTURN=1) —\n' +
        '       он же раздаёт STUN на порту 3478. Внешний STUN, если он вам осознанно нужен,\n' +
        '       задаётся явно: RELAY_PUBLIC_STUN=stun:stun.example.org:3478'
    );
  }
}

// --- X3DH prekeys ----------------------------------------------------------
// Формат подписи SPK должен совпадать с клиентским (src/crypto.js).
const SPK_SIG_PREFIX = 'licno-spk-v1|';
const SPK_PQ_SIG_PREFIX = 'licno-spk-v2|'; // БЕЗ-3: подпись покрывает и ML-KEM-ключ
// Публичный ключ ML-KEM-768 — 1184 байта, то есть ~1580 символов base64.
// Потолок с запасом: он же отсекает попытку раздуть таблицу prekey мусором.
const MAX_SPK_PQ_B64 = 2048;
const MAX_OTPS_PER_USER = 100;
// M2: троттлинг выдачи prekey на СОЕДИНЕНИЕ. Без него авторизованный клиент за
// пару секунд (rate-limit 80 кадров/с) высасывал все OTP жертвы по её адресу,
// деградируя forward secrecy её будущих собеседников. Легитимному клиенту
// prekeys-get нужен изредка (новый контакт), поэтому 60/мин с запасом хватает;
// при превышении отвечаем bundle:null (X3DH-фолбэк), OTP при этом НЕ тратится.
const PREKEY_GET_WINDOW_MS = 60000;
const PREKEY_GET_MAX = 60;
// H-4: троттлинг ВЫДАЧИ одноразовых prekey по ЦЕЛЕВОМУ адресу — ГЛОБАЛЬНО по всем
// соединениям. M2 (выше) считал на соединение и обходился числом соединений:
// атакующий открывал много сессий и высасывал OTP жертвы, деградируя forward
// secrecy её первых сообщений. Теперь на адрес выдаётся не больше PREKEY_TARGET_MAX
// OTP за окно; сверх лимита отдаём SPK без OTP (opk:null) — X3DH всё равно работает
// (SPK forward-secret), но одноразовые ключи не расходуются. Порог щедрый:
// легитимно OTP жертвы запрашивают редко (новый контакт).
const PREKEY_TARGET_WINDOW_MS = Number(process.env.RELAY_PREKEY_TARGET_MS) || 60000;
const PREKEY_TARGET_MAX = Number(process.env.RELAY_PREKEY_TARGET_MAX) || 30;
const otpDrain = new Map(); // targetPubkey -> { start, count } (реально выданные OTP в окне)
function sweepOtpDrain(now = Date.now()) {
  const cutoff = now - PREKEY_TARGET_WINDOW_MS;
  for (const [pk, d] of otpDrain) if (d.start < cutoff) otpDrain.delete(pk);
}
setInterval(sweepOtpDrain, PREKEY_TARGET_WINDOW_MS).unref();
const isB64Field = (s, max = 128) => typeof s === 'string' && s.length > 0 && s.length <= max;

function verifySpkSignature(spkObj, signPublicKeyB64) {
  try {
    // БЕЗ-3: у бандла с постквантовым ключом подпись покрывает и его, поэтому
    // формат подписываемой строки другой. Релей проверяет это не ради себя (он
    // и так не может подделать бандл — клиент сверяет подпись сам), а чтобы не
    // хранить заведомо негодные бандлы и не отдавать их вместо рабочих.
    const message = spkObj.pq
      ? SPK_PQ_SIG_PREFIX + spkObj.id + '|' + spkObj.pub + '|' + spkObj.pq
      : SPK_SIG_PREFIX + spkObj.id + '|' + spkObj.pub;
    return ed25519.verify(
      naclUtil.decodeUTF8(message),
      naclUtil.decodeBase64(spkObj.sig),
      naclUtil.decodeBase64(signPublicKeyB64)
    );
  } catch (e) {
    return false;
  }
}

const server = http.createServer((req, res) => {
  if (req.url === '/health') {
    const st = store.stats();
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(
      JSON.stringify({
        ok: true,
        protocol: RELAY_PROTOCOL,
        capabilities: RELAY_CAPABILITIES,
        maxLinkedDevices: MAX_ACTIVE_DEVICES,
        online: online.size,
        queued: st.usersQueued,
        messages: st.totalQueued,
        relays: relayDir.length,
        vapid: !!vapidPublicKey(),
        // ВЫС-51: это БАЗОВЫЙ ключ узла, по которому оператор сверяет
        // синхронность флота. Клиентам он не выдаётся — у каждого своя пара.
        vapidPublicKey: vapidPublicKey(),
        vapidSource: vapidKeySource,
        vapidFleetMember: !!VAPID_MEMBER,
      })
    );
    return;
  }
  // P2P-выдача общей VAPID-пары. Ответ всегда зашифрован на одноразовый NaCl-box
  // ключ разрешённого релея; браузер/обычный клиент этот endpoint использовать не
  // может. Обработчик сам проверяет relay-sign подпись и IP заявленного URL.
  if (req.method === 'POST' && req.url === '/vapid-fleet') {
    handleVapidFleetHttp(req, res).catch((e) => {
      console.warn('[vapid-fleet] HTTP handler failed:', e && e.message);
      if (!res.headersSent) res.writeHead(500, { 'content-type': 'application/json' });
      if (!res.writableEnded) res.end(JSON.stringify({ ok: false }));
    });
    return;
  }
  // ОБН-2: раздача обновлений приложения.
  //
  // Обновление жило по одному адресу — `https://lichno.pro/download/…`. Один
  // домен — одна точка отказа, и отказ этот чаще не технический: домен
  // блокируют, разделегируют, за него забывают заплатить. Обновления встают у
  // всех разом и ровно тогда, когда нужнее всего: после находки дыры в
  // предыдущей сборке.
  //
  // Раздавать это с релея безопасно ровно потому, что доверия к релею нет:
  // манифест подписан ключом выпуска, ключ вшит в приложение, файл сверяется с
  // отпечатком из подписанного манифеста. Релей не может подсунуть свою сборку
  // — у него нет ключа; он может только не отдать ничего.
  //
  // Раздача ВЫКЛЮЧЕНА, пока оператор не задал RELAY_UPDATE_DIR: файл весит
  // десятки мегабайт, и платит за них он.
  // ВЫП-10: страница знакомства. Сюда приводит системная камера того, у кого
  // приложения ещё нет: код знакомства теперь ссылка, а не набор символов.
  //
  // Данные знакомства узел НЕ ВИДИТ и видеть не должен — они во фрагменте
  // ссылки, а фрагмент браузер на сервер не отправляет.
  if (req.url === '/i' || req.url.startsWith('/i?') || req.url.startsWith('/i#')) {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { 'content-type': 'text/plain' });
      res.end('method');
      return;
    }
    const html = landing.landingHtml({
      userAgent: (req.headers && req.headers['user-agent']) || '',
      downloadUrl: `${updateFeed.RELEASE_FILE_PATH}?platform=android`,
      webUrl: webApp.WEB_APP_PREFIX,
    });
    const body = Buffer.from(html, 'utf8');
    res.writeHead(200, {
      'content-type': 'text/html; charset=utf-8',
      'content-length': String(body.length),
      'x-content-type-options': 'nosniff',
      'cache-control': 'no-cache',
    });
    if (req.method === 'HEAD') return res.end();
    res.end(body);
    return;
  }

  // ВЫП-9: веб-версия приложения. Её открывают там, где приложения не поставить
  // — на iPhone магазина у проекта нет, а APK туда не ставится вовсе.
  //
  // Отдаём только GET/HEAD и только из каталога веб-сборки: путь приходит из
  // сети, и ошибка здесь означала бы выдачу любого файла с диска узла.
  {
    const relative = webApp.webAppPath(req.url);
    if (relative !== null) {
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        res.writeHead(405, { 'content-type': 'text/plain' });
        res.end('method');
        return;
      }
      const full = relative ? webApp.resolveWebFile(WEB_DIR, relative) : '';
      let stat = null;
      try {
        stat = full ? fs.statSync(full) : null;
      } catch (e) {
        stat = null;
      }
      if (!stat || !stat.isFile()) {
        // Нет файла — отдаём страницу приложения: у веб-версии свои внутренние
        // адреса, и по прямой ссылке на них браузер приходит сюда.
        const page = webApp.resolveWebFile(WEB_DIR, 'index.html');
        let pageStat = null;
        try {
          pageStat = page ? fs.statSync(page) : null;
        } catch (e) {
          pageStat = null;
        }
        if (!pageStat || !pageStat.isFile()) {
          res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
          res.end('веб-версия на этом узле ещё не разложена');
          return;
        }
        res.writeHead(200, webApp.webAppHeaders('index.html', pageStat.size));
        if (req.method === 'HEAD') return res.end();
        fs.createReadStream(page).pipe(res);
        return;
      }
      res.writeHead(200, webApp.webAppHeaders(relative, stat.size));
      if (req.method === 'HEAD') return res.end();
      fs.createReadStream(full).pipe(res);
      return;
    }
  }

  if (req.url === '/update' || req.url.startsWith('/update?') || req.url.startsWith('/update/')) {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { 'content-type': 'text/plain' });
      res.end('method');
      return;
    }
    const parsed = new URL(req.url, 'http://x');
    const platform = parsed.searchParams.get('platform');
    const wantsFile = parsed.pathname === '/update/file';
    if (!wantsFile && parsed.pathname !== '/update') {
      res.writeHead(404, { 'content-type': 'text/plain' });
      res.end('not found');
      return;
    }
    const limiter = wantsFile ? updateFileRate : updateManifestRate;
    if (!limiter.allow(clientIp(req), Date.now())) {
      counters.updateHttpLimited += 1;
      res.writeHead(429, { 'content-type': 'text/plain', 'retry-after': '60' });
      res.end('rate');
      return;
    }
    if (wantsFile) {
      const verdict = updateFeed.fileResponse({
        dir: UPDATE_DIR,
        platform,
        stat: (target) => fs.statSync(target),
      });
      if (verdict.status !== 200) {
        res.writeHead(404, { 'content-type': 'text/plain' });
        res.end(verdict.reason || 'not found');
        return;
      }
      counters.updateFileServed += 1;
      res.writeHead(200, {
        'content-type': verdict.type,
        'content-length': String(verdict.size),
        'content-disposition': `attachment; filename="${verdict.filename}"`,
        'access-control-allow-origin': '*',
      });
      if (req.method === 'HEAD') {
        res.end();
        return;
      }
      // Потоком: держать десятки мегабайт в памяти релея ради раздачи —
      // верный способ уронить узел, на котором лежит чужая переписка.
      const stream = fs.createReadStream(verdict.path);
      stream.on('error', () => {
        // Файл убрали прямо во время отдачи. Заголовки уже ушли, и сказать об
        // этом нечем — рвём соединение: клиент увидит недокачанный файл, не
        // сойдётся отпечаток и пойдёт к следующему источнику.
        res.destroy();
      });
      stream.pipe(res);
      return;
    }
    // ОБН-5: адрес, по которому к нам пришли. Нужен, чтобы подставить себя в
    // манифест Tauri: у него адрес файла не подписан, а вот сам файл подписан,
    // и отправлять клиента за ним на недоступный сайт бессмысленно.
    //
    // Берём из заголовка Host, а не из настройки: релей стоит за прокси, знает
    // о себе только внутренний адрес, и любая настройка здесь разошлась бы с
    // действительностью молча. Подделать Host может только сам клиент — и
    // навредит этим лишь себе.
    const host = String((req.headers && req.headers.host) || '').trim();
    const selfUrl = /^[A-Za-z0-9.\-:[\]]{1,255}$/.test(host) ? `https://${host}` : '';
    const verdict = updateFeed.manifestResponse({
      dir: UPDATE_DIR,
      platform,
      selfUrl,
      read: (target) => fs.readFileSync(target, 'utf8'),
    });
    if (verdict.status !== 200) {
      res.writeHead(404, { 'content-type': 'text/plain' });
      res.end(verdict.reason || 'not found');
      return;
    }
    counters.updateManifestServed += 1;
    res.writeHead(200, {
      'content-type': 'application/json',
      'access-control-allow-origin': '*',
      // Манифест меняется раз в выпуск, но кэш здесь опаснее лишнего запроса:
      // придержанный старый манифест — это человек, не узнавший о починке.
      'cache-control': 'no-store',
    });
    res.end(req.method === 'HEAD' ? undefined : verdict.body);
    return;
  }

  // Метрики для мониторинга (Prometheus text format). Закрывается токеном
  // через RELAY_METRICS_TOKEN (см. metricsAuthorized).
  if (req.url === '/metrics' || req.url.startsWith('/metrics?')) {
    if (!metricsAuthorized(req)) {
      res.writeHead(403, { 'content-type': 'text/plain' });
      res.end('forbidden');
      return;
    }
    res.writeHead(200, { 'content-type': 'text/plain; version=0.0.4; charset=utf-8' });
    res.end(renderMetrics());
    return;
  }
  // Публичный каталог релеев — любой (клиент или другой релей) может забрать его
  // отсюда. Это и есть точка, из которой список реплицируется по сети.
  // ПЯЩ-1: репликация ящика между узлами. Отдаём записки, появившиеся после
  // курсора соседа, — тем же способом, каким уже реплицируется каталог релеев.
  //
  // Отдавать можно кому угодно и незачем что-либо скрывать: записка не несёт ни
  // автора, ни адресата, а их не знает и сам отдающий. Ограничение только на
  // объём одного ответа.
  if (req.url === '/mbx' || req.url.startsWith('/mbx?')) {
    // ВЫС-19: этот GET отдавал до 1,2 МБ на запрос в сорок байт — усилитель
    // ×30000 — без аутентификации и без ограничения частоты. Записки по-прежнему
    // открыты (они не несут ни автора, ни адресата, и репликация между
    // операторами по замыслу свободна), но дёргать эндпойнт как насос больше
    // нельзя: частота на IP ограничена, а страница ответа уменьшена — полный
    // перенос и так идёт постранично по курсору. Сосед своего флота с общим
    // токеном федерации (тем же, что у POST /relays) лимиту не подчиняется:
    // его догоняющая репликация после простоя — самый законный из потоков.
    const trustedPeer =
      !!GOSSIP_TOKEN && safeEqual((req.headers && req.headers['x-gossip-token']) || '', GOSSIP_TOKEN);
    if (!trustedPeer && !mbxHttpRate.allow(clientIp(req), Date.now())) {
      counters.mbxHttpLimited += 1;
      res.writeHead(429, { 'content-type': 'text/plain', 'retry-after': '60' });
      res.end('rate');
      return;
    }
    const after = Number(new URL(req.url, 'http://x').searchParams.get('after')) || 0;
    const rows = store.mbxAfter(after, trustedPeer ? mbx.SYNC_LIMIT : MBX_HTTP_PAGE);
    const last = rows.length ? rows[rows.length - 1].seq : after;
    res.writeHead(200, { 'content-type': 'application/json', 'access-control-allow-origin': '*' });
    res.end(
      JSON.stringify({
        seq: last,
        slot: mbx.slotOf(Date.now()),
        records: mbx
          .packRecords(rows.map((row) => ({ key: row.key, value: row.val, mac: row.mac })))
          .toString('base64'),
        slots: rows.map((row) => row.slot),
      })
    );
    return;
  }

  if (req.url === '/relays') {
    // POST — другой релей сообщает о себе/своём каталоге (push-gossip): так
    // сосед, у которого мы в peers, узнаёт про нас без ручной настройки.
    if (req.method === 'POST') {
      // M1: учимся из POST только при совпадении общего токена. Аноним не может
      // отравить каталог/подсунуть вредоносные релеи; при этом GET-каталог открыт.
      const gossipOk =
        !!GOSSIP_TOKEN && safeEqual((req.headers && req.headers['x-gossip-token']) || '', GOSSIP_TOKEN);
      let body = '';
      let aborted = false;
      // СРВ-11: обрыв клиента посреди тела (ECONNRESET) эмитит 'error' на req; без
      // слушателя это штатное сетевое событие уходило в uncaughtException-backstop.
      req.on('error', () => {
        aborted = true;
      });
      req.on('data', (c) => {
        body += c;
        if (body.length > 200000) {
          aborted = true;
          req.destroy();
        }
      });
      req.on('end', () => {
        if (aborted) return;
        try {
          const j = JSON.parse(body);
          if (gossipOk && Array.isArray(j.relays)) learnRelays(j.relays.filter(isValidRelayUrl));
        } catch (e) {
          // Тело приходит от кого угодно из сети: мусор вместо JSON — обычное
          // дело, каталог отдаём и без него. Жаловаться на чужой ввод значило
          // бы дать любому желающему наполнять наш лог.
        }
        res.writeHead(200, { 'content-type': 'application/json', 'access-control-allow-origin': '*' });
        res.end(JSON.stringify({ relays: relayDir }));
      });
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json', 'access-control-allow-origin': '*' });
    res.end(JSON.stringify({ relays: relayDir }));
    return;
  }
  res.writeHead(426);
  res.end('Upgrade Required: connect via WebSocket');
});

const wss = new WebSocketServer({ server, maxPayload: MAX_ENVELOPE_BYTES + 1024 * 1024 });

const BATCHABLE_SERVER_FRAMES = new Set([
  'message',
  'ack',
  'delivered',
  'binary-ack',
  'binary-delivered',
]);

function flushFrameBatch(ws) {
  clearTimeout(ws.frameBatchTimer);
  ws.frameBatchTimer = null;
  const frames = ws.frameBatchQueue || [];
  ws.frameBatchQueue = [];
  ws.frameBatchBytes = 0;
  if (!frames.length || ws.readyState !== ws.OPEN) return false;
  try {
    const payload = encodeMessagePack(frames);
    ws.send(
      packBinaryFrame(
        { type: 'frame-batch-v1', version: 1, count: frames.length },
        payload
      ),
      { binary: true }
    );
    return true;
  } catch (error) {
    return false;
  }
}

function sendImmediate(ws, obj) {
  if (!ws || ws.readyState !== ws.OPEN) return false;
  try {
    ws.send(JSON.stringify(obj));
    return true;
  } catch (error) {
    return false;
  }
}

// АУД-12: сколько весит кадр — без повторной сериализации.
//
// Раньше здесь стояла полная JSON.stringify(obj) ТОЛЬКО ради длины: результат
// выбрасывался, а тот же кадр упаковывался в MessagePack заново в
// flushFrameBatch. То есть каждый батчуемый кадр сериализовался дважды, на
// самом горячем пути однопоточного процесса.
//
// Кадры-квитанции (ack/delivered) состоят из пары коротких идентификаторов и
// заведомо меньше порога — измерять их нечего. У кадра `message` вес задаёт
// конверт, и его размер уже посчитан при постановке в очередь (store.bytes),
// поэтому вызывающий передаёт его подсказкой. Полная сериализация остаётся
// только для непредвиденного случая — чтобы поведение не менялось молча.
const RECEIPT_FRAMES = new Set(['ack', 'delivered', 'binary-ack', 'binary-delivered']);
const RECEIPT_FRAME_BYTES = 512; // с запасом: id + ref + флаги

function frameBatchBytes(obj, sizeHint) {
  if (Number.isFinite(sizeHint) && sizeHint >= 0) return sizeHint;
  if (RECEIPT_FRAMES.has(obj.type)) return RECEIPT_FRAME_BYTES;
  return JSON.stringify(obj).length;
}

function send(ws, obj, sizeHint) {
  if (ws && ws.readyState === ws.OPEN) {
    if (
      ws.frameBatchV1 &&
      ws.authed &&
      obj &&
      typeof obj === 'object' &&
      BATCHABLE_SERVER_FRAMES.has(obj.type)
    ) {
      const encodedLength = frameBatchBytes(obj, sizeHint);
      if (encodedLength <= 64 * 1024) {
        ws.frameBatchQueue.push(obj);
        ws.frameBatchBytes += encodedLength;
        if (ws.frameBatchQueue.length >= 24 || ws.frameBatchBytes >= 192 * 1024) {
          flushFrameBatch(ws);
        } else if (!ws.frameBatchTimer) {
          ws.frameBatchTimer = setTimeout(() => flushFrameBatch(ws), 10);
        }
        return true;
      }
    }
    return sendImmediate(ws, obj);
  }
  return false;
}

function sendBinary(ws, header, payload) {
  if (ws.readyState !== ws.OPEN) return false;
  try {
    ws.send(packBinaryFrame(header, payload), { binary: true });
    return true;
  } catch (error) {
    return false;
  }
}

function queuedMessageFrame(item) {
  const frame = { type: 'message', id: item.id, envelope: item.envelope };
  if (item.from) frame.from = item.from;
  if (item.fromAccount) frame.fromAccount = item.fromAccount;
  if (item.fromDeviceId) frame.fromDeviceId = item.fromDeviceId;
  if (item.deviceCertificate) frame.deviceCertificate = item.deviceCertificate;
  if (item.deviceRoster) frame.deviceRoster = item.deviceRoster;
  return frame;
}

/**
 * ПРФ-14: отдать получателю кадр `message` — двоично, если он это умеет.
 *
 * Решение принимается ПО СОЕДИНЕНИЮ ПОЛУЧАТЕЛЯ, а не по отправителю: конверт
 * лежит в очереди в одном и том же виде, а как его вынуть — дело того, кто
 * забирает. Поэтому клиент прежней версии продолжает получать ровно тот же
 * JSON-кадр, что и раньше, независимо от того, кто и чем ему написал.
 *
 * Двоично уходит только запечатанный конверт (см. envelopeFrame.sealedBytes).
 * Незапечатанный отдаётся JSON-ом: разложить ЕГО поля по открытому заголовку
 * значило бы вернуть релею отправителя и счётчики храповика.
 *
 * `immediate` повторяет разделение из deliver(): кадр, не попавший в очередь,
 * нельзя откладывать в пакет — от него зависит смысл ответа отправителю.
 */
function sendMessageFrame(ws, frame, sizeHint, { immediate = false } = {}) {
  if (ws && ws.binaryEnvelopeV1 && ws.readyState === ws.OPEN) {
    const bytes = envelopeFrame.sealedBytes(frame.envelope);
    if (bytes) {
      try {
        const header = envelopeFrame.buildMessageHeader(frame);
        // Порядок кадров обязан сохраниться. Квитанции копятся в пакете до 10 мс,
        // а двоичный кадр уходит сразу — не вытолкни мы накопленное сейчас,
        // получатель увидел бы сообщение раньше квитанций, отправленных до него.
        if (ws.frameBatchQueue && ws.frameBatchQueue.length) flushFrameBatch(ws);
        return sendBinary(ws, header, bytes);
      } catch (error) {
        // Заголовок не влез (16 КиБ на roster и сертификат) — это не повод
        // терять сообщение: отдаём прежним путём.
      }
    }
  }
  return immediate ? sendImmediate(ws, frame) : send(ws, frame, sizeHint);
}

function queuedBinaryHeader(item) {
  const header = {
    type: 'attachment-chunk',
    version: 1,
    id: item.id,
    from: item.from,
    transferId: item.transferId,
    index: item.index,
    total: item.total,
  };
  if (item.metadata && item.metadata.fromAccount) header.fromAccount = item.metadata.fromAccount;
  if (item.metadata && item.metadata.fromDeviceId) header.fromDeviceId = item.metadata.fromDeviceId;
  return header;
}

function senderMetadata(ws) {
  if (!ws || !ws.pubkey) return {};
  return {
    fromAccount: ws.accountPubkey || ws.pubkey,
    fromDeviceId: ws.deviceId || undefined,
    deviceCertificate: ws.deviceCertificate || undefined,
    deviceRoster: ws.accountPubkey ? store.getAccountRoster(ws.accountPubkey) || undefined : undefined,
  };
}

// Follower может получить общий VAPID уже после того, как PWA аутентифицировалась.
// Не заставляем пользователя ждать следующего реконнекта: сообщаем новый публичный
// ключ всем уже готовым клиентам отдельным совместимым кадром.
//
// ВЫС-51: каждому — СВОЙ ключ, выведенный из его адреса. Разослать здесь общий
// (тот, что приехал в bundle) значило бы отменить всю доработку ровно для тех
// клиентов, которые дождались раздачи ключа, — а таких на follower'е
// большинство.
onVapidActivated = () => {
  for (const ws of wss.clients) {
    if (ws.authed) send(ws, { type: 'vapid-key', vapidPublicKey: vapidPublicKeyFor(ws.pubkey) });
  }
};

// S1: выгрузка очереди потоком, с backpressure. Раньше flushQueue материализовал ВСЮ очередь
// получателя разом (queueFor → JSON.parse каждого тела) и синхронно писал всё в
// буфер сокета без учёта bufferedAmount: 400 конвертов по 16 МБ (в пределах квот)
// давали ~6 ГБ аллокаций в одном тике → OOM/блокировка event loop, а реконнекты
// превращали это в устойчивый DoS. Теперь берём только СПИСОК id (дёшево), тело
// достаём по одному и приостанавливаемся, когда буфер сокета вырос выше отметки.
const FLUSH_HIGH_WATER = 4 * 1024 * 1024; // порог bufferedAmount, при котором ждём
const FLUSH_RESUME_MS = 25; // пауза перед проверкой backpressure

/**
 * АУД-06 (продолжение): тело конверта читается с диска АСИНХРОННО.
 *
 * ЧТО БЫЛО НЕ ТАК
 *
 * Список идентификаторов брался дёшево, но каждое тело — синхронным
 * `readFileSync` внутри `while`. Замер: выгрузка 500 чанков по 300 КБ держала
 * событийный цикл 102–111 мс ОДНИМ СПЛОШНЫМ КУСКОМ — за это время узел не
 * принимает ни одного кадра, не отвечает на heartbeat и не обслуживает
 * остальных. И происходит это именно тогда, когда нагрузка максимальна: при
 * переподключении, то есть у всех сразу после сбоя сети.
 *
 * ЧТО СТАЛО
 *
 * Асинхронное чтение той же очереди: 27–29 мс суммарно, максимум 0,38 мс за
 * раз, задержка таймеров не больше 0,55 мс. Работа та же, но цикл отдаётся
 * между конвертами.
 *
 * ЧТО ИЗ ЭТОГО СЛЕДУЕТ ДЛЯ КОДА
 *
 * Между чтением и записью в сокет теперь есть пауза, а значит появляются два
 * состояния, которых раньше не существовало: сокет мог закрыться, пока читалось
 * тело (поэтому проверка повторяется ПОСЛЕ await), и отказ чтения теперь
 * отвергнутое обещание, а не исключение (поэтому у запуска есть catch).
 */
function flushQueue(pubkey, ws, onComplete) {
  const ids = store.queueIdsFor(pubkey);
  let i = 0;
  async function pump() {
    if (ws.readyState !== ws.OPEN) return; // получатель ушёл — прекращаем
    while (i < ids.length) {
      // backpressure: не заливаем сокет, если предыдущее ещё не ушло в сеть.
      if (typeof ws.bufferedAmount === 'number' && ws.bufferedAmount > FLUSH_HIGH_WATER) {
        setTimeout(start, FLUSH_RESUME_MS);
        return;
      }
      const item = await store.getItemAsync(ids[i]);
      i += 1;
      // Сокет мог закрыться, пока читалось тело. В синхронной версии этого не
      // могло случиться, поэтому проверки здесь и не было.
      if (ws.readyState !== ws.OPEN) return;
      // АУД-12: размер конверта известен из очереди — сериализовать кадр ради
      // одной длины больше не нужно.
      if (item) sendMessageFrame(ws, queuedMessageFrame(item), item.bytes);
    }
    if (onComplete) onComplete();
  }
  function start() {
    // Отказ чтения не должен превращаться в необработанное отвергнутое обещание:
    // на релее это глобальный обработчик и запись в лог без всякого контекста.
    pump().catch((error) => console.warn('[queue] выгрузка прервана:', (error && error.message) || error));
  }
  start();
  return ids.length;
}

/**
 * ЭТП5-4: сколько конвертов отдаём по одному жетону.
 *
 * Пятьдесят. Сосед везёт их дальше по Bluetooth — примерно тридцать посылок на
 * конверт, — и отдать ему всю очередь целиком значило бы занять его радио на
 * часы и разрядить его телефон за нашу переписку. Остальное дождётся следующего
 * жетона: очередь никуда не девается, потому что удалять её предъявитель не
 * может.
 */
const GW_PULL_MAX_ITEMS = 50;

/** Сколько выборок по жетонам берём с одного соседа за окно. */
const GW_PULL_RATE = 6;
const GW_PULL_WINDOW_MS = 60 * 1000;

const gatewayTicketRule = require('./gateway-ticket');
const gatewayTickets = gatewayTicketRule.createTicketLedger();
const gatewayPullRate = new Map();

function gatewayPullAllowed(pubkey) {
  const at = Date.now();
  const entry = gatewayPullRate.get(pubkey);
  if (!entry || at - entry.startedAt > GW_PULL_WINDOW_MS) {
    gatewayPullRate.set(pubkey, { startedAt: at, count: 1 });
    return true;
  }
  entry.count += 1;
  return entry.count <= GW_PULL_RATE;
}

/**
 * ЭТП5-4: отдать очередь владельца предъявителю жетона.
 *
 * Отказ всегда один и тот же на вид: подробная причина сказала бы предъявителю,
 * чем именно его жетон не подошёл, — а по этому легко подбирать. В журнал
 * причина всё-таки идёт: без неё разбирать жалобу «связь через соседа не
 * работает» было бы нечем.
 */
function handleGatewayPull(ws, msg) {
  if (!ws.authed || !ws.pubkey) return send(ws, { type: 'gw-pull-result', ok: false });
  // Предъявитель обязан быть ДОКАЗАННЫМ владельцем своего адреса. Иначе жетон,
  // выданный соседу, предъявил бы всякий, кто занял его адрес на этом релее, —
  // ровно та дыра, которую закрывает АУД-Э1 для обычной выгрузки.
  if (!ws.proven) return send(ws, { type: 'gw-pull-result', ok: false });
  if (!gatewayPullAllowed(ws.pubkey)) return send(ws, { type: 'gw-pull-result', ok: false });
  const owner = msg && msg.ticket && typeof msg.ticket.addr === 'string' ? msg.ticket.addr : '';
  const bound = owner ? store.getIdentity(owner) : null;
  const verdict = gatewayTicketRule.checkTicket({
    candidate: msg && msg.ticket,
    // Ключ владельца берём ЗАКРЕПЛЁННЫЙ на этом релее, а не из жетона: жетон
    // подписал бы себе кто угодно, значение имеет только закрепление.
    ownerSignKey: bound && bound.signPk,
    presenter: { addr: ws.pubkey, signKey: ws.signPk },
    now: Date.now(),
    // Прямая проверка подписи, а НЕ verifySignature: та собрана под вызов
    // соединения и приклеивает к данным свой префикс (CHALLENGE_SIG_PREFIX).
    // Подсунь мы её сюда — подпись жетона не сошлась бы никогда, и связь через
    // соседа просто не работала бы, без единого объяснения.
    verify: (bytes, sig, publicKey) =>
      ed25519.verify(bytes, naclUtil.decodeBase64(sig), naclUtil.decodeBase64(publicKey)),
    used: (nonce) => gatewayTickets.used(nonce),
  });
  if (!verdict.ok) {
    console.warn('[gw] жетон отклонён:', verdict.reason);
    return send(ws, { type: 'gw-pull-result', ok: false });
  }
  // Запоминаем СРАЗУ, до выгрузки: иначе два одновременных предъявления одного
  // жетона оба прошли бы проверку и оба получили бы очередь.
  gatewayTickets.remember(verdict.ticket);
  return flushQueueToAgent(verdict.ticket.addr, ws);
}

/**
 * Выгрузка очереди ЧУЖОГО адреса предъявителю жетона.
 *
 * Отдельным видом кадра, а не обычным `message`, и это не косметика: свои
 * конверты предъявитель разбирает храповиком и сохраняет у себя, а эти он
 * обязан ТОЛЬКО ДОВЕЗТИ. Приди они обычным кадром — его клиент попытался бы их
 * открыть, не смог и записал бы себе в переписку разрыв цепочки.
 *
 * Конверты НЕ удаляются и не помечаются доставленными: квитанцию принимает
 * только доказанный владелец. Поэтому худшее, что сделает недобросовестный
 * сосед, — не довезёт, и очередь останется на месте.
 */
function flushQueueToAgent(owner, ws) {
  const ids = store.queueIdsFor(owner).slice(0, GW_PULL_MAX_ITEMS);
  let index = 0;
  async function pump() {
    if (ws.readyState !== ws.OPEN) return;
    while (index < ids.length) {
      if (typeof ws.bufferedAmount === 'number' && ws.bufferedAmount > FLUSH_HIGH_WATER) {
        setTimeout(start, FLUSH_RESUME_MS);
        return;
      }
      const item = await store.getItemAsync(ids[index]);
      index += 1;
      if (ws.readyState !== ws.OPEN) return;
      // Только сам конверт и его номер. Ни отправителя, ни сертификата
      // устройства, ни списка устройств: всё это — социальный граф владельца, и
      // соседу для доставки оно не нужно ни в каком виде.
      if (item) send(ws, { type: 'gw-mail', addr: owner, id: item.id, envelope: item.envelope });
    }
    if (ws.readyState === ws.OPEN) {
      send(ws, { type: 'gw-pull-result', ok: true, addr: owner, count: ids.length });
    }
  }
  function start() {
    pump().catch((error) =>
      console.warn('[gw] выгрузка по жетону прервана:', (error && error.message) || error)
    );
  }
  start();
  return ids.length;
}

function flushBinaryQueue(pubkey, ws) {
  const ids = store.binaryQueueIdsFor(pubkey);
  let index = 0;
  async function pump() {
    if (ws.readyState !== ws.OPEN) return;
    while (index < ids.length) {
      if (typeof ws.bufferedAmount === 'number' && ws.bufferedAmount > FLUSH_HIGH_WATER) {
        setTimeout(start, FLUSH_RESUME_MS);
        return;
      }
      const item = await store.getBinaryItemAsync(ids[index]);
      index += 1;
      if (ws.readyState !== ws.OPEN) return;
      if (item) sendBinary(ws, queuedBinaryHeader(item), item.payload);
    }
  }
  function start() {
    pump().catch((error) =>
      console.warn('[queue] выгрузка вложений прервана:', (error && error.message) || error)
    );
  }
  start();
  return ids.length;
}

/**
 * СРВ-11: значение поля `queued` в квитанции. КОНСТАНТА, а не состояние.
 *
 * ЧТО БЫЛО НЕ ТАК
 *
 * `deliver` возвращал `queued:false`, если кадр ушёл в живой сокет получателя, и
 * `queued:true`, если лёг в очередь. Это значение уезжало отправителю в ack.
 * То есть релей отвечал на вопрос, которого ему никто не задавал: «этот адрес
 * сейчас в сети?».
 *
 * Спросить мог кто угодно. Регистрация свободна — достаточно сгенерировать пару
 * ключей; адрес получателя есть у любого, кто когда-либо был в переписке или
 * получил визитку. Служебный (`silent`) конверт получателя не будит и в UI не
 * виден: пуш для него не отправляется, а конверт при онлайне просто уходит в
 * сокет и отбрасывается клиентом. Ограничение — только частота кадров (80/с).
 *
 * Из посекундных ответов складывается профиль присутствия: во сколько человек
 * встаёт и ложится, когда он в дороге (обрывы), в какие часы работает, был ли он
 * онлайн в конкретную минуту. Опросив два адреса, видно и корреляцию — «эти двое
 * в сети одновременно», то есть граф общения, ради сокрытия которого сделаны
 * sealed sender и запечатанные метаданные очереди. Ни Signal, ни WhatsApp такого
 * не отдают: presence у них не серверное понятие.
 *
 * КАК УСТРОЕНО ЗДЕСЬ
 *
 * Поле осталось на проводе (его читают старые клиенты), но перестало быть
 * состоянием: в любой квитанции стоит одно и то же значение. Различить онлайн и
 * офлайн по ответу больше нельзя — ответ одинаков.
 *
 * Значение выбрано `true` и это не подгонка: конверт кладётся в очередь ВСЕГДА,
 * до всякой проверки сокета, и лежит там до квитанции `received` от получателя.
 * Живая отправка — лишь ускорение поверх очереди, а не замена ей. Так что
 * «принят и ждёт получателя» верно для каждого принятого конверта; неверным был
 * как раз прежний `queued:false`, который обещал доставку, хотя копия оставалась
 * в очереди.
 *
 * Полезное поведение не теряется. Настоящая доставка подтверждается отдельным
 * кадром `delivered` — его релей шлёт, когда ПОЛУЧАТЕЛЬ прислал `received`, то
 * есть разобрал конверт. Это сквозная квитанция (её нельзя получить, не имея
 * рабочей сессии с адресом), а не наблюдение сервера за сокетами, и именно на
 * ней стоят галочки в переписке. Признак `dropped` (конверт не принят) тоже
 * остаётся — без него клиент вычеркнул бы сообщение из outbox и потерял его.
 *
 * ЧЕГО ЭТА МЕРА НЕ ДАЁТ
 *
 * Узкая щель остаётся у `dropped`: он поднимается, только когда очередь
 * получателя забита под потолок И у отправителя нет своих слотов, а при живом
 * сокете конверт в этой ситуации всё равно уходит напрямую. Значит для жертвы с
 * ПЕРЕПОЛНЕННОЙ очередью ответ снова различает состояния. Закрыть это в ack
 * нельзя: отказ принять конверт — то самое, что клиент обязан узнать, иначе
 * сообщение молча пропадёт. Лечится это на уровне квот (server/store.js), где
 * свежий отправитель не должен получать отказ вместо вытеснения; здесь мы
 * ограничиваемся тем, что не создаём БЕСПЛАТНОГО опроса — забить чужую очередь
 * до потолка стоит сотен конвертов с нескольких личностей и само по себе шумно.
 *
 * Счётчики `licno_messages_delivered_online_total` / `..._queued_offline_total`
 * различие сохраняют, но это агрегат по узлу без адресов, и /metrics закрыт от
 * публичного доступа (M-1) — оракула из них не собрать.
 */
const ACK_QUEUED = true;

function deliver(from, to, envelope, silent, callPush, metadata = {}) {
  const id = nextId();
  // Enqueue; the copy is removed only when the recipient acks (received).
  // СРВ-2: enqueue возвращает false, если очередь получателя полна и у отправителя
  // нет своих слотов (чужие сообщения не вытесняем).
  const stored = store.enqueue({
    id,
    to,
    from,
    fromAccount: metadata.fromAccount,
    fromDeviceId: metadata.fromDeviceId,
    deviceCertificate: metadata.deviceCertificate,
    deviceRoster: metadata.deviceRoster,
    envelope,
    envelopeJson: metadata.envelopeJson, // АУД-06: уже построен вызывающим
    silent,
    callPush,
    ts: Date.now(),
    maxPerUser: MAX_QUEUE_PER_USER,
    maxPerSender: MAX_QUEUE_PER_SENDER,
    maxTotal: MAX_TOTAL_MESSAGES,
    maxTotalBytes: MAX_QUEUE_BYTES,
    reserve: QUEUE_RESERVE_SLOTS,
    reciprocityTtlMs: QUEUE_TTL_MS,
  });

  const ws = online.get(to);
  // СРВ-5: доставку онлайн засчитываем ТОЛЬКО если кадр реально ушёл в ОТКРЫТЫЙ
  // сокет (send вернул true). Раньше ветка `if (ws)` слепо возвращала queued:false
  // (=доставлено), даже когда сокет уже CLOSING и send молча ничего не отправил, —
  // отправитель видел ложный ✓, а конверт при полной очереди (stored=false) нигде
  // не оставался. Теперь при закрытом сокете проваливаемся ниже (в push/queue/drop).
  const liveFrame = queuedMessageFrame({ id, from, envelope, ...metadata });
  // Если очередь переполнена, этот кадр не имеет дисковой страховки: отправляем
  // его сразу, а не откладываем на 10 мс в пакет, чтобы `queued:false` означал
  // реальную передачу в WebSocket. Для сохранённого кадра пакет безопасен — при
  // обрыве до flush он останется в очереди и придёт после reconnect.
  if (ws && sendMessageFrame(ws, liveFrame, metadata.envelopeBytes, { immediate: !stored })) {
    counters.deliveredOnline += 1;
    // СРВ-11: живая отправка состоялась, но отправителю об этом не сообщаем —
    // именно здесь раньше уезжал `queued:false`, по которому строился профиль
    // присутствия. Счётчик (агрегат по узлу, без адресов) состояние сохраняет.
    return { queued: ACK_QUEUED, id };
  }

  // СРВ-2/СРВ-5: конверт НЕ влез в очередь (полная + нет своих слотов) и не ушёл
  // живьём. Возвращаем dropped:true — отправитель не считает это доставкой и покажет
  // «не доставлено». Ack всё равно шлём (не зацикливать ретрай в полную очередь), но
  // со флагом — клиент помечает «не доставлено» и не выдаёт ложный ✓.
  if (!stored) {
    counters.dropped += 1;
    // СРВ-11: `queued` и здесь константа — различие несёт только `dropped`, без
    // которого клиент вычеркнул бы сообщение из outbox и молча его потерял.
    return { queued: ACK_QUEUED, dropped: true, id };
  }

  // recipient offline -> maybe wake them
  counters.queuedOffline += 1;
  const token = store.getToken(to);
  const onInvalid = (r) => {
    if (r === 'invalid') store.delToken(to);
  };

  if (callPush) {
    // СРВ-3: троттлим звонковые пуши на адрес (анти-флуд), как и обычные.
    if (token && Date.now() - (lastCallPushAt.get(to) || 0) >= CALL_PUSH_MIN_INTERVAL_MS) {
      lastCallPushAt.set(to, Date.now());
      counters.pushes += 1;
      sendCallPush(token, to).then(onInvalid);
    }
    return { queued: ACK_QUEUED, id };
  }
  if (silent) return { queued: ACK_QUEUED, id }; // control message: deliver, no push
  // ПРФ-4: троттлинг считается на пару «получатель + чат», а не на получателя
  // целиком. Раньше сообщения из РАЗНЫХ чатов в одном 20-секундном окне давали
  // один пуш — остальные чаты устройство не будили вовсе, и это читалось как
  // потерянные сообщения. Дубли одного сообщения (веер по релеям) по-прежнему
  // схлопываются: у них общий и получатель, и чат.
  const chatTag = chatNotificationTag(metadata.fromAccount || from);
  if (token && messagePushGate.allow(to, chatTag, Date.now())) {
    counters.pushes += 1;
    // ВЫС-51: адрес получателя — им выбирается VAPID-пара устройства. В само
    // уведомление он не попадает (см. sendPush).
    sendPush(token, metadata.notificationId || id, chatTag, to).then(onInvalid);
  }
  return { queued: ACK_QUEUED, id };
}

/**
 * ПРФ-14: приём конверта — ОДИН путь для JSON-кадра `send` и двоичного `send-v1`.
 *
 * Вынесено из обработчика кадра именно ради этого. Квоты очереди, потолок
 * конверта, счётчики, признак `dropped` и форма квитанции обязаны совпадать до
 * байта: разойдись они, двоичный путь стал бы обходом ограничений очереди
 * (отправитель без квоты) или новым оракулом присутствия (квитанция другой
 * формы). Проверяется тестом «квитанции обоих путей неразличимы».
 *
 * `envelopeJson` вызывающий может передать готовым (двоичный путь строит его
 * сам, чтобы не сериализовать заново) — как и раньше на JSON-пути (АУД-06).
 */
function acceptEnvelope(ws, { to, envelope, silent, callPush, ref, envelopeJson, noMeta }) {
  // СРВ-4: адрес получателя ограничен по длине (см. MAX_ADDR_LEN) — иначе
  // гигантский `to` при крошечном envelope обходил байтовый потолок очереди.
  if (to.length > MAX_ADDR_LEN) {
    return send(ws, { type: 'error', error: 'invalid recipient' });
  }
  // АУД-06: сериализуем конверт ОДИН раз — и для проверки размера, и для
  // хранения. Раньше он сериализовался здесь ради длины, строка тут же
  // выбрасывалась, а store.enqueue строил её заново: на конверте в семь
  // мегабайт это лишний полный проход по памяти в однопоточном процессе, то
  // есть пауза для всех пользователей узла.
  let json = envelopeJson;
  if (json === undefined) {
    try {
      json = JSON.stringify(envelope);
    } catch (e) {
      return send(ws, { type: 'error', error: 'invalid envelope' });
    }
  }
  const size = Buffer.byteLength(json);
  if (size > MAX_ENVELOPE_BYTES) {
    return send(ws, { type: 'error', error: 'envelope too large' });
  }
  counters.msgsIn += 1;
  const r = deliver(ws.pubkey, to, envelope, silent, callPush, {
    // ВЫС-41: отправитель просит НЕ подставлять его метаданные снаружи —
    // значит получатель читает их изнутри запечатанного конверта, и внешняя
    // копия была бы ровно тем, что запечатывание и убирает: адрес аккаунта и
    // весь список устройств открытым текстом в очереди на диске.
    ...(noMeta ? {} : senderMetadata(ws)),
    notificationId: typeof ref === 'string' ? ref.slice(0, 160) : undefined,
    envelopeJson: json,
    envelopeBytes: size,
  });
  // СРВ-2: dropped — конверт не принят (полная очередь); клиент покажет «не
  // доставлено» вместо ложного «отправлено». Старый клиент поле игнорирует.
  // СРВ-11: `queued` больше не состояние получателя, а константа (см. ACK_QUEUED).
  // Отличить «в сети» от «не в сети» по квитанции нельзя ни здесь, ни в binary-ack.
  return send(ws, { type: 'ack', ref, id: r.id, queued: r.queued, dropped: !!r.dropped });
}

function deliverBinary(from, header, payload, metadata = {}) {
  const id = nextId();
  const stored = store.enqueueBinary({
    id,
    to: header.to,
    from,
    ref: header.ref,
    transferId: header.transferId,
    index: header.index,
    total: header.total,
    metadata,
    payload,
    ts: Date.now(),
    maxPerUser: MAX_QUEUE_PER_USER,
    maxPerSender: MAX_QUEUE_PER_SENDER,
    maxTotal: MAX_TOTAL_MESSAGES,
    maxTotalBytes: MAX_QUEUE_BYTES,
    reserve: QUEUE_RESERVE_SLOTS,
    reciprocityTtlMs: QUEUE_TTL_MS,
  });
  const recipient = online.get(header.to);
  if (recipient && sendBinary(recipient, queuedBinaryHeader({
    id,
    from,
    transferId: header.transferId,
    index: header.index,
    total: header.total,
    metadata,
  }), payload)) {
    counters.deliveredOnline += 1;
    // СРВ-11: тот же оракул присутствия жил и на бинарном пути. Кадр
    // `attachment-chunk` отправляется так же свободно, как обычный конверт, — и
    // `binary-ack` отвечал онлайн/офлайн ровно тем же способом. Константа здесь
    // обязана совпадать с обычной квитанцией, иначе опрос просто переехал бы на
    // вложения.
    return { id, queued: ACK_QUEUED, dropped: false };
  }
  if (!stored) {
    counters.dropped += 1;
    return { id, queued: ACK_QUEUED, dropped: true };
  }
  counters.queuedOffline += 1;
  return { id, queued: ACK_QUEUED, dropped: false };
}

// Recipient confirmed receipt of `id`: drop it from their queue and tell the
// original sender (if online) that it was delivered.
function ackReceived(recipientPubkey, id) {
  // ГРФ-1: адрес отправителя достаётся из зашифрованных метаданных строки очереди
  // (в базе открытым текстом его больше нет). null — конверта нет, он не этого
  // получателя, либо метаданные не открылись (потерян файл ключа): тогда квитанцию
  // «доставлено» отправить некому, но сам конверт из очереди уходит как обычно.
  const from = store.ack(recipientPubkey, id);
  if (from) {
    counters.acked += 1;
    const senderWs = online.get(from);
    if (senderWs) send(senderWs, { type: 'delivered', id });
  }
}

function ackBinaryReceived(recipientPubkey, id) {
  const accepted = store.ackBinary(recipientPubkey, id);
  if (!accepted) return;
  counters.acked += 1;
  const sender = online.get(accepted.from);
  if (sender) {
    send(sender, {
      type: 'binary-delivered',
      id,
      ref: accepted.ref,
      transferId: accepted.transferId,
      index: accepted.index,
    });
  }
}

function rateLimited(ws) {
  const now = Date.now();
  if (now - ws.rateStart > RATE_WINDOW_MS) {
    ws.rateStart = now;
    ws.rateCount = 0;
  }
  ws.rateCount += 1;
  return ws.rateCount > RATE_MAX_FRAMES;
}

/**
 * КРИТ-04: потолок на ДОРОГИЕ кадры — минутное окно на соединение.
 *
 * Считается отдельно для каждого вида: у них разная цена и разная нормальная
 * частота, и общий счётчик означал бы, что поиск в ящике съедает право
 * переписать список устройств. Возвращает true, когда пора отказать.
 *
 * Счётчик увеличивается ДО решения — то есть превышение продолжает считаться, и
 * молотящий в лимит соединение не «сбрасывает» его редкими паузами.
 */
function costlyLimited(ws, kind, max, now = Date.now()) {
  if (!ws.costly) ws.costly = new Map();
  const state = ws.costly.get(kind);
  let over;
  if (!state || now - state.start > COSTLY_WINDOW_MS) {
    ws.costly.set(kind, { start: now, count: 1 });
    over = 1 > max;
  } else {
    state.count += 1;
    over = state.count > max;
  }
  if (over) counters.costlyRefused += 1;
  return over;
}

/**
 * БЕЗ-5: учёт входящего потока. Возвращает true, если соединение пора рвать
 * (длительное превышение = абуз). При обычном превышении не рвёт и не отказывает,
 * а перестаёт читать сокет до конца окна: TCP-окно закрывается, отправитель
 * притормаживает сам, уже принятый кадр обрабатывается как обычно.
 */
function byteLimited(ws, bytes) {
  const gate = byteGate(ws.byteState, Date.now(), bytes, RATE_WINDOW_MS, RATE_MAX_BYTES, RATE_ABUSE_WINDOWS);
  ws.byteState = gate.state;
  if (gate.abusive) {
    counters.abusive += 1;
    return true;
  }
  if (gate.pauseMs > 0 && !ws.throttledUntil) {
    counters.throttled += 1;
    ws.throttledUntil = Date.now() + gate.pauseMs;
    try {
      ws.pause();
    } catch (e) {
      // Приторможенный сокет мог уже закрыться. Придержать нечего — счётчики
      // лимита всё равно выставлены, и следующий кадр от него не пройдёт.
    }
    const timer = setTimeout(() => {
      ws.throttledUntil = 0;
      try {
        ws.resume();
      } catch (e) {
        // Сокет закрылся, пока стоял на паузе: возобновлять нечего.
      }
    }, gate.pauseMs);
    // Придержанный сокет не должен удерживать процесс от штатного завершения.
    if (typeof timer.unref === 'function') timer.unref();
  }
  return false;
}

function closeRevokedDevice(devicePk, accountPk) {
  store.purgeDeviceTransport(devicePk);
  const target = online.get(devicePk);
  if (!target) return;
  if (target.accountPubkey === accountPk) {
    send(target, { type: 'device-revoked', accountPublicKey: accountPk });
    try {
      target.close(4003, 'device revoked');
    } catch (e) {
      try {
        target.terminate();
      } catch (e2) {
        // Отозванному устройству закрыли соединение обоими способами. Если и
        // terminate() не сработал, сокета уже нет — цель достигнута.
      }
    }
  }
}

/**
 * Состояние соединения в том виде, в каком его читает правило прав на ростер.
 * Собирается по ЗАЯВЛЕННОМУ адресу аккаунта: до проверки подписей другого у нас
 * нет, а само правило заявленному ничего не доверяет — см. rosterWriteGate.
 */
function rosterSession(ws, accountPublicKey) {
  const known =
    typeof accountPublicKey === 'string' && accountPublicKey ? store.getAccount(accountPublicKey) : null;
  return {
    proven: !!ws.proven,
    sessionPublicKey: ws.pubkey,
    knownAccountSignPublicKey: known ? known.accountSignPublicKey : null,
    boundRootSignPublicKey:
      typeof accountPublicKey === 'string' && accountPublicKey ? store.getSignKey(accountPublicKey) : null,
  };
}

function acceptSignedRoster(ws, candidate) {
  // КРИТ-04: права — ДО криптографии. Кадр может нести до тридцати двух
  // сертификатов, и каждый стоит проверки подписи; выяснять после них, что
  // прислал их посторонний, значит позволять постороннему назначать узлу работу.
  // Заявленным полям здесь не доверяется ничего: то же правило применяется ниже
  // к разобранному объекту, и решает именно оно.
  const claimed = candidate && typeof candidate === 'object' ? candidate : {};
  const early = rosterWriteGate(claimed, rosterSession(ws, claimed.accountPublicKey));
  if (!early.ok) {
    counters.rosterDeniedEarly += 1;
    return { ok: false, reason: early.reason };
  }

  let roster;
  try {
    roster = assertSignedRoster(candidate);
  } catch (error) {
    return { ok: false, reason: 'invalid-roster' };
  }
  // Второй, авторитетный вызов — уже по проверенным полям. Он остаётся тем
  // единственным местом, которое решает: подпись разобрана, значит и адрес
  // аккаунта с корневым ключом теперь настоящие, а не заявленные.
  const allowed = rosterWriteGate(roster, rosterSession(ws, roster.accountPublicKey));
  if (!allowed.ok) return { ok: false, reason: allowed.reason };
  const result = store.putAccountRoster(roster);
  if (!result.ok) return result;
  for (const devicePk of result.revokedDeviceKeys || []) closeRevokedDevice(devicePk, roster.accountPublicKey);
  return { ...result, roster };
}

function bindSocketToCertifiedDevice(ws, candidate) {
  if (!ws.proven) return { ok: false, reason: 'box-ownership-proof-required' };
  let certificate;
  try {
    certificate = assertDeviceCertificate(candidate);
  } catch (error) {
    return { ok: false, reason: 'invalid-device-certificate' };
  }
  if (
    certificate.devicePublicKey !== ws.pubkey ||
    certificate.deviceSignPublicKey !== store.getSignKey(ws.pubkey)
  ) {
    return { ok: false, reason: 'certificate-does-not-match-session' };
  }
  const account = store.getAccount(certificate.accountPublicKey);
  if (!account || account.accountSignPublicKey !== certificate.accountSignPublicKey) {
    return { ok: false, reason: 'unknown-account' };
  }
  const record = store.getAccountDevice(certificate.accountPublicKey, certificate.deviceId);
  if (!record) return { ok: false, reason: 'device-unknown' };
  if (record.revokedAt != null) return { ok: false, reason: 'device-revoked' };
  if (
    record.devicePublicKey !== certificate.devicePublicKey ||
    record.deviceSignPublicKey !== certificate.deviceSignPublicKey ||
    stableStringify(record.certificate) !== stableStringify(certificate)
  ) {
    return { ok: false, reason: 'certificate-not-in-roster' };
  }
  indexAccountSocket(ws, record);
  return { ok: true, record, roster: store.getAccountRoster(certificate.accountPublicKey) };
}

function enforceAuthTimeout(ws) {
  if (ws.authed) return false;
  send(ws, { type: 'error', error: 'auth timeout' });
  ws.terminate();
  return true;
}

function handleSocketMessage(ws, raw, isBinary, options = {}) {
  const handleBinary = options.handleBinary || handleBinaryFrameSafely;
  const handleJson = options.handleJson || handleFrameSafely;
  const topLevel = options.topLevel || handleTopLevelError;
  const logger = options.logger || console;
  if (rateLimited(ws)) {
    send(ws, { type: 'error', error: 'rate limit' });
    ws.terminate();
    return;
  }
  // БЕЗ-5: байтовый потолок. Кадр всё равно обрабатываем (иначе легитимный
  // отправитель потеряет чанк вложения) — притормаживание делает byteLimited.
  if (byteLimited(ws, raw.length || 0)) {
    send(ws, { type: 'error', error: 'byte rate limit' });
    ws.terminate();
    return;
  }

  if (isBinary) {
    try {
      handleBinary(ws, raw);
    } catch (error) {
      if (isFatalDbError(error)) {
        topLevel('binary-frame-fatal-db', error);
        return;
      }
      send(ws, { type: 'binary-error', error: 'invalid binary frame' });
    }
    return;
  }

  // АУД-06: отвергаем заведомо негодный кадр ДО toString и JSON.parse. Оба
  // прохода идут по всему буферу и на 33 мегабайтах занимают однопоточный узел
  // целиком — при том что кадр такого размера всё равно будет отвергнут ниже.
  const frameLimit = ws.authed ? MAX_JSON_FRAME_BYTES : MAX_PREAUTH_FRAME_BYTES;
  if (raw.length > frameLimit) {
    counters.oversized += 1;
    send(ws, { type: 'error', error: 'frame too large' });
    // До аутентификации это заведомо не наш клиент: рвём, а не переписываемся.
    if (!ws.authed) return ws.terminate();
    return;
  }

  let msg;
  try {
    msg = JSON.parse(raw.toString());
  } catch (e) {
    return send(ws, { type: 'error', error: 'bad json' });
  }
  try {
    handleJson(ws, msg);
  } catch (e) {
    // СРВ-5: фатальный сбой БД (SQLITE_CORRUPT/FULL/IOERR/READONLY) НЕ глушим здесь.
    // Раньше почти все обращения к БД шли внутри handleFrameSafely, и этот catch
    // отвечал `server error`, из-за чего механизм L4 (честный выход под рестарт
    // systemd) не срабатывал: узел «работал», ничего не доставляя и не удаляя.
    // Пробрасываем такие ошибки в top-level обработчик для управляемого выхода.
    if (isFatalDbError(e)) {
      topLevel('frame-fatal-db', e);
      return;
    }
    logger.error('[frame]', e && e.stack ? e.stack : e);
    try {
      send(ws, { type: 'error', error: 'server error' });
    } catch (e2) {
      // Сама ошибка уже ушла в лог строкой выше; ответ клиенту — вежливость,
      // а его сокет к этому моменту вполне мог оборваться.
    }
  }
}

wss.on('connection', (ws, req) => {
  // H4: per-IP лимит одновременных соединений (защита от коннект-флуда).
  const ip = clientIp(req);
  const nConn = (ipConns.get(ip) || 0) + 1;
  if (nConn > MAX_CONN_PER_IP) {
    try {
      send(ws, { type: 'error', error: 'too many connections' });
    } catch (e) {
      // Соединение всё равно закрывается следующей строкой: причина отказа —
      // любезность, а не часть протокола.
    }
    return ws.terminate();
  }
  ipConns.set(ip, nConn);
  ws.ip = ip;

  ws.isAlive = true;
  ws.authed = false;
  ws.pubkey = null;
  ws.pendingPubkey = null;
  ws.pendingSpk = null;
  ws.nonce = null;
  ws.ephSec = null;
  ws.accountPubkey = null;
  ws.deviceId = null;
  ws.deviceCertificate = null;
  ws.frameBatchV1 = false;
  // ПРФ-14: пока получатель не объявил обратного, он получает конверты JSON-ом.
  // Умолчание «не умеет» — единственная сторона ошибки, при которой обновление
  // релея не ломает уже установленные приложения.
  ws.binaryEnvelopeV1 = false;
  ws.frameBatchQueue = [];
  ws.frameBatchBytes = 0;
  ws.frameBatchTimer = null;
  ws.rateStart = Date.now();
  ws.rateCount = 0;
  ws.byteState = null; // БЕЗ-5
  ws.throttledUntil = 0;
  ws.on('pong', () => (ws.isAlive = true));
  // СРВ-4: без слушателя 'error' ошибка сокета (ECONNRESET при обрыве, превышение
  // maxPayload) бросается из EventEmitter → uncaughtException. Глобальный backstop
  // ловил, но стек раскручивался из произвольной точки (риск неконсистентности), а
  // это штатная, частая ситуация (любой RST от клиента). Гасим на месте.
  ws.on('error', () => {
    try {
      ws.terminate();
    } catch (e) {
      // Сюда приходят обрывы вроде ECONNRESET — сокета зачастую уже нет, и
      // terminate() бросает по той же причине, по которой мы его зовём.
    }
  });

  // Drop connections that never authenticate.
  ws.authTimer = setTimeout(() => enforceAuthTimeout(ws), AUTH_TIMEOUT_MS);

  ws.on('message', (raw, isBinary) => handleSocketMessage(ws, raw, isBinary));

  ws.on('close', () => {
    clearTimeout(ws.frameBatchTimer);
    ws.frameBatchQueue = [];
    clearTimeout(ws.authTimer);
    if (ws.ip) {
      const c = (ipConns.get(ws.ip) || 1) - 1;
      if (c <= 0) ipConns.delete(ws.ip);
      else ipConns.set(ws.ip, c);
    }
    unindexAccountSocket(ws);
    if (ws.pubkey && online.get(ws.pubkey) === ws) online.delete(ws.pubkey);
  });
});

// Обработка одного разобранного кадра. Вынесено в отдельную функцию, чтобы
// вызывающий мог обернуть её в try/catch (C-1: одна ошибка не роняет процесс).
function handleBinaryFrameSafely(ws, raw) {
  if (!ws.authed) return send(ws, { type: 'binary-error', error: 'not authenticated' });
  const { header, payload } = unpackBinaryFrame(raw);
  // СРЕД-03: кадр-пустышка. Уходит в мусор ЗДЕСЬ и целиком: тело не читается, в
  // очередь ничего не встаёт, `msgsIn` не растёт, пуш не уходит, ОТВЕТА НЕТ.
  //
  // Молчание — обязательное условие, а не экономия. Ответь узел хоть чем-нибудь
  // (`ack`, `binary-error`, что угодно), и в канале появился бы второй кадр,
  // жёстко привязанный к первому: наблюдатель отличал бы пустышку от сообщения
  // по одному только наличию пары, и вся мера свелась бы к самопометке.
  //
  // Проверка стоит первой: после сообщений это самый частый двоичный кадр, и
  // платить за него разбором остальных веток незачем. Учёт при этом остаётся
  // общим — пустышка проходит через потолок кадров и байтовый потолок соединения
  // наравне со всеми (handleSocketMessage), то есть полосу узла она занимает
  // честно и злоупотребить ею не проще, чем любым другим кадром.
  if (header.type === 'cover-v1' && header.version === 1) {
    counters.cover += 1;
    return true;
  }
  if (header.type === 'frame-batch-v1' && header.version === 1) {
    if (!ws.frameBatchV1 || payload.length > 256 * 1024) {
      return send(ws, { type: 'binary-error', error: 'frame batch not negotiated' });
    }
    const frames = decodeMessagePack(payload);
    if (
      !Array.isArray(frames) ||
      frames.length < 1 ||
      frames.length > 64 ||
      frames.length !== header.count
    ) {
      return send(ws, { type: 'binary-error', error: 'invalid frame batch' });
    }
    for (const frame of frames) {
      if (!frame || typeof frame !== 'object' || Array.isArray(frame)) {
        return send(ws, { type: 'binary-error', error: 'invalid frame in batch' });
      }
      if (rateLimited(ws)) {
        send(ws, { type: 'error', error: 'rate limit' });
        return ws.terminate();
      }
      handleFrameSafely(ws, frame);
    }
    return true;
  }
  // ПРФ-14: обычное сообщение двоичным кадром. Тело — сырые байты запечатанного
  // конверта, base64 вокруг них больше нет.
  if (header.type === envelopeFrame.SEND_FRAME_TYPE && header.version === 1) {
    if (
      typeof header.to !== 'string' ||
      !header.to ||
      header.to.length > MAX_ADDR_LEN ||
      (header.ref != null && (typeof header.ref !== 'string' || header.ref.length > 160)) ||
      !payload.length ||
      payload.length > MAX_SEALED_PAYLOAD_BYTES
    ) {
      return send(ws, { type: 'error', error: 'invalid envelope frame' });
    }
    // Конверт собирается ЗДЕСЬ, а не в очереди: store хранит его JSON-ом, как и
    // прежде. То есть двоичным стал провод, а не хранилище — и получатель со
    // старым клиентом достаёт из очереди ровно тот конверт, что раньше.
    const envelope = envelopeFrame.sealedEnvelope(header.sv, payload);
    if (!envelope) return send(ws, { type: 'error', error: 'invalid envelope frame' });
    // СРЕД-01: флаги читаются ОБЩИМ правилом, а не сравнением на месте. По
    // проводу ходят обе записи сразу — цифра от нынешнего клиента (её длина не
    // зависит от значения) и булево от клиента прежней версии, — и обе обязаны
    // читаться одинаково. Сравни релей с `true` — тихая копия веера стала бы
    // «громкой», и одно сообщение будило бы человека с каждого релея.
    const flags = envelopeFrame.sendHeaderFlags(header);
    return acceptEnvelope(ws, {
      to: header.to,
      envelope,
      envelopeJson: JSON.stringify(envelope),
      silent: flags.silent,
      callPush: flags.callPush,
      noMeta: flags.noMeta,
      ref: header.ref == null ? undefined : header.ref,
    });
  }
  if (
    header.type !== 'attachment-chunk' ||
    header.version !== 1 ||
    typeof header.to !== 'string' ||
    !header.to ||
    header.to.length > MAX_ADDR_LEN ||
    typeof header.transferId !== 'string' ||
    !/^[A-Za-z0-9_-]{12,64}$/.test(header.transferId) ||
    !Number.isInteger(header.index) ||
    !Number.isInteger(header.total) ||
    header.total < 1 ||
    header.total > MAX_BINARY_CHUNKS ||
    header.index < 0 ||
    header.index >= header.total ||
    payload.length < 40 ||
    payload.length > MAX_BINARY_CHUNK_BYTES ||
    (header.ref != null && (typeof header.ref !== 'string' || header.ref.length > 160))
  ) {
    return send(ws, { type: 'binary-error', ref: header.ref, error: 'invalid attachment chunk' });
  }
  counters.msgsIn += 1;
  const result = deliverBinary(ws.pubkey, header, payload, senderMetadata(ws));
  return send(ws, {
    type: 'binary-ack',
    ref: header.ref,
    id: result.id,
    transferId: header.transferId,
    index: header.index,
    queued: result.queued,
    dropped: result.dropped,
  });
}

function sendPushTestResult(ws, token, testId, channel, provider = sendTestPush, tokenStore = store) {
  // ВЫС-51: проверочный пуш подписывается ТОЙ ЖЕ парой, что и обычный, — иначе
  // диагностика в Профиле проверяла бы не тот путь, которым ходят уведомления.
  return provider(token, testId, channel, ws.pubkey)
    .then((result) => {
      if (result === 'invalid') tokenStore.delToken(ws.pubkey);
      send(ws, {
        type: 'push-test-result',
        testId,
        channel,
        accepted: result === true,
        error: result === 'invalid' ? 'invalid-subscription' : result === true ? undefined : 'provider-unavailable',
      });
    })
    .catch(() => {
      send(ws, { type: 'push-test-result', testId, channel, accepted: false, error: 'provider-error' });
    });
}

function handleFrameSafely(ws, msg) {
    // C-1: JSON.parse принимает не только объекты — "null", "true", "1", "[...]"
    // это валидный JSON. Обращение msg.type к такому значению роняло обработчик
    // (напр. null.type -> TypeError), а глобального перехватчика нет — падал ВЕСЬ
    // процесс от одного кадра неаутентифицированного клиента. Требуем объект.
    if (!msg || typeof msg !== 'object' || Array.isArray(msg)) {
      return send(ws, { type: 'error', error: 'bad frame' });
    }

    // --- handshake: hello -> challenge -> auth ---
    if (msg.type === 'hello') {
      // СРВ-6: hello после успешной аутентификации не принимаем. Раньше клиент,
      // авторизованный как A, мог повторным hello+auth встать как B: online.set(B)
      // добавлялся, а мёртвая запись A→ws оставалась навсегда (close снимает только
      // текущий ws.pubkey) — утечка + доставка для A уходила в закрытый сокет.
      if (ws.authed) {
        return send(ws, { type: 'error', error: 'already authenticated' });
      }
      // СРВ-9: каждый hello генерирует randomBytes + эфемерную box-пару (дорого по
      // CPU) ещё до аутентификации. Ограничиваем число hello на соединение, чтобы
      // один неаутентифицированный сокет не грузил узел генерацией ключей.
      ws.helloCount = (ws.helloCount || 0) + 1;
      if (ws.helloCount > 20) {
        send(ws, { type: 'error', error: 'too many hellos' });
        return ws.terminate();
      }
      if (typeof msg.pubkey !== 'string' || !msg.pubkey) {
        return send(ws, { type: 'error', error: 'hello requires pubkey' });
      }
      if (typeof msg.signPublicKey !== 'string' || !msg.signPublicKey) {
        return send(ws, { type: 'error', error: 'hello requires signPublicKey' });
      }
      // СРВ-7: длина адресов ограничена (валидный X25519/Ed25519 base64 ≈ 44 симв.).
      // Раньше box-`pubkey` на легаси-пути НИКОГДА не декодировался и попадал как есть
      // в БД/online/prekeys — мусорная строка в десятки МБ проходила auth (TOFU) и
      // забивала диск (лимит MAX_IDENTITIES считает штуки, не байты). MAX_ADDR_LEN
      // применялся только к полю `to` в send — теперь и к hello.
      if (msg.pubkey.length > MAX_ADDR_LEN || msg.signPublicKey.length > MAX_ADDR_LEN) {
        return send(ws, { type: 'error', error: 'invalid key' });
      }
      ws.frameBatchV1 =
        Array.isArray(msg.capabilities) && msg.capabilities.includes('frame-batch-v1');
      // ПРФ-14: получатель сам говорит, разберёт ли он двоичный кадр `message-v1`.
      // Спросить об этом больше некого: конверт ходит от узла к узлу, отправитель
      // о клиенте получателя ничего не знает и знать не должен.
      ws.binaryEnvelopeV1 =
        Array.isArray(msg.capabilities) &&
        msg.capabilities.includes(envelopeFrame.BINARY_ENVELOPE_CAPABILITY);
      ws.pendingPubkey = msg.pubkey;
      ws.pendingSpk = msg.signPublicKey;
      ws.nonce = naclUtil.encodeBase64(crypto.randomBytes(32));
      // H5/H6: эфемерная X25519-пара для доказательства владения box-ключом.
      // Публичную половинку кладём в challenge; секретку держим до auth.
      const eph = nacl.box.keyPair();
      ws.ephSec = naclUtil.encodeBase64(eph.secretKey);
      const reply = { type: 'challenge', nonce: ws.nonce, eph: naclUtil.encodeBase64(eph.publicKey) };
      // S6: если клиент прислал cnonce — подписываем его ключом релея (клиент
      // сверит с закреплённым ключом). Старый клиент без cnonce — просто без подписи.
      // СРВ-8: cnonce ограничен по длине (валидный nonce ≈ 44 симв.) — иначе релей
      // подписывал бы строку до ~33 МБ, а при флуде соединений это CPU-DoS без auth.
      if (typeof msg.cnonce === 'string' && msg.cnonce && msg.cnonce.length <= MAX_ADDR_LEN) {
        reply.relayPub = RELAY_KEYS.pub;
        reply.relaySig = signRelayAuth(msg.cnonce);
      }
      return send(ws, reply);
    }

    if (msg.type === 'auth') {
      if (!ws.pendingPubkey || !ws.nonce) {
        return send(ws, { type: 'error', error: 'say hello first' });
      }
      if (typeof msg.signature !== 'string') {
        return send(ws, { type: 'error', error: 'auth requires signature' });
      }
      // Шаг 1 (всегда, первым): подпись challenge доказывает владение ЗАЯВЛЕННЫМ
      // Ed25519-ключом. Проверяем против предъявленного spk — если не сходится,
      // это 'bad signature' независимо от состояния привязки.
      if (!verifySignature(ws.nonce, msg.signature, ws.pendingSpk)) {
        return send(ws, { type: 'error', error: 'bad signature' });
      }
      // Шаг 2 (H5/H6): доказательство владения BOX-ключом адреса. Новые клиенты
      // всегда присылают boxProof; старые — нет (легаси-путь, ниже).
      const boxProven =
        typeof msg.boxProof === 'string' &&
        ws.ephSec &&
        verifyBoxProof(ws.nonce, msg.boxProof, ws.pendingPubkey, ws.ephSec);

      const bound = store.getIdentity(ws.pendingPubkey); // { signPk, proven } | null
      if (bound && bound.proven) {
        // Адрес доказанно принадлежит владельцу box-ключа: подтвердить/сменить
        // связку можно ТОЛЬКО снова доказав владение box-ключом. Это закрывает
        // и oracle подписи (H5: перехваченной подписи мало), и захват (H6).
        if (!boxProven) {
          return send(ws, { type: 'error', error: 'box ownership proof required' });
        }
        if (bound.signPk !== ws.pendingSpk) store.rebindSignKey(ws.pendingPubkey, ws.pendingSpk, Date.now());
      } else if (bound && !bound.proven) {
        if (boxProven) {
          // Владелец box-ключа перебивает прежнюю (возможно сквоттерскую) связку
          // и закрепляет её как доказанную — сквоттер потом уже не отберёт.
          store.rebindSignKey(ws.pendingPubkey, ws.pendingSpk, Date.now());
        } else if (bound.signPk !== ws.pendingSpk) {
          // Легаси-путь (TOFU): сменить незакреплённый sign-ключ нельзя.
          return send(ws, { type: 'error', error: 'pubkey bound to a different key' });
        }
      } else {
        // Первая регистрация: закрепляем; proven только при доказанном владении.
        store.bindSignKey(ws.pendingPubkey, ws.pendingSpk, boxProven, Date.now());
      }
      // authenticated: take ownership of this pubkey
      counters.authOk += 1;
      ws.authed = true;
      ws.pubkey = ws.pendingPubkey;
      // H-2 (squatting): доказал ли ЭТОТ сеанс владение box-секреткой адреса.
      // Квитанции о приёме (`received` → удаление из очереди + `delivered`
      // отправителю) принимаем ТОЛЬКО от доказанного держателя — иначе тот, кто
      // «сквоттил» ещё не занятый адрес, мог вычерпать очередь жертвы и подделать
      // «доставлено». Актуальные клиенты всегда шлют boxProof, так что штатный
      // путь не меняется; страдает лишь недоказанный сеанс (сквоттер/старый клиент).
      ws.proven = !!boxProven;
      // ЭТП5-4: ключ подписи, которым этот сеанс себя доказал. Нужен жетону
      // доступа: он выдаётся конкретному соседу — и по адресу, и по ключу
      // подписи, — а сверить второе без этого поля было бы нечем.
      ws.signPk = ws.pendingSpk;
      ws.nonce = null;
      ws.ephSec = null;
      clearTimeout(ws.authTimer);

      // АУД-Э1: недоказанный сеанс НЕ получает входящий поток.
      //
      // Раньше флаг `proven` защищал только квитанции: сквоттер не мог стереть
      // очередь жертвы. Но соединение всё равно индексировалось в `online`, и
      // очередь ему выгружалась — то есть занявший ещё не закреплённый адрес
      // читал в реальном времени и шифртекст, и метаданные КАЖДОГО отправителя:
      // его адрес, идентификатор устройства, имя устройства из сертификата и
      // весь список устройств. Это тот самый социальный граф, который весь
      // остальной код прячет.
      //
      // Занять чужой адрес несложно: он публичен (это QR контакта), а
      // закрепление живёт на КАЖДОМ релее отдельно — достаточно найти узел, где
      // жертва ещё не аутентифицировалась. Вытеснение холодных identity
      // (evictColdIdentities ниже) возвращает адрес в незакреплённое состояние и
      // открывает окно заново.
      //
      // Теперь без доказательства владения box-ключом соединение авторизовано
      // ровно настолько, чтобы ОТПРАВЛЯТЬ. Приём требует доказательства.
      // Клиент узнаёт об этом явным полем, а не молчаливой тишиной в чатах.
      if (!ws.proven) {
        counters.unprovenReceive = (counters.unprovenReceive || 0) + 1;
        return send(ws, {
          type: 'ready',
          queued: 0,
          prekeys: 0,
          vapidPublicKey: vapidPublicKeyFor(ws.pubkey),
          protocol: RELAY_PROTOCOL,
          capabilities: RELAY_CAPABILITIES,
          maxLinkedDevices: MAX_ACTIVE_DEVICES,
          overloaded: relayOverloaded(),
          // Приём выключен, пока не доказано владение адресом. Старый клиент
          // поле игнорирует — он просто не увидит входящих, как не увидел бы их
          // и раньше, если бы адрес занял сквоттер.
          receiveBlocked: 'box-proof-required',
        });
      }

      // If a stale socket still claims this pubkey, replace it.
      const prev = online.get(ws.pubkey);
      if (prev && prev !== ws) {
        try {
          prev.terminate();
        } catch (e) {
          // Устаревший сокет этого адреса вытесняется из каталога строкой ниже
          // независимо от исхода: обычно он уже мёртв, оттого и вытесняется.
        }
      }
      online.set(ws.pubkey, ws);
      // M-02: отмечаем активность identity и держим каталог под глобальным потолком
      // (вытеснение самых холодных identity без ожидающих конвертов). Текущий pk
      // только что «тёплый», поэтому под вытеснение не попадает.
      store.touchIdentity(ws.pubkey, Date.now());
      const evicted = store.evictColdIdentities(MAX_IDENTITIES);
      if (evicted) console.log(`[identities] evicted ${evicted} cold identity(ies) over cap`);
      const flushedBinary = store.binaryQueueIdsFor(ws.pubkey).length;
      const flushed = flushQueue(ws.pubkey, ws, () => flushBinaryQueue(ws.pubkey, ws));
      // prekeys: сколько одноразовых prekey клиента осталось у этого релея —
      // клиент по этому числу решает, пора ли выгрузить свежую пачку.
      // vapidPublicKey: web-push (UnifiedPush) публичный ключ ЭТОГО УСТРОЙСТВА —
      // клиент передаёт его в expo-unified-push registerDevice()/subscribe().
      // ВЫС-51: ключ выводится из адреса соединения, поэтому у каждого
      // устройства он свой и push-провайдеру нечем склеить подписки «Лично» в
      // одну группу. Узнать чужой ключ кадром ready нельзя: адрес берётся из
      // аутентифицированного соединения. null — web-push не настроен.
      // АУД-06: `overloaded` — честный ответ узла на вопрос «тебе сейчас тяжело?».
      // Раньше сказать это было нечем: клиент держит пул релеев и умеет
      // переключаться, но признака, по которому стоит предпочесть соседа, у него
      // не было — перегруженный узел выглядел точно так же, как свободный, и
      // получал ровно столько же нагрузки. Старый клиент поле игнорирует.
      if (relayOverloaded()) counters.overloaded += 1;
      return send(ws, {
        type: 'ready',
        queued: flushed + flushedBinary,
        prekeys: store.countOtps(ws.pubkey),
        vapidPublicKey: vapidPublicKeyFor(ws.pubkey),
        protocol: RELAY_PROTOCOL,
        capabilities: RELAY_CAPABILITIES,
        maxLinkedDevices: MAX_ACTIVE_DEVICES,
        overloaded: relayOverloaded(),
      });
    }

    // --- relay directory (public READ allowed before auth for bootstrap) ---
    if (msg.type === 'relays') {
      return send(ws, { type: 'relays', relays: relayDir });
    }

    // App-level liveness: клиент шлёт ping, чтобы отличить живое соединение от
    // «тихо зависшего» при смене сети (WS-фреймы ping ему не видны из JS).
    if (msg.type === 'ping') {
      if (ws.deviceId) store.touchDevice(ws.pubkey, Date.now());
      // АУД-06: перегрузка приходит и уходит уже после подключения, поэтому
      // признак едет и в ответе на heartbeat — иначе клиент узнавал бы о ней
      // только при следующем реконнекте, то есть почти никогда.
      const busy = relayOverloaded();
      if (busy) counters.overloaded += 1;
      return send(ws, busy ? { type: 'pong', overloaded: true } : { type: 'pong' });
    }

    // --- everything past here requires authentication ---
    if (!ws.authed) return send(ws, { type: 'error', error: 'not authenticated' });

    if (msg.type === 'device-roster-put') {
      // КРИТ-04: список устройств переписывают при привязке или отзыве — у
      // человека это событие нескольких раз в год. Кадр же стоит проверки
      // подписи каждого сертификата, до тридцати двух в штуке.
      if (costlyLimited(ws, 'rosterPut', ROSTER_PUT_MAX_PER_MIN)) {
        return send(ws, { type: 'device-roster-error', error: 'rate' });
      }
      const accepted = acceptSignedRoster(ws, msg.roster);
      if (!accepted.ok) {
        return send(ws, { type: 'device-roster-error', error: accepted.reason || 'invalid-roster' });
      }
      send(ws, {
        type: 'device-roster-ok',
        accountPublicKey: accepted.roster.accountPublicKey,
        version: accepted.roster.version,
        unchanged: !!accepted.unchanged,
      });
      broadcastAccount(accepted.roster.accountPublicKey, {
        type: 'device-roster',
        roster: accepted.roster,
      });
      return;
    }

    if (msg.type === 'device-bind') {
      const bound = bindSocketToCertifiedDevice(ws, msg.certificate);
      if (!bound.ok) {
        return send(ws, { type: 'device-bind-error', error: bound.reason || 'device-bind-failed' });
      }
      return send(ws, {
        type: 'device-bound',
        accountPublicKey: bound.record.accountPublicKey,
        deviceId: bound.record.deviceId,
        roster: bound.roster,
      });
    }

    if (msg.type === 'device-roster-get') {
      const requested =
        typeof msg.accountPublicKey === 'string' && msg.accountPublicKey
          ? msg.accountPublicKey
          : ws.accountPubkey || ws.pubkey;
      const ownsRequested =
        requested === ws.accountPubkey ||
        (requested === ws.pubkey && !!store.getAccount(requested));
      if (!ownsRequested) return send(ws, { type: 'device-roster-error', error: 'forbidden' });
      return send(ws, { type: 'device-roster', roster: store.getAccountRoster(requested) });
    }

    if (msg.type === 'relay-advertise') {
      // M-1: учить каталог может ТОЛЬКО аутентифицированный клиент/релей — иначе
      // аноним отравлял бы список мусором и подсовывал вредоносные релеи (в т.ч.
      // как вектор SSRF через gossip). Плюс валидация URL (без приватных адресов).
      // СРВ-5 (частично): плюс потолок числа advertise на соединение — легитимный
      // клиент анонсирует свой набор релеев изредка, поэтому лимит щедрый, но
      // отсекает заливку мусора в каталог одним сокетом. Полное закрытие (жёсткая
      // привязка к доверенным узлам/токену федерации) вынесено в отчёт — требует
      // операторской настройки.
      ws.advCount = (ws.advCount || 0) + 1;
      if (ws.advCount > 30) {
        return send(ws, { type: 'relays', relays: relayDir });
      }
      const urls = Array.isArray(msg.relays) ? msg.relays : [msg.url];
      const clean = urls.filter((u) => isValidRelayUrl(u));
      if (clean.length) learnRelays(clean);
      return send(ws, { type: 'relays', relays: relayDir });
    }

    if (msg.type === 'turn') {
      return send(ws, { type: 'turn', iceServers: turnIceServers() });
    }

    if (msg.type === 'prekeys-put') {
      // АУД-Э1: публиковать prekey можно только доказав владение адресом.
      // Иначе занявший незакреплённый адрес подменяет бандл жертвы своим, и
      // отправители строят первую сессию с ним — то есть подпись SPK сверяется
      // с ЕГО ключом, закреплённым тем же захватом.
      if (!ws.proven) {
        return send(ws, { type: 'error', error: 'box ownership proof required' });
      }
      // Выгрузка СВОИХ публичных X3DH-prekey. Подпись SPK сверяется с TOFU-ключом
      // этого соединения — чужие/битые бандлы не сохраняются.
      const b = msg.bundle || {};
      const spkObj = b.spk;
      if (!spkObj || !isB64Field(spkObj.id, 32) || !isB64Field(spkObj.pub) || !isB64Field(spkObj.sig)) {
        return send(ws, { type: 'error', error: 'prekeys-put requires bundle.spk {id,pub,sig}' });
      }
      // БЕЗ-3: постквантовый ключ необязателен, но если объявлен — обязан быть
      // корректным base64 разумного размера. Подпись над ним проверяется ниже.
      if (spkObj.pq !== undefined && !isB64Field(spkObj.pq, MAX_SPK_PQ_B64)) {
        return send(ws, { type: 'error', error: 'bad bundle.spk.pq' });
      }
      const boundSpkKey = store.getSignKey(ws.pubkey);
      if (!boundSpkKey || !verifySpkSignature(spkObj, boundSpkKey)) {
        return send(ws, { type: 'error', error: 'bad prekey signature' });
      }
      const opks = (Array.isArray(b.opks) ? b.opks : [])
        .filter((k) => k && isB64Field(k.id, 32) && isB64Field(k.pub))
        .slice(0, MAX_OTPS_PER_USER)
        .map((k) => ({ id: k.id, pub: k.pub }));
      store.setSpk(ws.pubkey, { id: spkObj.id, pub: spkObj.pub, sig: spkObj.sig, pq: spkObj.pq });
      store.replaceOtps(ws.pubkey, opks);
      return send(ws, { type: 'prekeys-ok', otps: store.countOtps(ws.pubkey) });
    }

    // --- ПЯЩ-1: общий ящик записок -----------------------------------------
    //
    // Кадра «есть ли у тебя ключ K» здесь НЕТ и быть не должно. Ответив на него,
    // узел связал бы положившего со спросившим — то есть выдал бы ребро графа
    // знакомств, ради сокрытия которого весь замысел и существует. Вместо
    // вопроса узел отдаёт сводку обо ВСЁМ, что у него лежит; она одинакова для
    // всех, сверка идёт на телефоне, а при попадании забирается целая корзина
    // чужих записок.

    if (msg.type === 'mbx-put') {
      // Записки кладутся пачкой в base64: кадр редкий (раз в шесть часов) и
      // маленький (восемь записок — 1,8 КБ), заводить ради него двоичный путь
      // незачем.
      if (typeof msg.records !== 'string' || msg.records.length > 4 * mbx.RECORD_BYTES * mbx.MAX_PUT_RECORDS + 8) {
        return send(ws, { type: 'mbx-error', error: 'bad records' });
      }
      const nowPut = Date.now();
      if (nowPut - (ws.mbxPutStart || 0) > MBX_PUT_WINDOW_MS) {
        ws.mbxPutStart = nowPut;
        ws.mbxPutCount = 0;
      }
      ws.mbxPutCount = (ws.mbxPutCount || 0) + 1;
      if (ws.mbxPutCount > MBX_PUT_MAX) {
        return send(ws, { type: 'mbx-error', error: 'rate' });
      }
      let raw = null;
      try {
        raw = Buffer.from(msg.records, 'base64');
      } catch (e) {
        return send(ws, { type: 'mbx-error', error: 'bad records' });
      }
      const parsed = mbx.parsePut(raw, { now: nowPut, slot: msg.slot });
      if (!parsed) return send(ws, { type: 'mbx-error', error: 'bad records' });
      // Владельца у записки нет: ws.pubkey здесь НЕ сохраняется никуда, и это
      // не упущение, а условие. Узел, знающий автора, знал бы половину ребра.
      const added = store.mbxPut(parsed, mbxValueHash);
      mbxTrim();
      // КРИТ-04: сводку пересчитывает тот, кто изменил ящик, а не тот, кто о ней
      // спросил. Иначе стоимость пересчёта назначает спрашивающий.
      mbxRefreshDigest();
      return send(ws, { type: 'mbx-ok', added });
    }

    if (msg.type === 'mbx-digest') {
      if (costlyLimited(ws, 'mbxDigest', MBX_DIGEST_MAX_PER_MIN)) {
        return send(ws, { type: 'mbx-error', error: 'rate' });
      }
      const size = store.mbxCount();
      // Ключи берутся ФУНКЦИЕЙ: при попадании в кэш выборка всех ключей ящика не
      // происходит вовсе. Прежде она выполнялась до обращения к кэшу, то есть на
      // каждую просьбу, и кэш экономил только кодирование.
      const digest = mbxDigest.get(store.mbxRevision(), () => store.mbxKeys());
      return send(ws, {
        type: 'mbx-digest',
        size,
        depth: mbx.bucketDepth(size),
        p: digest.p,
        n: digest.n,
        bits: digest.bitsBase64,
      });
    }

    if (msg.type === 'mbx-fetch') {
      if (costlyLimited(ws, 'mbxFetch', MBX_FETCH_MAX_PER_MIN)) {
        return send(ws, { type: 'mbx-error', error: 'rate' });
      }
      const size = store.mbxCount();
      // Слишком узкую корзину не отдаём даже по просьбе: попросивший корзину из
      // десятка записок тем самым почти назвал ключ.
      if (!mbx.depthAllowed(msg.depth, size)) {
        return send(ws, { type: 'mbx-error', error: 'depth' });
      }
      const range = mbx.bucketRange(msg.bucket, msg.depth);
      if (!range) return send(ws, { type: 'mbx-error', error: 'bucket' });
      const rows = store.mbxBucket(range.low, range.high, mbx.SYNC_LIMIT);
      return send(ws, {
        type: 'mbx-bucket',
        depth: msg.depth,
        bucket: msg.bucket,
        count: rows.length,
        records: mbx.packRecords(rows.map((row) => ({ key: row.key, value: row.val, mac: row.mac }))).toString('base64'),
      });
    }

    // АУД-13: сколько СВОИХ одноразовых prekey у релея осталось.
    //
    // Раньше это число сообщалось только в `ready`, то есть узнать его можно было
    // лишь переподключившись. Телефон, который сутки держит соединение, пул не
    // пополнял никогда — а вычерпать его можно тридцатью ключами в минуту на
    // адрес. X3DH при этом продолжает работать через подписанный prekey, forward
    // secrecy не теряется; теряется дополнительный одноразовый слой для всех, кто
    // напишет вам первым в это окно. Кадр дешёвый (один индексный COUNT) и не
    // раскрывает ничего, чего клиент не знает про себя сам.
    if (msg.type === 'prekeys-count') {
      return send(ws, { type: 'prekeys-count', otps: store.countOtps(ws.pubkey) });
    }

    if (msg.type === 'prekeys-get') {
      // Бандл prekey получателя для X3DH: SPK + один одноразовый (выдаётся
      // РОВНО один раз). Публичные данные; подпись клиент сверяет сам с ключом,
      // закреплённым при QR-знакомстве, — релею верить не обязан.
      if (typeof msg.pubkey !== 'string' || !msg.pubkey) {
        return send(ws, { type: 'error', error: 'prekeys-get requires pubkey' });
      }
      // M2: троттлинг на соединение — при превышении отвечаем как «prekey нет»
      // (bundle:null), OTP не расходуется (клиент откатится на static/SPK-only).
      const nowPk = Date.now();
      if (nowPk - (ws.pkGetStart || 0) > PREKEY_GET_WINDOW_MS) {
        ws.pkGetStart = nowPk;
        ws.pkGetCount = 0;
      }
      ws.pkGetCount = (ws.pkGetCount || 0) + 1;
      if (ws.pkGetCount > PREKEY_GET_MAX) {
        return send(ws, { type: 'prekeys', pubkey: msg.pubkey, bundle: null });
      }
      const spkRec = store.getSpk(msg.pubkey);
      if (!spkRec) return send(ws, { type: 'prekeys', pubkey: msg.pubkey, bundle: null });
      // H-4: глобальный лимит выдачи OTP на целевой адрес. Сверх лимита — SPK без OTP
      // (opk:null): X3DH работает через SPK, одноразовые ключи жертвы не сливаются.
      const nowT = Date.now();
      const gate = rateGate(otpDrain.get(msg.pubkey), nowT, PREKEY_TARGET_WINDOW_MS, PREKEY_TARGET_MAX);
      otpDrain.set(msg.pubkey, gate.state);
      let opk = null;
      if (gate.allow) {
        opk = store.takeOtp(msg.pubkey);
        if (opk) gate.state.count += 1; // считаем только реально выданные
      }
      return send(ws, { type: 'prekeys', pubkey: msg.pubkey, bundle: { spk: spkRec, opk } });
    }

    if (msg.type === 'register') {
      // Токен пробуждения: FCM-токен ЛИБО web-push подписка UnifiedPush (JSON-строка
      // {endpoint,keys} — F-Droid/FOSS/hybrid). Тип определяется в push.js по форме.
      // Потолок длины — подписка (endpoint + ключи) длиннее FCM-токена.
      // АУД-Э1: перебить токен пробуждения можно только доказав владение
      // адресом. Иначе занявший незакреплённый адрес забирает себе ВСЕ пуши
      // жертвы: он получает точное время каждого входящего (трафик-анализ), а
      // она перестаёт получать уведомления вовсе и считает, что ей не пишут.
      if (!ws.proven) {
        return send(ws, { type: 'error', error: 'box ownership proof required' });
      }
      if (typeof msg.pushToken === 'string' && msg.pushToken && msg.pushToken.length <= 1024) {
        store.setToken(ws.pubkey, msg.pushToken);
      }
      return send(ws, { type: 'registered' });
    }

    if (msg.type === 'push-test') {
      const testId = typeof msg.testId === 'string' ? msg.testId : '';
      const channel = msg.channel === 'call' ? 'call' : 'message';
      if (!/^[A-Za-z0-9_-]{8,96}$/.test(testId)) {
        return send(ws, { type: 'push-test-result', testId, accepted: false, error: 'invalid-test-id' });
      }
      const now = Date.now();
      if (now - (ws.lastPushTestAt || 0) < 5000) {
        return send(ws, { type: 'push-test-result', testId, accepted: false, error: 'rate-limited' });
      }
      ws.lastPushTestAt = now;
      const token = store.getToken(ws.pubkey);
      if (!token) {
        return send(ws, { type: 'push-test-result', testId, accepted: false, error: 'not-registered' });
      }
      sendPushTestResult(ws, token, testId, channel);
      return;
    }

    if (msg.type === 'received') {
      // H-2: квитанцию принимаем только от доказанного владельца адреса. Недоказанный
      // держатель (сквоттер незанятого адреса) не может удалить конверт из очереди
      // и не спровоцирует ложный `delivered` — реальный владелец потом заберёт своё.
      if (typeof msg.id === 'string' && ws.proven) ackReceived(ws.pubkey, msg.id);
      return;
    }

    // ЭТП5-4: сосед принёс жетон и просит отдать ему очередь владельца.
    //
    // ЗАЧЕМ. Выход в интернет через соседа (ШЛЗ-1) работал в одну сторону:
    // сосед мог положить наш конверт в релей, но забрать нашу очередь не мог —
    // релей отдаёт её только доказавшему владение box-ключом адреса. Человек
    // без интернета мог писать, но не получать, а половина связи — не связь.
    //
    // ЧТО ЭТО НЕ ДАЁТ. Ни прочитать (конверты запечатаны на получателя), ни
    // удалить (квитанции по-прежнему только от `ws.proven` владельца), ни
    // предъявить дважды, ни воспользоваться чужим жетоном. Всё это — в правиле
    // gateway-ticket.js, общем у релея и телефона.
    if (msg.type === 'gw-pull') {
      handleGatewayPull(ws, msg);
      return;
    }

    if (msg.type === 'binary-received') {
      if (typeof msg.id === 'string' && ws.proven) ackBinaryReceived(ws.pubkey, msg.id);
      return;
    }

    if (msg.type === 'send') {
      if (typeof msg.to !== 'string' || !msg.to || !msg.envelope) {
        return send(ws, { type: 'error', error: 'send requires to + envelope' });
      }
      return acceptEnvelope(ws, {
        to: msg.to,
        envelope: msg.envelope,
        silent: !!msg.silent,
        callPush: !!msg.callPush,
        noMeta: !!msg.noMeta,
        ref: msg.ref,
      });
    }

    send(ws, { type: 'error', error: 'unknown type' });
}

// --- gossip: периодически синхронизируем каталог с известными релеями --------
// Каждый релей тянет /relays у пиров и сливает списки — так новый узел за
// несколько раундов становится известен почти всем, без центрального реестра.
function relayHttpBase(wsUrl) {
  return wsUrl.replace(/^ws:\/\//i, 'http://').replace(/^wss:\/\//i, 'https://');
}
// M-1 (SSRF): перед исходящим запросом к пиру резолвим его хост и отказываемся,
// если он указывает на приватный/loopback/link-local адрес. isValidRelayUrl уже
// блокирует ЛИТЕРАЛЬНЫЕ приватные IP; здесь ловим ХОСТНЕЙМЫ, которые резолвятся
// внутрь сети (DNS-rebinding-подобный вектор через отравленный каталог).
function hostOf(wsUrl) {
  return String(wsUrl)
    .replace(/^wss?:\/\//i, '')
    .replace(/[/?#].*$/, '')
    .replace(/:\d+$/, '')
    .replace(/^\[|\]$/g, '');
}
// L7 (TOCTOU/DNS-rebinding): резолвим хост ОДИН раз, проверяем ВСЕ адреса и
// возвращаем их для ПИННИНГА соединения. Раньше проверка (dns.lookup) и запрос
// (fetch со своим резолвингом) были разными разрешениями имени — вредоносный DNS
// мог отдать публичный IP на проверке и приватный на самом запросе. Теперь
// соединение идёт ровно на проверенные IP (кастомный lookup), а имя хоста
// сохраняется для SNI/валидации TLS-сертификата — сертификат по-прежнему сверяется.
async function safePeerAddrs(wsUrl, { allowPrivate = false } = {}) {
  const host = hostOf(wsUrl);
  if (!host || (!allowPrivate && isPrivateHost(host))) return null;
  try {
    const addrs = await dns.lookup(host, { all: true });
    if (!addrs.length) return null;
    if (!allowPrivate) {
      for (const a of addrs) if (isPrivateHost(a.address)) return null;
    }
    return addrs.map((a) => ({ address: a.address, family: a.family }));
  } catch (e) {
    return null; // не резолвится — не ходим
  }
}
// Кастомный lookup для http/https: игнорирует реальный DNS и отдаёт ТОЛЬКО
// заранее проверенные адреса (пиннинг) — между проверкой и коннектом имя уже не
// переразрешается, окно DNS-rebinding закрыто.
function pinnedLookup(pinned) {
  return (hostname, options, cb) => {
    if (options && options.all) return cb(null, pinned);
    cb(null, pinned[0].address, pinned[0].family);
  };
}
/** GET/POST JSON к пиру по проверенным IP. Возвращает распарсенный ответ или null. */
function httpJson(urlStr, { method = 'GET', headers = {}, body = null, pinned, timeoutMs = 5000 }) {
  return new Promise((resolve) => {
    // СРВ-9: единый идемпотентный финиш. Раньше при req.destroy() на гигантском
    // ответе (без аргумента 'error' НЕ эмитится) и при отсутствии res.on('error')
    // промис мог не зарезолвиться НИКОГДА — gossipOnce вставал на await навсегда, а
    // интервал каждые 60 с плодил новые зависшие контексты/сокеты. Теперь любой
    // исход (ответ, ошибка, таймаут, close, oversize) резолвит ровно один раз.
    let settled = false;
    const finish = (v) => {
      if (settled) return;
      settled = true;
      resolve(v);
    };
    let mod;
    try {
      mod = new URL(urlStr).protocol === 'https:' ? https : http;
    } catch (e) {
      return finish(null);
    }
    const req = mod.request(urlStr, { method, headers, lookup: pinnedLookup(pinned) }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        return finish(null);
      }
      let buf = '';
      res.on('data', (c) => {
        buf += c;
        if (buf.length > 1000000) {
          req.destroy(); // защита от гигантского ответа
          finish(null); // destroy не эмитит 'error' — резолвим явно
        }
      });
      res.on('end', () => {
        try {
          finish(JSON.parse(buf));
        } catch (e) {
          finish(null);
        }
      });
      res.on('error', () => finish(null)); // преждевременный обрыв со стороны пира
    });
    req.on('error', () => finish(null));
    req.on('close', () => finish(null)); // страховка: закрытие без end/error
    req.setTimeout(timeoutMs, () => req.destroy());
    if (body) req.write(body);
    req.end();
  });
}
async function fetchPeerRelays(wsUrl) {
  const pinned = await safePeerAddrs(wsUrl);
  if (!pinned) return null;
  const body = await httpJson(relayHttpBase(wsUrl) + '/relays', { pinned });
  return body && Array.isArray(body.relays) ? body.relays : null;
}
// Push-gossip: сообщить peer'у наш каталог (включая себя). Благодаря этому
// сосед, который сам нас в peers не прописывал (напр. самый первый релей),
// узнаёт про нас — распространение становится двунаправленным.
async function pushSelfTo(wsUrl) {
  const pinned = await safePeerAddrs(wsUrl);
  if (!pinned) return;
  await httpJson(relayHttpBase(wsUrl) + '/relays', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      // M1: свой токен федерации — чтобы пир с тем же токеном принял наш каталог.
      ...(GOSSIP_TOKEN ? { 'x-gossip-token': GOSSIP_TOKEN } : {}),
    },
    body: JSON.stringify({ relays: relayDir }),
    pinned,
  });
}

const vapidSyncState = { running: false };
async function vapidSyncWith(options = {}) {
  const state = options.state || vapidSyncState;
  const bundle = options.bundle === undefined ? vapidFleetBundle : options.bundle;
  const fleet = options.fleet === undefined ? VAPID_FLEET : options.fleet;
  const member = options.member === undefined ? VAPID_MEMBER : options.member;
  const selfUrl = options.selfUrl === undefined ? SELF_URL : options.selfUrl;
  const relayPublicKey = options.relayPublicKey || RELAY_KEYS.pub;
  const relaySecretKey = options.relaySecretKey || RELAY_KEYS.sec;
  const allowPrivate = options.allowPrivate === undefined ? VAPID_FLEET_ALLOW_PRIVATE : options.allowPrivate;
  const acceptsKey = options.acceptsKey || memberAcceptsKey;
  const resolvePeer = options.resolvePeer || safePeerAddrs;
  const createRequest = options.createRequest || createVapidRequest;
  const requestJson = options.requestJson || httpJson;
  const httpBase = options.httpBase || relayHttpBase;
  const openResponse = options.openResponse || openVapidResponse;
  const writeFile = options.writeFile || writeJsonAtomic;
  const keyFile = options.keyFile || RELAY_VAPID_KEY_FILE;
  const activate = options.activate || activateVapid;
  const logger = options.logger || console;
  if (
    state.running ||
    bundle ||
    !fleet ||
    !member ||
    !selfUrl ||
    !acceptsKey(member, relayPublicKey)
  ) {
    return false;
  }
  state.running = true;
  try {
    // Сначала genesis, затем остальные участники: после первой раздачи любой
    // получивший bundle может помочь новому узлу, поэтому падение genesis не
    // становится постоянной точкой отказа.
    const peers = [...fleet.relays]
      .filter((entry) => entry.url.toLowerCase() !== selfUrl.toLowerCase())
      .sort((a, b) => Number(b.url === fleet.genesis) - Number(a.url === fleet.genesis));
    for (const peer of peers) {
      const pinned = await resolvePeer(peer.url, { allowPrivate });
      if (!pinned) continue;
      let pending;
      try {
        pending = createRequest({
          config: fleet,
          relayUrl: selfUrl,
          relayPub: relayPublicKey,
          relaySecret: relaySecretKey,
        });
      } catch (e) {
        logger.warn('[vapid-fleet] локальная идентичность не разрешена:', e && e.message);
        return false;
      }
      const response = await requestJson(httpBase(peer.url) + '/vapid-fleet', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(pending.request),
        pinned,
        timeoutMs: 8000,
      });
      if (
        !response ||
        typeof response.senderUrl !== 'string' ||
        response.senderUrl.toLowerCase() !== peer.url.toLowerCase()
      ) {
        continue;
      }
      const receivedBundle = openResponse({
        config: fleet,
        request: pending.request,
        response,
        boxSecret: pending.boxSecret,
      });
      if (!receivedBundle) continue;
      try {
        writeFile(keyFile, receivedBundle);
        if (!activate(receivedBundle.publicKey, receivedBundle.privateKey, `fleet-peer:${peer.url}`, receivedBundle)) {
          throw new Error('web-push rejected the verified VAPID pair');
        }
        logger.log(`[vapid-fleet] общий VAPID epoch=${receivedBundle.epoch} получен от ${peer.url}`);
        return true;
      } catch (e) {
        logger.warn('[vapid-fleet] не удалось сохранить полученный VAPID:', e && e.message);
      }
    }
    return false;
  } finally {
    state.running = false;
  }
}
async function vapidSyncOnce() {
  return vapidSyncWith();
}

// ПЯЩ-1: забрать у соседа записки, появившиеся после нашего курсора.
//
// Курсор свой на каждого соседа и живёт в памяти: перезапуск узла означает
// повторную тягу с нуля, а это дёшево (записки живут тринадцать часов) и честнее
// хранения ещё одной таблицы. Ответ разбирается ровно так же строго, как кадр от
// клиента: сосед — такой же чужой ввод.
const mbxCursors = new Map();

async function fetchPeerNotes(wsUrl) {
  const after = mbxCursors.get(wsUrl) || 0;
  const pinned = await safePeerAddrs(wsUrl);
  if (!pinned) return 0;
  const body = await httpJson(relayHttpBase(wsUrl) + '/mbx?after=' + after, { pinned });
  if (!body || typeof body.records !== 'string') return 0;
  if (!Array.isArray(body.slots)) return 0;
  let raw = null;
  try {
    raw = Buffer.from(body.records, 'base64');
  } catch (e) {
    return 0;
  }
  if (!raw.length || raw.length % mbx.RECORD_BYTES !== 0) return 0;
  const count = raw.length / mbx.RECORD_BYTES;
  if (count !== body.slots.length || count > mbx.SYNC_LIMIT) return 0;
  const now = Date.now();
  const here = mbx.slotOf(now);
  const records = [];
  for (let i = 0; i < count; i += 1) {
    const slot = body.slots[i];
    // Отрезок сверяем по СВОИМ часам: сосед мог отдать давно протухшее либо
    // «из будущего», и хранить это у себя мы не обязаны.
    if (!Number.isInteger(slot) || Math.abs(slot - here) > mbx.SLOT_TOLERANCE) continue;
    const at = i * mbx.RECORD_BYTES;
    records.push({
      key: raw.subarray(at, at + mbx.KEY_BYTES),
      value: raw.subarray(at + mbx.KEY_BYTES, at + mbx.KEY_BYTES + mbx.VALUE_BYTES),
      mac: raw.subarray(at + mbx.KEY_BYTES + mbx.VALUE_BYTES, at + mbx.RECORD_BYTES),
      slot,
    });
  }
  if (Number.isInteger(body.seq) && body.seq > after) mbxCursors.set(wsUrl, body.seq);
  if (!records.length) return 0;
  const added = store.mbxPut(records, mbxValueHash);
  if (added) mbxTrim(now);
  return added;
}

async function gossipOnce() {
  const peers = relayDir.filter((u) => !SELF_URL || u.toLowerCase() !== SELF_URL.toLowerCase());
  let learned = false;
  for (const peer of peers) {
    const list = await fetchPeerRelays(peer);
    if (list && learnRelays(list)) learned = true;
    await pushSelfTo(peer); // рассказываем peer'у про себя (двунаправленно)
    // ПЯЩ-1: и тянем его записки. Без этого записка лежала бы ровно на том узле,
    // куда её положили, — то есть находила бы только тех, кто и так рядом.
    await fetchPeerNotes(peer);
  }
  mbxTrim();
  if (learned) console.log(`[gossip] directory now ${relayDir.length} relays`);
}
function scheduleFederation(options = {}) {
  const selfUrl = options.selfUrl === undefined ? SELF_URL : options.selfUrl;
  const seeds = options.seeds || PEER_SEED;
  const fleet = options.fleet === undefined ? VAPID_FLEET : options.fleet;
  const member = options.member === undefined ? VAPID_MEMBER : options.member;
  const bundle = options.bundle === undefined ? vapidFleetBundle : options.bundle;
  const runGossip = options.runGossip || gossipOnce;
  const runVapidSync = options.runVapidSync || vapidSyncOnce;
  const setEvery = options.setEvery || setInterval;
  const setLater = options.setLater || setTimeout;
  const timers = [];
  if (selfUrl || seeds.length) {
    const timer = setEvery(() => runGossip().catch(() => {}), GOSSIP_INTERVAL_MS);
    if (timer && typeof timer.unref === 'function') timer.unref();
    timers.push(timer);
  }
  if (fleet && member && !bundle) {
    const initial = setLater(() => runVapidSync().catch(() => {}), 2000);
    const repeat = setEvery(() => runVapidSync().catch(() => {}), VAPID_SYNC_INTERVAL_MS);
    if (initial && typeof initial.unref === 'function') initial.unref();
    if (repeat && typeof repeat.unref === 'function') repeat.unref();
    timers.push(initial, repeat);
  }
  return timers;
}
scheduleFederation();

// drop dead connections + backpressure (H4): рвём сокеты, чей буфер отправки
// раздулся (клиент не вычитывает) — иначе они держат память узла.
function heartbeatConnections(clients = wss.clients) {
  for (const ws of clients) {
    if (ws.bufferedAmount > MAX_BUFFERED_BYTES) {
      ws.terminate();
      continue;
    }
    if (!ws.isAlive) {
      ws.terminate();
      continue;
    }
    ws.isAlive = false;
    ws.ping();
  }
}
setInterval(heartbeatConnections, 30000).unref();

// TTL: периодически чистим протухшие конверты (не забрали за QUEUE_TTL_MS).
function expireQueuedEnvelopes(now = Date.now(), queueStore = store, { onFatal = handleTopLevelError } = {}) {
  try {
    const removed = queueStore.expireOlderThan(now - QUEUE_TTL_MS);
    if (removed) console.log(`[ttl] expired ${removed} stale envelope(s)`);
    // ГРФ-3: тем же часовым проходом стираем имена давно отозванных устройств —
    // раньше они лежали в account_devices открытым текстом и НАВСЕГДА.
    const redacted = store.redactRevokedDevices(Date.now());
    if (redacted) console.log(`[ttl] redacted ${redacted} revoked device record(s)`);
    return removed;
  } catch (e) {
    // Т-4: фатальный сбой БД здесь НЕ глушим.
    //
    // Раньше гасилась любая ошибка, включая SQLITE_CORRUPT. Узел после этого
    // «жил», а часовой проход молча переставал работать: очередь росла без TTL, а
    // имена отозванных устройств (ГРФ-3) продолжали лежать открытым текстом —
    // навсегда. Механизм L4 (честный выход под рестарт супервизора) до этого
    // места просто не дотягивался, потому что ошибка сюда не выходила.
    //
    // Нефатальные ошибки по-прежнему переживаются: разовая заминка не повод
    // ронять узел, а следующий проход через час попробует снова. Но о ней теперь
    // говорится — беззвучно пропущенная уборка выглядела как выполненная.
    if (isFatalDbError(e)) {
      onFatal('ttl', e);
      return 0;
    }
    console.warn('[ttl] проход уборки не выполнен:', (e && e.message) || e);
  }
  return 0;
}
setInterval(expireQueuedEnvelopes, 3600 * 1000).unref();

// --- ВЫП-8: узел сам забирает актуальный выпуск ------------------------------
//
// Через релеи обновление доезжает до установленного приложения ЕДИНСТВЕННЫМ
// путём: сайта и магазина у проекта нет. Пока выпуск клал оператор руками, на
// каждом узле и на каждую версию, — не раздавал никто, и выпущенное исправление
// до людей не доходило.
//
// Порядок здесь важен и объяснён в шапке updateMirror.js: подпись проверяется
// ДО того, как узел пойдёт по адресу из манифеста. Иначе подставленный манифест
// отправил бы его куда угодно и занял бы диск.
let mirrorRunning = false;

/** Что узел раздаёт сейчас: версия и отпечаток из лежащего манифеста. */
function mirroredRelease(platform) {
  try {
    const file = path.join(UPDATE_DIR, updateFeed.RELEASES[platform].manifest);
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    return { version: String(parsed.version || ''), sha256: String(parsed.sha256 || '') };
  } catch (e) {
    return null; // ещё ничего не раздаём — это норма, а не беда
  }
}

/** Проверка подписи — тем же кодом и тем же ключом, что и в приложении. */
function verifyReleaseSignature(payload, signature, key) {
  try {
    return ed25519.verify(
      naclUtil.decodeUTF8(payload),
      naclUtil.decodeBase64(signature),
      naclUtil.decodeBase64(key)
    );
  } catch (e) {
    return false;
  }
}

async function fetchText(url, limit) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 20000);
  try {
    const response = await fetch(url, { signal: controller.signal, redirect: 'follow' });
    if (!response.ok) return null;
    const text = await response.text();
    return text.length > limit ? null : text;
  } catch (e) {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function mirrorPlatform(platform) {
  const url = updateMirror.manifestUrl(UPDATE_SOURCE, platform);
  if (!url) return;
  const body = await fetchText(url, updateMirror.MAX_MANIFEST_BYTES);
  if (!body) return;

  const have = mirroredRelease(platform);
  const checked = updateMirror.checkedManifest({
    body,
    platform,
    publicKey: RELEASE_PUBLIC_KEY,
    verifySignature: verifyReleaseSignature,
    currentVersion: '0.0.0',
  });
  if (!checked.ok) {
    console.warn(`[update] манифест ${platform} отвергнут: ${checked.reason}`);
    return;
  }
  if (!updateMirror.needsFetch({ have, release: checked.release })) return;

  const fileUrl = updateMirror.usableFileUrl(checked.release.url);
  if (!fileUrl) {
    console.warn(`[update] адрес файла ${platform} не годится: нужен https`);
    return;
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 300000);
  let bytes = null;
  try {
    const response = await fetch(fileUrl, { signal: controller.signal, redirect: 'follow' });
    if (!response.ok) return;
    bytes = Buffer.from(await response.arrayBuffer());
  } catch (e) {
    console.warn(`[update] файл ${platform} не скачался:`, (e && e.message) || e);
    return;
  } finally {
    clearTimeout(timer);
  }

  const sha256 = crypto.createHash('sha256').update(bytes).digest('hex');
  const verdict = updateMirror.fileVerdict({ size: bytes.length, sha256, release: checked.release });
  if (!verdict.ok) {
    console.warn(`[update] файл ${platform} не сошёлся с подписанным манифестом: ${verdict.reason}`);
    return;
  }

  // Сначала файл, потом манифест. Манифест — объявление «файл готов»: появись
  // оно раньше, приложение пришло бы за файлом, которого ещё нет. Запись через
  // временное имя: оборвись процесс на середине, узел раздавал бы огрызок.
  fs.mkdirSync(UPDATE_DIR, { recursive: true });
  const names = updateFeed.RELEASES[platform];
  const filePath = path.join(UPDATE_DIR, names.file);
  const tmpPath = `${filePath}.part`;
  fs.writeFileSync(tmpPath, bytes);
  fs.renameSync(tmpPath, filePath);
  fs.writeFileSync(path.join(UPDATE_DIR, names.manifest), body, 'utf8');
  console.warn(`[update] ${platform}: раздаём ${checked.release.version} (${bytes.length} байт)`);
}


// --- ВЫП-9: веб-версия на узле ----------------------------------------------
//
// Её открывают там, где приложения нет и не будет: на iPhone магазина у проекта
// нет, а поставить APK туда нельзя. Для этих людей веб-версия — не запасной
// путь, а единственный.
//
// Дерево файлов, а не один файл, поэтому и проверок больше: подпись покрывает
// СВЁРТКУ списка, свёртка сверяется с самим списком, а каждый скачанный файл —
// со своим отпечатком. Подменить достаточно одного файла, того, который
// исполняется в браузере.

/** Какая версия многофайлового выпуска лежит сейчас. */
function mirroredTreeVersion(manifestName) {
  try {
    const parsed = JSON.parse(fs.readFileSync(path.join(UPDATE_DIR, manifestName), 'utf8'));
    return String(parsed.version || '');
  } catch (e) {
    return '';
  }
}

/**
 * Забрать выпуск, состоящий из НЕСКОЛЬКИХ файлов (ВЫП-9, ВЫП-11).
 *
 * Так устроены веб-версия (страница, бандл, значки) и настольный клиент
 * (установщик, его подпись minisign, манифест Tauri). Подписана свёртка списка,
 * список сверяется с ней, каждый файл — со своим отпечатком: подменить довольно
 * одного файла, а не всей сборки.
 *
 * `replaceDir` — для веб-версии: там сборку кладут ЦЕЛИКОМ через временный
 * каталог, иначе на середине загрузки узел раздавал бы половину новой и половину
 * старой, а это белый экран. Настольные файлы лежат рядом с андроидными, сносить
 * каталог нельзя — переносим по одному, каждый через временное имя.
 */
async function mirrorTree(platform, manifestName, targetDir, replaceDir) {
  const url = updateMirror.manifestUrl(UPDATE_SOURCE, platform);
  if (!url) return;
  const body = await fetchText(url, updateMirror.MAX_MANIFEST_BYTES);
  if (!body) return;

  const checked = updateMirror.checkedManifest({
    body,
    platform,
    publicKey: RELEASE_PUBLIC_KEY,
    verifySignature: verifyReleaseSignature,
    currentVersion: '0.0.0',
  });
  if (!checked.ok) {
    console.warn(`[update] манифест ${platform} отвергнут: ${checked.reason}`);
    return;
  }
  const have = mirroredTreeVersion(manifestName);
  if (
    have &&
    !updateMirror.needsFetch({
      have: { version: have, sha256: '' },
      release: { version: checked.release.version, sha256: '' },
    })
  ) {
    return;
  }

  let list = [];
  try {
    list = JSON.parse(body).files;
  } catch (e) {
    return;
  }
  const verdict = updateMirror.webFilesVerdict({ files: list, filesHash: checked.release.filesHash });
  if (!verdict.ok) {
    console.warn(`[update] список файлов ${platform} отвергнут: ${verdict.reason}`);
    return;
  }

  const stageDir = replaceDir ? `${replaceDir}.new` : path.join(targetDir, `.${platform}.new`);
  fs.rmSync(stageDir, { recursive: true, force: true });
  fs.mkdirSync(stageDir, { recursive: true });
  for (const item of list) {
    const safe = updateMirror.safeWebPath(item.path);
    const fileUrl = updateMirror.treeFileUrl(UPDATE_SOURCE, platform, safe);
    if (!safe || !fileUrl) {
      fs.rmSync(stageDir, { recursive: true, force: true });
      return;
    }
    let bytes = null;
    try {
      const response = await fetch(fileUrl, { redirect: 'follow' });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      bytes = Buffer.from(await response.arrayBuffer());
    } catch (e) {
      console.warn(`[update] файл ${platform} ${safe} не скачался:`, (e && e.message) || e);
      fs.rmSync(stageDir, { recursive: true, force: true });
      return;
    }
    const digest = crypto.createHash('sha256').update(bytes).digest('hex');
    if (bytes.length !== Number(item.size) || digest !== String(item.sha256).toLowerCase()) {
      console.warn(`[update] файл ${platform} ${safe} не сошёлся с подписанным списком`);
      fs.rmSync(stageDir, { recursive: true, force: true });
      return;
    }
    const target = path.join(stageDir, safe);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, bytes);
  }

  if (replaceDir) {
    const oldDir = `${replaceDir}.old`;
    fs.rmSync(oldDir, { recursive: true, force: true });
    if (fs.existsSync(replaceDir)) fs.renameSync(replaceDir, oldDir);
    fs.renameSync(stageDir, replaceDir);
    fs.rmSync(oldDir, { recursive: true, force: true });
  } else {
    for (const item of list) {
      const safe = updateMirror.safeWebPath(item.path);
      const from = path.join(stageDir, safe);
      const to = path.join(targetDir, safe);
      fs.mkdirSync(path.dirname(to), { recursive: true });
      fs.renameSync(from, to);
    }
    fs.rmSync(stageDir, { recursive: true, force: true });
  }
  // ОСНОВНОЙ ФАЙЛ ВЫПУСКА, если его нет в списке.
  //
  // У настольного клиента установщик лежит в РЕЛИЗЕ, а не в дереве: держать
  // десятки мегабайт в истории git незачем, и с каждым выпуском она росла бы
  // навсегда. В дереве едут только мелочи — манифест Tauri и подпись minisign.
  // Адрес установщика взят из подписанного манифеста, длина и отпечаток тоже
  // подписаны, так что проверять его есть чем.
  const mainName = (updateFeed.RELEASES[platform] || {}).file || '';
  const inList = list.some((item) => updateMirror.safeWebPath(item.path) === mainName);
  if (mainName && !inList) {
    const fileUrl = updateMirror.usableFileUrl(checked.release.url);
    if (!fileUrl) {
      console.warn(`[update] адрес файла ${platform} не годится: нужен https`);
      return;
    }
    let bytes = null;
    try {
      const response = await fetch(fileUrl, { redirect: 'follow' });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      bytes = Buffer.from(await response.arrayBuffer());
    } catch (e) {
      console.warn(`[update] файл ${platform} не скачался:`, (e && e.message) || e);
      return;
    }
    const digest = crypto.createHash('sha256').update(bytes).digest('hex');
    const fileOk = updateMirror.fileVerdict({ size: bytes.length, sha256: digest, release: checked.release });
    if (!fileOk.ok) {
      console.warn(`[update] файл ${platform} не сошёлся с подписанным манифестом: ${fileOk.reason}`);
      return;
    }
    const target = path.join(targetDir, mainName);
    const tmp = `${target}.part`;
    fs.writeFileSync(tmp, bytes);
    fs.renameSync(tmp, target);
  }

  // Манифест — ПОСЛЕДНИМ: он объявляет «файлы готовы».
  fs.writeFileSync(path.join(UPDATE_DIR, manifestName), body, 'utf8');
  console.warn(`[update] ${platform}: раздаём ${checked.release.version} (${list.length} файлов)`);
}

async function maintainUpdateMirror() {
  if (UPDATE_MIRROR_OFF || mirrorRunning) return;
  mirrorRunning = true;
  try {
    // Только платформы, чей манифест подписан НАШИМ ключом. У настольного
    // клиента формат чужой (Tauri, подпись minisign стоит на установщике), и
    // проверить его этим кодом нельзя — значит и качать вслепую нельзя тоже.
    for (const [platform, names] of Object.entries(updateFeed.RELEASES)) {
      if (names.kind !== 'licno') continue;
      await mirrorPlatform(platform);
    }
    // ВЫП-11: настольный выпуск — тоже дерево файлов (установщик, его подпись
    // minisign и манифест Tauri). Механизм тот же, что у веб-версии: подписана
    // свёртка списка, каждый файл сверяется со своим отпечатком.
    await mirrorTree('desktop', 'desktop-version.json', UPDATE_DIR);
    await mirrorTree('web', 'web-version.json', WEB_DIR, WEB_DIR);
  } catch (e) {
    console.warn('[update] обход зеркала не выполнен:', (e && e.message) || e);
  } finally {
    mirrorRunning = false;
  }
}

if (!UPDATE_MIRROR_OFF) {
  // Первый заход — с задержкой: при старте узла есть дела важнее, чем качать
  // десятки мегабайт, а обновление, опоздавшее на минуту, ничем не хуже.
  setTimeout(() => {
    maintainUpdateMirror();
  }, 60000).unref();
  setInterval(maintainUpdateMirror, UPDATE_MIRROR_MS).unref();
}

// АУД-06: тела крупных конвертов пишутся вне event-loop, поэтому перед выходом
// начатые записи надо дождаться — иначе конверт, чья запись шла в момент
// SIGTERM, потерял бы тело, а строка очереди осталась бы. Ждём ограниченно:
// зависшая файловая система не должна мешать перезапуску узла.
const SHUTDOWN_FLUSH_MS = 5000;
function performShutdown({
  queueStore = store,
  exit = (code) => process.exit(code),
  timeoutMs = SHUTDOWN_FLUSH_MS,
  setTimer = setTimeout,
  clearTimer = clearTimeout,
} = {}) {
  let finished = false;
  const finish = () => {
    if (finished) return;
    finished = true;
    try {
      queueStore.close();
    } catch (e) {
      // Конверты уже сброшены на диск, процесс завершается следующей строкой.
      // Незакрытый дескриптор переживёт нас ровно на мгновение.
    }
    exit(0);
  };
  const flush = typeof queueStore.flushPendingBlobs === 'function' ? queueStore.flushPendingBlobs() : null;
  if (!flush) {
    finish();
    return Promise.resolve();
  }
  let resolveDone;
  const done = new Promise((resolve) => { resolveDone = resolve; });
  const complete = () => {
    clearTimer(timer);
    finish();
    resolveDone();
  };
  const timer = setTimer(complete, timeoutMs);
  if (typeof timer.unref === 'function') timer.unref();
  Promise.resolve(flush).then(complete, complete);
  return done;
}
function createShutdownHandler({ stop = stopEmbeddedCoturn, perform = performShutdown } = {}) {
  let shuttingDown = false;
  return function shutdown() {
    if (shuttingDown) return;
    shuttingDown = true;
    stop();
    return perform();
  };
}
const shutdown = createShutdownHandler();
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

// C-1 (backstop): узел store-and-forward не должен умирать от одного битого
// кадра/промиса. Обычную необработанную ошибку логируем и продолжаем работу — это
// многократно безопаснее падения всего процесса (перманентный DoS всей ноды).
//
// L4: ИСКЛЮЧЕНИЕ — повреждение/сбой БД. Продолжать работу с битой SQLite опасно:
// узел будет тихо деградировать (терять/недоставлять конверты) вместо честного
// рестарта. Такие ошибки → управляемый выход, systemd (Restart=always) поднимет
// процесс заново, при старте WAL восстановится/подчистится.
function isFatalDbError(err) {
  const code = (err && err.code && String(err.code)) || '';
  const msg = (err && err.message && String(err.message)) || '';
  return (
    /^SQLITE_(CORRUPT|NOTADB|CANTOPEN|IOERR|FULL|READONLY)/.test(code) ||
    /malformed|not a database|disk image is malformed|disk I\/O error/i.test(msg)
  );
}
function handleTopLevelError(tag, err, {
  queueStore = store,
  exit = (code) => process.exit(code),
} = {}) {
  console.error(`[${tag}]`, err && err.stack ? err.stack : err);
  if (isFatalDbError(err)) {
    console.error('[fatal] сбой/повреждение БД — управляемый выход для рестарта под systemd');
    try {
      queueStore.close();
    } catch (e) {
      // База уже признана повреждённой — именно поэтому мы здесь. Отказ
      // close() ожидаем и ничего не добавляет к уже напечатанной причине.
    }
    exit(1);
  }
}
process.on('uncaughtException', (err) => handleTopLevelError('uncaughtException', err));
process.on('unhandledRejection', (err) => handleTopLevelError('unhandledRejection', err));

// СРВ-10: без слушателя 'error' у http.Server ошибка listen (напр. EADDRINUSE)
// уходила в uncaughtException-backstop, isFatalDbError=false → процесс продолжал
// жить, НЕ слушая порт (зомби; systemd не рестартует, т.к. процесс жив). Теперь на
// ошибке старта честно выходим — под рестарт супервизора.
function handleServerError(err, {
  queueStore = store,
  exit = (code) => process.exit(code),
} = {}) {
  console.error('[server] listen/HTTP error:', err && err.stack ? err.stack : err);
  if (err && (err.code === 'EADDRINUSE' || err.code === 'EACCES')) {
    try {
      queueStore.close();
    } catch (e) {
      // Причина выхода — занятый порт, она уже в логе. Процесс всё равно
      // умирает следующей строкой, и супервизор поднимет его заново.
    }
    exit(1);
  }
}
server.on('error', handleServerError);
// СРВ-4: ошибки на уровне ws-сервера (до/во время апгрейда) — тоже гасим, чтобы не
// уходили в uncaughtException.
wss.on('error', (err) => {
  console.error('[wss] error:', err && err.message ? err.message : err);
});

function logMetricsAccess(metricsToken = METRICS_TOKEN, logger = console) {
  if (metricsToken) return false;
  logger.log('[metrics] /metrics доступен только из приватной сети/localhost (задайте RELAY_METRICS_TOKEN для внешнего доступа)');
  return true;
}

server.listen(PORT, () => {
  console.log(`Лично relay listening on :${PORT} (health: /health, directory: /relays)`);
  console.log(`[dir] ${relayDir.length} relay(s) known${SELF_URL ? `, self=${SELF_URL}` : ' (set RELAY_SELF_URL to advertise self)'}`);
  // S6: публичный ключ подлинности этого релея — впишите его клиентам в
  // config.SEED_RELAY_KEYS для пиннинга (иначе релей не проверяется).
  console.log(`[relay-key] RELAY_SIGN_PUBLIC=${RELAY_KEYS.pub}${SELF_URL ? `  (для ${SELF_URL})` : ''}`);
  // НАТ-1: на чём именно проверяются подписи. Печатаем всегда, а не только при
  // отказе: «релей почему-то не держит нагрузку» разбирается с этой строки.
  console.log(
    '[sign]',
    ed25519.nativeAvailable()
      ? 'подпись через OpenSSL (×13 к JavaScript)'
      : `подпись через JavaScript — OpenSSL не включён: ${nativeEd25519.reason}`
  );
  console.log(
    '[dh]',
    x25519.nativeAvailable()
      ? 'общий секрет через OpenSSL (×18 к JavaScript)'
      : `общий секрет через JavaScript — OpenSSL не включён: ${nativeX25519.reason}`
  );
  console.log(
    '[push]',
    pushReady()
      ? 'FCM configured — wake-up pushes enabled'
      : 'FCM NOT configured — FCM clients get no wake-ups'
  );
  console.log(
    '[push]',
    vapidPublicKey()
      ? 'UnifiedPush web-push (VAPID) enabled'
      : 'UnifiedPush web-push (VAPID) NOT configured'
  );
  // M-1: без токена /metrics доступен ТОЛЬКО из приватной сети/localhost (публичный
  // скрейп отвергается). Для внешнего мониторинга задайте RELAY_METRICS_TOKEN.
  logMetricsAccess();
});

// Программный runtime-контракт нужен для встраивания релея в служебный процесс
// и для адресной проверки тех же обработчиков, которые обслуживают сеть.
module.exports.runtime = {
  server,
  wss,
  store,
  online,
  accountOnline,
  counters,
  eventLoopLag,
  sampleEventLoopLag,
  sweepPushGates,
  sweepOtpDrain,
  heartbeatConnections,
  expireQueuedEnvelopes,
  turnIceServers,
  learnRelays,
  eventLoopLagP99,
  relayOverloaded,
  renderMetrics,
  safeEqual,
  metricsAuthorized,
  readJsonRequest,
  vapidRequestRateAllowed,
  rememberVapidRequest,
  handleVapidFleetHttpWith,
  handleVapidFleetHttp,
  unindexAccountSocket,
  indexAccountSocket,
  broadcastAccount,
  clientIp,
  nextId,
  verifySignature,
  hmacSha512,
  concatU8,
  verifyBoxProof,
  loadOrCreateRelaySignKeys,
  signRelayAuth,
  activateVapid,
  resolveVapidKeysWith,
  resolveVapidKeys,
  resolveTurnSecret,
  startEmbeddedCoturn,
  stopEmbeddedCoturn,
  verifySpkSignature,
  flushFrameBatch,
  sendImmediate,
  frameBatchBytes,
  send,
  sendBinary,
  queuedMessageFrame,
  queuedBinaryHeader,
  senderMetadata,
  flushQueue,
  flushBinaryQueue,
  deliver,
  deliverBinary,
  ackReceived,
  ackBinaryReceived,
  rateLimited,
  byteLimited,
  closeRevokedDevice,
  acceptSignedRoster,
  bindSocketToCertifiedDevice,
  enforceAuthTimeout,
  handleSocketMessage,
  handleBinaryFrameSafely,
  sendPushTestResult,
  handleFrameSafely,
  relayHttpBase,
  hostOf,
  safePeerAddrs,
  pinnedLookup,
  httpJson,
  fetchPeerRelays,
  pushSelfTo, mirroredRelease, verifyReleaseSignature, fetchText, mirrorPlatform, mirroredTreeVersion, mirrorTree, maintainUpdateMirror,
  vapidSyncWith,
  vapidSyncOnce,
  gossipOnce,
  scheduleFederation,
  performShutdown,
  createShutdownHandler,
  shutdown,
  isFatalDbError,
  handleTopLevelError,
  handleServerError,
  logMetricsAccess,
};
