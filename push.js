/**
 * push.js — send FCM (Firebase Cloud Messaging) pushes so a recipient gets a
 * notification even when the app is fully closed.
 *
 * Privacy: the push carries NO message content and NO contact name — the server
 * only knows public keys. It just says "new encrypted message". The real text
 * is pulled from the queue (still E2E-encrypted) when the app opens.
 *
 * Config — ЛЮБОЙ из способов:
 *   1. Просто положить service-account.json в каталог данных (/data в Docker,
 *      рядом с relay.js на bare-metal) — файл найдётся сам, project_id
 *      прочитается из него. Ничего настраивать не нужно.
 *   2. Классически через env: FCM_PROJECT_ID + GOOGLE_APPLICATION_CREDENTIALS.
 * If unset, pushes are silently skipped (relay still works, just no wake-ups).
 */
const fs = require('fs');
const path = require('path');
const dns = require('dns').promises;
const https = require('https');
const webpush = require('web-push');
const { isPrivateHost } = require('./relays');
const { deviceVapidKeys, vapidSubject } = require('./vapid-identity');

// S13: кастомный lookup для web-push — отдаёт ТОЛЬКО заранее проверенные адреса
// (пиннинг), игнорируя повторное разрешение имени. Между проверкой и коннектом имя
// уже не переразрешается → окно DNS-rebinding (TOCTOU) закрыто. Имя хоста
// сохраняется для SNI/валидации TLS-сертификата (сертификат по-прежнему сверяется).
function pinnedLookup(pinned) {
  return (hostname, options, cb) => {
    if (options && options.all) return cb(null, pinned);
    cb(null, pinned[0].address, pinned[0].family);
  };
}

function loadGoogleAuth(load = require) {
  try {
    return load('google-auth-library').GoogleAuth || null;
  } catch (e) {
    return null;
  }
}
const GoogleAuth = loadGoogleAuth();

// Автопоиск service-account.json: env → каталог данных (volume) → рядом с кодом.
function autoDetectCredentials() {
  const candidates = [
    process.env.GOOGLE_APPLICATION_CREDENTIALS,
    path.join(path.dirname(process.env.RELAY_DB || path.join(__dirname, 'relay.db')), 'service-account.json'),
    path.join(__dirname, 'service-account.json'),
  ].filter(Boolean);
  for (const p of candidates) {
    try {
      if (fs.existsSync(p)) return p;
    } catch (e) {
      // Кандидат может лежать на недоступном пути (нет прав на каталог тома).
      // Это не повод падать на старте — проверяем следующий, а вернув null,
      // релей просто работает без FCM.
    }
  }
  return null;
}

const CREDENTIALS_FILE = autoDetectCredentials();
function applyCredentialsFile(credentialsFile, env = process.env) {
  if (credentialsFile && !env.GOOGLE_APPLICATION_CREDENTIALS) {
  // google-auth-library читает путь из этой переменной
    env.GOOGLE_APPLICATION_CREDENTIALS = credentialsFile;
  }
}
applyCredentialsFile(CREDENTIALS_FILE);

function detectProjectId(credentialsFile = CREDENTIALS_FILE, env = process.env, readFile = fs.readFileSync) {
  if (env.FCM_PROJECT_ID) return env.FCM_PROJECT_ID;
  if (!credentialsFile) return null;
  try {
    return JSON.parse(readFile(credentialsFile, 'utf8')).project_id || null;
  } catch (e) {
    return null;
  }
}

const PROJECT_ID = detectProjectId();
let auth = null;
let warned = false;

function ready(options = {}) {
  const {
    projectId = PROJECT_ID,
    env = process.env,
    googleAuth = GoogleAuth,
    log = console.log,
  } = options || {};
  if (projectId && env.GOOGLE_APPLICATION_CREDENTIALS && googleAuth) return true;
  if (!warned) {
    log('[push] FCM not configured — skipping wake-up pushes');
    warned = true;
  }
  return false;
}

async function accessToken() {
  if (!auth) {
    auth = new GoogleAuth({ scopes: ['https://www.googleapis.com/auth/firebase.messaging'] });
  }
  const client = await auth.getClient();
  const t = await client.getAccessToken();
  return t.token;
}

async function fcmSend(message) {
  if (!ready()) return false;
  try {
    const at = await accessToken();
    const res = await fetch(`https://fcm.googleapis.com/v1/projects/${PROJECT_ID}/messages:send`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${at}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ message }),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      console.log('[push] FCM error', res.status, text.slice(0, 200));
      if (res.status === 404 || res.status === 400) return 'invalid';
      return false;
    }
    return true;
  } catch (e) {
    console.log('[push] send failed:', e.message);
    return false;
  }
}

// ---------------------------------------------------------------------------
// UnifiedPush (web-push / VAPID) — открытый push БЕЗ Google (F-Droid / de-Googled).
// ---------------------------------------------------------------------------
//
// Клиент (expo-unified-push) регистрируется у дистрибьютора (ntfy) и получает
// web-push ПОДПИСКУ: { endpoint, keys:{ p256dh, auth } }. Она передаётся релею
// кадром register (JSON-строкой в поле pushToken). Релей шлёт ЗАШИФРОВАННЫЙ
// web-push (VAPID + RFC 8291); expo-unified-push расшифровывает и РИСУЕТ
// уведомление НАТИВНО из формы Notification { id, title?, body? } — контента
// сообщения в пуше нет (как и в FCM), только обобщённый текст.
//
// VAPID-пара релея: env RELAY_VAPID_PUBLIC/PRIVATE или персист в файле рядом с БД
// (relay.js resolveVapidKeys → setVapidKeys). Клиент забирает публичный ключ из
// кадра ready и передаёт в registerDevice. Во ФЕДЕРАЦИИ пуш шлёт лишь релей, у
// которого есть VAPID-приватный ключ подписки — как и с FCM service-account
// (доверенный релей).
//
// ВЫС-51: БАЗОВАЯ пара — общая у флота, а КЛИЕНТУ она не выдаётся никогда.
//
// Раньше выдавалась: одна пара на весь флот плюс постоянный subject означали,
// что push-провайдер (FCM/Mozilla/Apple) видит все подписки «Лично» одной
// группой и в любой момент отвечает на вопрос «сколько у этого мессенджера
// устройств, где они и когда их будят». Теперь из базового секрета выводится
// ПАРА НА УСТРОЙСТВО (vapid-identity.js): и кадр ready, и подпись пуша берут
// ключ, выведенный из адреса получателя. Базовый секрет при этом остаётся общим
// — только благодаря этому любой релей флота, у которого осела очередь, выводит
// ту же пару и может разбудить устройство.

const UP_MAX_ENDPOINT_LEN = 512;
const UP_MAX_SUB_LEN = 1024; // подписка (endpoint + ключи) длиннее FCM-токена

// Коды, которыми push-сервис отвечает на «подпись не тем ключом»: Mozilla —
// 401, FCM/Apple — 403, часть реализаций — 400. Отзыв подписки это НЕ значит
// (он приходит как 404/410), поэтому здесь уместна вторая попытка, а не
// удаление токена.
const VAPID_REJECTED = new Set([400, 401, 403]);

let vapidConfigured = false;
let vapidBase = null; // { publicKey, privateKey } — базовая пара узла
let vapidContact = null; // subject RFC 8292: контакт этого узла, а не всего флота
/**
 * Задать базовую VAPID-пару релея (зовётся из relay.js после resolveVapidKeys).
 * `selfUrl` — собственный адрес узла: из него делается контакт по умолчанию.
 */
function setVapidKeys(publicKey, privateKey, subject, selfUrl) {
  try {
    // RFC 8292 contact URI. Реальный HTTPS-домен лучше .invalid: push-сервис
    // может использовать subject для связи с оператором при злоупотреблениях.
    // ВЫС-51: по умолчанию это адрес САМОГО УЗЛА, а не общая для флота
    // константа, — провайдер и так видит IP запроса и нового не узнаёт.
    const contact = vapidSubject(selfUrl, subject);
    webpush.setVapidDetails(contact, publicKey, privateKey);
    vapidBase = { publicKey, privateKey };
    vapidContact = contact;
    vapidConfigured = true;
    return true;
  } catch (e) {
    console.warn('[push] VAPID некорректен:', e && e.message);
    vapidConfigured = false;
    return false;
  }
}
/**
 * Базовый публичный ключ узла — для /health и сверки флота между собой.
 * КЛИЕНТУ он больше не выдаётся: у клиента своя пара (vapidPublicKeyFor).
 */
function vapidPublicKey() {
  return vapidConfigured && vapidBase ? vapidBase.publicKey : null;
}

/**
 * Пара, которой подписываются пуши на это устройство.
 *
 * Без адреса (старый вызов, диагностика без привязки) остаётся базовая пара:
 * потерять уведомление хуже, чем отдать провайдеру один общий ключ. Вывод, не
 * давший пары (базовый секрет неожиданной формы), сюда же и приводит.
 */
function vapidKeysFor(address) {
  if (!vapidConfigured || !vapidBase) return null;
  return deviceVapidKeys(vapidBase.privateKey, address) || vapidBase;
}

/**
 * Публичный VAPID-ключ ЭТОГО устройства для кадра ready (null — web-push не
 * настроен). Адрес приходит из аутентифицированного соединения, поэтому узнать
 * чужой ключ таким запросом нельзя — только свой.
 */
function vapidPublicKeyFor(address) {
  const keys = vapidKeysFor(address);
  return keys ? keys.publicKey : null;
}

/** Литеральная (без DNS) валидация endpoint: http(s), длина, хост не приватный. */
function validUnifiedPushEndpoint(endpoint) {
  if (typeof endpoint !== 'string' || !endpoint || endpoint.length > UP_MAX_ENDPOINT_LEN) return false;
  let u;
  try {
    u = new URL(endpoint);
  } catch (e) {
    return false;
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return false;
  if (isPrivateHost(u.hostname)) return false;
  return true;
}

/**
 * Разобрать сохранённый токен как web-push подписку. Возвращает { endpoint, keys }
 * либо null (тогда это обычный FCM-токен). Валидирует форму, endpoint и SSRF
 * (литерально). Экспортируется для тестов.
 */
function parseSubscription(token) {
  if (typeof token !== 'string' || !token || token.length > UP_MAX_SUB_LEN) return null;
  if (token[0] !== '{') return null; // FCM-токен — не JSON
  let s;
  try {
    s = JSON.parse(token);
  } catch (e) {
    return null;
  }
  if (!s || typeof s.endpoint !== 'string' || !validUnifiedPushEndpoint(s.endpoint)) return null;
  const k = s.keys || {};
  if (typeof k.p256dh !== 'string' || !k.p256dh || typeof k.auth !== 'string' || !k.auth) return null;
  return { endpoint: s.endpoint, keys: { p256dh: k.p256dh, auth: k.auth } };
}

/** Это web-push подписка (UnifiedPush), а не FCM-токен? */
function isUnifiedPushEndpoint(token) {
  return parseSubscription(token) !== null;
}

let notifSeq = 0;
const MESSAGE_NOTIFICATION_ID = 1279877966; // стабильный id: новые сообщения обновляют одну карточку
const CALL_NOTIFICATION_ID = 1279877967;

/**
 * Отправить зашифрованный web-push на подписку. notification — форма expo-unified-
 * push { title, body } (id проставляем сами). SSRF: endpoint приходит от клиента,
 * поэтому резолвим и отвергаем приватные адреса ПЕРЕД отправкой (web-push-
 * библиотека ходит сама, без кастомного lookup; литеральный + резолв-чек закрывают
 * основной вектор). Возвращает true | false | 'invalid' (подписка отозвана).
 *
 * ВЫС-51 (переход на пару устройства). Подписка выпускается ПОД КОНКРЕТНЫЙ
 * ключ: push-сервис сверяет подпись с тем ключом, который клиент указал при
 * подписке, и чужой отвергает. Значит подписки, выпущенные ДО этой доработки
 * (под общий ключ флота), новым ключом не подписать — а молча перестать будить
 * уже установленные приложения нельзя.
 *
 * Поэтому переход такой: подписываем парой устройства, а на отказ «не тот
 * отправитель» повторяем прежней общей парой. Обе живут рядом, пока клиент не
 * перевыпустит подписку — он это делает сам при следующем запуске, потому что
 * `ready` уже отдаёт ему новый ключ и registerDevice/subscribe идут с ним.
 * Разовая лишняя попытка на старую подписку дешевле пропавшего уведомления, а
 * с новыми подписками её не бывает вовсе.
 */
async function unifiedPushSend(sub, notification, address) {
  if (!vapidConfigured) return false; // VAPID не задан — web-push не шлём
  const parsed = typeof sub === 'string' ? parseSubscription(sub) : sub;
  if (!parsed) return 'invalid';
  let pinned;
  try {
    const host = new URL(parsed.endpoint).hostname;
    if (isPrivateHost(host)) return 'invalid';
    const addrs = await dns.lookup(host, { all: true });
    if (!addrs.length) return false;
    for (const a of addrs) if (isPrivateHost(a.address)) return 'invalid';
    pinned = addrs.map((a) => ({ address: a.address, family: a.family }));
  } catch (e) {
    return false; // не резолвится — не ходим
  }
  try {
    notifSeq = (notifSeq + 1) % 1e9;
    const body = JSON.stringify({ id: notification.id || notifSeq, ...notification });
    // S13: коннектимся РОВНО на проверенные IP (пиннинг через agent.lookup). Раньше
    // web-push резолвил хост заново своим стеком — вредоносный DNS мог отдать
    // публичный IP на проверке и приватный на самом запросе (self-SSRF/rebinding).
    const agent = new https.Agent({ lookup: pinnedLookup(pinned), keepAlive: false });
    const deliver = (keys) =>
      webpush.sendNotification(parsed, body, {
        TTL: 3600,
        agent,
        vapidDetails: { subject: vapidContact, publicKey: keys.publicKey, privateKey: keys.privateKey },
      });
    const keys = vapidKeysFor(address);
    let res;
    try {
      res = await deliver(keys);
    } catch (e) {
      if (keys === vapidBase || !VAPID_REJECTED.has(e && e.statusCode)) throw e;
      res = await deliver(vapidBase); // подписка выпущена ещё под общий ключ флота
    }
    return !!res && res.statusCode >= 200 && res.statusCode < 300;
  } catch (e) {
    const code = e && e.statusCode;
    if (code === 404 || code === 410) return 'invalid'; // подписка отозвана
    console.log('[push] web-push send failed:', (e && e.message) || e);
    return false;
  }
}

/**
 * Content-free wake-up push for a new message. FCM или web-push (UnifiedPush).
 *
 * ПРФ-4: `chatTag` — НЕПРОЗРАЧНЫЙ признак чата (хэш адреса отправителя, см.
 * relay.chatNotificationTag). Он едет ТОЛЬКО в web-push, тело которого
 * зашифровано ключами подписки: провайдер пуша его не читает, а устройство
 * получает возможность не схлопывать уведомления разных чатов в одно.
 *
 * В FCM тег НЕ передаётся сознательно: тело FCM-сообщения уходит Google
 * открытым текстом, и стабильный признак отправителя дал бы ему псевдоним для
 * подсчёта «сколько разных людей пишет этому устройству и когда» — это
 * метаданные социального графа, ровно то, что мессенджер обязан скрывать.
 * Поэтому на FCM-пути остаётся прежний общий тег: там уведомления по-прежнему
 * схлопываются, зато Google не узнаёт ничего нового.
 *
 * АУД-Э1: `messageId` подчиняется ТОМУ ЖЕ правилу и по той же причине.
 *
 * Раньше он уходил в FCM, и вся его обработка сводилась к обрезке до 160
 * символов — а приходит он от клиента. Клиент кладёт туда публичный ключ:
 * `src/groups.js` формирует метку как «идентификатор сообщения : публичный ключ
 * участника», и 44 символа base64 помещаются в лимит целиком. То есть рядом с
 * токеном устройства Google передавался адрес получателя в «Лично», а общий
 * идентификатор у копий одного группового сообщения позволял ещё и связать
 * токены между собой — восстановив состав группы и список устройств человека.
 *
 * Схлопывание уведомлений на FCM-пути от этого не страдает: за него отвечает
 * `tag: 'new-message'`, а не идентификатор. Гашение уже показанного уведомления
 * по приходу сообщения работало и раньше лишь частично — клиент сопоставляет
 * его со СВОИМ `mid`, который с клиентской меткой веера не совпадает.
 *
 * ВЫС-51: `address` — адрес получателя. По нему выводится VAPID-пара устройства
 * (web-push). Ни в тело уведомления, ни в FCM он не попадает: это ключевой
 * материал, а не поле сообщения.
 */
async function sendPush(token, messageId, chatTag, address) {
  if (!token) return false;
  const sub = parseSubscription(token);
  const safeMessageId = typeof messageId === 'string' ? messageId.slice(0, 160) : '';
  // Тег недоверенной длины/формы в теле уведомления не нужен: берём только
  // безопасный алфавит base64url и ограничиваем длину.
  const safeChatTag =
    typeof chatTag === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(chatTag) ? chatTag : '';
  if (sub) {
    return unifiedPushSend(
      sub,
      {
        id: MESSAGE_NOTIFICATION_ID,
        title: 'Лично',
        body: 'Новое зашифрованное сообщение',
        type: 'message',
        messageId: safeMessageId,
        chatTag: safeChatTag,
        data: { type: 'message', messageId: safeMessageId, chatTag: safeChatTag },
      },
      address
    );
  }
  return fcmSend(messageFcmPayload(token));
}

/**
 * Тело FCM-уведомления о новом сообщении.
 *
 * Вынесено отдельной чистой функцией, чтобы состав полей можно было проверить
 * тестом. Всё, что здесь появится, уходит Google открытым текстом — поэтому
 * поле, добавленное сюда без разбора, стоит дороже обычной ошибки: увидеть его
 * в code review трудно, а последствия не откатываются (отправленное уже
 * отправлено).
 */
function messageFcmPayload(token) {
  return {
    token,
    notification: { title: 'Лично', body: 'Новое зашифрованное сообщение' },
    // tag: одинаковый у всех message-пушей — новое уведомление ЗАМЕНЯЕТ
    // предыдущее на устройстве, а не добавляется рядом. Даже если дубли
    // придут с нескольких релеев, пользователь увидит одно уведомление.
    android: { priority: 'HIGH', notification: { channel_id: 'messages', tag: 'new-message' } },
    // АУД-Э1: ничего, кроме типа. Идентификатор сообщения отсюда убран — он
    // приходил от клиента и содержал публичный ключ получателя.
    data: { type: 'message' },
  };
}

/** High-priority ring push for an incoming call. FCM или web-push (UnifiedPush). */
async function sendCallPush(token, address) {
  if (!token) return false;
  const sub = parseSubscription(token);
  if (sub) {
    return unifiedPushSend(
      sub,
      {
        id: CALL_NOTIFICATION_ID,
        title: 'Входящий звонок',
        body: 'Нажмите, чтобы ответить',
        type: 'call',
        data: { type: 'call' },
      },
      address
    );
  }
  return fcmSend({
    token,
    notification: { title: 'Входящий звонок', body: 'Нажмите, чтобы ответить' },
    android: {
      priority: 'HIGH',
      notification: { channel_id: 'calls', sound: 'default', tag: 'incoming-call' },
    },
    data: { type: 'call' },
  });
}

/**
 * Контрольный push для диагностики в Профиле. testId не содержит пользовательских
 * данных и позволяет отличить принятие запроса провайдером от получения телефоном.
 */
async function sendTestPush(token, testId, channel = 'message', address) {
  if (!token || typeof testId !== 'string' || !testId) return false;
  const isCall = channel === 'call';
  const notification = {
    title: 'Лично · проверка уведомлений',
    body: isCall ? 'Проверка канала аудио- и видеозвонков' : 'Проверка канала сообщений',
    type: 'push-test',
    testId,
    channel: isCall ? 'call' : 'message',
  };
  const sub = parseSubscription(token);
  if (sub) return unifiedPushSend(sub, notification, address);
  return fcmSend({
    token,
    notification: { title: notification.title, body: notification.body },
    android: {
      priority: 'HIGH',
      notification: {
        channel_id: isCall ? 'calls' : 'messages',
        tag: `push-test-${isCall ? 'call' : 'message'}`,
        sound: isCall ? 'default' : undefined,
      },
    },
    data: { type: 'push-test', testId, channel: notification.channel },
  });
}

/** Сгенерировать новую VAPID-пару (для персиста в relay.js). */
function generateVapidKeys() {
  return webpush.generateVAPIDKeys();
}

module.exports = {
  sendPush,
  messageFcmPayload,
  sendCallPush,
  sendTestPush,
  pushReady: ready,
  setVapidKeys,
  vapidPublicKey,
  vapidPublicKeyFor,
  generateVapidKeys,
  isUnifiedPushEndpoint,
  validUnifiedPushEndpoint,
  parseSubscription,
  loadGoogleAuth,
  applyCredentialsFile,
  detectProjectId,
};
