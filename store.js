/**
 * store.js — встроенное хранилище релея на SQLite (self-contained, без внешних
 * сервисов). Заменяет in-memory Map + перезапись JSON-файлов, снимая потолок по
 * RAM и блокировки event-loop: очереди/identities/токены/каталог живут на диске
 * (в volume контейнера), запись инкрементальная, чтение по индексу.
 *
 * Это делает ОДИН релей production-grade; масштабирование сети = больше таких
 * независимых релеев (без общего Redis, который связал бы узлы в кластер).
 *
 * Чистый модуль (только БД, без сети/крипты) — тестируется отдельно
 * (server/store.test.js).
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const Database = require('better-sqlite3');
// ВЫС-15: правило приёма в очередь получателя — резерв под корреспондентов и
// вытеснение чужого спама. Чистое и проверяется отдельно от базы.
const { admitEnvelope } = require('./queueAdmission');
// ВЫС-31: сколько выбрасывать из переполненного ящика — правило отдельно от базы.
const { evictionSize } = require('./mailboxEvict');

// S9: потолок и TTL реплицированного каталога релеев. Держим только N самых свежих
// анонсов и вычищаем протухшие — иначе gossip-мусор навсегда забивал каталог.
const RELAY_DIR_MAX = 500;
const RELAY_DIR_TTL_MS = 14 * 24 * 3600 * 1000; // 14 дней без анонса — забываем релей

// ГРФ-3: сколько держать редакцию отозванного устройства. Строку целиком не
// удаляем никогда (см. redactRevokedDevices), но человекочитаемое имя и полный
// сертификат стираем через этот срок после отзыва.
const REVOKED_DEVICE_REDACT_MS = 30 * 24 * 3600 * 1000; // 30 дней

// ГРФ-1: разовый VACUUM после миграции запускаем только на небольших базах —
// на многогигабайтной он занял бы минуты при старте и потребовал бы вдвое больше
// места на volume. Крупным релеям пишем в лог инструкцию сделать это руками.
const MIGRATION_VACUUM_MAX_BYTES = 512 * 1024 * 1024;

// ---------------------------------------------------------------------------
// ГРФ-1: ключ шифрования метаданных отправителя «на покое»
// ---------------------------------------------------------------------------
//
// ЧТО БЫЛО НЕ ТАК. В таблице queue рядом с шифртекстом лежали открытым текстом
// from_pk, from_account, from_device, device_cert и device_roster, а поверх
// (from_pk, to_pk, ts) стоял индекс — то есть готовая структура «кто кому и
// когда». Дампа базы (или её копии в бэкапе) хватало, чтобы восстановить граф
// общения всех, у кого хоть раз была непрочитанная очередь. Модуль
// src/sealedSender.js при этом утверждал обратное: «в базе данных отправителя
// больше нет». Запечатывание убирало отправителя из КОНВЕРТА, но релей тут же
// приписывал его обратно из аутентифицированного соединения.
//
// ПОЧЕМУ НЕЛЬЗЯ ПРОСТО УДАЛИТЬ. Эти поля не служебные: получателю, который был
// офлайн, они доставляются в кадре и без них связанное устройство отправителя не
// опознаётся (src/relay.js: resolveIncomingSender строит accountPublicKey из
// fromAccount и проверяет сертификат с roster). Хеш тут не подходит — из хеша
// кадр не соберёшь.
//
// КАК УСТРОЕНО. Метаданные складываются в ОДИН блоб, зашифрованный AES-256-GCM
// на ключе, который лежит НЕ в базе, а отдельным файлом `<база>.metakey` с
// правами 0600. Квоты на пару «отправитель→получатель» переехали на pair_tag —
// усечённый HMAC от пары на отдельном подключе; по нему же построен индекс.
//
// ЧТО ЭТО ДАЁТ И ЧЕГО НЕ ДАЁТ. Даёт: копия только базы (bak/replica/`.dump`,
// украденный бэкап, оператор с SQL-доступом) больше не содержит ни отправителей,
// ни пары «кто→кому» — ни в строках, ни в индексе. НЕ даёт: изъятие ВСЕГО
// volume забирает и файл ключа; наблюдающий за живым трафиком оператор видит
// пару в момент отправки, а процесс держит ключ в памяти. Это ровно та граница,
// которую честно описывает шапка src/sealedSender.js.
const AT_REST_KEY_SUFFIX = '.metakey';

function loadAtRestKey(dbPath) {
  // Для :memory: (тесты, эфемерный релей) файл заводить незачем: база не
  // переживает процесс, поэтому ключу достаточно жить в памяти.
  if (!dbPath || dbPath === ':memory:') return crypto.randomBytes(32);
  const keyPath = dbPath + AT_REST_KEY_SUFFIX;
  try {
    const raw = fs.readFileSync(keyPath, 'utf8').trim();
    const key = Buffer.from(raw, 'hex');
    if (key.length === 32) return key;
    console.warn('[store] файл ключа метаданных повреждён, создаю новый:', keyPath);
  } catch (error) {
    if (error.code !== 'ENOENT') {
      console.warn('[store] не удалось прочитать ключ метаданных', keyPath, error.message);
    }
  }
  const key = crypto.randomBytes(32);
  try {
    // wx падает, если файл возник между чтением и записью (гонка двух стартов):
    // тогда перечитываем чужой ключ, а не затираем его своим.
    fs.writeFileSync(keyPath, key.toString('hex'), { mode: 0o600, flag: 'wx' });
  } catch (error) {
    if (error.code === 'EEXIST') {
      const raw = fs.readFileSync(keyPath, 'utf8').trim();
      const existing = Buffer.from(raw, 'hex');
      if (existing.length === 32) return existing;
    }
    // Ключ не сохранился (read-only volume, нет прав). Работаем на эфемерном:
    // очередь переживёт процесс, но метаданные после перезапуска не откроются —
    // это хуже, чем плохо, поэтому кричим в лог, а не молчим.
    console.warn(
      '[store] не удалось сохранить ключ метаданных',
      keyPath,
      error.message,
      '— метаданные отправителя не переживут перезапуск'
    );
  }
  return key;
}

function subKey(master, label) {
  return crypto.createHmac('sha256', master).update(label).digest();
}

/**
 * opts.blobDir       — каталог для тел крупных конвертов (обычно рядом с БД, в
 *                      том же volume). Не задан — всё хранится в БД, как раньше.
 * opts.blobThreshold — порог в байтах: конверт крупнее уходит файлом на диск,
 *                      в очереди остаётся только ссылка (blob=1). Держит БД
 *                      маленькой и быстрой при потоке фото/видео офлайн-получателям.
 */
function createStore(dbPath, opts = {}) {
  const blobDir = opts.blobDir || null;
  const blobThreshold = opts.blobThreshold || 64 * 1024;
  if (blobDir) fs.mkdirSync(blobDir, { recursive: true });

  const db = new Database(dbPath || ':memory:');
  db.pragma('journal_mode = WAL'); // конкурентные чтения не блокируют запись
  db.pragma('synchronous = NORMAL');
  // ГРФ-2: затирать удалённое, а не просто помечать страницу свободной.
  //
  // Очередь — не журнал: строка живёт от постановки до квитанции (обычно
  // секунды). Но без secure_delete удалённая строка остаётся в файле базы и в
  // WAL до тех пор, пока страницу не переиспользуют, — то есть дамп диска отдавал
  // ИСТОРИЮ доставок, а не только то, что ждёт сейчас. Именно на этом держалось
  // обещание «дамп базы не восстанавливает граф общения», которого не было.
  //
  // Цена. ON заставляет SQLite обнулять освобождаемое место; там, где страницу
  // иначе не пришлось бы читать, появляется лишнее чтение+запись. Замер на этой
  // схеме (20 000 циклов INSERT+DELETE строки ~700 байт, WAL, synchronous=NORMAL,
  // два индекса): OFF 2,69/2,73 с, FAST 2,50/2,96 с, ON 2,63/2,71 с — разница в
  // пределах разброса между прогонами. Так и должно быть: удаляемая строка почти
  // всегда лежит на странице, которую транзакция и так переписывает, а тела
  // крупных конвертов в БД не хранятся вовсе (blobDir) — обнулять мегабайтные
  // ячейки не приходится. Поэтому берём ON, а не компромиссный FAST: FAST
  // пропускает зануление там, где оно стоило бы лишнего ввода-вывода, то есть
  // оставляет ровно те остатки, ради которых всё и затевалось.
  //
  // Чего НЕ закрывает: файлы-блобы в blobDir удаляются unlink'ом — их содержимое
  // остаётся на диске до перезаписи ФС. Там лежит только шифртекст, но факт
  // «этому получателю приходило вложение такого размера» переживает удаление.
  db.pragma('secure_delete = ON');
  db.exec(`
    CREATE TABLE IF NOT EXISTS queue (
      id        TEXT PRIMARY KEY,
      to_pk     TEXT NOT NULL,
      envelope  TEXT NOT NULL,
      silent    INTEGER DEFAULT 0,
      call_push INTEGER DEFAULT 0,
      ts        INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_queue_to ON queue(to_pk, ts);
    -- Бинарные чанки вложений хранятся raw-файлами, без base64/JSON тела.
    CREATE TABLE IF NOT EXISTS binary_queue (
      id           TEXT PRIMARY KEY,
      to_pk        TEXT NOT NULL,
      ref          TEXT,
      transfer_id  TEXT NOT NULL,
      chunk_index  INTEGER NOT NULL,
      total_chunks INTEGER NOT NULL,
      bytes        INTEGER NOT NULL,
      ts           INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_binary_queue_to ON binary_queue(to_pk, ts);
    -- ПЯЩ-1: общий ящик записок «ищи меня вот здесь».
    --
    -- Ни поля владельца, ни поля получателя здесь НЕТ — и взять их неоткуда:
    -- ключ выведен из секрета, который есть только у двоих, значение
    -- зашифровано, метку узел проверить не может. Оператор при всём желании не
    -- скажет, чья записка лежит у него на диске.
    --
    -- Первичный ключ (key, vh) допускает ДВЕ строки под одним ключом: иначе
    -- враждебный узел клал бы под чужой ключ подделку и вытеснял настоящую
    -- записку, а адресат, сверяя метку, молча ничего не находил бы. vh — хеш
    -- значения и метки вместе, чтобы «та же записка вторым путём» не плодила
    -- строк, а подделка не выдавала себя за неё.
    --
    -- seq нужен репликации между узлами: сосед тянет всё, что появилось после
    -- его курсора, и не пересылает то, что уже видел.
    CREATE TABLE IF NOT EXISTS mbx (
      key  BLOB NOT NULL,
      vh   BLOB NOT NULL,
      val  BLOB NOT NULL,
      mac  BLOB NOT NULL,
      slot INTEGER NOT NULL,
      seq  INTEGER NOT NULL,
      PRIMARY KEY (key, vh)
    );
    CREATE INDEX IF NOT EXISTS idx_mbx_seq ON mbx(seq);
    -- ОТЧ-1: отчёты о неполадках, оставленные приложениями.
    --
    -- Тело запечатано на публичный ключ владельца приложения: узел его не
    -- читает и прочитать не может — у него нет секретной половины. Здесь
    -- лежат только непрозрачные байты и время приёма, по которому отчёт
    -- уходит по сроку, если владелец за ним не пришёл. Ни адреса отправителя,
    -- ни чего-либо, что связало бы отчёт с человеком, таблица не хранит.
    CREATE TABLE IF NOT EXISTS reports (
      id   TEXT PRIMARY KEY,
      at   INTEGER NOT NULL,
      body TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_reports_at ON reports(at);
    CREATE TABLE IF NOT EXISTS identities  (pk TEXT PRIMARY KEY, sign_pk TEXT NOT NULL, proven INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS push_tokens (pk TEXT PRIMARY KEY, token TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS directory   (url TEXT PRIMARY KEY, last_seen INTEGER);
    -- X3DH: публичные prekey пользователей (подписанный + одноразовые).
    -- Релей хранит ТОЛЬКО публичные половинки; расшифровать ими ничего нельзя.
    CREATE TABLE IF NOT EXISTS prekeys_spk (pk TEXT PRIMARY KEY, id TEXT NOT NULL, pub TEXT NOT NULL, sig TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS prekeys_otp (pk TEXT NOT NULL, id TEXT NOT NULL, pub TEXT NOT NULL, PRIMARY KEY (pk, id));
    -- Связанные устройства v2. Существующие таблицы/адреса не меняются:
    -- account_pk равен прежнему публичному ключу основного телефона, а device_pk
    -- адресует отдельную очередь/токен/prekey конкретного устройства.
    CREATE TABLE IF NOT EXISTS accounts (
      account_pk     TEXT PRIMARY KEY,
      root_sign_pk   TEXT NOT NULL,
      roster_version INTEGER NOT NULL DEFAULT 0,
      roster_json    TEXT,
      updated_at     INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS account_devices (
      account_pk     TEXT NOT NULL,
      device_id      TEXT NOT NULL,
      device_pk      TEXT NOT NULL UNIQUE,
      device_sign_pk TEXT NOT NULL,
      certificate    TEXT NOT NULL,
      name           TEXT NOT NULL,
      platform       TEXT NOT NULL,
      issued_at      INTEGER NOT NULL,
      revoked_at     INTEGER,
      last_seen      INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (account_pk, device_id)
    );
    CREATE INDEX IF NOT EXISTS idx_account_devices_account ON account_devices(account_pk, revoked_at, issued_at);
    CREATE INDEX IF NOT EXISTS idx_account_devices_pk ON account_devices(device_pk);
  `);
  // Миграция существующих БД: колонка blob (1 = тело лежит файлом в blobDir).
  const hasBlobCol = db.prepare("SELECT count(*) c FROM pragma_table_info('queue') WHERE name='blob'").get().c;
  if (!hasBlobCol) db.exec('ALTER TABLE queue ADD COLUMN blob INTEGER DEFAULT 0');
  // S4: колонка bytes — размер конверта (тело в БД либо файл-blob). Нужна для
  // байтового потолка очереди и O(1)-учёта веса (см. liveBytes ниже). Старые
  // строки получают bytes=0 и добиваются реальным размером при старте (backfill).
  const hasBytesCol = db.prepare("SELECT count(*) c FROM pragma_table_info('queue') WHERE name='bytes'").get().c;
  if (!hasBytesCol) db.exec('ALTER TABLE queue ADD COLUMN bytes INTEGER DEFAULT 0');
  // Миграция (H-6): колонка proven — доказано ли владение box-ключом для этой
  // связки pk→sign_pk (см. relay.js: ECDH-proof). Старые связки остаются
  // proven=0 (легаси-совместимость), новые клиенты помечают их proven=1.
  const hasProvenCol = db.prepare("SELECT count(*) c FROM pragma_table_info('identities') WHERE name='proven'").get().c;
  if (!hasProvenCol) db.exec('ALTER TABLE identities ADD COLUMN proven INTEGER DEFAULT 0');
  // M-02: колонка last_seen — время последней аутентификации связки. Нужна для
  // LRU-вытеснения холодных identity при достижении глобального потолка (защита
  // диска от неограниченного роста каталога identity/prekey под Sybil-регистрацией).
  const hasLastSeenCol = db.prepare("SELECT count(*) c FROM pragma_table_info('identities') WHERE name='last_seen'").get().c;
  if (!hasLastSeenCol) db.exec('ALTER TABLE identities ADD COLUMN last_seen INTEGER DEFAULT 0');
  // БЕЗ-3: pq — публичная половина постквантового ключа ML-KEM-768. Хранится
  // рядом с классической и покрыта той же подписью владельца (релей её не
  // проверяет на подлинность содержимого, но и подменить не может: клиент
  // сверяет подпись сам). NULL у пользователей на прежней версии — тогда обмен
  // идёт по классической схеме.
  const hasSpkPqCol = db.prepare("SELECT count(*) c FROM pragma_table_info('prekeys_spk') WHERE name='pq'").get().c;
  if (!hasSpkPqCol) db.exec('ALTER TABLE prekeys_spk ADD COLUMN pq TEXT');
  // ГРФ-3: когда именно редактированы имя/сертификат отозванного устройства.
  // Отдельная колонка, а не «name IS NULL»: имя может законно отсутствовать у
  // легаси-строк, а нам нужно отличать «ещё не чистили» от «уже почищено».
  const deviceColumns0 = new Set(
    db.prepare("SELECT name FROM pragma_table_info('account_devices')").all().map((r) => r.name)
  );
  if (!deviceColumns0.has('redacted_at')) db.exec('ALTER TABLE account_devices ADD COLUMN redacted_at INTEGER');
  // ВЫС-31: порядок вытеснения записок, назначаемый УЗЛОМ при вставке.
  //
  // Не время и не ключ: время выбирает заливающий (он кладёт позже, значит
  // старейшими окажутся чужие), а ключ выбирает он же — записка кладётся с
  // любым ключом, и подобрать такой, что всегда идёт в конец очереди на
  // удаление, ничего не стоит. Случайное число, назначенное здесь, не выбирает
  // никто из них.
  //
  // У строк, лежавших до этой правки, значения нет — они уходят первыми. Это
  // верно: они и есть самые старые.
  const mbxColumns = new Set(
    db.prepare("SELECT name FROM pragma_table_info('mbx')").all().map((r) => r.name)
  );
  if (!mbxColumns.has('ord')) db.exec('ALTER TABLE mbx ADD COLUMN ord INTEGER');
  db.exec('CREATE INDEX IF NOT EXISTS idx_mbx_slot_ord ON mbx(slot, ord)');

  // --- ГРФ-1: метаданные отправителя — в зашифрованный блоб --------------------
  const columnsOf = (table) =>
    new Set(db.prepare(`SELECT name FROM pragma_table_info('${table}')`).all().map((r) => r.name));

  const metaKey = subKey(loadAtRestKey(dbPath), 'licno/queue-sender-meta/v1');
  const tagKey = subKey(metaKey, 'licno/queue-pair-tag/v1');

  /**
   * Запечатать метаданные отправителя. AES-256-GCM: помимо секретности даёт
   * целостность — подменённый в базе блоб не откроется, а не отдастся молча
   * искажённым. Возвращает Buffer (iv‖tag‖ct), чтобы не платить +33% base64 за
   * roster, который и так весит килобайты.
   */
  function sealMeta(value) {
    if (value == null) return null;
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', metaKey, iv);
    const body = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), body]);
  }

  /**
   * Открыть блоб. null — если ключ не тот (файл ключа потеряли/пересоздали),
   * блоб повреждён или его просто нет.
   *
   * Не бросаем и не сносим строку: без метаданных конверт всё равно доставляется,
   * и для отправителя без связанных устройств получатель опознаёт его по полю
   * `from` ВНУТРИ конверта. Ронять из-за этого всю очередь получателя нельзя.
   */
  function openMeta(blob) {
    if (!blob) return null;
    try {
      const buf = Buffer.isBuffer(blob) ? blob : Buffer.from(blob);
      if (buf.length < 28) return null;
      const decipher = crypto.createDecipheriv('aes-256-gcm', metaKey, buf.subarray(0, 12));
      decipher.setAuthTag(buf.subarray(12, 28));
      const plain = Buffer.concat([decipher.update(buf.subarray(28)), decipher.final()]);
      return JSON.parse(plain.toString('utf8'));
    } catch (error) {
      return null;
    }
  }

  /**
   * Метка пары «отправитель→получатель» для квот (S5/СРВ-2).
   *
   * Усечённый до 16 байт HMAC — не обратим без ключа, а для равенства пар
   * (единственное, что нужно квоте) 128 бит с запасом. Индекс строится по нему,
   * поэтому в базе больше нет структуры, перечисляющей «кто кому».
   */
  function pairTag(from, to) {
    if (!from) return null;
    return crypto
      .createHmac('sha256', tagKey)
      .update(String(from))
      .update('\u0000')
      .update(String(to))
      .digest()
      .subarray(0, 16);
  }

  {
    const qCols = columnsOf('queue');
    const bCols = columnsOf('binary_queue');
    if (!qCols.has('sender_meta')) db.exec('ALTER TABLE queue ADD COLUMN sender_meta BLOB');
    if (!qCols.has('pair_tag')) db.exec('ALTER TABLE queue ADD COLUMN pair_tag BLOB');
    if (!bCols.has('sender_meta')) db.exec('ALTER TABLE binary_queue ADD COLUMN sender_meta BLOB');
    if (!bCols.has('pair_tag')) db.exec('ALTER TABLE binary_queue ADD COLUMN pair_tag BLOB');
    // ВЫС-15: 1 — конверт от незнакомца (получатель этому отправителю не
    // писал). По флагу считается резерв и находится жертва вытеснения.
    if (!qCols.has('stranger')) db.exec('ALTER TABLE queue ADD COLUMN stranger INTEGER DEFAULT 0');
    if (!bCols.has('stranger')) db.exec('ALTER TABLE binary_queue ADD COLUMN stranger INTEGER DEFAULT 0');
    db.exec('CREATE INDEX IF NOT EXISTS idx_queue_stranger ON queue(to_pk, stranger, ts)');
    db.exec(
      'CREATE INDEX IF NOT EXISTS idx_binary_queue_stranger ON binary_queue(to_pk, stranger, ts)'
    );
    // ВЫС-15: метки пар, по которым НЕДАВНО проходили конверты. По ним очередь
    // отличает корреспондента (получатель ему сам писал) от незнакомца. Метка —
    // тот же усечённый HMAC, что и в квотах: ключей из неё не восстановить, а
    // срок и потолок не дают таблице стать вечным журналом.
    db.exec(`
      CREATE TABLE IF NOT EXISTS correspondents (tag BLOB PRIMARY KEY, ts INTEGER NOT NULL);
      CREATE INDEX IF NOT EXISTS idx_correspondents_ts ON correspondents(ts);
    `);

    // Индексы «кто→кому→когда» сносим ДО удаления колонок: SQLite не даёт
    // удалить проиндексированную колонку.
    db.exec('DROP INDEX IF EXISTS idx_queue_from_to');
    db.exec('DROP INDEX IF EXISTS idx_binary_queue_from_to');

    // Перенос уже накопленных строк.
    //
    // Пачками, а не одним SELECT: в очереди до RELAY_MAX_TOTAL_MESSAGES строк, и
    // у каждой в device_roster может лежать несколько килобайт — материализовать
    // всё разом значило бы съесть сотни мегабайт при старте. Пачка = транзакция,
    // маркер прогресса — сам sender_meta (он всегда непустой у перенесённой
    // строки), поэтому оборванная миграция продолжится с того же места.
    const legacyQueue = ['from_pk', 'from_account', 'from_device', 'device_cert', 'device_roster'].filter((c) =>
      qCols.has(c)
    );
    const legacyBinary = ['from_pk', 'meta_json'].filter((c) => bCols.has(c));
    const migrated = legacyQueue.length || legacyBinary.length;
    if (migrated) {
      const BATCH = 500;
      const parse = (raw) => {
        if (!raw) return undefined;
        try {
          return JSON.parse(raw);
        } catch (error) {
          return undefined;
        }
      };
      const drain = (table, columns, toMeta) => {
        const pick = db.prepare(
          `SELECT id, to_pk, ${columns.join(',')} FROM ${table} WHERE sender_meta IS NULL LIMIT ${BATCH}`
        );
        const set = db.prepare(`UPDATE ${table} SET sender_meta=?, pair_tag=? WHERE id=?`);
        const tx = db.transaction((rows) => {
          for (const row of rows) {
            set.run(sealMeta(toMeta(row)), pairTag(row.from_pk || null, row.to_pk), row.id);
          }
        });
        for (;;) {
          const rows = pick.all();
          if (!rows.length) break;
          tx(rows);
        }
      };
      if (legacyQueue.length) {
        drain('queue', legacyQueue, (row) => ({
          from: row.from_pk || undefined,
          fromAccount: row.from_account || row.from_pk || undefined,
          fromDeviceId: row.from_device || undefined,
          deviceCertificate: parse(row.device_cert),
          deviceRoster: parse(row.device_roster),
        }));
      }
      if (legacyBinary.length) {
        drain('binary_queue', legacyBinary, (row) => ({
          from: row.from_pk || undefined,
          metadata: parse(row.meta_json),
        }));
      }
      // Колонки сносим только после того, как ВСЁ перенесено: иначе прерванная
      // миграция унесла бы метаданные ещё не перенесённых строк.
      for (const col of legacyQueue) db.exec(`ALTER TABLE queue DROP COLUMN ${col}`);
      for (const col of legacyBinary) db.exec(`ALTER TABLE binary_queue DROP COLUMN ${col}`);
    }

    db.exec('CREATE INDEX IF NOT EXISTS idx_queue_pair ON queue(pair_tag, ts)');
    db.exec('CREATE INDEX IF NOT EXISTS idx_binary_queue_pair ON binary_queue(pair_tag, ts)');

    // DROP COLUMN переписывает строки, но освободившиеся страницы (со СТАРЫМ
    // открытым текстом) остаются в файле до переиспользования. secure_delete
    // задним числом их не чистит — это делает только VACUUM. На маленькой базе
    // выполняем сразу, на большой просим оператора: минуты простоя при старте и
    // двойной расход места на volume — не то, что делают молча.
    if (migrated && dbPath && dbPath !== ':memory:') {
      let size = 0;
      try {
        size = fs.statSync(dbPath).size;
      } catch (error) {
        size = 0;
      }
      if (size <= MIGRATION_VACUUM_MAX_BYTES) {
        db.exec('VACUUM');
        // В режиме WAL сам VACUUM пишет новые страницы в журнал, а СТАРЫЕ (с
        // открытым текстом) остаются в основном файле до контрольной точки.
        // Без этой строки чистка «сработала», но дамп файла базы по-прежнему
        // отдавал бы отправителей — ровно тот случай, когда мера успокаивает,
        // ничего не сделав.
        db.pragma('wal_checkpoint(TRUNCATE)');
      } else {
        console.warn(
          '[store] метаданные отправителя зашифрованы, но старые страницы с открытым текстом',
          'останутся в файле базы до `sqlite3',
          dbPath,
          'VACUUM` — выполните вручную в окно обслуживания'
        );
      }
    }
  }

  const blobPath = (mid) => path.join(blobDir, mid + '.json');
  const binaryPath = (mid) => path.join(blobDir, mid + '.bin');

  // ---------------------------------------------------------------------------
  // АУД-06: тела вложений пишутся на диск ВНЕ event-loop
  // ---------------------------------------------------------------------------
  //
  // Релей однопоточный. Пока идёт fs.writeFileSync на тридцать мегабайт, узел не
  // обслуживает НИКОГО: ни доставку, ни квитанции, ни heartbeat. Снаружи это
  // выглядит как «мессенджер подтормаживает» ровно тогда, когда кто-то отправил
  // видео, — и тем заметнее, чем больше людей на узле.
  //
  // Путей к диску ДВА, и раньше асинхронным сделали только первый, а описали это
  // так, будто закрыты оба:
  //   • JSON-конверт крупнее blobThreshold — файл <id>.json;
  //   • сырой чанк вложения (MAX_BINARY_CHUNK_BYTES = 300 КБ, до 4096 чанков на
  //     передачу) — файл <id>.bin. Это и есть путь фото и видео, ради которого
  //     всё затевалось, и он оставался полностью синхронным.
  // Замер (500 чанков по 300 КБ, три прогона): приём занимал петлю на 231–340 мс
  // суммарно, до 11,7 мс в одном тике, — стало 116–129 мс и до 9,1 мс, причём
  // остаток это уже не диск, а вставка в SQLite и AES-GCM метаданных. Реконнект
  // получателя с теми же 500 чанками — 100–110 мс СПЛОШНОЙ блокировки, потому
  // что relay.flushBinaryQueue вычитывает очередь тугим циклом в одном тике;
  // ровно на столько же опаздывал heartbeat. Через getBinaryItemAsync та же
  // очередь занимает петлю на 27–29 мс суммарно, максимум 0,38 мс за раз.
  //
  // КАК УСТРОЕНО. Один механизм на оба пути (writeBody): тело кладётся в карту
  // pending* и пишется через fs.promises во временный файл, затем rename. Строка
  // очереди появляется сразу, поэтому читатель может прийти за телом раньше, чем
  // оно легло на диск, — тогда он берёт его из pending*. В памяти тело живёт
  // только на время записи, и это не лишняя копия: и конверт, и чанк уже пришли
  // из сокета целиком, здесь держится ссылка на тот же буфер. Сколько таких тел
  // может накопиться, ограничено байтовым потолком очереди (maxTotalBytes):
  // строка учитывается в liveBytes сразу, а не по факту записи.
  //
  // Что с надёжностью. Окно между «строка есть» и «файл есть» существует и при
  // синхронной записи (fsync никто не звал), но здесь оно шире. Закрываем его
  // так: flushPendingBlobs дожидается всех начатых записей при штатной остановке
  // (close), а строка, чьё тело всё же не доехало, при чтении опознаётся и
  // сносится — этот путь был и раньше (rowToItem → dropRow). Потерять сообщение
  // молча по-прежнему невозможно: клиент держит его в своей очереди до квитанции.
  //
  // ЧТЕНИЕ. Выгрузка очереди (relay.flushQueue, flushBinaryQueue) ждёт промис и
  // пользуется getItemAsync/getBinaryItemAsync. Замер на 500 чанках по 300 КБ:
  // синхронный вариант держал петлю 102–111 мс ОДНИМ куском, асинхронный — 27–29
  // мс суммарно, максимум 0,38 мс за раз.
  //
  // Синхронные getItem/getBinaryItem остались: ими пользуются пути, где ждать
  // некому (квитанции, тесты). Оба варианта читают одно и то же и одинаково
  // берут тело из памяти, если оно ещё не доехало до диска.
  const pendingBlobs = new Map(); // mid -> { body: строка JSON, cancelled }
  const pendingBinaries = new Map(); // mid -> { body: Buffer чанка, cancelled }
  const bodyWrites = new Set(); // все незавершённые записи, включая отменённые

  /**
   * Записать тело файлом вне event-loop. Общая механика для конвертов и чанков:
   * два разных механизма в одном файле — гарантия, что следующий читатель починит
   * один и забудет второй.
   */
  function writeBody(pending, mid, file, body, what) {
    const entry = { body, cancelled: false };
    pending.set(mid, entry);
    const tmp = file + '.tmp';
    // tmp + rename: файл появляется атомарно, недописанных тел не бывает.
    const promise = fs.promises
      .writeFile(tmp, body)
      .then(async () => {
        // Строку могли удалить (ack, вытеснение, TTL), пока шла запись. Тогда
        // файл не нужен — иначе он остался бы сиротой, которую подберёт только
        // периодическая уборка.
        if (entry.cancelled) return fs.promises.unlink(tmp).catch(() => {});
        await fs.promises.rename(tmp, file);
        // Отмена могла случиться и МЕЖДУ записью и переименованием.
        if (entry.cancelled) await fs.promises.unlink(file).catch(() => {});
      })
      .catch((error) => {
        // Диск кончился/том только для чтения: строка очереди останется без тела
        // и будет снесена при первом же чтении (rowToItem/binaryRowToItem). Молча
        // это не проходит — иначе «сообщения пропадают» без единой строчки в логе.
        console.warn('[store] не удалось записать ' + what, mid, error && error.message);
        return fs.promises.unlink(tmp).catch(() => {});
      })
      .finally(() => {
        bodyWrites.delete(promise);
        if (pending.get(mid) === entry) pending.delete(mid);
      });
    bodyWrites.add(promise);
  }

  function writeBlob(mid, envJson) {
    writeBody(pendingBlobs, mid, blobPath(mid), envJson, 'тело конверта');
  }

  function writeBinary(mid, bytes) {
    if (!blobDir) throw new Error('binary blob directory is not configured');
    writeBody(pendingBinaries, mid, binaryPath(mid), bytes, 'чанк вложения');
  }

  /** Тело, ещё не доехавшее до диска. null — искать на диске как обычно. */
  function pendingBody(pending, mid) {
    const entry = pending.get(mid);
    return entry && !entry.cancelled ? entry.body : null;
  }

  const pendingBlob = (mid) => pendingBody(pendingBlobs, mid);
  const pendingBinary = (mid) => pendingBody(pendingBinaries, mid);

  function unlinkBody(pending, mid, file) {
    const entry = pending.get(mid);
    if (entry) {
      entry.cancelled = true; // запись доработает и уберёт за собой
      pending.delete(mid);
    }
    try {
      fs.unlinkSync(file);
    } catch (e) {
      // Тело могло уже исчезнуть (уборка сирот, ручное удаление тома). Запись,
      // если она ещё идёт, помечена cancelled выше и уберёт за собой сама.
    }
  }

  const unlinkBlob = (mid) => unlinkBody(pendingBlobs, mid, blobPath(mid));
  const unlinkBinary = (mid) => unlinkBody(pendingBinaries, mid, binaryPath(mid));

  /**
   * Дождаться, пока все начатые записи завершатся (и конвертов, и чанков). Нужно
   * при штатной остановке (иначе тело, чья запись шла в момент SIGTERM, было бы
   * потеряно) и в тестах, которые смотрят на файловую систему.
   *
   * Цикл, а не одно ожидание: пока ждём, могли начаться новые записи.
   */
  async function flushPendingBlobs() {
    while (bodyWrites.size) {
      await Promise.allSettled([...bodyWrites]);
    }
  }
  // Удалить строку очереди и синхронно поправить счётчики веса/количества.
  // r ДОЛЖЕН содержать поле bytes (все запросы, чьи строки сюда попадают,
  // выбирают bytes): byId/forUser — через SELECT *, oldest* — явно.
  function dropRow(r) {
    const removed = q.delId.run(r.id).changes;
    if (r.blob) unlinkBlob(r.id);
    // АУД-06: строку могли снять (ack, вытеснение, TTL), пока асинхронный
    // читатель ждал её тело с диска. Тогда счётчики уже поправлены, и вычитать
    // второй раз нельзя — liveCount/liveBytes «поплыли» бы вниз, а на них держатся
    // потолки очереди.
    if (!removed) return;
    liveCount = Math.max(0, liveCount - 1);
    liveBytes = Math.max(0, liveBytes - (r.bytes || 0));
  }

  const q = {
    insert: db.prepare(
      'INSERT OR REPLACE INTO queue (id,to_pk,envelope,silent,call_push,ts,blob,bytes,sender_meta,pair_tag,stranger) VALUES (?,?,?,?,?,?,?,?,?,?,?)'
    ),
    forUser: db.prepare('SELECT * FROM queue WHERE to_pk=? ORDER BY ts ASC'),
    // S1: только id (без тел) — для потокового flush с backpressure, чтобы не
    // материализовать всю очередь получателя в память разом.
    idsForUser: db.prepare('SELECT id FROM queue WHERE to_pk=? ORDER BY ts ASC'),
    countFor: db.prepare('SELECT count(*) c FROM queue WHERE to_pk=?'),
    // ГРФ-1: квота на пару считается по непрозрачной метке, а не по паре ключей.
    countFromTo: db.prepare('SELECT count(*) c FROM queue WHERE pair_tag=?'),
    oldestFor: db.prepare('SELECT id, blob, bytes FROM queue WHERE to_pk=? ORDER BY ts ASC LIMIT 1'),
    oldestFromTo: db.prepare('SELECT id, blob, bytes FROM queue WHERE pair_tag=? ORDER BY ts ASC LIMIT 1'),
    // ВЫС-15: резерв и вытеснение считаются по конвертам незнакомцев.
    strangerCount: db.prepare('SELECT count(*) c FROM queue WHERE to_pk=? AND stranger=1'),
    oldestStranger: db.prepare(
      'SELECT id, blob, bytes FROM queue WHERE to_pk=? AND stranger=1 ORDER BY ts ASC LIMIT 1'
    ),
    oldestGlobal: db.prepare('SELECT id, blob, bytes FROM queue ORDER BY ts ASC LIMIT 1'),
    byId: db.prepare('SELECT * FROM queue WHERE id=?'),
    delId: db.prepare('DELETE FROM queue WHERE id=?'),
    blobsOlder: db.prepare('SELECT id FROM queue WHERE blob=1 AND ts < ?'),
    blobIds: db.prepare('SELECT id FROM queue WHERE blob=1'),
    usersQueued: db.prepare('SELECT count(DISTINCT to_pk) c FROM queue'),
    totalQueued: db.prepare('SELECT count(*) c FROM queue'),
    sumBytes: db.prepare('SELECT coalesce(sum(bytes),0) c FROM queue'),
    needBackfill: db.prepare('SELECT id, blob FROM queue WHERE bytes=0'),
    setBytes: db.prepare('UPDATE queue SET bytes=? WHERE id=?'),
    expire: db.prepare('DELETE FROM queue WHERE ts < ?'),
    rowsForDrop: db.prepare('SELECT id, blob, bytes FROM queue WHERE to_pk=?'),
  };
  const binary = {
    insert: db.prepare(
      `INSERT INTO binary_queue
       (id,to_pk,ref,transfer_id,chunk_index,total_chunks,bytes,ts,sender_meta,pair_tag,stranger)
       VALUES (?,?,?,?,?,?,?,?,?,?,?)`
    ),
    idsForUser: db.prepare('SELECT id FROM binary_queue WHERE to_pk=? ORDER BY ts ASC,chunk_index ASC'),
    byId: db.prepare('SELECT * FROM binary_queue WHERE id=?'),
    delId: db.prepare('DELETE FROM binary_queue WHERE id=?'),
    countFor: db.prepare('SELECT count(*) c FROM binary_queue WHERE to_pk=?'),
    countFromTo: db.prepare('SELECT count(*) c FROM binary_queue WHERE pair_tag=?'),
    strangerCount: db.prepare('SELECT count(*) c FROM binary_queue WHERE to_pk=? AND stranger=1'),
    rowsForDrop: db.prepare('SELECT id,bytes FROM binary_queue WHERE to_pk=?'),
    older: db.prepare('SELECT id,bytes FROM binary_queue WHERE ts < ?'),
    expire: db.prepare('DELETE FROM binary_queue WHERE ts < ?'),
    allIds: db.prepare('SELECT id FROM binary_queue'),
    usersQueued: db.prepare('SELECT count(DISTINCT to_pk) c FROM binary_queue'),
    totalQueued: db.prepare('SELECT count(*) c FROM binary_queue'),
    sumBytes: db.prepare('SELECT coalesce(sum(bytes),0) c FROM binary_queue'),
  };

  function dropBinaryRow(row) {
    const removed = binary.delId.run(row.id).changes;
    unlinkBinary(row.id);
    if (!removed) return; // см. dropRow: строку уже сняли, счётчики трогать нельзя
    liveCount = Math.max(0, liveCount - 1);
    liveBytes = Math.max(0, liveBytes - (row.bytes || 0));
  }

  // ВЫС-15: корреспонденты — кому получатель сам недавно писал.
  const correspondents = {
    note: db.prepare('INSERT OR REPLACE INTO correspondents (tag, ts) VALUES (?, ?)'),
    get: db.prepare('SELECT ts FROM correspondents WHERE tag=?'),
    expire: db.prepare('DELETE FROM correspondents WHERE ts < ?'),
    count: db.prepare('SELECT count(*) c FROM correspondents'),
    dropOldest: db.prepare(
      'DELETE FROM correspondents WHERE tag IN (SELECT tag FROM correspondents ORDER BY ts ASC LIMIT ?)'
    ),
  };
  // Потолок таблицы. Метка — 16 байт HMAC плюс время; двести тысяч пар — около
  // семи мегабайт, при этом счёт идёт по ПАРАМ, а не по людям. Сверх потолка
  // вытесняются самые давние: они первыми перестали бы считаться «недавними».
  const MAX_CORRESPONDENTS = 200000;

  /** Отметить: по паре from→to только что прошёл конверт. */
  function noteCorrespondent(tag, ts) {
    if (!tag) return;
    correspondents.note.run(tag, ts);
    const over = correspondents.count.get().c - MAX_CORRESPONDENTS;
    if (over > 0) correspondents.dropOldest.run(over);
  }

  /** Писал ли получатель этому отправителю за срок памяти. */
  function isCorrespondent(tag, now, ttlMs) {
    if (!tag || !ttlMs) return false;
    const row = correspondents.get.get(tag);
    return !!row && now - row.ts <= ttlMs;
  }

  /** Строка binary_queue + уже добытое тело → кадр для отправки. */
  function binaryItem(row, payload) {
    // ГРФ-1: отправитель и его метаданные лежат зашифрованным блобом. Не
    // открылось (потерян/сменён файл ключа) — отдаём чанк без атрибуции: он
    // всё равно адресован этому получателю, а сносить его молча нельзя.
    const sealed = openMeta(row.sender_meta) || {};
    const metadata = sealed.metadata && typeof sealed.metadata === 'object' ? sealed.metadata : {};
    return {
      id: row.id,
      to: row.to_pk,
      from: sealed.from,
      ref: row.ref || undefined,
      transferId: row.transfer_id,
      index: row.chunk_index,
      total: row.total_chunks,
      metadata,
      payload,
      bytes: row.bytes,
      ts: row.ts,
    };
  }

  function binaryRowToItem(row) {
    if (!row) return null;
    // АУД-06: чанк мог ещё не доехать до диска — запись идёт вне event-loop.
    // Пока она идёт, тело лежит в памяти, и читатель берёт его оттуда.
    let payload = pendingBinary(row.id);
    if (payload == null) {
      try {
        payload = fs.readFileSync(binaryPath(row.id));
      } catch (error) {
        dropBinaryRow(row); // тела нет (том почистили, диск кончился) — строка мертва
        return null;
      }
    }
    return binaryItem(row, payload);
  }

  /**
   * АУД-06: то же самое, но чтение с диска уходит в пул потоков, а не в петлю.
   * Этим путём идёт выгрузка очереди в relay.flushBinaryQueue; см. шапку АУД-06.
   */
  async function binaryRowToItemAsync(row) {
    if (!row) return null;
    let payload = pendingBinary(row.id);
    if (payload == null) {
      try {
        payload = await fs.promises.readFile(binaryPath(row.id));
      } catch (error) {
        dropBinaryRow(row);
        return null;
      }
    }
    return binaryItem(row, payload);
  }
  // null — если тело-файл пропал (например, volume почистили руками): такая
  // строка мертва, подчищаем её и пропускаем.
  const rowToItem = (r) => {
    let envJson = r.envelope;
    if (r.blob) {
      // АУД-06: тело могло ещё не доехать до диска — запись идёт вне event-loop.
      // Пока она идёт, тело лежит в памяти, и читатель берёт его оттуда.
      envJson = pendingBlob(r.id);
      if (envJson == null) {
        try {
          envJson = fs.readFileSync(blobPath(r.id), 'utf8');
        } catch (e) {
          dropRow(r);
          return null;
        }
      }
    }
    return itemFromEnvelope(r, envJson);
  };

  /** АУД-06: то же, но с чтением тела в пуле потоков. См. binaryRowToItemAsync. */
  const rowToItemAsync = async (r) => {
    let envJson = r.envelope;
    if (r.blob) {
      envJson = pendingBlob(r.id);
      if (envJson == null) {
        try {
          envJson = await fs.promises.readFile(blobPath(r.id), 'utf8');
        } catch (e) {
          dropRow(r);
          return null;
        }
      }
    }
    return itemFromEnvelope(r, envJson);
  };

  const itemFromEnvelope = (r, envJson) => {
    // S6: тело могло испортиться (сбой питания между записью blob-файла и fsync;
    // порча строки БД). Без try/catch JSON.parse бросал бы на КАЖДОМ чтении очереди
    // этого получателя — flushQueue падал, клиент вместо `ready` получал ошибку и
    // зацикливал реконнекты (заблокирован до истечения TTL). Битую строку сносим.
    let envelope;
    try {
      envelope = JSON.parse(envJson);
    } catch (e) {
      dropRow(r);
      return null;
    }
    // ГРФ-1: from/fromAccount/fromDeviceId/сертификат/roster приезжают одним
    // зашифрованным блобом. Не открылось — конверт всё равно доставляем: у
    // отправителя без связанных устройств получатель опознаёт его по полю `from`
    // ВНУТРИ конверта (src/relay.js: resolveIncomingSender), и терять сообщение
    // из-за отсутствующей атрибуции хуже, чем доставить его без неё.
    const meta = openMeta(r.sender_meta) || {};
    return {
      id: r.id,
      from: meta.from || undefined,
      fromAccount: meta.fromAccount || meta.from || undefined,
      fromDeviceId: meta.fromDeviceId || undefined,
      deviceCertificate: meta.deviceCertificate || undefined,
      deviceRoster: meta.deviceRoster || undefined,
      envelope,
      silent: !!r.silent,
      callPush: !!r.call_push,
      ts: r.ts,
      // АУД-12: размер конверта уже посчитан при постановке в очередь. Без него
      // релей сериализовал кадр целиком только ради длины — и тут же выбрасывал
      // результат, чтобы упаковать тот же кадр в MessagePack заново.
      bytes: Number(r.bytes) || 0,
    };
  };

  // Backfill bytes для строк из старых БД (bytes=0): db-строки — длина envelope,
  // blob-строки — размер файла на диске. Разовая работа при старте; без неё учёт
  // liveBytes «поплыл» бы при вытеснении таких строк (dropRow вычитал бы 0).
  for (const r of q.needBackfill.all()) {
    let b = 0;
    if (r.blob) {
      try {
        b = fs.statSync(blobPath(r.id)).size;
      } catch (e) {
        b = 0;
      }
    } else {
      const row = q.byId.get(r.id);
      b = row ? Buffer.byteLength(row.envelope || '') : 0;
    }
    if (b > 0) q.setBytes.run(b, r.id);
  }

  // H-3/S4: глобальные счётчики очереди — по числу строк И по байтам (тела в БД +
  // файлы-blob). Держим в памяти и синхронно обновляем при вставке/удалении, чтобы
  // enqueue и /metrics работали за O(1), не сканируя таблицу/каталог на каждый кадр.
  let liveCount = q.totalQueued.get().c + binary.totalQueued.get().c;
  let liveBytes = q.sumBytes.get().c + binary.sumBytes.get().c;

  const id = {
    get: db.prepare('SELECT sign_pk, proven FROM identities WHERE pk=?'),
    set: db.prepare('INSERT OR IGNORE INTO identities (pk,sign_pk,proven,last_seen) VALUES (?,?,?,?)'),
    rebind: db.prepare('INSERT OR REPLACE INTO identities (pk,sign_pk,proven,last_seen) VALUES (?,?,?,?)'),
    touch: db.prepare('UPDATE identities SET last_seen=? WHERE pk=?'),
    count: db.prepare('SELECT count(*) c FROM identities'),
    // M-02: холодные identity без ожидающих конвертов — кандидаты на вытеснение
    // (identity с непрочитанной очередью НЕ трогаем, чтобы не потерять сообщения).
    coldNoQueue: db.prepare(
      `SELECT i.pk FROM identities i
       WHERE NOT EXISTS (SELECT 1 FROM queue q WHERE q.to_pk = i.pk)
         AND NOT EXISTS (SELECT 1 FROM binary_queue b WHERE b.to_pk = i.pk)
       ORDER BY i.last_seen ASC LIMIT ?`
    ),
    del: db.prepare('DELETE FROM identities WHERE pk=?'),
  };
  const tok = {
    get: db.prepare('SELECT token FROM push_tokens WHERE pk=?'),
    set: db.prepare('INSERT OR REPLACE INTO push_tokens (pk,token) VALUES (?,?)'),
    del: db.prepare('DELETE FROM push_tokens WHERE pk=?'),
  };
  const dir = {
    all: db.prepare('SELECT url FROM directory ORDER BY last_seen DESC'),
    upsert: db.prepare('INSERT OR REPLACE INTO directory (url,last_seen) VALUES (?,?)'),
    count: db.prepare('SELECT count(*) c FROM directory'),
    // S9: удалить записи старше TTL (протухшие анонсы).
    expire: db.prepare('DELETE FROM directory WHERE last_seen < ?'),
    // S9: оставить только N самых свежих (по last_seen) — вытеснение мусора.
    trim: db.prepare(
      'DELETE FROM directory WHERE url NOT IN (SELECT url FROM directory ORDER BY last_seen DESC LIMIT ?)'
    ),
  };
  // ПЯЩ-1: общий ящик записок. Ни одного запроса «по владельцу» здесь нет и быть
  // не может — владельца в таблице не существует.
  // ОТЧ-1: отчёты о неполадках. Запросы простые до скуки — и это правильно:
  // всё, что узел умеет с отчётом, — принять байты, отдать их владельцу по
  // подписи и забыть по сроку.
  const rep = {
    put: db.prepare('INSERT OR IGNORE INTO reports (id,at,body) VALUES (?,?,?)'),
    page: db.prepare('SELECT id,at,body FROM reports ORDER BY at LIMIT ?'),
    del: db.prepare('DELETE FROM reports WHERE id = ?'),
    expire: db.prepare('DELETE FROM reports WHERE at < ?'),
    count: db.prepare('SELECT count(*) c FROM reports'),
  };

  const mbxq = {
    put: db.prepare('INSERT OR IGNORE INTO mbx (key,vh,val,mac,slot,seq,ord) VALUES (?,?,?,?,?,?,?)'),
    // Сводка строится по ВСЕМ ключам сразу: она одинакова для всех и не зависит
    // от того, кто её попросил.
    keys: db.prepare('SELECT key FROM mbx'),
    // Корзина — диапазоном по ведущему столбцу первичного ключа, поэтому
    // отдельный индекс не нужен.
    bucket: db.prepare('SELECT key,val,mac,slot FROM mbx WHERE key>=? AND key<=? LIMIT ?'),
    // Репликация: всё, что появилось после курсора соседа.
    after: db.prepare('SELECT key,val,mac,slot,seq FROM mbx WHERE seq>? ORDER BY seq LIMIT ?'),
    count: db.prepare('SELECT count(*) c FROM mbx'),
    maxSeq: db.prepare('SELECT COALESCE(MAX(seq),0) s FROM mbx'),
    expire: db.prepare('DELETE FROM mbx WHERE slot <= ?'),
    oldestSlot: db.prepare('SELECT COALESCE(MIN(slot),0) s FROM mbx'),
    // ВЫС-31: убрать ПОРЦИЮ из самого старого отрезка, а не отрезок целиком.
    // Порядок — по назначенному узлом `ord`, поэтому выбор равномерен и не
    // подбирается тем, кто заливает ящик. NULL (строки прежней версии) в SQLite
    // сортируются первыми — они и есть самые старые.
    evictBatch: db.prepare(
      'DELETE FROM mbx WHERE rowid IN (SELECT rowid FROM mbx WHERE slot=? ORDER BY ord LIMIT ?)'
    ),
    slotCount: db.prepare('SELECT count(*) c FROM mbx WHERE slot=?'),
  };
  let mbxSeq = mbxq.maxSeq.get().s;
  // КРИТ-04: отдельный счётчик ИЗМЕНЕНИЙ ящика — для кэша сводки.
  //
  // Курсором репликации (mbxVersion, он же MAX(seq)) для этого пользоваться
  // нельзя: он растёт только при добавлении. Чистка по сроку и вытеснение
  // старого отрезка удаляют записки, не трогая максимума, — и кэш, сверяющийся
  // с ним, продолжал бы отдавать сводку, обещающую то, чего в ящике уже нет.
  // Ищущий шёл бы за корзиной и получал пустоту, считая, что записки не было.
  //
  // Счётчик живёт в памяти и при перезапуске начинается заново — вместе с самим
  // кэшем, который тоже пуст. Ящик правит только этот процесс, поэтому
  // разойтись с диском счётчику не с кем.
  let mbxRevision = 0;
  // Число записок читается на каждую просьбу о сводке и о корзине, а COUNT(*)
  // по тридцати тысячам строк — скан. Меняется оно ровно тогда же, когда и
  // ревизия, поэтому считается один раз на изменение.
  let mbxCountCache = null;
  let mbxCountAt = null;

  const spk = {
    get: db.prepare('SELECT id, pub, sig, pq FROM prekeys_spk WHERE pk=?'),
    set: db.prepare('INSERT OR REPLACE INTO prekeys_spk (pk,id,pub,sig,pq) VALUES (?,?,?,?,?)'),
    delFor: db.prepare('DELETE FROM prekeys_spk WHERE pk=?'),
  };
  const otp = {
    insert: db.prepare('INSERT OR IGNORE INTO prekeys_otp (pk,id,pub) VALUES (?,?,?)'),
    delAll: db.prepare('DELETE FROM prekeys_otp WHERE pk=?'),
    takeOne: db.prepare('SELECT id, pub FROM prekeys_otp WHERE pk=? LIMIT 1'),
    delOne: db.prepare('DELETE FROM prekeys_otp WHERE pk=? AND id=?'),
    count: db.prepare('SELECT count(*) c FROM prekeys_otp WHERE pk=?'),
  };
  const account = {
    get: db.prepare('SELECT account_pk, root_sign_pk, roster_version, roster_json, updated_at FROM accounts WHERE account_pk=?'),
    insert: db.prepare(
      'INSERT INTO accounts (account_pk,root_sign_pk,roster_version,roster_json,updated_at) VALUES (?,?,?,?,?)'
    ),
    updateRoster: db.prepare(
      'UPDATE accounts SET roster_version=?, roster_json=?, updated_at=? WHERE account_pk=?'
    ),
    count: db.prepare('SELECT count(*) c FROM accounts'),
  };
  const device = {
    byPk: db.prepare(
      'SELECT account_pk,device_id,device_pk,device_sign_pk,certificate,name,platform,issued_at,revoked_at,redacted_at,last_seen FROM account_devices WHERE device_pk=?'
    ),
    byId: db.prepare(
      'SELECT account_pk,device_id,device_pk,device_sign_pk,certificate,name,platform,issued_at,revoked_at,redacted_at,last_seen FROM account_devices WHERE account_pk=? AND device_id=?'
    ),
    forAccount: db.prepare(
      'SELECT account_pk,device_id,device_pk,device_sign_pk,certificate,name,platform,issued_at,revoked_at,redacted_at,last_seen FROM account_devices WHERE account_pk=? ORDER BY issued_at ASC, device_id ASC'
    ),
    upsert: db.prepare(`
      INSERT INTO account_devices
        (account_pk,device_id,device_pk,device_sign_pk,certificate,name,platform,issued_at,revoked_at,last_seen)
      VALUES (?,?,?,?,?,?,?,?,?,?)
      ON CONFLICT(account_pk,device_id) DO UPDATE SET
        device_pk=excluded.device_pk,
        device_sign_pk=excluded.device_sign_pk,
        -- ГРФ-3: уже вычищенную запись повторная публикация roster НЕ оживляет.
        -- Roster полный и содержит отозванные устройства навсегда, поэтому без
        -- этой оговорки имя возвращалось бы в базу на следующем же коннекте.
        certificate=CASE WHEN account_devices.redacted_at IS NULL THEN excluded.certificate ELSE '' END,
        name=CASE WHEN account_devices.redacted_at IS NULL THEN excluded.name ELSE '' END,
        platform=CASE WHEN account_devices.redacted_at IS NULL THEN excluded.platform ELSE '' END,
        issued_at=excluded.issued_at,
        revoked_at=excluded.revoked_at
    `),
    revokeById: db.prepare(
      'UPDATE account_devices SET revoked_at=? WHERE account_pk=? AND device_id=? AND revoked_at IS NULL'
    ),
    touch: db.prepare('UPDATE account_devices SET last_seen=? WHERE device_pk=?'),
    countActive: db.prepare('SELECT count(*) c FROM account_devices WHERE revoked_at IS NULL'),
    // ГРФ-3: стереть человекочитаемые поля давно отозванных устройств.
    redact: db.prepare(`
      UPDATE account_devices
         SET name='', platform='', certificate='', redacted_at=?
       WHERE revoked_at IS NOT NULL AND revoked_at <= ? AND redacted_at IS NULL
    `),
  };

  function deviceRow(r) {
    if (!r) return null;
    let certificate = null;
    try {
      certificate = JSON.parse(r.certificate);
    } catch (e) {
      // ГРФ-3: у вычищенной записи отозванного устройства сертификата больше нет
      // (пустая строка). Это не ошибка: подключиться такое устройство всё равно
      // не может (проверка revokedAt срабатывает раньше сверки сертификата).
      certificate = null;
    }
    return {
      accountPublicKey: r.account_pk,
      deviceId: r.device_id,
      devicePublicKey: r.device_pk,
      deviceSignPublicKey: r.device_sign_pk,
      certificate,
      name: r.name,
      platform: r.platform,
      issuedAt: r.issued_at,
      revokedAt: r.revoked_at == null ? null : r.revoked_at,
      redactedAt: r.redacted_at == null ? null : r.redacted_at,
      lastSeen: r.last_seen || 0,
    };
  }
  function dropQueueFor(to) {
    const rows = q.rowsForDrop.all(to);
    for (const row of rows) dropRow(row);
    const binaryRows = binary.rowsForDrop.all(to);
    for (const row of binaryRows) dropBinaryRow(row);
    return rows.length + binaryRows.length;
  }

  return {
    // --- queue --------------------------------------------------------------
    /**
     * Положить конверт в очередь получателя; при переполнении вытеснить старейший.
     * Тело крупнее blobThreshold уходит файлом в blobDir — в БД только ссылка.
     */
    enqueue({
      id: mid,
      to,
      from,
      fromAccount,
      fromDeviceId,
      deviceCertificate,
      deviceRoster,
      envelope,
      // АУД-06: сериализованный конверт, если вызывающий его уже построил.
      // Релей всё равно сериализует конверт для проверки размера, а здесь делал
      // это ВТОРОЙ раз: на конверте в семь мегабайт (вложение в группу по
      // легаси-пути) это лишний полный проход по памяти в однопоточном процессе,
      // то есть пауза для ВСЕХ пользователей узла. Строку принимаем, но не
      // доверяем ей вслепую: если её нет, считаем как раньше.
      envelopeJson,
      silent,
      callPush,
      ts,
      maxPerUser,
      maxPerSender,
      maxTotal,
      maxTotalBytes,
      // ВЫС-15: резерв слотов под корреспондентов и срок их памяти. По
      // умолчанию ВЫКЛЮЧЕНЫ: их включает вызывающий (релей передаёт
      // QUEUE_RESERVE_SLOTS и срок очереди) — прямые вызовы хранилища ведут
      // себя как раньше, и маленькие потолки в тестах не запирают незнакомцев.
      reserve = 0,
      reciprocityTtlMs = 0,
    }) {
      const envJson = typeof envelopeJson === 'string' ? envelopeJson : JSON.stringify(envelope);
      const bytes = Buffer.byteLength(envJson);
      // ГРФ-1: пара «отправитель→получатель» участвует в квотах только как
      // непрозрачная метка; сами ключи в базу открытым текстом не попадают.
      const tag = pairTag(from, to);

      // ВЫС-15: решение о приёме — чистым правилом (queueAdmission.js). История
      // его слоёв: S5 — квота пары с ротацией своего старейшего; СРВ-2 — при
      // полной очереди свежий отправитель не вытесняет чужие конверты (drop-new);
      // ВЫС-15 — незнакомцам закрыт резерв, а корреспондент (кому получатель сам
      // недавно писал) при полной очереди вытесняет старейший конверт незнакомца.
      // Иначе пять бесплатных личностей по maxPerSender конвертов выбирали
      // очередь целиком, и честные отправители получали отказ до самого TTL.
      const correspondent = isCorrespondent(pairTag(to, from), ts, reciprocityTtlMs);
      const verdict = admitEnvelope({
        recipientCount: q.countFor.get(to).c + binary.countFor.get(to).c,
        strangerCount: q.strangerCount.get(to).c + binary.strangerCount.get(to).c,
        senderCount: tag ? q.countFromTo.get(tag).c + binary.countFromTo.get(tag).c : 0,
        correspondent,
        senderKnown: !!from,
        maxPerUser,
        maxPerSender,
        reserve,
      });
      if (!verdict.admit) return false;
      if (verdict.evict === 'own') {
        // Ротируем свой старейший. Он может оказаться и бинарным чанком, но
        // рвать чужую передачу ради конверта нельзя — тогда честный отказ.
        const own = q.oldestFromTo.get(tag);
        if (own) dropRow(own);
        else return false;
      } else if (verdict.evict === 'stranger') {
        const spam = q.oldestStranger.get(to);
        if (spam) dropRow(spam);
        else return false; // незнакомые конверты — только чанки передач: не рвём
      } else if (verdict.evict === 'oldest') {
        const o = q.oldestFor.get(to);
        if (o) dropRow(o);
      }
      // S4/H-3: ГЛОБАЛЬНЫЕ потолки — по числу И по байтам. Без байтового лимита
      // один клиент мог засыпать очередь крупными блобами (до 32 МБ) на разные
      // адреса и переполнить диск volume: count-лимит при этом не срабатывал никогда.
      //
      // H-03: при достижении глобального потолка НЕ вытесняем старейший конверт во
      // всей очереди — раньше это молча удаляло уже принятые сообщения ДРУГИХ
      // получателей. Sybil-флудер (много одноразовых identity, по 1 конверту)
      // заполнял очередь до потолка, и каждый следующий конверт вычёркивал глобально
      // старейший — то есть реальные сообщения честных офлайн-пользователей (цензура/
      // тихая потеря). Теперь отклоняем НОВЫЙ конверт (drop-new, как СРВ-2 на уровне
      // получателя): чужие принятые конверты неприкосновенны, очередь дренируется по
      // TTL. deliver() вернёт dropped:true, клиент переотправит позже.
      if (
        (maxTotal && liveCount >= maxTotal) ||
        (maxTotalBytes && liveBytes + bytes > maxTotalBytes)
      ) {
        return false;
      }
      const asBlob = blobDir && bytes > blobThreshold;
      if (asBlob) writeBlob(mid, envJson);
      q.insert.run(
        mid,
        to,
        asBlob ? '' : envJson,
        silent ? 1 : 0,
        callPush ? 1 : 0,
        ts,
        asBlob ? 1 : 0,
        bytes,
        sealMeta({
          from: from || undefined,
          fromAccount: fromAccount || from || undefined,
          fromDeviceId: fromDeviceId || undefined,
          deviceCertificate: deviceCertificate || undefined,
          deviceRoster: deviceRoster || undefined,
        }),
        tag,
        from && !correspondent ? 1 : 0 // ВЫС-15: по флагу считается резерв
      );
      liveCount += 1;
      liveBytes += bytes;
      // ВЫС-15: по паре from→to прошёл конверт — отправитель этим фактом делает
      // получателя СВОИМ корреспондентом (обратное направление). Личности
      // флудера этого свойства у жертвы не получают никогда: она им не пишет.
      noteCorrespondent(tag, ts);
      return true; // СРВ-2: конверт сохранён (false выше — отклонён из-за полной очереди получателя)
    },
    /** Сохранить зашифрованный raw-чанк без перекодирования в JSON/base64. */
    enqueueBinary({
      id: binaryId,
      to,
      from,
      ref,
      transferId,
      index,
      total,
      metadata,
      payload,
      ts,
      maxPerUser,
      maxPerSender,
      maxTotal,
      maxTotalBytes,
      // ВЫС-15: как в enqueue — по умолчанию выключено, включает релей.
      reserve = 0,
      reciprocityTtlMs = 0,
    }) {
      const bytes = payload.length;
      const tag = pairTag(from, to); // ГРФ-1: см. enqueue
      const recipientCount = q.countFor.get(to).c + binary.countFor.get(to).c;
      const pairCount = q.countFromTo.get(tag).c + binary.countFromTo.get(tag).c;
      // ВЫС-15: и у чанков незнакомцам закрыт резерв. Вытеснения здесь нет и не
      // было — удалить чужой чанк значит порвать чужую передачу, — поэтому все
      // отказы остаются drop-new, меняется только граница для незнакомца.
      const correspondent = isCorrespondent(pairTag(to, from), ts, reciprocityTtlMs);
      if (maxPerUser && recipientCount >= maxPerUser) return false;
      if (
        maxPerUser &&
        reserve > 0 &&
        from &&
        !correspondent &&
        q.strangerCount.get(to).c + binary.strangerCount.get(to).c >=
          Math.max(0, maxPerUser - reserve)
      ) {
        return false;
      }
      if (maxPerSender && pairCount >= maxPerSender) return false;
      if (
        (maxTotal && liveCount >= maxTotal) ||
        (maxTotalBytes && liveBytes + bytes > maxTotalBytes)
      ) {
        return false;
      }
      // АУД-06: запись чанка уходит вне event-loop и возвращается сразу. Если она
      // потом не удастся (диск кончился), строка останется без тела и будет снята
      // при первом чтении — раньше вызывающий узнавал об этом исключением прямо
      // здесь, но платил за это остановкой всего узла на каждый чанк.
      if (binary.byId.get(binaryId)) throw new Error('binary id already queued');
      writeBinary(binaryId, payload);
      try {
        binary.insert.run(
          binaryId,
          to,
          ref || null,
          transferId,
          index,
          total,
          bytes,
          ts,
          sealMeta({ from: from || undefined, metadata: metadata || undefined }),
          tag,
          from && !correspondent ? 1 : 0 // ВЫС-15
        );
      } catch (error) {
        unlinkBinary(binaryId);
        throw error;
      }
      liveCount += 1;
      liveBytes += bytes;
      noteCorrespondent(tag, ts); // ВЫС-15: см. enqueue
      return true;
    },
    binaryQueueIdsFor(to) {
      return binary.idsForUser.all(to).map((row) => row.id);
    },
    getBinaryItem(binaryId) {
      return binaryRowToItem(binary.byId.get(binaryId));
    },
    /**
     * АУД-06: тот же чанк, но чтение с диска не занимает event-loop. Этим
     * вариантом пользуется relay.flushBinaryQueue — то есть путь массового
     * переподключения, где синхронное чтение и стоило дороже всего.
     */
    getBinaryItemAsync(binaryId) {
      return binaryRowToItemAsync(binary.byId.get(binaryId));
    },
    ackBinary(to, binaryId) {
      const row = binary.byId.get(binaryId);
      if (!row || row.to_pk !== to) return null;
      const result = {
        // ГРФ-1: адрес отправителя нужен, чтобы вернуть ему квитанцию; берём его
        // из зашифрованного блоба, а не из открытой колонки.
        from: (openMeta(row.sender_meta) || {}).from,
        ref: row.ref || undefined,
        transferId: row.transfer_id,
        index: row.chunk_index,
      };
      dropBinaryRow(row);
      return result;
    },
    /** Все конверты, ждущие получателя (в порядке поступления). */
    queueFor(to) {
      return q.forUser.all(to).map(rowToItem).filter(Boolean);
    },
    /** S1: только id ожидающих конвертов (в порядке поступления) — дёшево, без тел.
     *  Для потокового flush: тело каждого берётся getItem по одному, с backpressure. */
    queueIdsFor(to) {
      return q.idsForUser.all(to).map((r) => r.id);
    },
    getItem(mid) {
      const r = q.byId.get(mid);
      return r ? rowToItem(r) : null;
    },
    /** АУД-06: то же, но с чтением тела вне event-loop. См. getBinaryItemAsync. */
    getItemAsync(mid) {
      const r = q.byId.get(mid);
      return r ? rowToItemAsync(r) : Promise.resolve(null);
    },
    /**
     * Удалить конверт по id, если он адресован `to`. Вернуть адрес отправителя
     * (или null) — релей шлёт ему квитанцию «доставлено», если он сейчас онлайн.
     *
     * ГРФ-1: адрес достаётся из зашифрованного блоба метаданных. Если файл ключа
     * потерян, вернётся null: конверт удалится как обычно, но отправитель не
     * увидит вторую галочку. Хуже, чем полная функциональность, и лучше, чем
     * граф общения в дампе базы.
     */
    ack(to, mid) {
      const r = q.byId.get(mid);
      if (!r || r.to_pk !== to) return null;
      dropRow(r);
      return (openMeta(r.sender_meta) || {}).from || null;
    },
    /** Удалить очередь конкретного адреса устройства (после подписанного отзыва). */
    dropQueueFor,

    // --- ПЯЩ-1: общий ящик записок ------------------------------------------

    /**
     * Положить пачку записок. Возвращает, сколько легло НОВЫМИ.
     *
     * Повтор той же записки (та же пара значение+метка) молча игнорируется: она
     * пришла вторым путём, а не появилась заново. Подделка под тем же ключом
     * ложится ОТДЕЛЬНОЙ строкой — иначе ею вытесняли бы настоящую, и адресат,
     * сверяя метку, молча не находил бы ничего.
     */
    mbxPut(records, valueHash) {
      let added = 0;
      const insert = db.transaction((list) => {
        for (const record of list) {
          mbxSeq += 1;
          const changed = mbxq.put.run(
            Buffer.from(record.key),
            valueHash(record),
            Buffer.from(record.value),
            Buffer.from(record.mac),
            record.slot,
            mbxSeq,
            // ВЫС-31: порядок вытеснения назначает УЗЕЛ, а не отправитель и не
            // время вставки. Иначе заливающий ящик подбирает его так, чтобы под
            // нож всегда шли чужие записки.
            crypto.randomInt(0, 0x7fffffff)
          ).changes;
          if (changed) added += 1;
          else mbxSeq -= 1; // повтор — номер не расходуем
        }
      });
      insert(Array.isArray(records) ? records : []);
      if (added) mbxRevision += 1;
      return added;
    },

    /** Все ключи — для сводки. Ничего, кроме ключей, отсюда не уходит. */
    mbxKeys() {
      return mbxq.keys.all().map((row) => row.key);
    },

    /** Записки одной корзины. */
    mbxBucket(low, high, limit) {
      return mbxq.bucket.all(low, high, limit);
    },

    /** Записки после курсора — для репликации между узлами. */
    mbxAfter(seq, limit) {
      return mbxq.after.all(seq, limit);
    },

    mbxCount() {
      if (mbxCountAt === mbxRevision && mbxCountCache != null) return mbxCountCache;
      mbxCountCache = mbxq.count.get().c;
      mbxCountAt = mbxRevision;
      return mbxCountCache;
    },

    mbxVersion() {
      return mbxq.maxSeq.get().s;
    },

    /**
     * КРИТ-04: версия ящика ДЛЯ СВОДКИ — в отличие от mbxVersion, меняется и при
     * удалении. Именно с ней обязан сверяться кэш сводки.
     */
    mbxRevision() {
      return mbxRevision;
    },

    /** Убрать протухшее: все отрезки не новее указанного. */
    mbxExpire(slot) {
      const removed = mbxq.expire.run(slot).changes;
      if (removed) mbxRevision += 1;
      return removed;
    },

    /**
     * ВЫС-31: вытеснить ПОРЦИЮ из самого старого отрезка.
     *
     * Раньше здесь вычищался отрезок целиком — шесть часов записок одним
     * движением. Рассуждение за этим стояло верное: какая записка кому нужна,
     * узел не знает и знать не должен, поэтому «выбрасывать самые старые
     * поштучно значило бы резать по живому». Беда в том, что вычистить отрезок
     * целиком — это и есть резать по живому, только шире.
     *
     * И этим можно было пользоваться. Ящик открыт на запись любому, кто
     * подключился. Залив его до потолка, нападающий заставлял узел выбросить
     * старейший отрезок — а это ровно тот, за запиской из которого адресат
     * придёт в следующий раз: записка живёт два отрезка и забирается на втором.
     * Свои записки заливающий кладёт в текущий отрезок, и они не страдали.
     *
     * Теперь убирается ровно нужное число (evictionSize), и выбор внутри
     * отрезка идёт по назначенному узлом порядку — то есть равномерно. Доля
     * выброшенного у каждого равна его доле в ящике, и заливка бьёт прежде
     * всего по самому заливающему.
     *
     * `limit` — сколько записок убрать. Возвращает, сколько убрано.
     */
    mbxEvictSome(limit) {
      const want = Math.max(0, Math.floor(Number(limit) || 0));
      if (!want) return 0;
      const oldest = mbxq.oldestSlot.get().s;
      if (!oldest) return 0;
      const removed = mbxq.evictBatch.run(oldest, want).changes;
      if (removed) mbxRevision += 1;
      return removed;
    },

    /** Сколько записок лежит в этом отрезке. Нужно уборке, чтобы знать глубину. */
    mbxSlotCount(slot) {
      return mbxq.slotCount.get(slot).c;
    },

    /** Самый старый отрезок в ящике. Ноль — ящик пуст. */
    mbxOldestSlot() {
      return mbxq.oldestSlot.get().s;
    },

    /**
     * ВЫС-31: свести ящик к потолку, вытесняя порциями из старейших отрезков.
     *
     * Цикл здесь, а не у вызывающего: решение «сколько и откуда» — свойство
     * хранилища, и разнеси его по двум файлам, вернуть вытеснение целым
     * отрезком можно было бы правкой в одном из них, не задев проверок другого.
     *
     * `guard` не даёт зациклиться, если удаление почему-то ничего не меняет:
     * бесконечный цикл в однопоточном узле — это не «медленно», это «узел
     * перестал отвечать всем».
     */
    mbxTrimTo(max, guardRounds = 8) {
      let removed = 0;
      let guard = Math.max(1, Math.floor(Number(guardRounds) || 0));
      while (guard > 0) {
        const want = evictionSize(this.mbxCount(), max);
        if (!want) break;
        const dropped = this.mbxEvictSome(want);
        if (!dropped) break;
        removed += dropped;
        guard -= 1;
      }
      return removed;
    },
    /** Удалить всё старше `cutoffTs` (TTL). Вернуть число удалённых. */
    expireOlderThan(cutoffTs) {
      for (const r of q.blobsOlder.all(cutoffTs)) unlinkBlob(r.id);
      const binaryRows = binary.older.all(cutoffTs);
      for (const row of binaryRows) unlinkBinary(row.id);
      // ВЫС-15: память о корреспондентах стареет вместе с очередью — «недавно
      // писал» не должно означать «писал когда-либо».
      correspondents.expire.run(cutoffTs);
      const removed = q.expire.run(cutoffTs).changes + binary.expire.run(cutoffTs).changes;
      // массовое удаление — пересчитываем глобальные счётчики из БД (раз в час, дёшево).
      liveCount = q.totalQueued.get().c + binary.totalQueued.get().c;
      liveBytes = q.sumBytes.get().c + binary.sumBytes.get().c;
      return removed;
    },
    /**
     * Убрать из blobDir файлы, на которые не ссылается ни одна строка очереди
     * (остались после падения между записью файла и вставкой строки, либо после
     * нештатной чистки БД). Звать при старте. Вернуть число удалённых.
     */
    cleanupOrphanBlobs() {
      if (!blobDir) return 0;
      const referenced = new Set(q.blobIds.all().map((r) => r.id));
      const referencedBinary = new Set(binary.allIds.all().map((row) => row.id));
      let removed = 0;
      for (const f of fs.readdirSync(blobDir)) {
        const isTmp = f.endsWith('.json.tmp') || f.endsWith('.bin.tmp');
        const isBlob = f.endsWith('.json');
        const isBinary = f.endsWith('.bin');
        if (!isTmp && !isBlob && !isBinary) continue; // чужие файлы не трогаем
        const mid = f.replace(/\.(json|bin)(\.tmp)?$/, '');
        // АУД-06: недописанный tmp неотличим от брошенного, но у СВОЕЙ идущей
        // записи он есть в pending*. При старте таких нет; при вызове на живом
        // узле без этой проверки уборка снесла бы тело прямо из-под записи.
        if (isTmp && (pendingBlobs.has(mid) || pendingBinaries.has(mid))) continue;
        if (isBlob && referenced.has(mid)) continue; // живой блоб
        if (isBinary && referencedBinary.has(mid)) continue;
        try {
          fs.unlinkSync(path.join(blobDir, f)); // сирота или недописанный tmp
          removed += 1;
        } catch (e) {
          // Сирота могла исчезнуть между чтением каталога и удалением, либо быть
          // занята. Счётчик removed её не учтёт, а следующий проход попробует снова.
        }
      }
      return removed;
    },

    // --- identities (TOFU) --------------------------------------------------
    getSignKey(pk) {
      const r = id.get.get(pk);
      return r ? r.sign_pk : null;
    },
    /** Полная запись связки: { signPk, proven } либо null. */
    getIdentity(pk) {
      const r = id.get.get(pk);
      return r ? { signPk: r.sign_pk, proven: !!r.proven } : null;
    },
    bindSignKey(pk, signPk, proven = false, now = 0) {
      // INSERT OR IGNORE — первый выигрывает (TOFU). proven=1 только если владение
      // box-ключом реально доказано (ECDH-proof в relay.js). last_seen=now (M-02).
      id.set.run(pk, signPk, proven ? 1 : 0, now);
    },
    /**
     * Переписать связку (H-6): разрешено ТОЛЬКО когда предъявитель доказал
     * владение box-ключом адреса — тогда он может перебить чужую (в т.ч.
     * сквоттерскую) привязку и закрепить её как proven. Легаси-путь этого не
     * умеет, поэтому proven-связку нельзя перехватить без секретки box-ключа.
     */
    rebindSignKey(pk, signPk, now = 0) {
      id.rebind.run(pk, signPk, 1, now);
    },
    /** M-02: отметить активность identity (последняя аутентификация). */
    touchIdentity(pk, now) {
      id.touch.run(now, pk);
    },
    /** M-02: текущее число зарегистрированных identity. */
    identityCount() {
      return id.count.get().c;
    },
    /**
     * M-02: удержать число identity под глобальным потолком `max`. Вытесняем самые
     * ХОЛОДНЫЕ (давно не выходившие на связь) identity, у которых НЕТ ожидающих
     * конвертов в очереди (identity с недоставленными сообщениями не трогаем),
     * каскадно удаляя их prekey (SPK+OTP) и push-токен. Так каталог не растёт
     * бесконечно под Sybil-регистрацией, а активные/имеющие очередь пользователи не
     * страдают. Возвращает число вытесненных.
     */
    evictColdIdentities(max) {
      const over = id.count.get().c - max;
      if (over <= 0) return 0;
      const victims = id.coldNoQueue.all(over).map((r) => r.pk);
      const tx = db.transaction((pks) => {
        for (const pk of pks) {
          otp.delAll.run(pk);
          spk.delFor.run(pk);
          tok.del.run(pk);
          id.del.run(pk);
        }
      });
      tx(victims);
      return victims.length;
    },

    // --- push tokens --------------------------------------------------------
    getToken(pk) {
      const r = tok.get.get(pk);
      return r ? r.token : null;
    },
    setToken(pk, token) {
      tok.set.run(pk, token);
    },
    delToken(pk) {
      tok.del.run(pk);
    },

    // --- X3DH prekeys (только публичные половинки) ---------------------------
    /** Сохранить/заменить подписанный prekey пользователя. */
    setSpk(pk, s) {
      spk.set.run(pk, s.id, s.pub, s.sig, s.pq || null);
    },
    getSpk(pk) {
      const r = spk.get.get(pk);
      if (!r) return null;
      // БЕЗ-3: pq отдаём только если он есть — иначе поле не появляется вовсе,
      // и старый клиент видит ровно прежний бандл.
      return r.pq ? { id: r.id, pub: r.pub, sig: r.sig, pq: r.pq } : { id: r.id, pub: r.pub, sig: r.sig };
    },
    /** Заменить набор одноразовых prekey пользователя свежей пачкой. */
    replaceOtps(pk, list) {
      const tx = db.transaction((items) => {
        otp.delAll.run(pk);
        for (const k of items) otp.insert.run(pk, k.id, k.pub);
      });
      tx(list);
    },
    /** Выдать ОДИН одноразовый prekey и навсегда вычеркнуть его. */
    takeOtp(pk) {
      const r = otp.takeOne.get(pk);
      if (!r) return null;
      otp.delOne.run(pk, r.id);
      return { id: r.id, pub: r.pub };
    },
    countOtps(pk) {
      return otp.count.get(pk).c;
    },

    // --- связанные устройства v2 -------------------------------------------
    getAccount(accountPk) {
      const r = account.get.get(accountPk);
      if (!r) return null;
      return {
        accountPublicKey: r.account_pk,
        accountSignPublicKey: r.root_sign_pk,
        rosterVersion: r.roster_version || 0,
        updatedAt: r.updated_at || 0,
      };
    },
    getAccountRoster(accountPk) {
      const r = account.get.get(accountPk);
      if (!r || !r.roster_json) return null;
      try {
        return JSON.parse(r.roster_json);
      } catch (e) {
        return null;
      }
    },
    getDevice(devicePk) {
      return deviceRow(device.byPk.get(devicePk));
    },
    getAccountDevice(accountPk, deviceId) {
      return deviceRow(device.byId.get(accountPk, deviceId));
    },
    devicesForAccount(accountPk) {
      return device.forAccount.all(accountPk).map(deviceRow);
    },
    touchDevice(devicePk, now) {
      device.touch.run(now, devicePk);
    },
    /**
     * Сохранить уже криптографически проверенный полный roster.
     * Версия строго монотонна; повтор того же roster идемпотентен. Отозванный
     * deviceId нельзя оживить тем же сертификатом — повторная привязка требует
     * нового ключа, а значит нового deviceId.
     */
    putAccountRoster(roster) {
      const accountPk = roster.accountPublicKey;
      const rootSignPk = roster.accountSignPublicKey;
      const raw = JSON.stringify(roster);
      const current = account.get.get(accountPk);
      if (current && current.root_sign_pk !== rootSignPk) return { ok: false, reason: 'root-key-conflict' };
      if (current && roster.version < current.roster_version) return { ok: false, reason: 'stale-roster' };
      if (current && roster.version === current.roster_version) {
        return current.roster_json === raw
          ? { ok: true, unchanged: true, revokedDeviceKeys: [] }
          : { ok: false, reason: 'roster-version-conflict' };
      }

      const entries = roster.devices || [];
      const incomingIds = new Set(entries.map((entry) => entry.certificate.deviceId));
      const existing = device.forAccount.all(accountPk);
      const existingById = new Map(existing.map((row) => [row.device_id, row]));
      for (const entry of entries) {
        const cert = entry.certificate;
        const byPk = device.byPk.get(cert.devicePublicKey);
        if (byPk && (byPk.account_pk !== accountPk || byPk.device_id !== cert.deviceId)) {
          return { ok: false, reason: 'device-key-conflict' };
        }
        const old = existingById.get(cert.deviceId);
        if (old && old.device_pk !== cert.devicePublicKey) return { ok: false, reason: 'device-id-conflict' };
        if (old && old.revoked_at != null && entry.revokedAt == null) return { ok: false, reason: 'device-revoked' };
      }

      const revokedDeviceKeys = [];
      const tx = db.transaction(() => {
        if (!current) account.insert.run(accountPk, rootSignPk, 0, null, 0);
        for (const entry of entries) {
          const cert = entry.certificate;
          const old = existingById.get(cert.deviceId);
          const revokedAt = entry.revokedAt == null ? null : entry.revokedAt;
          if (revokedAt != null && (!old || old.revoked_at == null)) revokedDeviceKeys.push(cert.devicePublicKey);
          device.upsert.run(
            accountPk,
            cert.deviceId,
            cert.devicePublicKey,
            cert.deviceSignPublicKey,
            JSON.stringify(cert),
            cert.name,
            cert.platform,
            cert.issuedAt,
            revokedAt,
            old ? old.last_seen || 0 : 0
          );
        }
        // Roster полный: отсутствующий ранее активный сертификат считается
        // отозванным подписанной новой версией, а не удаляется из аудита.
        const missing = existing.filter((row) => row.revoked_at == null && !incomingIds.has(row.device_id));
        if (missing.length) {
          for (const row of missing) {
            device.revokeById.run(roster.updatedAt, accountPk, row.device_id);
            revokedDeviceKeys.push(row.device_pk);
          }
        }
        account.updateRoster.run(roster.version, raw, roster.updatedAt, accountPk);
      });
      tx();
      return { ok: true, unchanged: false, revokedDeviceKeys: [...new Set(revokedDeviceKeys)] };
    },
    /**
     * ГРФ-3: убрать человекочитаемые следы давно отозванных устройств.
     *
     * ЧТО БЫЛО НЕ ТАК. В account_devices рядом с ключами лежало ИМЯ устройства
     * («MacBook Виктора», «Телефон Ани») открытым текстом, а отозванные записи не
     * удалялись никогда — таблица работала вечным журналом «кто чем пользовался».
     * README при этом обещал, что релей «имён прочитать не может».
     *
     * ПОЧЕМУ НЕ УДАЛЯЕМ СТРОКУ ЦЕЛИКОМ. Она держит два инварианта: отозванный
     * deviceId нельзя оживить (putAccountRoster сверяется с revoked_at), а чужой
     * device_pk нельзя переприсвоить. Удалив строку, мы бы открыли и то и другое.
     * Поэтому оставляем ключи и метки времени, а имя/платформу/сертификат стираем.
     *
     * ЧЕГО ЭТО НЕ ДАЁТ. Тот же сертификат с тем же именем остаётся в подписанном
     * roster (accounts.roster_json): он подписан владельцем, отдаётся получателям
     * целиком и релей не вправе его редактировать. Полностью убрать имена с
     * сервера можно только перестав класть их в сертификат — это изменение
     * протокола на клиентах, не серверная правка.
     *
     * Возвращает число вычищенных записей.
     */
    redactRevokedDevices(now = Date.now(), retentionMs = REVOKED_DEVICE_REDACT_MS) {
      return device.redact.run(now, now - retentionMs).changes;
    },
    /** Транспортные данные отозванного устройства больше не нужны и не доставляются. */
    purgeDeviceTransport(devicePk) {
      const queued = dropQueueFor(devicePk);
      tok.del.run(devicePk);
      otp.delAll.run(devicePk);
      spk.delFor.run(devicePk);
      return queued;
    },

    // --- relay directory ----------------------------------------------------
    // S9: каталог отдаём уже усечённым до потолка (самые свежие вперёд), чтобы
    // мусор из gossip не раздувал ответы даже если чистка ещё не отработала.
    directory() {
      return dir.all.all().slice(0, RELAY_DIR_MAX).map((r) => r.url);
    },
    addRelays(urls, now) {
      const tx = db.transaction((list) => {
        for (const u of list) dir.upsert.run(u, now);
        // S9: раньше каталог только пополнялся (upsert) и НИКОГДА не чистился —
        // любой аутентифицированный клиент через relay-advertise заливал 500
        // валидных URL, после чего настоящие релеи не добавлялись, а gossip слал
        // запросы к мусорным адресам. Теперь на каждое пополнение вычищаем
        // протухшие (TTL) и вытесняем всё сверх потолка по свежести.
        if (Number.isFinite(now)) dir.expire.run(now - RELAY_DIR_TTL_MS);
        dir.trim.run(RELAY_DIR_MAX);
      });
      tx(urls);
    },

    // --- ОТЧ-1: отчёты о неполадках ------------------------------------------
    /** Принять отчёт. Повтор того же id молча игнорируется — это не ошибка. */
    addReport(id, at, body) {
      rep.put.run(String(id), Number(at) || 0, String(body));
    },
    /** Страница отчётов, самые старые вперёд: выгрузка идёт по кругу до пустой. */
    reportsPage(limit) {
      return rep.page.all(Math.max(1, Number(limit) || 1));
    },
    /** Удалить забранные отчёты. Возвращает, сколько записей реально ушло. */
    deleteReports(ids) {
      const list = (Array.isArray(ids) ? ids : []).map((id) => String(id));
      if (!list.length) return 0;
      let removed = 0;
      const tx = db.transaction((items) => {
        for (const id of items) removed += rep.del.run(id).changes;
      });
      tx(list);
      return removed;
    },
    /** Уборка по сроку: отчёт, за которым не пришли, не лежит вечно. */
    sweepReports(cutoff) {
      return rep.expire.run(Number(cutoff) || 0).changes;
    },
    reportsCount() {
      return rep.count.get().c;
    },

    // --- stats / lifecycle --------------------------------------------------
    stats() {
      return {
        usersQueued: q.usersQueued.get().c + binary.usersQueued.get().c,
        totalQueued: q.totalQueued.get().c + binary.totalQueued.get().c,
        relays: dir.count.get().c,
        accounts: account.count.get().c,
        activeDevices: device.countActive.get().c,
      };
    },
    /**
     * Сколько байт занимает очередь (тела в БД + blob-файлы). M10: раньше это
     * сканировало ВЕСЬ каталог блобов синхронно на КАЖДЫЙ скрейп /metrics
     * (readdirSync+statSync), блокируя event-loop при большом числе файлов. Теперь
     * возвращаем счётчик liveBytes, который поддерживается инкрементально — O(1).
     */
    queueBytes() {
      return liveBytes;
    },
    /**
     * АУД-06: дождаться записи начатых тел. Вызывается при штатной остановке —
     * иначе конверт, чья запись шла в момент SIGTERM, потерял бы тело.
     */
    flushPendingBlobs,
    /**
     * Форма схемы — для тестов (store.test.js). Обычному коду они не нужны, но
     * проверять «в базе нет колонки from_pk и индекса по (from_pk,to_pk)» иначе
     * нечем: база :memory: недоступна второму соединению, а именно на форме
     * схемы держится обещание ГРФ-1. Проверка, которую нельзя написать, — это
     * проверка, которой не будет.
     */
    tableColumnsForTest(table) {
      return db
        .prepare('SELECT name FROM pragma_table_info(?)')
        .all(table)
        .map((r) => r.name);
    },
    indexNamesForTest() {
      return db
        .prepare("SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'")
        .all()
        .map((r) => r.name);
    },
    close() {
      db.close();
    },
  };
}

module.exports = { createStore };
