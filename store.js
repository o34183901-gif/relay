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
const Database = require('better-sqlite3');

// S9: потолок и TTL реплицированного каталога релеев. Держим только N самых свежих
// анонсов и вычищаем протухшие — иначе gossip-мусор навсегда забивал каталог.
const RELAY_DIR_MAX = 500;
const RELAY_DIR_TTL_MS = 14 * 24 * 3600 * 1000; // 14 дней без анонса — забываем релей

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
  db.exec(`
    CREATE TABLE IF NOT EXISTS queue (
      id        TEXT PRIMARY KEY,
      to_pk     TEXT NOT NULL,
      from_pk   TEXT,
      envelope  TEXT NOT NULL,
      silent    INTEGER DEFAULT 0,
      call_push INTEGER DEFAULT 0,
      ts        INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_queue_to ON queue(to_pk, ts);
    CREATE INDEX IF NOT EXISTS idx_queue_from_to ON queue(from_pk, to_pk, ts);
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
  // v2: проверяемые метаданные устройства отправителя. Старые строки остаются
  // валидными (NULL => from_account равен from_pk на стороне relay/client).
  const queueColumns = new Set(db.prepare("SELECT name FROM pragma_table_info('queue')").all().map((r) => r.name));
  if (!queueColumns.has('from_account')) db.exec('ALTER TABLE queue ADD COLUMN from_account TEXT');
  if (!queueColumns.has('from_device')) db.exec('ALTER TABLE queue ADD COLUMN from_device TEXT');
  if (!queueColumns.has('device_cert')) db.exec('ALTER TABLE queue ADD COLUMN device_cert TEXT');
  if (!queueColumns.has('device_roster')) db.exec('ALTER TABLE queue ADD COLUMN device_roster TEXT');
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

  const blobPath = (mid) => path.join(blobDir, mid + '.json');
  function writeBlob(mid, envJson) {
    // tmp + rename: файл появляется атомарно, недописанных блобов не бывает
    const tmp = blobPath(mid) + '.tmp';
    fs.writeFileSync(tmp, envJson);
    fs.renameSync(tmp, blobPath(mid));
  }
  function unlinkBlob(mid) {
    try {
      fs.unlinkSync(blobPath(mid));
    } catch (e) {}
  }
  // Удалить строку очереди и синхронно поправить счётчики веса/количества.
  // r ДОЛЖЕН содержать поле bytes (все запросы, чьи строки сюда попадают,
  // выбирают bytes): byId/forUser — через SELECT *, oldest* — явно.
  function dropRow(r) {
    q.delId.run(r.id);
    if (r.blob) unlinkBlob(r.id);
    liveCount = Math.max(0, liveCount - 1);
    liveBytes = Math.max(0, liveBytes - (r.bytes || 0));
  }

  const q = {
    insert: db.prepare(
      'INSERT OR REPLACE INTO queue (id,to_pk,from_pk,envelope,silent,call_push,ts,blob,bytes,from_account,from_device,device_cert,device_roster) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)'
    ),
    forUser: db.prepare('SELECT * FROM queue WHERE to_pk=? ORDER BY ts ASC'),
    // S1: только id (без тел) — для потокового flush с backpressure, чтобы не
    // материализовать всю очередь получателя в память разом.
    idsForUser: db.prepare('SELECT id FROM queue WHERE to_pk=? ORDER BY ts ASC'),
    countFor: db.prepare('SELECT count(*) c FROM queue WHERE to_pk=?'),
    countFromTo: db.prepare('SELECT count(*) c FROM queue WHERE from_pk=? AND to_pk=?'),
    oldestFor: db.prepare('SELECT id, blob, bytes FROM queue WHERE to_pk=? ORDER BY ts ASC LIMIT 1'),
    oldestFromTo: db.prepare('SELECT id, blob, bytes FROM queue WHERE from_pk=? AND to_pk=? ORDER BY ts ASC LIMIT 1'),
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
  // null — если тело-файл пропал (например, volume почистили руками): такая
  // строка мертва, подчищаем её и пропускаем.
  const rowToItem = (r) => {
    let envJson = r.envelope;
    if (r.blob) {
      try {
        envJson = fs.readFileSync(blobPath(r.id), 'utf8');
      } catch (e) {
        dropRow(r);
        return null;
      }
    }
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
    return {
      id: r.id,
      from: r.from_pk || undefined,
      fromAccount: r.from_account || r.from_pk || undefined,
      fromDeviceId: r.from_device || undefined,
      deviceCertificate: (() => {
        if (!r.device_cert) return undefined;
        try {
          return JSON.parse(r.device_cert);
        } catch (e) {
          return undefined;
        }
      })(),
      deviceRoster: (() => {
        if (!r.device_roster) return undefined;
        try {
          return JSON.parse(r.device_roster);
        } catch (e) {
          return undefined;
        }
      })(),
      envelope,
      silent: !!r.silent,
      callPush: !!r.call_push,
      ts: r.ts,
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
  let liveCount = q.totalQueued.get().c;
  let liveBytes = q.sumBytes.get().c;

  const id = {
    get: db.prepare('SELECT sign_pk, proven FROM identities WHERE pk=?'),
    set: db.prepare('INSERT OR IGNORE INTO identities (pk,sign_pk,proven,last_seen) VALUES (?,?,?,?)'),
    rebind: db.prepare('INSERT OR REPLACE INTO identities (pk,sign_pk,proven,last_seen) VALUES (?,?,?,?)'),
    touch: db.prepare('UPDATE identities SET last_seen=? WHERE pk=?'),
    count: db.prepare('SELECT count(*) c FROM identities'),
    // M-02: холодные identity без ожидающих конвертов — кандидаты на вытеснение
    // (identity с непрочитанной очередью НЕ трогаем, чтобы не потерять сообщения).
    coldNoQueue: db.prepare(
      'SELECT i.pk FROM identities i WHERE NOT EXISTS (SELECT 1 FROM queue q WHERE q.to_pk = i.pk) ORDER BY i.last_seen ASC LIMIT ?'
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
  const spk = {
    get: db.prepare('SELECT id, pub, sig FROM prekeys_spk WHERE pk=?'),
    set: db.prepare('INSERT OR REPLACE INTO prekeys_spk (pk,id,pub,sig) VALUES (?,?,?,?)'),
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
      'SELECT account_pk,device_id,device_pk,device_sign_pk,certificate,name,platform,issued_at,revoked_at,last_seen FROM account_devices WHERE device_pk=?'
    ),
    byId: db.prepare(
      'SELECT account_pk,device_id,device_pk,device_sign_pk,certificate,name,platform,issued_at,revoked_at,last_seen FROM account_devices WHERE account_pk=? AND device_id=?'
    ),
    forAccount: db.prepare(
      'SELECT account_pk,device_id,device_pk,device_sign_pk,certificate,name,platform,issued_at,revoked_at,last_seen FROM account_devices WHERE account_pk=? ORDER BY issued_at ASC, device_id ASC'
    ),
    upsert: db.prepare(`
      INSERT INTO account_devices
        (account_pk,device_id,device_pk,device_sign_pk,certificate,name,platform,issued_at,revoked_at,last_seen)
      VALUES (?,?,?,?,?,?,?,?,?,?)
      ON CONFLICT(account_pk,device_id) DO UPDATE SET
        device_pk=excluded.device_pk,
        device_sign_pk=excluded.device_sign_pk,
        certificate=excluded.certificate,
        name=excluded.name,
        platform=excluded.platform,
        issued_at=excluded.issued_at,
        revoked_at=excluded.revoked_at
    `),
    revokeById: db.prepare(
      'UPDATE account_devices SET revoked_at=? WHERE account_pk=? AND device_id=? AND revoked_at IS NULL'
    ),
    touch: db.prepare('UPDATE account_devices SET last_seen=? WHERE device_pk=?'),
    countActive: db.prepare('SELECT count(*) c FROM account_devices WHERE revoked_at IS NULL'),
  };

  function deviceRow(r) {
    if (!r) return null;
    let certificate = null;
    try {
      certificate = JSON.parse(r.certificate);
    } catch (e) {}
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
      lastSeen: r.last_seen || 0,
    };
  }

  function dropQueueFor(to) {
    const rows = q.rowsForDrop.all(to);
    for (const row of rows) dropRow(row);
    return rows.length;
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
      silent,
      callPush,
      ts,
      maxPerUser,
      maxPerSender,
      maxTotal,
      maxTotalBytes,
    }) {
      const envJson = JSON.stringify(envelope);
      const bytes = Buffer.byteLength(envJson);

      // S5: квота на пару (отправитель→получатель). Один отправитель не может
      // занять в очереди получателя больше maxPerSender конвертов — при
      // переполнении вытесняется ЕГО ЖЕ старейший (self-eviction). Это закрывает
      // таргетированную цензуру: флудер, зная адрес жертвы, больше не выдавит её
      // реальные сообщения (от других отправителей) — ротирует только свой спам.
      if (maxPerSender && from && q.countFromTo.get(from, to).c >= maxPerSender) {
        const o = q.oldestFromTo.get(from, to);
        if (o) dropRow(o);
      }
      // СРВ-2: потолок на получателя. При переполнении вытесняем ТОЛЬКО СВОЙ
      // старейший конверт этого отправителя. Раньше при отсутствии своего
      // (свежий `from`) fallback вытеснял глобально старейший конверт получателя —
      // включая реальные сообщения от честных отправителей. Это позволяло
      // Sybil-флудеру (пачка одноразовых identity, по 1 конверту каждая) вымывать
      // очередь жертвы. Теперь чужие конверты не жертвуются: если у нового
      // отправителя своих слотов нет, отклоняем НОВЫЙ конверт (не сохраняем),
      // защищая уже накопленные сообщения жертвы.
      if (maxPerUser && q.countFor.get(to).c >= maxPerUser) {
        if (from) {
          const own = q.oldestFromTo.get(from, to);
          if (own) dropRow(own);
          else return false; // свежий отправитель не вытесняет чужие → новый конверт отклонён
        } else {
          // Легаси/без отправителя: некому атрибутировать, сохраняем прежнее
          // поведение (вытесняем старейший). В самом релее `from` всегда задан
          // (аутентифицированный отправитель), поэтому Sybil-вектор закрыт веткой выше.
          const o = q.oldestFor.get(to);
          if (o) dropRow(o);
        }
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
        from || null,
        asBlob ? '' : envJson,
        silent ? 1 : 0,
        callPush ? 1 : 0,
        ts,
        asBlob ? 1 : 0,
        bytes,
        fromAccount || from || null,
        fromDeviceId || null,
        deviceCertificate ? JSON.stringify(deviceCertificate) : null,
        deviceRoster ? JSON.stringify(deviceRoster) : null
      );
      liveCount += 1;
      liveBytes += bytes;
      return true; // СРВ-2: конверт сохранён (false выше — отклонён из-за полной очереди получателя)
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
    /** Удалить конверт по id, если он адресован `to`. Вернуть from_pk (или null). */
    ack(to, mid) {
      const r = q.byId.get(mid);
      if (!r || r.to_pk !== to) return null;
      dropRow(r);
      return r.from_pk || null;
    },
    /** Удалить очередь конкретного адреса устройства (после подписанного отзыва). */
    dropQueueFor,
    /** Удалить всё старше `cutoffTs` (TTL). Вернуть число удалённых. */
    expireOlderThan(cutoffTs) {
      for (const r of q.blobsOlder.all(cutoffTs)) unlinkBlob(r.id);
      const removed = q.expire.run(cutoffTs).changes;
      // массовое удаление — пересчитываем глобальные счётчики из БД (раз в час, дёшево).
      liveCount = q.totalQueued.get().c;
      liveBytes = q.sumBytes.get().c;
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
      let removed = 0;
      for (const f of fs.readdirSync(blobDir)) {
        const isTmp = f.endsWith('.json.tmp');
        const isBlob = f.endsWith('.json');
        if (!isTmp && !isBlob) continue; // чужие файлы не трогаем
        const mid = f.replace(/\.json(\.tmp)?$/, '');
        if (isBlob && referenced.has(mid)) continue; // живой блоб
        try {
          fs.unlinkSync(path.join(blobDir, f)); // сирота или недописанный tmp
          removed += 1;
        } catch (e) {}
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
      spk.set.run(pk, s.id, s.pub, s.sig);
    },
    getSpk(pk) {
      const r = spk.get.get(pk);
      return r ? { id: r.id, pub: r.pub, sig: r.sig } : null;
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

    // --- stats / lifecycle --------------------------------------------------
    stats() {
      return {
        usersQueued: q.usersQueued.get().c,
        totalQueued: q.totalQueued.get().c,
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
    close() {
      db.close();
    },
  };
}

module.exports = { createStore };
