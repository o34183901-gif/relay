const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const Database = require('better-sqlite3');

const { admitEnvelope } = require('./queueAdmission');
const { evictionSize } = require('./mailboxEvict');
const RELAY_DIR_MAX = 500;
const RELAY_DIR_TTL_MS = 14 * 24 * 3600 * 1000;
const REVOKED_DEVICE_REDACT_MS = 30 * 24 * 3600 * 1000;
const MIGRATION_VACUUM_MAX_BYTES = 512 * 1024 * 1024;
const AT_REST_KEY_SUFFIX = '.metakey';
function loadAtRestKey(dbPath) {
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
    fs.writeFileSync(keyPath, key.toString('hex'), { mode: 0o600, flag: 'wx' });
  } catch (error) {
    if (error.code === 'EEXIST') {
      const raw = fs.readFileSync(keyPath, 'utf8').trim();
      const existing = Buffer.from(raw, 'hex');
      if (existing.length === 32) return existing;
    }
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
function createStore(dbPath, opts = {}) {
  const blobDir = opts.blobDir || null;
  const blobThreshold = opts.blobThreshold || 64 * 1024;
  if (blobDir) fs.mkdirSync(blobDir, { recursive: true });
  const db = new Database(dbPath || ':memory:');
  db.pragma('journal_mode = WAL');
  db.pragma('synchronous = NORMAL');
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
  const hasBlobCol = db.prepare("SELECT count(*) c FROM pragma_table_info('queue') WHERE name='blob'").get().c;
  if (!hasBlobCol) db.exec('ALTER TABLE queue ADD COLUMN blob INTEGER DEFAULT 0');
  const hasBytesCol = db.prepare("SELECT count(*) c FROM pragma_table_info('queue') WHERE name='bytes'").get().c;
  if (!hasBytesCol) db.exec('ALTER TABLE queue ADD COLUMN bytes INTEGER DEFAULT 0');
  const hasProvenCol = db.prepare("SELECT count(*) c FROM pragma_table_info('identities') WHERE name='proven'").get().c;
  if (!hasProvenCol) db.exec('ALTER TABLE identities ADD COLUMN proven INTEGER DEFAULT 0');
  const hasLastSeenCol = db.prepare("SELECT count(*) c FROM pragma_table_info('identities') WHERE name='last_seen'").get().c;
  if (!hasLastSeenCol) db.exec('ALTER TABLE identities ADD COLUMN last_seen INTEGER DEFAULT 0');
  const hasSpkPqCol = db.prepare("SELECT count(*) c FROM pragma_table_info('prekeys_spk') WHERE name='pq'").get().c;
  if (!hasSpkPqCol) db.exec('ALTER TABLE prekeys_spk ADD COLUMN pq TEXT');
  const deviceColumns0 = new Set(
    db.prepare("SELECT name FROM pragma_table_info('account_devices')").all().map((r) => r.name)
  );
  if (!deviceColumns0.has('redacted_at')) db.exec('ALTER TABLE account_devices ADD COLUMN redacted_at INTEGER');
  const mbxColumns = new Set(
    db.prepare("SELECT name FROM pragma_table_info('mbx')").all().map((r) => r.name)
  );
  if (!mbxColumns.has('ord')) db.exec('ALTER TABLE mbx ADD COLUMN ord INTEGER');
  db.exec('CREATE INDEX IF NOT EXISTS idx_mbx_slot_ord ON mbx(slot, ord)');
  const columnsOf = (table) =>
    new Set(db.prepare(`SELECT name FROM pragma_table_info('${table}')`).all().map((r) => r.name));
  const metaKey = subKey(loadAtRestKey(dbPath), 'licno/queue-sender-meta/v1');
  const tagKey = subKey(metaKey, 'licno/queue-pair-tag/v1');
  function sealMeta(value) {
    if (value == null) return null;
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', metaKey, iv);
    const body = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), body]);
  }
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
    if (!qCols.has('stranger')) db.exec('ALTER TABLE queue ADD COLUMN stranger INTEGER DEFAULT 0');
    if (!bCols.has('stranger')) db.exec('ALTER TABLE binary_queue ADD COLUMN stranger INTEGER DEFAULT 0');
    db.exec('CREATE INDEX IF NOT EXISTS idx_queue_stranger ON queue(to_pk, stranger, ts)');
    db.exec(
      'CREATE INDEX IF NOT EXISTS idx_binary_queue_stranger ON binary_queue(to_pk, stranger, ts)'
    );
    db.exec(`
      CREATE TABLE IF NOT EXISTS correspondents (tag BLOB PRIMARY KEY, ts INTEGER NOT NULL);
      CREATE INDEX IF NOT EXISTS idx_correspondents_ts ON correspondents(ts);
    `);
    db.exec('DROP INDEX IF EXISTS idx_queue_from_to');
    db.exec('DROP INDEX IF EXISTS idx_binary_queue_from_to');
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
      for (const col of legacyQueue) db.exec(`ALTER TABLE queue DROP COLUMN ${col}`);
      for (const col of legacyBinary) db.exec(`ALTER TABLE binary_queue DROP COLUMN ${col}`);
    }
    db.exec('CREATE INDEX IF NOT EXISTS idx_queue_pair ON queue(pair_tag, ts)');
    db.exec('CREATE INDEX IF NOT EXISTS idx_binary_queue_pair ON binary_queue(pair_tag, ts)');
    if (migrated && dbPath && dbPath !== ':memory:') {
      let size = 0;
      try {
        size = fs.statSync(dbPath).size;
      } catch (error) {
        size = 0;
      }
      if (size <= MIGRATION_VACUUM_MAX_BYTES) {
        db.exec('VACUUM');
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
  const pendingBlobs = new Map();
  const pendingBinaries = new Map();
  const bodyWrites = new Set();
  function writeBody(pending, mid, file, body, what) {
    const entry = { body, cancelled: false };
    pending.set(mid, entry);
    const tmp = file + '.tmp';
    const promise = fs.promises
      .writeFile(tmp, body)
      .then(async () => {
        if (entry.cancelled) return fs.promises.unlink(tmp).catch(() => {});
        await fs.promises.rename(tmp, file);
        if (entry.cancelled) await fs.promises.unlink(file).catch(() => {});
      })
      .catch((error) => {
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
  function pendingBody(pending, mid) {
    const entry = pending.get(mid);
    return entry && !entry.cancelled ? entry.body : null;
  }
  const pendingBlob = (mid) => pendingBody(pendingBlobs, mid);
  const pendingBinary = (mid) => pendingBody(pendingBinaries, mid);
  function unlinkBody(pending, mid, file) {
    const entry = pending.get(mid);
    if (entry) {
      entry.cancelled = true;
      pending.delete(mid);
    }
    try {
      fs.unlinkSync(file);
    } catch (e) {
    }
  }
  const unlinkBlob = (mid) => unlinkBody(pendingBlobs, mid, blobPath(mid));
  const unlinkBinary = (mid) => unlinkBody(pendingBinaries, mid, binaryPath(mid));
  async function flushPendingBlobs() {
    while (bodyWrites.size) {
      await Promise.allSettled([...bodyWrites]);
    }
  }
  function dropRow(r) {
    const removed = q.delId.run(r.id).changes;
    if (r.blob) unlinkBlob(r.id);
    if (!removed) return;
    liveCount = Math.max(0, liveCount - 1);
    liveBytes = Math.max(0, liveBytes - (r.bytes || 0));
  }
  const q = {
    insert: db.prepare(
      'INSERT OR REPLACE INTO queue (id,to_pk,envelope,silent,call_push,ts,blob,bytes,sender_meta,pair_tag,stranger) VALUES (?,?,?,?,?,?,?,?,?,?,?)'
    ),
    forUser: db.prepare('SELECT * FROM queue WHERE to_pk=? ORDER BY ts ASC'),
    idsForUser: db.prepare('SELECT id FROM queue WHERE to_pk=? ORDER BY ts ASC'),
    countFor: db.prepare('SELECT count(*) c FROM queue WHERE to_pk=?'),
    countFromTo: db.prepare('SELECT count(*) c FROM queue WHERE pair_tag=?'),
    oldestFor: db.prepare('SELECT id, blob, bytes FROM queue WHERE to_pk=? ORDER BY ts ASC LIMIT 1'),
    oldestFromTo: db.prepare('SELECT id, blob, bytes FROM queue WHERE pair_tag=? ORDER BY ts ASC LIMIT 1'),
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
    if (!removed) return;
    liveCount = Math.max(0, liveCount - 1);
    liveBytes = Math.max(0, liveBytes - (row.bytes || 0));
  }
  const correspondents = {
    note: db.prepare('INSERT OR REPLACE INTO correspondents (tag, ts) VALUES (?, ?)'),
    get: db.prepare('SELECT ts FROM correspondents WHERE tag=?'),
    expire: db.prepare('DELETE FROM correspondents WHERE ts < ?'),
    count: db.prepare('SELECT count(*) c FROM correspondents'),
    dropOldest: db.prepare(
      'DELETE FROM correspondents WHERE tag IN (SELECT tag FROM correspondents ORDER BY ts ASC LIMIT ?)'
    ),
  };
  const MAX_CORRESPONDENTS = 200000;
  function noteCorrespondent(tag, ts) {
    if (!tag) return;
    correspondents.note.run(tag, ts);
    const over = correspondents.count.get().c - MAX_CORRESPONDENTS;
    if (over > 0) correspondents.dropOldest.run(over);
  }
  function isCorrespondent(tag, now, ttlMs) {
    if (!tag || !ttlMs) return false;
    const row = correspondents.get.get(tag);
    return !!row && now - row.ts <= ttlMs;
  }
  function binaryItem(row, payload) {
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
    let payload = pendingBinary(row.id);
    if (payload == null) {
      try {
        payload = fs.readFileSync(binaryPath(row.id));
      } catch (error) {
        dropBinaryRow(row);
        return null;
      }
    }
    return binaryItem(row, payload);
  }
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
  const rowToItem = (r) => {
    let envJson = r.envelope;
    if (r.blob) {
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
    let envelope;
    try {
      envelope = JSON.parse(envJson);
    } catch (e) {
      dropRow(r);
      return null;
    }
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
      bytes: Number(r.bytes) || 0,
    };
  };
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
  let liveCount = q.totalQueued.get().c + binary.totalQueued.get().c;
  let liveBytes = q.sumBytes.get().c + binary.sumBytes.get().c;
  const id = {
    get: db.prepare('SELECT sign_pk, proven FROM identities WHERE pk=?'),
    set: db.prepare('INSERT OR IGNORE INTO identities (pk,sign_pk,proven,last_seen) VALUES (?,?,?,?)'),
    rebind: db.prepare('INSERT OR REPLACE INTO identities (pk,sign_pk,proven,last_seen) VALUES (?,?,?,?)'),
    touch: db.prepare('UPDATE identities SET last_seen=? WHERE pk=?'),
    count: db.prepare('SELECT count(*) c FROM identities'),
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
    expire: db.prepare('DELETE FROM directory WHERE last_seen < ?'),
    trim: db.prepare(
      'DELETE FROM directory WHERE url NOT IN (SELECT url FROM directory ORDER BY last_seen DESC LIMIT ?)'
    ),
  };
  const rep = {
    put: db.prepare('INSERT OR IGNORE INTO reports (id,at,body) VALUES (?,?,?)'),
    page: db.prepare('SELECT id,at,body FROM reports ORDER BY at LIMIT ?'),
    del: db.prepare('DELETE FROM reports WHERE id = ?'),
    expire: db.prepare('DELETE FROM reports WHERE at < ?'),
    count: db.prepare('SELECT count(*) c FROM reports'),
  };
  const mbxq = {
    put: db.prepare('INSERT OR IGNORE INTO mbx (key,vh,val,mac,slot,seq,ord) VALUES (?,?,?,?,?,?,?)'),
    keys: db.prepare('SELECT key FROM mbx'),
    bucket: db.prepare('SELECT key,val,mac,slot FROM mbx WHERE key>=? AND key<=? LIMIT ?'),
    after: db.prepare('SELECT key,val,mac,slot,seq FROM mbx WHERE seq>? ORDER BY seq LIMIT ?'),
    count: db.prepare('SELECT count(*) c FROM mbx'),
    maxSeq: db.prepare('SELECT COALESCE(MAX(seq),0) s FROM mbx'),
    expire: db.prepare('DELETE FROM mbx WHERE slot <= ?'),
    oldestSlot: db.prepare('SELECT COALESCE(MIN(slot),0) s FROM mbx'),
    evictBatch: db.prepare(
      'DELETE FROM mbx WHERE rowid IN (SELECT rowid FROM mbx WHERE slot=? ORDER BY ord LIMIT ?)'
    ),
    slotCount: db.prepare('SELECT count(*) c FROM mbx WHERE slot=?'),
  };
  let mbxSeq = mbxq.maxSeq.get().s;
  let mbxRevision = 0;
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
    enqueue({
      id: mid,
      to,
      from,
      fromAccount,
      fromDeviceId,
      deviceCertificate,
      deviceRoster,
      envelope,
      envelopeJson,
      silent,
      callPush,
      ts,
      maxPerUser,
      maxPerSender,
      maxTotal,
      maxTotalBytes,
      reserve = 0,
      reciprocityTtlMs = 0,
    }) {
      const envJson = typeof envelopeJson === 'string' ? envelopeJson : JSON.stringify(envelope);
      const bytes = Buffer.byteLength(envJson);
      const tag = pairTag(from, to);
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
        const own = q.oldestFromTo.get(tag);
        if (own) dropRow(own);
        else return false;
      } else if (verdict.evict === 'stranger') {
        const spam = q.oldestStranger.get(to);
        if (spam) dropRow(spam);
        else return false;
      } else if (verdict.evict === 'oldest') {
        const o = q.oldestFor.get(to);
        if (o) dropRow(o);
      }
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
        from && !correspondent ? 1 : 0
      );
      liveCount += 1;
      liveBytes += bytes;
      noteCorrespondent(tag, ts);
      return true;
    },
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
      reserve = 0,
      reciprocityTtlMs = 0,
    }) {
      const bytes = payload.length;
      const tag = pairTag(from, to);
      const recipientCount = q.countFor.get(to).c + binary.countFor.get(to).c;
      const pairCount = q.countFromTo.get(tag).c + binary.countFromTo.get(tag).c;
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
          from && !correspondent ? 1 : 0
        );
      } catch (error) {
        unlinkBinary(binaryId);
        throw error;
      }
      liveCount += 1;
      liveBytes += bytes;
      noteCorrespondent(tag, ts);
      return true;
    },
    binaryQueueIdsFor(to) {
      return binary.idsForUser.all(to).map((row) => row.id);
    },
    getBinaryItem(binaryId) {
      return binaryRowToItem(binary.byId.get(binaryId));
    },
    getBinaryItemAsync(binaryId) {
      return binaryRowToItemAsync(binary.byId.get(binaryId));
    },
    ackBinary(to, binaryId) {
      const row = binary.byId.get(binaryId);
      if (!row || row.to_pk !== to) return null;
      const result = {
        from: (openMeta(row.sender_meta) || {}).from,
        ref: row.ref || undefined,
        transferId: row.transfer_id,
        index: row.chunk_index,
      };
      dropBinaryRow(row);
      return result;
    },
    queueFor(to) {
      return q.forUser.all(to).map(rowToItem).filter(Boolean);
    },
    queueIdsFor(to) {
      return q.idsForUser.all(to).map((r) => r.id);
    },
    getItem(mid) {
      const r = q.byId.get(mid);
      return r ? rowToItem(r) : null;
    },
    getItemAsync(mid) {
      const r = q.byId.get(mid);
      return r ? rowToItemAsync(r) : Promise.resolve(null);
    },
    ack(to, mid) {
      const r = q.byId.get(mid);
      if (!r || r.to_pk !== to) return null;
      dropRow(r);
      return (openMeta(r.sender_meta) || {}).from || null;
    },
    dropQueueFor,
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
            crypto.randomInt(0, 0x7fffffff)
          ).changes;
          if (changed) added += 1;
          else mbxSeq -= 1;
        }
      });
      insert(Array.isArray(records) ? records : []);
      if (added) mbxRevision += 1;
      return added;
    },
    mbxKeys() {
      return mbxq.keys.all().map((row) => row.key);
    },
    mbxBucket(low, high, limit) {
      return mbxq.bucket.all(low, high, limit);
    },
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
    mbxRevision() {
      return mbxRevision;
    },
    mbxExpire(slot) {
      const removed = mbxq.expire.run(slot).changes;
      if (removed) mbxRevision += 1;
      return removed;
    },
    mbxEvictSome(limit) {
      const want = Math.max(0, Math.floor(Number(limit) || 0));
      if (!want) return 0;
      const oldest = mbxq.oldestSlot.get().s;
      if (!oldest) return 0;
      const removed = mbxq.evictBatch.run(oldest, want).changes;
      if (removed) mbxRevision += 1;
      return removed;
    },
    mbxSlotCount(slot) {
      return mbxq.slotCount.get(slot).c;
    },
    mbxOldestSlot() {
      return mbxq.oldestSlot.get().s;
    },
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
    expireOlderThan(cutoffTs) {
      for (const r of q.blobsOlder.all(cutoffTs)) unlinkBlob(r.id);
      const binaryRows = binary.older.all(cutoffTs);
      for (const row of binaryRows) unlinkBinary(row.id);
      correspondents.expire.run(cutoffTs);
      const removed = q.expire.run(cutoffTs).changes + binary.expire.run(cutoffTs).changes;
      liveCount = q.totalQueued.get().c + binary.totalQueued.get().c;
      liveBytes = q.sumBytes.get().c + binary.sumBytes.get().c;
      return removed;
    },
    cleanupOrphanBlobs() {
      if (!blobDir) return 0;
      const referenced = new Set(q.blobIds.all().map((r) => r.id));
      const referencedBinary = new Set(binary.allIds.all().map((row) => row.id));
      let removed = 0;
      for (const f of fs.readdirSync(blobDir)) {
        const isTmp = f.endsWith('.json.tmp') || f.endsWith('.bin.tmp');
        const isBlob = f.endsWith('.json');
        const isBinary = f.endsWith('.bin');
        if (!isTmp && !isBlob && !isBinary) continue;
        const mid = f.replace(/\.(json|bin)(\.tmp)?$/, '');
        if (isTmp && (pendingBlobs.has(mid) || pendingBinaries.has(mid))) continue;
        if (isBlob && referenced.has(mid)) continue;
        if (isBinary && referencedBinary.has(mid)) continue;
        try {
          fs.unlinkSync(path.join(blobDir, f));
          removed += 1;
        } catch (e) {
        }
      }
      return removed;
    },
    getSignKey(pk) {
      const r = id.get.get(pk);
      return r ? r.sign_pk : null;
    },
    getIdentity(pk) {
      const r = id.get.get(pk);
      return r ? { signPk: r.sign_pk, proven: !!r.proven } : null;
    },
    bindSignKey(pk, signPk, proven = false, now = 0) {
      id.set.run(pk, signPk, proven ? 1 : 0, now);
    },
    rebindSignKey(pk, signPk, now = 0) {
      id.rebind.run(pk, signPk, 1, now);
    },
    touchIdentity(pk, now) {
      id.touch.run(now, pk);
    },
    identityCount() {
      return id.count.get().c;
    },
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
    setSpk(pk, s) {
      spk.set.run(pk, s.id, s.pub, s.sig, s.pq || null);
    },
    getSpk(pk) {
      const r = spk.get.get(pk);
      if (!r) return null;
      return r.pq ? { id: r.id, pub: r.pub, sig: r.sig, pq: r.pq } : { id: r.id, pub: r.pub, sig: r.sig };
    },
    replaceOtps(pk, list) {
      const tx = db.transaction((items) => {
        otp.delAll.run(pk);
        for (const k of items) otp.insert.run(pk, k.id, k.pub);
      });
      tx(list);
    },
    takeOtp(pk) {
      const r = otp.takeOne.get(pk);
      if (!r) return null;
      otp.delOne.run(pk, r.id);
      return { id: r.id, pub: r.pub };
    },
    countOtps(pk) {
      return otp.count.get(pk).c;
    },
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
    redactRevokedDevices(now = Date.now(), retentionMs = REVOKED_DEVICE_REDACT_MS) {
      return device.redact.run(now, now - retentionMs).changes;
    },
    purgeDeviceTransport(devicePk) {
      const queued = dropQueueFor(devicePk);
      tok.del.run(devicePk);
      otp.delAll.run(devicePk);
      spk.delFor.run(devicePk);
      return queued;
    },
    directory() {
      return dir.all.all().slice(0, RELAY_DIR_MAX).map((r) => r.url);
    },
    addRelays(urls, now) {
      const tx = db.transaction((list) => {
        for (const u of list) dir.upsert.run(u, now);
        if (Number.isFinite(now)) dir.expire.run(now - RELAY_DIR_TTL_MS);
        dir.trim.run(RELAY_DIR_MAX);
      });
      tx(urls);
    },
    addReport(id, at, body) {
      rep.put.run(String(id), Number(at) || 0, String(body));
    },
    reportsPage(limit) {
      return rep.page.all(Math.max(1, Number(limit) || 1));
    },
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
    sweepReports(cutoff) {
      return rep.expire.run(Number(cutoff) || 0).changes;
    },
    reportsCount() {
      return rep.count.get().c;
    },
    stats() {
      return {
        usersQueued: q.usersQueued.get().c + binary.usersQueued.get().c,
        totalQueued: q.totalQueued.get().c + binary.totalQueued.get().c,
        relays: dir.count.get().c,
        accounts: account.count.get().c,
        activeDevices: device.countActive.get().c,
      };
    },
    queueBytes() {
      return liveBytes;
    },
    flushPendingBlobs,
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