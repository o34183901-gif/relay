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
    CREATE TABLE IF NOT EXISTS identities  (pk TEXT PRIMARY KEY, sign_pk TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS push_tokens (pk TEXT PRIMARY KEY, token TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS directory   (url TEXT PRIMARY KEY, last_seen INTEGER);
  `);
  // Миграция существующих БД: колонка blob (1 = тело лежит файлом в blobDir).
  const hasBlobCol = db.prepare("SELECT count(*) c FROM pragma_table_info('queue') WHERE name='blob'").get().c;
  if (!hasBlobCol) db.exec('ALTER TABLE queue ADD COLUMN blob INTEGER DEFAULT 0');

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
  function dropRow(r) {
    q.delId.run(r.id);
    if (r.blob) unlinkBlob(r.id);
  }

  const q = {
    insert: db.prepare(
      'INSERT OR REPLACE INTO queue (id,to_pk,from_pk,envelope,silent,call_push,ts,blob) VALUES (?,?,?,?,?,?,?,?)'
    ),
    forUser: db.prepare('SELECT * FROM queue WHERE to_pk=? ORDER BY ts ASC'),
    countFor: db.prepare('SELECT count(*) c FROM queue WHERE to_pk=?'),
    oldestFor: db.prepare('SELECT id, blob FROM queue WHERE to_pk=? ORDER BY ts ASC LIMIT 1'),
    byId: db.prepare('SELECT * FROM queue WHERE id=?'),
    delId: db.prepare('DELETE FROM queue WHERE id=?'),
    blobsOlder: db.prepare('SELECT id FROM queue WHERE blob=1 AND ts < ?'),
    blobIds: db.prepare('SELECT id FROM queue WHERE blob=1'),
    usersQueued: db.prepare('SELECT count(DISTINCT to_pk) c FROM queue'),
    totalQueued: db.prepare('SELECT count(*) c FROM queue'),
    expire: db.prepare('DELETE FROM queue WHERE ts < ?'),
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
    return {
      id: r.id,
      from: r.from_pk || undefined,
      envelope: JSON.parse(envJson),
      silent: !!r.silent,
      callPush: !!r.call_push,
      ts: r.ts,
    };
  };

  const id = {
    get: db.prepare('SELECT sign_pk FROM identities WHERE pk=?'),
    set: db.prepare('INSERT OR IGNORE INTO identities (pk,sign_pk) VALUES (?,?)'),
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
  };

  return {
    // --- queue --------------------------------------------------------------
    /**
     * Положить конверт в очередь получателя; при переполнении вытеснить старейший.
     * Тело крупнее blobThreshold уходит файлом в blobDir — в БД только ссылка.
     */
    enqueue({ id: mid, to, from, envelope, silent, callPush, ts, maxPerUser }) {
      if (maxPerUser && q.countFor.get(to).c >= maxPerUser) {
        const o = q.oldestFor.get(to);
        if (o) dropRow(o);
      }
      const envJson = JSON.stringify(envelope);
      const asBlob = blobDir && Buffer.byteLength(envJson) > blobThreshold;
      if (asBlob) writeBlob(mid, envJson);
      q.insert.run(mid, to, from || null, asBlob ? '' : envJson, silent ? 1 : 0, callPush ? 1 : 0, ts, asBlob ? 1 : 0);
    },
    /** Все конверты, ждущие получателя (в порядке поступления). */
    queueFor(to) {
      return q.forUser.all(to).map(rowToItem).filter(Boolean);
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
    /** Удалить всё старше `cutoffTs` (TTL). Вернуть число удалённых. */
    expireOlderThan(cutoffTs) {
      for (const r of q.blobsOlder.all(cutoffTs)) unlinkBlob(r.id);
      return q.expire.run(cutoffTs).changes;
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
    bindSignKey(pk, signPk) {
      id.set.run(pk, signPk); // INSERT OR IGNORE — первый выигрывает (TOFU)
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

    // --- relay directory ----------------------------------------------------
    directory() {
      return dir.all.all().map((r) => r.url);
    },
    addRelays(urls, now) {
      const tx = db.transaction((list) => {
        for (const u of list) dir.upsert.run(u, now);
      });
      tx(urls);
    },

    // --- stats / lifecycle --------------------------------------------------
    stats() {
      return {
        usersQueued: q.usersQueued.get().c,
        totalQueued: q.totalQueued.get().c,
        relays: dir.count.get().c,
      };
    },
    close() {
      db.close();
    },
  };
}

module.exports = { createStore };
