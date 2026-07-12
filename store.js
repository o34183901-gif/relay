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
const Database = require('better-sqlite3');

function createStore(dbPath) {
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

  const q = {
    insert: db.prepare(
      'INSERT OR REPLACE INTO queue (id,to_pk,from_pk,envelope,silent,call_push,ts) VALUES (?,?,?,?,?,?,?)'
    ),
    forUser: db.prepare('SELECT * FROM queue WHERE to_pk=? ORDER BY ts ASC'),
    countFor: db.prepare('SELECT count(*) c FROM queue WHERE to_pk=?'),
    oldestFor: db.prepare('SELECT id FROM queue WHERE to_pk=? ORDER BY ts ASC LIMIT 1'),
    byId: db.prepare('SELECT * FROM queue WHERE id=?'),
    delId: db.prepare('DELETE FROM queue WHERE id=?'),
    usersQueued: db.prepare('SELECT count(DISTINCT to_pk) c FROM queue'),
    totalQueued: db.prepare('SELECT count(*) c FROM queue'),
    expire: db.prepare('DELETE FROM queue WHERE ts < ?'),
  };
  const rowToItem = (r) => ({
    id: r.id,
    from: r.from_pk || undefined,
    envelope: JSON.parse(r.envelope),
    silent: !!r.silent,
    callPush: !!r.call_push,
    ts: r.ts,
  });

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
    /** Положить конверт в очередь получателя; при переполнении вытеснить старейший. */
    enqueue({ id: mid, to, from, envelope, silent, callPush, ts, maxPerUser }) {
      if (maxPerUser && q.countFor.get(to).c >= maxPerUser) {
        const o = q.oldestFor.get(to);
        if (o) q.delId.run(o.id);
      }
      q.insert.run(mid, to, from || null, JSON.stringify(envelope), silent ? 1 : 0, callPush ? 1 : 0, ts);
    },
    /** Все конверты, ждущие получателя (в порядке поступления). */
    queueFor(to) {
      return q.forUser.all(to).map(rowToItem);
    },
    getItem(mid) {
      const r = q.byId.get(mid);
      return r ? rowToItem(r) : null;
    },
    /** Удалить конверт по id, если он адресован `to`. Вернуть from_pk (или null). */
    ack(to, mid) {
      const r = q.byId.get(mid);
      if (!r || r.to_pk !== to) return null;
      q.delId.run(mid);
      return r.from_pk || null;
    },
    /** Удалить всё старше `cutoffTs` (TTL). Вернуть число удалённых. */
    expireOlderThan(cutoffTs) {
      return q.expire.run(cutoffTs).changes;
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
