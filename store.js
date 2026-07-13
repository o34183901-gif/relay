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
    CREATE INDEX IF NOT EXISTS idx_queue_from_to ON queue(from_pk, to_pk, ts);
    CREATE TABLE IF NOT EXISTS identities  (pk TEXT PRIMARY KEY, sign_pk TEXT NOT NULL, proven INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS push_tokens (pk TEXT PRIMARY KEY, token TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS directory   (url TEXT PRIMARY KEY, last_seen INTEGER);
    -- X3DH: публичные prekey пользователей (подписанный + одноразовые).
    -- Релей хранит ТОЛЬКО публичные половинки; расшифровать ими ничего нельзя.
    CREATE TABLE IF NOT EXISTS prekeys_spk (pk TEXT PRIMARY KEY, id TEXT NOT NULL, pub TEXT NOT NULL, sig TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS prekeys_otp (pk TEXT NOT NULL, id TEXT NOT NULL, pub TEXT NOT NULL, PRIMARY KEY (pk, id));
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
      'INSERT OR REPLACE INTO queue (id,to_pk,from_pk,envelope,silent,call_push,ts,blob,bytes) VALUES (?,?,?,?,?,?,?,?,?)'
    ),
    forUser: db.prepare('SELECT * FROM queue WHERE to_pk=? ORDER BY ts ASC'),
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
    set: db.prepare('INSERT OR IGNORE INTO identities (pk,sign_pk,proven) VALUES (?,?,?)'),
    rebind: db.prepare('INSERT OR REPLACE INTO identities (pk,sign_pk,proven) VALUES (?,?,?)'),
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
  const spk = {
    get: db.prepare('SELECT id, pub, sig FROM prekeys_spk WHERE pk=?'),
    set: db.prepare('INSERT OR REPLACE INTO prekeys_spk (pk,id,pub,sig) VALUES (?,?,?,?)'),
  };
  const otp = {
    insert: db.prepare('INSERT OR IGNORE INTO prekeys_otp (pk,id,pub) VALUES (?,?,?)'),
    delAll: db.prepare('DELETE FROM prekeys_otp WHERE pk=?'),
    takeOne: db.prepare('SELECT id, pub FROM prekeys_otp WHERE pk=? LIMIT 1'),
    delOne: db.prepare('DELETE FROM prekeys_otp WHERE pk=? AND id=?'),
    count: db.prepare('SELECT count(*) c FROM prekeys_otp WHERE pk=?'),
  };

  return {
    // --- queue --------------------------------------------------------------
    /**
     * Положить конверт в очередь получателя; при переполнении вытеснить старейший.
     * Тело крупнее blobThreshold уходит файлом в blobDir — в БД только ссылка.
     */
    enqueue({ id: mid, to, from, envelope, silent, callPush, ts, maxPerUser, maxPerSender, maxTotal, maxTotalBytes }) {
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
      // адреса и переполнить диск volume: count-лимит при этом не срабатывал
      // никогда. При превышении вытесняем самый старый конверт во всей очереди.
      if (maxTotal || maxTotalBytes) {
        while (
          (maxTotal && liveCount >= maxTotal) ||
          (maxTotalBytes && liveBytes + bytes > maxTotalBytes)
        ) {
          const o = q.oldestGlobal.get();
          if (!o) break;
          dropRow(o);
        }
      }
      const asBlob = blobDir && bytes > blobThreshold;
      if (asBlob) writeBlob(mid, envJson);
      q.insert.run(mid, to, from || null, asBlob ? '' : envJson, silent ? 1 : 0, callPush ? 1 : 0, ts, asBlob ? 1 : 0, bytes);
      liveCount += 1;
      liveBytes += bytes;
      return true; // СРВ-2: конверт сохранён (false выше — отклонён из-за полной очереди получателя)
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
    bindSignKey(pk, signPk, proven = false) {
      // INSERT OR IGNORE — первый выигрывает (TOFU). proven=1 только если владение
      // box-ключом реально доказано (ECDH-proof в relay.js).
      id.set.run(pk, signPk, proven ? 1 : 0);
    },
    /**
     * Переписать связку (H-6): разрешено ТОЛЬКО когда предъявитель доказал
     * владение box-ключом адреса — тогда он может перебить чужую (в т.ч.
     * сквоттерскую) привязку и закрепить её как proven. Легаси-путь этого не
     * умеет, поэтому proven-связку нельзя перехватить без секретки box-ключа.
     */
    rebindSignKey(pk, signPk) {
      id.rebind.run(pk, signPk, 1);
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
