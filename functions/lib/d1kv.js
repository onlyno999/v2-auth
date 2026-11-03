// D1-backed drop-in for the KV namespace binding.
//
// The whole codebase talks to env.V2 through exactly four calls —
// get(key) -> string|null, put(key, string, {expirationTtl?}),
// delete(key), list({prefix, limit, cursor}) — so this shim
// implements that surface over one SQLite table and the migration
// to D1 needs no endpoint changes (the swap happens in
// functions/_middleware.js whenever a D1 binding named DB exists).
//
// Why: KV's free plan caps list() at 1,000 calls/day and writes at
// 1,000/day; D1's free plan allows 5M row reads and 100k row
// writes/day, and a prefix scan here is an indexed range read of
// exactly the rows returned. D1 is also strongly consistent — the
// KV eventual-consistency ghosts (a written record briefly
// unreadable, a lost open: pointer) cannot happen.

const nowSec = () => Math.floor(Date.now() / 1000);

export class D1KV {
  constructor(db) {
    this.db = db;
    this.ready = null;
  }

  // CREATE TABLE is idempotent; memoize per isolate so it runs at
  // most once, and simply retry next request if it ever fails.
  schema() {
    if (!this.ready) {
      this.ready = this.db
        .prepare("CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL, exp INTEGER)")
        .run()
        .then(() => true)
        .catch((e) => {
          this.ready = null;
          throw e;
        });
    }
    return this.ready;
  }

  async get(key) {
    await this.schema();
    const row = await this.db
      .prepare("SELECT v FROM kv WHERE k = ?1 AND (exp IS NULL OR exp > ?2)")
      .bind(key, nowSec())
      .first();
    return row ? row.v : null;
  }

  async put(key, value, opts = {}) {
    await this.schema();
    const exp = opts && opts.expirationTtl ? nowSec() + Math.floor(opts.expirationTtl) : null;
    await this.db
      .prepare(
        "INSERT INTO kv (k, v, exp) VALUES (?1, ?2, ?3) " +
          "ON CONFLICT(k) DO UPDATE SET v = excluded.v, exp = excluded.exp",
      )
      .bind(key, String(value), exp)
      .run();
  }

  async delete(key) {
    await this.schema();
    await this.db.prepare("DELETE FROM kv WHERE k = ?1").bind(key).run();
  }

  // Prefix range scan over the primary-key index. The cursor is the
  // last returned key (callers only ever pass it back verbatim).
  async list({ prefix = "", limit = 1000, cursor } = {}) {
    await this.schema();
    const upper = prefix
      ? prefix.slice(0, -1) + String.fromCharCode(prefix.charCodeAt(prefix.length - 1) + 1)
      : null;
    const conds = ["(exp IS NULL OR exp > ?1)"];
    const binds = [nowSec()];
    if (prefix) {
      conds.push("k >= ?2", "k < ?3");
      binds.push(prefix, upper);
    }
    if (cursor) {
      conds.push(`k > ?${binds.length + 1}`);
      binds.push(cursor);
    }
    const limIdx = binds.length + 1;
    binds.push(limit + 1);
    const { results } = await this.db
      .prepare(`SELECT k FROM kv WHERE ${conds.join(" AND ")} ORDER BY k LIMIT ?${limIdx}`)
      .bind(...binds)
      .all();
    const complete = results.length <= limit;
    const page = complete ? results : results.slice(0, limit);
    return {
      keys: page.map((r) => ({ name: r.k })),
      list_complete: complete,
      cursor: complete ? undefined : page[page.length - 1].k,
    };
  }
}
