import { json, readJson, isAdmin, nowSec, bumpDataVersion } from "../../lib/core.js";

// POST {confirm: "migrate"} -> one-shot copy of every durable
// record from the old KV namespace (env.KV_ORIG, preserved by the
// middleware) into D1. Idempotent (upserts); safe to re-run —
// re-running after cutover would overwrite newer D1 rows with
// stale KV ones, so run it once, before real traffic moves to D1.
//
// Ephemeral buckets are skipped on purpose: rl: (rate limits) and
// chal: (attestation challenges) are worthless minutes later.
// last:/attestfail: rows get a fresh TTL mirroring their KV nature
// (they were written with expirationTtl there).
const PREFIXES = ["lic:", "dev:", "open:", "dist:", "gst:", "sub:", "last:", "attestfail:"];
const TTL = { "last:": 40 * 86400, "attestfail:": 7 * 86400 };

export async function onRequestPost({ request, env }) {
  if (!(await isAdmin(env, request))) return json({ ok: false, reason: "unauthorized" }, 401);
  if (!env.KV_ORIG || !env.DB) {
    return json({ ok: false, reason: "no_kv_or_no_d1" }, 400);
  }
  const body = await readJson(request);
  if (body.confirm !== "migrate") return json({ ok: false, reason: "confirm_required" }, 400);

  const counts = {};
  for (const prefix of PREFIXES) {
    let cursor;
    let n = 0;
    do {
      const page = await env.KV_ORIG.list({ prefix, limit: 200, cursor });
      cursor = page.list_complete ? undefined : page.cursor;
      for (const k of page.keys) {
        const v = await env.KV_ORIG.get(k.name);
        if (v === null) continue; // expired between list and get
        const ttl = TTL[prefix];
        const exp = ttl ? nowSec() + ttl : null;
        await env.DB.prepare(
          "INSERT INTO kv (k, v, exp) VALUES (?1, ?2, ?3) " +
            "ON CONFLICT(k) DO UPDATE SET v = excluded.v, exp = excluded.exp",
        )
          .bind(k.name, v, exp)
          .run();
        n++;
      }
    } while (cursor);
    counts[prefix] = n;
  }
  // The copies above write SQL directly, bypassing the put*
  // helpers — invalidate the cached console tables explicitly.
  bumpDataVersion();
  return json({ ok: true, counts });
}
