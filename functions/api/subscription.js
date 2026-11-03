import { readJson, nowSec, gate, putDev, logEvent } from "../lib/core.js";

const FRESH_SEC = 1800; // lazy refresh window: 30 min

// POST {machineCode, sig, ts, nonce} or {machineCode, token}
// Validates first; only then serves the subscription stored in KV,
// refreshing it from the upstream URL (kept in a server secret) when
// the KV copy is older than FRESH_SEC. Nobody opens -> nobody fetches.
export async function onRequestPost({ request, env }) {
  const body = await readJson(request);
  const g = await gate(env, body.machineCode, body, "/api/subscription");
  if (!g.ok) {
    await logEvent(env, "sub_deny", body.machineCode || "", g.reason);
    return new Response(JSON.stringify({ ok: false, reason: g.reason }), {
      status: g.status || 403,
      headers: { "content-type": "application/json", "cache-control": "no-store" },
    });
  }

  let content = await env.KV.get("sub:content");
  const fetchedAt = parseInt((await env.KV.get("sub:fetched_at")) || "0", 10);
  if (!content || nowSec() - fetchedAt > FRESH_SEC) {
    try {
      const up = await fetch(env.SUB_URL, { headers: { "user-agent": "okhttp/4.9.0" } });
      if (up.ok) {
        const text = await up.text();
        if (text && text.length > 50) {
          content = text;
          await env.KV.put("sub:content", text);
          await env.KV.put("sub:fetched_at", String(nowSec()));
          await logEvent(env, "sub_refresh", body.machineCode);
        }
      }
    } catch { /* keep serving the stale KV copy */ }
  }
  if (!content) {
    return new Response(JSON.stringify({ ok: false, reason: "sub_unavailable" }), {
      status: 502, headers: { "content-type": "application/json", "cache-control": "no-store" },
    });
  }
  const dev = { ...g.dev, last_seen: nowSec(), pulls: (g.dev.pulls || 0) + 1 };
  await putDev(env, body.machineCode, dev);
  return new Response(content, {
    status: 200,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
  });
}
