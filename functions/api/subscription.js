import { readJson, nowSec, gate, putDev, logEvent } from "../lib/core.js";

const FRESH_SEC = 1800; // lazy refresh window: 30 min

// Channel config: each license carries channel "main" | "dist".
// main -> env.SUB_URL (KV sub:*), dist -> env.SUB_URL_DIST (KV subd:*).
// If the dist URL is not configured yet, dist devices fall back to main.
function channelCfg(env, channel) {
  if (channel === "dist" && env.SUB_URL_DIST) {
    return { url: env.SUB_URL_DIST, prefix: "subd" };
  }
  return { url: env.SUB_URL, prefix: "sub" };
}

async function serveSubscription(env, channel) {
  const { url, prefix } = channelCfg(env, channel);
  let content = await env.V2.get(prefix + ":content");
  const fetchedAt = parseInt((await env.V2.get(prefix + ":fetched_at")) || "0", 10);
  if (!content || nowSec() - fetchedAt > FRESH_SEC) {
    try {
      const up = await fetch(url, { headers: { "user-agent": "okhttp/4.9.0" } });
      if (up.ok) {
        const text = await up.text();
        if (text && text.length > 50) {
          content = text;
          await env.V2.put(prefix + ":content", text);
          await env.V2.put(prefix + ":fetched_at", String(nowSec()));
        }
      }
    } catch { /* keep serving the stale KV copy */ }
  }
  return content;
}

// POST {machineCode, sig, ts, nonce} or {machineCode, token}
// Validates first; only then serves the subscription for the device's
// channel, cached in KV and lazily refreshed from the channel's URL.
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

  const channel = g.lic.channel === "dist" ? "dist" : "main";
  const content = await serveSubscription(env, channel);
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
