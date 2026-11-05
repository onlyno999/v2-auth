import { readJson, nowSec, gate, putDev, logEvent } from "../lib/core.js";

// Channel config: each license carries channel "main" | "dist".
// main -> env.SUB_URL (KV sub:*), dist -> env.SUB_URL_DIST (KV subd:*).
// Distributors share the main subscription unless a SEPARATE, VALID
// dist URL is configured: a value that is not an http(s) URL at all
// (the dashboard once held the literal text "mm") counts as "not
// configured" and falls back to main, instead of breaking every
// distributor pull.
function usableUrl(v) {
  if (!v) return null;
  try {
    const u = new URL(v);
    return u.protocol === "http:" || u.protocol === "https:" ? v : null;
  } catch {
    return null;
  }
}
function channelCfg(env, channel) {
  if (channel === "dist") {
    const dist = usableUrl(env.SUB_URL_DIST);
    if (dist) return { url: dist, prefix: "subd" };
  }
  return { url: usableUrl(env.SUB_URL), prefix: "sub" };
}

export async function serveSubscription(env, channel) {
  const { url, prefix } = channelCfg(env, channel);
  // REAL-TIME pull (owner, 2026-11-05): every serve fetches the
  // subscription address fresh, so upstream changes (nodes added
  // or removed) reach customers on their very next pull instead
  // of up to 30 minutes later. The fetched copy is still stored
  // — purely as the emergency fallback for the moments the
  // upstream itself is unreachable; a stored copy is served ONLY
  // when the live fetch fails, never because it is "fresh
  // enough".
  if (url) {
    try {
      const up = await fetch(url, {
        headers: { "user-agent": "okhttp/4.9.0" },
        signal: AbortSignal.timeout(8000),
      });
      if (up.ok) {
        const text = await up.text();
        if (text && text.length > 50) {
          try {
            await env.V2.put(prefix + ":content", text);
            await env.V2.put(prefix + ":fetched_at", String(nowSec()));
          } catch { /* the fallback copy is best-effort */ }
          return text;
        }
      }
    } catch { /* upstream down: fall through to the stored copy */ }
  }
  try {
    return await env.V2.get(prefix + ":content");
  } catch {
    return null;
  }
}

// POST {machineCode, sig, ts, nonce} or {machineCode, token}
// Validates first; only then serves the subscription for the device's
// channel, pulled from the channel's URL in real time on every call.
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
