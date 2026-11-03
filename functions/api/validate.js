import { json, readJson, nowSec, gate, putDev, logEvent } from "../lib/core.js";

// POST {machineCode, sig, ts, nonce} or {machineCode, token}
// The every-open check. Success returns the license expiry.
export async function onRequestPost({ request, env }) {
  const body = await readJson(request);
  const g = await gate(env, body.machineCode, body, "/api/validate");
  if (!g.ok) {
    await logEvent(env, "validate_fail", body.machineCode || "", g.reason);
    return json({ ok: false, reason: g.reason }, g.status || 403);
  }
  const dev = { ...g.dev, last_seen: nowSec() };
  await putDev(env, body.machineCode, dev);
  return json({
    ok: true,
    expires_at: g.lic.expires_at ?? null,
    days_left: g.lic.expires_at ? Math.max(0, Math.floor((g.lic.expires_at - nowSec()) / 86400)) : null,
    remain_sec: g.lic.expires_at ? Math.max(0, g.lic.expires_at - nowSec()) : null,
  });
}
