import {
  json, nowSec, getMember, putMember, memberIdFromRequest, vaultSeal, vaultOpen,
} from "../../lib/core.js";

// GET -> the logged-in member's own view: username, remaining time
// and his sealed personal subscription link. Nothing else — never
// the real subscription URL.
export async function onRequestGet({ request, env }) {
  const id = await memberIdFromRequest(env, request);
  if (!id) return json({ ok: false, reason: "unauthorized" }, 401);
  const rec = await getMember(env, id);
  if (!rec) return json({ ok: false, reason: "not_found" }, 404);

  let sealed = rec.sealed || null;
  let payload = null;
  try { payload = JSON.parse((await vaultOpen(env, sealed)) || "null"); } catch { payload = null; }
  if (!sealed || !payload || payload.m !== id) {
    sealed = await vaultSeal(env, JSON.stringify({ m: id }));
    if (!sealed) return json({ ok: false, reason: "vault_unavailable" }, 500);
    await putMember(env, id, { ...rec, sealed });
  }

  const origin = new URL(request.url).origin;
  const remainSec = rec.expires_at ? Math.max(0, rec.expires_at - nowSec()) : null;
  return json({
    ok: true,
    username: rec.username,
    expires_at: rec.expires_at ?? null,
    days_left: rec.expires_at ? Math.max(0, Math.ceil((rec.expires_at - nowSec()) / 86400)) : null,
    remain_sec: remainSec,
    minutes_left: remainSec === null ? null : Math.ceil(remainSec / 60),
    link: `${origin}/s/${sealed}`,
  });
}
