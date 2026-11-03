import {
  json, nowSec, getGuest, putGuest, guestIdFromRequest, vaultSeal, vaultOpen,
} from "../../lib/core.js";

// GET -> the logged-in guest's own view: username, remaining time and
// his sealed personal subscription link. Nothing else is exposed —
// in particular never the real subscription URL.
export async function onRequestGet({ request, env }) {
  const id = await guestIdFromRequest(env, request);
  if (!id) return json({ ok: false, reason: "unauthorized" }, 401);
  const rec = await getGuest(env, id);
  if (!rec) return json({ ok: false, reason: "not_found" }, 404);

  // The sealed token is minted at creation; if it ever stops opening
  // (e.g. SESSION_SECRET rotated), mint a fresh one so his link — and
  // only his link — keeps working.
  let sealed = rec.sealed || null;
  let payload = null;
  try { payload = JSON.parse((await vaultOpen(env, sealed)) || "null"); } catch { payload = null; }
  if (!sealed || !payload || payload.g !== id) {
    sealed = await vaultSeal(env, JSON.stringify({ g: id }));
    if (!sealed) return json({ ok: false, reason: "vault_unavailable" }, 500);
    await putGuest(env, id, { ...rec, sealed });
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
