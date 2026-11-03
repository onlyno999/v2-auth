import {
  json, readJson, nowSec, sha256hex, getGuest, guestProblem, guestSessionCookie, logEvent,
} from "../../lib/core.js";

// POST {id, password} -> guest session cookie. The guest was created
// by hand in the admin console; there is no self-registration and no
// activation code involved anymore.
export async function onRequestPost({ request, env }) {
  const body = await readJson(request);
  const ip = request.headers.get("cf-connecting-ip") || "local";
  const bucket = `rlg:${ip}:${Math.floor(nowSec() / 3600)}`;
  const tries = parseInt((await env.V2.get(bucket)) || "0", 10);
  if (tries > 30) return json({ ok: false, reason: "rate_limited" }, 429);
  await env.V2.put(bucket, String(tries + 1), { expirationTtl: 3700 });

  const rec = body.id ? await getGuest(env, String(body.id)) : null;
  if (!rec) return json({ ok: false, reason: "not_found" }, 404);
  const problem = guestProblem(rec);
  if (problem === "disabled") return json({ ok: false, reason: "disabled" }, 403);
  if (problem === "expired") return json({ ok: false, reason: "expired" }, 403);
  if ((await sha256hex(body.password || "")) !== rec.pw_hash) {
    await logEvent(env, "guest_login_fail", rec.username, "bad_password");
    return json({ ok: false, reason: "bad_password" }, 401);
  }
  const cookie = await guestSessionCookie(env, String(body.id));
  await logEvent(env, "guest_login", rec.username);
  return json({ ok: true, session: cookie }, 200, {
    "set-cookie": `gsess=${cookie}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=2592000`,
  });
}
