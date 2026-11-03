import { json, readJson, sha256hex, getDist, distSessionCookie, sessionDays } from "../../lib/core.js";

// POST {slug, password, days?} -> distributor session cookie.
// days is the login persistence choice: default 1, maximum 7.
export async function onRequestPost({ request, env }) {
  const body = await readJson(request);
  const rec = body.slug ? await getDist(env, body.slug) : null;
  if (!rec || rec.status !== "active") return json({ ok: false, reason: "no_distributor" }, 401);
  if (!rec.pw_hash) return json({ ok: false, reason: "needs_setup" }, 401);
  if ((await sha256hex(body.password || "")) !== rec.pw_hash) {
    return json({ ok: false, reason: "bad_password" }, 401);
  }
  const days = sessionDays(body);
  const cookie = await distSessionCookie(env, body.slug, days);
  return json({ ok: true, name: rec.name, session: cookie, days }, 200, {
    "set-cookie": `dsess=${cookie}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${days * 86400}`,
  });
}
