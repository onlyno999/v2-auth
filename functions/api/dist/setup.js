import { json, readJson, sha256hex, getDist, putDist, distSessionCookie } from "../../lib/core.js";

// POST {slug, password} -> first-visit password setup. Only works while
// the distributor has no password yet (freshly created by the admin, or
// after the admin reset it). Sets the hash in KV and logs him in.
export async function onRequestPost({ request, env }) {
  const body = await readJson(request);
  const rec = body.slug ? await getDist(env, body.slug) : null;
  if (!rec || rec.status !== "active") return json({ ok: false, reason: "no_distributor" }, 401);
  if (rec.pw_hash) return json({ ok: false, reason: "already_set" }, 409);
  if (!body.password || String(body.password).length < 6) {
    return json({ ok: false, reason: "weak_password" }, 400);
  }
  await putDist(env, body.slug, { ...rec, pw_hash: await sha256hex(String(body.password)) });
  const cookie = await distSessionCookie(env, body.slug);
  return json({ ok: true, name: rec.name, session: cookie }, 200, {
    "set-cookie": `dsess=${cookie}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=2592000`,
  });
}
