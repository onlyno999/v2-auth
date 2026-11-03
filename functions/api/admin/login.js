import { json, readJson, sessionCookie } from "../../lib/core.js";

// POST {password} -> sets the admin session cookie.
export async function onRequestPost({ request, env }) {
  const body = await readJson(request);
  if (!env.ADMIN_PASSWORD || body.password !== env.ADMIN_PASSWORD) {
    // TEMP DIAGNOSTIC (remove after login issue is resolved): let the
    // server report what it actually sees, hashes only — never values.
    const { sha256hex } = await import("../../lib/core.js");
    const diag = {
      pw_set: !!env.ADMIN_PASSWORD,
      pw_len: env.ADMIN_PASSWORD ? env.ADMIN_PASSWORD.length : 0,
      pw_hash: env.ADMIN_PASSWORD ? (await sha256hex(env.ADMIN_PASSWORD)).slice(0, 8) : null,
      recv_len: (body.password || "").length,
      recv_hash: body.password ? (await sha256hex(body.password)).slice(0, 8) : null,
      ss_set: !!env.SESSION_SECRET,
      kv_bound: !!env.V2,
    };
    return json({ ok: false, reason: "bad_password", diag }, 401);
  }
  const cookie = await sessionCookie(env, request);
  return json({ ok: true }, 200, {
    "set-cookie": `sess=${cookie}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=43200`,
  });
}
