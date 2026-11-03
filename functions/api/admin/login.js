import { json, readJson, sessionCookie, sessionDays } from "../../lib/core.js";

// POST {password, days?} -> sets the admin session cookie. days is
// the user's own persistence choice: default 1, maximum 7.
export async function onRequestPost({ request, env }) {
  const body = await readJson(request);
  if (!env.ADMIN_PASSWORD || body.password !== env.ADMIN_PASSWORD) {
    return json({ ok: false, reason: "bad_password" }, 401);
  }
  const days = sessionDays(body);
  const cookie = await sessionCookie(env, request, days);
  // The token is also returned in the body: the console keeps it in
  // localStorage and sends it as x-session, so a refresh never asks
  // for the password again while it is valid (the chosen 1-7 days).
  return json({ ok: true, session: cookie, days }, 200, {
    "set-cookie": `sess=${cookie}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${days * 86400}`,
  });
}
