import { json, readJson, sessionCookie } from "../../lib/core.js";

// POST {password} -> sets the admin session cookie.
export async function onRequestPost({ request, env }) {
  const body = await readJson(request);
  if (!env.ADMIN_PASSWORD || body.password !== env.ADMIN_PASSWORD) {
    return json({ ok: false, reason: "bad_password" }, 401);
  }
  const cookie = await sessionCookie(env, request);
  // The token is also returned in the body: the console keeps it in
  // localStorage and sends it as x-session, so a refresh never asks
  // for the password again while it is valid (30 days).
  return json({ ok: true, session: cookie }, 200, {
    "set-cookie": `sess=${cookie}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=2592000`,
  });
}
