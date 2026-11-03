import { json } from "../../lib/core.js";

// POST -> expire the dsess cookie. Sessions are stateless, so
// this cannot revoke a token — it exists so a browser that holds
// distributor A's session stops presenting it on distributor B's
// page (the console checks /api/dist/me against its URL slug and
// calls this when they differ: a link must land on ITS account).
export async function onRequestPost() {
  return json({ ok: true }, 200, {
    "set-cookie": "dsess=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0",
  });
}
