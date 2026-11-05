import { json } from "../../lib/core.js";

// POST -> expire the admin session cookie. Sessions are stateless,
// so this cannot revoke a copied token; it clears this browser's
// cookie while the console removes its localStorage token itself.
export async function onRequestPost() {
  return json({ ok: true }, 200, {
    "set-cookie": "sess=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0",
  });
}
