import { json, isAdmin } from "../../lib/core.js";

// GET -> session check only, zero KV access. The console's
// auto-login uses this instead of the devices table: the table
// builder spends KV list() calls (a small daily quota), and a
// login check must never burn them — a burned quota once made
// every refresh look like a logout.
export async function onRequestGet({ request, env }) {
  if (!(await isAdmin(env, request))) return json({ ok: false, reason: "unauthorized" }, 401);
  return json({ ok: true });
}
