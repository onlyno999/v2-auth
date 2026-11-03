import { json, isAdmin, listStock } from "../../lib/core.js";

// GET /api/admin/stock -> the restock ledger (newest first).
export async function onRequestGet({ request, env }) {
  if (!(await isAdmin(env, request))) return json({ ok: false, reason: "unauthorized" }, 401);
  return json({ ok: true, stock: await listStock(env, 100) });
}
