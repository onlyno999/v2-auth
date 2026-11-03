import { json, distSlugFromRequest, listStock } from "../../lib/core.js";

// GET /api/dist/stock -> MY ledger lines only: what I stocked up
// from my parent, and what I stocked my direct subs with.
export async function onRequestGet({ request, env }) {
  const me = await distSlugFromRequest(env, request);
  if (!me) return json({ ok: false, reason: "unauthorized" }, 401);
  const all = await listStock(env, 300);
  return json({
    ok: true,
    bought: all.filter((x) => x.dist === me),
    granted: all.filter((x) => x.from === me),
  });
}
