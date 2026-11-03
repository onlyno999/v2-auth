import { json, readJson, isAdmin, listStock } from "../../lib/core.js";
import { buildTree } from "../../lib/tree.js";

// The console's monthly bill (owner, 2026-11-04): a summary page
// listing every DIRECT (level-1) distributor and what he owes
// the console this month. The amount is his whole subtree's
// month openings, duration-weighted into month units, times the
// unit price — the ONE wholesale price the console charges its
// level-1 distributors (owner settled it at 4 yuan per month
// unit, 2026-11-04: retail is 10, the level-1 keeps 6 to feed
// his tree; the console's volume is the whole tree's openings,
// collected from the level-1s only). The price is one global
// setting the owner can change on the page (meta:unitprice);
// the code default applies until he saves one.
const PRICE_KEY = "meta:unitprice";

async function unitPrice(env) {
  const raw = await env.V2.get(PRICE_KEY);
  const n = raw ? Number(raw) : NaN;
  return Number.isFinite(n) && n > 0 ? n : 4;
}

export async function onRequestGet({ request, env }) {
  if (!(await isAdmin(env, request))) return json({ ok: false, reason: "unauthorized" }, 401);
  const price = await unitPrice(env);
  // Level-1 distributors = records with no parent.
  const roots = [];
  let cursor;
  do {
    const page = await env.V2.list({ prefix: "dist:", limit: 200, cursor });
    cursor = page.list_complete ? undefined : page.cursor;
    for (const k of page.keys) {
      const raw = await env.V2.get(k.name);
      if (!raw) continue;
      const rec = JSON.parse(raw);
      if (!rec.parent) roots.push(k.name.slice(5));
    }
  } while (cursor);
  const rows = [];
  for (const slug of roots) {
    const tree = await buildTree(env, slug);
    if (!tree) continue;
    rows.push({
      slug,
      name: tree.dist.name || "",
      status: tree.dist.status,
      subs: tree.totals.subs,
      devices: tree.totals.devices,
      month_count: tree.stats.month.count,
      month_units: tree.stats.month.units,
      due: Math.round(tree.stats.month.units * price * 100) / 100,
      total_units: tree.stats.total.units,
    });
  }
  rows.sort((a, b) => b.due - a.due);
  return json({
    ok: true,
    unit_price: price,
    rows,
    total_due: Math.round(rows.reduce((a, r) => a + r.due, 0) * 100) / 100,
    total_units: rows.reduce((a, r) => a + r.month_units, 0),
  });
}

export async function onRequestPost({ request, env }) {
  if (!(await isAdmin(env, request))) return json({ ok: false, reason: "unauthorized" }, 401);
  const body = await readJson(request);
  const n = Number(body.unit_price);
  if (!Number.isFinite(n) || n <= 0 || n > 10000) {
    return json({ ok: false, reason: "bad_price" }, 400);
  }
  await env.V2.put(PRICE_KEY, String(n));
  return json({ ok: true, unit_price: n });
}
