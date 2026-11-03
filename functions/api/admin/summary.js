import { json, readJson, isAdmin, tierForLevel } from "../../lib/core.js";
import { buildTree } from "../../lib/tree.js";

// The console's monthly bill (owner, 2026-11-04): a summary page
// listing every DIRECT (level-1) distributor and what he owes
// the console this month. The take is TIERED by the seller's
// level (owner, 2026-11-04, correcting a flat-4 reading of vb's
// guest): a level-1's own sale settles at the base price
// (default 4), a level-2 sale at base-1, level 3 at base-2,
// and anything deeper at 1 yuan — the ladder's floor, so the
// console still earns on the deepest layer. The level-1's bill
// is the sum over his whole subtree's month openings bucketed
// by seller level; he alone settles with the console. The base
// price is one global setting (meta:unitprice), default 4.
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
    const breakdown = Object.entries(tree.stats.month.by_level || {})
      .map(([lv, units]) => ({ level: Number(lv), units, rate: tierForLevel(price, Number(lv)), amount: Math.round(units * tierForLevel(price, Number(lv)) * 100) / 100 }))
      .sort((a, b) => a.level - b.level);
    rows.push({
      slug,
      name: tree.dist.name || "",
      status: tree.dist.status,
      subs: tree.totals.subs,
      devices: tree.totals.devices,
      month_count: tree.stats.month.count,
      month_units: tree.stats.month.units,
      breakdown,
      due: Math.round(breakdown.reduce((a, b) => a + b.amount, 0) * 100) / 100,
      total_units: tree.stats.total.units,
    });
  }
  rows.sort((a, b) => b.due - a.due);
  return json({
    ok: true,
    unit_price: price,
    tiers: [1, 2, 3, 4, 5].map((lv) => ({ level: lv, rate: tierForLevel(price, lv) })),
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
