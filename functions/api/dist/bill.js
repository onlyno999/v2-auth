import {
  json, readJson, getDist, putDist, distSlugFromRequest, listDistChildren, tierForLevel, distLevel,
} from "../../lib/core.js";
import { buildTree } from "../../lib/tree.js";

// A distributor's own bill book (owner, 2026-11-04): the console's
// price to ITS level-1s is fixed and not his concern; what HE
// charges his own subs is his business — so his console carries
// his own price box. This endpoint serves his 对账 page:
//   - my_price: what he charges his direct subs per month unit
//     (stored on his record; POST saves it);
//   - rows: each direct sub's bill = the sub's whole subtree
//     month units x my_price — the mirror of the admin summary,
//     one level down;
//   - owe_parent: HIS bill upward = his whole subtree's month
//     units x his parent's price (the console's global price
//     when his parent is the console), so both sides of every
//     father-son account read the same numbers.
async function consolePrice(env) {
  const raw = await env.V2.get("meta:unitprice");
  const n = raw ? Number(raw) : NaN;
  return Number.isFinite(n) && n > 0 ? n : 4;
}

// What one unit sold by MY subs costs me — the floor basis for
// my own pricing (every layer keeps at least 1 yuan). When my
// parent is the console, my subs' sales settle upward at the
// tier for THEIR level; when my parent is a distributor, my
// cost is simply his price. Null when unknowable (parent has
// not priced yet).
async function costBasis(env, rec) {
  if (!rec.parent) {
    const base = await consolePrice(env);
    return { cost: tierForLevel(base, distLevel(rec) + 1), base };
  }
  const p = await getDist(env, rec.parent);
  if (p && Number.isFinite(p.price) && p.price > 0) return { cost: p.price, base: null };
  return { cost: null, base: null };
}

export async function onRequestGet({ request, env }) {
  const me = await distSlugFromRequest(env, request);
  if (!me) return json({ ok: false, reason: "unauthorized" }, 401);
  const rec = await getDist(env, me);
  if (!rec) return json({ ok: false, reason: "unauthorized" }, 401);
  const myPrice = Number.isFinite(rec.price) && rec.price > 0 ? rec.price : null;

  let parentPrice = null;
  if (!rec.parent) parentPrice = await consolePrice(env);
  else {
    const p = await getDist(env, rec.parent);
    if (p && Number.isFinite(p.price) && p.price > 0) parentPrice = p.price;
  }
  const myTree = await buildTree(env, me);
  const myUnits = myTree ? myTree.stats.month.units : 0;
  // Owed upward: to the console it is the TIERED sum over my
  // subtree's sales by seller level; to a distributor parent it
  // is his price times my subtree units (the goods I stocked).
  let oweBreakdown = null;
  let oweParent = null;
  if (!rec.parent && myTree) {
    oweBreakdown = Object.entries(myTree.stats.month.by_level || {})
      .map(([lv, units]) => ({ level: Number(lv), units, rate: tierForLevel(parentPrice, Number(lv)), amount: Math.round(units * tierForLevel(parentPrice, Number(lv)) * 100) / 100 }))
      .sort((a, b) => a.level - b.level);
    oweParent = Math.round(oweBreakdown.reduce((a, b) => a + b.amount, 0) * 100) / 100;
  } else if (parentPrice !== null) {
    oweParent = Math.round(myUnits * parentPrice * 100) / 100;
  }
  const basis = await costBasis(env, rec);

  const rows = [];
  if (myPrice !== null) {
    for (const k of await listDistChildren(env, me)) {
      const t = await buildTree(env, k.slug);
      if (!t) continue;
      rows.push({
        slug: k.slug,
        name: t.dist.name || "",
        month_count: t.stats.month.count,
        month_units: t.stats.month.units,
        due: Math.round(t.stats.month.units * myPrice * 100) / 100,
      });
    }
    rows.sort((a, b) => b.due - a.due);
  }
  return json({
    ok: true,
    my_price: myPrice,
    parent_price: parentPrice,
    parent: rec.parent || "admin",
    my_units: myUnits,
    owe_parent: oweParent,
    owe_breakdown: oweBreakdown,
    cost_basis: basis.cost,
    price_floor: basis.cost === null ? null : basis.cost + 1,
    rows,
    total_due: Math.round(rows.reduce((a, r) => a + r.due, 0) * 100) / 100,
  });
}

export async function onRequestPost({ request, env }) {
  const me = await distSlugFromRequest(env, request);
  if (!me) return json({ ok: false, reason: "unauthorized" }, 401);
  const rec = await getDist(env, me);
  if (!rec) return json({ ok: false, reason: "unauthorized" }, 401);
  const body = await readJson(request);
  const n = Number(body.price);
  if (!Number.isFinite(n) || n <= 0 || n > 10000) {
    return json({ ok: false, reason: "bad_price" }, 400);
  }
  // Ladder floor (owner, 2026-11-04): pricing is his own business
  // FROM level 1 down — but every layer must keep at least 1 yuan
  // per unit, so a price may not sit below what a sub's sale
  // costs him + 1. For a level-1 that cost is the console tier
  // for level 2 (base - 1 = 3 by default, floor 4); deeper, it
  // is his parent's price. When the parent has not priced yet
  // the cost is unknowable and any price stands.
  const { cost } = await costBasis(env, rec);
  if (cost !== null && n < cost + 1) {
    return json({ ok: false, reason: "below_floor", cost, floor: cost + 1 }, 400);
  }
  await putDist(env, me, { ...rec, price: n });
  return json({ ok: true, price: n });
}
