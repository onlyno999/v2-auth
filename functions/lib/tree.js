import { getDist, listDistChildren, distLevel, cachedPayload, quotaCostFor, nowSec, beijingDay, tierForLevel, consoleUnitPrice } from "./core.js";

// Shared subtree builder for the two 名下 pages (admin tree.html
// and distributor subtree.html): one distributor's direct people
// listed in full, plus totals over his WHOLE subtree.
async function scan(env, prefix) {
  const out = [];
  let cursor;
  do {
    const page = await env.V2.list({ prefix, limit: 200, cursor });
    cursor = page.list_complete ? undefined : page.cursor;
    for (const k of page.keys) {
      const raw = await env.V2.get(k.name);
      if (raw) out.push({ key: k.name, rec: JSON.parse(raw) });
    }
  } while (cursor);
  return out;
}

export async function buildTree(env, slug) {
  const root = await getDist(env, slug);
  if (!root) return null;
  return cachedPayload(env, "tree:" + slug, 20000, async () => {
    const [lics, guests, devs] = await Promise.all([
      scan(env, "lic:"), scan(env, "gst:"), scan(env, "dev:"),
    ]);
    const devByMachine = new Map(devs.map((d) => [d.key.slice(4), d.rec]));
    const devicesOf = (s) => lics
      .filter((l) => l.rec.dist === s && (l.rec.status === "active" || l.rec.status === "revoked"))
      .map((l) => {
        const dev = devByMachine.get(l.rec.machine) || {};
        return {
          machine: l.rec.machine,
          note: l.rec.note || "",
          status: l.rec.status,
          activated_at: l.rec.activated_at || null,
          expires_at: l.rec.expires_at ?? null,
          last_seen: dev.last_seen || null,
          pulls: dev.pulls || 0,
        };
      });
    const guestsOf = (s) => guests
      .filter((g) => g.rec.dist === s)
      .map((g) => ({
        id: g.key.slice(4),
        username: g.rec.username || "",
        status: g.rec.status || "active",
        expires_at: g.rec.expires_at ?? null,
      }));
    const pendingOf = (s) => lics.filter(
      (l) => l.rec.dist === s && (l.rec.status === "issued" || l.rec.status === "open"),
    ).length;
    const totals = { devices: 0, guests: 0, subs: 0 };
    const members = new Set();
    const levelOf = new Map([[slug, distLevel(root)]]);
    const census = {}; // absolute level -> descendant count
    const walk = async (s, seen) => {
      if (seen.has(s)) return;
      seen.add(s);
      members.add(s);
      totals.devices += devicesOf(s).length;
      totals.guests += guestsOf(s).length;
      const kids = await listDistChildren(env, s);
      totals.subs += kids.length;
      for (const k of kids) {
        const lv = distLevel(k.rec);
        levelOf.set(k.slug, lv);
        census[lv] = (census[lv] || 0) + 1;
        await walk(k.slug, seen);
      }
    };
    await walk(slug, new Set());

    // Opening statistics over the whole subtree (owner,
    // 2026-11-04): how many memberships were opened per day,
    // duration-weighted into month units, valued at the 10-yuan
    // reference month price — what the seller actually charges
    // his own customers is his business; the book runs at 10.
    const REF_PRICE = 10;
    const monthPrefix = beijingDay(nowSec()).slice(0, 7);
    const cutoff = nowSec() - 30 * 86400;
    const byDay = new Map();
    const statsTotal = { count: 0, units: 0, money: 0 };
    const statsMonth = { count: 0, units: 0, money: 0, by_level: {} };
    const tallyOpen = (dist, createdAt, durationSec, fallbackDays) => {
      if (!members.has(dist) || !createdAt) return;
      const units = quotaCostFor(durationSec || (fallbackDays || 30) * 86400);
      statsTotal.count++; statsTotal.units += units; statsTotal.money += units * REF_PRICE;
      const day = beijingDay(createdAt);
      if (day.startsWith(monthPrefix)) {
        statsMonth.count++; statsMonth.units += units; statsMonth.money += units * REF_PRICE;
        const lv = levelOf.get(dist) || 0;
        if (lv >= 1) statsMonth.by_level[lv] = (statsMonth.by_level[lv] || 0) + units;
      }
      if (createdAt >= cutoff) {
        const d = byDay.get(day) || { day, count: 0, units: 0, money: 0 };
        d.count++; d.units += units; d.money += units * REF_PRICE;
        byDay.set(day, d);
      }
    };
    for (const l of lics) tallyOpen(l.rec.dist, l.rec.created_at, l.rec.duration_sec, l.rec.days);
    for (const g of guests) tallyOpen(g.rec.dist, g.rec.created_at, g.rec.duration_sec, g.rec.days);
    const daily = [...byDay.values()].sort((a, b) => (a.day < b.day ? 1 : -1));
    const stats = { census, daily, month: statsMonth, total: statsTotal, ref_price: REF_PRICE };
    // What this distributor owes HIS parent this month, and what
    // each direct sub owes HIM — the same numbers his own bill
    // page shows, synced onto every roster page (owner,
    // 2026-11-04: '二级的、三级的，都应该相应的同步'). To the
    // console the amount is the tiered sum over his subtree; to
    // a distributor parent it is the parent's price times his
    // subtree month units; unpriced parent -> null (unknowable).
    let oweParent = null;
    if (!root.parent) {
      const base = await consoleUnitPrice(env);
      oweParent = Math.round(Object.entries(statsMonth.by_level || {})
        .reduce((a, [lv, u]) => a + u * tierForLevel(base, Number(lv)), 0) * 100) / 100;
    } else {
      const p = await getDist(env, root.parent);
      if (p && Number.isFinite(p.price) && p.price > 0) {
        oweParent = Math.round(statsMonth.units * p.price * 100) / 100;
      }
    }
    const myPrice = Number.isFinite(root.price) && root.price > 0 ? root.price : null;
    const kids = await listDistChildren(env, slug);
    const subs = [];
    for (const k of kids) {
      const subTree = await buildTree(env, k.slug);
      const subUnits = subTree ? subTree.stats.month.units : 0;
      subs.push({
        slug: k.slug,
        name: k.rec.name || "",
        status: k.rec.status || "active",
        level: distLevel(k.rec),
        children: (await listDistChildren(env, k.slug)).length,
        devices: devicesOf(k.slug).length,
        pending: pendingOf(k.slug),
        guests: guestsOf(k.slug).length,
        month_units: subUnits,
        owe_to_root: myPrice === null ? null : Math.round(subUnits * myPrice * 100) / 100,
      });
    }
    return {
      ok: true,
      dist: {
        slug,
        name: root.name || "",
        level: distLevel(root),
        parent: root.parent || null,
        status: root.status || "active",
      },
      subs,
      owe_parent: oweParent,
      devices: devicesOf(slug),
      guests: guestsOf(slug),
      pending: pendingOf(slug),
      totals,
      stats,
    };
  });
}
