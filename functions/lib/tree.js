import { getDist, listDistChildren, distLevel, cachedPayload } from "./core.js";

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
    const walk = async (s, seen) => {
      if (seen.has(s)) return;
      seen.add(s);
      totals.devices += devicesOf(s).length;
      totals.guests += guestsOf(s).length;
      const kids = await listDistChildren(env, s);
      totals.subs += kids.length;
      for (const k of kids) await walk(k.slug, seen);
    };
    await walk(slug, new Set());
    const kids = await listDistChildren(env, slug);
    const subs = [];
    for (const k of kids) {
      subs.push({
        slug: k.slug,
        name: k.rec.name || "",
        status: k.rec.status || "active",
        level: distLevel(k.rec),
        children: (await listDistChildren(env, k.slug)).length,
        devices: devicesOf(k.slug).length,
        pending: pendingOf(k.slug),
        guests: guestsOf(k.slug).length,
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
      devices: devicesOf(slug),
      guests: guestsOf(slug),
      pending: pendingOf(slug),
      totals,
    };
  });
}
