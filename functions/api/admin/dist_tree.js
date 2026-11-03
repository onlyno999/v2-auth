import {
  json, isAdmin, getDist, listDistChildren, distLevel, cachedPayload,
} from "../../lib/core.js";

// GET /api/admin/dist_tree?slug=X -> one distributor's 下名册
// (owner, 2026-11-04): clicking a distributor in the admin console
// opens his subtree — how many people sit under him, at every
// level — and the admin stops any of their lines from there
// (existing action endpoints do the stopping; this is the view).
// Direct people are listed in full; totals count the WHOLE tree.
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

export async function onRequestGet({ request, env }) {
  if (!(await isAdmin(env, request))) return json({ ok: false, reason: "unauthorized" }, 401);
  const slug = (new URL(request.url).searchParams.get("slug") || "").toLowerCase();
  const root = await getDist(env, slug);
  if (!root) return json({ ok: false, reason: "not_found" }, 404);

  const payload = await cachedPayload(env, "admin:disttree:" + slug, 20000, async () => {
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

    // Recursive totals over the whole subtree (the tree is at
    // most 5 levels deep; the visited set is belt-and-braces).
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
  return json(payload);
}
