import {
  json, readJson, nowSec, isAdmin, sha256hex, getDist, putDist, SLUG_RE, RESERVED_SLUGS,
  bumpDataVersion, cachedPayload, moveDistributor, listDistChildren, distLevel,
} from "../../lib/core.js";

// GET -> all distributors. POST -> create / update / disable / enable.
export async function onRequestGet({ request, env }) {
  if (!(await isAdmin(env, request))) return json({ ok: false, reason: "unauthorized" }, 401);
  const out = await cachedPayload(env, "admin:dist", 20000, async () => {
    // Tally each distributor's users (owner, 2026-11-04: the console
    // must show how many users sit under each distributor):
    // activated customers (active/revoked licenses), not-yet-claimed
    // codes (issued/open), and his guest accounts.
    const tally = new Map();
    const bump = (slug, field) => {
      if (!slug) return;
      const t = tally.get(slug) || { devices: 0, pending: 0, guests: 0 };
      t[field]++;
      tally.set(slug, t);
    };
    for (const prefix of ["lic:", "gst:"]) {
      let cursor;
      do {
        const page = await env.V2.list({ prefix, limit: 200, cursor });
        cursor = page.list_complete ? undefined : page.cursor;
        for (const k of page.keys) {
          const raw = await env.V2.get(k.name);
          if (!raw) continue;
          const rec = JSON.parse(raw);
          if (prefix === "gst:") bump(rec.dist, "guests");
          else if (rec.status === "active" || rec.status === "revoked") bump(rec.dist, "devices");
          else if (rec.status === "issued" || rec.status === "open") bump(rec.dist, "pending");
        }
      } while (cursor);
    }
    const rows = [];
    const page = await env.V2.list({ prefix: "dist:", limit: 200 });
    for (const k of page.keys) {
      const raw = await env.V2.get(k.name);
      // KV is eventually consistent: a just-written key can list before
      // its value is readable. Never render a ghost row from "{}" —
      // skip it; it appears whole on the next refresh.
      if (!raw) continue;
      const rec = JSON.parse(raw);
      const slug = k.name.slice(5);
      rows.push({
        slug, ...rec, pw_hash: undefined, has_pw: !!rec.pw_hash,
        level: distLevel(rec), parent: rec.parent || null,
        users: tally.get(slug) || { devices: 0, pending: 0, guests: 0 },
      });
    }
    for (const r of rows) {
      r.children = rows.filter((x) => x.parent === r.slug).length;
    }
    return rows;
  });
  return json({ ok: true, distributors: out });
}

export async function onRequestPost({ request, env }) {
  await bumpDataVersion(env); // any console mutation invalidates cached table payloads
  if (!(await isAdmin(env, request))) return json({ ok: false, reason: "unauthorized" }, 401);
  const body = await readJson(request);
  const slug = (body.slug || "").toLowerCase();

  if (body.action === "create") {
    if (!SLUG_RE.test(slug) || RESERVED_SLUGS.has(slug)) {
      return json({ ok: false, reason: "bad_slug" }, 400);
    }
    // Password is optional: leave it empty and the distributor sets
    // his own on first visit (stored hashed in KV, admin never sees it).
    if (body.password && String(body.password).length < 6) {
      return json({ ok: false, reason: "weak_password" }, 400);
    }
    if (await getDist(env, slug)) return json({ ok: false, reason: "exists" }, 409);
    // Placement in the tree (owner, 2026-11-04): distributors do
    // NOT open distributors themselves — the admin adds everyone
    // manually, either directly under the console (level 1) or
    // under an existing distributor's name, inside the ternary
    // caps (at most 3 children each, five levels deep).
    let level = 1, parent = null;
    if (body.parent) {
      const pSlug = String(body.parent).toLowerCase();
      const pRec = await getDist(env, pSlug);
      if (!pRec) return json({ ok: false, reason: "parent_not_found" }, 404);
      if (distLevel(pRec) >= 5) return json({ ok: false, reason: "max_level" }, 400);
      if ((await listDistChildren(env, pSlug)).length >= 3) {
        return json({ ok: false, reason: "children_limit" }, 400);
      }
      level = distLevel(pRec) + 1;
      parent = pSlug;
    }
    await putDist(env, slug, {
      name: body.name || slug,
      pw_hash: body.password ? await sha256hex(String(body.password)) : null,
      quota: Number.isFinite(body.quota) ? Math.floor(body.quota) : 100,
      used: 0,
      status: "active",
      level,
      parent,
      created_at: nowSec(),
    });
    return json({ ok: true, slug });
  }

  // A just-created record may not be readable everywhere yet (KV
  // eventual consistency): retry the read before saying not_found.
  let rec = await getDist(env, slug);
  for (let i = 0; !rec && i < 3; i++) {
    await new Promise((r) => setTimeout(r, 700));
    rec = await getDist(env, slug);
  }
  if (!rec) return json({ ok: false, reason: "not_found" }, 404);
  switch (body.action) {
    case "disable":
      await putDist(env, slug, { ...rec, status: "disabled" });
      return json({ ok: true });
    case "enable":
      await putDist(env, slug, { ...rec, status: "active" });
      return json({ ok: true });
    case "rename":
      {
        const name = String(body.name || "").trim().slice(0, 40);
        if (!name) return json({ ok: false, reason: "no_name" }, 400);
        await putDist(env, slug, { ...rec, name });
      }
      return json({ ok: true });
    case "reslug": {
      // Change the login identifier itself (owner's request): the
      // record moves to the new key — name, password hash, quota,
      // usage and status all travel; only his /<slug> login link
      // changes and the old address dies. Licenses and guests he
      // already issued are re-stamped so every console keeps
      // attributing them to him under the new slug.
      const next = (body.new_slug || "").toLowerCase();
      if (!SLUG_RE.test(next) || RESERVED_SLUGS.has(next)) {
        return json({ ok: false, reason: "bad_slug" }, 400);
      }
      if (next === slug) return json({ ok: true, slug });
      if (await getDist(env, next)) return json({ ok: false, reason: "exists" }, 409);
      await moveDistributor(env, slug, next, rec);
      return json({ ok: true, slug: next });
    }
    case "quota":
      await putDist(env, slug, { ...rec, quota: Math.floor(body.quota ?? rec.quota) });
      return json({ ok: true });
    case "password":
      if (!body.password || String(body.password).length < 6) {
        return json({ ok: false, reason: "weak_password" }, 400);
      }
      await putDist(env, slug, { ...rec, pw_hash: await sha256hex(String(body.password)) });
      return json({ ok: true });
    case "resetpw":
      // Clear the password: on his next visit the distributor sets a
      // fresh one himself (see /api/dist/setup).
      await putDist(env, slug, { ...rec, pw_hash: null });
      return json({ ok: true });
    case "delete":
      // Only a disabled account can be deleted (guard against wiping
      // an active distributor). His already-issued customers keep
      // their licenses untouched; the /<slug> link dies immediately.
      if (rec.status !== "disabled") return json({ ok: false, reason: "disable_first" }, 400);
      if ((await listDistChildren(env, slug)).length) {
        return json({ ok: false, reason: "has_children" }, 400);
      }
      await env.V2.delete("dist:" + slug);
      return json({ ok: true });
    default:
      return json({ ok: false, reason: "bad_action" }, 400);
  }
}
