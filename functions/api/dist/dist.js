import {
  json, readJson, nowSec, sha256hex, getDist, putDist, distSlugFromRequest,
  SLUG_RE, RESERVED_SLUGS, bumpDataVersion, moveDistributor, listDistChildren,
  distLevel,
} from "../../lib/core.js";

// The distributor tree (owner's design, 2026-11-04): five levels,
// ternary — every distributor may open AT MOST 3 sub-distributors
// (1 -> 3 -> 9 -> 27 -> 81). Admin-created distributors are
// level 1; a level-5 distributor cannot open more. Creating a sub
// does NOT consume the parent's issuing quota; the sub's own quota
// is set by the parent and governs the sub's own issuing.
//
// GET  -> my direct sub-distributors (with their user counts).
// POST -> create / manage MY OWN sub-distributors only.
const MAX_CHILDREN = 3;
const MAX_LEVEL = 5;

async function tallyUsers(env, slug) {
  const t = { devices: 0, pending: 0, guests: 0 };
  for (const prefix of ["lic:", "gst:"]) {
    let cursor;
    do {
      const page = await env.V2.list({ prefix, limit: 200, cursor });
      cursor = page.list_complete ? undefined : page.cursor;
      for (const k of page.keys) {
        const raw = await env.V2.get(k.name);
        if (!raw) continue;
        const rec = JSON.parse(raw);
        if (rec.dist !== slug) continue;
        if (prefix === "gst:") t.guests++;
        else if (rec.status === "active" || rec.status === "revoked") t.devices++;
        else if (rec.status === "issued" || rec.status === "open") t.pending++;
      }
    } while (cursor);
  }
  return t;
}

export async function onRequestGet({ request, env }) {
  const slug = await distSlugFromRequest(env, request);
  if (!slug) return json({ ok: false, reason: "unauthorized" }, 401);
  const me = await getDist(env, slug);
  if (!me) return json({ ok: false, reason: "unauthorized" }, 401);
  const kids = await listDistChildren(env, slug);
  const out = [];
  for (const k of kids) {
    out.push({
      slug: k.slug,
      name: k.rec.name || "",
      quota: k.rec.quota,
      used: k.rec.used || 0,
      status: k.rec.status || "active",
      has_pw: !!k.rec.pw_hash,
      level: distLevel(k.rec),
      children: (await listDistChildren(env, k.slug)).length,
      users: await tallyUsers(env, k.slug),
    });
  }
  return json({
    ok: true,
    level: distLevel(me),
    max_children: MAX_CHILDREN,
    max_level: MAX_LEVEL,
    can_create: false,
    distributors: out,
  });
}

export async function onRequestPost({ request, env }) {
  await bumpDataVersion(env); // console mutations invalidate cached tables
  const slug = await distSlugFromRequest(env, request);
  if (!slug) return json({ ok: false, reason: "unauthorized" }, 401);
  const me = await getDist(env, slug);
  if (!me) return json({ ok: false, reason: "unauthorized" }, 401);
  const body = await readJson(request);

  if (body.action === "create") {
    // Owner (2026-11-04): distributors never open distributors —
    // every distributor is added manually by the admin console,
    // under whoever's name it belongs. This console only MANAGES.
    return json({ ok: false, reason: "admin_only" }, 403);
  }

  // Every other action targets one of MY sub-distributors.
  const child = (body.slug || "").toLowerCase();
  const rec = await getDist(env, child);
  if (!rec || rec.parent !== slug) return json({ ok: false, reason: "not_found" }, 404);
  switch (body.action) {
    case "disable":
      await putDist(env, child, { ...rec, status: "disabled" });
      return json({ ok: true });
    case "enable":
      await putDist(env, child, { ...rec, status: "active" });
      return json({ ok: true });
    case "rename": {
      const name = String(body.name || "").trim().slice(0, 40);
      if (!name) return json({ ok: false, reason: "no_name" }, 400);
      await putDist(env, child, { ...rec, name });
      return json({ ok: true });
    }
    case "quota":
      await putDist(env, child, { ...rec, quota: Math.floor(body.quota ?? rec.quota) });
      return json({ ok: true });
    case "resetpw":
      await putDist(env, child, { ...rec, pw_hash: null });
      return json({ ok: true });
    case "reslug": {
      const next = (body.new_slug || "").toLowerCase();
      if (!SLUG_RE.test(next) || RESERVED_SLUGS.has(next)) {
        return json({ ok: false, reason: "bad_slug" }, 400);
      }
      if (next === child) return json({ ok: true, slug: child });
      if (await getDist(env, next)) return json({ ok: false, reason: "exists" }, 409);
      await moveDistributor(env, child, next, rec);
      return json({ ok: true, slug: next });
    }
    case "delete":
      if (rec.status !== "disabled") return json({ ok: false, reason: "disable_first" }, 400);
      if ((await listDistChildren(env, child)).length) {
        return json({ ok: false, reason: "has_children" }, 400);
      }
      await env.V2.delete("dist:" + child);
      return json({ ok: true });
    default:
      return json({ ok: false, reason: "bad_action" }, 400);
  }
}
