import {
  json, readJson, nowSec, isAdmin, sha256hex, getDist, putDist, SLUG_RE, RESERVED_SLUGS,
  bumpDataVersion, cachedPayload,
} from "../../lib/core.js";

// GET -> all distributors. POST -> create / update / disable / enable.
export async function onRequestGet({ request, env }) {
  if (!(await isAdmin(env, request))) return json({ ok: false, reason: "unauthorized" }, 401);
  const out = await cachedPayload("admin:dist", 20000, async () => {
    const rows = [];
    const page = await env.V2.list({ prefix: "dist:", limit: 200 });
    for (const k of page.keys) {
      const raw = await env.V2.get(k.name);
      // KV is eventually consistent: a just-written key can list before
      // its value is readable. Never render a ghost row from "{}" —
      // skip it; it appears whole on the next refresh.
      if (!raw) continue;
      const rec = JSON.parse(raw);
      rows.push({ slug: k.name.slice(5), ...rec, pw_hash: undefined, has_pw: !!rec.pw_hash });
    }
    return rows;
  });
  return json({ ok: true, distributors: out });
}

export async function onRequestPost({ request, env }) {
  bumpDataVersion(); // any console mutation invalidates cached table payloads
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
    await putDist(env, slug, {
      name: body.name || slug,
      pw_hash: body.password ? await sha256hex(String(body.password)) : null,
      quota: Number.isFinite(body.quota) ? Math.floor(body.quota) : 100,
      used: 0,
      status: "active",
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
      await env.V2.delete("dist:" + slug);
      return json({ ok: true });
    default:
      return json({ ok: false, reason: "bad_action" }, 400);
  }
}
