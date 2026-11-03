import {
  json, readJson, nowSec, isAdmin, sha256hex, getDist, putDist, SLUG_RE, RESERVED_SLUGS,
} from "../../lib/core.js";

// GET -> all distributors. POST -> create / update / disable / enable.
export async function onRequestGet({ request, env }) {
  if (!(await isAdmin(env, request))) return json({ ok: false, reason: "unauthorized" }, 401);
  const out = [];
  const page = await env.V2.list({ prefix: "dist:", limit: 200 });
  for (const k of page.keys) {
    const rec = JSON.parse((await env.V2.get(k.name)) || "{}");
    out.push({ slug: k.name.slice(5), ...rec, pw_hash: undefined });
  }
  return json({ ok: true, distributors: out });
}

export async function onRequestPost({ request, env }) {
  if (!(await isAdmin(env, request))) return json({ ok: false, reason: "unauthorized" }, 401);
  const body = await readJson(request);
  const slug = (body.slug || "").toLowerCase();

  if (body.action === "create") {
    if (!SLUG_RE.test(slug) || RESERVED_SLUGS.has(slug)) {
      return json({ ok: false, reason: "bad_slug" }, 400);
    }
    if (!body.password || String(body.password).length < 6) {
      return json({ ok: false, reason: "weak_password" }, 400);
    }
    if (await getDist(env, slug)) return json({ ok: false, reason: "exists" }, 409);
    await putDist(env, slug, {
      name: body.name || slug,
      pw_hash: await sha256hex(String(body.password)),
      quota: Number.isFinite(body.quota) ? Math.floor(body.quota) : 100,
      used: 0,
      status: "active",
      created_at: nowSec(),
    });
    return json({ ok: true, slug });
  }

  const rec = await getDist(env, slug);
  if (!rec) return json({ ok: false, reason: "not_found" }, 404);
  switch (body.action) {
    case "disable":
      await putDist(env, slug, { ...rec, status: "disabled" });
      return json({ ok: true });
    case "enable":
      await putDist(env, slug, { ...rec, status: "active" });
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
    default:
      return json({ ok: false, reason: "bad_action" }, 400);
  }
}
