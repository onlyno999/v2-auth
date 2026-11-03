import { json, distSlugFromRequest, getDist } from "../../lib/core.js";

// GET -> the logged-in distributor's own info + quota state.
export async function onRequestGet({ request, env }) {
  const slug = await distSlugFromRequest(env, request);
  if (!slug) return json({ ok: false, reason: "unauthorized" }, 401);
  const rec = await getDist(env, slug);
  return json({
    ok: true, slug, name: rec.name, quota: rec.quota, used: rec.used,
    remaining: rec.quota < 0 ? -1 : Math.max(0, rec.quota - rec.used),
  });
}
