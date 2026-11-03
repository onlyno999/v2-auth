import { json, distSlugFromRequest, getLicByKey } from "../../lib/core.js";

// GET -> only this distributor's own customers.
export async function onRequestGet({ request, env }) {
  const slug = await distSlugFromRequest(env, request);
  if (!slug) return json({ ok: false, reason: "unauthorized" }, 401);
  const out = [];
  let cursor;
  do {
    const page = await env.V2.list({ prefix: "dev:", limit: 200, cursor });
    cursor = page.list_complete ? undefined : page.cursor;
    for (const k of page.keys) {
      const dev = JSON.parse((await env.V2.get(k.name)) || "{}");
      if (!dev.lic) continue;
      const lic = await getLicByKey(env, dev.lic);
      if (!lic || lic.dist !== slug) continue;
      out.push({
        machine: k.name.slice(4),
        platform: dev.platform || "",
        last_seen: dev.last_seen || null,
        pulls: dev.pulls || 0,
        lic: {
          status: lic.status, note: lic.note || "",
          activated_at: lic.activated_at, expires_at: lic.expires_at,
        },
      });
    }
  } while (cursor);
  return json({ ok: true, devices: out });
}
