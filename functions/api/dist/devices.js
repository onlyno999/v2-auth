import { json, distSlugFromRequest, getLicByKey } from "../../lib/core.js";

// GET -> only this distributor's own customers.
export async function onRequestGet({ request, env }) {
  const slug = await distSlugFromRequest(env, request);
  if (!slug) return json({ ok: false, reason: "unauthorized" }, 401);
  const out = [];
  const devKeys = [];
  let cursor;
  do {
    const page = await env.V2.list({ prefix: "dev:", limit: 200, cursor });
    cursor = page.list_complete ? undefined : page.cursor;
    devKeys.push(...page.keys.map((k) => k.name));
  } while (cursor);
  const devVals = await Promise.all(devKeys.map((k) => env.V2.get(k)));
  const devs = devKeys.map((k, i) => [k.slice(4), JSON.parse(devVals[i] || "{}")]);
  const licKeys = [...new Set(devs.map(([, d]) => d.lic).filter(Boolean))];
  const licVals = await Promise.all(licKeys.map((k) => env.V2.get(k)));
  const licByKey = new Map(licKeys.map((k, i) => [k, JSON.parse(licVals[i] || "{}")]));
  for (const [machine, dev] of devs) {
    if (!dev.lic) continue;
    const lic = licByKey.get(dev.lic);
    if (!lic || lic.dist !== slug) continue;
    out.push({
      machine,
      platform: dev.platform || "",
      last_seen: dev.last_seen || null,
      pulls: dev.pulls || 0,
      lic: {
        status: lic.status, note: lic.note || "",
        activated_at: lic.activated_at, expires_at: lic.expires_at,
      },
    });
  }
  return json({ ok: true, devices: out });
}
