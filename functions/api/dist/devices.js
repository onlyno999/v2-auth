import { json, distSlugFromRequest, getLicByKey, cachedPayload } from "../../lib/core.js";

// GET -> only this distributor's own customers.
export async function onRequestGet({ request, env }) {
  const slug = await distSlugFromRequest(env, request);
  if (!slug) return json({ ok: false, reason: "unauthorized" }, 401);
  const out = await cachedPayload(env, "dist:devices:" + slug, 20000, () => buildDevices(env, slug));
  return json({ ok: true, devices: out });
}

async function buildDevices(env, slug) {
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
  // Sold but not yet activated (owner, 2026-11-04: his customer
  // list read empty while his quota already counted the sales —
  // 'not one person under him, and the quota is out of sync').
  // An issued code / direct open has no device record until the
  // buyer first opens the app, so list those licenses too,
  // flagged pending, on top: they ARE his people, just waiting.
  const pending = [];
  let cursor2;
  do {
    const page = await env.V2.list({ prefix: "lic:", limit: 200, cursor: cursor2 });
    cursor2 = page.list_complete ? undefined : page.cursor;
    for (const k of page.keys) {
      const raw = await env.V2.get(k.name);
      if (!raw) continue;
      const rec = JSON.parse(raw);
      if (rec.dist !== slug) continue;
      if (rec.status !== "issued" && rec.status !== "open") continue;
      pending.push({
        machine: rec.machine,
        pending: true,
        platform: "",
        last_seen: null,
        pulls: 0,
        lic: {
          status: rec.status, note: rec.note || "",
          created_at: rec.created_at || null,
          duration_sec: rec.duration_sec || null,
          days: rec.days || null,
        },
      });
    }
  } while (cursor2);
  pending.sort((a, b) => (b.lic.created_at || 0) - (a.lic.created_at || 0));
  return [...pending, ...out];
}
