import { json, isAdmin, getLicByKey } from "../../lib/core.js";

// GET -> device table for the admin console.
export async function onRequestGet({ request, env }) {
  if (!(await isAdmin(env, request))) return json({ ok: false, reason: "unauthorized" }, 401);
  const out = [];
  let cursor;
  do {
    const page = await env.KV.list({ prefix: "dev:", limit: 200, cursor });
    cursor = page.list_complete ? undefined : page.cursor;
    for (const k of page.keys) {
      const dev = JSON.parse((await env.KV.get(k.name)) || "{}");
      const machine = k.name.slice(4);
      const lic = dev.lic ? await getLicByKey(env, dev.lic) : null;
      const last = await env.KV.get("last:" + machine);
      out.push({
        machine,
        platform: dev.platform || "",
        first_seen: dev.first_seen || null,
        last_seen: dev.last_seen || null,
        pulls: dev.pulls || 0,
        integrity: dev.integrity || null,
        lic: lic
          ? {
              status: lic.status, days: lic.days, note: lic.note || "",
              created_at: lic.created_at, activated_at: lic.activated_at,
              expires_at: lic.expires_at,
            }
          : null,
        last_event: last ? JSON.parse(last) : null,
      });
    }
  } while (cursor);
  // Pending direct-opens (not yet claimed)
  const opens = [];
  const op = await env.KV.list({ prefix: "open:", limit: 200 });
  for (const k of op.keys) opens.push(k.name.slice(5));
  return json({ ok: true, devices: out, pending_open: opens });
}
