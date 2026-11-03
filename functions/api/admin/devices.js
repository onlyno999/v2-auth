import { json, isAdmin, getLicByKey } from "../../lib/core.js";

// GET -> device table for the admin console.
export async function onRequestGet({ request, env }) {
  if (!(await isAdmin(env, request))) return json({ ok: false, reason: "unauthorized" }, 401);
  const out = [];
  let cursor;
  do {
    const page = await env.V2.list({ prefix: "dev:", limit: 200, cursor });
    cursor = page.list_complete ? undefined : page.cursor;
    for (const k of page.keys) {
      const dev = JSON.parse((await env.V2.get(k.name)) || "{}");
      const machine = k.name.slice(4);
      const lic = dev.lic ? await getLicByKey(env, dev.lic) : null;
      const last = await env.V2.get("last:" + machine);
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
              channel: lic.channel || "main", dist: lic.dist || null,
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
  const op = await env.V2.list({ prefix: "open:", limit: 200 });
  for (const k of op.keys) opens.push(k.name.slice(5));
  // Issued-but-not-activated licenses (seller's "codes I handed out" view)
  const issued = [];
  let lc;
  do {
    const page = await env.V2.list({ prefix: "lic:", limit: 200, cursor: lc });
    lc = page.list_complete ? undefined : page.cursor;
    for (const k of page.keys) {
      const lic = JSON.parse((await env.V2.get(k.name)) || "{}");
      if (lic.status === "issued" || lic.status === "open") {
        issued.push({
          licKey: k.name,
          machine: lic.machine, note: lic.note || "", days: lic.days,
          channel: lic.channel || "main", dist: lic.dist || null,
          status: lic.status, created_at: lic.created_at,
        });
      }
    }
  } while (lc);
  issued.sort((a, b) => (b.created_at || 0) - (a.created_at || 0));
  return json({ ok: true, devices: out, pending_open: opens, issued });
}
