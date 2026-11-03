import {
  json, readJson, nowSec, isAdmin, getDev, getLicByKey, putLic, logEvent, parseDeltaSec,
} from "../../lib/core.js";

// POST {machineCode, action: revoke|restore|unbind|extend, days?}  (admin)
// Or {licKey, action: revoke} to kill an issued-but-unused code.
export async function onRequestPost({ request, env }) {
  if (!(await isAdmin(env, request))) return json({ ok: false, reason: "unauthorized" }, 401);
  const body = await readJson(request);

  if (body.licKey) {
    const lic = await getLicByKey(env, body.licKey);
    if (!lic) return json({ ok: false, reason: "not_found" }, 404);
    if (body.action === "revoke") {
      await putLic(env, { ...lic, status: "revoked" });
      if (lic.machine) await env.V2.delete("open:" + lic.machine);
      await logEvent(env, "admin_revoke_code", lic.machine || "");
      return json({ ok: true });
    }
    return json({ ok: false, reason: "bad_action" }, 400);
  }

  const machine = body.machineCode;
  if (!machine) return json({ ok: false, reason: "no_machine" }, 400);
  const dev = await getDev(env, machine);
  const licKey = dev?.lic || (await env.V2.get("open:" + machine));
  const lic = licKey ? await getLicByKey(env, licKey) : null;

  switch (body.action) {
    case "revoke": {
      if (!lic) return json({ ok: false, reason: "not_found" }, 404);
      await putLic(env, { ...lic, status: "revoked" });
      await logEvent(env, "admin_revoke", machine);
      return json({ ok: true });
    }
    case "restore": {
      if (!lic) return json({ ok: false, reason: "not_found" }, 404);
      await putLic(env, { ...lic, status: dev ? "active" : "issued" });
      await logEvent(env, "admin_restore", machine);
      return json({ ok: true });
    }
    case "unbind": {
      await env.V2.delete("dev:" + machine);
      await env.V2.delete("open:" + machine);
      if (lic && lic.status !== "revoked") {
        await putLic(env, { ...lic, status: "issued", activated_at: lic.activated_at });
      }
      await logEvent(env, "admin_unbind", machine);
      return json({ ok: true });
    }
    case "delete": {
      // Hard delete: the device row, its license and any open claim
      // all go. The machine is treated as never-activated afterwards
      // (it would need a fresh code). Unlike revoke, nothing remains.
      await env.V2.delete("dev:" + machine);
      await env.V2.delete("open:" + machine);
      if (licKey) await env.V2.delete(licKey);
      await logEvent(env, "admin_delete_device", machine);
      return json({ ok: true });
    }
    case "extend": {
      if (!lic) return json({ ok: false, reason: "not_found" }, 404);
      if (!lic.expires_at) return json({ ok: false, reason: "permanent" }, 400);
      const deltaSec = parseDeltaSec(body);
      if (deltaSec === null) return json({ ok: false, reason: "bad_duration" }, 400);
      const expires_at = lic.expires_at + deltaSec;
      await putLic(env, { ...lic, expires_at });
      await logEvent(env, "admin_extend", machine, `${deltaSec}s`);
      return json({ ok: true, expires_at, now: nowSec() });
    }
    default:
      return json({ ok: false, reason: "bad_action" }, 400);
  }
}
