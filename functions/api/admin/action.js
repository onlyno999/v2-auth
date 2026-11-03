import {
  json, readJson, nowSec, isAdmin, getDev, getLicByKey, putLic, logEvent, parseDeltaSec,
  bumpDataVersion,
} from "../../lib/core.js";

// POST {machineCode, action: revoke|restore|unbind|extend|set_expiry,
//       days?, expires_at?}  (admin). set_expiry writes an absolute
// expiry (epoch seconds), or null for permanent.
// Or {licKey, action: revoke} to kill an issued-but-unused code.
export async function onRequestPost({ request, env }) {
  await bumpDataVersion(env); // any console mutation invalidates cached table payloads
  if (!(await isAdmin(env, request))) return json({ ok: false, reason: "unauthorized" }, 401);
  const body = await readJson(request);

  if (body.licKey) {
    const lic = await getLicByKey(env, body.licKey);
    if (!lic) return json({ ok: false, reason: "not_found" }, 404);
    if (body.action === "revoke") {
      // 作废 an unused code is a hard delete (owner's rule: what the
      // console deletes must disappear from KV too — no tombstones).
      // The license record, its open claim and any refusal note go.
      await env.V2.delete(body.licKey);
      if (lic.machine) {
        await env.V2.delete("open:" + lic.machine);
        await env.V2.delete("attestfail:" + lic.machine);
      }
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
      await env.V2.delete("last:" + machine);
      await env.V2.delete("attestfail:" + machine);
      if (lic && lic.status !== "revoked") {
        await putLic(env, { ...lic, status: "issued", activated_at: lic.activated_at });
      }
      await logEvent(env, "admin_unbind", machine);
      return json({ ok: true });
    }
    case "delete": {
      // Hard delete: the device row, its license and every per-
      // machine trace all go (owner's rule: console deletions must
      // clean KV too). The machine is treated as never-activated
      // afterwards (it would need a fresh code). Unlike revoke
      // (停用, restorable), nothing remains.
      await env.V2.delete("dev:" + machine);
      await env.V2.delete("open:" + machine);
      await env.V2.delete("last:" + machine);
      await env.V2.delete("attestfail:" + machine);
      await env.V2.delete("chal:" + machine);
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
    case "set_expiry": {
      // Manual edit of the expiry moment itself (the console's
      // 修改时间 button): an absolute epoch-second deadline, or null
      // to make the license permanent. A past moment is allowed —
      // it simply expires the license immediately.
      if (!lic) return json({ ok: false, reason: "not_found" }, 404);
      if (!("expires_at" in body)) return json({ ok: false, reason: "bad_expiry" }, 400);
      if (body.expires_at === null) {
        await putLic(env, { ...lic, expires_at: null, days: 0, duration_sec: null });
        await logEvent(env, "admin_set_expiry", machine, "permanent");
        return json({ ok: true, expires_at: null, now: nowSec() });
      }
      const expires_at = Number(body.expires_at);
      if (!Number.isFinite(expires_at) || Math.floor(expires_at) !== expires_at || expires_at <= 0) {
        return json({ ok: false, reason: "bad_expiry" }, 400);
      }
      const days = Math.max(0, Math.ceil((expires_at - nowSec()) / 86400));
      await putLic(env, { ...lic, expires_at, days });
      await logEvent(env, "admin_set_expiry", machine, String(expires_at));
      return json({ ok: true, expires_at, now: nowSec() });
    }
    default:
      return json({ ok: false, reason: "bad_action" }, 400);
  }
}
