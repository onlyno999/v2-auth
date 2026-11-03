import {
  json, readJson, nowSec, isAdmin, newLicenseCode, codeKey, logEvent, vaultSeal,
} from "../../lib/core.js";

// POST {machineCode, days, note, mode: "code"|"open"}  (admin)
// mode "code": returns a license code pre-bound to the machine.
// mode "open": direct-open — the user claims it from the app.
export async function onRequestPost({ request, env }) {
  if (!(await isAdmin(env, request))) return json({ ok: false, reason: "unauthorized" }, 401);
  const body = await readJson(request);
  if (!body.machineCode) return json({ ok: false, reason: "no_machine" }, 400);
  const days = Number.isFinite(body.days) ? Math.max(0, Math.floor(body.days)) : 30;
  const code = newLicenseCode();
  const key = await codeKey(code);
  const mode = body.mode === "open" ? "open" : "code";
  const rec = {
    days,
    status: mode === "open" ? "open" : "issued",
    machine: body.machineCode,
    note: body.note || "",
    channel: body.channel === "dist" ? "dist" : "main",
    code_enc: mode === "code" ? await vaultSeal(env, code) : null,
    created_at: nowSec(),
    activated_at: null,
    expires_at: null,
  };
  await env.V2.put(key, JSON.stringify(rec));
  if (mode === "open") {
    await env.V2.put("open:" + body.machineCode, key);
    await logEvent(env, "admin_open", body.machineCode, `${days}d`);
    return json({ ok: true, mode });
  }
  await logEvent(env, "admin_issue", body.machineCode, `${days}d`);
  return json({ ok: true, mode, code });
}
