import {
  json, readJson, nowSec, isAdmin, newLicenseCode, codeKey, logEvent, vaultSeal,
  parseDurationSec, durationSeconds, fmtDuration, normalizeMachineCode,
} from "../../lib/core.js";

// POST {machineCode, days | durationValue+durationUnit, note,
//       mode: "code"|"open", channel}  (admin)
// Duration accepts minute-level values (min 1 minute) via
// durationValue/durationUnit, or the legacy whole-{days} field
// (0 = permanent). mode "code": returns a license code pre-bound to
// the machine. mode "open": direct-open — the user claims it.
export async function onRequestPost({ request, env }) {
  if (!(await isAdmin(env, request))) return json({ ok: false, reason: "unauthorized" }, 401);
  const body = await readJson(request);
  // The machine field must hold a machine code — never an activation
  // code. Normalize (case/spacing) and validate the 4-4-4-4 format;
  // anything else (above all V2O-…) is refused instead of being
  // parked where no device can ever claim it.
  const machine = normalizeMachineCode(body.machineCode);
  if (!machine) return json({ ok: false, reason: "bad_machine" }, 400);
  let sec = parseDurationSec(body);
  if (sec === null) return json({ ok: false, reason: "bad_duration" }, 400);
  if (sec === undefined) sec = 30 * 86400;
  const code = newLicenseCode();
  const key = await codeKey(code);
  const mode = body.mode === "open" ? "open" : "code";
  const rec = {
    // `days` stays as a coarse compatibility field (ceil); the exact
    // length lives in duration_sec and rules the real expiry.
    days: sec ? Math.ceil(sec / 86400) : 0,
    duration_sec: sec || null,
    status: mode === "open" ? "open" : "issued",
    machine,
    note: body.note || "",
    channel: body.channel === "dist" ? "dist" : "main",
    code_enc: mode === "code" ? await vaultSeal(env, code) : null,
    created_at: nowSec(),
    activated_at: null,
    expires_at: null,
  };
  await env.V2.put(key, JSON.stringify(rec));
  if (mode === "open") {
    await env.V2.put("open:" + machine, key);
    await logEvent(env, "admin_open", machine, fmtDuration(durationSeconds(rec)));
    return json({ ok: true, mode });
  }
  await logEvent(env, "admin_issue", machine, fmtDuration(durationSeconds(rec)));
  return json({ ok: true, mode, code });
}
