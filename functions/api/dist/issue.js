import {
  json, readJson, nowSec, distSlugFromRequest, getDist, putDist,
  newLicenseCode, codeKey, logEvent, vaultSeal, normalizeMachineCode, bumpDataVersion,
  parseDurationSec, fmtDuration,
} from "../../lib/core.js";

// POST {machineCode, durationValue+durationUnit | days, note, mode}
// (distributor session). Issues a license stamped dist=<slug>,
// channel="dist". Rules: any duration from 1 minute up to 365 days
// (owner, 2026-11-04: distributors set hours and minutes too, not
// just whole days), never permanent, quota enforced.
export async function onRequestPost({ request, env }) {
  await bumpDataVersion(env); // license write below bypasses putLic; invalidate cached tables
  const slug = await distSlugFromRequest(env, request);
  if (!slug) return json({ ok: false, reason: "unauthorized" }, 401);
  const body = await readJson(request);
  const machine = normalizeMachineCode(body.machineCode);
  if (!machine) return json({ ok: false, reason: "bad_machine" }, 400);
  const sec = parseDurationSec(body);
  if (sec === null || sec === undefined) return json({ ok: false, reason: "bad_duration" }, 400);
  if (sec === 0) return json({ ok: false, reason: "no_permanent" }, 400);
  if (sec > 365 * 86400) return json({ ok: false, reason: "days_range" }, 400);
  const days = Math.ceil(sec / 86400); // coarse compatibility field

  const rec = await getDist(env, slug);
  if (rec.quota >= 0 && rec.used >= rec.quota) {
    return json({ ok: false, reason: "quota_exhausted" }, 403);
  }
  const code = newLicenseCode();
  const key = await codeKey(code);
  const mode = body.mode === "open" ? "open" : "code";
  await env.V2.put(key, JSON.stringify({
    days,
    duration_sec: sec,
    status: mode === "open" ? "open" : "issued",
    machine,
    note: body.note || "",
    channel: "dist",
    dist: slug,
    code_enc: mode === "code" ? await vaultSeal(env, code) : null,
    created_at: nowSec(),
    activated_at: null,
    expires_at: null,
  }));
  if (mode === "open") await env.V2.put("open:" + machine, key);
  await putDist(env, slug, { ...rec, used: rec.used + 1 });
  await logEvent(env, "dist_issue", machine, `${slug}:${fmtDuration(sec)}`);
  return json(mode === "open" ? { ok: true, mode } : { ok: true, mode, code });
}
