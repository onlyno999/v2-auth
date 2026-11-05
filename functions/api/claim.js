import { json, readJson, getLicByKey, logEvent, normalizeMachineCode, nowSec } from "../lib/core.js";
import { finishActivation } from "./activate.js";

// POST {machineCode, pubkey, platform, signer?}
// Direct-open flow: admin pre-opened this machine in the console; the
// user taps "I have paid" and claims the device token.
//
// Reinstall recovery (owner, 2026-11-05): a direct-open customer who
// deletes and reinstalls the app lost his token with the app data —
// and claim used to serve ONLY never-claimed ("open") licenses, so
// the reinstalled app was told "not opened" while the console showed
// a live, unexpired license; the owner had to re-authorize the
// machine by hand every time. A CODELESS license (code_enc null —
// direct-open issues carry no code) now stays claimable for its
// machine in "open", "active" and post-unbind "issued" states:
// finishActivation re-issues a fresh token (the old one dies) and
// KEEPS the original activated_at/expires_at, so a re-claim never
// extends the term. The build binding does the guarding: a
// reinstall of the genuine build presents the same signer digest
// and passes; a repackaged build is refused signer_mismatch.
// Licenses WITH a code are never claimable — their recovery is
// re-entering the code, which /api/activate already allows for
// active licenses.
function claimable(lic, machine) {
  if (!lic || lic.machine !== machine) return false;
  if (lic.status === "open") return true;
  if ((lic.status === "active" || lic.status === "issued") && !lic.code_enc) return true;
  return false;
}

export async function onRequestPost({ request, env }) {
  const body = await readJson(request);
  if (!body.machineCode) return json({ ok: false, reason: "bad_request" }, 400);
  const ip = request.headers.get("cf-connecting-ip") || "local";
  const bucket = `rlc:${ip}:${Math.floor(nowSec() / 3600)}`;
  const tries = parseInt((await env.V2.get(bucket)) || "0", 10);
  if (tries > 20) return json({ ok: false, reason: "rate_limited" }, 429);
  await env.V2.put(bucket, String(tries + 1), { expirationTtl: 3700 });

  const machine = normalizeMachineCode(body.machineCode) || body.machineCode;
  let lic = null;
  const licKey = await env.V2.get("open:" + machine);
  if (licKey) {
    const cand = await getLicByKey(env, licKey);
    if (claimable(cand, machine)) lic = cand;
  }
  if (!lic) {
    // Scan: the open: pointer is a second, separate KV write in the
    // issue request — if it is lost, the claim used to answer
    // no_open forever while the console kept listing the license as
    // awaiting claim (production incident, 2026-11-04). And after a
    // successful claim the pointer is deleted, so reinstall
    // recovery can only ever be found here. The license records are
    // the source of truth: an unclaimed open wins; otherwise the
    // newest claimable record for this machine.
    const found = [];
    let cursor;
    do {
      const page = await env.V2.list({ prefix: "lic:", limit: 200, cursor });
      cursor = page.list_complete ? undefined : page.cursor;
      for (const k of page.keys) {
        const cand = await getLicByKey(env, k.name);
        if (claimable(cand, machine)) found.push(cand);
      }
    } while (cursor);
    found.sort((a, b) =>
      (a.status === "open" ? 0 : 1) - (b.status === "open" ? 0 : 1) ||
      (b.created_at || 0) - (a.created_at || 0));
    lic = found[0] || null;
  }
  if (!lic) return json({ ok: false, reason: "no_open" }, 404);
  if (lic.expires_at && lic.expires_at < nowSec()) {
    await logEvent(env, "claim", body.machineCode, "expired");
    return json({ ok: false, reason: "expired" }, 403);
  }
  const res = await finishActivation(env, lic, body);
  if (res.status === 200) await env.V2.delete("open:" + machine);
  await logEvent(env, "claim", body.machineCode);
  return res;
}
