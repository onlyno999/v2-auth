import { json, readJson, getLicByKey, logEvent, normalizeMachineCode, nowSec } from "../lib/core.js";
import { finishActivation } from "./activate.js";

// POST {machineCode, pubkey, platform, signer?}
// Direct-open flow: admin pre-opened this machine in the console; the
// user taps "I have paid" and claims the device token.
//
// Reinstall recovery (owner, 2026-11-05): a customer who deletes
// and reinstalls the app loses his token with the app data — and
// claim used to serve ONLY never-claimed ("open") licenses, so
// the reinstalled app was told "not opened" while the console
// showed a live, unexpired license; the owner had to re-
// authorize the machine by hand every time. The first fix tried
// to keep code-issued licenses out of claim (recovery = re-enter
// the code) — and promptly locked out the owner's OWN phone,
// whose license was code/legacy-issued: the backend had him
// authorized, tapping direct-open still said "not opened".
// Final rule: the machine binding IS the authorization. Any
// license bound to this machine in "open", "active" or post-
// unbind "issued" state is claimable; finishActivation issues a
// fresh token (the old one dies) and KEEPS the original
// activated_at/expires_at, so a re-claim never extends the
// term. The guards are the build binding (a genuine reinstall
// presents the same signer digest; a repackaged build gets
// signer_mismatch) and the rate limit below — a machine code
// is an identity the customer shares with his seller, not a
// secret, and a stolen re-claim wins nothing durable: the
// owner re-claims in one tap or revokes from the console.
function claimable(lic, machine) {
  if (!lic || lic.machine !== machine) return false;
  return lic.status === "open" || lic.status === "active" || lic.status === "issued";
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
