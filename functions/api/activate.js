import {
  json, readJson, nowSec, sha256hex,
  getLicByCode, getDev, putLic, putDev, licProblem, logEvent, newToken, durationSeconds,
} from "../lib/core.js";

// Shared activation tail: license is valid -> create device + token.
export async function finishActivation(env, lic, body) {
  const machineCode = body.machineCode;

  // Build binding (owner's design, 2026-11-04, replacing Key
  // Attestation chain verification): the client reports the SHA-256
  // of its own signing certificate. The FIRST activation of a
  // machine stores digest + machine code in KV; every later
  // activation must present the same digest — a repackaged build is
  // signed with another key and is refused. The per-machine random
  // credential is the device token issued below; ordinary opens only
  // validate that token and never re-check the build.
  // (Chain verification was retired after its home-grown verifier
  // rejected the owner's genuine 2.0 build with attest_chain_sig:
  // reproduced locally with synthetic chains — the ECDSA scalar size
  // was tied to the hash instead of the issuer curve, and the
  // attestation OID constant had the wrong length byte, so no real
  // chain could ever pass.)
  const signer = typeof body.signer === "string" && body.signer ? body.signer.toLowerCase() : null;
  const dev = await getDev(env, machineCode);
  if (dev && dev.signer && signer !== dev.signer) {
    await logEvent(env, "activate_fail", machineCode, "signer_mismatch");
    await env.V2.put("attestfail:" + machineCode,
      JSON.stringify({ reason: "signer_mismatch", at: nowSec() }), { expirationTtl: 7 * 86400 });
    return json({ ok: false, reason: "signer_mismatch" }, 403);
  }

  const token = newToken();
  const activatedAt = lic.activated_at || nowSec();
  const durSec = durationSeconds(lic);
  const expiresAt = lic.expires_at ?? (durSec ? activatedAt + durSec : null);
  const newLic = { ...lic, status: "active", activated_at: activatedAt, expires_at: expiresAt };
  await putLic(env, newLic);
  await putDev(env, machineCode, {
    lic: lic.key,
    token_hash: await sha256hex(token),
    pubkey: body.pubkey || "",
    platform: body.platform || "",
    signer: signer || (dev && dev.signer) || null,
    first_seen: nowSec(),
    last_seen: nowSec(),
    pulls: 0,
    integrity: null,
  });
  await env.V2.delete("attestfail:" + machineCode);
  await logEvent(env, "activate", machineCode);
  return json({ ok: true, token, expires_at: expiresAt });
}

// POST {machineCode, code, pubkey, platform, attestation?}
export async function onRequestPost({ request, env }) {
  const body = await readJson(request);
  const ip = request.headers.get("cf-connecting-ip") || "local";
  const bucket = `rl:${ip}:${Math.floor(nowSec() / 3600)}`;
  const tries = parseInt((await env.V2.get(bucket)) || "0", 10);
  if (tries > 20) return json({ ok: false, reason: "rate_limited" }, 429);
  await env.V2.put(bucket, String(tries + 1), { expirationTtl: 3700 });

  if (!body.machineCode || !body.code) return json({ ok: false, reason: "bad_request" }, 400);
  const lic = await getLicByCode(env, body.code);
  const problem = licProblem(lic, body.machineCode);
  if (problem) {
    await logEvent(env, "activate_fail", body.machineCode, problem);
    return json({ ok: false, reason: problem }, 403);
  }
  if (lic.status !== "issued" && lic.status !== "active") {
    return json({ ok: false, reason: "not_issued" }, 403);
  }
  return finishActivation(env, lic, body);
}
