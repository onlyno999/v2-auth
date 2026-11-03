import {
  json, readJson, nowSec, sha256hex, b64Decode,
  getLicByCode, putLic, putDev, licProblem, logEvent, newToken, durationSeconds,
} from "../lib/core.js";
import { verifyAttestation } from "../lib/attest.js";

// Shared activation tail: license is valid -> create device + token.
export async function finishActivation(env, lic, body) {
  const machineCode = body.machineCode;

  // Optional/required attestation of the genuine app build.
  let integrity = null;
  if (body.attestation || env.ATTEST_REQUIRED === "1") {
    if (!body.attestation) return json({ ok: false, reason: "attest_missing" }, 403);
    const chal = await env.V2.get("chal:" + machineCode);
    if (!chal) return json({ ok: false, reason: "attest_no_challenge" }, 403);
    const verdict = await verifyAttestation(body.attestation.map((c) => b64Decode(c)), {
      challenge: b64Decode(chal),
      packageName: env.EXPECTED_PACKAGE || "com.v2ray.ang.fdroid",
      // The genuine client builds are signed with the owner's personal
      // certificate; its SHA-256 is public (printed on every APK), so
      // it is safe as a built-in default. A repackaged build is signed
      // with a different key and fails this check. Env can override.
      certSha256Hex: env.EXPECTED_CERT_SHA256 || "221f4dd0cfef8b76785ffc82ada95b23961553927aadbcc920395fdbd119758a",
      rootPinHex: env.ATTEST_ROOT_SHA256 || null,
    });
    if (!verdict.ok) {
      await logEvent(env, "attest_fail", machineCode, verdict.reason);
      return json({ ok: false, reason: verdict.reason }, 403);
    }
    integrity = { boot: verdict.boot, root: verdict.rootHex, level: verdict.securityLevel };
    await env.V2.delete("chal:" + machineCode);
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
    first_seen: nowSec(),
    last_seen: nowSec(),
    pulls: 0,
    integrity,
  });
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
