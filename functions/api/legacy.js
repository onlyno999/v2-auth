import {
  json, readJson, nowSec, codeKey, getLicByKey, logEvent, bumpDataVersion,
} from "../lib/core.js";
import { finishActivation } from "./activate.js";

// Legacy offline-code conversion. The pre-online app activated with
// ECDSA-signed offline codes (format v3: 63-byte payload + 64-byte raw
// signature, Crockford-base32). On first open of the online build the
// client presents its stored legacy code here; the server verifies it
// against the legacy PUBLIC key (verification only — issuing stays
// offline in the owner's keygen tools), checks the machine binding and
// expiry, and converts it into an online license with the same expiry.
// LEGACY_PUB_B64 (SPKI, base64) may override the bundled public key.
const LEGACY_PUB_B64_DEFAULT =
  "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8lZ3ZIHPgIaims2SRAsiWL5XDnVa68rVNlcDvtejAoA1Td/x9ZyXHcxZTXrYnYUzFAn5HEPLIU6fYFS7V3fW3w==";

const B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
function b32Decode(text) {
  const norm = String(text || "")
    .toUpperCase()
    .replace(/[-\s]/g, "")
    .replace(/O/g, "0")
    .replace(/[IL]/g, "1");
  const out = [];
  let buffer = 0;
  let bits = 0;
  for (const c of norm) {
    const v = B32.indexOf(c);
    if (v < 0) throw new Error("bad char");
    buffer = (buffer << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}

function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// POST {machineCode, code, pubkey, platform} -> {ok, token, expires_at}
export async function onRequestPost({ request, env }) {
  const body = await readJson(request);
  const ip = request.headers.get("cf-connecting-ip") || "local";
  const bucket = `rl:${ip}:${Math.floor(nowSec() / 3600)}`;
  const tries = parseInt((await env.V2.get(bucket)) || "0", 10);
  if (tries > 20) return json({ ok: false, reason: "rate_limited" }, 429);
  await env.V2.put(bucket, String(tries + 1), { expirationTtl: 3700 });

  if (!body.machineCode || !body.code) {
    return json({ ok: false, reason: "bad_request" }, 400);
  }

  let blob;
  let machineHash;
  try {
    blob = b32Decode(body.code);
    machineHash = b32Decode(body.machineCode);
  } catch {
    return json({ ok: false, reason: "bad_code" }, 403);
  }
  if (blob.length !== 127 || blob[0] !== 0x03 || machineHash.length !== 10) {
    return json({ ok: false, reason: "bad_code" }, 403);
  }
  const payload = blob.slice(0, 63);
  const sig = blob.slice(63, 127);

  let verified = false;
  try {
    const key = await crypto.subtle.importKey(
      "spki",
      b64ToBytes(env.LEGACY_PUB_B64 || LEGACY_PUB_B64_DEFAULT),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    verified = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" }, key, sig, payload,
    );
  } catch {
    verified = false;
  }
  if (!verified) {
    await logEvent(env, "legacy_fail", body.machineCode, "bad_signature");
    return json({ ok: false, reason: "bad_signature" }, 403);
  }

  const codeMachine = payload.slice(5, 15);
  if (!codeMachine.every((b, i) => b === machineHash[i])) {
    await logEvent(env, "legacy_fail", body.machineCode, "bound_other");
    return json({ ok: false, reason: "bound_other" }, 403);
  }

  const expiryMinutes =
    ((payload[1] << 24) | (payload[2] << 16) | (payload[3] << 8) | payload[4]) >>> 0;
  const expiresAt = expiryMinutes === 0 ? null : expiryMinutes * 60;
  if (expiresAt !== null && nowSec() > expiresAt) {
    await logEvent(env, "legacy_fail", body.machineCode, "expired");
    return json({ ok: false, reason: "expired" }, 403);
  }

  // Convert: one online license per legacy code, expiry preserved.
  const key = await codeKey(body.code);
  let lic = await getLicByKey(env, key);
  if (!lic) {
    lic = {
      key,
      days: 0,
      status: "issued",
      machine: body.machineCode,
      note: "老码转入",
      channel: "main",
      created_at: nowSec(),
      activated_at: null,
      expires_at: expiresAt,
    };
    await env.V2.put(key, JSON.stringify(lic));
    await bumpDataVersion(env);
  }
  await logEvent(env, "legacy_convert", body.machineCode);
  return finishActivation(env, lic, body);
}
