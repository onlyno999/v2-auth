import { json, readJson, b64urlEncode } from "../lib/core.js";

// POST {machineCode} -> {challenge}  (for Key Attestation at activation)
export async function onRequestPost({ request, env }) {
  const body = await readJson(request);
  if (!body.machineCode) return json({ ok: false, reason: "no_machine" }, 400);
  const rnd = new Uint8Array(32);
  crypto.getRandomValues(rnd);
  const challenge = b64urlEncode(rnd);
  await env.V2.put("chal:" + body.machineCode, challenge, { expirationTtl: 300 });
  return json({ ok: true, challenge });
}
