import { json, readJson, getLicByKey, logEvent } from "../lib/core.js";
import { finishActivation } from "./activate.js";

// POST {machineCode, pubkey, platform, attestation?}
// Direct-open flow: admin pre-opened this machine in the console; the
// user taps "I have paid" and claims the device token.
export async function onRequestPost({ request, env }) {
  const body = await readJson(request);
  if (!body.machineCode) return json({ ok: false, reason: "bad_request" }, 400);
  const licKey = await env.KV.get("open:" + body.machineCode);
  if (!licKey) return json({ ok: false, reason: "no_open" }, 404);
  const lic = await getLicByKey(env, licKey);
  if (!lic || lic.status !== "open") return json({ ok: false, reason: "no_open" }, 404);
  const res = await finishActivation(env, lic, body);
  if (res.status === 200) await env.KV.delete("open:" + body.machineCode);
  await logEvent(env, "claim", body.machineCode);
  return res;
}
