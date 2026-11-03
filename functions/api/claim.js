import { json, readJson, getLicByKey, logEvent, normalizeMachineCode } from "../lib/core.js";
import { finishActivation } from "./activate.js";

// POST {machineCode, pubkey, platform, attestation?}
// Direct-open flow: admin pre-opened this machine in the console; the
// user taps "I have paid" and claims the device token.
export async function onRequestPost({ request, env }) {
  const body = await readJson(request);
  if (!body.machineCode) return json({ ok: false, reason: "bad_request" }, 400);
  const machine = normalizeMachineCode(body.machineCode) || body.machineCode;
  let lic = null;
  const licKey = await env.V2.get("open:" + machine);
  if (licKey) lic = await getLicByKey(env, licKey);
  if (!lic || lic.status !== "open") {
    // Fallback scan: the open: pointer is a second, separate KV write
    // in the issue request — if it is lost, the claim used to answer
    // no_open forever while the console kept listing the license as
    // awaiting claim (production incident, 2026-11-04: the seller had
    // opened the machine, the app kept saying "not opened"). The
    // license record is the source of truth: find an open one bound
    // to this machine and claim it.
    lic = null;
    let cursor;
    do {
      const page = await env.V2.list({ prefix: "lic:", limit: 200, cursor });
      cursor = page.list_complete ? undefined : page.cursor;
      for (const k of page.keys) {
        const cand = await getLicByKey(env, k.name);
        if (cand && cand.status === "open" && cand.machine === machine) { lic = cand; break; }
      }
    } while (cursor && !lic);
  }
  if (!lic) return json({ ok: false, reason: "no_open" }, 404);
  const res = await finishActivation(env, lic, body);
  if (res.status === 200) await env.V2.delete("open:" + machine);
  await logEvent(env, "claim", body.machineCode);
  return res;
}
