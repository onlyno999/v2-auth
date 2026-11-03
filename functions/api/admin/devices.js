import { json, isAdmin, vaultOpen, durationSeconds, fmtDuration } from "../../lib/core.js";

// Fetch every key under a prefix (paged).
async function listKeys(env, prefix) {
  const keys = [];
  let cursor;
  do {
    const page = await env.V2.list({ prefix, limit: 200, cursor });
    cursor = page.list_complete ? undefined : page.cursor;
    keys.push(...page.keys.map((k) => k.name));
  } while (cursor);
  return keys;
}
// Fetch many keys' values in parallel (KV gets are independent).
async function getMany(env, keys) {
  const vals = await Promise.all(keys.map((k) => env.V2.get(k)));
  return new Map(keys.map((k, i) => [k, vals[i]]));
}

// GET -> device table for the admin console. All KV reads are parallel:
// on a slow client connection the response must complete fast, or the
// phone gives up and shows 加载失败.
export async function onRequestGet({ request, env }) {
  if (!(await isAdmin(env, request))) return json({ ok: false, reason: "unauthorized" }, 401);

  const [devKeys, openKeys, licKeys] = await Promise.all([
    listKeys(env, "dev:"), listKeys(env, "open:"), listKeys(env, "lic:"),
  ]);
  const [devVals, licVals, lastVals] = await Promise.all([
    getMany(env, devKeys),
    getMany(env, licKeys),
    getMany(env, devKeys.map((k) => "last:" + k.slice(4))),
  ]);
  const licByKey = new Map(licKeys.map((k) => [k, JSON.parse(licVals.get(k) || "{}")]));
  const failKeys = await listKeys(env, "attestfail:");
  const failVals = await getMany(env, failKeys);
  const failByMachine = new Map(failKeys.map((k) => [k.slice(11), JSON.parse(failVals.get(k) || "null")]));

  const out = devKeys.map((k) => {
    const machine = k.slice(4);
    const dev = JSON.parse(devVals.get(k) || "{}");
    const lic = dev.lic ? licByKey.get(dev.lic) : null;
    const last = lastVals.get("last:" + machine);
    return {
      machine,
      platform: dev.platform || "",
      first_seen: dev.first_seen || null,
      last_seen: dev.last_seen || null,
      pulls: dev.pulls || 0,
      integrity: dev.integrity || null,
      lic: lic
        ? {
            status: lic.status, days: lic.days, note: lic.note || "",
            duration_sec: lic.duration_sec ?? null,
            duration_text: fmtDuration(durationSeconds(lic)),
            channel: lic.channel || "main", dist: lic.dist || null,
            created_at: lic.created_at, activated_at: lic.activated_at,
            expires_at: lic.expires_at,
          }
        : null,
      last_event: last ? JSON.parse(last) : null,
    };
  });

  const issuedRaw = [];
  for (const [k, lic] of licByKey) {
    if (lic.status === "issued" || lic.status === "open") {
      issuedRaw.push({
        licKey: k,
        machine: lic.machine, note: lic.note || "", days: lic.days,
        duration_sec: lic.duration_sec ?? null,
        duration_text: fmtDuration(durationSeconds(lic)),
        channel: lic.channel || "main", dist: lic.dist || null,
        status: lic.status, created_at: lic.created_at,
        code_enc: lic.code_enc || null,
        // The refusal note is kept per machine; only show it on a
        // license that already existed when the refusal happened —
        // a freshly issued license must not inherit an old stamp.
        attest_fail: (() => {
          const f = failByMachine.get(lic.machine);
          return f && f.at >= (lic.created_at || 0) ? f : null;
        })(),
      });
    }
  }
  // Unseal the re-copyable codes (only those issued after the vault
  // existed carry one; older codes stay hash-only and unrecoverable).
  const issued = await Promise.all(issuedRaw.map(async (i) => ({
    ...i,
    code_enc: undefined,
    code: i.code_enc ? await vaultOpen(env, i.code_enc) : null,
  })));
  issued.sort((a, b) => (b.created_at || 0) - (a.created_at || 0));
  return json({
    ok: true,
    devices: out,
    pending_open: openKeys.map((k) => k.slice(5)),
    issued,
  });
}
