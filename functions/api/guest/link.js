import {
  json, readJson, nowSec, getLicByCode, putLic, putDev, licProblem, logEvent, vaultSeal,
} from "../../lib/core.js";

// POST {code} -> {ok, link, expires_at}
// Guest self-service for customers on third-party clients (Shadowrocket
// & friends): the customer enters the activation code the seller gave
// him and receives a personal subscription link. The link carries only
// an AES-GCM sealed license reference (see the code vault in core.js);
// the real subscription URL never leaves the server, and the link dies
// the moment the license is revoked, deleted or expired, because /s/
// re-checks the license on every fetch.
//
// First use activates the license (its validity window starts then),
// mirroring app activation but without a device record.
export async function onRequestPost({ request, env }) {
  const body = await readJson(request);
  const ip = request.headers.get("cf-connecting-ip") || "local";
  const bucket = `rl:${ip}:${Math.floor(nowSec() / 3600)}`;
  const tries = parseInt((await env.V2.get(bucket)) || "0", 10);
  if (tries > 20) return json({ ok: false, reason: "rate_limited" }, 429);
  await env.V2.put(bucket, String(tries + 1), { expirationTtl: 3700 });

  if (!body.code) return json({ ok: false, reason: "bad_request" }, 400);
  const lic = await getLicByCode(env, body.code);
  if (!lic) return json({ ok: false, reason: "not_found" }, 404);
  const problem = licProblem(lic, lic.machine);
  if (problem) {
    await logEvent(env, "guest_link_fail", lic.machine || "", problem);
    return json({ ok: false, reason: problem }, 403);
  }
  if (lic.status !== "issued" && lic.status !== "open" && lic.status !== "active") {
    return json({ ok: false, reason: "not_issued" }, 403);
  }

  let current = lic;
  if (lic.status !== "active") {
    const activatedAt = nowSec();
    current = {
      ...lic,
      status: "active",
      activated_at: activatedAt,
      expires_at: lic.expires_at ?? (lic.days ? activatedAt + lic.days * 86400 : null),
    };
    await putLic(env, current);
    if (lic.machine) {
      await env.V2.delete("open:" + lic.machine);
      // Register a link-device so the customer appears in the admin
      // device table and the usual actions (revoke / extend / delete)
      // work on him. No token or pubkey: app-side auth stays closed.
      await putDev(env, lic.machine, {
        lic: lic.key,
        token_hash: "",
        pubkey: "",
        platform: "订阅链接",
        first_seen: activatedAt,
        last_seen: activatedAt,
        pulls: 0,
        integrity: null,
        guest: true,
      });
    }
    await logEvent(env, "guest_activate", lic.machine || "");
  }

  const sealed = await vaultSeal(env, JSON.stringify({ k: lic.key }));
  if (!sealed) return json({ ok: false, reason: "vault_unavailable" }, 500);
  const origin = new URL(request.url).origin;
  await logEvent(env, "guest_link", lic.machine || "");
  return json({ ok: true, link: `${origin}/s/${sealed}`, expires_at: current.expires_at ?? null });
}
