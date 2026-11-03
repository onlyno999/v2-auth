import { getLicByKey, licProblem, vaultOpen, logEvent } from "../lib/core.js";
import { serveSubscription } from "../api/subscription.js";

// GET /s/<sealed-token>
// The personal subscription link handed out by /api/guest/link (and
// pasted into Shadowrocket or any other client as a subscription URL).
// The token is an opaque AES-GCM sealed license reference; every fetch
// re-checks the license, so revoking, deleting or expiring the license
// in the console kills the link immediately. Serves exactly the same
// content as the app channel, via the same lazy KV cache.
export async function onRequestGet({ request, env, params }) {
  const deny = (reason, status = 403) =>
    new Response(JSON.stringify({ ok: false, reason }), {
      status,
      headers: { "content-type": "application/json", "cache-control": "no-store" },
    });

  let payload = null;
  try {
    payload = JSON.parse((await vaultOpen(env, params.token)) || "null");
  } catch {
    payload = null;
  }
  if (!payload || !payload.k) return deny("bad_link", 404);

  const lic = await getLicByKey(env, payload.k);
  if (!lic) return deny("not_found", 404);
  const problem = licProblem(lic, lic.machine);
  if (problem) {
    await logEvent(env, "guest_sub_deny", lic.machine || "", problem);
    return deny(problem);
  }
  if (lic.status !== "active") return deny("not_active");

  const content = await serveSubscription(env, lic.channel === "dist" ? "dist" : "main");
  if (!content) return deny("sub_unavailable", 502);
  return new Response(content, {
    status: 200,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
  });
}
