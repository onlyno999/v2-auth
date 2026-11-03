import { getGuest, guestProblem, vaultOpen, logEvent, noteGuestFetch } from "../lib/core.js";
import { serveSubscription } from "../api/subscription.js";

// GET /s/<sealed-token>
// A guest's personal subscription link, pasted into Shadowrocket or
// any other third-party client as a subscription URL. The token is an
// opaque AES-GCM sealed guest reference, minted when the admin
// created the guest; the real subscription URL never leaves the
// server. Every fetch re-reads the guest record, so the moment the
// admin disables or deletes the guest — or his time runs out — this
// link stops serving subscription data; re-enabling revives it.
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
  if (!payload || !payload.g) return deny("bad_link", 404);

  const rec = await getGuest(env, payload.g);
  if (!rec) return deny("not_found", 404);
  const problem = guestProblem(rec);
  if (problem) {
    await logEvent(env, "guest_sub_deny", rec.username || "", problem);
    return deny(problem);
  }

  // Fetch watching: note where this fetch came from (Cloudflare IP
  // geolocation). More than 5 distinct provinces in 7 days means
  // the link is being shared — the guest is disabled on the spot
  // and this fetch is denied too. TEST_REGION_HEADER exists only
  // in local dev vars (never set in production) so the region rule
  // can be exercised end-to-end with an x-test-region header.
  const cf = request.cf || {};
  let region = "";
  if (env.TEST_REGION_HEADER) region = request.headers.get("x-test-region") || "";
  if (!region) region = cf.region || "";
  if (!region && cf.country) region = cf.country;
  const verdict = await noteGuestFetch(env, payload.g, rec, {
    ip: request.headers.get("cf-connecting-ip") || "",
    ua: (request.headers.get("user-agent") || "").slice(0, 120),
    region,
  });
  if (verdict.disabled) return deny("disabled");

  const content = await serveSubscription(env, rec.channel === "dist" ? "dist" : "main");
  if (!content) return deny("sub_unavailable", 502);
  return new Response(content, {
    status: 200,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
  });
}
