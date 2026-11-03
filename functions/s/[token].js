import { getGuest, guestProblem, vaultOpen, logEvent } from "../lib/core.js";
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

  const content = await serveSubscription(env, "main");
  if (!content) return deny("sub_unavailable", 502);
  return new Response(content, {
    status: 200,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
  });
}
