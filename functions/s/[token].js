import { getGuest, guestProblem, vaultOpen, logEvent, noteGuestFetch, beijingDay, nowSec } from "../lib/core.js";
import { serveSubscription } from "../api/subscription.js";

// ---------- poisoned subscription for expired guests ----------
// Every server address in the subscription becomes one dead IP:
// raw IPv4s anywhere in the text, the authority host of every
// share URI (domains included — an IP-only pass would leave
// domain-addressed nodes alive), and the "add" field inside
// vmess payloads. Ports, credentials and names stay untouched so
// the file stays structurally valid and clients accept the update.
const FAKE_IP = "114.115.116.117";
const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;

function b64DecodeText(s) {
  const bin = atob(s.replace(/\s+/g, ""));
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}
function b64EncodeText(s) {
  const bytes = new TextEncoder().encode(s);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export function poisonSubscription(content) {
  let text = content;
  let wasB64 = false;
  try {
    const decoded = b64DecodeText(content.trim());
    if (decoded.includes("://")) {
      text = decoded;
      wasB64 = true;
    }
  } catch {
    // Not base64: transform the content as-is.
  }
  const lines = text.split(/\r?\n/).map((line) => {
    const vm = line.match(/^vmess:\/\/(.+)$/);
    if (vm) {
      try {
        let inner = b64DecodeText(vm[1]);
        inner = inner.replace(/"add"\s*:\s*"[^"]*"/, `"add": "${FAKE_IP}"`);
        inner = inner.replace(IPV4_RE, FAKE_IP);
        return "vmess://" + b64EncodeText(inner);
      } catch {
        return line.replace(IPV4_RE, FAKE_IP);
      }
    }
    return line
      .replace(/^([a-z0-9+.-]+:\/\/[^/@]*@)([^/:?#]+)/i, `$1${FAKE_IP}`)
      .replace(IPV4_RE, FAKE_IP);
  });
  const out = lines.join("\n");
  return wasB64 ? b64EncodeText(out) : out;
}

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
  if (problem === "expired" && rec.expires_at && beijingDay(nowSec()) === beijingDay(rec.expires_at)) {
    // Two-stage expiry (owner's design, 2026-11-04): ON the expiry
    // day an expired guest gets a poisoned subscription instead of
    // an error — a bare 403 leaves the client's cached nodes
    // working, but a well-formed update whose every server address
    // is a dead IP makes the client overwrite its config with junk
    // on the next refresh. From the next day on, the generic hard
    // cut below applies and the link serves nothing at all.
    // Served on the fly from the live record — renew the guest and
    // the real content is back on the very next fetch. If the real
    // subscription cannot be fetched, fall back to the hard cut.
    const content = await serveSubscription(env, rec.channel === "dist" ? "dist" : "main");
    if (content) {
      await logEvent(env, "guest_sub_poison", rec.username || "", "expired");
      return new Response(poisonSubscription(content), {
        status: 200,
        headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
      });
    }
    return deny("expired");
  }
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
  if (verdict.dailyBlocked) return deny("daily_limit", 429);
  if (verdict.disabled) return deny("disabled");

  const content = await serveSubscription(env, rec.channel === "dist" ? "dist" : "main");
  if (!content) return deny("sub_unavailable", 502);
  return new Response(content, {
    status: 200,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
  });
}
