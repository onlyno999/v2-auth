// Shared helpers for the v2-auth Pages Functions.
// KV layout (see PLAN.md):
//   lic:<sha256hex(code)>  -> license record JSON
//   dev:<machineCode>      -> device record JSON
//   open:<machineCode>     -> pending direct-open license code hash
//   sub:content, sub:fetched_at -> subscription payload + fetch time
//   rl:<ip>:<hour>         -> activate rate-limit counter

export const json = (obj, status = 200, extraHeaders = {}) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...extraHeaders },
  });

export const nowSec = () => Math.floor(Date.now() / 1000);

// ---------- table-payload cache ----------
// The console table builders scan whole key prefixes; on KV that
// burned the 1,000/day list() quota in one evening. Built payloads
// are cached per isolate for a few seconds. The cache version is
// a row in the store itself ("meta:dataver"), NOT isolate memory:
// production runs many isolates, and an in-memory version once
// made a console edit look like it "didn't take" — the write had
// landed, but another isolate kept serving its stale table for up
// to the TTL. Every record mutation funnels through the put*
// helpers (or an explicit bump at the handler), each bump rewrites
// the version row, and a cache hit requires a version match — so
// an edit is visible on the very next load, on any isolate. The
// version check costs one row read per table load.
const _payloadCache = new Map();
export async function bumpDataVersion(env) {
  try {
    await env.V2.put("meta:dataver", `${Date.now()}:${Math.random().toString(36).slice(2)}`);
  } catch {
    // A failed bump only means tables may serve the TTL-stale copy.
  }
}
export async function cachedPayload(env, key, ttlMs, builder) {
  let ver = null;
  try {
    ver = await env.V2.get("meta:dataver");
  } catch {
    // Version unreadable: fall through and rebuild.
  }
  const hit = _payloadCache.get(key);
  if (hit && hit.v === ver && Date.now() - hit.at < ttlMs) return hit.val;
  const val = await builder();
  _payloadCache.set(key, { v: ver, at: Date.now(), val });
  return val;
}

const enc = new TextEncoder();

export async function sha256hex(text) {
  const buf = await crypto.subtle.digest("SHA-256", enc.encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function b64urlEncode(bytes) {
  let s = btoa(String.fromCharCode(...new Uint8Array(bytes)));
  return s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64Decode(b64) {
  const bin = atob(b64.replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"; // no 0/O/1/I/L
export function newLicenseCode() {
  const rnd = new Uint8Array(20);
  crypto.getRandomValues(rnd);
  const chars = [...rnd].map((b) => CODE_ALPHABET[b % CODE_ALPHABET.length]).join("");
  return `V2O-${chars.slice(0, 5)}-${chars.slice(5, 10)}-${chars.slice(10, 15)}-${chars.slice(15, 20)}`;
}
export const normalizeCode = (code) => (code || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
export const codeKey = async (code) => "lic:" + (await sha256hex(normalizeCode(code)));

export function newToken() {
  const rnd = new Uint8Array(32);
  crypto.getRandomValues(rnd);
  return b64urlEncode(rnd);
}

// ---------- machine codes ----------
// App machine codes are 16 Crockford-Base32 chars grouped 4-4-4-4
// (alphabet excludes I, L, O, U). Normalize by trimming, uppercasing
// and dropping spaces/dashes, then require exactly 16 alphabet chars
// and re-group canonically. This specifically rejects activation
// codes (V2O-… is 23 chars and contains O) pasted into the machine
// field — the mix-up that silently parked a direct-open under a code
// name, where no real machine could ever claim it.
export const MACHINE_RE = /^[0-9A-HJKMNP-TV-Z]{16}$/;
export function normalizeMachineCode(raw) {
  const s = String(raw || "").toUpperCase().replace(/[\s-]/g, "");
  if (!MACHINE_RE.test(s)) return null;
  return s.match(/.{4}/g).join("-");
}
export const isMachineCode = (raw) => normalizeMachineCode(raw) !== null;

// ---------- code vault ----------
// Newly issued codes also keep an AES-GCM sealed copy (key derived
// from SESSION_SECRET) so the seller can re-copy a code he handed out
// from the admin console. Lookup-by-code still uses only the SHA-256
// hash; if SESSION_SECRET ever rotates, old sealed copies simply stop
// decrypting and the copy button hides.
async function vaultKey(env) {
  const raw = await crypto.subtle.digest("SHA-256", enc.encode((env.SESSION_SECRET || "") + "|v2-code-vault"));
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}
export async function vaultSeal(env, text) {
  if (!env.SESSION_SECRET) return null;
  try {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await vaultKey(env), enc.encode(text));
    const buf = new Uint8Array(12 + ct.byteLength);
    buf.set(iv);
    buf.set(new Uint8Array(ct), 12);
    return b64urlEncode(buf);
  } catch {
    return null;
  }
}
export async function vaultOpen(env, sealed) {
  if (!env.SESSION_SECRET || !sealed) return null;
  try {
    const buf = b64Decode(sealed);
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: buf.slice(0, 12) }, await vaultKey(env), buf.slice(12),
    );
    return new TextDecoder().decode(pt);
  } catch {
    return null;
  }
}

// ---------- KV record access ----------
export async function getLicByCode(env, code) {
  const raw = await env.V2.get(await codeKey(code));
  return raw ? { key: await codeKey(code), ...JSON.parse(raw) } : null;
}
export async function putLic(env, lic) {
  await bumpDataVersion(env);
  await env.V2.put(lic.key, JSON.stringify(lic.rec ?? lic));
}
export async function getLicByKey(env, key) {
  const raw = await env.V2.get(key);
  return raw ? { key, ...JSON.parse(raw) } : null;
}
export async function getDev(env, machineCode) {
  const raw = await env.V2.get("dev:" + machineCode);
  return raw ? JSON.parse(raw) : null;
}
export async function putDev(env, machineCode, dev) {
  await bumpDataVersion(env);
  await env.V2.put("dev:" + machineCode, JSON.stringify(dev));
}
export async function logEvent(env, kind, machineCode = "", detail = "") {
  // Best-effort, low volume: one small key per day-bucket counter plus a
  // rolling "last events" list is overkill for v1; keep a per-day counter.
  const day = new Date().toISOString().slice(0, 10);
  const k = `stat:${day}:${kind}`;
  const cur = parseInt((await env.V2.get(k)) || "0", 10);
  await env.V2.put(k, String(cur + 1), { expirationTtl: 60 * 60 * 24 * 40 });
  if (machineCode) {
    await env.V2.put(`last:${machineCode}`, JSON.stringify({ kind, detail, ts: nowSec() }), {
      expirationTtl: 60 * 60 * 24 * 30,
    });
  }
}

// ---------- license state ----------
export function licProblem(lic, machineCode) {
  if (!lic) return "not_found";
  if (lic.status === "revoked") return "revoked";
  if (lic.machine && lic.machine !== machineCode) return "bound_other";
  if (lic.expires_at && nowSec() > lic.expires_at) return "expired";
  return null;
}

// ---------- durations ----------
// Records carry `days` (legacy whole-day field) plus, for sub-day
// durations, `duration_sec` (exact seconds). Effective length:
// duration_sec wins when present, else days*86400, else 0 = permanent.
// Expiry is always computed in seconds, so a 5-minute license really
// lives 300 seconds.
// The duration a record effectively spans, for DISPLAY: once an
// expiry exists, the span from its start (activation for licenses,
// creation for guests) to that expiry is the truth — so editing
// the expiry （修改时间） or extending immediately shows in the
// consoles' 时长 column instead of the stale originally-granted
// length (owner caught exactly that on a guest row, 2026-11-04).
// Falls back to the granted duration before any expiry is set
// (issued-not-activated licenses, permanent records).
export function spanDurationSeconds(rec) {
  const start = rec.activated_at || rec.created_at;
  if (rec.expires_at && start) return Math.max(0, rec.expires_at - start);
  return durationSeconds(rec);
}
export function durationSeconds(rec) {
  if (rec && Number.isFinite(rec.duration_sec) && rec.duration_sec > 0) {
    return Math.floor(rec.duration_sec);
  }
  if (rec && Number.isFinite(rec.days) && rec.days > 0) return Math.floor(rec.days) * 86400;
  return 0;
}
export const DURATION_UNITS = { minute: 60, hour: 3600, day: 86400 };
// Parse a duration from a request body. Preferred shape:
// {durationValue, durationUnit: "minute"|"hour"|"day"} (minimum 60s).
// Legacy fallback: {days: n} whole days (0 = permanent).
// Returns seconds (>= 0), null = invalid, undefined = not provided.
export function parseDurationSec(body) {
  if (body.durationValue !== undefined || body.durationUnit !== undefined) {
    const mult = DURATION_UNITS[body.durationUnit];
    const v = Number(body.durationValue);
    if (!mult || !Number.isFinite(v) || v <= 0) return null;
    const sec = Math.floor(v) * mult;
    if (sec < 60 || sec > 3650 * 86400) return null;
    return sec;
  }
  if (body.days !== undefined) {
    const d = Number(body.days);
    if (!Number.isFinite(d) || d < 0 || Math.floor(d) !== d || d > 3650) return null;
    return d * 86400;
  }
  return undefined;
}
// Signed delta version for "extend" calls: same shapes, but negative
// values are allowed (used to shorten / force-expire in tests).
// Returns delta seconds, null = invalid, 0 = nothing to add.
export function parseDeltaSec(body) {
  if (body.durationValue !== undefined || body.durationUnit !== undefined) {
    const mult = DURATION_UNITS[body.durationUnit];
    const v = Number(body.durationValue);
    if (!mult || !Number.isFinite(v) || v === 0) return null;
    return Math.floor(v) * mult;
  }
  const d = Math.floor(body.days || 0);
  return d * 86400;
}
// Human label for a duration in seconds — never rounds 5 minutes
// down to "0 天".
export function fmtDuration(sec) {
  if (!sec || sec <= 0) return "永久";
  if (sec < 3600) return `${Math.round(sec / 60)}分钟`;
  if (sec < 86400) return Number.isInteger(sec / 3600) ? `${sec / 3600}小时` : `${Math.round(sec / 60)}分钟`;
  if (sec % 86400 === 0) return `${sec / 86400}天`;
  const d = Math.floor(sec / 86400);
  const h = Math.round((sec % 86400) / 3600);
  return h ? `${d}天${h}小时` : `${d}天`;
}

// ---------- request signature (device key, ES256) ----------
// Canonical string signed by the device private key (Android Keystore):
//   `${machineCode}|${ts}|${nonce}|${path}`
export async function verifyDeviceSig(env, machineCode, body, path) {
  const dev = await getDev(env, machineCode);
  if (!dev || !dev.pubkey) return { ok: false, reason: "no_device" };
  const { ts, nonce, sig } = body || {};
  if (!ts || !nonce || !sig) return { ok: false, reason: "bad_sig" };
  if (Math.abs(nowSec() - Number(ts)) > 300) return { ok: false, reason: "stale" };
  try {
    const key = await crypto.subtle.importKey(
      "spki", b64Decode(dev.pubkey), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]
    );
    const ok = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" }, key,
      b64Decode(sig), enc.encode(`${machineCode}|${ts}|${nonce}|${path}`)
    );
    return ok ? { ok: true, dev } : { ok: false, reason: "bad_sig" };
  } catch {
    return { ok: false, reason: "bad_sig" };
  }
}

// Bearer-token fallback (used right after activation / if key is lost the
// admin unbinds and the user re-activates; token alone never pulls a sub
// more than validate allows — same checks apply).
export async function checkToken(env, machineCode, token) {
  const dev = await getDev(env, machineCode);
  if (!dev || !token) return { ok: false, reason: "no_device" };
  const h = await sha256hex(token);
  return h === dev.token_hash ? { ok: true, dev } : { ok: false, reason: "bad_token" };
}

// Full gate used by validate + subscription.
export async function gate(env, machineCode, body, path) {
  if (!machineCode) return { ok: false, reason: "no_machine", status: 400 };
  let auth;
  if (body && body.sig) auth = await verifyDeviceSig(env, machineCode, body, path);
  else if (body && body.token) auth = await checkToken(env, machineCode, body.token);
  else return { ok: false, reason: "no_auth", status: 401 };
  if (!auth.ok) return { ok: false, reason: auth.reason, status: 403 };
  const lic = await getLicByKey(env, auth.dev.lic);
  const problem = licProblem(lic, machineCode);
  if (problem) return { ok: false, reason: problem, status: 403, lic };
  return { ok: true, dev: auth.dev, lic };
}

// ---------- admin session ----------
// Login persistence is the user's own choice at the login form
// (2026-11-04): how many days the console login stays valid —
// default 1 day, maximum 7. Applies to the admin and distributor
// consoles; guest-page sessions are a separate thing, unchanged.
export function sessionDays(body) {
  const d = Math.floor(Number(body && body.days));
  if (!Number.isFinite(d)) return 1;
  return Math.min(7, Math.max(1, d));
}
export async function sessionCookie(env, req, days = 1) {
  const payload = b64urlEncode(enc.encode(JSON.stringify({ exp: nowSec() + days * 86400, admin: true })));
  const mac = await hmac(env.SESSION_SECRET, payload);
  return `${payload}.${mac}`;
}
export async function hmac(secret, text) {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(text));
  return b64urlEncode(sig);
}
export async function isAdmin(env, request) {
  const headerSecret = request.headers.get("x-admin-secret");
  if (headerSecret && env.ADMIN_SECRET && headerSecret === env.ADMIN_SECRET) return true;
  if (!env.SESSION_SECRET) return false;
  // Session token arrives either as the sess cookie or as an x-session
  // header (the console stores it in localStorage too: some networks /
  // browsers drop cookies, and a refresh must not demand the password
  // again while the token is still valid). Try EVERY presented token:
  // a stale cookie must not shadow a fresh header token — with
  // cookie-first precedence, one old cookie locked the owner out of
  // every console call (401s) even right after a password login,
  // because the login page trusts the body token client-side while
  // these checks kept verifying the dead cookie.
  const cookie = request.headers.get("cookie") || "";
  const m = cookie.match(/sess=([^;]+)/);
  const tokens = [m && m[1], request.headers.get("x-session")].filter(Boolean);
  for (const token of tokens) {
    const [payload, mac] = token.split(".");
    if (!payload || !mac) continue;
    if ((await hmac(env.SESSION_SECRET, payload)) !== mac) continue;
    try {
      const data = JSON.parse(new TextDecoder().decode(b64Decode(payload)));
      if (data.admin === true && data.exp > nowSec()) return true;
    } catch {
      // try the next token
    }
  }
  return false;
}

export async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

// ---------- distributors ----------
// KV: dist:<slug> -> {name, pw_hash, quota, used, status, created_at}
// The distributor's login address is https://<domain>/<slug> (see
// functions/_middleware.js). Licenses they issue carry dist=<slug>
// and channel="dist" (they pull SUB_URL_DIST).
export async function getDist(env, slug) {
  const raw = await env.V2.get("dist:" + slug);
  return raw ? JSON.parse(raw) : null;
}
export async function putDist(env, slug, rec) {
  await bumpDataVersion(env);
  await env.V2.put("dist:" + slug, JSON.stringify(rec));
}

// Move a distributor to a new slug: the record (name, password,
// quota, usage, status, tree position) is copied to the new key,
// the old key dies, his licenses and guests are re-stamped, and
// his sub-distributors' parent pointers follow. Returns nothing;
// callers validate first (format, uniqueness, scope).
export async function moveDistributor(env, oldSlug, newSlug, rec) {
  await putDist(env, newSlug, { ...rec });
  await env.V2.delete("dist:" + oldSlug);
  for (const prefix of ["lic:", "gst:", "dist:"]) {
    let cursor;
    do {
      const page = await env.V2.list({ prefix, limit: 200, cursor });
      cursor = page.list_complete ? undefined : page.cursor;
      for (const k of page.keys) {
        if (prefix === "dist:" && k.name === "dist:" + newSlug) continue;
        const raw = await env.V2.get(k.name);
        if (!raw) continue;
        const item = JSON.parse(raw);
        if (prefix === "dist:") {
          if (item.parent === oldSlug) {
            item.parent = newSlug;
            await env.V2.put(k.name, JSON.stringify(item));
          }
        } else if (item.dist === oldSlug) {
          item.dist = newSlug;
          await env.V2.put(k.name, JSON.stringify(item));
        }
      }
    } while (cursor);
  }
}

// Direct sub-distributors of a slug (the ternary tree: each
// distributor may open at most 3, five levels deep).
export async function listDistChildren(env, slug) {
  const out = [];
  let cursor;
  do {
    const page = await env.V2.list({ prefix: "dist:", limit: 200, cursor });
    cursor = page.list_complete ? undefined : page.cursor;
    for (const k of page.keys) {
      const raw = await env.V2.get(k.name);
      if (!raw) continue;
      const rec = JSON.parse(raw);
      if (rec.parent === slug) out.push({ slug: k.name.slice(5), rec });
    }
  } while (cursor);
  return out;
}

// Deleting a distributor clears EVERYTHING he issued with him
// (owner's standing rule, restated 2026-11-04: 'once deleted, it
// must be cleared out'). The old code deleted only the dist
// record and left his licenses and guests alive as orphans —
// still validating, still pulling subscriptions, still listed
// under a dead channel, while the parent's card read empty:
// exactly the 'deleted but not synced' mess the owner kept
// hitting. Cascade: his licenses (any status) plus every per-
// machine trace (same set as the admin device hard delete),
// his guests, then the dist record itself. The stock ledger
// (stk:) is NOT touched: it is the accounting history of money
// that really moved, not a live reference. Callers keep the
// guards (disabled first, no children) — children are placed
// and removed one by one, never cascaded silently.
export async function deleteDistributorCascade(env, slug) {
  let licenses = 0, guests = 0;
  let cursor;
  do {
    const page = await env.V2.list({ prefix: "lic:", limit: 200, cursor });
    cursor = page.list_complete ? undefined : page.cursor;
    for (const k of page.keys) {
      const raw = await env.V2.get(k.name);
      if (!raw) continue;
      const rec = JSON.parse(raw);
      if (rec.dist !== slug) continue;
      if (rec.machine) {
        await env.V2.delete("dev:" + rec.machine);
        await env.V2.delete("open:" + rec.machine);
        await env.V2.delete("last:" + rec.machine);
        await env.V2.delete("chal:" + rec.machine);
        await env.V2.delete("attestfail:" + rec.machine);
      }
      await env.V2.delete(k.name);
      licenses++;
    }
  } while (cursor);
  cursor = undefined;
  do {
    const page = await env.V2.list({ prefix: "gst:", limit: 200, cursor });
    cursor = page.list_complete ? undefined : page.cursor;
    for (const k of page.keys) {
      const raw = await env.V2.get(k.name);
      if (!raw) continue;
      const rec = JSON.parse(raw);
      if (rec.dist !== slug) continue;
      await env.V2.delete(k.name);
      guests++;
    }
  } while (cursor);
  await env.V2.delete("dist:" + slug);
  return { licenses, guests };
}

// Quota is priced by DURATION (owner, 2026-11-04: the tree runs
// on margin — a year card may not cost the same shelf space as a
// month card). One unit of quota = one average month
// (365.25/12 days); any issue costs ceil(duration / month),
// minimum 1. A 365-day card costs exactly 12.
export const MONTH_SEC = 2629800;
// The console's base (level-1) price per month unit: one global
// setting the owner can change on the summary page
// (meta:unitprice); the code default applies until he saves one.
export async function consoleUnitPrice(env) {
  const raw = await env.V2.get("meta:unitprice");
  const n = raw ? Number(raw) : NaN;
  return Number.isFinite(n) && n > 0 ? n : 3;
}

export function quotaCostFor(durationSec) {
  return Math.max(1, Math.ceil(durationSec / MONTH_SEC));
}

// Restock ledger: every quota INCREASE granted to a distributor
// is a purchase from his parent (or from the admin console) —
// money settles offline, the system only keeps the book. Key
// stk:<ts>:<rand> sorts chronologically.
export async function recordStock(env, dist, from, delta) {
  if (!delta || delta <= 0) return;
  const key = "stk:" + nowSec() + ":" + Math.random().toString(36).slice(2, 8);
  await env.V2.put(key, JSON.stringify({ dist, from, delta, at: nowSec() }));
}
export async function listStock(env, limit = 300) {
  const out = [];
  let cursor;
  do {
    const page = await env.V2.list({ prefix: "stk:", limit: 200, cursor });
    cursor = page.list_complete ? undefined : page.cursor;
    for (const k of page.keys) {
      const raw = await env.V2.get(k.name);
      if (raw) out.push(JSON.parse(raw));
    }
  } while (cursor);
  return out.sort((a, b) => b.at - a.at).slice(0, limit);
}

export function distLevel(rec) {
  return rec && Number.isFinite(rec.level) ? rec.level : 1;
}
export const SLUG_RE = /^[a-z0-9][a-z0-9_-]{1,23}$/;
export const RESERVED_SLUGS = new Set(["api", "index", "dist", "admin", "assets", "guest", "s", "g", "tree", "subtree", "summary"]);

export async function distSessionCookie(env, slug, days = 1) {
  const payload = b64urlEncode(enc.encode(JSON.stringify({ exp: nowSec() + days * 86400, dist: slug })));
  const mac = await hmac(env.SESSION_SECRET, payload);
  return `${payload}.${mac}`;
}
export async function distSlugFromRequest(env, request) {
  if (!env.SESSION_SECRET) return null;
  // Try every presented token (cookie and header): a stale dsess
  // cookie must not shadow a fresh x-dsess header token — same
  // lockout bug as isAdmin.
  const cookie = request.headers.get("cookie") || "";
  const m = cookie.match(/dsess=([^;]+)/);
  const tokens = [m && m[1], request.headers.get("x-dsess")].filter(Boolean);
  for (const token of tokens) {
    const [payload, mac] = token.split(".");
    if (!payload || !mac) continue;
    if ((await hmac(env.SESSION_SECRET, payload)) !== mac) continue;
    try {
      const data = JSON.parse(new TextDecoder().decode(b64Decode(payload)));
      if (!data.dist || data.exp <= nowSec()) continue;
      const rec = await getDist(env, data.dist);
      if (!rec || rec.status !== "active") continue;
      return data.dist;
    } catch {
      // try the next token
    }
  }
  return null;
}

// ---------- guests ----------
// KV: gst:<id> -> {username, pw_hash, note, days, status, created_at,
//   expires_at, sealed}
// Guests are customers on third-party clients (Shadowrocket & co).
// The admin creates them by hand in the console — username + password
// + validity — and manages them like distributors (disable / enable /
// extend / password / delete). Each guest has a personal page at
// /g/<id>: it shows nothing but a password box until he logs in, then
// only his remaining time and his sealed personal subscription link
// (/s/<token>) to copy. The real subscription URL never leaves the
// server, and /s/ re-checks this record on every fetch, so disabling,
// deleting or expiring the guest cuts the link at once.
export async function getGuest(env, id) {
  if (!id) return null;
  const raw = await env.V2.get("gst:" + id);
  return raw ? JSON.parse(raw) : null;
}
export async function putGuest(env, id, rec) {
  await bumpDataVersion(env);
  await env.V2.put("gst:" + id, JSON.stringify(rec));
}
export function newGuestId() {
  const rnd = new Uint8Array(12);
  crypto.getRandomValues(rnd);
  return [...rnd].map((b) => CODE_ALPHABET[b % CODE_ALPHABET.length].toLowerCase()).join("");
}
export function guestProblem(rec) {
  if (!rec) return "not_found";
  if (rec.status === "disabled") return "disabled";
  if (rec.expires_at && nowSec() > rec.expires_at) return "expired";
  return null;
}

// ---------- guest fetch watching ----------
// Every successful /s/ fetch is noted on the guest record: total
// count, last IP / client / region, and the set of regions seen in
// the last 7 days (region -> last-seen). Region is Cloudflare's IP
// geolocation for the fetching client (request.cf.region; the
// country code is the bucket when no region is reported). The
// owner's sharing rule (2026-11-04): one link showing up in more
// than 5 different provinces inside a week is being shared — the
// guest is disabled on the spot, the tripping fetch included.
// Re-enabling in a console clears the region history, so a
// forgiven guest starts clean instead of re-tripping at once.
export const GUEST_REGION_LIMIT = 5;
export const GUEST_REGION_WINDOW_SEC = 7 * 86400;
// Daily fetch cap (owner's rule, 2026-11-04): one guest link may be
// fetched at most 10 times per Beijing day; the 11th fetch is
// refused and the link stays blocked until the day rolls over —
// it recovers by itself the next day, no console action needed.
export const GUEST_DAILY_LIMIT = 10;
export function beijingDay(ts) {
  return new Date((ts + 8 * 3600) * 1000).toISOString().slice(0, 10);
}
// The daily cap is settable per guest (owner, 2026-11-04): the
// record's daily_limit wins — unset means the global default,
// 0 means unlimited.
export function guestDailyLimit(rec) {
  if (rec.daily_limit === undefined || rec.daily_limit === null) return GUEST_DAILY_LIMIT;
  if (rec.daily_limit === 0) return Infinity;
  return rec.daily_limit;
}
// Console input for the limit: absent = leave as-is, null/"" =
// reset to the default, an integer 0..999 = set it (0 = unlimited).
export function guestLimitInput(v) {
  if (v === undefined) return { ok: true, set: false };
  if (v === null || v === "") return { ok: true, set: true, value: null };
  const n = Number(v);
  if (!Number.isInteger(n) || n < 0 || n > 999) return { ok: false };
  return { ok: true, set: true, value: n };
}

export async function noteGuestFetch(env, id, rec, meta) {
  const now = nowSec();
  const today = beijingDay(now);
  const dayCount = rec.fetch_day === today ? rec.fetch_day_count || 0 : 0;
  const limit = guestDailyLimit(rec);
  if (limit !== Infinity && dayCount >= limit) {
    // Blocked fetches are not recorded: retries must not inflate
    // the stats, and the block lifts by itself at midnight.
    return { dailyBlocked: true, disabled: false, dayCount };
  }
  const regions = { ...(rec.fetch_regions || {}) };
  for (const [k, ts] of Object.entries(regions)) {
    if (now - ts > GUEST_REGION_WINDOW_SEC) delete regions[k];
  }
  if (meta.region) regions[meta.region] = now;
  const regionCount = Object.keys(regions).length;
  const next = {
    ...rec,
    fetch_regions: regions,
    fetch_count: (rec.fetch_count || 0) + 1,
    fetch_day: today,
    fetch_day_count: dayCount + 1,
    last_fetch_at: now,
    last_ip: meta.ip || rec.last_ip || "",
    last_ua: meta.ua || rec.last_ua || "",
    last_region: meta.region || rec.last_region || "",
  };
  if (regionCount > GUEST_REGION_LIMIT) {
    next.status = "disabled";
    next.auto_disabled = { at: now, regions: Object.keys(regions) };
    await putGuest(env, id, next);
    await logEvent(env, "guest_auto_disable", rec.username || id, Object.keys(regions).join(","));
    return { disabled: true, regionCount, dayCount: dayCount + 1 };
  }
  await putGuest(env, id, next);
  return { disabled: false, regionCount, dayCount: dayCount + 1 };
}

export function guestFetchView(rec) {
  const now = nowSec();
  const regions = Object.entries(rec.fetch_regions || {})
    .filter(([, ts]) => now - ts <= GUEST_REGION_WINDOW_SEC)
    .map(([k]) => k);
  return {
    fetch_count: rec.fetch_count || 0,
    fetch_day_count: rec.fetch_day === beijingDay(now) ? rec.fetch_day_count || 0 : 0,
    daily_limit: guestDailyLimit(rec) === Infinity ? 0 : guestDailyLimit(rec),
    last_fetch_at: rec.last_fetch_at || null,
    last_ip: rec.last_ip || "",
    last_ua: rec.last_ua || "",
    last_region: rec.last_region || "",
    regions_7d: regions,
    auto_disabled: rec.auto_disabled || null,
  };
}

export function guestFetchReset() {
  return { fetch_regions: {}, auto_disabled: null, fetch_day: null, fetch_day_count: 0 };
}

export async function guestSessionCookie(env, id) {
  const payload = b64urlEncode(enc.encode(JSON.stringify({ exp: nowSec() + 60 * 60 * 24 * 30, gst: id })));
  const mac = await hmac(env.SESSION_SECRET, payload);
  return `${payload}.${mac}`;
}
// Returns the guest id for a valid session whose account is still
// usable (exists, not disabled, not expired); otherwise null. The
// record is re-read on every call, so an admin disable kills live
// sessions immediately.
export async function guestIdFromRequest(env, request) {
  if (!env.SESSION_SECRET) return null;
  const cookie = request.headers.get("cookie") || "";
  const m = cookie.match(/gsess=([^;]+)/);
  const token = (m && m[1]) || request.headers.get("x-gsess");
  if (!token) return null;
  const [payload, mac] = token.split(".");
  if (!payload || !mac) return null;
  if ((await hmac(env.SESSION_SECRET, payload)) !== mac) return null;
  try {
    const data = JSON.parse(new TextDecoder().decode(b64Decode(payload)));
    if (!data.gst || data.exp <= nowSec()) return null;
    const rec = await getGuest(env, data.gst);
    if (guestProblem(rec)) return null;
    return data.gst;
  } catch {
    return null;
  }
}
