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

// ---------- KV record access ----------
export async function getLicByCode(env, code) {
  const raw = await env.KV.get(await codeKey(code));
  return raw ? { key: await codeKey(code), ...JSON.parse(raw) } : null;
}
export async function putLic(env, lic) {
  await env.KV.put(lic.key, JSON.stringify(lic.rec ?? lic));
}
export async function getLicByKey(env, key) {
  const raw = await env.KV.get(key);
  return raw ? { key, ...JSON.parse(raw) } : null;
}
export async function getDev(env, machineCode) {
  const raw = await env.KV.get("dev:" + machineCode);
  return raw ? JSON.parse(raw) : null;
}
export async function putDev(env, machineCode, dev) {
  await env.KV.put("dev:" + machineCode, JSON.stringify(dev));
}
export async function logEvent(env, kind, machineCode = "", detail = "") {
  // Best-effort, low volume: one small key per day-bucket counter plus a
  // rolling "last events" list is overkill for v1; keep a per-day counter.
  const day = new Date().toISOString().slice(0, 10);
  const k = `stat:${day}:${kind}`;
  const cur = parseInt((await env.KV.get(k)) || "0", 10);
  await env.KV.put(k, String(cur + 1), { expirationTtl: 60 * 60 * 24 * 40 });
  if (machineCode) {
    await env.KV.put(`last:${machineCode}`, JSON.stringify({ kind, detail, ts: nowSec() }), {
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
export async function sessionCookie(env, req) {
  const payload = b64urlEncode(enc.encode(JSON.stringify({ exp: nowSec() + 60 * 60 * 12, admin: true })));
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
  const cookie = request.headers.get("cookie") || "";
  const m = cookie.match(/sess=([^;]+)/);
  if (!m || !env.SESSION_SECRET) return false;
  const [payload, mac] = m[1].split(".");
  if (!payload || !mac) return false;
  if ((await hmac(env.SESSION_SECRET, payload)) !== mac) return false;
  try {
    const data = JSON.parse(new TextDecoder().decode(b64Decode(payload)));
    return data.admin === true && data.exp > nowSec();
  } catch {
    return false;
  }
}

export async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}
