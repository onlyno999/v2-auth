import {
  json, readJson, nowSec, distSlugFromRequest, getDist, putDist, sha256hex,
  bumpDataVersion,
  getGuest, putGuest, newGuestId, guestProblem, vaultSeal, SLUG_RE,
  parseDurationSec, durationSeconds, fmtDuration, logEvent,
} from "../../lib/core.js";

// Distributor-side guest accounts: a distributor adds his own
// third-party-client customers (username + password + validity) from
// his own console, exactly like the admin — except his guests are
// stamped channel="dist" + dist=<slug> (their /s/ links serve the
// distributor channel), creation consumes one quota slot, and the
// distributor rules apply: no permanent guests, max 1 year, and a
// guest can only be deleted while disabled. He sees and manages
// only his own guests.

async function listOwnGuests(env, slug) {
  const out = [];
  const page = await env.V2.list({ prefix: "gst:", limit: 200 });
  for (const k of page.keys) {
    const raw = await env.V2.get(k.name);
    if (!raw) continue;
    const rec = JSON.parse(raw);
    if (rec.dist !== slug) continue;
    out.push({ id: k.name.slice(4), rec });
  }
  // Oldest first: a newly added guest appends at the bottom of the
  // list, in the order they were added.
  out.sort((a, b) => (a.rec.created_at || 0) - (b.rec.created_at || 0));
  return out;
}

export async function onRequestGet({ request, env }) {
  const slug = await distSlugFromRequest(env, request);
  if (!slug) return json({ ok: false, reason: "unauthorized" }, 401);
  const own = await listOwnGuests(env, slug);
  return json({
    ok: true,
    guests: own.map(({ id, rec }) => ({
      id,
      username: rec.username, note: rec.note || "",
      duration_text: fmtDuration(durationSeconds(rec)),
      status: rec.status, created_at: rec.created_at, expires_at: rec.expires_at,
      expired: rec.status !== "disabled" && !!guestProblem(rec),
    })),
  });
}

export async function onRequestPost({ request, env }) {
  await bumpDataVersion(env); // any console mutation invalidates cached table payloads
  const slug = await distSlugFromRequest(env, request);
  if (!slug) return json({ ok: false, reason: "unauthorized" }, 401);
  const body = await readJson(request);

  if (body.action === "create") {
    const username = String(body.username || "").trim();
    if (!username || username.length > 24) return json({ ok: false, reason: "bad_username" }, 400);
    if (!body.password || String(body.password).length < 6) {
      return json({ ok: false, reason: "weak_password" }, 400);
    }
    const sec = parseDurationSec(body);
    if (sec === null || sec === undefined) return json({ ok: false, reason: "bad_duration" }, 400);
    if (sec === 0) return json({ ok: false, reason: "no_permanent" }, 400);
    if (sec > 365 * 86400) return json({ ok: false, reason: "days_range" }, 400);
    const own = await listOwnGuests(env, slug);
    if (own.some(({ rec }) => rec.username === username)) {
      return json({ ok: false, reason: "exists" }, 409);
    }
    const dist = await getDist(env, slug);
    if (dist.quota >= 0 && dist.used >= dist.quota) {
      return json({ ok: false, reason: "quota_exhausted" }, 403);
    }
    let id = newGuestId();
    for (let i = 0; (await getGuest(env, id)) && i < 5; i++) id = newGuestId();
    if (!SLUG_RE.test(id)) return json({ ok: false, reason: "bad_id" }, 500);
    const sealed = await vaultSeal(env, JSON.stringify({ g: id }));
    if (!sealed) return json({ ok: false, reason: "vault_unavailable" }, 500);
    const createdAt = nowSec();
    await putGuest(env, id, {
      username,
      pw_hash: await sha256hex(String(body.password)),
      note: String(body.note || "").slice(0, 60),
      days: Math.ceil(sec / 86400),
      duration_sec: sec,
      status: "active",
      created_at: createdAt,
      expires_at: createdAt + sec,
      sealed,
      channel: "dist",
      dist: slug,
    });
    await putDist(env, slug, { ...dist, used: dist.used + 1 });
    await logEvent(env, "dist_guest_create", username, slug);
    return json({ ok: true, id, path: "/g/" + id });
  }

  const id = String(body.id || "");
  let rec = await getGuest(env, id);
  for (let i = 0; !rec && i < 3; i++) {
    await new Promise((r) => setTimeout(r, 700));
    rec = await getGuest(env, id);
  }
  if (!rec || rec.dist !== slug) return json({ ok: false, reason: "not_found" }, 404);
  switch (body.action) {
    case "disable":
      await putGuest(env, id, { ...rec, status: "disabled" });
      return json({ ok: true });
    case "enable":
      await putGuest(env, id, { ...rec, status: "active" });
      return json({ ok: true });
    case "set_expiry": {
      if (!("expires_at" in body)) return json({ ok: false, reason: "bad_expiry" }, 400);
      if (body.expires_at === null) return json({ ok: false, reason: "no_permanent" }, 400);
      const expires_at = Number(body.expires_at);
      if (!Number.isFinite(expires_at) || Math.floor(expires_at) !== expires_at || expires_at <= 0) {
        return json({ ok: false, reason: "bad_expiry" }, 400);
      }
      if (expires_at > nowSec() + 365 * 86400) return json({ ok: false, reason: "days_range" }, 400);
      const days = Math.max(0, Math.ceil((expires_at - nowSec()) / 86400));
      await putGuest(env, id, { ...rec, expires_at, days });
      return json({ ok: true, expires_at });
    }
    case "password":
      if (!body.password || String(body.password).length < 6) {
        return json({ ok: false, reason: "weak_password" }, 400);
      }
      await putGuest(env, id, { ...rec, pw_hash: await sha256hex(String(body.password)) });
      return json({ ok: true });
    case "delete":
      if (rec.status !== "disabled") return json({ ok: false, reason: "disable_first" }, 400);
      await env.V2.delete("gst:" + id);
      return json({ ok: true });
    default:
      return json({ ok: false, reason: "bad_action" }, 400);
  }
}
