import {
  json, readJson, nowSec, isAdmin, sha256hex, getGuest, putGuest, newGuestId,
  bumpDataVersion, cachedPayload,
  guestProblem, vaultSeal, SLUG_RE, parseDurationSec, parseDeltaSec, durationSeconds, fmtDuration,
} from "../../lib/core.js";

// GET -> all guests. POST -> create / disable / enable / extend /
// password / delete. Mirrors the distributor management API: guests
// are added by hand (username + password + validity in days; 0 =
// permanent), passwords are stored only as SHA-256 hashes, and a
// guest can only be deleted while disabled.
export async function onRequestGet({ request, env }) {
  if (!(await isAdmin(env, request))) return json({ ok: false, reason: "unauthorized" }, 401);
  const out = await cachedPayload(env, "admin:guests", 20000, async () => {
    const rows = [];
    const page = await env.V2.list({ prefix: "gst:", limit: 200 });
    for (const k of page.keys) {
      const raw = await env.V2.get(k.name);
      if (!raw) continue; // KV eventual consistency: never render a ghost row
      const rec = JSON.parse(raw);
      rows.push({
        id: k.name.slice(4),
        username: rec.username, note: rec.note || "", days: rec.days,
        channel: rec.channel || "main", dist: rec.dist || null,
        duration_sec: rec.duration_sec ?? null,
        duration_text: fmtDuration(durationSeconds(rec)),
        status: rec.status, created_at: rec.created_at, expires_at: rec.expires_at,
        expired: rec.status !== "disabled" && !!guestProblem(rec),
      });
    }
    // Oldest first: a newly added guest appends at the bottom of the
    // list, in the order they were added.
    rows.sort((a, b) => (a.created_at || 0) - (b.created_at || 0));
    return rows;
  });
  return json({ ok: true, guests: out });
}

async function findByUsername(env, username) {
  const page = await env.V2.list({ prefix: "gst:", limit: 200 });
  for (const k of page.keys) {
    const rec = await getGuest(env, k.name.slice(4));
    if (rec && rec.username === username) return k.name.slice(4);
  }
  return null;
}

export async function onRequestPost({ request, env }) {
  await bumpDataVersion(env); // any console mutation invalidates cached table payloads
  if (!(await isAdmin(env, request))) return json({ ok: false, reason: "unauthorized" }, 401);
  const body = await readJson(request);

  if (body.action === "create") {
    const username = String(body.username || "").trim();
    if (!username || username.length > 24) return json({ ok: false, reason: "bad_username" }, 400);
    if (!body.password || String(body.password).length < 6) {
      return json({ ok: false, reason: "weak_password" }, 400);
    }
    // Duration: minute-level via durationValue/durationUnit, or the
    // legacy whole-{days} field (0 = permanent). Minimum 1 minute.
    const sec = parseDurationSec(body);
    if (sec === null || sec === undefined) return json({ ok: false, reason: "bad_duration" }, 400);
    if (await findByUsername(env, username)) return json({ ok: false, reason: "exists" }, 409);
    let id = newGuestId();
    for (let i = 0; (await getGuest(env, id)) && i < 5; i++) id = newGuestId();
    if (!SLUG_RE.test(id)) return json({ ok: false, reason: "bad_id" }, 500);
    const createdAt = nowSec();
    // Seal the guest's personal subscription token once, so the link
    // he copies stays the same string; /s/ opens it per fetch.
    const sealed = await vaultSeal(env, JSON.stringify({ g: id }));
    if (!sealed) return json({ ok: false, reason: "vault_unavailable" }, 500);
    await putGuest(env, id, {
      username,
      pw_hash: await sha256hex(String(body.password)),
      note: String(body.note || "").slice(0, 60),
      // `days` stays as a coarse compatibility field (ceil); the
      // exact length lives in duration_sec.
      days: sec ? Math.ceil(sec / 86400) : 0,
      duration_sec: sec || null,
      status: "active",
      created_at: createdAt,
      expires_at: sec > 0 ? createdAt + sec : null,
      sealed,
    });
    return json({ ok: true, id, path: "/g/" + id });
  }

  const id = String(body.id || "");
  // KV eventual consistency: retry the read before saying not_found.
  let rec = await getGuest(env, id);
  for (let i = 0; !rec && i < 3; i++) {
    await new Promise((r) => setTimeout(r, 700));
    rec = await getGuest(env, id);
  }
  if (!rec) return json({ ok: false, reason: "not_found" }, 404);
  switch (body.action) {
    case "disable":
      await putGuest(env, id, { ...rec, status: "disabled" });
      return json({ ok: true });
    case "enable":
      await putGuest(env, id, { ...rec, status: "active" });
      return json({ ok: true });
    case "extend": {
      if (!rec.expires_at) return json({ ok: false, reason: "permanent" }, 400);
      const deltaSec = parseDeltaSec(body);
      if (deltaSec === null) return json({ ok: false, reason: "bad_duration" }, 400);
      if (!deltaSec) return json({ ok: false, reason: "bad_days" }, 400);
      const expires_at = rec.expires_at + deltaSec;
      await putGuest(env, id, { ...rec, expires_at });
      return json({ ok: true, expires_at });
    }
    case "set_expiry": {
      // Manual edit of the expiry moment itself (the console's
      // 修改时间 button for guests): an absolute epoch-second
      // deadline — date, hour, minute and second all editable — or
      // null for permanent. A past moment expires him at once.
      if (!("expires_at" in body)) return json({ ok: false, reason: "bad_expiry" }, 400);
      if (body.expires_at === null) {
        await putGuest(env, id, { ...rec, expires_at: null, days: 0, duration_sec: null });
        return json({ ok: true, expires_at: null });
      }
      const expires_at = Number(body.expires_at);
      if (!Number.isFinite(expires_at) || Math.floor(expires_at) !== expires_at || expires_at <= 0) {
        return json({ ok: false, reason: "bad_expiry" }, 400);
      }
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
      // Guard like distributors: only a disabled guest can be deleted.
      // Deleting kills the /g/<id> page and the /s/ link at once.
      if (rec.status !== "disabled") return json({ ok: false, reason: "disable_first" }, 400);
      await env.V2.delete("gst:" + id);
      return json({ ok: true });
    default:
      return json({ ok: false, reason: "bad_action" }, 400);
  }
}
