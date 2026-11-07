import {
  json, readJson, nowSec, isAdmin, sha256hex, getMember, putMember, newGuestId,
  bumpDataVersion, cachedPayload, memberProblem, vaultSeal, SLUG_RE,
  parseDurationSec, parseDeltaSec, spanDurationSeconds, fmtDuration,
} from "../../lib/core.js";

// GET -> all formal members. POST -> create / disable / enable /
// extend / set_expiry / rename / password / delete. Formal members
// （小火箭正式会员） are paying customers on third-party clients
// (iPhone / Shadowrocket): hand-added like guests, but a separate
// list with no fetch watching or daily cap. A member can only be
// deleted while disabled.
export async function onRequestGet({ request, env }) {
  if (!(await isAdmin(env, request))) return json({ ok: false, reason: "unauthorized" }, 401);
  const out = await cachedPayload(env, "admin:members", 20000, async () => {
    const rows = [];
    const page = await env.V2.list({ prefix: "mem:", limit: 200 });
    for (const k of page.keys) {
      const raw = await env.V2.get(k.name);
      if (!raw) continue;
      const rec = JSON.parse(raw);
      rows.push({
        id: k.name.slice(4),
        username: rec.username, note: rec.note || "", days: rec.days,
        duration_sec: rec.duration_sec ?? null,
        duration_text: fmtDuration(spanDurationSeconds(rec)),
        status: rec.status, created_at: rec.created_at, expires_at: rec.expires_at,
        expired: rec.status !== "disabled" && !!memberProblem(rec),
      });
    }
    rows.sort((a, b) => (a.created_at || 0) - (b.created_at || 0));
    return rows;
  });
  return json({ ok: true, members: out });
}

async function findByUsername(env, username) {
  const page = await env.V2.list({ prefix: "mem:", limit: 200 });
  for (const k of page.keys) {
    const rec = await getMember(env, k.name.slice(4));
    if (rec && rec.username === username) return k.name.slice(4);
  }
  return null;
}

export async function onRequestPost({ request, env }) {
  await bumpDataVersion(env);
  if (!(await isAdmin(env, request))) return json({ ok: false, reason: "unauthorized" }, 401);
  const body = await readJson(request);

  if (body.action === "create") {
    const username = String(body.username || "").trim();
    if (!username || username.length > 24) return json({ ok: false, reason: "bad_username" }, 400);
    if (!body.password || String(body.password).length < 6) {
      return json({ ok: false, reason: "weak_password" }, 400);
    }
    const sec = parseDurationSec(body);
    if (sec === null || sec === undefined) return json({ ok: false, reason: "bad_duration" }, 400);
    if (await findByUsername(env, username)) return json({ ok: false, reason: "exists" }, 409);
    let id = newGuestId();
    for (let i = 0; (await getMember(env, id)) && i < 5; i++) id = newGuestId();
    if (!SLUG_RE.test(id)) return json({ ok: false, reason: "bad_id" }, 500);
    const createdAt = nowSec();
    const sealed = await vaultSeal(env, JSON.stringify({ m: id }));
    if (!sealed) return json({ ok: false, reason: "vault_unavailable" }, 500);
    await putMember(env, id, {
      username,
      pw_hash: await sha256hex(String(body.password)),
      note: String(body.note || "").slice(0, 60),
      days: sec ? Math.ceil(sec / 86400) : 0,
      duration_sec: sec || null,
      status: "active",
      created_at: createdAt,
      expires_at: sec > 0 ? createdAt + sec : null,
      sealed,
    });
    return json({ ok: true, id, path: "/m/" + id });
  }

  const id = String(body.id || "");
  let rec = await getMember(env, id);
  for (let i = 0; !rec && i < 3; i++) {
    await new Promise((r) => setTimeout(r, 700));
    rec = await getMember(env, id);
  }
  if (!rec) return json({ ok: false, reason: "not_found" }, 404);
  switch (body.action) {
    case "disable":
      await putMember(env, id, { ...rec, status: "disabled" });
      return json({ ok: true });
    case "enable":
      await putMember(env, id, { ...rec, status: "active" });
      return json({ ok: true });
    case "extend": {
      if (!rec.expires_at) return json({ ok: false, reason: "permanent" }, 400);
      const deltaSec = parseDeltaSec(body);
      if (deltaSec === null) return json({ ok: false, reason: "bad_duration" }, 400);
      if (!deltaSec) return json({ ok: false, reason: "bad_days" }, 400);
      const expires_at = rec.expires_at + deltaSec;
      await putMember(env, id, { ...rec, expires_at });
      return json({ ok: true, expires_at });
    }
    case "set_expiry": {
      if (!("expires_at" in body)) return json({ ok: false, reason: "bad_expiry" }, 400);
      if (body.expires_at === null) {
        await putMember(env, id, { ...rec, expires_at: null, days: 0, duration_sec: null });
        return json({ ok: true, expires_at: null });
      }
      const expires_at = Number(body.expires_at);
      if (!Number.isFinite(expires_at) || Math.floor(expires_at) !== expires_at || expires_at <= 0) {
        return json({ ok: false, reason: "bad_expiry" }, 400);
      }
      const days = Math.max(0, Math.ceil((expires_at - nowSec()) / 86400));
      await putMember(env, id, { ...rec, expires_at, days });
      return json({ ok: true, expires_at });
    }
    case "rename": {
      const username = String(body.username || "").trim();
      if (!username || username.length > 24) return json({ ok: false, reason: "bad_username" }, 400);
      await putMember(env, id, { ...rec, username });
      return json({ ok: true, username });
    }
    case "password":
      if (!body.password || String(body.password).length < 6) {
        return json({ ok: false, reason: "weak_password" }, 400);
      }
      await putMember(env, id, { ...rec, pw_hash: await sha256hex(String(body.password)) });
      return json({ ok: true });
    case "delete":
      if (rec.status !== "disabled") return json({ ok: false, reason: "disable_first" }, 400);
      await env.V2.delete("mem:" + id);
      return json({ ok: true });
    default:
      return json({ ok: false, reason: "bad_action" }, 400);
  }
}
