import {
  json, readJson, getDev, getLicByKey, putLic, getDist, putDist, getGuest,
  putGuest, guestFetchReset, distSlugFromRequest, bumpDataVersion, logEvent,
} from "../../lib/core.js";

// POST {kind: device|guest|sub, target, action} — a distributor
// manages the people under him (owner, 2026-11-04: 他下面的人他
// 自己管的): from his roster page he cuts and restores lines for
// any customer, guest or sub-distributor in his OWN subtree.
// Scope is proven by walking the target owner's parent chain up
// to the caller; anything outside the subtree is a 404.
async function inMySubtree(env, owner, me) {
  if (!owner) return false;
  if (owner === me) return true;
  let cur = await getDist(env, owner);
  for (let i = 0; i < 6 && cur; i++) {
    if (cur.parent === me) return true;
    cur = cur.parent ? await getDist(env, cur.parent) : null;
  }
  return false;
}

export async function onRequestPost({ request, env }) {
  await bumpDataVersion(env);
  const me = await distSlugFromRequest(env, request);
  if (!me) return json({ ok: false, reason: "unauthorized" }, 401);
  const body = await readJson(request);
  const target = String(body.target || "");

  if (body.kind === "device") {
    const dev = await getDev(env, target);
    const licKey = dev?.lic || (await env.V2.get("open:" + target));
    const lic = licKey ? await getLicByKey(env, licKey) : null;
    if (!lic || !(await inMySubtree(env, lic.dist, me))) {
      return json({ ok: false, reason: "not_found" }, 404);
    }
    if (body.action === "revoke") {
      await putLic(env, { ...lic, status: "revoked" });
      await logEvent(env, "dist_revoke", target);
      return json({ ok: true });
    }
    if (body.action === "restore") {
      await putLic(env, { ...lic, status: dev ? "active" : "issued" });
      return json({ ok: true });
    }
    return json({ ok: false, reason: "bad_action" }, 400);
  }

  if (body.kind === "guest") {
    const rec = await getGuest(env, target);
    if (!rec || !(await inMySubtree(env, rec.dist, me))) {
      return json({ ok: false, reason: "not_found" }, 404);
    }
    if (body.action === "disable") {
      await putGuest(env, target, { ...rec, status: "disabled" });
      await logEvent(env, "dist_guest_disable", target);
      return json({ ok: true });
    }
    if (body.action === "enable") {
      await putGuest(env, target, { ...rec, status: "active", ...guestFetchReset() });
      return json({ ok: true });
    }
    return json({ ok: false, reason: "bad_action" }, 400);
  }

  if (body.kind === "sub") {
    const slug = target.toLowerCase();
    const rec = await getDist(env, slug);
    if (!rec || slug === me || !(await inMySubtree(env, slug, me))) {
      return json({ ok: false, reason: "not_found" }, 404);
    }
    if (body.action === "disable") {
      await putDist(env, slug, { ...rec, status: "disabled" });
      await logEvent(env, "dist_sub_disable", slug);
      return json({ ok: true });
    }
    if (body.action === "enable") {
      await putDist(env, slug, { ...rec, status: "active" });
      return json({ ok: true });
    }
    return json({ ok: false, reason: "bad_action" }, 400);
  }

  return json({ ok: false, reason: "bad_kind" }, 400);
}
