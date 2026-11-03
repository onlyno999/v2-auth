import { json, getDist, distSlugFromRequest } from "../../lib/core.js";
import { buildTree } from "../../lib/tree.js";

// GET /api/dist/subtree?slug=X -> the roster page data for one of
// MY OWN sub-distributors (or for myself). Scope rule: X must be
// me or sit somewhere in my subtree — verified by walking X's
// parent chain up to me (the tree is at most 5 levels deep).
// View only: managing people stays in the consoles.
export async function onRequestGet({ request, env }) {
  const me = await distSlugFromRequest(env, request);
  if (!me) return json({ ok: false, reason: "unauthorized" }, 401);
  const slug = (new URL(request.url).searchParams.get("slug") || me).toLowerCase();
  if (slug !== me) {
    let cur = await getDist(env, slug);
    if (!cur) return json({ ok: false, reason: "not_found" }, 404);
    let inTree = false;
    for (let i = 0; i < 6 && cur; i++) {
      if (cur.parent === me) { inTree = true; break; }
      cur = cur.parent ? await getDist(env, cur.parent) : null;
    }
    if (!inTree) return json({ ok: false, reason: "not_found" }, 404);
  }
  const payload = await buildTree(env, slug);
  if (!payload) return json({ ok: false, reason: "not_found" }, 404);
  return json({ ...payload, viewer: me });
}
