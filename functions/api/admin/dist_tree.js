import { json, isAdmin } from "../../lib/core.js";
import { buildTree } from "../../lib/tree.js";

// GET /api/admin/dist_tree?slug=X -> one distributor's roster for
// the standalone tree page (public/tree.html). The stopping
// itself goes through the existing action endpoints.
export async function onRequestGet({ request, env }) {
  if (!(await isAdmin(env, request))) return json({ ok: false, reason: "unauthorized" }, 401);
  const slug = (new URL(request.url).searchParams.get("slug") || "").toLowerCase();
  const payload = await buildTree(env, slug);
  if (!payload) return json({ ok: false, reason: "not_found" }, 404);
  return json(payload);
}
