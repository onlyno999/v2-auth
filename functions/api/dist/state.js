import { json, getDist } from "../../lib/core.js";

// GET ?slug= -> whether this distributor exists and still needs to
// set a password (first visit). The portal page itself only renders
// for existing slugs, so existence is not a secret here.
export async function onRequestGet({ request, env }) {
  const slug = new URL(request.url).searchParams.get("slug") || "";
  const rec = slug ? await getDist(env, slug) : null;
  if (!rec) return json({ ok: false, reason: "not_found" }, 404);
  return json({
    ok: true, name: rec.name,
    needs_setup: !rec.pw_hash,
    disabled: rec.status !== "active",
  });
}
