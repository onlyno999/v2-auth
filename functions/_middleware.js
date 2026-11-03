import { SLUG_RE, RESERVED_SLUGS } from "./lib/core.js";
import { D1KV } from "./lib/d1kv.js";

// Two jobs, in order:
// 1. Storage backend selection. While no D1 binding exists,
//    env.V2 stays the KV namespace and nothing changes (safe to
//    deploy before the dashboard binding). Once a D1 database is
//    bound as DB, env.V2 becomes the D1 shim for every route —
//    including the portal checks below — and env.KV_ORIG keeps a
//    handle on the real KV namespace for the migration endpoint.
// 2. Portal routing:
//    - GET /<slug> (e.g. https://domain/mmm) serves the distributor
//      console when a distributor with that slug exists.
//    - GET /g/<id> serves a guest's personal page when that guest exists.
//    Everything else falls through to the normal site.
export async function onRequest(context) {
  const { request, env } = context;
  if (env.DB && !env.__d1kv) {
    env.KV_ORIG = env.V2;
    env.V2 = new D1KV(env.DB);
    env.__d1kv = true;
  }
  const url = new URL(request.url);
  if (request.method === "GET") {
    const g = url.pathname.match(/^\/g\/([^/.]+)$/);
    if (g && SLUG_RE.test(g[1])) {
      const exists = await env.V2.get("gst:" + g[1]);
      if (exists) {
        url.pathname = "/guest.html";
        return env.ASSETS.fetch(new Request(url.toString(), { method: "GET" }));
      }
    }
    const m = url.pathname.match(/^\/([^/.]+)$/);
    if (m && SLUG_RE.test(m[1]) && !RESERVED_SLUGS.has(m[1])) {
      const exists = await env.V2.get("dist:" + m[1]);
      if (exists) {
        url.pathname = "/dist.html";
        return env.ASSETS.fetch(new Request(url.toString(), { method: "GET" }));
      }
    }
  }
  return context.next();
}
