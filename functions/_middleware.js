import { SLUG_RE, RESERVED_SLUGS } from "./lib/core.js";
import { D1KV } from "./lib/d1kv.js";

// Two jobs, in order:
// 1. Storage backend: env.V2 becomes the D1 shim for every route —
//    including the portal checks below. (2026-11-04: the owner
//    cut over to D1 and deliberately discarded the old KV data —
//    no migration, no KV fallback. The KV binding itself can be
//    removed from the dashboard; every route passes through here
//    first, so nothing ever touches the raw binding.)
// 2. Portal routing:
//    - GET /<slug> (e.g. https://domain/mmm) serves the distributor
//      console when a distributor with that slug exists.
//    - GET /g/<id> serves a guest's personal page when that guest exists.
//    Everything else falls through to the normal site.
export async function onRequest(context) {
  const { request, env } = context;
  if (env.DB && !env.__d1kv) {
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
    const mm = url.pathname.match(/^\/m\/([^/.]+)$/);
    if (mm && SLUG_RE.test(mm[1])) {
      const exists = await env.V2.get("mem:" + mm[1]);
      if (exists) {
        url.pathname = "/member.html";
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
