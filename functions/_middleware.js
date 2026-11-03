import { SLUG_RE, RESERVED_SLUGS } from "./lib/core.js";

// Distributor portal: GET /<slug> (e.g. https://domain/mmm) serves the
// distributor console when a distributor with that slug exists.
// Everything else falls through to the normal site.
export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const m = url.pathname.match(/^\/([^/.]+)$/);
  if (request.method === "GET" && m && SLUG_RE.test(m[1]) && !RESERVED_SLUGS.has(m[1])) {
    const exists = await env.V2.get("dist:" + m[1]);
    if (exists) {
      url.pathname = "/dist.html";
      return env.ASSETS.fetch(new Request(url.toString(), { method: "GET" }));
    }
  }
  return context.next();
}
