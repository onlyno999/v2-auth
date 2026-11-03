// Session credential precedence check: a stale cookie must not
// shadow a valid header token (and vice versa). Field bug: the
// owner's browser held an old sess cookie, so every console call
// 401'd even right after a successful password login, because
// isAdmin only ever looked at the cookie when one was present.
import { isAdmin, sessionCookie, distSlugFromRequest, distSessionCookie } from "../functions/lib/core.js";

const env = {
  SESSION_SECRET: "precedence-test-secret",
  // distSlugFromRequest also checks the distributor record in KV.
  V2: {
    async get(k) {
      if (k === "dist:mm") return JSON.stringify({ slug: "mm", status: "active" });
      return null;
    },
  },
};

const req = (headers) => new Request("https://example.test/api/admin/devices", { headers });
let pass = 0, fail = 0;
const check = (name, cond) => { if (cond) { pass++; console.log("ok  -", name); } else { fail++; console.log("FAIL-", name); } };

const goodAdmin = await sessionCookie(env, req({}));
const junk = "AAAAAAAAAAAAAAAA.BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

check("admin: header token alone", await isAdmin(env, req({ "x-session": goodAdmin })) === true);
check("admin: cookie alone", await isAdmin(env, req({ cookie: `sess=${goodAdmin}` })) === true);
check("admin: stale cookie + valid header (field bug)", await isAdmin(env, req({ cookie: `sess=${junk}`, "x-session": goodAdmin })) === true);
check("admin: valid cookie + junk header", await isAdmin(env, req({ cookie: `sess=${goodAdmin}`, "x-session": junk })) === true);
check("admin: both junk rejected", await isAdmin(env, req({ cookie: `sess=${junk}`, "x-session": junk })) === false);
check("admin: nothing presented", await isAdmin(env, req({})) === false);

const goodDist = await distSessionCookie(env, "mm");
check("dist: header token alone", await distSlugFromRequest(env, req({ "x-dsess": goodDist })) === "mm");
check("dist: stale cookie + valid header (same bug)", await distSlugFromRequest(env, req({ cookie: `dsess=${junk}`, "x-dsess": goodDist })) === "mm");
check("dist: both junk rejected", await distSlugFromRequest(env, req({ cookie: `dsess=${junk}`, "x-dsess": junk })) === null);

console.log(`\n${pass}/${pass + fail} passed`);
process.exit(fail ? 1 : 0);
