// Focused check: distributor channel with a GARBAGE SUB_URL_DIST.
// Run against a dedicated dev server (port 8790) whose .dev.vars has
//   SUB_URL=http://127.0.0.1:8899/sub_main.txt
//   SUB_URL_DIST=mm            <- the literal mistake from production
// A distributor guest's /s/ link must serve the MAIN subscription
// (distributors share one subscription) instead of failing.
import { readFileSync } from "node:fs";

const BASE = "http://127.0.0.1:8790";
let pass = 0, fail = 0;
const check = (name, cond, extra = "") => {
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${extra ? "  (" + extra + ")" : ""}`);
  cond ? pass++ : fail++;
};
const j = async (path, body, headers = {}) => {
  const r = await fetch(BASE + path, {
    method: body ? "POST" : "GET",
    headers: { "content-type": "application/json", ...headers },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: r.status, data: await r.json().catch(() => ({})) };
};

const login = await fetch(BASE + "/api/admin/login", {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ password: "liantong-test-pw" }),
});
const cookie = (login.headers.get("set-cookie") || "").split(";")[0];
check("admin login", login.status === 200 && cookie.startsWith("sess="));

await j("/api/admin/dist", { action: "create", slug: "fbk", name: "回落测试分销", password: "fbk-pw-123", quota: 5 }, { cookie });
const dLogin = await fetch(BASE + "/api/dist/login", {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ slug: "fbk", password: "fbk-pw-123" }),
});
const dcookie = (dLogin.headers.get("set-cookie") || "").split(";")[0];
check("dist login", dLogin.status === 200 && dcookie.startsWith("dsess="));

const created = await j("/api/dist/guest", { action: "create", username: "回落游客", password: "guest-pw-9", durationValue: 30, durationUnit: "day" }, { cookie: dcookie });
check("dist creates guest", created.status === 200 && !!created.data.id, JSON.stringify(created.data).slice(0, 80));

const gLogin = await j("/api/guest/login", { id: created.data.id, password: "guest-pw-9" });
const me = await (await fetch(BASE + "/api/guest/me", { headers: { "x-gsess": gLogin.data.session } })).json();
check("guest gets his link", !!me.link);

const res = await fetch(me.link);
const text = await res.text();
const expected = readFileSync(new URL("./fixtures/sub_main.txt", import.meta.url), "utf8");
check("dist guest link serves MAIN subscription despite garbage SUB_URL_DIST",
  res.status === 200 && text === expected, "status=" + res.status);

console.log(`\n==== ${pass} passed, ${fail} failed ====`);
process.exit(fail ? 1 : 0);
