// Focused check: attestation is required BY DEFAULT (no
// ATTEST_REQUIRED in this server's env). Run against a dedicated
// dev server (port 8790) with a fresh KV state. A code activation
// without an attestation chain must be refused (attest_missing);
// nothing gets issued to an unproven build.
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

const M = "TEST-MACH-0000-0009";
const issue = await j("/api/admin/issue", { machineCode: M, days: 30, mode: "code" }, { cookie });
check("admin issues a code", issue.status === 200 && !!issue.data.code, JSON.stringify(issue.data).slice(0, 60));

const act = await j("/api/activate", { machineCode: M, code: issue.data.code, pubkey: "x", platform: "android" });
check("chainless activation refused by default", act.status === 403 && act.data.reason === "attest_missing", JSON.stringify(act.data));

const bogus = await j("/api/activate", { machineCode: M, code: issue.data.code, pubkey: "x", platform: "android", attestation: ["AAAA"] });
check("garbage chain refused too", bogus.status === 403 && bogus.data.reason !== "attest_missing", JSON.stringify(bogus.data));

console.log(`\n==== ${pass} passed, ${fail} failed ====`);
process.exit(fail ? 1 : 0);
