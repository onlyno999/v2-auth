// Attestation policy check (revised after the 2026-11-04 incident):
// attestation is verified WHEN PRESENT and a bad chain is refused,
// but a chainless activation must still succeed by default —
// pre-2.0 clients cannot produce a chain, and requiring one bricked
// every activation. Run against a dedicated dev server (port 8790)
// with a fresh KV state and NO ATTEST_REQUIRED in its env.
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
check("chainless activation SUCCEEDS by default (legacy clients)", act.status === 200 && !!act.data.token, JSON.stringify(act.data).slice(0, 60));

const M2 = "TEST-MACH-0000-0010";
const issue2 = await j("/api/admin/issue", { machineCode: M2, days: 30, mode: "code" }, { cookie });
const bogus = await j("/api/activate", { machineCode: M2, code: issue2.data.code, pubkey: "x", platform: "android", attestation: ["AAAA"] });
check("garbage chain still refused (verify-when-present)", bogus.status === 403 && bogus.data.reason !== "attest_missing", JSON.stringify(bogus.data));

console.log(`\n==== ${pass} passed, ${fail} failed ====`);
process.exit(fail ? 1 : 0);
