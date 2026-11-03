// Signer-binding policy check (owner's design, 2026-11-04): the
// first activation of a machine binds its signing-cert digest in
// KV; later activations must present the same digest or are refused
// (signer_mismatch, surfaced in the admin console data). Runs
// against a dedicated dev server (port 8790) with a fresh KV state.
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
const A = "aa".repeat(32);
const B = "bb".repeat(32);

const login = await fetch(BASE + "/api/admin/login", {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ password: "liantong-test-pw" }),
});
const cookie = (login.headers.get("set-cookie") || "").split(";")[0];
check("admin login", login.status === 200 && cookie.startsWith("sess="));

const M = "TEST-MACH-0000-0021";
const i1 = await j("/api/admin/issue", { machineCode: M, days: 30, mode: "code" }, { cookie });
const a1 = await j("/api/activate", { machineCode: M, code: i1.data.code, pubkey: "x", platform: "android", signer: A });
check("first activation binds signer A", a1.status === 200 && !!a1.data.token, JSON.stringify(a1.data).slice(0, 50));

const i2 = await j("/api/admin/issue", { machineCode: M, days: 30, mode: "code" }, { cookie });
const a2 = await j("/api/activate", { machineCode: M, code: i2.data.code, pubkey: "x", platform: "android", signer: B });
check("different signer refused", a2.status === 403 && a2.data.reason === "signer_mismatch", JSON.stringify(a2.data));

const devs = await j("/api/admin/devices", null, { cookie });
const row = (devs.data.issued || []).find((i) => i.machine === M);
check("console data carries the refusal reason", !!row && !!row.attest_fail && row.attest_fail.reason === "signer_mismatch", JSON.stringify(row && row.attest_fail));

const a3 = await j("/api/activate", { machineCode: M, code: i2.data.code, pubkey: "x", platform: "android", signer: A });
check("same signer A activates again", a3.status === 200 && !!a3.data.token, JSON.stringify(a3.data).slice(0, 50));

// Claim (direct-open) path binds the same way.
const M2 = "TEST-MACH-0000-0022";
await j("/api/admin/issue", { machineCode: M2, days: 30, mode: "open" }, { cookie });
const c1 = await j("/api/claim", { machineCode: M2, pubkey: "x", platform: "android", signer: B });
check("first claim binds signer B", c1.status === 200 && !!c1.data.token, JSON.stringify(c1.data).slice(0, 50));
await j("/api/admin/issue", { machineCode: M2, days: 30, mode: "open" }, { cookie });
const c2 = await j("/api/claim", { machineCode: M2, pubkey: "x", platform: "android", signer: A });
check("claim with another signer refused", c2.status === 403 && c2.data.reason === "signer_mismatch", JSON.stringify(c2.data));

console.log(`\n==== ${pass} passed, ${fail} failed ====`);
process.exit(fail ? 1 : 0);
