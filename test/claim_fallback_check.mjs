// Regression test for the 2026-11-04 production incident: the
// console listed a license as "opened, awaiting claim" while
// /api/claim answered no_open — the open: pointer record was
// missing although the license record (status "open") existed.
// Claim must fall back to scanning license records. Runs the real
// claim handler against an in-memory KV stub (no dev server).
import { onRequestPost } from "../functions/api/claim.js";

const store = new Map();
const env = {
  ATTEST_REQUIRED: "0", // attestation opt-out (no chain fabricatable here)
  SESSION_SECRET: "unit-test-secret",
  V2: {
    async get(k) { return store.has(k) ? store.get(k) : null; },
    async put(k, v) { store.set(k, String(v)); },
    async delete(k) { store.delete(k); },
    async list({ prefix }) {
      const keys = [...store.keys()].filter((k) => k.startsWith(prefix)).map((name) => ({ name }));
      return { keys, list_complete: true };
    },
  },
};
const MACHINE = "TEST-MACH-0000-0007";
const licRec = {
  days: 2, duration_sec: 2 * 86400, status: "open", machine: MACHINE,
  note: "", channel: "main", code_enc: null,
  created_at: 1700000000, activated_at: null, expires_at: null,
};
store.set("lic:deadbeef", JSON.stringify(licRec));
// NOTE: deliberately NO "open:" + MACHINE pointer — the incident.

let pass = 0, fail = 0;
const check = (name, cond, extra = "") => {
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${extra ? "  (" + extra + ")" : ""}`);
  cond ? pass++ : fail++;
};
const req = (body) => ({ json: async () => body });
const claim = async (machineCode) => {
  const res = await onRequestPost({ request: new Request("http://x/api/claim", { method: "POST" }), env });
  return res;
};
// onRequestPost reads the body via readJson(request) — feed it a
// real Request with a JSON body instead of the stub above.
const claimBody = async (bodyObj) => onRequestPost({
  request: new Request("http://x/api/claim", {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(bodyObj),
  }),
  env,
});

const r1 = await claimBody({ machineCode: MACHINE, pubkey: "pk", platform: "android" });
const d1 = await r1.json();
check("claim succeeds WITHOUT the open: pointer (fallback scan)", r1.status === 200 && d1.ok === true && !!d1.token, JSON.stringify(d1).slice(0, 80));

const after = JSON.parse(store.get("lic:deadbeef"));
check("license flipped to active by the fallback claim", after.status === "active");
check("device record created", [...store.keys()].some((k) => k === "dev:" + MACHINE));

const r2 = await claimBody({ machineCode: MACHINE, pubkey: "pk", platform: "android" });
const d2 = await r2.json();
check("second claim finds nothing open anymore", r2.status === 404 && d2.reason === "no_open", JSON.stringify(d2));

const r3 = await claimBody({ machineCode: "TEST-MACH-0000-0999", pubkey: "pk", platform: "android" });
const d3 = await r3.json();
check("unknown machine still no_open", r3.status === 404 && d3.reason === "no_open", JSON.stringify(d3));

console.log(`\n==== ${pass} passed, ${fail} failed ====`);
process.exit(fail ? 1 : 0);
