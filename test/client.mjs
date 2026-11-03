// End-to-end test for v2-auth (assumes `wrangler pages dev` on :8788
// with .dev.vars ADMIN_PASSWORD=liantong-test-pw).
import { parseKeyDescription, readTlv } from "../functions/lib/attest.js";

const BASE = "http://127.0.0.1:8788";
let pass = 0, fail = 0;
const check = (name, cond, extra = "") => {
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${extra ? "  (" + extra + ")" : ""}`);
  cond ? pass++ : fail++;
};

// ---------- 1. attestation DER parser unit test ----------
function derLen(n) {
  if (n < 128) return [n];
  const b = [];
  while (n > 0) { b.unshift(n & 0xff); n >>= 8; }
  return [0x80 | b.length, ...b];
}
const T = (tagBytes, content) => new Uint8Array([...tagBytes, ...derLen(content.length), ...content]);
const SEQ = (...kids) => T([0x30], kids.flatMap((k) => [...k]));
const INT = (v) => T([0x02], [v]);
const ENUM = (v) => T([0x0a], [v]);
const OCT = (bytes) => T([0x04], [...bytes]);
const BOOL = (v) => T([0x01], [v ? 0xff : 0x00]);
const CTX709 = (content) => T([0xbf, 0x85, 0x45], content);
const CTX704 = (content) => T([0xbf, 0x85, 0x40], content);

{
  const challenge = new Uint8Array(32).fill(0xab);
  const digest = new Uint8Array(32).fill(0x22);
  const pkgInfo = SEQ(OCT(new TextEncoder().encode("com.v2ray.ang.fdroid")), INT(107));
  const appId = SEQ(T([0x31], [...pkgInfo]), T([0x31], [...OCT(digest)]));
  const root = SEQ(OCT(new Uint8Array(32).fill(7)), BOOL(true), ENUM(0), OCT(new Uint8Array(32).fill(9)));
  const kd = SEQ(
    INT(3), ENUM(1), INT(3), ENUM(1), OCT(challenge), OCT(new Uint8Array(0)),
    SEQ(CTX709([...appId])), SEQ(CTX704([...root]))
  );
  const parsed = parseKeyDescription(kd, readTlv(kd, 0));
  check("attest: challenge", Buffer.from(parsed.challenge).equals(Buffer.from(challenge)));
  check("attest: level TEE", parsed.securityLevel === 1);
  check("attest: package", parsed.software.appId.packages[0] === "com.v2ray.ang.fdroid");
  check("attest: digest", parsed.software.appId.digests[0] === "22".repeat(32));
  check("attest: boot locked+verified", parsed.tee.rootOfTrust.deviceLocked === true && parsed.tee.rootOfTrust.verifiedBootState === 0);
}

// ---------- 2. HTTP flow ----------
const j = async (path, body, headers = {}) => {
  const r = await fetch(BASE + path, {
    method: "POST", headers: { "content-type": "application/json", ...headers },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: r.status, data: await r.json().catch(() => null), headers: r.headers };
};
const b64u = (bytes) => Buffer.from(bytes).toString("base64url");
async function newDeviceKey() {
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const spki = await crypto.subtle.exportKey("spki", kp.publicKey);
  return { kp, pubkey: Buffer.from(spki).toString("base64") };
}
async function signedCall(path, machine, kp) {
  const ts = Math.floor(Date.now() / 1000);
  const nonce = b64u(crypto.getRandomValues(new Uint8Array(12)));
  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, kp.privateKey,
    new TextEncoder().encode(`${machine}|${ts}|${nonce}|${path}`)
  );
  const r = await fetch(BASE + path, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ machineCode: machine, ts, nonce, sig: b64u(new Uint8Array(sig)) }),
  });
  return { status: r.status, text: await r.text() };
}

const login = await fetch(BASE + "/api/admin/login", {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ password: "liantong-test-pw" }),
});
const cookie = (login.headers.get("set-cookie") || "").split(";")[0];
check("admin login", login.status === 200 && cookie.startsWith("sess="));
const badLogin = await j("/api/admin/login", { password: "wrong" });
check("admin bad password rejected", badLogin.status === 401);

const M1 = "TESTMACH000000001", M2 = "TESTMACH000000002", M3 = "TESTMACH000000003";
const issue1 = await j("/api/admin/issue", { machineCode: M1, days: 30, note: "测试客户甲", mode: "code" }, { cookie });
check("issue code", issue1.status === 200 && /^V2O-/.test(issue1.data.code || ""), issue1.data.code);
const issue2 = await j("/api/admin/issue", { machineCode: M2, days: 365, note: "", mode: "code" }, { cookie });

const dev1 = await newDeviceKey();
const badActivate = await j("/api/activate", { machineCode: M1, code: "V2O-XXXXX-XXXXX-XXXXX-XXXXX", pubkey: dev1.pubkey });
check("activate wrong code rejected", badActivate.status === 403 && badActivate.data.reason === "not_found");
const crossActivate = await j("/api/activate", { machineCode: M1, code: issue2.data.code, pubkey: dev1.pubkey });
check("code bound to other machine rejected", crossActivate.status === 403 && crossActivate.data.reason === "bound_other");
const act1 = await j("/api/activate", { machineCode: M1, code: issue1.data.code, pubkey: dev1.pubkey, platform: "android-test" });
check("activate ok + token", act1.status === 200 && !!act1.data.token && !!act1.data.expires_at);

const val1 = await signedCall("/api/validate", M1, dev1.kp);
check("signed validate ok", val1.status === 200 && JSON.parse(val1.text).ok === true, val1.text.slice(0, 80));
const valTok = await j("/api/validate", { machineCode: M1, token: act1.data.token });
check("token validate ok", valTok.status === 200 && valTok.data.ok === true);
const valBadTok = await j("/api/validate", { machineCode: M1, token: "bogus" });
check("bad token rejected", valBadTok.status === 403);

const ts = Math.floor(Date.now() / 1000);
const wrongSig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, dev1.kp.privateKey,
  new TextEncoder().encode("something else"));
const valBadSig = await j("/api/validate", { machineCode: M1, ts, nonce: "n1", sig: b64u(new Uint8Array(wrongSig)) });
check("bad signature rejected", valBadSig.status === 403 && valBadSig.data.reason === "bad_sig");

const sub1 = await signedCall("/api/subscription", M1, dev1.kp);
const subHash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(sub1.text));
check("subscription delivered", sub1.status === 200 && sub1.text.length > 500,
  `len=${sub1.text.length} sha256=${Buffer.from(subHash).toString("hex").slice(0, 16)}…`);
const subDeny = await j("/api/subscription", { machineCode: M1, token: "bogus" });
check("subscription denied without auth", subDeny.status === 403);

// claim flow (direct-open)
const open3 = await j("/api/admin/issue", { machineCode: M3, days: 90, note: "直开户", mode: "open" }, { cookie });
const dev3 = await newDeviceKey();
const claim3 = await j("/api/claim", { machineCode: M3, pubkey: dev3.pubkey, platform: "android-test" });
check("claim direct-open ok", open3.status === 200 && claim3.status === 200 && !!claim3.data.token);
const claimAgain = await j("/api/claim", { machineCode: M3, pubkey: dev3.pubkey });
check("second claim rejected", claimAgain.status === 404);

// revoke / restore / expire
const revoke = await j("/api/admin/action", { machineCode: M1, action: "revoke" }, { cookie });
const valRevoked = await signedCall("/api/validate", M1, dev1.kp);
check("revoked device locked out", revoke.status === 200 && valRevoked.status === 403 && JSON.parse(valRevoked.text).reason === "revoked");
const restore = await j("/api/admin/action", { machineCode: M1, action: "restore" }, { cookie });
const valRestored = await signedCall("/api/validate", M1, dev1.kp);
check("restore works", restore.status === 200 && valRestored.status === 200);
const ext = await j("/api/admin/action", { machineCode: M1, action: "extend", days: -10000 }, { cookie });
const valExpired = await signedCall("/api/validate", M1, dev1.kp);
check("expired license locked out", ext.status === 200 && valExpired.status === 403 && JSON.parse(valExpired.text).reason === "expired");

const devList = await fetch(BASE + "/api/admin/devices", { headers: { cookie } }).then((r) => r.json());
check("device table lists devices", devList.ok && devList.devices.length >= 2, `${devList.devices?.length} devices`);
const noAuthList = await fetch(BASE + "/api/admin/devices").then((r) => r.status);
check("device table requires login", noAuthList === 401);

console.log(`\n==== ${pass} passed, ${fail} failed ====`);
process.exit(fail ? 1 : 0);
