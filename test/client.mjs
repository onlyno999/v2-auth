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

// issued-but-unused codes are listed for the seller, and can be killed
const listWithIssued = await (await fetch(BASE + "/api/admin/devices", { headers: { cookie } })).json();
const issuedM2 = (listWithIssued.issued || []).find((i) => i.machine === M2);
check("issued code listed before activation", !!issuedM2 && issuedM2.status === "issued");
check("issued code re-copyable via vault", issuedM2.code === issue2.data.code, issuedM2.code);
const killCode = await j("/api/admin/action", { licKey: issuedM2.licKey, action: "revoke" }, { cookie });
const dev2x = await newDeviceKey();
const deadActivate = await j("/api/activate", { machineCode: M2, code: issue2.data.code, pubkey: dev2x.pubkey });
check("revoked unused code cannot activate", killCode.status === 200 && deadActivate.status === 403 && deadActivate.data.reason === "revoked");
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

// distributor channel: separate subscription URL (SUB_URL_DIST)
const M4 = "TESTMACH000000004";
const issueD = await j("/api/admin/issue", { machineCode: M4, days: 30, note: "分销客户", mode: "code", channel: "dist" }, { cookie });
const dev4 = await newDeviceKey();
const act4 = await j("/api/activate", { machineCode: M4, code: issueD.data.code, pubkey: dev4.pubkey });
const subDist = await signedCall("/api/subscription", M4, dev4.kp);
const expectedDist = await (await fetch("http://127.0.0.1:8899/sub_dist.txt")).text();
check("dist channel gets dist subscription",
  act4.status === 200 && subDist.status === 200 && subDist.text === expectedDist,
  `len=${subDist.text.length}`);

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

// session token via header (localStorage path): refresh must not
// demand the password again while the token is valid.
const login2 = await j("/api/admin/login", { password: "liantong-test-pw" });
const sessToken = login2.data.session;
check("login returns session token", login2.status === 200 && typeof sessToken === "string" && sessToken.includes("."));
const headerAuth = await fetch(BASE + "/api/admin/devices", { headers: { "x-session": sessToken } });
check("x-session header authenticates", headerAuth.status === 200);
const badHeaderAuth = await fetch(BASE + "/api/admin/devices", { headers: { "x-session": "bogus.token" } });
check("bogus x-session rejected", badHeaderAuth.status === 401);

// ---------- 3. distributor portal (/mmm) ----------
const createDist = await j("/api/admin/dist", { action: "create", slug: "mmm", name: "分销老王", password: "dist-pw-1", quota: 2 }, { cookie });
check("admin creates distributor", createDist.status === 200 && createDist.data.ok === true);
const portal = await fetch(BASE + "/mmm");
const portalHtml = await portal.text();
check("portal /mmm serves distributor console", portal.status === 200 && portalHtml.includes("分销商后台"));
check("unknown slug 404s", (await fetch(BASE + "/nosuchslug")).status === 404);
const distBadLogin = await j("/api/dist/login", { slug: "mmm", password: "nope" });
check("dist bad password rejected", distBadLogin.status === 401);
const renameDist = await j("/api/admin/dist", { slug: "mmm", action: "rename", name: "老王本王" }, { cookie });
const distList2 = await (await fetch(BASE + "/api/admin/dist", { headers: { cookie } })).json();
check("distributor renamed", renameDist.status === 200 && (distList2.distributors || []).some((d) => d.slug === "mmm" && d.name === "老王本王"));
const distLoginRes = await fetch(BASE + "/api/dist/login", {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ slug: "mmm", password: "dist-pw-1" }),
});
const dcookie = (distLoginRes.headers.get("set-cookie") || "").split(";")[0];
check("dist login ok", distLoginRes.status === 200 && dcookie.startsWith("dsess="));
const dme = await fetch(BASE + "/api/dist/me", { headers: { cookie: dcookie } }).then((r) => r.json());
check("dist me + quota", dme.ok === true && dme.remaining === 2);
const M5 = "TESTMACH000000005", M6 = "TESTMACH000000006", M7 = "TESTMACH000000007";
const dIssue1 = await j("/api/dist/issue", { machineCode: M5, days: 30, note: "王客户", mode: "code" }, { cookie: dcookie });
check("dist issues code", dIssue1.status === 200 && /^V2O-/.test(dIssue1.data.code || ""));
const dPerm = await j("/api/dist/issue", { machineCode: M6, days: 0, note: "" }, { cookie: dcookie });
check("dist permanent rejected (max 1y rule)", dPerm.status === 400);
const dev5 = await newDeviceKey();
const act5 = await j("/api/activate", { machineCode: M5, code: dIssue1.data.code, pubkey: dev5.pubkey });
const sub5 = await signedCall("/api/subscription", M5, dev5.kp);
check("dist customer pulls DIST subscription", act5.status === 200 && sub5.status === 200 && sub5.text === expectedDist);
const dIssue2 = await j("/api/dist/issue", { machineCode: M6, days: 90, note: "", mode: "code" }, { cookie: dcookie });
const dIssue3 = await j("/api/dist/issue", { machineCode: M7, days: 90, note: "", mode: "code" }, { cookie: dcookie });
check("quota exhausted at limit", dIssue2.status === 200 && dIssue3.status === 403 && dIssue3.data.reason === "quota_exhausted");
const dDevices = await fetch(BASE + "/api/dist/devices", { headers: { cookie: dcookie } }).then((r) => r.json());
check("dist sees only own customers", dDevices.ok === true && dDevices.devices.length === 1 && dDevices.devices[0].machine === M5);
const disableDist = await j("/api/admin/dist", { slug: "mmm", action: "disable" }, { cookie });
const distLoginDisabled = await j("/api/dist/login", { slug: "mmm", password: "dist-pw-1" });
check("disabled distributor cannot log in", disableDist.status === 200 && distLoginDisabled.status === 401);

// distributor self-setup: admin creates WITHOUT a password; the
// distributor sets his own on first visit (saved hashed in KV).
const createDist2 = await j("/api/admin/dist", { action: "create", slug: "abc", name: "自设密码分销", quota: 5 }, { cookie });
const state1 = await (await fetch(BASE + "/api/dist/state?slug=abc")).json();
check("create without password -> needs_setup", createDist2.status === 200 && state1.ok === true && state1.needs_setup === true);
const loginBeforeSetup = await j("/api/dist/login", { slug: "abc", password: "whatever1" });
check("login blocked before setup", loginBeforeSetup.status === 401 && loginBeforeSetup.data.reason === "needs_setup");
const setupRes = await fetch(BASE + "/api/dist/setup", {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ slug: "abc", password: "self-set-1" }),
});
const sCookie = (setupRes.headers.get("set-cookie") || "").split(";")[0];
check("distributor sets own password + auto-login", setupRes.status === 200 && sCookie.startsWith("dsess="));
const setupAgain = await j("/api/dist/setup", { slug: "abc", password: "another-1" });
check("second setup rejected", setupAgain.status === 409);
const resetPw = await j("/api/admin/dist", { slug: "abc", action: "resetpw" }, { cookie });
const state2 = await (await fetch(BASE + "/api/dist/state?slug=abc")).json();
check("admin reset -> needs_setup again", resetPw.status === 200 && state2.needs_setup === true);

// delete: only a disabled account can be removed, then the slug is gone
const delActive = await j("/api/admin/dist", { slug: "abc", action: "delete" }, { cookie });
check("delete of active account refused", delActive.status === 400);
await j("/api/admin/dist", { slug: "abc", action: "disable" }, { cookie });
const delOk = await j("/api/admin/dist", { slug: "abc", action: "delete" }, { cookie });
const state3 = await fetch(BASE + "/api/dist/state?slug=abc");
check("disabled account deleted, slug gone", delOk.status === 200 && state3.status === 404);

// device hard delete: row + license gone, token useless afterwards
const delDev = await j("/api/admin/action", { machineCode: M1, action: "delete" }, { cookie });
const afterDel = await (await fetch(BASE + "/api/admin/devices", { headers: { cookie } })).json();
check("device deleted from table", delDev.status === 200 && !(afterDel.devices || []).some((d) => d.machine === M1));
const valAfterDel = await j("/api/validate", { machineCode: M1, token: act1.data.token });
check("validate denied after device delete", valAfterDel.status === 403);

// ---- guest customers (admin-managed; /g/<id> page + sealed link) ----
const expectedSub = readFileSync(new URL("./fixtures/sub_main.txt", import.meta.url), "utf8");
const gNoAuth = await j("/api/admin/guest", { action: "create", username: "x", password: "guest-pw-1", days: 30 });
check("guest admin api requires login", gNoAuth.status === 401);
const gCreate = await j("/api/admin/guest", { action: "create", username: "小火箭阿强", password: "guest-pw-1", days: 30, note: "游客甲" }, { cookie });
check("admin creates guest", gCreate.status === 200 && !!gCreate.data.id && gCreate.data.path === "/g/" + gCreate.data.id, JSON.stringify(gCreate.data).slice(0, 90));
const GID = gCreate.data.id;
const gDup = await j("/api/admin/guest", { action: "create", username: "小火箭阿强", password: "guest-pw-2", days: 30 }, { cookie });
check("duplicate guest username rejected", gDup.status === 409);
const gWeak = await j("/api/admin/guest", { action: "create", username: "弱口令游客", password: "123", days: 30 }, { cookie });
check("weak guest password rejected", gWeak.status === 400);
const gList = await (await fetch(BASE + "/api/admin/guest", { headers: { cookie } })).json();
check("guest listed for admin", gList.ok === true && (gList.guests || []).some((g) => g.id === GID && g.username === "小火箭阿强" && !("pw_hash" in g)));
const gPage = await fetch(BASE + "/g/" + GID);
const gPageHtml = await gPage.text();
check("guest page pre-login shows password box only", gPage.status === 200 && gPageHtml.includes('id="pw"') && !gPageHtml.includes("/s/"));
check("unknown guest page 404s", (await fetch(BASE + "/g/zzzzzzzzzzzz")).status === 404);
const gOldEndpoint = await j("/api/guest/link", { code: "whatever" });
check("old code-exchange endpoint gone", gOldEndpoint.status === 404 || gOldEndpoint.status === 405);
const gMeAnon = await fetch(BASE + "/api/guest/me");
check("guest me requires login", gMeAnon.status === 401);
const gBadPw = await j("/api/guest/login", { id: GID, password: "nope-nope" });
check("guest bad password rejected", gBadPw.status === 401 && gBadPw.data.reason === "bad_password");
const gLoginRes = await fetch(BASE + "/api/guest/login", {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ id: GID, password: "guest-pw-1" }),
});
const gcookie = (gLoginRes.headers.get("set-cookie") || "").split(";")[0];
check("guest login ok", gLoginRes.status === 200 && gcookie.startsWith("gsess="));
const gMe = await (await fetch(BASE + "/api/guest/me", { headers: { cookie: gcookie } })).json();
check("guest me: remaining time + sealed link only, no real address",
  gMe.ok === true && gMe.username === "小火箭阿强" && gMe.days_left >= 29 && gMe.days_left <= 30 &&
  typeof gMe.link === "string" && gMe.link.includes("/s/") && !JSON.stringify(gMe).includes("8899"),
  JSON.stringify(gMe).slice(0, 110));
const gFetch = await fetch(gMe.link);
check("guest link serves subscription content", gFetch.status === 200 && (await gFetch.text()) === expectedSub);
check("tampered guest link rejected", (await fetch(BASE + "/s/AAAAbbbbCCCCdddd")).status === 404);
await j("/api/admin/guest", { id: GID, action: "disable" }, { cookie });
check("guest link dead after disable", (await fetch(gMe.link)).status === 403);
const gLoginOff = await j("/api/guest/login", { id: GID, password: "guest-pw-1" });
check("disabled guest cannot log in", gLoginOff.status === 403 && gLoginOff.data.reason === "disabled");
const gMeOff = await fetch(BASE + "/api/guest/me", { headers: { cookie: gcookie } });
check("disabled guest session rejected", gMeOff.status === 401);
await j("/api/admin/guest", { id: GID, action: "enable" }, { cookie });
check("guest link back after enable", (await fetch(gMe.link)).status === 200);
await j("/api/admin/guest", { id: GID, action: "extend", days: -10000 }, { cookie });
check("expired guest link dead", (await fetch(gMe.link)).status === 403);
await j("/api/admin/guest", { id: GID, action: "extend", days: 10001 }, { cookie });
check("extended guest link alive again", (await fetch(gMe.link)).status === 200);
await j("/api/admin/guest", { id: GID, action: "password", password: "guest-pw-9" }, { cookie });
check("old guest password dead after change", (await j("/api/guest/login", { id: GID, password: "guest-pw-1" })).status === 401);
check("new guest password works", (await j("/api/guest/login", { id: GID, password: "guest-pw-9" })).status === 200);
const gDelActive = await j("/api/admin/guest", { id: GID, action: "delete" }, { cookie });
check("delete of active guest refused", gDelActive.status === 400);
await j("/api/admin/guest", { id: GID, action: "disable" }, { cookie });
const gDel = await j("/api/admin/guest", { id: GID, action: "delete" }, { cookie });
check("guest deleted, link + page gone", gDel.status === 200 && (await fetch(gMe.link)).status === 404 && (await fetch(BASE + "/g/" + GID)).status === 404);

// ---- minute-level durations (admin licenses + guests) ----
const MM1 = "TESTMACH000000101", MM2 = "TESTMACH000000102", MM3 = "TESTMACH000000103";
const minIssue = await j("/api/admin/issue", { machineCode: MM1, durationValue: 5, durationUnit: "minute", note: "五分钟客户", mode: "code" }, { cookie });
check("issue 5-minute code", minIssue.status === 200 && /^V2O-/.test(minIssue.data.code || ""));
const devM1 = await newDeviceKey();
const actM1 = await j("/api/activate", { machineCode: MM1, code: minIssue.data.code, pubkey: devM1.pubkey });
const listM = await (await fetch(BASE + "/api/admin/devices", { headers: { cookie } })).json();
const rowM1 = (listM.devices || []).find((d) => d.machine === MM1);
check("5-minute expiry exact (expires_at - activated_at == 300)",
  actM1.status === 200 && !!rowM1 && rowM1.lic.expires_at - rowM1.lic.activated_at === 300,
  rowM1 ? `diff=${rowM1.lic.expires_at - rowM1.lic.activated_at}` : "row missing");
const valM1 = await j("/api/validate", { machineCode: MM1, token: actM1.data.token });
check("5-minute validate remain_sec in range", valM1.status === 200 && valM1.data.remain_sec > 0 && valM1.data.remain_sec <= 300, `remain=${valM1.data.remain_sec}`);
const oneIssue = await j("/api/admin/issue", { machineCode: MM2, durationValue: 1, durationUnit: "minute", note: "一分钟客户", mode: "code" }, { cookie });
const devM2 = await newDeviceKey();
await j("/api/activate", { machineCode: MM2, code: oneIssue.data.code, pubkey: devM2.pubkey });
const listM2 = await (await fetch(BASE + "/api/admin/devices", { headers: { cookie } })).json();
const rowM2 = (listM2.devices || []).find((d) => d.machine === MM2);
check("1-minute expiry exact (diff == 60)", !!rowM2 && rowM2.lic.expires_at - rowM2.lic.activated_at === 60,
  rowM2 ? `diff=${rowM2.lic.expires_at - rowM2.lic.activated_at}` : "row missing");
const minIssued = await j("/api/admin/issue", { machineCode: MM3, durationValue: 5, durationUnit: "minute", note: "未激活五分钟", mode: "code" }, { cookie });
const listM3 = await (await fetch(BASE + "/api/admin/devices", { headers: { cookie } })).json();
const issuedM3 = (listM3.issued || []).find((i) => i.machine === MM3);
check("issued list shows 5分钟, not 0 天", minIssued.status === 200 && !!issuedM3 && issuedM3.duration_text === "5分钟", issuedM3 ? issuedM3.duration_text : "missing");
const badDur = await j("/api/admin/issue", { machineCode: MM3, durationValue: 0, durationUnit: "minute", mode: "code" }, { cookie });
check("zero-minute duration rejected", badDur.status === 400);
const badUnit = await j("/api/admin/issue", { machineCode: MM3, durationValue: 5, durationUnit: "week", mode: "code" }, { cookie });
check("bogus duration unit rejected", badUnit.status === 400);
// guest with a 1-minute account: login, minute-level remaining, expiry
const gmCreate = await j("/api/admin/guest", { action: "create", username: "一分钟游客", password: "guest-pw-1", durationValue: 1, durationUnit: "minute" }, { cookie });
check("admin creates 1-minute guest", gmCreate.status === 200 && !!gmCreate.data.id, JSON.stringify(gmCreate.data).slice(0, 80));
const GMID = gmCreate.data.id;
const gmLogin = await j("/api/guest/login", { id: GMID, password: "guest-pw-1" });
check("1-minute guest logs in", gmLogin.status === 200 && typeof gmLogin.data.session === "string");
const gmMe = await (await fetch(BASE + "/api/guest/me", { headers: { "x-gsess": gmLogin.data.session } })).json();
check("1-minute guest sees minute-level remaining", gmMe.ok === true && gmMe.remain_sec > 0 && gmMe.remain_sec <= 60 && gmMe.minutes_left === 1, `remain_sec=${gmMe.remain_sec}`);
check("1-minute guest link serves before expiry", (await fetch(gmMe.link)).status === 200);
await j("/api/admin/guest", { id: GMID, action: "extend", days: -1 }, { cookie });
check("guest link dies once past expiry", (await fetch(gmMe.link)).status === 403);
const gmLoginExpired = await j("/api/guest/login", { id: GMID, password: "guest-pw-1" });
check("expired guest cannot log in", gmLoginExpired.status === 403 && gmLoginExpired.data.reason === "expired");
await j("/api/admin/guest", { id: GMID, action: "extend", days: 2 }, { cookie });
check("guest link alive again after extend", (await fetch(gmMe.link)).status === 200);
await j("/api/admin/guest", { id: GMID, action: "disable" }, { cookie });
await j("/api/admin/guest", { id: GMID, action: "delete" }, { cookie });

// ---- legacy offline-code conversion (fixture key; skipped if absent) ----
import { readFileSync } from "node:fs";
let legacyFx = null;
try { legacyFx = JSON.parse(readFileSync(new URL("./fixtures/legacy_test_key.json", import.meta.url), "utf8")); } catch {}
if (legacyFx) {
  const B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  const b32enc = (bytes) => {
    let s = "", buf = 0, bits = 0;
    for (const b of bytes) { buf = (buf << 8) | b; bits += 8; while (bits >= 5) { bits -= 5; s += B32[(buf >> bits) & 31]; } }
    if (bits > 0) s += B32[(buf << (5 - bits)) & 31];
    return s;
  };
  const group = (s) => s.match(/.{1,4}/g).join("-");
  const priv = await crypto.subtle.importKey("jwk", legacyFx.jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const devL = await newDeviceKey();
  async function makeLegacyCode(machineHash, expiryMinutes) {
    const payload = new Uint8Array(63);
    payload[0] = 0x03;
    payload[1] = (expiryMinutes >>> 24) & 0xff; payload[2] = (expiryMinutes >>> 16) & 0xff;
    payload[3] = (expiryMinutes >>> 8) & 0xff; payload[4] = expiryMinutes & 0xff;
    payload.set(machineHash, 5);
    crypto.getRandomValues(payload.subarray(15));
    const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, priv, payload));
    const blob = new Uint8Array(127); blob.set(payload); blob.set(sig, 63);
    return group(b32enc(blob));
  }
  const hashL = new Uint8Array(10); crypto.getRandomValues(hashL);
  const machineL = group(b32enc(hashL));
  const futureMin = Math.floor(Date.now() / 60000) + 60 * 24 * 30;
  const legacyCode = await makeLegacyCode(hashL, futureMin);
  const conv = await j("/api/legacy", { machineCode: machineL, code: legacyCode, pubkey: devL.pubkey, platform: "android-test" });
  check("legacy code converts + token issued", conv.status === 200 && !!conv.data.token, JSON.stringify(conv.data).slice(0, 80));
  const valL = await j("/api/validate", { machineCode: machineL, token: conv.data.token });
  check("converted device validates", valL.status === 200 && valL.data.ok === true);
  const convWrongMachine = await j("/api/legacy", { machineCode: M2, code: legacyCode, pubkey: devL.pubkey });
  check("legacy code bound to its machine", convWrongMachine.status === 403 && convWrongMachine.data.reason === "bound_other");
  const expiredCode = await makeLegacyCode(hashL, Math.floor(Date.now() / 60000) - 60);
  const convExpired = await j("/api/legacy", { machineCode: machineL, code: expiredCode, pubkey: devL.pubkey });
  check("expired legacy code refused", convExpired.status === 403 && convExpired.data.reason === "expired");
  const tampered = legacyCode.slice(0, -2) + (legacyCode.endsWith("A") ? "B" : "A") + legacyCode.slice(-1);
  const convBad = await j("/api/legacy", { machineCode: machineL, code: tampered, pubkey: devL.pubkey });
  check("tampered legacy code refused", convBad.status === 403);
}

console.log(`\n==== ${pass} passed, ${fail} failed ====`);
process.exit(fail ? 1 : 0);
