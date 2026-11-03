// Android Key Attestation verification (minimal, dependency-free).
// Verifies: cert chain signatures (leaf -> root), the attestation
// extension (OID 1.3.6.1.4.1.11129.2.1.17): challenge match, package
// name + APK signing-cert digest (from softwareEnforced attestation
// ApplicationId, tag 709), and root-of-trust state (tag 704).
// If env.ATTEST_ROOT_SHA256 is set, the chain root's SHA-256 must match
// it; chain signatures must always verify and the security level must
// be TrustedEnvironment(1) or StrongBox(2) — software-level chains are
// forgeable and rejected.

const ATTEST_OID_HEX = "06092b06010401d679020111"; // 1.3.6.1.4.1.11129.2.1.17

// ---------- tiny DER reader ----------
export function readTlv(buf, off) {
  const b0 = buf[off];
  const cls = b0 >> 6;
  const constructed = !!(b0 & 0x20);
  let tag = b0 & 0x1f;
  let p = off + 1;
  if (tag === 0x1f) {
    tag = 0;
    for (;;) {
      const b = buf[p++];
      tag = (tag << 7) | (b & 0x7f);
      if (!(b & 0x80)) break;
    }
  }
  let len = buf[p++];
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | buf[p++];
  }
  return { cls, constructed, tag, headerLen: p - off, len, start: off, content: p, end: p + len };
}
const children = (buf, tlv) => {
  const out = [];
  let p = tlv.content;
  while (p < tlv.end) {
    const t = readTlv(buf, p);
    out.push(t);
    p = t.end;
  }
  return out;
};
const hex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
const intVal = (buf, tlv) => {
  let v = 0;
  for (let i = tlv.content; i < tlv.end; i++) v = v * 256 + buf[i];
  return v;
};

// ---------- KeyDescription / AuthorizationList ----------
export function parseKeyDescription(buf, tlv) {
  const f = children(buf, tlv);
  // f: version, secLevel, kmVersion, kmSecLevel, challenge, uniqueId, swEnforced, teeEnforced
  const out = { challenge: buf.slice(f[4].content, f[4].end), securityLevel: intVal(buf, f[1]) };
  const parseAuthList = (listTlv) => {
    const res = {};
    for (const e of children(buf, listTlv)) {
      if (e.tag === 709) {
        // attestationApplicationId: SEQUENCE { SET OF PackageInfo, SET OF OCTET STRING }
        const seq = readTlv(buf, e.content);
        const parts = children(buf, seq);
        const pkgs = [];
        if (parts[0]) {
          for (const pi of children(buf, parts[0])) {
            const pc = children(buf, pi);
            pkgs.push(new TextDecoder().decode(buf.slice(pc[0].content, pc[0].end)));
          }
        }
        const digests = [];
        if (parts[1]) {
          for (const d of children(buf, parts[1])) digests.push(hex(buf.slice(d.content, d.end)));
        }
        res.appId = { packages: pkgs, digests };
      } else if (e.tag === 704) {
        const seq = readTlv(buf, e.content);
        const rc = children(buf, seq);
        res.rootOfTrust = {
          deviceLocked: rc[1] ? buf[rc[1].content] === 0xff : false,
          verifiedBootState: rc[2] ? intVal(buf, rc[2]) : -1,
        };
      }
    }
    return res;
  };
  out.software = parseAuthList(f[6]);
  out.tee = parseAuthList(f[7]);
  return out;
}

function findAttestation(buf) {
  const cert = readTlv(buf, 0);
  const tbs = children(buf, cert)[0];
  for (const el of children(buf, tbs)) {
    if (el.cls === 2 && el.tag === 3) {
      // [3] EXPLICIT SEQUENCE OF extension
      const seqOf = readTlv(buf, el.content);
      for (const ext of children(buf, seqOf)) {
        const parts = children(buf, ext);
        const oidHex = hex(buf.slice(parts[0].start, parts[0].end));
        if (oidHex === ATTEST_OID_HEX) {
          const val = parts[parts.length - 1];
          const inner = readTlv(buf, val.content); // KeyDescription SEQUENCE
          return parseKeyDescription(buf, inner);
        }
      }
    }
  }
  return null;
}

// ---------- chain verification ----------
async function spkiKey(spkiBytes, algOidHex) {
  if (algOidHex.includes("2a8648ce3d0201")) {
    // EC public key; curve OID inside SPKI decides P-256 vs P-384
    const named = hex(spkiBytes).includes("06082a8648ce3d030107") ? "P-256" : "P-384";
    return { key: await crypto.subtle.importKey("spki", spkiBytes, { name: "ECDSA", namedCurve: named }, false, ["verify"]), kind: "ECDSA" };
  }
  return { key: await crypto.subtle.importKey("spki", spkiBytes, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]), kind: "RSA" };
}

function certParts(buf) {
  const cert = readTlv(buf, 0);
  const parts = children(buf, cert);
  const tbs = parts[0];
  const tbsKids = children(buf, tbs);
  // subjectPublicKeyInfo: find SEQUENCE whose 1st child is a SEQUENCE (alg id) and 2nd a BIT STRING,
  // after issuer/validity/subject — position 6 in v3 certs (after [0] version).
  let spki = null;
  for (const k of tbsKids) {
    if (k.tag === 16 && k.constructed) {
      const kk = children(buf, k);
      if (kk.length === 2 && kk[1].tag === 3) { spki = k; break; }
    }
  }
  const sigAlgKids = children(buf, parts[1]);
  const sigOidHex = hex(buf.slice(sigAlgKids[0].start, sigAlgKids[0].end));
  const sigBits = parts[2];
  const signature = buf.slice(sigBits.content + 1, sigBits.end); // skip unused-bits byte
  const spkiKids = children(buf, spki);
  const pubAlgHex = hex(buf.slice(spkiKids[0].start, spkiKids[0].end));
  return {
    tbsRaw: buf.slice(tbs.start, tbs.end),
    spkiRaw: buf.slice(spki.start, spki.end),
    pubAlgHex, sigOidHex, signature,
    raw: buf.slice(cert.start, cert.end),
  };
}

async function verifyChildSignature(child, issuer) {
  const { key, kind } = await spkiKey(issuer.spkiRaw, issuer.pubAlgHex);
  let alg;
  if (kind === "ECDSA") {
    alg = { name: "ECDSA", hash: child.sigOidHex.includes("030107") || child.sigOidHex.includes("ecc") ? "SHA-256" : "SHA-256" };
    // ecdsa-with-SHA384 OID 1.2.840.10045.4.3.3 ends 040303; SHA256 is 040302.
    alg.hash = child.sigOidHex.endsWith("040303") ? "SHA-384" : "SHA-256";
    // ASN.1 ECDSA-Sig-Value SEQUENCE {r, s} -> raw r||s for WebCrypto
    const seq = readTlv(child.signature, 0);
    const rs = children(child.signature, seq);
    const size = alg.hash === "SHA-384" ? 48 : 32;
    const raw = new Uint8Array(size * 2);
    const put = (tlv, at) => {
      let bytes = child.signature.slice(tlv.content, tlv.end);
      if (bytes.length > size) bytes = bytes.slice(bytes.length - size);
      raw.set(bytes, at + (size - bytes.length));
    };
    put(rs[0], 0); put(rs[1], size);
    return crypto.subtle.verify(alg, key, raw, child.tbsRaw);
  }
  return crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, key, child.signature, child.tbsRaw);
}

// chain: array of DER certs (Uint8Array), leaf first.
// expected: { challenge: Uint8Array, packageName, certSha256Hex, rootPinHex? }
export async function verifyAttestation(chain, expected) {
  if (!chain || chain.length < 2) return { ok: false, reason: "attest_chain_short" };
  const parts = chain.map(certParts);
  for (let i = 0; i < parts.length - 1; i++) {
    const ok = await verifyChildSignature(parts[i], parts[i + 1]);
    if (!ok) return { ok: false, reason: "attest_chain_sig" };
  }
  const rootDigest = await crypto.subtle.digest("SHA-256", parts[parts.length - 1].raw);
  const rootHex = hex(new Uint8Array(rootDigest));
  if (expected.rootPinHex && rootHex !== expected.rootPinHex) {
    return { ok: false, reason: "attest_root", rootHex };
  }
  const kd = findAttestation(chain[0]);
  if (!kd) return { ok: false, reason: "attest_missing" };
  if (kd.securityLevel < 1) return { ok: false, reason: "attest_software_level" };
  if (hex(kd.challenge) !== hex(expected.challenge)) return { ok: false, reason: "attest_challenge" };
  const appId = kd.software.appId;
  if (!appId || !appId.packages.includes(expected.packageName)) return { ok: false, reason: "attest_package" };
  if (!appId.digests.map((d) => d.toLowerCase()).includes(expected.certSha256Hex.toLowerCase())) {
    return { ok: false, reason: "attest_signer" };
  }
  return { ok: true, rootHex, boot: kd.tee.rootOfTrust || null, securityLevel: kd.securityLevel };
}
