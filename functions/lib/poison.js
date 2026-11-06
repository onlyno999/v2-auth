// ---------- poisoned subscription for expired licenses ----------
// Every server address in the subscription becomes one dead IP:
// raw IPv4s anywhere in the text, the authority host of every
// share URI (domains included — an IP-only pass would leave
// domain-addressed nodes alive), and the "add" field inside
// vmess payloads. Every UUID is replaced too: a poisoned file that
// kept the real UUID would leak it — anyone could pair it with a
// live address by hand and keep connecting. Ports and names stay
// untouched so the file stays structurally valid and clients
// accept the update.
//
// Shared by the guest link (/s/<token>) and the device pull
// (/api/subscription): both serve this on the Beijing expiry day
// of an expired license, and hard-deny from the next day on.
const FAKE_IP = "114.115.116.117";
const FAKE_UUID = "00000000-0000-4000-8000-000000000000";
const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const UUID_RE = /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g;

function b64DecodeText(s) {
  const bin = atob(s.replace(/\s+/g, ""));
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}
function b64EncodeText(s) {
  const bytes = new TextEncoder().encode(s);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export function poisonSubscription(content) {
  let text = content;
  let wasB64 = false;
  try {
    const decoded = b64DecodeText(content.trim());
    if (decoded.includes("://")) {
      text = decoded;
      wasB64 = true;
    }
  } catch {
    // Not base64: transform the content as-is.
  }
  const lines = text.split(/\r?\n/).map((line) => {
    const vm = line.match(/^vmess:\/\/(.+)$/);
    if (vm) {
      try {
        let inner = b64DecodeText(vm[1]);
        inner = inner.replace(/"add"\s*:\s*"[^"]*"/, `"add": "${FAKE_IP}"`);
        inner = inner.replace(/"id"\s*:\s*"[^"]*"/, `"id": "${FAKE_UUID}"`);
        inner = inner.replace(UUID_RE, FAKE_UUID);
        inner = inner.replace(IPV4_RE, FAKE_IP);
        return "vmess://" + b64EncodeText(inner);
      } catch {
        return line.replace(UUID_RE, FAKE_UUID).replace(IPV4_RE, FAKE_IP);
      }
    }
    return line
      .replace(/^([a-z0-9+.-]+:\/\/[^/@]*@)([^/:?#]+)/i, `$1${FAKE_IP}`)
      .replace(UUID_RE, FAKE_UUID)
      .replace(IPV4_RE, FAKE_IP);
  });
  const out = lines.join("\n");
  return wasB64 ? b64EncodeText(out) : out;
}
