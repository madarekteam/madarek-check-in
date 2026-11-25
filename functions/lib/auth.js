
const encoder = new TextEncoder();

function toBase64Url(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function fromBase64Url(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - base64.length % 4) % 4);
  return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
}

async function sign(value, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  return toBase64Url(
    await crypto.subtle.sign("HMAC", key, encoder.encode(value))
  );
}

export async function verifyOrganizerSession(request, env) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/(?:^|;\s*)madarek_session=([^;]+)/);

  if (!match || !env.ORGANIZER_SESSION_SECRET) return false;

  const parts = match[1].split(".");
  if (parts.length !== 2) return false;

  const [timestamp, signature] = parts;
  if (!/^\d+$/.test(timestamp)) return false;

  const issuedAt = Number(timestamp);
  const now = Date.now();

  if (!Number.isSafeInteger(issuedAt)) return false;
  if (issuedAt > now + 60000) return false;
  if (now - issuedAt > 8 * 60 * 60 * 1000) return false;

  const expected = await sign(timestamp, env.ORGANIZER_SESSION_SECRET);

  if (signature.length !== expected.length) return false;

  const a = encoder.encode(signature);
  const b = encoder.encode(expected);

  let difference = 0;
  for (let i = 0; i < a.length; i++) {
    difference |= a[i] ^ b[i];
  }

  return difference === 0;
}
