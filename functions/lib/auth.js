
const COOKIE_NAME = "madarek_session";
const SESSION_DURATION = 8 * 60 * 60;

async function hmac(value, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(value)
  );

  return Array.from(new Uint8Array(signature))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

async function safeEqual(a, b) {
  const encoder = new TextEncoder();

  const x = new Uint8Array(
    await crypto.subtle.digest("SHA-256", encoder.encode(a))
  );

  const y = new Uint8Array(
    await crypto.subtle.digest("SHA-256", encoder.encode(b))
  );

  let difference = 0;

  for (let i = 0; i < x.length; i++) {
    difference |= x[i] ^ y[i];
  }

  return difference === 0;
}

export async function verifyOrganizerSession(request, env) {
  if (!env.ORGANIZER_SESSION_SECRET) return false;

  const cookies = request.headers.get("Cookie") || "";
  const item = cookies.split(";")
    .map(v => v.trim())
    .find(v => v.startsWith(COOKIE_NAME + "="));

  if (!item) return false;

  const token = item.slice(COOKIE_NAME.length + 1);
  const parts = token.split(".");

  if (parts.length !== 2) return false;

  const [timestamp, signature] = parts;

  if (!/^\d+$/.test(timestamp)) return false;

  const issuedAt = Number(timestamp);
  const now = Math.floor(Date.now() / 1000);

  if (
    !Number.isSafeInteger(issuedAt) ||
    issuedAt > now ||
    now - issuedAt > SESSION_DURATION
  ) {
    return false;
  }

  const expected = await hmac(
    timestamp,
    env.ORGANIZER_SESSION_SECRET
  );

  return safeEqual(signature, expected);
}
