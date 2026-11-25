const COOKIE_NAME = "madarek_session";
const SESSION_DURATION = 8 * 60 * 60;

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...headers
    }
  });
}

function bytesToHex(bytes) {
  return Array.from(new Uint8Array(bytes))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

async function hmac(value, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  return bytesToHex(
    await crypto.subtle.sign(
      "HMAC",
      key,
      new TextEncoder().encode(value)
    )
  );
}

async function hash(value) {
  return new Uint8Array(
    await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(value)
    )
  );
}

async function safeEqual(a, b) {
  const x = await hash(a);
  const y = await hash(b);

  let difference = 0;
  for (let i = 0; i < x.length; i++) {
    difference |= x[i] ^ y[i];
  }

  return difference === 0;
}

function getCookie(request, name) {
  const cookies = request.headers.get("Cookie") || "";
  const item = cookies.split(";").map(v => v.trim())
    .find(v => v.startsWith(name + "="));

  return item ? item.slice(name.length + 1) : null;
}

async function validSession(request, secret) {
  const token = getCookie(request, COOKIE_NAME);
  if (!token) return false;

  const parts = token.split(".");
  if (parts.length !== 2) return false;

  const [timestamp, signature] = parts;

  if (!/^\d+$/.test(timestamp)) return false;

  const issuedAt = Number(timestamp);
  const now = Math.floor(Date.now() / 1000);

  if (issuedAt > now || now - issuedAt > SESSION_DURATION) {
    return false;
  }

  const expected = await hmac(timestamp, secret);
  return safeEqual(signature, expected);
}

export async function onRequest(context) {
  const { request, env } = context;

  if (!env.ORGANIZER_USERNAME ||
      !env.ORGANIZER_PASSWORD ||
      !env.ORGANIZER_SESSION_SECRET) {
    return json({ error: "إعدادات تسجيل الدخول غير مكتملة." }, 500);
  }

  if (request.method === "GET") {
    const authenticated = await validSession(
      request,
      env.ORGANIZER_SESSION_SECRET
    );

    return json({ authenticated });
  }

  if (request.method === "DELETE") {
    return json(
      { success: true },
      200,
      {
        "Set-Cookie":
          `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`
      }
    );
  }

  if (request.method !== "POST") {
    return json({ error: "طريقة الطلب غير مدعومة." }, 405);
  }

  let data;

  try {
    data = await request.json();
  } catch {
    return json({ error: "بيانات الطلب غير صحيحة." }, 400);
  }

  const username = String(data.username || "");
  const password = String(data.password || "");

  const usernameValid = await safeEqual(
    username,
    env.ORGANIZER_USERNAME
  );

  const passwordValid = await safeEqual(
    password,
    env.ORGANIZER_PASSWORD
  );

  if (!usernameValid || !passwordValid) {
    return json({ error: "اسم المستخدم أو كلمة المرور غير صحيحة." }, 401);
  }

  const timestamp = String(Math.floor(Date.now() / 1000));
  const signature = await hmac(
    timestamp,
    env.ORGANIZER_SESSION_SECRET
  );

  return json(
    { success: true },
    200,
    {
      "Set-Cookie":
        `${COOKIE_NAME}=${timestamp}.${signature}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_DURATION}`
    }
  );
}
