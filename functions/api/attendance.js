
import { isSameOrigin } from "../lib/csrf.js";
import { verifyOrganizerSession } from "../lib/auth.js";

export async function onRequest(context) {
  const { request, env } = context;

  const headers = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store"
  };

  const respond = (data, status = 200) =>
    new Response(JSON.stringify(data), { status, headers });

  if (request.method !== "POST") {
    return respond({ ok: false, message: "Method not allowed" }, 405);
  }

  if (!isSameOrigin(request)) {
  return respond({
    ok: false,
    message: "الطلب غير مصرح به."
  }, 403);
}

  const authenticated = await verifyOrganizerSession(request, env);

  if (!authenticated) {
    return respond({
      ok: false,
      message: "يجب تسجيل دخول المنظم أولاً."
    }, 401);
  }

  if (!env.APPS_SCRIPT_URL || !env.MADAREK_API_SECRET) {
    return respond({
      ok: false,
      message: "إعدادات الاتصال غير مكتملة."
    }, 500);
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return respond({
      ok: false,
      message: "طلب غير صالح."
    }, 400);
  }

  const allowedActions = [
    "verifyAttendanceTicket",
    "confirmAttendance"
  ];

  if (!allowedActions.includes(body.action)) {
    return respond({
      ok: false,
      message: "عملية غير مسموح بها."
    }, 400);
  }

  const ticketId = body.ticketId;

  if (
    typeof ticketId !== "string" ||
    ticketId.length < 10 ||
    ticketId.length > 100
  ) {
    return respond({
      ok: false,
      message: "رمز التذكرة غير صالح."
    }, 400);
  }

  try {
    const upstream = await fetch(env.APPS_SCRIPT_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        secret: env.MADAREK_API_SECRET,
        action: body.action,
        payload: {
          ticketId
        }
      }),
      redirect: "follow"
    });

    if (!upstream.ok) {
      return respond({
        ok: false,
        message: "تعذر الاتصال بنظام التسجيل."
      }, 502);
    }

    const result = await upstream.json();

    return respond(result);

  } catch (error) {
    return respond({
      ok: false,
      message: "حدث خطأ أثناء الاتصال بنظام التسجيل."
    }, 502);
  }
}
