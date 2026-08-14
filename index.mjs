export default {
  async fetch(request, env) {
    const VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
    const ALLOW_ORIGIN = [
      "https://metro.littleliu016.dpdns.org",
    ];

    const corsHeaders = {
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type"
    };

    if (request.method === "OPTIONS") {
      const origin = request.headers.get("origin") || "";
      if (ALLOW_ORIGIN.includes(origin)) {
        corsHeaders["Access-Control-Allow-Origin"] = origin;
      }
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);
    if (url.pathname !== "/api/verify" || request.method !== "POST") {
      return new Response("Not Found", { status: 404 });
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return Response.json({ success: false, msg: "请求体错误" }, { status: 400 });
    }
    const { token } = body;
    const clientIP = request.headers.get("CF-Connecting-IP");

    if (!token) {
      return Response.json({ success: false, msg: "缺少验证令牌" }, { status: 400 });
    }

    const formData = new FormData();
    formData.append("secret", env.TURNSTILE_SECRET);
    formData.append("response", token);
    if (clientIP) formData.append("remoteip", clientIP);

    const verifyRes = await fetch(VERIFY_URL, {
      method: "POST",
      body: formData
    });
    const verifyData = await verifyRes.json();

    const origin = request.headers.get("origin") || "";
    if (ALLOW_ORIGIN.includes(origin)) {
      corsHeaders["Access-Control-Allow-Origin"] = origin;
    }

    return Response.json({
      success: verifyData.success,
      msg: verifyData.success ? "验证通过" : "人机校验失败"
    }, { headers: corsHeaders });
  }
};
