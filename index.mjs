export default {
  async fetch(request, env) {
    const VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
    const ALLOW_ORIGIN = [
      "https://metro.littleliu016.dpdns.org/" // 👉 改成你cdmetro前端完整域名！
    ];

    const corsHeaders = {
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type"
    };

    const url = new URL(request.url);
    // 调试用：访问根路径打印pathname
    if(url.pathname === "/"){
      return Response.json({
        debug_pathname: url.pathname,
        target: "/api/verify"
      })
    }

    if (url.pathname !== "/api/verify") {
      return new Response("Not Found", { status: 404 });
    }

    if (request.method === "OPTIONS") {
      const origin = request.headers.get("origin") || "";
      if (ALLOW_ORIGIN.includes(origin)) {
        corsHeaders["Access-Control-Allow-Origin"] = origin;
      }
      return new Response(null, { headers: corsHeaders });
    }

    if(request.method !== "POST"){
      return Response.json({success:false,msg:"仅支持POST"},{status:405})
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
