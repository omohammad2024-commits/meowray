
// User portal + runner admin surfaces (loopback :18081, reached publicly
// through the mux as the default HTTP route). Persian RTL, dark MeowRay
// brand, zero external resources (works on blocked/offline networks).
// Pages are server-rendered string templates — no client framework, no
// heavy in-memory rendering; static shell parts are built once.

const LOGO_SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" fill="none" stroke="#5eead4" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M14 26 L10 10 L24 18"/><path d="M50 26 L54 10 L40 18"/><circle cx="32" cy="38" r="17"/><circle cx="26" cy="37" r="1.6" fill="#5eead4"/><circle cx="38" cy="37" r="1.6" fill="#5eead4"/><path d="M29 44 Q32 46.5 35 44"/><path d="M12 40 H22 M14 47 L23 44 M52 40 H42 M50 47 L41 44"/></svg>';

const PORTAL_CSS = [
  ":root{--bg:#070b12;--surface:#0d1420;--raised:#121c2e;--border:#1e2c44;--text:#e6f0fa;--muted:#93a7bf;--accent:#5eead4;--accent2:#38bdf8;--danger:#fb7185;--ok:#34d399}",
  "*{box-sizing:border-box}body{margin:0;background:radial-gradient(60rem 30rem at 80% -10%,rgba(56,189,248,.08),transparent),var(--bg);color:var(--text);font-family:Tahoma,'Segoe UI',sans-serif;line-height:1.7}",
  "a{color:var(--accent2)}main{max-width:56rem;margin:0 auto;padding:1.2rem}",
  ".brand{display:flex;align-items:center;gap:.7rem;margin:1rem 0}.brand svg{width:44px;height:44px}.brand h1{font-size:1.35rem;margin:0;letter-spacing:-.3px}.brand small{color:var(--muted);display:block;font-size:.78rem}",
  ".card{background:linear-gradient(180deg,var(--raised),var(--surface));border:1px solid var(--border);border-radius:16px;padding:1.1rem 1.2rem;margin:.8rem 0;box-shadow:0 10px 30px rgba(0,0,0,.35)}",
  ".card h2{font-size:1.02rem;margin:.1rem 0 .7rem}.muted{color:var(--muted)}.small{font-size:.85rem}",
  "label{display:block;margin:.6rem 0 .25rem;color:var(--muted);font-size:.88rem}input,select{width:100%;background:#0a111d;border:1px solid var(--border);border-radius:10px;color:var(--text);padding:.6rem .7rem;font:inherit}",
  "button,.btn{display:inline-block;background:linear-gradient(90deg,var(--accent),var(--accent2));color:#04202b;border:0;border-radius:10px;padding:.55rem 1.1rem;font:inherit;font-weight:700;cursor:pointer;text-decoration:none}",
  "button.ghost,.btn.ghost{background:transparent;color:var(--accent);border:1px solid var(--border)}button.danger{background:transparent;color:var(--danger);border:1px solid var(--danger)}",
  ".row{display:flex;gap:.6rem;flex-wrap:wrap;align-items:center}.grow{flex:1}",
  ".cfg{border:1px solid var(--border);border-radius:12px;padding:.7rem .8rem;margin:.5rem 0;background:#0a111d}.cfg code{display:block;direction:ltr;text-align:left;word-break:break-all;color:#a5f3fc;font-size:.78rem;margin-top:.3rem}",
  ".pill{display:inline-block;border:1px solid var(--border);border-radius:999px;padding:.05rem .6rem;font-size:.78rem;color:var(--muted)}",
  ".ok{color:var(--ok)}.bad{color:var(--danger)}table{width:100%;border-collapse:collapse;font-size:.88rem}th,td{border-bottom:1px solid var(--border);padding:.45rem .4rem;text-align:right}th{color:var(--muted);font-weight:600}",
  ".qr{background:#fff;border-radius:12px;padding:8px;display:inline-block;line-height:0}.bar{height:10px;background:#0a111d;border:1px solid var(--border);border-radius:99px;overflow:hidden}.bar i{display:block;height:100%;background:linear-gradient(90deg,var(--accent),var(--accent2))}",
  ".err{background:rgba(251,113,133,.12);border:1px solid var(--danger);color:#fecdd3;border-radius:10px;padding:.5rem .8rem;margin:.6rem 0}",
  "footer{color:var(--muted);font-size:.78rem;text-align:center;margin:2rem 0 1rem}",
].join("\n");

function pageShell(title, bodyHtml) {
  return "<!doctype html><html lang=\"fa\" dir=\"rtl\"><head><meta charset=\"utf-8\">" +
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">" +
    "<title>" + htmlEscape(title) + " · " + BRAND + "</title><link rel=\"icon\" href=\"/logo.svg\">" +
    "<style>" + PORTAL_CSS + "</style></head><body><main>" +
    "<div class=\"brand\">" + LOGO_SVG + "<div><h1>" + BRAND + "</h1><small>پنل اتصال شخصی شما</small></div></div>" +
    bodyHtml +
    "<footer>" + BRAND + " · " + RUNNER_VERSION + "</footer></main></body></html>";
}
function statusShell(title, bodyHtml) {
  // Boot/status page (served by the mux before the portal is up).
  return "<!doctype html><html lang=\"fa\" dir=\"rtl\"><head><meta charset=\"utf-8\">" +
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>" + htmlEscape(title) + " · " + BRAND + "</title>" +
    "<style>" + PORTAL_CSS + ".spin{width:44px;height:44px;border-radius:50%;border:4px solid var(--border);border-top-color:var(--accent);animation:sp 1s linear infinite;margin:1rem auto}@keyframes sp{to{transform:rotate(360deg)}}</style></head>" +
    "<body><main><div class=\"brand\">" + LOGO_SVG + "<div><h1>" + BRAND + "</h1><small>در حال راه‌اندازی</small></div></div>" +
    bodyHtml + "</main><script>setTimeout(function(){location.reload()},6000)</script></body></html>";
}
function fmtBytes(n) {
  if (!Number.isFinite(n)) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0, v = n;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return faDigits(v.toFixed(v >= 100 || i === 0 ? 0 : 1)) + " " + units[i];
}
function fmtDateFa(iso) {
  if (!iso) return "بدون انقضا";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "—";
  return faDigits(d.toLocaleDateString("fa-IR")) ;
}

// ---- request plumbing ----
const rateBuckets = new Map();
function rateLimited(key, max, windowMs) {
  const now = Date.now();
  const arr = (rateBuckets.get(key) || []).filter((t) => now - t < windowMs);
  if (arr.length >= max) { rateBuckets.set(key, arr); return true; }
  arr.push(now);
  rateBuckets.set(key, arr);
  return false;
}
function readBody(req, cap) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > (cap || 65536)) { reject(new Error("body too large")); req.destroy(); return; }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}
async function parseBody(req) {
  const raw = await readBody(req);
  const type = String(req.headers["content-type"] || "");
  if (type.includes("application/json")) { try { return JSON.parse(raw || "{}"); } catch (e) { return {}; } }
  const out = {};
  for (const [k, v] of new URLSearchParams(raw)) out[k] = v;
  return out;
}
function sendJson(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { "Content-Type": "application/json; charset=utf-8", "Content-Length": Buffer.byteLength(body), "Cache-Control": "no-store" });
  res.end(body);
}
function sendHtml(res, code, html) {
  res.writeHead(code, { "Content-Type": "text/html; charset=utf-8", "Content-Length": Buffer.byteLength(html), "Cache-Control": "no-store" });
  res.end(html);
}
function redirect(res, to) { res.writeHead(302, { Location: to, "Cache-Control": "no-store" }); res.end(); }
function sessionUser(req) {
  const cookie = String(req.headers.cookie || "");
  const m = cookie.match(/(?:^|;\s*)mr_session=([^;]+)/);
  if (!m) return null;
  let decoded = "";
  try { decoded = decodeURIComponent(m[1]); } catch (e) { return null; }
  const username = verifySessionToken(decoded);
  if (!username) return null;
  return findUser(username);
}
function setSessionCookie(res, username) {
  const token = makeSessionToken(username);
  const secure = CFG.publicScheme === "https" ? "; Secure" : "";
  res.setHeader("Set-Cookie", "mr_session=" + encodeURIComponent(token) + "; Path=/; HttpOnly; SameSite=Lax; Max-Age=" + 30 * 24 * 3600 + secure);
}
function publicBase(req) {
  if (RT.publicHost) return { host: RT.publicHost, port: CFG.publicPort, url: CFG.publicScheme + "://" + RT.publicHost + ":" + CFG.publicPort };
  const hostHeader = String((req && req.headers.host) || "127.0.0.1");
  const m = hostHeader.match(/^(.*):(\d+)$/);
  if (m) return { host: m[1], port: Number(m[2]), url: CFG.publicScheme + "://" + hostHeader };
  return { host: hostHeader, port: CFG.publicPort, url: CFG.publicScheme + "://" + hostHeader + ":" + CFG.publicPort };
}

// ---- auth actions (shared by HTML forms and JSON API) ----
async function authRegister(body, ip) {
  if (CFG.registration === "closed") return { code: 403, error: "ثبت‌نام بسته است." };
  // Fail CLOSED: invite mode with no configured code must never degenerate
  // into open registration (an omitted invite would satisfy "" === "").
  if (CFG.registration === "invite" && (!CFG.inviteCode || String(body.invite || "") !== CFG.inviteCode)) return { code: 403, error: "کد دعوت درست نیست." };
  const username = String(body.username || "").trim();
  const password = String(body.password || "");
  if (!/^[A-Za-z0-9_.-]{3,32}$/.test(username)) return { code: 400, error: "نام کاربری باید ۳ تا ۳۲ کاراکتر لاتین باشد." };
  if (password.length < 8 || password.length > 128) return { code: 400, error: "رمز باید ۸ تا ۱۲۸ کاراکتر باشد." };
  if (rateLimited("reg:" + ip, 5, 10 * 60 * 1000)) return { code: 429, error: "کمی صبر کنید و دوباره تلاش کنید." };
  if (findUser(username)) return { code: 409, error: "این نام کاربری گرفته شده است." };
  const user = newPortalUser(username, await hashPassword(password), "user");
  const users = readUsers();
  users.push(user);
  writeUsers(users);
  reconcileNow("register").catch(() => {});
  return { code: 201, user };
}
async function authLogin(body, ip) {
  const username = String(body.username || "").trim();
  const password = String(body.password || "");
  if (rateLimited("login:" + ip, 10, 5 * 60 * 1000)) return { code: 429, error: "تلاش‌های ورود زیاد شده؛ چند دقیقه صبر کنید." };
  const user = findUser(username);
  if (!user || !(await verifyPassword(password, user.passwordHash))) return { code: 401, error: "نام کاربری یا رمز اشتباه است." };
  if (user.enabled === false) return { code: 403, error: "این حساب غیرفعال شده است." };
  if (user.expiresAt && Date.parse(user.expiresAt) <= Date.now()) return { code: 403, error: "اشتراک این حساب به پایان رسیده است." };
  return { code: 200, user };
}

// ---- health ----
const trafficCache = new Map();
async function userTrafficCached(user) {
  const hit = trafficCache.get(user.username);
  if (hit && Date.now() - hit.at < 30000) return hit.value;
  try {
    const cookie = await getAdminCookie();
    const value = await collectUserTraffic(cookie, user);
    trafficCache.set(user.username, { at: Date.now(), value });
    return value;
  } catch (e) { return null; }
}
function buildHealth() {
  const tree = treeRssBytes(process.pid);
  let panel = 0, xray = 0, other = 0;
  for (const d of tree.detail) {
    if (d.self) continue;
    if ((d.cmd || "").includes("vpn-ui")) panel += d.rss;
    else if ((d.cmd || "").includes("xray")) xray += d.rss;
    else other += d.rss;
  }
  return {
    ok: RT.ready && RT.panelUp,
    brand: BRAND,
    version: RUNNER_VERSION,
    panelVersion: VERSIONS.panel.version,
    ready: RT.ready,
    panelUp: RT.panelUp,
    panelApiOk: RT.panelApiOk,
    inbounds: RT.inboundCount,
    clients: RT.clientCount,
    restarts: RT.restarts,
    uptimeSec: Math.floor((Date.now() - RT.bootStartedAt) / 1000),
    rssMb: {
      node: Math.round(tree.detail[0].rss / 1048576),
      panel: Math.round(panel / 1048576),
      xray: Math.round(xray / 1048576),
      other: Math.round(other / 1048576),
      total: Math.round(tree.total / 1048576),
    },
    diskFreeMb: Math.round(diskFreeBytes(P.root) / 1048576),
    lastReconcile: RT.lastReconcile,
    fatal: RT.fatal || undefined,
  };
}

// ---- pages ----
function loginPage(error) {
  return pageShell("ورود", '<div class="card"><h2>ورود به حساب</h2>' +
    (error ? '<div class="err">' + htmlEscape(error) + "</div>" : "") +
    '<form method="post" action="/login"><label>نام کاربری</label><input name="username" autocomplete="username" required>' +
    '<label>رمز عبور</label><input name="password" type="password" autocomplete="current-password" required>' +
    '<div class="row" style="margin-top:1rem"><button type="submit">ورود</button>' +
    (CFG.registration !== "closed" ? '<a class="btn ghost" href="/register">ساخت حساب</a>' : "") +
    "</div></form></div>");
}
function registerPage(error) {
  return pageShell("ثبت‌نام", '<div class="card"><h2>ساخت حساب</h2>' +
    (error ? '<div class="err">' + htmlEscape(error) + "</div>" : "") +
    '<form method="post" action="/register"><label>نام کاربری (لاتین)</label><input name="username" autocomplete="username" required>' +
    '<label>رمز عبور (حداقل ۸ کاراکتر)</label><input name="password" type="password" autocomplete="new-password" required>' +
    (CFG.registration === "invite" ? '<label>کد دعوت</label><input name="invite" required>' : "") +
    '<div class="row" style="margin-top:1rem"><button type="submit">ساخت حساب</button><a class="btn ghost" href="/login">ورود</a></div></form></div>');
}
async function dashboardPage(req, user) {
  const base = publicBase(req);
  const configs = generateUserConfigs(user, base.host, base.port);
  const subUrl = base.url + "/sub/" + user.subToken;
  const traffic = await userTrafficCached(user);
  const limitBytes = Math.round((Number(user.trafficLimitGb) || 0) * 1073741824);
  const usedPct = traffic && limitBytes > 0 ? Math.min(100, Math.round((traffic.total / limitBytes) * 100)) : 0;
  let qr = "";
  try { qr = qrSvg(subUrl, 3); } catch (e) {}
  const active = isUserActive(user);
  const body =
    '<div class="card"><h2>داشبورد ' + htmlEscape(user.username) + ' <span class="pill">' + (user.role === "admin" ? "مدیر" : "کاربر") + '</span></h2>' +
    '<div class="row"><span class="pill">وضعیت: ' + (active ? '<b class="ok">فعال</b>' : '<b class="bad">غیرفعال/منقضی</b>') + "</span>" +
    '<span class="pill">انقضا: ' + fmtDateFa(user.expiresAt) + "</span>" +
    '<span class="pill">سقف ترافیک: ' + (limitBytes ? fmtBytes(limitBytes) : "نامحدود") + "</span>" +
    (traffic ? '<span class="pill">مصرف: ' + fmtBytes(traffic.total) + "</span>" : "") + "</div>" +
    (limitBytes && traffic ? '<div class="bar" style="margin-top:.7rem"><i style="width:' + usedPct + '%"></i></div>' : "") +
    '<form method="post" action="/logout" style="margin-top:.8rem"><button class="ghost" type="submit">خروج</button>' +
    (user.role === "admin" ? ' <a class="btn ghost" href="/admin">مدیریت رانر</a>' : "") + "</form></div>" +
    '<div class="card"><h2>لینک اشتراک (Subscription)</h2>' +
    '<div class="cfg"><span>لینک اشتراک — در v2rayNG / NekoBox / Streisand وارد کنید</span><code>' + htmlEscape(subUrl) + '</code>' +
    '<div class="row" style="margin-top:.5rem"><button type="button" onclick="navigator.clipboard.writeText(this.dataset.v)" data-v="' + htmlEscape(subUrl) + '">کپی لینک</button></div></div>' +
    (qr ? '<div style="text-align:center;margin-top:.6rem"><span class="qr">' + qr + "</span></div>" : "") + "</div>" +
    '<div class="card"><h2>کانفیگ‌ها</h2>' +
    configs.map((c) => '<div class="cfg"><span>' + htmlEscape(c.name) + '</span><code>' + htmlEscape(c.uri) + '</code><div class="row" style="margin-top:.4rem"><button type="button" onclick="navigator.clipboard.writeText(this.dataset.v)" data-v="' + htmlEscape(c.uri) + '">کپی</button></div></div>').join("") +
    "</div>";
  return pageShell("داشبورد", body);
}
function healthPage() {
  const h = buildHealth();
  const row = (k, v) => "<tr><th>" + k + "</th><td>" + v + "</td></tr>";
  return pageShell("سلامت سیستم",
    '<div class="card"><h2>سلامت رانر ' + (h.ok ? '<span class="ok">● سالم</span>' : '<span class="bad">● مشکل دارد</span>') + "</h2><table>" +
    row("نسخه رانر", htmlEscape(h.version)) +
    row("پنل بالا است", h.panelUp ? "بله" : "خیر") +
    row("API پنل", h.panelApiOk ? "متصل" : "قطع") +
    row("اینباندها", faDigits(h.inbounds)) +
    row("کلاینت‌ها", faDigits(h.clients)) +
    row("ری‌استارت پنل", faDigits(h.restarts)) +
    row("آپتایم (ثانیه)", faDigits(h.uptimeSec)) +
    row("رم نود / پنل / ایکس‌ری (MB)", faDigits(h.rssMb.node) + " / " + faDigits(h.rssMb.panel) + " / " + faDigits(h.rssMb.xray)) +
    row("رم کل (MB)", faDigits(h.rssMb.total)) +
    row("دیسک آزاد (MB)", faDigits(h.diskFreeMb)) +
    row("آخرین همگام‌سازی", h.lastReconcile ? htmlEscape(h.lastReconcile.at) + " (+" + h.lastReconcile.added + " ~" + h.lastReconcile.updated + " -" + h.lastReconcile.removed + ")" : "—") +
    "</table></div>");
}
async function adminPage(req, user, msg) {
  const users = readUsers();
  const h = buildHealth();
  const rows = users.map((u) => "<tr><td>" + htmlEscape(u.username) + (u.role === "admin" ? " 👑" : "") + "</td>" +
    "<td>" + (u.trafficLimitGb ? faDigits(u.trafficLimitGb) + " GB" : "نامحدود") + "</td>" +
    "<td>" + fmtDateFa(u.expiresAt) + "</td>" +
    "<td>" + (u.enabled === false ? '<span class="bad">غیرفعال</span>' : '<span class="ok">فعال</span>') + "</td>" +
    '<td><form method="post" action="/admin/users/delete" onsubmit="return confirm(\'حذف شود؟\')"><input type="hidden" name="username" value="' + htmlEscape(u.username) + '"><button class="danger" type="submit" ' + (u.username === user.username ? "disabled" : "") + ">حذف</button></form></td></tr>").join("");
  return pageShell("مدیریت رانر",
    (msg ? '<div class="card">' + htmlEscape(msg) + "</div>" : "") +
    '<div class="card"><h2>وضعیت</h2><p class="muted small">رم کل: ' + faDigits(h.rssMb.total) + "MB · اینباند: " + faDigits(h.inbounds) + " · کلاینت: " + faDigits(h.clients) + ' · <a href="/health">صفحه سلامت</a> · <a href="/healthz">JSON</a></p></div>' +
    '<div class="card"><h2>کاربران</h2><table><tr><th>نام</th><th>سقف</th><th>انقضا</th><th>وضعیت</th><th></th></tr>' + rows + "</table>" +
    '<h2 style="margin-top:1.2rem">ساخت کاربر</h2><form method="post" action="/admin/users/create"><div class="row">' +
    '<input class="grow" name="username" placeholder="نام کاربری" required><input class="grow" name="password" type="password" placeholder="رمز" required></div>' +
    '<div class="row" style="margin-top:.5rem"><input class="grow" name="trafficGb" type="number" min="0" placeholder="سقف GB (خالی=پیش‌فرض)"><input class="grow" name="expiryDays" type="number" min="0" placeholder="روز اعتبار (خالی=پیش‌فرض)"></div>' +
    '<button type="submit" style="margin-top:.7rem">ساخت</button></form></div>' +
    '<div class="card"><h2>پشتیبان و مهاجرت</h2><p class="muted small">باندل شامل کل وضعیت (دیتابیس پنل، کاربران، تنظیمات) در یک فایل است. روی هاست تازه: فایل را کنار index.js با نام restore.tar.gz بگذارید و اجرا کنید — یا مسیرش را در MEOWRAY_RESTORE بدهید.</p>' +
    '<div class="row"><a class="btn" href="/api/admin/backup">دانلود باندل پشتیبان</a>' +
    '<form method="post" action="/admin/reconcile"><button class="ghost" type="submit">همگام‌سازی دستی کلاینت‌ها</button></form></div></div>');
}

// ---- router ----
async function portalHandle(req, res) {
  const url = new URL(req.url, "http://portal.local");
  const route = url.pathname;
  // The mux stamps the real public peer on every proxied request (and
  // overwrites any client-supplied value); direct loopback callers fall
  // back to their socket address. Auth rate limiting keys on this.
  const ip = String(req.headers["x-meowray-client-ip"] || (req.socket && req.socket.remoteAddress) || "?");
  try {
    if (route === "/logo.svg") {
      res.writeHead(200, { "Content-Type": "image/svg+xml", "Cache-Control": "public, max-age=86400" });
      return res.end(LOGO_SVG);
    }
    if (route === "/healthz") return sendJson(res, RT.ready ? 200 : 503, buildHealth());
    if (route === "/health") {
      // Human health view is an admin surface (RSS/counts detail); the
      // machine endpoint /healthz above stays public for host checks.
      const hu = sessionUser(req);
      if (!hu || hu.role !== "admin") return redirect(res, "/login");
      return sendHtml(res, 200, healthPage());
    }
    if (route.startsWith("/sub/")) {
      const token = decodeURIComponent(route.slice(5));
      const user = findUserByToken(token);
      if (!user) { res.writeHead(404, { "Content-Type": "text/plain" }); return res.end("not found"); }
      if (!isUserActive(user)) { res.writeHead(403, { "Content-Type": "text/plain; charset=utf-8" }); return res.end("subscription inactive"); }
      const base = publicBase(req);
      const links = generateUserConfigs(user, base.host, base.port).map((c) => c.uri);
      const body = Buffer.from(links.join("\n")).toString("base64");
      res.writeHead(200, {
        "Content-Type": "text/plain; charset=utf-8",
        "Profile-Title": Buffer.from(BRAND).toString("base64"),
        "Subscription-Userinfo": "upload=0; download=0; total=" + Math.round((Number(user.trafficLimitGb) || 0) * 1073741824) + "; expire=" + (user.expiresAt ? Math.floor(Date.parse(user.expiresAt) / 1000) : 0),
        "Cache-Control": "no-store",
      });
      return res.end(body);
    }
    if (route === "/api/auth/register" && req.method === "POST") {
      const r = await authRegister(await parseBody(req), ip);
      if (r.error) return sendJson(res, r.code, { ok: false, error: r.error });
      setSessionCookie(res, r.user.username);
      return sendJson(res, r.code, { ok: true, username: r.user.username });
    }
    if (route === "/api/auth/login" && req.method === "POST") {
      const r = await authLogin(await parseBody(req), ip);
      if (r.error) return sendJson(res, r.code, { ok: false, error: r.error });
      setSessionCookie(res, r.user.username);
      return sendJson(res, 200, { ok: true, username: r.user.username, role: r.user.role });
    }
    if (route === "/api/auth/logout" && req.method === "POST") {
      res.setHeader("Set-Cookie", "mr_session=; Path=/; HttpOnly; Max-Age=0");
      return sendJson(res, 200, { ok: true });
    }
    if (route === "/login") {
      if (req.method === "GET") return sendHtml(res, 200, loginPage(""));
      const r = await authLogin(await parseBody(req), ip);
      if (r.error) return sendHtml(res, 401, loginPage(r.error));
      setSessionCookie(res, r.user.username);
      return redirect(res, "/dashboard");
    }
    if (route === "/register") {
      if (CFG.registration === "closed") return sendHtml(res, 403, loginPage("ثبت‌نام بسته است."));
      if (req.method === "GET") return sendHtml(res, 200, registerPage(""));
      const r = await authRegister(await parseBody(req), ip);
      if (r.error) return sendHtml(res, r.code, registerPage(r.error));
      setSessionCookie(res, r.user.username);
      return redirect(res, "/dashboard");
    }
    if (route === "/logout" && req.method === "POST") {
      res.setHeader("Set-Cookie", "mr_session=; Path=/; HttpOnly; Max-Age=0");
      return redirect(res, "/login");
    }
    if (route === "/api/user/info" && req.method === "GET") {
      const user = sessionUser(req);
      if (!user) return sendJson(res, 401, { ok: false, error: "unauthorized" });
      const base = publicBase(req);
      const traffic = await userTrafficCached(user);
      return sendJson(res, 200, {
        ok: true,
        username: user.username, role: user.role, active: isUserActive(user),
        trafficLimitGb: user.trafficLimitGb, expiresAt: user.expiresAt,
        traffic, subUrl: base.url + "/sub/" + user.subToken,
        configs: generateUserConfigs(user, base.host, base.port),
      });
    }
    if (route === "/dashboard" || route === "/") {
      const user = sessionUser(req);
      if (!user) return redirect(res, "/login");
      return sendHtml(res, 200, await dashboardPage(req, user));
    }
    // ---- admin (role=admin session required) ----
    if (route === "/admin" || route.startsWith("/admin/") || route.startsWith("/api/admin/")) {
      const user = sessionUser(req);
      if (!user) {
        if (route.startsWith("/api/")) return sendJson(res, 401, { ok: false, error: "unauthorized" });
        return redirect(res, "/login");
      }
      if (user.role !== "admin") return sendJson(res, 403, { ok: false, error: "admin only" });
      if (route === "/admin" && req.method === "GET") return sendHtml(res, 200, await adminPage(req, user, url.searchParams.get("msg") || ""));
      if (route === "/api/admin/backup" && req.method === "GET") {
        const stamp = new Date().toISOString().replace(/[:.]/g, "-");
        const out = path.join(P.backupsDir, "meowray-backup-" + stamp + ".tar.gz");
        const info = await createBundle(P.root, out);
        log("backup bundle created: " + out + " (" + info.files + " files)");
        res.writeHead(200, {
          "Content-Type": "application/gzip",
          "Content-Disposition": "attachment; filename=\"meowray-backup.tar.gz\"",
          "Content-Length": fs.statSync(out).size,
        });
        // Downloaded backups must not accumulate inside the (quota-limited)
        // state dir — remove the file once the response is done.
        res.on("close", () => { try { fs.rmSync(out, { force: true }); } catch (e) {} });
        return fs.createReadStream(out).pipe(res);
      }
      if (route === "/api/admin/users" && req.method === "POST") {
        const body = await parseBody(req);
        const username = String(body.username || "").trim();
        if (!/^[A-Za-z0-9_.-]{3,32}$/.test(username)) return sendJson(res, 400, { ok: false, error: "bad username" });
        if (findUser(username)) return sendJson(res, 409, { ok: false, error: "exists" });
        const newPass = String(body.password || "");
        if (newPass.length < 8 || newPass.length > 128) return sendJson(res, 400, { ok: false, error: "password must be 8-128 chars" });
        const limits = {
          trafficGb: body.trafficGb != null ? Math.max(0, Number(body.trafficGb) || 0) : undefined,
          expiresAt: body.expiryDays != null ? (Number(body.expiryDays) > 0 ? new Date(Date.now() + Number(body.expiryDays) * 86400000).toISOString() : null) : undefined,
        };
        const nu = newPortalUser(username, await hashPassword(newPass), "user",
          { trafficGb: limits.trafficGb, expiresAt: limits.expiresAt });
        if (limits.trafficGb === undefined) nu.trafficLimitGb = CFG.userTrafficGb;
        const users = readUsers(); users.push(nu); writeUsers(users);
        const sync = await reconcileNow("admin-create");
        return sendJson(res, 201, { ok: true, username, subToken: nu.subToken, reconcile: sync });
      }
      if (route === "/api/admin/users/update" && req.method === "POST") {
        const body = await parseBody(req);
        const users = readUsers();
        const target = users.find((u) => u.username === String(body.username || ""));
        if (!target) return sendJson(res, 404, { ok: false, error: "no such user" });
        if (body.trafficGb != null) target.trafficLimitGb = Math.max(0, Number(body.trafficGb) || 0);
        if (body.expiryDays != null) target.expiresAt = Number(body.expiryDays) > 0 ? new Date(Date.now() + Number(body.expiryDays) * 86400000).toISOString() : null;
        if (body.enabled != null) target.enabled = body.enabled === true || body.enabled === "true";
        if (body.password != null && String(body.password) !== "") {
          const np = String(body.password);
          if (np.length < 8 || np.length > 128) return sendJson(res, 400, { ok: false, error: "password must be 8-128 chars" });
          target.passwordHash = await hashPassword(np);
        }
        writeUsers(users);
        const sync = await reconcileNow("admin-update");
        return sendJson(res, 200, { ok: true, reconcile: sync });
      }
      if ((route === "/api/admin/users/delete" && req.method === "POST") || (route === "/admin/users/delete" && req.method === "POST")) {
        const body = await parseBody(req);
        const username = String(body.username || "");
        if (username === user.username) return sendJson(res, 400, { ok: false, error: "cannot delete self" });
        const targetUser = readUsers().find((u) => u.username === username);
        const users = readUsers().filter((u) => u.username !== username);
        writeUsers(users);
        const vault = readVault();
        const retired = new Set(vault.retiredUsers || []);
        retired.add(username);
        const vaultPatch = { retiredUsers: Array.from(retired) };
        // Record the deleted user's subId so reconcile removes ONLY the
        // clients carrying it — never a foreign client sharing the name.
        if (targetUser && targetUser.subToken) {
          const rt = Object.assign({}, vault.retiredTokens || {});
          rt[username] = targetUser.subToken;
          vaultPatch.retiredTokens = rt;
        }
        writeVault(vaultPatch);
        const sync = await reconcileNow("admin-delete");
        if (route.startsWith("/admin/")) return redirect(res, "/admin?msg=" + encodeURIComponent("کاربر حذف و کلاینت‌هایش جمع شد."));
        return sendJson(res, 200, { ok: true, reconcile: sync });
      }
      if (route === "/admin/users/create" && req.method === "POST") {
        const body = await parseBody(req);
        const username = String(body.username || "").trim();
        if (!/^[A-Za-z0-9_.-]{3,32}$/.test(username) || findUser(username)) return redirect(res, "/admin?msg=" + encodeURIComponent("نام کاربری نامعتبر یا تکراری است."));
        const formPass = String(body.password || "");
        if (formPass.length < 8 || formPass.length > 128) return redirect(res, "/admin?msg=" + encodeURIComponent("رمز باید ۸ تا ۱۲۸ کاراکتر باشد."));
        const nu = newPortalUser(username, await hashPassword(formPass), "user", {
          trafficGb: body.trafficGb !== "" && body.trafficGb != null ? Math.max(0, Number(body.trafficGb) || 0) : undefined,
          expiresAt: body.expiryDays !== "" && body.expiryDays != null ? (Number(body.expiryDays) > 0 ? new Date(Date.now() + Number(body.expiryDays) * 86400000).toISOString() : null) : undefined,
        });
        if (body.trafficGb === "" || body.trafficGb == null) nu.trafficLimitGb = CFG.userTrafficGb;
        const users = readUsers(); users.push(nu); writeUsers(users);
        await reconcileNow("admin-create-form");
        return redirect(res, "/admin?msg=" + encodeURIComponent("کاربر ساخته شد: " + username));
      }
      if (route === "/admin/reconcile" && req.method === "POST") {
        await reconcileNow("admin-manual");
        return redirect(res, "/admin?msg=" + encodeURIComponent("همگام‌سازی انجام شد."));
      }
      if (route === "/api/admin/reconcile" && req.method === "POST") {
        const sync = await reconcileNow("admin-manual");
        return sendJson(res, 200, { ok: true, reconcile: sync });
      }
    }
    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    return res.end("not found");
  } catch (e) {
    log("portal error on " + route + ": " + (e && e.message));
    try { sendJson(res, 500, { ok: false, error: "internal error" }); } catch (err) {}
  }
}
function startUserServer() {
  const server = http.createServer((req, res) => { portalHandle(req, res); });
  server.on("error", (err) => { log("FATAL: portal port " + USER_PORT + " could not be opened: " + err.message); process.exit(1); });
  server.listen(USER_PORT, "127.0.0.1", () => log("portal on 127.0.0.1:" + USER_PORT));
  return server;
}
