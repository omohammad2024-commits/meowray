"use strict";
// MeowRay boot smoke — full end-to-end against a real boot of dist/index.js.
// Usage: node tests/smoke.js [srcDir] [workDir] [port]
//   srcDir: folder containing index.js + package.json (default: ../dist)
//   workDir: scratch dir for state (default: ../smoke-v1)
// Boots cold (real pinned-binary download), exercises portal + panel API +
// reconciliation, measures RSS/disk, restarts and re-checks idempotency.
const fs = require("fs");
const path = require("path");
const http = require("http");
const net = require("net");
const { spawn, execSync } = require("child_process");

const SRC = path.resolve(process.argv[2] || path.join(__dirname, "..", "dist"));
const WORK = path.resolve(process.argv[3] || path.join(__dirname, "..", "smoke-v1"));
const PORT = Number(process.argv[4] || 18100);
const ADMIN_PASS = "DummyPass#123";
const STATE = path.join(WORK, "state");
const APP = path.join(WORK, "app");

let passed = 0, failed = 0;
const failures = [];
function ok(cond, name) {
  if (cond) { passed++; }
  else { failed++; failures.push(name); console.log("FAIL: " + name); }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function request(method, route, opts) {
  opts = opts || {};
  return new Promise((resolve, reject) => {
    const body = opts.form ? new URLSearchParams(opts.form).toString()
      : opts.json ? JSON.stringify(opts.json) : (opts.body || null);
    const headers = Object.assign({}, opts.headers || {});
    if (opts.form) headers["Content-Type"] = "application/x-www-form-urlencoded";
    if (opts.json) headers["Content-Type"] = "application/json";
    if (opts.cookie) headers.Cookie = opts.cookie;
    if (body) headers["Content-Length"] = Buffer.byteLength(body);
    const req = http.request({ host: "127.0.0.1", port: PORT, path: route, method, headers }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("error", reject);
    req.setTimeout(20000, () => req.destroy(new Error("request timeout " + route)));
    if (body) req.write(body);
    req.end();
  });
}
const keepAliveAgent = new http.Agent({ keepAlive: true, maxSockets: 1 });
function requestShared(route) {
  // One single TCP connection reused across services — the regression case
  // for connection-level splicing (portal → panel → portal on one socket).
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port: PORT, path: route, method: "GET", agent: keepAliveAgent }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("error", reject);
    req.setTimeout(20000, () => req.destroy(new Error("shared request timeout " + route)));
    req.end();
  });
}
function cookieOf(res) {
  const raw = res.headers["set-cookie"] || [];
  return raw.map((c) => c.split(";")[0]).join("; ");
}
function treeRssBytes(rootPid) {
  const procs = new Map();
  for (const name of fs.readdirSync("/proc")) {
    if (!/^\d+$/.test(name)) continue;
    try {
      const status = fs.readFileSync("/proc/" + name + "/status", "utf8");
      const ppid = Number((status.match(/PPid:\s*(\d+)/) || [])[1]);
      const rss = Number((status.match(/VmRSS:\s*(\d+) kB/) || [])[1] || 0) * 1024;
      procs.set(Number(name), { ppid, rss });
    } catch (e) {}
  }
  let total = 0;
  const queue = [rootPid];
  const seen = new Set();
  while (queue.length) {
    const pid = queue.pop();
    if (seen.has(pid)) continue;
    seen.add(pid);
    const p = procs.get(pid);
    if (p) total += p.rss;
    for (const [cpid, cp] of procs) if (cp.ppid === pid) queue.push(cpid);
  }
  return total;
}
function portFree(port) {
  return new Promise((resolve) => {
    const s = net.connect({ host: "127.0.0.1", port }, () => { s.end(); resolve(false); });
    s.on("error", () => resolve(true));
    s.setTimeout(1500, () => { s.destroy(); resolve(true); });
  });
}

let child = null, childLog = "";
function boot() {
  childLog = "";
  const env = Object.assign({}, process.env);
  delete env.SELFTEST; delete env.MEOWRAY_UNIT;
  Object.assign(env, {
    PORT: String(PORT), PANEL_HOST: "127.0.0.1", PANEL_SCHEME: "http",
    MEOWRAY_ROOT: STATE, MEOWRAY_ADMIN_USER: "admin", MEOWRAY_ADMIN_PASSWORD: ADMIN_PASS,
  });
  const started = Date.now();
  child = spawn(process.execPath, ["index.js"], { cwd: APP, env, stdio: ["ignore", "pipe", "pipe"] });
  child.stdout.on("data", (d) => { childLog += d.toString(); });
  child.stderr.on("data", (d) => { childLog += d.toString(); });
  return started;
}
async function waitReady(timeoutMs) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    if (childLog.includes('"event":"ready"')) return Date.now() - t0;
    if (child.exitCode !== null) throw new Error("app exited early code=" + child.exitCode + "\n" + childLog.slice(-3000));
    await sleep(500);
  }
  throw new Error("timeout waiting for ready\n" + childLog.slice(-3000));
}
async function stop() {
  if (!child || child.exitCode !== null) return;
  child.kill("SIGTERM");
  const t0 = Date.now();
  while (child.exitCode === null && Date.now() - t0 < 15000) await sleep(250);
  if (child.exitCode === null) { child.kill("SIGKILL"); await sleep(500); }
}
async function panelList(cookie) {
  // The binary restarts xray after client changes; its API can answer
  // transient junk for a few seconds around those restarts. Retry briefly.
  let lastErr = null;
  for (let attempt = 0; attempt < 8; attempt++) {
    try {
      const res = await request("GET", "/kb/panel/api/inbounds/list", { cookie, headers: { "X-Requested-With": "XMLHttpRequest" } });
      const parsed = JSON.parse(res.body);
      if (parsed && Array.isArray(parsed.obj)) return parsed.obj;
      lastErr = new Error("unexpected list response: " + res.body.slice(0, 120));
    } catch (e) { lastErr = e; }
    await sleep(2000);
  }
  throw lastErr || new Error("panelList failed");
}
function clientsOf(inbounds, emailPrefix) {
  const out = [];
  for (const ib of inbounds) {
    const settings = typeof ib.settings === "string" ? JSON.parse(ib.settings) : ib.settings;
    for (const c of (settings && settings.clients) || []) if (String(c.email || "").startsWith(emailPrefix)) out.push({ remark: ib.remark, client: c });
  }
  return out;
}

async function main() {
  // Internal ports are fixed (18080/18081): a leftover instance from an
  // earlier run would silently contaminate this one. Refuse to start dirty.
  for (const p of [18080, 18081, PORT]) {
    if (!(await portFree(p))) { console.error("PREFLIGHT: port " + p + " is busy — kill leftover instances first"); process.exit(2); }
  }
  fs.rmSync(WORK, { recursive: true, force: true });
  fs.mkdirSync(APP, { recursive: true });
  fs.copyFileSync(path.join(SRC, "index.js"), path.join(APP, "index.js"));
  fs.copyFileSync(path.join(SRC, "package.json"), path.join(APP, "package.json"));

  // ---------- cold boot ----------
  const t0 = boot();
  const coldMs = await waitReady(420000);
  console.log("cold boot to ready: " + coldMs + "ms");
  ok(coldMs > 0, "cold boot reached ready");

  let res = await request("GET", "/healthz");
  const health = JSON.parse(res.body);
  ok(res.status === 200 && health.ok === true, "healthz ok");
  eq9(health);
  function eq9(h) { ok(h.inbounds === 9, "healthz reports 9 inbounds (got " + h.inbounds + ")"); }

  res = await request("GET", "/kb/");
  ok(res.status === 200 && /login|Login|ورود/i.test(res.body), "panel login page on /kb/");
  res = await request("GET", "/login");
  ok(res.status === 200 && res.body.includes("MeowRay"), "portal login page branded");
  res = await request("GET", "/");
  ok(res.status === 302 && String(res.headers.location || "").includes("/login"), "portal root redirects to login");
  res = await request("POST", "/api/auth/register", { json: { username: "nope123", password: "Nope#12345" } });
  ok(res.status === 403, "registration closed by default (got " + res.status + ")");

  // portal admin login (bridged to panel admin password)
  res = await request("POST", "/api/auth/login", { json: { username: "admin", password: ADMIN_PASS } });
  ok(res.status === 200, "portal admin login");
  const portalCookie = cookieOf(res);
  res = await request("POST", "/api/auth/login", { json: { username: "admin", password: "wrong" } });
  ok(res.status === 401, "portal wrong password rejected");

  // panel API login through the mux
  res = await request("POST", "/kb/login", { form: { username: "admin", password: ADMIN_PASS } });
  if (!(res.status === 200 && JSON.parse(res.body).success === true)) {
    console.log("DEBUG panel login response: status=" + res.status + " body=" + res.body.slice(0, 300));
  }
  ok(res.status === 200 && JSON.parse(res.body).success === true, "panel API login");
  const panelCookie = cookieOf(res);
  let inbounds = await panelList(panelCookie);
  ok(inbounds.length === 9, "panel has 9 inbounds (got " + inbounds.length + ")");

  // keep-alive regression: portal, panel and portal again over ONE connection
  const s1 = await requestShared("/healthz");
  ok(s1.status === 200 && JSON.parse(s1.body).ok === true, "shared-conn portal healthz");
  const s2 = await requestShared("/kb/");
  ok(s2.status === 200 && /x-ui|vpn-ui|panel/i.test(s2.body), "shared-conn panel page after portal request");
  const s3 = await requestShared("/healthz");
  ok(s3.status === 200 && JSON.parse(s3.body).ok === true, "shared-conn portal again after panel request");
  keepAliveAgent.destroy();

  // ---------- create user → reconciliation creates clients ----------
  res = await request("POST", "/api/admin/users", { cookie: portalCookie, json: { username: "smokeuser", password: "Smoke#1234", trafficGb: 5, expiryDays: 30 } });
  ok(res.status === 201, "admin creates user (got " + res.status + ")");
  const created = JSON.parse(res.body);
  const subToken = created.subToken;
  ok(typeof subToken === "string" && subToken.length >= 16, "sub token issued");
  inbounds = await panelList(panelCookie);
  let mine = clientsOf(inbounds, "smokeuser-");
  ok(mine.length === 7, "user synced into 7 managed inbounds (got " + mine.length + ")");
  const wsClient = mine.find((x) => x.remark === "VLESS-WS");
  ok(wsClient && wsClient.client.totalGB === 5 * 1073741824, "client quota = 5 GB in panel");

  // ---------- subscription ----------
  res = await request("GET", "/sub/" + subToken);
  ok(res.status === 200, "sub endpoint 200");
  const links = Buffer.from(res.body, "base64").toString("utf8").split("\n").filter(Boolean);
  ok(links.length >= 6, "sub has >= 6 links (got " + links.length + ")");
  ok(links.filter((l) => l.startsWith("vless://")).length === 4, "4 vless links");
  ok(links.some((l) => l.startsWith("vmess://")) && links.some((l) => l.startsWith("trojan://")), "vmess + trojan links");
  ok(links.every((l) => l.includes("127.0.0.1:" + PORT) || l.startsWith("vmess://")), "links point at public endpoint");
  const vmess = JSON.parse(Buffer.from(links.find((l) => l.startsWith("vmess://")).slice(8), "base64").toString("utf8"));
  ok(vmess.add === "127.0.0.1" && Number(vmess.port) === PORT, "vmess points at public endpoint");

  // ---------- reconciliation: quota change + disable propagate ----------
  res = await request("POST", "/api/admin/users/update", { cookie: portalCookie, json: { username: "smokeuser", trafficGb: 2 } });
  ok(res.status === 200, "admin updates quota");
  inbounds = await panelList(panelCookie);
  mine = clientsOf(inbounds, "smokeuser-");
  ok(mine.length === 7 && mine.every((x) => x.client.totalGB === 2 * 1073741824), "quota change propagated to all clients (MF hole fixed)");
  res = await request("POST", "/api/admin/users/update", { cookie: portalCookie, json: { username: "smokeuser", enabled: false } });
  inbounds = await panelList(panelCookie);
  mine = clientsOf(inbounds, "smokeuser-");
  ok(mine.length === 7 && mine.every((x) => x.client.enable === false), "disable propagated to all clients");
  res = await request("POST", "/api/admin/users/update", { cookie: portalCookie, json: { username: "smokeuser", enabled: true } });
  inbounds = await panelList(panelCookie);
  mine = clientsOf(inbounds, "smokeuser-");
  ok(mine.every((x) => x.client.enable === true), "re-enable propagated");

  // ---------- idle RSS + disk ----------
  // The Go panel's RSS decays for ~2 minutes after work (GOMEMLIMIT GC +
  // madvdontneed). Report both the early figure and the settled one; the
  // settled figure is what a long-running free container actually lives at.
  await sleep(15000);
  const rssEarly = treeRssBytes(child.pid);
  await sleep(90000);
  const rss = treeRssBytes(child.pid);
  const disk = Number(execSync("du -sb " + JSON.stringify(STATE)).toString().split("\t")[0]);
  console.log("RSS early: " + (rssEarly / 1048576).toFixed(1) + " MB · settled (105s idle): " + (rss / 1048576).toFixed(1) + " MB · state disk: " + (disk / 1048576).toFixed(1) + " MB");
  ok(rss > 0, "rss measured");

  // ---------- warm restart: idempotency ----------
  await stop();
  ok(await portFree(PORT), "public port free after shutdown");
  const t1 = boot();
  const warmMs = await waitReady(180000);
  console.log("warm boot to ready: " + warmMs + "ms");
  res = await request("GET", "/healthz");
  ok(res.status === 200 && JSON.parse(res.body).ok === true, "healthz ok after restart");
  res = await request("POST", "/kb/login", { form: { username: "admin", password: ADMIN_PASS } });
  const panelCookie2 = cookieOf(res);
  inbounds = await panelList(panelCookie2);
  ok(inbounds.length === 9, "still 9 inbounds after restart (got " + inbounds.length + ")");
  mine = clientsOf(inbounds, "smokeuser-");
  ok(mine.length === 7, "still exactly 7 clients after restart — no duplicates (got " + mine.length + ")");
  res = await request("GET", "/sub/" + subToken);
  const links2 = Buffer.from(res.body, "base64").toString("utf8").split("\n").filter(Boolean);
  ok(JSON.stringify(links2) === JSON.stringify(links), "sub links identical after restart");
  await stop();
  ok(await portFree(PORT), "public port free after final shutdown");

  try { fs.writeFileSync(path.join(WORK, "app.log"), childLog); } catch (e) {}
  const summary = {
    coldMs, warmMs,
    rssMB: Math.round(rss / 1048576 * 10) / 10,
    rssEarlyMB: Math.round(rssEarly / 1048576 * 10) / 10,
    diskMB: Math.round(disk / 1048576 * 10) / 10,
    inbounds: inbounds.length, clients: mine.length, links: links.length,
    asserts: { passed, failed },
  };
  console.log("SMOKE SUMMARY " + JSON.stringify(summary));
  fs.writeFileSync(path.join(WORK, "smoke-summary.json"), JSON.stringify(summary, null, 2));
  if (failures.length) console.log("failures: " + failures.join(" | "));
  process.exit(failed ? 1 : 0);
}
main().catch(async (e) => {
  console.error(e);
  try { fs.writeFileSync(path.join(WORK, "app.log"), childLog); console.log("app log tail:\n" + childLog.slice(-2500)); } catch (err) {}
  try { await stop(); } catch (err) {}
  process.exit(1);
});
