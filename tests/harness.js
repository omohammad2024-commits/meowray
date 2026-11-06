"use strict";
// Shared harness for migration/failure suites (dev-only).
const fs = require("fs");
const path = require("path");
const http = require("http");
const net = require("net");
const { spawn, execSync } = require("child_process");

const PHASE0_BIN = path.join(__dirname, "..", "smoke", "vpn", "vpn-ui-amd64");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function request(port, method, route, opts) {
  opts = opts || {};
  return new Promise((resolve, reject) => {
    const body = opts.form ? new URLSearchParams(opts.form).toString()
      : opts.json ? JSON.stringify(opts.json) : (opts.body || null);
    const headers = Object.assign({}, opts.headers || {});
    if (opts.form) headers["Content-Type"] = "application/x-www-form-urlencoded";
    if (opts.json) headers["Content-Type"] = "application/json";
    if (opts.cookie) headers.Cookie = opts.cookie;
    if (body) headers["Content-Length"] = Buffer.byteLength(body);
    const req = http.request({ host: "127.0.0.1", port, path: route, method, headers }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString("utf8"), raw: Buffer.concat(chunks) }));
    });
    req.on("error", reject);
    req.setTimeout(opts.timeoutMs || 30000, () => req.destroy(new Error("request timeout " + route)));
    if (body) req.write(body);
    req.end();
  });
}
function cookieOf(res) {
  return (res.headers["set-cookie"] || []).map((c) => c.split(";")[0]).join("; ");
}
function prepareApp(srcDir, appDir) {
  fs.mkdirSync(appDir, { recursive: true });
  fs.copyFileSync(path.join(srcDir, "index.js"), path.join(appDir, "index.js"));
  fs.copyFileSync(path.join(srcDir, "package.json"), path.join(appDir, "package.json"));
}
// Dev shortcut: pre-place the Phase-0 patched pinned binary + its .ok hash so
// ensureBinary takes the verified-cache path (cold download is covered by
// tests/smoke.js). Returns false if the Phase-0 binary is unavailable.
function seedBinaryShortcut(stateDir) {
  if (!fs.existsSync(PHASE0_BIN)) return false;
  const panelDir = path.join(stateDir, "panel");
  fs.mkdirSync(panelDir, { recursive: true });
  const dest = path.join(panelDir, "vpn-ui-amd64");
  fs.copyFileSync(PHASE0_BIN, dest);
  fs.chmodSync(dest, 0o755);
  const sha = execSync("sha256sum " + JSON.stringify(dest)).toString().split(" ")[0];
  fs.writeFileSync(path.join(panelDir, "vpn-ui-amd64.ok"), sha);
  return true;
}
function boot(opts) {
  const env = Object.assign({}, process.env);
  delete env.SELFTEST; delete env.MEOWRAY_UNIT;
  Object.assign(env, {
    PORT: String(opts.port), PANEL_HOST: "127.0.0.1", PANEL_SCHEME: "http",
    MEOWRAY_ROOT: opts.stateDir, MEOWRAY_ADMIN_USER: "admin",
    MEOWRAY_ADMIN_PASSWORD: opts.adminPass || "DummyPass#123",
  }, opts.extraEnv || {});
  const handle = { log: "", child: null, startedAt: Date.now() };
  handle.child = spawn(process.execPath, ["index.js"], { cwd: opts.appDir, env, stdio: ["ignore", "pipe", "pipe"] });
  handle.child.stdout.on("data", (d) => { handle.log += d.toString(); });
  handle.child.stderr.on("data", (d) => { handle.log += d.toString(); });
  return handle;
}
async function waitReady(handle, timeoutMs) {
  const t0 = Date.now();
  while (Date.now() - t0 < (timeoutMs || 240000)) {
    if (handle.log.includes('"event":"ready"')) return Date.now() - t0;
    if (handle.child.exitCode !== null) throw new Error("app exited early code=" + handle.child.exitCode + "\n" + handle.log.slice(-2500));
    await sleep(500);
  }
  throw new Error("timeout waiting for ready\n" + handle.log.slice(-2500));
}
async function stop(handle) {
  const child = handle.child;
  if (!child || child.exitCode !== null) return;
  child.kill("SIGTERM");
  const t0 = Date.now();
  while (child.exitCode === null && Date.now() - t0 < 15000) await sleep(250);
  if (child.exitCode === null) { child.kill("SIGKILL"); await sleep(500); }
}
function portFree(port) {
  return new Promise((resolve) => {
    const s = net.connect({ host: "127.0.0.1", port }, () => { s.end(); resolve(false); });
    s.on("error", () => resolve(true));
    s.setTimeout(1500, () => { s.destroy(); resolve(true); });
  });
}
async function preflight(ports) {
  for (const p of [18080, 18081].concat(ports)) {
    if (!(await portFree(p))) { console.error("PREFLIGHT: port " + p + " busy — kill leftover instances first"); process.exit(2); }
  }
}
async function panelLogin(port, pass) {
  const res = await request(port, "POST", "/kb/login", { form: { username: "admin", password: pass || "DummyPass#123" } });
  return cookieOf(res);
}
async function panelList(port, cookie) {
  // The binary restarts xray after client changes; its API can answer
  // transient junk for a few seconds around those restarts. Retry briefly.
  let lastErr = null;
  for (let attempt = 0; attempt < 8; attempt++) {
    try {
      const res = await request(port, "GET", "/kb/panel/api/inbounds/list", { cookie, headers: { "X-Requested-With": "XMLHttpRequest" } });
      const parsed = JSON.parse(res.body);
      if (parsed && Array.isArray(parsed.obj)) return parsed.obj;
      lastErr = new Error("unexpected list response: " + res.body.slice(0, 80));
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
function panelPids() {
  const pids = [];
  for (const name of fs.readdirSync("/proc")) {
    if (!/^\d+$/.test(name)) continue;
    try {
      if (fs.readFileSync("/proc/" + name + "/comm", "utf8").trim() === "vpn-ui-amd64") pids.push(Number(name));
    } catch (e) {}
  }
  return pids;
}
module.exports = { request, cookieOf, prepareApp, seedBinaryShortcut, boot, waitReady, stop, portFree, preflight, panelLogin, panelList, clientsOf, panelPids, sleep, PHASE0_BIN };
