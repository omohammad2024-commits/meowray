"use strict";
// Failure-mode suite: every scenario must fail LOUDLY or recover cleanly —
// never silently corrupt state.
//   F1 public port busy        → process exits nonzero with a clear FATAL
//   F2 corrupt restore bundle  → restore refused, old/fresh state boots
//   F3 traversal bundle        → refused, nothing written outside the root
//   F4 panel child SIGKILL     → supervisor restarts it, health recovers
//   F5 expired user            → reconcile disables its panel clients
//   F6 partial binary download → resume completes, hash verifies, boot ok
//   F7 garbage binary cache    → hash reject, clean re-download, boot ok
//   F8 planted binary + self-consistent .ok → discarded, pinned re-download
//   F9 invite mode, no code configured → registration fail-closed (403)
const fs = require("fs");
const path = require("path");
const net = require("net");
const zlib = require("zlib");
const H = require("./harness");

const SRC = path.resolve(path.join(__dirname, "..", "dist"));
const WORK = path.resolve(path.join(__dirname, "..", "failure-v1"));
process.env.MEOWRAY_UNIT = "1";
const U = require("../dist/index.js");

let passed = 0, failed = 0;
const failures = [];
function ok(cond, name) {
  if (cond) passed++;
  else { failed++; failures.push(name); console.log("FAIL: " + name); }
}
function scenarioDir(name) {
  const dir = path.join(WORK, name);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

async function f1() {
  const port = 18200;
  const blocker = net.createServer(() => {});
  await new Promise((r) => blocker.listen(port, "0.0.0.0", r));
  const dir = scenarioDir("f1");
  const app = path.join(dir, "app"), state = path.join(dir, "state");
  H.prepareApp(SRC, app);
  const h = H.boot({ appDir: app, stateDir: state, port });
  const t0 = Date.now();
  while (h.child.exitCode === null && Date.now() - t0 < 30000) await H.sleep(250);
  ok(h.child.exitCode !== null && h.child.exitCode !== 0, "F1 app exits nonzero on busy port (code=" + h.child.exitCode + ")");
  ok(/could not be opened|EADDRINUSE/.test(h.log), "F1 loud port error in log");
  blocker.close();
}
async function f2() {
  const port = 18201;
  const dir = scenarioDir("f2");
  const app = path.join(dir, "app"), state = path.join(dir, "state");
  H.prepareApp(SRC, app);
  H.seedBinaryShortcut(state);
  fs.writeFileSync(path.join(app, "restore.tar.gz"), Buffer.from("definitely not a gzip bundle"));
  const h = H.boot({ appDir: app, stateDir: state, port });
  await H.waitReady(h, 180000);
  ok(h.log.includes("RESTORE REFUSED"), "F2 corrupt bundle refused loudly");
  const res = await H.request(port, "GET", "/healthz");
  ok(res.status === 200 && JSON.parse(res.body).ok === true, "F2 fresh state boots healthy after refused restore");
  await H.stop(h);
}
async function f3() {
  const port = 18202;
  const dir = scenarioDir("f3");
  const app = path.join(dir, "app"), state = path.join(dir, "state");
  H.prepareApp(SRC, app);
  H.seedBinaryShortcut(state);
  const tar = U.buildTarBuffer([
    { name: "state.json", data: Buffer.from("{}") },
    { name: "../evil.txt", data: Buffer.from("pwned") },
  ]);
  fs.writeFileSync(path.join(app, "restore.tar.gz"), zlib.gzipSync(tar));
  const h = H.boot({ appDir: app, stateDir: state, port });
  await H.waitReady(h, 180000);
  ok(h.log.includes("RESTORE REFUSED"), "F3 traversal bundle refused");
  ok(!fs.existsSync(path.join(dir, "evil.txt")) && !fs.existsSync(path.join(app, "evil.txt")) && !fs.existsSync(path.join(WORK, "evil.txt")), "F3 nothing written outside the state root");
  await H.stop(h);
}
async function f4() {
  const port = 18203;
  const dir = scenarioDir("f4");
  const app = path.join(dir, "app"), state = path.join(dir, "state");
  H.prepareApp(SRC, app);
  H.seedBinaryShortcut(state);
  const h = H.boot({ appDir: app, stateDir: state, port });
  await H.waitReady(h, 180000);
  const pids = H.panelPids();
  ok(pids.length >= 1, "F4 panel child found (pid " + pids.join(",") + ")");
  process.kill(pids[0], "SIGKILL");
  let recovered = false;
  const t0 = Date.now();
  while (Date.now() - t0 < 90000) {
    try {
      const res = await H.request(port, "GET", "/healthz");
      if (res.status === 200) {
        const health = JSON.parse(res.body);
        if (health.ok === true && health.panelUp === true && health.restarts >= 1) { recovered = true; break; }
      }
    } catch (e) {}
    await H.sleep(1500);
  }
  ok(recovered, "F4 supervisor restarted the panel and health recovered");
  await H.stop(h);
}
async function f5() {
  const port = 18204;
  const dir = scenarioDir("f5");
  const app = path.join(dir, "app"), state = path.join(dir, "state");
  H.prepareApp(SRC, app);
  H.seedBinaryShortcut(state);
  const h = H.boot({ appDir: app, stateDir: state, port });
  await H.waitReady(h, 180000);
  let res = await H.request(port, "POST", "/api/auth/login", { json: { username: "admin", password: "DummyPass#123" } });
  const portal = H.cookieOf(res);
  res = await H.request(port, "POST", "/api/admin/users", { cookie: portal, json: { username: "exp1", password: "Exp#12345", trafficGb: 5, expiryDays: 30 } });
  ok(res.status === 201, "F5 user created");
  const panel = await H.panelLogin(port);
  let clients = H.clientsOf(await H.panelList(port, panel), "exp1-");
  ok(clients.length === 7 && clients.every((x) => x.client.enable === true), "F5 clients start enabled");
  // expire the user directly in the runner store, then reconcile
  const usersFile = path.join(state, "data", "mr_users.json");
  const users = JSON.parse(fs.readFileSync(usersFile, "utf8"));
  users.find((u) => u.username === "exp1").expiresAt = new Date(Date.now() - 60000).toISOString();
  fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));
  res = await H.request(port, "POST", "/api/admin/reconcile", { cookie: portal });
  ok(res.status === 200, "F5 manual reconcile ran");
  clients = H.clientsOf(await H.panelList(port, panel), "exp1-");
  ok(clients.length === 7 && clients.every((x) => x.client.enable === false), "F5 expired user's clients are disabled in the panel");
  await H.stop(h);
}
async function f6() {
  const port = 18205;
  const dir = scenarioDir("f6");
  const app = path.join(dir, "app"), state = path.join(dir, "state");
  H.prepareApp(SRC, app);
  // first 24 MB of the real pinned binary = an interrupted download
  const panelDir = path.join(state, "panel");
  fs.mkdirSync(panelDir, { recursive: true });
  const src = fs.openSync(H.PHASE0_BIN, "r");
  const buf = Buffer.alloc(24 * 1048576);
  fs.readSync(src, buf, 0, buf.length, 0);
  fs.closeSync(src);
  fs.writeFileSync(path.join(panelDir, "vpn-ui-amd64"), buf);
  const h = H.boot({ appDir: app, stateDir: state, port });
  await H.waitReady(h, 420000);
  const full = fs.statSync(path.join(panelDir, "vpn-ui-amd64")).size;
  ok(full === fs.statSync(H.PHASE0_BIN).size, "F6 resumed download completed the binary (" + full + " bytes)");
  const res = await H.request(port, "GET", "/healthz");
  ok(res.status === 200 && JSON.parse(res.body).ok === true, "F6 boot healthy after resume");
  await H.stop(h);
}
async function f7() {
  const port = 18206;
  const dir = scenarioDir("f7");
  const app = path.join(dir, "app"), state = path.join(dir, "state");
  H.prepareApp(SRC, app);
  const panelDir = path.join(state, "panel");
  fs.mkdirSync(panelDir, { recursive: true });
  fs.writeFileSync(path.join(panelDir, "vpn-ui-amd64"), Buffer.alloc(1048576, 0x41)); // garbage
  fs.writeFileSync(path.join(panelDir, "vpn-ui-amd64.ok"), "deadbeef");
  const h = H.boot({ appDir: app, stateDir: state, port });
  await H.waitReady(h, 420000);
  const res = await H.request(port, "GET", "/healthz");
  ok(res.status === 200 && JSON.parse(res.body).ok === true, "F7 garbage cache rejected, re-downloaded, boot healthy");
  await H.stop(h);
}

async function f8() {
  const port = 18207;
  const dir = scenarioDir("f8");
  const app = path.join(dir, "app"), state = path.join(dir, "state");
  H.prepareApp(SRC, app);
  const panelDir = path.join(state, "panel");
  fs.mkdirSync(panelDir, { recursive: true });
  // Take the genuine patched binary and corrupt it AWAY from the patch
  // site, then write a SELF-CONSISTENT .ok mark for the corrupted bytes.
  // A trust model based on the mark (or on the patch needle alone) would
  // execute this file; the pinned-hash model must discard + re-download.
  const bin = fs.readFileSync(H.PHASE0_BIN);
  bin[100000000] = bin[100000000] ^ 0xff;
  fs.writeFileSync(path.join(panelDir, "vpn-ui-amd64"), bin);
  const sha = require("crypto").createHash("sha256").update(bin).digest("hex");
  fs.writeFileSync(path.join(panelDir, "vpn-ui-amd64.ok"), sha);
  const h = H.boot({ appDir: app, stateDir: state, port });
  await H.waitReady(h, 420000);
  const after = require("crypto").createHash("sha256").update(fs.readFileSync(path.join(panelDir, "vpn-ui-amd64"))).digest("hex");
  ok(after === U.VERSIONS.panel.patchedSha256, "F8 planted binary with self-consistent .ok discarded; on-disk binary is the pinned+patched release");
  const res = await H.request(port, "GET", "/healthz");
  ok(res.status === 200 && JSON.parse(res.body).ok === true, "F8 boot healthy after re-download");
  await H.stop(h);
}
async function f9() {
  const port = 18208;
  const dir = scenarioDir("f9");
  const app = path.join(dir, "app"), state = path.join(dir, "state");
  H.prepareApp(SRC, app);
  H.seedBinaryShortcut(state);
  const h = H.boot({ appDir: app, stateDir: state, port, extraEnv: { REGISTRATION: "invite" } });
  await H.waitReady(h, 180000);
  let res = await H.request(port, "POST", "/api/auth/register", { json: { username: "sneaky1", password: "Sneak#1234" } });
  ok(res.status === 403, "F9 invite without configured code rejects registration with no invite (got " + res.status + ")");
  res = await H.request(port, "POST", "/api/auth/register", { json: { username: "sneaky1", password: "Sneak#1234", invite: "anything" } });
  ok(res.status === 403, "F9 invite without configured code rejects registration with any invite (got " + res.status + ")");
  ok(h.log.includes("REJECTED (fail-closed)"), "F9 boot log warns invite mode is fail-closed");
  await H.stop(h);
}

async function main() {
  await H.preflight([18200, 18201, 18202, 18203, 18204, 18205, 18206, 18207, 18208]);
  fs.rmSync(WORK, { recursive: true, force: true });
  fs.mkdirSync(WORK, { recursive: true });
  await f1(); console.log("F1 done");
  await f2(); console.log("F2 done");
  await f3(); console.log("F3 done");
  await f4(); console.log("F4 done");
  await f5(); console.log("F5 done");
  await f6(); console.log("F6 done");
  await f7(); console.log("F7 done");
  await f8(); console.log("F8 done");
  await f9(); console.log("F9 done");
  console.log("failure: " + passed + " passed, " + failed + " failed");
  if (failures.length) console.log("failures: " + failures.join(" | "));
  fs.writeFileSync(path.join(WORK, "failure-summary.json"), JSON.stringify({ passed, failed }, null, 2));
  process.exit(failed ? 1 : 0);
}
const handles = [];
const origBoot = H.boot;
H.boot = (opts) => { const h = origBoot(opts); handles.push(h); return h; };
main().catch(async (e) => {
  console.error(e);
  for (const h of handles) { try { await H.stop(h); } catch (err) {} }
  process.exit(1);
});
