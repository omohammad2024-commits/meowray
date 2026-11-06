"use strict";
// Migration smoke: boot A → create user → download backup bundle → boot B
// in a fresh dir with restore.tar.gz → same inbounds/clients/links.
// The bundle carries the panel binary, so B does not re-download.
const fs = require("fs");
const path = require("path");
const H = require("./harness");

const SRC = path.resolve(process.argv[2] || path.join(__dirname, "..", "dist"));
const WORK = path.resolve(process.argv[3] || path.join(__dirname, "..", "migration-v1"));
const PORT = 18110;
let passed = 0, failed = 0;
const failures = [];
function ok(cond, name) {
  if (cond) passed++;
  else { failed++; failures.push(name); console.log("FAIL: " + name); }
}

async function main() {
  await H.preflight([PORT]);
  fs.rmSync(WORK, { recursive: true, force: true });
  const appA = path.join(WORK, "a", "app"), stateA = path.join(WORK, "a", "state");
  const appB = path.join(WORK, "b", "app"), stateB = path.join(WORK, "b", "state");
  H.prepareApp(SRC, appA);
  H.prepareApp(SRC, appB);
  ok(H.seedBinaryShortcut(stateA), "binary shortcut seeded (cold path covered by smoke.js)");

  // ---- boot A, create a user, snapshot the truth ----
  const a = H.boot({ appDir: appA, stateDir: stateA, port: PORT });
  await H.waitReady(a, 180000);
  let res = await H.request(PORT, "POST", "/api/auth/login", { json: { username: "admin", password: "DummyPass#123" } });
  const portalA = H.cookieOf(res);
  ok(res.status === 200, "A portal login");
  res = await H.request(PORT, "POST", "/api/admin/users", { cookie: portalA, json: { username: "miguser", password: "Mig#12345", trafficGb: 7, expiryDays: 15 } });
  ok(res.status === 201, "A user created");
  const token = JSON.parse(res.body).subToken;
  const panelA = await H.panelLogin(PORT);
  const inboundsA = await H.panelList(PORT, panelA);
  const clientsA = H.clientsOf(inboundsA, "miguser-");
  ok(inboundsA.length === 9, "A has 9 inbounds");
  ok(clientsA.length === 7, "A user in 7 inbounds (got " + clientsA.length + ")");
  res = await H.request(PORT, "GET", "/sub/" + token);
  const linksA = Buffer.from(res.body, "base64").toString("utf8");
  ok(linksA.split("\n").filter(Boolean).length === 6, "A sub has 6 links");

  // ---- backup bundle via the admin endpoint ----
  res = await H.request(PORT, "GET", "/api/admin/backup", { cookie: portalA, timeoutMs: 600000 });
  ok(res.status === 200, "backup endpoint 200");
  const bundlePath = path.join(WORK, "backup.tar.gz");
  fs.writeFileSync(bundlePath, res.raw);
  const bundleMB = res.raw.length / 1048576;
  console.log("backup bundle: " + bundleMB.toFixed(1) + " MB");
  ok(res.raw.length > 150 * 1048576, "bundle carries the binary (197 MB gzipped; B booting without a download below is the real proof)");
  await H.stop(a);
  ok(await H.portFree(PORT), "A stopped, port free");

  // ---- boot B from the bundle on a fresh root ----
  fs.copyFileSync(bundlePath, path.join(appB, "restore.tar.gz"));
  const b = H.boot({ appDir: appB, stateDir: stateB, port: PORT });
  const bootMs = await H.waitReady(b, 300000);
  console.log("B boot (restore + start): " + bootMs + "ms");
  ok(b.log.includes("state restored"), "B log confirms restore");
  const panelB = await H.panelLogin(PORT);
  const inboundsB = await H.panelList(PORT, panelB);
  const clientsB = H.clientsOf(inboundsB, "miguser-");
  ok(inboundsB.length === 9, "B has 9 inbounds after migration");
  ok(clientsB.length === 7, "B user clients survived migration (got " + clientsB.length + ")");
  ok(clientsB.every((x) => x.client.totalGB === 7 * 1073741824), "B client quotas intact");
  res = await H.request(PORT, "GET", "/sub/" + token);
  const linksB = Buffer.from(res.body, "base64").toString("utf8");
  ok(linksB === linksA, "B sub links byte-identical to A");
  res = await H.request(PORT, "POST", "/api/auth/login", { json: { username: "miguser", password: "Mig#12345" } });
  ok(res.status === 200, "B portal login for migrated user");
  res = await H.request(PORT, "GET", "/healthz");
  ok(res.status === 200 && JSON.parse(res.body).ok === true, "B healthz ok");
  await H.stop(b);
  ok(await H.portFree(PORT), "B stopped, port free");

  console.log("migration: " + passed + " passed, " + failed + " failed");
  if (failures.length) console.log("failures: " + failures.join(" | "));
  fs.writeFileSync(path.join(WORK, "migration-summary.json"), JSON.stringify({ passed, failed, bundleMB: Math.round(bundleMB * 10) / 10, bootBMs: bootMs }, null, 2));
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
