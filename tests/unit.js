"use strict";
// MeowRay unit suite (dev-only; runs against the built dist/index.js in
// MEOWRAY_UNIT mode + the artifact selftest). Counts are reported by the
// runner; any failure exits nonzero.
process.env.MEOWRAY_UNIT = "1";
const fs = require("fs");
const os = require("os");
const path = require("path");
const zlib = require("zlib");
const { execFileSync } = require("child_process");
const U = require("../dist/index.js");

let passed = 0, failed = 0;
const failures = [];
function ok(cond, name) {
  if (cond) passed++;
  else { failed++; failures.push(name); console.log("FAIL: " + name); }
}
function eq(a, b, name) { ok(a === b, name + " (got " + JSON.stringify(a) + ", want " + JSON.stringify(b) + ")"); }

async function main() {
  // ---- config / env parsing ----
  eq(U.parseConfig({}).registration, "closed", "registration closed default");
  eq(U.parseConfig({ PORT: "7000" }).publicPort, 7000, "PORT parsed");
  eq(U.parseConfig({ SERVER_PORT: "7001", PORT: "7000" }).publicPort, 7001, "SERVER_PORT wins");
  eq(U.parseConfig({ USER_EXPIRY_DAYS: "0" }).userExpiryDays, 0, "explicit unlimited expiry");
  eq(U.parseCgroupLimit("max", ""), 0, "cgroup v2 max");
  eq(U.parseCgroupLimit("", "536870912"), 536870912, "cgroup v1 value");

  // ---- mux ----
  const ctx = U.muxCtx();
  eq(U.pickPort(Buffer.from("GET /kb HTTP/1.1\r\n\r\n"), ctx), 18080, "mux /kb → panel");
  eq(U.pickPort(Buffer.from("GET /sub/xyz HTTP/1.1\r\n\r\n"), ctx), 18081, "mux /sub → portal");
  eq(U.pickPort(Buffer.from([0x00, 0x01, 0x02]), ctx), 21001, "mux binary → vless");
  ok(U.httpMethod(Buffer.from("POST /x HTTP/1.1")) === true, "httpMethod POST");
  ok(U.httpMethod(Buffer.from([0x16, 0x03, 0x01])) === false, "httpMethod TLS false");

  // ---- bundle round-trip on real files ----
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mr-unit-"));
  const state = path.join(tmp, "state");
  fs.mkdirSync(path.join(state, "data"), { recursive: true });
  fs.mkdirSync(path.join(state, "backups"), { recursive: true });
  fs.writeFileSync(path.join(state, "state.json"), JSON.stringify({ a: 1 }));
  fs.writeFileSync(path.join(state, "data", "vpn-ui.db"), Buffer.from([0, 1, 2, 250, 251, 252]));
  fs.writeFileSync(path.join(state, "data", "empty.bin"), "");
  fs.writeFileSync(path.join(state, "backups", "old.tar.gz"), "should be skipped");
  fs.writeFileSync(path.join(state, "data", "partial.part"), "should be skipped");
  const bundlePath = path.join(tmp, "bundle.tar.gz");
  const info = await U.createBundle(state, bundlePath);
  eq(info.files, 3, "bundle includes only real state files");
  const dest = path.join(tmp, "restored");
  const ex = await U.extractBundle(bundlePath, dest);
  eq(ex.files, 3, "extract file count");
  eq(fs.readFileSync(path.join(dest, "data", "vpn-ui.db")).length, 6, "binary file round-trip");
  eq(JSON.parse(fs.readFileSync(path.join(dest, "state.json"), "utf8")).a, 1, "json round-trip");
  ok(fs.existsSync(path.join(dest, "data", "empty.bin")), "empty file round-trip");
  // exec-bit preservation through a bundle (a restored binary must stay runnable)
  const state2 = path.join(tmp, "state2");
  fs.mkdirSync(state2, { recursive: true });
  const binPath = path.join(state2, "tool.bin");
  fs.writeFileSync(binPath, "#!/bin/sh\necho hi\n");
  fs.chmodSync(binPath, 0o755);
  const bundle2 = path.join(tmp, "bundle2.tar.gz");
  await U.createBundle(state2, bundle2);
  const dest2 = path.join(tmp, "restored2");
  await U.extractBundle(bundle2, dest2);
  eq(fs.statSync(path.join(dest2, "tool.bin")).mode & 0o777, 0o755, "bundle preserves exec bit");

  // ---- bundle attacks ----
  const evilTar = U.buildTarBuffer([{ name: "../evil.txt", data: Buffer.from("x") }]);
  const evilGz = path.join(tmp, "evil.tar.gz");
  fs.writeFileSync(evilGz, zlib.gzipSync(evilTar));
  let refused = false;
  try { await U.extractBundle(evilGz, path.join(tmp, "evil-out")); } catch (e) { refused = /unsafe/.test(e.message); }
  ok(refused, "traversal entry refused");
  ok(!fs.existsSync(path.join(tmp, "evil.txt")), "nothing written outside dest");
  const garbage = path.join(tmp, "garbage.tar.gz");
  fs.writeFileSync(garbage, Buffer.from("this is not gzip at all"));
  refused = false;
  try { await U.extractBundle(garbage, path.join(tmp, "garbage-out")); } catch (e) { refused = true; }
  ok(refused, "corrupt bundle refused");
  const linkTar = U.buildTarBuffer([{ name: "x", data: Buffer.alloc(0), type: "2", linkname: "/etc/passwd" }]);
  const linkGz = path.join(tmp, "link.tar.gz");
  fs.writeFileSync(linkGz, zlib.gzipSync(linkTar));
  refused = false;
  try { await U.extractBundle(linkGz, path.join(tmp, "link-out")); } catch (e) { refused = true; }
  ok(refused, "symlink entry refused");

  // ---- glibc deb pipeline with the real pinned deb (libgcc, small) ----
  const debPath = path.join(tmp, "libgcc.deb");
  const libgccPin = U.VERSIONS.glibcDebs.find((d) => d[1] === "libgcc.deb");
  await U.download(libgccPin[0], debPath, 60000);
  const sum = execFileSync("sha256sum", [debPath]).toString().split(" ")[0];
  eq(sum, libgccPin[2], "libgcc deb hash matches pin");
  const members = U.parseAr(fs.readFileSync(debPath));
  const packed = members["data.tar.zst"] || members["data.tar.xz"] || members["data.tar.gz"];
  ok(Boolean(packed), "deb has a data.tar member");
  const tar = U.decompressDebData(packed);
  const glibcOut = path.join(tmp, "glibc-out");
  const written = U.extractNeededFromTar(tar, glibcOut, new Set(["libgcc_s.so.1"]));
  eq(written, 1, "one glibc file extracted");
  const soFile = fs.readFileSync(path.join(glibcOut, "libgcc_s.so.1"));
  ok(soFile.length > 10000, "libgcc_s.so.1 has real size");
  eq(soFile.subarray(0, 4).toString("latin1"), "\x7fELF", "extracted file is ELF");

  // ---- portal link generation ----
  const user = { id: "11111111-2222-3333-4444-555555555555", username: "u1" };
  const cfgs = U.generateUserConfigs(user, "example.test", 8443);
  eq(cfgs.length, 6, "6 configs generated");
  ok(cfgs.every((c) => c.uri.includes("example.test:8443") || c.type === "vmess"), "configs carry public endpoint");
  const vm = JSON.parse(Buffer.from(cfgs[1].uri.slice(8), "base64").toString("utf8"));
  eq(vm.add, "example.test", "vmess add");
  eq(vm.port, "8443", "vmess port");
  eq(U.emailFor({ username: "alice" }, "VLESS-WS"), "alice-vless-ws", "email slug");

  // ---- artifact selftest (same code path as `npm test`) ----
  const out = execFileSync(process.execPath, [path.join(__dirname, "..", "dist", "index.js")],
    { env: Object.assign({}, process.env, { SELFTEST: "1", MEOWRAY_UNIT: "" }), encoding: "utf8" });
  const m = out.match(/selftest ok — (\d+) asserts/);
  ok(Boolean(m), "artifact selftest green");
  if (m) console.log("artifact selftest asserts: " + m[1]);

  fs.rmSync(tmp, { recursive: true, force: true });
  console.log("unit: " + passed + " passed, " + failed + " failed");
  if (failures.length) console.log("failures: " + failures.join(" | "));
  process.exit(failed ? 1 : 0);
}
main().catch((e) => { console.error(e); process.exit(1); });
