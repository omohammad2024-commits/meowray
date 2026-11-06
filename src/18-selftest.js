
// In-artifact selftest (SELFTEST=1 node index.js, wired to `npm test`).
// Exercises the pure logic + the patcher + the dropcache helper + a tar
// round-trip. It never boots the panel; the boot smoke lives in tests/.

async function runSelfTest() {
  let n = 0;
  const assert = (cond, name) => { if (!cond) throw new Error("selftest failed: " + name); n++; };

  // config defaults & parsing
  const c0 = parseConfig({});
  assert(c0.registration === "closed", "registration closed by default");
  assert(c0.userTrafficGb === 10 && c0.userExpiryDays === 30, "secure defaults for new users");
  assert(c0.publicPort === 8080, "default port");
  const c1 = parseConfig({ PORT: "9999", REGISTRATION: "open", USER_TRAFFIC_GB: "0", MEOWRAY_ROOT: "/tmp/x-state" });
  assert(c1.publicPort === 9999 && c1.registration === "open" && c1.userTrafficGb === 0, "env parsing");
  assert(c1.root === "/tmp/x-state", "MEOWRAY_ROOT respected");

  // cgroup parser
  assert(parseCgroupLimit("max", "") === 0, "cgroup max = unlimited");
  assert(parseCgroupLimit("3221225472", "") === 3221225472, "cgroup v2 value");
  assert(parseCgroupLimit("", "9223372036854771712") === 0, "cgroup v1 huge = unlimited");

  // mux routing
  const ctx = muxCtx();
  assert(pickPort(Buffer.from("PRI * HTTP/2.0\r\n\r\n"), ctx) === INBOUND_PORTS.grpc, "h2 preface → grpc");
  assert(pickPort(Buffer.from("GET /kb/ HTTP/1.1\r\nHost: x\r\n\r\n"), ctx) === PANEL_PORT, "/kb → panel");
  assert(pickPort(Buffer.from("GET /bp-vless HTTP/1.1\r\n\r\n"), ctx) === INBOUND_PORTS.vlessWs, "/bp-vless → ws inbound");
  assert(pickPort(Buffer.from("GET /bp-up?x=1 HTTP/1.1\r\n\r\n"), ctx) === INBOUND_PORTS.upgrade, "/bp-up → upgrade");
  assert(pickPort(Buffer.from("GET /dashboard HTTP/1.1\r\n\r\n"), ctx) === USER_PORT, "other http → portal");
  assert(pickPort(Buffer.from([0x16, 0x03, 0x01, 0x00]), ctx) === INBOUND_PORTS.vless, "binary → vless tcp");
  assert(shouldWait(Buffer.alloc(0)) === true, "wait on empty");
  assert(shouldWait(Buffer.from("PRI * HT")) === true, "wait on partial preface");
  assert(shouldWait(Buffer.from("GE")) === true, "wait on partial method");
  assert(shouldWait(Buffer.from("GET /kb HTTP/1.1")) === true, "wait on partial request line");
  assert(shouldWait(Buffer.from([0x16, 0x03])) === false, "no wait on binary");
  // per-request routing (keep-alive safe): path decides, not the connection
  assert(routeHttpPath("/kb/panel/api/inbounds/list", ctx) === PANEL_PORT, "route /kb → panel");
  assert(routeHttpPath("/kb", ctx) === PANEL_PORT, "route bare /kb → panel");
  assert(routeHttpPath("/healthz", ctx) === USER_PORT, "route /healthz → portal");
  assert(routeHttpPath("/bp-vmess?ed=2048", ctx) === INBOUND_PORTS.vmessWs, "route /bp-vmess → vmess inbound");
  assert(routeHttpPath("/sub/token", ctx) === USER_PORT, "route /sub → portal");

  // binary patcher (synthetic buffer)
  const needle = Buffer.from(VERSIONS.panel.patchNeedleHex, "hex");
  const fake = Buffer.concat([Buffer.alloc(100, 7), needle, Buffer.alloc(50, 9)]);
  const patched = patchBinaryBuffer(fake);
  assert(patched.changed === true, "patch applies");
  const jumpAt = 100 + needle.length - 6;
  assert(patched.buf.subarray(jumpAt, jumpAt + 6).equals(Buffer.from(VERSIONS.panel.patchJumpHex, "hex")), "jump bytes written");
  assert(patchBinaryBuffer(patched.buf).changed === false, "patch is idempotent-detectable");
  let threw = false;
  try { patchBinaryBuffer(Buffer.alloc(64, 1)); } catch (e) { threw = true; }
  assert(threw, "patch fails closed on unknown binary");

  // dropcache helper: pinned hash + real execution
  assert(sha256Buffer(dropcacheBuffer()) === VERSIONS.dropcacheSha256, "dropcache hash pinned");
  CFG = c1; initPaths(); ensureStateDirs();
  const dc = ensureDropcache();
  assert(spawnSync(dc, [__filename], { timeout: 4000 }).status === 0, "dropcache exits 0 on a real file");
  assert(spawnSync(dc, [], { timeout: 4000 }).status === 1, "dropcache exits 1 without args");

  // tar bundle helpers
  assert(validateTarEntryName("data/vpn-ui.db") === true, "tar name ok");
  assert(validateTarEntryName("../evil") === false, "tar name rejects ..");
  assert(validateTarEntryName("/abs/path") === false, "tar name rejects absolute");
  assert(validateTarEntryName("a\\b") === false, "tar name rejects backslash");
  const longName = "dir/" + "x".repeat(120) + "/file.bin";
  const tarBuf = buildTarBuffer([{ name: "a.txt", data: Buffer.from("hello") }, { name: longName, data: Buffer.from("world") }]);
  const parsed = parseTarBuffer(tarBuf);
  assert(parsed.length === 2 && parsed[0].data.toString() === "hello" && parsed[1].name === longName, "tar round-trip incl. long names");

  // QR invariants (deep validation against an independent implementation is in tests/)
  const m = qrMatrix("https://example.com/sub/abc123");
  assert(m.length >= 21 && m.length <= 57, "qr size in range");
  assert(m[0][0] === 1 && m[0][6] === 1 && m[6][0] === 1, "qr finder pattern");
  assert(m.every((row) => row.every((v) => v === 0 || v === 1)), "qr modules are binary");

  // password hashing + sessions (against the temp state dir)
  const hash = await hashPassword("correct horse");
  assert(await verifyPassword("correct horse", hash) === true, "scrypt verify ok");
  assert(await verifyPassword("wrong horse", hash) === false, "scrypt verify rejects");
  const token = makeSessionToken("alice");
  assert(verifySessionToken(token) === "alice", "session token round-trip");
  assert(verifySessionToken(token + "x") === null, "session token rejects tampering");

  // reconciliation planner
  const user = { id: "11111111-2222-3333-4444-555555555555", username: "bob", subToken: "tok123", trafficLimitGb: 5, expiresAt: null, enabled: true };
  const plan1 = planClientSync({ protocol: "vless", remark: "VLESS-WS", existingClients: [], users: [user], retiredUsernames: [] });
  assert(plan1.added === 1 && plan1.clients[0].email === "bob-vless-ws" && plan1.clients[0].totalGB === 5 * 1073741824, "planner adds with limits");
  const existing = [Object.assign({}, plan1.clients[0], { totalGB: 1 })];
  const plan2 = planClientSync({ protocol: "vless", remark: "VLESS-WS", existingClients: existing, users: [user], retiredUsernames: [] });
  assert(plan2.updated === 1 && plan2.clients[0].totalGB === 5 * 1073741824, "planner updates quota (MF hole)");
  const plan3 = planClientSync({ protocol: "vless", remark: "VLESS-WS", existingClients: plan1.clients, users: [], retiredUsernames: ["bob"] });
  assert(plan3.removed === 1 && plan3.clients.length === 0, "planner removes retired user clients");
  const foreign = [{ email: "someone-else@example.com", id: "x" }];
  const plan4 = planClientSync({ protocol: "vless", remark: "VLESS-WS", existingClients: foreign, users: [], retiredUsernames: ["bob"] });
  assert(plan4.removed === 0 && plan4.clients.length === 1, "planner preserves foreign clients");
  const plan5 = planClientSync({ protocol: "vless", remark: "VLESS-WS", existingClients: plan1.clients, users: [user], retiredUsernames: [] });
  assert(plan5.changed === false, "planner is idempotent");
  // Ownership guard: a foreign client that reuses our e-mail pattern with
  // a different subId is neither merged/hijacked nor deleted.
  const colliding = [{ email: "bob-vless-ws", id: "foreign-id", subId: "not-bobs-token", totalGB: 999 }];
  const plan6 = planClientSync({ protocol: "vless", remark: "VLESS-WS", existingClients: colliding, users: [user], retiredUsernames: [] });
  assert(plan6.updated === 0 && plan6.added === 0 && plan6.clients.length === 1 && plan6.clients[0].id === "foreign-id" && plan6.clients[0].totalGB === 999, "planner never hijacks a foreign client with a colliding email");
  const plan7 = planClientSync({ protocol: "vless", remark: "VLESS-WS", existingClients: colliding, users: [], retiredUsernames: ["bob"], retiredTokens: { bob: "tok123" } });
  assert(plan7.removed === 0 && plan7.clients.length === 1, "planner never deletes a foreign client on user deletion");
  const plan8 = planClientSync({ protocol: "vless", remark: "VLESS-WS", existingClients: plan1.clients, users: [], retiredUsernames: ["bob"], retiredTokens: { bob: "tok123" } });
  assert(plan8.removed === 1 && plan8.clients.length === 0, "planner removes retired clients when the subId matches");

  // env allowlist: a planted secret must NOT reach the panel child env
  process.env.MEOWRAY_TEST_SECRET_X = "should-not-leak";
  const env = panelEnv();
  assert(!("MEOWRAY_TEST_SECRET_X" in env), "child env is allowlisted");
  assert(env.GOMAXPROCS === "1" && /MiB$/.test(env.GOMEMLIMIT), "child env always carries memory caps");
  delete process.env.MEOWRAY_TEST_SECRET_X;

  // wg keypair shape + config links
  const keys = wgKeyPair();
  assert(Buffer.from(keys.pubKey, "base64").length === 32 && Buffer.from(keys.secretKey, "base64").length === 32, "wg keys are 32 bytes");
  const configs = generateUserConfigs({ id: user.id }, "example.test", 443);
  assert(configs.length === 6 && configs[0].uri.startsWith("vless://"), "6 subscription configs");
  const vmess = JSON.parse(Buffer.from(configs[1].uri.slice(8), "base64").toString("utf8"));
  assert(vmess.id === user.id && vmess.add === "example.test", "vmess config decodes");

  log("selftest ok — " + n + " asserts");
  return n;
}
