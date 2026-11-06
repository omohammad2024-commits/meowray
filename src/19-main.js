
// Boot orchestration + CLI + entry dispatch.
//
// Boot order (designed for slow free hosts):
//   validate → restore bundle if present → dirs → mux+portal up immediately
//   (status page) → binary + glibc staged in PARALLEL → geo trim → panel
//   `setting` → supervised panel start → login → seed → first reconcile →
//   ready. Any fatal step logs loudly and EXITS (the host restarts us) —
//   never a zombie that only serves a status page.

async function maybeRestore() {
  const candidates = [];
  if (CFG.restorePath) candidates.push(CFG.restorePath);
  candidates.push(path.join(process.cwd(), "restore.tar.gz"));
  candidates.push(P.restoreFile);
  const bundlePath = candidates.find((p) => p && fs.existsSync(p));
  if (!bundlePath) return false;
  // Idempotency without destruction: remember the hash of the last applied
  // bundle. A later boot with the same bundle skips the restore (no
  // rollback), and the operator's file is NEVER moved or deleted — it may
  // be their only copy, and a cross-device rename is not atomic.
  let bundleHash = "";
  try { bundleHash = await sha256File(bundlePath); } catch (e) {}
  if (bundleHash && readVault().lastRestoreHash === bundleHash) {
    log("restore bundle already applied (hash match) — skipping restore");
    return false;
  }
  log("restore bundle found: " + bundlePath + " — restoring state before boot");
  const staging = CFG.root + ".restore-tmp";
  fs.rmSync(staging, { recursive: true, force: true });
  fs.mkdirSync(staging, { recursive: true });
  try {
    const info = await extractBundle(bundlePath, staging);
    const looksValid = fs.existsSync(path.join(staging, "state.json")) || fs.existsSync(path.join(staging, "data"));
    if (!looksValid) throw new Error("bundle does not look like a MeowRay state (no state.json / data)");
    // Swap: keep the previous state as a sibling backup, never delete it here.
    if (fs.existsSync(CFG.root) && fs.readdirSync(CFG.root).length > 0) {
      const bak = CFG.root + ".bak-" + new Date().toISOString().replace(/[:.]/g, "-");
      fs.renameSync(CFG.root, bak);
      log("previous state kept at " + bak);
    }
    fs.renameSync(staging, CFG.root);
    initPaths(); // rebind paths to the (possibly new) root
    log("state restored: " + info.files + " files, " + Math.round(info.bytes / 1048576) + " MB");
    if (bundleHash) {
      try { writeVault({ lastRestoreHash: bundleHash, lastRestoreAt: new Date().toISOString() }); } catch (e) {}
    }
    return true;
  } catch (e) {
    fs.rmSync(staging, { recursive: true, force: true });
    log("RESTORE REFUSED (old state kept): " + e.message);
    return false;
  }
}

async function boot() {
  if (process.platform !== "linux" || process.arch !== "x64") {
    throw new Error("MeowRay runs on linux/x64 only (this host: " + process.platform + "/" + process.arch + ")");
  }
  if (!Number.isInteger(CFG.publicPort) || CFG.publicPort < 1 || CFG.publicPort > 65535) {
    throw new Error("invalid public port: " + CFG.publicPort);
  }
  await maybeRestore();
  ensureStateDirs();
  startPublicServer();
  startUserServer();

  // --- credentials -------------------------------------------------------
  const vault0 = readVault();
  const firstBoot = !vault0.panelPass;
  const panelUser = vault0.adminUser || CFG.adminUser;
  if (vault0.adminUser && CFG.adminUser !== vault0.adminUser) {
    log("note: MEOWRAY_ADMIN_USER differs from the first-boot admin user; the panel keeps the original (" + vault0.adminUser + ")");
  }
  let firstPassword = "";
  if (firstBoot) firstPassword = CFG.adminPasswordEnv || randomPassword();
  if (CFG.registration === "invite" && !CFG.inviteCode) {
    log("WARNING: REGISTRATION=invite but MEOWRAY_INVITE_CODE is empty — portal registrations will be REJECTED (fail-closed) until a code is set");
  }
  const candidates = [];
  if (CFG.adminPasswordEnv) candidates.push({ username: panelUser, password: CFG.adminPasswordEnv });
  candidates.push({ username: panelUser, password: firstBoot ? firstPassword : vault0.panelPass });
  RT.credCandidates = candidates;

  // --- stage binary + runtime in parallel --------------------------------
  RT.status = "staging panel binary";
  const hostPromise = detectPublicHost().catch(() => "");
  const jobs = [ensureBinary()];
  const glibcNeeded = needsBundledGlibc();
  if (glibcNeeded) jobs.push(ensureRuntime());
  const results = await Promise.all(jobs);
  log("panel binary: " + results[0]);
  if (glibcNeeded) {
    log("bundled glibc: " + results[1]);
    const linked = linkLoader();
    if (linked) {
      try { RT.directExec = patchInterpreter(P.binFile, linked); } catch (e) { RT.directExec = false; log("direct exec patch skipped: " + e.message); }
    }
  }
  trimGeoFiles(); // warm-boot leftovers, before the panel starts

  // --- configure the panel ------------------------------------------------
  RT.status = "configuring panel";
  const settingArgs = ["setting", "-port", String(CFG.panelPort), "-listenIP", "127.0.0.1", "-webBasePath", "kb"];
  if (firstBoot) settingArgs.push("-username", panelUser, "-password", firstPassword);
  const setting = await runBin(settingArgs, 90000);
  if (setting.code !== 0) {
    throw new Error("panel `setting` failed (code " + setting.code + "): " + setting.out.trim().split(/\r?\n/).filter(Boolean).slice(-3).join(" | ").slice(0, 400));
  }
  if (firstBoot && /Failed to update username and password/i.test(setting.out)) {
    log("random first-boot password was not applied by the binary; falling back to factory admin/admin for the first login");
    RT.credCandidates = [{ username: "admin", password: "admin" }];
    writeVault({ panelPass: "admin", adminUser: "admin", factoryFallback: true });
  }

  // --- start + login -------------------------------------------------------
  RT.status = "starting panel";
  RT.publicHost = await hostPromise;
  if (!RT.publicHost) log("WARNING: public host not detected — set PANEL_HOST so subscription links point at this server");
  if (await portOpen(PANEL_PORT)) {
    throw new Error("internal panel port " + PANEL_PORT + " is already in use — another MeowRay instance is running on this host; refusing to adopt a foreign panel");
  }
  startPanel();
  const up = await waitForPanel(90000);
  if (!up) throw new Error("panel did not open its internal port within 90s");
  RT.panelUp = true;
  const login = await panelLoginWhenReady(RT.credCandidates);
  RT.adminCookie = login.cookie;
  const panelPassword = login.used.password;
  if (readVault().panelPass !== panelPassword) writeVault({ panelPass: panelPassword, adminUser: login.used.username, version: RUNNER_VERSION });
  if (firstBoot && !CFG.adminPasswordEnv) log("FIRST-BOOT admin password (generated, shown once): " + panelPassword + " — user: " + login.used.username);
  if (firstBoot && CFG.adminPasswordEnv) log("FIRST-BOOT: admin password taken from MEOWRAY_ADMIN_PASSWORD env (value not printed) — user: " + login.used.username);

  // --- seed + reconcile ----------------------------------------------------
  RT.status = "seeding inbounds";
  const seeded = await seed();
  log("inbounds: " + seeded.made.join(", "));
  if (seeded.skipped.length) log("inbounds skipped: " + seeded.skipped.join(" | "));
  await ensureAdminPortalUser(panelPassword);
  writeAccessCard();
  await reconcileNow("boot");

  RT.ready = true;
  RT.readyAt = Date.now();
  RT.status = "ready";
  log(JSON.stringify({
    event: "ready", version: RUNNER_VERSION, panel: VERSIONS.panel.version,
    bootMs: RT.readyAt - RT.bootStartedAt, inbounds: RT.inboundCount, clients: RT.clientCount,
    host: RT.publicHost || null, port: CFG.publicPort, registration: CFG.registration,
  }));
  log("admin panel: " + CFG.publicScheme + "://" + (RT.publicHost || "HOST") + ":" + CFG.publicPort + PANEL_BASE + "/");
  log("user portal: " + CFG.publicScheme + "://" + (RT.publicHost || "HOST") + ":" + CFG.publicPort + "/");

  if (CFG.reconcileSec > 0) {
    setInterval(() => { reconcileNow("interval").catch(() => {}); rotateLogsIfNeeded(); }, CFG.reconcileSec * 1000).unref();
  }
}

async function cliBackup(outPath) {
  initPaths();
  if (!fs.existsSync(P.root)) throw new Error("state dir does not exist: " + P.root);
  const info = await createBundle(P.root, outPath);
  log("backup written: " + outPath + " (" + info.files + " files)");
}

// ---- entry dispatch ----
if (process.env.MEOWRAY_UNIT === "1") {
  CFG = parseConfig(process.env);
  initPaths();
  module.exports = {
    parseConfig, parseCgroupLimit, pickPort, shouldWait, httpMethod, muxCtx, routeHttpPath,
    planClientSync, desiredClientFor, buildTarBuffer, parseTarBuffer, validateTarEntryName,
    qrMatrix, qrBuildMatrix, qrDataCodewords, qrInterleave, qrFormatBits, qrTotalData,
    patchBinaryBuffer, panelEnv, goMemLimitMb, generateUserConfigs,
    createBundle, extractBundle, verifyPassword, hashPassword,
    decompressDebData, extractNeededFromTar, parseAr, download, VERSIONS,
    emailFor, clientLimits, wgKeyPair, sha256Buffer, dropcacheBuffer,
  };
} else if (process.argv.includes("--version")) {
  process.stdout.write(RUNNER_VERSION + "\n");
} else if (process.argv.includes("--backup")) {
  CFG = parseConfig(process.env);
  const idx = process.argv.indexOf("--backup");
  const out = process.argv[idx + 1];
  if (!out) { log("--backup needs an output path"); process.exit(2); }
  cliBackup(path.resolve(out)).then(() => process.exit(0), (e) => { log("backup failed: " + e.message); process.exit(1); });
} else if (process.env.SELFTEST === "1") {
  (async () => {
    CFG = parseConfig(Object.assign({}, process.env, { MEOWRAY_ROOT: fs.mkdtempSync(path.join(os.tmpdir(), "meowray-selftest-")) }));
    initPaths();
    try { await runSelfTest(); process.exit(0); }
    catch (e) { console.error(e); process.exit(1); }
    finally { try { fs.rmSync(CFG.root, { recursive: true, force: true }); } catch (e) {} }
  })();
} else {
  CFG = parseConfig(process.env);
  initPaths();
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
  process.on("unhandledRejection", (err) => log("unhandledRejection: " + (err && err.message)));
  process.on("uncaughtException", (err) => log("uncaughtException: " + (err && err.message)));
  boot().catch((err) => {
    RT.fatal = err.message;
    log("FATAL boot error: " + err.message + " — exiting so the host can restart cleanly");
    if (RT.child && !RT.child.killed) { try { RT.child.kill("SIGTERM"); } catch (e) {} }
    setTimeout(() => process.exit(1), 2500);
  });
}
