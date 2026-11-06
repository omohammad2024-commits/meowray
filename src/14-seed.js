
// Seeding: create the planned inbounds exactly once (matched by remark),
// refresh their public link targets when the host changes, write the access
// card, bridge the portal admin user, and run the first reconciliation.

async function refreshLinks(cookie, host) {
  if (!host) return 0;
  const rows = await listInbounds(cookie);
  const managed = new Set(MANAGED_REMARKS);
  let changed = 0;
  for (const row of rows) {
    if (!managed.has(row.remark)) continue;
    let stream = {};
    try { stream = JSON.parse(asText(row.streamSettings) || "{}"); } catch (e) { stream = {}; }
    const current = Array.isArray(stream.externalProxy) ? (stream.externalProxy[0] || {}) : {};
    if (current.dest === host && Number(current.port) === CFG.publicPort && current.forceTls === "none") continue;
    stream.externalProxy = externalProxyField(host, CFG.publicPort);
    let settings = {};
    try { settings = JSON.parse(asText(row.settings) || "{}"); } catch (e) { settings = {}; }
    await updateInbound(cookie, row, settings, stream);
    changed++;
  }
  return changed;
}

function writeAccessCard() {
  const host = RT.publicHost || "HOST";
  const lines = [
    BRAND + " — access card",
    "Runner: " + RUNNER_VERSION + " · Panel: vpn-ui v" + VERSIONS.panel.version,
    "",
    "Admin panel:  " + CFG.publicScheme + "://" + host + ":" + CFG.publicPort + PANEL_BASE + "/",
    "User portal:  " + CFG.publicScheme + "://" + host + ":" + CFG.publicPort + "/",
    "Health:       " + CFG.publicScheme + "://" + host + ":" + CFG.publicPort + "/healthz",
    "Admin user:   " + CFG.adminUser,
    "Admin password: NOT stored in this file. It was printed ONCE in the first-boot",
    "  console log, or set it yourself via the MEOWRAY_ADMIN_PASSWORD env var.",
    "  If you change the password inside the panel UI, set MEOWRAY_ADMIN_PASSWORD",
    "  to the new password and restart so the runner can log in again.",
    "",
    "Registration: " + CFG.registration + " · New-user defaults: " +
      (CFG.userTrafficGb ? CFG.userTrafficGb + " GB" : "unlimited") + ", " +
      (CFG.userExpiryDays ? CFG.userExpiryDays + " days" : "no expiry"),
    "State directory: " + P.root,
    "Migration: download a bundle from the portal admin page, put it next to",
    "  index.js on the new host as restore.tar.gz (or set MEOWRAY_RESTORE), start.",
  ];
  writeFileAtomic(P.accessFile, lines.join("\n") + "\n", 0o600);
}

// The portal admin account mirrors the panel admin credentials.
async function ensureAdminPortalUser(panelPassword) {
  const users = readUsers();
  const hash = await hashPassword(panelPassword);
  const existing = users.find((u) => u.username === CFG.adminUser);
  if (existing) {
    existing.passwordHash = hash;
    existing.role = "admin";
    if (existing.enabled === false) existing.enabled = true;
    writeUsers(users);
    return existing;
  }
  const admin = newPortalUser(CFG.adminUser, hash, "admin", { trafficGb: 0, expiresAt: null });
  users.push(admin);
  writeUsers(users);
  return admin;
}

async function seed() {
  const cookie = await getAdminCookie();
  await applyBrand(cookie);
  const existing = await listInbounds(cookie);
  const have = new Set(existing.map((r) => r.remark));
  const keys = wgKeyPair();
  const made = existing.map((r) => r.remark);
  const skipped = [];
  for (const spec of plannedInbounds(RT.publicHost, CFG.publicPort, keys)) {
    if (have.has(spec.remark)) continue;
    try {
      await addInbound(cookie, spec);
      made.push(spec.remark);
      log("inbound created: " + spec.remark);
    } catch (e) {
      skipped.push(spec.remark + " (" + e.message + ")");
      log("inbound NOT created: " + e.message);
    }
  }
  const refreshed = await refreshLinks(cookie, RT.publicHost);
  if (refreshed) log("link targets refreshed for host " + RT.publicHost + ": " + refreshed);
  RT.inboundCount = made.length;
  return { made, skipped };
}
