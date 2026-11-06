
// Client reconciliation — the loop MF never closed. MF's sync only ADDED
// missing clients; quota/expiry/enable changes and deletions never reached
// existing clients. Here a pure planner computes the full desired client set
// per inbound (add + update + remove), and an applier writes it back through
// the panel's full-row update endpoint. The planner is pure → unit-tested.

function desiredClientFor(user, protocol) {
  const limits = clientLimits(user);
  const base = {
    email: null, // filled by caller (per-inbound remark slug)
    limitIp: 0,
    totalGB: limits.totalGB,
    expiryTime: limits.expiryTime,
    enable: limits.enable,
    tgId: "",
    subId: user.subToken,
  };
  if (protocol === "vless" || protocol === "vmess") {
    return Object.assign(base, { id: user.id, alterId: 0, flow: "" });
  }
  if (protocol === "trojan") {
    return Object.assign(base, { password: user.id });
  }
  return null;
}
const MANAGED_FIELDS = ["id", "password", "alterId", "email", "limitIp", "totalGB", "expiryTime", "enable", "tgId", "subId", "flow"];
function planClientSync(args) {
  const { protocol, remark, existingClients, users, retiredUsernames, retiredTokens } = args;
  const existing = Array.isArray(existingClients) ? existingClients : [];
  const retired = new Set(retiredUsernames || []);
  const retiredTok = retiredTokens || {};
  const slug = String(remark || "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  const desiredByEmail = new Map();
  for (const u of users || []) {
    const d = desiredClientFor(u, protocol);
    if (!d) continue;
    d.email = emailFor(u, remark);
    desiredByEmail.set(d.email, d);
  }
  const out = [];
  const seen = new Set();
  let added = 0, updated = 0, removed = 0;
  for (const client of existing) {
    const email = client && client.email ? String(client.email) : "";
    const desired = desiredByEmail.get(email);
    if (desired) {
      seen.add(email);
      // Ownership: an existing client is ours to rewrite only if it carries
      // the user's subId (everything this runner creates is stamped with
      // it) or no subId at all. A hand-made panel client that merely
      // reuses our "<user>-<slug>" e-mail pattern with a FOREIGN subId is
      // not hijacked — it is left untouched and blocks the duplicate add.
      if (client.subId && client.subId !== desired.subId) { out.push(client); continue; }
      const merged = Object.assign({}, client);
      let differs = false;
      for (const f of MANAGED_FIELDS) {
        if (desired[f] === undefined) continue;
        if (merged[f] !== desired[f]) differs = true;
        merged[f] = desired[f];
      }
      if (protocol !== "vless") delete merged.flow;
      if (differs) updated++;
      out.push(merged);
      continue;
    }
    // Removal: only clients this runner manages (email = "<user>-<slug>")
    // whose username was explicitly retired (deleted in the portal). When
    // the retired user's subId was recorded at deletion time, the client
    // must carry exactly that subId — a hand-made client that happens to
    // share the e-mail pattern is never deleted. (States written before
    // tokens were recorded fall back to the e-mail-only match.)
    const suffix = "-" + slug;
    if (email && email.endsWith(suffix)) {
      const username = email.slice(0, email.length - suffix.length);
      if (retired.has(username)) {
        const tok = retiredTok[username];
        if (!tok || client.subId === tok) { removed++; continue; }
      }
    }
    out.push(client);
  }
  for (const [email, d] of desiredByEmail) {
    if (seen.has(email)) continue;
    if (protocol !== "vless") { const c = Object.assign({}, d); delete c.flow; out.push(c); }
    else out.push(d);
    added++;
  }
  return { clients: out, changed: added + updated + removed > 0, added, updated, removed };
}

async function getAdminCookie() {
  if (RT.adminCookie) return RT.adminCookie;
  const res = await panelLoginWhenReady(RT.credCandidates || []);
  RT.adminCookie = res.cookie;
  return RT.adminCookie;
}

// One reconciliation pass over all inbounds. Returns a summary; never throws.
// Singleflight: interval + event-driven reconciles must never overlap —
// two concurrent full-row updates could interleave and drop a client that
// the next round would just re-add (self-healing, but noisy). Concurrent
// callers share the in-flight run.
let reconcileInFlight = null;
async function reconcileNow(reason) {
  if (reconcileInFlight) return reconcileInFlight;
  const run = reconcileRun(reason);
  reconcileInFlight = run;
  try { return await run; }
  finally { if (reconcileInFlight === run) reconcileInFlight = null; }
}
async function reconcileRun(reason) {
  const summary = { at: new Date().toISOString(), reason: reason || "manual", added: 0, updated: 0, removed: 0, inbounds: 0, clients: 0, error: "" };
  try {
    const cookie = await getAdminCookie();
    const rows = await listInbounds(cookie);
    const users = readUsers();
    const vaultNow = readVault();
    const retired = (vaultNow.retiredUsers || []).slice();
    const retiredTokens = vaultNow.retiredTokens || {};
    const retiredStillPresent = new Set();
    summary.inbounds = rows.length;
    for (const row of rows) {
      // Per-user clients exist only for vless/vmess/trojan. Shadowsocks and
      // WireGuard are shared inbounds (one global config, MF's model) and
      // are intentionally not reconciled per user.
      if (!["vless", "vmess", "trojan"].includes(row.protocol)) continue;
      let settings = {};
      try { settings = JSON.parse(asText(row.settings) || "{}"); } catch (e) { settings = {}; }
      if (!Array.isArray(settings.clients)) settings.clients = [];
      const plan = planClientSync({ protocol: row.protocol, remark: row.remark, existingClients: settings.clients, users, retiredUsernames: retired, retiredTokens });
      summary.clients += plan.clients.length;
      if (plan.changed) {
        settings.clients = plan.clients;
        await updateInbound(cookie, row, settings);
        summary.added += plan.added; summary.updated += plan.updated; summary.removed += plan.removed;
        log("reconcile: " + row.remark + " +" + plan.added + " ~" + plan.updated + " -" + plan.removed + " (" + summary.reason + ")");
      }
      // track retired usernames that still have clients anywhere
      for (const c of plan.clients) {
        const email = String((c && c.email) || "");
        for (const name of retired) if (email === name + "-" + String(row.remark || "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "")) retiredStillPresent.add(name);
      }
    }
    if (retired.length) {
      const keep = retired.filter((n) => retiredStillPresent.has(n));
      if (keep.length !== retired.length) {
        const keptTokens = {};
        for (const n of keep) if (retiredTokens[n]) keptTokens[n] = retiredTokens[n];
        writeVault({ retiredUsers: keep, retiredTokens: keptTokens });
      }
    }
    RT.inboundCount = rows.length;
    RT.clientCount = summary.clients;
    RT.panelApiOk = true;
  } catch (e) {
    summary.error = e.message;
    RT.panelApiOk = false;
    RT.adminCookie = null; // force a fresh panel login next round (stale-cookie self-heal)
    log("reconcile failed (" + summary.reason + "): " + e.message);
  }
  RT.lastReconcile = summary;
  return summary;
}
// Sum a user's up/down traffic from panel client stats (bytes).
async function collectUserTraffic(cookie, user) {
  const rows = await listInbounds(cookie);
  let up = 0, down = 0;
  for (const row of rows) {
    const stats = Array.isArray(row.clientStats) ? row.clientStats : [];
    const email = emailFor(user, row.remark);
    for (const s of stats) if (s && s.email === email) { up += Number(s.up) || 0; down += Number(s.down) || 0; }
  }
  return { up, down, total: up + down };
}
