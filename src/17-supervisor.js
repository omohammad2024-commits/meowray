
// Supervisor: the panel child is restarted with backoff when it dies
// (MF exited with it). Health is tracked in RT for /healthz; a child that
// cannot start at boot is a FATAL boot error handled by main — never a
// zombie status page.

const RESTART_BACKOFF_MS = [1000, 2000, 4000, 8000, 16000, 30000];
let restartAttempt = 0;
let stableTimer = null;

function portOpen(port) {
  return new Promise((resolve) => {
    const socket = net.connect({ host: "127.0.0.1", port }, () => { socket.end(); resolve(true); });
    socket.on("error", () => resolve(false));
    socket.setTimeout(1000, () => { socket.destroy(); resolve(false); });
  });
}
async function waitForPanel(timeoutMs) {
  const deadline = Date.now() + (timeoutMs || 90000);
  while (Date.now() < deadline) {
    if (await portOpen(PANEL_PORT)) return true;
    await sleep(750);
  }
  return false;
}
function startPanel() {
  const launch = binLaunch(["run"]);
  const child = spawn(launch.command, launch.args, { cwd: P.panelDir, env: panelEnv(), stdio: ["ignore", "pipe", "pipe"] });
  RT.child = child;
  RT.childStartedAt = Date.now();
  RT.panelUp = false;
  let geoHandled = false;
  const emit = (buf) => {
    const text = buf.toString("utf8");
    process.stdout.write(text);
    if (!geoHandled && /extracted bundled geo|Web server running/i.test(text)) {
      geoHandled = true;
      setTimeout(() => { try { trimGeoFiles(); } catch (e) {} }, 500);
    }
  };
  child.stdout.on("data", emit);
  child.stderr.on("data", emit);
  child.on("error", (err) => log("panel spawn failed: " + err.message));
  child.on("exit", (code, signal) => {
    RT.child = null;
    RT.panelUp = false;
    RT.adminCookie = null;
    if (RT.stopping) return;
    RT.restarts++;
    const delay = RESTART_BACKOFF_MS[Math.min(restartAttempt, RESTART_BACKOFF_MS.length - 1)];
    restartAttempt++;
    log("panel exited (" + (signal || code) + ") — supervisor restart #" + RT.restarts + " in " + delay + "ms");
    setTimeout(async () => {
      if (RT.stopping) return;
      try {
        startPanel();
        const up = await waitForPanel(60000);
        if (up) {
          RT.panelUp = true;
          try {
            const res = await panelLoginWhenReady(RT.credCandidates || []);
            RT.adminCookie = res.cookie;
            await reconcileNow("supervisor-restart");
          } catch (e) { log("post-restart login failed: " + e.message); }
        } else log("panel did not come back after restart");
      } catch (e) { log("supervisor restart failed: " + e.message); }
    }, delay);
  });
  // Reset backoff once the child has been stable for a minute.
  if (stableTimer) clearTimeout(stableTimer);
  stableTimer = setTimeout(() => { restartAttempt = 0; }, 60000);
  return child;
}
function rotateLogsIfNeeded() {
  try {
    const file = path.join(P.logDir, "vpn-ui.log");
    if (fs.existsSync(file) && fs.statSync(file).size > 5 * 1024 * 1024) {
      fs.renameSync(file, file + ".1");
      log("panel log rotated (>5 MB)");
    }
  } catch (e) {}
}
function shutdown() {
  if (RT.stopping) return;
  RT.stopping = true;
  if (RT.child && !RT.child.killed) { try { RT.child.kill("SIGTERM"); } catch (e) {} }
  setTimeout(() => process.exit(0), 600).unref();
}
