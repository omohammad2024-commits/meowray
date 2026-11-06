
// Paths (ALL state under CFG.root) + the runner's runtime state + vault.
//
// Vault honesty note: the panel binary cannot reset its admin password after
// first boot (verified experimentally against v1.9.4: `setting -password` is
// a no-op on an existing DB) and offers the runner no token auth, so an
// unattended runner must keep ONE usable copy of the panel admin password.
// We keep exactly one copy, in state.json with mode 0600, never duplicated
// into PANEL.txt or logs (MF kept it in two plaintext files with default
// permissions). Every secret the runner only *verifies* (portal passwords)
// is scrypt-hashed, never stored usable.

let P = null; // paths, built by initPaths()
function initPaths() {
  const root = CFG.root;
  P = {
    root,
    panelDir: path.join(root, "panel"),
    binFile: path.join(root, "panel", "vpn-ui-amd64"),
    binMark: path.join(root, "panel", "vpn-ui-amd64.ok"),
    dataDir: path.join(root, "data"),
    xrayDir: path.join(root, "bin"),
    logDir: path.join(root, "log"),
    glibcDir: path.join(root, "panel", "glibc"),
    loaderCopy: path.join(root, "panel", "ld.so"),
    dropcacheFile: path.join(root, "panel", "dropcache"),
    stateFile: path.join(root, "state.json"),
    usersFile: path.join(root, "data", "mr_users.json"),
    accessFile: path.join(root, "PANEL.txt"),
    backupsDir: path.join(root, "backups"),
    restoreFile: path.join(root, "restore.tar.gz"),
  };
  return P;
}
function ensureStateDirs() {
  for (const d of [P.root, P.panelDir, P.dataDir, P.xrayDir, P.logDir, P.backupsDir]) {
    fs.mkdirSync(d, { recursive: true });
  }
}

// Runtime (in-memory) state.
const RT = {
  ready: false,
  fatal: "",            // fatal boot error message; process exits instead of zombie-serving
  status: "starting",
  publicHost: "",
  child: null,
  childStartedAt: 0,
  restarts: 0,
  stopping: false,
  adminCookie: null,
  panelUp: false,
  panelApiOk: false,
  inboundCount: 0,
  clientCount: 0,
  loader: "",
  libPath: "",
  directExec: false,
  trimmed: false,
  lastReconcile: null,
  bootStartedAt: Date.now(),
  readyAt: 0,
};

// Persistent runner state (state.json, 0600).
function readVault() { return readJsonFile(P.stateFile, {}); }
function writeVault(patch) {
  const next = Object.assign(readVault(), patch);
  writeFileAtomic(P.stateFile, JSON.stringify(next, null, 2), 0o600);
  return next;
}
function vaultSessionSecret() {
  const v = readVault();
  if (v.sessionSecret) return v.sessionSecret;
  const secret = randomHex(32);
  writeVault({ sessionSecret: secret });
  return secret;
}
