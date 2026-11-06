
// Configuration: everything comes from env, parsed by ONE pure function so it
// can be unit-tested with synthetic env objects. Defaults are secure:
// registration CLOSED, non-zero default quota/expiry for new portal users.

function envInt(env, name, fallback) {
  const n = Number(env[name]);
  return Number.isFinite(n) && env[name] !== "" && env[name] != null ? Math.floor(n) : fallback;
}
function envStr(env, name, fallback) {
  const v = env[name];
  return v != null && String(v).trim() !== "" ? String(v).trim() : fallback;
}

function parseConfig(env) {
  const publicPort = envInt(env, "SERVER_PORT", envInt(env, "PORT", 8080));
  // State root: MEOWRAY_ROOT is the state dir itself. KATABUMP_ROOT (MF-era
  // compat) is treated as a parent. Default: ./meowray-state under cwd
  // (on KataBump the cwd is /home/container, which persists).
  let root;
  if (env.MEOWRAY_ROOT && String(env.MEOWRAY_ROOT).trim()) root = path.resolve(String(env.MEOWRAY_ROOT).trim());
  else if (env.KATABUMP_ROOT && String(env.KATABUMP_ROOT).trim()) root = path.join(path.resolve(String(env.KATABUMP_ROOT).trim()), "meowray-state");
  else root = path.join(process.cwd(), "meowray-state");

  const regRaw = envStr(env, "REGISTRATION", "closed").toLowerCase();
  const registration = regRaw === "open" ? "open" : regRaw === "invite" ? "invite" : "closed";

  return {
    publicPort,
    root,
    panelHost: envStr(env, "PANEL_HOST", ""),
    serverIp: envStr(env, "SERVER_IP", ""),
    publicScheme: envStr(env, "PUBLIC_SCHEME", "http").toLowerCase() === "https" ? "https" : "http",
    adminUser: envStr(env, "MEOWRAY_ADMIN_USER", "admin"),
    adminPasswordEnv: env.MEOWRAY_ADMIN_PASSWORD ? String(env.MEOWRAY_ADMIN_PASSWORD) : "",
    registration,
    inviteCode: env.MEOWRAY_INVITE_CODE ? String(env.MEOWRAY_INVITE_CODE) : "",
    // Defaults for NEW portal users. Explicit 0 in env = unlimited / no expiry.
    userTrafficGb: Math.max(0, envInt(env, "USER_TRAFFIC_GB", 10)),
    userExpiryDays: Math.max(0, envInt(env, "USER_EXPIRY_DAYS", 30)),
    // Go child memory cap in MiB; 0 = auto (70% of cgroup limit, else 192).
    goMemLimitMb: Math.max(0, envInt(env, "MEOWRAY_GOMEMLIMIT_MB", 0)),
    reconcileSec: Math.max(0, envInt(env, "MEOWRAY_RECONCILE_SEC", 60)),
    restorePath: env.MEOWRAY_RESTORE ? String(env.MEOWRAY_RESTORE).trim() : "",
    panelPort: PANEL_PORT,
    userPort: USER_PORT,
    panelBase: PANEL_BASE,
  };
}

// The one live config instance; assigned in main() (and in unit-test mode).
let CFG = null;
