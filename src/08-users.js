
// Portal users: JSON store in the state dir (0600), scrypt password hashes,
// HMAC session tokens, per-user limits. The admin portal user is bridged to
// the panel admin credentials.

function readUsers() {
  const raw = readJsonFile(P.usersFile, []);
  return Array.isArray(raw) ? raw : [];
}
function writeUsers(users) {
  writeFileAtomic(P.usersFile, JSON.stringify(users, null, 2), 0o600);
}
function findUser(username) { return readUsers().find((u) => u.username === username) || null; }
function findUserByToken(token) { return readUsers().find((u) => u.subToken === token) || null; }

// scrypt with a small concurrency cap so auth bursts cannot eat the CPU of a
// 25%-of-one-core free container.
let scryptActive = 0;
const scryptQueue = [];
function scryptAsync(password, salt) {
  return new Promise((resolve, reject) => {
    const run = () => {
      scryptActive++;
      crypto.scrypt(password, salt, 32, { N: 16384, r: 8, p: 1 }, (err, key) => {
        scryptActive--;
        const next = scryptQueue.shift();
        if (next) next();
        if (err) reject(err); else resolve(key);
      });
    };
    if (scryptActive < 2) run(); else scryptQueue.push(run);
  });
}
async function hashPassword(password, salt) {
  if (!salt) salt = randomHex(16);
  const key = await scryptAsync(String(password), salt);
  return salt + ":" + key.toString("hex");
}
async function verifyPassword(password, stored) {
  try {
    const [salt, hex] = String(stored || "").split(":");
    if (!salt || !hex) return false;
    const key = await scryptAsync(String(password), salt);
    const a = Buffer.from(key.toString("hex"), "utf8");
    const b = Buffer.from(hex, "utf8");
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch (e) { return false; }
}

// Sessions: base64url(payload).base64url(hmac) — 30 days, like MF.
function makeSessionToken(username) {
  const payload = Buffer.from(JSON.stringify({ u: username, exp: Date.now() + 30 * 24 * 3600 * 1000 })).toString("base64url");
  const sig = crypto.createHmac("sha256", vaultSessionSecret()).update(payload).digest("base64url");
  return payload + "." + sig;
}
function verifySessionToken(token) {
  try {
    const [payload, sig] = String(token || "").split(".");
    if (!payload || !sig) return null;
    const expect = crypto.createHmac("sha256", vaultSessionSecret()).update(payload).digest("base64url");
    const a = Buffer.from(sig, "utf8"), b = Buffer.from(expect, "utf8");
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    const obj = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (!obj.u || !obj.exp || obj.exp < Date.now()) return null;
    return obj.u;
  } catch (e) { return null; }
}

function newPortalUser(username, passwordHash, role, limits) {
  return {
    id: crypto.randomUUID(),
    username,
    passwordHash,
    role: role || "user",
    subToken: randomHex(12),
    trafficLimitGb: limits && limits.trafficGb != null ? limits.trafficGb : CFG.userTrafficGb,
    expiresAt: limits && limits.expiresAt !== undefined ? limits.expiresAt
      : (CFG.userExpiryDays > 0 ? new Date(Date.now() + CFG.userExpiryDays * 24 * 3600 * 1000).toISOString() : null),
    enabled: true,
    createdAt: new Date().toISOString(),
  };
}
function isUserActive(u) {
  if (!u || u.enabled === false) return false;
  if (u.expiresAt && Date.parse(u.expiresAt) <= Date.now()) return false;
  return true;
}
// Limits in the units the panel expects (totalGB in BYTES, expiryTime epoch ms; 0 = none).
function clientLimits(u) {
  const totalGB = Math.round((Number(u.trafficLimitGb) || 0) * 1024 * 1024 * 1024);
  const t = u.expiresAt ? Date.parse(u.expiresAt) : 0;
  return { totalGB, expiryTime: Number.isFinite(t) && t > 0 ? t : 0, enable: isUserActive(u) };
}
// The panel requires client e-mails unique across ALL inbounds: qualify with
// the inbound remark slug (username alone silently collides after inbound #1).
function emailFor(u, remark) {
  const slug = String(remark || "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "inbound";
  return u.username + "-" + slug;
}
