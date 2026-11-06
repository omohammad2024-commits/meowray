
// Small shared helpers. Pure where practical (unit-tested via the bundle).

function log(line) {
  process.stdout.write("[" + new Date().toISOString() + "] [meowray] " + line + "\n");
}
function sleep(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }
function faDigits(s) { return String(s).replace(/\d/g, (d) => "۰۱۲۳۴۵۶۷۸۹"[d]); }
function htmlEscape(text) {
  return String(text == null ? "" : text).replace(/[&<>"]/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[ch]));
}
function randomHex(bytes) { return crypto.randomBytes(bytes).toString("hex"); }
function randomPassword() {
  // 18 chars from an unambiguous alphabet; used for the first-boot admin password.
  const alpha = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789";
  const raw = crypto.randomBytes(18);
  let out = "";
  for (const b of raw) out += alpha[b % alpha.length];
  return out;
}
function sha256File(file) {
  return new Promise((resolve, reject) => {
    const h = crypto.createHash("sha256");
    const rs = fs.createReadStream(file);
    rs.on("data", (c) => h.update(c));
    rs.on("end", () => resolve(h.digest("hex")));
    rs.on("error", reject);
  });
}
function sha256Buffer(buf) { return crypto.createHash("sha256").update(buf).digest("hex"); }

// Atomic file write with explicit permissions (default 0600 — state is private).
function writeFileAtomic(file, data, mode) {
  const tmp = file + ".tmp-" + process.pid;
  fs.writeFileSync(tmp, data, { mode: mode == null ? 0o600 : mode });
  try { fs.chmodSync(tmp, mode == null ? 0o600 : mode); } catch (e) {}
  fs.renameSync(tmp, file);
}
function readJsonFile(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, "utf8")); } catch (e) { return fallback; }
}

function diskFreeBytes(dir) {
  try {
    const r = spawnSync("df", ["-B1", "--output=avail", dir], { encoding: "utf8", timeout: 5000 });
    const lines = String(r.stdout || "").trim().split("\n");
    const n = Number(lines[lines.length - 1]);
    return Number.isFinite(n) ? n : 0;
  } catch (e) { return 0; }
}

// cgroup memory limit in bytes (0 = none / unlimited / unknown). Pure parser
// split out for unit tests: parseCgroupLimit(textV2, textV1).
function parseCgroupLimit(v2text, v1text) {
  const v2 = String(v2text == null ? "" : v2text).trim();
  if (v2 && v2 !== "max") {
    const n = Number(v2);
    if (Number.isFinite(n) && n > 0 && n < 1e15) return n;
  }
  const v1 = String(v1text == null ? "" : v1text).trim();
  const n1 = Number(v1);
  if (Number.isFinite(n1) && n1 > 0 && n1 < 1e15) return n1;
  return 0;
}
function cgroupLimit() {
  let v2 = null, v1 = null;
  try { v2 = fs.readFileSync("/sys/fs/cgroup/memory.max", "utf8"); } catch (e) {}
  try { v1 = fs.readFileSync("/sys/fs/cgroup/memory/memory.limit_in_bytes", "utf8"); } catch (e) {}
  return parseCgroupLimit(v2, v1);
}

// RSS of a pid in bytes (Linux /proc). 0 when unavailable.
function rssOfPid(pid) {
  try {
    const text = fs.readFileSync("/proc/" + pid + "/status", "utf8");
    const m = text.match(/VmRSS:\s*(\d+)\s*kB/);
    return m ? Number(m[1]) * 1024 : 0;
  } catch (e) { return 0; }
}
// All descendants of a pid (for process-tree RSS accounting).
function childPids(pid) {
  const out = [];
  let entries = [];
  try { entries = fs.readdirSync("/proc"); } catch (e) { return out; }
  const byParent = new Map();
  for (const name of entries) {
    if (!/^\d+$/.test(name)) continue;
    try {
      const stat = fs.readFileSync("/proc/" + name + "/stat", "utf8");
      const close = stat.lastIndexOf(")");
      const fields = stat.slice(close + 2).split(" ");
      const ppid = Number(fields[1]);
      if (!byParent.has(ppid)) byParent.set(ppid, []);
      byParent.get(ppid).push(Number(name));
    } catch (e) {}
  }
  const walk = (p) => { for (const c of byParent.get(p) || []) { out.push(c); walk(c); } };
  walk(pid);
  return out;
}
function treeRssBytes(rootPid) {
  let total = rssOfPid(rootPid);
  const detail = [{ pid: rootPid, rss: total, self: true }];
  for (const pid of childPids(rootPid)) {
    const rss = rssOfPid(pid);
    let cmd = "";
    try { cmd = fs.readFileSync("/proc/" + pid + "/comm", "utf8").trim(); } catch (e) {}
    detail.push({ pid, rss, cmd });
    total += rss;
  }
  return { total, detail };
}
function dirSizeBytes(dir) {
  let total = 0;
  const walk = (d) => {
    let entries = [];
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch (e) { return; }
    for (const e of entries) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.isFile()) { try { total += fs.statSync(p).size; } catch (err) {} }
    }
  };
  walk(dir);
  return total;
}
function isPublicIp(text) {
  const ip = String(text || "").trim();
  if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) return false;
  const parts = ip.split(".").map(Number);
  if (parts.some((n) => n > 255)) return false;
  if (parts[0] === 10 || parts[0] === 127) return false;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return false;
  if (parts[0] === 192 && parts[1] === 168) return false;
  if (parts[0] === 169 && parts[1] === 254) return false;
  return true;
}
