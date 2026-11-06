// MeowRay — single-file runner. Built from src/ modules by build.js; do not edit dist directly.

// ===== src/00-head.js =====
// MeowRay — a portable, single-public-port runner for the vpn-ui panel binary.
// Written from scratch as small modules, bundled into ONE index.js (see build.js).
// Form factor: upload index.js + package.json to KataBump / Railway / any Node host.
// Zero npm dependencies — Node.js builtins only. Non-root. One public TCP port.
// All state lives under ONE directory (MEOWRAY_ROOT) so a host ban is a
// minutes-long migration (export one bundle, restore on the new host), never a rebuild.

const http = require("http");
const https = require("https");
const net = require("net");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const zlib = require("zlib");
const os = require("os");
const { spawn, spawnSync } = require("child_process");


// ===== src/01-versions.js =====

// ---------------------------------------------------------------------------
// VERSION TABLE — every pinned external artifact lives here, nowhere else.
// To bump a version: add/replace the row (url + sha256 + patch bytes for the
// panel binary), then run `npm test` (selftest dry-runs the patch) and the
// boot smoke. The root-check patch is byte-exact and FAILS CLOSED on any
// binary whose bytes differ from the pinned release.
// ---------------------------------------------------------------------------
const RUNNER_VERSION = "meowray-1.0.0";
const BRAND = "MeowRay";

const VERSIONS = {
  panel: {
    version: "1.9.4",
    // Sir-MmD/vpn-ui v1.9.4 release binary (same pinned artifact MF Panel used).
    url: "https://github.com/Sir-MmD/vpn-ui/releases/download/v1.9.4/vpn-ui-amd64",
    sha256: "18ec321d9074b319bd5756508bbc523ab5d95450b832c406acdd72e987a2da8f",
    // SHA-256 of the pinned binary AFTER the root patch below (the patch is
    // a fixed 6-byte replacement, so this is deterministic). Provenance:
    // derived from the Phase-0 artifact whose pre-patch hash was verified
    // against sha256 above; re-derived by reverting the 6 jump bytes in the
    // patched file, which reproduces sha256 exactly. ensureBinary accepts
    // ONLY these two hashes — a cached binary is never trusted via its
    // .ok mark or the patch needle alone. To bump: download the new
    // release, verify sha256, apply the patch, record the new patched hash.
    patchedSha256: "dab7332ce04b9cce90e9b975e4c7353193bfe2e0d1f59011020c478df5430bba",
    // Unique bytes inside vpn-ui v1.9.4 requireRoot, ending at the euid==0
    // conditional jump. Replacing that jump with an unconditional jump lets
    // the panel boot without root; it grants no kernel capabilities.
    patchNeedleHex: "3425f8ffffff48837c2420000f84f4000000",
    patchExpectHex: "0f84f4000000", // the conditional jump that must be present
    patchJumpHex: "e9f500000090",   // unconditional jump over the root check
  },
  // Bundled glibc runtime, used ONLY when the host glibc is < 2.34.
  // [url, local name, expected SHA-256] — hashes match Ubuntu's signed
  // jammy / jammy-updates Packages index.
  glibcDebs: [
    ["https://archive.ubuntu.com/ubuntu/pool/main/g/glibc/libc6_2.35-0ubuntu3.15_amd64.deb", "libc6.deb",
      "79e35256227e16a607c154cdeb8d76ff12d20e31de286ea7fd9ad3b96fe0452d"],
    ["https://archive.ubuntu.com/ubuntu/pool/main/g/gcc-12/libgcc-s1_12.3.0-1ubuntu1~22.04.3_amd64.deb", "libgcc.deb",
      "d383e642d83263147f7b4b69fb92cf1036e5246c6be3accf10b77f986684589a"],
    ["https://archive.ubuntu.com/ubuntu/pool/main/libx/libxcrypt/libcrypt1_4.4.27-1_amd64.deb", "libcrypt.deb",
      "3fa566e9f861a08736cbc5a97562d9d6e4f0c00450fbeafcb6d7583423b04a98"],
  ],
  glibcFiles: [
    "ld-linux-x86-64.so.2", "libc.so.6", "libresolv.so.2", "libnss_dns.so.2",
    "libnss_files.so.2", "libgcc_s.so.1", "libcrypt.so.1", "libcrypt.so.1.1.0",
  ],
  // Our own tiny static ELF helper (hand-assembled for MeowRay, source in
  // src/04-dropcache.js): open(path) + posix_fadvise(DONTNEED) + exit_group.
  dropcacheSha256: "eb09fe61e2e7f80366fa696958d1aa1feae2dd5ef735d81c49a0780356096941",
};

// Internal fixed ports (loopback only). The public port comes from env.
const PANEL_PORT = 18080;
const USER_PORT = 18081;
const PANEL_BASE = "/kb";


// ===== src/02-utils.js =====

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


// ===== src/03-config.js =====

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


// ===== src/04-dropcache.js =====

// dropcache helper: a tiny hand-assembled static x86-64 ELF (186 bytes) that
// asks the kernel to drop ONE file from the page cache:
//   fd = open(argv[1], O_RDONLY); posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
//   exit_group(0 on success, 1 on failure)
// Assembly (offsets verified by unit test executing it):
//   cmp qword [rsp],2 ; jb fail ; mov rdi,[rsp+16] ; xor esi,esi ;
//   mov eax,2 ; syscall ; test rax,rax ; js fail ; mov edi,eax ;
//   xor esi,esi ; xor edx,edx ; mov r10d,4 ; mov eax,221 ; syscall ;
//   test rax,rax ; jnz fail ; xor edi,edi ; jmp done ; fail: mov edi,1 ;
//   done: mov eax,231 ; syscall
// Written for MeowRay (not copied from any other project); its SHA-256 is
// pinned in VERSIONS.dropcacheSha256 and re-verified on every write.
const DROPCACHE_HEX =
  "7f454c4602010100000000000000000002003e0001000000780040000000000040000000000000000000000000000000" +
  "000000004000380001000000000000000100000005000000000000000000000000004000000000000000400000000000" +
  "ba00000000000000ba00000000000000001000000000000048833c2402722f488b7c241031f6b8020000000f054885c0" +
  "781c89c731f631d241ba04000000b8dd0000000f054885c0750431ffeb05bf01000000b8e70000000f05";

function dropcacheBuffer() { return Buffer.from(DROPCACHE_HEX, "hex"); }

function ensureDropcache() {
  const file = P.dropcacheFile;
  let ok = false;
  try { ok = fs.existsSync(file) && sha256Buffer(fs.readFileSync(file)) === VERSIONS.dropcacheSha256; } catch (e) {}
  if (!ok) {
    fs.rmSync(file, { force: true });
    fs.writeFileSync(file, dropcacheBuffer());
  }
  // A restored state keeps the right bytes but may lose the exec bit
  // (bundle extraction does not restore modes for helper binaries).
  try { fs.chmodSync(file, 0o755); } catch (e) {}
  return file;
}

let dropcacheWarned = false;
function dropFileCache(file) {
  if (!file || !fs.existsSync(file)) return;
  try {
    const r = spawnSync(ensureDropcache(), [file], { timeout: 4000, stdio: "ignore" });
    if ((r.error || r.status !== 0) && !dropcacheWarned) {
      dropcacheWarned = true;
      log("page-cache drop skipped (harmless, slightly higher RAM): " + (r.error ? r.error.message : "exit " + r.status));
    }
  } catch (e) {
    if (!dropcacheWarned) { dropcacheWarned = true; log("page-cache drop skipped: " + e.message); }
  }
}


// ===== src/05-bundle.js =====

// State bundle: the whole state directory as ONE .tar.gz file, built and
// extracted with Node builtins only (streaming — the panel binary is ~346 MB
// and must never be buffered in RAM on a 308 MB host).
// Security: extraction validates every entry name (no absolute paths, no
// "..", no links/devices) BEFORE writing anything for that entry; anything
// suspicious aborts the restore and keeps the old state untouched.

const BUNDLE_MAX_BYTES = 6 * 1024 * 1024 * 1024; // sanity cap on extracted size

function validateTarEntryName(name) {
  if (!name || typeof name !== "string") return false;
  if (name.startsWith("/") || name.includes("\\")) return false;
  const parts = name.split("/");
  for (const part of parts) {
    if (part === ".." || part === ".") return false;
    if (part.includes("\0")) return false;
  }
  return true;
}

function tarHeader(name, size, typeflag, mode, mtimeSec) {
  if (name.length > 100) {
    // ustar prefix split at a '/' boundary
    let split = -1;
    for (let i = Math.min(155, name.length - 1); i > 0; i--) {
      const candidate = name.length - (i + 1);
      if (name[i] === "/" && candidate <= 100 && i <= 155) { split = i; break; }
    }
    if (split < 0) throw new Error("path too long for tar: " + name);
    return tarHeaderWithPrefix(name.slice(split + 1), name.slice(0, split), size, typeflag, mode, mtimeSec);
  }
  return tarHeaderWithPrefix(name, "", size, typeflag, mode, mtimeSec);
}
function tarHeaderWithPrefix(name, prefix, size, typeflag, mode, mtimeSec) {
  const h = Buffer.alloc(512);
  h.write(name, 0, 100, "utf8");
  h.write(("0000000" + (mode & 0o777).toString(8)).slice(-7) + "\0", 100);
  h.write("0000000\0", 108); // uid
  h.write("0000000\0", 116); // gid
  h.write(("00000000000" + size.toString(8)).slice(-11) + " ", 124);
  h.write(("00000000000" + Math.floor(mtimeSec).toString(8)).slice(-11) + " ", 136);
  h.fill(0x20, 148, 156); // checksum as spaces during computation
  h.write(typeflag, 156);
  h.write("ustar\0", 257);
  h.write("00", 263);
  if (prefix) h.write(prefix, 345, 155, "utf8");
  let sum = 0;
  for (const b of h) sum += b;
  h.write(("000000" + sum.toString(8)).slice(-6) + "\0 ", 148);
  return h;
}
function tarPadding(size) { const r = size % 512; return r === 0 ? 0 : 512 - r; }

// In-memory tar build/parse (unit tests + small payloads).
function buildTarBuffer(entries) {
  const chunks = [];
  for (const e of entries) {
    const data = e.data || Buffer.alloc(0);
    chunks.push(tarHeader(e.name, e.type === "5" ? 0 : data.length, e.type || "0", e.mode || 0o644, e.mtime || 0));
    if (e.type !== "5") { chunks.push(data); const pad = tarPadding(data.length); if (pad) chunks.push(Buffer.alloc(pad)); }
  }
  chunks.push(Buffer.alloc(1024)); // end-of-archive
  return Buffer.concat(chunks);
}
function parseTarBuffer(buf) {
  const entries = [];
  let off = 0;
  while (off + 512 <= buf.length) {
    const h = buf.subarray(off, off + 512);
    if (h[0] === 0) break;
    off += 512;
    const name = h.subarray(0, 100).toString("utf8").replace(/\0.*$/, "");
    const prefix = h.subarray(345, 500).toString("utf8").replace(/\0.*$/, "");
    const full = prefix ? prefix + "/" + name : name;
    const size = parseInt(h.subarray(124, 136).toString("utf8").replace(/\0.*$/, "").trim(), 8) || 0;
    const type = String.fromCharCode(h[156] || 48);
    const linkname = h.subarray(157, 257).toString("utf8").replace(/\0.*$/, "");
    const data = buf.subarray(off, off + size);
    entries.push({ name: full, size, type, linkname, data: Buffer.from(data) });
    off += size + tarPadding(size);
  }
  return entries;
}

function listStateFiles(stateDir, skipDirs) {
  const out = [];
  const walk = (dir, rel) => {
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { return; }
    for (const e of entries) {
      const relPath = rel ? rel + "/" + e.name : e.name;
      if (e.isDirectory()) {
        if (skipDirs && skipDirs.has(e.name) && !rel) continue;
        walk(path.join(dir, e.name), relPath);
      } else if (e.isFile()) {
        if (e.name.endsWith(".part")) continue;
        if (e.name.endsWith(".sock")) continue; // runtime socket, never state
        out.push(relPath);
      }
    }
  };
  walk(stateDir, "");
  return out.sort();
}

async function streamWrite(stream, chunk) {
  if (!stream.write(chunk)) await new Promise((res) => stream.once("drain", res));
}

// createBundle(stateDir, outPath) → {files, bytes}
// The panel DB is a live SQLite WAL database: copying db/-wal/-shm files
// raw can produce an inconsistent set that crashes the binary on restore
// (observed: `setting` killed by signal on a raw-copied restore). When
// node:sqlite is available, substitute a VACUUM INTO snapshot — a single
// consistent file with no WAL companions. Falls back to the raw copy.
function vacuumPanelDb(dbFull, tmpPath) {
  try {
    const { DatabaseSync } = require("node:sqlite");
    fs.rmSync(tmpPath, { force: true });
    const db = new DatabaseSync(dbFull, { readOnly: true });
    db.exec("VACUUM INTO '" + tmpPath.replace(/'/g, "''") + "'");
    db.close();
    return fs.existsSync(tmpPath) && fs.statSync(tmpPath).size > 0;
  } catch (e) {
    return false;
  }
}
async function createBundle(stateDir, outPath) {
  let files = listStateFiles(stateDir, new Set(["backups"]));
  const dbRel = "data/vpn-ui.db";
  let vacuumTmp = null;
  if (files.includes(dbRel)) {
    const tmp = outPath + ".vacuum.db";
    if (vacuumPanelDb(path.join(stateDir, dbRel), tmp)) {
      vacuumTmp = tmp;
      files = files.filter((f) => f !== dbRel && f !== dbRel + "-wal" && f !== dbRel + "-shm");
    }
  }
  // Level 1: the payload is mostly a 330 MB binary that barely compresses;
  // backup speed matters more than the last few percent of size.
  const gz = zlib.createGzip({ level: 1 });
  const out = fs.createWriteStream(outPath, { mode: 0o600 });
  gz.pipe(out);
  let bytes = 0;
  const allFiles = vacuumTmp ? files.concat([dbRel]) : files;
  for (const rel of allFiles) {
    const full = vacuumTmp && rel === dbRel ? vacuumTmp : path.join(stateDir, rel);
    const stat = fs.statSync(full);
    await streamWrite(gz, tarHeader(rel, stat.size, "0", stat.mode, stat.mtimeMs / 1000));
    bytes += 512;
    await new Promise((resolve, reject) => {
      const rs = fs.createReadStream(full);
      rs.on("data", (chunk) => {
        bytes += chunk.length;
        if (!gz.write(chunk)) { rs.pause(); gz.once("drain", () => rs.resume()); }
      });
      rs.on("end", resolve);
      rs.on("error", reject);
    });
    const pad = tarPadding(stat.size);
    if (pad) await streamWrite(gz, Buffer.alloc(pad));
    bytes += pad;
  }
  await streamWrite(gz, Buffer.alloc(1024));
  await new Promise((resolve, reject) => { gz.end(); out.on("finish", resolve); out.on("error", reject); });
  if (vacuumTmp) { try { fs.rmSync(vacuumTmp, { force: true }); } catch (e) {} }
  return { files: allFiles.length, bytes };
}

// extractBundle(bundlePath, destDir) → {files, bytes}; throws on anything invalid.
async function extractBundle(bundlePath, destDir) {
  const gun = zlib.createGunzip();
  const input = fs.createReadStream(bundlePath);
  let leftover = Buffer.alloc(0);
  let mode = "header"; // header | data
  let current = null;
  let files = 0, bytes = 0;
  let fileStream = null;

  const processBuffer = async (final) => {
    for (;;) {
      if (mode === "header") {
        if (leftover.length < 512) { if (final) throw new Error("truncated tar header"); return; }
        const h = leftover.subarray(0, 512);
        if (h[0] === 0) { mode = "end"; return; }
        const name = h.subarray(0, 100).toString("utf8").replace(/\0.*$/, "");
        const prefix = h.subarray(345, 500).toString("utf8").replace(/\0.*$/, "");
        const full = prefix ? prefix + "/" + name : name;
        const size = parseInt(h.subarray(124, 136).toString("utf8").replace(/\0.*$/, "").trim(), 8) || 0;
        const type = String.fromCharCode(h[156] || 48);
        const entryMode = parseInt(h.subarray(100, 108).toString("utf8").replace(/\0.*$/, "").trim(), 8) || 0o600;
        if (!validateTarEntryName(full)) throw new Error("unsafe path in bundle: " + JSON.stringify(full));
        if (type !== "0" && type !== "\0" && type !== "5") throw new Error("unsupported entry type in bundle: " + type + " for " + full);
        bytes += size;
        if (bytes > BUNDLE_MAX_BYTES) throw new Error("bundle expands beyond sanity cap");
        leftover = leftover.subarray(512);
        const target = path.join(destDir, full);
        if (path.resolve(target) !== path.resolve(destDir) && !path.resolve(target).startsWith(path.resolve(destDir) + path.sep)) {
          throw new Error("bundle entry escapes destination: " + full);
        }
        if (type === "5") {
          fs.mkdirSync(target, { recursive: true });
          mode = "header";
          continue;
        }
        fs.mkdirSync(path.dirname(target), { recursive: true });
        fileStream = fs.createWriteStream(target, { mode: 0o600 });
        current = { remaining: size, pad: tarPadding(size), name: full, entryMode, target };
        mode = "data";
        files++;
      } else if (mode === "data") {
        const need = current.remaining + current.pad;
        if (leftover.length === 0) { if (final) throw new Error("truncated tar data"); return; }
        const take = Math.min(leftover.length, need);
        const writeBytes = Math.min(take, current.remaining);
        if (writeBytes > 0) await streamWrite(fileStream, leftover.subarray(0, writeBytes));
        leftover = leftover.subarray(take);
        current.remaining -= writeBytes;
        const consumed = take - writeBytes;
        current.pad -= consumed;
        if (current.remaining === 0 && current.pad === 0) {
          await new Promise((res, rej) => { fileStream.end(); fileStream.on("finish", res); fileStream.on("error", rej); });
          // Apply the archived mode only now that the file definitely
          // exists (chmod right after createWriteStream races its open
          // and silently loses the exec bit — a restored panel binary
          // then fails to spawn with EACCES).
          try { fs.chmodSync(current.target, current.entryMode & 0o777); } catch (e) {}
          fileStream = null;
          current = null;
          mode = "header";
          continue;
        }
        if (leftover.length === 0) return;
      } else {
        return;
      }
    }
  };

  await new Promise((resolve, reject) => {
    input.on("error", reject);
    gun.on("error", reject);
    gun.on("data", (chunk) => {
      gun.pause();
      leftover = leftover.length ? Buffer.concat([leftover, chunk]) : chunk;
      processBuffer(false).then(() => gun.resume(), reject);
    });
    gun.on("end", resolve);
    input.pipe(gun);
  });
  await processBuffer(true);
  return { files, bytes };
}


// ===== src/06-qr.js =====

// QR Code generator written for MeowRay: byte mode, error level M,
// versions 1–8 (up to ~150 chars — plenty for a subscription URL).
// No memorized format/version tables: format and version info are computed
// with their BCH codes; Reed–Solomon runs over GF(256)/0x11d. The encoder is
// cross-validated module-for-module against Nayuki's qrcodegen in the test
// suite (tests/qr-check.js, dev-only; segno was rejected as reference — it
// emits a non-spec 0x00 pad byte on byte-boundary payloads).

const QR_TABLE = {
  1: { total: 26, ec: 10, groups: [[1, 16]], align: [], rem: 0 },
  2: { total: 44, ec: 16, groups: [[1, 28]], align: [6, 18], rem: 7 },
  3: { total: 70, ec: 26, groups: [[1, 44]], align: [6, 22], rem: 7 },
  4: { total: 100, ec: 18, groups: [[2, 32]], align: [6, 26], rem: 7 },
  5: { total: 134, ec: 24, groups: [[2, 43]], align: [6, 30], rem: 7 },
  6: { total: 172, ec: 16, groups: [[4, 27]], align: [6, 34], rem: 7 },
  7: { total: 196, ec: 18, groups: [[4, 31]], align: [6, 22, 38], rem: 0 },
  8: { total: 242, ec: 22, groups: [[2, 38], [2, 39]], align: [6, 24, 42], rem: 0 },
};
const GF_EXP = new Array(512);
const GF_LOG = new Array(256);
(function initGf() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x; GF_LOG[x] = i;
    x <<= 1; if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255];
})();
function gfMul(a, b) { return a === 0 || b === 0 ? 0 : GF_EXP[GF_LOG[a] + GF_LOG[b]]; }
function rsGenerator(deg) {
  // g(x) = Π_{i=0}^{deg-1} (x − α^i); coefficients in descending order.
  let poly = [1];
  for (let i = 0; i < deg; i++) {
    const next = new Array(poly.length + 1).fill(0);
    for (let j = 0; j < next.length; j++) {
      const fromX = j < poly.length ? poly[j] : 0;              // x · P term
      const fromRoot = j > 0 ? gfMul(poly[j - 1], GF_EXP[i]) : 0; // α^i · P term
      next[j] = fromX ^ fromRoot;
    }
    poly = next;
  }
  return poly;
}
function rsRemainder(data, gen) {
  const res = new Array(gen.length - 1).fill(0);
  for (const b of data) {
    const factor = b ^ res.shift();
    res.push(0);
    for (let i = 0; i < gen.length - 1; i++) res[i] ^= gfMul(gen[i + 1], factor);
  }
  return res;
}
function qrDataCodewords(bytes, version) {
  const info = QR_TABLE[version];
  const totalData = info.groups.reduce((s, [c, n]) => s + c * n, 0);
  const bits = [];
  const push = (val, len) => { for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1); };
  push(0b0100, 4); // byte mode
  push(bytes.length, 8); // length (versions 1–9 use 8 bits in byte mode)
  for (const b of bytes) push(b, 8);
  const capacity = totalData * 8;
  const term = Math.min(4, capacity - bits.length);
  for (let i = 0; i < term; i++) bits.push(0);
  while (bits.length % 8 !== 0) bits.push(0);
  const pads = [0xec, 0x11];
  let pi = 0;
  while (bits.length < capacity) { push(pads[pi % 2], 8); pi++; }
  const out = [];
  for (let i = 0; i < bits.length; i += 8) {
    let v = 0; for (let j = 0; j < 8; j++) v = (v << 1) | bits[i + j];
    out.push(v);
  }
  return out;
}
function qrInterleave(dataCw, version) {
  const info = QR_TABLE[version];
  const gen = rsGenerator(info.ec);
  const dataBlocks = [];
  const ecBlocks = [];
  let off = 0;
  for (const [count, per] of info.groups) {
    for (let i = 0; i < count; i++) {
      const block = dataCw.slice(off, off + per); off += per;
      dataBlocks.push(block);
      ecBlocks.push(rsRemainder(block, gen));
    }
  }
  const out = [];
  const maxData = Math.max(...dataBlocks.map((b) => b.length));
  for (let i = 0; i < maxData; i++) for (const b of dataBlocks) if (i < b.length) out.push(b[i]);
  for (let i = 0; i < info.ec; i++) for (const b of ecBlocks) out.push(b[i]);
  return { codewords: out, remainderBits: info.rem }; // remainder bits are appended as 0 bits by the matrix builder
}
function qrFormatBits(mask) {
  const data = mask; // EC level M indicator bits are 00, so data = 0b00<<3 | mask
  let rem = data << 10;
  const g = 0b10100110111;
  for (let i = 14; i >= 10; i--) if ((rem >>> i) & 1) rem ^= g << (i - 10);
  return (((data << 10) | rem) ^ 0b101010000010010).toString(2).padStart(15, "0");
}
function qrVersionBits(version) {
  let rem = version << 12;
  const g = 0x1f25;
  for (let i = 17; i >= 12; i--) if ((rem >>> i) & 1) rem ^= g << (i - 12);
  return ((version << 12) | rem).toString(2).padStart(18, "0");
}
function qrBuildMatrix(version, codewords, remBits, mask) {
  const size = version * 4 + 17;
  const m = Array.from({ length: size }, () => new Array(size).fill(null));
  const set = (r, c, v) => { if (r >= 0 && r < size && c >= 0 && c < size) m[r][c] = v; };
  function finder(r0, c0) {
    for (let r = -1; r < 8; r++) for (let c = -1; c < 8; c++) {
      const inside = r >= 0 && r < 7 && c >= 0 && c < 7;
      const border = inside && (r === 0 || r === 6 || c === 0 || c === 6);
      const core = r >= 2 && r <= 4 && c >= 2 && c <= 4;
      set(r0 + r, c0 + c, inside ? (border || core ? 1 : 0) : 0);
    }
  }
  finder(0, 0); finder(0, size - 7); finder(size - 7, 0);
  const info = QR_TABLE[version];
  for (const r of info.align) for (const c of info.align) {
    if (m[r] && m[r][c] !== null) continue; // overlaps finder areas
    // skip positions overlapping finder patterns
    if ((r < 9 && c < 9) || (r < 9 && c > size - 10) || (r > size - 10 && c < 9)) continue;
    for (let dr = -2; dr <= 2; dr++) for (let dc = -2; dc <= 2; dc++) {
      set(r + dr, c + dc, Math.max(Math.abs(dr), Math.abs(dc)) !== 1 ? 1 : 0);
    }
  }
  for (let i = 8; i < size - 8; i++) { if (m[6][i] === null) m[6][i] = i % 2 === 0 ? 1 : 0; if (m[i][6] === null) m[i][6] = i % 2 === 0 ? 1 : 0; }
  // reserve format info cells
  for (let i = 0; i < 9; i++) { if (m[8][i] === null) m[8][i] = 0; if (m[i][8] === null) m[i][8] = 0; }
  for (let i = 0; i < 8; i++) { if (m[8][size - 1 - i] === null) m[8][size - 1 - i] = 0; if (m[size - 1 - i][8] === null) m[size - 1 - i][8] = 0; }
  m[size - 8][8] = 1; // dark module
  if (version >= 7) {
    const bits = qrVersionBits(version);
    for (let i = 0; i < 18; i++) {
      const v = Number(bits[17 - i]);
      m[Math.floor(i / 3)][size - 11 + (i % 3)] = v;
      m[size - 11 + (i % 3)][Math.floor(i / 3)] = v;
    }
  }
  // data bits (codewords + remainder), MSB first
  const bits = [];
  for (const cw of codewords) for (let i = 7; i >= 0; i--) bits.push((cw >>> i) & 1);
  for (let i = 0; i < remBits; i++) bits.push(0);
  const maskFn = [
    (r, c) => (r + c) % 2 === 0, (r) => r % 2 === 0, (r, c) => c % 3 === 0,
    (r, c) => (r + c) % 3 === 0, (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
    (r, c) => ((r * c) % 2) + ((r * c) % 3) === 0,
    (r, c) => (((r * c) % 2) + ((r * c) % 3)) % 2 === 0,
    (r, c) => (((r + c) % 2) + ((r * c) % 3)) % 2 === 0,
  ][mask];
  let bi = 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++) {
      for (let j = 0; j < 2; j++) {
        const c = right - j;
        const upward = ((right + 1) & 2) === 0;
        const r = upward ? size - 1 - vert : vert;
        if (m[r][c] === null) {
          let v = bi < bits.length ? bits[bi++] : 0;
          if (maskFn(r, c)) v ^= 1;
          m[r][c] = v;
        }
      }
    }
  }
  // format info placement (bit(i) = the i-th format bit, 14 = MSB)
  const fb = qrFormatBits(mask);
  const bit = (i) => Number(fb[14 - i]);
  for (let i = 0; i <= 5; i++) m[8][i] = bit(14 - i);   // (8,0..5) = bits 14..9
  m[8][7] = bit(8); m[8][8] = bit(7); m[7][8] = bit(6);
  for (let i = 9; i < 15; i++) m[14 - i][8] = bit(14 - i); // (5..0,8) = bits 5..0
  for (let i = 0; i < 7; i++) m[size - 1 - i][8] = bit(14 - i); // (size-1..size-7,8) = bits 14..8
  for (let i = 0; i < 8; i++) m[8][size - 8 + i] = bit(7 - i);  // (8,size-8..size-1) = bits 7..0
  m[size - 8][8] = 1;
  return m;
}
function qrPenalty(m) {
  const size = m.length;
  let penalty = 0;
  const lines = [];
  for (let i = 0; i < size; i++) { lines.push(m[i]); lines.push(m.map((row) => row[i])); }
  for (const line of lines) {
    let run = 1;
    for (let i = 1; i <= line.length; i++) {
      if (i < line.length && line[i] === line[i - 1]) run++;
      else { if (run >= 5) penalty += 3 + (run - 5); run = 1; }
    }
    // rule 3: finder-like patterns with 4-module quiet zone
    const s = line.join("");
    for (let i = 0; i + 11 <= s.length; i++) {
      const w = s.slice(i, i + 11);
      if (w === "10111010000" || w === "00001011101") penalty += 40;
    }
  }
  for (let r = 0; r < size - 1; r++) for (let c = 0; c < size - 1; c++) {
    const v = m[r][c];
    if (m[r][c + 1] === v && m[r + 1][c] === v && m[r + 1][c + 1] === v) penalty += 3;
  }
  let dark = 0;
  for (const row of m) for (const v of row) dark += v;
  const total = size * size;
  const percent = Math.floor((dark * 100) / total);
  const lower = Math.floor(percent / 5) * 5;
  const upper = lower + 5;
  const k = Math.min(Math.abs(lower - 50), Math.abs(upper - 50)) / 5;
  penalty += k * 10;
  return penalty;
}
// qrMatrix(text) → 2D array of 0/1 (no quiet zone). Throws if too long.
function qrTotalData(version) {
  return QR_TABLE[version].groups.reduce((s, [c, n]) => s + c * n, 0);
}
function qrMatrix(text) {
  const bytes = Array.from(Buffer.from(String(text), "utf8"));
  for (let version = 1; version <= 8; version++) {
    const info = QR_TABLE[version];
    const totalData = info.groups.reduce((s, [c, n]) => s + c * n, 0);
    if (bytes.length + 2 > totalData) continue;
    const dataCw = qrDataCodewords(bytes, version);
    const { codewords, remainderBits } = qrInterleave(dataCw, version);
    let best = null, bestPenalty = Infinity;
    for (let mask = 0; mask < 8; mask++) {
      const matrix = qrBuildMatrix(version, codewords, remainderBits, mask);
      const p = qrPenalty(matrix);
      if (p < bestPenalty) { bestPenalty = p; best = matrix; }
    }
    return best;
  }
  throw new Error("text too long for QR (max ~150 chars)");
}
function qrSvg(text, scale) {
  const matrix = qrMatrix(text);
  const size = matrix.length;
  const q = 4; // quiet zone
  const s = scale || 4;
  const dim = (size + q * 2) * s;
  let d = "";
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (matrix[r][c]) d += "M" + (c + q) * s + " " + (r + q) * s + "h" + s + "v" + s + "h-" + s + "z";
    }
  }
  return '<svg xmlns="http://www.w3.org/2000/svg" width="' + dim + '" height="' + dim + '" viewBox="0 0 ' + dim + " " + dim + '"><rect width="' + dim + '" height="' + dim + '" fill="#ffffff"/><path d="' + d + '" fill="#0b0f14"/></svg>';
}


// ===== src/07-state.js =====

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


// ===== src/08-users.js =====

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


// ===== src/09-download.js =====

// Downloads: HTTPS-only, resumable (.part + Range / curl -C -), with retries.
// Callers ALWAYS verify a pinned SHA-256 before the artifact is used.

function downloadViaCurl(url, partFile) {
  return new Promise((resolve) => {
    const child = spawn("curl", ["-fL", "--retry", "5", "--connect-timeout", "20", "-C", "-", "-o", partFile, url],
      { stdio: ["ignore", "ignore", "pipe"] });
    let err = "";
    child.stderr.on("data", (c) => { err += c.toString("utf8"); if (err.length > 4000) err = err.slice(-2000); });
    child.on("error", () => resolve(false));
    child.on("exit", (code) => resolve(code === 0));
  });
}
function downloadViaHttps(url, partFile, redirects) {
  return new Promise((resolve) => {
    let start = 0;
    try { start = fs.statSync(partFile).size; } catch (e) {}
    const headers = start > 0 ? { Range: "bytes=" + start + "-" } : {};
    const req = https.get(url, { headers, timeout: 60000 }, (res) => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
        res.resume();
        if ((redirects || 0) > 5) return resolve(false);
        return resolve(downloadViaHttps(res.headers.location, partFile, (redirects || 0) + 1));
      }
      if (res.statusCode === 416) return resolve(true); // range beyond EOF: already complete
      let flags = "w";
      if (start > 0 && res.statusCode === 206) flags = "a";
      else if (start > 0 && res.statusCode === 200) flags = "w"; // server ignored Range: restart
      else if (res.statusCode !== 200 && res.statusCode !== 206) { res.resume(); return resolve(false); }
      const ws = fs.createWriteStream(partFile, { flags });
      res.pipe(ws);
      ws.on("finish", () => resolve(true));
      ws.on("error", () => resolve(false));
      res.on("error", () => resolve(false));
    });
    req.on("timeout", () => { req.destroy(); resolve(false); });
    req.on("error", () => resolve(false));
  });
}
// download(url, dest): resume-capable; throws after retries are exhausted.
async function download(url, dest) {
  const part = dest + ".part";
  let lastError = "";
  for (let attempt = 0; attempt < 4; attempt++) {
    const viaCurl = await downloadViaCurl(url, part);
    if (!viaCurl) {
      const viaHttps = await downloadViaHttps(url, part);
      if (!viaHttps) { lastError = "download failed (curl and https)"; await sleep(1500 * (attempt + 1)); continue; }
    }
    try {
      fs.renameSync(part, dest);
      return true;
    } catch (e) { lastError = e.message; await sleep(1000); }
  }
  throw new Error("download failed for " + url + ": " + lastError);
}
// fetchText: small HTTPS GET (public-IP detection; HTTPS only — no http fallback).
function fetchText(url, timeoutMs, depth) {
  const d = depth || 0;
  return new Promise((resolve) => {
    const req = https.get(url, { timeout: timeoutMs || 6000 }, (res) => {
      if ([301, 302, 307, 308].includes(res.statusCode) && res.headers.location) {
        res.resume();
        if (d >= 5) return resolve(""); // redirect loop must not hang boot
        return resolve(fetchText(res.headers.location, timeoutMs, d + 1));
      }
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve(Buffer.concat(chunks).toString("utf8").trim()));
    });
    req.on("error", () => resolve(""));
    req.on("timeout", () => { req.destroy(); resolve(""); });
  });
}
function publicHostFromEnv() {
  if (CFG.panelHost) return CFG.panelHost;
  if (CFG.serverIp) return CFG.serverIp;
  return "";
}
async function detectPublicHost() {
  const known = publicHostFromEnv();
  if (known) return known;
  for (const url of ["https://api.ipify.org", "https://icanhazip.com"]) {
    const ip = await fetchText(url);
    if (isPublicIp(ip)) return ip;
  }
  return "";
}


// ===== src/10-binary.js =====

// Panel binary lifecycle: pinned download → SHA-256 verify → fail-closed
// root-check patch → optional bundled-glibc runtime for old hosts →
// allowlisted child environment → supervised launch helpers.

function systemGlibc() {
  for (const file of ["/lib/x86_64-linux-gnu/libc.so.6", "/lib64/libc.so.6"]) {
    if (!fs.existsSync(file)) continue;
    const r = spawnSync(file, [], { encoding: "utf8", timeout: 4000 });
    const m = String((r.stdout || "") + (r.stderr || "")).match(/release version (\d+)\.(\d+)/);
    if (m) return { major: Number(m[1]), minor: Number(m[2]) };
  }
  return null;
}
function needsBundledGlibc() {
  const g = systemGlibc();
  if (!g) return true;
  return g.major < 2 || (g.major === 2 && g.minor < 34);
}

// --- fail-closed byte patch (needle/expect/jump from the version table) ---
function findBytesInBuffer(buf, needle) { return buf.indexOf(needle); }
function patchBinaryBuffer(buf) {
  const needle = Buffer.from(VERSIONS.panel.patchNeedleHex, "hex");
  const expect = Buffer.from(VERSIONS.panel.patchExpectHex, "hex");
  const jump = Buffer.from(VERSIONS.panel.patchJumpHex, "hex");
  const patchedNeedle = Buffer.concat([needle.subarray(0, needle.length - 6), jump]);
  if (buf.indexOf(patchedNeedle) >= 0) return { buf, changed: false };
  const at = buf.indexOf(needle);
  if (at < 0) throw new Error("root-check pattern not found — only pinned v" + VERSIONS.panel.version + " is supported");
  const jumpAt = at + needle.length - 6;
  if (!buf.subarray(jumpAt, jumpAt + 6).equals(expect)) throw new Error("root-check bytes differ from the pinned release");
  const out = Buffer.from(buf);
  jump.copy(out, jumpAt);
  return { buf: out, changed: true };
}
function patchBinaryFile(file) {
  // The binary is ~346 MB: patch in place with a streaming search, never load it whole.
  const needle = Buffer.from(VERSIONS.panel.patchNeedleHex, "hex");
  const expect = Buffer.from(VERSIONS.panel.patchExpectHex, "hex");
  const jump = Buffer.from(VERSIONS.panel.patchJumpHex, "hex");
  const patchedNeedle = Buffer.concat([needle.subarray(0, needle.length - 6), jump]);
  const fd = fs.openSync(file, "r+");
  try {
    const size = fs.fstatSync(fd).size;
    const find = (target) => {
      const overlap = target.length - 1;
      let offset = 0, prev = Buffer.alloc(0);
      while (offset < size) {
        const chunk = Buffer.alloc(1024 * 1024);
        const n = fs.readSync(fd, chunk, 0, chunk.length, offset);
        if (n <= 0) break;
        const window = prev.length ? Buffer.concat([prev, chunk.subarray(0, n)]) : chunk.subarray(0, n);
        const at = window.indexOf(target);
        if (at >= 0) return offset - prev.length + at;
        prev = Buffer.from(window.subarray(Math.max(0, window.length - overlap)));
        offset += n;
      }
      return -1;
    };
    if (find(patchedNeedle) >= 0) return false;
    const found = find(needle);
    if (found < 0) throw new Error("root-check pattern not found — only pinned v" + VERSIONS.panel.version + " is supported");
    const jumpAt = found + needle.length - 6;
    const cur = Buffer.alloc(6);
    fs.readSync(fd, cur, 0, 6, jumpAt);
    if (!cur.equals(expect)) throw new Error("root-check bytes differ from the pinned release");
    fs.writeSync(fd, jump, 0, 6, jumpAt);
    fs.fsyncSync(fd);
    return true;
  } finally { fs.closeSync(fd); }
}

// Hash of the on-disk binary with the optional interpreter patch undone.
// patchInterpreter (old-glibc hosts) rewrites exactly INTERP_OLD.length
// bytes in the first 64 KB: the stock interp string becomes this host's
// loader path, NUL-padded. That transform is deterministic and reversible,
// so a binary carrying it can still be verified against the pinned+patched
// hash by substituting the stock bytes back while streaming. Any other
// content in the interp slot → not our transform → "" (untrusted).
async function sha256FileInterpReset(file) {
  const loader = String(P.loaderCopy || "");
  if (!loader || Buffer.byteLength(loader) > INTERP_OLD.length) return "";
  const head = Buffer.alloc(65536);
  const fd = fs.openSync(file, "r");
  let n = 0;
  try { n = fs.readSync(fd, head, 0, head.length, 0); } finally { fs.closeSync(fd); }
  const view = head.subarray(0, n);
  const at = view.indexOf(Buffer.from(loader, "utf8"));
  if (at < 0 || at + INTERP_OLD.length > view.length) return "";
  const expect = Buffer.alloc(INTERP_OLD.length);
  expect.write(loader, 0, "utf8");
  if (!view.subarray(at, at + INTERP_OLD.length).equals(expect)) return "";
  const stock = Buffer.from(INTERP_OLD, "utf8");
  return new Promise((resolve, reject) => {
    const h = crypto.createHash("sha256");
    const rs = fs.createReadStream(file, { highWaterMark: 1024 * 1024 });
    let pos = 0;
    rs.on("data", (chunk) => {
      const start = at, end = at + INTERP_OLD.length;
      if (pos + chunk.length > start && pos < end) {
        chunk = Buffer.from(chunk);
        const s = Math.max(start - pos, 0), e = Math.min(end - pos, chunk.length);
        stock.copy(chunk, s, Math.max(pos - start, 0), Math.max(pos - start, 0) + (e - s));
      }
      h.update(chunk);
      pos += chunk.length;
    });
    rs.on("end", () => resolve(h.digest("hex")));
    rs.on("error", reject);
  });
}

async function ensureBinary() {
  if (fs.existsSync(P.binFile)) {
    const hashed = await sha256File(P.binFile);
    // Trust is anchored ONLY in the version table: the on-disk binary must
    // hash to the pinned release (pre-patch) or to the pinned release after
    // our root patch (post-patch). The .ok mark is a courtesy note for
    // humans, never an authority — anything that can write the state dir
    // (e.g. a restore bundle) must not be able to plant a binary plus a
    // self-consistent mark, or a needle lookalike, and have it executed.
    if (hashed === VERSIONS.panel.patchedSha256) { try { fs.chmodSync(P.binFile, 0o755); } catch (e) {} return "cached"; }
    if (hashed === VERSIONS.panel.sha256) {
      patchBinaryFile(P.binFile);
      const after = await sha256File(P.binFile);
      if (after !== VERSIONS.panel.patchedSha256) throw new Error("patched panel binary hash mismatch — refused");
      fs.chmodSync(P.binFile, 0o755);
      writeFileAtomic(P.binMark, after, 0o644);
      return "patched";
    }
    if (needsBundledGlibc()) {
      // Warm boot on an old-glibc host: the file may carry our reversible
      // interpreter patch on top of the root patch. Verify by undoing it.
      try {
        const reset = await sha256FileInterpReset(P.binFile);
        if (reset === VERSIONS.panel.patchedSha256) { try { fs.chmodSync(P.binFile, 0o755); } catch (e) {} return "cached"; }
      } catch (e) { /* fall through to re-download */ }
    }
    log("existing panel binary matches neither the pinned hash nor the pinned+patched hash — discarding and re-downloading");
    fs.rmSync(P.binFile, { force: true });
    fs.rmSync(P.binMark, { force: true });
  }
  RT.status = "downloading panel binary v" + VERSIONS.panel.version + " (~330 MB, one time)";
  log(RT.status);
  // A transport-level "successful" download can still deliver wrong bytes
  // (poisoned cache, truncated-then-padded edge): verify, and give the
  // download a second full chance before declaring a fatal boot error.
  let verified = false;
  for (let attempt = 0; attempt < 2 && !verified; attempt++) {
    await download(VERSIONS.panel.url, P.binFile);
    const got = await sha256File(P.binFile);
    if (got === VERSIONS.panel.sha256) verified = true;
    else {
      fs.rmSync(P.binFile, { force: true });
      log("downloaded binary hash mismatch (attempt " + (attempt + 1) + "/2)" + (attempt === 0 ? " — retrying clean" : ""));
    }
  }
  if (!verified) throw new Error("downloaded binary hash mismatch after retry — refused");
  patchBinaryFile(P.binFile);
  const afterPatch = await sha256File(P.binFile);
  if (afterPatch !== VERSIONS.panel.patchedSha256) throw new Error("patched panel binary hash mismatch — refused");
  fs.chmodSync(P.binFile, 0o755);
  writeFileAtomic(P.binMark, afterPatch, 0o644);
  dropFileCache(P.binFile);
  return "downloaded";
}

// --- bundled glibc (old hosts only) ---
function parseAr(buf) {
  if (buf.subarray(0, 8).toString("utf8") !== "!<arch>\n") throw new Error("deb is not an ar archive");
  const files = {};
  let offset = 8;
  while (offset + 60 <= buf.length) {
    const header = buf.subarray(offset, offset + 60).toString("latin1");
    offset += 60;
    const name = header.slice(0, 16).trim().replace(/\/$/, "");
    const size = parseInt(header.slice(48, 58).trim(), 10);
    if (!name || !Number.isFinite(size) || size < 0) break;
    files[name] = buf.subarray(offset, offset + size);
    offset += size + (size % 2);
  }
  return files;
}
function decompressDebData(packed) {
  // Node >= 22.15 ships zstd in zlib. Fall back to system zstd if present.
  if (typeof zlib.zstdDecompressSync === "function") return zlib.zstdDecompressSync(packed);
  const tmpIn = P.glibcDir + "/.data.zst";
  const tmpOut = P.glibcDir + "/.data.tar";
  fs.writeFileSync(tmpIn, packed);
  const r = spawnSync("zstd", ["-d", "-f", tmpIn, "-o", tmpOut], { timeout: 60000 });
  if (r.status !== 0 || !fs.existsSync(tmpOut)) throw new Error("cannot decompress deb data (no zstd available)");
  const out = fs.readFileSync(tmpOut);
  fs.rmSync(tmpIn, { force: true }); fs.rmSync(tmpOut, { force: true });
  return out;
}
function extractNeededFromTar(tar, dest, wanted) {
  const entries = parseTarBuffer(tar);
  const saved = {};
  for (const e of entries) {
    const base = e.name.split("/").pop();
    if (!wanted.has(base)) continue;
    if (e.type === "2") {
      const linkBase = String(e.linkname || "").split("/").pop();
      if (linkBase && !saved[base]) saved[base] = { link: linkBase };
    } else if (e.type === "0" || e.type === "\0") {
      saved[base] = e.data;
    }
  }
  fs.mkdirSync(dest, { recursive: true });
  let written = 0;
  for (const name of Object.keys(saved)) {
    let value = saved[name];
    const seen = new Set();
    while (value && value.link) {
      if (seen.has(value.link)) break;
      seen.add(value.link);
      value = saved[value.link];
    }
    if (!Buffer.isBuffer(value) || value.length === 0) continue;
    fs.writeFileSync(path.join(dest, name), value);
    fs.chmodSync(path.join(dest, name), 0o755);
    written++;
  }
  return written;
}
async function ensureRuntime() {
  const loader = path.join(P.glibcDir, "ld-linux-x86-64.so.2");
  const mark = path.join(P.glibcDir, "ok");
  if (fs.existsSync(loader) && fs.existsSync(path.join(P.glibcDir, "libc.so.6")) && fs.existsSync(mark)) {
    RT.loader = loader; RT.libPath = P.glibcDir;
    return "cached";
  }
  RT.status = "host glibc is old — staging the bundled compatible runtime (one time)";
  log(RT.status);
  fs.mkdirSync(P.glibcDir, { recursive: true });
  const wanted = new Set(VERSIONS.glibcFiles);
  // Downloads run in parallel (independent artifacts).
  await Promise.all(VERSIONS.glibcDebs.map(async ([url, name, expected]) => {
    const dest = path.join(P.glibcDir, name);
    await download(url, dest);
    const got = await sha256File(dest);
    if (got !== expected) { fs.rmSync(dest, { force: true }); throw new Error("glibc deb hash mismatch: " + name); }
    const members = parseAr(fs.readFileSync(dest));
    const packed = members["data.tar.zst"];
    if (!packed) throw new Error("data.tar.zst missing in " + name);
    extractNeededFromTar(decompressDebData(Buffer.from(packed)), P.glibcDir, wanted);
    fs.rmSync(dest, { force: true });
  }));
  if (!fs.existsSync(loader) || !fs.existsSync(path.join(P.glibcDir, "libc.so.6")) || !fs.existsSync(path.join(P.glibcDir, "libresolv.so.2"))) {
    throw new Error("bundled glibc extraction incomplete");
  }
  fs.writeFileSync(mark, "glibc-2.35\n");
  RT.loader = loader; RT.libPath = P.glibcDir;
  return "downloaded";
}
const INTERP_OLD = "/lib64/ld-linux-x86-64.so.2";
function linkLoader() {
  const src = path.join(P.glibcDir, "ld-linux-x86-64.so.2");
  if (!fs.existsSync(src)) return "";
  if (Buffer.byteLength(P.loaderCopy) > INTERP_OLD.length) return "";
  fs.copyFileSync(src, P.loaderCopy);
  fs.chmodSync(P.loaderCopy, 0o755);
  return P.loaderCopy;
}
function patchInterpreter(file, loaderPath) {
  if (Buffer.byteLength(loaderPath) > INTERP_OLD.length) return false;
  const fd = fs.openSync(file, "r+");
  try {
    const head = Buffer.alloc(65536);
    const n = fs.readSync(fd, head, 0, head.length, 0);
    const at = head.subarray(0, n).indexOf(INTERP_OLD);
    if (at < 0) return false;
    const replacement = Buffer.alloc(INTERP_OLD.length);
    replacement.write(loaderPath, 0, "utf8");
    fs.writeSync(fd, replacement, 0, replacement.length, at);
    fs.fsyncSync(fd);
    return true;
  } finally { fs.closeSync(fd); }
}
function binLaunch(args) {
  if (RT.directExec || !RT.loader) return { command: P.binFile, args };
  return { command: RT.loader, args: ["--library-path", RT.libPath, P.binFile].concat(args) };
}

// Child environment: ALLOWLIST ONLY (MF passed the entire process env to a
// downloaded binary). We build from scratch; nothing else leaks.
function goMemLimitMb() {
  if (CFG.goMemLimitMb > 0) return CFG.goMemLimitMb;
  const limit = cgroupLimit();
  if (limit > 0) return Math.max(96, Math.floor((limit / (1024 * 1024)) * 0.6));
  return 192;
}
function panelEnv() {
  const env = {
    PATH: process.env.PATH || "/usr/local/bin:/usr/bin:/bin",
    HOME: P.root,
    TZ: process.env.TZ || "UTC",
    LANG: process.env.LANG || "C.UTF-8",
    VPNUI_DB_FOLDER: P.dataDir,
    VPNUI_BIN_FOLDER: P.xrayDir,
    VPNUI_LOG_FOLDER: P.logDir,
    VPNUI_LOG_LEVEL: "info",
    NO_COLOR: "1",
    GOMAXPROCS: "1",
    GODEBUG: "madvdontneed=1",
    MALLOC_ARENA_MAX: "1",
    GOMEMLIMIT: goMemLimitMb() + "MiB",
  };
  if (RT.libPath) env.LD_LIBRARY_PATH = RT.libPath;
  return env;
}
function runBin(args, timeoutMs) {
  return new Promise((resolve) => {
    const launch = binLaunch(args);
    const child = spawn(launch.command, launch.args, { cwd: P.panelDir, env: panelEnv(), stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    let settled = false;
    const timer = setTimeout(() => { try { child.kill("SIGKILL"); } catch (e) {} }, timeoutMs || 90000);
    const finish = (code) => { if (settled) return; settled = true; clearTimeout(timer); resolve({ code, out }); };
    const take = (buf) => { out += buf.toString("utf8"); if (out.length > 20000) out = out.slice(-12000); };
    child.stdout.on("data", take);
    child.stderr.on("data", take);
    child.on("error", () => finish(-1));
    child.on("exit", (code) => finish(code));
  });
}
// Trim RU/IR geo data (kept from MF's playbook): the extracted xray dir ships
// per-country geo files this deployment never routes with.
function trimGeoFiles() {
  for (const name of ["geosite_RU.dat", "geoip_RU.dat", "geosite_IR.dat", "geoip_IR.dat"]) {
    try { fs.rmSync(path.join(P.xrayDir, name), { force: true }); } catch (e) {}
  }
  dropFileCache(P.binFile);
  dropFileCache(path.join(P.xrayDir, "xray-linux-amd64"));
  dropFileCache(path.join(P.xrayDir, "geoip.dat"));
  dropFileCache(path.join(P.xrayDir, "geosite.dat"));
}


// ===== src/11-panelapi.js =====

// Panel API client (loopback only): login, inbounds list/add/update, branding.
// Same wire protocol MF used — form-urlencoded POSTs against /kb/... — but
// written fresh against the endpoints the panel exposes.

function formBody(fields) { return new URLSearchParams(fields).toString(); }

function panelRequest(method, urlPath, opts) {
  opts = opts || {};
  const body = opts.body || "";
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: "127.0.0.1",
      port: CFG.panelPort,
      method,
      path: urlPath,
      headers: {
        "X-Requested-With": "XMLHttpRequest",
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": Buffer.byteLength(body),
        Cookie: opts.cookie || "",
      },
      timeout: 20000,
    }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        const jar = [];
        if (opts.cookie) jar.push(opts.cookie);
        for (const row of res.headers["set-cookie"] || []) jar.push(row.split(";")[0]);
        resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString("utf8"), cookie: jar.join("; ") });
      });
    });
    req.on("error", (err) => { err.retry = true; reject(err); });
    req.on("timeout", () => req.destroy(Object.assign(new Error("panel api timeout"), { retry: true })));
    if (body) req.write(body);
    req.end();
  });
}
function parsePanelJson(res) {
  try { return JSON.parse(res.body); } catch (e) { return {}; }
}
async function panelLogin(username, password) {
  const res = await panelRequest("POST", PANEL_BASE + "/login", { body: formBody({ username, password }) });
  const parsed = parsePanelJson(res);
  if (!parsed.success) {
    const err = new Error("panel login failed: " + res.body.slice(0, 160));
    err.retry = false;
    throw err;
  }
  return res.cookie;
}
async function panelLoginWhenReady(candidates) {
  // candidates: array of {username, password}; first success wins.
  let last = new Error("panel never became ready for login");
  for (let round = 0; round < 30; round++) {
    for (const cand of candidates) {
      try { return { cookie: await panelLogin(cand.username, cand.password), used: cand }; }
      catch (e) { last = e; if (!e.retry && round > 2 && candidates.length === 1) throw e; }
    }
    await sleep(2500);
  }
  throw last;
}
async function listInbounds(cookie) {
  const res = await panelRequest("GET", PANEL_BASE + "/panel/api/inbounds/list", { cookie });
  const parsed = parsePanelJson(res);
  if (!parsed.success) throw new Error("inbounds list failed: " + res.body.slice(0, 160));
  return parsed.obj || [];
}
function asText(value) {
  if (value == null) return "";
  return typeof value === "string" ? value : JSON.stringify(value);
}
async function addInbound(cookie, spec) {
  const fields = {
    remark: spec.remark,
    enable: "true",
    listen: spec.listen || "127.0.0.1",
    port: String(spec.port),
    protocol: spec.protocol,
    settings: JSON.stringify(spec.settings),
    streamSettings: spec.stream || "{}",
    sniffing: spec.sniffing || sniffingJson(),
    total: "0",
    expiryTime: "0",
  };
  const res = await panelRequest("POST", PANEL_BASE + "/panel/api/inbounds/add", { cookie, body: formBody(fields) });
  const parsed = parsePanelJson(res);
  if (!parsed.success) throw new Error(spec.remark + ": " + (parsed.msg || res.body.slice(0, 200)));
  return parsed.obj;
}
// Full-row update (the panel's update endpoint replaces settings wholesale —
// this is the lever reconciliation uses to add/update/remove clients).
async function updateInbound(cookie, row, settingsObj, streamObj) {
  const fields = {
    id: String(row.id),
    remark: row.remark || "",
    enable: row.enable ? "true" : "false",
    listen: row.listen || "",
    port: String(row.port),
    protocol: row.protocol,
    settings: JSON.stringify(settingsObj),
    streamSettings: JSON.stringify(streamObj || JSON.parse(asText(row.streamSettings) || "{}")),
    sniffing: asText(row.sniffing) || "{}",
    total: String(row.total || 0),
    expiryTime: String(row.expiryTime || 0),
  };
  const res = await panelRequest("POST", PANEL_BASE + "/panel/api/inbounds/update/" + row.id, { cookie, body: formBody(fields) });
  const parsed = parsePanelJson(res);
  if (!parsed.success) throw new Error("update " + row.remark + ": " + (parsed.msg || res.body.slice(0, 200)));
  return true;
}
async function applyBrand(cookie) {
  try {
    const named = await panelRequest("POST", PANEL_BASE + "/panel/api/server/serverName", {
      cookie, body: formBody({ serverName: BRAND }),
    });
    if (parsePanelJson(named).success) log("panel server name: " + BRAND);
  } catch (e) { log("server name not set: " + e.message); }
  try {
    const current = await panelRequest("POST", PANEL_BASE + "/panel/setting/all", { cookie, body: "" });
    const parsed = parsePanelJson(current);
    const obj = parsed.obj;
    if (!parsed.success || !obj || typeof obj !== "object" || Array.isArray(obj)) return;
    if (obj.subTitle === BRAND) return;
    if (Number(obj.webPort) !== CFG.panelPort || String(obj.webBasePath || "") !== CFG.panelBase || obj.webListen !== "127.0.0.1") {
      log("subTitle skipped (panel address settings differ from runner expectations)");
      return;
    }
    const fields = {};
    for (const key of Object.keys(obj)) {
      const v = obj[key];
      if (v != null && typeof v === "object") return; // unexpected shape: leave settings alone
      fields[key] = v == null ? "" : String(v);
    }
    fields.subTitle = BRAND;
    const saved = await panelRequest("POST", PANEL_BASE + "/panel/setting/update", { cookie, body: formBody(fields) });
    if (parsePanelJson(saved).success) log("panel subscription title: " + BRAND);
  } catch (e) { log("subTitle not set: " + e.message); }
}


// ===== src/12-inbounds.js =====

// Inbound plan: the protocols that can actually run inside a non-root
// container on one public port. Same proven set as the Phase-0 anatomy:
// TCP fallback chain (VLESS → Trojan → Shadowsocks) behind the binary mux
// entry, WS/gRPC/HTTPUpgrade inbounds on loopback paths, and a userspace
// WireGuard on the public UDP port. All stream security is "none" — TLS is
// terminated by the host edge (Railway/KataBump/Cloudflare) in front of the
// single public port; the mux never sees raw internet TLS.

const INBOUND_PORTS = {
  vless: 21001, trojan: 21002, ss: 21003,
  vlessWs: 21011, vmessWs: 21012, trojanWs: 21013, grpc: 21014, upgrade: 21015,
};
// Public path prefix → internal inbound port (used by the mux).
const PATH_ROUTES = {
  "/bp-vless": INBOUND_PORTS.vlessWs,
  "/bp-vmess": INBOUND_PORTS.vmessWs,
  "/bp-trojan": INBOUND_PORTS.trojanWs,
  "/bp-up": INBOUND_PORTS.upgrade,
};
const GRPC_SERVICE = "bpgrpc";

function sniffingJson() {
  return JSON.stringify({ enabled: true, destOverride: ["http", "tls", "quic"], metadataOnly: false, routeOnly: false });
}
function externalProxyField(host, publicPort) {
  if (!host) return [];
  return [{ forceTls: "none", dest: host, port: publicPort, remark: "meowray" }];
}
function streamJson(network, extra, host, publicPort) {
  const body = Object.assign({ network, security: "none" }, extra || {});
  const proxy = externalProxyField(host, publicPort);
  if (proxy.length) body.externalProxy = proxy;
  return JSON.stringify(body);
}
function wgKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("x25519");
  const pubJwk = publicKey.export({ format: "jwk" });
  const privJwk = privateKey.export({ format: "jwk" });
  const toB64 = (b64url) => Buffer.from(b64url, "base64url").toString("base64");
  return { pubKey: toB64(pubJwk.x), secretKey: toB64(privJwk.d) };
}

function plannedInbounds(host, publicPort, wgKeys) {
  const ssPassword = crypto.randomBytes(32).toString("base64");
  const tcpHeader = { tcpSettings: { acceptProxyProtocol: false, header: { type: "none" } } };
  return [
    {
      remark: "VLESS-TCP", port: INBOUND_PORTS.vless, protocol: "vless",
      settings: { clients: [], decryption: "none", fallbacks: [{ dest: INBOUND_PORTS.trojan, xver: 0 }] },
      stream: streamJson("tcp", tcpHeader, host, publicPort),
    },
    {
      remark: "Trojan-TCP", port: INBOUND_PORTS.trojan, protocol: "trojan",
      settings: { clients: [], fallbacks: [{ dest: INBOUND_PORTS.ss, xver: 0 }] },
      stream: streamJson("tcp", tcpHeader, host, publicPort),
    },
    {
      remark: "Shadowsocks", port: INBOUND_PORTS.ss, protocol: "shadowsocks",
      settings: { method: "2022-blake3-aes-256-gcm", password: ssPassword, network: "tcp", ivCheck: false, clients: [] },
      stream: streamJson("tcp", tcpHeader, host, publicPort),
    },
    {
      remark: "VLESS-WS", port: INBOUND_PORTS.vlessWs, protocol: "vless",
      settings: { clients: [], decryption: "none" },
      stream: streamJson("ws", { wsSettings: { path: "/bp-vless", headers: {} } }, host, publicPort),
    },
    {
      remark: "VMess-WS", port: INBOUND_PORTS.vmessWs, protocol: "vmess",
      settings: { clients: [] },
      stream: streamJson("ws", { wsSettings: { path: "/bp-vmess", headers: {} } }, host, publicPort),
    },
    {
      remark: "Trojan-WS", port: INBOUND_PORTS.trojanWs, protocol: "trojan",
      settings: { clients: [] },
      stream: streamJson("ws", { wsSettings: { path: "/bp-trojan", headers: {} } }, host, publicPort),
    },
    {
      remark: "VLESS-gRPC", port: INBOUND_PORTS.grpc, protocol: "vless",
      settings: { clients: [], decryption: "none" },
      stream: streamJson("grpc", { grpcSettings: { serviceName: GRPC_SERVICE, multiMode: false } }, host, publicPort),
    },
    {
      remark: "VLESS-HTTPUpgrade", port: INBOUND_PORTS.upgrade, protocol: "vless",
      settings: { clients: [], decryption: "none" },
      stream: streamJson("httpupgrade", { httpupgradeSettings: { path: "/bp-up", host: "" } }, host, publicPort),
    },
    {
      remark: "WireGuard", listen: "0.0.0.0", port: publicPort, protocol: "wireguard",
      settings: {
        mtu: 1280, secretKey: wgKeys.secretKey, pubKey: wgKeys.pubKey, noKernelTun: true,
        address: ["10.10.0.1/32"], clientNetwork: "10.10.0.0/24", clients: [], peers: [],
      },
      stream: "{}", sniffing: "{}",
    },
  ];
}
const MANAGED_REMARKS = ["VLESS-TCP", "Trojan-TCP", "Shadowsocks", "VLESS-WS", "VMess-WS", "Trojan-WS", "VLESS-gRPC", "VLESS-HTTPUpgrade"];

// Subscription link builders (standard URI shapes; host/port point at the mux).
function generateUserConfigs(user, host, publicPort) {
  const h = host || RT.publicHost || publicHostFromEnv() || "127.0.0.1";
  const p = publicPort || CFG.publicPort;
  const uuid = user.id;
  const vmessObj = {
    v: "2", ps: BRAND + " - VMess WS", add: h, port: String(p), id: uuid, aid: "0",
    scy: "auto", net: "ws", type: "none", host: "", path: "/bp-vmess", tls: "none", sni: "", alpn: "",
  };
  return [
    { id: "vless-ws", name: "VLESS WebSocket", type: "vless", uri: "vless://" + uuid + "@" + h + ":" + p + "?path=%2Fbp-vless&security=none&encryption=none&type=ws#" + encodeURIComponent(BRAND + " - VLESS WS") },
    { id: "vmess-ws", name: "VMess WebSocket", type: "vmess", uri: "vmess://" + Buffer.from(JSON.stringify(vmessObj)).toString("base64") },
    { id: "trojan-ws", name: "Trojan WebSocket", type: "trojan", uri: "trojan://" + uuid + "@" + h + ":" + p + "?path=%2Fbp-trojan&security=none&type=ws#" + encodeURIComponent(BRAND + " - Trojan WS") },
    { id: "vless-tcp", name: "VLESS TCP", type: "vless", uri: "vless://" + uuid + "@" + h + ":" + p + "?security=none&encryption=none&type=tcp#" + encodeURIComponent(BRAND + " - VLESS TCP") },
    { id: "vless-up", name: "VLESS HTTPUpgrade", type: "vless", uri: "vless://" + uuid + "@" + h + ":" + p + "?path=%2Fbp-up&security=none&encryption=none&type=httpupgrade#" + encodeURIComponent(BRAND + " - HTTPUpgrade") },
    { id: "vless-grpc", name: "VLESS gRPC", type: "vless", uri: "vless://" + uuid + "@" + h + ":" + p + "?serviceName=" + GRPC_SERVICE + "&security=none&encryption=none&type=grpc#" + encodeURIComponent(BRAND + " - gRPC") },
  ];
}


// ===== src/13-reconcile.js =====

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


// ===== src/14-seed.js =====

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


// ===== src/15-portal.js =====

// User portal + runner admin surfaces (loopback :18081, reached publicly
// through the mux as the default HTTP route). Persian RTL, dark MeowRay
// brand, zero external resources (works on blocked/offline networks).
// Pages are server-rendered string templates — no client framework, no
// heavy in-memory rendering; static shell parts are built once.

const LOGO_SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" fill="none" stroke="#5eead4" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M14 26 L10 10 L24 18"/><path d="M50 26 L54 10 L40 18"/><circle cx="32" cy="38" r="17"/><circle cx="26" cy="37" r="1.6" fill="#5eead4"/><circle cx="38" cy="37" r="1.6" fill="#5eead4"/><path d="M29 44 Q32 46.5 35 44"/><path d="M12 40 H22 M14 47 L23 44 M52 40 H42 M50 47 L41 44"/></svg>';

const PORTAL_CSS = [
  ":root{--bg:#070b12;--surface:#0d1420;--raised:#121c2e;--border:#1e2c44;--text:#e6f0fa;--muted:#93a7bf;--accent:#5eead4;--accent2:#38bdf8;--danger:#fb7185;--ok:#34d399}",
  "*{box-sizing:border-box}body{margin:0;background:radial-gradient(60rem 30rem at 80% -10%,rgba(56,189,248,.08),transparent),var(--bg);color:var(--text);font-family:Tahoma,'Segoe UI',sans-serif;line-height:1.7}",
  "a{color:var(--accent2)}main{max-width:56rem;margin:0 auto;padding:1.2rem}",
  ".brand{display:flex;align-items:center;gap:.7rem;margin:1rem 0}.brand svg{width:44px;height:44px}.brand h1{font-size:1.35rem;margin:0;letter-spacing:-.3px}.brand small{color:var(--muted);display:block;font-size:.78rem}",
  ".card{background:linear-gradient(180deg,var(--raised),var(--surface));border:1px solid var(--border);border-radius:16px;padding:1.1rem 1.2rem;margin:.8rem 0;box-shadow:0 10px 30px rgba(0,0,0,.35)}",
  ".card h2{font-size:1.02rem;margin:.1rem 0 .7rem}.muted{color:var(--muted)}.small{font-size:.85rem}",
  "label{display:block;margin:.6rem 0 .25rem;color:var(--muted);font-size:.88rem}input,select{width:100%;background:#0a111d;border:1px solid var(--border);border-radius:10px;color:var(--text);padding:.6rem .7rem;font:inherit}",
  "button,.btn{display:inline-block;background:linear-gradient(90deg,var(--accent),var(--accent2));color:#04202b;border:0;border-radius:10px;padding:.55rem 1.1rem;font:inherit;font-weight:700;cursor:pointer;text-decoration:none}",
  "button.ghost,.btn.ghost{background:transparent;color:var(--accent);border:1px solid var(--border)}button.danger{background:transparent;color:var(--danger);border:1px solid var(--danger)}",
  ".row{display:flex;gap:.6rem;flex-wrap:wrap;align-items:center}.grow{flex:1}",
  ".cfg{border:1px solid var(--border);border-radius:12px;padding:.7rem .8rem;margin:.5rem 0;background:#0a111d}.cfg code{display:block;direction:ltr;text-align:left;word-break:break-all;color:#a5f3fc;font-size:.78rem;margin-top:.3rem}",
  ".pill{display:inline-block;border:1px solid var(--border);border-radius:999px;padding:.05rem .6rem;font-size:.78rem;color:var(--muted)}",
  ".ok{color:var(--ok)}.bad{color:var(--danger)}table{width:100%;border-collapse:collapse;font-size:.88rem}th,td{border-bottom:1px solid var(--border);padding:.45rem .4rem;text-align:right}th{color:var(--muted);font-weight:600}",
  ".qr{background:#fff;border-radius:12px;padding:8px;display:inline-block;line-height:0}.bar{height:10px;background:#0a111d;border:1px solid var(--border);border-radius:99px;overflow:hidden}.bar i{display:block;height:100%;background:linear-gradient(90deg,var(--accent),var(--accent2))}",
  ".err{background:rgba(251,113,133,.12);border:1px solid var(--danger);color:#fecdd3;border-radius:10px;padding:.5rem .8rem;margin:.6rem 0}",
  "footer{color:var(--muted);font-size:.78rem;text-align:center;margin:2rem 0 1rem}",
].join("\n");

function pageShell(title, bodyHtml) {
  return "<!doctype html><html lang=\"fa\" dir=\"rtl\"><head><meta charset=\"utf-8\">" +
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">" +
    "<title>" + htmlEscape(title) + " · " + BRAND + "</title><link rel=\"icon\" href=\"/logo.svg\">" +
    "<style>" + PORTAL_CSS + "</style></head><body><main>" +
    "<div class=\"brand\">" + LOGO_SVG + "<div><h1>" + BRAND + "</h1><small>پنل اتصال شخصی شما</small></div></div>" +
    bodyHtml +
    "<footer>" + BRAND + " · " + RUNNER_VERSION + "</footer></main></body></html>";
}
function statusShell(title, bodyHtml) {
  // Boot/status page (served by the mux before the portal is up).
  return "<!doctype html><html lang=\"fa\" dir=\"rtl\"><head><meta charset=\"utf-8\">" +
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>" + htmlEscape(title) + " · " + BRAND + "</title>" +
    "<style>" + PORTAL_CSS + ".spin{width:44px;height:44px;border-radius:50%;border:4px solid var(--border);border-top-color:var(--accent);animation:sp 1s linear infinite;margin:1rem auto}@keyframes sp{to{transform:rotate(360deg)}}</style></head>" +
    "<body><main><div class=\"brand\">" + LOGO_SVG + "<div><h1>" + BRAND + "</h1><small>در حال راه‌اندازی</small></div></div>" +
    bodyHtml + "</main><script>setTimeout(function(){location.reload()},6000)</script></body></html>";
}
function fmtBytes(n) {
  if (!Number.isFinite(n)) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0, v = n;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return faDigits(v.toFixed(v >= 100 || i === 0 ? 0 : 1)) + " " + units[i];
}
function fmtDateFa(iso) {
  if (!iso) return "بدون انقضا";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "—";
  return faDigits(d.toLocaleDateString("fa-IR")) ;
}

// ---- request plumbing ----
const rateBuckets = new Map();
function rateLimited(key, max, windowMs) {
  const now = Date.now();
  const arr = (rateBuckets.get(key) || []).filter((t) => now - t < windowMs);
  if (arr.length >= max) { rateBuckets.set(key, arr); return true; }
  arr.push(now);
  rateBuckets.set(key, arr);
  return false;
}
function readBody(req, cap) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > (cap || 65536)) { reject(new Error("body too large")); req.destroy(); return; }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}
async function parseBody(req) {
  const raw = await readBody(req);
  const type = String(req.headers["content-type"] || "");
  if (type.includes("application/json")) { try { return JSON.parse(raw || "{}"); } catch (e) { return {}; } }
  const out = {};
  for (const [k, v] of new URLSearchParams(raw)) out[k] = v;
  return out;
}
function sendJson(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { "Content-Type": "application/json; charset=utf-8", "Content-Length": Buffer.byteLength(body), "Cache-Control": "no-store" });
  res.end(body);
}
function sendHtml(res, code, html) {
  res.writeHead(code, { "Content-Type": "text/html; charset=utf-8", "Content-Length": Buffer.byteLength(html), "Cache-Control": "no-store" });
  res.end(html);
}
function redirect(res, to) { res.writeHead(302, { Location: to, "Cache-Control": "no-store" }); res.end(); }
function sessionUser(req) {
  const cookie = String(req.headers.cookie || "");
  const m = cookie.match(/(?:^|;\s*)mr_session=([^;]+)/);
  if (!m) return null;
  let decoded = "";
  try { decoded = decodeURIComponent(m[1]); } catch (e) { return null; }
  const username = verifySessionToken(decoded);
  if (!username) return null;
  return findUser(username);
}
function setSessionCookie(res, username) {
  const token = makeSessionToken(username);
  const secure = CFG.publicScheme === "https" ? "; Secure" : "";
  res.setHeader("Set-Cookie", "mr_session=" + encodeURIComponent(token) + "; Path=/; HttpOnly; SameSite=Lax; Max-Age=" + 30 * 24 * 3600 + secure);
}
function publicBase(req) {
  if (RT.publicHost) return { host: RT.publicHost, port: CFG.publicPort, url: CFG.publicScheme + "://" + RT.publicHost + ":" + CFG.publicPort };
  const hostHeader = String((req && req.headers.host) || "127.0.0.1");
  const m = hostHeader.match(/^(.*):(\d+)$/);
  if (m) return { host: m[1], port: Number(m[2]), url: CFG.publicScheme + "://" + hostHeader };
  return { host: hostHeader, port: CFG.publicPort, url: CFG.publicScheme + "://" + hostHeader + ":" + CFG.publicPort };
}

// ---- auth actions (shared by HTML forms and JSON API) ----
async function authRegister(body, ip) {
  if (CFG.registration === "closed") return { code: 403, error: "ثبت‌نام بسته است." };
  // Fail CLOSED: invite mode with no configured code must never degenerate
  // into open registration (an omitted invite would satisfy "" === "").
  if (CFG.registration === "invite" && (!CFG.inviteCode || String(body.invite || "") !== CFG.inviteCode)) return { code: 403, error: "کد دعوت درست نیست." };
  const username = String(body.username || "").trim();
  const password = String(body.password || "");
  if (!/^[A-Za-z0-9_.-]{3,32}$/.test(username)) return { code: 400, error: "نام کاربری باید ۳ تا ۳۲ کاراکتر لاتین باشد." };
  if (password.length < 8 || password.length > 128) return { code: 400, error: "رمز باید ۸ تا ۱۲۸ کاراکتر باشد." };
  if (rateLimited("reg:" + ip, 5, 10 * 60 * 1000)) return { code: 429, error: "کمی صبر کنید و دوباره تلاش کنید." };
  if (findUser(username)) return { code: 409, error: "این نام کاربری گرفته شده است." };
  const user = newPortalUser(username, await hashPassword(password), "user");
  const users = readUsers();
  users.push(user);
  writeUsers(users);
  reconcileNow("register").catch(() => {});
  return { code: 201, user };
}
async function authLogin(body, ip) {
  const username = String(body.username || "").trim();
  const password = String(body.password || "");
  if (rateLimited("login:" + ip, 10, 5 * 60 * 1000)) return { code: 429, error: "تلاش‌های ورود زیاد شده؛ چند دقیقه صبر کنید." };
  const user = findUser(username);
  if (!user || !(await verifyPassword(password, user.passwordHash))) return { code: 401, error: "نام کاربری یا رمز اشتباه است." };
  if (user.enabled === false) return { code: 403, error: "این حساب غیرفعال شده است." };
  if (user.expiresAt && Date.parse(user.expiresAt) <= Date.now()) return { code: 403, error: "اشتراک این حساب به پایان رسیده است." };
  return { code: 200, user };
}

// ---- health ----
const trafficCache = new Map();
async function userTrafficCached(user) {
  const hit = trafficCache.get(user.username);
  if (hit && Date.now() - hit.at < 30000) return hit.value;
  try {
    const cookie = await getAdminCookie();
    const value = await collectUserTraffic(cookie, user);
    trafficCache.set(user.username, { at: Date.now(), value });
    return value;
  } catch (e) { return null; }
}
function buildHealth() {
  const tree = treeRssBytes(process.pid);
  let panel = 0, xray = 0, other = 0;
  for (const d of tree.detail) {
    if (d.self) continue;
    if ((d.cmd || "").includes("vpn-ui")) panel += d.rss;
    else if ((d.cmd || "").includes("xray")) xray += d.rss;
    else other += d.rss;
  }
  return {
    ok: RT.ready && RT.panelUp,
    brand: BRAND,
    version: RUNNER_VERSION,
    panelVersion: VERSIONS.panel.version,
    ready: RT.ready,
    panelUp: RT.panelUp,
    panelApiOk: RT.panelApiOk,
    inbounds: RT.inboundCount,
    clients: RT.clientCount,
    restarts: RT.restarts,
    uptimeSec: Math.floor((Date.now() - RT.bootStartedAt) / 1000),
    rssMb: {
      node: Math.round(tree.detail[0].rss / 1048576),
      panel: Math.round(panel / 1048576),
      xray: Math.round(xray / 1048576),
      other: Math.round(other / 1048576),
      total: Math.round(tree.total / 1048576),
    },
    diskFreeMb: Math.round(diskFreeBytes(P.root) / 1048576),
    lastReconcile: RT.lastReconcile,
    fatal: RT.fatal || undefined,
  };
}

// ---- pages ----
function loginPage(error) {
  return pageShell("ورود", '<div class="card"><h2>ورود به حساب</h2>' +
    (error ? '<div class="err">' + htmlEscape(error) + "</div>" : "") +
    '<form method="post" action="/login"><label>نام کاربری</label><input name="username" autocomplete="username" required>' +
    '<label>رمز عبور</label><input name="password" type="password" autocomplete="current-password" required>' +
    '<div class="row" style="margin-top:1rem"><button type="submit">ورود</button>' +
    (CFG.registration !== "closed" ? '<a class="btn ghost" href="/register">ساخت حساب</a>' : "") +
    "</div></form></div>");
}
function registerPage(error) {
  return pageShell("ثبت‌نام", '<div class="card"><h2>ساخت حساب</h2>' +
    (error ? '<div class="err">' + htmlEscape(error) + "</div>" : "") +
    '<form method="post" action="/register"><label>نام کاربری (لاتین)</label><input name="username" autocomplete="username" required>' +
    '<label>رمز عبور (حداقل ۸ کاراکتر)</label><input name="password" type="password" autocomplete="new-password" required>' +
    (CFG.registration === "invite" ? '<label>کد دعوت</label><input name="invite" required>' : "") +
    '<div class="row" style="margin-top:1rem"><button type="submit">ساخت حساب</button><a class="btn ghost" href="/login">ورود</a></div></form></div>');
}
async function dashboardPage(req, user) {
  const base = publicBase(req);
  const configs = generateUserConfigs(user, base.host, base.port);
  const subUrl = base.url + "/sub/" + user.subToken;
  const traffic = await userTrafficCached(user);
  const limitBytes = Math.round((Number(user.trafficLimitGb) || 0) * 1073741824);
  const usedPct = traffic && limitBytes > 0 ? Math.min(100, Math.round((traffic.total / limitBytes) * 100)) : 0;
  let qr = "";
  try { qr = qrSvg(subUrl, 3); } catch (e) {}
  const active = isUserActive(user);
  const body =
    '<div class="card"><h2>داشبورد ' + htmlEscape(user.username) + ' <span class="pill">' + (user.role === "admin" ? "مدیر" : "کاربر") + '</span></h2>' +
    '<div class="row"><span class="pill">وضعیت: ' + (active ? '<b class="ok">فعال</b>' : '<b class="bad">غیرفعال/منقضی</b>') + "</span>" +
    '<span class="pill">انقضا: ' + fmtDateFa(user.expiresAt) + "</span>" +
    '<span class="pill">سقف ترافیک: ' + (limitBytes ? fmtBytes(limitBytes) : "نامحدود") + "</span>" +
    (traffic ? '<span class="pill">مصرف: ' + fmtBytes(traffic.total) + "</span>" : "") + "</div>" +
    (limitBytes && traffic ? '<div class="bar" style="margin-top:.7rem"><i style="width:' + usedPct + '%"></i></div>' : "") +
    '<form method="post" action="/logout" style="margin-top:.8rem"><button class="ghost" type="submit">خروج</button>' +
    (user.role === "admin" ? ' <a class="btn ghost" href="/admin">مدیریت رانر</a>' : "") + "</form></div>" +
    '<div class="card"><h2>لینک اشتراک (Subscription)</h2>' +
    '<div class="cfg"><span>لینک اشتراک — در v2rayNG / NekoBox / Streisand وارد کنید</span><code>' + htmlEscape(subUrl) + '</code>' +
    '<div class="row" style="margin-top:.5rem"><button type="button" onclick="navigator.clipboard.writeText(this.dataset.v)" data-v="' + htmlEscape(subUrl) + '">کپی لینک</button></div></div>' +
    (qr ? '<div style="text-align:center;margin-top:.6rem"><span class="qr">' + qr + "</span></div>" : "") + "</div>" +
    '<div class="card"><h2>کانفیگ‌ها</h2>' +
    configs.map((c) => '<div class="cfg"><span>' + htmlEscape(c.name) + '</span><code>' + htmlEscape(c.uri) + '</code><div class="row" style="margin-top:.4rem"><button type="button" onclick="navigator.clipboard.writeText(this.dataset.v)" data-v="' + htmlEscape(c.uri) + '">کپی</button></div></div>').join("") +
    "</div>";
  return pageShell("داشبورد", body);
}
function healthPage() {
  const h = buildHealth();
  const row = (k, v) => "<tr><th>" + k + "</th><td>" + v + "</td></tr>";
  return pageShell("سلامت سیستم",
    '<div class="card"><h2>سلامت رانر ' + (h.ok ? '<span class="ok">● سالم</span>' : '<span class="bad">● مشکل دارد</span>') + "</h2><table>" +
    row("نسخه رانر", htmlEscape(h.version)) +
    row("پنل بالا است", h.panelUp ? "بله" : "خیر") +
    row("API پنل", h.panelApiOk ? "متصل" : "قطع") +
    row("اینباندها", faDigits(h.inbounds)) +
    row("کلاینت‌ها", faDigits(h.clients)) +
    row("ری‌استارت پنل", faDigits(h.restarts)) +
    row("آپتایم (ثانیه)", faDigits(h.uptimeSec)) +
    row("رم نود / پنل / ایکس‌ری (MB)", faDigits(h.rssMb.node) + " / " + faDigits(h.rssMb.panel) + " / " + faDigits(h.rssMb.xray)) +
    row("رم کل (MB)", faDigits(h.rssMb.total)) +
    row("دیسک آزاد (MB)", faDigits(h.diskFreeMb)) +
    row("آخرین همگام‌سازی", h.lastReconcile ? htmlEscape(h.lastReconcile.at) + " (+" + h.lastReconcile.added + " ~" + h.lastReconcile.updated + " -" + h.lastReconcile.removed + ")" : "—") +
    "</table></div>");
}
async function adminPage(req, user, msg) {
  const users = readUsers();
  const h = buildHealth();
  const rows = users.map((u) => "<tr><td>" + htmlEscape(u.username) + (u.role === "admin" ? " 👑" : "") + "</td>" +
    "<td>" + (u.trafficLimitGb ? faDigits(u.trafficLimitGb) + " GB" : "نامحدود") + "</td>" +
    "<td>" + fmtDateFa(u.expiresAt) + "</td>" +
    "<td>" + (u.enabled === false ? '<span class="bad">غیرفعال</span>' : '<span class="ok">فعال</span>') + "</td>" +
    '<td><form method="post" action="/admin/users/delete" onsubmit="return confirm(\'حذف شود؟\')"><input type="hidden" name="username" value="' + htmlEscape(u.username) + '"><button class="danger" type="submit" ' + (u.username === user.username ? "disabled" : "") + ">حذف</button></form></td></tr>").join("");
  return pageShell("مدیریت رانر",
    (msg ? '<div class="card">' + htmlEscape(msg) + "</div>" : "") +
    '<div class="card"><h2>وضعیت</h2><p class="muted small">رم کل: ' + faDigits(h.rssMb.total) + "MB · اینباند: " + faDigits(h.inbounds) + " · کلاینت: " + faDigits(h.clients) + ' · <a href="/health">صفحه سلامت</a> · <a href="/healthz">JSON</a></p></div>' +
    '<div class="card"><h2>کاربران</h2><table><tr><th>نام</th><th>سقف</th><th>انقضا</th><th>وضعیت</th><th></th></tr>' + rows + "</table>" +
    '<h2 style="margin-top:1.2rem">ساخت کاربر</h2><form method="post" action="/admin/users/create"><div class="row">' +
    '<input class="grow" name="username" placeholder="نام کاربری" required><input class="grow" name="password" type="password" placeholder="رمز" required></div>' +
    '<div class="row" style="margin-top:.5rem"><input class="grow" name="trafficGb" type="number" min="0" placeholder="سقف GB (خالی=پیش‌فرض)"><input class="grow" name="expiryDays" type="number" min="0" placeholder="روز اعتبار (خالی=پیش‌فرض)"></div>' +
    '<button type="submit" style="margin-top:.7rem">ساخت</button></form></div>' +
    '<div class="card"><h2>پشتیبان و مهاجرت</h2><p class="muted small">باندل شامل کل وضعیت (دیتابیس پنل، کاربران، تنظیمات) در یک فایل است. روی هاست تازه: فایل را کنار index.js با نام restore.tar.gz بگذارید و اجرا کنید — یا مسیرش را در MEOWRAY_RESTORE بدهید.</p>' +
    '<div class="row"><a class="btn" href="/api/admin/backup">دانلود باندل پشتیبان</a>' +
    '<form method="post" action="/admin/reconcile"><button class="ghost" type="submit">همگام‌سازی دستی کلاینت‌ها</button></form></div></div>');
}

// ---- router ----
async function portalHandle(req, res) {
  const url = new URL(req.url, "http://portal.local");
  const route = url.pathname;
  // The mux stamps the real public peer on every proxied request (and
  // overwrites any client-supplied value); direct loopback callers fall
  // back to their socket address. Auth rate limiting keys on this.
  const ip = String(req.headers["x-meowray-client-ip"] || (req.socket && req.socket.remoteAddress) || "?");
  try {
    if (route === "/logo.svg") {
      res.writeHead(200, { "Content-Type": "image/svg+xml", "Cache-Control": "public, max-age=86400" });
      return res.end(LOGO_SVG);
    }
    if (route === "/healthz") return sendJson(res, RT.ready ? 200 : 503, buildHealth());
    if (route === "/health") {
      // Human health view is an admin surface (RSS/counts detail); the
      // machine endpoint /healthz above stays public for host checks.
      const hu = sessionUser(req);
      if (!hu || hu.role !== "admin") return redirect(res, "/login");
      return sendHtml(res, 200, healthPage());
    }
    if (route.startsWith("/sub/")) {
      const token = decodeURIComponent(route.slice(5));
      const user = findUserByToken(token);
      if (!user) { res.writeHead(404, { "Content-Type": "text/plain" }); return res.end("not found"); }
      if (!isUserActive(user)) { res.writeHead(403, { "Content-Type": "text/plain; charset=utf-8" }); return res.end("subscription inactive"); }
      const base = publicBase(req);
      const links = generateUserConfigs(user, base.host, base.port).map((c) => c.uri);
      const body = Buffer.from(links.join("\n")).toString("base64");
      res.writeHead(200, {
        "Content-Type": "text/plain; charset=utf-8",
        "Profile-Title": Buffer.from(BRAND).toString("base64"),
        "Subscription-Userinfo": "upload=0; download=0; total=" + Math.round((Number(user.trafficLimitGb) || 0) * 1073741824) + "; expire=" + (user.expiresAt ? Math.floor(Date.parse(user.expiresAt) / 1000) : 0),
        "Cache-Control": "no-store",
      });
      return res.end(body);
    }
    if (route === "/api/auth/register" && req.method === "POST") {
      const r = await authRegister(await parseBody(req), ip);
      if (r.error) return sendJson(res, r.code, { ok: false, error: r.error });
      setSessionCookie(res, r.user.username);
      return sendJson(res, r.code, { ok: true, username: r.user.username });
    }
    if (route === "/api/auth/login" && req.method === "POST") {
      const r = await authLogin(await parseBody(req), ip);
      if (r.error) return sendJson(res, r.code, { ok: false, error: r.error });
      setSessionCookie(res, r.user.username);
      return sendJson(res, 200, { ok: true, username: r.user.username, role: r.user.role });
    }
    if (route === "/api/auth/logout" && req.method === "POST") {
      res.setHeader("Set-Cookie", "mr_session=; Path=/; HttpOnly; Max-Age=0");
      return sendJson(res, 200, { ok: true });
    }
    if (route === "/login") {
      if (req.method === "GET") return sendHtml(res, 200, loginPage(""));
      const r = await authLogin(await parseBody(req), ip);
      if (r.error) return sendHtml(res, 401, loginPage(r.error));
      setSessionCookie(res, r.user.username);
      return redirect(res, "/dashboard");
    }
    if (route === "/register") {
      if (CFG.registration === "closed") return sendHtml(res, 403, loginPage("ثبت‌نام بسته است."));
      if (req.method === "GET") return sendHtml(res, 200, registerPage(""));
      const r = await authRegister(await parseBody(req), ip);
      if (r.error) return sendHtml(res, r.code, registerPage(r.error));
      setSessionCookie(res, r.user.username);
      return redirect(res, "/dashboard");
    }
    if (route === "/logout" && req.method === "POST") {
      res.setHeader("Set-Cookie", "mr_session=; Path=/; HttpOnly; Max-Age=0");
      return redirect(res, "/login");
    }
    if (route === "/api/user/info" && req.method === "GET") {
      const user = sessionUser(req);
      if (!user) return sendJson(res, 401, { ok: false, error: "unauthorized" });
      const base = publicBase(req);
      const traffic = await userTrafficCached(user);
      return sendJson(res, 200, {
        ok: true,
        username: user.username, role: user.role, active: isUserActive(user),
        trafficLimitGb: user.trafficLimitGb, expiresAt: user.expiresAt,
        traffic, subUrl: base.url + "/sub/" + user.subToken,
        configs: generateUserConfigs(user, base.host, base.port),
      });
    }
    if (route === "/dashboard" || route === "/") {
      const user = sessionUser(req);
      if (!user) return redirect(res, "/login");
      return sendHtml(res, 200, await dashboardPage(req, user));
    }
    // ---- admin (role=admin session required) ----
    if (route === "/admin" || route.startsWith("/admin/") || route.startsWith("/api/admin/")) {
      const user = sessionUser(req);
      if (!user) {
        if (route.startsWith("/api/")) return sendJson(res, 401, { ok: false, error: "unauthorized" });
        return redirect(res, "/login");
      }
      if (user.role !== "admin") return sendJson(res, 403, { ok: false, error: "admin only" });
      if (route === "/admin" && req.method === "GET") return sendHtml(res, 200, await adminPage(req, user, url.searchParams.get("msg") || ""));
      if (route === "/api/admin/backup" && req.method === "GET") {
        const stamp = new Date().toISOString().replace(/[:.]/g, "-");
        const out = path.join(P.backupsDir, "meowray-backup-" + stamp + ".tar.gz");
        const info = await createBundle(P.root, out);
        log("backup bundle created: " + out + " (" + info.files + " files)");
        res.writeHead(200, {
          "Content-Type": "application/gzip",
          "Content-Disposition": "attachment; filename=\"meowray-backup.tar.gz\"",
          "Content-Length": fs.statSync(out).size,
        });
        // Downloaded backups must not accumulate inside the (quota-limited)
        // state dir — remove the file once the response is done.
        res.on("close", () => { try { fs.rmSync(out, { force: true }); } catch (e) {} });
        return fs.createReadStream(out).pipe(res);
      }
      if (route === "/api/admin/users" && req.method === "POST") {
        const body = await parseBody(req);
        const username = String(body.username || "").trim();
        if (!/^[A-Za-z0-9_.-]{3,32}$/.test(username)) return sendJson(res, 400, { ok: false, error: "bad username" });
        if (findUser(username)) return sendJson(res, 409, { ok: false, error: "exists" });
        const newPass = String(body.password || "");
        if (newPass.length < 8 || newPass.length > 128) return sendJson(res, 400, { ok: false, error: "password must be 8-128 chars" });
        const limits = {
          trafficGb: body.trafficGb != null ? Math.max(0, Number(body.trafficGb) || 0) : undefined,
          expiresAt: body.expiryDays != null ? (Number(body.expiryDays) > 0 ? new Date(Date.now() + Number(body.expiryDays) * 86400000).toISOString() : null) : undefined,
        };
        const nu = newPortalUser(username, await hashPassword(newPass), "user",
          { trafficGb: limits.trafficGb, expiresAt: limits.expiresAt });
        if (limits.trafficGb === undefined) nu.trafficLimitGb = CFG.userTrafficGb;
        const users = readUsers(); users.push(nu); writeUsers(users);
        const sync = await reconcileNow("admin-create");
        return sendJson(res, 201, { ok: true, username, subToken: nu.subToken, reconcile: sync });
      }
      if (route === "/api/admin/users/update" && req.method === "POST") {
        const body = await parseBody(req);
        const users = readUsers();
        const target = users.find((u) => u.username === String(body.username || ""));
        if (!target) return sendJson(res, 404, { ok: false, error: "no such user" });
        if (body.trafficGb != null) target.trafficLimitGb = Math.max(0, Number(body.trafficGb) || 0);
        if (body.expiryDays != null) target.expiresAt = Number(body.expiryDays) > 0 ? new Date(Date.now() + Number(body.expiryDays) * 86400000).toISOString() : null;
        if (body.enabled != null) target.enabled = body.enabled === true || body.enabled === "true";
        if (body.password != null && String(body.password) !== "") {
          const np = String(body.password);
          if (np.length < 8 || np.length > 128) return sendJson(res, 400, { ok: false, error: "password must be 8-128 chars" });
          target.passwordHash = await hashPassword(np);
        }
        writeUsers(users);
        const sync = await reconcileNow("admin-update");
        return sendJson(res, 200, { ok: true, reconcile: sync });
      }
      if ((route === "/api/admin/users/delete" && req.method === "POST") || (route === "/admin/users/delete" && req.method === "POST")) {
        const body = await parseBody(req);
        const username = String(body.username || "");
        if (username === user.username) return sendJson(res, 400, { ok: false, error: "cannot delete self" });
        const targetUser = readUsers().find((u) => u.username === username);
        const users = readUsers().filter((u) => u.username !== username);
        writeUsers(users);
        const vault = readVault();
        const retired = new Set(vault.retiredUsers || []);
        retired.add(username);
        const vaultPatch = { retiredUsers: Array.from(retired) };
        // Record the deleted user's subId so reconcile removes ONLY the
        // clients carrying it — never a foreign client sharing the name.
        if (targetUser && targetUser.subToken) {
          const rt = Object.assign({}, vault.retiredTokens || {});
          rt[username] = targetUser.subToken;
          vaultPatch.retiredTokens = rt;
        }
        writeVault(vaultPatch);
        const sync = await reconcileNow("admin-delete");
        if (route.startsWith("/admin/")) return redirect(res, "/admin?msg=" + encodeURIComponent("کاربر حذف و کلاینت‌هایش جمع شد."));
        return sendJson(res, 200, { ok: true, reconcile: sync });
      }
      if (route === "/admin/users/create" && req.method === "POST") {
        const body = await parseBody(req);
        const username = String(body.username || "").trim();
        if (!/^[A-Za-z0-9_.-]{3,32}$/.test(username) || findUser(username)) return redirect(res, "/admin?msg=" + encodeURIComponent("نام کاربری نامعتبر یا تکراری است."));
        const formPass = String(body.password || "");
        if (formPass.length < 8 || formPass.length > 128) return redirect(res, "/admin?msg=" + encodeURIComponent("رمز باید ۸ تا ۱۲۸ کاراکتر باشد."));
        const nu = newPortalUser(username, await hashPassword(formPass), "user", {
          trafficGb: body.trafficGb !== "" && body.trafficGb != null ? Math.max(0, Number(body.trafficGb) || 0) : undefined,
          expiresAt: body.expiryDays !== "" && body.expiryDays != null ? (Number(body.expiryDays) > 0 ? new Date(Date.now() + Number(body.expiryDays) * 86400000).toISOString() : null) : undefined,
        });
        if (body.trafficGb === "" || body.trafficGb == null) nu.trafficLimitGb = CFG.userTrafficGb;
        const users = readUsers(); users.push(nu); writeUsers(users);
        await reconcileNow("admin-create-form");
        return redirect(res, "/admin?msg=" + encodeURIComponent("کاربر ساخته شد: " + username));
      }
      if (route === "/admin/reconcile" && req.method === "POST") {
        await reconcileNow("admin-manual");
        return redirect(res, "/admin?msg=" + encodeURIComponent("همگام‌سازی انجام شد."));
      }
      if (route === "/api/admin/reconcile" && req.method === "POST") {
        const sync = await reconcileNow("admin-manual");
        return sendJson(res, 200, { ok: true, reconcile: sync });
      }
    }
    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    return res.end("not found");
  } catch (e) {
    log("portal error on " + route + ": " + (e && e.message));
    try { sendJson(res, 500, { ok: false, error: "internal error" }); } catch (err) {}
  }
}
function startUserServer() {
  const server = http.createServer((req, res) => { portalHandle(req, res); });
  server.on("error", (err) => { log("FATAL: portal port " + USER_PORT + " could not be opened: " + err.message); process.exit(1); });
  server.listen(USER_PORT, "127.0.0.1", () => log("portal on 127.0.0.1:" + USER_PORT));
  return server;
}


// ===== src/16-mux.js =====

// Single-public-port multiplexer.
//
// Why not pure first-byte splicing? Browsers and HTTP clients reuse a
// keep-alive connection for MANY requests, and those requests can belong
// to different services (portal → panel). A connection-level splice sends
// every later request to whichever service the FIRST request chose — the
// panel would 404 portal paths and vice versa. So:
//   * HTTP connections are handed to a real HTTP server that routes PER
//     REQUEST and proxies (streaming, never buffered) to the loopback
//     service: /kb… → panel, /bp-… → WS/HTTPUpgrade inbounds, else portal.
//   * WebSocket upgrades are spliced raw after the routing decision (an
//     upgraded connection never carries a second HTTP request).
//   * HTTP/2 prefaces (gRPC clients) and non-HTTP bytes (VLESS-TCP) are
//     spliced raw — those connections are single-service by nature.

const HTTP_METHODS = ["GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "];
function httpMethod(buf) {
  const head = buf.subarray(0, 8).toString("latin1");
  return HTTP_METHODS.some((m) => head.startsWith(m));
}
function pickPort(buf, ctx) {
  const text = buf.subarray(0, Math.min(buf.length, 2048)).toString("latin1");
  if (text.startsWith("PRI * HTTP/2.0")) return ctx.grpcPort;
  if (httpMethod(buf)) {
    const line = text.split("\r\n")[0];
    const parts = line.split(" ");
    const reqPath = parts.length >= 2 ? parts[1] : "/";
    return routeHttpPath(reqPath, ctx);
  }
  return ctx.tcpPort;
}
function routeHttpPath(reqPath, ctx) {
  ctx = ctx || muxCtx();
  const pathOnly = String(reqPath || "/").split("?")[0];
  if (pathOnly === ctx.panelBase || pathOnly.startsWith(ctx.panelBase + "/")) return ctx.panelPort;
  for (const prefix of Object.keys(ctx.pathRoutes)) {
    if (pathOnly === prefix || pathOnly.startsWith(prefix + "/")) return ctx.pathRoutes[prefix];
  }
  return ctx.userPort;
}
function shouldWait(buf) {
  if (buf.length === 0) return true;
  const text = buf.subarray(0, Math.min(buf.length, 1024)).toString("latin1");
  if ("PRI * HTTP/2.0".startsWith(text)) return true; // possible H2 preface, incomplete
  if (/^[A-Z]{1,7}$/.test(text)) return true;          // partial HTTP method
  if (httpMethod(buf)) {
    // Need the full request line to read the path. The scan window covers
    // the whole sniff buffer, so a lean request with a long URL does not
    // stall until the sniff timer when its request line is already here.
    return !text.includes("\r\n") && buf.length < 1024;
  }
  return false;
}
function muxCtx() {
  return { panelPort: PANEL_PORT, userPort: USER_PORT, pathRoutes: PATH_ROUTES, grpcPort: INBOUND_PORTS.grpc, tcpPort: INBOUND_PORTS.vless, panelBase: PANEL_BASE };
}
function splice(socket, port, initial) {
  const upstream = net.connect({ host: "127.0.0.1", port }, () => {
    if (initial && initial.length) upstream.write(initial);
    socket.pipe(upstream);
    upstream.pipe(socket);
  });
  const kill = () => { try { socket.destroy(); } catch (e) {} try { upstream.destroy(); } catch (e) {} };
  socket.on("error", kill);
  upstream.on("error", kill);
  socket.on("close", () => { try { upstream.destroy(); } catch (e) {} });
}

// ---- per-request HTTP proxying ----
function proxyRequest(req, res) {
  const port = routeHttpPath(req.url);
  // Stamp the real public peer for the loopback services (the portal keys
  // its auth rate limiting on it). Always overwritten here, so a client
  // can never spoof it; the header only ever travels over loopback.
  const headers = Object.assign({}, req.headers);
  headers["x-meowray-client-ip"] = (req.socket && req.socket.remoteAddress) || "";
  const upstream = http.request(
    { host: "127.0.0.1", port, method: req.method, path: req.url, headers },
    (upRes) => {
      res.writeHead(upRes.statusCode || 502, upRes.headers);
      upRes.pipe(res);
    }
  );
  upstream.on("error", () => {
    if (!res.headersSent) res.writeHead(502, { "Content-Type": "text/plain; charset=utf-8" });
    try { res.end("bad gateway"); } catch (e) {}
  });
  req.on("error", () => { try { upstream.destroy(); } catch (e) {} });
  req.pipe(upstream);
}
function rawRequestHead(req) {
  let out = req.method + " " + req.url + " HTTP/" + req.httpVersion + "\r\n";
  const raw = req.rawHeaders || [];
  for (let i = 0; i + 1 < raw.length; i += 2) out += raw[i] + ": " + raw[i + 1] + "\r\n";
  return out + "\r\n";
}
let muxHttpServer = null;
function getMuxHttpServer() {
  if (muxHttpServer) return muxHttpServer;
  muxHttpServer = http.createServer(proxyRequest);
  muxHttpServer.on("upgrade", (req, socket, head) => {
    const ctx = muxCtx();
    const port = routeHttpPath(req.url, ctx);
    if (port === ctx.userPort || port === ctx.panelPort) { socket.destroy(); return; }
    const initial = Buffer.concat([Buffer.from(rawRequestHead(req), "latin1"), head || Buffer.alloc(0)]);
    splice(socket, port, initial);
  });
  muxHttpServer.on("clientError", (err, socket) => { try { socket.destroy(); } catch (e) {} });
  // CONNECT (and any non-request upgrade) is never legitimate here.
  muxHttpServer.on("connect", (req, socket) => { try { socket.destroy(); } catch (e) {} });
  return muxHttpServer;
}

function statusPageBuffer() {
  const failed = Boolean(RT.fatal);
  const body = '<div class="card" style="text-align:center">' +
    (failed ? "" : '<div class="spin"></div>') +
    "<h2>" + (failed ? "خطا در راه‌اندازی" : BRAND + " در حال آماده‌سازی است") + "</h2>" +
    "<p>" + htmlEscape(RT.fatal || RT.status) + "</p>" +
    '<p class="muted small">نسخه ' + RUNNER_VERSION + (failed ? "" : " · این صفحه هر چند ثانیه تازه می‌شود") + "</p></div>";
  const html = statusShell(failed ? "خطا" : "در حال راه‌اندازی", body);
  return "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\nCache-Control: no-store\r\nContent-Length: " +
    Buffer.byteLength(html) + "\r\n\r\n" + html;
}
function handleSocket(socket) {
  let buf = Buffer.alloc(0);
  let done = false;
  const finish = () => {
    if (done) return;
    done = true;
    clearTimeout(timer);
    socket.removeListener("data", onData);
    if (!RT.ready) {
      if (httpMethod(buf) || buf.length === 0) socket.end(statusPageBuffer());
      else socket.destroy();
      return;
    }
    if (httpMethod(buf)) {
      // Hand the whole connection to the HTTP server (buffered bytes first);
      // it routes per request from here on.
      socket.pause();
      socket.unshift(buf);
      getMuxHttpServer().emit("connection", socket);
      socket.resume();
      return;
    }
    socket.pause();
    splice(socket, pickPort(buf, muxCtx()), buf);
  };
  const onData = (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    if (!RT.ready) return finish();
    if (!shouldWait(buf) || buf.length >= 4096) finish();
  };
  const timer = setTimeout(finish, 2000);
  socket.on("data", onData);
  socket.on("error", () => socket.destroy());
}
function startPublicServer() {
  const server = net.createServer(handleSocket);
  server.on("error", (err) => {
    // Port busy etc: fail LOUDLY, never linger half-alive.
    log("FATAL: public port " + CFG.publicPort + " could not be opened: " + err.message);
    process.exit(1);
  });
  server.listen(CFG.publicPort, "0.0.0.0", () => {
    log("public TCP port " + CFG.publicPort + " open · " + RUNNER_VERSION);
  });
  return server;
}


// ===== src/17-supervisor.js =====

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


// ===== src/18-selftest.js =====

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


// ===== src/19-main.js =====

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
