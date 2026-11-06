
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
