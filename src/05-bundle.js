
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
