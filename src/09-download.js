
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
