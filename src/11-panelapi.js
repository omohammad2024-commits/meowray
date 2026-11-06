
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
