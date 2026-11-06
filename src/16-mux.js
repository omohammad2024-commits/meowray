
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
