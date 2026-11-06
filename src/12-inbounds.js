
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
