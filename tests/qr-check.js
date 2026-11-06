"use strict";
// QR cross-validation: our encoder vs Nayuki's qrcodegen (canonical Python
// port) — module-for-module, every mask, several payloads incl. multi-block.
//
// NOTE: segno was tried first as the reference and REJECTED with evidence:
// it emits a non-spec 0x00 pad byte when the data ends exactly on a byte
// boundary (verified 2026-11-06: 'HELLO WORLD' V1-M pads 00 ec 11 instead
// of ec 11 ec; both matrices decode via zxing, but only ours matches the
// spec and qrcodegen bit-for-bit).
process.env.MEOWRAY_UNIT = "1";
const { execFileSync } = require("child_process");
const path = require("path");
const fs = require("fs");
const os = require("os");
const U = require("../dist/index.js");

const samples = [
  "HELLO WORLD",
  "https://example.com/sub/abc123",
  "http://host.test:18090/sub/0123456789abcdef01234567",
  "vless://11111111-2222-3333-4444-555555555555@h:443?path=%2Fbp-vless&security=none&type=ws#MeowRay",
  "trojan://pw@h:443?path=%2Fbp-trojan&security=none&type=ws#MeowRay-Trojan-WS",
];
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "qr-check-"));
const script = [
  "from qrcodegen import QrCode, QrSegment",
  "import sys, json",
  "text, mask, out = sys.argv[1], int(sys.argv[2]), sys.argv[3]",
  "seg = QrSegment.make_bytes(text.encode())",
  "q = QrCode.encode_segments([seg], QrCode.Ecc.MEDIUM, 1, 8, mask, False)",
  "size = q.get_size()",
  "m = [[1 if q.get_module(x, y) else 0 for x in range(size)] for y in range(size)]",
  "json.dump({'version': q._version, 'matrix': m}, open(out, 'w'))",
].join("\n");
let checks = 0, failures = 0;
for (const text of samples) {
  for (let mask = 0; mask < 8; mask++) {
    const bytes = Array.from(Buffer.from(text, "utf8"));
    let version = 0;
    for (let v = 1; v <= 8; v++) if (12 + bytes.length * 8 <= U.qrTotalData(v) * 8) { version = v; break; }
    if (!version) { console.log("skip (too long):", text); continue; }
    const dataCw = U.qrDataCodewords(bytes, version);
    const { codewords, remainderBits } = U.qrInterleave(dataCw, version);
    const mine = U.qrBuildMatrix(version, codewords, remainderBits, mask);
    const pyFile = path.join(tmp, "m.json");
    execFileSync("python3", ["-c", script, text, String(mask), pyFile],
      { env: Object.assign({}, process.env, { PYTHONPATH: "/tmp/pylibs" }), stdio: ["ignore", "ignore", "pipe"] });
    const ref = JSON.parse(fs.readFileSync(pyFile, "utf8"));
    checks++;
    if (ref.version !== version) { console.log("VERSION MISMATCH", { text: text.slice(0, 24), mask, mine: version, ref: ref.version }); failures++; continue; }
    let diff = 0;
    for (let r = 0; r < mine.length; r++) for (let c = 0; c < mine.length; c++) if (mine[r][c] !== ref.matrix[r][c]) diff++;
    if (diff) { console.log("DIFF", { text: text.slice(0, 24), mask, diff }); failures++; }
  }
}
fs.rmSync(tmp, { recursive: true, force: true });
console.log("qr-check: " + checks + " mask/sample combos vs qrcodegen, " + failures + " failures");
process.exit(failures ? 1 : 0);
