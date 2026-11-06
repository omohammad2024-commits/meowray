"use strict";
// MeowRay build: bundles src/*.js (ordered fragments, shared top-level scope)
// into the single-file deliverable dist/index.js. Zero dependencies.
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const ROOT = __dirname;
const SRC = path.join(ROOT, "src");
const DIST = path.join(ROOT, "dist");

const ORDER = [
  "00-head.js",
  "01-versions.js",
  "02-utils.js",
  "03-config.js",
  "04-dropcache.js",
  "05-bundle.js",
  "06-qr.js",
  "07-state.js",
  "08-users.js",
  "09-download.js",
  "10-binary.js",
  "11-panelapi.js",
  "12-inbounds.js",
  "13-reconcile.js",
  "14-seed.js",
  "15-portal.js",
  "16-mux.js",
  "17-supervisor.js",
  "18-selftest.js",
  "19-main.js",
];

function main() {
  const parts = [];
  for (const name of ORDER) {
    const file = path.join(SRC, name);
    if (!fs.existsSync(file)) throw new Error("missing source module: " + name);
    const code = fs.readFileSync(file, "utf8");
    parts.push("\n// ===== src/" + name + " =====\n" + code.replace(/^"use strict";\s*/m, ""));
  }
  const banner = "// MeowRay — single-file runner. Built from src/ modules by build.js; do not edit dist directly.\n";
  const out = banner + parts.join("\n");
  // sanity: no leftover local requires of our own modules
  if (/require\(["']\.\//.test(out)) throw new Error("bundle contains a local require()");
  fs.mkdirSync(DIST, { recursive: true });
  const target = path.join(DIST, "index.js");
  fs.writeFileSync(target, out);
  const pkg = {
    name: "meowray",
    version: "1.0.0",
    private: true,
    description: "MeowRay — portable single-port panel runner (KataBump / Railway / any Node host)",
    main: "index.js",
    scripts: {
      start: "node index.js",
      test: "SELFTEST=1 node index.js",
    },
    engines: { node: ">=18" },
  };
  fs.writeFileSync(path.join(DIST, "package.json"), JSON.stringify(pkg, null, 2) + "\n");
  const sha = crypto.createHash("sha256").update(out).digest("hex");
  console.log("built dist/index.js", out.length, "bytes sha256", sha);
}
main();
