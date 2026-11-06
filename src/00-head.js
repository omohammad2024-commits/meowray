"use strict";

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
