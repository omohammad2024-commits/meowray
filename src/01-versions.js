
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
