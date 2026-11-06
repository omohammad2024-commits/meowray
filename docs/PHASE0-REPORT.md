# MeowRay — Phase 0 Report: MF Panel Audit + Local Smoke

تاریخ: 2026-11-06 · محیط تست: همین VM (Linux amd64, Node v24.22.1) · زیپ مرجع دست‌نخورده ماند: `~/workspace/user/files/M-F-PANEL-main.zip`

---

## خلاصه‌ی فارسی (نتیجه اول)

**حکم ممیزی امنیتی: تمیز — بک‌دور یا نشت کریدنشیال پیدا نشد.** کل `index.js` (۵٬۱۸۰ خط) قبل از هر اجرا به‌صورت استاتیک خوانده و grep شد. هر دانلودی که می‌کند هش SHA-256 پین‌شده دارد و قبل از اجرا وریفای می‌شود: باینری پنل، هر سه کتابخانه‌ی glibc اوبونتو، و حتی هلپر ۴۰۰ بایتی dropcache. تنها هاست‌های خارجی کل فایل: `github.com` (دانلود باینری)، `archive.ubuntu.com` (کتابخانه‌ها)، `api.ipify.org` و `icanhazip.com` (فقط فهمیدن IP عمومی خود سرور). هیچ `eval`/`Function` در مسیر اجرایی نیست، هیچ توکن یا رمز هاردکدی نیست، هیچ تله‌متری‌ای نیست. تنها اعتماد ذاتی: خود باینری ۳۳۰ مگابایتی آپ‌استریم (Sir-MmD/vpn-ui) که سورسش را نداریم و هش فقط «همان ریلیز رسمی بودن» را ثابت می‌کند.

**حکم اسموک لوکال: کامل پاس شد، با عدد.** اجرای ایزوله با کریدنشیال دامی: بوت سرد (با دانلود ۳۳۰MB) ≈ ۱۴٫۵ ثانیه، بوت گرم ≈ ۴ ثانیه؛ هر ۹ اینباند دقیقاً طبق پلن ساخته شد (VLESS/Trojan/SS روی TCP زنجیره‌ی fallback + VLESS/VMess/Trojan روی WS + gRPC + HTTPUpgrade + WireGuard یوزراسپیس)؛ پنل ادمین روی `/kb/` جواب ۲۰۰ داد (۴۱٬۸۸۱ بایت، تایتل برندشده)، پرتال کاربر لاگین شد، لینک سابسکریپشن ۶ کانفیگ معتبر داد (UUID و JSON ویمِس ساختاراً وریفای شد)؛ ری‌استارت دوم هیچ اینباند تکراری نساخت (آیدمپوتنسی واقعی). مصرف رم آیدلِ کل سه پروسه ≈ **۵۲۷MB RSS** — یعنی روی پلن رایگان KataBump (۳۰۸MB) عملاً جا نمی‌شود؛ خود کد هم زیر ۷۰۰MB هشدار می‌دهد. بعد از تست همه‌ی پروسه‌ها کشته و پورت‌ها آزاد چک شدند.

**جمع‌بندی برای MeowRay:** MF Panel کفِ کار است، نه سقف (دستور محمد). اسکلتش سالم و قابل کپی است (مالتی‌پلکسر تک‌پورت، دانلود هش‌پین‌شده، پچ fail-closed، زیرو-دیپندنسی)، ولی ضعف‌های واقعی دارد: ترنسپورت‌هایش همه deprecated ـن (خود Xray موقع بوت اخطار داد)، دو اینباند از ۹ تا (SS و WireGuard) به کاربر نهایی هیچ کانفیگی نمی‌دهند، تغییر سقف ترافیک/انقضای کاربرِ موجود هرگز به اینباندها اعمال نمی‌شود، ثبت‌نام پیش‌فرض باز و سهمیه پیش‌فرض نامحدود است، و رمش برای پلن رایگان سنگین است. لیست کامل ضعف‌ها با مدرک + لیست «MeowRay باید این‌طوری ردش کند» در بخش پایانی ریپورت است.

---

## 1. Inventory

| File | Bytes | Lines | SHA-256 |
| :--- | ---: | ---: | :--- |
| `M-F-PANEL-main.zip` (original, untouched) | 79,135 | — | `bfe20804faf9d00c96952cfcb859f0f1b753e8a9b5c78cfe6f070814d013bdda` |
| `index.js` | 284,512 | 5,180 | `17627aa1b6b12b3401771a1839d4bd1cb98afff22f0feae798be83a9edfa562a` |
| `README.md` | 10,200 | 97 | `3df2e4ab25382ced27074d11c23a0c6253a492524fa0c96510e15d7a53409430` |
| `code.txt` | 4,117 | 113 | `a1cf5f97c02c0bacef4eb5e28457081cfff97e584e8e21c7efd0aacf26bf9a1d` |
| `package.json` | 415 | 14 | `d03b170f66a7b5f62ac743b4b0d065f910211716e73a4b165e7028934aeb6e74` |

Extracted copy: `~/workspace/meowray/reference/mf-panel/` · Node available: **v24.22.1** (package.json requires ≥16; zero npm dependencies — Node builtins only).

**README.md actually says:** a non-root runner for "vpn-ui v1.9.4" (branded M&F Panel, version string `mf-panel-katabump-1.1`) for KataBump + Railway, with a Persian user portal, subscription dashboard, and an auto-renew bot (Playwright + GitHub Actions, every 3 days). It documents the routing table (portal `/` →18081, admin `/kb` →18080, `/bp-vless` →21011, `/bp-vmess` →21012, `/bp-trojan` →21013, `/bp-up` →21015, gRPC serviceName `bpgrpc` →21014, TCP chain 21001→21002→21003, WireGuard UDP on the public port), install steps for both hosts, the env vars, and the renew-bot setup (GitHub secrets `KATABUMP_EMAIL`, `KATABUMP_PASSWORD`, `SERVER_ID`). Contact: Telegram `@M_Fpanel`.

**code.txt actually contains:** the three (blank) Katabump secret names, then the full `renew.py` (Playwright headless-Chromium login to `control.katabump.com`, navigates to the server page, clicks "Renew", screenshots on error) and `.github/workflows/renew.yml` (cron `0 12 */3 * *` + manual dispatch, Python 3.10). Privacy leftover: `renew.py` has a **hardcoded default `SERVER_ID` = `d1712508`** (the author's own server id) used when the secret is unset.

**package.json:** name `mf-panel` v1.1.0, `start: node index.js`, `test:` runs the file with `SELFTEST=1`. No dependencies.

---

## 2. Static Security Audit (before any execution)

Method: full read of all entry/boot/download/patch/portal code paths + targeted greps over all 5,180 lines (URLs, domains, spawn targets, env reads, eval/vm, secrets). Every external domain in the file — exhaustive list: `github.com`, `archive.ubuntu.com`, `api.ipify.org`, `icanhazip.com`, `t.me` (HTML anchor only), `www.w3.org` (SVG namespaces only).

| # | Item (evidence) | Verdict |
| :--- | :--- | :--- |
| 1 | Panel binary download: `index.js:28` `VPN_URL = https://github.com/Sir-MmD/vpn-ui/releases/download/v1.9.4/vpn-ui-amd64`; `index.js:29` `VPN_SHA = 18ec321d…a2da8f`. Hash verified before patch/run (`ensureBinary`, lines 592–599; cached copies re-verified 568–590; mismatch → file deleted + abort) | ✅ Expected, well-implemented |
| 2 | glibc compat downloads (only when system glibc < 2.34): 3 `.deb`s from `archive.ubuntu.com` (libc6 2.35-0ubuntu3.15, libgcc-s1 12.3.0, libcrypt1 4.4.27), each SHA-256 pinned in `GLIBC_DEBS` (lines 277–286) and verified in `ensureRuntime` (lines 388–395; mismatch → delete + throw). Extraction is pure JS (ar parser + vendored fzstd), no `dpkg`/`apt` | ✅ Expected, hash-pinned |
| 3 | Embedded `dropcache` helper: base64 x86-64 ELF (~400 B) written to `vpn/dropcache`, full assembly source printed in comments above it (open + `posix_fadvise(DONTNEED)` + exit). SHA-256 (`FADVISE_SHA`, line 451) re-verified on every write in `ensureFadvise` (lines 487–500) | ✅ Expected; source disclosed + hash-checked |
| 4 | Binary patching: `patchBinary` (548–566) replaces the `requireRoot` JE jump with an unconditional JMP in the pinned binary; byte-exact needle + expected-bytes check, **fails closed** if the pattern differs ("only v1.9.4 supported"). `patchInterpreter` (466–485) rewrites the ELF interpreter path when the bundled glibc loader is used | ⚠️ Expected-for-function (documented), but version-locked — see weaknesses |
| 5 | Public-IP detection: GET `api.ipify.org` (https, then **http fallback**), `icanhazip.com` (`detectPublicHost`, 711–719). Sends nothing except the request itself; skipped entirely when `PANEL_HOST`/`SERVER_IP` is set | ✅ Expected; http fallback is a minor wart |
| 6 | Internal panel API client `panelRequest` (725–761): hardcoded `127.0.0.1:18080` only | ✅ No external API calls |
| 7 | Spawn targets (all arg arrays, **no `shell:` anywhere**): `curl` (downloads, `-fL --retry 8 -C -`), `df -B1`, system `libc.so.6` with no args (glibc version probe), `dropcache`, and the panel binary itself (`setting`, `run`) | ✅ Expected, no shell-string injection surface |
| 8 | `eval` / `new Function`: **none**. `require("vm")` appears only inside `runSelfTest` (lines 4249, 4262) to syntax-check its own inline page scripts and render a test QR — not reachable in production flow | ✅ Clean |
| 9 | Hardcoded credentials/tokens: **none for third parties.** Upstream factory default `admin/admin` is used only as a fallback login attempt inside `seed()` (1052–1063) and is immediately replaced by a random first-boot password; session secret is randomly generated per install (1264–1273) | ✅ Clean (one design note in weaknesses: plaintext password at rest) |
| 10 | Telemetry / phone-home / exfiltration: **none found.** No analytics, no webhook, no posting of env/files/IP anywhere. The only outbound flows are items 1, 2, 5. Portal/brand pages contain zero external resources (the code's own selftest even asserts this, line 4238) | ✅ Clean |
| 11 | Vendored blobs: fzstd decompressor (lines 4456–5047, by 101arrowz, gist credited at 4789), QR-code generator (1585–2017), brand logo/CSS/JS as base64 (lines 23–27; decodes to an SVG logo, a theme CSS, and a DOM-rebranding script — all presentation) | ✅ Accounted for, no hidden payloads |
| 12 | `code.txt` renew bot: logs into Katabump with the *operator's own* GitHub secrets; takes an error screenshot locally. Hardcoded fallback `SERVER_ID=d1712508` (author's own) | ⚠️ Benign but sloppy — must not be copied |

**Audit verdict: NO red flags. Cleared for isolated local execution with dummy credentials.**

Supply-chain note (not a finding against MF): the design inherently trusts the closed-source 330 MB upstream binary from `Sir-MmD/vpn-ui`. The SHA pin proves "the pinned release", not "benign upstream". MeowRay inherits this trust decision explicitly.

---

## 3. Anatomy

**Boot chain** (`main`, 4339–4455): validate port/arch (linux/x64 only) → create dirs → start public TCP mux + user portal server immediately (status page while booting) → cgroup RAM + disk checks (needs ≥420 MB free on first run) → `ensureBinary` (download 345,757,800 B binary via curl with resume, or Node https fallback; SHA-256 verify; `patchBinary`; chmod) → if glibc < 2.34: `ensureRuntime` (download+verify+extract Ubuntu libs, patch ELF interpreter, direct-exec via bundled loader) → drop page-cache + trim RU/IR geo files → configure panel by running the binary's own `setting -port 18080 -listenIP 127.0.0.1 -webBasePath kb [-username/-password on first boot]` → detect public host → start panel child (`run`) → wait ≤90 s for port 18080 → `seed()` → log URLs + first-boot credentials.

**Single public port / mux** (`handleSocket`/`pickPort`, 3762–3775, 4040–4075): raw TCP server on `SERVER_PORT|PORT` (default 8080). It sniffs the first bytes of each connection: HTTP/2 preface (`PRI * HTTP/2.0`) → gRPC inbound (21014); HTTP request line → path prefix routing (`/bp-vless`→21011, `/bp-vmess`→21012, `/bp-trojan`→21013, `/bp-up`→21015, `/kb…`→panel 18080, everything else→user portal 18081); non-HTTP binary → VLESS-TCP (21001). Panel traffic goes through `brandProxy`, which rewrites the panel's HTML on the fly (title, logo, theme CSS/JS injection under `/kb/_alireza/`). Before `state.ready`, HTTP requests get a Persian "starting" status page; non-HTTP sockets are dropped. Panel and portal bind **127.0.0.1 only**; all inbounds bind 127.0.0.1 except WireGuard (0.0.0.0, UDP, on the public port itself).

**Pre-created inbounds** (`plannedInbounds`, 840–918; all `security: "none"`, sniffing http/tls/quic, `externalProxy` set to the public host:port so panel-generated links point at the mux):

| Remark | Protocol | Internal port | Transport / settings |
| :--- | :--- | ---: | :--- |
| VLESS-TCP | vless | 21001 | raw TCP, fallback → Trojan-TCP |
| Trojan-TCP | trojan | 21002 | raw TCP, fallback → Shadowsocks |
| Shadowsocks | shadowsocks | 21003 | `2022-blake3-aes-256-gcm`, one shared random password, **no per-user clients** |
| VLESS-WS | vless | 21011 | WebSocket `/bp-vless` |
| VMess-WS | vmess | 21012 | WebSocket `/bp-vmess` |
| Trojan-WS | trojan | 21013 | WebSocket `/bp-trojan` |
| VLESS-gRPC | vless | 21014 | gRPC, serviceName `bpgrpc` |
| VLESS-HTTPUpgrade | vless | 21015 | HTTPUpgrade `/bp-up` |
| WireGuard | wireguard | PUBLIC_PORT (UDP) | xray userspace WG (`noKernelTun: true`, MTU 1280, 10.10.0.1/32, clients 10.10.0.0/24), fresh X25519 keypair per seed run |

**User portal** (built into index.js, port 18081): routes `/`, `/login`, `/register`, `/dashboard`, `/sub`, `/sub/<token>`, `/api/auth/register|login|logout`, `/api/user/info`, `/logo.svg`. Users in `vpn/data/mf_users.json` (JSON file, in-process lock, `.bak` sibling), passwords **scrypt**-hashed, sessions = HMAC-SHA256-signed tokens (`mf_session` cookie, HttpOnly, SameSite=Lax, 30 d), rate limiting on auth endpoints, body size caps. On login/registration each portal user is synced into the panel as a client of every VLESS/VMess (uuid = portal user id) and Trojan (password = portal user id) inbound with `subId = subToken` and per-user `totalGB`/`expiryTime`. Subscription endpoint returns base64 of 6 links (VLESS-WS, VMess-WS, Trojan-WS, VLESS-TCP, VLESS-HTTPUpgrade, VLESS-gRPC) + a dashboard with an inline-SVG QR of the sub URL (vendored QR lib, zero-dep). The portal `admin` user is bridged to the panel admin password.

**State on disk** (under `KATABUMP_ROOT` or `/home/container` or cwd): `vpn/vpn-ui-amd64` (+`.ok` hash mark), `vpn/bin/` (extracted xray + geo files), `vpn/data/` (panel SQLite `vpn-ui.db`, `mf_users.json`), `vpn/log/`, `vpn/state.json` (admin username, **plaintext admin password**, session secret), `vpn/PANEL.txt` (human-readable access card with the same password), `vpn/dropcache`, `vpn/glibc/` (only on old-glibc hosts).

**Env vars (complete list):** `SERVER_PORT`/`PORT` (public port, default 8080), `PANEL_HOST` (public domain for links), `SERVER_IP` (public IP alternative), `KATABUMP_ROOT` (data root), `REGISTRATION` (`open` default / `closed`), `USER_TRAFFIC_GB` (default 0 = unlimited), `USER_EXPIRY_DAYS` (default 0 = no expiry), `SELFTEST` (test mode). Child panel env adds `VPNUI_DB_FOLDER/BIN_FOLDER/LOG_FOLDER`, `GOMAXPROCS=1`, `GODEBUG=madvdontneed=1`, `MALLOC_ARENA_MAX=1`, and `GOMEMLIMIT` scaled to the cgroup limit when one is detected — but the child inherits the **full** `process.env`.

**Renew system:** not in the zip as files — `code.txt` carries `renew.py` + `renew.yml` verbatim for manual copy into a GitHub repo (see §1).

---

## 4. Local Smoke (isolated, dummy credentials only)

Setup: copy of `index.js`+`package.json` in `~/workspace/meowray/smoke/`, env `KATABUMP_ROOT=<smoke dir>`, `SERVER_PORT=18090`, `PANEL_HOST=smoke.test` (also suppresses public-IP lookups), `REGISTRATION=closed`. No real credential used anywhere; the admin password was randomly generated by the program itself on first boot and is redacted here.

| Check | Result |
| :--- | :--- |
| Built-in selftest (`SELFTEST=1`, = `npm test`) | ✅ `selftest ok` + `brand proxy ok`, exit 0, **0.52 s** |
| Cold boot (incl. 330 MB download at ~25 MB/s on this VM) | ✅ public port open at +0.05 s (status page HTTP 200), panel ready + seeded at **≈14.5 s** total |
| Warm boot (binary cached) | ✅ fully seeded in **≈4.0 s**; log: "باینری آماده است و دوباره دانلود نشد" |
| Panel UI via mux `GET /kb/` | ✅ **HTTP 200, 41,881 B**, `<title>M&F Panel</title>` (brand proxy active) |
| Portal `GET /` | ✅ **HTTP 302** → login; portal API login with dummy admin ✅ `{"ok":true}` |
| Panel API (login + `inbounds/list`) | ✅ success, **9 inbounds** — exactly the planned table above; admin client present in 7 (all but Shadowsocks and WireGuard, which have **0 clients**) |
| Listening sockets | ✅ 18080/18081 + 21001–21003 + 21011–21015 on 127.0.0.1 only; public TCP 18090 on 0.0.0.0; **UDP 18090** (WireGuard) bound |
| Subscription `GET /sub/<token>` | ✅ HTTP 200, 1,368 B; base64 decodes to **6 links**; VLESS/Trojan UUIDs match the UUID regex and `@smoke.test:18090`; VMess base64 JSON parses with all required fields (`v,ps,add,port,id,net,type,path`, UUID valid) |
| Idempotency (full restart) | ✅ inbounds still **9**, zero "created" lines on second boot — seed matched all by remark |
| RAM at idle (RSS, post-boot) | node **141 MB** + vpn-ui **356 MB** + xray **30 MB** = **≈527 MB total** |
| Disk footprint | `vpn/` = **501 MB** (binary 345.8 MB + bin/data/log) |
| Cleanup | ✅ node killed via SIGTERM (its handler stops the panel child), **0 related processes remain, all smoke ports free** |

Notable log evidence from the bundled Xray during seeding — deprecation warnings for **WebSocket, VMess, Trojan (no Flow), gRPC and HTTPUpgrade** transports, each recommending migration to XHTTP / VLESS-Encryption. Also logged by the runner itself: protocols that "have no kernel in this container" (OpenVPN/L2TP/PPTP/IKEv2/SSTP/GRE) are not created.

---

## 5. MF Panel Weaknesses / Mediocrities (with evidence) — the floor

1. **It rides deprecated transports only.** Every WS/VMess/Trojan/gRPC/HTTPUpgrade inbound triggered an Xray deprecation warning in our own smoke log (§4); there is **no XHTTP, no Reality, no Vision flow, and no TLS on any inbound** (`security: "none"` everywhere in `plannedInbounds`). On a raw KataBump address the portal and panel logins also travel over plain HTTP.
2. **RAM blows the free tier it targets.** Measured ≈527 MB RSS idle (node 141 + panel 356 + xray 30) vs KataBump free's 308 MB. The code itself admits idle ≈380 MB and warns below 700 MB (`main`, log line + `state.note`). `GOMEMLIMIT` caps only the Go child, only when a cgroup limit is detectable.
3. **Two of nine inbounds are dead weight.** Shadowsocks (shared password, 0 clients) and WireGuard (0 clients/peers) are created and listen, but `generateUserConfigs` returns only 6 links — portal users can never receive SS or WG configs. They cost RAM/attack surface for zero delivered function.
4. **User-limit changes never propagate.** `syncUsersToInboundsNow` (1397–1477) only *adds* missing clients; an existing client is skipped entirely, so raising/lowering a user's GB quota, expiry or enable flag in the portal never reaches the inbounds. Quota enforcement for existing users is effectively frozen at first-sync values.
5. **Insecure defaults.** `REGISTRATION=open` by default and `USER_TRAFFIC_GB=0`/`USER_EXPIRY_DAYS=0` (unlimited, no expiry): a stock deploy lets anyone on the internet self-register an unlimited account.
6. **Secrets at rest in plaintext.** `vpn/state.json` contains `username`, `password`, `sessionSecret` in clear text (verified in smoke), and `vpn/PANEL.txt` repeats the admin password; both written with default (group-readable) permissions.
7. **Full environment leaks into the downloaded binary.** `panelEnv` (603–621) passes the entire `process.env` to the panel child — on a KataBump container that can include unrelated operator secrets placed as env vars.
8. **Single-version lock-in.** The root-check patch is byte-locked to vpn-ui v1.9.4 and fails closed on anything else; the download URL and hash are constants. Any upstream security fix requires hand-crafting a new needle — there is no version table or upgrade path.
9. **No supervision.** If the panel child exits, the runner exits with it (`startPanel` exit handler) — on KataBump that means manual restart; if `main()` throws early, the process instead lingers forever serving only the status page (`setInterval` keep-alive, line 4451), which looks "up" to a casual check while the VPN is dead. No health endpoint exists.
10. **Monolith maintainability.** One 5,180-line / 284 KB file where ~1,000+ lines are vendored fzstd + QR code and the first "code" lines are giant base64 brand blobs; panel, portal, mux, downloader and patcher are all interleaved. Its own test (`SELFTEST`) is 58 asserts over helpers/rendering — it never boots the panel or creates an inbound.
11. **Config drift by design.** Seeding matches inbounds by remark string only; if a newer runner changes a planned inbound's settings, existing installs silently keep the old settings forever (same skip logic as #4).
12. **Renew bot is fragile and leaky.** `code.txt:renew.py` — hardcoded fallback `SERVER_ID=d1712508` (the author's server), selector-based clicking (breaks on any Katabump UI change), 3-day cadence against a 4-day expiry (one missed/failed run ≈ dead server), no failure notification, and the account password lives in GitHub secrets with no rotation story.
13. **No backup/export/migration.** All state (panel DB, users, secrets) lives in the container filesystem; KataBump deleting a server = total, unrecoverable loss. Nothing in the runner exports or restores state.
14. **Plain-HTTP fallback for IP detection** (`http://api.ipify.org` tried second) — small, but it is an integrity-weak channel in an otherwise HTTPS-only download design (the glibc path explicitly removed its HTTP fallback; this one kept it).
15. **Disk pressure unhandled over time.** 501 MB state on a 716 MB free disk, panel logs in `vpn/log/` with no rotation in the runner; long-running installs will fill the disk and die silently.
16. **Mux robustness limits.** Routing is decided from the first chunk with a 2 s sniff timer (`handleSocket`); the brand proxy buffers whole HTML pages (cap 1.5 MB) to rewrite them; neither is a bug per se, but both are throughput/latency ceilings a busier server will hit.

## 6. What MeowRay should copy / fix / drop — and the Exceed List

### Copy (proven patterns worth keeping)
- Two-file form factor (`index.js` + `package.json`), **zero npm dependencies**, Node-builtins only.
- SHA-256 pinning + verify-before-run for *every* downloaded/executed artifact, fail-closed patching, resumable downloads (`.part` + curl `-C -`).
- The single-port first-byte mux (H2/HTTP-path/binary sniffing) and 127.0.0.1-only internal services.
- First-boot random admin password + `PANEL.txt` access card UX; scrypt portal passwords; HMAC session tokens; auth rate limiting; selftest asserts including "no external resources in pages".
- RAM tricks: geo-file trimming, page-cache drop helper, `GOMAXPROCS=1`/`GOMEMLIMIT` scaling.

### Fix / Drop (relative to MF, before any new features)
- Drop or fully wire Shadowsocks + WireGuard (see Exceed #4) — no dead inbounds.
- Closed registration + mandatory default quotas out of the box; `state.json`/`PANEL.txt` written `0600`; child process gets an **allowlisted** env, not the full env.
- HTTPS-only public-IP detection (drop the http fallback).

### MeowRay Exceed List (same form factor: one `index.js` + `package.json`, JS-only, zero-dep unless noted)
1. **Modern transport set:** add **VLESS-XHTTP (stream-up)** as the flagship inbound (Xray's own recommended successor in the smoke-log warnings) alongside WS fallback; on Railway also offer a TCP-Proxy mode with **VLESS-Reality** where a raw public port exists. *Benefit: not building on deprecated transports; better filtering resistance for Iran.*
2. **Real lifecycle reconciliation:** a periodic sync that adds **and updates and removes** inbound clients to match portal state (quota/expiry/enable enforced on existing users, not just at creation). *Benefit: quotas actually mean something — MF's #4 hole closed.*
3. **Supervisor + health:** runner restarts the panel child with backoff, exposes `/healthz` JSON (panel up?, inbound count, RSS, disk) on the portal, and exits loudly instead of zombie-serving a status page when the binary can't start. *Benefit: KataBump/Railway restarts self-heal; monitoring becomes possible.*
4. **No dead protocols:** per-user Shadowsocks-2022 clients and per-user WireGuard peers (own keypair + allocated /32) generated by the portal and included in the subscription — or the inbound isn't created. *Benefit: 9/9 inbounds deliver configs, incl. a real UDP option.*
5. **RAM diet to fit the free tier:** defer portal rendering cost, trim geo files *before* xray starts, always set `GOMEMLIMIT` (default cap even without cgroup detection), lazy-load the fzstd/QR sections. Target: **≤250 MB total idle RSS** verified by the same smoke harness (MF baseline: 527 MB). *Benefit: actually runs on KataBump free's 308 MB instead of merely warning about it.*
6. **Secure-by-default profile:** `REGISTRATION=closed` default with optional invite codes; first-boot forces non-zero default user quota unless explicitly set unlimited; session cookies get `Secure` when `PUBLIC_SCHEME=https` (Railway edge) is configured. *Benefit: a stock deploy is not an open public proxy.*
7. **Version agility:** a small table of supported upstream versions `{version → url, sha256, patch needle}` selectable via env, with the patch dry-run inside selftest. *Benefit: upstream security fixes become a one-line table entry, not surgery.*
8. **Faster cold start:** ship/download the panel binary **compressed** (`.zst`) and decompress with the already-vendored fzstd — the raw 345.8 MB download is the dominant cold-boot cost (~13 s of the 14.5 s here; far worse on KataBump's network). Parallelize binary + glibc staging. *Benefit: materially faster first boot and re-deploys.*
9. **Backup/restore built in:** admin-triggered (and scheduled) export of panel DB + users + state as one downloadable bundle from the panel, and first-boot import from a file/env URL. *Benefit: KataBump server deletion stops being total loss.*
10. **Renew v2:** 2-day cadence, failure → Telegram notification to the owner (their own bot token as a GitHub secret), screenshot uploaded as a workflow artifact, and **no hardcoded fallback server id** (fail fast if the secret is missing). *Benefit: the free server stops dying silently.*
11. **CI boot-smoke, not just unit asserts:** a GitHub Actions job that actually boots the artifact, asserts panel 200, portal login, 9+ inbounds via API, a structurally valid subscription payload, and an RSS budget. *Benefit: MF's selftest would pass even if the panel never started; ours can't.*
12. **Modular source, single-file artifact:** develop in small modules with a zero-dep build step that bundles them into the single upload `index.js` (artifact is what's tested). *Benefit: MF's 5,180-line monolith becomes reviewable without giving up the two-file upload UX.*
13. **Log hygiene:** size-capped rotation for `vpn/log/` inside the runner + structured one-line JSON boot report (versions, hashes, ports, inbound list). *Benefit: no silent disk-fill death on a 716 MB disk; support/debugging gets evidence, not vibes.*
14. **Portal UX upgrade (still zero-dep):** per-protocol copy buttons + per-config QR (not only the sub QR), live traffic/expiry display pulled from panel stats, countdown to expiry, and one-tap import deep-links for v2rayNG/NekoBox/Streisand. *Benefit: the user-facing half stops being the weakest part of the product.*

---

*Evidence artifacts: smoke logs `~/workspace/meowray/smoke/smoke.log` + `smoke2.log`; reference copy `~/workspace/meowray/reference/mf-panel/`; original zip untouched. All smoke processes terminated and ports verified free at the end of the run.*
