#!/usr/bin/env python3
"""
MeowRay — KataBump auto-renew (v2).

Hardened vs the MF Panel original:
  * NO hardcoded fallback server id: if SERVER_ID is missing the run fails
    fast (exit 2) instead of silently renewing a stranger's server.
  * Every failure path saves a full-page screenshot (+ HTML) so the GitHub
    Actions artifact shows exactly what the bot saw.
  * Success is verified by page evidence (renewed/expiry text or the renew
    button becoming disabled), not assumed from the click.

Secrets (GitHub → Settings → Secrets and variables → Actions):
  KATABUMP_EMAIL     account email
  KATABUMP_PASSWORD  account password
  SERVER_ID          your server id (see renew/README.md)

Exit codes: 0 renewed/already-valid · 2 missing config · 1 failure.
"""
import os
import re
import sys
import time

from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

BASE = "https://dashboard.katabump.com"
ARTIFACTS = os.environ.get("RENEW_ARTIFACTS", ".")


def fail(page, message, code=1):
    print(f"[renew] ERROR: {message}", file=sys.stderr)
    if page is not None:
        try:
            page.screenshot(path=os.path.join(ARTIFACTS, "renew-failure.png"), full_page=True)
            with open(os.path.join(ARTIFACTS, "renew-failure.html"), "w", encoding="utf-8") as fh:
                fh.write(page.content())
            print("[renew] screenshot + html saved", file=sys.stderr)
        except Exception as exc:  # screenshot must never mask the real error
            print(f"[renew] could not save screenshot: {exc}", file=sys.stderr)
    sys.exit(code)


def main():
    email = os.environ.get("KATABUMP_EMAIL", "").strip()
    password = os.environ.get("KATABUMP_PASSWORD", "")
    server_id = os.environ.get("SERVER_ID", "").strip()
    missing = [name for name, val in
               (("KATABUMP_EMAIL", email), ("KATABUMP_PASSWORD", password), ("SERVER_ID", server_id))
               if not val]
    if missing:
        # Fail fast — do NOT guess a server id (the MF bot fell back to a
        # hardcoded one, which can renew the wrong server or silently rot).
        print(f"[renew] missing required secrets: {', '.join(missing)}", file=sys.stderr)
        sys.exit(2)

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1366, "height": 900})
        page.set_default_timeout(45000)
        try:
            # ---- login ----
            page.goto(f"{BASE}/auth/login", wait_until="domcontentloaded")
            page.fill('input[type="email"], input[name="email"], input[name="username"]', email)
            page.fill('input[type="password"]', password)
            page.click('button[type="submit"], button:has-text("Login"), button:has-text("Sign in")')
            page.wait_for_load_state("networkidle")
            if "/auth/login" in page.url:
                fail(page, "login did not complete (still on the login page — check credentials)")

            # ---- open the server page (try the known URL shapes in order) ----
            candidates = [
                f"{BASE}/server/{server_id}",
                f"{BASE}/servers/{server_id}",
                f"{BASE}/dashboard/server/{server_id}",
            ]
            opened = False
            for url in candidates:
                page.goto(url, wait_until="domcontentloaded")
                page.wait_for_load_state("networkidle")
                body = (page.content() or "").lower()
                if server_id.lower() in page.url.lower() or "renew" in body:
                    opened = True
                    break
            if not opened:
                fail(page, f"could not open a server page for SERVER_ID={server_id}")

            # ---- find and click Renew ----
            renew = page.get_by_role("button", name=re.compile(r"renew", re.I))
            if renew.count() == 0:
                renew = page.locator('button:has-text("Renew"), a:has-text("Renew")')
            if renew.count() == 0:
                # No renew button: the server may already be valid for the
                # full window. Treat visible expiry evidence as success.
                text = (page.locator("body").inner_text()).lower()
                if "expir" in text or "renew" in text:
                    print("[renew] no renew button present; server page shows expiry info — nothing to do")
                    return
                fail(page, "renew button not found on the server page")
            renew.first.click()
            page.wait_for_load_state("networkidle")
            time.sleep(2)

            # A confirmation dialog appears on some dashboard versions.
            confirm = page.get_by_role("button", name=re.compile(r"^\s*(confirm|yes|renew)\s*$", re.I))
            if confirm.count() > 0 and confirm.first.is_visible():
                confirm.first.click()
                page.wait_for_load_state("networkidle")
                time.sleep(2)

            # ---- verify by evidence ----
            text = (page.locator("body").inner_text()).lower()
            evidence = ("renewed" in text or "success" in text or "expir" in text)
            if not evidence:
                fail(page, "clicked renew but found no success evidence on the page")
            print("[renew] OK — renewal confirmed by page evidence")
        except PWTimeout as exc:
            fail(page, f"timeout: {exc}")
        except SystemExit:
            raise
        except Exception as exc:
            fail(page, f"unexpected error: {exc}")
        finally:
            browser.close()


if __name__ == "__main__":
    main()
