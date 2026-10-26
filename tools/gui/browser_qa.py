#!/usr/bin/env python3
"""Independent real-browser QA for the isolated synthetic preview, never the live API.

Uses existing Playwright 1.61.0 and cached Chromium; installs nothing. Pass the
private preview manifest, never a token value. Artifacts contain synthetic data.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import re
import stat
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit
from xml.sax.saxutils import escape

from playwright.sync_api import Error, expect, sync_playwright

PREVIEW_TMP = Path("/tmp")  # noqa: S108 -- fixed parent of the owned synthetic directories.


def check(value, message):
    if not value:
        raise AssertionError(message)


def private_json(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        check(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_nlink == 1
            and info.st_size <= 16384,
            "unsafe synthetic manifest",
        )
        return json.loads(os.read(fd, 16385))
    finally:
        os.close(fd)


class Audit:
    def __init__(self, context, token):
        self.token = token
        self.requests = []
        self.console_errors = []
        self.page_errors = []
        self.violations = []
        self.http_errors = []
        context.on("request", self.observe)
        context.on(
            "response",
            lambda response: (
                self.http_errors.append(
                    {"status": response.status, "path": urlsplit(response.url).path}
                )
                if response.status >= 400
                else None
            ),
        )
        context.route("**/*", self.route)

    def allowed(self, request):
        url = urlsplit(request.url)
        allowed = (url.scheme, url.netloc) == ("http", "127.0.0.1:18745")
        allowed_path = url.path.startswith("/ui/") or re.fullmatch(
            r"/(healthz|coverage|devices(?:/[^/]+(?:/activity)?)?|incidents(?:/[^/]+)?)",
            url.path,
        )
        query = parse_qs(url.query)
        credential = self.token in unquote(request.url) or any(
            name.lower() in {"token", "key", "authorization", "access_token", "api_key"}
            for name in query
        )
        return bool(allowed and allowed_path and request.method == "GET" and not credential)

    def route(self, route):
        # Abort an unexpected target before a product bug could reach it.
        if not self.allowed(route.request):
            route.abort()
            return
        route.continue_()

    def observe(self, request):
        # Request events also include page-level intercepted error fixtures.
        if not self.allowed(request):
            self.violations.append("unexpected origin, route, method or credential URL")
            return
        url = urlsplit(request.url)
        query = parse_qs(url.query)
        api = not url.path.startswith("/ui/")
        authorization = request.headers.get("authorization", "")
        if api and authorization != "Bearer " + self.token:
            self.violations.append("API request lacks synthetic bearer")
        if not api and authorization:
            self.violations.append("bearer attached to static shell")
        # Headers and credential values are deliberately never recorded.
        self.requests.append(
            {"method": request.method, "path": url.path, "query_keys": sorted(query)}
        )

    def attach(self, page):
        def console(message):
            if self.token in message.text:
                self.violations.append("credential in browser console")
            if message.type == "error":
                self.console_errors.append(message.text.replace(self.token, "[redacted]"))

        page.on("console", console)
        page.on(
            "pageerror",
            lambda error: self.page_errors.append(str(error).replace(self.token, "[redacted]")),
        )

    def count(self, path):
        return sum(row["path"] == path for row in self.requests)

    def verify(self, page, expected_network_errors=False):
        check(not self.violations, "; ".join(self.violations))
        check(not self.page_errors, "uncaught browser script error")
        errors = self.console_errors
        if expected_network_errors:
            errors = [x for x in errors if not x.startswith("Failed to load resource:")]
        check(not errors, "unexpected browser console error")
        check(self.token not in page.url, "credential retained in page URL")
        private = page.evaluate(
            """token => ({
          local: Object.values(localStorage).some(v => v.includes(token)),
          session: Object.values(sessionStorage).some(v => v.includes(token)),
          cookie: document.cookie.includes(token),
          injected: window.__guiInjected === 1,
        })""",
            self.token,
        )
        check(not any(private.values()), "storage, cookie or injected-script boundary failed")


class BrowserQA:
    def __init__(self, manifest, output, browser_executable=None):
        self.manifest = manifest
        self.url = manifest["url"]
        path = Path(manifest["token_file"])
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            check(
                stat.S_ISREG(info.st_mode)
                and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_nlink == 1
                and 0 < info.st_size <= 4096,
                "unsafe synthetic token file",
            )
            self.token = os.read(fd, 4097).decode("ascii").strip()
        finally:
            os.close(fd)
        check(
            self.token and all(33 <= ord(c) <= 126 for c in self.token), "invalid synthetic token"
        )
        self.output = output
        self.browser_executable = browser_executable
        self.results = []

    def connect(self, page):
        page.goto(self.url)
        expect(page.locator("#preview-banner")).to_be_visible()
        page.locator("#connect-collector").fill("synthetic-preview")
        page.locator("#token").fill(self.token)
        page.get_by_role("button", name="Connect", exact=True).click()
        page.locator("#content .health-strip").wait_for()
        check(page.locator("#token").input_value() == "", "token input retained secret")

    def view(self, page, name):
        page.locator(f'nav button[data-view="{name}"]').click()
        expect(page.locator("#content")).to_have_attribute("aria-busy", "false")

    def screenshot(self, page, name):
        page.screenshot(
            path=str(self.output / (name + ".png")),
            full_page=True,
            mask=[page.locator("#token")],
            animations="disabled",
        )

    def chart_labels(self, page):
        check(
            page.locator(".chart-meta").first.evaluate("""element => {
          const labels=[...element.children]; if(labels.length!==2) return false;
          const [a,b]=labels.map(x=>x.getBoundingClientRect());
          return b.left >= a.right + 4 || b.top >= a.bottom;
        }"""),
            "paired chart labels overlap or run together",
        )

    def case(self, browser, name, callback, viewport=None, network_errors=False):
        context = browser.new_context(
            viewport=viewport or {"width": 1440, "height": 1050},
            service_workers="block",
            reduced_motion="reduce",
        )
        audit = Audit(context, self.token)
        page = context.new_page()
        page.set_default_timeout(8000)
        audit.attach(page)
        try:
            callback(page, context, audit)
            audit.verify(page, network_errors)
            self.results.append({"case": name, "status": "pass", "requests": audit.requests})
        except (AssertionError, Error, OSError, ValueError, KeyError, TypeError) as error:
            try:
                self.screenshot(page, "failure-" + name)
            except Error:
                pass  # Preserve the primary failure if the renderer itself crashed.
            self.results.append(
                {
                    "case": name,
                    "status": "fail",
                    "error": str(error).replace(self.token, "[redacted]")[:3000],
                    "console_errors": audit.console_errors,
                    "page_errors": audit.page_errors,
                    "http_errors": audit.http_errors,
                    "requests": audit.requests,
                    "violations": audit.violations,
                }
            )
        finally:
            context.close()

    def journey(self, page, context, audit):
        self.connect(page)
        expect(page.locator("#content")).to_contain_text("Multicast discovery unavailable")
        expect(page.locator("#content")).to_contain_text("Historical quality")
        self.chart_labels(page)
        self.screenshot(page, "desktop-overview")
        self.view(page, "inventory")
        expect(page.locator("#scope-label")).to_contain_text("all stored sources")
        expect(page.locator("#content")).to_contain_text(self.manifest["attack_device_id"])
        expect(page.locator("#content")).to_contain_text("<img src=x")
        check(page.locator("#content img").count() == 0, "HTML name became an image")
        expect(page.locator("#content")).to_contain_text("192.0.2.1")
        expect(page.locator("#content")).to_contain_text("2001:db8::2")
        expect(page.locator("#content")).to_contain_text("unknown")
        check(page.locator("tbody tr").count() == 25, "actual API page limit not respected")
        self.screenshot(page, "desktop-inventory")
        page.get_by_role("button", name="Next", exact=True).click()
        expect(page.locator(".pager")).to_contain_text("Page 2")
        page.get_by_role("button", name="Previous", exact=True).click()
        expect(page.locator(".pager")).to_contain_text("Page 1")
        page.locator(".identity-button").filter(has_text=self.manifest["attack_device_id"]).click()
        expect(page.get_by_role("complementary", name="Identity detail")).to_be_visible()
        expect(page.locator("#content")).to_contain_text("synthetic-host-01")
        page.get_by_role("button", name="View activity", exact=True).click()
        expect(page.locator("#content")).to_contain_text("Learning")
        check(
            page.locator("svg.chart rect.gap").count() > 0, "missing activity was not drawn as gaps"
        )
        check(page.locator("svg.chart .baseline").count() == 0, "learning baseline drawn as mature")
        self.chart_labels(page)
        self.screenshot(page, "desktop-activity")
        page.get_by_text("Hourly observations and quality", exact=True).click()
        expect(page.locator("#content")).to_contain_text("Unavailable")
        self.view(page, "incidents")
        expect(page.locator("#content")).to_contain_text("does not establish normality")
        page.locator(".identity-button").filter(has_text=self.manifest["incident_id"]).click()
        expect(page.get_by_role("complementary", name="Incident evidence")).to_be_visible()
        expect(page.locator("#content")).to_contain_text("Unusual does not mean malicious")
        expect(page.locator("#content")).to_contain_text("3420s")
        self.screenshot(page, "desktop-incidents")
        page.locator("#disconnect").click()
        expect(page.locator("#connect-panel")).to_be_visible()
        check(page.locator("#content").inner_text() == "", "disconnect retained observations")
        check(page.locator("#token").input_value() == "", "disconnect retained input token")

    def mobile(self, page, context, audit):
        self.connect(page)
        check(
            page.evaluate("document.documentElement.scrollWidth <= innerWidth"),
            "mobile document overflows viewport",
        )
        self.screenshot(page, "mobile-overview")
        self.view(page, "inventory")
        check(
            page.evaluate("document.documentElement.scrollWidth <= innerWidth"),
            "mobile inventory overflows whole document",
        )
        self.screenshot(page, "mobile-inventory")
        region = page.get_by_role("region", name=re.compile(r"^Scrollable table:"))
        expect(region).to_have_attribute("tabindex", "0")
        region.focus()
        expect(region).to_be_focused()
        page.keyboard.press("ArrowRight")
        for _ in range(30):
            if region.evaluate("element => element.scrollLeft > 0"):
                break
            page.wait_for_timeout(50)
        check(
            region.evaluate("element => element.scrollLeft > 0"),
            "focused mobile table cannot scroll horizontally by keyboard",
        )
        self.screenshot(page, "mobile-inventory-keyboard-scroll")
        page.locator("#disconnect").click()
        page.locator("#connect-collector").focus()
        page.keyboard.press("Tab")
        expect(page.locator("#token")).to_be_focused()
        page.keyboard.press("Tab")
        expect(page.get_by_role("button", name="Connect", exact=True)).to_be_focused()

    def error_recovery(self, page, context, audit, status):
        self.connect(page)

        def fail(route):
            route.fulfill(
                status=status,
                json={
                    "ok": False,
                    "data": None,
                    "page": {},
                    "error": {"code": "synthetic_failure", "message": "synthetic"},
                },
            )

        page.route("**/coverage?*", fail, times=1)
        page.locator("#refresh").click()
        expect(page.locator("#notice")).to_be_visible()
        if status == 401:
            expect(page.locator("#connect-panel")).to_be_visible()
            check(page.locator("#content").inner_text() == "", "401 retained observations")
            check(page.locator("#token").input_value() == "", "401 retained input token")
            self.connect(page)
        else:
            expect(page.locator("#notice")).to_contain_text("previous snapshot")
            page.get_by_role("button", name="Retry", exact=True).click()
            expect(page.locator("#notice")).to_be_hidden()

    def malformed(self, page, context, audit):
        page.route(
            "**/coverage?*",
            lambda route: route.fulfill(status=200, content_type="application/json", body="{"),
            times=1,
        )
        page.goto(self.url)
        page.locator("#token").fill(self.token)
        page.get_by_role("button", name="Connect", exact=True).click()
        expect(page.locator("#notice")).to_be_visible()
        expect(page.locator("#content")).to_contain_text("Data unavailable")
        check(page.locator(".health-strip").count() == 0, "malformed data rendered current metrics")

    def unknown_coverage(self, page, context, audit):
        def unknown(route):
            response = route.fetch()
            payload = response.json()
            payload["data"]["collector"].update(
                {
                    "latest_observation_received_at": None,
                    "latest_window_end": None,
                    "latest_dns_observation_received_at": None,
                    "latest_dns_observation_window_end": None,
                    "source_flags_latest": None,
                    "backlog_batches": 1,
                    "backlog_capped": True,
                    "oldest_pending_received_at": None,
                    "summary_capped": True,
                }
            )
            route.fulfill(response=response, json=payload)

        page.route("**/coverage?*", unknown, times=1)
        self.connect(page)
        expect(page.locator("#content")).to_contain_text("Stale / unknown")
        expect(page.locator("#content")).to_contain_text("Capped or unknown")
        expect(page.locator(".health-strip")).not_to_contain_text("Drained")

    def retry_after(self, page, context, audit):
        page.clock.install()
        self.connect(page)
        calls = []

        def limited(route):
            calls.append(1)
            route.fulfill(
                status=429,
                headers={"Retry-After": "60"},
                json={
                    "ok": False,
                    "data": None,
                    "page": {},
                    "error": {"code": "rate_limited", "message": "synthetic"},
                },
            )

        page.route("**/coverage?*", limited, times=1)
        page.locator("#refresh").click()
        expect(page.locator("#notice")).to_contain_text("Request limit reached")
        before = audit.count("/coverage")
        page.clock.fast_forward(59000)
        check(audit.count("/coverage") == before, "Retry-After was bypassed")
        page.clock.fast_forward(2000)
        expect(page.locator("#notice")).to_be_hidden()
        check(
            len(calls) == 1 and audit.count("/coverage") == before + 1,
            "backoff did not recover with one request",
        )

    def offline(self, page, context, audit):
        self.connect(page)
        context.set_offline(True)
        page.locator("#refresh").click()
        expect(page.locator("#notice")).to_contain_text("previous snapshot")
        context.set_offline(False)
        page.get_by_role("button", name="Retry", exact=True).click()
        expect(page.locator("#notice")).to_be_hidden()

    def visibility(self, page, context, audit):
        page.clock.install()
        self.connect(page)
        # Exercise the application's visibility handler in a real browser without
        # freezing Chromium itself (which would mask an app polling bug).
        page.evaluate("""() => { window.__qaHidden = true;
          Object.defineProperty(document, 'hidden', {configurable:true,get:()=>window.__qaHidden});
          document.dispatchEvent(new Event('visibilitychange')); }""")
        before = audit.count("/coverage")
        page.clock.fast_forward(90000)
        check(audit.count("/coverage") == before, "hidden app continued polling")
        expect(page.locator("#refresh-status")).to_contain_text("paused")
        page.evaluate(
            "window.__qaHidden=false;document.dispatchEvent(new Event('visibilitychange'))"
        )
        expect(page.locator("#refresh-status")).not_to_contain_text("paused")
        expect(page.locator("#content")).to_have_attribute("aria-busy", "false")
        check(audit.count("/coverage") == before + 1, "visible app did not refresh once")

    def stale_and_paths(self, page, context, audit):
        self.connect(page)
        result = page.evaluate(
            """async token => {
          const {ApiClient, StaleResult} = await import('/ui/client.js');
          const original = window.fetch; const client = new ApiClient(); client.setToken(token);
          let resolve, calls=0;
          try {
            window.fetch = () => {calls++; return new Promise(r=>{resolve=r});};
            const pending = client.devices(); client.invalidate();
            resolve(new Response(
              JSON.stringify({ok:true,data:[],page:{next_cursor:null},error:null}),
              {status:200,headers:{'Content-Type':'application/json'}}));
            let stale=false; try {await pending} catch(e) {stale=e instanceof StaleResult}
            const before=calls; let rejected=0;
            for (const id of ['.','..','bad/id','bad\\\\id','\\u0000']) {
              try {await client.device(id)} catch(e) {if(e.code==='invalid_input') rejected++;}
            }
            return {stale,rejected,noExtraFetch:calls===before};
          } finally {window.fetch=original;client.disconnect();}
        }""",
            self.token,
        )
        check(
            result == {"stale": True, "rejected": 5, "noExtraFetch": True},
            "late old-generation result or dynamic path escaped the client boundary",
        )

    def stale_scope(self, page, context, audit):
        self.connect(page)
        self.view(page, "inventory")
        page.get_by_role("button", name="Next", exact=True).click()
        expect(page.locator(".pager")).to_contain_text("Page 2")
        page.locator("#range").select_option("168")
        page.get_by_role("button", name="Apply source & range", exact=True).click()
        expect(page.locator(".pager")).to_contain_text("Page 1")
        check(
            "cursor"
            not in [r for r in audit.requests if r["path"] == "/devices"][-1]["query_keys"],
            "scope change reused an old inventory cursor",
        )
        self.view(page, "overview")
        page.evaluate("""() => {
          window.__qaOriginalFetch=window.fetch; window.__qaHeld=false;
          window.fetch=(url,options)=>{
            if (!window.__qaHeld && new URL(url,location.origin).pathname==='/coverage') {
              window.__qaHeld=true;
              return new Promise(resolve=>{ window.__qaRelease=()=>resolve(new Response(
                JSON.stringify({ok:true,page:{next_cursor:null},error:null,
                  data:{hours:[],collector:{collector_id:'STALE_SCOPE_SENTINEL',last_seq:999999}}}),
                {status:200,headers:{'Content-Type':'application/json'}})); });
            }
            return window.__qaOriginalFetch(url,options);
          };
        }""")
        try:
            page.locator("#refresh").click()
            check(
                page.evaluate("() => window.__qaHeld === true"),
                "stale-response fixture did not hold the intended request",
            )
            page.locator("#range").select_option("24")
            page.get_by_role("button", name="Apply source & range", exact=True).click()
            page.locator("#content .health-strip").wait_for()
            expect(page.locator("#scope-label")).to_contain_text("Last 24 hours")
            page.evaluate("window.__qaRelease()")
            page.evaluate("() => new Promise(resolve=>setTimeout(resolve,25))")
            expect(page.locator("#content")).not_to_contain_text("STALE_SCOPE_SENTINEL")
            expect(page.locator("#content")).not_to_contain_text("999999")
        finally:
            page.evaluate("() => { window.fetch=window.__qaOriginalFetch; }")

    def run(self):
        # Host/container fontconfig caches can use incompatible cache formats.
        # Isolate only this QA browser's font cache; never touch the user's cache.
        font_cache = self.output / "font-cache"
        font_cache.mkdir(mode=0o700)
        font_config = self.output / "fontconfig.conf"
        font_config.write_text(
            "<?xml version='1.0'?><fontconfig>"
            "<dir>/usr/share/fonts</dir><cachedir>"
            + escape(str(font_cache))
            + "</cachedir></fontconfig>"
        )
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                headless=True,
                executable_path=str(self.browser_executable) if self.browser_executable else None,
                env={
                    **os.environ,
                    "FONTCONFIG_FILE": str(font_config),
                    "FONTCONFIG_PATH": "/etc/fonts",
                },
            )
            version = browser.version
            try:
                self.case(browser, "real-api-journey", self.journey)
                self.case(
                    browser, "mobile-keyboard", self.mobile, viewport={"width": 390, "height": 844}
                )
                for status in (401, 503):
                    self.case(
                        browser,
                        str(status) + "-recovery",
                        lambda p, c, a, s=status: self.error_recovery(p, c, a, s),
                        network_errors=True,
                    )
                self.case(browser, "malformed", self.malformed)
                self.case(browser, "null-capped-coverage", self.unknown_coverage)
                self.case(browser, "retry-after", self.retry_after, network_errors=True)
                self.case(browser, "offline-recovery", self.offline, network_errors=True)
                self.case(browser, "hidden-polling", self.visibility)
                self.case(browser, "stale-generation-paths", self.stale_and_paths)
                self.case(browser, "stale-scope-cursor-reset", self.stale_scope)
            except Error as error:
                self.results.append(
                    {
                        "case": "browser-runtime",
                        "status": "fail",
                        "error": str(error).replace(self.token, "[redacted]")[:3000],
                    }
                )
            finally:
                browser.close()
        report = {
            "browser": version,
            "playwright": importlib.metadata.version("playwright"),
            "origin": "http://127.0.0.1:18745",
            "synthetic_only": True,
            "cases": self.results,
        }
        (self.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        passed = sum(x["status"] == "pass" for x in self.results)
        print(
            json.dumps(
                {
                    "passed": passed,
                    "failed": len(self.results) - passed,
                    "artifacts": str(self.output),
                    "browser": version,
                }
            )
        )
        return 0 if passed == len(self.results) else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--browser-executable",
        type=Path,
        help="optional already-installed Chromium executable; never downloads",
    )
    args = parser.parse_args()
    root = args.manifest.parent
    check(
        root.parent == PREVIEW_TMP
        and root.name.startswith("vigie-gui-preview-")
        and root.resolve() == root,
        "only an isolated synthetic preview is allowed",
    )
    manifest = private_json(args.manifest)
    check(
        manifest.get("synthetic") is True
        and manifest.get("collector_id") == "synthetic-preview"
        and manifest.get("url") == "http://127.0.0.1:18745/ui/?preview=synthetic"
        and Path(manifest["token_file"]).parent == root,
        "unexpected synthetic manifest",
    )
    check(
        args.output.parent == PREVIEW_TMP and args.output.name.startswith("vigie-gui-qa-"),
        "QA artifacts need a fresh direct /tmp/vigie-gui-qa-* directory",
    )
    os.umask(0o077)
    args.output.mkdir(mode=0o700)
    return BrowserQA(manifest, args.output, args.browser_executable).run()


if __name__ == "__main__":
    raise SystemExit(main())
