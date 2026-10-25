#!/usr/bin/env python3
"""Focused synthetic-only focus, polling-race and incomplete-coverage regressions.

The optional source overlay tests assets before the separately owned preview
wheel is rebuilt. Reports identify that mode; it is not installed-wheel proof.
Uses the existing Playwright/browser and private font cache, installs nothing.
"""
from __future__ import annotations

import argparse
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit
from xml.sax.saxutils import escape

from browser_qa import BrowserQA, check, private_json
from playwright.sync_api import expect, sync_playwright


class HardeningQA(BrowserQA):
    def prepare(self, page):
        if self.source_assets is None:
            return
        assets = {"/ui/": "index.html", **{
            "/ui/" + name: name for name in
            ("index.html", "styles.css", "app.js", "client.js", "views.js")
        }}

        def asset(route):
            name = assets.get(urlsplit(route.request.url).path)
            if name is None:
                route.continue_()
                return
            kind = "text/html" if name.endswith(".html") else (
                "text/css" if name.endswith(".css") else "text/javascript")
            response = route.fetch()
            route.fulfill(response=response, content_type=kind,
                          body=(self.source_assets / name).read_bytes())
        page.route("**/ui/**", asset)

    def focus_lifecycle(self, page, context, audit):
        self.prepare(page)
        self.connect(page)
        expect(page.locator("#view-title")).to_be_focused()
        expect(page.locator("#refresh-status")).not_to_contain_text("paused")
        self.view(page, "inventory")
        expect(page.locator("#view-title")).to_be_focused()
        page.locator("#content .identity-button").first.click()
        expect(page.get_by_role("complementary", name="Identity detail")).to_be_focused()
        page.get_by_role("button", name="View activity", exact=True).click()
        expect(page.locator(".chart")).to_be_visible()
        expect(page.locator("#view-title")).to_be_focused()
        self.view(page, "incidents")
        page.locator("#content .identity-button").first.click()
        expect(page.get_by_role("complementary", name="Incident evidence")).to_be_focused()
        page.locator("#disconnect").click()
        expect(page.locator("#token")).to_be_focused()
        check(not page.locator("#content").inner_text(), "disconnect retained observations")

    def header_focus_during_request(self, page, context, audit):
        self.prepare(page)
        self.connect(page)
        page.evaluate("""() => {
          window.__originalFetch=window.fetch;
          window.fetch=(url,options)=> window.__originalFetch(url,options).then(response=> {
            if (new URL(url,location.origin).pathname!=='/coverage') return response;
            return new Promise(resolve=> {window.__release=()=>resolve(response)});
          });
        }""")
        try:
            page.locator("nav button[data-view=overview]").click()
            page.wait_for_function("() => typeof window.__release==='function'")
            page.locator("#collector").focus()
            page.evaluate("() => window.__release()")
            expect(page.locator("#content")).to_have_attribute("aria-busy", "false")
            expect(page.locator("#collector")).to_be_focused()
            expect(page.locator("#refresh-status")).not_to_contain_text("paused")
        finally:
            page.evaluate("() => {window.fetch=window.__originalFetch}")

    def interaction_polling(self, page, context, audit):
        self.prepare(page)
        now = datetime.now(UTC).replace(minute=10, second=0, microsecond=0)
        page.clock.install(time=now)
        self.connect(page)
        self.view(page, "inventory")
        region = page.get_by_role("region", name="Scrollable table: Inventory identity, Type, "
                                  "Status, Last observed IP, Last seen · UTC")
        region.focus()
        expect(page.locator("#refresh-status")).to_contain_text("paused while interacting")
        before = audit.count("/devices")
        page.clock.fast_forward(61000)
        expect(region).to_be_focused()
        check(audit.count("/devices") == before, "automatic polling ignored active reading")
        page.evaluate("""() => {
          Object.defineProperty(document,'hidden',{configurable:true,get:()=>true});
          document.dispatchEvent(new Event('visibilitychange'));
          Object.defineProperty(document,'hidden',{configurable:true,get:()=>false});
          document.dispatchEvent(new Event('visibilitychange'));
        }""")
        expect(region).to_be_focused()
        check(audit.count("/devices") == before, "visibility resume replaced active reading")
        # Explicit refresh remains available and retains the header button focus.
        page.locator("#refresh").click()
        expect(page.locator("#content")).to_have_attribute("aria-busy", "false")
        expect(page.locator("#refresh")).to_be_focused()
        check(audit.count("/devices") == before + 1, "explicit refresh was blocked")
        snapshot = page.locator("#refresh-status").inner_text().split("Updated ", 1)[1]
        snapshot = snapshot.split(" · refresh", 1)[0]
        page.evaluate("""() => {
          window.__originalFetch=window.fetch; window.__held=false;
          window.fetch=(url,options)=> {
            if (!window.__held && new URL(url,location.origin).pathname==='/devices') {
              window.__held=true;
              return window.__originalFetch(url,options).then(async response=> {
                const value=await response.json(); value.page.next_cursor='WRONG_CURSOR_SENTINEL';
                return new Promise(resolve=> {window.__release=()=>resolve(new Response(
                  JSON.stringify(value),{status:200,headers:{'Content-Type':'application/json'}}));});
              });
            }
            return window.__originalFetch(url,options);
          };
        }""")
        try:
            page.clock.fast_forward(31000)
            page.wait_for_function("() => typeof window.__release==='function'")
            region.focus()
            region.evaluate("element => {window.__focusedRegion=element}")
            page.evaluate("() => window.__release()")
            expect(page.locator("#content")).to_have_attribute("aria-busy", "false")
            check(page.evaluate("() => window.__focusedRegion.isConnected"),
                  "pending automatic response replaced focused observations")
            expect(region).to_be_focused()
            expect(page.locator("#refresh-status")).to_contain_text("snapshot " + snapshot)
        finally:
            page.evaluate("() => {window.fetch=window.__originalFetch}")
        # The discarded response's sentinel cursor must never overwrite page state.
        page.get_by_role("button", name="Next", exact=True).click()
        expect(page.locator(".pager")).to_contain_text("Page 2")
        expect(page.locator("#notice")).to_be_hidden()
        expect(page.locator("#view-title")).to_be_focused()
        before = audit.count("/devices")
        page.clock.fast_forward(31000)
        expect(page.locator("#content")).to_have_attribute("aria-busy", "false")
        check(audit.count("/devices") == before + 1, "polling did not resume after reading")

    def hidden_scope_change(self, page, context, audit):
        self.prepare(page)
        self.connect(page)
        page.locator(".table-wrap").first.focus()
        before = audit.count("/coverage")
        page.evaluate("""() => {
          Object.defineProperty(document,'hidden',{configurable:true,get:()=>true});
          document.dispatchEvent(new Event('visibilitychange'));
          document.querySelector('#collector').value='missing-synthetic-source';
          document.querySelector('#range').value='168';
          document.querySelector('#scope-form').requestSubmit();
        }""")
        check(not page.locator(".health-strip").count(), "hidden source change retained old data")
        check(audit.count("/coverage") == before, "hidden scope change made a request")
        page.evaluate("""() => {
          Object.defineProperty(document,'hidden',{configurable:true,get:()=>false});
          document.dispatchEvent(new Event('visibilitychange'));
        }""")
        expect(page.locator("#notice")).to_contain_text("not found")
        expect(page.locator("#scope-label")).to_contain_text("missing-synthetic-source")
        check(not page.locator(".health-strip").count(), "old source appeared under new labels")
        page.locator("#collector").fill("synthetic-preview")
        page.get_by_role("button", name="Apply source & range", exact=True).click()
        expect(page.locator(".hour")).to_have_count(168)
        self.view(page, "inventory")
        page.locator(".table-wrap").first.focus()
        page.evaluate("""() => {
          Object.defineProperty(document,'hidden',{configurable:true,get:()=>true});
          document.dispatchEvent(new Event('visibilitychange'));
          document.querySelector('nav button[data-view=activity]').click();
        }""")
        check(not page.locator(".data-table").count(), "hidden view change retained inventory")
        page.evaluate("""() => {
          Object.defineProperty(document,'hidden',{configurable:true,get:()=>false});
          document.dispatchEvent(new Event('visibilitychange'));
        }""")
        expect(page.locator("#content")).to_contain_text("Choose an identity to inspect")
        expect(page.locator("#view-title")).to_have_text("Activity")

    def incomplete_coverage(self, page, context, audit):
        self.prepare(page)
        page.route("**/coverage?*", lambda route: route.fulfill(status=200, json={
            "ok": True, "page": {"next_cursor": None}, "error": None,
            "data": {"collector": {"collector_id": "synthetic-preview"}, "hours": []},
        }))
        page.goto(self.url)
        page.locator("#token").fill(self.token)
        page.get_by_role("button", name="Connect", exact=True).click()
        expect(page.locator("#notice")).to_be_visible()
        check(not page.locator(".health-strip").count(), "incomplete range rendered metrics")
        expect(page.locator("#content")).not_to_contain_text("All displayed hours qualified")
        direct = page.evaluate("""async () => {
          const {coverageView}=await import('/ui/views.js');
          return coverageView({collector:{},hours:[]}).textContent;
        }""")
        check("Coverage unavailable" in direct and "All displayed hours qualified" not in direct,
              "empty direct coverage view still made a quality claim")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--browser-executable", type=Path, required=True)
    parser.add_argument("--source-assets", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    manifest = private_json(args.manifest)
    check(manifest.get("synthetic") is True and manifest.get("collector_id") == "synthetic-preview"
          and manifest.get("url") == "http://127.0.0.1:18745/ui/?preview=synthetic"
          and Path(manifest["token_file"]).parent == args.manifest.parent,
          "unexpected synthetic manifest")
    args.output.mkdir(mode=0o700)
    cache = args.output / "font-cache"
    cache.mkdir(mode=0o700)
    config = args.output / "fontconfig.conf"
    config.write_text("<?xml version='1.0'?><fontconfig><dir>/usr/share/fonts</dir><cachedir>"
                      + escape(str(cache)) + "</cachedir></fontconfig>")
    qa = HardeningQA(manifest, args.output, args.browser_executable)
    qa.source_assets = args.source_assets
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, executable_path=str(args.browser_executable),
            env={**os.environ, "FONTCONFIG_FILE": str(config), "FONTCONFIG_PATH": "/etc/fonts"})
        try:
            for name in ("focus_lifecycle", "header_focus_during_request",
                         "interaction_polling", "hidden_scope_change", "incomplete_coverage"):
                qa.case(browser, name, getattr(qa, name),
                        network_errors=name == "hidden_scope_change")
        finally:
            browser.close()
    report = {"source_overlay": args.source_assets is not None, "cases": qa.results}
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    passed = sum(case["status"] == "pass" for case in qa.results)
    print(json.dumps({"passed": passed, "failed": len(qa.results)-passed,
                      "source_overlay": report["source_overlay"], "artifacts": str(args.output)}))
    return 0 if passed == len(qa.results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
