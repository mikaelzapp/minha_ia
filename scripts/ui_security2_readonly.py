"""Read-only actual-server Chromium check. Never approves, downloads or runs scanners."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"
CHROME = Path(os.environ.get("LOCALAPPDATA", "")) / "ms-playwright/chromium-1228/chrome-win64/chrome.exe"


def main():
    result = {"fixture": False, "read_only": True, "timestamp": datetime.now(timezone.utc).isoformat(),
              "tests": {}, "page_errors": [], "console_errors": [], "http_errors": [], "external_requests": [], "blocked_mutations": []}
    with tempfile.TemporaryDirectory(prefix="security2-ui-live-", dir=REPORTS) as profile:
        with sync_playwright() as p:
            context = p.chromium.launch_persistent_context(profile, executable_path=str(CHROME), headless=True,
                viewport={"width": 1440, "height": 1000}, args=["--disable-background-networking", "--disable-component-update", "--disable-sync", "--no-first-run"])
            def readonly(route):
                request = route.request
                parsed = urlsplit(request.url)
                if parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
                    result["external_requests"].append(request.url)
                    return route.abort()
                if request.method not in {"GET", "HEAD"} and not (request.method == "POST" and parsed.path == "/api/workspace-modes/compatibility"):
                    result["blocked_mutations"].append(parsed.path)
                    return route.abort()
                route.continue_()
            context.route("**/*", readonly)
            page = context.pages[0]
            page.set_default_timeout(40000)
            page.on("pageerror", lambda error: result["page_errors"].append(str(error)))
            page.on("console", lambda item: result["console_errors"].append(item.text) if item.type == "error" else None)
            page.on("response", lambda response: result["http_errors"].append({"url": response.url, "status": response.status}) if response.status >= 400 else None)
            try:
                page.goto("http://127.0.0.1:8765", wait_until="networkidle")
                page.locator("#nav-security").click()
                with page.expect_response(lambda response: response.url.endswith("/api/security/v2/status")) as response:
                    page.locator("#security2-open").click()
                inventory = response.value.json()
                expect(page.locator("#security2-dialog")).to_be_visible()
                expect(page.locator(".sec2-grid .sec2-card")).to_have_count(10)
                result["tests"]["real_inventory_and_ten_modules"] = {"status": "passed", "engines": inventory["integrated_engines"], "external_tool_configured": {row["id"]: row["configured"] for row in inventory["scanners"]["tools"]}, "ghidra_available": inventory["ghidra"]["available"]}
                page.screenshot(path=str(REPORTS / "security2-ui-live-desktop.png"), full_page=True)
                for tab in ("targets", "tools", "web", "network", "auth", "code", "malware", "reverse", "osint", "blue", "reports", "remediation", "jobs"):
                    page.locator(f'[data-sec2-tab="{tab}"]').click()
                    expect(page.locator("#sec2-content h3").first).to_be_visible()
                result["tests"]["all_module_forms_readonly"] = {"status": "passed", "forms_submitted": 0}
                page.locator('[data-sec2-tab="tools"]').click()
                expect(page.locator("#sec2-installation")).to_contain_text("Nuclei portátil")
                if not inventory.get("installation", {}).get("installed"):
                    expect(page.locator("#sec2-install-nuclei")).to_be_visible()
                result["tests"]["optional_installer_visible_no_download"] = {"status": "passed", "clicked": False}
                page.locator('[data-sec2-tab="auth"]').click()
                page.locator("#sec2-engine").select_option("appsec_auth")
                expect(page.locator("#sec2-target")).to_have_value("http://127.0.0.1:8899/")
                expect(page.locator("#sec2-profile option")).to_have_count(3)
                expect(page.locator("#sec2-synthetic")).to_be_visible()
                result["tests"]["auth_fictitious_data_controls"] = "passed"
                page.locator('[data-sec2-tab="reports"]').click()
                open_buttons = page.locator("#sec2-report-list").get_by_role("button", name="Abrir relatório", exact=True)
                if open_buttons.count():
                    open_buttons.first.click()
                    expect(page.locator("#sec2-report-detail")).to_contain_text("Relatório selecionado")
                    expected = 4 if inventory.get("export_formats", {}).get("pdf") else 3
                    expect(page.locator("#sec2-report-detail a[download]")).to_have_count(expected)
                    result["tests"]["actual_report_and_available_exports"] = {"status": "passed", "formats": expected, "exports_downloaded": 0}
                else:
                    result["tests"]["actual_report_and_available_exports"] = {"status": "not_run", "reason": "No saved report available."}
                page.locator('[data-sec2-tab="remediation"]').click()
                expect(page.locator("#sec2-rem-path")).to_have_value("settings.json")
                expect(page.locator("#sec2-content")).to_contain_text("3.500 caracteres")
                result["tests"]["coder_and_remediation_forms_no_inference_or_write"] = "passed"
                for width in (390, 320):
                    page.set_viewport_size({"width": width, "height": 844})
                    page.locator('[data-sec2-tab="dashboard"]').click()
                    assert not page.evaluate("document.documentElement.scrollWidth > innerWidth")
                    assert not page.locator("#security2-dialog").evaluate("el=>el.scrollWidth>el.clientWidth")
                    assert not page.locator(".sec2-body").evaluate("el=>el.scrollWidth>el.clientWidth")
                    result["tests"][f"mobile_{width}"] = "passed"
                    if width == 390:
                        page.screenshot(path=str(REPORTS / "security2-ui-live-mobile.png"), full_page=True)
                page.get_by_role("button", name="Painel anterior", exact=True).click()
                expect(page.locator("#security-dialog")).to_be_visible()
                assert not page.locator("#security-dialog").evaluate("el=>el.scrollWidth>el.clientWidth")
                page.locator("#security-close").click()
                expect(page.locator("#model-select")).to_be_visible()
                result["tests"]["old_security_and_chat_preserved"] = "passed"
                assert not result["page_errors"] and not result["console_errors"] and not result["http_errors"]
                assert not result["external_requests"] and not result["blocked_mutations"]
                result["status"] = "passed"
            except Exception as exc:
                result["status"] = "failed"
                result["page_errors"].append(str(exc))
                page.screenshot(path=str(REPORTS / "security2-ui-live-error.png"), full_page=True)
            finally:
                context.close()
    (REPORTS / "security2-ui-live.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"status": result["status"], "tests": len(result["tests"]), "errors": result["page_errors"]}, ensure_ascii=False))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
