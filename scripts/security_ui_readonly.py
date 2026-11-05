"""Read-only browser smoke of the running local Security Center; never submits forms."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"
URL = "http://127.0.0.1:8765"
CHROME = Path(os.environ.get("LOCALAPPDATA", "")) / "ms-playwright/chromium-1228/chrome-win64/chrome.exe"


def main() -> int:
    REPORTS.mkdir(exist_ok=True)
    report = {"timestamp": datetime.now(timezone.utc).isoformat(), "fixture": False, "read_only": True,
              "tests": {}, "page_errors": [], "console_errors": [], "external_requests": [], "blocked_mutations": []}
    requests = []
    with tempfile.TemporaryDirectory(prefix="security-live-ui-", dir=REPORTS) as profile:
        with sync_playwright() as p:
            context = p.chromium.launch_persistent_context(profile, executable_path=str(CHROME), headless=True,
                viewport={"width": 1440, "height": 1000}, args=["--disable-background-networking", "--disable-component-update", "--disable-sync", "--no-first-run"])

            def readonly(route):
                req = route.request; parsed = urlsplit(req.url)
                if parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
                    report["external_requests"].append(req.url); route.abort(); return
                requests.append({"path": parsed.path, "method": req.method})
                if req.method not in {"GET", "HEAD"}:
                    report["blocked_mutations"].append({"path": parsed.path, "method": req.method}); route.abort(); return
                route.continue_()

            context.route("**/*", readonly)
            page = context.pages[0]; page.set_default_timeout(90000)
            page.on("pageerror", lambda error: report["page_errors"].append(str(error)))
            page.on("console", lambda message: report["console_errors"].append(message.text) if message.type == "error" else None)
            try:
                page.goto(URL, wait_until="networkidle")
                expect(page.locator("#model-select")).not_to_have_value("")
                with page.expect_response(lambda response: response.url.endswith("/api/security/status")) as response:
                    page.locator("#nav-security").click()
                inventory = response.value.json()
                assert response.value.status == 200
                expect(page.locator("#security-load-status")).to_contain_text("atualizado")
                assert len(inventory["agents"]) == 6
                expect(page.locator(".security-stat")).to_have_count(4)
                report["tests"]["inventory"] = {"status": "passed", "security_agents": len(inventory["agents"]), "capability_cards": page.locator(".security-capability").count(),
                    "rea_available": inventory["capabilities"]["rea"]["available"], "dynamic_available": inventory["capabilities"]["dynamic_analysis"]["available"], "virustotal_available": inventory["capabilities"]["virustotal"]["available"]}
                page.screenshot(path=str(REPORTS / "security-center-live-desktop.png"), full_page=True)
                page.locator('[data-security-tab="agents"]').click()
                for name in ("RED TEAM", "OSINT", "REA", "MALWARE LAB", "BLUE TEAM", "CODE AUDITOR"):
                    expect(page.locator(".security-agent-card h4").filter(has_text=f"NEXUS {name}")).to_have_count(1)
                assert page.locator("#security-model option").count() >= 1
                report["tests"]["agents_and_models"] = {"status": "passed", "cards": page.locator(".security-agent-card").count(), "model_options": page.locator("#security-model option").count()}
                for tab in ("scopes", "network", "osint", "files", "code", "windows", "reports"):
                    page.locator(f'[data-security-tab="{tab}"]').click()
                    expect(page.locator(f"#security-{tab}")).to_be_visible()
                report["tests"]["all_forms_readonly"] = {"status": "passed", "forms_submitted": 0}
                for width in (390, 320):
                    page.set_viewport_size({"width": width, "height": 844})
                    page.locator('[data-security-tab="overview"]').click()
                    assert not page.locator("#security-dialog").evaluate("el => el.scrollWidth > el.clientWidth")
                    assert not page.locator("#security-content").evaluate("el => el.scrollWidth > el.clientWidth")
                    assert not page.evaluate("document.documentElement.scrollWidth > innerWidth")
                    if width == 390: page.screenshot(path=str(REPORTS / "security-center-live-mobile.png"), full_page=True)
                    report["tests"][f"mobile_{width}"] = {"status": "passed", "horizontal_overflow": False}
                page.locator("#security-close").click()
                assert not report["page_errors"], report["page_errors"]
                assert not report["console_errors"], report["console_errors"]
                assert not report["blocked_mutations"], report["blocked_mutations"]
                assert not report["external_requests"], report["external_requests"]
                assert not any(req["path"] == "/api/chat" for req in requests)
                report["status"] = "passed"
            except Exception as error:
                report["status"] = "failed"; report["error"] = f"{type(error).__name__}: {error}"
                page.screenshot(path=str(REPORTS / "security-center-live-failure.png"), full_page=True)
            finally:
                report["requests"] = requests; context.close()
    (REPORTS / "security-ui-live.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"status": report["status"], "tests": report["tests"], "error": report.get("error"), "report": "reports/security-ui-live.json"}, ensure_ascii=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
