"""Read-only smoke of the actual local server. No download, model load or form submission."""
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
CHROME = Path(os.environ.get("LOCALAPPDATA", "")) / "ms-playwright/chromium-1228/chrome-win64/chrome.exe"
URL = "http://127.0.0.1:8765"


def main() -> int:
    report = {"fixture": False, "read_only": True, "timestamp": datetime.now(timezone.utc).isoformat(), "tests": {}, "page_errors": [], "console_errors": [], "external_requests": [], "blocked_mutations": [], "http_errors": []}
    requests = []
    with tempfile.TemporaryDirectory(prefix="multimodal-live-", dir=REPORTS) as profile:
        with sync_playwright() as p:
            context = p.chromium.launch_persistent_context(profile, executable_path=str(CHROME), headless=True, viewport={"width": 1440, "height": 1000}, args=["--disable-background-networking", "--disable-component-update", "--disable-sync", "--no-first-run"])
            def readonly(route):
                request = route.request; parsed = urlsplit(request.url)
                if parsed.hostname not in {"127.0.0.1", "localhost", "::1"}: report["external_requests"].append(request.url); route.abort(); return
                requests.append({"path": parsed.path, "method": request.method})
                if request.method not in {"GET", "HEAD"} and not (request.method == "POST" and parsed.path == "/api/workspace-modes/compatibility"):
                    report["blocked_mutations"].append({"path": parsed.path, "method": request.method}); route.abort(); return
                route.continue_()
            context.route("**/*", readonly); page = context.pages[0]; page.set_default_timeout(90000)
            page.on("pageerror", lambda error: report["page_errors"].append(str(error)))
            page.on("console", lambda message: report["console_errors"].append(message.text) if message.type == "error" else None)
            page.on("response", lambda response: report["http_errors"].append({"url": response.url, "status": response.status}) if response.status >= 400 else None)
            try:
                page.goto(URL, wait_until="networkidle")
                expect(page.locator("#workspace-mode-select option")).to_have_count(6)
                expect(page.locator("#model-select")).not_to_have_value("")
                selected = page.locator("#model-select").input_value()
                for identity in ("chat", "search", "tor", "pentest", "developer", "security"):
                    page.locator(f'[data-workspace-mode="{identity}"]').click()
                    expect(page.locator("#workspace-mode-select")).to_have_value(identity)
                    expect(page.locator("#model-select")).to_have_value(selected)
                    expect(page.locator("#workspace-compatibility")).not_to_have_text("Verificando modelo…")
                report["tests"]["six_modes_real_compatibility"] = {"status": "passed", "selected_model_preserved": selected}
                page.locator('[data-workspace-mode="developer"]').click(); page.get_by_role("button", name="Histórico e reversão de arquivos").click()
                expect(page.locator(".developer-history")).to_contain_text("Alterações aprovadas")
                report["tests"]["developer_history_readonly"] = {"status": "passed", "reversions": 0}
                with page.expect_response(lambda response: response.url.endswith("/api/library/models")) as response: page.locator("#nav-ai-library").click()
                inventory = response.value.json(); count = len(inventory["models"])
                expect(page.locator(".library-model-grid .library-card")).to_have_count(count)
                assert inventory["connected"]
                report["tests"]["ollama_library_real_inventory"] = {"status": "passed", "models": [model["name"] for model in inventory["models"]], "loaded": [model["name"] for model in inventory["models"] if model.get("loaded")]}
                page.screenshot(path=str(REPORTS / "multimodal-library-live-desktop.png"), full_page=True)
                for tab in ("add", "import", "variant", "jobs", "installed"):
                    page.locator(f'[data-tab="{tab}"]').click()
                report["tests"]["all_model_forms_without_submission"] = {"status": "passed", "jobs_created": 0, "downloads": 0, "uploads": 0}
                page.locator("#library-close").click()
                with page.expect_response(lambda response: response.url.endswith("/api/library/agents")) as response: page.locator("#nav-agent-library").click()
                agents = response.value.json()["agents"]; expect(page.locator(".library-agent-grid .library-card")).to_have_count(len(agents))
                builtins = [agent for agent in agents if agent.get("builtin")]
                assert builtins
                page.locator(".library-agent-grid .library-card").filter(has=page.locator("h4", has_text=builtins[0]["name"])).get_by_role("button", name="Ver configuração").click()
                expect(page.locator("#library-agent-name")).to_be_disabled()
                report["tests"]["agent_library_real_registry"] = {"status": "passed", "agents": len(agents), "builtins": len(builtins), "builtin_readonly": True}
                for width in (390, 320):
                    page.set_viewport_size({"width": width, "height": 844})
                    assert not page.evaluate("document.documentElement.scrollWidth > innerWidth")
                    assert not page.locator("#library-dialog").evaluate("el=>el.scrollWidth > el.clientWidth")
                    assert not page.locator(".library-body").evaluate("el=>el.scrollWidth > el.clientWidth")
                    report["tests"][f"mobile_library_{width}"] = {"status": "passed", "horizontal_overflow": False}
                    if width == 390: page.screenshot(path=str(REPORTS / "multimodal-agent-live-mobile.png"), full_page=True)
                page.locator("#library-close").click(); page.locator("#sidebar-toggle").click(); page.locator('[data-workspace-mode="search"]').click()
                assert "is-open" not in page.locator("#sidebar").get_attribute("class")
                assert not page.evaluate("document.documentElement.scrollWidth > innerWidth")
                report["tests"]["mobile_navigation_real"] = {"status": "passed"}
                page.set_viewport_size({"width": 1440, "height": 1000}); page.locator("#nav-security").click()
                expect(page.locator("#security-load-status")).to_contain_text("atualizado")
                for tab in ("overview", "agents", "scopes", "network", "osint", "files", "code", "windows", "reports"):
                    page.locator(f'[data-security-tab="{tab}"]').click(); expect(page.locator(f"#security-{tab}")).to_be_visible()
                page.locator('[data-security-tab="agents"]').click()
                page.locator(".security-agent-card").filter(has=page.locator("h4", has_text="NEXUS MALWARE LAB")).get_by_role("button", name="Usar agente no chat").click()
                expect(page.locator("#workspace-mode-select")).to_have_value("security"); expect(page.locator("#mode-select")).to_have_value("REVIEW"); expect(page.locator("#agent-select")).to_have_value("malware_lab")
                report["tests"]["security_center_preserved_and_agent_integration"] = {"status": "passed", "panels": 9, "forms_submitted": 0}
                with page.expect_response(lambda response: "/api/research/reports" in response.url) as response: page.locator("#nav-reports").click()
                research = response.value.json(); expect(page.locator("#research-report-list")).to_be_visible()
                expect(page.locator("#research-report-list")).not_to_contain_text("Consultando relatórios")
                report["tests"]["research_reports_real_registry"] = {"status": "passed", "reports": len(research["reports"]), "exports_requested": 0}
                assert not report["page_errors"], report["page_errors"]
                assert not report["console_errors"], report["console_errors"]
                assert not report["http_errors"], report["http_errors"]
                assert not report["external_requests"], report["external_requests"]
                assert not report["blocked_mutations"], report["blocked_mutations"]
                report["status"] = "passed"
            except Exception as error:
                report["status"] = "failed"; report["error"] = f"{type(error).__name__}: {error}"; page.screenshot(path=str(REPORTS / "multimodal-ui-live-failure.png"), full_page=True)
            finally: report["requests"] = requests; context.close()
    (REPORTS / "multimodal-ui-live.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"status": report["status"], "tests": report["tests"], "error": report.get("error"), "report": "reports/multimodal-ui-live.json"}, ensure_ascii=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
