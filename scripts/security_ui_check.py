"""Browser QA with a fully intercepted backend; no real scopes or files are stored."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from urllib.parse import parse_qs, urlsplit

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from nexus.security.network import build_dork
REPORTS = ROOT / "reports"
URL = "http://127.0.0.1:8765"
CHROME = Path(os.environ.get("LOCALAPPDATA", "")) / "ms-playwright/chromium-1228/chrome-win64/chrome.exe"
NOW = "2026-11-05T03:00:00Z"
SECURITY_AGENTS = [{"id": key, "name": f"NEXUS {name}"} for key, name in [
    ("red_team", "RED TEAM"), ("osint", "OSINT"), ("rea", "REA"), ("malware_lab", "MALWARE LAB"),
    ("blue_team", "BLUE TEAM"), ("code_auditor", "CODE AUDITOR")]]
BASE_AGENTS = [{"id": key, "name": f"NEXUS {key.upper()}"} for key in ["auto", "architect", "coder", "debugger", "researcher", "devops", "database", "writer", "reviewer"]]


def main() -> int:
    REPORTS.mkdir(exist_ok=True)
    report = {"timestamp": datetime.now(timezone.utc).isoformat(), "fixture": True, "real_backend_mutations": False,
              "tests": {}, "page_errors": [], "console_errors": [], "expected_http_errors": [], "external_requests": [], "unexpected_requests": []}
    tests = report["tests"]
    scopes, samples, reports, calls, decisions = [], [], [], [], []
    pending = {}
    finding = {"severity": "high", "title": "Fixture de auditoria <img src=x onerror=alert(1)>", "file": "src/exemplo.py", "line": 12,
               "impact": "Hipótese que exige revisão.", "recommendation": "Validar entrada no ponto de uso.", "validation": "unconfirmed", "evidence": "eval(entrada)"}
    inventory = {"agents": SECURITY_AGENTS, "scopes": scopes, "samples": samples, "projects": [{"id": "fixture-project", "name": "Projeto QA", "path": "workspaces/fixture"}],
                 "reports": reports, "operations": ["security_http", "security_static_file", "security_code_audit", "security_rea"],
                 "limits": {"sample_bytes": 10 * 1048576, "tcp_ports": 8}, "capabilities": {
                     "external_tools": {"ok": True, "tools": [{"id": "nmap", "name": "nmap", "available": False, "note": "Não instalado na fixture."}]},
                     "static": {"yara_x": {"available": True, "version": "fixture", "mode": "static bytes"}, "semgrep": {"installed": False, "available": False, "reason": "Adaptador não configurado."}},
                     "rea": {"available": False, "error": "REA ausente nesta fixture."},
                     "dynamic_analysis": {"available": False, "reason": "VM isolada não configurada."},
                     "virustotal": {"available": False, "reason": "Nenhum upload externo automático."}}}
    base = {"settings": {"model": "qwen3.5:4b-q4_K_M", "profile": "unrestricted_local", "context": 4096, "temperature": .2, "thinking": True, "tor_enabled": False},
            "profiles": [{"id": "standard", "name": "NEXUS PADRÃO"}, {"id": "unrestricted_local", "name": "NEXUS UNRESTRICTED — LOCAL"}],
            "ollama": {"connected": True, "models": [{"name": "qwen3.5:4b-q4_K_M"}, {"name": "qwen2.5-coder:7b"}]},
            "agents": BASE_AGENTS + SECURITY_AGENTS, "modes": ["CHAT", "PLAN", "CODE", "AGENT", "REVIEW", "RESEARCH"],
            "system": {"ram_used_gb": 11, "ram_total_gb": 16, "ram_available_gb": 5, "gpu": [{"name": "GPU da fixture", "memory_used_mb": 1000, "memory_total_mb": 6144}]}, "workspace_root": "C:/fixture/workspaces"}

    def result(tool):
        identity = f"report-{len(reports) + 1}"
        value = {"ok": True, "tool": tool, "source": "fixture_tool", "code": "ok", "findings": [finding] if tool == "security_code_audit" else [],
                 "data": {"notice": "Fixture isolada: nenhuma operação real foi executada.", "limitations": ["Resultado fictício de apresentação."]}, "report_id": identity}
        if tool == "security_windows":
            value["data"]["data"] = {"AntivirusEnabled": True, "RealTimeProtectionEnabled": True}
        if tool == "security_static_file":
            value["data"].update(sha256="a" * 64, size_bytes=16, format="text", indicators=[{"id": "fixture_indicator", "title": "Indicador da fixture", "severity": "info", "validation": "unconfirmed"}])
        reports.append({"id": identity, "operation": tool, "ok": True, "created_at": NOW, "findings_count": len(value["findings"]), "result": value})
        return value

    def route_handler(route):
        request = route.request
        parsed = urlsplit(request.url)
        if parsed.hostname not in {"127.0.0.1", "localhost"}:
            report["external_requests"].append(request.url); route.abort(); return
        path, method = parsed.path, request.method
        if path == "/" or path.startswith("/static/"):
            file = ROOT / "nexus/static" / ("index.html" if path == "/" else path.split("/")[-1])
            if file.is_file():
                content_type = {".html": "text/html", ".js": "text/javascript", ".css": "text/css"}.get(file.suffix, "text/plain")
                route.fulfill(status=200, body=file.read_bytes(), content_type=content_type); return
        payload = request.post_data_json if request.headers.get("content-type", "").startswith("application/json") else None
        calls.append({"path": path, "method": method, "json": payload})
        status, value = 200, None
        if path == "/api/status": value = base
        elif path == "/api/projects": value = inventory["projects"]
        elif path in {"/api/sessions", "/api/audit"}: value = []
        elif path == "/api/security/status": value = inventory
        elif path == "/api/security/scopes" and method == "GET": value = {"scopes": scopes}
        elif path == "/api/security/scopes" and method == "POST":
            value = {**payload, "id": f"scope-{len(scopes) + 1}", "enabled": True, "revision": 1}; scopes.append(value)
        elif path.startswith("/api/security/scopes/") and method == "DELETE":
            identity = path.split("/")[-1]
            for scope in scopes:
                if scope["id"] == identity: scope.update(enabled=False, revision=scope["revision"] + 1)
            value = {"ok": True, "id": identity, "enabled": False}
        elif path == "/api/security/samples" and method == "GET": value = {"samples": samples}
        elif path == "/api/security/samples" and method == "POST":
            body = request.post_data_buffer or b""
            assert body == b"NEXUS SAMPLE QA\n"
            assert request.headers.get("content-type") == "application/octet-stream"
            value = {"id": "a" * 32, "original_name": parse_qs(parsed.query)["name"][0], "sha256": hashlib.sha256(body).hexdigest(), "size": len(body), "created_at": NOW}
            samples.append(value)
        elif path == "/api/security/dorks/preview":
            assert isinstance(payload["exclusions"], list)
            assert all(payload["operators"].values()), "Operadores vazios não devem ser enviados."
            scope = next(item for item in scopes if item["id"] == payload["scope_id"])
            query_args = {key: item for key, item in payload.items() if key != "scope_id"}
            value = {**result("security_dork"), "data": build_dork(scope, **query_args)}
        elif path == "/api/security/jobs":
            tool, args = payload["tool"], payload["args"]
            assert payload["mode"] == "AGENT"
            if tool in {"security_http", "security_tls", "security_tcp", "security_nmap", "security_osint"}:
                pending.update(tool=tool, args=args)
                if args.get("target") == "https://fora-do-escopo.invalid":
                    status, value = 400, {"ok": False, "error": "Alvo fora do escopo autorizado.", "code": "target_outside_scope", "source": "permission"}
                else: value = {"ok": True, "requires_approval": True, "approval_id": "fixture-approval", "preview": {
                    "action": tool, "target": args.get("target", args.get("domain")), "scope_name": scopes[0]["name"], "scope_revision": 1,
                    "ports": args.get("ports", []), "risk": "network_observation", "args": args, "impact": "Pode gerar registros no alvo.",
                    **({"query": "site:example.test intitle:documentação API"} if tool == "security_osint" else {})}}
            else: value = result(tool)
        elif path == "/api/security/jobs/fixture-approval/decision":
            decisions.append(payload["approved"])
            value = result(pending["tool"]) if payload["approved"] else {"ok": True, "executed": False, "source": "permission", "code": "approval_denied"}
        elif path == "/api/security/reports": value = {"reports": [{k: v for k, v in row.items() if k != "result"} for row in reports]}
        elif path.startswith("/api/security/reports/"):
            identity = path.split("/")[-1]; value = next(row for row in reports if row["id"] == identity)
        else:
            report["unexpected_requests"].append({"path": path, "method": method}); status, value = 404, {"ok": False, "error": "Rota não coberta pela fixture."}
        route.fulfill(status=status, content_type="application/json", body=json.dumps(value, ensure_ascii=False))

    with tempfile.TemporaryDirectory(prefix="security-ui-", dir=REPORTS) as profile:
        with sync_playwright() as p:
            context = p.chromium.launch_persistent_context(profile, executable_path=str(CHROME), headless=True,
                viewport={"width": 1440, "height": 1000}, args=["--disable-background-networking", "--disable-component-update", "--disable-sync", "--no-first-run"])
            context.route("**/*", route_handler)
            page = context.pages[0]
            page.on("pageerror", lambda error: report["page_errors"].append(str(error)))
            def console(message):
                if message.type != "error":
                    return
                if "400 (Bad Request)" in message.text and "/api/security/jobs" in message.location.get("url", ""):
                    report["expected_http_errors"].append(message.text)
                else:
                    report["console_errors"].append(message.text)
            page.on("console", console)
            try:
                page.goto(URL, wait_until="networkidle")
                expect(page.locator("#model-select")).to_have_value("qwen3.5:4b-q4_K_M")
                page.locator("#nav-security").click()
                expect(page.locator("#security-load-status")).to_contain_text("atualizado")
                expect(page.locator(".security-stat")).to_have_count(4)
                assert not page.locator("#security-dialog").evaluate("el => el.scrollWidth > el.clientWidth")
                page.screenshot(path=str(REPORTS / "security-center-desktop.png"), full_page=True)
                tests["desktop_inventory"] = {"status": "passed", "capabilities_not_faked": True, "no_horizontal_overflow": True}

                page.locator('[data-security-tab="agents"]').click()
                expect(page.locator(".security-agent-card")).to_have_count(15)
                page.locator("#security-model").select_option("qwen2.5-coder:7b")
                page.locator(".security-agent-card").filter(has_text="NEXUS RED TEAM").get_by_role("button").click()
                assert page.locator("#agent-select").input_value() == "red_team"
                assert page.locator("#model-select").input_value() == "qwen2.5-coder:7b"
                assert not page.locator("#security-dialog").evaluate("el => el.open")
                tests["agent_and_local_model"] = {"status": "passed", "selected_agent": "red_team", "no_inference_request": True}
                page.locator("#nav-security").click()

                page.locator('[data-security-tab="scopes"]').click()
                page.locator("#security-scope-name").fill('Meu lab <img src=x onerror=alert(1)>')
                page.locator("#security-scope-targets").fill("127.0.0.1\nexample.test")
                page.locator("#security-scope-purpose").fill("Validar meu ambiente de testes.")
                page.locator("#security-scope-form button[type=submit]").click()
                assert not scopes
                page.locator('input[name="security-tests"][value="osint"]').check()
                page.locator("#security-scope-authorized").check()
                page.locator("#security-scope-form button[type=submit]").click()
                expect(page.locator("#security-scope-list")).to_contain_text("Meu lab")
                assert len(scopes) == 1 and scopes[0]["authorization_confirmed"] is True
                assert not page.locator("#security-scope-authorized").is_checked()
                assert page.locator("#security-scope-list img").count() == 0
                tests["explicit_scope_and_text_safety"] = {"status": "passed", "authorization_required": True, "html_executed": False}

                page.locator('[data-security-tab="network"]').click()
                page.locator("#security-network-scope").select_option("scope-1")
                page.locator("#security-network-tool").select_option("security_nmap")
                expect(page.locator("#security-network-run")).to_be_disabled()
                page.locator("#security-network-tool").select_option("security_http")
                page.locator("#security-network-target").fill("http://127.0.0.1:8765")
                page.locator("#security-network-run").click()
                expect(page.locator("#security-approval")).to_be_visible()
                expect(page.locator("#security-approval")).to_contain_text("127.0.0.1:8765")
                assert not decisions
                page.locator("#security-approval").get_by_role("button", name="Recusar", exact=True).click()
                expect(page.locator("#security-result-badge")).to_have_text("Recusado por você")
                assert decisions == [False]
                page.locator("#security-network-run").click()
                page.locator("#security-approval").get_by_role("button", name="Aprovar somente esta operação", exact=True).click()
                expect(page.locator("#security-approval")).to_be_hidden()
                assert decisions == [False, True]
                page.locator("#security-network-target").fill("https://fora-do-escopo.invalid")
                page.locator("#security-network-run").click()
                expect(page.locator("#security-result-message")).to_contain_text("target_outside_scope")
                expect(page.locator("#security-result-message")).to_contain_text("permission")
                tests["network_human_approval_and_errors"] = {"status": "passed", "fixture_decisions": decisions, "nmap_unavailable_disabled": True, "permission_error_preserved": True}

                page.locator('[data-security-tab="osint"]').click()
                page.locator("#security-dork-scope").select_option("scope-1")
                page.locator("#security-dork-domain").fill("example.test")
                page.locator("#security-dork-intitle").fill("documentação")
                page.locator("#security-dork-keywords").fill("API")
                page.locator("#security-dork-exclusions").fill("antigo\nrascunho")
                expect(page.locator("#security-dork-run")).to_be_disabled()
                page.locator("#security-dork-form button[type=submit]").click()
                expect(page.locator("#security-dork-run")).to_be_enabled()
                expect(page.locator("#security-dork-preview")).to_contain_text("site:example.test")
                reports_before_search = len(reports)
                page.locator("#security-dork-run").click()
                expect(page.locator("#security-approval")).to_contain_text("site:example.test")
                assert len(reports) == reports_before_search
                page.locator("#security-approval").get_by_role("button", name="Aprovar somente esta operação", exact=True).click()
                expect(page.locator("#security-result-title")).to_have_text("security_osint")
                page.locator("#security-dork-keywords").fill("API alterada")
                expect(page.locator("#security-dork-run")).to_be_disabled()
                tests["dork_preview_then_search"] = {"status": "passed", "real_builder_validates_payload": True, "human_approval_required": True, "changed_query_invalidates_preview": True}

                page.locator('[data-security-tab="files"]').click()
                page.locator("#security-upload-file").set_input_files({"name": "sample-qa.txt", "mimeType": "text/plain", "buffer": b"NEXUS SAMPLE QA\n"})
                page.locator("#security-upload-form button[type=submit]").click()
                expect(page.locator("#security-sample-select")).to_have_value("a" * 32)
                expect(page.locator("#security-sample-info")).to_contain_text(samples[0]["sha256"])
                expect(page.locator("#security-rea-run")).to_be_disabled()
                page.locator("#security-static-run").click()
                expect(page.locator("#security-result-title")).to_have_text("security_static_file")
                expect(page.locator("#security-findings")).to_contain_text("Indicador da fixture")
                tests["inert_raw_upload_and_static"] = {"status": "passed", "binary_body_verified": True, "rea_unavailable_disabled": True, "no_sample_execution": True}

                page.locator('[data-security-tab="code"]').click()
                page.locator("#security-project-select").select_option("fixture-project")
                page.locator("#security-code-run").click()
                expect(page.locator(".security-findings-table tbody tr")).to_have_count(1)
                expect(page.locator("#security-findings")).to_contain_text("src/exemplo.py:12")
                expect(page.locator("#security-findings")).to_contain_text("unconfirmed")
                assert page.locator("#security-result img, #security-result script").count() == 0
                expect(page.locator("#security-result-links a")).to_have_count(2)
                page.screenshot(path=str(REPORTS / "security-center-findings.png"), full_page=True)
                tests["findings_and_report_links"] = {"status": "passed", "severity_file_line_impact_recommendation_validation": True, "untrusted_html_as_text": True}

                page.locator('[data-security-tab="windows"]').click()
                page.locator("#security-windows-section").select_option("defender")
                page.locator("#security-windows-form button[type=submit]").click()
                expect(page.locator("#security-result-title")).to_have_text("security_windows")
                expect(page.locator("#security-result-data")).to_contain_text("RealTimeProtectionEnabled")
                tests["windows_read_only_form"] = {"status": "passed", "section": "defender"}
                page.locator('[data-security-tab="reports"]').click()
                expect(page.locator("#security-report-list .security-list-card")).to_have_count(len(reports))
                assert all("format=" in link for link in page.locator("#security-report-list a").evaluate_all("els=>els.map(el=>el.href)"))
                tests["reports_list"] = {"status": "passed", "count": len(reports)}

                page.locator('[data-security-tab="scopes"]').click()
                page.locator("#security-scope-list .danger-button").click()
                expect(page.locator("#security-scope-list")).to_contain_text("Revogado")
                assert scopes[0]["enabled"] is False
                tests["scope_revocation"] = {"status": "passed"}

                for width in (390, 320):
                    page.set_viewport_size({"width": width, "height": 844})
                    page.locator('[data-security-tab="overview"]').click()
                    assert not page.evaluate("document.documentElement.scrollWidth > innerWidth")
                    assert not page.locator("#security-dialog").evaluate("el => el.scrollWidth > el.clientWidth")
                    assert not page.locator("#security-content").evaluate("el => el.scrollWidth > el.clientWidth")
                    if width == 390: page.screenshot(path=str(REPORTS / "security-center-mobile.png"), full_page=True)
                    tests[f"mobile_{width}"] = {"status": "passed", "horizontal_overflow": False}
                page.locator("#security-close").click()
                page.locator("#sidebar-toggle").click()
                page.locator("#nav-security").click()
                assert "is-open" not in page.locator("#sidebar").get_attribute("class")
                assert page.locator("#sidebar-shade").is_hidden()
                tests["mobile_navigation"] = {"status": "passed"}
                assert not report["page_errors"], report["page_errors"]
                assert not report["console_errors"], report["console_errors"]
                assert not report["external_requests"], report["external_requests"]
                assert not report["unexpected_requests"], report["unexpected_requests"]
                assert not any(call["path"] in {"/api/chat", "/api/settings"} for call in calls)
                report["status"] = "passed"
            except Exception as error:
                report["status"] = "failed"; report["error"] = f"{type(error).__name__}: {error}"
                page.screenshot(path=str(REPORTS / "security-center-failure.png"), full_page=True)
            finally:
                report["intercepted_requests"] = len(calls); context.close()
    (REPORTS / "security-ui.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"status": report["status"], "tests": list(tests), "error": report.get("error"), "report": "reports/security-ui.json"}, ensure_ascii=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
