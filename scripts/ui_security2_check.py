"""Chromium UI fixture: v2 API replies are intercepted, never scanner execution."""
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
SCOPE_ID = "a" * 32
REPORT_ID = "b" * 32
RUN_ID = "c" * 32
PLAN_ID = "d" * 32


def main():
    result = {"fixture": True, "actual_scanners_executed": False, "timestamp": datetime.now(timezone.utc).isoformat(),
              "tests": {}, "errors": [], "external_requests": [], "unexpected_mutations": []}
    scope = {"id": SCOPE_ID, "revision": 1, "enabled": True, "name": "NEXUS_LAB_UI_SCOPE", "targets": ["127.0.0.1"],
             "allowed_tests": ["appsec_sqli", "appsec_auth"], "allowed_ports": [8899], "environment": "lab", "environment_class": "lab", "hosting": "own"}
    finding = {"id": "fixture-sqli-finding", "title": "SQLi fictícia · evidência controlada", "severity": "high", "confirmed": True,
               "cwe": "CWE-89", "evidence": {"marker_present": True}, "recommendation": "Parametrizar consulta."}
    report = {"id": REPORT_ID, "operation": "v2:appsec_sqli", "created_at": "2026-11-05T12:00:00Z", "result": {
              "ok": True, "schema": "nexus-security-report/2", "target": "http://127.0.0.1:8899/sqli", "project_id": "lab-project",
              "tools_used": ["appsec_sqli"], "findings": [finding], "coverage": {"synthetic_fixture": True}, "limitations": ["Fixture de interface; não executou scanner."]}}
    base = {"agents": [], "scopes": [scope], "projects": [{"id": "lab-project", "name": "NEXUS_LAB_UI_PROJECT", "path": "ui-fixture"}],
            "samples": [], "operations": [], "reports": [{"id": REPORT_ID, "operation": report["operation"], "created_at": report["created_at"], "ok": True, "findings_count": 1}], "capabilities": {}}
    run = {"id": RUN_ID, "engine": "appsec_sqli", "state": "queued", "target": "http://127.0.0.1:8899/sqli", "events": [], "created_at": report["created_at"]}
    plan = {"id": PLAN_ID, "state": "prepared", "created_at": report["created_at"], "source_target": report["result"]["target"], "scope": scope,
            "diffs": [{"path": "settings.json", "diff": '-{"fixed":false}\n+{"fixed":true}'}]}
    observations = []
    with tempfile.TemporaryDirectory(prefix="security2-ui-fixture-", dir=REPORTS) as profile:
        with sync_playwright() as p:
            context = p.chromium.launch_persistent_context(profile, executable_path=str(CHROME), headless=True,
                viewport={"width": 1440, "height": 1000}, args=["--disable-background-networking", "--disable-component-update", "--disable-sync", "--no-first-run"])
            def route_handler(route):
                request = route.request
                parsed = urlsplit(request.url)
                if parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
                    result["external_requests"].append(request.url)
                    return route.abort()
                path = parsed.path
                payload = request.post_data_json if request.method == "POST" else None
                if path == "/api/security/status":
                    return route.fulfill(json=base)
                if path.startswith("/api/security/v2") or path == "/api/security/scopes" and request.method == "POST":
                    observations.append({"path": path, "method": request.method, "payload": payload})
                    if path.endswith("/status"):
                        return route.fulfill(json={"scanners": {"tools": [{"id": key, "available": False, "configured": False, "note": "Fixture: ferramenta ausente."} for key in ("nuclei", "zap", "nmap_service")], "templates": []},
                            "ghidra": {"available": False, "reason": "Fixture: Ghidra não configurado."}, "integrated_engines": ["appsec_sqli", "appsec_auth", "http_headers", "code_audit", "windows"], "runs": [run], "limits": {"concurrency": 1}, "export_formats": {"json": True, "md": True, "html": True, "pdf": True}})
                    if path.endswith("/remediation/plans"):
                        return route.fulfill(json={"plans": [plan]})
                    if path.endswith("/remediation/" + PLAN_ID):
                        return route.fulfill(json=plan)
                    if path.endswith("/runs"):
                        return route.fulfill(json={"runs": [run]})
                    if path.endswith("/runs/" + RUN_ID):
                        return route.fulfill(json=run)
                    if path.endswith("/runs/" + RUN_ID + "/cancel"):
                        run["state"] = "cancelled"
                        return route.fulfill(json={"ok": True, "state": "cancelled"})
                    if path.endswith("/reports/" + REPORT_ID):
                        return route.fulfill(json=report)
                    if path.endswith("/decision"):
                        return route.fulfill(json={"ok": True, "queued": payload["approved"], "job": run} if payload["approved"] else {"ok": True, "code": "approval_denied"})
                    if path.endswith("/preview") or path.endswith("-preview"):
                        return route.fulfill(json={"ok": True, "requires_approval": True, "approval_id": "e" * 32, "preview": {"target": report["result"]["target"], "impact": "Fixture; nenhuma execução real.", "diffs": plan["diffs"]}})
                    if path == "/api/security/scopes":
                        return route.fulfill(json={"ok": True, **scope})
                    return route.fulfill(status=400, json={"error": "Endpoint fixture não previsto: " + path})
                if request.method not in {"GET", "HEAD"} and path != "/api/workspace-modes/compatibility":
                    result["unexpected_mutations"].append(path)
                    return route.abort()
                route.continue_()
            context.route("**/*", route_handler)
            page = context.pages[0]
            page.set_default_timeout(20000)
            page.on("pageerror", lambda error: result["errors"].append(str(error)))
            try:
                page.goto("http://127.0.0.1:8765", wait_until="networkidle")
                page.locator("#nav-security").click()
                page.locator("#security2-open").click()
                expect(page.locator("#security2-dialog")).to_be_visible()
                expect(page.locator(".sec2-nav [data-sec2-tab]")).to_have_count(14)
                expect(page.locator(".sec2-grid .sec2-card")).to_have_count(10)
                result["tests"]["dashboard_ten_modules"] = "passed"
                page.screenshot(path=str(REPORTS / "security2-ui-fixture-desktop.png"), full_page=True)
                for tab in ("targets", "tools", "web", "network", "auth", "code", "malware", "reverse", "osint", "blue", "reports", "remediation", "jobs"):
                    page.locator(f'[data-sec2-tab="{tab}"]').click()
                    expect(page.locator("#sec2-content h3").first).to_be_visible()
                result["tests"]["all_modules_and_real_controls_render"] = "passed"
                page.locator('[data-sec2-tab="tools"]').click()
                expect(page.locator("#sec2-content")).to_contain_text("Fixture: ferramenta ausente")
                result["tests"]["unavailable_distinguished_from_configured"] = "passed"
                page.locator("#sec2-install-nuclei").click()
                expect(page.locator("#sec2-approval")).to_be_visible()
                payload = next(row["payload"] for row in observations if row["path"].endswith("/installations/preview"))
                assert payload == {"tool": "nuclei"}
                page.locator("#sec2-approval").get_by_role("button", name="Negar", exact=True).click()
                expect(page.locator("#sec2-approval")).to_be_hidden()
                assert not any(row["payload"] and row["payload"].get("approved") is True for row in observations)
                result["tests"]["nuclei_installation_preview_denied_no_download"] = "passed"
                page.locator('[data-sec2-tab="targets"]').click()
                page.locator("#sec2-scope-name").fill("NEXUS_LAB_UI_NEW")
                page.locator("#sec2-permission-appsec_sqli").check()
                page.locator("#sec2-scope-authorization").check()
                page.locator("#sec2-scope-form").get_by_role("button", name="Cadastrar escopo").click()
                expect(page.locator("#sec2-status")).to_contain_text("Escopo cadastrado")
                payload = next(row["payload"] for row in observations if row["path"] == "/api/security/scopes")
                assert payload["allowed_ports"] == [8899] and payload["environment_class"] == "lab" and payload["authorization_confirmed"] is True
                result["tests"]["scope_form_payload"] = "passed"
                page.locator('[data-sec2-tab="auth"]').click()
                page.locator("#sec2-job-scope").select_option(SCOPE_ID)
                page.locator("#sec2-synthetic").check()
                page.locator("#sec2-audit-form").get_by_role("button", name="Preparar auditoria").click()
                expect(page.locator("#sec2-status")).to_contain_text("selecione SAFE ACTIVE")
                assert not any(row["path"].endswith("/v2/preview") for row in observations)
                page.locator("#sec2-profile").select_option("SAFE ACTIVE")
                page.locator("#sec2-audit-form").get_by_role("button", name="Preparar auditoria").click()
                expect(page.locator("#sec2-approval")).to_be_visible()
                assert next(row["payload"] for row in observations if row["path"].endswith("/v2/preview"))["args"]["lab_confirmation"] is True
                page.locator("#sec2-approval").get_by_role("button", name="Negar", exact=True).click()
                expect(page.locator("#sec2-approval")).to_be_hidden()
                result["tests"]["active_profile_and_negative_approval"] = "passed"
                page.locator('[data-sec2-tab="jobs"]').click()
                page.get_by_role("button", name="Ver eventos e evidências").click()
                expect(page.locator("#sec2-run-detail")).to_contain_text("queued")
                page.get_by_role("button", name="Interromper tarefa").click()
                expect(page.locator("#sec2-run-list")).to_contain_text("cancelled")
                result["tests"]["job_events_cancel"] = "passed"
                run.update(engine="install_tool", state="completed", events=[{"stage": "download", "downloaded_bytes": 256, "total_bytes": 1024, "total_source": "fixture"}])
                page.locator('[data-sec2-tab="jobs"]').click()
                page.get_by_role("button", name="Ver eventos e evidências").click()
                expect(page.locator("#sec2-run-detail .sec2-download progress")).to_have_attribute("max", "1024")
                expect(page.locator("#sec2-run-detail .sec2-download progress")).to_have_attribute("value", "256")
                result["tests"]["installer_progress_uses_reported_bytes_fixture"] = "passed"
                run.update(engine="ghidra", state="completed", events=[], result={"ok": True, "source": "Ghidra headless / fixture exporter", "language_id": "x86:LE:64:default",
                    "functions": [{"name": "NEXUS_LAB_test_function", "address": "00401000", "signature": "int NEXUS_LAB_test_function(void)", "source": "Ghidra function manager fixture",
                                   "pseudocode": "int NEXUS_LAB_test_function(void) { return 42; }", "pseudocode_source": "Ghidra native decompiler fixture"}],
                    "strings": [{"value": "NEXUS_LAB_STRING"}], "references": [{"from": "00401000", "to": "00402000"}], "imports": [], "exports": [], "entry_points": ["00401000"], "decompiler": {"available": True}, "coverage": {"fixture": True}})
                page.locator('[data-sec2-tab="jobs"]').click()
                page.get_by_role("button", name="Ver eventos e evidências").click()
                expect(page.locator("#sec2-run-detail")).to_contain_text("NEXUS_LAB_test_function")
                page.locator("#sec2-run-detail summary").filter(has_text="Pseudocódigo").click()
                expect(page.locator("#sec2-run-detail")).to_contain_text("Ghidra native decompiler fixture")
                result["tests"]["ghidra_view_fixture_origin_pseudocode"] = "passed"
                run.update(engine="nmap_service", result={"ok": True, "evidence": {"ports": [{"host": "127.0.0.1", "port": 8899, "protocol": "tcp", "state": "open", "service": None, "version": None, "evidence": {"source": "fixture"}}]}})
                page.locator('[data-sec2-tab="jobs"]').click()
                page.get_by_role("button", name="Ver eventos e evidências").click()
                expect(page.locator("#sec2-run-detail .sec2-table")).to_contain_text("versão não comprovada")
                expect(page.locator("#sec2-run-detail")).to_contain_text("Porta aberta não confirma vulnerabilidade")
                result["tests"]["network_table_no_service_guessed"] = "passed"
                page.locator('[data-sec2-tab="reports"]').click()
                page.locator("#sec2-retention-before").fill("2026-01-01")
                page.locator("#sec2-retention-form").get_by_role("button", name="Revisar limpeza por data").click()
                expect(page.locator("#sec2-approval")).to_be_visible()
                payload = next(row["payload"] for row in observations if row["path"].endswith("/retention/preview"))
                assert payload == {"before": "2026-01-01"}
                page.locator("#sec2-approval").get_by_role("button", name="Negar", exact=True).click()
                result["tests"]["retention_preview_date_denied_no_deletion"] = "passed"
                page.get_by_role("button", name="Abrir relatório", exact=True).click()
                expect(page.locator("#sec2-report-detail .sec2-table")).to_contain_text("SQLi fictícia")
                expect(page.locator("#sec2-report-detail a[download]")).to_have_count(4)
                page.locator("#sec2-report-detail input[type=checkbox]").check()
                page.get_by_role("button", name="Deseja que o NEXUS prepare").click()
                expect(page.locator("#sec2-rem-findings")).to_have_value("fixture-sqli-finding")
                page.get_by_role("button", name="Preparar plano e diffs").click()
                expect(page.locator("#sec2-approval")).to_be_visible()
                payload = next(row["payload"] for row in observations if row["path"].endswith("/remediation/preview"))
                assert payload["edits"] == [{"path": "settings.json", "content": '{"fixed": true}\n'}]
                assert "changes" not in payload
                page.locator("#sec2-approval").get_by_role("button", name="Negar", exact=True).click()
                result["tests"]["report_selection_to_supervised_diff"] = "passed"
                page.locator('[data-sec2-tab="remediation"]').click()
                page.get_by_role("button", name="Ver plano e diffs").click()
                expect(page.locator("#sec2-revalidate-target")).to_have_value("http://127.0.0.1:8899/sqli")
                page.locator("#sec2-revalidate-target").fill("http://127.0.0.1:8899/sqli")
                page.get_by_role("button", name="Revisar testes e revalidação").click()
                expect(page.locator("#sec2-approval")).to_be_visible()
                payload = next(row["payload"] for row in observations if row["path"].endswith("/revalidate-preview"))
                assert payload["scope_id"] == SCOPE_ID and payload["target"].endswith("/sqli")
                page.locator("#sec2-approval").get_by_role("button", name="Negar", exact=True).click()
                result["tests"]["revalidation_requires_scope_and_staging_target"] = "passed"
                for width in (390, 320):
                    page.set_viewport_size({"width": width, "height": 844})
                    page.locator('[data-sec2-tab="dashboard"]').click()
                    assert not page.evaluate("document.documentElement.scrollWidth > innerWidth")
                    assert not page.locator("#security2-dialog").evaluate("el=>el.scrollWidth>el.clientWidth")
                    assert not page.locator(".sec2-body").evaluate("el=>el.scrollWidth>el.clientWidth")
                    result["tests"][f"mobile_{width}"] = "passed"
                    if width == 390:
                        page.screenshot(path=str(REPORTS / "security2-ui-fixture-mobile.png"), full_page=True)
                assert not result["errors"] and not result["external_requests"] and not result["unexpected_mutations"]
                result["status"] = "passed"
            except Exception as exc:
                result["status"] = "failed"
                result["errors"].append(str(exc))
                page.screenshot(path=str(REPORTS / "security2-ui-fixture-error.png"), full_page=True)
            finally:
                result["observed_fixture_requests"] = [{"path": row["path"], "method": row["method"]} for row in observations]
                context.close()
    (REPORTS / "security2-ui-fixture.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"status": result.get("status"), "tests": len(result["tests"]), "errors": result["errors"]}, ensure_ascii=False))
    return 0 if result.get("status") == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
