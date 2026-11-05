"""Contract-driven browser fixtures. No model, network, scope or filesystem mutations occur."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
import traceback
from urllib.parse import parse_qs, urlsplit

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"
CHROME = Path(os.environ.get("LOCALAPPDATA", "")) / "ms-playwright/chromium-1228/chrome-win64/chrome.exe"
NOW = datetime.now(timezone.utc).isoformat()


def main() -> int:
    REPORTS.mkdir(exist_ok=True)
    report = {"fixture": True, "timestamp": NOW, "tests": {}, "page_errors": [], "console_errors": [], "external_requests": [], "unexpected_requests": []}
    tests = report["tests"]
    model_name = "qwen3.5:4b-q4_K_M"
    modes = [{"id": identity, "name": name, "description": "Capacidades reais são verificadas pelo backend.", "agent": agent,
              "operation_mode": operation, "recommended_model": model_name, "required_capabilities": [] if identity == "chat" else ["tools"], "tools": [] if identity == "chat" else ["read_file", "search_web"]}
             for identity, name, agent, operation in [("chat", "Chat", "auto", "CHAT"), ("search", "Search Normal", "researcher", "RESEARCH"), ("tor", "Search Deep Web / Tor", "researcher", "RESEARCH"), ("pentest", "Hacking / Pentest", "red_team", "AGENT"), ("developer", "Developer", "coder", "CODE"), ("security", "Security / Antivirus", "malware_lab", "REVIEW")]]
    tools = [{"name": "read_file", "description": "Ler arquivos autorizados"}, {"name": "write_file", "description": "Escrita com aprovação"}, {"name": "search_web", "description": "Pesquisa pública"}]
    def agent(identity, name, mode="chat", builtin=True):
        return {"id": identity, "name": name, "description": "<img src=x onerror=alert(1)> é dado, sem execução.", "icon": "◇", "workspace_mode": mode,
                "prompt": "Execute tarefas autorizadas e verifique resultados.", "default_model": "", "tool_allowlist": ["read_file"], "memory": {"read": True, "write": False, "scope": "project"},
                "permissions": {"file_read": True, "file_write": False, "terminal": False, "external_network": False}, "search": {"provider": "auto", "max_results": 5, "tor_enabled": False}, "builtin": builtin, "revision": 1}
    agents = [agent("auto", "Automático"), agent("coder", "NEXUS CODER", "developer"), agent("researcher", "NEXUS RESEARCH", "search"), agent("red_team", "NEXUS RED TEAM", "pentest"), agent("malware_lab", "NEXUS MALWARE LAB", "security")]
    models = [{"name": name, "size": 2000000000, "capabilities": capabilities, "tools": "tools" in capabilities, "vision": "vision" in capabilities, "quantization": "Q4_K_M", "parameter_size": "4B", "context_length": 32768, "loaded": name == model_name, "size_vram": 1000000000 if name == model_name else None, "default": name == model_name, "digest": "a" * 64}
              for name, capabilities in [(model_name, ["completion", "tools", "vision"]), ("plain:1b", ["completion"]), ("embeddinggemma:latest", ["embedding"])]]
    settings = {"model": model_name, "profile": "unrestricted_local", "context": 4096, "temperature": .2, "quality_mode": "careful", "tor_enabled": False}
    sessions, approvals, jobs, calls, uploads = [], {}, {}, [], []
    changes = [{"id": "change1", "path": "fixture/main.py", "created_at": NOW, "before_sha256": "b" * 64, "after_sha256": "c" * 64, "created_new": False}]
    state = {"counter": 0, "cancelled": 0, "chat": 0}
    projects = [{"id": "p1", "name": "Projeto A", "path": "fixture/a"}, {"id": "p2", "name": "Projeto B", "path": "fixture/b"}]
    def base():
        return {"settings": settings, "profiles": [{"id": "standard", "name": "NEXUS PADRÃO"}, {"id": "unrestricted_local", "name": "NEXUS UNRESTRICTED — LOCAL", "preserve_original": True}],
                "ollama": {"connected": True, "models": models}, "agents": agents, "modes": ["CHAT", "PLAN", "CODE", "AGENT", "REVIEW", "RESEARCH"],
                "system": {"ram_used_gb": 12, "ram_total_gb": 16, "ram_available_gb": 4, "gpu": [{"name": "GPU da fixture", "memory_used_mb": 1024, "memory_total_mb": 6144}]}, "workspace_root": "C:/fixture/workspaces"}
    def inventory():
        return {"connected": True, "models": models, "default_model": settings["model"], "resources": {"ram_available_gb": 4, "disk_free_gb": 40}, "jobs": list(jobs.values()), "uploads": uploads}
    def envelope(item):
        return {"format": "nexus-agent", "version": 1, "agent": {k: v for k, v in item.items() if k not in {"id", "builtin", "revision"}}}
    def route_handler(route):
        request = route.request; parsed = urlsplit(request.url); path = parsed.path; method = request.method
        if parsed.hostname not in {"127.0.0.1", "localhost"}:
            report["external_requests"].append(request.url); route.abort(); return
        if path == "/" or path.startswith("/static/"):
            file = ROOT / "nexus/static" / ("index.html" if path == "/" else path.split("/")[-1])
            if file.is_file():
                route.fulfill(status=200, body=file.read_bytes(), content_type={".html": "text/html", ".js": "text/javascript", ".css": "text/css"}.get(file.suffix, "text/plain")); return
        payload = request.post_data_json if request.headers.get("content-type", "").startswith("application/json") else None
        calls.append({"path": path, "method": method, "json": payload, "query": parsed.query})
        status, value = 200, None
        if path == "/api/status": value = base()
        elif path == "/api/workspace-modes": value = {"modes": modes, "active": "chat", "tor_enabled": False}
        elif path == "/api/workspace-modes/compatibility":
            compatible = payload["workspace_mode"] == "chat" or payload["model"] != "plain:1b"
            value = {"compatible": compatible, "reason": "O modelo não declara suporte a ferramentas." if not compatible else "", "capabilities": ["completion"], "suggestions": [model_name] if not compatible else []}
        elif path == "/api/agents": value = {"agents": agents}
        elif path == "/api/projects": value = projects
        elif path == "/api/security/status":
            value = {"agents": [agent("red_team", "NEXUS RED TEAM", "pentest"), agent("malware_lab", "NEXUS MALWARE LAB", "security")], "scopes": [], "samples": [], "projects": projects, "reports": [], "operations": ["security_static_file", "security_http"], "capabilities": {"rea": {"available": False, "error": "Fixture"}, "static": {"YARA-X": {"available": True}}, "external_tools": {"tools": [{"id": "nmap", "available": False, "reason": "Fixture"}]}, "dynamic_analysis": {"available": False, "reason": "Sem VM"}, "virustotal": {"available": False, "reason": "Não configurado"}}}
        elif path == "/api/audit": value = []
        elif path == "/api/settings" and method == "POST": settings.update(payload); value = {"ok": True}
        elif path == "/api/research/tor/status": value = {"enabled": settings["tor_enabled"], "proxy": "socks5h://127.0.0.1:9050", "configured": True, "reachable": False, "verified": False, "reason": "Fixture: nenhum proxy real foi consultado."}
        elif path == "/api/research/tor/check": value = {"ok": True, "is_tor": True, "ip": "192.0.2.1", "proxy": "fixture", "fixture": True}
        elif path == "/api/research/reports": value = {"reports": [{"id": "research1", "session_id": "s1", "project_id": "p1", "created_at": NOW, "tool": "search_many", "ok": True}]}
        elif path == "/api/research/reports/research1": value = {"id": "research1", "created_at": NOW, "result": {"ok": True, "tool": "search_many", "retrieved_at": NOW, "via_tor": False, "queries": [{"query": "documentação oficial", "provider": "fixture", "ok": True, "results": [{"url": "https://example.invalid/docs", "title": "<img src=x> documentação", "source_date": "2026-11-05"}]}]}}
        elif path == "/api/developer/changes": value = {"changes": changes, "supported": "approved_file_writes_only"}
        elif path == "/api/developer/changes/change1/preview": value = {"approval_id": "rollback1", "expires_in": 300, "preview": {"action": "restore_file", "path": "fixture/main.py", "diff": "--- atual\n+++ anterior\n-print(2)\n+print(1)"}}
        elif path == "/api/developer/changes/rollback1/decision": value = {"ok": True, "path": "fixture/main.py", "change_id": "rollback-change"}
        elif path == "/api/sessions" and method == "GET": value = sessions
        elif path == "/api/sessions" and method == "POST":
            value = {"id": f"s{len(sessions) + 1}", **payload}; sessions.append(value)
        elif path.startswith("/api/sessions/"):
            value = {**next(item for item in sessions if item["id"] == path.split("/")[-1]), "messages": [{"role": "assistant", "content": "Histórico preservado", "metadata": {"model": model_name, "models_used": [model_name, "plain:1b"], "review_model": "plain:1b", "agent": "researcher", "workspace_mode": "search", "profile": "standard"}}]}
        elif path == "/api/chat":
            assert payload["workspace_mode"] in {mode["id"] for mode in modes}; state["chat"] += 1
            standard = payload["profile"] == "standard"
            metadata = {"model": payload["model"], "models_used": [payload["model"], "plain:1b"] if standard else [payload["model"]], "agent": payload["agent"], "workspace_mode": payload["workspace_mode"], "profile": payload["profile"]}
            if standard: metadata["review_model"] = "plain:1b"
            events = [{"type": "profile", "model": payload["model"], "agent": payload["agent"], "workspace_mode": payload["workspace_mode"], "profile": {"id": payload["profile"], "name": "NEXUS PADRÃO" if standard else "NEXUS UNRESTRICTED — LOCAL"}}, {"type": "token", "content": "Resposta da fixture com fonte verificada pelo teste."}, {"type": "research_status", "performed": True, "queries": ["documentação"], "sources_count": 2, "via_tor": False}, {"type": "metrics", "tokens_per_second": 20}, {"type": "provenance", "metadata": metadata}, {"type": "done"}]
            route.fulfill(status=200, content_type="application/x-ndjson", body="\n".join(json.dumps(item) for item in events) + "\n"); return
        elif path == "/api/library/models": value = inventory()
        elif path == "/api/library/models/preview":
            state["counter"] += 1; identity = f"approval{state['counter']}"; approvals[identity] = dict(payload)
            value = {"ok": True, "approval_id": identity, "expires_in": 300, "preview": {**payload, "estimated_download_bytes": 400000000 if payload["action"] == "pull" else None, "warnings": ["Fixture: nenhuma operação real será executada."], "resources": inventory()["resources"], "source": "fixture", **({"modelfile": "FROM " + payload["base"] + "\nPARAMETER num_ctx 4096"} if payload["action"] == "variant" else {})}}
        elif path == "/api/library/models/jobs" and method == "POST":
            prepared = approvals.pop(payload["approval_id"])
            if not payload["approved"]: value = {"ok": True, "approved": False}
            else:
                if prepared["action"] == "delete": assert payload["confirmation"] == prepared["model"]
                identity = f"job{len(jobs) + 1}"; job = {"id": identity, "status": "running" if prepared["action"] == "pull" else "completed", "action": prepared["action"], "model": prepared["model"], "progress": {"status": "pulling fixture layer", "completed": 20, "total": 100} if prepared["action"] == "pull" else {}, "events": [{"status": "Fixture, not a real operation"}], "result": {"ok": True}}
                jobs[identity] = job
                if prepared["action"] in {"variant", "import", "hf"}: models.append({**models[0], "name": prepared["model"], "loaded": False, "default": False})
                if prepared["action"] == "delete": models[:] = [model for model in models if model["name"] != prepared["model"]]
                if prepared["action"] == "default": settings["model"] = prepared["model"]
                value = {"ok": True, "job_id": identity, "job": job}
        elif path == "/api/library/models/jobs": value = {"jobs": list(jobs.values())}
        elif path.startswith("/api/library/models/jobs/"):
            identity = path.split("/")[5]
            if path.endswith("/cancel"): jobs[identity]["status"] = "cancelled"; state["cancelled"] += 1
            value = jobs[identity]
        elif path == "/api/library/models/uploads":
            assert request.headers.get("content-type") == "application/octet-stream"; assert request.post_data_buffer == b"GGUF-fixture-only"
            value = {"id": "upload1", "name": parse_qs(parsed.query)["name"][0], "size": 17, "sha256": "f" * 64, "architecture": "fixture", "version": 3, "tensor_count": 0}; uploads.append(value)
        elif path == "/api/library/agents" and method == "GET": value = {"agents": agents, "modes": modes, "tools": tools}
        elif path == "/api/library/agents" and method == "POST": value = {**payload, "id": "custom_fixture", "builtin": False, "revision": 1}; agents.append(value)
        elif path == "/api/library/agents/import": value = {**payload["agent"], "id": "custom_imported", "builtin": False, "revision": 1}; agents.append(value)
        elif path.startswith("/api/library/agents/"):
            identity = path.split("/")[4]; original = next(item for item in agents if item["id"] == identity)
            if path.endswith("/duplicate"):
                value = {**original, "id": "custom_copy", "name": original["name"] + " (cópia)", "builtin": False, "revision": 1}; agents.append(value)
            elif path.endswith("/export"):
                route.fulfill(status=200, content_type="application/json", headers={"Content-Disposition": 'attachment; filename="nexus-agent.json"'}, body=json.dumps(envelope(original))); return
            elif method == "PUT":
                assert payload["revision"] == original["revision"]; original.update(payload); original["revision"] += 1; value = original
            elif method == "DELETE": agents.remove(original); value = {"ok": True, "deleted": True, "id": identity}
        else: report["unexpected_requests"].append({"path": path, "method": method}); status, value = 404, {"error": "Unexpected fixture request"}
        route.fulfill(status=status, content_type="application/json", body=json.dumps(value, ensure_ascii=False))

    with tempfile.TemporaryDirectory(prefix="multimodal-ui-", dir=REPORTS) as profile:
        with sync_playwright() as p:
            context = p.chromium.launch_persistent_context(profile, executable_path=str(CHROME), headless=True, viewport={"width": 1440, "height": 1000}, args=["--disable-background-networking", "--disable-component-update", "--disable-sync", "--no-first-run"])
            context.route("**/*", route_handler); page = context.pages[0]; page.set_default_timeout(15000)
            page.on("pageerror", lambda error: report["page_errors"].append(str(error)))
            page.on("console", lambda message: report["console_errors"].append(message.text) if message.type == "error" else None)
            page.on("dialog", lambda dialog: dialog.accept())
            try:
                page.goto("http://127.0.0.1:8765", wait_until="networkidle")
                expect(page.locator("#workspace-mode-select option")).to_have_count(6)
                for mode in modes:
                    page.locator(f'[data-workspace-mode="{mode["id"]}"]').click()
                    expect(page.locator("#workspace-mode-select")).to_have_value(mode["id"])
                    expect(page.locator("#agent-select")).to_have_value(mode["agent"])
                    expect(page.locator("#mode-select")).to_have_value(mode["operation_mode"])
                    expect(page.locator("#model-select")).to_have_value(model_name)
                tests["six_modes_agents_and_independent_model"] = {"status": "passed", "modes": len(modes)}
                page.locator('[data-workspace-mode="search"]').click(); page.locator("#model-select").select_option("plain:1b")
                expect(page.locator("#workspace-compatibility")).to_contain_text("não declara")
                page.locator("#prompt").fill("Teste bloqueado por capacidade ausente"); page.locator("#chat-form").evaluate("form => form.requestSubmit()")
                assert state["chat"] == 0
                page.get_by_role("button", name=f"Usar {model_name}", exact=True).click(); expect(page.locator("#workspace-compatibility")).to_have_text("Modelo compatível")
                tests["compatibility_blocks_missing_tools"] = {"status": "passed", "model_suggestion": model_name}
                page.locator("#prompt").fill("Pesquise a documentação da fixture"); page.locator("#send-button").click()
                expect(page.locator(".research-evidence")).to_contain_text("2 fontes")
                expect(page.locator(".message-inference")).to_contain_text(model_name)
                page.wait_for_function("!document.getElementById('model-select').disabled")
                page.locator("#profile-select").select_option("standard"); page.locator("#prompt").fill("Revise a resposta com o perfil padrão cuidadoso"); page.locator("#send-button").click()
                expect(page.locator(".message-inference").last).to_contain_text(f"{model_name} + plain:1b")
                expect(page.locator(".message-inference").last).to_contain_text("Revisão: plain:1b")
                expect(page.locator(".message-inference").last).to_contain_text("NEXUS PADRÃO")
                page.wait_for_function("!document.getElementById('model-select').disabled")
                expect(page.locator("#model-select")).to_have_value(model_name)
                page.locator("#sessions .session-button").first.click(); expect(page.locator("#messages")).to_contain_text("Histórico preservado"); expect(page.locator(".message-inference")).to_contain_text(f"{model_name} + plain:1b"); expect(page.locator(".message-inference")).to_contain_text("Revisão: plain:1b")
                tests["stream_and_history_attribute_primary_review_models"] = {"status": "passed", "models_used": [model_name, "plain:1b"], "selector_unchanged": True, "fixture_only": True}
                page.locator("#project-select").select_option("p1"); expect(page.locator("#session-title")).to_have_text("Nova conversa")
                assert len(sessions) == 1
                page.locator(".session-filters summary").click(); page.locator("#sessions-filter-mode").select_option("search")
                expect(page.locator("#sessions .session-item")).to_have_count(1)
                assert any("workspace_mode=search" in call["query"] for call in calls if call["path"] == "/api/sessions")
                page.locator(".session-filters summary").click()
                tests["chat_metadata_research_evidence_history_project_separation"] = {"status": "passed", "history_preserved": True}
                page.locator('[data-workspace-mode="tor"]').click(); assert not settings["tor_enabled"]
                page.get_by_role("button", name="Ativar Tor explicitamente", exact=True).click(); expect(page.locator("#monitor-tor")).to_have_text("Autorizado")
                page.get_by_role("button", name="Verificar proxy e saída", exact=True).click(); expect(page.locator("#tor-context-status")).to_contain_text('"is_tor": true')
                tests["tor_requires_explicit_activation_and_check"] = {"status": "passed", "fixture_only": True}
                page.locator('[data-workspace-mode="developer"]').click(); page.get_by_role("button", name="Histórico e reversão de arquivos").click()
                page.get_by_role("button", name="Revisar reversão").click(); expect(page.locator(".developer-rollback pre")).to_contain_text("+print(1)")
                page.get_by_role("button", name="Aprovar esta reversão").click(); expect(page.locator(".developer-rollback")).to_contain_text("concluída")
                tests["developer_rollback_requires_preview_and_decision"] = {"status": "passed"}
                page.locator("#nav-security").click(); expect(page.locator("#security-load-status")).to_contain_text("atualizado")
                for tab in ("agents", "scopes", "network", "osint", "files", "code", "windows", "reports"):
                    page.locator(f'[data-security-tab="{tab}"]').click(); expect(page.locator(f"#security-{tab}")).to_be_visible()
                page.locator('[data-security-tab="agents"]').click()
                page.locator(".security-agent-card").filter(has=page.locator("h4", has_text="NEXUS MALWARE LAB")).get_by_role("button", name="Usar agente no chat").click()
                expect(page.locator("#workspace-mode-select")).to_have_value("security"); expect(page.locator("#mode-select")).to_have_value("REVIEW"); expect(page.locator("#agent-select")).to_have_value("malware_lab")
                tests["security_center_preserved_and_agent_mode_integrated"] = {"status": "passed", "forms_submitted": 0}
                page.locator("#nav-reports").click(); expect(page.locator("#research-report-list .security-list-card")).to_have_count(1)
                page.get_by_role("button", name="Ver fontes e evidências", exact=True).click(); expect(page.locator(".research-report-evidence")).to_contain_text("documentação oficial"); expect(page.locator(".research-report-evidence")).to_contain_text("2026-11-05")
                assert page.locator(".research-report-evidence img").count() == 0
                expect(page.locator("#research-report-list a")).to_have_count(2)
                page.locator("#security-close").click()
                tests["research_reports_sources_dates_and_exports"] = {"status": "passed", "untrusted_html_as_text": True}
                page.locator("#nav-ai-library").click(); expect(page.locator(".library-model-grid .library-card")).to_have_count(3)
                expect(page.locator(".library-card").filter(has_text="embeddinggemma").get_by_role("button", name="Usar na conversa")).to_be_disabled()
                page.screenshot(path=str(REPORTS / "multimodal-library-desktop.png"), full_page=True)
                tests["models_inventory_and_embedding_incompatibility"] = {"status": "passed", "models": 3}
                for label in ("Tornar padrão", "Testar carregamento", "Descarregar"):
                    selected_card = page.locator(".library-model-grid .library-card").filter(has=page.locator("h4", has_text=model_name))
                    selected_card.get_by_role("button", name=label, exact=True).click()
                    expect(page.locator("#library-approval")).to_be_visible()
                    page.get_by_role("button", name="Aprovar somente esta operação", exact=True).click()
                    expect(page.locator("#library-content")).to_contain_text("completed")
                    page.locator('[data-tab="installed"]').click()
                tests["default_load_test_and_unload_each_require_approval"] = {"status": "passed", "fixture_only": True}
                page.locator('[data-tab="add"]').click(); page.locator("#library-pull-name").fill("test:pull"); page.locator("#library-pull-form button[type=submit]").click()
                expect(page.locator("#library-approval")).to_contain_text("Download estimado")
                assert not any(job["action"] == "pull" for job in jobs.values())
                page.get_by_role("button", name="Aprovar somente esta operação", exact=True).click(); expect(page.locator("#library-content progress")).to_have_attribute("value", "20")
                page.get_by_role("button", name="Solicitar cancelamento", exact=True).click(); expect(page.locator("#library-content")).to_contain_text("cancelled")
                assert state["cancelled"] == 1
                tests["download_approval_real_contract_progress_and_cancel"] = {"status": "passed", "progress_bytes": [20, 100], "fixture_only": True}
                page.locator('[data-tab="variant"]').click(); page.locator("#library-variant-name").fill("qa:variant"); page.locator("#library-variant-system").fill("Responda objetivamente.")
                page.locator("#library-variant-form button[type=submit]").click(); expect(page.locator("#library-approval pre").last).to_contain_text("FROM")
                page.get_by_role("button", name="Aprovar somente esta operação", exact=True).click(); expect(page.locator("#library-content")).to_contain_text("completed")
                page.locator('[data-tab="installed"]').click(); variant = page.locator(".library-model-grid .library-card").filter(has=page.locator("h4", has_text="qa:variant")); expect(variant).to_have_count(1)
                variant.get_by_role("button", name="Remover", exact=True).click(); page.get_by_role("button", name="Aprovar somente esta operação", exact=True).click()
                expect(page.locator("#library-status")).to_contain_text("Digite o nome completo")
                page.locator("#library-delete-confirmation").fill("qa:variant"); page.get_by_role("button", name="Aprovar somente esta operação", exact=True).click(); expect(page.locator("#library-content")).to_contain_text("completed")
                tests["variant_and_typed_delete_confirmation"] = {"status": "passed", "fixture_only": True}
                page.locator('[data-tab="import"]').click(); page.locator("#library-gguf-file").set_input_files({"name": "fixture.gguf", "mimeType": "application/octet-stream", "buffer": b"GGUF-fixture-only"}); page.locator("#library-gguf-model").fill("qa:gguf")
                page.locator("#library-import-form button[type=submit]").click(); expect(page.locator("#library-import-result")).to_contain_text("SHA-256")
                expect(page.locator("#library-approval")).to_be_visible(); page.get_by_role("button", name="Cancelar aprovação", exact=True).click()
                page.locator('[data-tab="add"]').click(); page.locator("#library-hf-model").fill("qa:hf"); page.locator("#library-hf-repo").fill("trusted/model-GGUF"); page.locator("#library-hf-file").fill("model.gguf"); page.locator("#library-hf-form button[type=submit]").click()
                expect(page.locator("#library-approval")).to_contain_text("qa:hf"); page.get_by_role("button", name="Cancelar aprovação", exact=True).click()
                tests["gguf_raw_upload_and_hf_reference_preview"] = {"status": "passed", "fixture_only": True}
                page.locator("#library-close").click(); page.locator("#nav-agent-library").click(); expect(page.locator(".library-agent-card")).to_have_count(0)
                expect(page.locator(".library-agent-grid .library-card")).to_have_count(5)
                assert page.locator("#library-content img, #library-content script").count() == 0
                first = page.locator(".library-agent-grid .library-card").first; first.get_by_role("button", name="Ver configuração").click(); expect(page.locator("#library-agent-name")).to_be_disabled()
                page.get_by_role("button", name="Duplicar e personalizar").click(); expect(page.locator("#library-agent-name")).to_be_enabled()
                page.locator("#library-agent-name").fill("Especialista QA"); page.locator("#library-agent-mode").select_option("developer"); page.locator("#library-agent-file-write").check(); page.locator("#library-agent-tool-1").check()
                page.locator("#library-agent-form button[type=submit]").click(); expect(page.locator("#library-status")).to_contain_text("salvo e validado")
                custom = next(item for item in agents if item["id"] == "custom_copy"); assert custom["permissions"]["file_write"] and "write_file" in custom["tool_allowlist"]
                with page.expect_download() as download: page.locator("#library-agent-form").get_by_role("link", name="Exportar JSON").click()
                assert download.value.suggested_filename.startswith("nexus-") and download.value.suggested_filename.endswith(".json")
                page.locator('[data-tab="agents"]').click(); page.locator("#library-agent-import-file").set_input_files({"name": "agent.json", "mimeType": "application/json", "buffer": json.dumps(envelope(custom)).encode()})
                page.locator("#library-agent-import-form button[type=submit]").click(); expect(page.locator("#library-status")).to_contain_text("importado e validado")
                tests["agent_duplicate_edit_export_import_and_untrusted_text"] = {"status": "passed", "builtin_readonly": True}
                page.locator('[data-tab="agents"]').click(); page.locator(".library-agent-grid .library-card").filter(has=page.locator("h4", has_text="Especialista QA")).last.get_by_role("button", name="Excluir", exact=True).click()
                expect(page.locator("#library-status")).to_contain_text("excluído")
                tests["custom_agent_delete_confirmation"] = {"status": "passed"}
                page.locator('[data-tab="editor"]').click(); expect(page.locator("#library-agent-name")).to_have_value("")
                page.locator("#library-agent-name").fill("Agente criado visualmente"); page.locator("#library-agent-prompt").fill("Analise e verifique código autorizado.")
                page.locator("#library-agent-form button[type=submit]").click(); expect(page.locator("#library-status")).to_contain_text("salvo e validado")
                page.locator('[data-tab="agents"]').click(); page.locator(".library-agent-grid .library-card").filter(has=page.locator("h4", has_text="Agente criado visualmente")).get_by_role("button", name="Usar agente", exact=True).click()
                expect(page.locator("#agent-select")).to_have_value("custom_fixture"); expect(page.locator("#workspace-mode-select")).to_have_value("developer")
                page.locator("#nav-agent-library").click()
                tests["new_agent_creation_and_activation"] = {"status": "passed", "fixture_only": True}
                for width in (390, 320):
                    page.set_viewport_size({"width": width, "height": 844})
                    assert not page.evaluate("document.documentElement.scrollWidth > innerWidth")
                    assert not page.locator("#library-dialog").evaluate("el=>el.scrollWidth > el.clientWidth")
                    assert not page.locator(".library-body").evaluate("el=>el.scrollWidth > el.clientWidth")
                    page.locator('[data-tab="editor"]').click()
                    assert not page.locator(".library-body").evaluate("el=>el.scrollWidth > el.clientWidth")
                    if width == 390: page.screenshot(path=str(REPORTS / "multimodal-agent-mobile.png"), full_page=True)
                    page.locator('[data-tab="agents"]').click()
                    tests[f"mobile_library_{width}"] = {"status": "passed", "horizontal_overflow": False}
                page.locator("#library-close").click(); page.locator("#sidebar-toggle").click(); page.locator('[data-workspace-mode="search"]').click()
                assert "is-open" not in page.locator("#sidebar").get_attribute("class")
                assert not page.evaluate("document.documentElement.scrollWidth > innerWidth")
                page.screenshot(path=str(REPORTS / "multimodal-chat-mobile.png"), full_page=True)
                tests["mobile_mode_navigation"] = {"status": "passed"}
                assert not report["page_errors"], report["page_errors"]
                assert not report["console_errors"], report["console_errors"]
                assert not report["unexpected_requests"], report["unexpected_requests"]
                assert not report["external_requests"], report["external_requests"]
                report["status"] = "passed"
            except Exception as error:
                report["status"] = "failed"; report["error"] = f"{type(error).__name__}: {error}"; report["traceback"] = traceback.format_exc(); page.screenshot(path=str(REPORTS / "multimodal-ui-failure.png"), full_page=True)
            finally: report["requests"] = calls; context.close()
    (REPORTS / "multimodal-ui.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"status": report["status"], "tests": list(tests), "error": report.get("error"), "report": "reports/multimodal-ui.json"}, ensure_ascii=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
