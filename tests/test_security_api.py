"""HTTP integration of human Security Center decisions, with no external network."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
import copy
import hashlib
import json
from pathlib import Path
import threading
import time
from types import SimpleNamespace
from unittest.mock import Mock

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from nexus.security.api import install_security_routes
from nexus.security.center import SecurityCenter
from nexus.security.store import MAX_SAMPLE


@pytest.fixture
def api_case(tmp_path, monkeypatch):
    workspace = tmp_path / "workspaces"
    (workspace / "demo").mkdir(parents=True)
    data = tmp_path / "data"
    data.mkdir()
    original = data / "existing-user-data.txt"
    original.write_bytes(b"preserved previous user data")
    center = SecurityCenter(data, workspace, lambda: [{"id": "demo", "path": "demo"}])
    monkeypatch.setattr(center, "catalog", lambda: {"external_tools": {}, "dynamic_analysis": {"available": False}})
    activity = Mock()
    semaphore = asyncio.Semaphore(1)

    async def blocking(function, *args, **kwargs):
        return await asyncio.to_thread(function, *args, **kwargs)

    app = FastAPI()
    pending = install_security_routes(app, lambda: center, blocking, lambda: semaphore, lambda: activity)
    with TestClient(app, raise_server_exceptions=False) as client:
        yield SimpleNamespace(client=client, center=center, store=center.store, pending=pending,
                              activity=activity, workspace=workspace, original=original)
    assert original.read_bytes() == b"preserved previous user data"


@pytest.fixture
def api_scope(api_case):
    response = api_case.client.post("/api/security/scopes", json={"name": "Laboratório autorizado", "targets": ["127.0.0.1", "example.com"],
        "allowed_tests": ["http_headers", "tls_certificate", "tcp_connect", "nmap_basic", "osint"],
        "authorization_confirmed": True, "environment": "lab", "purpose": "Testes de integração isolados"})
    assert response.status_code == 200, response.text
    return response.json()


def prepare_http(case, scope, **changes):
    payload = {"tool": "security_http", "args": {"scope_id": scope["id"], "target": "http://127.0.0.1:9876/"}, "mode": "AGENT"}
    payload.update(changes)
    response = case.client.post("/api/security/jobs", json=payload)
    assert response.status_code == 200, response.text
    assert response.json().get("requires_approval") is True
    return response.json()


@pytest.fixture
def http_operation(monkeypatch):
    from nexus.security import network
    operation = Mock(return_value={"ok": True, "tool": "http_headers", "findings": [],
                                  "evidence": {"method": "HEAD", "status": 200, "body_fetched": False}})
    monkeypatch.setattr(network, "inspect_http", operation)
    return operation


def test_scope_api_requires_explicit_authorization_before_persisting(api_case):
    response = api_case.client.post("/api/security/scopes", json={"name": "Unconfirmed", "targets": ["example.com"], "allowed_tests": ["http_headers"]})
    assert response.status_code == 400 and response.json()["ok"] is False
    assert api_case.client.get("/api/security/scopes").json() == {"scopes": []}


def test_scope_api_roundtrip_revocation_and_human_activity(api_case, api_scope):
    listed = api_case.client.get("/api/security/scopes").json()["scopes"]
    assert listed == [api_scope]
    assert api_scope["revision"] == 1 and api_scope["authorization_confirmed"] is True
    response = api_case.client.delete("/api/security/scopes/" + api_scope["id"])
    assert response.status_code == 200 and response.json()["enabled"] is False
    changed = api_case.client.get("/api/security/scopes").json()["scopes"][0]
    assert changed["revision"] == 2 and changed["enabled"] is False
    names = [call.args[0] for call in api_case.activity.add.call_args_list]
    assert "security_scope_created" in names and "security_scope_revoked" in names


@pytest.mark.parametrize("mode", ["PLAN", "CODE", "RESEARCH", "REVIEW", "CHAT", "unknown"])
def test_active_network_job_is_denied_in_other_modes_without_adapter_calls(api_case, api_scope, http_operation, mode):
    response = api_case.client.post("/api/security/jobs", json={"tool": "security_http", "mode": mode,
        "args": {"scope_id": api_scope["id"], "target": "http://127.0.0.1/"}})
    assert response.status_code == 403 and response.json()["source"] == "permission"
    assert api_case.pending == {}
    http_operation.assert_not_called()


def test_model_cannot_create_a_scope_by_tool_name(api_case):
    response = api_case.client.post("/api/security/jobs", json={"tool": "security_create_scope", "mode": "AGENT",
        "args": {"targets": ["example.com"], "authorization_confirmed": True}})
    assert response.status_code == 403
    assert api_case.store.list_scopes() == []


def test_network_job_stays_pending_without_effect_until_approved(api_case, api_scope, http_operation):
    prepared = prepare_http(api_case, api_scope)
    identity = prepared["approval_id"]
    assert prepared["preview"]["scope_revision"] == api_scope["revision"]
    assert api_case.pending[identity]["args"]["scope_revision"] == api_scope["revision"]
    http_operation.assert_not_called()
    assert api_case.client.get("/api/security/reports").json() == {"reports": []}
    decision = api_case.client.post(f"/api/security/jobs/{identity}/decision", json={"approved": True})
    assert decision.status_code == 200 and decision.json()["ok"] is True
    assert "report_id" in decision.json() and identity not in api_case.pending
    assert http_operation.call_args.args[1] == "http://127.0.0.1:9876/"


def test_denied_network_job_has_no_effect_and_cannot_be_replayed(api_case, api_scope, http_operation):
    prepared = prepare_http(api_case, api_scope)
    url = f"/api/security/jobs/{prepared['approval_id']}/decision"
    denied = api_case.client.post(url, json={"approved": False})
    assert denied.status_code == 200 and denied.json()["executed"] is False
    assert denied.json()["code"] == "approval_denied"
    assert api_case.client.post(url, json={"approved": True}).status_code == 404
    http_operation.assert_not_called()
    assert api_case.store.reports() == []


def test_approval_is_single_use_and_decision_cannot_retarget_frozen_arguments(api_case, api_scope, http_operation):
    prepared = prepare_http(api_case, api_scope)
    url = f"/api/security/jobs/{prepared['approval_id']}/decision"
    response = api_case.client.post(url, json={"approved": True, "args": {"target": "http://outside.invalid/"}})
    assert response.status_code == 200 and response.json()["ok"]
    assert http_operation.call_count == 1
    assert http_operation.call_args.args[1] == "http://127.0.0.1:9876/"
    assert api_case.client.post(url, json={"approved": True}).status_code == 404


def test_revoke_scope_after_preview_cancels_previously_approved_operation(api_case, api_scope, http_operation):
    prepared = prepare_http(api_case, api_scope)
    assert api_case.client.delete("/api/security/scopes/" + api_scope["id"]).status_code == 200
    response = api_case.client.post(f"/api/security/jobs/{prepared['approval_id']}/decision", json={"approved": True})
    assert response.status_code == 200 and response.json()["ok"] is False
    assert response.json()["code"] == "scope_revoked" and response.json()["source"] == "permission"
    http_operation.assert_not_called()


def test_change_scope_revision_after_preview_cancels_operation(api_case, api_scope, http_operation):
    prepared = prepare_http(api_case, api_scope)
    with api_case.store.connection() as db:
        db.execute("UPDATE scopes SET revision=2 WHERE id=?", (api_scope["id"],))
    response = api_case.client.post(f"/api/security/jobs/{prepared['approval_id']}/decision", json={"approved": True})
    assert not response.json()["ok"] and response.json()["code"] == "scope_changed"
    http_operation.assert_not_called()


def test_expired_or_mutated_pending_approval_cannot_execute(api_case, api_scope, http_operation):
    expired = prepare_http(api_case, api_scope)["approval_id"]
    api_case.pending[expired]["deadline"] = 0
    assert api_case.client.post(f"/api/security/jobs/{expired}/decision", json={"approved": True}).status_code == 404
    changed = prepare_http(api_case, api_scope)["approval_id"]
    api_case.pending[changed]["args"]["target"] = "http://127.0.0.1:9999/"
    assert api_case.client.post(f"/api/security/jobs/{changed}/decision", json={"approved": True}).status_code == 409
    http_operation.assert_not_called()


def test_pending_approval_resource_limit_without_sending_network_requests(api_case, api_scope, http_operation):
    for _ in range(32):
        prepare_http(api_case, api_scope)
    response = api_case.client.post("/api/security/jobs", json={"tool": "security_http", "mode": "AGENT",
        "args": {"scope_id": api_scope["id"], "target": "http://127.0.0.1/"}})
    assert response.status_code == 429 and len(api_case.pending) == 32
    http_operation.assert_not_called()


def test_outside_scope_and_invalid_ports_never_create_pending_operations(api_case, api_scope, http_operation):
    cases = [{"tool": "security_http", "args": {"scope_id": api_scope["id"], "target": "http://10.23.45.67/"}},
             {"tool": "security_tcp", "args": {"scope_id": api_scope["id"], "target": "127.0.0.1", "ports": [True]}},
             {"tool": "security_tcp", "args": {"scope_id": api_scope["id"], "target": "127.0.0.1", "ports": []}}]
    for payload in cases:
        response = api_case.client.post("/api/security/jobs", json={"mode": "AGENT", **payload})
        assert response.status_code == 400, response.text
    assert api_case.pending == {}
    http_operation.assert_not_called()


def test_upload_is_raw_local_inert_hashed_and_analysis_never_executes_sample(api_case, monkeypatch):
    import subprocess
    marker = api_case.workspace / "must-not-be-created.txt"
    content = f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n".encode()
    operation = Mock(side_effect=AssertionError("uploaded sample must never run"))
    monkeypatch.setattr(subprocess, "Popen", operation)
    uploaded = api_case.client.post("/api/security/samples?name=owned.py", content=content, headers={"Content-Type": "application/octet-stream"})
    assert uploaded.status_code == 200, uploaded.text
    sample = uploaded.json()
    assert sample["sha256"] == hashlib.sha256(content).hexdigest()
    assert sample["size"] == len(content)
    assert "path" not in sample
    path, _ = api_case.store.sample(sample["id"])
    assert path.suffix == ".bin" and path.read_bytes() == content
    response = api_case.client.post("/api/security/jobs", json={"tool": "security_static_file", "mode": "PLAN", "args": {"sample_id": sample["id"]}})
    assert response.status_code == 200 and response.json()["ok"]
    assert response.json()["executed_target"] is False
    assert not marker.exists()
    operation.assert_not_called()


@pytest.mark.parametrize("name", ["../outside.exe", ".env", "id_rsa", "C:\\outside.exe", "name\nexe"])
def test_upload_rejects_paths_credentials_and_control_names(api_case, name):
    response = api_case.client.post("/api/security/samples", params={"name": name}, content=b"harmless lab")
    assert response.status_code == 400
    assert api_case.client.get("/api/security/samples").json() == {"samples": []}


def test_upload_stream_limit_rejects_overflow_before_ingest(api_case):
    response = api_case.client.post("/api/security/samples?name=lab.bin", content=b"a" * (MAX_SAMPLE + 1))
    assert response.status_code == 413
    assert api_case.store.list_samples() == []


def test_dork_preview_never_sends_query_or_resolves_target(api_case, api_scope, monkeypatch):
    from nexus.security import network
    dns = Mock(side_effect=AssertionError("preview must not resolve DNS"))
    search = Mock(side_effect=AssertionError("preview must not execute search"))
    monkeypatch.setattr(network.socket, "getaddrinfo", dns)
    monkeypatch.setattr(network, "run_osint", search)
    response = api_case.client.post("/api/security/dorks/preview", json={"scope_id": api_scope["id"],
        "domain": "example.com", "operators": {"intitle": "technical report"}, "document_type": "pdf", "max_results": 3})
    assert response.status_code == 200 and response.json()["ok"]
    assert response.json()["data"]["query"] == 'site:example.com intitle:"technical report" filetype:pdf'
    dns.assert_not_called()
    search.assert_not_called()


def test_osint_job_exposes_full_query_before_search_and_revoked_approval_has_no_effect(api_case, api_scope, monkeypatch):
    tools = Mock()
    monkeypatch.setattr(api_case.center, "tool_factory", lambda: tools)
    args = {"scope_id": api_scope["id"], "domain": "example.com", "keywords": ["API", "reference"],
            "exclusions": ["draft", "old"], "max_results": 2}
    response = api_case.client.post("/api/security/jobs", json={"tool": "security_osint", "mode": "RESEARCH", "args": args})
    assert response.status_code == 200, response.text
    prepared = response.json()
    assert prepared["requires_approval"] is True
    assert prepared["preview"]["query"] == 'site:example.com "API" "reference" -"draft" -"old"'
    assert prepared["preview"]["scope_revision"] == api_scope["revision"]
    tools.execute.assert_not_called()
    assert api_case.client.delete("/api/security/scopes/" + api_scope["id"]).status_code == 200
    decided = api_case.client.post(f"/api/security/jobs/{prepared['approval_id']}/decision", json={"approved": True})
    assert decided.status_code == 200 and not decided.json()["ok"]
    assert decided.json()["code"] == "scope_revoked"
    tools.execute.assert_not_called()


def test_approved_osint_preserves_previewed_array_terms_and_omits_internal_identifiers(api_case, api_scope, monkeypatch):
    tools = Mock()
    tools.execute.return_value = {"ok": True, "provider": "synthetic", "results": [{"url": "https://example.com/guide.pdf", "title": "Owned public guide"}]}
    monkeypatch.setattr(api_case.center, "tool_factory", lambda: tools)
    args = {"scope_id": api_scope["id"], "scope_revision": api_scope["revision"], "domain": "example.com",
            "keywords": ["public API"], "exclusions": ["draft"], "document_type": "pdf", "max_results": 2}
    prepared = api_case.client.post("/api/security/jobs", json={"tool": "security_osint", "mode": "RESEARCH", "args": args}).json()
    tools.execute.assert_not_called()
    result = api_case.client.post(f"/api/security/jobs/{prepared['approval_id']}/decision", json={"approved": True})
    assert result.status_code == 200 and result.json()["ok"], result.text
    tools.execute.assert_called_once_with("search_web", {"query": prepared["preview"]["query"], "max_results": 2})
    tools.close.assert_called_once()


def test_tool_failure_and_missing_optional_tool_are_saved_as_failure_reports(api_case, api_scope, monkeypatch):
    from nexus.security import network
    monkeypatch.setattr(network, "_nmap_path", lambda: None)
    prepared = api_case.client.post("/api/security/jobs", json={"tool": "security_nmap", "mode": "AGENT", "args": {
        "scope_id": api_scope["id"], "target": "127.0.0.1", "ports": [80]}}).json()
    response = api_case.client.post(f"/api/security/jobs/{prepared['approval_id']}/decision", json={"approved": True})
    assert response.status_code == 200 and response.json()["ok"] is False
    assert response.json()["code"] == "TOOL_UNAVAILABLE"
    report_id = response.json()["report_id"]
    reports = api_case.client.get("/api/security/reports").json()["reports"]
    assert reports[0]["id"] == report_id and reports[0]["ok"] is False


def test_reports_download_json_markdown_and_refuse_unknown_format(api_case):
    saved = api_case.store.save_report("security_code_audit", {"ok": True, "findings": [], "note": "hypotheses require validation"})
    url = "/api/security/reports/" + saved["id"]
    response = api_case.client.get(url)
    assert response.status_code == 200 and response.json()["result"]["ok"]
    assert "attachment" in response.headers["content-disposition"]
    markdown = api_case.client.get(url + "?format=md")
    assert markdown.status_code == 200 and "text/markdown" in markdown.headers["content-type"]
    assert "hipóteses" in markdown.text or "achados exigem validação" in markdown.text
    assert api_case.client.get(url + "?format=exe").status_code == 400
    assert api_case.client.get("/api/security/reports/absent").status_code == 400


def test_security_status_combines_existing_projects_agents_and_real_capability_flags(api_case):
    response = api_case.client.get("/api/security/status")
    assert response.status_code == 200
    result = response.json()
    assert len(result["agents"]) == 16 and result["projects"][0]["id"] == "demo"
    assert {row["id"] for row in result["agents"]} >= {"red_team", "osint", "rea", "malware_lab", "blue_team", "code_auditor",
        "security_orchestrator", "web_auditor", "auth_auditor", "database_auditor", "remediation_engineer", "report_analyst"}
    assert result["limits"]["dynamic_execution"] is False
    assert result["capabilities"]["dynamic_analysis"]["available"] is False
    assert result["scopes"] == [] and result["samples"] == []


def test_two_human_jobs_share_the_inference_resource_slot(api_case, monkeypatch):
    from nexus.security import platform
    guard = threading.Lock()
    active = maximum = calls = 0

    def observe(section="overview"):
        nonlocal active, maximum, calls
        with guard:
            active += 1
            maximum = max(maximum, active)
            calls += 1
        try:
            time.sleep(0.05)
            return {"ok": True, "section": section, "read_only": True}
        finally:
            with guard:
                active -= 1

    monkeypatch.setattr(platform, "blue_status", observe)
    payload = {"tool": "security_windows", "mode": "PLAN", "args": {"section": "overview"}}
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(api_case.client.post, "/api/security/jobs", json=payload) for _ in range(2)]
        results = [future.result(timeout=5) for future in futures]
    assert all(response.status_code == 200 and response.json()["ok"] for response in results)
    assert calls == 2 and maximum == 1


@pytest.fixture
def integrated_app_case(monkeypatch):
    # Existing support isolates app singletons before importing nexus.app.
    import test_api as support
    scenario = support.ApiTests(methodName="runTest")
    scenario.setUp()
    center = SecurityCenter(scenario.data, scenario.workspace, lambda: [{"id": "demo", "path": "demo"}])
    monkeypatch.setattr(center, "catalog", lambda: {"external_tools": {}})
    monkeypatch.setattr(support.api, "get_security", lambda: center)
    # install_security_routes captured get_security's original function; that
    # function still reads the isolated globals provided by the established fixture.
    yield scenario
    scenario.tearDown()


def test_actual_app_security_routes_keep_existing_auth_origin_and_host_guards(integrated_app_case):
    case = integrated_app_case
    assert case.client.get("/api/security/scopes").status_code == 401
    assert case.client.post("/api/security/scopes", json={}).status_code == 401
    case.authenticate()
    for headers in [{"Origin": "https://outside.example"}, {"Host": "outside.example"}, {"Sec-Fetch-Site": "cross-site"}]:
        response = case.client.post("/api/security/scopes", json={"authorization_confirmed": True}, headers=headers)
        assert response.status_code == 403
    assert case.client.get("/api/security/scopes").json() == {"scopes": []}


def test_actual_app_security_operations_preserve_existing_sessions_and_models(integrated_app_case):
    case = integrated_app_case
    case.authenticate()
    before = case.client.get("/api/sessions").json()
    response = case.client.post("/api/security/jobs", json={"tool": "security_context", "args": {}, "mode": "PLAN"})
    assert response.status_code == 200 and response.json()["ok"]
    assert case.client.get("/api/sessions").json() == before
    assert case.engine.requests == []


@pytest.mark.parametrize("method,path", [("POST", "/api/security/scopes"), ("POST", "/api/security/jobs"),
    ("PUT", "/api/security/scopes"), ("PATCH", "/api/security/jobs")])
def test_actual_app_rejects_oversized_chunked_json_without_content_length_or_effects(integrated_app_case, method, path):
    case = integrated_app_case
    case.authenticate()
    encoded = json.dumps({"tool": "security_context", "args": {}, "mode": "PLAN", "padding": "x" * 2_500_001}).encode()
    chunks = (encoded[offset:offset + 65536] for offset in range(0, len(encoded), 65536))
    response = case.client.request(method, path, content=chunks, headers={"Content-Type": "application/json"})
    assert "content-length" not in response.request.headers
    assert response.request.headers["transfer-encoding"] == "chunked"
    assert response.status_code == 413, response.text
    assert case.client.get("/api/security/scopes").json() == {"scopes": []}
    assert case.client.get("/api/security/reports").json() == {"reports": []}
    assert case.engine.requests == []
    assert not any(call.args[0] in {"security_scope_created", "security_operation", "security_approval_requested"}
                   for call in case.audit.add.call_args_list)


def test_actual_app_replays_valid_chunked_json_to_route_handler(integrated_app_case):
    case = integrated_app_case
    case.authenticate()
    encoded = b'{"tool":"security_context","args":{},"mode":"PLAN"}'
    chunks = (encoded[offset:offset + 7] for offset in range(0, len(encoded), 7))
    response = case.client.post("/api/security/jobs", content=chunks, headers={"Content-Type": "application/json"})
    assert "content-length" not in response.request.headers
    assert response.status_code == 200 and response.json()["ok"], response.text
    assert response.json()["tool"] == "security_context"
    assert case.engine.requests == []


def test_actual_app_keeps_larger_sample_upload_stream_separate_from_json_limit(integrated_app_case):
    case = integrated_app_case
    case.authenticate()
    content = b"a" * 2_500_001
    chunks = (content[offset:offset + 65536] for offset in range(0, len(content), 65536))
    response = case.client.post("/api/security/samples?name=harmless-large.bin", content=chunks,
                                headers={"Content-Type": "application/octet-stream"})
    assert "content-length" not in response.request.headers
    assert response.status_code == 200, response.text
    assert response.json()["size"] == len(content)
    assert response.json()["sha256"] == hashlib.sha256(content).hexdigest()
