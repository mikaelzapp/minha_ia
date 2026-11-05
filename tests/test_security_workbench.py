"""Security Center 2 integration, permissions and supervised copy regression.

Only synthetic local projects and loopback laboratories are used. Scanner mocks
exercise orchestration and are not reported as native scanner executions.
"""
import asyncio
from contextlib import asynccontextmanager
import copy
import json
from pathlib import Path
import threading
import time
from types import SimpleNamespace
from unittest.mock import Mock
import uuid

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from nexus.security.center import SecurityCenter
from nexus.security.common import SecurityError, utcnow
from nexus.security import remediation, reporting, scanners, appsec, network
from nexus.security.workbench import Workbench, digest
from nexus.security.workbench_api import install_workbench_routes
from scripts.security_lab import lab_server


@pytest.fixture
def case(tmp_path, monkeypatch):
    workspace = tmp_path / "workspaces"
    project = workspace / "demo"
    project.mkdir(parents=True)
    (project / "app.py").write_text("answer = 1\n", encoding="utf-8")
    (project / ".env").write_text("SECRET=must-stay-original-only\n")
    data = tmp_path / "data"
    projects = [{"id": "demo", "path": "demo"}]
    center = SecurityCenter(data, workspace, lambda: projects)
    monkeypatch.setattr(center, "catalog", lambda: {})
    monkeypatch.setattr(remediation.shutil, "which", lambda _: None)
    monkeypatch.setattr("nexus.security.workbench.psutil.virtual_memory", lambda: SimpleNamespace(available=8 * 1024**3, percent=35))
    w = Workbench(lambda: center)
    return SimpleNamespace(w=w, center=center, store=center.store, project=project,
                           workspace=workspace, data=data, projects=projects)


@pytest.fixture
def api(case):
    semaphore = asyncio.Semaphore(1)
    activity = Mock()
    async def blocking(function, *args):
        return await asyncio.to_thread(function, *args)
    @asynccontextmanager
    async def lifespan(app):
        yield
        await close()
    application = FastAPI(lifespan=lifespan)
    close = install_workbench_routes(application, lambda: case.w, blocking, lambda: semaphore, lambda: activity)
    with TestClient(application, raise_server_exceptions=False) as client:
        yield SimpleNamespace(client=client, case=case, activity=activity)


def scope_for(case, port=8081, **changes):
    return case.store.create_scope({"name": "Synthetic loopback", "targets": ["127.0.0.1"],
        "allowed_tests": ["http_headers", "tcp_connect", "appsec_sqli", "appsec_auth", "nuclei", "zap", "nmap_service", "asset_inventory"],
        "allowed_ports": [port], "environment": "lab", "environment_class": "lab",
        "hosting": "own", "authorization_confirmed": True, **changes})


def queue(case, payload):
    preview = case.w.preview(payload)
    approved = case.w.decision(preview["approval_id"], True)
    return approved["job"]["id"]


def source_report(case, *, engine="appsec_sqli", target="http://127.0.0.1:8081/sqli", scope=None):
    finding = {"id": "synthetic-finding", "title": "Synthetic SQLi", "severity": "high", "cwe": "CWE-89",
               "confirmed": True, "parameter": "name", "endpoint": target, "evidence": {"synthetic": True}}
    source_run = {"id": uuid.uuid4().hex, "engine": engine, "state": "completed", "created_at": utcnow(),
                  "project_id": "demo", "target": target, "events": [], "ok": True}
    case.w._save(source_run)
    saved = case.store.save_report("v2:" + engine, {"schema": "nexus-security-report/2", "ok": True,
        "project_id": "demo", "target": target, "scope": scope, "engine": engine,
        "run_id": source_run["id"], "findings": [finding], "coverage": {"synthetic": True}})
    return saved


def proposed(case, **changes):
    source = source_report(case)
    args = {"report_id": source["id"], "project_id": "demo", "finding_ids": ["synthetic-finding"],
            "edits": [{"path": "app.py", "content": "answer = 2\n"}], **changes}
    return remediation.Remediation(case.w).preview(args)


def prepare_plan(case):
    p = proposed(case)
    job = case.w.decision(p["approval_id"], True)["job"]
    run = case.w.execute(job["id"])
    assert run["ok"], run
    return remediation.Remediation(case.w).get(p["preview"]["plan_id"])


def apply_plan(case, plan):
    p = remediation.Remediation(case.w).apply_preview(plan["id"])
    job = case.w.decision(p["approval_id"], True)["job"]
    result = case.w.execute(job["id"])
    assert result["ok"], result
    return remediation.Remediation(case.w).get(plan["id"])


def completed(api, identity):
    for _ in range(200):
        response = api.client.get("/api/security/v2/runs/" + identity)
        assert response.status_code == 200
        run = response.json()
        if run["state"] not in {"queued", "running", "cancelling"}:
            return run
        time.sleep(.01)
    pytest.fail("Synthetic job did not finish within two seconds")


def test_status_lists_ten_independent_modules_and_absent_native_tools(api):
    response = api.client.get("/api/security/v2/status")
    assert response.status_code == 200, response.text
    value = response.json()
    assert len(value["modules"]) == 10
    assert {"reverse", "auth", "remediation", "reports"} <= {m["id"] for m in value["modules"]}
    assert value["limits"]["concurrency"] == 1 and not value["limits"]["dynamic_sample_execution"]
    assert value["ghidra"]["target_executed"] is False


@pytest.mark.parametrize("value", ["true", 1, None, [], {}])
def test_decision_api_requires_strict_boolean(api, value):
    preview = api.case.w.preview({"engine": "windows", "args": {"section": "overview"}})
    response = api.client.post("/api/security/v2/approvals/" + preview["approval_id"] + "/decision", json={"approved": value})
    assert response.status_code == 422
    assert not api.case.w.runs()


def test_decision_api_rejects_argument_injection(api):
    p = api.case.w.preview({"engine": "windows", "args": {"section": "overview"}})
    response = api.client.post("/api/security/v2/approvals/" + p["approval_id"] + "/decision", json={"approved": True, "args": {"section": "tasks"}})
    assert response.status_code == 422
    assert not api.case.w.runs()


def test_denied_and_single_use_have_no_effect(case, monkeypatch):
    operation = Mock(side_effect=AssertionError("denied action must not execute"))
    monkeypatch.setattr(case.center, "execute", operation)
    p = case.w.preview({"engine": "windows", "args": {"section": "overview"}})
    assert case.w.decision(p["approval_id"], False)["executed"] is False
    with pytest.raises(SecurityError):
        case.w.decision(p["approval_id"], True)
    operation.assert_not_called()
    assert not case.w.runs()


@pytest.mark.parametrize("change", ["expired", "mutated", "configuration"])
def test_approval_expiry_mutation_and_config_drift_block_execution(case, change):
    p = case.w.preview({"engine": "windows", "args": {"section": "overview"}})
    if change == "expired":
        case.w.pending[p["approval_id"]]["deadline"] = 0
    elif change == "mutated":
        case.w.pending[p["approval_id"]]["payload"]["args"]["section"] = "tasks"
    else:
        case.w.config_path.write_text('{"changed":true}')
    with pytest.raises(SecurityError):
        case.w.decision(p["approval_id"], True)
    assert not case.w.live


def test_network_approval_is_bound_to_scope_and_revocation(case):
    scope = scope_for(case)
    p = case.w.preview({"engine": "http_headers", "scope_id": scope["id"], "args": {"target": "http://127.0.0.1:8081/"}})
    case.store.revoke_scope(scope["id"])
    with pytest.raises(SecurityError, match="revogado"):
        case.w.decision(p["approval_id"], True)
    assert not case.w.runs()


def test_scope_revalidated_after_queue_before_network(case, monkeypatch):
    scope = scope_for(case)
    operation = Mock(side_effect=AssertionError("must not execute revoked scope"))
    monkeypatch.setattr(network, "inspect_http", operation)
    identity = queue(case, {"engine": "http_headers", "scope_id": scope["id"], "args": {"target": "http://127.0.0.1:8081/"}})
    case.store.revoke_scope(scope["id"])
    result = case.w.execute(identity)
    assert not result["ok"] and result["code"] == "scope_revoked"
    operation.assert_not_called()


def test_cancel_queued_never_calls_adapter(case, monkeypatch):
    operation = Mock(side_effect=AssertionError("cancelled operation must not execute"))
    monkeypatch.setattr(case.center, "execute", operation)
    identity = queue(case, {"engine": "windows", "args": {"section": "overview"}})
    assert case.w.cancel(identity)["cancellable"]
    run = case.w.execute(identity)
    assert run["state"] == "cancelled" and not run["ok"]
    operation.assert_not_called()


def test_restart_marks_unfinished_as_interrupted(case):
    identity = queue(case, {"engine": "windows", "args": {"section": "overview"}})
    restarted = Workbench(lambda: case.center)
    assert restarted.run(identity)["state"] == "interrupted"
    assert not restarted.run(identity)["ok"]


def test_api_real_async_job_records_report_and_audit(api, monkeypatch):
    monkeypatch.setattr(api.case.center, "execute", lambda *a: {"ok": True, "data": ["rows"], "findings": []})
    p = api.client.post("/api/security/v2/preview", json={"engine": "windows", "args": {"section": "processes"}}).json()
    response = api.client.post("/api/security/v2/approvals/" + p["approval_id"] + "/decision", json={"approved": True})
    assert response.status_code == 200
    run = completed(api, response.json()["job"]["id"])
    assert run["state"] == "completed" and run["report_id"]
    assert api.case.store.report(run["report_id"])["result"]["tools_used"] == ["windows"]
    deadline = time.monotonic() + 2
    while not any(call.args[0] == "security_v2_finished" for call in api.activity.add.call_args_list) and time.monotonic() < deadline:
        time.sleep(.01)
    assert any(call.args[0] == "security_v2_finished" for call in api.activity.add.call_args_list)


@pytest.mark.parametrize("engine", ["nuclei", "zap", "nmap_service"])
def test_unconfigured_external_engine_is_not_implicitly_executed(case, monkeypatch, engine):
    operation = Mock(side_effect=AssertionError("must not launch scanner"))
    monkeypatch.setattr(scanners.subprocess, "Popen", operation)
    scope = scope_for(case)
    args = {"target": "http://127.0.0.1:8081/"}
    if engine == "nmap_service":
        args["ports"] = [8081]
    identity = queue(case, {"engine": engine, "scope_id": scope["id"], "args": args})
    run = case.w.execute(identity)
    assert not run["ok"] and "unavailable" in run["result"]["code"]
    operation.assert_not_called()


def test_missing_ghidra_is_explicit_unavailable_not_fake_decompile(case, monkeypatch):
    sample = case.store.ingest("owned.exe", b"MZ" + bytes(32))
    monkeypatch.delenv("GHIDRA_HOME", raising=False)
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    identity = queue(case, {"engine": "ghidra", "sample_id": sample["id"], "args": {}})
    run = case.w.execute(identity)
    assert not run["ok"] and not run["result"]["target_executed"]
    assert run["result"]["code"] == "ghidra_unavailable" and "functions" not in run["result"]


@pytest.mark.parametrize("format", ["json", "md", "html"])
def test_report_exports_redact_credentials_and_html_is_inert(api, format):
    row = api.case.store.save_report("v2:test", {"ok": True, "password": "synthetic-private-value",
        "evidence": '<script>alert("fixture")</script>\nAuthorization: Bearer synthetic-private-token',
        "findings": []})
    response = api.client.get(f"/api/security/v2/reports/{row['id']}?format={format}")
    assert response.status_code == 200
    assert "synthetic-private-value" not in response.text and "synthetic-private-token" not in response.text
    if format == "html":
        assert "<script>" not in response.text and "&lt;script&gt;" in response.text
        assert "default-src 'none'" in response.text


def test_report_delete_requires_single_use_human_approval(api):
    row = api.case.store.save_report("v2:test", {"ok": True, "findings": []})
    p = api.client.post(f"/api/security/v2/reports/{row['id']}/delete-preview").json()
    assert api.case.store.report(row["id"])
    response = api.client.post(f"/api/security/v2/approvals/{p['approval_id']}/decision", json={"approved": True})
    assert response.status_code == 200 and response.json()["deleted"] == row["id"]
    with pytest.raises(SecurityError):
        api.case.store.report(row["id"])


def test_correlation_merges_same_weakness_location_parameter_but_preserves_sources():
    rows = reporting.correlate([
        {"engine": "zap", "cwe": "CWE-89", "endpoint": "http://127.0.0.1/search", "parameter": "q", "severity": "medium"},
        {"engine": "nuclei", "cwe": "CWE-89", "endpoint": "http://127.0.0.1/search", "parameter": "q", "severity": "high", "confirmed": True},
        {"engine": "code", "cwe": "CWE-89", "endpoint": "http://127.0.0.1/search", "parameter": "id", "severity": "low"}])
    assert len(rows) == 2
    merged = next(row for row in rows if row["parameter"] == "q")
    assert merged["sources"] == ["nuclei", "zap"] and merged["occurrences"] == 2
    assert merged["severity"] == "high" and merged["confirmed"]


def test_unknown_location_findings_are_not_blindly_merged():
    rows = reporting.correlate([{ "cwe": "CWE-89", "title": "A"}, {"cwe": "CWE-89", "title": "B"}])
    assert len(rows) == 2


def test_untrusted_scanner_classification_and_output_shapes():
    assert reporting.correlate([{"info": {"classification": ["malformed"]}, "title": "Fixture"}])
    with pytest.raises(ValueError):
        reporting.correlate({"not": "a findings list"})


def test_correlation_endpoint_rejects_cross_project_reports(api):
    ids = [api.case.store.save_report("v2:test", {"ok": True, "project_id": p, "target": "http://127.0.0.1/", "findings": []})["id"] for p in ("demo", "other")]
    assert api.client.post("/api/security/v2/reports/correlate", json={"report_ids": ids}).status_code == 400


def test_remediation_requires_selected_real_findings_and_matching_project(case):
    source = source_report(case)
    with pytest.raises(SecurityError):
        remediation.Remediation(case.w).preview({"report_id": source["id"], "project_id": "demo",
            "finding_ids": ["not-real"], "edits": [{"path": "app.py", "content": "answer=2\n"}]})
    assert not remediation.Remediation(case.w).list()["plans"]


@pytest.mark.parametrize("path", ["../outside.py", ".env", "data/private.py", "new-file.py"])
def test_remediation_refuses_escape_sensitive_and_uncopied_files(case, path):
    with pytest.raises(ValueError):
        proposed(case, edits=[{"path": path, "content": "safe = True\n"}])
    assert (case.project / "app.py").read_text() == "answer = 1\n"


def test_remediation_tests_require_explicit_execution_approval(case):
    with pytest.raises(SecurityError, match="autorização"):
        proposed(case, tests=[["python", "-m", "pytest"]])


def test_remediation_preview_has_diff_and_no_write_until_approved(case):
    p = proposed(case)
    assert "+answer = 2" in p["preview"]["diffs"][0]["diff"]
    assert not (case.w.root / "remediation").exists()
    assert (case.project / "app.py").read_text() == "answer = 1\n"
    case.w.decision(p["approval_id"], False)
    assert not remediation.Remediation(case.w).list()["plans"]


def test_prepare_copies_verified_source_and_omits_secrets(case):
    plan = prepare_plan(case)
    branch = Path(plan["branch_path"])
    assert (branch / "app.py").read_text() == "answer = 1\n"
    assert not (branch / ".env").exists()
    assert plan["original_modified"] is False and plan["state"] == "prepared"
    assert (case.project / ".env").read_text() == "SECRET=must-stay-original-only\n"


def test_source_mutation_after_preview_prevents_preparation(case):
    p = proposed(case)
    (case.project / "app.py").write_text("answer = 99\n")
    job = case.w.decision(p["approval_id"], True)["job"]
    result = case.w.execute(job["id"])
    assert not result["ok"] and result["code"] == "source_changed"
    assert not (case.w.root / "remediation").exists()


def test_apply_only_approved_copy_diff_and_records_developer_history(case):
    plan = apply_plan(case, prepare_plan(case))
    assert Path(plan["branch_path"], "app.py").read_text() == "answer = 2\n"
    assert (case.project / "app.py").read_text() == "answer = 1\n"
    assert plan["state"] == "applied" and plan["changes"][0]["change_id"]
    assert plan["tests_ok"] is True and not plan["original_modified"]


def test_branch_drift_after_apply_approval_prevents_overwrite(case):
    plan = prepare_plan(case)
    p = remediation.Remediation(case.w).apply_preview(plan["id"])
    Path(plan["branch_path"], "app.py").write_text("answer = 77\n")
    job = case.w.decision(p["approval_id"], True)["job"]
    result = case.w.execute(job["id"])
    assert not result["ok"] and result["code"] == "branch_changed"
    assert Path(plan["branch_path"], "app.py").read_text() == "answer = 77\n"


def test_deleted_project_revokes_pending_apply(case):
    plan = prepare_plan(case)
    p = remediation.Remediation(case.w).apply_preview(plan["id"])
    case.projects.clear()
    job = case.w.decision(p["approval_id"], True)["job"]
    result = case.w.execute(job["id"])
    assert not result["ok"] and result["code"] == "project_not_found"
    assert Path(plan["branch_path"], "app.py").read_text() == "answer = 1\n"


def test_revision_compare_and_swap_blocks_stale_apply(case):
    plan = prepare_plan(case)
    p = remediation.Remediation(case.w).apply_preview(plan["id"])
    plan["revision"] += 1
    remediation.Remediation(case.w).save(plan)
    job = case.w.decision(p["approval_id"], True)["job"]
    result = case.w.execute(job["id"])
    assert not result["ok"]
    assert Path(plan["branch_path"], "app.py").read_text() == "answer = 1\n"


@pytest.mark.parametrize("validation,expected", [("inconclusive", "inconclusive"), ("no_finding_in_coverage", "absent_in_revalidated_coverage")])
def test_revalidation_does_not_turn_missing_baseline_into_resolution(case, monkeypatch, validation, expected):
    plan = apply_plan(case, prepare_plan(case))
    monkeypatch.setattr(appsec, "run_sqli", lambda *a, **kw: {"ok": True, "validation": validation, "findings": []})
    payload = {"plan_id": plan["id"], "revision": plan["revision"], "scope_id": scope_for(case)["id"], "args": {"target": "http://127.0.0.1:8081/sqli"}}
    result = remediation.Remediation(case.w).revalidate(payload, threading.Event(), lambda _: None)
    assert result["comparison"][0]["status"] == expected
    assert not result.get("resolved", False)


def test_real_loopback_sqli_runs_through_workbench_then_fixed(case):
    with lab_server() as lab:
        scope = scope_for(case, lab.server_port)
        args = {"target": lab.url + "/sqli", "lab_confirmation": True}
        lab.fixed = False
        before = case.w.execute(queue(case, {"engine": "appsec_sqli", "scope_id": scope["id"], "project_id": "demo", "args": args}))
        assert before["ok"] and before["findings_count"] >= 1, before
        lab.fixed = True
        after = case.w.execute(queue(case, {"engine": "appsec_sqli", "scope_id": scope["id"], "project_id": "demo", "args": args}))
        assert after["ok"] and after["findings_count"] == 0, after
        assert after["result"]["validation"] == "no_finding_in_coverage"
        assert case.store.report(before["report_id"])["result"]["scope"]["id"] == scope["id"]


def test_real_auth_tokens_and_fictitious_passwords_never_enter_persisted_run(case):
    with lab_server() as lab:
        lab.fixed = False
        scope = scope_for(case, lab.server_port)
        identity = queue(case, {"engine": "appsec_auth", "scope_id": scope["id"], "project_id": "demo", "args": {
            "target": lab.url, "lab_confirmation": True, "synthetic_accounts_confirmed": True}})
        run = case.w.execute(identity)
        assert run["ok"] and run["findings_count"] >= 1, run
        serialized = json.dumps(run) + json.dumps(case.store.report(run["report_id"]))
        assert "NEXUS_LAB_PASSWORD" not in serialized
        for session in lab.sessions:
            assert session not in serialized
        assert identity not in case.w.live


def test_chat_tool_uses_current_configuration_and_preserves_scope(case):
    case.center.workbench = lambda: case.w
    with lab_server() as lab:
        scope = scope_for(case, lab.server_port)
        state = case.center.execute("security_workbench", {})
        args = {"engine": "appsec_sqli", "scope_id": scope["id"], "scope_revision": scope["revision"],
            "target": lab.url + "/sqli", "arguments": {"lab_confirmation": True}, "configuration_digest": state["configuration_digest"]}
        before = len(lab.observations)
        display = case.center.approval("security_audit_v2", args)
        assert display["scope_id"] == scope["id"] and len(lab.observations) == before
        result = case.center.execute("security_audit_v2", args)
        assert result["ok"] and result["data"]["state"] == "completed"
        assert result["findings"] and len(lab.observations) > before
        assert not case.w.pending


def test_chat_tool_denies_config_drift_and_scope_revocation(case):
    case.center.workbench = lambda: case.w
    scope = scope_for(case)
    args = {"engine": "appsec_sqli", "scope_id": scope["id"], "target": "http://127.0.0.1:8081/sqli",
        "configuration_digest": "0" * 64, "arguments": {"lab_confirmation": True}}
    with pytest.raises(SecurityError, match="Configuração mudou"):
        case.center.approval("security_audit_v2", args)
    args["configuration_digest"] = digest({})
    case.store.revoke_scope(scope["id"])
    result = case.center.execute("security_audit_v2", args)
    assert not result["ok"] and result["code"] == "scope_revoked"


def test_security_v2_tool_never_appears_in_readonly_operational_modes(case):
    for mode in ("CHAT", "PLAN", "CODE", "REVIEW", "RESEARCH"):
        assert "security_audit_v2" not in {x["function"]["name"] for x in case.center.schemas(mode)}
    assert "security_audit_v2" in {x["function"]["name"] for x in case.center.schemas("AGENT")}


@pytest.mark.parametrize("payload", [{"engine": "appsec_sqli", "args": {}}, {"engine": "appsec_sqli", "scope_id": "bad", "args": {}}])
def test_missing_scope_is_typed_error_not_internal_failure(api, payload):
    response = api.client.post("/api/security/v2/preview", json=payload)
    assert response.status_code == 400 and response.json()["code"] == "scope_required"


def test_secret_redaction_preserves_nonsecret_cookie_evidence():
    value = reporting.sanitize({"cookie_attributes": [{"httponly": False, "samesite": "lax"}],
        "credentials_retained": False, "password": "arbitrary secret", "authorization": "arbitrary header"})
    assert value["cookie_attributes"][0]["httponly"] is False
    assert value["credentials_retained"] is False
    assert value["password"] == value["authorization"] == "[redigido]"


def test_approved_process_test_can_be_cancelled_without_waiting_full_timeout():
    import sys
    from nexus.security.common import run_process
    event = threading.Event()
    timer = threading.Timer(0.2, event.set)
    started = time.monotonic()
    timer.start()
    try:
        result = run_process([sys.executable, "-I", "-c", "import time;time.sleep(10)"], timeout=15, cancel=event)
    finally:
        timer.cancel()
    assert result["cancelled"] and not result["ok"]
    assert time.monotonic() - started < 5


def test_retention_preview_and_denial_preserve_data_then_approval_removes_only_selected(case):
    identity = queue(case, {"engine": "code_audit", "project_id": "demo", "args": {}})
    run = case.w.execute(identity)
    old_report = case.store.save_report("legacy", {"ok": True, "findings": []})
    preview = case.w.retention_preview({"before": "2099-01-01"})
    assert len(preview["preview"]["runs"]) == 1
    case.w.decision(preview["approval_id"], False)
    assert case.w.run(identity)["report_id"] == run["report_id"]
    preview = case.w.retention_preview({"before": "2099-01-01"})
    result = case.w.decision(preview["approval_id"], True)
    assert result["deleted_runs"] == result["deleted_reports"] == 1
    assert case.store.report(old_report["id"])["operation"] == "legacy"
    assert (case.project / "app.py").exists()


def test_retention_rechecks_new_plan_dependencies_and_preserves_active_runs(case):
    identity = queue(case, {"engine": "code_audit", "project_id": "demo", "args": {}})
    run = case.w.execute(identity)
    preview = case.w.retention_preview({"before": "2099-01-01"})
    plan = {"id": uuid.uuid4().hex, "created_at": utcnow(), "source_report_id": run["report_id"]}
    remediation.Remediation(case.w).save(plan)
    with pytest.raises(SecurityError) as error:
        case.w.decision(preview["approval_id"], True)
    assert error.value.code == "retention_changed"
    assert not case.w.retention_preview({"before": "2099-01-01"})["preview"]["runs"]
    pending_id = queue(case, {"engine": "code_audit", "project_id": "demo", "args": {}})
    assert not case.w.retention_preview({"before": "2099-01-01"})["preview"]["runs"]
    case.w.cancel(pending_id)
    case.w.execute(pending_id)


def test_official_installation_preview_never_downloads_and_denial_keeps_tools_absent(api, monkeypatch):
    from nexus.security.installers import NucleiInstaller
    download = Mock(side_effect=AssertionError("A preview must not download"))
    monkeypatch.setattr(NucleiInstaller, "run", download)
    response = api.client.post("/api/security/v2/installations/preview", json={"tool": "nuclei"})
    assert response.status_code == 200 and response.json()["preview"]["download_bytes"] == 46_067_128
    preview = response.json()
    response = api.client.post("/api/security/v2/approvals/" + preview["approval_id"] + "/decision", json={"approved": False})
    assert response.json()["executed"] is False and not download.called
    assert not (api.case.data / "security" / "tools").exists()


def test_installation_job_waits_for_approval_and_artifact_change_blocks_download(case, monkeypatch):
    from nexus.security.installers import NucleiInstaller
    run = Mock(return_value={"ok": True, "installed": True})
    monkeypatch.setattr(NucleiInstaller, "run", run)
    preview = case.w.installation_preview({"tool": "nuclei"})
    job = case.w.decision(preview["approval_id"], True)["job"]
    assert not run.called
    original = NucleiInstaller.preview
    monkeypatch.setattr(NucleiInstaller, "preview", lambda self: {**original(self), "version": "changed"})
    result = case.w.execute(job["id"])
    assert not result["ok"] and result["code"] == "installation_changed"
    assert not run.called


def test_repeated_scanner_evidence_does_not_become_controlled_confirmation():
    rows = reporting.correlate([
        {"engine": engine, "endpoint": "http://127.0.0.1/item", "cwe": "CWE-79",
         "confirmed": True, "confirmation": "scanner_evidence"}
        for engine in ("nuclei", "zap")])
    assert len(rows) == 1 and rows[0]["occurrences"] == 2
    assert rows[0]["confirmation"] == "scanner_evidence"
    assert rows[0]["sources"] == ["nuclei", "zap"]


def test_distinct_cves_with_same_cwe_and_endpoint_remain_distinct():
    rows = reporting.correlate([
        {"engine": "nuclei", "endpoint": "http://127.0.0.1/item", "cwe": "CWE-79",
         "cve": cve, "confirmed": True, "confirmation": "scanner_evidence"}
        for cve in ("CVE-2024-1001", "CVE-2025-1002")])
    assert len(rows) == 2
    assert {row["cve"] for row in rows} == {"CVE-2024-1001", "CVE-2025-1002"}
    assert all(row["occurrences"] == 1 for row in rows)


@pytest.mark.parametrize("changes", [{"parameter": "id"}, {"marker": "NEXUS_LAB_OTHER_MARKER"}, {"target": "http://127.0.0.1:8081/sqli/"}])
def test_revalidation_preview_refuses_changed_parameter_or_marker(case, changes):
    plan = apply_plan(case, prepare_plan(case))
    scope = scope_for(case)
    with pytest.raises(SecurityError) as exc:
        remediation.Remediation(case.w).revalidate_preview(plan["id"], {
            "scope_id": scope["id"], "args": {"target": "http://127.0.0.1:8081/sqli", "lab_confirmation": True, **changes}})
    assert exc.value.code == "revalidation_coverage_changed"


@pytest.mark.parametrize("changes", [{"parameter": "id"}, {"marker": "NEXUS_LAB_OTHER_MARKER"}, {"target": "http://127.0.0.1:8081/sqli/"}])
def test_revalidation_execution_rechecks_signature_before_network(case, monkeypatch, changes):
    plan = apply_plan(case, prepare_plan(case))
    scope = scope_for(case)
    operation = Mock(side_effect=AssertionError("Changed coverage must not be mistaken for regression"))
    monkeypatch.setattr(appsec, "run_sqli", operation)
    with pytest.raises(SecurityError) as exc:
        remediation.Remediation(case.w).revalidate({"plan_id": plan["id"], "revision": plan["revision"],
            "scope_id": scope["id"], "args": {"target": "http://127.0.0.1:8081/sqli", "lab_confirmation": True, **changes}},
            threading.Event(), lambda _: None)
    assert exc.value.code == "revalidation_coverage_changed"
    operation.assert_not_called()


def static_patch_plan(case, patched_source):
    unsafe = 'def lookup(db, name):\n    return db.execute(f"SELECT marker FROM records WHERE name = \'{name}\'").fetchall()\n'
    (case.project / "app.py").write_text(unsafe, encoding="utf-8")
    before = case.w.execute(queue(case, {"engine": "code_audit", "project_id": "demo", "args": {}}))
    assert before["ok"], before
    source = case.store.report(before["report_id"])["result"]
    finding = next(f for f in source["findings"] if f["rule_id"] == "PY-SQL-CONSTRUCTION")
    p = remediation.Remediation(case.w).preview({"report_id": before["report_id"], "project_id": "demo",
        "finding_ids": [finding["id"]], "edits": [{"path": "app.py", "content": patched_source}]})
    prepared = case.w.execute(case.w.decision(p["approval_id"], True)["job"]["id"])
    assert prepared["ok"], prepared
    plan = remediation.Remediation(case.w).get(p["preview"]["plan_id"])
    return apply_plan(case, plan), unsafe


def test_actual_ast_audit_patch_then_static_branch_revalidation(case):
    fixed = 'def lookup(db, name):\n    return db.execute("SELECT marker FROM records WHERE name = ?", (name,)).fetchall()\n'
    plan, original = static_patch_plan(case, fixed)
    p = remediation.Remediation(case.w).revalidate_preview(plan["id"], {})
    assert p["preview"]["action"] == "revalidate_static_code"
    result = case.w.execute(case.w.decision(p["approval_id"], True)["job"]["id"])
    assert result["ok"], result
    assert result["result"]["comparison"][0]["status"] == "absent_in_revalidated_coverage"
    assert not result["result"]["findings"]
    assert (case.project / "app.py").read_text(encoding="utf-8") == original
    assert Path(plan["branch_path"], "app.py").read_text(encoding="utf-8") == fixed


def test_static_finding_moved_to_next_line_is_still_present(case):
    shifted = '# A comment is not a SQL injection correction.\ndef lookup(db, name):\n    return db.execute(f"SELECT marker FROM records WHERE name = \'{name}\'").fetchall()\n'
    plan, _ = static_patch_plan(case, shifted)
    p = remediation.Remediation(case.w).revalidate_preview(plan["id"], {})
    result = case.w.execute(case.w.decision(p["approval_id"], True)["job"]["id"])
    assert result["ok"], result
    assert result["result"]["findings"]
    assert result["result"]["comparison"][0]["status"] == "still_present"


def test_truncated_static_revalidation_does_not_claim_absent_finding(case, monkeypatch):
    fixed = 'def lookup(db, name):\n    return db.execute("SELECT marker FROM records WHERE name = ?", (name,)).fetchall()\n'
    plan, _ = static_patch_plan(case, fixed)
    p = remediation.Remediation(case.w).revalidate_preview(plan["id"], {})
    from nexus.security import static
    monkeypatch.setattr(static, "audit_project", lambda _: {"ok": True, "findings": [], "truncated": True,
        "limit_reasons": ["time_budget"], "skipped_count": 0})
    result = case.w.execute(case.w.decision(p["approval_id"], True)["job"]["id"])
    assert not result["ok"]
    assert result["result"]["comparison"][0]["status"] == "inconclusive"
