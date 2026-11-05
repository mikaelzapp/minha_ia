"""Security Center integration over isolated local storage; no external services."""
import asyncio
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nexus.security.center import SecurityCenter, task_plan
from nexus.security.common import SecurityError
from nexus.security.store import MAX_SAMPLE, SecurityStore
from nexus.tools import Tools


@pytest.fixture
def center_case(tmp_path, monkeypatch):
    workspace = tmp_path / "workspaces"
    project = workspace / "demo"
    project.mkdir(parents=True)
    data = tmp_path / "data"
    data.mkdir()
    projects = [{"id": "demo", "name": "Demonstração", "path": "demo"}]
    factory = Mock()
    factory.return_value = Mock()
    center = SecurityCenter(data, workspace, lambda: projects, factory)
    monkeypatch.setattr(center, "catalog", lambda: {"external_tools": [], "dynamic_analysis": {"available": False}})
    return SimpleNamespace(center=center, store=center.store, workspace=workspace, project=project,
                           data=data, projects=projects, tool_factory=factory)


@pytest.fixture
def authorized_scope(center_case):
    return center_case.store.create_scope({"name": "Meu laboratório", "targets": ["127.0.0.1", "example.com"],
        "allowed_tests": ["http_headers", "tls_certificate", "tcp_connect", "nmap_basic", "osint"],
        "authorization_confirmed": True, "environment": "lab", "purpose": "Testes isolados"})


def test_scope_registration_has_explicit_confirmation_and_no_implicit_remote_grant(center_case):
    with pytest.raises(ValueError):
        center_case.store.create_scope({"name": "não autorizado", "targets": ["example.com"], "allowed_tests": ["http_headers"]})
    assert center_case.store.list_scopes() == []


def test_scope_revision_and_revocation_are_durable(center_case, authorized_scope):
    store = SecurityStore(center_case.data)
    identity = authorized_scope["id"]
    assert store.get_scope(identity, 1)["authorization_confirmed"] is True
    assert store.revoke_scope(identity)["enabled"] is False
    rows = store.list_scopes()
    assert rows[0]["revision"] == 2 and rows[0]["enabled"] is False
    with pytest.raises(SecurityError) as error:
        store.get_scope(identity, 1)
    assert error.value.code == "scope_revoked" and error.value.source == "permission"


def test_scope_changed_revision_refuses_old_preparation_even_if_enabled(center_case, authorized_scope):
    with center_case.store.connection() as db:
        db.execute("UPDATE scopes SET revision=revision+1 WHERE id=?", (authorized_scope["id"],))
    with pytest.raises(SecurityError) as error:
        center_case.store.get_scope(authorized_scope["id"], authorized_scope["revision"])
    assert error.value.code == "scope_changed"


@pytest.mark.parametrize("mode", ["PLAN", "CODE", "REVIEW", "RESEARCH"])
def test_active_network_tools_are_exposed_only_in_agent(center_case, mode):
    names = {item["function"]["name"] for item in center_case.center.schemas(mode)}
    assert "security_context" in names
    assert not names.intersection({"security_http", "security_tls", "security_tcp", "security_nmap"})


@pytest.mark.parametrize("mode", ["CHAT", "not-a-mode", "", None])
def test_unknown_or_chat_mode_has_no_security_tools(center_case, mode):
    assert center_case.center.schemas(mode) == []


def test_schema_callers_cannot_mutate_global_tool_contract(center_case):
    definitions = center_case.center.schemas("AGENT")
    definitions[0]["function"]["description"] = "changed by caller"
    assert center_case.center.schemas("AGENT")[0]["function"]["description"] != "changed by caller"


def test_model_tools_do_not_create_scopes_install_tools_or_execute_samples(center_case):
    names = {item["function"]["name"] for item in center_case.center.schemas("AGENT")}
    assert names and not names.intersection({"create_scope", "security_grant", "security_install", "security_execute_sample", "security_quarantine"})
    assert "operational_policy" in center_case.center.context()


def test_network_prepare_is_concrete_and_does_not_execute_request(center_case, authorized_scope, monkeypatch):
    from nexus.security import network
    operation = Mock(side_effect=AssertionError("approval is only a preview"))
    monkeypatch.setattr(network, "inspect_http", operation)
    args = {"scope_id": authorized_scope["id"], "target": "http://127.0.0.1:8765/"}
    preview = center_case.center.approval("security_http", args)
    assert preview["scope_revision"] == 1
    assert preview["authorized_target"]["addresses"] == ["127.0.0.1"]
    assert preview["target"] == args["target"]
    assert preview["args"] == args and "logs" in preview["impact"]
    operation.assert_not_called()


def test_revoke_between_prepare_and_execute_prevents_network_effect(center_case, authorized_scope, monkeypatch):
    from nexus.security import network
    operation = Mock(side_effect=AssertionError("revoked operation must not run"))
    monkeypatch.setattr(network, "inspect_http", operation)
    args = {"scope_id": authorized_scope["id"], "target": "http://127.0.0.1/"}
    preview = center_case.center.approval("security_http", args)
    center_case.store.revoke_scope(authorized_scope["id"])
    result = center_case.center.execute("security_http", {**args, "scope_revision": preview["scope_revision"]})
    assert not result["ok"] and result["source"] == "permission"
    assert result["code"] == "scope_revoked"
    operation.assert_not_called()
    assert center_case.store.report(result["report_id"])["result"]["code"] == "scope_revoked"


def test_changed_revision_between_prepare_and_execute_prevents_network_effect(center_case, authorized_scope, monkeypatch):
    from nexus.security import network
    operation = Mock()
    monkeypatch.setattr(network, "tcp_probe", operation)
    args = {"scope_id": authorized_scope["id"], "target": "127.0.0.1", "ports": [8080]}
    preview = center_case.center.approval("security_tcp", args)
    with center_case.store.connection() as db:
        db.execute("UPDATE scopes SET revision=revision+1 WHERE id=?", (authorized_scope["id"],))
    result = center_case.center.execute("security_tcp", {**args, "scope_revision": preview["scope_revision"]})
    assert not result["ok"] and result["code"] == "scope_changed"
    operation.assert_not_called()


@pytest.mark.parametrize("ports", [[], [0], [True], [65536], ["80"], list(range(1, 10))])
def test_invalid_ports_are_rejected_during_approval(center_case, authorized_scope, ports):
    with pytest.raises(ValueError):
        center_case.center.approval("security_tcp", {"scope_id": authorized_scope["id"], "target": "127.0.0.1", "ports": ports})


def test_outside_target_rejected_before_any_network_adapter(center_case, authorized_scope, monkeypatch):
    from nexus.security import network
    operation = Mock()
    monkeypatch.setattr(network, "inspect_http", operation)
    result = center_case.center.execute("security_http", {"scope_id": authorized_scope["id"], "target": "http://10.99.99.99/"})
    assert not result["ok"] and "escopo" in result["error"]
    operation.assert_not_called()


@pytest.mark.parametrize("name", ["../sample.exe", "C:\\sample.exe", "dir/sample.exe", ".env", "id_rsa", "secret.key", "x\x00exe", ".", "..", "name\r\n.exe"])
def test_sample_names_cannot_escape_or_import_credential_files(center_case, name):
    with pytest.raises(ValueError):
        center_case.store.ingest(name, b"harmless lab")
    assert center_case.store.list_samples() == []
    assert list(center_case.store.samples_dir.iterdir()) == []


@pytest.mark.parametrize("content", [b"", b"a" * (MAX_SAMPLE + 1)], ids=["empty", "oversized"])
def test_sample_byte_limit_creates_no_file(center_case, content):
    with pytest.raises(ValueError):
        center_case.store.ingest("sample.exe", content)
    assert list(center_case.store.samples_dir.iterdir()) == []


def test_sample_upload_is_inert_unique_hashed_and_existing_files_preserved(center_case):
    original = center_case.workspace / "original.exe"
    original.write_bytes(b"existing project bytes")
    content = b"harmless lab sample; this string mentions powershell but does not execute it"
    a = center_case.store.ingest("sample.exe", content)
    b = center_case.store.ingest("sample.exe", content)
    path, metadata = center_case.store.sample(a["id"])
    assert path.suffix == ".bin" and path.parent == center_case.store.samples_dir
    assert path.read_bytes() == content
    assert a["id"] != b["id"] and a["sha256"] == b["sha256"] == hashlib.sha256(content).hexdigest()
    assert metadata["original_name"] == "sample.exe"
    assert original.read_bytes() == b"existing project bytes"


def test_changed_sample_hash_blocks_analysis_before_adapter(center_case, monkeypatch):
    from nexus.security import static
    sample = center_case.store.ingest("sample.exe", b"original harmless bytes")
    path, _ = center_case.store.sample(sample["id"])
    path.write_bytes(b"changed harmless bytes")
    operation = Mock()
    monkeypatch.setattr(static, "analyze_file", operation)
    result = center_case.center.execute("security_static_file", {"sample_id": sample["id"]})
    assert not result["ok"] and result["code"] == "sample_changed"
    operation.assert_not_called()


@pytest.mark.parametrize("identity", ["../outside", "a" * 31, "g" * 32, "' OR 1=1 --"])
def test_sample_identity_is_not_a_path_or_sql(center_case, identity):
    with pytest.raises(SecurityError):
        center_case.store.sample(identity)


def test_store_refuses_link_in_data_directory_ancestry(tmp_path, monkeypatch):
    data = tmp_path / "linked-data"
    data.mkdir()
    actual = Tools._is_link
    monkeypatch.setattr(Tools, "_is_link", staticmethod(lambda path: Path(path) == data or actual(Path(path))))
    with pytest.raises(ValueError):
        SecurityStore(data)
    assert not (data / "security/security.sqlite3").exists()


def test_sample_store_link_change_blocks_ingest(center_case, monkeypatch):
    actual = Tools._is_link
    monkeypatch.setattr(Tools, "_is_link", staticmethod(lambda path: Path(path) == center_case.store.samples_dir or actual(Path(path))))
    with pytest.raises(ValueError):
        center_case.store.ingest("sample.exe", b"harmless")
    assert center_case.store.list_samples() == []


def test_static_analysis_never_executes_uploaded_script(center_case, monkeypatch):
    import subprocess
    marker = center_case.workspace / "must-not-exist.txt"
    sample_bytes = f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n".encode()
    sample = center_case.store.ingest("danger-looking.py", sample_bytes)
    process = Mock(side_effect=AssertionError("sample analysis must not spawn a process"))
    monkeypatch.setattr(subprocess, "Popen", process)
    result = center_case.center.execute("security_static_file", {"sample_id": sample["id"]})
    assert result["ok"] and result["executed_target"] is False
    assert not marker.exists()
    process.assert_not_called()


def test_investigate_workflow_is_sequential_and_passes_same_isolated_file(center_case, monkeypatch):
    from nexus.security import static, rea
    sample = center_case.store.ingest("owned-program.exe", b"harmless lab")
    order = []

    def analyze(path, **kwargs):
        assert path.suffix == ".bin"
        order.append(("static", path))
        return {"ok": True, "findings": [{"title": "hypothesis", "confirmed": False}]}

    def reverse(self, path):
        order.append(("rea", path))
        return {"ok": False, "code": "provider_unavailable", "error": "Decompiler absent"}

    monkeypatch.setattr(static, "analyze_file", analyze)
    monkeypatch.setattr(rea.REA, "analyze", reverse)
    result = center_case.center.execute("security_investigate", {"sample_id": sample["id"]})
    assert result["ok"] and result["data"]["workflow"] == ["malware_lab", "rea"]
    assert [x[0] for x in order] == ["static", "rea"] and order[0][1] == order[1][1]
    assert result["data"]["rea"]["code"] == "provider_unavailable"


def test_registered_project_audit_does_not_run_project_code(center_case, monkeypatch):
    import subprocess
    marker = center_case.workspace / "must-not-run.txt"
    code = f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n"
    (center_case.project / "owned.py").write_text(code)
    process = Mock(side_effect=AssertionError("code audit is static"))
    monkeypatch.setattr(subprocess, "Popen", process)
    result = center_case.center.execute("security_code_audit", {"project_id": "demo"})
    assert result["ok"] and result["executed_target"] is False
    assert not marker.exists() and (center_case.project / "owned.py").read_text() == code
    process.assert_not_called()


@pytest.mark.parametrize("path", ["../outside", "ABSOLUTE_OUTSIDE"])
def test_registered_project_cannot_escape_workspace(center_case, tmp_path, monkeypatch, path):
    from nexus.security import static
    outside = tmp_path / "outside"
    outside.mkdir()
    center_case.projects[0]["path"] = str(outside) if path == "ABSOLUTE_OUTSIDE" else path
    operation = Mock()
    monkeypatch.setattr(static, "audit_project", operation)
    result = center_case.center.execute("security_code_audit", {"project_id": "demo"})
    assert not result["ok"] and result["code"] == "project_outside_workspace"
    operation.assert_not_called()


def test_unregistered_project_not_inferred_from_arbitrary_path(center_case):
    result = center_case.center.execute("security_code_audit", {"project_id": "../outside"})
    assert not result["ok"] and result["code"] == "project_not_found"


def test_missing_optional_nmap_is_recorded_honestly(center_case, authorized_scope, monkeypatch):
    from nexus.security import network
    monkeypatch.setattr(network, "_nmap_path", lambda: None)
    result = center_case.center.execute("security_nmap", {"scope_id": authorized_scope["id"], "target": "127.0.0.1", "ports": [80]})
    assert not result["ok"] and result["code"] == "TOOL_UNAVAILABLE"
    assert result["data"]["available"] is False and "report_id" in result


def test_osint_closes_existing_search_tool_and_preserves_provider_error(center_case, authorized_scope):
    tool = center_case.tool_factory.return_value
    tool.execute.return_value = {"ok": False, "error": "SearXNG unavailable"}
    result = center_case.center.execute("security_osint", {"scope_id": authorized_scope["id"], "domain": "example.com", "keywords": "public docs"})
    assert not result["ok"] and result["code"] == "SEARCH_FAILED"
    tool.close.assert_called_once()


def test_osint_approval_shows_array_terms_and_scope_revision_before_any_search(center_case, authorized_scope):
    args = {"scope_id": authorized_scope["id"], "domain": "example.com", "keywords": ["API", "technical docs"],
            "exclusions": ["obsolete", "draft"], "operators": {"intitle": "reference"}, "max_results": 3}
    preview = center_case.center.approval("security_osint", args)
    assert preview["scope_revision"] == authorized_scope["revision"]
    assert preview["query"] == 'site:example.com intitle:"reference" "API" "technical docs" -"obsolete" -"draft"'
    assert preview["args"]["query_preview"] == preview["query"]
    center_case.tool_factory.assert_not_called()
    # Dispatch must remove both scope identifiers before calling the builder.
    built = center_case.center.execute("security_dork", {**args, "scope_revision": preview["scope_revision"]})
    assert built["ok"] and built["data"]["query"] == preview["query"]
    center_case.tool_factory.assert_not_called()


def test_osint_revocation_after_query_preview_prevents_search(center_case, authorized_scope):
    args = {"scope_id": authorized_scope["id"], "domain": "example.com", "exclusions": ["draft"]}
    preview = center_case.center.approval("security_osint", args)
    center_case.store.revoke_scope(authorized_scope["id"])
    result = center_case.center.execute("security_osint", {**args, "scope_revision": preview["scope_revision"]})
    assert not result["ok"] and result["code"] == "scope_revoked"
    center_case.tool_factory.assert_not_called()


def test_static_indicators_are_preserved_as_structured_findings_in_report(center_case, monkeypatch):
    from nexus.security import static
    sample = center_case.store.ingest("owned.bin", b"harmless fixture")
    indicator = {"title": "Synthetic suspicious string", "severity": "info", "confidence": "low", "confirmed": False}
    monkeypatch.setattr(static, "analyze_file", lambda *args, **kwargs: {"ok": True, "indicators": [indicator]})
    result = center_case.center.execute("security_static_file", {"sample_id": sample["id"]})
    assert result["findings"] == [indicator]
    assert center_case.store.reports()[0]["findings_count"] == 1


def test_store_redacts_secret_values_and_reports_have_size_limit(center_case):
    saved = center_case.store.save_report("security_code_audit", {"ok": True, "text": "password=private-value-12345"})
    loaded = center_case.store.report(saved["id"])
    assert "private-value-12345" not in json.dumps(loaded)
    with pytest.raises(SecurityError, match="2 MiB"):
        center_case.store.save_report("security_code_audit", {"text": "x" * (2 * 1024 * 1024)})
    assert len(center_case.store.reports()) == 1


def test_long_plain_text_redaction_keeps_prefix_and_removes_url_credential():
    from nexus.memory import redact_secrets
    prefix = "x" * 100_000
    text = prefix + " https://user:private-pass@example.com/owned"
    result = redact_secrets(text)
    assert result.startswith(prefix + " https://")
    assert "private-pass" not in result and "example.com/owned" in result


def test_security_tools_share_existing_agenttools_approval_and_execution_boundary(center_case, authorized_scope):
    from nexus.access import Access, AgentTools
    base = Tools(center_case.workspace, center_case.data)
    access = Access(center_case.data, center_case.workspace)
    wrapped = AgentTools(base, access, lambda: False, security=lambda: center_case.center)
    try:
        names = {item["function"]["name"] for item in wrapped.schemas("AGENT")}
        assert {"read_file", "write_file", "security_http", "security_investigate"}.issubset(names)
        assert "pc_write_file" not in names
        assert not any(item["function"]["name"].startswith("security_") for item in wrapped.schemas("CHAT"))
        preview = wrapped.approval("security_http", {"scope_id": authorized_scope["id"], "target": "http://127.0.0.1/"})
        assert preview["action"] == "security_http" and preview["scope_id"] == authorized_scope["id"]
        result = wrapped.execute("security_context", {})
        assert result["ok"] and result["data"]["scopes"][0]["id"] == authorized_scope["id"]
    finally:
        wrapped.close()


@pytest.mark.parametrize("message,expected", [
    ("Investigue meu executável sample.exe", "malware_lab"),
    ("Audite meu aplicativo com red team", "red_team"),
    ("Proteção do Windows e Defender", "blue_team"),
    ("OSINT com dorks dos meus documentos públicos", "osint"),
    ("Auditoria de código autorizada", "code_auditor"),
])
def test_engine_routes_to_security_agents_and_respects_explicit_user_agent(message, expected):
    from nexus.engine import route_agent
    assert route_agent("auto", "AGENT", message) == expected
    assert route_agent("coder", "AGENT", message) == "coder"


@pytest.mark.parametrize("profile", ["standard", "unrestricted_local"])
def test_security_agents_include_separate_operational_role_in_both_profiles(profile):
    from nexus.engine import system_prompt
    from nexus.profiles import role_instructions
    prompt = system_prompt("red_team", "AGENT", "authorized-workspace", profile=profile)
    assert role_instructions("security_center") in prompt
    assert "authorized-workspace" in prompt
    assert "AGENT" in prompt


def test_model_switch_unloads_previously_used_unconfigured_9b_and_preserves_unrelated_model():
    from nexus.engine import Ollama
    engine = Ollama("http://127.0.0.1:11434")
    primary, alternate, unrelated = "qwen3.5:4b-q4_K_M", "owned-abliterated:9b", "unrelated:model"
    loaded = {primary, unrelated}
    unloaded = []

    async def inventory():
        return {"connected": True, "running": [{"name": name} for name in loaded]}

    async def unload(name):
        loaded.remove(name)
        unloaded.append(name)

    engine.inventory = inventory
    engine.unload = unload

    async def switch_sequence():
        await engine.prepare(primary, [primary])
        await engine.prepare(alternate, [primary])
        loaded.add(alternate)  # Simulate Ollama loading the requested model.
        assert primary not in loaded
        await engine.prepare(primary, [primary])
        loaded.add(primary)

    asyncio.run(switch_sequence())
    assert unloaded == [primary, alternate]
    assert loaded == {primary, unrelated}


def test_coding_consultant_receives_explicit_active_9b_instead_of_configured_default(center_case, monkeypatch):
    import test_api as support
    settings = {"ollama_url": "http://127.0.0.1:11434", "searxng_url": "", "tor_enabled": False,
                "tor_proxy": "socks5h://127.0.0.1:9050", "model": "configured-main:4b",
                "coding_model": "qwen2.5-coder:7b", "computer_enabled": False}
    monkeypatch.setattr(support.api, "settings", settings)
    monkeypatch.setattr(support.api, "DATA", center_case.data)
    monkeypatch.setattr(support.api, "WORKSPACES", center_case.workspace)
    tools = support.api.get_tools(profile="unrestricted_local", primary_model="explicit-active:9b")
    try:
        consultant = tools.coding()
        assert consultant.primary_model == "explicit-active:9b"
        assert consultant.model == "qwen2.5-coder:7b"
        assert consultant.profile == "unrestricted_local"
    finally:
        tools.close()


@pytest.mark.parametrize("message,expected", [
    ("Investigue este executável .exe autorizado", ["malware_lab", "rea"]),
    ("Faça engenharia reversa do meu programa", ["rea"]),
    ("Verifique o Defender e a proteção do Windows", ["blue_team"]),
    ("Prepare uma pesquisa OSINT com dorks", ["osint"]),
    ("Faça auditoria de código do meu repositório", ["code_auditor"]),
    ("Audite meu aplicativo com red team", ["red_team"]),
])
def test_routing_selects_capability_without_rejecting_security_terms(message, expected):
    assert task_plan(message) == expected
