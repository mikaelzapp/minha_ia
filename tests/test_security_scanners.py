"""Optional scanner contracts: fixtures never masquerade as real installed tools."""
from contextlib import contextmanager
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nexus.security import network
from nexus.security import scanners as mod


@pytest.fixture
def scope(monkeypatch):
    monkeypatch.setattr(network, "ALLOWED_TESTS", network.ALLOWED_TESTS | mod.ENGINES)
    return {"id": "lab-scanner", "revision": 1, "name": "Laboratório fictício", "targets": ["127.0.0.1", "example.com"],
            "allowed_tests": sorted(network.ALLOWED_TESTS), "environment": "lab", "purpose": "teste fictício",
            "authorization_confirmed": True, "include_subdomains": False, "enabled": True,
            "allowed_ports": [*range(1, 11), 80, 443, 8123]}


def adapter(tmp_path):
    return mod.ScannerAdapters(tmp_path)


def mock_binary(tmp_path, monkeypatch, engine="nuclei"):
    binary = tmp_path / ("scanner.exe" if os.name == "nt" else "scanner")
    binary.write_bytes(b"fixture never executed")
    instance = mod.ScannerAdapters(tmp_path, {engine: {"approved": True, "path": str(binary),
                                                      "sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}})
    monkeypatch.setattr(mod.psutil, "virtual_memory", lambda: SimpleNamespace(available=4 * 1024**3))
    monkeypatch.setattr(instance, "_version", lambda *args: "3.11.1" if engine == "nuclei" else "7.98")
    return instance, binary


def test_inventory_is_read_only_does_not_execute_path_candidates(tmp_path, monkeypatch):
    executable = tmp_path / "untrusted.exe"
    executable.write_bytes(b"not executed")
    monkeypatch.setattr(mod.shutil, "which", lambda _: str(executable))
    process = Mock(side_effect=AssertionError("Inventory must not launch binaries"))
    monkeypatch.setattr(mod.subprocess, "Popen", process)
    rows = adapter(tmp_path).inventory()
    assert all(row["available"] and not row["configured"] and not row["executed"] for row in rows["tools"])
    assert all(row["version"] is None for row in rows["tools"])
    assert len(rows["templates"]) == 3
    process.assert_not_called()
    assert not (tmp_path / "security").exists()


def test_missing_tool_does_not_start_process(scope, tmp_path, monkeypatch):
    process = Mock(side_effect=AssertionError("No scanner installed"))
    monkeypatch.setattr(mod.subprocess, "Popen", process)
    result = adapter(tmp_path).run("nuclei", scope, {"target": "http://127.0.0.1/"})
    assert not result["ok"] and result["code"] == "tool_unavailable"
    process.assert_not_called()


@pytest.mark.parametrize("target,code", [("http://example.com/", "isolation_requirement"),
    ("https://127.0.0.1/", "isolation_requirement"), ("http://8.8.8.8/", "security_error"),
    ("http://u:p@127.0.0.1/", "security_error"), ("http://127.0.0.1/?token=x", "security_error")])
def test_external_ambiguous_or_unscoped_scanner_destinations_blocked(scope, tmp_path, target, code):
    with pytest.raises(ValueError):
        adapter(tmp_path).preview("nuclei", scope, {"target": target})


def test_preview_does_not_resolve_or_execute(scope, tmp_path, monkeypatch):
    monkeypatch.setattr(network, "_resolve", Mock(side_effect=AssertionError("No DNS preview")))
    monkeypatch.setattr(mod.subprocess, "Popen", Mock(side_effect=AssertionError("No process preview")))
    result = adapter(tmp_path).preview("nuclei", scope, {"target": "http://127.0.0.1:8123/"})
    assert result["requires_approval"] and result["scope_revision"] == 1
    assert result["args"]["rate_limit"] == 2
    assert any("GET" in impact for impact in result["impact"])


@pytest.mark.parametrize("args", [{"argv": ["--update"]}, {"templates": ["https://outside.test/x.yaml"]},
    {"templates": ["cves/"]}, {"templates": [{}]}, {"templates": []}, {"rate_limit": 1000},
    {"duration_seconds": True}, {"duration_seconds": 9999}, {"level": "all"}])
def test_no_arbitrary_flags_templates_plans_or_unbounded_limits(scope, tmp_path, args):
    with pytest.raises(ValueError):
        adapter(tmp_path).preview("nuclei", scope, {"target": "http://127.0.0.1/", **args})


def test_production_declared_scope_cannot_run_external_scanner(scope, tmp_path):
    scope["environment"] = "production"
    with pytest.raises(mod.SecurityError, match="ambiente"):
        adapter(tmp_path).preview("zap", scope, {"target": "http://127.0.0.1/", "level": "STAGING FULL"})


@pytest.mark.parametrize("environment", ["production-lab", "homolog-production", "staging production"])
def test_environment_substrings_do_not_grant_lab_execution(scope, tmp_path, environment):
    scope["environment"] = environment
    with pytest.raises(mod.SecurityError, match="ambiente"):
        adapter(tmp_path).preview("nuclei", scope, {"target": "http://127.0.0.1/"})


def test_explicit_environment_class_and_port_grants_required(scope, tmp_path):
    scope["environment_class"] = "production"
    with pytest.raises(mod.SecurityError, match="ambiente"):
        adapter(tmp_path).preview("nuclei", scope, {"target": "http://127.0.0.1/"})
    scope["environment_class"] = "lab"
    scope.pop("allowed_ports")
    with pytest.raises(mod.SecurityError, match="portas"):
        adapter(tmp_path).preview("nmap_service", scope, {"target": "127.0.0.1"})


def test_scanner_output_cannot_claim_other_origin():
    raw = {"template-id": "nexus-http-baseline", "matched-at": "http://outside.test/"}
    with pytest.raises(mod.SecurityError, match="origem"):
        mod.parse_nuclei(json.dumps(raw).encode(), ["nexus-http-baseline"], "http://127.0.0.1/")


def test_nmap_default_small_ports_extended_requires_explicit_preview(scope, tmp_path):
    with pytest.raises(ValueError):
        adapter(tmp_path).preview("nmap_service", scope, {"target": "127.0.0.1", "ports": list(range(1, 10))})
    value = adapter(tmp_path).preview("nmap_service", scope, {"target": "127.0.0.1", "ports": list(range(1, 10)), "expanded_ports_approved": True})
    assert value["args"]["expanded_ports_approved"]


def test_nmap_version_detection_is_active_and_port_grants_apply(scope, tmp_path):
    with pytest.raises(ValueError):
        adapter(tmp_path).preview("nmap_service", scope, {"target": "127.0.0.1", "service_detection": True})
    scope["allowed_ports"] = [80]
    with pytest.raises(ValueError, match="Porta"):
        adapter(tmp_path).preview("nmap_service", scope, {"target": "127.0.0.1", "ports": [443], "level": "SAFE ACTIVE"})
    value = adapter(tmp_path).preview("nmap_service", scope, {"target": "127.0.0.1", "ports": [80], "level": "SAFE ACTIVE", "service_detection": True})
    assert value["args"]["service_detection"]


def test_binary_hash_drift_blocks_before_launch(scope, tmp_path, monkeypatch):
    instance, binary = mock_binary(tmp_path, monkeypatch)
    binary.write_bytes(b"changed bytes")
    process = Mock(side_effect=AssertionError("Hash drift must block"))
    monkeypatch.setattr(mod.subprocess, "Popen", process)
    result = instance.run("nuclei", scope, {"target": "http://127.0.0.1/"})
    assert result["code"] == "scanner_integrity"
    process.assert_not_called()


def test_revoked_or_changed_scope_blocked_even_after_approval(scope, tmp_path, monkeypatch):
    instance, _ = mock_binary(tmp_path, monkeypatch)
    changed = {**scope, "revision": 2}
    result = instance.run("nuclei", scope, {"target": "http://127.0.0.1/"}, scope_loader=lambda: changed)
    assert result["code"] == "scope_revoked"


def test_ram_budget_prevents_loading_scanner(scope, tmp_path, monkeypatch):
    instance, _ = mock_binary(tmp_path, monkeypatch)
    monkeypatch.setattr(mod.psutil, "virtual_memory", lambda: SimpleNamespace(available=100 * 1024**2))
    result = instance.run("nuclei", scope, {"target": "http://127.0.0.1/"})
    assert result["code"] == "resource_budget"


def test_environment_omits_host_credentials_and_proxy(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENAI_API_KEY", "secret-host-key")
    monkeypatch.setenv("HTTPS_PROXY", "http://user:password@private")
    monkeypatch.setenv("JAVA_TOOL_OPTIONS", "-javaagent:evil.jar")
    env = mod._environment(tmp_path)
    assert not any(x in env for x in ["OPENAI_API_KEY", "HTTPS_PROXY", "JAVA_TOOL_OPTIONS", "PATH"])
    assert env["DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD"] == "true"


def test_nuclei_fixture_jsonl_uses_reviewed_metadata_and_omits_raw_secrets():
    raw = {"template-id": "nexus-http-baseline", "info": {"name": "malicious title", "severity": "critical"},
           "matched-at": "http://user:password@127.0.0.1/a?token=private", "request": "Authorization: secret",
           "response": "private-content", "extracted-results": ["private-secret"]}
    result = mod.parse_nuclei(json.dumps(raw).encode(), ["nexus-http-baseline"])
    assert result[0]["severity"] == "info" and result[0]["confirmed"] is False
    assert result[0]["endpoint"] == "http://127.0.0.1/a"
    assert not any(secret in json.dumps(result) for secret in ["password", "private", "malicious title"])


@pytest.mark.parametrize("body", [b'{"template-id":"unreviewed"}', b'bad json', b'[]'])
def test_nuclei_unreviewed_or_invalid_json_output_not_success(body):
    with pytest.raises(ValueError):
        mod.parse_nuclei(body, ["nexus-http-baseline"])


def test_zap_fixture_report_omits_attack_evidence_request_and_query_secrets():
    report = {"site": [{"@name": "http://127.0.0.1/", "alerts": [{"pluginid": "40018", "name": "SQL Injection", "riskcode": "3",
               "confidence": "2", "cweid": "89", "instances": [{"uri": "http://127.0.0.1/login?token=secret", "method": "GET", "param": "name",
               "attack": "secret-attack", "evidence": "customer-private-data"}], "requestHeader": "Authorization: bearer-private"}]}]}
    value = mod.parse_zap(json.dumps(report).encode())
    assert value[0]["cwe"] == "89" and value[0]["status"] == "scanner_indication"
    assert not any(secret in json.dumps(value) for secret in ["secret", "customer-private", "bearer-private"])


def test_zap_plan_levels_only_reviewed_jobs_and_rules(tmp_path):
    instance = adapter(tmp_path)
    args = {"target": "http://127.0.0.1:8123/", "rate_limit": 2, "level": "PASSIVE"}
    passive = instance.zap_plan(args, tmp_path)
    assert "activeScan" not in [job["type"] for job in passive["jobs"]]
    assert not any(job["type"].startswith("spider") for job in passive["jobs"])
    active = instance.zap_plan({**args, "level": "SAFE ACTIVE"}, tmp_path)
    scan = next(job for job in active["jobs"] if job["type"] == "activeScan")
    assert scan["policyDefinition"]["defaultThreshold"] == "Off"
    assert [x["id"] for x in scan["policyDefinition"]["rules"]] == [40012, 40018]
    assert scan["parameters"]["threadPerHost"] == 1


def test_zap_openapi_local_discovery_never_fetches_or_runs_import_job(scope, tmp_path, monkeypatch):
    monkeypatch.setattr(network, "_resolve", Mock(side_effect=AssertionError("Preview never fetches DNS")))
    monkeypatch.setattr(mod.subprocess, "Popen", Mock(side_effect=AssertionError("Preview never starts importer")))
    definition = {"openapi": "3.0.3", "paths": {"/health": {"get": {"responses": {"200": {"description": "ok"}}}},
        "/metadata": {"head": {}}, "/records": {"post": {}}, "/records/{id}": {"get": {}}}}
    value = adapter(tmp_path).preview("zap", scope, {"target": "http://127.0.0.1/", "endpoints": ["/manual"], "openapi": definition})
    plan = adapter(tmp_path).zap_plan(value["args"], tmp_path)
    requestor = next(job for job in plan["jobs"] if job["type"] == "requestor")
    assert [(x["url"], x["method"]) for x in requestor["requests"]] == [
        ("http://127.0.0.1/", "GET"), ("http://127.0.0.1/manual", "GET"), ("http://127.0.0.1/health", "GET"), ("http://127.0.0.1/metadata", "HEAD")]
    assert not any(job["type"] in {"openapi", "spider", "spiderAjax", "script"} for job in plan["jobs"])
    assert value["discovery"]["requests_planned"] == 4
    assert value["discovery"]["remote_definitions_fetched"] is False
    assert {x["reason"] for x in value["discovery"]["openapi_skipped"]} == {
        "only_get_head_discovery", "path_parameters_require_explicit_synthetic_values"}


@pytest.mark.parametrize("extra", [{"servers": [{"url": "http://outside.test/"}]}, {"callbacks": {}}, {"webhooks": {}},
    {"components": {"schemas": {"Remote": {"$ref": "http://outside.test/private"}}}},
    {"components": {"schemas": {"Remote": {"$ref": "file:///private"}}}}, {"host": "outside.test"}])
def test_zap_openapi_rejects_external_effects_at_any_depth(scope, tmp_path, extra):
    with pytest.raises(ValueError):
        adapter(tmp_path).preview("zap", scope, {"target": "http://127.0.0.1/", "openapi": {"openapi": "3.0.0", "paths": {}, **extra}})


@pytest.mark.parametrize("path", ["https://outside.test/a", "//outside.test/a", "/../secret", "/%252e%252e/secret", "/bad?token=x", "/users/{id}"])
def test_zap_manual_endpoints_reject_offorigin_or_ambiguous_paths(scope, tmp_path, path):
    with pytest.raises(ValueError):
        adapter(tmp_path).preview("zap", scope, {"target": "http://127.0.0.1/", "endpoints": [path]})


def test_zap_openapi_size_and_discovery_counts_are_bounded(scope, tmp_path):
    with pytest.raises(ValueError, match="dez"):
        adapter(tmp_path).preview("zap", scope, {"target": "http://127.0.0.1/", "endpoints": [f"/a{i}" for i in range(11)]})
    with pytest.raises(ValueError, match="128"):
        adapter(tmp_path).preview("zap", scope, {"target": "http://127.0.0.1/", "openapi": {"openapi": "3.0.0", "paths": {}, "description": "x" * 128 * 1024}})
    definition = {"openapi": "3.0.0", "paths": {f"/a{i}": {"get": {}} for i in range(15)}}
    value = adapter(tmp_path).preview("zap", scope, {"target": "http://127.0.0.1/", "openapi": definition})
    assert len(value["discovery"]["openapi_paths"]) == 10
    assert value["discovery"]["requests_planned"] == 11
    assert len(value["discovery"]["openapi_skipped"]) == 5


@pytest.mark.parametrize("extra", [{"enum": list(range(10001))}, {"example": float("inf")}])
def test_zap_openapi_excessive_complexity_and_nonfinite_json_rejected(scope, tmp_path, extra):
    with pytest.raises(ValueError):
        adapter(tmp_path).preview("zap", scope, {"target": "http://127.0.0.1/", "openapi": {"openapi": "3.0.0", "paths": {}, **extra}})


def test_zap_openapi_local_refs_not_resolved_and_examples_not_in_plan(scope, tmp_path):
    definition = {"openapi": "3.0.0", "paths": {"/health": {"get": {"responses": {"200": {"$ref": "#/components/schemas/Health"}}}}},
                  "components": {"schemas": {"Health": {"type": "string", "example": "private-example-must-not-be-forwarded"}}}}
    value = adapter(tmp_path).preview("zap", scope, {"target": "http://127.0.0.1/", "openapi": definition})
    plan = adapter(tmp_path).zap_plan(value["args"], tmp_path)
    assert "private-example" not in json.dumps(plan)
    assert "$ref" not in json.dumps(plan)
    assert "private-example" not in json.dumps(value["discovery"])


def test_zap_endpoint_discovery_preserves_approved_base_path(scope, tmp_path):
    with pytest.raises(ValueError, match="caminho base"):
        adapter(tmp_path).preview("zap", scope, {"target": "http://127.0.0.1/api/", "endpoints": ["/admin"]})
    value = adapter(tmp_path).preview("zap", scope, {"target": "http://127.0.0.1/api/", "endpoints": ["/api/health", "/api/health"]})
    assert value["discovery"]["requests_planned"] == 2


def test_zap_fixture_run_keeps_spec_examples_out_of_results(scope, tmp_path, monkeypatch):
    instance = adapter(tmp_path)
    binary, java = tmp_path / "zap.jar", tmp_path / "java.exe"
    binary.write_bytes(b"JAR fixture never executed")
    java.write_bytes(b"Java fixture never executed")
    monkeypatch.setattr(instance, "_binary", lambda engine: (binary, java))
    monkeypatch.setattr(instance, "_version", lambda *args: "2.17.0")
    monkeypatch.setattr(mod.psutil, "virtual_memory", lambda: SimpleNamespace(available=4 * 1024**3))

    def capture(argv, **kwargs):
        plan = json.loads(Path(argv[argv.index("-autorun") + 1]).read_text(encoding="utf-8"))
        assert "sensitive-schema-example" not in json.dumps(plan)
        kwargs["output_files"][0].write_text('{"site": []}', encoding="utf-8")
        return {"ok": True, "exit_code": 0, "code": "ok", "stdout": b"", "stderr": b"", "duration_seconds": 0.1}

    monkeypatch.setattr(mod, "run_bounded", capture)
    definition = {"openapi": "3.0.0", "paths": {"/health": {"get": {"description": "sensitive-schema-example"}}}}
    result = instance.run("zap", scope, {"target": "http://127.0.0.1/", "openapi": definition})
    assert result["ok"], result
    assert result["evidence"]["discovery"]["requests_planned"] == 2
    assert "openapi" not in result["evidence"]["config"]
    assert "sensitive-schema-example" not in json.dumps(result)


def test_nmap_probe_evidence_distinguished_from_port_mapping():
    xml = b'''<!DOCTYPE nmaprun><nmaprun><host><address addr="127.0.0.1" addrtype="ipv4"/><ports>
      <port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" method="table" product="invented" version="99"/></port>
      <port protocol="tcp" portid="8080"><state state="open"/><service name="http" method="probed" product="FixtureHTTP" version="1.0"/></port>
      </ports></host></nmaprun>'''
    rows = mod.parse_nmap(xml, [80, 8080], "127.0.0.1", True)
    assert rows[0]["service"] is None and rows[0]["version"] is None
    assert rows[0]["service_hint"] == "http"
    assert rows[1]["version"] == "FixtureHTTP 1.0"


def test_nmap_summary_only_infers_exact_complement_and_marks_missing_inconclusive():
    xml = b'<nmaprun><host><ports><extraports state="closed" count="2"><extrareasons reason="conn-refused" count="2"/></extraports></ports></host></nmaprun>'
    rows = mod.parse_nmap(xml, [80, 443], "127.0.0.1", False)
    assert [row["state"] for row in rows] == ["closed", "closed"]
    assert all(row["evidence"]["source"] == "nmap_extraports_complement" for row in rows)
    missing = mod.parse_nmap(b'<nmaprun/>', [80, 443], "127.0.0.1", False)
    assert all(row["state"] == "not_reported" for row in missing)


@pytest.mark.parametrize("data", [b'<!DOCTYPE nmaprun [<!ENTITY x SYSTEM "file:///secret">]><nmaprun/>',
    b'<!DOCTYPE nmaprun SYSTEM "https://outside.test/x.dtd"><nmaprun/>', b'<root/>',
    b'<nmaprun><host><address addr="8.8.8.8" addrtype="ipv4"/></host></nmaprun>'])
def test_nmap_output_entities_wrong_hosts_or_document_rejected(data):
    with pytest.raises(ValueError):
        mod.parse_nmap(data, [80], "127.0.0.1", False)


def test_nuclei_process_fixture_argv_bounds_and_real_guard_but_no_real_scanner(scope, tmp_path, monkeypatch):
    instance, binary = mock_binary(tmp_path, monkeypatch)
    observed = []

    def capture(argv, **kwargs):
        observed.append(argv)
        assert argv[0] == str(binary)
        assert all(x in argv for x in ["-ni", "-duc", "-dr", "-or", "-proxy", "-pi", "-jsonl"])
        assert all(x not in argv for x in ["-code", "-headless", "-update", "-fuzz"])
        assert kwargs["scope_check"]()["revision"] == 1
        return {"ok": True, "exit_code": 0, "code": "ok", "stdout": b"", "stderr": b"", "duration_seconds": 0.1}

    monkeypatch.setattr(mod, "run_bounded", capture)
    result = instance.run("nuclei", scope, {"target": "http://127.0.0.1:8123/"})
    assert result["ok"], result
    assert not result["findings"]
    assert "garantia" in result["notice"] and result["evidence"]["network_guard"]["origin_pinned"]
    assert len(observed) == 1
    assert not list((tmp_path / "security" / "scanners").iterdir())


@contextmanager
def local_server():
    class Handler(BaseHTTPRequestHandler):
        calls = []

        def do_GET(self):
            self.calls.append(self.path)
            self.send_response(302 if self.path == "/redirect" else 200)
            self.send_header("Set-Cookie", "synthetic=yes; HttpOnly")
            if self.path == "/redirect":
                self.send_header("Location", "http://outside.invalid/private")
            self.end_headers()
            self.wfile.write(b"NEXUS_SYNTHETIC_EXPOSURE_V1")

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, Handler.calls
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_real_proxy_forwards_only_pinned_lab_origin_and_strips_redirect(scope):
    with local_server() as (server, calls):
        target = f"http://127.0.0.1:{server.server_port}/"
        scope["allowed_ports"].append(server.server_port)
        destination = network.ScopePolicy(scope).authorize_target(target, "nuclei")
        cancel = threading.Event()
        with mod._ScopedProxy(destination, rate=5, maximum=4, check=lambda: scope, cancel=cancel) as proxy:
            conn = http.client.HTTPConnection("127.0.0.1", proxy.server.server_port, timeout=4)
            conn.request("GET", target + "redirect")
            response = conn.getresponse()
            assert response.status == 302 and response.getheader("Location") is None
            assert "HttpOnly" in response.getheader("Set-Cookie")
            response.read()
            conn.close()
            conn = http.client.HTTPConnection("127.0.0.1", proxy.server.server_port, timeout=4)
            conn.request("GET", "http://127.0.0.1:1/private")
            assert conn.getresponse().status == 403
            conn.close()
            assert proxy.requests == 1 and proxy.denied == 1
    assert calls == ["/redirect"] and not cancel.is_set()


def test_real_proxy_disallows_write_methods_and_connect(scope):
    destination = network.ScopePolicy(scope).authorize_target("http://127.0.0.1:8123/", "nuclei")
    with mod._ScopedProxy(destination, rate=5, maximum=2, check=lambda: scope, cancel=threading.Event()) as proxy:
        for method, target in [("POST", "http://127.0.0.1:8123/"), ("DELETE", "http://127.0.0.1:8123/"), ("CONNECT", "127.0.0.1:8123")]:
            conn = http.client.HTTPConnection("127.0.0.1", proxy.server.server_port, timeout=2)
            conn.request(method, target)
            response = conn.getresponse()
            assert response.status == 403
            response.read()
            conn.close()
        assert proxy.requests == 0


def test_real_subprocess_capture_cancel_and_cleanup(tmp_path):
    cancel = threading.Event()
    timer = threading.Timer(0.3, cancel.set)
    timer.start()
    try:
        result = mod.run_bounded([sys.executable, "-c", "import time; print('synthetic',flush=True); time.sleep(10)"],
            cwd=tmp_path, env=mod._environment(tmp_path), timeout=5, cancel_event=cancel)
    finally:
        timer.cancel()
    assert result["code"] == "cancelled" and not result["ok"]
    assert result["duration_seconds"] < 4 and b"synthetic" in result["stdout"]


def test_real_subprocess_output_limit(tmp_path):
    result = mod.run_bounded([sys.executable, "-c", "print('x'*50000)"], cwd=tmp_path,
                            env=mod._environment(tmp_path), timeout=5, max_output=1024)
    assert result["code"] == "output_limit" and not result["ok"]
    assert len(result["stdout"]) <= 1024


def test_real_subprocess_scope_revocation_stops_child(tmp_path):
    started = time.monotonic()

    def check():
        if time.monotonic() - started > 0.2:
            raise mod.SecurityError("revoked", "scope_revoked")

    with pytest.raises(mod.SecurityError, match="revoked"):
        mod.run_bounded([sys.executable, "-c", "import time; time.sleep(10)"], cwd=tmp_path,
                        env=mod._environment(tmp_path), timeout=5, scope_check=check)
    assert time.monotonic() - started < 4
