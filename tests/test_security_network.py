"""Network adapters: only synthetic DNS/socket responses and harmless loopback HTTP."""
from contextlib import contextmanager
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import ssl
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nexus.security import network as net


@pytest.fixture
def scope():
    return {"id": "lab", "revision": 2, "name": "Meu laboratório", "targets": ["127.0.0.1", "example.com"],
            "allowed_tests": sorted(net.ALLOWED_TESTS), "authorization_confirmed": True,
            "environment": "lab", "purpose": "teste autorizado", "include_subdomains": False}


@pytest.mark.parametrize("target", ["0.0.0.0/0", "::/0", "224.0.0.0/4", "ff00::/8", "0.0.0.0",
    "::", "169.254.169.254", "fe80::1", "::ffff:127.0.0.1", "127.1", "2130706433", "0x7f000001",
    "127.0.0.1/24", "https://example.com", "*.example.com", "example.com/path", "example.com@evil.test"])
def test_rejects_open_special_or_ambiguous_scope_targets(scope, target):
    scope["targets"] = [target]
    with pytest.raises(ValueError):
        net.normalize_scope(scope)


@pytest.mark.parametrize("payload", [{}, {"authorization_confirmed": "true"}, {"authorization_confirmed": 1}])
def test_scope_requires_human_explicit_boolean_authorization(payload):
    with pytest.raises(ValueError, match="explicitamente"):
        net.normalize_scope(payload)


def test_scope_normalization_preserves_technical_terms_and_not_content_classification(scope):
    scope.update(name="Malware e exploração do meu laboratório", targets=["Example.COM.", "127.0.0.1", "127.0.0.1"])
    normalized = net.normalize_scope(scope)
    assert normalized["targets"] == ["example.com", "127.0.0.1"]
    assert normalized["name"].startswith("Malware")
    assert "id" not in normalized and "revision" not in normalized


@pytest.mark.parametrize("field,value", [("targets", []), ("targets", "example.com"), ("allowed_tests", ["exploit"]),
    ("allowed_tests", []), ("include_subdomains", "yes"), ("name", ""), ("name", "bad\nname")])
def test_invalid_scope_shape(scope, field, value):
    scope[field] = value
    with pytest.raises(ValueError):
        net.normalize_scope(scope)


def test_host_domain_grant_is_exact_by_default_and_preview_no_dns(scope, monkeypatch):
    dns = Mock(side_effect=AssertionError("preview must not resolve"))
    monkeypatch.setattr(net.socket, "getaddrinfo", dns)
    policy = net.ScopePolicy(scope)
    result = policy.authorize_target("https://example.com/", "http_headers", resolve=False)
    assert result["scope_id"] == "lab" and result["scope_revision"] == 2
    for host in ["sub.example.com", "evil-example.com", "example.com.evil.test"]:
        with pytest.raises(ValueError, match="fora do escopo"):
            policy.authorize_target(host, "http_headers", resolve=False)
    dns.assert_not_called()


def test_subdomains_must_be_enabled_explicitly(scope):
    scope["include_subdomains"] = True
    assert net.ScopePolicy(scope).authorize_target("sub.example.com", "http_headers", resolve=False)["host"] == "sub.example.com"


@pytest.mark.parametrize("target", ["http://u:p@example.com/", "http://example.com@127.0.0.1/",
    "http://127.0.0.1/a/../b", "http://127.0.0.1/%2e%2e/b", "http://127.0.0.1/%252e%252e/b",
    "http://127.0.0.1/a\\b", "http://127.0.0.1/%0d%0aX-Evil:bad", "http://127.0.0.1/?token=secret",
    "file:///etc/passwd", "http://127.0.0.1:99999/", "//example.com/", "http://127.0.0.1/#fragment"])
def test_url_credentials_queries_escapes_and_other_schemes_are_operational_errors(scope, target):
    with pytest.raises(ValueError):
        net.ScopePolicy(scope).authorize_target(target, "http_headers")


def test_disabled_scope_and_missing_tool_permission(scope):
    scope["enabled"] = False
    with pytest.raises(ValueError, match="revogado"):
        net.ScopePolicy(scope)
    scope["enabled"] = True
    scope["allowed_tests"] = ["osint"]
    with pytest.raises(ValueError, match="tipo de teste"):
        net.ScopePolicy(scope).authorize_target("example.com", "http_headers", resolve=False)


def test_network_grant_authorizes_one_ip_but_never_a_cidr_as_operation(scope):
    scope["targets"] = ["10.20.30.0/24"]
    policy = net.ScopePolicy(scope)
    assert policy.authorize_target("10.20.30.4", "tcp_connect")["addresses"] == ["10.20.30.4"]
    with pytest.raises(ValueError):
        policy.authorize_target("10.20.31.4", "tcp_connect")
    with pytest.raises(ValueError):
        policy.authorize_target("10.20.30.0/24", "tcp_connect")


def test_domain_grant_does_not_grant_private_dns_pivot(scope, monkeypatch):
    monkeypatch.setattr(net.socket, "getaddrinfo", lambda *a: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.4", 443))])
    with pytest.raises(ValueError, match="interno"):
        net.ScopePolicy(scope).authorize_target("example.com", "http_headers")
    scope["targets"].append("10.0.0.0/24")
    assert net.ScopePolicy(scope).authorize_target("example.com", "http_headers")["addresses"] == ["10.0.0.4"]


def test_one_unsafe_dns_answer_blocks_entire_target(scope, monkeypatch):
    monkeypatch.setattr(net.socket, "getaddrinfo", lambda *a: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.4", 443))])
    with pytest.raises(ValueError, match="interno"):
        net.ScopePolicy(scope).authorize_target("example.com", "http_headers")


def test_repeated_operation_revalidates_dns_instead_of_reusing_old_addresses(scope, monkeypatch):
    addresses = iter(["93.184.215.14", "10.0.0.4"])
    monkeypatch.setattr(net.socket, "getaddrinfo", lambda *a: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (next(addresses), 80))])
    fake = Mock()
    fake.recv.return_value = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"
    factory = Mock(return_value=fake)
    monkeypatch.setattr(net.socket, "socket", factory)
    assert net.inspect_http(scope, "http://example.com/")["ok"]
    result = net.inspect_http(scope, "http://example.com/")
    assert not result["ok"] and result["code"] == "SCOPE_OR_INPUT"
    assert factory.call_count == 1


@contextmanager
def local_server():
    class Handler(BaseHTTPRequestHandler):
        calls = []

        def do_HEAD(self):
            self.calls.append(self.path)
            self.send_response(302 if self.path == "/redirect" else 200)
            if self.path == "/redirect":
                self.send_header("Location", "http://outside.invalid/private")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Set-Cookie", "privatecookie=must-not-export")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port, Handler.calls
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_real_readonly_loopback_headers_redact_cookies_no_redirect_follow(scope):
    with local_server() as (port, calls):
        result = net.inspect_http(scope, f"http://127.0.0.1:{port}/redirect")
    assert result["ok"]
    assert calls == ["/redirect"]
    assert result["evidence"]["status"] == 302
    assert result["evidence"]["redirect"]["in_scope"] is False
    assert result["evidence"]["cookies_returned"] == 1
    assert "privatecookie" not in json.dumps(result)
    assert result["evidence"]["body_fetched"] is False
    assert all(f["confirmed"] is False for f in result["findings"])


def test_http_socket_connects_pinned_literal_not_hostname_again(scope, monkeypatch):
    dns = Mock(return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", 80))])
    monkeypatch.setattr(net.socket, "getaddrinfo", dns)
    fake = Mock()
    fake.recv.return_value = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"
    factory = Mock(return_value=fake)
    monkeypatch.setattr(net.socket, "socket", factory)
    result = net.inspect_http(scope, "http://example.com/")
    assert result["ok"]
    fake.connect.assert_called_once_with(("93.184.215.14", 80))
    assert dns.call_count == 1
    assert b"Host: example.com\r\n" in fake.sendall.call_args.args[0]


def test_http_header_budget_and_malformed_responses(scope, monkeypatch):
    fake = Mock()
    fake.recv.return_value = b"x" * 2048
    monkeypatch.setattr(net, "_connect", lambda *a: (fake, "127.0.0.1"))
    result = net.inspect_http(scope, "http://127.0.0.1/")
    assert not result["ok"] and "16 KiB" in result["error"]
    assert result["code"] == "PROTOCOL_ERROR"
    fake.close.assert_called_once()


def test_tls_invalid_certificate_never_falls_back_to_unverified(scope, monkeypatch):
    fake = Mock()
    context = Mock()
    context.wrap_socket.side_effect = ssl.SSLCertVerificationError(1, "self-signed")
    factory = Mock(return_value=context)
    monkeypatch.setattr(net.ssl, "create_default_context", factory)
    monkeypatch.setattr(net, "_connect", lambda *a: (fake, "127.0.0.1"))
    result = net.inspect_tls(scope, "https://127.0.0.1/")
    assert not result["ok"] and result["code"] == "TLS_CERTIFICATE_INVALID"
    factory.assert_called_once_with()
    context.wrap_socket.assert_called_once()


def test_tls_reports_verified_fingerprint_and_validity(scope, monkeypatch):
    fake = Mock()
    fake.getpeercert.side_effect = lambda binary_form=False: b"dercertificate" if binary_form else {
        "notBefore": "Jan 1 00:00:00 2026 GMT", "notAfter": "Jan 1 00:00:00 2027 GMT", "subjectAltName": [("DNS", "example.com")]}
    fake.version.return_value = "TLSv1.3"
    fake.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    monkeypatch.setattr(net, "_connect", lambda *a: (fake, "127.0.0.1"))
    monkeypatch.setattr(net, "_tls", lambda *a: fake)
    result = net.inspect_tls(scope, "https://127.0.0.1/")
    assert result["ok"] and result["evidence"]["verified"] is True
    assert result["evidence"]["sha256"] == hashlib.sha256(b"dercertificate").hexdigest()


def test_real_loopback_tcp_connect_only_no_payload(scope):
    with local_server() as (port, calls):
        result = net.tcp_probe(scope, "127.0.0.1", [port])
    assert result["ok"] and result["evidence"]["ports"][0]["state"] == "open"
    assert result["evidence"]["payload_sent"] is False and calls == []


@pytest.mark.parametrize("ports", [[], [0], [65536], [True], ["80"], list(range(1, 10))])
def test_tcp_port_bounds_are_not_topic_filters(scope, ports):
    result = net.tcp_probe(scope, "127.0.0.1", ports)
    assert result["ok"] is False and result["code"] == "SCOPE_OR_INPUT"


def test_unavailable_nmap_is_honest_and_no_process_created(scope, monkeypatch):
    monkeypatch.setattr(net, "_nmap_path", lambda: None)
    process = Mock(side_effect=AssertionError("must not execute"))
    monkeypatch.setattr(net.subprocess, "Popen", process)
    result = net.run_nmap(scope, "127.0.0.1", [80])
    assert not result["ok"] and result["code"] == "TOOL_UNAVAILABLE"
    process.assert_not_called()


def test_nmap_fixed_argv_no_shell_scripts_or_remote_dns(scope, monkeypatch, tmp_path):
    executable = tmp_path / "nmap.exe"
    executable.write_bytes(b"synthetic mock executable never run")
    monkeypatch.setattr(net, "_nmap_path", lambda: executable)
    output = b'''<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun><host><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host></nmaprun>'''
    factory = Mock(return_value=(0, output, b""))
    monkeypatch.setattr(net, "_run_nmap_capture", factory)
    result = net.run_nmap(scope, "127.0.0.1", [80, 443])
    assert result["ok"]
    argv = factory.call_args.args[0]
    assert argv[-1] == "127.0.0.1" and "-sT" in argv and "-n" in argv
    assert not any(x in argv for x in ["--script", "-A", "-sV", "-sU", "-O"])
    assert result["evidence"]["signature_verified"] is False
    assert result["evidence"]["ports"][0]["state"] == "open"


@pytest.mark.parametrize("xml", [b'<!DOCTYPE nmaprun [<!ENTITY x SYSTEM "file:///private">]><nmaprun/>',
    b'<!DOCTYPE nmaprun SYSTEM "https://evil.invalid/external.dtd"><nmaprun/>',
    '<!DOCTYPE nmaprun [<!ENTITY x "expanded">]><nmaprun/>'.encode("utf-16")])
def test_nmap_refuses_entities_and_noncanonical_dtd(scope, monkeypatch, tmp_path, xml):
    executable = tmp_path / "nmap.exe"
    executable.write_bytes(b"not executed")
    monkeypatch.setattr(net, "_nmap_path", lambda: executable)
    monkeypatch.setattr(net, "_run_nmap_capture", Mock(return_value=(0, xml, b"")))
    result = net.run_nmap(scope, "127.0.0.1", [80])
    assert not result["ok"] and result["code"] == "PROTOCOL_ERROR"


def test_process_capture_has_no_shell_and_enforces_output_budget(monkeypatch):
    process = Mock(returncode=0)
    process.__enter__ = Mock(return_value=process)
    process.__exit__ = Mock(return_value=False)
    process.poll.return_value = None

    def launch(argv, **kwargs):
        assert kwargs["shell"] is False
        kwargs["stdout"].write(b"x" * (net.MAX_NMAP_XML + 1))
        kwargs["stdout"].flush()
        return process

    monkeypatch.setattr(net.subprocess, "Popen", launch)
    with pytest.raises(ValueError, match="limite"):
        net._run_nmap_capture(["dummy-never-executed"])
    process.kill.assert_called_once()


def test_process_capture_enforces_timeout_and_kills_child(monkeypatch):
    process = Mock(returncode=0)
    process.__enter__ = Mock(return_value=process)
    process.__exit__ = Mock(return_value=False)
    process.poll.return_value = None
    monkeypatch.setattr(net.subprocess, "Popen", Mock(return_value=process))
    timer = iter([0, 31])
    monkeypatch.setattr(net.time, "monotonic", lambda: next(timer))
    with pytest.raises(net.subprocess.TimeoutExpired):
        net._run_nmap_capture(["dummy-never-executed"])
    process.kill.assert_called_once()


def test_dork_preview_does_not_touch_dns_and_quotes_free_text(scope, monkeypatch):
    monkeypatch.setattr(net.socket, "getaddrinfo", Mock(side_effect=AssertionError("No network in preview")))
    built = net.build_dork(scope, "example.com", {"intitle": "technical report"}, "pdf", ["vulnerability laboratory"], ["old"], 3)
    assert built["query"] == 'site:example.com intitle:"technical report" filetype:pdf "vulnerability laboratory" -"old"'
    assert built["preview_only"] is True


@pytest.mark.parametrize("kwargs", [{"operators": {"site": "evil.test"}}, {"keywords": 'x" OR site:evil.test'},
    {"document_type": "pdf OR html"}, {"max_results": 100}, {"domain": "outside.test"},
    {"keywords": "api_key=supersecret"}, {"keywords": "ghp_abcdefghijklmnopqrstuv"}])
def test_dork_refuses_scope_escape_operator_injection_and_secret_disclosure(scope, kwargs):
    args = {"domain": "example.com", **kwargs}
    with pytest.raises(ValueError):
        net.build_dork(scope, **args)


def test_osint_rebuilds_query_filters_domains_and_does_not_fetch_results(scope):
    tools = Mock()
    tools.execute.return_value = {"ok": True, "provider": "mock", "results": [
        {"url": "https://example.com/report.pdf", "title": "report"},
        {"url": "https://outside.test/report.pdf", "title": "outside"},
        {"url": "https://sub.example.com/report.pdf", "title": "not granted"},
        {"url": "https://u:p@example.com/private", "title": "credentials"}]}
    result = net.run_osint(scope, {"domain": "example.com", "keywords": "technical", "query": "site:outside.test"}, tools)
    assert result["ok"]
    assert [x["url"] for x in result["evidence"]["results"]] == ["https://example.com/report.pdf"]
    tools.execute.assert_called_once_with("search_web", {"query": 'site:example.com "technical"', "max_results": 5})


@pytest.mark.parametrize("value", ["CVE-2024-1", "CVE-2024-1234/../../x", "https://evil.test", "CVE-2024-1234\r\nX:bad", 5])
def test_cve_only_accepts_identifier_no_url_input(value):
    result = net.lookup_cve(value)
    assert result["ok"] is False and result["code"] == "SCOPE_OR_INPUT"


def test_cve_fixed_official_source_records_evidence_without_claiming_host_vulnerability(monkeypatch):
    record = {"cveMetadata": {"cveId": "CVE-2024-1234", "state": "PUBLISHED"},
              "containers": {"cna": {"title": "Lab bug", "descriptions": [{"lang": "en", "value": "public description"}]}}}
    body = json.dumps(record).encode()
    response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    fake = Mock()
    fake.recv.side_effect = [response, b""]
    monkeypatch.setattr(net, "_resolve", lambda *a: ["93.184.215.14"])
    monkeypatch.setattr(net, "_connect", lambda *a: (fake, "93.184.215.14"))
    monkeypatch.setattr(net, "_tls", lambda *a: fake)
    result = net.lookup_cve("cve-2024-1234")
    assert result["ok"] and result["evidence"]["title"] == "Lab bug"
    request = fake.sendall.call_args.args[0]
    assert b"Host: cveawg.mitre.org" in request and b"/api/cve/CVE-2024-1234" in request
    assert "não confirma" in result["evidence"]["notice"]
