"""Real synthetic loopback SQL/auth regression; no public endpoints or credentials."""
import copy
import json
from pathlib import Path
import threading
from unittest.mock import Mock

import pytest

from nexus.security import appsec
from nexus.security import network
from scripts.security_lab import lab_server, LabServer


@pytest.fixture
def scope(monkeypatch):
    # Keep this adapter suite independently runnable during additive integration.
    monkeypatch.setattr(network, "ALLOWED_TESTS", network.ALLOWED_TESTS | {"appsec_sqli", "appsec_auth"})
    return {"id": "synthetic-appsec", "revision": 1, "name": "Loopback fictício",
            "targets": ["127.0.0.1"], "allowed_tests": ["appsec_sqli", "appsec_auth"],
            "environment": "lab", "authorization_confirmed": True}


@pytest.fixture(scope="module")
def lab():
    with lab_server() as server:
        yield server


def test_real_sqli_confirmed_then_fixed_parameterized(scope, lab):
    lab.fixed = False
    before = appsec.run_sqli(scope, lab.url + "/sqli", lab_confirmation=True)
    assert before["ok"] and before["validation"] == "confirmed_controlled"
    assert before["requests"] == 6
    assert before["findings"][0]["cwe"] == "CWE-89"
    assert before["evidence"]["no_data_expansion"]
    lab.fixed = True
    after = appsec.run_sqli(scope, lab.url + "/sqli", lab_confirmation=True)
    assert after["ok"] and not after["findings"]
    assert after["validation"] == "no_finding_in_coverage"


def test_real_auth_matrix_cookie_cors_logout_then_fixed(scope, lab):
    lab.fixed = False
    before = appsec.run_auth(scope, lab.url, synthetic_accounts_confirmed=True, lab_confirmation=True)
    assert before["ok"], before
    assert before["requests"] == 12
    ids = {row["id"] for row in before["findings"]}
    assert {"APPSEC-BOLA", "APPSEC-CORS-CREDENTIALS", "APPSEC-SESSION-LOGOUT", "APPSEC-COOKIE-ATTRIBUTES"} <= ids
    matrix = before["evidence"]["access_matrix"]
    assert any(row["actor"] == "A" and row["resource_owner"] == "B" and row["synthetic_marker_present"] for row in matrix)
    text = json.dumps(before)
    assert "NEXUS_LAB_PASSWORD" not in text
    assert "Set-Cookie" not in text and "body" not in text
    for session in lab.sessions:
        assert session not in text
    lab.fixed = True
    after = appsec.run_auth(scope, lab.url, synthetic_accounts_confirmed=True, lab_confirmation=True)
    assert after["ok"] and not after["findings"], after
    assert after["not_tested"] and after["evidence"]["credentials_retained"] is False


@pytest.mark.parametrize("environment", ["production", "prod", "prod-lab", "lab-production", "preview", "desenvolvimento", "staging-prod", ""])
def test_active_tests_refuse_environment_without_exact_lab_class(scope, environment):
    scope["environment"] = environment
    with pytest.raises(ValueError):
        appsec.preview_sqli(scope, "http://127.0.0.1/sqli", lab_confirmation=True)


@pytest.mark.parametrize("environment", sorted(appsec.ENVIRONMENTS))
def test_exact_lab_environment_classes(scope, environment):
    scope["environment"] = environment
    assert appsec.preview_sqli(scope, "http://127.0.0.1/sqli", lab_confirmation=True)["approval_required"]


@pytest.mark.parametrize("value", [False, 1, "true", None])
def test_explicit_boolean_lab_and_synthetic_account_approval(scope, value):
    with pytest.raises(ValueError):
        appsec.preview_sqli(scope, "http://127.0.0.1/sqli", lab_confirmation=value)
    with pytest.raises(ValueError):
        appsec.preview_auth(scope, "http://127.0.0.1", synthetic_accounts_confirmed=value, lab_confirmation=True)


@pytest.mark.parametrize("value", ["customer-row", "admin", "NEXUS_LAB_A' OR 1=1", "NEXUS_LAB_", "NEXUS_LAB_A\r\nX:bad", 1])
def test_sql_fixture_requires_synthetic_identifier_without_arbitrary_payload(scope, value):
    with pytest.raises(ValueError):
        appsec.preview_sqli(scope, "http://127.0.0.1/sqli", baseline=value, lab_confirmation=True)


@pytest.mark.parametrize("target", ["http://192.0.2.1/", "http://127.0.0.1/a/../b", "http://u:p@127.0.0.1/", "http://127.0.0.1/?secret=x", "file:///tmp/a"])
def test_preview_scope_and_url_validation_no_connection(scope, monkeypatch, target):
    connect = Mock(side_effect=AssertionError("must not connect"))
    monkeypatch.setattr(network, "_connect", connect)
    with pytest.raises(ValueError):
        appsec.preview_sqli(scope, target, lab_confirmation=True)
    connect.assert_not_called()


def test_preview_has_no_credentials_and_no_dns(scope, monkeypatch):
    dns = Mock(side_effect=AssertionError("preview must not resolve"))
    monkeypatch.setattr(network, "_resolve", dns)
    result = appsec.preview_auth(scope, "http://127.0.0.1", synthetic_accounts_confirmed=True, lab_confirmation=True)
    serialized = json.dumps(result)
    assert "PASSWORD" not in serialized and "password_field" not in serialized
    assert result["requests_planned"] == 12
    dns.assert_not_called()


@pytest.mark.parametrize("path", ["//example.com/a", "/api/../NEXUS_LAB_A", "/api/%2e%2e/NEXUS_LAB_A", "/a?secret=x", "/a#b", "http://example.com/NEXUS_LAB_A"])
def test_auth_fixture_paths_cannot_escape_origin_or_add_queries(scope, path):
    fixture = copy.deepcopy(appsec.DEFAULT_FIXTURE)
    fixture["account_a"]["resource"] = path
    with pytest.raises(ValueError):
        appsec.preview_auth(scope, "http://127.0.0.1", fixture, True, True)


def test_accounts_and_resources_must_differ(scope):
    fixture = copy.deepcopy(appsec.DEFAULT_FIXTURE)
    fixture["account_b"] = fixture["account_a"]
    with pytest.raises(ValueError):
        appsec.preview_auth(scope, "http://127.0.0.1", fixture, True, True)


def test_revocation_checked_before_every_request(scope, lab):
    lab.fixed = False
    calls = 0
    def loader():
        nonlocal calls
        calls += 1
        return {**scope, "enabled": calls < 4}
    result = appsec.run_sqli(scope, lab.url + "/sqli", lab_confirmation=True, scope_loader=loader)
    assert not result["ok"] and result["requests"] < 6


def test_scope_revision_change_and_cancellation_no_connect(scope, monkeypatch):
    connect = Mock(side_effect=AssertionError("must not connect"))
    monkeypatch.setattr(network, "_connect", connect)
    result = appsec.run_sqli(scope, "http://127.0.0.1/sqli", lab_confirmation=True, scope_loader=lambda: {**scope, "revision": 2})
    assert result["code"] == "scope_changed"
    event = threading.Event()
    event.set()
    result = appsec.run_auth(scope, "http://127.0.0.1", synthetic_accounts_confirmed=True, lab_confirmation=True, cancel=event)
    assert result["code"] == "cancelled"
    connect.assert_not_called()


def test_sql_static_auditor_existing_rule_not_dynamic_confirmation(tmp_path):
    from nexus.security.static import audit_project
    (tmp_path / "app.py").write_text("def lookup(cursor, user_input):\n    return cursor.execute(f\"SELECT marker FROM records WHERE name = '{user_input}'\")\n", encoding="utf-8")
    result = audit_project(tmp_path)
    row = next(row for row in result["findings"] if row["id"] == "PY-SQL-CONSTRUCTION")
    assert row["validation"] == "unconfirmed"
    assert row["file"] == "app.py" and row["line"] == 2


def test_lab_config_fixed_mode_switch_without_code_execution(scope, tmp_path):
    settings = tmp_path / "settings.json"
    settings.write_text('{"fixed": false}', encoding="utf-8")
    with lab_server(root=tmp_path) as server:
        before = appsec.run_sqli(scope, server.url + "/sqli", lab_confirmation=True)
        assert before["validation"] == "confirmed_controlled"
        settings.write_text('{"fixed": true}', encoding="utf-8")
        after = appsec.run_sqli(scope, server.url + "/sqli", lab_confirmation=True)
        assert not after["findings"]
        settings.write_text("invalid configuration", encoding="utf-8")
        assert server.fixed_mode() is True


def test_lab_never_binds_public_interfaces():
    with pytest.raises(ValueError):
        LabServer(("0.0.0.0", 0))


def test_failed_fixture_login_is_inconclusive_without_secret_values(scope, lab):
    fixture = copy.deepcopy(appsec.DEFAULT_FIXTURE)
    fixture["account_a"]["password"] = "NEXUS_LAB_WRONG_SECRET"
    result = appsec.run_auth(scope, lab.url, fixture, True, True)
    assert result["code"] == "fixture_login_failed"
    assert "NEXUS_LAB_WRONG_SECRET" not in json.dumps(result)


def test_sql_baseline_missing_is_inconclusive(scope, lab):
    result = appsec.run_sqli(scope, lab.url + "/sqli", baseline="NEXUS_LAB_UNKNOWN", lab_confirmation=True)
    assert result["ok"] and result["validation"] == "inconclusive"


def test_transport_rejects_query_before_socket(scope, monkeypatch):
    connect = Mock(side_effect=AssertionError("must not connect"))
    monkeypatch.setattr(network, "_connect", connect)
    transport = appsec._Transport(scope, "appsec_auth")
    with pytest.raises(ValueError):
        transport.request("http://127.0.0.1/?token=real")
    connect.assert_not_called()


def test_response_limit_and_repeated_failures_stop(scope, monkeypatch):
    transport = appsec._Transport(scope, "appsec_auth")
    transport.failures = 3
    with pytest.raises(ValueError, match="Limite"):
        transport.check()
    transport.failures = 0
    transport.requests = appsec.MAX_REQUESTS
    with pytest.raises(ValueError, match="Limite"):
        transport.check()


def test_untrusted_cookie_values_never_appear_in_public_evidence():
    from email.message import Message
    headers = Message()
    headers.add_header("Set-Cookie", "lab=secretValue; HttpOnly; SameSite=Lax; Secure")
    jar, flags = appsec._cookies({"headers": headers})
    assert "secretValue" in jar and "secretValue" not in json.dumps(flags)
    assert flags == [{"name": "lab", "httponly": True, "secure": True, "samesite": "lax"}]


@pytest.mark.parametrize("raw", [
    b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\n{}",
    b"HTTP/1.1 200 OK\r\nX-Untrusted: " + b"x" * (appsec.MAX_HEADERS + 1) + b"\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n" + b"x" * (appsec.MAX_RESPONSE + appsec.MAX_HEADERS),
    b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial-private-cookie-value",
])
def test_malformed_oversize_compressed_http_does_not_expose_bytes(scope, monkeypatch, raw):
    class Socket:
        def __init__(self):
            self.raw, self.closed = bytearray(raw), False
        def settimeout(self, _timeout):
            pass
        def sendall(self, _request):
            pass
        def recv(self, count):
            output = bytes(self.raw[:count])
            del self.raw[:count]
            return output
        def close(self):
            self.closed = True
    sock = Socket()
    monkeypatch.setattr(network, "_connect", lambda *_args: (sock, "127.0.0.1"))
    result = appsec.run_sqli(scope, "http://127.0.0.1/sqli", lab_confirmation=True)
    assert not result["ok"] and sock.closed
    assert "private-cookie-value" not in json.dumps(result)
    assert "xxxx" not in json.dumps(result)


def test_invalid_target_credentials_omitted_even_direct_adapter_error(scope):
    result = appsec.run_sqli(scope, "http://real-user:real-secret@127.0.0.1/", lab_confirmation=True)
    assert not result["ok"]
    assert "real-user" not in json.dumps(result) and "real-secret" not in json.dumps(result)


def test_auth_origin_path_must_match_the_preview(scope):
    with pytest.raises(ValueError, match="origem"):
        appsec.preview_auth(scope, "http://127.0.0.1/unexpected/", synthetic_accounts_confirmed=True, lab_confirmation=True)


def test_environment_class_overrides_free_text_lab_label(scope):
    scope["environment_class"] = "production"
    with pytest.raises(ValueError):
        appsec.preview_sqli(scope, "http://127.0.0.1/sqli", lab_confirmation=True)
    scope.update(environment="Homologação da aplicação", environment_class="staging")
    assert appsec.preview_sqli(scope, "http://127.0.0.1/sqli", lab_confirmation=True)
