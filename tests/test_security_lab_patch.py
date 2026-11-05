"""Real HTTP before/after exact shipped SQL source; no unknown project execution."""
import hashlib
import http.client
import json
import os
from pathlib import Path
from urllib.parse import urlencode
from unittest.mock import Mock

import pytest

from scripts import security_lab as lab
from nexus.security.static import audit_project


def request(server, name):
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=4)
    try:
        connection.request("GET", "/sqli?" + urlencode({"name": name}))
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        connection.close()


def project(tmp_path, source, *, fixed=False):
    (tmp_path / "settings.json").write_text(json.dumps({"fixed": fixed}), encoding="utf-8")
    (tmp_path / "queries.py").write_bytes(source.encode("utf-8"))
    return tmp_path / "queries.py"


def test_real_http_source_patch_fixes_sqli_and_static_finding_without_auth_toggle(tmp_path):
    source = project(tmp_path, lab.VULNERABLE_QUERY_SOURCE)
    before_audit = audit_project(tmp_path)
    finding = next(x for x in before_audit["findings"] if x["id"] == "PY-SQL-CONSTRUCTION")
    assert finding["file"] == "queries.py" and finding["line"] == 2
    injected = "NEXUS_LAB_A' OR '1'='1"
    with lab.lab_server(root=tmp_path) as server:
        status, baseline = request(server, "NEXUS_LAB_A")
        assert status == 200 and baseline["markers"] == ["NEXUS_LAB_SQLI_MARKER_A"]
        status, before = request(server, injected)
        assert status == 200 and set(before["markers"]) == {"NEXUS_LAB_SQLI_MARKER_A", "NEXUS_LAB_SQLI_MARKER_B"}
        assert before["query_source"]["mode"] == "vulnerable"
        assert before["query_source"]["sha256"] == hashlib.sha256(lab.VULNERABLE_QUERY_SOURCE.encode()).hexdigest()
        source.write_bytes(lab.FIXED_QUERY_SOURCE.encode("utf-8"))
        status, after = request(server, injected)
        assert status == 200 and after["markers"] == []
        assert after["query_source"]["mode"] == "parameterized"
        assert after["query_source"]["sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
        assert request(server, "NEXUS_LAB_A")[1]["markers"] == baseline["markers"]
        assert server.fixed_mode() is False  # SQL source and auth/session fixture are independent.
    assert not any(x["id"] == "PY-SQL-CONSTRUCTION" for x in audit_project(tmp_path)["findings"])


def test_unknown_query_code_never_compiled_or_executed_and_never_falls_back(tmp_path, monkeypatch):
    sentinel = tmp_path / "must-not-exist.txt"
    source = project(tmp_path, lab.FIXED_QUERY_SOURCE, fixed=True)
    source.write_text("from pathlib import Path\nPath(" + repr(str(sentinel)) + ").write_text('arbitrary effect')\n" + lab.FIXED_QUERY_SOURCE,
                      encoding="utf-8")
    compiler = Mock(side_effect=AssertionError("Unknown source must never be compiled"))
    monkeypatch.setattr(lab, "compile", compiler, raising=False)
    with lab.lab_server(root=tmp_path) as server:
        status, result = request(server, "NEXUS_LAB_A")
    assert status == 503 and result["code"] == "unapproved_query_fixture"
    assert not sentinel.exists()
    compiler.assert_not_called()
    assert "Path(" not in json.dumps(result) and str(tmp_path) not in json.dumps(result)


def test_sql_fixture_remains_independent_from_fixed_auth_settings(tmp_path):
    project(tmp_path, lab.VULNERABLE_QUERY_SOURCE, fixed=True)
    with lab.lab_server(root=tmp_path) as server:
        assert server.fixed_mode() is True
        assert len(request(server, "NEXUS_LAB_A' OR '1'='1")[1]["markers"]) == 2


@pytest.mark.parametrize("payload", [lab.FIXED_QUERY_SOURCE.replace("\n", "\r\n").encode(),
    b"\xef\xbb\xbf" + lab.FIXED_QUERY_SOURCE.encode(), (lab.FIXED_QUERY_SOURCE + "# unreviewed edit\n").encode(),
    lab.FIXED_QUERY_SOURCE.replace("lookup_name", "unknown_function").encode(), b"x" * 4097, b"\xff\xfe"])
def test_only_exact_utf8_fixture_bytes_are_accepted(tmp_path, payload, monkeypatch):
    source = tmp_path / "queries.py"
    source.write_bytes(payload)
    compiler = Mock(side_effect=AssertionError("No approximate source matching"))
    monkeypatch.setattr(lab, "compile", compiler, raising=False)
    with pytest.raises(lab.LabFixtureError):
        lab._load_query_fixture(tmp_path)
    compiler.assert_not_called()


def test_known_source_compiles_into_minimal_namespace_and_does_not_import_project(tmp_path):
    source = project(tmp_path, lab.FIXED_QUERY_SOURCE)
    (tmp_path / "sitecustomize.py").write_text("raise RuntimeError('unknown project code')\n", encoding="utf-8")
    lookup, metadata = lab._load_query_fixture(tmp_path)
    assert lookup.__globals__["__builtins__"] == {}
    assert metadata == {"mode": "parameterized", "sha256": hashlib.sha256(source.read_bytes()).hexdigest(), "known_fixture": True}
    database = Mock()
    database.execute.return_value.fetchall.return_value = [("synthetic",)]
    assert lookup(database, "name' value") == [("synthetic",)]
    database.execute.assert_called_once_with("SELECT marker FROM records WHERE name = ?", ("name' value",))


def test_hardlinked_fixture_is_rejected(tmp_path):
    original = tmp_path / "original.py"
    original.write_bytes(lab.FIXED_QUERY_SOURCE.encode())
    os.link(original, tmp_path / "queries.py")
    with pytest.raises(lab.LabFixtureError):
        lab._load_query_fixture(tmp_path)


def test_nonregular_fixture_is_rejected(tmp_path):
    (tmp_path / "queries.py").mkdir()
    with lab.lab_server(root=tmp_path) as server:
        status, result = request(server, "NEXUS_LAB_A")
    assert status == 503 and result["code"] == "unapproved_query_fixture"


def test_absent_optional_source_preserves_settings_sql_fallback(tmp_path):
    (tmp_path / "settings.json").write_text('{"fixed":false}', encoding="utf-8")
    with lab.lab_server(root=tmp_path) as server:
        assert lab._load_query_fixture(tmp_path) is None
        status, before = request(server, "NEXUS_LAB_A' OR '1'='1")
        assert status == 200 and len(before["markers"]) == 2 and "query_source" not in before
        (tmp_path / "settings.json").write_text('{"fixed":true}', encoding="utf-8")
        status, after = request(server, "NEXUS_LAB_A' OR '1'='1")
        assert status == 200 and after["markers"] == [] and "query_source" not in after
