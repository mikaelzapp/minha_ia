import io
import json
from pathlib import Path
import queue
import time

import pytest

from nexus.security import rea


@pytest.fixture
def sample(tmp_path):
    path = tmp_path / "security/samples/1234.sample"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"MZ" + b"\0" * 100)
    return tmp_path, path


class Session:
    def __init__(self):
        self.calls = []
        self.closed = False
        self.deadline = time.monotonic() + 45

    def tool(self, name, args):
        self.calls.append((name, args))
        if name == "binary_session":
            return {"structuredContent": {"result": {
                "analysis_provider_candidates": [{"provider": {"id": "ghidra", "name": "Ghidra"},
                    "availability": {"status": "unavailable", "reason": "not installed"}}],
                "tool_availability": {"groups": [{"names": ["inspect_pe_imports", "execute_binary"], "available": True}]}}}}
        return {"structuredContent": {"operation": name}, "content": []}

    def close(self):
        self.closed = True


def test_missing_package_is_not_mcp_ready(monkeypatch, tmp_path):
    monkeypatch.setattr(rea, "_package", lambda: {"available": False})
    result = rea.REA(tmp_path).inventory()
    assert not result["ok"] and not result["available"] and result["code"] == "rea_unavailable"


def test_connected_mcp_does_not_claim_decompiler(monkeypatch, tmp_path):
    session = Session()
    monkeypatch.setattr(rea.REA, "_session", lambda self: session)
    result = rea.REA(tmp_path).inventory()
    assert result["available"] and result["mcp"]["connected"] and session.closed
    assert result["providers"][0]["availability"]["status"] == "unavailable"
    assert "execute_binary" not in json.dumps(result)


def test_pe_is_static_only_and_always_closes(monkeypatch, sample):
    root, path = sample
    session = Session()
    monkeypatch.setattr(rea.REA, "_session", lambda self: session)
    result = rea.REA(root).analyze(path)
    assert result["ok"] and not result["target_executed"] and result["sha256"]
    assert [name for name, _ in session.calls] == ["inspect_pe_imports", "inspect_managed_artifact"]
    assert session.closed


def test_zip_uses_inventory_and_closes_target(monkeypatch, sample):
    root, path = sample
    path.write_bytes(b"PK\x03\x04" + b"\0" * 100)
    session = Session()
    monkeypatch.setattr(rea.REA, "_session", lambda self: session)
    assert rea.REA(root).analyze(path)["ok"]
    assert [name for name, _ in session.calls] == ["open_binary", "inspect_artifact", "close_binary"]


def test_elf_export_inspection_is_target_free(monkeypatch, sample):
    root, path = sample
    path.write_bytes(b"\x7fELF" + b"\0" * 100)
    session = Session()
    monkeypatch.setattr(rea.REA, "_session", lambda self: session)
    assert rea.REA(root).analyze(path)["ok"]
    assert session.calls[0][0] == "inspect_native_exports"


def test_timeout_is_not_a_model_refusal(monkeypatch, sample):
    root, path = sample
    def unavailable(self):
        raise rea.REAError("tool_timeout", "deadline")
    monkeypatch.setattr(rea.REA, "_session", unavailable)
    result = rea.REA(root).analyze(path)
    assert not result["ok"] and result["code"] == "tool_timeout"
    assert not result["target_executed"] and "fallback" in result


def test_changed_sample_discards_evidence(monkeypatch, sample):
    root, path = sample
    session = Session()
    original = session.tool
    def changing(name, args):
        result = original(name, args)
        path.write_bytes(path.read_bytes() + b"changed")
        return result
    session.tool = changing
    monkeypatch.setattr(rea.REA, "_session", lambda self: session)
    result = rea.REA(root).analyze(path)
    assert not result["ok"] and result["code"] == "artifact_changed" and "evidence" not in result


def test_outside_isolated_store_never_starts_process(monkeypatch, tmp_path):
    path = tmp_path / "private.exe"
    path.write_bytes(b"MZ")
    monkeypatch.setattr(rea.REA, "_session", lambda self: pytest.fail("must not start"))
    result = rea.REA(tmp_path).analyze(path)
    assert result["code"] == "outside_sample_store"


def test_runtime_directory_is_not_accepted_as_sample(monkeypatch, tmp_path):
    path = tmp_path / "security/rea/script.mjs"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"MZ")
    monkeypatch.setattr(rea.REA, "_session", lambda self: pytest.fail("must not start"))
    assert rea.REA(tmp_path).analyze(path)["code"] == "outside_sample_store"


def test_tool_allowlist_blocks_runtime_operations():
    client = object.__new__(rea._Stdio)
    client.request = lambda *a, **kw: pytest.fail("must not request")
    with pytest.raises(rea.REAError, match="somente inspeção estática"):
        client.tool("execute_binary", {"path": "C:/Windows/system32/cmd.exe"})


def test_mcp_errors_and_notifications_are_handled():
    client = object.__new__(rea._Stdio)
    client.counter = 0
    client.deadline = time.monotonic() + 1
    client.failure = None
    client.stdout_bytes = 0
    client.responses = queue.Queue()
    client._send = lambda value: None
    client.responses.put({"jsonrpc": "2.0", "method": "notifications/progress", "params": {}})
    client.responses.put({"jsonrpc": "2.0", "id": 1, "error": {"code": -32602, "message": "bad input"}})
    with pytest.raises(rea.REAError) as exc:
        client.request("tools/call", {})
    assert exc.value.code == "rea_rpc_error"


def test_transport_output_limit_fails_closed():
    client = object.__new__(rea._Stdio)
    client.process = type("Proc", (), {"stdout": io.BytesIO(b"x" * (rea.MAX_OUTPUT + 1))})()
    client.failure = None
    client.stdout_bytes = 0
    client.responses = queue.Queue()
    client._read()
    assert client.failure.code == "output_limit" and client.responses.empty()


def test_transport_invalid_json_fails_closed():
    client = object.__new__(rea._Stdio)
    client.process = type("Proc", (), {"stdout": io.BytesIO(b"not json\n")})()
    client.failure = None
    client.stdout_bytes = 0
    client.responses = queue.Queue()
    client._read()
    assert client.failure.code == "invalid_tool_output"


def test_protocol_failure_closes_client(monkeypatch, tmp_path):
    class Proc:
        stdin = io.BytesIO()
        stdout = io.BytesIO()
        stderr = io.BytesIO()
        pid = 999999999
        def wait(self, **kwargs): return 0
    monkeypatch.setattr(rea.subprocess, "Popen", lambda *a, **kw: Proc())
    monkeypatch.setattr(rea._Stdio, "request", lambda *a, **kw: (_ for _ in ()).throw(rea.REAError("bad", "bad handshake")))
    closed = []
    monkeypatch.setattr(rea._Stdio, "close", lambda self: closed.append(True))
    with pytest.raises(rea.REAError):
        rea._Stdio("node", "entry", tmp_path)
    assert closed
