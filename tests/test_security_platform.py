import base64
import json
import os
from pathlib import Path
from types import SimpleNamespace

import psutil
import pytest

from nexus.security import platform


def test_unknown_section_does_not_spawn(monkeypatch):
    monkeypatch.setattr(platform, "run_process", lambda *a, **kw: pytest.fail("spawn"))
    assert platform.blue_status("defender; Stop-Service WinDefend")["code"] == "invalid_section"


def test_processes_do_not_collect_command_lines(monkeypatch):
    def processes(attrs, ad_value):
        assert "cmdline" not in attrs and "environ" not in attrs
        return [SimpleNamespace(info={"pid": 7, "name": "python", "memory_info": SimpleNamespace(rss=123)})]
    monkeypatch.setattr(platform.psutil, "process_iter", processes)
    result = platform.blue_status("processes")
    assert result["ok"] and result["data"][0]["rss_bytes"] == 123
    assert "memory_info" not in result["data"][0]


def test_process_inventory_is_bounded(monkeypatch):
    monkeypatch.setattr(platform.psutil, "process_iter", lambda *a, **kw:
                        (SimpleNamespace(info={"pid": n}) for n in range(1000)))
    result = platform.blue_status("processes")
    assert len(result["data"]) == 150 and result["truncated"]


def test_access_denial_is_tool_failure(monkeypatch):
    def deny(*a, **kw):
        raise psutil.AccessDenied()
    monkeypatch.setattr(platform.psutil, "net_connections", deny)
    result = platform.blue_status("connections")
    assert result["code"] == "permission_denied" and not result["ok"]


def test_connection_metadata_without_packets(monkeypatch):
    addr = lambda ip, port: SimpleNamespace(ip=ip, port=port)
    monkeypatch.setattr(platform.psutil, "net_connections", lambda **kw: [SimpleNamespace(
        pid=12, family=2, type=1, laddr=addr("127.0.0.1", 8765), raddr=(), status="LISTEN")])
    result = platform.blue_status("connections")
    assert result["data"][0]["local"]["port"] == 8765
    assert result["data"][0]["remote"] is None


@pytest.mark.skipif(os.name != "nt", reason="Windows native PowerShell contract")
@pytest.mark.parametrize("section", ["startup", "tasks", "defender", "events"])
def test_native_queries_are_literal_read_only_scripts(monkeypatch, section):
    def run(argv, **kwargs):
        assert argv[1:4] == ["-NoProfile", "-NonInteractive", "-EncodedCommand"]
        script = base64.b64decode(argv[4]).decode("utf-16le")
        assert platform.SCRIPTS[section] in script
        assert "Set-Mp" not in script and "Start-MpScan" not in script and "Remove-" not in script
        assert kwargs == {"timeout": 20, "max_output": 512 * 1024, "redact_output": False}
        return {"ok": True, "output": '{"healthy":true}'}
    monkeypatch.setattr(platform, "run_process", run)
    assert platform.blue_status(section)["data"] == {"healthy": True}


@pytest.mark.skipif(os.name != "nt", reason="Windows native PowerShell contract")
@pytest.mark.parametrize("response,code", [
    ({"ok": False, "timed_out": True}, "tool_timeout"),
    ({"ok": False, "truncated": True}, "output_limit"),
    ({"ok": False, "output": "cmdlet unavailable", "exit_code": 1}, "native_query_failed"),
    ({"ok": True, "output": "not JSON"}, "invalid_tool_output"),
])
def test_native_failures_are_not_protection_disabled(monkeypatch, response, code):
    monkeypatch.setattr(platform, "run_process", lambda *a, **kw: response)
    result = platform.blue_status("defender")
    assert result["code"] == code and not result["ok"]
    assert "data" not in result


def test_provenance_does_not_execute_discovered_files(monkeypatch, tmp_path):
    tool = tmp_path / "nmap.exe"
    tool.write_bytes(b"untrusted PATH executable, never launched")
    monkeypatch.setattr(platform.shutil, "which", lambda name: str(tool) if name.startswith("nmap") else None)
    monkeypatch.setattr(platform, "run_process", lambda *a, **kw: pytest.fail("must not execute"))
    row = platform.provenance_inventory()["tools"][0]
    assert row["available"] and row["sha256"] and not row["trusted"]
    assert not row["executed"] and not row["signature_verified"] and row["version"] is None


def test_runtime_errors_are_redacted(monkeypatch):
    def failure(*a, **kw):
        raise OSError("Authorization: Bearer abcdefghijklmnopqrstuvwxyz1234567890")
    monkeypatch.setattr(platform.psutil, "net_connections", failure)
    result = platform.blue_status("connections")
    assert "abcdefghijklmnopqrstuvwxyz1234567890" not in json.dumps(result)


@pytest.mark.skipif(os.name != "nt", reason="Windows native PowerShell contract")
def test_event_json_is_parsed_before_secret_redaction(monkeypatch):
    secret = "never-expose-event-password-123"
    event = {"Id": 1121, "Message": f"Observed password={secret} in command arguments", "ProviderName": "Defender"}
    def run(argv, **kwargs):
        assert kwargs["redact_output"] is False
        return {"ok": True, "output": json.dumps([event])}
    monkeypatch.setattr(platform, "run_process", run)
    result = platform._powershell("events")
    assert result["ok"] and result["data"][0]["Id"] == 1121
    assert secret not in json.dumps(result)
    assert "[REDACTED]" in result["data"][0]["Message"]


@pytest.mark.skipif(os.name != "nt", reason="Windows native PowerShell contract")
def test_native_failure_sanitizes_raw_diagnostics(monkeypatch):
    secret = "never-expose-error-password-456"
    monkeypatch.setattr(platform, "run_process", lambda *a, **kw:
                        {"ok": False, "exit_code": 1, "output": f"Query failed password={secret}"})
    result = platform._powershell("events")
    assert not result["ok"] and result["code"] == "native_query_failed"
    assert secret not in json.dumps(result) and "[REDACTED]" in result["error"]


def test_process_output_redaction_remains_the_default():
    import sys
    from nexus.security.common import run_process
    secret = "never-expose-default-password-789"
    result = run_process([sys.executable, "-I", "-c", f"print('password={secret}')"], timeout=5)
    assert result["ok"] and secret not in result["output"] and "[REDACTED]" in result["output"]
