"""Harmless fixtures only. No real malware, EICAR, project imports or installers."""
import hashlib
import json
import os
from pathlib import Path
import struct

import pytest

from nexus.security import static as scanner


def put(tmp_path, data, name="sample.bin"):
    target = tmp_path / name
    target.write_bytes(data if isinstance(data, bytes) else data.encode())
    return target


def synthetic_pe():
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 128)
    data[128:132] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 132, 0x8664, 1, 0, 0, 0, 240, 0x22)
    struct.pack_into("<H", data, 152, 0x20B)
    struct.pack_into("<I", data, 168, 0x1000)
    data[392:400] = b".text\0\0\0"
    struct.pack_into("<IIII", data, 400, 512, 0x1000, 512, 512)
    struct.pack_into("<I", data, 428, 0xE0000020)
    return bytes(data)


def test_s01_hash_and_real_header(tmp_path):
    data = synthetic_pe()
    result = scanner.analyze_file(put(tmp_path, data), original_name="demo.exe")
    assert result["ok"] and not result["executed"]
    assert result["sha256"] == hashlib.sha256(data).hexdigest()
    assert result["name"] == "demo.exe" and result["format"] == "PE/DOS"
    assert result["pe"]["valid_pe_header"]
    assert result["pe"]["architecture"] == "x86-64"
    assert result["pe"]["sections"][0]["writable_executable"]
    assert any(item["id"] == "pe_writable_executable" for item in result["indicators"])
    assert all(item["validation"] == "unconfirmed" for item in result["indicators"])


@pytest.mark.parametrize("data,kind", [(b"\x7fELF\x02\0\0", "ELF"), (b"%PDF-1.7\n", "PDF"),
    (b"PK\x03\x04\0\0", "ZIP"), (b"\x1f\x8babc", "GZIP"), (b"\x00asm\x01\0\0\0", "WebAssembly"),
    (b"\x89PNG\r\n\x1a\n", "PNG"), (b"\xff\xd8\xff", "JPEG"), (b"hello world", "UTF-8 text"),
    (b"\0\0\0\0", "unknown"), (b"", "empty")])
def test_s02_format_magic(tmp_path, data, kind):
    assert scanner.analyze_file(put(tmp_path, data), original_name="misleading.exe")["format"] == kind


@pytest.mark.parametrize("data", [b"MZ", b"MZ" + bytes(70), b"MZ" + bytes(57) + b"\xff" * 12])
def test_s03_truncated_headers(tmp_path, data):
    result = scanner.analyze_file(put(tmp_path, data))
    assert result["ok"] and not result["pe"]["valid_pe_header"]
    assert result["pe"]["error"]


def test_s04_sections_outside_file(tmp_path):
    data = bytearray(synthetic_pe())
    struct.pack_into("<II", data, 408, 0xFFFFFFFF, 0xFFFFFFF0)
    result = scanner.analyze_file(put(tmp_path, bytes(data)))
    section = result["pe"]["sections"][0]
    assert not section["data_within_file"] and "entropy" not in section


def test_s05_string_encodings_and_redaction(tmp_path):
    token = "sk-" + "A" * 25
    data = b"NEXUS_SAFE_MARKER\0" + "UTF16 marker".encode("utf-16le") + b"\0\0"
    data += "UTF16 big marker".encode("utf-16be") + b"\0\0"
    data += f'api_key = "{token}"\0'.encode()
    result = scanner.analyze_file(put(tmp_path, data))
    dumped = json.dumps(result)
    assert token not in dumped and "[REDACTED" in dumped
    assert {item["encoding"] for item in result["strings"]} == {"ASCII", "UTF-16LE", "UTF-16BE"}


def test_s06_strings_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner, "MAX_STRINGS", 3)
    result = scanner.analyze_file(put(tmp_path, b"abcdefg\0" * 100))
    assert len(result["strings"]) == 3 and result["strings_truncated"]


def test_s07_size_guard(tmp_path):
    path = tmp_path / "large.bin"
    with path.open("wb") as stream:
        stream.truncate(20 * 1024 * 1024 + 1)
    result = scanner.analyze_file(path)
    assert not result["ok"] and "limite" in result["error"]


@pytest.mark.parametrize("name", [".env", ".env.local", "id_rsa", "db.sqlite3", "account.key", "tokens.json"])
def test_s08_protected_file(tmp_path, name):
    result = scanner.analyze_file(put(tmp_path, b"should not be read", name))
    assert not result["ok"] and "protegido" in result["error"]


def test_s09_hardlink(tmp_path):
    target = put(tmp_path, b"safe marker")
    alias = tmp_path / "alias.bin"
    os.link(target, alias)
    assert not scanner.analyze_file(alias)["ok"]
    assert not scanner.analyze_file(target)["ok"]


def test_s10_link(tmp_path):
    target = put(tmp_path, b"safe marker")
    alias = tmp_path / "alias.bin"
    try:
        alias.symlink_to(target)
    except OSError:
        pytest.skip("Creating Windows symlinks requires a privilege not present in this test process.")
    assert not scanner.analyze_file(alias)["ok"]


def test_s11_project_is_not_imported(tmp_path):
    put(tmp_path, 'raise RuntimeError("this file must never execute")\nx = 1\n', "app.py")
    result = scanner.audit_project(tmp_path)
    assert result["ok"] and not result["executed"] and result["files_scanned"] == 1
    assert not result["findings"]


def test_s12_ast_findings_and_evidence(tmp_path):
    put(tmp_path, '''from subprocess import run as launch
import pickle as pk
from yaml import load
import requests
value = input()
eval(value)
pk.loads(value)
load(value)
launch("echo " + value, shell=True)
query = f"select * from demo where id={value}"
cursor.execute(query)
requests.get("https://example.invalid", verify=False)
''', "app.py")
    result = scanner.audit_project(tmp_path)
    findings = result["findings"]
    identifiers = {item["id"] for item in findings}
    assert {"PY-DYNAMIC-CODE", "PY-UNSAFE-DESERIALIZATION", "PY-YAML-LOAD", "PY-SHELL-COMMAND",
            "PY-SQL-CONSTRUCTION", "PY-TLS-VERIFY"} <= identifiers
    for finding in findings:
        assert {"id", "title", "severity", "confidence", "file", "line", "impact", "recommendation", "evidence", "validation"} <= finding.keys()
        assert finding["validation"] == "unconfirmed" and finding["line"] > 0


def test_s13_safe_api_usage(tmp_path):
    put(tmp_path, '''import subprocess
import yaml
cursor.execute("select * from demo where id=?", (value,))
subprocess.run(["echo", value], shell=False)
yaml.load(text, Loader=yaml.SafeLoader)
yaml.safe_load(text)
# eval(text) is commentary
note = "exec(text)"
''', "app.py")
    assert not scanner.audit_project(tmp_path)["findings"]


def test_s14_literal_values_never_leave_report(tmp_path):
    marker = "demo-only-unique-value-6789"
    put(tmp_path, f'API_KEY = "{marker}"\nprint(API_KEY)\n', "app.py")
    result = scanner.audit_project(tmp_path)
    dumped = json.dumps(result)
    assert marker not in dumped and any(item["id"] == "HARDCODED-CREDENTIAL" for item in result["findings"])


def test_s15_ignores_private_stores(tmp_path):
    put(tmp_path, "DO_NOT_EXPORT=not-a-real-value", ".env")
    put(tmp_path, b"private database bytes", "memory.sqlite3")
    nested = tmp_path / ".aws"
    nested.mkdir()
    put(nested, "private", "accounts.txt")
    data = tmp_path / "data"
    data.mkdir()
    put(data, 'eval(text)', "store.py")
    put(tmp_path, "print('safe')", "app.py")
    result = scanner.audit_project(tmp_path)
    assert result["files_scanned"] == 1
    assert len(result["skipped"]) == 4
    assert "DO_NOT_EXPORT" not in json.dumps(result)


def test_s16_js_php_docker_rules(tmp_path):
    put(tmp_path, 'eval(value); element.innerHTML = value;\nexec("echo " + value);', "app.js")
    put(tmp_path, '<?php unserialize($data); shell_exec($data);', "app.php")
    put(tmp_path, "FROM python:latest\nUSER root\n", "Dockerfile")
    identifiers = {item["id"] for item in scanner.audit_project(tmp_path)["findings"]}
    assert {"JS-DYNAMIC-CODE", "WEB-DOM-HTML", "JS-CHILD-EXEC", "PHP-COMMAND", "PHP-DESERIALIZATION",
            "DOCKER-MUTABLE-TAG", "DOCKER-ROOT"} <= identifiers


def test_s17_manifest_inventory_not_cves(tmp_path):
    put(tmp_path, json.dumps({"dependencies": {"demo-lib": "^1.2.3"}, "devDependencies": {"test-lib": "2.0.0"}}), "package.json")
    put(tmp_path, "example-lib==1.2.3\nother-lib>=2; python_version>'3'\n", "requirements.txt")
    put(tmp_path, '[project]\ndependencies = ["demo-pkg>=1"]\n', "pyproject.toml")
    put(tmp_path, '[dependencies]\ndemo = "1.0"\n', "Cargo.toml")
    result = scanner.audit_project(tmp_path)
    manifests = result["dependency_manifests"]
    assert len(manifests) == 4 and all(item["vulnerabilities_checked"] is False for item in manifests)
    assert {package["name"] for item in manifests for package in item["packages"]} >= {"demo-lib", "example-lib", "demo-pkg", "demo"}
    assert "CVE-" not in json.dumps(result)


def test_s18_bad_manifest_and_ast_are_reported(tmp_path):
    put(tmp_path, '{"dependencies": ', "package.json")
    put(tmp_path, 'def broken(:\n', "app.py")
    result = scanner.audit_project(tmp_path)
    assert result["ok"]
    assert result["dependency_manifests"][0]["parse_error"]
    assert next(item for item in result["files"] if item["file"] == "app.py")["parse_error"]


def test_s19_project_file_budget(tmp_path, monkeypatch):
    for number in range(5):
        put(tmp_path, "x = 1", f"part{number}.py")
    monkeypatch.setattr(scanner, "MAX_PROJECT_FILES", 2)
    result = scanner.audit_project(tmp_path)
    assert result["files_scanned"] == 2 and result["truncated"]
    assert "file_budget" in result["limit_reasons"]


def test_s20_project_byte_budget(tmp_path, monkeypatch):
    for number in range(3):
        put(tmp_path, "x = 1\n" * 10, f"part{number}.py")
    monkeypatch.setattr(scanner, "MAX_PROJECT_BYTES", 70)
    result = scanner.audit_project(tmp_path)
    assert result["bytes_read"] <= 70 and "byte_budget" in result["limit_reasons"]


def test_s21_entry_budget_and_binary(tmp_path, monkeypatch):
    put(tmp_path, b"\0\0\0", "binary.py")
    for number in range(3):
        put(tmp_path, b"safe", f"part{number}.bin")
    monkeypatch.setattr(scanner, "MAX_ENTRIES", 2)
    result = scanner.audit_project(tmp_path)
    assert "entry_budget" in result["limit_reasons"]


def test_s22_yara_real_safe_marker(tmp_path):
    if not scanner.tool_capabilities()["yara_x"]["installed"]:
        pytest.skip("Optional YARA-X not installed")
    marker = put(tmp_path, b"NEXUS_SAFE_MARKER_ONLY")
    rules = put(tmp_path, 'rule SafeFixture { strings: $a = "NEXUS_SAFE_MARKER_ONLY" condition: $a }', "fixture.yar")
    result = scanner.scan_yara(marker, rules)
    assert result["available"] and result["ok"] and result["scanned"]
    assert result["matches"][0]["rule"] == "SafeFixture"
    assert result["matches"][0]["pattern_offsets"][0]["offsets"] == [0]


def test_s23_yara_default_is_descriptor(tmp_path):
    if not scanner.tool_capabilities()["yara_x"]["installed"]:
        pytest.skip("Optional YARA-X not installed")
    result = scanner.analyze_file(put(tmp_path, synthetic_pe()))
    assert result["yara"]["ok"]
    assert any(item["rule"] == "NEXUS_PE_Header" for item in result["yara"]["matches"])
    assert all(item["validation"] == "unconfirmed" for item in result["yara"]["matches"])


def test_s24_yara_cannot_include_files(tmp_path):
    if not scanner.tool_capabilities()["yara_x"]["installed"]:
        pytest.skip("Optional YARA-X not installed")
    marker = put(tmp_path, b"NEXUS_SAFE_MARKER_ONLY")
    rules = put(tmp_path, 'include "anything.yar"\nrule X { condition: true }', "fixture.yar")
    result = scanner.scan_yara(marker, rules)
    assert not result["ok"] and not result["scanned"] and not result["matches"]


def test_s25_engine_inventory_never_executes(monkeypatch):
    monkeypatch.setattr(scanner.shutil, "which", lambda command: f"C:/demo/{command}.exe")
    result = scanner.inventory_optional_engines()
    for name in ["capa", "floss", "semgrep", "trivy"]:
        assert result[name]["installed"] and not result[name]["available"]
    assert not result["decompile"]["available"]


def test_s26_missing_targets(tmp_path):
    assert not scanner.analyze_file(tmp_path / "none.bin")["ok"]
    assert not scanner.audit_project(tmp_path / "none")["ok"]
    assert not scanner.analyze_file(tmp_path)["ok"]


def test_s27_hypotheses_are_not_verdicts(tmp_path):
    result = scanner.analyze_file(put(tmp_path, bytes(range(256)) * 8 + b"powershell"))
    assert result["entropy"] > 7.2
    assert any(item["id"] == "high_entropy" for item in result["indicators"])
    assert "ausência não comprova segurança" in result["notice"]
    assert "malicious" not in result and "safe" not in result


def test_s28_finding_budget_is_visible(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner, "MAX_FINDINGS", 2)
    put(tmp_path, "eval(value)\n" * 10, "app.py")
    result = scanner.audit_project(tmp_path)
    assert len(result["findings"]) == 2 and result["truncated"]
    assert "finding_budget" in result["limit_reasons"]


def test_s29_source_size_and_encoding(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner, "MAX_SOURCE_BYTES", 20)
    put(tmp_path, b"x" * 30, "big.py")
    put(tmp_path, b"\xff\xfehello", "odd.py")
    result = scanner.audit_project(tmp_path)
    assert result["files_scanned"] == 0
    assert {item["reason"] for item in result["skipped"]} == {"source_file_size_limit", "unsupported_encoding"}


@pytest.mark.parametrize("endian,machine,architecture", [("<", 62, "x86-64"), (">", 183, "ARM64")])
def test_s30_elf_architecture(tmp_path, endian, machine, architecture):
    data = bytearray(64)
    data[:6] = b"\x7fELF\x02" + (b"\x01" if endian == "<" else b"\x02")
    struct.pack_into(endian + "H", data, 18, machine)
    result = scanner.analyze_file(put(tmp_path, bytes(data)))
    assert result["architecture"] == architecture and result["elf"]["bits"] == 64


def test_s31_recognizable_value_is_not_exported(tmp_path):
    value = "sk-" + "Z" * 30
    put(tmp_path, f'VALUE = "{value}"\n', "app.py")
    result = scanner.audit_project(tmp_path)
    assert value not in json.dumps(result)
    assert result["findings"][0]["id"] == "HARDCODED-TOKEN"


def test_s32_prefixed_literal(tmp_path):
    value = "demo-only-value-912"
    put(tmp_path, f'db_password = "{value}"\n', "app.py")
    result = scanner.audit_project(tmp_path)
    assert value not in json.dumps(result) and result["findings"][0]["id"] == "HARDCODED-CREDENTIAL"


def test_s33_without_optional_engine(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner.importlib.util, "find_spec", lambda name: None)
    result = scanner.analyze_file(put(tmp_path, b"safe marker"))
    assert result["ok"] and not result["yara"]["available"] and not result["yara"]["scanned"]


def test_s34_descriptor_does_not_execute_content(tmp_path):
    payload = put(tmp_path, b"powershell.exe this-is-plain-text-not-a-command")
    result = scanner.analyze_file(payload)
    assert result["executed"] is False
    assert any(item["id"] == "shell_reference" for item in result["indicators"])
