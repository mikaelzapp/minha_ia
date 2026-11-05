"""Adapter contracts use fixtures; native runner tests never claim Ghidra ran."""
import hashlib
import json
import os
from pathlib import Path
import sys
import threading
import time

import pytest

from nexus.security import ghidra


@pytest.fixture
def installation(tmp_path, monkeypatch):
    root = tmp_path / "engine"
    jdk = tmp_path / "jdk"
    for relative, content in {
        "Ghidra/application.properties": b"application.name=Ghidra\napplication.version=12.2\napplication.java.min=25\n",
        "Ghidra/Framework/Utility/lib/Utility.jar": b"jar-fixture-not-executable",
        "support/analyzeHeadless.bat" if os.name == "nt" else "support/analyzeHeadless": b"launcher-fixture",
    }.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    (jdk / "bin").mkdir(parents=True)
    (jdk / "release").write_text('JAVA_VERSION="25.0.1"\n')
    (jdk / "bin" / ("java.exe" if os.name == "nt" else "java")).write_bytes(b"java-fixture")
    (jdk / "bin" / ("javac.exe" if os.name == "nt" else "javac")).write_bytes(b"javac-fixture")
    config = {"install_dir": str(root), "java_home": str(jdk)}
    monkeypatch.setattr(ghidra, "_java_candidates", lambda _: [str(jdk)])
    monkeypatch.setattr(ghidra.psutil, "virtual_memory", lambda: type("Mem", (), {"available": 8 * ghidra.MIB * 1024})())
    return root, jdk, config


@pytest.fixture
def sample(tmp_path):
    path = tmp_path / "data/security/samples/registered.bin"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"MZ" + bytes(100))
    return tmp_path / "data", path


def evidence(digest, **extra):
    return {"schema": "nexus-ghidra-v1", "sha256": digest, "language_id": "x86:LE:64:default",
            "compiler_spec": "windows", "executable_format": "PE", "image_base": "140000000",
            "analysis_timed_out": False, "functions": [{"name": "main", "address": "140001000",
                "pseudocode": "int main(void) { return 0; }", "pseudocode_source": "Ghidra fixture"}],
            "strings": [], "references": [], "imports": [], "exports": [], "entry_points": [],
            "coverage": {"functions_exported": 1}, "decompiler": {"available": True}, **extra}


def stub_analysis(monkeypatch, path, *, transform=None, callback=None):
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    calls = []
    def runner(argv, workdir, env, **kwargs):
        calls.append((argv, workdir, env, kwargs))
        value = evidence(digest)
        if transform:
            value = transform(value)
        (workdir / "result.json").write_text(json.dumps(value), encoding="utf-8")
        if callback:
            callback()
        return {"ok": True, "code": "ok", "output": "fixture", "exit_code": 0, "duration_seconds": .01}
    monkeypatch.setattr(ghidra, "_run", runner)
    return calls


def test_missing_engine_does_not_execute(monkeypatch, tmp_path):
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    monkeypatch.delenv("GHIDRA_HOME", raising=False)
    monkeypatch.setattr(ghidra.shutil, "which", lambda _: None)
    monkeypatch.setattr(ghidra.subprocess, "Popen", lambda *a, **k: pytest.fail("must not execute"))
    result = ghidra.Ghidra(tmp_path).inventory()
    assert not result["available"] and result["code"] == "ghidra_unavailable"
    assert not result["isolation"]["os_sandbox"] and not result["executed"]


def test_detects_installation_without_execution(installation, sample, monkeypatch):
    _, _, cfg = installation
    monkeypatch.setattr(ghidra.subprocess, "Popen", lambda *a, **k: pytest.fail("must not execute"))
    result = ghidra.Ghidra(sample[0], cfg).inventory()
    assert result["version"] == "12.2" and result["java_version"] == "25.0.1"
    assert result["java_required_min"] == 25 and result["utility_sha256"]
    assert not result["signature_verified"] and not result["installation_verified"]


def test_jre_is_not_accepted_as_jdk(installation, sample):
    _, jdk, cfg = installation
    (jdk / "bin" / ("javac.exe" if os.name == "nt" else "javac")).unlink()
    assert ghidra.Ghidra(sample[0], cfg).inventory()["code"] == "jdk_unavailable"


def test_old_java_not_accepted(installation, sample):
    _, jdk, cfg = installation
    (jdk / "release").write_text('JAVA_VERSION="21.0.9"\n')
    assert ghidra.Ghidra(sample[0], cfg).inventory()["code"] == "jdk_unavailable"


def test_version_metadata_invalid(installation, sample):
    root, _, cfg = installation
    (root / "Ghidra/application.properties").write_text("application.version=invalid\n")
    assert ghidra.Ghidra(sample[0], cfg).inventory()["code"] == "invalid_installation"


@pytest.mark.parametrize("config", [{"timeout_seconds": True}, {"heap_mib": 100000},
    {"max_functions": 201}, {"max_strings": 0}, {"max_references": -1}, {"decompile": "false"},
    {"isolation_acknowledged": "yes"}, {"install_dir": "relative"}, {"rss_mib": 512}])
def test_invalid_limits_rejected(tmp_path, config):
    with pytest.raises(ghidra.SecurityError):
        ghidra.Ghidra(tmp_path, config)


def test_outside_store_never_runs(installation, sample, tmp_path, monkeypatch):
    _, _, cfg = installation
    other = tmp_path / "private.exe"
    other.write_bytes(b"MZ")
    monkeypatch.setattr(ghidra, "_run", lambda *a, **k: pytest.fail("must not run"))
    assert ghidra.Ghidra(sample[0], cfg).analyze(other)["code"] == "outside_sample_store"


def test_relative_path_never_runs(sample):
    assert ghidra.Ghidra(sample[0]).analyze("registered.bin")["code"] == "outside_sample_store"


def test_nested_runtime_file_not_accepted(installation, sample, monkeypatch):
    _, _, cfg = installation
    path = sample[1].parent / "runtime/other.bin"
    path.parent.mkdir()
    path.write_bytes(b"MZ")
    monkeypatch.setattr(ghidra, "_run", lambda *a, **k: pytest.fail("must not run"))
    assert ghidra.Ghidra(sample[0], cfg).analyze(path)["code"] == "outside_sample_store"


def test_changed_approved_sample_is_blocked(installation, sample):
    _, _, cfg = installation
    result = ghidra.Ghidra(sample[0], cfg).analyze(sample[1], expected_sha256="0" * 64)
    assert result["code"] == "artifact_changed" and not result["target_executed"]


def test_unsupported_format_does_not_import(installation, sample):
    _, _, cfg = installation
    sample[1].write_bytes(b"PK\x03\x04zip")
    assert ghidra.Ghidra(sample[0], cfg).analyze(sample[1])["code"] == "unsupported_static_format"


@pytest.mark.skipif(os.name != "nt", reason="Windows resource boundary")
def test_private_directory_requires_explicit_isolation_ack(installation, sample, monkeypatch):
    _, _, cfg = installation
    monkeypatch.setattr(ghidra, "_run", lambda *a, **k: pytest.fail("must not run"))
    result = ghidra.Ghidra(sample[0], cfg).analyze(sample[1])
    assert result["code"] == "isolation_acknowledgement_required"


@pytest.mark.skipif(os.name != "nt", reason="Windows resource boundary")
def test_memory_budget_checked_before_spawn(installation, sample, monkeypatch):
    _, _, cfg = installation
    monkeypatch.setattr(ghidra.psutil, "virtual_memory", lambda: type("M", (), {"available": 128 * ghidra.MIB})())
    cfg["isolation_acknowledged"] = True
    monkeypatch.setattr(ghidra, "_run", lambda *a, **k: pytest.fail("must not run"))
    assert ghidra.Ghidra(sample[0], cfg).analyze(sample[1])["code"] == "insufficient_memory"


@pytest.mark.skipif(os.name != "nt", reason="Windows resource boundary")
def test_fixture_static_export_binds_hash_and_cleans_workspace(installation, sample, monkeypatch):
    _, _, cfg = installation
    cfg["isolation_acknowledged"] = True
    calls = stub_analysis(monkeypatch, sample[1])
    result = ghidra.Ghidra(sample[0], cfg).analyze(sample[1])
    assert result["ok"] and result["functions"][0]["name"] == "main", result.get("error")
    assert not result["target_executed"] and not result["isolation"]["os_sandbox"]
    argv, workdir, env, options = calls[0]
    assert str(sample[1]) not in argv and str(workdir / "sample.bin") in argv
    assert not workdir.exists()
    assert "-readOnly" in argv and "-deleteProject" in argv and "-max-cpu" in argv
    assert "-Xmx768m" in argv and options["memory_bytes"] == 1536 * ghidra.MIB
    assert not any(key in env for key in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "NODE_OPTIONS", "OPENAI_API_KEY"))


@pytest.mark.skipif(os.name != "nt", reason="Windows resource boundary")
def test_installed_bytes_changed_rejected(installation, sample, monkeypatch):
    _, _, cfg = installation
    cfg.update(isolation_acknowledged=True, utility_sha256="0" * 64)
    monkeypatch.setattr(ghidra, "_run", lambda *a, **k: pytest.fail("must not run"))
    assert ghidra.Ghidra(sample[0], cfg).analyze(sample[1])["code"] == "installation_changed"


@pytest.mark.skipif(os.name != "nt", reason="Windows resource boundary")
@pytest.mark.parametrize("mutation", [lambda e: {**e, "sha256": "0" * 64}, lambda e: {**e, "schema": "bad"},
    lambda e: {**e, "target_executed": True}, lambda e: {**e, "functions": [{}] * 201},
    lambda e: {**e, "imports": "bad"}, lambda e: {**e, "sha256": 17},
    lambda e: {**e, "functions": [["invalid"]]}, lambda e: {**e, "analysis_timed_out": "false"},
    lambda e: {**e, "coverage": {"untrusted": float("nan")}}])
def test_invalid_export_discarded(installation, sample, monkeypatch, mutation):
    _, _, cfg = installation
    cfg["isolation_acknowledged"] = True
    stub_analysis(monkeypatch, sample[1], transform=mutation)
    result = ghidra.Ghidra(sample[0], cfg).analyze(sample[1])
    assert not result["ok"] and result["code"] == "invalid_tool_output"
    assert "functions" not in result and not result["target_executed"]


@pytest.mark.skipif(os.name != "nt", reason="Windows resource boundary")
def test_original_change_discards_fixture_evidence(installation, sample, monkeypatch):
    _, _, cfg = installation
    cfg["isolation_acknowledged"] = True
    stub_analysis(monkeypatch, sample[1], callback=lambda: sample[1].write_bytes(b"changed"))
    result = ghidra.Ghidra(sample[0], cfg).analyze(sample[1])
    assert not result["ok"] and result["code"] == "artifact_changed" and "functions" not in result


@pytest.mark.skipif(os.name != "nt", reason="Windows resource boundary")
def test_partial_analysis_not_reported_complete(installation, sample, monkeypatch):
    _, _, cfg = installation
    cfg["isolation_acknowledged"] = True
    stub_analysis(monkeypatch, sample[1], transform=lambda e: {**e, "analysis_timed_out": True})
    result = ghidra.Ghidra(sample[0], cfg).analyze(sample[1])
    assert result["ok"] and result["code"] == "partial" and result["analysis_timed_out"]


@pytest.mark.skipif(os.name != "nt", reason="Windows resource boundary")
def test_pre_cancel_no_spawn(installation, sample, monkeypatch):
    _, _, cfg = installation
    cfg["isolation_acknowledged"] = True
    cancel = threading.Event()
    cancel.set()
    monkeypatch.setattr(ghidra, "_run", lambda *a, **k: pytest.fail("must not run"))
    assert ghidra.Ghidra(sample[0], cfg).analyze(sample[1], cancel=cancel)["code"] == "cancelled"


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object native test")
def test_native_runner_really_limits_and_reaps_process(tmp_path):
    events = []
    result = ghidra._run([sys.executable, "-c", "print('harmless runner test')"], tmp_path, dict(os.environ),
                         timeout=5, memory_bytes=192 * ghidra.MIB, on_event=events.append)
    assert result["ok"] and "harmless runner test" in result["output"]
    assert events[0]["event"] == "analyzer_started"
    assert not ghidra.psutil.pid_exists(events[0]["pid"])
    assert result["resource_boundary"].startswith("Windows Job Object")


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object native test")
def test_native_runner_timeout(tmp_path):
    result = ghidra._run([sys.executable, "-c", "import time; time.sleep(30)"], tmp_path, dict(os.environ),
                         timeout=.15, memory_bytes=192 * ghidra.MIB)
    assert not result["ok"] and result["code"] == "tool_timeout"


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object native test")
def test_native_runner_cancel(tmp_path):
    cancel = threading.Event()
    timer = threading.Timer(.15, cancel.set)
    timer.start()
    try:
        result = ghidra._run([sys.executable, "-c", "import time; time.sleep(30)"], tmp_path, dict(os.environ),
                             timeout=5, memory_bytes=192 * ghidra.MIB, cancel=cancel)
        assert not result["ok"] and result["code"] == "cancelled"
    finally:
        timer.cancel()


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object native test")
def test_native_runner_memory_allocation_exceeds_job_limit(tmp_path):
    # Allocation is rejected by the kernel before consuming 512 MiB on this notebook.
    result = ghidra._run([sys.executable, "-c", "x=bytearray(512*1024*1024); print('unexpected')"],
                         tmp_path, dict(os.environ), timeout=5, memory_bytes=128 * ghidra.MIB)
    assert not result["ok"] and result["code"] in {"analyzer_failed", "memory_limit"}
    assert "unexpected" not in result["output"]


def test_hardlinked_sample_rejected(sample, tmp_path):
    alias = tmp_path / "alias"
    os.link(sample[1], alias)
    result = ghidra.Ghidra(sample[0]).analyze(sample[1])
    assert not result["ok"] and result["code"] == "unsafe_file"


@pytest.mark.skipif(os.name != "nt", reason="Windows resource boundary")
@pytest.mark.parametrize("reported_version,expected", [("25.0.1", True), ("1.8.0", False), ("26.0.0", False)])
def test_dependency_validation_does_not_claim_headless_analysis(installation, sample, monkeypatch, reported_version, expected):
    _, _, cfg = installation
    calls = []
    def runner(argv, *args, **kwargs):
        calls.append(argv)
        return {"ok": True, "code": "ok", "output": 'openjdk version "' + reported_version + '"'}
    monkeypatch.setattr(ghidra, "_run", runner)
    result = ghidra.Ghidra(sample[0], cfg).validate()
    assert result["ok"] is expected and not result["headless_analyzer_tested"]
    assert calls[0][-1] == "-version" and len(calls[0]) == 2
