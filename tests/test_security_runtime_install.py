"""Portable runtime acquisition: synthetic ZIP/network evidence, no real Java."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import sys
import threading
import time
import zipfile

import httpx
import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/install_security_runtime.py"
SPEC = importlib.util.spec_from_file_location("security_runtime_installer", SCRIPT)
mod = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mod
SPEC.loader.exec_module(mod)


def archive_bytes(entries=None):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, value in entries or [("dist/", b""), ("dist/bin/java.exe", b"MZsynthetic"), ("dist/release", b'JAVA_VERSION="25"')]:
            archive.writestr(name, value)
    return buf.getvalue()


def package(data):
    return mod.Package("java", "25-test", "https://github.com/adoptium/test.zip", len(data), hashlib.sha256(data).hexdigest(),
                       "https://github.com/adoptium/test", "dist", 1024 * 1024, ("bin/java.exe", "release"))


def mocked_client(monkeypatch, handler):
    original = httpx.Client
    def client(**kwargs):
        assert kwargs["trust_env"] is False
        assert kwargs["follow_redirects"] is False
        return original(transport=httpx.MockTransport(handler), **kwargs)
    monkeypatch.setattr(mod.httpx, "Client", client)


def test_fixed_official_catalog_and_preview_no_network_or_mutation(tmp_path, monkeypatch):
    monkeypatch.setattr(mod.httpx, "Client", lambda **k: pytest.fail("offline inventory contacted network"))
    assert mod.PACKAGES["java"].archive_bytes == 141285173
    assert mod.PACKAGES["ghidra"].sha256 == "2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67"
    assert mod.PACKAGES["zap"].archive_bytes == 286652857
    assert not mod.inventory(mod.PACKAGES["java"], tmp_path / "new")["installed"]
    assert not (tmp_path / "new").exists()


@pytest.mark.parametrize("url", ["http://github.com/a", "https://github.com.evil.invalid/a", "https://user@github.com/a",
    "https://github.com:4433/a", "https://github.com/a#x", "https://evil.invalid/a", "https://github.com\\evil.invalid/a"])
def test_download_allowlist(url):
    with pytest.raises(ValueError):
        mod.checked_url(url)


def test_stream_hash_redirect_and_signed_url_not_retained(tmp_path, monkeypatch):
    data = archive_bytes()
    def handler(request):
        if request.url.host == "github.com":
            return httpx.Response(302, headers={"location": "https://release-assets.githubusercontent.com/a?sig=not-persisted"})
        return httpx.Response(200, content=data)
    mocked_client(monkeypatch, handler)
    events = []
    result = mod.download(package(data), tmp_path / "archive.zip", deadline=time.monotonic() + 30, emit=lambda **v: events.append(v))
    assert (tmp_path / "archive.zip").read_bytes() == data
    assert result["redirect_hosts"] == ["github.com", "release-assets.githubusercontent.com"]
    assert "not-persisted" not in json.dumps(result)
    assert events[-1]["stage"] == "archive_verified"


@pytest.mark.parametrize("case", ["hash", "size", "encoding", "redirect", "status"])
def test_download_rejects_mismatch_without_install(tmp_path, monkeypatch, case):
    data = archive_bytes()
    def handler(request):
        if case == "redirect":
            return httpx.Response(302, headers={"location": "https://evil.invalid/x"})
        if case == "status":
            return httpx.Response(404)
        if case == "encoding":
            return httpx.Response(200, content=data, headers={"content-encoding": "gzip"})
        return httpx.Response(200, content=data if case == "size" else b"X" * len(data))
    mocked_client(monkeypatch, handler)
    pkg = package(data)
    if case == "size":
        pkg = mod.Package(**{**pkg.__dict__, "archive_bytes": len(data) + 1})
    with pytest.raises((ValueError, httpx.DecodingError)):
        mod.download(pkg, tmp_path / "archive.zip", deadline=time.monotonic() + 30, emit=lambda **v: None)
    assert not (tmp_path / "runtime").exists()


@pytest.mark.parametrize("bad", ["../outside", "/absolute", "dist/../outside", "dist/CON.txt", "dist/bad. ",
    "dist/a\\b", "dist/c:ads", "another/ok", "dist//bad"])
def test_zip_prevalidation_rejects_paths_before_extracting(tmp_path, bad):
    data = archive_bytes([("dist/bin/java.exe", b"ok"), ("dist/release", b"ok"), (bad, b"bad")])
    # ZipInfo normalizes native Windows separators when constructing fixtures.
    # Replace both local/central member names to retain this hostile raw ZIP.
    if "\\" in bad:
        data = data.replace(bad.replace("\\", "/").encode(), bad.encode())
    source = tmp_path / "a.zip"
    source.write_bytes(data)
    with pytest.raises(ValueError):
        mod.unpack(package(data), source, tmp_path / "stage", deadline=time.monotonic() + 10, emit=lambda **v: None)
    assert not (tmp_path / "stage").exists()


@pytest.mark.parametrize("kind", ["symlink", "device", "collision", "file_parent", "metadata", "missing"])
def test_zip_rejects_links_devices_collisions_and_reserved_manifest(tmp_path, kind):
    entries = [("dist/bin/java.exe", b"ok"), ("dist/release", b"ok")]
    if kind == "missing":
        entries.pop()
    else:
        entries.append(("dist/" + {"collision": "RELEASE", "file_parent": "release/child", "metadata": mod.MANIFEST}.get(kind, "bad"), b"x"))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        for name, value in entries:
            info = zipfile.ZipInfo(name)
            if name == "dist/bad":
                info.create_system = 3
                info.external_attr = ((stat.S_IFLNK if kind == "symlink" else stat.S_IFCHR) | 0o777) << 16
            archive.writestr(info, value)
    source = tmp_path / "a.zip"
    source.write_bytes(buf.getvalue())
    with pytest.raises(ValueError):
        mod.unpack(package(buf.getvalue()), source, tmp_path / "stage", deadline=time.monotonic() + 10, emit=lambda **v: None)
    assert not (tmp_path / "stage").exists()


def test_complete_install_idempotence_hashes_and_cleanup(tmp_path, monkeypatch):
    data = archive_bytes()
    mocked_client(monkeypatch, lambda request: httpx.Response(200, content=data))
    monkeypatch.setattr(mod.platform, "system", lambda: "Windows")
    monkeypatch.setattr(mod.platform, "machine", lambda: "AMD64")
    result = mod.install(package(data), base=tmp_path, emit=lambda **v: None)
    assert result["ok"] and not result["executed"] and not result["global_environment_changed"]
    target = mod.destination(package(data), tmp_path)
    assert (target / "bin/java.exe").read_bytes() == b"MZsynthetic"
    assert not list(target.parent.glob(".nexus-runtime-*"))
    assert mod.inventory(package(data), tmp_path)["files_verified"] == 2
    monkeypatch.setattr(mod.httpx, "Client", lambda **k: pytest.fail("idempotence redownloaded"))
    assert mod.install(package(data), base=tmp_path, emit=lambda **v: None)["code"] == "already_installed"
    (target / "release").write_bytes(b"tampered")
    with pytest.raises(ValueError, match="differs"):
        mod.install(package(data), base=tmp_path, emit=lambda **v: None)


def test_existing_unknown_directory_never_overwritten(tmp_path, monkeypatch):
    data = archive_bytes()
    target = mod.destination(package(data), tmp_path)
    target.mkdir(parents=True)
    sentinel = target / "personal.txt"
    sentinel.write_text("preserve")
    with pytest.raises(ValueError, match="no valid installation"):
        mod.inventory(package(data), tmp_path)
    assert sentinel.read_text() == "preserve"


def test_failure_cleans_only_own_temporary(tmp_path, monkeypatch):
    data = archive_bytes()
    mocked_client(monkeypatch, lambda request: httpx.Response(200, content=b"X" * len(data)))
    monkeypatch.setattr(mod.platform, "system", lambda: "Windows")
    monkeypatch.setattr(mod.platform, "machine", lambda: "AMD64")
    keep = tmp_path / "keep"
    keep.mkdir()
    with pytest.raises(ValueError, match="mismatch"):
        mod.install(package(data), base=tmp_path, emit=lambda **v: None)
    assert keep.exists()
    parent = mod.destination(package(data), tmp_path).parent
    assert not list(parent.glob(".nexus-runtime-*"))
    with pytest.raises(ValueError, match="Refusing cleanup"):
        mod.cleanup_owned(keep, tmp_path)


def test_cancellation_and_deadline_before_network(tmp_path):
    cancelled = threading.Event()
    cancelled.set()
    with pytest.raises(ValueError, match="cancelled"):
        mod.download(package(archive_bytes()), tmp_path / "x", deadline=time.monotonic() + 10, cancel=cancelled)
    with pytest.raises(ValueError, match="deadline"):
        mod.check(time.monotonic() - 1)


def test_untracked_file_and_hardlink_refused(tmp_path, monkeypatch):
    data = archive_bytes()
    mocked_client(monkeypatch, lambda request: httpx.Response(200, content=data))
    monkeypatch.setattr(mod.platform, "system", lambda: "Windows")
    monkeypatch.setattr(mod.platform, "machine", lambda: "AMD64")
    mod.install(package(data), base=tmp_path, emit=lambda **v: None)
    target = mod.destination(package(data), tmp_path)
    (target / "extra").write_text("unexpected")
    with pytest.raises(ValueError, match="untracked"):
        mod.inventory(package(data), tmp_path)
