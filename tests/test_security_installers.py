"""Pinned installer tests use synthetic ZIP bytes and mocked HTTP only."""
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import threading
from types import SimpleNamespace
from unittest.mock import Mock
import zipfile

import httpx
import pytest

from nexus.security import installers as mod


def make_zip(entries=None):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, payload in entries or [("nuclei.exe", b"MZ" + bytes(range(256)) * 4), ("README.md", b"synthetic fixture, not a scanner")]:
            archive.writestr(name, payload)
    return data.getvalue()


@pytest.fixture
def fixture_release(monkeypatch):
    payload = make_zip()
    monkeypatch.setattr(mod, "ARCHIVE_BYTES", len(payload))
    monkeypatch.setattr(mod, "ARCHIVE_SHA256", hashlib.sha256(payload).hexdigest())
    monkeypatch.setattr(mod, "_supported", lambda: True)
    return payload


def transport(monkeypatch, handler):
    original = httpx.Client
    calls = []

    def client(**kwargs):
        assert kwargs["trust_env"] is False and kwargs["follow_redirects"] is False
        assert kwargs["headers"]["Accept-Encoding"] == "identity"
        calls.append(kwargs)
        return original(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(mod.httpx, "Client", client)
    return calls


def no_owned_temps(installer):
    return not installer.parent.exists() or not list(installer.parent.glob(".nexus-install-*"))


def test_catalog_is_pinned_official_and_inventory_offline_readonly(tmp_path, monkeypatch):
    client = Mock(side_effect=AssertionError("Offline inventory must not access HTTP"))
    monkeypatch.setattr(mod.httpx, "Client", client)
    state = mod.NucleiInstaller(tmp_path).inventory()
    assert state["ok"] and not state["installed"] and state["version"] == "3.11.1"
    assert mod.ARCHIVE_BYTES == 46_067_128
    assert mod.ARCHIVE_SHA256 == "bb6cb9ff8939b753f6fcab06fd30a15f5bc61d8382a597871334c007a85ff9d2"
    assert mod.ARCHIVE_URL == "https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_windows_amd64.zip"
    assert not (tmp_path / "security").exists()
    client.assert_not_called()


def test_preview_requires_supported_platform_and_disk_budget(tmp_path, monkeypatch):
    installer = mod.NucleiInstaller(tmp_path)
    monkeypatch.setattr(mod, "_supported", lambda: False)
    with pytest.raises(mod.SecurityError, match="Windows"):
        installer.preview()
    monkeypatch.setattr(mod, "_supported", lambda: True)
    monkeypatch.setattr(mod.shutil, "disk_usage", lambda _: SimpleNamespace(free=1))
    with pytest.raises(mod.SecurityError, match="Espaço"):
        installer.preview()
    assert not (tmp_path / "security").exists()


def test_success_extracts_only_executable_records_provenance_never_runs_it(tmp_path, monkeypatch, fixture_release):
    http_calls = transport(monkeypatch, lambda request: httpx.Response(200, content=fixture_release))
    events = []
    installer = mod.NucleiInstaller(tmp_path)
    result = installer.run(emit=events.append)
    assert result["ok"] and result["installed"] and result["executed"] is False
    assert result["requires_configuration_approval"] and result["version_verified"] is False
    assert installer.executable.read_bytes().startswith(b"MZ")
    assert sorted(x.name for x in installer.destination.iterdir()) == ["installation.json", "nuclei.exe"]
    record = json.loads(installer.manifest.read_text(encoding="utf-8"))
    assert record["archive_sha256"] == hashlib.sha256(fixture_release).hexdigest()
    assert record["exe_sha256"] == hashlib.sha256(installer.executable.read_bytes()).hexdigest()
    assert record["version_verified_by_execution"] is False
    assert installer.inventory()["installed"]
    assert no_owned_temps(installer)
    assert len(http_calls) == 1
    downloads = [event for event in events if event["stage"] == "download"]
    assert downloads and all(0 < x["downloaded_bytes"] <= len(fixture_release) for x in downloads)
    assert any(x["stage"] == "archive_verified" and x["downloaded_bytes"] == len(fixture_release) for x in events)
    assert installer.run()["code"] == "already_installed"
    assert len(http_calls) == 1


def test_official_redirect_chain_allowed_but_signed_url_not_persisted(tmp_path, monkeypatch, fixture_release):
    requested = []

    def handler(request):
        requested.append(str(request.url))
        if request.url.host == "github.com":
            return httpx.Response(302, headers={"location": "https://release-assets.githubusercontent.com/fixture?sig=do-not-retain"})
        return httpx.Response(200, content=fixture_release)

    transport(monkeypatch, handler)
    installer = mod.NucleiInstaller(tmp_path)
    result = installer.run()
    assert result["ok"] and len(requested) == 2
    assert result["provenance"]["redirect_hosts"] == ["github.com", "release-assets.githubusercontent.com"]
    assert "do-not-retain" not in json.dumps(result)


@pytest.mark.parametrize("location", ["https://outside.test/nuclei.zip", "http://github.com/nuclei.zip", "https://user:pass@github.com/x",
    "https://github.com:444/x", "https://github.com.evil.test/x", "https://objects.githubusercontent.com/x#fragment"])
def test_redirect_to_nonofficial_or_ambiguous_destination_refused(tmp_path, monkeypatch, fixture_release, location):
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(302, headers={"location": location})

    transport(monkeypatch, handler)
    installer = mod.NucleiInstaller(tmp_path)
    result = installer.run()
    assert not result["ok"] and result["code"] == "download_redirect_denied"
    assert len(requests) == 1 and not installer.destination.exists() and no_owned_temps(installer)


@pytest.mark.parametrize("kind,code", [("short", "download_size_mismatch"), ("long", "download_size_mismatch"),
    ("hash", "download_hash_mismatch"), ("length", "download_size_mismatch"), ("encoding", "download_encoding"), ("http", "download_http_error")])
def test_download_size_hash_encoding_and_http_errors_never_install(tmp_path, monkeypatch, fixture_release, kind, code):
    payload, headers, status = fixture_release, {}, 200
    if kind == "short":
        payload = payload[:-1]
    elif kind == "long":
        payload += b"extra"
    elif kind == "hash":
        payload = bytes([payload[0] ^ 1]) + payload[1:]
    elif kind == "length":
        headers["content-length"] = "999999999"
    elif kind == "encoding":
        headers["content-encoding"] = "deflate"
    elif kind == "http":
        status = 404
    transport(monkeypatch, lambda request: httpx.Response(status, headers=headers, stream=httpx.ByteStream(payload)))
    installer = mod.NucleiInstaller(tmp_path)
    result = installer.run()
    assert not result["ok"] and result["code"] == code
    assert not installer.destination.exists() and no_owned_temps(installer)


def test_cancel_before_download_does_not_access_network_or_make_directories(tmp_path, monkeypatch, fixture_release):
    client = Mock(side_effect=AssertionError("Cancelled operation has no effect"))
    monkeypatch.setattr(mod.httpx, "Client", client)
    cancel = threading.Event()
    cancel.set()
    installer = mod.NucleiInstaller(tmp_path)
    result = installer.run(cancel=cancel)
    assert result["code"] == "cancelled" and not (tmp_path / "security").exists()
    client.assert_not_called()


def test_cancel_during_stream_closes_response_and_cleans_owned_files(tmp_path, monkeypatch, fixture_release):
    cancel, closed = threading.Event(), []

    class Stream(httpx.SyncByteStream):
        def __iter__(self):
            # Larger chunks than this synthetic release still exercise the
            # real stream cancellation check; no actual executable is present.
            yield fixture_release[:10]
            cancel.set()
            yield fixture_release[10:]

        def close(self):
            closed.append(True)

    transport(monkeypatch, lambda request: httpx.Response(200, stream=Stream()))
    installer = mod.NucleiInstaller(tmp_path)
    result = installer.run(cancel=cancel)
    assert result["code"] == "cancelled" and closed
    assert not installer.destination.exists() and no_owned_temps(installer)


@pytest.mark.parametrize("name", ["../nuclei.exe", "sub/nuclei.exe", "C:/nuclei.exe", "nuclei.exe:stream", "unknown.exe"])
def test_zip_traversal_nested_stream_or_extra_executable_rejected(tmp_path, monkeypatch, name):
    payload = make_zip([("nuclei.exe", b"MZfixture"), (name, b"MZmust-never-write")])
    monkeypatch.setattr(mod, "ARCHIVE_BYTES", len(payload))
    monkeypatch.setattr(mod, "ARCHIVE_SHA256", hashlib.sha256(payload).hexdigest())
    monkeypatch.setattr(mod, "_supported", lambda: True)
    transport(monkeypatch, lambda request: httpx.Response(200, content=payload))
    installer = mod.NucleiInstaller(tmp_path)
    result = installer.run()
    assert result["code"] == "unsafe_tool_archive" and not installer.destination.exists()
    assert not (tmp_path / "nuclei.exe").exists() and no_owned_temps(installer)


def test_zip_symbolic_link_is_rejected(tmp_path, monkeypatch):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        link = zipfile.ZipInfo("nuclei.exe")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(link, "other-file")
    payload = data.getvalue()
    monkeypatch.setattr(mod, "ARCHIVE_BYTES", len(payload))
    monkeypatch.setattr(mod, "ARCHIVE_SHA256", hashlib.sha256(payload).hexdigest())
    monkeypatch.setattr(mod, "_supported", lambda: True)
    transport(monkeypatch, lambda request: httpx.Response(200, content=payload))
    assert mod.NucleiInstaller(tmp_path).run()["code"] == "unsafe_tool_archive"


@pytest.mark.parametrize("kind,code", [("ratio", "unsafe_tool_archive"), ("header", "invalid_tool_header"), ("missing", "unsafe_tool_archive")])
def test_zip_bomb_invalid_header_or_missing_binary_rejected(tmp_path, monkeypatch, kind, code):
    entries = [("nuclei.exe", b"MZ" + b"x" * 100000)] if kind == "ratio" else [("nuclei.exe", b"not-a-PE")] if kind == "header" else [("README.md", b"no exe")]
    payload = make_zip(entries)
    monkeypatch.setattr(mod, "ARCHIVE_BYTES", len(payload))
    monkeypatch.setattr(mod, "ARCHIVE_SHA256", hashlib.sha256(payload).hexdigest())
    monkeypatch.setattr(mod, "_supported", lambda: True)
    transport(monkeypatch, lambda request: httpx.Response(200, content=payload))
    installer = mod.NucleiInstaller(tmp_path)
    assert installer.run()["code"] == code
    assert not installer.destination.exists() and no_owned_temps(installer)


def test_existing_unrelated_destination_never_overwritten(tmp_path, monkeypatch, fixture_release):
    installer = mod.NucleiInstaller(tmp_path)
    installer.destination.mkdir(parents=True)
    sentinel = installer.destination / "user-data.txt"
    sentinel.write_bytes(b"preserve")
    client = Mock(side_effect=AssertionError("Conflicting destination prevents download"))
    monkeypatch.setattr(mod.httpx, "Client", client)
    result = installer.run()
    assert result["code"] == "installation_conflict" and sentinel.read_bytes() == b"preserve"
    client.assert_not_called()


def test_destination_created_during_download_preserved(tmp_path, monkeypatch, fixture_release):
    transport(monkeypatch, lambda request: httpx.Response(200, content=fixture_release))
    installer = mod.NucleiInstaller(tmp_path)

    def event(value):
        if value["stage"] == "archive_verified":
            installer.destination.mkdir()
            (installer.destination / "user-data.txt").write_bytes(b"preserve")

    result = installer.run(emit=event)
    assert result["code"] == "installation_conflict"
    assert (installer.destination / "user-data.txt").read_bytes() == b"preserve"
    assert no_owned_temps(installer)


def test_modified_installed_executable_is_reported_as_conflict(tmp_path, monkeypatch, fixture_release):
    transport(monkeypatch, lambda request: httpx.Response(200, content=fixture_release))
    installer = mod.NucleiInstaller(tmp_path)
    assert installer.run()["ok"]
    installer.executable.write_bytes(b"MZmodified")
    assert installer.inventory()["code"] == "installation_conflict"
    assert installer.run()["code"] == "installation_conflict"
    assert installer.executable.read_bytes() == b"MZmodified"


def test_official_translated_readmes_do_not_prevent_executable_only_install(tmp_path, monkeypatch):
    payload = make_zip([(name, b"Documentation") for name in ["README_CN.md", "README_ES.md", "README_ID.md", "README_JP.md", "README_KR.md", "README_PT-BR.md", "README_TR.md"]] + [("nuclei.exe", b"MZ" + bytes(range(256)))])
    monkeypatch.setattr(mod, "ARCHIVE_BYTES", len(payload))
    monkeypatch.setattr(mod, "ARCHIVE_SHA256", hashlib.sha256(payload).hexdigest())
    transport(monkeypatch, lambda request: httpx.Response(200, content=payload))
    installer = mod.NucleiInstaller(tmp_path)
    assert installer.run()["ok"]
    assert sorted(p.name for p in installer.destination.iterdir()) == ["installation.json", "nuclei.exe"]


@pytest.mark.parametrize("corrupt", [False, True])
def test_official_cache_verified_before_reuse_without_network(tmp_path, monkeypatch, fixture_release, corrupt):
    cache = tmp_path / "security/tools/downloads/nuclei_3.11.1_windows_amd64.zip"
    cache.parent.mkdir(parents=True)
    cache.write_bytes(fixture_release[:-1] + b"x" if corrupt else fixture_release)
    http = Mock(side_effect=AssertionError("Verified cache path must not access HTTP"))
    monkeypatch.setattr(mod.httpx, "Client", http)
    installer = mod.NucleiInstaller(tmp_path)
    result = installer.run()
    assert result["ok"] is (not corrupt)
    if corrupt:
        assert result["code"] == "download_hash_mismatch" and not installer.destination.exists()
    else:
        assert result["provenance"]["archive_source"] == "verified_local_cache"
    http.assert_not_called()
