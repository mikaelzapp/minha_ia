"""Model Library with real parsing/storage and an isolated Ollama HTTP transport."""
import asyncio
import copy
import hashlib
import json
from pathlib import Path
import struct
from types import SimpleNamespace
from unittest.mock import Mock

import httpx
import pytest

from nexus.library.models import (LibraryError, ModelLibrary, check_compatibility,
    inspect_gguf, model_name, MAX_UPLOAD, TERMINAL, test_budget as budget_for)


def gguf(architecture="llama", *, split=1, data=True):
    def string(value):
        value = value.encode()
        return struct.pack("<Q", len(value)) + value
    metadata = string("general.architecture") + struct.pack("<I", 8) + string(architecture)
    metadata += string("llama.context_length") + struct.pack("<II", 4, 4096)
    metadata += string("split.count") + struct.pack("<II", 4, split)
    payload = b"GGUF" + struct.pack("<IQQ", 3, 1, 3) + metadata
    payload += string("test.weight") + struct.pack("<IQIQ", 1, 4, 0, 0)
    payload += b"\x00" * (-len(payload) % 32)
    return payload + (struct.pack("<ffff", 1, 2, 3, 4) if data else b"")


class MockOllama:
    def __init__(self):
        self.models = {"original:latest": {"name": "original:latest", "digest": "originalhash", "size": 1234,
            "details": {"quantization_level": "Q4_K_M", "parameter_size": "4B"}, "capabilities": ["completion", "tools"]},
            "small:test": {"name": "small:test", "digest": "smallhash", "size": 512, "capabilities": ["completion"]}}
        self.requests = []
        self.running = []
        self.stream_lines = [{"status": "pulling layer", "digest": "sha256:abc", "completed": 25, "total": 100}, {"status": "success"}]
        self.manifest = {"config": {"size": 1, "digest": "sha256:config"}, "layers": [{"size": 99, "digest": "sha256:weight"}]}
        self.hf_bytes = gguf()

    async def handler(self, request):
        raw = await request.aread()
        body = json.loads(raw) if raw and request.headers.get("content-type", "").startswith("application/json") else None
        self.requests.append((request.method, str(request.url), body, raw))
        path = request.url.path
        if request.url.host == "registry.ollama.ai":
            return httpx.Response(200, json=self.manifest)
        if request.url.host == "huggingface.co":
            if path.startswith("/api/models/"):
                return httpx.Response(200, json={"sha": "a" * 40, "cardData": {"license": "apache-2.0"}, "siblings": [
                    {"rfilename": "weights.gguf", "lfs": {"sha256": hashlib.sha256(self.hf_bytes).hexdigest(), "size": len(self.hf_bytes)}}]})
            return httpx.Response(200, content=self.hf_bytes)
        if path == "/api/tags":
            return httpx.Response(200, json={"models": list(self.models.values())})
        if path == "/api/ps":
            return httpx.Response(200, json={"models": self.running})
        if path == "/api/show":
            item = self.models.get(body["model"])
            if item is None:
                return httpx.Response(404, json={"error": "model missing"})
            return httpx.Response(200, json={**item, "model_info": {"llama.context_length": 8192}})
        if path in {"/api/pull", "/api/create"}:
            if self.stream_lines[-1].get("status") == "success":
                self.models[body["model"]] = {"name": body["model"], "digest": "newhash", "size": 512, "capabilities": ["completion"]}
            return httpx.Response(200, content="\n".join(json.dumps(line) for line in self.stream_lines) + "\n")
        if path.startswith("/api/blobs/"):
            return httpx.Response(404 if request.method == "HEAD" else 201)
        if path == "/api/delete":
            self.models.pop(body["model"])
            return httpx.Response(200)
        if path == "/api/generate":
            return httpx.Response(200, json={"done": True, "response": "NEXUS OK", "eval_count": 4, "eval_duration": 200000000, "load_duration": 50000000})
        return httpx.Response(500, json={"error": path})


@pytest.fixture
def case(tmp_path):
    mock = MockOllama()
    settings = {"model": "original:latest", "coding_model": "", "embedding_model": "", "ollama_url": "http://127.0.0.1:11434"}
    def update(values):
        settings.update(values)
        return settings
    manager = ModelLibrary(tmp_path, lambda: settings.copy(), update,
        client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(mock.handler), trust_env=False),
        resources=lambda: {"ram_available_gb": 5, "disk_free_gb": 50, "gpu": [{"memory_total_mb": 6144, "memory_used_mb": 1000}]})
    return SimpleNamespace(manager=manager, mock=mock, settings=settings, activity=Mock(), tmp=tmp_path)


async def operation(case, payload, *, confirmation=None):
    value = await case.manager.preview(payload)
    job = case.manager.approve(value["approval_id"], True, confirmation)
    semaphore = asyncio.Semaphore(1)
    await case.manager.run(job["id"], lambda: semaphore, lambda: case.activity)
    return case.manager.job(job["id"])


@pytest.mark.parametrize("value", ["http://evil/x", "../model", "a/../../x", "a/b/c", "UPPER", "a:cloud", "abc-cloud", "a\n:tag", "C:\\file", " a", "a;cmd", "a:tag:bad", "a@digest", None, 23, "a..b"])
def test_names_reject_urls_paths_remote_and_shell(value):
    with pytest.raises(LibraryError):
        model_name(value)


@pytest.mark.parametrize("value,expected", [("qwen3:4b", "qwen3:4b"), ("autor/modelo:Q4_K_M", "autor/modelo:Q4_K_M"), ("local-model", "local-model:latest")])
def test_name_canonicalization(value, expected):
    assert model_name(value) == expected


def test_inventory_reads_ollama_metadata_without_loading(case):
    result = asyncio.run(case.manager.inventory())
    assert result["connected"] is True
    item = next(item for item in result["models"] if item["name"] == "original:latest")
    assert item["tools"] is True and item["vision"] is False and item["context_length"] == 8192
    assert item["quantization"] == "Q4_K_M" and item["loaded"] is False and item["default"] is True
    assert all("generate" not in request[1] and "pull" not in request[1] for request in case.mock.requests)


def test_compatibility_reports_missing_and_remote_capabilities():
    assert check_compatibility({"capabilities": ["completion"]}, ["tools"])["missing"] == ["tools"]
    assert check_compatibility({"capabilities": ["completion", "tools"]}, ["tools"])["compatible"] is True
    assert check_compatibility({"name": "abc:cloud", "capabilities": ["tools"]}, ["tools"])["compatible"] is False


def test_preview_does_not_start_download_and_denial_is_consumed(case):
    async def run():
        value = await case.manager.preview({"action": "pull", "model": "new:tiny"})
        assert value["preview"]["estimated_download_bytes"] == 100
        assert not any("/api/pull" in item[1] for item in case.mock.requests)
        assert case.manager.approve(value["approval_id"], False) is None
        with pytest.raises(LibraryError, match="expirada"):
            case.manager.approve(value["approval_id"], True)
    asyncio.run(run())


def test_pull_records_actual_ndjson_progress_and_success(case):
    job = asyncio.run(operation(case, {"action": "pull", "model": "new:tiny"}))
    assert job["status"] == "completed"
    assert any(event.get("percent") == 25 for event in job["events"])
    assert job["progress"]["percent"] is None  # success carries no invented byte total
    assert "args" not in job
    assert "original:latest" in case.mock.models


@pytest.mark.parametrize("lines,code", [([{ "status": "pulling"}], "ollama_stream_incomplete"), ([{"error": "network failed"}], "ollama_error")])
def test_pull_incomplete_or_error_is_not_success(case, lines, code):
    case.mock.stream_lines = lines
    job = asyncio.run(operation(case, {"action": "pull", "model": "new:tiny"}))
    assert job["status"] == "failed" and job["code"] == code


def test_manifest_change_invalidates_approval_before_pull(case):
    async def run():
        value = await case.manager.preview({"action": "pull", "model": "new:tiny"})
        job = case.manager.approve(value["approval_id"], True)
        case.mock.manifest["layers"][0]["size"] = 100000
        await case.manager.run(job["id"], lambda: asyncio.Semaphore(1), lambda: case.activity)
        assert case.manager.job(job["id"])["code"] == "manifest_changed"
        assert not any("/api/pull" in item[1] for item in case.mock.requests)
    asyncio.run(run())


def test_changed_ollama_address_invalidates_the_bound_approval(case):
    async def run():
        value = await case.manager.preview({"action": "variant", "model": "variant:test", "base": "small:test"})
        job = case.manager.approve(value["approval_id"], True)
        before = len(case.mock.requests)
        case.settings["ollama_url"] = "http://127.0.0.1:11435"
        await case.manager.run(job["id"], lambda: asyncio.Semaphore(1), lambda: case.activity)
        assert case.manager.job(job["id"])["code"] == "ollama_changed"
        assert len(case.mock.requests) == before
    asyncio.run(run())


def test_existing_tags_never_overwritten_by_add_operations(case):
    async def run():
        for action in ("pull", "variant", "import", "hf"):
            with pytest.raises(LibraryError, match="já está instalado"):
                await case.manager.preview({"action": action, "model": "original:latest"})
    asyncio.run(run())


def test_delete_requires_typed_name_and_protects_config_references(case):
    async def run():
        with pytest.raises(LibraryError, match="em uso"):
            await case.manager.preview({"action": "delete", "model": "original:latest"})
        value = await case.manager.preview({"action": "delete", "model": "small:test"})
        with pytest.raises(LibraryError, match="nome completo"):
            case.manager.approve(value["approval_id"], True, "wrong")
        job = case.manager.approve(value["approval_id"], True, "small:test")
        await case.manager.run(job["id"], lambda: asyncio.Semaphore(1), lambda: case.activity)
        assert case.manager.job(job["id"])["status"] == "completed" and "small:test" not in case.mock.models
    asyncio.run(run())


def test_delete_revalidates_new_reference_after_approval(case):
    async def run():
        value = await case.manager.preview({"action": "delete", "model": "small:test"})
        job = case.manager.approve(value["approval_id"], True, "small:test")
        case.settings["coding_model"] = "small:test"
        await case.manager.run(job["id"], lambda: asyncio.Semaphore(1), lambda: case.activity)
        assert case.manager.job(job["id"])["code"] == "model_referenced"
        assert "small:test" in case.mock.models
    asyncio.run(run())


def test_variant_uses_structured_api_and_never_downloads_base(case):
    system = 'Answer technically.\nFROM evil:latest\nSYSTEM """ is plain text'
    job = asyncio.run(operation(case, {"action": "variant", "model": "variant:test", "base": "small:test", "system": system, "temperature": .1, "context": 2048}))
    assert job["status"] == "completed"
    create = next(item[2] for item in case.mock.requests if item[1].endswith("/api/create"))
    assert create["from"] == "small:test" and create["system"] == system
    assert create["parameters"] == {"temperature": .1, "num_ctx": 2048}
    assert not any("/api/pull" in item[1] for item in case.mock.requests)
    assert system not in (case.manager.root / "jobs.json").read_text()


def test_variant_base_must_exist_and_not_change(case):
    async def run():
        with pytest.raises(LibraryError, match="base instalado"):
            await case.manager.preview({"action": "variant", "model": "variant:test", "base": "missing:base"})
        value = await case.manager.preview({"action": "variant", "model": "variant:test", "base": "small:test"})
        job = case.manager.approve(value["approval_id"], True)
        case.mock.models["small:test"]["digest"] = "changed"
        await case.manager.run(job["id"], lambda: asyncio.Semaphore(1), lambda: case.activity)
        assert case.manager.job(job["id"])["code"] == "base_changed"
    asyncio.run(run())


@pytest.mark.parametrize("extra", [{"context": 0}, {"context": 65536}, {"context": True}, {"temperature": -1}, {"temperature": float("nan")}, {"system": "\x00"}, {"shell": "cmd"}])
def test_variant_rejects_invalid_parameters(case, extra):
    async def run():
        with pytest.raises(LibraryError):
            await case.manager.preview({"action": "variant", "model": "variant:test", "base": "small:test", **extra})
    asyncio.run(run())


def test_default_unload_and_small_load_test_use_real_api_contract(case):
    async def run():
        default = await operation(case, {"action": "default", "model": "small:test"})
        assert default["status"] == "completed" and case.settings["model"] == "small:test"
        unload = await operation(case, {"action": "unload", "model": "small:test"})
        assert unload["status"] == "completed"
        tested = await operation(case, {"action": "test", "model": "small:test"})
        assert tested["result"]["metrics"]["tokens_per_second"] == 20
        request = next(item[2] for item in reversed(case.mock.requests) if item[1].endswith("/api/generate"))
        assert request["keep_alive"] == 0 and request["options"]["num_predict"] == 48
    asyncio.run(run())


def test_load_test_prevents_concurrent_large_models(case):
    case.mock.running = [{"name": "original:latest"}]
    job = asyncio.run(operation(case, {"action": "test", "model": "small:test"}))
    assert job["status"] == "failed" and job["code"] == "model_already_loaded"
    assert not any("/api/generate" in item[1] for item in case.mock.requests)


def test_small_model_budget_allows_750mb_ram_and_large_model_requests_margin(case):
    small = budget_for({"size": 270898672}, {"ram_available_gb": .75, "gpu": [{"memory_total_mb": 6144, "memory_used_mb": 500}]})
    assert small["can_test"] is True and small["minimum_ram_available_gb"] == .5
    large = budget_for({"size": 6594474755}, {"ram_available_gb": 2, "gpu": [{"memory_total_mb": 6144, "memory_used_mb": 500}]})
    assert large["can_test"] is False and large["minimum_ram_available_gb"] == 4
    assert budget_for({"size": 3389983735}, {"ram_available_gb": 1.2, "gpu": [{"memory_total_mb": 6144, "memory_used_mb": 500}]})["can_test"] is True


def test_load_test_rechecks_ram_after_waiting_in_queue(case):
    async def run():
        value = await case.manager.preview({"action": "test", "model": "small:test"})
        job = case.manager.approve(value["approval_id"], True)
        case.manager.resources = lambda: {"ram_available_gb": .25, "gpu": []}
        await case.manager.run(job["id"], lambda: asyncio.Semaphore(1), lambda: case.activity)
        assert case.manager.job(job["id"])["code"] == "memory_low"
        assert not any("/api/generate" in item[1] for item in case.mock.requests)
    asyncio.run(run())


def test_shared_semaphore_queues_and_cancel_never_executes(case):
    async def run():
        semaphore = asyncio.Semaphore(1)
        await semaphore.acquire()
        value = await case.manager.preview({"action": "pull", "model": "new:tiny"})
        job = case.manager.approve(value["approval_id"], True)
        case.manager.start(job["id"], lambda: semaphore, lambda: case.activity)
        await asyncio.sleep(0)
        assert case.manager.job(job["id"])["status"] == "queued"
        case.manager.cancel(job["id"])
        await asyncio.sleep(.01)
        assert case.manager.job(job["id"])["status"] == "cancelled"
        semaphore.release()
        assert not any("/api/pull" in item[1] for item in case.mock.requests)
        await case.manager.close()
    asyncio.run(run())


def test_cancel_immediately_before_task_started(case):
    async def run():
        value = await case.manager.preview({"action": "pull", "model": "new:tiny"})
        job = case.manager.approve(value["approval_id"], True)
        case.manager.start(job["id"], lambda: asyncio.Semaphore(1), lambda: case.activity)
        case.manager.cancel(job["id"])
        await asyncio.sleep(.01)
        assert case.manager.job(job["id"])["status"] == "cancelled"
        assert case.manager.tasks == {}
    asyncio.run(run())


def test_restart_marks_unfinished_jobs_interrupted_preserves_existing_data(case):
    async def run():
        value = await case.manager.preview({"action": "pull", "model": "new:tiny"})
        return case.manager.approve(value["approval_id"], True)["id"]
    identity = asyncio.run(run())
    original = case.tmp / "user-project.txt"
    original.write_text("keep")
    new = ModelLibrary(case.tmp, lambda: case.settings, lambda x: x)
    assert new.job(identity)["status"] == "interrupted" and original.read_text() == "keep"


def test_gguf_parser_validates_header_architecture_tensors(tmp_path):
    path = tmp_path / "model.gguf"
    path.write_bytes(gguf())
    result = inspect_gguf(path)
    assert result["architecture"] == "llama" and result["tensor_count"] == 1 and result["load_tested"] is False
    assert result["metadata"]["llama.context_length"] == 4096


@pytest.mark.parametrize("payload,code", [(b"MZnotamodel", "gguf_invalid"), (gguf("unknown"), "gguf_architecture"), (gguf(split=2), "gguf_split_unsupported"), (gguf(data=False), "gguf_invalid"), (gguf()[:32], "gguf_invalid")])
def test_gguf_parser_rejects_unsupported_or_truncated_payload(tmp_path, payload, code):
    path = tmp_path / "bad.gguf"
    path.write_bytes(payload)
    with pytest.raises(LibraryError) as error:
        inspect_gguf(path)
    assert error.value.code == code


async def upload(case, payload=None, **kwargs):
    async def chunks():
        content = gguf() if payload is None else payload
        for index in range(0, len(content), 3):
            yield content[index:index + 3]
    return await case.manager.ingest(chunks(), kwargs.pop("name", "model.gguf"), **kwargs)


def test_upload_is_streamed_hashed_and_imports_only_validated_blob(case):
    async def run():
        item = await upload(case, expected_hash=hashlib.sha256(gguf()).hexdigest())
        assert item["integrity"] == "matched_expected_sha256"
        assert item["sha256"] == hashlib.sha256(gguf()).hexdigest()
        job = await operation(case, {"action": "import", "model": "import:test", "upload_id": item["id"]})
        assert job["status"] == "completed"
        create = next(item[2] for item in case.mock.requests if item[1].endswith("/api/create"))
        assert create["files"] == {"model.gguf": "sha256:" + item["sha256"]}
        posted = next(item[3] for item in case.mock.requests if "/api/blobs/" in item[1] and item[0] == "POST")
        assert posted == gguf()
        assert not any("/api/generate" in item[1] for item in case.mock.requests)
    asyncio.run(run())


@pytest.mark.parametrize("name", ["../file.gguf", "C:\\file.gguf", "bad.py", "file.gguf.exe", "a..gguf"])
def test_upload_rejects_paths_non_gguf_and_scripts(case, name):
    with pytest.raises(LibraryError):
        asyncio.run(upload(case, name=name))


def test_upload_integrity_mismatch_removes_only_new_file(case):
    old = case.manager.upload_dir / "preserved.txt"
    old.write_text("keep")
    with pytest.raises(LibraryError, match="SHA-256"):
        asyncio.run(upload(case, expected_hash="0" * 64))
    assert list(case.manager.upload_dir.glob("*.gguf")) == [] and old.read_text() == "keep"


def test_upload_changed_after_approval_never_sent_to_ollama(case):
    async def run():
        item = await upload(case)
        preview = await case.manager.preview({"action": "import", "model": "import:test", "upload_id": item["id"]})
        job = case.manager.approve(preview["approval_id"], True)
        path, _ = case.manager.get_upload(item["id"])
        payload = bytearray(path.read_bytes())
        payload[-1] ^= 1
        path.write_bytes(payload)
        await case.manager.run(job["id"], lambda: asyncio.Semaphore(1), lambda: case.activity)
        assert case.manager.job(job["id"])["code"] == "integrity_mismatch"
        assert not any("/api/blobs/" in item[1] for item in case.mock.requests)
    asyncio.run(run())


def test_upload_cleanup_does_not_remove_ollama_model(case):
    item = asyncio.run(upload(case))
    assert case.manager.remove_upload(item["id"])["ollama_model_removed"] is False
    assert case.manager.uploads() == [] and len(case.mock.models) == 2


def test_hugging_face_reference_pins_commit_hash_and_downloads_no_scripts(case):
    job = asyncio.run(operation(case, {"action": "hf", "model": "hfimport:test", "repo": "author/repo", "filename": "weights.gguf"}))
    assert job["status"] == "completed"
    downloaded = [item[1] for item in case.mock.requests if "/resolve/" in item[1]]
    assert len(downloaded) == 1 and "/" + "a" * 40 + "/weights.gguf" in downloaded[0]
    assert all(not item[1].endswith(".py") for item in case.mock.requests)
    item = case.manager.uploads()[0]
    assert item["integrity"] == "matched_expected_sha256" and item["source"]["commit"] == "a" * 40


def test_hf_declared_unsupported_architecture_is_rejected_before_weights(case):
    original = case.mock.handler
    async def handler(request):
        response = await original(request)
        if request.url.host == "huggingface.co" and request.url.path.startswith("/api/models/"):
            metadata = response.json()
            metadata["gguf"] = {"architecture": "not_supported"}
            return httpx.Response(200, json=metadata)
        return response
    case.manager.client_factory = lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler))
    async def run():
        with pytest.raises(LibraryError, match="Arquitetura"):
            await case.manager.preview({"action": "hf", "model": "hfimport:test", "repo": "author/repo", "filename": "weights.gguf"})
        assert not any("/resolve/" in request[1] for request in case.mock.requests)
    asyncio.run(run())


@pytest.mark.parametrize("changes", [{"repo": "https://evil/x"}, {"repo": "a/../x"}, {"filename": "../weights.gguf"}, {"filename": "weights.py"}, {"revision": "../main"}])
def test_hf_reference_rejects_urls_paths_scripts_and_bad_revision(case, changes):
    async def run():
        with pytest.raises(LibraryError):
            await case.manager.preview({"action": "hf", "model": "hfimport:test", "repo": "author/repo", "filename": "weights.gguf", **changes})
    asyncio.run(run())


@pytest.mark.parametrize("url", ["http://huggingface.co/x", "https://127.0.0.1/x", "https://evil.test/a.gguf", "https://huggingface.co.evil.test/x", "https://user:pass@huggingface.co/x", "https://huggingface.co:8080/x"])
def test_hf_redirects_restricted_to_https_delivery_hosts(url):
    with pytest.raises(LibraryError):
        ModelLibrary._hf_redirect(url)


def test_hardlinked_upload_or_library_storage_is_rejected(case):
    import os
    original = case.tmp / "outside"
    original.write_bytes(gguf())
    hard = case.tmp / "linked.gguf"
    os.link(original, hard)
    with pytest.raises(LibraryError):
        inspect_gguf(hard)


def test_pending_arguments_cannot_be_changed_after_human_preview(case):
    async def run():
        value = await case.manager.preview({"action": "pull", "model": "new:tiny"})
        case.manager.pending[value["approval_id"]]["args"]["model"] = "changed:huge"
        with pytest.raises(LibraryError, match="Argumentos mudaram"):
            case.manager.approve(value["approval_id"], True)
    asyncio.run(run())
