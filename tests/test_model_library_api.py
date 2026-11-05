"""Human model operations through FastAPI, with no actual model downloads."""
import asyncio
import hashlib
from types import SimpleNamespace
from unittest.mock import Mock

from fastapi import FastAPI
from fastapi.testclient import TestClient
import httpx
import pytest

from nexus.library.model_api import install_model_routes
from nexus.library.models import ModelLibrary
from test_model_library import MockOllama, gguf


@pytest.fixture
def api(tmp_path):
    mock = MockOllama()
    settings = {"model": "original:latest", "coding_model": "", "embedding_model": "", "ollama_url": "http://127.0.0.1:11434"}
    manager = ModelLibrary(tmp_path, lambda: settings.copy(), lambda values: settings.update(values),
        client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(mock.handler)),
        resources=lambda: {"ram_available_gb": 4, "gpu": [], "disk_free_gb": 50})
    gate = asyncio.Semaphore(1)
    activity = Mock()
    app = FastAPI()
    install_model_routes(app, lambda: manager, lambda: gate, lambda: activity)
    with TestClient(app) as client:
        yield SimpleNamespace(client=client, manager=manager, mock=mock, activity=activity, gate=gate)


BASE = "/api/library/models"


def preview(api, **payload):
    response = api.client.post(BASE + "/preview", json=payload)
    assert response.status_code == 200, response.text
    return response.json()


def test_inventory_http_exposes_metadata_without_implicit_generation(api):
    response = api.client.get(BASE)
    assert response.status_code == 200
    result = response.json()
    assert result["connected"] is True and len(result["models"]) == 2
    assert result["jobs"] == [] and result["uploads"] == []
    assert not any("/api/generate" in item[1] for item in api.mock.requests)


def test_preview_and_approval_http_do_not_accept_argument_replacement(api):
    value = preview(api, action="variant", model="variant:test", base="small:test", context=2048)
    bad = api.client.post(BASE + "/jobs", json={"approval_id": value["approval_id"], "approved": True, "model": "huge:other"})
    assert bad.status_code == 422
    assert not any("/api/create" in item[1] for item in api.mock.requests)
    denied = api.client.post(BASE + "/jobs", json={"approval_id": value["approval_id"], "approved": False})
    assert denied.json()["code"] == "approval_denied"
    assert api.manager.pending == {}


def test_approval_requires_boolean_and_is_single_use(api):
    value = preview(api, action="variant", model="variant:test", base="small:test")
    assert api.client.post(BASE + "/jobs", json={"approval_id": value["approval_id"], "approved": "true"}).status_code == 422
    launched = api.client.post(BASE + "/jobs", json={"approval_id": value["approval_id"], "approved": True})
    assert launched.status_code == 200
    identity = launched.json()["job_id"]
    for _ in range(100):
        job = api.client.get(BASE + "/jobs/" + identity).json()
        if job["status"] in {"completed", "failed", "cancelled"}:
            break
    assert job["status"] == "completed", job
    assert api.client.post(BASE + "/jobs", json={"approval_id": value["approval_id"], "approved": True}).status_code == 400
    assert api.client.get(BASE + "/jobs").json()["jobs"][0]["id"] == identity
    assert "args" not in job
    assert any(call.args[0] == "model_approval_granted" for call in api.activity.add.call_args_list)


def test_delete_http_requires_full_name_confirmation(api):
    value = preview(api, action="delete", model="small:test")
    refused = api.client.post(BASE + "/jobs", json={"approval_id": value["approval_id"], "approved": True})
    assert refused.status_code == 400 and refused.json()["code"] == "confirmation_required"
    assert "small:test" in api.mock.models
    launched = api.client.post(BASE + "/jobs", json={"approval_id": value["approval_id"], "approved": True, "confirmation": "small:test"})
    assert launched.status_code == 200
    identity = launched.json()["job_id"]
    for _ in range(100):
        job = api.client.get(BASE + "/jobs/" + identity).json()
        if job["status"] in {"completed", "failed"}:
            break
    assert job["status"] == "completed" and "small:test" not in api.mock.models


def test_raw_gguf_upload_hash_and_cleanup_http(api):
    payload = gguf()
    digest = hashlib.sha256(payload).hexdigest()
    result = api.client.post(BASE + "/uploads", params={"name": "teste.gguf", "sha256": digest}, content=payload,
        headers={"Content-Type": "application/octet-stream"})
    assert result.status_code == 200, result.text
    upload = result.json()
    assert upload["sha256"] == digest and upload["architecture"] == "llama"
    assert api.client.get(BASE).json()["uploads"][0]["id"] == upload["id"]
    assert api.client.delete(BASE + "/uploads/" + upload["id"]).json()["ollama_model_removed"] is False
    assert api.manager.uploads() == []


def test_upload_errors_are_technical_not_model_refusals(api):
    bad = api.client.post(BASE + "/uploads", params={"name": "a.gguf"}, content=b"MZ executable")
    assert bad.status_code == 400 and bad.json()["code"] == "gguf_invalid"
    assert bad.json()["source"] == "application"
    bad = api.client.post(BASE + "/uploads", params={"name": "../a.gguf"}, content=gguf())
    assert bad.status_code == 400
    assert api.manager.uploads() == []


def test_unknown_job_and_invalid_actions_are_explicit(api):
    assert api.client.get(BASE + "/jobs/absent").status_code == 404
    assert api.client.post(BASE + "/jobs/absent/cancel").status_code == 404
    result = api.client.post(BASE + "/preview", json={"action": "execute", "model": "local:test"})
    assert result.status_code == 400 and result.json()["code"] == "library_input"


def test_model_api_never_bypasses_approval_via_delete_verb(api):
    assert api.client.delete(BASE + "/small:test").status_code == 404
    assert "small:test" in api.mock.models
