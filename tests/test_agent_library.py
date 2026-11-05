"""Agent configuration, persistence and HTTP contracts; never execute imported text."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import json
import os
from pathlib import Path
import sqlite3
from types import SimpleNamespace
from unittest.mock import Mock

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from nexus.library.agents import AgentLibrary, AgentLibraryError, EDITABLE
from nexus.library.agent_api import install_agent_routes


@pytest.fixture
def configuration():
    return {"name": "Especialista de testes", "description": "Audita projetos próprios.", "icon": "◈",
        "workspace_mode": "developer", "prompt": "Leia os arquivos e cite evidências antes de sugerir mudanças.",
        "default_model": "qwen3.5:4b-q4_K_M", "tool_allowlist": ["read_file", "list_files"],
        "memory": {"read": True, "write": False, "scope": "project"},
        "permissions": {"file_read": True, "file_write": False, "terminal": False, "external_network": False},
        "search": {"provider": "auto", "max_results": 5, "tor_enabled": False}}


@pytest.fixture
def library(tmp_path, configuration):
    builtins = [{**configuration, "id": "coder", "name": "NEXUS CODER"}]
    tools = [{"type": "function", "function": {"name": name, "description": name + " description"}}
             for name in ("read_file", "list_files", "write_file", "run_command", "search_web", "security_http")]
    return AgentLibrary(tmp_path / "data", lambda: builtins, lambda: tools,
                        lambda: [{"id": identity, "name": identity} for identity in ("chat", "search", "tor", "pentest", "developer", "security")])


def test_independent_storage_and_builtin_readonly(library, configuration):
    assert library.path.name == "agents.sqlite3" and library.path.parent.name == "library"
    builtin = library.get("coder")
    assert builtin["builtin"] is True and builtin["revision"] == 0
    for operation in (lambda: library.update("coder", configuration, 1), lambda: library.delete("coder", 1)):
        with pytest.raises(AgentLibraryError, match="somente leitura") as error:
            operation()
        assert error.value.status_code == 409
    assert library.get("coder") == builtin


def test_create_update_delete_and_restart_preserve_unrelated_files(library, configuration):
    unrelated = library.root.parent / "existing-memory.sqlite3"
    unrelated.write_bytes(b"preserve original unrelated database")
    created = library.create(configuration)
    assert created["id"].startswith("custom_") and created["revision"] == 1
    restarted = AgentLibrary(library.root.parent, library._builtins, library._tools, library._modes)
    assert restarted.get(created["id"]) == created
    changed = restarted.update(created["id"], {**configuration, "description": "Revisado"}, 1)
    assert changed["revision"] == 2 and changed["created_at"] == created["created_at"]
    assert changed["description"] == "Revisado"
    assert restarted.delete(created["id"], 2)["deleted"] is True
    with pytest.raises(AgentLibraryError) as error:
        restarted.get(created["id"])
    assert error.value.status_code == 404
    assert unrelated.read_bytes() == b"preserve original unrelated database"


def test_defaults_do_not_grant_operational_access(library):
    result = library.create({"name": "Mínimo", "prompt": "Explique a solicitação."})
    assert result["workspace_mode"] == "chat" and result["tool_allowlist"] == []
    assert result["memory"] == {"read": True, "write": False, "scope": "project"}
    assert result["permissions"] == {"file_read": True, "file_write": False, "terminal": False, "external_network": False}
    assert result["search"]["tor_enabled"] is False


@pytest.mark.parametrize("key,value", [
    ("name", ""), ("name", "a" * 121), ("name", 2), ("description", "a" * 2001),
    ("icon", "<svg>"), ("icon", "line\nbreak"), ("icon", "a" * 65),
    ("prompt", ""), ("prompt", "a" * 24001), ("prompt", "bad\x00value"),
    ("workspace_mode", "ROOT"), ("workspace_mode", []), ("default_model", "https://example.com/model"),
    ("default_model", "../model"), ("default_model", "qwen:cloud"), ("default_model", "qwen-cloud"),
    ("tool_allowlist", "read_file"), ("tool_allowlist", ["grant_root"]), ("tool_allowlist", [{}]),
    ("memory", {"scope": "all_projects"}), ("memory", {"scope": []}), ("memory", {"read": 1}),
    ("memory", {"credentials": True}), ("permissions", {"root": True}), ("permissions", {"terminal": "true"}),
    ("permissions", {"scope_id": "forged"}), ("permissions", {"model_pull": True}),
    ("search", {"provider": "arbitrary"}), ("search", {"provider": []}),
    ("search", {"max_results": True}), ("search", {"max_results": 100}),
    ("search", {"tor_enabled": "yes"}), ("search", {"proxy": "http://untrusted"}),
    ("unknown", True),
])
def test_invalid_fields_do_not_persist(library, configuration, key, value):
    payload = {**configuration, key: value}
    with pytest.raises(AgentLibraryError):
        library.create(payload)
    assert len(library.list()) == 1


def test_unicode_byte_budget_and_invalid_surrogate(library, configuration):
    for name in ("é" * 61, "bad\ud800"):
        with pytest.raises(AgentLibraryError):
            library.create({**configuration, "name": name})


def test_duplicate_and_export_import_are_independent_data(library, configuration, tmp_path):
    original = library.get("coder")
    duplicate = library.duplicate("coder", {"name": "Meu especialista"})
    assert duplicate["builtin"] is False and duplicate["name"] == "Meu especialista"
    envelope = library.export(duplicate["id"])
    assert envelope["format"] == "nexus-agent" and envelope["version"] == 1
    assert set(envelope["agent"]) == EDITABLE and "id" not in envelope["agent"]
    # Text remains inert even if it resembles executable Python or a shell command.
    marker = tmp_path / "must-not-exist.txt"
    envelope["agent"]["prompt"] = "import pathlib; pathlib.Path(" + repr(str(marker)) + ").write_text('executed')"
    imported = library.import_agent(json.loads(json.dumps(envelope)))
    assert imported["id"] != duplicate["id"] and imported["prompt"] == envelope["agent"]["prompt"]
    assert not marker.exists() and library.get("coder") == original


@pytest.mark.parametrize("changes", [
    {"format": "python"}, {"version": True}, {"version": 2}, {"script": "run"}, {"agent": None},
])
def test_import_rejects_unknown_or_executable_envelope(library, configuration, changes):
    envelope = {"format": "nexus-agent", "version": 1, "agent": configuration, **changes}
    with pytest.raises(AgentLibraryError):
        library.import_agent(envelope)


def test_import_rejects_identity_and_authorization_injection(library, configuration):
    for fields in ({"id": "coder"}, {"builtin": True}, {"revision": 100}, {"authorized_roots": ["C:\\"]}):
        with pytest.raises(AgentLibraryError):
            library.import_agent({"format": "nexus-agent", "version": 1, "agent": {**configuration, **fields}})


def test_revision_conflict_never_overwrites_new_edit(library, configuration):
    agent = library.create(configuration)
    changed = library.update(agent["id"], {**configuration, "name": "Primeira edição"}, 1)
    for operation in (lambda: library.update(agent["id"], {**configuration, "name": "Edição atrasada"}, 1),
                      lambda: library.delete(agent["id"], 1)):
        with pytest.raises(AgentLibraryError) as error:
            operation()
        assert error.value.code == "agent_revision_conflict"
    assert library.get(agent["id"]) == changed


def test_concurrent_edits_allow_one_matching_revision(library, configuration):
    agent = library.create(configuration)
    def edit(index):
        try:
            library.update(agent["id"], {**configuration, "name": f"Edição {index}"}, 1)
            return True
        except AgentLibraryError as error:
            assert error.code == "agent_revision_conflict"
            return False
    with ThreadPoolExecutor(max_workers=4) as executor:
        outcomes = list(executor.map(edit, range(4)))
    assert outcomes.count(True) == 1 and library.get(agent["id"])["revision"] == 2


def test_activation_rechecks_current_tool_registry(library, configuration):
    agent = library.create(configuration)
    library._tools = lambda: [{"name": "list_files", "description": "Still installed"}]
    with pytest.raises(AgentLibraryError, match="read_file"):
        library.resolve(agent["id"])


def test_database_hardlink_and_sidecar_link_rejected(library, tmp_path):
    linked = tmp_path / "db-copy.sqlite3"
    os.link(library.path, linked)
    with pytest.raises(AgentLibraryError, match="links|hardlink"):
        library.list()
    linked.unlink()
    journal = Path(str(library.path) + "-journal")
    sentinel = tmp_path / "unrelated.txt"
    sentinel.write_text("unchanged", encoding="utf-8")
    os.link(sentinel, journal)
    with pytest.raises(AgentLibraryError):
        library.create({"name": "Denied", "prompt": "Never saved"})
    assert sentinel.read_text(encoding="utf-8") == "unchanged"


def test_storage_parent_symlink_rejected(library, tmp_path):
    linked = tmp_path / "linked-data"
    try:
        linked.symlink_to(library.root.parent, target_is_directory=True)
    except OSError:
        pytest.skip("Windows symlinks require Developer Mode or elevated privileges")
    with pytest.raises(AgentLibraryError, match="links|junctions"):
        AgentLibrary(linked, library._builtins, library._tools, library._modes)


@pytest.fixture
def http_case(library):
    app = FastAPI()
    activity = Mock()
    async def blocking(function, *args):
        return await asyncio.to_thread(function, *args)
    install_agent_routes(app, lambda: library, blocking, lambda: activity)
    with TestClient(app) as client:
        yield SimpleNamespace(client=client, activity=activity, library=library)


def test_http_complete_agent_lifecycle_and_export(http_case, configuration):
    client = http_case.client
    listed = client.get("/api/library/agents").json()
    assert listed["agents"][0]["builtin"] is True
    assert {row["id"] for row in listed["modes"]} == {"chat", "search", "tor", "pentest", "developer", "security"}
    assert "read_file" in {row["name"] for row in listed["tools"]}
    created = client.post("/api/library/agents", json=configuration).json()
    identity = created["id"]
    assert client.get("/api/library/agents/" + identity).json() == created
    changed = client.put("/api/library/agents/" + identity, json={**configuration, "revision": 1, "name": "Novo nome"}).json()
    assert changed["revision"] == 2
    exported = client.get(f"/api/library/agents/{identity}/export")
    assert "attachment" in exported.headers["content-disposition"]
    imported = client.post("/api/library/agents/import", json=exported.json()).json()
    assert imported["id"] != identity
    copied = client.post("/api/library/agents/coder/duplicate", json={"name": "Cópia"}).json()
    assert copied["name"] == "Cópia" and not copied["builtin"]
    assert client.delete(f"/api/library/agents/{identity}?revision=2").json()["deleted"] is True
    events = [call.args[0] for call in http_case.activity.add.call_args_list]
    assert events == ["agent_created", "agent_updated", "agent_imported", "agent_duplicated", "agent_deleted"]
    # Prompts, paths and configuration data are never copied into the activity log.
    assert all(set(call.args[1]) == {"id", "revision"} for call in http_case.activity.add.call_args_list)


def test_http_validation_readonly_missing_conflict_and_no_error_audit(http_case, configuration):
    client = http_case.client
    assert client.post("/api/library/agents", json={**configuration, "permissions": {"root": True}}).status_code == 400
    assert client.get("/api/library/agents/custom_" + "f" * 32).status_code == 404
    assert client.get("/api/library/agents/bad%3Cheader/export").status_code == 400
    assert client.put("/api/library/agents/coder", json={**configuration, "revision": 1}).status_code == 409
    assert client.delete("/api/library/agents/coder?revision=1").status_code == 409
    agent = client.post("/api/library/agents", json=configuration).json()
    path = "/api/library/agents/" + agent["id"]
    assert client.put(path, json=configuration).status_code == 400
    assert client.put(path, json={**configuration, "revision": 2}).status_code == 409
    assert client.delete(path).status_code == 422
    assert client.get(path).json()["revision"] == 1
    assert http_case.activity.add.call_count == 1


def test_http_corrupt_database_reports_technical_error(http_case):
    http_case.library.path.write_bytes(b"not a sqlite file")
    response = http_case.client.get("/api/library/agents")
    assert response.status_code == 400 and response.json()["code"] == "agent_storage_error"
    assert response.json()["source"] == "agent_library"
